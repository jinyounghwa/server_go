// Lambda (REST-JSON). Functions run as local processes (python3 / node) per invocation.
// Versions (PublishVersion snapshots config + code) and aliases resolve "fn:qualifier" / ?Qualifier= on Invoke and Get*.
// ponytail: no warm containers, layers, weighted alias routing, or container images; the host interpreter is used
// regardless of the runtime's minor version. Add a container runner when isolation matters.
use crate::{b64, err, now_ms, unb64, ApiErr, App, ACCOUNT, REGION};
use axum::{body::Body, http::HeaderMap, response::Response};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, LazyLock},
    time::{Duration, Instant},
};
use tokio::{io::AsyncWriteExt, process::Command, sync::Semaphore};

// ponytail: at most 8 function processes at once, to stay inside the host's CPU budget.
static SLOTS: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(8));

#[derive(Clone, Default)]
pub struct InvokeConfig {
    retries: Option<i64>,       // MaximumRetryAttempts (0..2, default 2 for async invokes)
    age: Option<i64>,           // MaximumEventAgeInSeconds
    on_success: Option<String>, // DestinationConfig ARNs
    on_failure: Option<String>,
}

#[derive(Clone)]
pub struct Func {
    arn: String,
    runtime: String,
    role: String,
    handler: String,
    timeout: u64,
    memory: u64,
    env: Map<String, Value>,
    description: String,
    dir: PathBuf,
    size: usize,
    sha: String,
    modified: String,
    perms: Vec<Value>, // resource-based policy statements from AddPermission
    version: String,   // "$LATEST" or the published number
    versions: Vec<Func>, // published snapshots; version n is versions[n - 1]
    aliases: BTreeMap<String, (String, String)>, // alias -> (version, description)
    icfg: InvokeConfig, // per-function (not per-qualifier) async invoke config: retries, age, destinations
}
pub struct Mapping {
    source: String,
    function: String,
    batch: u64,
    enabled: bool,
    modified: f64,
    start: Option<String>, // Kinesis StartingPosition
    retries: i64,          // Kinesis MaximumRetryAttempts (-1 = until it succeeds)
    bisect: bool,          // Kinesis BisectBatchOnFunctionError
    fail_dest: Option<String>, // Kinesis DestinationConfig.OnFailure.Arn (SQS or SNS)
}

#[derive(Default)]
pub struct Lambda {
    f: BTreeMap<String, Func>,
    maps: BTreeMap<String, Mapping>,
}

pub fn arn(name: &str) -> String {
    format!("arn:aws:lambda:{}:{ACCOUNT}:function:{name}", *REGION)
}
// Accepts a name, a function ARN, or a partial ARN; drops any :qualifier.
pub fn name_of(id: &str) -> String {
    let id = id.split_once("function:").map_or(id, |(_, rest)| rest);
    id.split(':').next().unwrap_or(id).to_string()
}
fn alias_json(n: &str, a: &str, (ver, desc): &(String, String)) -> Value {
    json!({"AliasArn": format!("{}:{a}", arn(n)), "Name": a, "FunctionVersion": ver, "Description": desc, "RevisionId": format!("{n}-{a}-{ver}")})
}
// "name", "name:qualifier", ARN, or ARN:qualifier → (name, qualifier).
pub fn split_qualifier(id: &str) -> (String, Option<String>) {
    let rest = id.split_once("function:").map_or(id, |(_, r)| r);
    let mut it = rest.splitn(2, ':');
    (it.next().unwrap_or("").to_string(), it.next().map(String::from))
}
fn not_found(n: &str) -> ApiErr {
    ApiErr { status: 404, ..err("ResourceNotFoundException", format!("Function not found: {}", arn(n))) }
}

fn config(n: &str, f: &Func) -> Value {
    json!({"FunctionName": n, "FunctionArn": f.arn, "Runtime": f.runtime, "Role": f.role, "Handler": f.handler,
        "CodeSize": f.size, "CodeSha256": f.sha, "Description": f.description, "Timeout": f.timeout, "MemorySize": f.memory,
        "LastModified": f.modified, "Version": f.version, "PackageType": "Zip", "State": "Active", "LastUpdateStatus": "Successful",
        "Environment": {"Variables": f.env}, "Architectures": ["x86_64"], "TracingConfig": {"Mode": "PassThrough"}})
}

// Unpack a base64 zip into a fresh directory named after its hash.
fn unpack(name: &str, zip_b64: &str) -> Result<(PathBuf, usize, String), ApiErr> {
    let bad = |m: String| err("InvalidParameterValueException", m);
    let bytes = unb64(zip_b64).ok_or_else(|| bad("ZipFile is not valid base64".into()))?;
    let sha = b64(&Sha256::digest(&bytes));
    let tag: String = sha.chars().filter(|c| c.is_ascii_alphanumeric()).take(12).collect();
    let dir = std::env::temp_dir().join("rocalcloud").join("lambda").join(format!("{name}-{tag}"));
    if !dir.exists() {
        // ZipArchive::extract rejects entries that would escape the directory.
        zip::ZipArchive::new(std::io::Cursor::new(&bytes))
            .and_then(|mut z| z.extract(&dir))
            .map_err(|e| bad(format!("Could not unzip uploaded file: {e}")))?;
    }
    Ok((dir, bytes.len(), sha))
}

fn modified_now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3f+0000").to_string()
}

fn mapping_json(id: &str, m: &Mapping) -> Value {
    let mut v = json!({"UUID": id, "EventSourceArn": m.source, "FunctionArn": arn(&m.function), "BatchSize": m.batch,
           "State": if m.enabled { "Enabled" } else { "Disabled" }, "LastModified": m.modified, "StateTransitionReason": "USER_INITIATED"});
    if let Some(s) = &m.start {
        v["StartingPosition"] = s.clone().into();
        v["MaximumRetryAttempts"] = m.retries.into();
        v["BisectBatchOnFunctionError"] = m.bisect.into();
        if let Some(d) = &m.fail_dest {
            v["DestinationConfig"] = json!({"OnFailure": {"Destination": d}});
        }
    }
    v
}

fn icfg_json(n: &str, c: &InvokeConfig) -> Value {
    let mut v = json!({"FunctionArn": arn(n), "LastModified": modified_now(),
        "MaximumRetryAttempts": c.retries.unwrap_or(2), "MaximumEventAgeInSeconds": c.age.unwrap_or(21600)});
    let dest = |a: &Option<String>| a.as_ref().map_or(json!({}), |s| json!({"Destination": s}));
    if c.on_success.is_some() || c.on_failure.is_some() {
        v["DestinationConfig"] = json!({"OnSuccess": dest(&c.on_success), "OnFailure": dest(&c.on_failure)});
    }
    v
}

pub struct Invocation {
    pub payload: Value,
    pub error: Option<String>, // "Unhandled" when the handler threw or timed out
    pub log_tail: String,
    pub version: String,
}

const PY_BOOT: &str = r#"
import json, os, sys, time, traceback, importlib
sys.path.insert(0, os.getcwd())
mod, fn = os.environ["_HANDLER"].rsplit(".", 1)
deadline = time.time() + float(os.environ["_RC_TIMEOUT"])
class Context:
    function_name = os.environ["AWS_LAMBDA_FUNCTION_NAME"]
    function_version = "$LATEST"
    invoked_function_arn = os.environ["_RC_ARN"]
    memory_limit_in_mb = os.environ["AWS_LAMBDA_FUNCTION_MEMORY_SIZE"]
    aws_request_id = os.environ["_RC_REQUEST_ID"]
    log_group_name = "/aws/lambda/" + function_name
    def get_remaining_time_in_millis(self): return int(max(0, deadline - time.time()) * 1000)
event = json.load(sys.stdin)
try:
    out = {"ok": True, "result": getattr(importlib.import_module(mod), fn)(event, Context())}
except Exception as e:
    traceback.print_exc()
    out = {"ok": False, "error": {"errorMessage": str(e), "errorType": type(e).__name__, "stackTrace": traceback.format_tb(e.__traceback__)}}
sys.stdout.flush()
with open(os.environ["_RC_RESULT"], "w") as f:
    json.dump(out, f, default=str)
"#;

const NODE_BOOT: &str = r#"
const fs = require("fs"), path = require("path"), { pathToFileURL } = require("url");
const h = process.env._HANDLER, file = h.slice(0, h.lastIndexOf(".")), fn = h.slice(h.lastIndexOf(".") + 1);
const deadline = Date.now() + Number(process.env._RC_TIMEOUT) * 1000;
const ctx = { functionName: process.env.AWS_LAMBDA_FUNCTION_NAME, functionVersion: "$LATEST", invokedFunctionArn: process.env._RC_ARN,
  memoryLimitInMB: process.env.AWS_LAMBDA_FUNCTION_MEMORY_SIZE, awsRequestId: process.env._RC_REQUEST_ID,
  getRemainingTimeInMillis: () => Math.max(0, deadline - Date.now()) };
const done = out => fs.writeFileSync(process.env._RC_RESULT, JSON.stringify(out));
(async () => {
  try {
    const ext = [".mjs", ".js", ".cjs"].find(e => fs.existsSync(path.resolve(file + e)));
    if (!ext) throw new Error(`Cannot find module '${file}'`);
    const m = await import(pathToFileURL(path.resolve(file + ext)).href);
    const handler = m[fn] || (m.default && m.default[fn]);
    if (typeof handler !== "function") throw new Error(`${h} is undefined or not exported`);
    const event = JSON.parse(fs.readFileSync(0, "utf8") || "{}");
    const result = await new Promise((res, rej) => {
      const r = handler(event, ctx, (e, v) => (e ? rej(e) : res(v)));
      if (r && typeof r.then === "function") r.then(res, rej); else if (handler.length < 3) res(r);
    });
    done({ ok: true, result: result === undefined ? null : result });
  } catch (e) {
    console.error(e);
    done({ ok: false, error: { errorMessage: String(e && e.message || e), errorType: (e && e.name) || "Error", stackTrace: String(e && e.stack || "").split("\n") } });
  }
})();
"#;

// Run one invocation: spawn the runtime, feed the event, collect result and logs (also written to CloudWatch Logs).
pub async fn invoke(app: &Arc<App>, id: &str, event: Value) -> Result<Invocation, ApiErr> {
    let (name, qual) = split_qualifier(id);
    let name = name.as_str();
    let f = app.lambda.lock().unwrap().resolve(name, qual.as_deref())?;
    let (exe, boot) = if f.runtime.starts_with("python") {
        (std::env::var("RC_PYTHON").unwrap_or("python3".into()), PY_BOOT)
    } else if f.runtime.starts_with("nodejs") {
        (std::env::var("RC_NODE").unwrap_or("node".into()), NODE_BOOT)
    } else {
        return Err(err("InvalidRuntimeException", format!("Runtime {} is not supported locally (python*, nodejs* only)", f.runtime)));
    };
    let rid = uuid::Uuid::new_v4().to_string();
    let result = std::env::temp_dir().join(format!("rocalcloud-result-{rid}.json"));
    // Code inside the function calls this emulator, signed as the execution role when it exists.
    let creds = app.iam.lock().unwrap().session_for_role(&f.role, name);
    let (akid, secret, token) = creds.unwrap_or(("test".into(), "test".into(), String::new()));

    let _slot = SLOTS.acquire().await.expect("semaphore closed");
    let t0 = Instant::now();
    let mut cmd = Command::new(&exe);
    cmd.arg(if f.runtime.starts_with("python") { "-c" } else { "-e" }).arg(boot).current_dir(&f.dir)
        .envs(f.env.iter().filter_map(|(k, v)| Some((k, v.as_str()?))))
        .env("_HANDLER", &f.handler).env("_RC_TIMEOUT", f.timeout.to_string()).env("_RC_ARN", &f.arn)
        .env("_RC_REQUEST_ID", &rid).env("_RC_RESULT", &result)
        .env("AWS_LAMBDA_FUNCTION_NAME", name).env("AWS_LAMBDA_FUNCTION_MEMORY_SIZE", f.memory.to_string())
        .env("AWS_LAMBDA_FUNCTION_VERSION", &f.version).env("AWS_LAMBDA_LOG_GROUP_NAME", format!("/aws/lambda/{name}"))
        .env("AWS_REGION", REGION.as_str()).env("AWS_DEFAULT_REGION", REGION.as_str())
        .env("AWS_ENDPOINT_URL", crate::endpoint()).env("AWS_ACCESS_KEY_ID", akid).env("AWS_SECRET_ACCESS_KEY", secret)
        .env("AWS_SESSION_TOKEN", token).env("PYTHONUNBUFFERED", "1")
        .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn().map_err(|e| ApiErr { status: 500, ..err("ServiceException", format!("could not start {exe}: {e}")) })?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(event.to_string().as_bytes()).await;
    }
    let out = tokio::time::timeout(Duration::from_secs(f.timeout), child.wait_with_output()).await;
    let ms = t0.elapsed().as_secs_f64() * 1000.0;

    let (mut log, outcome) = match out {
        Ok(Ok(o)) => {
            let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
            let r: Value = std::fs::read(&result).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_else(|| {
                json!({"ok": false, "error": {"errorMessage": format!("Runtime exited with {} before returning a result", o.status), "errorType": "Runtime.ExitError"}})
            });
            (text, r)
        }
        Ok(Err(e)) => (String::new(), json!({"ok": false, "error": {"errorMessage": e.to_string(), "errorType": "Runtime.Error"}})),
        Err(_) => (String::new(), json!({"ok": false, "error": {"errorMessage": format!("Task timed out after {:.2} seconds", f.timeout as f64), "errorType": "Sandbox.Timedout"}})),
    };
    let _ = std::fs::remove_file(&result);
    if outcome["ok"] != true {
        log += &format!("{}\n", outcome["error"]["errorMessage"].as_str().unwrap_or(""));
    }
    let lines = std::iter::once(format!("START RequestId: {rid} Version: {}", f.version))
        .chain(log.lines().map(String::from))
        .chain([format!("END RequestId: {rid}"),
                format!("REPORT RequestId: {rid}\tDuration: {ms:.2} ms\tBilled Duration: {} ms\tMemory Size: {} MB", ms.ceil() as u64, f.memory)]);
    let now = now_ms();
    let stream = format!("{}/[{}]{}", chrono::Utc::now().format("%Y/%m/%d"), f.version, &rid[..8]);
    let entries: Vec<(i64, String)> = lines.map(|l| (now, l)).collect();
    let tail = entries.iter().map(|(_, l)| l.as_str()).collect::<Vec<_>>().join("\n");
    app.logs.lock().unwrap().put(&format!("/aws/lambda/{name}"), &stream, entries);
    Ok(match outcome["ok"].as_bool() {
        Some(true) => Invocation { payload: outcome["result"].clone(), error: None, log_tail: tail, version: f.version.clone() },
        _ => Invocation { payload: outcome["error"].clone(), error: Some("Unhandled".into()), log_tail: tail, version: f.version.clone() },
    })
}

fn reply(status: u16, v: Value) -> Response {
    Response::builder().status(status).header("content-type", "application/json").body(Body::from(v.to_string())).unwrap()
}
pub fn error_reply(e: ApiErr) -> Response {
    Response::builder().status(e.status).header("content-type", "application/json").header("x-amzn-errortype", &e.code)
        .body(Body::from(json!({"Type": "User", "message": e.msg, "__type": e.code}).to_string())).unwrap()
}

// Operation name for routing, events and IAM. `path` starts after the API version segment.
pub fn op_of(method: &str, path: &str) -> &'static str {
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    match (method, parts.as_slice()) {
        ("POST", ["functions"]) => "CreateFunction",
        ("GET", ["functions"]) => "ListFunctions",
        ("GET", ["functions", _]) => "GetFunction",
        ("DELETE", ["functions", _]) => "DeleteFunction",
        ("GET", ["functions", _, "configuration"]) => "GetFunctionConfiguration",
        ("PUT", ["functions", _, "configuration"]) => "UpdateFunctionConfiguration",
        ("PUT", ["functions", _, "code"]) => "UpdateFunctionCode",
        ("POST", ["functions", _, "invocations"]) => "Invoke",
        ("POST", ["functions", _, "policy"]) => "AddPermission",
        ("POST", ["functions", _, "versions"]) => "PublishVersion",
        ("GET", ["functions", _, "versions"]) => "ListVersionsByFunction",
        ("POST", ["functions", _, "aliases"]) => "CreateAlias",
        ("GET", ["functions", _, "aliases"]) => "ListAliases",
        ("GET", ["functions", _, "aliases", _]) => "GetAlias",
        ("PUT", ["functions", _, "aliases", _]) => "UpdateAlias",
        ("DELETE", ["functions", _, "aliases", _]) => "DeleteAlias",
        ("GET", ["functions", _, "policy"]) => "GetPolicy",
        ("DELETE", ["functions", _, "policy", _]) => "RemovePermission",
        ("PUT", ["functions", _, "event-invoke-config"]) => "PutFunctionEventInvokeConfig",
        ("GET", ["functions", _, "event-invoke-config"]) => "GetFunctionEventInvokeConfig",
        ("POST", ["functions", _, "event-invoke-config"]) => "UpdateFunctionEventInvokeConfig", // botocore sends POST for the PATCH-shaped op
        ("DELETE", ["functions", _, "event-invoke-config"]) => "DeleteFunctionEventInvokeConfig",
        ("POST", ["event-source-mappings"]) => "CreateEventSourceMapping",
        ("GET", ["event-source-mappings"]) => "ListEventSourceMappings",
        ("GET", ["event-source-mappings", _]) => "GetEventSourceMapping",
        ("DELETE", ["event-source-mappings", _]) => "DeleteEventSourceMapping",
        _ => "Unsupported",
    }
}
// Function resource policy, consulted by the authorizer.
impl Lambda {
    // The function a qualifier selects: $LATEST (none), a version number, or an alias.
    fn resolve(&self, name: &str, qual: Option<&str>) -> Result<Func, ApiErr> {
        let f = self.f.get(name).ok_or_else(|| not_found(name))?;
        let missing = |q: &str| ApiErr { status: 404, ..err("ResourceNotFoundException", format!("Function not found: {}:{q}", arn(name))) };
        let q = match qual {
            None | Some("$LATEST") => return Ok(f.clone()),
            Some(q) => q,
        };
        let ver = if q.bytes().all(|b| b.is_ascii_digit()) { q.to_string() } else { f.aliases.get(q).ok_or_else(|| missing(q))?.0.clone() };
        if ver == "$LATEST" {
            return Ok(f.clone());
        }
        ver.parse::<usize>().ok().and_then(|n| f.versions.get(n.wrapping_sub(1))).cloned().ok_or_else(|| missing(q))
    }
    pub fn policy(&self, name: &str) -> Option<Value> {
        let f = self.f.get(name)?;
        (!f.perms.is_empty()).then(|| json!({"Statement": f.perms}))
    }
}

pub fn path_name(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    (parts.first() == Some(&"functions")).then(|| parts.get(1).map(|n| name_of(&crate::s3::pct_decode(n)))).flatten()
}

pub async fn api(app: &Arc<App>, op: &str, path: &str, q: &std::collections::HashMap<String, String>, h: &HeaderMap, body: &[u8]) -> Response {
    let j: Value = serde_json::from_slice(body).unwrap_or(json!({}));
    let name = path_name(path).unwrap_or_default();
    let parts: Vec<String> = path.trim_matches('/').split('/').map(crate::s3::pct_decode).collect();
    let seg = |i: usize| parts.get(i).cloned().unwrap_or_default();
    let qual = q.get("Qualifier").cloned().or_else(|| split_qualifier(&seg(1)).1);
    // Destinations (and mapping OnFailure targets) must exist when saved, like S3 notification targets.
    if let Err(e) = check_dest_arns(app, op, &j) {
        return error_reply(e);
    }
    if op == "Invoke" {
        let event: Value = if body.is_empty() { json!({}) } else { serde_json::from_slice(body).unwrap_or(Value::String(String::from_utf8_lossy(body).into())) };
        let kind = h.get("x-amz-invocation-type").and_then(|v| v.to_str().ok()).unwrap_or("RequestResponse");
        if let Err(e) = app.lambda.lock().unwrap().resolve(&name, qual.as_deref()) {
            return error_reply(e);
        }
        match kind {
            "DryRun" => return Response::builder().status(204).body(Body::empty()).unwrap(),
            "Event" => {
                let icfg = app.lambda.lock().unwrap().resolve(&name, qual.as_deref()).ok().map(|f| f.icfg).unwrap_or_default();
                let (app, name) = (app.clone(), qual.as_ref().map_or(name.clone(), |q| format!("{name}:{q}")));
                tokio::spawn(async move { invoke_async(app, &name, event, icfg).await });
                return Response::builder().status(202).body(Body::empty()).unwrap();
            }
            _ => {}
        }
        let target = qual.as_ref().map_or(name.clone(), |q| format!("{name}:{q}"));
        return match invoke(app, &target, event).await {
            Err(e) => error_reply(e),
            Ok(inv) => {
                let mut r = Response::builder().status(200).header("content-type", "application/json").header("x-amz-executed-version", &inv.version);
                if let Some(e) = &inv.error {
                    r = r.header("x-amz-function-error", e);
                }
                if h.get("x-amz-log-type").is_some_and(|v| v == "Tail") {
                    let t = inv.log_tail.as_bytes();
                    r = r.header("x-amz-log-result", b64(&t[t.len().saturating_sub(4096)..]));
                }
                r.body(Body::from(inv.payload.to_string())).unwrap()
            }
        };
    }
    let res = (|| -> Result<(u16, Value), ApiErr> {
        let mut st = app.lambda.lock().unwrap();
        Ok(match op {
            "CreateFunction" => {
                let n = crate::need(&j, "FunctionName")?.to_string();
                if st.f.contains_key(&n) {
                    return Err(ApiErr { status: 409, ..err("ResourceConflictException", format!("Function already exist: {n}")) });
                }
                let zip = j["Code"]["ZipFile"].as_str().ok_or_else(|| err("InvalidParameterValueException", "Code.ZipFile is required (S3 code and images are not supported yet)"))?;
                let (dir, size, sha) = unpack(&n, zip)?;
                let f = Func {
                    arn: arn(&n), runtime: crate::need(&j, "Runtime")?.into(), role: crate::need(&j, "Role")?.into(), handler: crate::need(&j, "Handler")?.into(),
                    timeout: j["Timeout"].as_u64().unwrap_or(3), memory: j["MemorySize"].as_u64().unwrap_or(128),
                    env: j["Environment"]["Variables"].as_object().cloned().unwrap_or_default(),
                    description: j["Description"].as_str().unwrap_or("").into(), dir, size, sha, modified: modified_now(), perms: vec![],
                    version: "$LATEST".into(), versions: vec![], aliases: BTreeMap::new(), icfg: InvokeConfig::default(),
                };
                let out = config(&n, &f);
                st.f.insert(n, f);
                (201, out)
            }
            "ListFunctions" => (200, json!({"Functions": st.f.iter().map(|(n, f)| config(n, f)).collect::<Vec<_>>()})),
            "GetFunction" => {
                let f = st.resolve(&name, qual.as_deref())?;
                (200, json!({"Configuration": config(&name, &f), "Code": {"RepositoryType": "S3", "Location": format!("file://{}", f.dir.display())}}))
            }
            "GetFunctionConfiguration" => (200, config(&name, &st.resolve(&name, qual.as_deref())?)),
            "PublishVersion" => {
                let f = st.f.get_mut(&name).ok_or_else(|| not_found(&name))?;
                // Like AWS, publishing unchanged code + config again returns the last version.
                if let Some(last) = f.versions.last().filter(|v| v.sha == f.sha && v.modified == f.modified) {
                    return Ok((201, config(&name, last)));
                }
                let n = (f.versions.len() + 1).to_string();
                let mut v = Func { versions: vec![], aliases: BTreeMap::new(), perms: vec![], version: n.clone(), arn: format!("{}:{n}", arn(&name)), ..f.clone() };
                if let Some(d) = j["Description"].as_str() {
                    v.description = d.into();
                }
                let out = config(&name, &v);
                f.versions.push(v);
                (201, out)
            }
            "ListVersionsByFunction" => {
                let f = st.f.get(&name).ok_or_else(|| not_found(&name))?;
                (200, json!({"Versions": std::iter::once(config(&name, f)).chain(f.versions.iter().map(|v| config(&name, v))).collect::<Vec<_>>()}))
            }
            "CreateAlias" | "UpdateAlias" => {
                let f = st.f.get_mut(&name).ok_or_else(|| not_found(&name))?;
                let a = if op == "CreateAlias" { crate::need(&j, "Name")?.to_string() } else { seg(3) };
                if a.is_empty() || a.bytes().all(|b| b.is_ascii_digit()) || a == "$LATEST" || !a.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                    return Err(err("ValidationException", format!("Alias name {a} is not valid (letters, digits, - and _, not only digits)")));
                }
                let cur = f.aliases.get(&a).cloned();
                match (op, &cur) {
                    ("CreateAlias", Some(_)) => return Err(ApiErr { status: 409, ..err("ResourceConflictException", format!("Alias already exists: {}:{a}", arn(&name))) }),
                    ("UpdateAlias", None) => return Err(ApiErr { status: 404, ..err("ResourceNotFoundException", format!("Alias not found: {}:{a}", arn(&name))) }),
                    _ => {}
                }
                let ver = j["FunctionVersion"].as_str().map(String::from).or(cur.as_ref().map(|c| c.0.clone())).ok_or_else(|| err("ValidationException", "FunctionVersion is required"))?;
                if ver != "$LATEST" && !ver.parse::<usize>().is_ok_and(|n| n >= 1 && n <= f.versions.len()) {
                    return Err(ApiErr { status: 404, ..err("ResourceNotFoundException", format!("Function not found: {}:{ver}", arn(&name))) });
                }
                if !j["RoutingConfig"].is_null() {
                    return Err(err("InvalidParameterValueException", "Weighted alias routing (RoutingConfig) is not supported locally"));
                }
                let desc = j["Description"].as_str().map(String::from).or(cur.map(|c| c.1)).unwrap_or_default();
                f.aliases.insert(a.clone(), (ver, desc));
                (if op == "CreateAlias" { 201 } else { 200 }, alias_json(&name, &a, &f.aliases[&a]))
            }
            "ListAliases" => {
                let f = st.f.get(&name).ok_or_else(|| not_found(&name))?;
                (200, json!({"Aliases": f.aliases.iter().map(|(a, v)| alias_json(&name, a, v)).collect::<Vec<_>>()}))
            }
            "GetAlias" | "DeleteAlias" => {
                let f = st.f.get_mut(&name).ok_or_else(|| not_found(&name))?;
                let a = seg(3);
                let nf = || ApiErr { status: 404, ..err("ResourceNotFoundException", format!("Alias not found: {}:{a}", arn(&name))) };
                if op == "GetAlias" {
                    (200, alias_json(&name, &a, f.aliases.get(&a).ok_or_else(nf)?))
                } else {
                    f.aliases.remove(&a).ok_or_else(nf)?;
                    (204, Value::Null)
                }
            }
            "DeleteFunction" => {
                st.f.remove(&name).ok_or_else(|| not_found(&name))?;
                st.maps.retain(|_, m| m.function != name);
                (204, Value::Null)
            }
            "UpdateFunctionCode" => {
                let zip = j["ZipFile"].as_str().ok_or_else(|| err("InvalidParameterValueException", "ZipFile is required"))?;
                let (dir, size, sha) = unpack(&name, zip)?;
                let f = st.f.get_mut(&name).ok_or_else(|| not_found(&name))?;
                (f.dir, f.size, f.sha, f.modified) = (dir, size, sha, modified_now());
                (200, config(&name, f))
            }
            "UpdateFunctionConfiguration" => {
                let f = st.f.get_mut(&name).ok_or_else(|| not_found(&name))?;
                for (k, v) in j.as_object().into_iter().flatten() {
                    match k.as_str() {
                        "Runtime" => f.runtime = v.as_str().unwrap_or(&f.runtime).into(),
                        "Role" => f.role = v.as_str().unwrap_or(&f.role).into(),
                        "Handler" => f.handler = v.as_str().unwrap_or(&f.handler).into(),
                        "Timeout" => f.timeout = v.as_u64().unwrap_or(f.timeout),
                        "MemorySize" => f.memory = v.as_u64().unwrap_or(f.memory),
                        "Description" => f.description = v.as_str().unwrap_or("").into(),
                        "Environment" => f.env = v["Variables"].as_object().cloned().unwrap_or_default(),
                        _ => {}
                    }
                }
                f.modified = modified_now();
                (200, config(&name, f))
            }
            // Resource-based policy: statements are evaluated for IAM-signed calls (see iam::authorize_with).
            // Service principals (sns.amazonaws.com …) gate SNS/EventBridge/S3 triggers with ENFORCE_IAM=1 (main.rs service_gate).
            "AddPermission" => {
                let f = st.f.get_mut(&name).ok_or_else(|| not_found(&name))?;
                let sid = crate::need(&j, "StatementId")?;
                let action = crate::need(&j, "Action")?;
                let who = crate::need(&j, "Principal")?;
                if sid.is_empty() || sid.len() > 100 || !sid.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                    return Err(err("InvalidParameterValueException", "StatementId must match [a-zA-Z0-9-_]{1,100}"));
                }
                if f.perms.iter().any(|s| s["Sid"] == sid) {
                    return Err(ApiErr { status: 409, ..err("ResourceConflictException", format!("The statement id ({sid}) provided already exists. Please provide a new statement id, or remove the existing statement.")) });
                }
                let principal = if who.ends_with(".amazonaws.com") {
                    json!({"Service": who})
                } else if who.len() == 12 && who.bytes().all(|b| b.is_ascii_digit()) {
                    json!({"AWS": format!("arn:aws:iam::{who}:root")})
                } else if who == "*" {
                    json!("*")
                } else {
                    json!({"AWS": who})
                };
                let mut st_json = json!({"Sid": sid, "Effect": "Allow", "Principal": principal, "Action": action, "Resource": arn(&name)});
                if let Some(src) = j["SourceArn"].as_str() {
                    st_json["Condition"] = json!({"ArnLike": {"AWS:SourceArn": src}});
                }
                f.perms.push(st_json.clone());
                (201, json!({"Statement": st_json.to_string()}))
            }
            "GetPolicy" => {
                let f = st.f.get(&name).ok_or_else(|| not_found(&name))?;
                if f.perms.is_empty() {
                    return Err(ApiErr { status: 404, ..err("ResourceNotFoundException", "The resource you requested does not exist.") });
                }
                (200, json!({"Policy": json!({"Version": "2012-10-17", "Id": "default", "Statement": f.perms}).to_string(), "RevisionId": uuid::Uuid::new_v4().to_string()}))
            }
            "RemovePermission" => {
                let sid = crate::s3::pct_decode(path.trim_matches('/').rsplit('/').next().unwrap_or(""));
                let f = st.f.get_mut(&name).ok_or_else(|| not_found(&name))?;
                let before = f.perms.len();
                f.perms.retain(|s| s["Sid"] != sid.as_str());
                if f.perms.len() == before {
                    return Err(ApiErr { status: 404, ..err("ResourceNotFoundException", format!("Statement {sid} is not found in resource policy.")) });
                }
                (204, json!({}))
            }
            "PutFunctionEventInvokeConfig" | "UpdateFunctionEventInvokeConfig" => {
                // Stored per function, not per qualifier (ponytail: no version/alias-specific invoke configs).
                let f = st.f.get_mut(&name).ok_or_else(|| not_found(&name))?;
                let mut c = if op == "PutFunctionEventInvokeConfig" { InvokeConfig::default() } else { f.icfg.clone() };
                if let Some(v) = j["MaximumRetryAttempts"].as_i64() {
                    if !(0..=2).contains(&v) {
                        return Err(err("InvalidParameterValueException", "MaximumRetryAttempts must be between 0 and 2"));
                    }
                    c.retries = Some(v);
                }
                if let Some(v) = j["MaximumEventAgeInSeconds"].as_i64() {
                    if !(60..=21600).contains(&v) {
                        return Err(err("InvalidParameterValueException", "MaximumEventAgeInSeconds must be between 60 and 21600"));
                    }
                    c.age = Some(v);
                }
                if let Some(d) = j["DestinationConfig"].as_object() {
                    if d.contains_key("OnSuccess") {
                        c.on_success = d["OnSuccess"]["Destination"].as_str().map(String::from);
                    }
                    if d.contains_key("OnFailure") {
                        c.on_failure = d["OnFailure"]["Destination"].as_str().map(String::from);
                    }
                }
                f.icfg = c.clone();
                (200, icfg_json(&name, &c))
            }
            "GetFunctionEventInvokeConfig" => {
                let f = st.f.get(&name).ok_or_else(|| not_found(&name))?;
                (200, icfg_json(&name, &f.icfg))
            }
            "DeleteFunctionEventInvokeConfig" => {
                let f = st.f.get_mut(&name).ok_or_else(|| not_found(&name))?;
                f.icfg = InvokeConfig::default();
                (204, json!({}))
            }
            "CreateEventSourceMapping" => {
                let fname = name_of(crate::need(&j, "FunctionName")?);
                st.f.get(&fname).ok_or_else(|| not_found(&fname))?;
                let src = crate::need(&j, "EventSourceArn")?.to_string();
                let kinesis = src.starts_with("arn:aws:kinesis:");
                if !kinesis && !src.starts_with("arn:aws:sqs:") {
                    return Err(err("InvalidParameterValueException", "Only SQS and Kinesis event sources are supported locally"));
                }
                let bad = |m: &str| err("InvalidParameterValueException", m.to_string());
                let start = j["StartingPosition"].as_str().map(String::from);
                if kinesis {
                    if !matches!(start.as_deref(), Some("TRIM_HORIZON" | "LATEST")) {
                        return Err(bad("StartingPosition must be TRIM_HORIZON or LATEST for a Kinesis event source"));
                    }
                    if !app.kinesis.lock().unwrap().exists(src.rsplit('/').next().unwrap_or("")) {
                        return Err(bad("Stream not found"));
                    }
                }
                let (dflt, max) = if kinesis { (100, 10000) } else { (10, 10) };
                let retries = j["MaximumRetryAttempts"].as_i64().unwrap_or(-1);
                if !(-1..=10000).contains(&retries) {
                    return Err(bad("MaximumRetryAttempts must be between -1 and 10000"));
                }
                let id = uuid::Uuid::new_v4().to_string();
                let bisect = kinesis && j["BisectBatchOnFunctionError"].as_bool().unwrap_or(false);
                let fail_dest = j["DestinationConfig"]["OnFailure"]["Destination"].as_str().map(String::from);
                let m = Mapping { source: src, function: fname, batch: j["BatchSize"].as_u64().unwrap_or(dflt).clamp(1, max), enabled: j["Enabled"].as_bool().unwrap_or(true),
                                  modified: crate::epoch(), start: start.filter(|_| kinesis), retries, bisect, fail_dest };
                let out = mapping_json(&id, &m);
                st.maps.insert(id.clone(), m);
                let app = app.clone();
                if kinesis {
                    tokio::spawn(async move { poll_kinesis(app, id).await });
                } else {
                    tokio::spawn(async move { poll_sqs(app, id).await });
                }
                (202, out)
            }
            "ListEventSourceMappings" => {
                let fname = q.get("FunctionName").map(|f| name_of(f));
                let list: Vec<Value> = st.maps.iter().filter(|(_, m)| fname.as_ref().is_none_or(|f| *f == m.function)
                    && q.get("EventSourceArn").is_none_or(|s| *s == m.source)).map(|(id, m)| mapping_json(id, m)).collect();
                (200, json!({ "EventSourceMappings": list }))
            }
            "GetEventSourceMapping" | "DeleteEventSourceMapping" => {
                let id = path.trim_matches('/').rsplit('/').next().unwrap_or("").to_string();
                let nf = || ApiErr { status: 404, ..err("ResourceNotFoundException", format!("The resource you requested does not exist. (Service: Lambda; UUID: {id})")) };
                if op == "GetEventSourceMapping" {
                    (200, mapping_json(&id, st.maps.get(&id).ok_or_else(nf)?))
                } else {
                    let m = st.maps.remove(&id).ok_or_else(nf)?;
                    let mut v = mapping_json(&id, &m);
                    v["State"] = "Deleting".into();
                    (202, v)
                }
            }
            _ => return Err(ApiErr { status: 404, ..err("UnknownOperationException", format!("{op} is not supported yet")) }),
        })
    })();
    match res {
        Ok((204, _)) => Response::builder().status(204).body(Body::empty()).unwrap(),
        Ok((s, v)) => reply(s, v),
        Err(e) => error_reply(e),
    }
}

// Invoke and report the outcome as an event (used by async invokes, SNS and SQS triggers).
pub async fn invoke_logged(app: &Arc<App>, name: &str, event: Value, source: &str) -> bool {
    invoke_ev(app, name, event, source).await.0
}

// Invoke, emit the request event, and return (ok, error message).
async fn invoke_ev(app: &Arc<App>, name: &str, event: Value, source: &str) -> (bool, Option<String>) {
    let r = invoke(app, name, event).await;
    let ok = matches!(&r, Ok(i) if i.error.is_none());
    let msg = r.ok().and_then(|i| i.error.and_then(|_| i.payload["errorMessage"].as_str().map(String::from)));
    crate::emit(app, json!({"ts": chrono::Utc::now().to_rfc3339(), "service": "lambda", "op": "Invoke", "target": name, "trigger": source,
        "status": if ok { 200 } else { 500 }, "error": msg.clone()}));
    (ok, msg)
}

// Destination ARNs saved with Lambda Destinations or a mapping's OnFailure must point at something that exists.
fn check_dest_arns(app: &Arc<App>, op: &str, j: &Value) -> Result<(), ApiErr> {
    let mut arns = vec![];
    for key in ["OnSuccess", "OnFailure"] {
        if let Some(a) = j["DestinationConfig"][key]["Destination"].as_str() {
            arns.push(a.to_string());
        }
    }
    if arns.is_empty() {
        return Ok(());
    }
    if matches!(op, "CreateEventSourceMapping") {
        // Event source mapping OnFailure targets: SQS queues or SNS topics only (AWS).
        if arns.iter().any(|a| !a.starts_with("arn:aws:sqs:") && !a.starts_with("arn:aws:sns:")) {
            return Err(err("InvalidParameterValueException", "OnFailure destination for an event source mapping must be an SQS queue or SNS topic ARN"));
        }
    }
    for a in &arns {
        let ok = if a.starts_with("arn:aws:sqs:") {
            app.sqs.lock().unwrap().exists(a.rsplit(':').next().unwrap_or(""))
        } else if a.starts_with("arn:aws:sns:") {
            app.sns.lock().unwrap().exists(a)
        } else if a.starts_with("arn:aws:lambda:") {
            app.lambda.lock().unwrap().exists(&name_of(a))
        } else if a.starts_with("arn:aws:events:") {
            app.eb.lock().unwrap().bus_exists(a.rsplit('/').next().unwrap_or(""))
        } else {
            false
        };
        if !ok {
            return Err(err("InvalidParameterValueException", format!("The destination ARN {a} does not exist or is not a supported destination (SQS, SNS, Lambda, EventBridge bus)")));
        }
    }
    Ok(())
}

// Asynchronous (Event) invocation with per-function destinations: retry failures up to MaximumRetryAttempts
// (or MaximumEventAgeInSeconds), then route the AWS-shaped result envelope to OnFailure / OnSuccess.
// Delivery reuses main.rs send_to_target; the target's resource policy is NOT evaluated for these sends
// (AWS delivers with the function's execution role; service_gate skips non sns/events/s3 senders).
async fn invoke_async(app: Arc<App>, name: &str, event: Value, icfg: InvokeConfig) {
    let attempts = icfg.retries.unwrap_or(2).clamp(0, 2) as u32 + 1;
    let age = icfg.age.filter(|a| *a > 0).map(|a| Duration::from_secs(a as u64));
    let t0 = Instant::now();
    let rid = uuid::Uuid::new_v4().to_string();
    let far = name_of(name);
    let mut count = 0u32;
    let (failed, condition, response) = loop {
        count += 1;
        let (ok, payload, msg) = match invoke(&app, name, event.clone()).await {
            Ok(i) if i.error.is_none() => (true, i.payload, None),
            Ok(i) => (false, Value::Null, Some(i.payload["errorMessage"].clone())),
            Err(_) => (false, Value::Null, None),
        };
        let failed = !ok;
        crate::emit(&app, json!({"ts": chrono::Utc::now().to_rfc3339(), "service": "lambda", "op": "Invoke", "target": name, "trigger": "async",
            "status": if failed { 500 } else { 200 }, "error": msg.clone(), "attempt": count}));
        let response = if failed { msg.unwrap_or(Value::Null) } else { payload };
        if !failed || count >= attempts || age.is_some_and(|a| t0.elapsed() > a) {
            let condition = if failed { json!(if count >= attempts { "RetriesExhausted" } else { "EventAgeExceeded" }) } else { Value::Null };
            break (failed, condition, response);
        }
        tokio::time::sleep(Duration::from_millis(200)).await; // fixed short backoff; AWS backs off up to ~1h
    };
    let dest = if failed { icfg.on_failure.as_deref() } else { icfg.on_success.as_deref() };
    if let Some(dest) = dest.filter(|d| !d.is_empty()) {
        let payload = json!({
            "version": "1.0",
            "timestamp": now_ms(),
            "requestContext": {"requestId": rid, "functionArn": arn(&far), "condition": condition, "approximateInvokeCount": count},
            "requestPayload": event,
            "responseContext": if failed { Value::Null } else { json!({"statusCode": 200}) },
            "responsePayload": response,
        });
        crate::send_to_target(&app, &rid, dest, payload, "lambda", &arn(&far));
    }
}

// One loop per SQS event source mapping: receive a batch, invoke, delete on success.
// Failed batches stay in the queue and come back after the visibility timeout (and reach a DLQ via redrive).
async fn poll_sqs(app: Arc<App>, id: String) {
    loop {
        let Some((queue, func, batch, enabled)) = app.lambda.lock().unwrap().maps.get(&id).map(|m| (m.source.clone(), m.function.clone(), m.batch, m.enabled)) else {
            return; // mapping deleted
        };
        let qname = queue.rsplit(':').next().unwrap_or("").to_string();
        let msgs = if enabled { app.sqs.lock().unwrap().receive_batch(&qname, batch) } else { vec![] };
        if msgs.is_empty() {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }
        let records: Vec<Value> = msgs.iter().map(|m| {
            let mut r = m.clone();
            r["eventSource"] = "aws:sqs".into();
            r["eventSourceARN"] = queue.clone().into();
            r["awsRegion"] = REGION.as_str().into();
            r
        }).collect();
        if invoke_logged(&app, &func, json!({ "Records": records }), "sqs").await {
            let mut sqs = app.sqs.lock().unwrap();
            for m in &msgs {
                sqs.delete_receipt(&qname, m["receiptHandle"].as_str().unwrap_or(""));
            }
        }
    }
}

// One loop per Kinesis event source mapping: every shard is read in order from its own position. A failed batch is
// retried (blocking that shard, as in AWS) until it succeeds or MaximumRetryAttempts is used up, then skipped.
// BisectBatchOnFunctionError splits a failed batch in half and retries each half; a skipped batch's metadata is
// routed to DestinationConfig.OnFailure. ponytail: no tumbling windows or parallelization factor.
async fn poll_kinesis(app: Arc<App>, id: String) {
    let Some((src, start)) = app.lambda.lock().unwrap().maps.get(&id).map(|m| (m.source.clone(), m.start.clone())) else { return };
    let stream = src.rsplit('/').next().unwrap_or("").to_string();
    let mut pos = app.kinesis.lock().unwrap().positions(&stream, start.as_deref() == Some("LATEST"));
    let mut failures = vec![0i64; pos.len()];
    loop {
        let Some((func, batch, enabled, retries, role, bisect, fail_dest)) = ({
            let l = app.lambda.lock().unwrap();
            l.maps.get(&id).map(|m| (m.function.clone(), m.batch as usize, m.enabled, m.retries, l.f.get(&m.function).map(|f| f.role.clone()).unwrap_or_default(), m.bisect, m.fail_dest.clone()))
        }) else {
            return; // mapping deleted
        };
        let mut busy = false;
        // Follow resharding: newly appended shards start from their beginning (they are empty at creation).
        let cur = app.kinesis.lock().unwrap().shard_count(&stream);
        while pos.len() < cur {
            pos.push(0);
            failures.push(0);
        }
        for i in 0..pos.len() {
            let recs = if enabled { app.kinesis.lock().unwrap().read(&stream, i, pos[i], batch) } else { vec![] };
            if recs.is_empty() {
                continue;
            }
            busy = true;
            pos[i] += try_kinesis_batch(&app, &func, i, &src, &role, recs, retries, &mut failures[i], bisect, fail_dest.clone()).await;
            tokio::time::sleep(Duration::from_millis(100)).await; // give a failed shard a moment before the next pass
        }
        if !busy {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

// Try one (sub)batch; returns how many leading records are consumed (delivered or skipped). A failed batch is
// bisected when enabled, so a good half keeps its progress while the bad half retries on its own budget.
async fn try_kinesis_batch(app: &Arc<App>, func: &str, shard: usize, src: &str, role: &str, recs: Vec<Value>, retries: i64, fail: &mut i64, bisect: bool, dest: Option<String>) -> usize {
    let records: Vec<Value> = recs.iter().map(|r| json!({"kinesis": r, "eventSource": "aws:kinesis", "eventVersion": "1.0",
        "eventID": format!("shardId-{shard:012}:{}", r["sequenceNumber"].as_str().unwrap_or("")), "eventName": "aws:kinesis:record",
        "invokeIdentityArn": role, "awsRegion": REGION.as_str(), "eventSourceARN": src})).collect();
    if invoke_logged(app, func, json!({ "Records": records }), "kinesis").await {
        *fail = 0;
        return recs.len();
    }
    if bisect && recs.len() > 1 {
        let mid = recs.len() / 2;
        let (a, b) = recs.split_at(mid);
        let (mut fa, mut fb) = (0i64, 0i64);
        let done = Box::pin(try_kinesis_batch(app, func, shard, src, role, a.to_vec(), retries, &mut fa, bisect, dest.clone())).await;
        if done < a.len() {
            return done; // the first half still blocks the shard; the rest is retried from there
        }
        return done + Box::pin(try_kinesis_batch(app, func, shard, src, role, b.to_vec(), retries, &mut fb, bisect, dest)).await;
    }
    *fail += 1;
    if retries >= 0 && *fail >= retries {
        *fail = 0;
        if let Some(d) = dest.filter(|d| !d.is_empty()) {
            let meta = json!({
                "StreamArn": src,
                "ShardId": format!("shardId-{shard:012}"),
                "StartSequenceNumber": recs.first().and_then(|r| r["sequenceNumber"].as_str()),
                "EndSequenceNumber": recs.last().and_then(|r| r["sequenceNumber"].as_str()),
                "BatchSize": recs.len(),
                "ErrorCode": "Lambda.FunctionError",
            });
            crate::send_to_target(app, &uuid::Uuid::new_v4().to_string(), &d, meta, "lambda", src);
        }
        return recs.len(); // give up on this batch
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    0
}

impl Lambda {
    pub fn exists(&self, name: &str) -> bool {
        self.f.contains_key(name)
    }

    pub fn admin(&self) -> Value {
        self.f
            .iter()
            .map(|(n, f)| {
                let maps: Vec<Value> = self.maps.iter().filter(|(_, m)| m.function == *n).map(|(_, m)| json!([if m.start.is_some() { "Kinesis 트리거" } else { "SQS 트리거" }, m.source, format!("배치 {}", m.batch)])).collect();
                let mut rows = vec![json!(["런타임", f.runtime, f.handler]), json!(["역할", f.role, ""]), json!(["제한", format!("{}초", f.timeout), format!("{} MB", f.memory)])];
                if f.icfg.on_success.is_some() || f.icfg.on_failure.is_some() {
                    rows.push(json!(["실패 시 재시도", format!("{}회", f.icfg.retries.unwrap_or(2)), format!("최대 {}초", f.icfg.age.unwrap_or(3600))]));
                }
                if let Some(d) = &f.icfg.on_failure {
                    rows.push(json!(["실패 대상", "OnFailure", d]));
                }
                if let Some(d) = &f.icfg.on_success {
                    rows.push(json!(["성공 대상", "OnSuccess", d]));
                }
                rows.extend(maps);
                json!({"name": n, "count": rows.len() - 3, "sub": format!("{} · 로그 그룹 /aws/lambda/{n}", f.arn), "cols": ["항목", "값", ""], "rows": rows})
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invoke_config_round_trip() {
        let c = InvokeConfig { retries: Some(1), age: Some(600), on_success: None, on_failure: Some("arn:aws:sqs:us-east-1:000000000000:dlq".into()) };
        let v = icfg_json("f", &c);
        assert_eq!(v["MaximumRetryAttempts"], 1);
        assert_eq!(v["MaximumEventAgeInSeconds"], 600);
        assert_eq!(v["DestinationConfig"]["OnFailure"]["Destination"], "arn:aws:sqs:us-east-1:000000000000:dlq");
        assert!(v["DestinationConfig"]["OnSuccess"].is_object(), "unset side is an empty object");
        // Defaults mirror AWS: 2 retries, 6 hours.
        let d = icfg_json("f", &InvokeConfig::default());
        assert_eq!(d["MaximumRetryAttempts"], 2);
        assert_eq!(d["MaximumEventAgeInSeconds"], 21600);
    }

    #[test]
    fn mapping_json_carries_failure_config() {
        let m = Mapping { source: "arn:aws:kinesis:us-east-1:000000000000:stream/s".into(), function: "f".into(), batch: 10,
            enabled: true, modified: 0.0, start: Some("LATEST".into()), retries: 3, bisect: true,
            fail_dest: Some("arn:aws:sqs:us-east-1:000000000000:bad".into()) };
        let v = mapping_json("u", &m);
        assert_eq!(v["BisectBatchOnFunctionError"], true);
        assert_eq!(v["DestinationConfig"]["OnFailure"]["Destination"], "arn:aws:sqs:us-east-1:000000000000:bad");
        assert_eq!(v["MaximumRetryAttempts"], 3);
    }
}

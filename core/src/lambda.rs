// Lambda (REST-JSON). Functions run as local processes (python3 / node) per invocation.
// ponytail: no warm containers, layers, versions/aliases, or container images; the host interpreter is used
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
}
pub struct Mapping {
    source: String,
    function: String,
    batch: u64,
    enabled: bool,
    modified: f64,
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
fn not_found(n: &str) -> ApiErr {
    ApiErr { status: 404, ..err("ResourceNotFoundException", format!("Function not found: {}", arn(n))) }
}

fn config(n: &str, f: &Func) -> Value {
    json!({"FunctionName": n, "FunctionArn": f.arn, "Runtime": f.runtime, "Role": f.role, "Handler": f.handler,
        "CodeSize": f.size, "CodeSha256": f.sha, "Description": f.description, "Timeout": f.timeout, "MemorySize": f.memory,
        "LastModified": f.modified, "Version": "$LATEST", "PackageType": "Zip", "State": "Active", "LastUpdateStatus": "Successful",
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
    json!({"UUID": id, "EventSourceArn": m.source, "FunctionArn": arn(&m.function), "BatchSize": m.batch,
           "State": if m.enabled { "Enabled" } else { "Disabled" }, "LastModified": m.modified, "StateTransitionReason": "USER_INITIATED"})
}

pub struct Invocation {
    pub payload: Value,
    pub error: Option<String>, // "Unhandled" when the handler threw or timed out
    pub log_tail: String,
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
pub async fn invoke(app: &Arc<App>, name: &str, event: Value) -> Result<Invocation, ApiErr> {
    let f = app.lambda.lock().unwrap().f.get(name).cloned().ok_or_else(|| not_found(name))?;
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
        .env("AWS_LAMBDA_FUNCTION_VERSION", "$LATEST").env("AWS_LAMBDA_LOG_GROUP_NAME", format!("/aws/lambda/{name}"))
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
    let lines = std::iter::once(format!("START RequestId: {rid} Version: $LATEST"))
        .chain(log.lines().map(String::from))
        .chain([format!("END RequestId: {rid}"),
                format!("REPORT RequestId: {rid}\tDuration: {ms:.2} ms\tBilled Duration: {} ms\tMemory Size: {} MB", ms.ceil() as u64, f.memory)]);
    let now = now_ms();
    let stream = format!("{}/[$LATEST]{}", chrono::Utc::now().format("%Y/%m/%d"), &rid[..8]);
    let entries: Vec<(i64, String)> = lines.map(|l| (now, l)).collect();
    let tail = entries.iter().map(|(_, l)| l.as_str()).collect::<Vec<_>>().join("\n");
    app.logs.lock().unwrap().put(&format!("/aws/lambda/{name}"), &stream, entries);
    Ok(match outcome["ok"].as_bool() {
        Some(true) => Invocation { payload: outcome["result"].clone(), error: None, log_tail: tail },
        _ => Invocation { payload: outcome["error"].clone(), error: Some("Unhandled".into()), log_tail: tail },
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
        ("GET", ["functions", _, "policy"]) => "GetPolicy",
        ("DELETE", ["functions", _, "policy", _]) => "RemovePermission",
        ("POST", ["event-source-mappings"]) => "CreateEventSourceMapping",
        ("GET", ["event-source-mappings"]) => "ListEventSourceMappings",
        ("GET", ["event-source-mappings", _]) => "GetEventSourceMapping",
        ("DELETE", ["event-source-mappings", _]) => "DeleteEventSourceMapping",
        _ => "Unsupported",
    }
}
// Function resource policy, consulted by the authorizer.
impl Lambda {
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
    if op == "Invoke" {
        let event: Value = if body.is_empty() { json!({}) } else { serde_json::from_slice(body).unwrap_or(Value::String(String::from_utf8_lossy(body).into())) };
        let kind = h.get("x-amz-invocation-type").and_then(|v| v.to_str().ok()).unwrap_or("RequestResponse");
        if !app.lambda.lock().unwrap().f.contains_key(&name) {
            return error_reply(not_found(&name));
        }
        match kind {
            "DryRun" => return Response::builder().status(204).body(Body::empty()).unwrap(),
            "Event" => {
                let (app, name) = (app.clone(), name.clone());
                tokio::spawn(async move { invoke_logged(&app, &name, event, "async").await });
                return Response::builder().status(202).body(Body::empty()).unwrap();
            }
            _ => {}
        }
        return match invoke(app, &name, event).await {
            Err(e) => error_reply(e),
            Ok(inv) => {
                let mut r = Response::builder().status(200).header("content-type", "application/json").header("x-amz-executed-version", "$LATEST");
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
                };
                let out = config(&n, &f);
                st.f.insert(n, f);
                (201, out)
            }
            "ListFunctions" => (200, json!({"Functions": st.f.iter().map(|(n, f)| config(n, f)).collect::<Vec<_>>()})),
            "GetFunction" => {
                let f = st.f.get(&name).ok_or_else(|| not_found(&name))?;
                (200, json!({"Configuration": config(&name, f), "Code": {"RepositoryType": "S3", "Location": format!("file://{}", f.dir.display())}}))
            }
            "GetFunctionConfiguration" => (200, config(&name, st.f.get(&name).ok_or_else(|| not_found(&name))?)),
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
            "CreateEventSourceMapping" => {
                let fname = name_of(crate::need(&j, "FunctionName")?);
                st.f.get(&fname).ok_or_else(|| not_found(&fname))?;
                let src = crate::need(&j, "EventSourceArn")?.to_string();
                if !src.starts_with("arn:aws:sqs:") {
                    return Err(err("InvalidParameterValueException", "Only SQS event sources are supported locally"));
                }
                let id = uuid::Uuid::new_v4().to_string();
                let m = Mapping { source: src, function: fname, batch: j["BatchSize"].as_u64().unwrap_or(10).clamp(1, 10), enabled: j["Enabled"].as_bool().unwrap_or(true), modified: crate::epoch() };
                let out = mapping_json(&id, &m);
                st.maps.insert(id.clone(), m);
                let app = app.clone();
                tokio::spawn(async move { poll_sqs(app, id).await });
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
    let r = invoke(app, name, event).await;
    let ok = matches!(&r, Ok(i) if i.error.is_none());
    crate::emit(app, json!({"ts": chrono::Utc::now().to_rfc3339(), "service": "lambda", "op": "Invoke", "target": name, "trigger": source,
        "status": if ok { 200 } else { 500 }, "error": r.as_ref().ok().and_then(|i| i.error.as_ref().map(|_| i.payload["errorMessage"].clone()))}));
    ok
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

impl Lambda {
    pub fn exists(&self, name: &str) -> bool {
        self.f.contains_key(name)
    }
    pub fn admin(&self) -> Value {
        self.f
            .iter()
            .map(|(n, f)| {
                let maps: Vec<Value> = self.maps.iter().filter(|(_, m)| m.function == *n).map(|(_, m)| json!(["SQS 트리거", m.source, format!("배치 {}", m.batch)])).collect();
                let mut rows = vec![json!(["런타임", f.runtime, f.handler]), json!(["역할", f.role, ""]), json!(["제한", format!("{}초", f.timeout), format!("{} MB", f.memory)])];
                rows.extend(maps);
                json!({"name": n, "count": rows.len() - 3, "sub": format!("{} · 로그 그룹 /aws/lambda/{n}", f.arn), "cols": ["항목", "값", ""], "rows": rows})
            })
            .collect()
    }
}

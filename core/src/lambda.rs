// Lambda (REST-JSON). Functions run as local processes (python3 / node) per invocation.
// Versions (PublishVersion snapshots config + code) and aliases resolve "fn:qualifier" / ?Qualifier= on Invoke and Get*.
// Layers (PublishLayerVersion …) unpack once per version; a function's layers go on PYTHONPATH / NODE_PATH, later layers first,
// which matches AWS's "later layers overwrite earlier ones in /opt". ponytail: NODE_PATH only reaches require(), not ESM
// import of bare specifiers; /opt itself is not emulated.
// ponytail: no container images (PackageType=Image) yet; Zip functions run in warm resident host processes
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
use tokio::{io::{AsyncBufReadExt, AsyncWriteExt}, process::Command, sync::{mpsc, Semaphore}};

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
    package: String, // "Zip" or "Image"
    image: Option<String>, // local docker image uri when package is Image
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
    aliases: BTreeMap<String, Alias>, // alias -> (version, description)
    icfg: InvokeConfig, // per-function (not per-qualifier) async invoke config: retries, age, destinations
    layers: Vec<(String, PathBuf, usize)>, // (LayerVersionArn, unpacked dir, size), in configured order
}
// One published layer version. Deleted versions become None so numbering never repeats.
#[derive(Clone)]
struct LayerVer {
    dir: PathBuf,
    size: usize,
    sha: String,
    desc: String,
    license: String,
    runtimes: Vec<Value>,
    archs: Vec<Value>,
    created: String,
    perms: Vec<Value>,
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
    // idle warm processes per "name|version|last-modified" key; reset() drops them (kill_on_drop)
    pub warm: std::sync::Mutex<std::collections::HashMap<String, Vec<WarmProc>>>,
    // idle image containers (PackageType=Image) per the same key scheme; dropping one removes the container
    pub img: std::sync::Mutex<std::collections::HashMap<String, Vec<ImgWarm>>>,
    layers: BTreeMap<String, Vec<Option<LayerVer>>>,
}

pub fn layer_arn(name: &str) -> String {
    format!("arn:aws:lambda:{}:{ACCOUNT}:layer:{name}", *REGION)
}
// IAM resource for a /layers/... path: the layer, or the layer version when the path names one.
pub fn layer_resource(path: &str) -> Option<String> {
    let p: Vec<&str> = path.trim_matches('/').split('/').collect();
    match p.as_slice() {
        ["layers"] => Some("*".into()),
        ["layers", n, "versions", v, ..] => Some(format!("{}:{v}", layer_arn(n))),
        ["layers", n, ..] => Some(layer_arn(n)),
        _ => None,
    }
}
// "arn:aws:lambda:region:acct:layer:name:version" → (name, version).
fn parse_layer_arn(a: &str) -> Option<(String, usize)> {
    let p: Vec<&str> = a.split(':').collect();
    match p.as_slice() {
        ["arn", "aws", "lambda", _, _, "layer", n, v] => Some((n.to_string(), v.parse().ok()?)),
        _ => None,
    }
}
fn layer_json(n: &str, v: usize, l: &LayerVer) -> Value {
    json!({"Content": {"Location": format!("file://{}", l.dir.display()), "CodeSha256": l.sha, "CodeSize": l.size},
        "LayerArn": layer_arn(n), "LayerVersionArn": format!("{}:{v}", layer_arn(n)), "Description": l.desc, "CreatedDate": l.created,
        "Version": v, "CompatibleRuntimes": l.runtimes, "CompatibleArchitectures": l.archs, "LicenseInfo": l.license})
}

pub fn arn(name: &str) -> String {
    format!("arn:aws:lambda:{}:{ACCOUNT}:function:{name}", *REGION)
}
// Accepts a name, a function ARN, or a partial ARN; drops any :qualifier.
pub fn name_of(id: &str) -> String {
    let id = id.split_once("function:").map_or(id, |(_, rest)| rest);
    id.split(':').next().unwrap_or(id).to_string()
}
// One alias: its primary version, optional weighted routing to one additional version, and an
// optional qualifier-specific async invoke config (None inherits the $LATEST config).
#[derive(Clone, Default)]
struct Alias {
    ver: String,
    desc: String,
    weights: Option<(String, f64)>, // AdditionalVersionWeights: (version, weight in 0..=1)
    icfg: Option<InvokeConfig>,
}

fn alias_json(n: &str, a: &str, al: &Alias) -> Value {
    let mut v = json!({"AliasArn": format!("{}:{a}", arn(n)), "Name": a, "FunctionVersion": al.ver, "Description": al.desc,
        "RevisionId": format!("{n}-{a}-{}", al.ver)});
    if let Some((v2, w)) = &al.weights {
        let mut m = serde_json::Map::new();
        m.insert(v2.clone(), json!(w));
        v["RoutingConfig"] = json!({"AdditionalVersionWeights": Value::Object(m)});
    }
    v
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
    let mut v = json!({"FunctionName": n, "FunctionArn": f.arn, "Runtime": f.runtime, "Role": f.role, "Handler": f.handler,
        "CodeSize": f.size, "CodeSha256": f.sha, "Description": f.description, "Timeout": f.timeout, "MemorySize": f.memory,
        "LastModified": f.modified, "Version": f.version, "PackageType": f.package, "State": "Active", "LastUpdateStatus": "Successful",
        "Environment": {"Variables": f.env}, "Architectures": ["x86_64"], "TracingConfig": {"Mode": "PassThrough"},
        "Layers": f.layers.iter().map(|(a, _, s)| json!({"Arn": a, "CodeSize": s})).collect::<Vec<_>>()});
    if f.package == "Image" {
        // runtime and handler live inside the image
        v.as_object_mut().unwrap().remove("Runtime");
        v.as_object_mut().unwrap().remove("Handler");
        v["CodeImageUri"] = f.image.clone().unwrap_or_default().into();
    }
    v
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
    pub cold: bool, // true when a process was started for this invocation
}

// A resident runtime process. Line protocol: one JSON request per line on stdin,
// one JSON result line on fd 1; function logs go to stderr. {"ready":1} marks init done.
pub struct WarmProc {
    pub child: tokio::process::Child,
    pub stdin: tokio::process::ChildStdin,
    pub res: mpsc::Receiver<String>,
    pub since: Instant, // last idle since
}

// Idle processes exit after 5 minutes (swept on invoke and by the reaper in main.rs).
const WARM_IDLE: Duration = Duration::from_secs(300);

pub fn sweep_warm(w: &mut std::collections::HashMap<String, Vec<WarmProc>>) {
    for v in w.values_mut() {
        v.retain(|p| p.since.elapsed() < WARM_IDLE);
    }
    w.retain(|_, v| !v.is_empty());
}

// One resident RIE container ("docker run -d") answering POST /2015-03-31/functions/function/invocations.
pub struct ImgWarm {
    pub cid: String,
    pub port: u16,
    pub seen: usize, // log lines already handed to earlier invocations
    pub since: Instant,
}

impl Drop for ImgWarm {
    fn drop(&mut self) {
        let _ = std::process::Command::new(docker_cli()).args(["rm", "-f", &self.cid]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
    }
}

pub fn sweep_img(w: &mut std::collections::HashMap<String, Vec<ImgWarm>>) {
    for v in w.values_mut() {
        v.retain(|p| p.since.elapsed() < WARM_IDLE);
    }
    w.retain(|_, v| !v.is_empty());
}

// Drop every pool entry (processes and containers) belonging to a function name.
fn forget(lam: &mut Lambda, name: &str) {
    let prefix = format!("{name}|");
    {
        let mut w = lam.warm.lock().unwrap();
        w.retain(|k, _| !k.starts_with(&prefix));
    }
    let mut i = lam.img.lock().unwrap();
    i.retain(|k, _| !k.starts_with(&prefix));
}

fn docker_cli() -> String {
    std::env::var("RC_DOCKER").unwrap_or_else(|_| "docker".into())
}

async fn pipe_lines<R: tokio::io::AsyncRead + Unpin + Send + 'static>(r: R, tx: mpsc::Sender<String>) {
    let mut br = tokio::io::BufReader::new(r);
    let mut line = String::new();
    loop {
        line.clear();
        match br.read_line(&mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if tx.send(line.trim_end_matches(['\r', '\n']).to_string()).await.is_err() {
                    break;
                }
            }
        }
    }
}

// Warm variant: the handler module is imported once and kept; each invocation is one JSON
// request line on stdin answered by one JSON result line on fd 1 (function prints go to stderr).
// The first comment line doubles as a pgrep marker for tests.
const PY_BOOT_WARM: &str = r#"
# rocalcloud-lambda-warm
import json, os, sys, time, traceback, importlib
sys.path.insert(0, os.getcwd())
_p = os.fdopen(1, "w", 1)
mod, fn = os.environ["_HANDLER"].rsplit(".", 1)
class _Cap:
    def __init__(self): self.buf = ""; self.lines = []
    def write(self, s):
        self.buf += str(s)
        if "\n" in self.buf:
            parts = self.buf.split("\n")
            self.buf = parts.pop()
            self.lines.extend(p for p in parts if p)
        return len(s)
    def flush(self): pass
_cap = _Cap()
sys.stdout = sys.stderr = _cap
class Context:
    function_name = os.environ["AWS_LAMBDA_FUNCTION_NAME"]
    function_version = os.environ.get("AWS_LAMBDA_FUNCTION_VERSION", "$LATEST")
    invoked_function_arn = os.environ["_RC_ARN"]
    memory_limit_in_mb = os.environ["AWS_LAMBDA_FUNCTION_MEMORY_SIZE"]
    log_group_name = "/aws/lambda/" + function_name
    def __init__(self, rid, deadline):
        self.aws_request_id = rid
        self._d = deadline
    def get_remaining_time_in_millis(self): return int(max(0, self._d - time.time()) * 1000)
try:
    _handler = getattr(importlib.import_module(mod), fn)
except Exception as e:
    traceback.print_exc()
    _p.write(json.dumps({"ok": False, "error": {"errorMessage": "module import failed: " + str(e), "errorType": "Runtime.ImportModuleError"}, "logs": _cap.lines}) + "\n")
    sys.exit(1)
_p.write('{"ready":1}\n')
while True:
    line = sys.stdin.readline()
    if not line: break
    try:
        req = json.loads(line)
    except Exception:
        break
    ctx = Context(req.get("rid", ""), req.get("deadline", time.time() + float(os.environ.get("_RC_TIMEOUT", "3"))))
    _cap = _Cap()
    sys.stdout = sys.stderr = _cap
    try:
        out = {"ok": True, "result": _handler(req.get("event"), ctx)}
    except Exception as e:
        traceback.print_exc()
        out = {"ok": False, "error": {"errorMessage": str(e), "errorType": type(e).__name__, "stackTrace": traceback.format_tb(e.__traceback__)}}
    out["logs"] = _cap.lines
    _p.write(json.dumps(out, default=str) + "\n")
"#;

const NODE_BOOT_WARM: &str = r#"
// rocalcloud-lambda-warm
const fs = require("fs"), path = require("path"), { pathToFileURL } = require("url");
const _w = (o) => fs.writeSync(1, JSON.stringify(o) + "\n");
let _logs = [];
let _buf = "";
const _cap = (...a) => {
  _buf += a.map(x => typeof x === "string" ? x : JSON.stringify(x)).join(" ");
  if (_buf.includes("\n")) { const parts = _buf.split("\n"); _buf = parts.pop(); for (const ln of parts) if (ln) _logs.push(ln); }
};
console.log = console.info = console.warn = console.error = console.debug = _cap;
process.stdout.write = (s) => { _cap(String(s)); return true; };
process.stderr.write = (s) => { _cap(String(s)); return true; };
const h = process.env._HANDLER, file = h.slice(0, h.lastIndexOf(".")), fn = h.slice(h.lastIndexOf(".") + 1);
(async () => {
  let handler = null;
  try {
    const ext = [".mjs", ".js", ".cjs"].find(e => fs.existsSync(path.resolve(file + e)));
    if (!ext) throw new Error(`Cannot find module '${file}'`);
    const m = await import(pathToFileURL(path.resolve(file + ext)).href);
    handler = m[fn] || (m.default && m.default[fn]);
    if (typeof handler !== "function") throw new Error(`${h} is undefined or not exported`);
  } catch (e) {
    _cap(e);
    _w({ ok: false, error: { errorMessage: String(e && e.message || e), errorType: "Runtime.ImportModuleError" }, logs: _logs });
    process.exit(1);
  }
  _w({ ready: 1 });
  const readline = require("readline");
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  let chain = Promise.resolve();
  rl.on("line", (line) => { chain = chain.then(() => (async () => {
    let req = {};
    try { req = JSON.parse(line); } catch (e) { process.exit(1); }
    const deadline = req.deadline ? req.deadline * 1000 : Date.now() + Number(process.env._RC_TIMEOUT) * 1000;
    const ctx = { functionName: process.env.AWS_LAMBDA_FUNCTION_NAME, functionVersion: process.env.AWS_LAMBDA_FUNCTION_VERSION || "$LATEST",
      invokedFunctionArn: process.env._RC_ARN, memoryLimitInMB: process.env.AWS_LAMBDA_FUNCTION_MEMORY_SIZE, awsRequestId: req.rid,
      getRemainingTimeInMillis: () => Math.max(0, deadline - Date.now()) };
    const logs = _logs; _logs = [];
    let out;
    try {
      const r = await new Promise((res, rej) => {
        const p = handler(req.event, ctx, (e, v) => (e ? rej(e) : res(v)));
        if (p && typeof p.then === "function") p.then(res, rej); else if (handler.length < 3) res(p);
      });
      out = { ok: true, result: r === undefined ? null : r };
    } catch (e) {
      _cap(e);
      out = { ok: false, error: { errorMessage: String(e && e.message || e), errorType: (e && e.name) || "Error", stackTrace: String(e && e.stack || "").split("\n") } };
    }
    out.logs = logs;
    _w(out);
  })()).catch(() => {}); });
  rl.on("close", () => process.exit(0));
})();
"#;

// Run one invocation: spawn the runtime, feed the event, collect result and logs (also written to CloudWatch Logs).
pub async fn invoke(app: &Arc<App>, id: &str, event: Value) -> Result<Invocation, ApiErr> {
    let (name, qual) = split_qualifier(id);
    let name = name.as_str();
    let f = app.lambda.lock().unwrap().resolve_weighted(name, qual.as_deref(), true)?;
    if f.package == "Image" {
        return invoke_image(app, &f, name, event).await;
    }
    let (exe, warm_boot) = if f.runtime.starts_with("python") {
        (std::env::var("RC_PYTHON").unwrap_or("python3".into()), PY_BOOT_WARM)
    } else if f.runtime.starts_with("nodejs") {
        (std::env::var("RC_NODE").unwrap_or("node".into()), NODE_BOOT_WARM)
    } else {
        return Err(err("InvalidRuntimeException", format!("Runtime {} is not supported locally (python*, nodejs* only)", f.runtime)));
    };
    let rid = uuid::Uuid::new_v4().to_string();
    // Code inside the function calls this emulator, signed as the execution role when it exists.
    let creds = app.iam.lock().unwrap().session_for_role(&f.role, name);
    let (akid, secret, token) = creds.unwrap_or(("test".into(), "test".into(), String::new()));

    let _slot = SLOTS.acquire().await.expect("semaphore closed");
    let t0 = Instant::now();
    // Later layers win, so they go first on the search path.
    let layer_path = std::env::join_paths(f.layers.iter().rev().flat_map(|(_, d, _)| {
        if f.runtime.starts_with("python") { vec![d.join("python"), d.join("python/lib").join(&f.runtime).join("site-packages")] } else { vec![d.join("nodejs/node_modules")] }
    })).unwrap_or_default();
    let path_var = if f.runtime.starts_with("python") { "PYTHONPATH" } else { "NODE_PATH" };
    // One warm process per function, version and code/config stamp; a change replaces it.
    let key = format!("{name}|{}|{}", f.version, f.modified);
    let pooled = {
        let lam = app.lambda.lock().unwrap();
        let mut w = lam.warm.lock().unwrap();
        sweep_warm(&mut w);
        w.get_mut(&key).and_then(|v| v.pop())
    };
    let (mut proc, mut cold) = match pooled {
        Some(p) => (p, false),
        None => (spawn_warm(&exe, warm_boot, &f, name, &layer_path, path_var, &akid, &secret, &token).await?, true),
    };
    let started = proc.since; // spawn time - elapsed at the {"ready":1} line is the init duration
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();
    let req = format!("{}\n", json!({"event": event, "rid": rid, "deadline": now + f.timeout as f64}));
    // A pooled process may have died meanwhile: write failure restarts it once.
    if proc.stdin.write_all(req.as_bytes()).await.is_err() || proc.stdin.flush().await.is_err() {
        proc = spawn_warm(&exe, warm_boot, &f, name, &layer_path, path_var, &akid, &secret, &token).await?;
        cold = true;
        proc.stdin.write_all(req.as_bytes()).await.map_err(|e| ApiErr { status: 500, ..err("ServiceException", format!("could not send to function process: {e}")) })?;
    }

    // One JSON result line per request ({"ready":1} lines from init are skipped).
    let mut init_ms = 0.0f64;
    let outcome: Value;
    let mut keep = false;
    match tokio::time::timeout(Duration::from_secs(f.timeout), async {
        loop {
            match proc.res.recv().await {
                None => break None,
                Some(l) if l.contains("\"ready\"") => {
                    init_ms = started.elapsed().as_secs_f64() * 1000.0;
                    continue;
                }
                Some(l) => break Some(l),
            }
        }
    })
    .await
    {
        Err(_) => {
            let _ = proc.child.kill().await;
            outcome = json!({"ok": false, "error": {"errorMessage": format!("Task timed out after {:.2} seconds", f.timeout as f64), "errorType": "Sandbox.Timedout"}});
        }
        Ok(None) => {
            let code = proc.child.wait().await.ok().and_then(|s| s.code());
            outcome = json!({"ok": false, "error": {"errorMessage": format!("Runtime exited with code {} before returning a result", code.map_or_else(|| "unknown".into(), |c| c.to_string())), "errorType": "Runtime.ExitError"}});
        }
        Ok(Some(l)) => {
            outcome = serde_json::from_str(&l).unwrap_or_else(|_| json!({"ok": false, "error": {"errorMessage": "unparsable result from function process", "errorType": "Runtime.Error"}}));
            keep = true;
        }
    }
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    if keep {
        proc.since = Instant::now();
        let lam = app.lambda.lock().unwrap();
        let mut w = lam.warm.lock().unwrap();
        sweep_warm(&mut w);
        w.entry(key).or_default().push(proc);
    }

    let mut log = outcome["logs"].as_array().into_iter().flatten().filter_map(|l| l.as_str().map(String::from)).collect::<Vec<_>>().join("\n");
    if outcome["ok"] != true {
        log += &format!("{}\n", outcome["error"]["errorMessage"].as_str().unwrap_or(""));
    }
    let init = if cold { format!("\tInit Duration: {init_ms:.2} ms") } else { String::new() };
    let lines = std::iter::once(format!("START RequestId: {rid} Version: {}", f.version))
        .chain(log.lines().map(String::from))
        .chain([format!("END RequestId: {rid}"),
                format!("REPORT RequestId: {rid}\tDuration: {ms:.2} ms\tBilled Duration: {} ms\tMemory Size: {} MB{init}", ms.ceil() as u64, f.memory)]);
    let now = now_ms();
    let stream = format!("{}/[{}]{}", chrono::Utc::now().format("%Y/%m/%d"), f.version, &rid[..8]);
    let entries: Vec<(i64, String)> = lines.map(|l| (now, l)).collect();
    let tail = entries.iter().map(|(_, l)| l.as_str()).collect::<Vec<_>>().join("\n");
    app.logs.lock().unwrap().put(&format!("/aws/lambda/{name}"), &stream, entries);
    Ok(match outcome["ok"].as_bool() {
        Some(true) => Invocation { payload: outcome["result"].clone(), error: None, log_tail: tail, version: f.version.clone(), cold },
        _ => Invocation { payload: outcome["error"].clone(), error: Some("Unhandled".into()), log_tail: tail, version: f.version.clone(), cold },
    })
}

// Start a resident runtime process with pipes for the line protocol (fd 1) and logs (stderr).
async fn spawn_warm(
    exe: &str,
    boot: &'static str,
    f: &Func,
    name: &str,
    layer_path: &std::ffi::OsString,
    path_var: &str,
    akid: &str,
    secret: &str,
    token: &str,
) -> Result<WarmProc, ApiErr> {
    let mut cmd = Command::new(exe);
    cmd.arg(if f.runtime.starts_with("python") { "-c" } else { "-e" }).arg(boot).current_dir(&f.dir)
        .env(path_var, layer_path)
        .envs(f.env.iter().filter_map(|(k, v)| Some((k, v.as_str()?))))
        .env("_HANDLER", &f.handler).env("_RC_TIMEOUT", f.timeout.to_string()).env("_RC_ARN", &f.arn)
        .env("AWS_LAMBDA_FUNCTION_NAME", name).env("AWS_LAMBDA_FUNCTION_MEMORY_SIZE", f.memory.to_string())
        .env("AWS_LAMBDA_FUNCTION_VERSION", &f.version).env("AWS_LAMBDA_LOG_GROUP_NAME", format!("/aws/lambda/{name}"))
        .env("AWS_REGION", REGION.as_str()).env("AWS_DEFAULT_REGION", REGION.as_str())
        .env("AWS_ENDPOINT_URL", crate::endpoint()).env("AWS_ACCESS_KEY_ID", akid).env("AWS_SECRET_ACCESS_KEY", secret)
        .env("AWS_SESSION_TOKEN", token).env("PYTHONUNBUFFERED", "1")
        .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let mut child = cmd.spawn().map_err(|e| ApiErr { status: 500, ..err("ServiceException", format!("could not start {exe}: {e}")) })?;
    let stdin = child.stdin.take().expect("piped stdin");
    let (res_tx, res_rx) = mpsc::channel(8);
    if let Some(out) = child.stdout.take() {
        tokio::spawn(pipe_lines(out, res_tx));
    }
    Ok(WarmProc { child, stdin, res: res_rx, since: Instant::now() })
}

// PackageType=Image: one resident RIE container per function+version+stamp, invoked over
// 127.0.0.1 POST /2015-03-31/functions/function/invocations. Images must exist locally.
// ponytail: boot time inside the invocation timeout; log tailing is docker logs - based.
async fn invoke_image(app: &Arc<App>, f: &Func, name: &str, event: Value) -> Result<Invocation, ApiErr> {
    let rid = uuid::Uuid::new_v4().to_string();
    let image = f.image.clone().ok_or_else(|| err("InvalidParameterValueException", "function has no image"))?;
    let creds = app.iam.lock().unwrap().session_for_role(&f.role, name);
    let (akid, secret, token) = creds.unwrap_or(("test".into(), "test".into(), String::new()));
    let _slot = SLOTS.acquire().await.expect("semaphore closed");
    let t0 = Instant::now();
    let key = format!("{name}|{}|{}", f.version, f.modified);
    let pooled = {
        let lam = app.lambda.lock().unwrap();
        let mut w = lam.img.lock().unwrap();
        sweep_img(&mut w);
        w.get_mut(&key).and_then(|v| v.pop())
    };
    let (mut cw, cold) = match pooled {
        Some(c) => (c, false),
        None => (start_image(f, name, &image, &akid, &secret, &token, &rid).await?, true),
    };

    // The RIE needs a moment to boot: retry connection failures until the invocation deadline.
    let deadline = t0 + Duration::from_secs(f.timeout.max(3));
    let body = event.to_string();
    let mut resp: Option<(u16, Vec<(String, String)>, Vec<u8>)> = None;
    let mut boot_err = String::new();
    while resp.is_none() {
        let r = tokio::time::timeout_at(deadline.into(), rie_post(cw.port, &body)).await;
        match r {
            Err(_) => break,
            Ok(Err(e)) => {
                boot_err = e;
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            Ok(Ok(r)) => resp = Some(r),
        }
    }
    let init_ms = if cold { t0.elapsed().as_secs_f64() * 1000.0 } else { 0.0 };
    let (outcome, keep): (Value, bool) = match resp {
        None => {
            // timeout, or the container never answered
            let reason = if t0.elapsed() >= Duration::from_secs(f.timeout) {
                format!("Task timed out after {:.2} seconds", f.timeout as f64)
            } else {
                format!("container did not answer on port {}: {boot_err}", cw.port)
            };
            let _ = tokio::process::Command::new(docker_cli()).args(["rm", "-f", &cw.cid]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().await;
            (json!({"ok": false, "error": {"errorMessage": reason, "errorType": if t0.elapsed() >= Duration::from_secs(f.timeout) { "Sandbox.Timedout" } else { "Runtime.ContainerError" }}}), false)
        }
        Some((status, headers, body)) => {
            let err_type = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("lambda-runtime-function-error-type")).map(|(_, v)| v.clone());
            let payload: Value = serde_json::from_slice(&body)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).into()));
            if status != 200 {
                (json!({"ok": false, "error": {"errorMessage": format!("container answered {status}"), "errorType": "Runtime.ContainerError"}}), true)
            } else if let Some(e) = err_type.filter(|e| !e.is_empty()) {
                (json!({"ok": false, "error": payload, "containerError": e}), true)
            } else {
                (json!({"ok": true, "result": payload}), true)
            }
        }
    };

    // Function logs are the container stdout (docker logs), tailed past what earlier invocations took.
    let mut log = String::new();
    if let Ok(o) = tokio::process::Command::new(docker_cli()).args(["logs", &cw.cid]).output().await {
        let text = String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr);
        let lines: Vec<&str> = text.lines().collect();
        if cw.seen < lines.len() {
            log = lines[cw.seen..].join("\n");
        }
        cw.seen = lines.len();
    }
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    if keep {
        cw.since = Instant::now();
        let lam = app.lambda.lock().unwrap();
        let mut w = lam.img.lock().unwrap();
        sweep_img(&mut w);
        w.entry(key).or_default().push(cw);
    }

    if outcome["ok"] != true {
        log += &format!("{}\n", outcome["error"]["errorMessage"].as_str().unwrap_or(""));
    }
    let init = if cold { format!("\tInit Duration: {init_ms:.2} ms") } else { String::new() };
    let lines = std::iter::once(format!("START RequestId: {rid} Version: {}", f.version))
        .chain(log.lines().map(String::from))
        .chain([format!("END RequestId: {rid}"),
                format!("REPORT RequestId: {rid}\tDuration: {ms:.2} ms\tBilled Duration: {} ms\tMemory Size: {} MB{init}", ms.ceil() as u64, f.memory)]);
    let now = now_ms();
    let stream = format!("{}/[{}]{}", chrono::Utc::now().format("%Y/%m/%d"), f.version, &rid[..8]);
    let entries: Vec<(i64, String)> = lines.map(|l| (now, l)).collect();
    let tail = entries.iter().map(|(_, l)| l.as_str()).collect::<Vec<_>>().join("\n");
    app.logs.lock().unwrap().put(&format!("/aws/lambda/{name}"), &stream, entries);
    Ok(match outcome["ok"].as_bool() {
        Some(true) => Invocation { payload: outcome["result"].clone(), error: None, log_tail: tail, version: f.version.clone(), cold },
        _ => Invocation { payload: outcome["error"].clone(), error: Some("Unhandled".into()), log_tail: tail, version: f.version.clone(), cold },
    })
}

// docker run -d the image on a free loopback port, with the function env and role credentials.
async fn start_image(f: &Func, name: &str, image: &str, akid: &str, secret: &str, token: &str, rid: &str) -> Result<ImgWarm, ApiErr> {
    let port = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await
        .and_then(|l| l.local_addr())
        .map_err(|e| err("ServiceException", format!("no free port for the function container: {e}")))?
        .port();
    let cname = format!("rc-lambda-{}", &rid[..8]);
    // Containers reach the emulator at host.docker.internal (BIND=0.0.0.0 to allow it).
    let emu_port = crate::endpoint().rsplit(':').next().unwrap_or("4566").to_string();
    // docker run [OPTIONS] IMAGE: every flag must come before the image, or it becomes the container command.
    let mut cmd = tokio::process::Command::new(docker_cli());
    cmd.args(["run", "-d", "--rm", "--name", &cname, "-p", &format!("127.0.0.1:{port}:8080"),
              "--memory", &format!("{}m", f.memory), "--add-host", "host.docker.internal:host-gateway"]);
    for (k, v) in f.env.iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))) {
        cmd.args(["-e", &format!("{k}={v}")]);
    }
    for (k, v) in [
        ("AWS_REGION", REGION.as_str().to_string()),
        ("AWS_DEFAULT_REGION", REGION.as_str().to_string()),
        ("AWS_ENDPOINT_URL", format!("http://host.docker.internal:{emu_port}")),
        ("AWS_ACCESS_KEY_ID", akid.to_string()),
        ("AWS_SECRET_ACCESS_KEY", secret.to_string()),
        ("AWS_SESSION_TOKEN", token.to_string()),
        ("AWS_LAMBDA_FUNCTION_NAME", name.to_string()),
        ("AWS_LAMBDA_FUNCTION_VERSION", f.version.clone()),
        ("AWS_LAMBDA_FUNCTION_MEMORY_SIZE", f.memory.to_string()),
        ("AWS_LAMBDA_LOG_GROUP_NAME", format!("/aws/lambda/{name}")),
    ] {
        cmd.args(["-e", &format!("{k}={v}")]);
    }
    cmd.arg(image);
    cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let out = cmd.output().await.map_err(|e| err("ServiceException", format!("docker run failed: {e}")))?;
    if !out.status.success() {
        return Err(err("InvalidParameterValueException", format!("could not start image {image}: {}", String::from_utf8_lossy(&out.stderr))));
    }
    let cid = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok(ImgWarm { cid, port, seen: 0, since: Instant::now() })
}

// Minimal HTTP/1.1 POST to the RIE (Connection: close, chunked bodies decoded).
async fn rie_post(port: u16, body: &str) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    use tokio::io::AsyncReadExt;
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.map_err(|e| e.to_string())?;
    let req = format!("POST /2015-03-31/functions/function/invocations HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    s.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&raw).to_string();
    let mut parts = text.split("\r\n\r\n");
    let head = parts.next().ok_or("empty response")?;
    let rest: Vec<&str> = parts.collect();
    let mut hl = head.lines();
    let status: u16 = hl.next().and_then(|l| l.split_whitespace().nth(1)).and_then(|c| c.parse().ok()).ok_or("no status")?;
    let headers: Vec<(String, String)> = hl.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
    let chunked = headers.iter().any(|(k, v)| k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked"));
    let body_bytes = if chunked {
        let mut out = Vec::new();
        for seg in rest {
            let mut rem = seg;
            loop {
                let (sz, tail) = rem.split_once("\r\n").ok_or("bad chunk")?;
                let n = usize::from_str_radix(sz.trim().split(';').next().unwrap_or("0"), 16).map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                let (data, t2) = tail.split_at_checked(n).ok_or("short chunk")?;
                out.extend_from_slice(data.as_bytes());
                rem = t2.strip_prefix("\r\n").unwrap_or(t2);
            }
        }
        out
    } else {
        rest.join("\r\n\r\n").into_bytes()
    };
    Ok((status, headers, body_bytes))
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
        ("GET", ["layers"]) => "ListLayers", // also GetLayerVersionByArn (?find=LayerVersion&Arn=)
        ("POST", ["layers", _, "versions"]) => "PublishLayerVersion",
        ("GET", ["layers", _, "versions"]) => "ListLayerVersions",
        ("GET", ["layers", _, "versions", _]) => "GetLayerVersion",
        ("DELETE", ["layers", _, "versions", _]) => "DeleteLayerVersion",
        ("POST", ["layers", _, "versions", _, "policy"]) => "AddLayerVersionPermission",
        ("GET", ["layers", _, "versions", _, "policy"]) => "GetLayerVersionPolicy",
        ("DELETE", ["layers", _, "versions", _, "policy", _]) => "RemoveLayerVersionPermission",
        _ => "Unsupported",
    }
}
// Function resource policy, consulted by the authorizer.
impl Lambda {
    // The function a qualifier selects: $LATEST (none), a version number, or an alias.
    fn resolve(&self, name: &str, qual: Option<&str>) -> Result<Func, ApiErr> {
        self.resolve_weighted(name, qual, false)
    }

    // invoke() resolves aliases with their AdditionalVersionWeights; other reads stay deterministic.
    fn resolve_weighted(&self, name: &str, qual: Option<&str>, route: bool) -> Result<Func, ApiErr> {
        let f = self.f.get(name).ok_or_else(|| not_found(name))?;
        let missing = |q: &str| ApiErr { status: 404, ..err("ResourceNotFoundException", format!("Function not found: {}:{q}", arn(name))) };
        let q = match qual {
            None | Some("$LATEST") => return Ok(f.clone()),
            Some(q) => q,
        };
        let mut ver = if q.bytes().all(|b| b.is_ascii_digit()) {
            q.to_string()
        } else {
            f.aliases.get(q).ok_or_else(|| missing(q))?.ver.clone()
        };
        if let Some((v2, w)) = f.aliases.get(q).and_then(|a| a.weights.as_ref()) {
            if route && rand::random::<f64>() < *w {
                ver = v2.clone();
            }
        }
        if ver == "$LATEST" {
            return Ok(f.clone());
        }
        ver.parse::<usize>().ok().and_then(|n| f.versions.get(n.wrapping_sub(1))).cloned().ok_or_else(|| missing(q))
    }

    fn icfg_read(f: &Func, qk: &str) -> InvokeConfig {
        if qk == "$LATEST" {
            f.icfg.clone()
        } else if qk.bytes().all(|b| b.is_ascii_digit()) {
            qk.parse::<usize>().ok().and_then(|n| f.versions.get(n.wrapping_sub(1))).map(|v| v.icfg.clone()).unwrap_or_default()
        } else {
            f.aliases.get(qk).and_then(|a| a.icfg.clone()).unwrap_or_else(|| f.icfg.clone())
        }
    }

    fn icfg_write(f: &mut Func, qk: &str, c: InvokeConfig) {
        if qk == "$LATEST" {
            f.icfg = c;
        } else if qk.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(n) = qk.parse::<usize>() {
                if let Some(v) = f.versions.get_mut(n.wrapping_sub(1)) {
                    v.icfg = c;
                }
            }
        } else if let Some(a) = f.aliases.get_mut(qk) {
            a.icfg = Some(c);
        }
    }

    // The async invoke config for a qualifier: an alias keeps its own (or inherits $LATEST),
    // a version snapshot keeps the config frozen into it, no qualifier = $LATEST.
    fn icfg_of(&self, name: &str, qual: Option<&str>) -> InvokeConfig {
        let Some(f) = self.f.get(name) else { return InvokeConfig::default() };
        match qual {
            None | Some("$LATEST") => f.icfg.clone(),
            Some(q) if !q.bytes().all(|b| b.is_ascii_digit()) => {
                f.aliases.get(q).and_then(|a| a.icfg.clone()).unwrap_or_else(|| f.icfg.clone())
            }
            Some(q) => q.parse::<usize>().ok().and_then(|n| f.versions.get(n.wrapping_sub(1))).map(|v| v.icfg.clone()).unwrap_or_default(),
        }
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
                let icfg = app.lambda.lock().unwrap().icfg_of(&name, qual.as_deref());
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
                let mut r = Response::builder().status(200).header("content-type", "application/json").header("x-amz-executed-version", &inv.version)
                    .header("x-rc-cold-start", if inv.cold { "true" } else { "false" });
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
                let (dir, size, sha, image, package) = if j["PackageType"].as_str() == Some("Image") {
                    // Images must already exist in local Docker: no ECR emulation, no pull.
                    if j["Code"]["ZipFile"].is_string() || j.get("Layers").is_some_and(|l| l.as_array().is_some_and(|a| !a.is_empty())) {
                        return Err(err("InvalidParameterValueException", "ZipFile and Layers cannot be used with PackageType=Image"));
                    }
                    let uri = j["Code"]["ImageUri"].as_str().filter(|s| !s.is_empty()).ok_or_else(|| err("InvalidParameterValueException", "Code.ImageUri is required for PackageType=Image"))?;
                    let out = std::process::Command::new(docker_cli()).args(["image", "inspect", uri]).output().map_err(|e| err("ServiceException", format!("docker unavailable: {e}")))?;
                    if !out.status.success() {
                        return Err(err("InvalidParameterValueException", format!("Image {uri} does not exist in local Docker (no ECR emulation or pull)")));
                    }
                    (std::env::temp_dir(), 0, uri.to_string(), Some(uri.into()), "Image".into())
                } else if j["Code"]["ImageUri"].is_string() {
                    return Err(err("InvalidParameterValueException", "ImageUri requires PackageType=Image"));
                } else {
                    let zip = j["Code"]["ZipFile"].as_str().ok_or_else(|| err("InvalidParameterValueException", "Code.ZipFile is required (S3 code is not supported)"))?;
                    let (dir, size, sha) = unpack(&n, zip)?;
                    (dir, size, sha, None, "Zip".into())
                };
                let f = Func {
                    arn: arn(&n), package, image, runtime: j["Runtime"].as_str().unwrap_or("").into(), role: j["Role"].as_str().unwrap_or("").into(), handler: j["Handler"].as_str().unwrap_or("").into(),
                    timeout: j["Timeout"].as_u64().unwrap_or(3), memory: j["MemorySize"].as_u64().unwrap_or(128),
                    env: j["Environment"]["Variables"].as_object().cloned().unwrap_or_default(),
                    description: j["Description"].as_str().unwrap_or("").into(), dir, size, sha, modified: modified_now(), perms: vec![],
                    version: "$LATEST".into(), versions: vec![], aliases: BTreeMap::new(), icfg: InvokeConfig::default(),
                    layers: if j["PackageType"].as_str() == Some("Image") { vec![] } else { st.layer_refs(&j["Layers"])? },
                };
                if f.package == "Zip" && (f.runtime.is_empty() || f.handler.is_empty()) {
                    return Err(err("InvalidParameterValueException", "Runtime and Handler are required for Zip functions"));
                }
                let out = config(&n, &f);
                st.f.insert(n, f);
                (201, out)
            }
            "ListFunctions" => (200, json!({"Functions": st.f.iter().map(|(n, f)| config(n, f)).collect::<Vec<_>>()})),
            "GetFunction" => {
                let f = st.resolve(&name, qual.as_deref())?;
                let code = if f.package == "Image" {
                    json!({"RepositoryType": "ECR", "ImageUri": f.image.clone().unwrap_or_default()})
                } else {
                    json!({"RepositoryType": "S3", "Location": format!("file://{}", f.dir.display())})
                };
                (200, json!({"Configuration": config(&name, &f), "Code": code}))
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
                let ver = j["FunctionVersion"].as_str().map(String::from).or(cur.as_ref().map(|c| c.ver.clone())).ok_or_else(|| err("ValidationException", "FunctionVersion is required"))?;
                if ver != "$LATEST" && !ver.parse::<usize>().is_ok_and(|n| n >= 1 && n <= f.versions.len()) {
                    return Err(ApiErr { status: 404, ..err("ResourceNotFoundException", format!("Function not found: {}:{ver}", arn(&name))) });
                }
                // AdditionalVersionWeights: one extra version with a weight in 0..=1.
                let mut weights = cur.as_ref().and_then(|c| c.weights.clone());
                if let Some(rc) = j["RoutingConfig"].as_object() {
                    if let Some(w) = rc["AdditionalVersionWeights"].as_object() {
                        let kv: Vec<(String, f64)> = w.iter().filter_map(|(k, v)| v.as_f64().map(|f| (k.clone(), f))).collect();
                        let (v2, weight) = match kv.as_slice() {
                            [(v2, w)] if *w > 0.0 => (v2.clone(), *w),
                            [_] => return Err(err("InvalidParameterValueException", "The routing config weight must be greater than 0.0")),
                            _ => return Err(err("InvalidParameterValueException", "AdditionalVersionWeights must reference exactly one additional version")),
                        };
                        if !(0.0..=1.0).contains(&weight) {
                            return Err(err("InvalidParameterValueException", format!("The routing config weight {weight} is invalid: 0.0 to 1.0 only")));
                        }
                        if v2 == ver {
                            return Err(err("InvalidParameterValueException", "The routing config additional version must differ from the alias version"));
                        }
                        if v2 != "$LATEST" && !v2.parse::<usize>().is_ok_and(|n| n >= 1 && n <= f.versions.len()) {
                            return Err(ApiErr { status: 404, ..err("ResourceNotFoundException", format!("Function not found: {}:{v2}", arn(&name))) });
                        }
                        weights = Some((v2, weight));
                    }
                }
                let desc = j["Description"].as_str().map(String::from).or_else(|| cur.as_ref().map(|c| c.desc.clone())).unwrap_or_default();
                let icfg = cur.as_ref().and_then(|c| c.icfg.clone());
                f.aliases.insert(a.clone(), Alias { ver, desc, weights, icfg });
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
                forget(&mut *st, &name);
                (204, Value::Null)
            }
            "UpdateFunctionCode" => {
                let f = st.f.get_mut(&name).ok_or_else(|| not_found(&name))?;
                if f.package == "Image" {
                    let uri = j["ImageUri"].as_str().filter(|s| !s.is_empty())
                        .ok_or_else(|| err("InvalidParameterValueException", "ImageUri is required for image functions"))?;
                    let out = std::process::Command::new(docker_cli()).args(["image", "inspect", uri]).output().map_err(|e| err("ServiceException", format!("docker unavailable: {e}")))?;
                    if !out.status.success() {
                        return Err(err("InvalidParameterValueException", format!("Image {uri} does not exist in local Docker")));
                    }
                    f.image = Some(uri.into());
                    f.sha = uri.into();
                    f.modified = modified_now();
                } else if j["ImageUri"].is_string() {
                    return Err(err("InvalidParameterValueException", "ImageUri requires a function created with PackageType=Image"));
                } else {
                    let zip = j["ZipFile"].as_str().ok_or_else(|| err("InvalidParameterValueException", "ZipFile is required"))?;
                    let (dir, size, sha) = unpack(&name, zip)?;
                    (f.dir, f.size, f.sha, f.modified) = (dir, size, sha, modified_now());
                }
                let out = config(&name, f);
                forget(&mut *st, &name);
                (200, out)
            }
            "UpdateFunctionConfiguration" => {
                let layers = if j.get("Layers").is_some() { Some(st.layer_refs(&j["Layers"])?) } else { None };
                let f = st.f.get_mut(&name).ok_or_else(|| not_found(&name))?;
                if let Some(l) = layers {
                    f.layers = l;
                }
                for (k, v) in j.as_object().into_iter().flatten() {
                    match k.as_str() {
                        "Runtime" => f.runtime = v.as_str().unwrap_or(&f.runtime).into(),
                        "Role" => f.role = v.as_str().unwrap_or(&f.role).into(),
                        "Handler" => f.handler = v.as_str().unwrap_or(&f.handler).into(),
                        "Timeout" => f.timeout = v.as_u64().unwrap_or(f.timeout),
                        "MemorySize" => f.memory = v.as_u64().unwrap_or(f.memory),
                        "Description" => f.description = v.as_str().unwrap_or("").into(),
                        "Environment" => f.env = v["Variables"].as_object().cloned().unwrap_or_default(),
                        "Layers" => {} // resolved below, outside this borrow
                        _ => {}
                    }
                }
                f.modified = modified_now();
                let out = config(&name, f);
                forget(&mut *st, &name);
                (200, out)
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
                // Stored per qualifier: $LATEST on the function, an alias on the alias, a version on its snapshot.
                let f = st.f.get_mut(&name).ok_or_else(|| not_found(&name))?;
                let qk = q.get("Qualifier").cloned().or_else(|| j["Qualifier"].as_str().map(String::from)).unwrap_or_else(|| "$LATEST".into());
                if qk != "$LATEST" && !qk.bytes().all(|b| b.is_ascii_digit()) && !f.aliases.contains_key(&qk) {
                    return Err(ApiErr { status: 404, ..err("ResourceNotFoundException", format!("Function not found: {}:{qk}", arn(&name))) });
                }
                let mut c = if op == "PutFunctionEventInvokeConfig" { InvokeConfig::default() } else { Lambda::icfg_read(f, &qk) };
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
                Lambda::icfg_write(f, &qk, c.clone());
                (200, icfg_json(&name, &c))
            }
            "GetFunctionEventInvokeConfig" => {
                let f = st.f.get(&name).ok_or_else(|| not_found(&name))?;
                let qk = q.get("Qualifier").cloned().or_else(|| j["Qualifier"].as_str().map(String::from)).unwrap_or_else(|| "$LATEST".into());
                (200, icfg_json(&name, &Lambda::icfg_read(f, &qk)))
            }
            "DeleteFunctionEventInvokeConfig" => {
                let f = st.f.get_mut(&name).ok_or_else(|| not_found(&name))?;
                let qk = q.get("Qualifier").cloned().or_else(|| j["Qualifier"].as_str().map(String::from)).unwrap_or_else(|| "$LATEST".into());
                Lambda::icfg_write(f, &qk, InvokeConfig::default());
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
            "PublishLayerVersion" => {
                let n = seg(1);
                if n.is_empty() || n.len() > 64 || !n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                    return Err(err("ValidationException", format!("Layer name {n} is not valid ([a-zA-Z0-9-_]{{1,64}})")));
                }
                let zip = j["Content"]["ZipFile"].as_str().ok_or_else(|| err("InvalidParameterValueException", "Content.ZipFile is required (S3 layer content is not supported locally)"))?;
                let (dir, size, sha) = unpack(&format!("layer-{n}"), zip)?;
                let arr = |k: &str| j[k].as_array().cloned().unwrap_or_default();
                let l = LayerVer { dir, size, sha, desc: j["Description"].as_str().unwrap_or("").into(), license: j["LicenseInfo"].as_str().unwrap_or("").into(),
                                   runtimes: arr("CompatibleRuntimes"), archs: arr("CompatibleArchitectures"), created: modified_now(), perms: vec![] };
                let vs = st.layers.entry(n.clone()).or_default();
                vs.push(Some(l));
                (201, layer_json(&n, vs.len(), vs.last().unwrap().as_ref().unwrap()))
            }
            "ListLayers" if q.get("find").is_some_and(|f| f == "LayerVersion") => {
                let a = q.get("Arn").cloned().unwrap_or_default();
                let (n, v) = parse_layer_arn(&a).ok_or_else(|| err("ValidationException", format!("{a} is not a layer version ARN")))?;
                (200, layer_json(&n, v, st.layer_ver(&n, v)?))
            }
            "ListLayers" | "ListLayerVersions" => {
                let rt = q.get("CompatibleRuntime");
                let fits = |l: &LayerVer| rt.is_none_or(|r| l.runtimes.iter().any(|x| x == r.as_str()));
                // Newest first, like AWS.
                if op == "ListLayers" {
                    let list: Vec<Value> = st.layers.iter().filter_map(|(n, vs)| {
                        let (v, l) = vs.iter().enumerate().rev().find_map(|(i, l)| l.as_ref().filter(|l| fits(l)).map(|l| (i + 1, l)))?;
                        Some(json!({"LayerName": n, "LayerArn": layer_arn(n), "LatestMatchingVersion": layer_json(n, v, l)}))
                    }).collect();
                    (200, json!({"Layers": list}))
                } else {
                    let n = seg(1);
                    let vs = st.layers.get(&n).cloned().unwrap_or_default();
                    let list: Vec<Value> = vs.iter().enumerate().rev().filter_map(|(i, l)| l.as_ref().filter(|l| fits(l)).map(|l| layer_json(&n, i + 1, l))).collect();
                    (200, json!({"LayerVersions": list}))
                }
            }
            "GetLayerVersion" => {
                let (n, v) = (seg(1), seg(3).parse().unwrap_or(0));
                (200, layer_json(&n, v, st.layer_ver(&n, v)?))
            }
            "DeleteLayerVersion" => {
                // Idempotent like AWS; functions already using the version keep their unpacked copy.
                let (n, v) = (seg(1), seg(3).parse::<usize>().unwrap_or(0));
                if let Some(slot) = st.layers.get_mut(&n).and_then(|vs| vs.get_mut(v.wrapping_sub(1))) {
                    *slot = None;
                }
                (204, Value::Null)
            }
            "AddLayerVersionPermission" | "GetLayerVersionPolicy" | "RemoveLayerVersionPermission" => {
                let (n, v) = (seg(1), seg(3).parse::<usize>().unwrap_or(0));
                st.layer_ver(&n, v)?;
                let l = st.layers.get_mut(&n).and_then(|vs| vs.get_mut(v - 1)).and_then(|s| s.as_mut()).unwrap();
                let varn = format!("{}:{v}", layer_arn(&n));
                match op {
                    "AddLayerVersionPermission" => {
                        let sid = crate::need(&j, "StatementId")?.to_string();
                        let action = crate::need(&j, "Action")?;
                        let who = crate::need(&j, "Principal")?;
                        if !matches!(action, "lambda:GetLayerVersion" | "lambda:ListLayerVersions") {
                            return Err(err("InvalidParameterValueException", "Action must be lambda:GetLayerVersion or lambda:ListLayerVersions"));
                        }
                        // ponytail: one local account, so only this account or "*" can be granted.
                        let principal = match who {
                            "*" => json!("*"),
                            w if w == ACCOUNT || w == format!("arn:aws:iam::{ACCOUNT}:root") => json!({"AWS": format!("arn:aws:iam::{ACCOUNT}:root")}),
                            w => return Err(err("InvalidParameterValueException", format!("Principal {w} is not this account (only {ACCOUNT} or * locally)"))),
                        };
                        if l.perms.iter().any(|s| s["Sid"] == sid.as_str()) {
                            return Err(ApiErr { status: 409, ..err("ResourceConflictException", format!("The statement id ({sid}) provided already exists.")) });
                        }
                        let s = json!({"Sid": sid, "Effect": "Allow", "Principal": principal, "Action": action, "Resource": varn});
                        l.perms.push(s.clone());
                        (201, json!({"Statement": s.to_string(), "RevisionId": uuid::Uuid::new_v4().to_string()}))
                    }
                    "GetLayerVersionPolicy" => {
                        if l.perms.is_empty() {
                            return Err(ApiErr { status: 404, ..err("ResourceNotFoundException", "No policy is associated with the given resource.") });
                        }
                        (200, json!({"Policy": json!({"Version": "2012-10-17", "Id": "default", "Statement": l.perms}).to_string(), "RevisionId": uuid::Uuid::new_v4().to_string()}))
                    }
                    _ => {
                        let sid = seg(5);
                        let before = l.perms.len();
                        l.perms.retain(|s| s["Sid"] != sid.as_str());
                        if l.perms.len() == before {
                            return Err(ApiErr { status: 404, ..err("ResourceNotFoundException", format!("Statement {sid} is not found in resource policy.")) });
                        }
                        (204, Value::Null)
                    }
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
    fn layer_ver(&self, n: &str, v: usize) -> Result<&LayerVer, ApiErr> {
        self.layers.get(n).and_then(|vs| vs.get(v.wrapping_sub(1))).and_then(|l| l.as_ref())
            .ok_or_else(|| ApiErr { status: 404, ..err("ResourceNotFoundException", format!("Layer version {}:{v} does not exist.", layer_arn(n))) })
    }
    // A function's Layers list → (arn, dir, size). At most 5, each an existing version, one version per layer.
    fn layer_refs(&self, v: &Value) -> Result<Vec<(String, PathBuf, usize)>, ApiErr> {
        let bad = |m: String| err("InvalidParameterValueException", m);
        let arns: Vec<&str> = v.as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect()).unwrap_or_default();
        if arns.len() > 5 {
            return Err(bad("Cannot reference more than 5 layers.".into()));
        }
        let mut seen = std::collections::HashSet::new();
        arns.iter().map(|a| {
            let (n, ver) = parse_layer_arn(a).ok_or_else(|| bad(format!("{a} is not a layer version ARN")))?;
            if !seen.insert(n.clone()) {
                return Err(bad(format!("Two different versions of the same layer are not allowed: {n}")));
            }
            let l = self.layer_ver(&n, ver).map_err(|_| bad(format!("Layer version {a} does not exist.")))?;
            Ok((a.to_string(), l.dir.clone(), l.size))
        }).collect()
    }

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
                rows.extend(f.layers.iter().map(|(a, _, s)| json!(["레이어", a, format!("{s} B")])));
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
    fn layer_arns_and_resources() {
        assert_eq!(parse_layer_arn("arn:aws:lambda:us-east-1:000000000000:layer:libs:3"), Some(("libs".into(), 3)));
        assert_eq!(parse_layer_arn("arn:aws:lambda:us-east-1:000000000000:layer:libs"), None);
        assert_eq!(parse_layer_arn("arn:aws:lambda:us-east-1:000000000000:function:f:3"), None);
        assert!(layer_resource("layers/libs/versions/2/policy").unwrap().ends_with(":layer:libs:2"));
        assert!(layer_resource("layers/libs/versions").unwrap().ends_with(":layer:libs"));
        assert_eq!(layer_resource("functions/f"), None);
        let mut st = Lambda::default();
        st.layers.insert("libs".into(), vec![None, Some(LayerVer { dir: "/tmp/x".into(), size: 1, sha: String::new(), desc: String::new(), license: String::new(),
            runtimes: vec![], archs: vec![], created: String::new(), perms: vec![] })]);
        let a = |v: u32| json!(format!("arn:aws:lambda:us-east-1:000000000000:layer:libs:{v}"));
        assert_eq!(st.layer_refs(&json!([a(2)])).unwrap().len(), 1);
        assert!(st.layer_refs(&json!([a(1)])).is_err(), "deleted version");
        assert!(st.layer_refs(&json!([a(2), a(2)])).is_err(), "same layer twice");
        assert!(st.layer_refs(&Value::Array(vec![a(2); 6])).is_err(), "more than five");
    }

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

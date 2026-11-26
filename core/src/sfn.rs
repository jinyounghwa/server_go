// Step Functions (JSON 1.0) with an Amazon States Language interpreter.
// Parallel branches and Map items run concurrently (Map honours MaxConcurrency).
// A failing branch or item stops the rest. JSONPath supports $.a.b[0], [*], [-1], ['key'], and $$ context paths;
// filter expressions ?(...) are rejected. Task states honour TimeoutSeconds (default 60s) and heartbeats,
// and .waitForTaskToken integrations pause until SendTaskSuccess/Failure (see Sfn.waiting). ponytail: no JSONata, no
// Express sync starts, waiting task tokens are memory-only and lost on restart.
use crate::{b64, epoch, err, need, unb64, ApiErr, App, ACCOUNT, REGION};
use md5::Md5;
use rand::Rng;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::{collections::{BTreeMap, BTreeSet}, future::Future, pin::Pin, sync::Arc, time::Duration};

struct Machine {
    name: String,
    def: String,
    role: String,
    ty: String,
    created: f64,
}
struct Exec {
    machine: String,
    name: String,
    status: &'static str,
    start: f64,
    stop: Option<f64>,
    input: Value,
    output: Option<Value>,
    error: Option<(String, String)>,
    history: Vec<Value>,
}

#[derive(Default)]
pub struct Sfn {
    machines: BTreeMap<String, Machine>,
    execs: BTreeMap<String, Exec>,
    // Task tokens paused at a .waitForTaskToken integration. ponytail: memory only,
    // a restart forgets them (the paired executions fail with States.Timeout at their deadline).
    waiting: BTreeMap<String, Wait>,
    // Tokens already resolved/timed out, so late SendTask* gets TaskTimedOut. Capped at 4096.
    done: BTreeSet<String>,
}

enum TaskOutcome {
    Ok(Value),
    Err(String, String),
}

struct Wait {
    exec: String,
    deadline: i64,                 // epoch ms
    hb_interval: Option<u64>,      // HeartbeatSeconds in ms
    heartbeat: Option<i64>,        // next heartbeat deadline, epoch ms
    tx: tokio::sync::mpsc::UnboundedSender<TaskOutcome>,
}

type Fail = (String, String); // (error, cause)
fn fail(e: &str, c: impl Into<String>) -> Fail {
    (e.to_string(), c.into())
}

fn machine_arn(n: &str) -> String {
    format!("arn:aws:states:{}:{ACCOUNT}:stateMachine:{n}", *REGION)
}
fn not_found(kind: &str, a: &str) -> ApiErr {
    err(&format!("{kind}DoesNotExist"), format!("{kind} Does Not Exist: '{a}'"))
}

// ---------- JSONPath / templates ----------

#[derive(Debug)]
enum Seg {
    Key(String),
    Idx(isize),
    Wild,
}

fn parse_jpath(path: &str) -> Result<Vec<Seg>, Fail> {
    let rest = path.strip_prefix('$').ok_or_else(|| fail("States.Runtime", format!("Invalid JSONPath '{path}'")))?;
    let mut segs = Vec::new();
    let b = rest.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'.' => {
                i += 1;
                if i < b.len() && b[i] == b'.' {
                    return Err(fail("States.Runtime", format!("Recursive descent '..' is not supported in '{path}'")));
                }
                let start = i;
                while i < b.len() && b[i] != b'.' && b[i] != b'[' {
                    i += 1;
                }
                if i == start {
                    return Err(fail("States.Runtime", format!("Empty segment in JSONPath '{path}'")));
                }
                let key = &rest[start..i];
                if key == "*" {
                    segs.push(Seg::Wild);
                } else {
                    segs.push(Seg::Key(key.to_string()));
                }
            }
            b'[' => {
                i += 1;
                if i >= b.len() {
                    return Err(fail("States.Runtime", format!("Unclosed '[' in JSONPath '{path}'")));
                }
                if rest[i..].starts_with("?(") {
                    return Err(fail("States.Runtime", format!("JSONPath filter expressions ?(...) are not supported: '{path}'")));
                }
                if b[i] == b'\'' || b[i] == b'"' {
                    let q = b[i];
                    i += 1;
                    let mut key = String::new();
                    while i < b.len() && b[i] != q {
                        if b[i] == b'\\' && i + 1 < b.len() {
                            i += 1;
                        }
                        key.push(b[i] as char);
                        i += 1;
                    }
                    if i >= b.len() || b[i] != q || i + 1 >= b.len() || b[i + 1] != b']' {
                        return Err(fail("States.Runtime", format!("Malformed quoted key in JSONPath '{path}'")));
                    }
                    i += 2;
                    segs.push(Seg::Key(key));
                } else {
                    let start = i;
                    while i < b.len() && b[i] != b']' {
                        i += 1;
                    }
                    if i >= b.len() {
                        return Err(fail("States.Runtime", format!("Unclosed '[' in JSONPath '{path}'")));
                    }
                    let inner = rest[start..i].trim();
                    i += 1;
                    if inner == "*" {
                        segs.push(Seg::Wild);
                    } else if let Ok(idx) = inner.parse::<isize>() {
                        segs.push(Seg::Idx(idx));
                    } else {
                        return Err(fail("States.Runtime", format!("Unsupported bracket expression '[{inner}]' in '{path}'")));
                    }
                }
            }
            _ => return Err(fail("States.Runtime", format!("Invalid JSONPath '{path}'"))),
        }
    }
    Ok(segs)
}

fn eval_segs(v: &Value, segs: &[Seg]) -> Option<Value> {
    let Some((first, tail)) = segs.split_first() else {
        return Some(v.clone());
    };
    match first {
        Seg::Key(k) => eval_segs(v.get(k)?, tail),
        Seg::Idx(idx) => {
            let arr = v.as_array()?;
            let pos = if *idx < 0 { arr.len().checked_add_signed(*idx)? } else { *idx as usize };
            eval_segs(arr.get(pos)?, tail)
        }
        Seg::Wild => match v {
            Value::Array(arr) => Some(Value::Array(arr.iter().filter_map(|el| eval_segs(el, tail)).collect())),
            Value::Object(map) => Some(Value::Array(map.values().filter_map(|el| eval_segs(el, tail)).collect())),
            _ => None,
        },
    }
}

fn jget_res(v: &Value, path: &str) -> Result<Option<Value>, Fail> {
    if path == "$" {
        return Ok(Some(v.clone()));
    }
    let segs = parse_jpath(path)?;
    Ok(eval_segs(v, &segs))
}

pub fn jget(v: &Value, path: &str) -> Option<Value> {
    jget_res(v, path).ok().flatten()
}

fn jget_ctx_res(input: &Value, ctx: &Value, path: &str) -> Result<Option<Value>, Fail> {
    if let Some(rest) = path.strip_prefix("$$") {
        jget_res(ctx, &format!("${rest}"))
    } else {
        jget_res(input, path)
    }
}

fn jset(mut target: Value, path: &str, val: Value) -> Value {
    let Some(p) = path.strip_prefix("$.") else { return val };
    let keys: Vec<&str> = p.split('.').collect();
    if !target.is_object() {
        target = json!({});
    }
    let mut cur = &mut target;
    for k in &keys[..keys.len() - 1] {
        if !cur[*k].is_object() {
            cur[*k] = json!({});
        }
        cur = &mut cur[*k];
    }
    cur[keys[keys.len() - 1]] = val;
    target
}

// Split intrinsic arguments on commas outside quotes, parentheses, and brackets.
fn args(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut quoted, mut esc, mut depth) = (vec![], String::new(), false, false, 0i32);
    for c in s.chars() {
        if esc {
            cur.push(c);
            esc = false;
            continue;
        }
        match c {
            '\\' if quoted => {
                cur.push(c);
                esc = true;
                continue;
            }
            '\'' => quoted = !quoted,
            '(' | '[' if !quoted => depth += 1,
            ')' | ']' if !quoted => depth -= 1,
            ',' if !quoted && depth == 0 => {
                out.push(cur.trim().to_string());
                cur.clear();
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

fn value_of(expr: &str, input: &Value, ctx: &Value) -> Result<Value, Fail> {
    let e = expr.trim();
    if let Some(s) = e.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        return Ok(Value::String(s.replace("\\'", "'")));
    }
    if let Some(rest) = e.strip_prefix("$$") {
        return jget_res(ctx, &format!("${rest}"))?.ok_or_else(|| fail("States.Runtime", format!("Context path {e} not found")));
    }
    if e.starts_with('$') {
        return jget_res(input, e)?.ok_or_else(|| fail("States.Runtime", format!("The JSONPath '{e}' could not be found in the input")));
    }
    if e.starts_with("States.") {
        return intrinsic(e, input, ctx);
    }
    serde_json::from_str(e).map_err(|_| fail("States.Runtime", format!("Invalid argument {e}")))
}

fn merge_obj(a: &Map<String, Value>, b: &Map<String, Value>, deep: bool) -> Map<String, Value> {
    let mut out = a.clone();
    for (k, v) in b {
        if deep {
            if let (Some(Value::Object(oa)), Value::Object(ob)) = (out.get(k), v) {
                out.insert(k.clone(), Value::Object(merge_obj(oa, ob, true)));
                continue;
            }
        }
        out.insert(k.clone(), v.clone());
    }
    out
}

fn as_i64(v: Option<&Value>, label: &str) -> Result<i64, Fail> {
    let v = v.ok_or_else(|| fail("States.Runtime", format!("Missing integer argument: {label}")))?;
    v.as_i64()
        .or_else(|| v.as_f64().map(|f| f.round() as i64))
        .ok_or_else(|| fail("States.Runtime", format!("Expected integer for {label}")))
}

fn as_arr<'a>(v: Option<&'a Value>, name: &str) -> Result<&'a Vec<Value>, Fail> {
    v.and_then(Value::as_array).ok_or_else(|| fail("States.Runtime", format!("{name} requires an array argument")))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ponytail: States.Hash supports MD5, SHA-256, SHA-384, SHA-512 (no SHA-1 crate); other algorithms return States.Runtime.
fn intrinsic(e: &str, input: &Value, ctx: &Value) -> Result<Value, Fail> {
    let (name, rest) = e.split_once('(').ok_or_else(|| fail("States.Runtime", format!("Bad intrinsic {e}")))?;
    let a: Vec<Value> = args(rest.strip_suffix(')').unwrap_or(rest)).iter().map(|x| value_of(x, input, ctx)).collect::<Result<_, _>>()?;
    let text = |v: &Value| v.as_str().map_or(v.to_string(), String::from);
    Ok(match name {
        "States.Format" => {
            let tpl = a.first().map(text).unwrap_or_default();
            let mut parts = tpl.split("{}");
            let mut out = parts.next().unwrap_or("").to_string();
            for (p, v) in parts.zip(a.iter().skip(1)) {
                out += &text(v);
                out += p;
            }
            Value::String(out)
        }
        "States.StringToJson" => serde_json::from_str(&a.first().map(text).unwrap_or_default()).map_err(|e| fail("States.Runtime", e.to_string()))?,
        "States.JsonToString" => Value::String(a.first().cloned().unwrap_or_default().to_string()),
        "States.Array" => Value::Array(a),
        "States.ArrayPartition" => {
            let arr = as_arr(a.first(), name)?;
            let sz = as_i64(a.get(1), "chunkSize")?;
            if sz <= 0 {
                return Err(fail("States.Runtime", "States.ArrayPartition chunkSize must be a positive integer"));
            }
            Value::Array(arr.chunks(sz as usize).map(|c| Value::Array(c.to_vec())).collect())
        }
        "States.ArrayContains" => {
            let arr = as_arr(a.first(), name)?;
            let needle = a.get(1).ok_or_else(|| fail("States.Runtime", "States.ArrayContains requires 2 arguments"))?;
            Value::Bool(arr.iter().any(|x| x == needle))
        }
        "States.ArrayRange" => {
            let (start, end, step) = (as_i64(a.first(), "start")?, as_i64(a.get(1), "end")?, as_i64(a.get(2), "step")?);
            if step == 0 {
                return Err(fail("States.Runtime", "States.ArrayRange step must not be 0"));
            }
            let mut out = Vec::new();
            let mut cur = start;
            while (step > 0 && cur <= end) || (step < 0 && cur >= end) {
                if out.len() >= 1000 {
                    return Err(fail("States.Runtime", "States.ArrayRange exceeds 1000 elements"));
                }
                out.push(json!(cur));
                cur = match cur.checked_add(step) { Some(n) => n, None => break };
            }
            Value::Array(out)
        }
        "States.ArrayGetItem" => {
            let arr = as_arr(a.first(), name)?;
            let idx = as_i64(a.get(1), "index")?;
            if idx < 0 || (idx as usize) >= arr.len() {
                return Err(fail("States.Runtime", format!("States.ArrayGetItem index {idx} out of range")));
            }
            arr[idx as usize].clone()
        }
        "States.ArrayLength" => json!(as_arr(a.first(), name)?.len()),
        "States.ArrayUnique" => {
            let arr = as_arr(a.first(), name)?;
            let mut out = Vec::new();
            for item in arr {
                if !out.contains(item) {
                    out.push(item.clone());
                }
            }
            Value::Array(out)
        }
        "States.Base64Encode" => {
            let s = a.first().and_then(Value::as_str).ok_or_else(|| fail("States.Runtime", "States.Base64Encode requires a string"))?;
            Value::String(b64(s.as_bytes()))
        }
        "States.Base64Decode" => {
            let s = a.first().and_then(Value::as_str).ok_or_else(|| fail("States.Runtime", "States.Base64Decode requires a string"))?;
            let bytes = unb64(s).ok_or_else(|| fail("States.Runtime", "States.Base64Decode invalid base64"))?;
            Value::String(String::from_utf8(bytes).map_err(|e| fail("States.Runtime", format!("States.Base64Decode invalid UTF-8: {e}")))?)
        }
        "States.Hash" => {
            let data = a.first().and_then(Value::as_str).ok_or_else(|| fail("States.Runtime", "States.Hash data must be a string"))?;
            let algo = a.get(1).and_then(Value::as_str).ok_or_else(|| fail("States.Runtime", "States.Hash algorithm must be a string"))?;
            let digest = match algo {
                "MD5" => hex_lower(&Md5::digest(data.as_bytes())),
                "SHA-256" => hex_lower(&Sha256::digest(data.as_bytes())),
                "SHA-384" => hex_lower(&Sha384::digest(data.as_bytes())),
                "SHA-512" => hex_lower(&Sha512::digest(data.as_bytes())),
                _ => return Err(fail("States.Runtime", format!("Unsupported hash algorithm {algo}"))),
            };
            Value::String(digest)
        }
        "States.StringSplit" => {
            let s = a.first().and_then(Value::as_str).ok_or_else(|| fail("States.Runtime", "States.StringSplit requires a string"))?;
            let delim = a.get(1).and_then(Value::as_str).ok_or_else(|| fail("States.Runtime", "States.StringSplit requires a delimiter string"))?;
            let parts: Vec<Value> = if delim.is_empty() {
                s.split_whitespace().map(|p| Value::String(p.into())).collect()
            } else {
                s.split(|c: char| delim.contains(c)).filter(|p| !p.is_empty()).map(|p| Value::String(p.into())).collect()
            };
            Value::Array(parts)
        }
        "States.JsonMerge" => {
            let o1 = a.first().and_then(Value::as_object).ok_or_else(|| fail("States.Runtime", "States.JsonMerge first argument must be an object"))?;
            let o2 = a.get(1).and_then(Value::as_object).ok_or_else(|| fail("States.Runtime", "States.JsonMerge second argument must be an object"))?;
            let deep = a.get(2).and_then(Value::as_bool).ok_or_else(|| fail("States.Runtime", "States.JsonMerge third argument must be a boolean"))?;
            Value::Object(merge_obj(o1, o2, deep))
        }
        "States.MathRandom" => {
            let (start, end) = (as_i64(a.first(), "start")?, as_i64(a.get(1), "end")?);
            if start >= end {
                return Err(fail("States.Runtime", "States.MathRandom start must be less than end"));
            }
            let span = (end - start) as u64;
            let n = if let Some(seed) = a.get(2) {
                let s = as_i64(Some(seed), "seed")? as u64;
                // Deterministic LCG step when an explicit seed is supplied.
                let mixed = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407) >> 17;
                start + (mixed % span) as i64
            } else {
                rand::thread_rng().gen_range(start..end)
            };
            json!(n)
        }
        "States.UUID" => Value::String(uuid::Uuid::new_v4().to_string()),
        "States.MathAdd" => {
            let sum: f64 = a.iter().filter_map(Value::as_f64).sum();
            if sum.fract() == 0.0 && a.iter().all(|v| v.is_i64()) { json!(sum as i64) } else { json!(sum) }
        }
        _ => return Err(fail("States.Runtime", format!("Unsupported intrinsic {name}"))),
    })
}

// Parameters / ResultSelector / ItemSelector: "key.$" fields are paths or intrinsics.
fn template(t: &Value, input: &Value, ctx: &Value) -> Result<Value, Fail> {
    Ok(match t {
        Value::Object(m) => {
            let mut out = Map::new();
            for (k, v) in m {
                match k.strip_suffix(".$") {
                    Some(k2) => out.insert(k2.into(), value_of(v.as_str().unwrap_or(""), input, ctx)?),
                    None => out.insert(k.clone(), template(v, input, ctx)?),
                };
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(|x| template(x, input, ctx)).collect::<Result<_, _>>()?),
        other => other.clone(),
    })
}

fn path_or(v: &Value, ctx: &Value, p: &Value) -> Result<Value, Fail> {
    match p {
        Value::Null => Ok(json!({})), // explicit null discards
        Value::String(s) => jget_ctx_res(v, ctx, s)?.ok_or_else(|| fail("States.Runtime", format!("Invalid path '{s}'"))),
        _ => Ok(v.clone()),
    }
}

// ---------- Choice ----------

fn choice_ok(rule: &Value, input: &Value, ctx: &Value) -> bool {
    if let Some(a) = rule["And"].as_array() {
        return a.iter().all(|r| choice_ok(r, input, ctx));
    }
    if let Some(a) = rule["Or"].as_array() {
        return a.iter().any(|r| choice_ok(r, input, ctx));
    }
    if rule.get("Not").is_some() {
        return !choice_ok(&rule["Not"], input, ctx);
    }
    let var = rule["Variable"].as_str().and_then(|p| jget_ctx_res(input, ctx, p).ok().flatten());
    rule.as_object().into_iter().flatten().filter(|(k, _)| *k != "Variable" && *k != "Next").all(|(k, want)| {
        let (op, want) = match k.strip_suffix("Path") {
            Some(op) if k != "IsPresent" => (op, want.as_str().and_then(|p| jget_ctx_res(input, ctx, p).ok().flatten()).unwrap_or(Value::Null)),
            _ => (k.as_str(), want.clone()),
        };
        match op {
            "IsPresent" => want.as_bool() == Some(var.is_some()),
            "IsNull" => want.as_bool() == Some(var == Some(Value::Null)),
            "IsNumeric" => want.as_bool() == Some(var.as_ref().is_some_and(Value::is_number)),
            "IsString" => want.as_bool() == Some(var.as_ref().is_some_and(Value::is_string)),
            "IsBoolean" => want.as_bool() == Some(var.as_ref().is_some_and(Value::is_boolean)),
            "BooleanEquals" => var.as_ref().and_then(Value::as_bool).is_some_and(|b| Some(b) == want.as_bool()),
            "StringMatches" => matches!((var.as_ref().and_then(Value::as_str), want.as_str()), (Some(v), Some(w)) if crate::iam::glob(w, v, false)),
            _ => {
                let ord = if op.starts_with("Numeric") {
                    var.as_ref().and_then(Value::as_f64).zip(want.as_f64()).and_then(|(a, b)| a.partial_cmp(&b))
                } else {
                    var.as_ref().and_then(Value::as_str).zip(want.as_str()).map(|(a, b)| a.cmp(b))
                };
                let Some(o) = ord else { return false };
                use std::cmp::Ordering::*;
                match op.trim_start_matches("Numeric").trim_start_matches("String").trim_start_matches("Timestamp") {
                    "Equals" => o == Equal,
                    "LessThan" => o == Less,
                    "GreaterThan" => o == Greater,
                    "LessThanEquals" => o != Greater,
                    "GreaterThanEquals" => o != Less,
                    _ => false,
                }
            }
        }
    })
}

fn error_matches(list: &Value, e: &str) -> bool {
    crate::iam::strs(list).iter().any(|x| x == "States.ALL" || x == e || (x == "States.TaskFailed" && !e.starts_with("States.")))
}

// ---------- tasks ----------

// Pause the execution until SendTaskSuccess/Failure resolves the token, a heartbeat is missed or TimeoutSeconds passes.
async fn wait_task(app: &Arc<App>, exec: &str, state: &str, token: &str, st: &Value) -> Result<Value, Fail> {
    let timeout_ms = st["TimeoutSeconds"].as_u64().unwrap_or(60).clamp(1, u64::MAX / 2) * 1000;
    let hb_interval = st["HeartbeatSeconds"].as_u64().filter(|s| *s > 0).map(|s| s * 1000);
    let deadline = crate::now_ms() + timeout_ms as i64;
    let heartbeat = hb_interval.map(|h| crate::now_ms() + h as i64);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    app.sfn.lock().unwrap().waiting.insert(token.to_string(), Wait { exec: exec.into(), deadline, hb_interval, heartbeat, tx });
    loop {
        let wake = {
            let s = app.sfn.lock().unwrap();
            let Some(w) = s.waiting.get(token) else { return Err(fail("States.Timeout", "task token was resolved while waiting")) };
            w.heartbeat.unwrap_or(w.deadline).min(w.deadline)
        };
        let sleep_ms = (wake - crate::now_ms()).max(1) as u64;
        tokio::select! {
            out = rx.recv() => {
                let _ = app.sfn.lock().unwrap().waiting.remove(token);
                return match out {
                    Some(TaskOutcome::Ok(v)) => Ok(v),
                    Some(TaskOutcome::Err(e, c)) => Err((e, c)),
                    None => Err(fail("States.Timeout", format!("State {state} timed out"))),
                };
            }
            _ = tokio::time::sleep(Duration::from_millis(sleep_ms)) => {
                let n = crate::now_ms();
                let mut s = app.sfn.lock().unwrap();
                let Some(w) = s.waiting.get(token) else { return Err(fail("States.Timeout", "task token was resolved while waiting")) };
                if w.heartbeat.is_some_and(|h| n >= h) || n >= w.deadline {
                    s.waiting.remove(token);
                    s.done.insert(token.to_string());
                    return Err(fail("States.Timeout", format!("State {state} timed out: no task token activity within its limit")));
                }
                // else: the heartbeat deadline was pushed forward by SendTaskHeartbeat while we slept.
            }
        }
    }
}

async fn task(app: &Arc<App>, resource: &str, p: Value) -> Result<Value, Fail> {
    if resource.starts_with("arn:aws:lambda:") {
        return invoke(app, &crate::lambda::name_of(resource), p).await;
    }
    let svc = resource.strip_prefix("arn:aws:states:::").unwrap_or(resource);
    let svc = svc.split(".sync").next().unwrap_or(svc);
    let text = |v: &Value| v.as_str().map_or(v.to_string(), String::from);
    match svc {
        "lambda:invoke" => {
            let payload = invoke(app, &crate::lambda::name_of(p["FunctionName"].as_str().unwrap_or("")), p["Payload"].clone()).await?;
            Ok(json!({"Payload": payload, "StatusCode": 200, "ExecutedVersion": "$LATEST"}))
        }
        "sqs:sendMessage" => {
            let q = p["QueueUrl"].as_str().unwrap_or("").rsplit('/').next().unwrap_or("").to_string();
            if !app.sqs.lock().unwrap().deliver(&q, text(&p["MessageBody"]), &p["MessageAttributes"], None, None) {
                return Err(fail("SQS.QueueDoesNotExist", format!("Queue {q} does not exist")));
            }
            Ok(json!({"MessageId": uuid::Uuid::new_v4().to_string()}))
        }
        "sns:publish" => {
            crate::send_to_target(app, "states", p["TopicArn"].as_str().unwrap_or(""), Value::String(text(&p["Message"])), "states", "");
            Ok(json!({"MessageId": uuid::Uuid::new_v4().to_string()}))
        }
        s if s.starts_with("dynamodb:") => {
            let mut op = s["dynamodb:".len()..].to_string();
            op[..1].make_ascii_uppercase();
            crate::ddb::handle(app, &op, p.to_string().as_bytes()).map_err(|e| fail(&format!("DynamoDB.{}", e.code), e.msg))
        }
        _ => Err(fail("States.Runtime", format!("Resource {resource} is not supported locally"))),
    }
}

async fn invoke(app: &Arc<App>, name: &str, payload: Value) -> Result<Value, Fail> {
    match crate::lambda::invoke(app, name, payload).await {
        Err(e) => Err(fail(&format!("Lambda.{}", e.code), e.msg)),
        Ok(i) if i.error.is_some() => Err(fail(i.payload["errorType"].as_str().unwrap_or("Error"), i.payload.to_string())),
        Ok(i) => Ok(i.payload),
    }
}

// ---------- interpreter ----------

fn record(app: &App, exec: &str, ty: &str, details: Value) {
    let mut s = app.sfn.lock().unwrap();
    if let Some(x) = s.execs.get_mut(exec) {
        let id = x.history.len() as u64 + 1;
        let key = if ty.ends_with("StateEntered") {
            "stateEnteredEventDetails".to_string()
        } else if ty.ends_with("StateExited") {
            "stateExitedEventDetails".to_string()
        } else {
            format!("{}{}EventDetails", ty[..1].to_lowercase(), &ty[1..])
        };
        x.history.push(json!({"timestamp": epoch(), "type": ty, "id": id, "previousEventId": id - 1, key: details}));
    }
}
fn stopped(app: &App, exec: &str) -> bool {
    app.sfn.lock().unwrap().execs.get(exec).is_none_or(|x| x.status == "ABORTED")
}

type Run<'a> = Pin<Box<dyn Future<Output = Result<Value, Fail>> + Send + 'a>>;

fn run_states<'a>(app: &'a Arc<App>, exec: &'a str, def: &'a Value, input: Value, ctx: Value) -> Run<'a> {
    Box::pin(async move {
        let mut cur = def["StartAt"].as_str().ok_or_else(|| fail("States.Runtime", "StartAt is missing"))?.to_string();
        let mut data = input;
        let mut attempts: BTreeMap<usize, u32> = BTreeMap::new();
        loop {
            if stopped(app, exec) {
                return Err(fail("States.Aborted", "Execution was stopped"));
            }
            let st = def["States"].get(&cur).ok_or_else(|| fail("States.Runtime", format!("State {cur} does not exist")))?;
            let ty = st["Type"].as_str().unwrap_or("");
            let mut sctx = ctx.clone();
            sctx["State"] = json!({"Name": cur, "EnteredTime": chrono::Utc::now().to_rfc3339()});
            if attempts.is_empty() {
                record(app, exec, &format!("{ty}StateEntered"), json!({"name": cur, "input": data.to_string()}));
                crate::emit(app, json!({"ts": chrono::Utc::now().to_rfc3339(), "service": "states", "op": "StateEntered", "target": cur, "type": ty, "status": 200,
                                        "execution": exec.rsplit(':').next()}));
            }
            let eff = path_or(&data, &sctx, st.get("InputPath").unwrap_or(&json!("$")))?;
            let params = |v: &Value| st.get("Parameters").map_or(Ok(v.clone()), |p| template(p, v, &sctx));

            if ty == "Choice" {
                let next = st["Choices"].as_array().into_iter().flatten().find(|c| choice_ok(c, &eff, &sctx)).and_then(|c| c["Next"].as_str())
                    .or(st["Default"].as_str()).ok_or_else(|| fail("States.NoChoiceMatched", format!("No Choices matched in state {cur}")))?;
                data = path_or(&eff, &sctx, st.get("OutputPath").unwrap_or(&json!("$")))?;
                record(app, exec, "ChoiceStateExited", json!({"name": cur, "output": data.to_string()}));
                (cur, attempts) = (next.to_string(), BTreeMap::new());
                continue;
            }
            let result: Result<Value, Fail> = match ty {
                "Pass" => match st.get("Result") { Some(r) => Ok(r.clone()), None => params(&eff) },
                "Succeed" => return path_or(&eff, &sctx, st.get("OutputPath").unwrap_or(&json!("$"))),
                "Fail" => return Err(fail(st["Error"].as_str().unwrap_or("States.Fail"), st["Cause"].as_str().unwrap_or(""))),
                "Wait" => {
                    let ts = st["Timestamp"].as_str().map(String::from)
                        .or_else(|| st["TimestampPath"].as_str().and_then(|p| jget(&eff, p)).and_then(|v| v.as_str().map(String::from)));
                    let secs = st["Seconds"].as_f64()
                        .or_else(|| st["SecondsPath"].as_str().and_then(|p| jget(&eff, p)).and_then(|v| v.as_f64()))
                        .or_else(|| ts.and_then(|t| chrono::DateTime::parse_from_rfc3339(&t).ok()).map(|t| (t.timestamp_millis() - crate::now_ms()) as f64 / 1000.0))
                        .unwrap_or(0.0);
                    tokio::time::sleep(Duration::from_secs_f64(secs.max(0.0))).await;
                    Ok(eff.clone())
                }
                "Task" => {
                    let res = st["Resource"].as_str().unwrap_or("");
                    let wtt = res.strip_suffix(".waitForTaskToken");
                    let resource = wtt.unwrap_or(res);
                    // The token is exposed to Parameters as $$.Task.Token (AWS) and $.Task.Token (locally too).
                    let mut eff2 = eff.clone();
                    let mut sctx2 = sctx.clone();
                    let mut token = String::new();
                    if wtt.is_some() {
                        token = uuid::Uuid::new_v4().simple().to_string();
                        eff2["Task"] = json!({"Token": token.clone()});
                        sctx2["Task"] = json!({"Token": token.clone()});
                    }
                    let p = match st.get("Parameters") {
                        Some(pp) => template(pp, &eff2, &sctx2)?,
                        None => eff2,
                    };
                    if wtt.is_some() {
                        let _sent = task(app, resource, p).await?;
                        wait_task(app, exec, &cur, &token, st).await
                    } else {
                        // TimeoutSeconds applies to plain tasks too (AWS default: 60s).
                        let secs = st["TimeoutSeconds"].as_u64().unwrap_or(60).max(1);
                        match tokio::time::timeout(Duration::from_secs(secs), task(app, resource, p)).await {
                            Ok(r) => r,
                            Err(_) => Err(fail("States.Timeout", format!("State {cur} timed out after {secs}s"))),
                        }
                    }
                }
                "Parallel" => match params(&eff) {
                    // Branches run concurrently; the first branch to fail stops the others (their futures are dropped).
                    Ok(p) => {
                        let runs = st["Branches"].as_array().into_iter().flatten().map(|b| run_states(app, exec, b, p.clone(), ctx.clone()));
                        futures_util::future::try_join_all(runs).await.map(Value::Array)
                    }
                    Err(e) => Err(e),
                },
                "Map" => {
                    let items_res = match st["ItemsPath"].as_str() {
                        Some(p) => jget_ctx_res(&eff, &sctx, p),
                        None => Ok(Some(eff.clone())),
                    };
                    let proc_def = st.get("ItemProcessor").or(st.get("Iterator")).cloned().unwrap_or_default();
                    match items_res {
                        Err(e) => Err(e),
                        Ok(items) => match items.as_ref().and_then(Value::as_array) {
                            None => Err(fail("States.Runtime", "Map ItemsPath did not select an array")),
                            Some(items) => {
                                let sel = st.get("ItemSelector").or(st.get("Parameters"));
                                let inputs: Result<Vec<(Value, Value)>, Fail> = items.iter().enumerate().map(|(i, item)| {
                                    let mut mctx = sctx.clone();
                                    mctx["Map"] = json!({"Item": {"Index": i, "Value": item}});
                                    let v = sel.map_or(Ok(item.clone()), |s| template(s, &eff, &mctx))?;
                                    Ok((v, mctx))
                                }).collect();
                                match inputs {
                                    Err(e) => Err(e),
                                    // Items run concurrently up to MaxConcurrency (0 or absent = no limit); results keep item order.
                                    Ok(inputs) => {
                                        let limit = st["MaxConcurrency"].as_u64().filter(|n| *n > 0).map_or(inputs.len().max(1), |n| n as usize);
                                        let runs = inputs.into_iter().map(|(v, mctx)| run_states(app, exec, &proc_def, v, mctx));
                                        use futures_util::{StreamExt, TryStreamExt};
                                        // A failing item stops the Map: remaining items are not started and running ones are dropped.
                                        futures_util::stream::iter(runs).buffered(limit).try_collect::<Vec<_>>().await.map(Value::Array)
                                    }
                                }
                            }
                        },
                    }
                }
                other => Err(fail("States.Runtime", format!("Unsupported state type {other}"))),
            };
            match result {
                Ok(r) => {
                    let r = match st.get("ResultSelector") { Some(s) => template(s, &r, &sctx)?, None => r };
                    data = match st.get("ResultPath") {
                        Some(Value::Null) => data,
                        Some(Value::String(p)) => jset(data, p, r),
                        _ => r,
                    };
                    data = path_or(&data, &sctx, st.get("OutputPath").unwrap_or(&json!("$")))?;
                    record(app, exec, &format!("{ty}StateExited"), json!({"name": cur, "output": data.to_string()}));
                    if st["End"] == true {
                        return Ok(data);
                    }
                    cur = st["Next"].as_str().ok_or_else(|| fail("States.Runtime", format!("State {cur} has no Next or End")))?.to_string();
                    attempts.clear();
                }
                Err((e, cause)) => {
                    // Retry with backoff, then Catch, then fail the execution.
                    let retry = st["Retry"].as_array().into_iter().flatten().enumerate().find(|(_, r)| error_matches(&r["ErrorEquals"], &e));
                    if let Some((i, r)) = retry {
                        let n = attempts.entry(i).or_insert(0);
                        if *n < r["MaxAttempts"].as_u64().unwrap_or(3) as u32 {
                            let wait = r["IntervalSeconds"].as_f64().unwrap_or(1.0) * r["BackoffRate"].as_f64().unwrap_or(2.0).powi(*n as i32);
                            *n += 1;
                            record(app, exec, "TaskRetry", json!({"name": cur, "error": e, "attempt": *n}));
                            tokio::time::sleep(Duration::from_secs_f64(wait)).await;
                            continue;
                        }
                    }
                    let Some(c) = st["Catch"].as_array().into_iter().flatten().find(|c| error_matches(&c["ErrorEquals"], &e)) else {
                        return Err((e, cause));
                    };
                    let info = json!({"Error": e, "Cause": cause});
                    data = match c.get("ResultPath") {
                        Some(Value::Null) => data,
                        Some(Value::String(p)) => jset(data, p, info),
                        _ => info,
                    };
                    record(app, exec, &format!("{ty}StateExited"), json!({"name": cur, "output": data.to_string(), "caught": e}));
                    cur = c["Next"].as_str().unwrap_or("").to_string();
                    attempts.clear();
                }
            }
        }
    })
}

// Run an execution to completion in the background.
pub async fn run(app: Arc<App>, exec: String) {
    let (def, input, ctx) = {
        let s = app.sfn.lock().unwrap();
        let x = &s.execs[&exec];
        let m = &s.machines[&x.machine];
        let def: Value = serde_json::from_str(&m.def).unwrap_or_default();
        let ctx = json!({"Execution": {"Id": exec, "Name": x.name, "Input": x.input, "StartTime": chrono::Utc::now().to_rfc3339()},
                         "StateMachine": {"Id": x.machine, "Name": m.name}});
        (def, x.input.clone(), ctx)
    };
    let out = run_states(&app, &exec, &def, input, ctx).await;
    let (ty, details) = match &out {
        Ok(v) => ("ExecutionSucceeded", json!({"output": v.to_string()})),
        Err((e, c)) => ("ExecutionFailed", json!({"error": e, "cause": c})),
    };
    record(&app, &exec, ty, details);
    let status = {
        let mut s = app.sfn.lock().unwrap();
        let Some(x) = s.execs.get_mut(&exec) else { return };
        if x.status == "RUNNING" {
            x.status = if out.is_ok() { "SUCCEEDED" } else { "FAILED" };
            x.stop = Some(epoch());
            match out {
                Ok(v) => x.output = Some(v),
                Err(e) => x.error = Some(e),
            }
        }
        x.status
    };
    crate::emit(&app, json!({"ts": chrono::Utc::now().to_rfc3339(), "service": "states", "op": "ExecutionFinished",
        "target": exec.rsplit(':').next(), "status": if status == "SUCCEEDED" { 200 } else { 500 }, "result": status}));
}

impl Sfn {
    fn exec_json(arn: &str, x: &Exec) -> Value {
        let mut v = json!({"executionArn": arn, "stateMachineArn": x.machine, "name": x.name, "status": x.status,
                           "startDate": x.start, "input": x.input.to_string()});
        if let Some(t) = x.stop {
            v["stopDate"] = t.into();
        }
        if let Some(o) = &x.output {
            v["output"] = o.to_string().into();
        }
        if let Some((e, c)) = &x.error {
            (v["error"], v["cause"]) = (e.clone().into(), c.clone().into());
        }
        v
    }

    // Returns the response and, for StartExecution, the execution to run.
    pub fn handle(&mut self, op: &str, r: &Value) -> Result<(Value, Option<String>), ApiErr> {
        let v = match op {
            "CreateStateMachine" => {
                let n = need(r, "name")?;
                let def = need(r, "definition")?;
                let parsed: Value = serde_json::from_str(def).map_err(|e| err("InvalidDefinition", format!("Invalid State Machine Definition: {e}")))?;
                if parsed["StartAt"].as_str().is_none_or(|s| parsed["States"].get(s).is_none()) {
                    return Err(err("InvalidDefinition", "Invalid State Machine Definition: StartAt must name a state in States"));
                }
                let arn = machine_arn(n);
                if self.machines.get(&arn).is_some_and(|m| m.def != def) {
                    return Err(err("StateMachineAlreadyExists", format!("State Machine Already Exists: '{arn}'")));
                }
                let created = epoch();
                self.machines.entry(arn.clone()).or_insert(Machine { name: n.into(), def: def.into(), role: r["roleArn"].as_str().unwrap_or("").into(),
                    ty: r["type"].as_str().unwrap_or("STANDARD").into(), created });
                json!({"stateMachineArn": arn, "creationDate": self.machines[&arn].created})
            }
            "DescribeStateMachine" => {
                let a = need(r, "stateMachineArn")?;
                let m = self.machines.get(a).ok_or_else(|| not_found("StateMachine", a))?;
                json!({"stateMachineArn": a, "name": m.name, "status": "ACTIVE", "definition": m.def, "roleArn": m.role, "type": m.ty, "creationDate": m.created})
            }
            "ListStateMachines" => json!({"stateMachines": self.machines.iter()
                .map(|(a, m)| json!({"stateMachineArn": a, "name": m.name, "type": m.ty, "creationDate": m.created})).collect::<Vec<_>>()}),
            "UpdateStateMachine" => {
                let a = need(r, "stateMachineArn")?;
                let m = self.machines.get_mut(a).ok_or_else(|| not_found("StateMachine", a))?;
                if let Some(d) = r["definition"].as_str() {
                    serde_json::from_str::<Value>(d).map_err(|e| err("InvalidDefinition", e.to_string()))?;
                    m.def = d.into();
                }
                if let Some(role) = r["roleArn"].as_str() {
                    m.role = role.into();
                }
                json!({"updateDate": epoch()})
            }
            "DeleteStateMachine" => {
                self.machines.remove(need(r, "stateMachineArn")?);
                json!({})
            }
            "StartExecution" => {
                let a = need(r, "stateMachineArn")?;
                let m = self.machines.get(a).ok_or_else(|| not_found("StateMachine", a))?;
                let name = r["name"].as_str().map_or_else(|| uuid::Uuid::new_v4().to_string(), String::from);
                let arn = format!("arn:aws:states:{}:{ACCOUNT}:execution:{}:{name}", *REGION, m.name);
                if self.execs.contains_key(&arn) {
                    return Err(err("ExecutionAlreadyExists", format!("Execution Already Exists: '{arn}'")));
                }
                let input: Value = serde_json::from_str(r["input"].as_str().unwrap_or("{}")).map_err(|e| err("InvalidExecutionInput", e.to_string()))?;
                let start = epoch();
                self.execs.insert(arn.clone(), Exec { machine: a.into(), name, status: "RUNNING", start, stop: None, input: input.clone(), output: None, error: None,
                    history: vec![json!({"timestamp": start, "type": "ExecutionStarted", "id": 1, "previousEventId": 0,
                                         "executionStartedEventDetails": {"input": input.to_string(), "roleArn": m.role}})]});
                return Ok((json!({"executionArn": arn, "startDate": start}), Some(arn)));
            }
            "DescribeExecution" => {
                let a = need(r, "executionArn")?;
                Self::exec_json(a, self.execs.get(a).ok_or_else(|| not_found("Execution", a))?)
            }
            "ListExecutions" => {
                let m = need(r, "stateMachineArn")?;
                let f = r["statusFilter"].as_str();
                let list: Vec<Value> = self.execs.iter().filter(|(_, x)| x.machine == m && f.is_none_or(|s| s == x.status))
                    .map(|(a, x)| { let mut v = Self::exec_json(a, x); v.as_object_mut().unwrap().retain(|k, _| !["input", "output", "error", "cause"].contains(&k.as_str())); v })
                    .collect();
                json!({ "executions": list })
            }
            "StopExecution" => {
                let a = need(r, "executionArn")?;
                let x = self.execs.get_mut(a).ok_or_else(|| not_found("Execution", a))?;
                if x.status == "RUNNING" {
                    x.status = "ABORTED";
                    x.stop = Some(epoch());
                    x.error = r["error"].as_str().map(|e| (e.to_string(), r["cause"].as_str().unwrap_or("").to_string()));
                    let a2 = a;
                    for (tok, w) in self.waiting.split_off(&String::new()).into_iter().filter(|(_, w)| w.exec == a2) {
                        let _ = w.tx.send(TaskOutcome::Err("States.Timeout".into(), "execution was stopped while waiting for the task token".into()));
                        self.done.insert(tok);
                    }
                }
                json!({"stopDate": x.stop})
            }
            "GetExecutionHistory" => {
                let a = need(r, "executionArn")?;
                let x = self.execs.get(a).ok_or_else(|| not_found("Execution", a))?;
                let mut h = x.history.clone();
                if r["reverseOrder"].as_bool() == Some(true) {
                    h.reverse();
                }
                json!({ "events": h })
            }
            "SendTaskSuccess" | "SendTaskFailure" => {
                let t = need(r, "taskToken")?;
                let out = if op == "SendTaskSuccess" {
                    let v = match r["output"].clone() {
                        Value::String(s) => serde_json::from_str::<Value>(&s).map_err(|e| err("InvalidExecutionInput", format!("Invalid Output: {e}")))?,
                        other => other,
                    };
                    TaskOutcome::Ok(v)
                } else {
                    TaskOutcome::Err(r["error"].as_str().unwrap_or("").into(), r["cause"].as_str().unwrap_or("").into())
                };
                let w = self.waiting.remove(t).ok_or_else(|| self.token_err(t))?;
                self.remember_done(t);
                let _ = w.tx.send(out);
                json!({})
            }
            "SendTaskHeartbeat" => {
                let t = need(r, "taskToken")?;
                let miss = self.token_err(t);
                let w = self.waiting.get_mut(t).ok_or(miss)?;
                let interval = w.hb_interval.ok_or_else(|| err("TaskTimedOut", format!("Task Timed Out: '{t}' does not use heartbeats")))?;
                w.heartbeat = Some(crate::now_ms() + interval as i64);
                json!({})
            }
            _ => return Err(err("UnknownOperationException", format!("{op} is not supported yet"))),
        };
        Ok((v, None))
    }

    fn token_err(&self, t: &str) -> ApiErr {
        if self.done.contains(t) {
            err("TaskTimedOut", format!("Task Timed Out: '{t}' has already been resolved"))
        } else {
            err("TaskDoesNotExist", format!("Task Does Not Exist: '{t}'"))
        }
    }

    fn remember_done(&mut self, t: &str) {
        self.done.insert(t.into());
        while self.done.len() > 4096 {
            let first = self.done.iter().next().cloned();
            match first {
                Some(f) => { self.done.remove(&f); }
                None => break,
            }
        }
    }

    pub fn admin(&self) -> Value {
        self.machines
            .iter()
            .map(|(a, m)| {
                let rows: Vec<Value> = self.execs.iter().filter(|(_, x)| x.machine == *a).rev().take(100)
                    .map(|(_, x)| json!([x.name, x.status, x.output.as_ref().map(Value::to_string).or(x.error.as_ref().map(|e| format!("{}: {}", e.0, e.1)))])).collect();
                json!({"name": m.name, "count": rows.len(), "sub": format!("{} · {}", m.ty, a), "cols": ["실행", "상태", "결과"], "rows": rows})
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_and_templates() {
        let v = json!({"a": {"b": [1, {"c": "x"}]}, "n": 2});
        assert_eq!(jget(&v, "$.a.b[1].c"), Some(json!("x")));
        assert_eq!(jset(v.clone(), "$.r.s", json!(5))["r"]["s"], 5);
        let t = json!({"msg.$": "States.Format('n={} c={}', $.n, $.a.b[1].c)", "fixed": 1, "all.$": "$.n"});
        assert_eq!(template(&t, &v, &json!({})).unwrap(), json!({"msg": "n=2 c=x", "fixed": 1, "all": 2}));
        assert!(choice_ok(&json!({"And": [{"Variable": "$.n", "NumericGreaterThan": 1}, {"Variable": "$.a.b[1].c", "StringEquals": "x"}]}), &v, &json!({})));
        assert!(!choice_ok(&json!({"Variable": "$.missing", "IsPresent": true}), &v, &json!({})));
    }

    #[test]
    fn jsonpath_extended_and_context() {
        let v = json!({"items": [{"id": 1}, {"id": 2}, {"id": 3}], "a.b": {"c d": 99}});
        let ctx = json!({"Execution": {"Id": "exec-1"}, "State": {"Name": "Run"}, "Map": {"Item": {"Index": 2, "Value": "z"}}});
        assert_eq!(jget(&v, "$.items[*].id"), Some(json!([1, 2, 3])));
        assert_eq!(jget(&v, "$.items[-1].id"), Some(json!(3)));
        assert_eq!(jget(&v, "$.items[-3].id"), Some(json!(1)));
        assert_eq!(jget(&v, "$['a.b']['c d']"), Some(json!(99)));
        assert_eq!(value_of("$$.Execution.Id", &v, &ctx).unwrap(), json!("exec-1"));
        assert_eq!(value_of("$$.State.Name", &v, &ctx).unwrap(), json!("Run"));
        assert_eq!(value_of("$$.Map.Item.Value", &v, &ctx).unwrap(), json!("z"));
        // Filter expressions ?(...) must be rejected with a clear error
        assert!(jget_res(&v, "$.items[?(@.id > 1)]").is_err());
        assert!(value_of("$.items[?(@.id > 1)]", &v, &ctx).is_err());
    }

    #[test]
    fn intrinsics_all_day5() {
        let inp = json!({"arr": [1, 2, 2, 3, 4], "s": "hello", "csv": "a,b;c,,d", "o1": {"a": 1, "b": {"x": 1}}, "o2": {"b": {"y": 2}, "c": 3}});
        let ev = |e: &str| value_of(e, &inp, &json!({}));
        assert_eq!(ev("States.ArrayPartition($.arr, 2)").unwrap(), json!([[1, 2], [2, 3], [4]]));
        assert!(ev("States.ArrayPartition($.arr, 0)").is_err());
        assert_eq!(ev("States.ArrayContains($.arr, 3)").unwrap(), json!(true));
        assert_eq!(ev("States.ArrayContains($.arr, 9)").unwrap(), json!(false));
        assert_eq!(ev("States.ArrayRange(1, 5, 2)").unwrap(), json!([1, 3, 5]));
        assert_eq!(ev("States.ArrayRange(5, 1, -2)").unwrap(), json!([5, 3, 1]));
        assert!(ev("States.ArrayRange(1, 5, 0)").is_err());
        assert_eq!(ev("States.ArrayGetItem($.arr, 3)").unwrap(), json!(3));
        assert!(ev("States.ArrayGetItem($.arr, 99)").is_err());
        assert_eq!(ev("States.ArrayLength($.arr)").unwrap(), json!(5));
        assert_eq!(ev("States.ArrayUnique($.arr)").unwrap(), json!([1, 2, 3, 4]));
        assert_eq!(ev("States.Base64Encode($.s)").unwrap(), json!("aGVsbG8="));
        assert_eq!(ev("States.Base64Decode('aGVsbG8=')").unwrap(), json!("hello"));
        assert!(ev("States.Base64Decode('!!!')").is_err());
        assert_eq!(ev("States.Hash('hello', 'SHA-256')").unwrap(), json!("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"));
        assert_eq!(ev("States.Hash('hello', 'MD5')").unwrap(), json!("5d41402abc4b2a76b9719d911017c592"));
        assert!(ev("States.Hash('hello', 'SHA-1')").is_err());
        assert_eq!(ev("States.StringSplit($.csv, ',;')").unwrap(), json!(["a", "b", "c", "d"]));
        assert_eq!(ev("States.JsonMerge($.o1, $.o2, false)").unwrap(), json!({"a": 1, "b": {"y": 2}, "c": 3}));
        assert_eq!(ev("States.JsonMerge($.o1, $.o2, true)").unwrap(), json!({"a": 1, "b": {"x": 1, "y": 2}, "c": 3}));
        let r1 = ev("States.MathRandom(1, 100, 42)").unwrap().as_i64().unwrap();
        let r2 = ev("States.MathRandom(1, 100, 42)").unwrap().as_i64().unwrap();
        assert!(r1 == r2 && (1..100).contains(&r1));
        assert!(ev("States.MathRandom(10, 10)").is_err());
    }
#[test]
    fn task_token_lifecycle() {
        let mut s = Sfn::default();
        // Unknown token: TaskDoesNotExist.
        let e = s.handle("SendTaskSuccess", &json!({"taskToken": "bogus", "output": {"a": 1}})).unwrap_err();
        assert_eq!(e.code, "TaskDoesNotExist");
        // Register a wait, resolve it, then reuse the token: TaskTimedOut.
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        s.waiting.insert("tok1".into(), Wait { exec: "e".into(), deadline: i64::MAX, hb_interval: None, heartbeat: None, tx });
        s.handle("SendTaskSuccess", &json!({"taskToken": "tok1", "output": "{\"a\": 1}"})).unwrap();
        let e = s.handle("SendTaskFailure", &json!({"taskToken": "tok1", "error": "X", "cause": "c"})).unwrap_err();
        assert_eq!(e.code, "TaskTimedOut");
        // Heartbeat on a task without HeartbeatSeconds: TaskTimedOut.
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        s.waiting.insert("tok2".into(), Wait { exec: "e".into(), deadline: i64::MAX, hb_interval: None, heartbeat: None, tx });
        let e = s.handle("SendTaskHeartbeat", &json!({"taskToken": "tok2"})).unwrap_err();
        assert_eq!(e.code, "TaskTimedOut");
        // Heartbeat with an interval resets the next deadline.
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        s.waiting.insert("tok3".into(), Wait { exec: "e".into(), deadline: i64::MAX, hb_interval: Some(5000), heartbeat: Some(0), tx });
        s.handle("SendTaskHeartbeat", &json!({"taskToken": "tok3"})).unwrap();
        assert!(s.waiting["tok3"].heartbeat.unwrap() > 0);
        // Output must be JSON.
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        s.waiting.insert("tok4".into(), Wait { exec: "e".into(), deadline: i64::MAX, hb_interval: None, heartbeat: None, tx });
        let e = s.handle("SendTaskSuccess", &json!({"taskToken": "tok4", "output": "not-json{"})).unwrap_err();
        assert_eq!(e.code, "InvalidExecutionInput");
    }
}

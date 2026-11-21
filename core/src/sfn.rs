// Step Functions (JSON 1.0) with an Amazon States Language interpreter.
// ponytail: Parallel/Map branches run one after another; JSONPath supports $.a.b[0] only; no JSONata,
// task tokens, activities, Express sync starts or state TimeoutSeconds.
use crate::{epoch, err, need, ApiErr, App, ACCOUNT, REGION};
use serde_json::{json, Map, Value};
use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc, time::Duration};

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

pub fn jget(v: &Value, path: &str) -> Option<Value> {
    if path == "$" {
        return Some(v.clone());
    }
    let mut cur = v;
    for seg in path.strip_prefix("$.")?.split('.') {
        let (name, rest) = seg.split_once('[').map_or((seg, ""), |(n, r)| (n, r));
        if !name.is_empty() {
            cur = cur.get(name)?;
        }
        for idx in rest.split('[').filter(|s| !s.is_empty()) {
            cur = cur.get(idx.trim_end_matches(']').parse::<usize>().ok()?)?;
        }
    }
    Some(cur.clone())
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

// Split intrinsic arguments on commas outside quotes.
fn args(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut quoted, mut depth) = (vec![], String::new(), false, 0);
    for c in s.chars() {
        match c {
            '\'' => quoted = !quoted,
            '(' if !quoted => depth += 1,
            ')' if !quoted => depth -= 1,
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
        return Ok(Value::String(s.into()));
    }
    if let Some(rest) = e.strip_prefix("$$") {
        return jget(ctx, &format!("${rest}")).ok_or_else(|| fail("States.Runtime", format!("Context path {e} not found")));
    }
    if e.starts_with('$') {
        return jget(input, e).ok_or_else(|| fail("States.Runtime", format!("The JSONPath '{e}' could not be found in the input")));
    }
    if e.starts_with("States.") {
        return intrinsic(e, input, ctx);
    }
    serde_json::from_str(e).map_err(|_| fail("States.Runtime", format!("Invalid argument {e}")))
}

// ponytail: Format, StringToJson, JsonToString, Array, UUID, MathAdd only.
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
        "States.UUID" => Value::String(uuid::Uuid::new_v4().to_string()),
        "States.MathAdd" => json!(a.iter().filter_map(Value::as_f64).sum::<f64>()),
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

fn path_or(v: &Value, p: &Value) -> Result<Value, Fail> {
    match p {
        Value::Null => Ok(json!({})), // explicit null discards
        Value::String(s) => jget(v, s).ok_or_else(|| fail("States.Runtime", format!("Invalid path '{s}'"))),
        _ => Ok(v.clone()),
    }
}

// ---------- Choice ----------

fn choice_ok(rule: &Value, input: &Value) -> bool {
    if let Some(a) = rule["And"].as_array() {
        return a.iter().all(|r| choice_ok(r, input));
    }
    if let Some(a) = rule["Or"].as_array() {
        return a.iter().any(|r| choice_ok(r, input));
    }
    if rule.get("Not").is_some() {
        return !choice_ok(&rule["Not"], input);
    }
    let var = rule["Variable"].as_str().and_then(|p| jget(input, p));
    rule.as_object().into_iter().flatten().filter(|(k, _)| *k != "Variable" && *k != "Next").all(|(k, want)| {
        let (op, want) = match k.strip_suffix("Path") {
            Some(op) if k != "IsPresent" => (op, want.as_str().and_then(|p| jget(input, p)).unwrap_or(Value::Null)),
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
            if !app.sqs.lock().unwrap().deliver(&q, text(&p["MessageBody"]), &p["MessageAttributes"]) {
                return Err(fail("SQS.QueueDoesNotExist", format!("Queue {q} does not exist")));
            }
            Ok(json!({"MessageId": uuid::Uuid::new_v4().to_string()}))
        }
        "sns:publish" => {
            crate::send_to_target(app, "states", p["TopicArn"].as_str().unwrap_or(""), Value::String(text(&p["Message"])), "states");
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
            let eff = path_or(&data, st.get("InputPath").unwrap_or(&json!("$")))?;
            let params = |v: &Value| st.get("Parameters").map_or(Ok(v.clone()), |p| template(p, v, &sctx));

            if ty == "Choice" {
                let next = st["Choices"].as_array().into_iter().flatten().find(|c| choice_ok(c, &eff)).and_then(|c| c["Next"].as_str())
                    .or(st["Default"].as_str()).ok_or_else(|| fail("States.NoChoiceMatched", format!("No Choices matched in state {cur}")))?;
                data = path_or(&eff, st.get("OutputPath").unwrap_or(&json!("$")))?;
                record(app, exec, "ChoiceStateExited", json!({"name": cur, "output": data.to_string()}));
                (cur, attempts) = (next.to_string(), BTreeMap::new());
                continue;
            }
            let result: Result<Value, Fail> = match ty {
                "Pass" => match st.get("Result") { Some(r) => Ok(r.clone()), None => params(&eff) },
                "Succeed" => return path_or(&eff, st.get("OutputPath").unwrap_or(&json!("$"))),
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
                "Task" => match params(&eff) {
                    Ok(p) => task(app, st["Resource"].as_str().unwrap_or(""), p).await,
                    Err(e) => Err(e),
                },
                "Parallel" => match params(&eff) {
                    Ok(p) => {
                        let mut out = vec![];
                        let mut failed = None;
                        for b in st["Branches"].as_array().into_iter().flatten() {
                            match run_states(app, exec, b, p.clone(), ctx.clone()).await {
                                Ok(v) => out.push(v),
                                Err(e) => {
                                    failed = Some(e);
                                    break;
                                }
                            }
                        }
                        failed.map_or(Ok(Value::Array(out)), Err)
                    }
                    Err(e) => Err(e),
                },
                "Map" => {
                    let items = st["ItemsPath"].as_str().map_or(Some(eff.clone()), |p| jget(&eff, p));
                    let proc_def = st.get("ItemProcessor").or(st.get("Iterator")).cloned().unwrap_or_default();
                    match items.as_ref().and_then(Value::as_array) {
                        None => Err(fail("States.Runtime", "Map ItemsPath did not select an array")),
                        Some(items) => {
                            let mut out = vec![];
                            let mut failed = None;
                            for (i, item) in items.iter().enumerate() {
                                let mut mctx = sctx.clone();
                                mctx["Map"] = json!({"Item": {"Index": i, "Value": item}});
                                let sel = st.get("ItemSelector").or(st.get("Parameters"));
                                let item_in = match sel.map(|s| template(s, &eff, &mctx)) {
                                    Some(Err(e)) => { failed = Some(e); break }
                                    Some(Ok(v)) => v,
                                    None => item.clone(),
                                };
                                match run_states(app, exec, &proc_def, item_in, ctx.clone()).await {
                                    Ok(v) => out.push(v),
                                    Err(e) => { failed = Some(e); break }
                                }
                            }
                            failed.map_or(Ok(Value::Array(out)), Err)
                        }
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
                    data = path_or(&data, st.get("OutputPath").unwrap_or(&json!("$")))?;
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
            _ => return Err(err("UnknownOperationException", format!("{op} is not supported yet"))),
        };
        Ok((v, None))
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
        assert!(choice_ok(&json!({"And": [{"Variable": "$.n", "NumericGreaterThan": 1}, {"Variable": "$.a.b[1].c", "StringEquals": "x"}]}), &v));
        assert!(!choice_ok(&json!({"Variable": "$.missing", "IsPresent": true}), &v));
    }
}

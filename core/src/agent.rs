// Explanation agent. Rule-based explanations always work; a local LLM (Ollama, RC_LLM_URL / RC_LLM_MODEL) adds
// a short natural-language layer and answers questions through four tools. Destructive API calls need confirmation.
// GPU care: one LLM call at a time, >= 1.5 s apart, short context and output, model unloaded after 5 idle minutes.
use crate::{err, ApiErr, App};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::{Arc, LazyLock, Mutex}, time::{Duration, Instant}};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static LLM_URL: LazyLock<String> = LazyLock::new(|| std::env::var("RC_LLM_URL").unwrap_or_else(|_| "http://127.0.0.1:11434".into()));
static LLM_MODEL: LazyLock<String> = LazyLock::new(|| std::env::var("RC_LLM_MODEL").unwrap_or_else(|_| "qwen3.5:9b".into()));
static ONE_AT_A_TIME: LazyLock<tokio::sync::Mutex<Option<Instant>>> = LazyLock::new(|| tokio::sync::Mutex::new(None));
static PENDING: LazyLock<Mutex<HashMap<String, (String, String, Value)>>> = LazyLock::new(Default::default);

// ---------- rule-based explanations ----------

pub fn rules(e: &Value) -> String {
    let svc = e["service"].as_str().unwrap_or("");
    let op = e["op"].as_str().unwrap_or("");
    let status = e["status"].as_u64().unwrap_or(0);
    let code = e["error"]["code"].as_str().unwrap_or("");
    let msg = e["error"]["message"].as_str().unwrap_or("");
    if let Some(a) = e.get("auth").filter(|a| a["decision"] != "allowed") {
        let reason = a["reason"].as_str().unwrap_or("");
        let enforced = if a["enforced"] == true { "그래서 요청이 거부됐습니다." } else { "지금은 ENFORCE_IAM이 꺼져 있어 기록만 하고 통과시켰습니다." };
        return if a["decision"] == "explicitDeny" {
            format!("IAM 정책의 Deny 문장이 이 동작을 명시적으로 막았습니다. Deny는 어떤 Allow보다 우선하므로, 해당 문장을 고치거나 범위를 좁혀야 합니다. {enforced} (근거: {reason})")
        } else {
            format!("이 주체에게 해당 동작을 허용하는 정책이 없습니다(암묵적 거부). 필요한 Action과 Resource를 Allow하는 문장을 붙이세요. {enforced} (근거: {reason})")
        };
    }
    if let Some(f) = e["chaos"]["fault"].as_str() {
        return format!("장애 주입 규칙이 일부러 {f}를 냈습니다. 실제 장애가 아닙니다. 앱의 재시도와 대체 경로를 시험하는 용도이며, POST /_admin/chaos에 빈 규칙을 보내면 꺼집니다.");
    }
    if status < 400 {
        return match (svc, op) {
            ("lambda", "Invoke") if e["trigger"].is_string() => format!("{} 이벤트가 Lambda 함수 {}를 호출했고 정상 처리됐습니다.", e["trigger"].as_str().unwrap_or(""), e["target"].as_str().unwrap_or("")),
            (_, "Deliver") => format!("{}가 {}로 메시지를 전달했습니다.", svc, e["target"].as_str().unwrap_or("")),
            _ => format!("{svc} {op} 요청이 정상 처리됐습니다."),
        };
    }
    let hint = match code {
        c if c.contains("NotFound") || c.starts_with("NoSuch") || c == "QueueDoesNotExist" || c == "ParameterNotFound" || c.ends_with("DoesNotExist") =>
            "대상이 없습니다. 이름 철자와 리전을 확인하고, 먼저 만들었는지(또는 이미 지웠는지) 보세요.",
        "ConditionalCheckFailedException" => "조건식(ConditionExpression)이 현재 항목과 맞지 않아 쓰기가 취소됐습니다. 동시 수정이나 중복 생성을 막는 정상 동작일 수 있습니다.",
        "TransactionCanceledException" => "트랜잭션 안의 조건 하나가 실패해 전체가 취소됐습니다. CancellationReasons에서 몇 번째 항목인지 확인하세요.",
        c if c.contains("AlreadyExists") || c.contains("InUse") || c.contains("Conflict") || c == "BucketAlreadyOwnedByYou" || c == "UsernameExistsException" =>
            "같은 이름의 리소스가 이미 있습니다. 기존 것을 쓰거나 이름을 바꾸세요.",
        c if c.contains("Throttl") || c.contains("Throughput") || c == "SlowDown" || c == "RequestThrottled" =>
            "요청 속도 한도를 넘었습니다. SDK의 재시도와 지수 백오프로 흡수하는 것이 정상입니다.",
        c if c.contains("Validation") || c.contains("InvalidParameter") || c.starts_with("Invalid") || c == "MissingParameter" || c == "SerializationException" =>
            "요청 형식이나 값이 잘못됐습니다. 오류 메시지에 적힌 파라미터를 고치세요.",
        "NotAuthorizedException" => "인증 정보(비밀번호, 토큰, SECRET_HASH)가 맞지 않습니다.",
        "UserNotConfirmedException" => "가입 확인 전 사용자입니다. 확인 코드(관리 화면 또는 CodeSent 이벤트)로 ConfirmSignUp을 먼저 하세요.",
        "InvalidPasswordException" => "비밀번호가 사용자 풀의 정책(길이, 대소문자, 숫자, 기호)을 만족하지 않습니다.",
        "MessageRejected" => "SES 샌드박스처럼 인증된 발신자만 보낼 수 있습니다. VerifyEmailIdentity를 먼저 하세요.",
        c if c.contains("AccessDenied") || c == "UnauthorizedOperation" || c == "AuthorizationError" => "권한이 없어 거부됐습니다.",
        "NotImplemented" | "UnknownOperationException" | "InvalidAction" => "이 에뮬레이터가 아직 지원하지 않는 기능입니다. 지원 목록은 README에 있습니다.",
        "DependencyViolation" | "DeleteConflict" | "BucketNotEmpty" | "HostedZoneNotEmpty" => "다른 리소스가 아직 이걸 쓰고 있어서 지울 수 없습니다. 연결된 것부터 정리하세요.",
        _ if svc == "lambda" && status >= 500 => "함수 코드가 예외를 던졌거나 시간 초과로 끝났습니다. /aws/lambda/<함수> 로그 그룹에서 원인을 보세요.",
        _ if status >= 500 => "서버 쪽 오류입니다. 같은 요청을 다시 해 보고, 반복되면 에뮬레이터 로그를 확인하세요.",
        _ => "요청이 거부됐습니다. 오류 메시지를 확인하세요.",
    };
    if code.is_empty() { hint.to_string() } else { format!("{code}: {hint} (메시지: {msg})") }
}

// ---------- minimal HTTP client for Ollama ----------

async fn post_json(url: &str, body: &Value) -> Result<Value, String> {
    let rest = url.strip_prefix("http://").ok_or("RC_LLM_URL must be http://host:port")?;
    let (hostport, path) = rest.split_once('/').map_or((rest, "/".to_string()), |(h, p)| (h, format!("/{p}")));
    let mut s = tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(hostport)).await
        .map_err(|_| "LLM 서버 연결 시간 초과".to_string())?.map_err(|e| format!("LLM 서버에 연결할 수 없습니다: {e}"))?;
    let b = body.to_string();
    s.write_all(format!("POST {path} HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len()).as_bytes())
        .await.map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(120), s.read_to_end(&mut out)).await.map_err(|_| "LLM 응답 시간 초과".to_string())?.map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out);
    let (head, body) = text.split_once("\r\n\r\n").ok_or("잘못된 HTTP 응답")?;
    let body = if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        let mut r = String::new();
        let mut rest = body;
        while let Some((size, after)) = rest.split_once("\r\n") {
            let n = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
            if n == 0 || after.len() < n {
                break;
            }
            r += &after[..n];
            rest = after[n..].trim_start_matches("\r\n");
        }
        r
    } else {
        body.to_string()
    };
    if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
        return Err(format!("LLM 서버 오류: {}", head.lines().next().unwrap_or("")));
    }
    serde_json::from_str(&body).map_err(|e| e.to_string())
}

// One chat completion, optionally constrained to a JSON schema.
async fn chat(messages: &[Value], format: Option<&Value>) -> Result<String, String> {
    let mut gate = ONE_AT_A_TIME.lock().await;
    if let Some(t) = *gate {
        let gap = Duration::from_millis(1500);
        if t.elapsed() < gap {
            tokio::time::sleep(gap - t.elapsed()).await;
        }
    }
    let mut req = json!({"model": *LLM_MODEL, "messages": messages, "stream": false, "think": false, "keep_alive": "5m",
                         "options": {"temperature": 0.2, "num_ctx": 4096, "num_predict": 400}});
    if let Some(f) = format {
        req["format"] = f.clone();
    }
    let r = post_json(&format!("{}/api/chat", *LLM_URL), &req).await;
    *gate = Some(Instant::now());
    r.map(|v| v["message"]["content"].as_str().unwrap_or("").trim().to_string())
}

pub async fn status() -> Value {
    match tokio::time::timeout(Duration::from_secs(2), post_json(&format!("{}/api/show", *LLM_URL), &json!({"model": *LLM_MODEL}))).await {
        Ok(Ok(_)) => json!({"available": true, "model": *LLM_MODEL, "url": *LLM_URL}),
        Ok(Err(e)) => json!({"available": false, "model": *LLM_MODEL, "url": *LLM_URL, "reason": e}),
        Err(_) => json!({"available": false, "model": *LLM_MODEL, "url": *LLM_URL, "reason": "timeout"}),
    }
}

const SYSTEM: &str = "너는 로컬 클라우드 에뮬레이터 rocalcloud의 해설가다. 한국어로 짧게 답한다. 주어진 사실만 쓰고, 모르는 것은 모른다고 말한다.";

fn compact(e: &Value) -> Value {
    let mut c = e.clone();
    if let Some(o) = c.as_object_mut() {
        o.retain(|k, _| ["service", "op", "status", "target", "principal", "auth", "error", "chaos", "trigger", "request_id", "result"].contains(&k.as_str()));
    }
    c
}

pub async fn explain(app: &App, request_id: &str, use_llm: bool) -> Result<Value, ApiErr> {
    let ev = app.recent.lock().unwrap().iter().rev().find(|e| e["request_id"] == request_id).cloned()
        .ok_or_else(|| ApiErr { status: 404, ..err("NotFound", "이 요청 ID는 최근 이벤트 1000건 안에 없습니다.") })?;
    let rule = rules(&ev);
    if !use_llm {
        return Ok(json!({"request_id": request_id, "rule": rule, "llm": null}));
    }
    let prompt = format!("요청 사실: {}\n규칙 해설: {rule}\n개발자에게 1~3문장으로, 왜 이런 결과가 났는지와 다음에 할 일을 설명해라.", compact(&ev));
    let llm = chat(&[json!({"role": "system", "content": SYSTEM}), json!({"role": "user", "content": prompt})], None).await;
    Ok(match llm {
        Ok(t) => json!({"request_id": request_id, "rule": rule, "llm": t, "model": *LLM_MODEL}),
        Err(e) => json!({"request_id": request_id, "rule": rule, "llm": null, "llm_error": e}),
    })
}

// ---------- tools ----------

const DESTRUCTIVE: &[&str] = &["Delete", "Purge", "Terminate", "Remove", "Stop", "Disable", "Schedule", "Detach", "Deregister", "Revoke"];

fn summarize_state(app: &App, service: Option<&str>) -> Value {
    let state = json!({
        "dynamodb": app.ddb.lock().unwrap().admin(), "s3": app.s3.lock().unwrap().admin(), "sqs": app.sqs.lock().unwrap().admin(),
        "sns": app.sns.lock().unwrap().admin(), "lambda": app.lambda.lock().unwrap().admin(), "ssm": app.ssm.lock().unwrap().admin(),
        "secretsmanager": app.secrets.lock().unwrap().admin(), "logs": app.logs.lock().unwrap().admin(), "events": app.eb.lock().unwrap().admin(),
        "states": app.sfn.lock().unwrap().admin(), "kinesis": app.kinesis.lock().unwrap().admin(), "cloudformation": app.cfn.lock().unwrap().admin(),
    });
    let names = |v: &Value| v.as_array().into_iter().flatten().map(|x| json!({"name": x["name"], "count": x["count"]})).collect::<Vec<_>>();
    match service {
        Some(s) => json!({ s: names(&state[s]) }),
        None => Value::Object(state.as_object().unwrap().iter().map(|(k, v)| (k.clone(), json!(names(v)))).filter(|(_, v)| v.as_array().is_some_and(|a| !a.is_empty())).collect()),
    }
}

// Executes an API call against a JSON-protocol service as the account root.
async fn call_api(app: &Arc<App>, service: &str, op: &str, params: &Value) -> Result<Value, String> {
    let api = |r: Result<Value, ApiErr>| r.map_err(|e| format!("{}: {}", e.code, e.msg));
    match service {
        "dynamodb" => api(crate::ddb::handle(app, op, params.to_string().as_bytes())),
        "sqs" => api(crate::sqs::handle(app, op, params.to_string().as_bytes(), &crate::endpoint()[7..]).await),
        "ssm" => api(app.ssm.lock().unwrap().handle(op, params)),
        "secretsmanager" => api(app.secrets.lock().unwrap().handle(op, params)),
        "kms" => api(app.kms.lock().unwrap().handle(op, params)),
        "logs" => api(app.logs.lock().unwrap().handle(op, params)),
        "kinesis" => api(app.kinesis.lock().unwrap().handle(op, params)),
        "states" => api(app.sfn.lock().unwrap().handle(op, params).map(|(v, _)| v)),
        _ => Err(format!("call_api는 dynamodb, sqs, ssm, secretsmanager, kms, logs, kinesis, states만 지원합니다 (요청: {service})")),
    }
}

fn clip(v: &Value, n: usize) -> String {
    let s = v.to_string();
    if s.len() <= n { s } else { format!("{}…(생략)", &s[..s.char_indices().take_while(|(i, _)| *i < n).last().map_or(0, |(i, c)| i + c.len_utf8())]) }
}

async fn run_tool(app: &Arc<App>, action: &str, a: &Value) -> Result<Value, Value> {
    Ok(match action {
        "list_resources" => summarize_state(app, a["service"].as_str().filter(|s| !s.is_empty())),
        "recent_events" => {
            let n = a["n"].as_u64().unwrap_or(10).min(20) as usize;
            let only_err = a["only_errors"] == true;
            let svc = a["service"].as_str().filter(|s| !s.is_empty());
            let r = app.recent.lock().unwrap();
            let list: Vec<Value> = r.iter().rev().filter(|e| (!only_err || e["status"].as_u64().unwrap_or(0) >= 400 || e["auth"]["decision"].as_str().is_some_and(|d| d != "allowed"))
                && svc.is_none_or(|s| e["service"] == s)).take(n).map(compact).collect();
            json!(list)
        }
        "explain_event" => {
            let id = a["request_id"].as_str().unwrap_or("");
            let ev = app.recent.lock().unwrap().iter().rev().find(|e| e["request_id"] == id).cloned();
            ev.map_or(json!("그 요청 ID를 찾지 못했습니다"), |e| json!(rules(&e)))
        }
        "call_api" => {
            let (svc, op) = (a["service"].as_str().unwrap_or(""), a["operation"].as_str().unwrap_or(""));
            let params = if a["params"].is_object() { a["params"].clone() } else { json!({}) };
            if DESTRUCTIVE.iter().any(|d| op.starts_with(d)) {
                let token = uuid::Uuid::new_v4().simple().to_string()[..12].to_string();
                PENDING.lock().unwrap().insert(token.clone(), (svc.into(), op.into(), params.clone()));
                return Err(json!({"needs_confirmation": token, "service": svc, "operation": op, "params": params}));
            }
            call_api(app, svc, op, &params).await.unwrap_or_else(|e| json!({ "error": e }))
        }
        other => json!(format!("알 수 없는 도구 {other}")),
    })
}

// The model must answer with exactly this shape (Ollama structured output).
fn step_schema() -> Value {
    json!({"type": "object", "required": ["action", "args", "answer"], "properties": {
        "action": {"type": "string", "enum": ["list_resources", "recent_events", "explain_event", "call_api", "answer"]},
        "args": {"type": "object", "properties": {
            "service": {"type": "string"}, "n": {"type": "integer"}, "only_errors": {"type": "boolean"}, "request_id": {"type": "string"},
            "operation": {"type": "string"}, "params": {"type": "object"}}},
        "answer": {"type": "string"}}})
}

const TOOLS: &str = "도구:\n\
- list_resources {service?}: 지금 있는 리소스 이름과 개수\n\
- recent_events {service?, n?, only_errors?}: 최근 요청 기록\n\
- explain_event {request_id}: 요청 하나의 결과 해설\n\
- call_api {service, operation, params}: dynamodb·sqs·ssm·secretsmanager·kms·logs·kinesis·states의 API를 AWS 형식 파라미터로 호출 (예: dynamodb Scan {\"TableName\":\"t\"})\n\
- answer: 최종 답. answer 필드에 한국어로 쓴다.\n\
한 번에 하나의 action만 고른다. 정보가 충분하면 바로 answer를 고른다.";

// Rule-based answer when the LLM is unavailable: summarize recent problems.
fn fallback(app: &App, why: &str) -> Value {
    let r = app.recent.lock().unwrap();
    let problems: Vec<String> = r.iter().rev().filter(|e| e["status"].as_u64().unwrap_or(0) >= 400).take(5)
        .map(|e| format!("- {} {} → {}", e["service"].as_str().unwrap_or(""), e["op"].as_str().unwrap_or(""), rules(e))).collect();
    let body = if problems.is_empty() { "최근 오류는 없습니다.".to_string() } else { format!("최근 오류 요약:\n{}", problems.join("\n")) };
    json!({"answer": format!("로컬 LLM을 쓸 수 없어 규칙 기반으로 답합니다 ({why}).\n{body}"), "steps": [], "llm": false})
}

pub async fn ask(app: &Arc<App>, question: &str, confirm: Option<&str>) -> Value {
    if let Some(tok) = confirm {
        let Some((svc, op, params)) = PENDING.lock().unwrap().remove(tok) else {
            return json!({"answer": "확인 토큰이 없거나 이미 사용됐습니다."});
        };
        let r = call_api(app, &svc, &op, &params).await;
        return json!({"answer": match &r { Ok(_) => format!("{svc} {op}를 실행했습니다."), Err(e) => format!("{svc} {op} 실패: {e}") }, "result": r.unwrap_or_else(|e| json!(e))});
    }
    let mut msgs = vec![json!({"role": "system", "content": format!("{SYSTEM}\n{TOOLS}")}), json!({"role": "user", "content": question})];
    let schema = step_schema();
    let mut steps = vec![];
    for i in 0..5 {
        if i == 4 {
            msgs.push(json!({"role": "user", "content": "이제 지금까지의 도구 결과로 answer를 골라 답해라."}));
        }
        let raw = match chat(&msgs, Some(&schema)).await {
            Ok(r) => r,
            Err(e) if steps.is_empty() => return fallback(app, &e),
            Err(e) => return json!({"answer": format!("LLM 호출이 중간에 실패했습니다: {e}"), "steps": steps, "llm": true}),
        };
        let Ok(step) = serde_json::from_str::<Value>(&raw) else {
            return json!({"answer": raw, "steps": steps, "llm": true});
        };
        let action = step["action"].as_str().unwrap_or("answer");
        if action == "answer" {
            return json!({"answer": step["answer"], "steps": steps, "llm": true, "model": *LLM_MODEL});
        }
        let result = run_tool(app, action, &step["args"]).await;
        let (shown, stop) = match &result {
            Ok(v) => (v.clone(), None),
            Err(confirm) => (confirm.clone(), Some(confirm.clone())),
        };
        steps.push(json!({"action": action, "args": step["args"], "result": clip(&shown, 600)}));
        if let Some(c) = stop {
            return json!({"answer": format!("{} {}는 되돌릴 수 없는 작업이라 실행 전에 확인이 필요합니다.", c["service"].as_str().unwrap_or(""), c["operation"].as_str().unwrap_or("")),
                          "confirm": c, "steps": steps, "llm": true});
        }
        msgs.push(json!({"role": "assistant", "content": raw}));
        msgs.push(json!({"role": "user", "content": format!("도구 결과: {}", clip(&shown, 2000))}));
    }
    json!({"answer": "답을 정리하지 못했습니다.", "steps": steps, "llm": true})
}

// ---------- infrastructure-code draft ----------

// Deterministic CloudFormation YAML for the current S3 buckets, DynamoDB tables, SQS queues, SNS topics/subscriptions
// and SSM parameters (small models are weak at long code, so no LLM here).
pub fn template(app: &App) -> String {
    let logical = |name: &str, suffix: &str| -> String {
        let base: String = name.split(|c: char| !c.is_ascii_alphanumeric()).filter(|s| !s.is_empty())
            .map(|s| { let mut c = s.chars(); c.next().map_or(String::new(), |f| f.to_ascii_uppercase().to_string() + c.as_str()) }).collect();
        format!("{}{suffix}", if base.is_empty() { "Res".into() } else { base })
    };
    let mut res = serde_json::Map::new();
    let mut skipped = vec![];
    for b in app.s3.lock().unwrap().bucket_names() {
        res.insert(logical(&b, "Bucket"), json!({"Type": "AWS::S3::Bucket", "Properties": {"BucketName": b}}));
    }
    for (n, p) in app.ddb.lock().unwrap().export() {
        res.insert(logical(&n, "Table"), json!({"Type": "AWS::DynamoDB::Table", "Properties": p}));
    }
    let queues = app.sqs.lock().unwrap().export();
    let qref = |arn: &str| -> Value {
        let name = arn.rsplit(':').next().unwrap_or("");
        if queues.iter().any(|(n, _)| n == name) { json!({"Fn::GetAtt": [logical(name, "Queue"), "Arn"]}) } else { json!(arn) }
    };
    for (n, attrs) in &queues {
        let mut p = json!({"QueueName": n});
        for (k, v) in attrs {
            p[k] = match k.as_str() {
                "RedrivePolicy" => {
                    let rp: Value = serde_json::from_str(v).unwrap_or_default();
                    json!({"deadLetterTargetArn": qref(rp["deadLetterTargetArn"].as_str().unwrap_or("")), "maxReceiveCount": rp["maxReceiveCount"]})
                }
                "FifoQueue" | "ContentBasedDeduplication" => json!(v == "true"),
                _ => v.parse::<i64>().map_or(json!(v), |n| json!(n)),
            };
        }
        res.insert(logical(n, "Queue"), json!({"Type": "AWS::SQS::Queue", "Properties": p}));
    }
    let (topics, subs) = app.sns.lock().unwrap().export();
    for t in &topics {
        let n = t.rsplit(':').next().unwrap_or("");
        res.insert(logical(n, "Topic"), json!({"Type": "AWS::SNS::Topic", "Properties": {"TopicName": n}}));
    }
    for (i, (t, proto, ep, attrs)) in subs.iter().enumerate() {
        let tn = t.rsplit(':').next().unwrap_or("");
        let mut p = json!({"TopicArn": {"Ref": logical(tn, "Topic")}, "Protocol": proto, "Endpoint": if proto == "sqs" { qref(ep) } else { json!(ep) }});
        for k in ["RawMessageDelivery", "FilterPolicy"] {
            if let Some(v) = attrs.get(k) {
                p[k] = if k == "FilterPolicy" { serde_json::from_str(v).unwrap_or(json!(v)) } else { json!(v == "true") };
            }
        }
        res.insert(format!("{}Subscription{}", logical(tn, ""), i + 1), json!({"Type": "AWS::SNS::Subscription", "Properties": p}));
    }
    for (n, ty, v) in app.ssm.lock().unwrap().export() {
        if ty == "SecureString" {
            skipped.push(format!("SSM SecureString {n} (CloudFormation cannot create SecureString parameters)"));
            continue;
        }
        res.insert(logical(&n, "Parameter"), json!({"Type": "AWS::SSM::Parameter", "Properties": {"Name": n, "Type": ty, "Value": v}}));
    }
    let t = json!({"AWSTemplateFormatVersion": "2010-09-09", "Description": "Draft generated by rocalcloud from the current local resources", "Resources": res});
    let mut out = serde_yaml::to_string(&t).unwrap_or_default();
    if !skipped.is_empty() {
        out += &format!("# Skipped:\n{}", skipped.iter().map(|s| format!("#   - {s}\n")).collect::<String>());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_texts() {
        assert!(rules(&json!({"service": "s3", "op": "GetObject", "status": 403, "auth": {"decision": "explicitDeny", "enforced": true, "reason": "r"}})).contains("명시적"));
        assert!(rules(&json!({"service": "sqs", "op": "GetQueueUrl", "status": 400, "error": {"code": "QueueDoesNotExist", "message": "m"}})).contains("대상이 없습니다"));
        assert!(rules(&json!({"service": "dynamodb", "op": "Query", "status": 400, "chaos": {"fault": "ProvisionedThroughputExceededException"}})).contains("장애 주입"));
        assert!(rules(&json!({"service": "lambda", "op": "Invoke", "status": 500})).contains("/aws/lambda"));
        assert_eq!(clip(&json!("가나다라마바사"), 8).chars().count() <= 12, true);
    }
}

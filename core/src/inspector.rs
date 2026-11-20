// Verification agent (inspector): attacks and fault-tests the local emulator itself.
// Execution and verdict are strictly deterministic code targeting 127.0.0.1 only.
// The local LLM (shared with agent.rs) is optional and only proposes extra test scenarios.
use crate::{agent, b64, emit, endpoint, err, error_of, s3, ApiErr, App, ACCOUNT, ENFORCE, REGION};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_SCENARIOS: usize = 40;
const MAX_HISTORY: usize = 20;
const MAX_TIMEOUT_SECS: u64 = 60;
const PREFIX: &str = "rc-insp-";

#[derive(Default)]
pub struct Inspector {
    pub running: bool,
    pub history: Vec<Value>,
}

// ---------- local-only HTTP client ----------

fn loopback_hostport() -> Result<String, String> {
    let ep = endpoint();
    let rest = ep.strip_prefix("http://").ok_or("로컬 HTTP 엔드포인트가 아닙니다")?;
    let hostport = rest.split('/').next().unwrap_or(rest);
    let host = hostport.split(':').next().unwrap_or("");
    if host != "127.0.0.1" && host != "localhost" {
        return Err(format!("안전장치: 로컬 루프백(127.0.0.1)만 허용됩니다 (거부됨: {host})"));
    }
    Ok(hostport.to_string())
}

#[derive(Clone, Debug)]
struct HttpResp {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
    error_code: Option<String>,
}

fn decode_chunked(body: &str) -> String {
    let mut r = String::new();
    let mut rest = body;
    while let Some((size, after)) = rest.split_once("\r\n") {
        let n = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
        if n == 0 || after.len() < n {
            break;
        }
        r.push_str(&after[..n]);
        rest = after[n..].trim_start_matches("\r\n");
    }
    r
}

// Requests built with sig_header() carry a placeholder signature; sign them for real so VERIFY_SIGV4=1 accepts them.
// With VERIFY_SIGV4=1, unsigned requests are signed as root, except probes marked x-rc-unsigned.
fn resign(method: &str, path: &str, host: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<(String, String)> {
    let get = |n: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| *v);
    let unsigned = get("authorization").is_none() && get("x-rc-unsigned").is_none() && *crate::VERIFY;
    let auth = get("authorization").filter(|a| a.ends_with("Signature=00"));
    let mut rest: Vec<(String, String)> = headers.iter()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("x-rc-unsigned") && (auth.is_none() || !k.eq_ignore_ascii_case("authorization")))
        .map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let Some(app) = crate::APP.get() else { return rest };
    let root;
    let a = match auth {
        Some(a) => a,
        None if unsigned => {
            let svc = match get("x-amz-target") {
                Some(t) => ["dynamodb", "sqs", "secretsmanager", "ssm", "kms", "logs", "events", "states", "cognito-idp", "kinesis", "ecs"]
                    .into_iter().find(|s| json_target_prefix(s).is_some_and(|p| t.starts_with(p))).unwrap_or("s3"),
                None if path.starts_with("/2015-03-31/") => "lambda",
                None => "s3",
            };
            root = sig_header("test", svc);
            &root
        }
        None => return rest,
    };
    let cred = a.split("Credential=").nth(1).unwrap_or("").split(',').next().unwrap_or("");
    let p: Vec<&str> = cred.split('/').collect();
    let (secret, token) = app.iam.lock().unwrap().secret_of(p[0]);
    if let Some(t) = token {
        rest.push(("x-amz-security-token".into(), t));
    }
    let extra: Vec<(&str, &str)> = rest.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let signed = crate::sigv4::sign(method, path, host, &extra, body, p[0], &secret, p.get(2).unwrap_or(&""), p.get(3).unwrap_or(&""));
    rest.extend(signed);
    rest
}

async fn local_http(method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<HttpResp, String> {
    let hostport = loopback_hostport()?;
    let owned = resign(method, path, &hostport, headers, body);
    let headers: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let mut s = tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(&hostport))
        .await
        .map_err(|_| "로컬 에뮬레이터 연결 시간 초과".to_string())?
        .map_err(|e| format!("로컬 에뮬레이터 연결 실패: {e}"))?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n");
    let has_cl = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length"));
    for (k, v) in &headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !has_cl {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
    if !body.is_empty() {
        s.write_all(body).await.map_err(|e| e.to_string())?;
    }
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out))
        .await
        .map_err(|_| "응답 시간 초과".to_string())?
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out);
    let (head, raw_body) = text.split_once("\r\n\r\n").ok_or("잘못된 HTTP 응답")?;
    let status = head.lines().next().and_then(|l| l.split_whitespace().nth(1)).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
    let mut hdrs = HashMap::new();
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            hdrs.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let resp_body = if hdrs.get("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        decode_chunked(raw_body)
    } else {
        raw_body.to_string()
    };
    let error_code = if status >= 400 {
        error_of(resp_body.as_bytes()).and_then(|v| v["code"].as_str().map(String::from))
    } else {
        None
    };
    Ok(HttpResp { status, headers: hdrs, body: resp_body, error_code })
}

// Send an oversized Content-Length header without allocating 256 MiB in RAM.
async fn send_oversize_probe(declared_len: usize) -> Result<HttpResp, String> {
    let hostport = loopback_hostport()?;
    let mut s = tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(&hostport))
        .await
        .map_err(|_| "연결 시간 초과".to_string())?
        .map_err(|e| e.to_string())?;
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {hostport}\r\nX-Amz-Target: DynamoDB_20120810.ListTables\r\nContent-Type: application/x-amz-json-1.0\r\nContent-Length: {declared_len}\r\nConnection: close\r\n\r\n{{"
    );
    let _ = s.write_all(req.as_bytes()).await;
    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await.ok().and_then(Result::ok).unwrap_or(0);
    let text = String::from_utf8_lossy(&buf[..n]);
    let status = text.lines().next().and_then(|l| l.split_whitespace().nth(1)).and_then(|x| x.parse::<u16>().ok()).unwrap_or(0);
    Ok(HttpResp { status, headers: HashMap::new(), body: text.into_owned(), error_code: None })
}

fn sig_header(akid: &str, svc: &str) -> String {
    format!("AWS4-HMAC-SHA256 Credential={akid}/20261120/{}/{svc}/aws4_request, SignedHeaders=host, Signature=00", *REGION)
}

fn json_target_prefix(service: &str) -> Option<&'static str> {
    match service {
        "dynamodb" => Some("DynamoDB_20120810."),
        "sqs" => Some("AmazonSQS."),
        "secretsmanager" => Some("secretsmanager."),
        "ssm" => Some("AmazonSSM."),
        "kms" => Some("TrentService."),
        "logs" => Some("Logs_20140328."),
        "events" => Some("AWSEvents."),
        "states" => Some("AWSStepFunctions."),
        "cognito-idp" => Some("AWSCognitoIdentityProviderService."),
        "kinesis" => Some("Kinesis_20131202."),
        "ecs" => Some("AmazonEC2ContainerServiceV20141113."),
        _ => None,
    }
}

async fn call_json(service: &str, op: &str, body: &Value, akid: Option<&str>) -> Result<HttpResp, String> {
    let pre = json_target_prefix(service).ok_or_else(|| format!("지원하지 않는 JSON 서비스: {service}"))?;
    let target = format!("{pre}{op}");
    let auth = akid.map(|k| sig_header(k, service));
    let mut hdrs: Vec<(&str, &str)> = vec![("x-amz-target", &target), ("content-type", "application/x-amz-json-1.0")];
    if let Some(a) = &auth {
        hdrs.push(("authorization", a));
    }
    local_http("POST", "/", &hdrs, body.to_string().as_bytes()).await
}

async fn call_query(service: &str, version: &str, action: &str, params: &[(&str, &str)], akid: Option<&str>) -> Result<HttpResp, String> {
    let mut form = format!("Action={action}&Version={version}");
    for (k, v) in params {
        form.push('&');
        form.push_str(k);
        form.push('=');
        form.push_str(&pct_encode(v));
    }
    let auth = akid.map(|k| sig_header(k, service));
    let mut hdrs: Vec<(&str, &str)> = vec![("content-type", "application/x-www-form-urlencoded")];
    if let Some(a) = &auth {
        hdrs.push(("authorization", a));
    }
    local_http("POST", "/", &hdrs, form.as_bytes()).await
}

fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn repro_step(method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Value {
    let h: Vec<Value> = headers.iter().map(|(k, v)| json!([k, v])).collect();
    json!({"method": method, "path": path, "headers": h, "body": body})
}

fn make_result(
    id: &str,
    name: &str,
    kind: &str,
    severity: &str,
    service: &str,
    passed: bool,
    blocked: bool,
    detail: String,
    elapsed_ms: f64,
    expect: Value,
    actual: Value,
    repro: Vec<Value>,
) -> Value {
    json!({
        "id": id, "name": name, "kind": kind, "severity": severity, "service": service,
        "passed": passed, "blocked": blocked, "detail": detail, "elapsed_ms": (elapsed_ms * 10.0).round() / 10.0,
        "expect": expect, "actual": actual, "repro": repro,
    })
}

// ---------- deterministic verdict rule ----------

pub fn judge(expect: &Value, status: u16, error_code: Option<&str>, body: &str) -> (bool, String) {
    if let Some(s) = expect["status"].as_u64() {
        if status as u64 != s {
            return (false, format!("기대 상태코드 {s}, 실제 {status} (오류: {})", error_code.unwrap_or("없음")));
        }
    }
    if let Some(arr) = expect["status_in"].as_array() {
        if !arr.iter().any(|x| x.as_u64() == Some(status as u64)) {
            return (false, format!("기대 상태코드 {arr:?}, 실제 {status}"));
        }
    }
    if let Some(lt) = expect["status_lt"].as_u64() {
        if (status as u64) >= lt || status == 0 {
            return (false, format!("상태코드가 {lt} 미만이어야 하나 실제 {status}"));
        }
    }
    if let Some(ec) = expect["error_code"].as_str().filter(|s| !s.is_empty()) {
        if error_code != Some(ec) {
            return (false, format!("기대 오류 코드 {ec}, 실제 {}", error_code.unwrap_or("없음")));
        }
    }
    if let Some(sub) = expect["body_not_contains"].as_str().filter(|s| !s.is_empty()) {
        if body.contains(sub) {
            return (false, format!("응답에 금지된 문자열({sub})이 포함됐습니다"));
        }
    }
    if let Some(sub) = expect["body_contains"].as_str().filter(|s| !s.is_empty()) {
        if !body.contains(sub) {
            return (false, format!("응답에 기대 문자열({sub})이 없습니다"));
        }
    }
    (true, format!("기대 조건 충족 (HTTP {status}{})", error_code.map(|c| format!(" {c}")).unwrap_or_default()))
}

// ---------- built-in scenarios ----------

async fn sc_admin_csrf() -> Value {
    let t0 = Instant::now();
    let targets = [("/_admin/reset", "{}"), ("/_admin/chaos", "{\"rules\":[]}"), ("/_inspect/run", "{}")];
    let mut bad = vec![];
    let mut repro = vec![];
    for (p, b) in targets {
        repro.push(repro_step("POST", p, &[("content-type", "application/json")], b));
        match local_http("POST", p, &[("content-type", "application/json")], b.as_bytes()).await {
            Ok(r) if r.status == 403 => {}
            Ok(r) => bad.push(format!("{p} → {}", r.status)),
            Err(e) => bad.push(format!("{p} → {e}")),
        }
    }
    let ok = bad.is_empty();
    let detail = if ok {
        "x-rocalcloud 헤더 없는 관리 POST 3건이 모두 403으로 차단됐습니다.".into()
    } else {
        format!("CSRF 헤더 없이 통과된 엔드포인트: {}", bad.join(", "))
    };
    make_result("sec-admin-csrf", "관리 API CSRF 헤더 차단", "security", "critical", "iam", ok, ok, detail,
        t0.elapsed().as_secs_f64() * 1000.0, json!({"status": 403}), json!({"failures": bad}), repro)
}

async fn sc_iam_implicit_deny(tag: &str) -> Value {
    let t0 = Instant::now();
    let user = format!("{PREFIX}noallow-{tag}");
    let bucket = format!("{PREFIX}bkt-{tag}");
    let _ = local_http("PUT", &format!("/{bucket}"), &[], b"").await;
    let _ = local_http("PUT", &format!("/{bucket}/secret.txt"), &[], b"top-secret").await;
    let _ = call_query("iam", "2010-05-08", "CreateUser", &[("UserName", &user)], None).await;
    let ak_resp = call_query("iam", "2010-05-08", "CreateAccessKey", &[("UserName", &user)], None).await;
    let akid = ak_resp.as_ref().ok().and_then(|r| s3::tags(&r.body, "AccessKeyId").into_iter().next()).unwrap_or_default();
    let auth = sig_header(&akid, "s3");
    let res = local_http("GET", &format!("/{bucket}/secret.txt"), &[("authorization", &auth)], b"").await;
    // cleanup
    if !akid.is_empty() {
        let _ = call_query("iam", "2010-05-08", "DeleteAccessKey", &[("UserName", &user), ("AccessKeyId", &akid)], None).await;
    }
    let _ = call_query("iam", "2010-05-08", "DeleteUser", &[("UserName", &user)], None).await;
    let _ = local_http("DELETE", &format!("/{bucket}/secret.txt"), &[], b"").await;
    let _ = local_http("DELETE", &format!("/{bucket}"), &[], b"").await;

    let repro = vec![repro_step("GET", &format!("/{bucket}/secret.txt"), &[("authorization", &auth)], "")];
    match res {
        Ok(r) if *ENFORCE => {
            let (ok, msg) = judge(&json!({"status": 403, "error_code": "AccessDenied"}), r.status, r.error_code.as_deref(), &r.body);
            make_result("sec-iam-implicit-deny", "IAM 암묵적 거부 차단", "security", "high", "s3", ok, ok,
                if ok { "권한 없는 사용자의 S3 읽기가 403 AccessDenied로 차단됐습니다.".into() } else { msg },
                t0.elapsed().as_secs_f64() * 1000.0, json!({"status": 403, "error_code": "AccessDenied"}),
                json!({"status": r.status, "error_code": r.error_code}), repro)
        }
        Ok(r) => make_result("sec-iam-implicit-deny", "IAM 암묵적 거부 차단", "security", "info", "s3", true, false,
            format!("ENFORCE_IAM=0 모드라 요청(HTTP {})이 보고만 되고 통과했습니다. 강제 검증은 ENFORCE_IAM=1로 실행하세요.", r.status),
            t0.elapsed().as_secs_f64() * 1000.0, json!({"enforced": false}), json!({"status": r.status}), repro),
        Err(e) => make_result("sec-iam-implicit-deny", "IAM 암묵적 거부 차단", "security", "high", "s3", false, false, e,
            t0.elapsed().as_secs_f64() * 1000.0, json!({"status": 403}), json!({}), repro),
    }
}

async fn sc_iam_explicit_deny(tag: &str) -> Value {
    let t0 = Instant::now();
    let user = format!("{PREFIX}deny-{tag}");
    let bucket = format!("{PREFIX}dbkt-{tag}");
    let _ = local_http("PUT", &format!("/{bucket}"), &[], b"").await;
    let _ = local_http("PUT", &format!("/{bucket}/payroll.csv"), &[], b"salary").await;
    let _ = call_query("iam", "2010-05-08", "CreateUser", &[("UserName", &user)], None).await;
    let policy = json!({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "*", "Resource": "*"},
        {"Effect": "Deny", "Action": "s3:GetObject", "Resource": format!("arn:aws:s3:::{bucket}/*")}
    ]}).to_string();
    let _ = call_query("iam", "2010-05-08", "PutUserPolicy", &[("UserName", &user), ("PolicyName", "p"), ("PolicyDocument", &policy)], None).await;
    let ak_resp = call_query("iam", "2010-05-08", "CreateAccessKey", &[("UserName", &user)], None).await;
    let akid = ak_resp.as_ref().ok().and_then(|r| s3::tags(&r.body, "AccessKeyId").into_iter().next()).unwrap_or_default();
    let auth = sig_header(&akid, "s3");
    let res = local_http("GET", &format!("/{bucket}/payroll.csv"), &[("authorization", &auth)], b"").await;
    // cleanup
    let _ = call_query("iam", "2010-05-08", "DeleteUserPolicy", &[("UserName", &user), ("PolicyName", "p")], None).await;
    if !akid.is_empty() {
        let _ = call_query("iam", "2010-05-08", "DeleteAccessKey", &[("UserName", &user), ("AccessKeyId", &akid)], None).await;
    }
    let _ = call_query("iam", "2010-05-08", "DeleteUser", &[("UserName", &user)], None).await;
    let _ = local_http("DELETE", &format!("/{bucket}/payroll.csv"), &[], b"").await;
    let _ = local_http("DELETE", &format!("/{bucket}"), &[], b"").await;

    let repro = vec![repro_step("GET", &format!("/{bucket}/payroll.csv"), &[("authorization", &auth)], "")];
    match res {
        Ok(r) if *ENFORCE => {
            let (ok, msg) = judge(&json!({"status": 403, "error_code": "AccessDenied"}), r.status, r.error_code.as_deref(), &r.body);
            make_result("sec-iam-explicit-deny", "IAM 명시적 거부(Deny) 우선 차단", "security", "critical", "s3", ok, ok,
                if ok { "Allow *가 있어도 명시적 Deny가 s3:GetObject를 403 AccessDenied로 차단했습니다.".into() } else { msg },
                t0.elapsed().as_secs_f64() * 1000.0, json!({"status": 403, "error_code": "AccessDenied"}),
                json!({"status": r.status, "error_code": r.error_code}), repro)
        }
        Ok(r) => make_result("sec-iam-explicit-deny", "IAM 명시적 거부(Deny) 우선 차단", "security", "info", "s3", true, false,
            format!("ENFORCE_IAM=0 모드라 요청(HTTP {})이 보고만 됐습니다.", r.status),
            t0.elapsed().as_secs_f64() * 1000.0, json!({"enforced": false}), json!({"status": r.status}), repro),
        Err(e) => make_result("sec-iam-explicit-deny", "IAM 명시적 거부(Deny) 우선 차단", "security", "critical", "s3", false, false, e,
            t0.elapsed().as_secs_f64() * 1000.0, json!({"status": 403}), json!({}), repro),
    }
}

async fn sc_s3_path_traversal(tag: &str) -> Value {
    let t0 = Instant::now();
    let bucket = format!("{PREFIX}trav-{tag}");
    let _ = local_http("PUT", &format!("/{bucket}"), &[], b"").await;
    let probes = [
        format!("/{bucket}/../../_admin/state"),
        format!("/{bucket}/%2e%2e/%2e%2e/etc/passwd"),
        format!("/{bucket}/a/../../../_agent/status"),
    ];
    let mut bad = vec![];
    let mut repro = vec![];
    for p in &probes {
        repro.push(repro_step("GET", p, &[], ""));
        match local_http("GET", p, &[], b"").await {
            Ok(r) => {
                if r.status == 200 || r.body.contains("\"dynamodb\"") || r.body.contains("root:x:") {
                    bad.push(format!("{p} → HTTP {} (경로 탈출 의심)", r.status));
                }
            }
            Err(e) => bad.push(format!("{p} → {e}")),
        }
    }
    let _ = local_http("DELETE", &format!("/{bucket}"), &[], b"").await;
    let ok = bad.is_empty();
    make_result("sec-s3-path-traversal", "S3 경로 조작(../, %2e%2e) 격리", "security", "high", "s3", ok, ok,
        if ok { "경로 조작 키 3건이 모두 버킷 경계나 관리 API를 탈출하지 못했습니다.".into() } else { bad.join("; ") },
        t0.elapsed().as_secs_f64() * 1000.0, json!({"status_in": [400, 404]}), json!({"failures": bad}), repro)
}

async fn sc_missing_sigv4() -> Value {
    let t0 = Instant::now();
    let probes: [(&str, Vec<(&str, &str)>); 2] = [
        ("서명 헤더 누락", vec![("x-amz-target", "DynamoDB_20120810.ListTables"), ("content-type", "application/x-amz-json-1.0"), ("x-rc-unsigned", "1")]),
        ("기형 SigV4 헤더", vec![("x-amz-target", "DynamoDB_20120810.ListTables"), ("content-type", "application/x-amz-json-1.0"), ("authorization", "AWS4-HMAC-SHA256 Credential=BAD")]),
    ];
    let mut bad = vec![];
    let mut repro = vec![];
    for (label, hdrs) in probes {
        repro.push(repro_step("POST", "/", &hdrs, "{}"));
        match local_http("POST", "/", &hdrs, b"{}").await {
            Ok(r) if r.status < 500 && r.headers.contains_key("x-amzn-requestid") && (!*crate::VERIFY || r.status >= 400) => {}
            Ok(r) => bad.push(format!("{label} → HTTP {}", r.status)),
            Err(e) => bad.push(format!("{label} → {e}")),
        }
    }
    let ok = bad.is_empty();
    make_result("sec-missing-sigv4", "서명 누락·기형 SigV4 안전 처리", "security", "medium", "iam", ok, false,
        if ok { if *crate::VERIFY { "서명 누락·기형 헤더 요청이 패닉이나 5xx 없이 거부됐습니다 (VERIFY_SIGV4=1)." } else { "서명 누락·기형 헤더 요청이 패닉이나 5xx 없이 처리됐습니다 (서명 검증은 VERIFY_SIGV4=1일 때만)." }.into() } else { bad.join("; ") },
        t0.elapsed().as_secs_f64() * 1000.0, json!({"status_lt": 500}), json!({"failures": bad}), repro)
}

async fn sc_oversize_payload() -> Value {
    let t0 = Instant::now();
    let limit_plus_one = (256usize << 20) + 1;
    let repro = vec![repro_step("POST", "/", &[("content-length", &limit_plus_one.to_string())], "{")];
    match send_oversize_probe(limit_plus_one).await {
        Ok(r) => {
            let ok = r.status == 413;
            make_result("sec-oversize-payload", "과대 페이로드(256 MiB 초과) 거부", "security", "high", "s3", ok, ok,
                if ok { "256 MiB+1 요청이 413 Payload Too Large로 즉시 거부됐습니다.".into() } else { format!("기대 413, 실제 HTTP {}", r.status) },
                t0.elapsed().as_secs_f64() * 1000.0, json!({"status": 413}), json!({"status": r.status}), repro)
        }
        Err(e) => make_result("sec-oversize-payload", "과대 페이로드(256 MiB 초과) 거부", "security", "high", "s3", false, false, e,
            t0.elapsed().as_secs_f64() * 1000.0, json!({"status": 413}), json!({}), repro),
    }
}

async fn sc_injection_input(tag: &str) -> Value {
    let t0 = Instant::now();
    let pname = format!("/{PREFIX}inj-{tag}");
    let payload = "]]><Code>Hacked</Code><script>alert(1)</script>' OR 1=1 --";
    let put = call_json("ssm", "PutParameter", &json!({"Name": pname, "Value": payload, "Type": "String", "Overwrite": true}), None).await;
    let get = call_json("ssm", "GetParameter", &json!({"Name": pname}), None).await;
    let _ = call_json("ssm", "DeleteParameter", &json!({"Name": pname}), None).await;
    let repro = vec![repro_step("POST", "/", &[("x-amz-target", "AmazonSSM.PutParameter")], &json!({"Name": pname, "Value": payload, "Type": "String"}).to_string())];
    match (put, get) {
        (Ok(p), Ok(g)) if p.status == 200 && g.status == 200 => {
            let v: Value = serde_json::from_str(&g.body).unwrap_or_default();
            let got = v["Parameter"]["Value"].as_str().unwrap_or("");
            let ok = got == payload;
            make_result("sec-injection-input", "인젝션성 입력(XML·SQL·XSS) 무변조 격리", "security", "medium", "ssm", ok, false,
                if ok { "특수문자·XML 태그 입력이 5xx 없이 그대로 안전하게 저장·조회됐습니다.".into() } else { "저장된 값이 변조됐습니다.".into() },
                t0.elapsed().as_secs_f64() * 1000.0, json!({"status": 200}), json!({"status": g.status}), repro)
        }
        (p, g) => make_result("sec-injection-input", "인젝션성 입력(XML·SQL·XSS) 무변조 격리", "security", "medium", "ssm", false, false,
            format!("put={p:?}, get={g:?}"), t0.elapsed().as_secs_f64() * 1000.0, json!({"status": 200}), json!({}), repro),
    }
}

async fn sc_chaos_throttle(app: &App) -> Value {
    let t0 = Instant::now();
    let prev = app.chaos.lock().unwrap().clone();
    *app.chaos.lock().unwrap() = vec![json!({"service": "dynamodb", "op": "ListTables", "throttle_rate": 1.0})];
    let hit = call_json("dynamodb", "ListTables", &json!({}), None).await;
    *app.chaos.lock().unwrap() = prev;
    let recovered = call_json("dynamodb", "ListTables", &json!({}), None).await;
    let repro = vec![repro_step("POST", "/", &[("x-amz-target", "DynamoDB_20120810.ListTables")], "{}")];
    match (hit, recovered) {
        (Ok(h), Ok(r)) => {
            let (ok1, m1) = judge(&json!({"status": 400, "error_code": "ProvisionedThroughputExceededException"}), h.status, h.error_code.as_deref(), &h.body);
            let ok2 = r.status == 200;
            let ok = ok1 && ok2;
            make_result("chaos-throttle-recovery", "장애 주입(스로틀링) 및 해제 후 복구", "chaos", "medium", "dynamodb", ok, false,
                if ok { "스로틀링 주입 시 ProvisionedThroughputExceededException 반환, 해제 후 200 복구 확인.".into() } else { format!("주입: {m1}, 복구 HTTP {}", r.status) },
                t0.elapsed().as_secs_f64() * 1000.0, json!({"status": 400, "error_code": "ProvisionedThroughputExceededException"}),
                json!({"hit_status": h.status, "hit_code": h.error_code, "recovered_status": r.status}), repro)
        }
        (a, b) => make_result("chaos-throttle-recovery", "장애 주입(스로틀링) 및 해제 후 복구", "chaos", "medium", "dynamodb", false, false,
            format!("{a:?} / {b:?}"), t0.elapsed().as_secs_f64() * 1000.0, json!({"status": 400}), json!({}), repro),
    }
}

async fn sc_chaos_5xx(app: &App) -> Value {
    let t0 = Instant::now();
    let prev = app.chaos.lock().unwrap().clone();
    *app.chaos.lock().unwrap() = vec![json!({"service": "s3", "op": "ListBuckets", "error_rate": 1.0})];
    let hit = local_http("GET", "/", &[], b"").await;
    *app.chaos.lock().unwrap() = prev;
    let recovered = local_http("GET", "/", &[], b"").await;
    let repro = vec![repro_step("GET", "/", &[], "")];
    match (hit, recovered) {
        (Ok(h), Ok(r)) => {
            let (ok1, m1) = judge(&json!({"status": 500, "error_code": "InternalError"}), h.status, h.error_code.as_deref(), &h.body);
            let ok2 = r.status == 200;
            let ok = ok1 && ok2;
            make_result("chaos-5xx-recovery", "장애 주입(S3 500) 및 해제 후 복구", "chaos", "medium", "s3", ok, false,
                if ok { "S3 500 InternalError 주입 확인, 해제 후 200 복구 확인.".into() } else { format!("주입: {m1}, 복구 HTTP {}", r.status) },
                t0.elapsed().as_secs_f64() * 1000.0, json!({"status": 500, "error_code": "InternalError"}),
                json!({"hit_status": h.status, "hit_code": h.error_code, "recovered_status": r.status}), repro)
        }
        (a, b) => make_result("chaos-5xx-recovery", "장애 주입(S3 500) 및 해제 후 복구", "chaos", "medium", "s3", false, false,
            format!("{a:?} / {b:?}"), t0.elapsed().as_secs_f64() * 1000.0, json!({"status": 500}), json!({}), repro),
    }
}

async fn sc_dlq_buildup(tag: &str) -> Value {
    let t0 = Instant::now();
    let dlq_name = format!("{PREFIX}dlq-{tag}");
    let q_name = format!("{PREFIX}main-{tag}");
    let dlq_r = call_json("sqs", "CreateQueue", &json!({"QueueName": dlq_name}), None).await;
    let dlq_url = dlq_r.as_ref().ok().and_then(|r| serde_json::from_str::<Value>(&r.body).ok()).and_then(|v| v["QueueUrl"].as_str().map(String::from)).unwrap_or_default();
    let dlq_arn = format!("arn:aws:sqs:{}:{ACCOUNT}:{dlq_name}", *REGION);
    let redrive = json!({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": "2"}).to_string();
    let q_r = call_json("sqs", "CreateQueue", &json!({"QueueName": q_name, "Attributes": {"VisibilityTimeout": "0", "RedrivePolicy": redrive}}), None).await;
    let q_url = q_r.as_ref().ok().and_then(|r| serde_json::from_str::<Value>(&r.body).ok()).and_then(|v| v["QueueUrl"].as_str().map(String::from)).unwrap_or_default();

    let _ = call_json("sqs", "SendMessage", &json!({"QueueUrl": q_url, "MessageBody": "poison-pill"}), None).await;
    // Receive 3 times without deleting → moves to DLQ after 2 receives.
    for _ in 0..3 {
        let _ = call_json("sqs", "ReceiveMessage", &json!({"QueueUrl": q_url, "MaxNumberOfMessages": 1}), None).await;
    }
    let dlq_msg = call_json("sqs", "ReceiveMessage", &json!({"QueueUrl": dlq_url, "MaxNumberOfMessages": 1}), None).await;
    // cleanup
    if !q_url.is_empty() {
        let _ = call_json("sqs", "DeleteQueue", &json!({"QueueUrl": q_url}), None).await;
    }
    if !dlq_url.is_empty() {
        let _ = call_json("sqs", "DeleteQueue", &json!({"QueueUrl": dlq_url}), None).await;
    }
    let repro = vec![repro_step("POST", "/", &[("x-amz-target", "AmazonSQS.SendMessage")], &json!({"QueueUrl": q_url, "MessageBody": "poison-pill"}).to_string())];
    match dlq_msg {
        Ok(r) => {
            let v: Value = serde_json::from_str(&r.body).unwrap_or_default();
            let body = v["Messages"][0]["Body"].as_str().unwrap_or("");
            let ok = r.status == 200 && body == "poison-pill";
            make_result("inc-dlq-buildup", "SQS 반복 실패 → DLQ 적체 확인", "incident", "high", "sqs", ok, false,
                if ok { "maxReceiveCount=2 초과 후 독성 메시지가 DLQ로 정상 이동했습니다.".into() } else { format!("DLQ 수신 실패: HTTP {} {}", r.status, r.body) },
                t0.elapsed().as_secs_f64() * 1000.0, json!({"body_contains": "poison-pill"}), json!({"status": r.status, "dlq_body": body}), repro)
        }
        Err(e) => make_result("inc-dlq-buildup", "SQS 반복 실패 → DLQ 적체 확인", "incident", "high", "sqs", false, false, e,
            t0.elapsed().as_secs_f64() * 1000.0, json!({"status": 200}), json!({}), repro),
    }
}

fn make_py_zip(code: &str) -> Result<String, String> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut zw = zip::ZipWriter::new(&mut buf);
        zw.start_file("index.py", zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored))
            .map_err(|e| e.to_string())?;
        zw.write_all(code.as_bytes()).map_err(|e| e.to_string())?;
        zw.finish().map_err(|e| e.to_string())?;
    }
    Ok(b64(&buf.into_inner()))
}

async fn sc_lambda_repeated_fail(tag: &str) -> Value {
    let t0 = Instant::now();
    let fname = format!("{PREFIX}fail-{tag}");
    let z = match make_py_zip("def handler(event, ctx):\n    raise RuntimeError('inspector-boom')\n") {
        Ok(z) => z,
        Err(e) => return make_result("inc-lambda-repeated-fail", "Lambda 반복 실패 및 에러 로그 기록", "incident", "medium", "lambda", false, false, e, 0.0, json!({}), json!({}), vec![]),
    };
    let create_body = json!({
        "FunctionName": fname, "Runtime": "python3.12",
        "Role": format!("arn:aws:iam::{ACCOUNT}:role/r"),
        "Handler": "index.handler", "Code": {"ZipFile": z}
    });
    let auth = sig_header("root", "lambda");
    let cr = local_http("POST", "/2015-03-31/functions", &[("content-type", "application/json"), ("authorization", &auth)], create_body.to_string().as_bytes()).await;
    let mut unhandled = 0usize;
    for _ in 0..3 {
        if let Ok(r) = local_http("POST", &format!("/2015-03-31/functions/{fname}/invocations"), &[("authorization", &auth)], b"{}").await {
            if r.headers.get("x-amz-function-error").map(String::as_str) == Some("Unhandled") {
                unhandled += 1;
            }
        }
    }
    let log_group = format!("/aws/lambda/{fname}");
    let logs_r = call_json("logs", "FilterLogEvents", &json!({"logGroupName": log_group}), None).await;
    let logged = logs_r.as_ref().is_ok_and(|r| r.status == 200 && r.body.contains("inspector-boom"));
    // cleanup
    let _ = local_http("DELETE", &format!("/2015-03-31/functions/{fname}"), &[("authorization", &auth)], b"").await;
    let _ = call_json("logs", "DeleteLogGroup", &json!({"logGroupName": log_group}), None).await;

    let repro = vec![repro_step("POST", &format!("/2015-03-31/functions/{fname}/invocations"), &[], "{}")];
    let ok = cr.is_ok_and(|r| r.status < 300) && unhandled == 3 && logged;
    make_result("inc-lambda-repeated-fail", "Lambda 반복 실패 및 에러 로그 기록", "incident", "medium", "lambda", ok, false,
        if ok { "Lambda 3회 연속 예외 발생 시 모두 Unhandled 반환 및 CloudWatch Logs 기록 확인.".into() }
        else { format!("Unhandled={unhandled}/3, 로그 기록={logged}") },
        t0.elapsed().as_secs_f64() * 1000.0, json!({"unhandled": 3, "logged": true}),
        json!({"unhandled": unhandled, "logged": logged}), repro)
}

async fn sc_perf_concurrent(tag: &str) -> Value {
    let t0 = Instant::now();
    let tname = format!("{PREFIX}perf-{tag}");
    let _ = call_json("dynamodb", "CreateTable", &json!({
        "TableName": tname, "BillingMode": "PAY_PER_REQUEST",
        "KeySchema": [{"AttributeName": "id", "KeyType": "HASH"}],
        "AttributeDefinitions": [{"AttributeName": "id", "AttributeType": "S"}]
    }), None).await;
    let burst_t0 = Instant::now();
    let mut futs = vec![];
    for i in 0..20 {
        let tn = tname.clone();
        futs.push(tokio::spawn(async move {
            let p = call_json("dynamodb", "PutItem", &json!({"TableName": tn, "Item": {"id": {"S": format!("k{i}")}, "v": {"N": i.to_string()}}}), None).await;
            let g = call_json("dynamodb", "GetItem", &json!({"TableName": tn, "Key": {"id": {"S": format!("k{i}")}}}), None).await;
            (p.is_ok_and(|r| r.status == 200), g.is_ok_and(|r| r.status == 200))
        }));
    }
    let mut ok_cnt = 0usize;
    for f in futs {
        if let Ok((a, b)) = f.await {
            if a { ok_cnt += 1; }
            if b { ok_cnt += 1; }
        }
    }
    let burst_ms = burst_t0.elapsed().as_secs_f64() * 1000.0;
    let rps = if burst_ms > 0.0 { 40.0 / (burst_ms / 1000.0) } else { 0.0 };
    let _ = call_json("dynamodb", "DeleteTable", &json!({"TableName": tname}), None).await;

    let ok = ok_cnt == 40;
    make_result("perf-concurrent-burst", "동시 요청 처리량 (40건 병렬)", "perf", "low", "dynamodb", ok, false,
        format!("{ok_cnt}/40 성공 · {:.1}ms ({:.0} req/s)", burst_ms, rps),
        t0.elapsed().as_secs_f64() * 1000.0, json!({"succeeded": 40}),
        json!({"succeeded": ok_cnt, "burst_ms": (burst_ms * 10.0).round() / 10.0, "rps": rps.round()}), vec![])
}

async fn sc_fuzz_random() -> Value {
    let t0 = Instant::now();
    let cases: Vec<(&str, &str, Vec<(&str, &str)>, &[u8])> = vec![
        ("POST", "/", vec![("x-amz-target", "DynamoDB_20120810.PutItem")], b"{broken json"),
        ("POST", "/", vec![("x-amz-target", "DynamoDB_20120810.NoSuchOp")], b"{}"),
        ("POST", "/", vec![("x-amz-target", "AmazonSQS.SendMessage")], b""),
        ("POST", "/", vec![("x-amz-target", "AmazonSSM.PutParameter")], b"null"),
        ("POST", "/", vec![("x-amz-target", "TrentService.Decrypt")], b"{\"CiphertextBlob\":\"!!!not-b64!!!\"}"),
        ("POST", "/", vec![("x-amz-target", "AWSStepFunctions.StartExecution")], b"{\"stateMachineArn\":\"bad\"}"),
        ("POST", "/", vec![("content-type", "application/x-www-form-urlencoded")], b"Action=NoSuchAction&Version=2010-05-08"),
        ("POST", "/", vec![("content-type", "application/x-www-form-urlencoded")], b"Action=&Version=2016-11-15"),
        ("GET", "/%ZZ%99/bad%20key?list-type=2&max-keys=abc", vec![], b""),
        ("PUT", "/nonexistent-bucket-zz/key", vec![], b"\x00\x01\x02\xff\xfe"),
        ("DELETE", "/nonexistent-bucket-zz", vec![], b""),
        ("POST", "/2015-03-31/functions/nope/invocations", vec![("authorization", "AWS4-HMAC-SHA256 Credential=a/b/c/lambda/d")], b"{{{{"),
        ("GET", "/_admin/reach?from=a&to=b&port=notanumber", vec![], b""),
        ("POST", "/_api/nope/hello", vec![], b"garbage"),
        ("PATCH", "/weird/path/here", vec![], b"[]"),
    ];
    let mut crashed = vec![];
    let mut repro = vec![];
    for (m, p, h, b) in cases {
        match local_http(m, p, &h, b).await {
            Ok(r) if r.status > 0 && r.status < 500 || r.status == 501 => {}
            Ok(r) => {
                crashed.push(format!("{m} {p} → HTTP {}", r.status));
                repro.push(repro_step(m, p, &h, &String::from_utf8_lossy(b)));
            }
            Err(e) => {
                crashed.push(format!("{m} {p} → {e}"));
                repro.push(repro_step(m, p, &h, &String::from_utf8_lossy(b)));
            }
        }
    }
    let alive = local_http("GET", "/_admin/state", &[], b"").await.is_ok_and(|r| r.status == 200);
    let ok = crashed.is_empty() && alive;
    make_result("fuzz-random-inputs", "무작위·기형 입력 퍼징 (15건)", "fuzz", "high", "dynamodb", ok, false,
        if ok { "기형 입력 15건 모두 5xx 패닉 없이 처리됐고 서버 헬스체크(200) 정상.".into() }
        else { format!("생존={alive}, 이상 응답: {}", crashed.join("; ")) },
        t0.elapsed().as_secs_f64() * 1000.0, json!({"status_lt": 500, "alive": true}),
        json!({"alive": alive, "crashed": crashed}), repro)
}

// ---------- generic replay / regression / LLM scenario runner ----------

pub async fn run_custom_scenario(sc: &Value) -> Value {
    let t0 = Instant::now();
    let id = sc["id"].as_str().unwrap_or("custom");
    let name = sc["name"].as_str().unwrap_or(id);
    let kind = sc["kind"].as_str().unwrap_or("regression");
    let severity = sc["severity"].as_str().unwrap_or("medium");
    let service = sc["service"].as_str().unwrap_or("dynamodb");
    let expect = &sc["expect"];

    // Either raw HTTP steps (`repro` or `steps` with `method`) or JSON-service `steps` with `service`/`op`.
    let steps = sc["steps"].as_array().or_else(|| sc["repro"].as_array()).cloned().unwrap_or_default();
    if steps.is_empty() || steps.len() > 20 {
        return make_result(id, name, kind, severity, service, false, false, "스텝이 비어 있거나 20개를 초과했습니다.".into(),
            0.0, expect.clone(), json!({}), vec![]);
    }
    let mut last: Option<HttpResp> = None;
    let mut repro = vec![];
    for st in &steps {
        let res = if let Some(m) = st["method"].as_str() {
            let p = st["path"].as_str().unwrap_or("/");
            let hdr_owned: Vec<(String, String)> = st["headers"].as_array().into_iter().flatten()
                .filter_map(|x| Some((x[0].as_str()?.to_string(), x[1].as_str()?.to_string()))).collect();
            let hdrs: Vec<(&str, &str)> = hdr_owned.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            let body = st["body"].as_str().unwrap_or("");
            repro.push(repro_step(m, p, &hdrs, body));
            local_http(m, p, &hdrs, body.as_bytes()).await
        } else {
            let svc = st["service"].as_str().unwrap_or(service);
            let op = st["op"].as_str().unwrap_or("");
            let params = if st["params"].is_object() { st["params"].clone() } else { json!({}) };
            let pre = json_target_prefix(svc).unwrap_or("");
            repro.push(repro_step("POST", "/", &[("x-amz-target", &format!("{pre}{op}")), ("content-type", "application/x-amz-json-1.0")], &params.to_string()));
            call_json(svc, op, &params, None).await
        };
        match res {
            Ok(r) => last = Some(r),
            Err(e) => {
                return make_result(id, name, kind, severity, service, false, false, e,
                    t0.elapsed().as_secs_f64() * 1000.0, expect.clone(), json!({}), repro);
            }
        }
    }
    let r = last.unwrap();
    let (ok, msg) = judge(expect, r.status, r.error_code.as_deref(), &r.body);
    make_result(id, name, kind, severity, service, ok, ok && r.status == 403, msg,
        t0.elapsed().as_secs_f64() * 1000.0, expect.clone(),
        json!({"status": r.status, "error_code": r.error_code}), repro)
}

// ---------- regressions directory ----------

fn regressions_dir() -> PathBuf {
    for cand in ["tests/regressions", "../tests/regressions"] {
        let p = Path::new(cand);
        if p.exists() || p.parent().is_some_and(Path::exists) {
            return p.to_path_buf();
        }
    }
    PathBuf::from("tests/regressions")
}

fn load_regressions() -> Vec<Value> {
    let dir = regressions_dir();
    let Ok(rd) = std::fs::read_dir(&dir) else { return vec![] };
    let mut files: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.extension().is_some_and(|e| e == "json")).collect();
    files.sort();
    files.into_iter().filter_map(|p| std::fs::read_to_string(p).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok())).collect()
}

fn save_regression(res: &Value) -> Option<String> {
    let dir = regressions_dir();
    std::fs::create_dir_all(&dir).ok()?;
    let id = res["id"].as_str().unwrap_or("case").chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect::<String>();
    let path = dir.join(format!("{id}.json"));
    let doc = json!({
        "id": id, "name": res["name"], "kind": "regression", "severity": res["severity"],
        "service": res["service"], "expect": res["expect"], "repro": res["repro"],
    });
    std::fs::write(&path, serde_json::to_string_pretty(&doc).ok()?).ok()?;
    Some(path.to_string_lossy().into_owned())
}

// ---------- optional LLM scenario generator ----------

const DESTRUCTIVE_OPS: &[&str] = &["Delete", "Purge", "Terminate", "Remove", "Stop", "Disable", "Schedule", "Detach", "Deregister", "Revoke"];

fn llm_scenario_schema() -> Value {
    json!({
        "type": "object",
        "required": ["scenarios"],
        "properties": {
            "scenarios": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["name", "kind", "severity", "service", "op", "params", "expect_status"],
                    "properties": {
                        "name": {"type": "string"},
                        "kind": {"type": "string", "enum": ["security", "incident", "fuzz"]},
                        "severity": {"type": "string", "enum": ["high", "medium", "low"]},
                        "service": {"type": "string", "enum": ["dynamodb", "sqs", "ssm", "secretsmanager", "kms", "logs", "kinesis", "states"]},
                        "op": {"type": "string", "pattern": "^[A-Z][A-Za-z0-9]+$"},
                        "params": {"type": "object"},
                        "expect_status": {"type": "integer"}
                    }
                }
            }
        }
    })
}

async fn generate_llm_scenarios(app: &App) -> (Vec<Value>, Option<String>) {
    let counts = json!({
        "dynamodb": app.ddb.lock().unwrap().admin().as_array().map_or(0, Vec::len),
        "sqs": app.sqs.lock().unwrap().admin().as_array().map_or(0, Vec::len),
        "ssm": app.ssm.lock().unwrap().admin().as_array().map_or(0, Vec::len),
        "kms": app.kms.lock().unwrap().admin().as_array().map_or(0, Vec::len),
    });
    let sys = "너는 로컬 클라우드 에뮬레이터 rocalcloud의 보안·안정성 검증 시나리오 생성기다. JSON으로만 답한다. 존재하지 않는 리소스(이름에 rc-insp- 접두사 사용)나 잘못된 파라미터로 오류 처리를 시험하는 안전한 시나리오 2개만 제안해라. 삭제(Delete/Purge) 작업은 쓰지 마라.";
    let usr = format!("현재 리소스 개수: {counts}. 경계값·오류 처리 테스트 시나리오 2개를 만들어라. 기대 상태코드가 확실하지 않으면 expect_status를 0(5xx 미만이면 통과)으로 두어라.");
    let raw = match agent::chat(&[json!({"role": "system", "content": sys}), json!({"role": "user", "content": usr})], Some(&llm_scenario_schema())).await {
        Ok(r) => r,
        Err(e) => return (vec![], Some(e)),
    };
    let Ok(v) = serde_json::from_str::<Value>(&raw) else {
        return (vec![], Some("LLM 응답 JSON 파싱 실패".into()));
    };
    let mut out = vec![];
    for (i, s) in v["scenarios"].as_array().into_iter().flatten().take(3).enumerate() {
        let op = s["op"].as_str().unwrap_or("");
        if op.is_empty() || DESTRUCTIVE_OPS.iter().any(|d| op.starts_with(d)) {
            continue; // safety guard: never let LLM propose destructive ops
        }
        let exp = match s["expect_status"].as_u64() {
            Some(c) if (200..600).contains(&c) => json!({"status": c}),
            _ => json!({"status_lt": 500}),
        };
        out.push(json!({
            "id": format!("llm-{}", i + 1),
            "name": s["name"].as_str().unwrap_or("LLM 제안 시나리오"),
            "kind": s["kind"].as_str().unwrap_or("fuzz"),
            "severity": s["severity"].as_str().unwrap_or("low"),
            "service": s["service"].as_str().unwrap_or("dynamodb"),
            "steps": [{"service": s["service"], "op": op, "params": s["params"]}],
            "expect": exp,
        }));
    }
    (out, None)
}

// ---------- main runner ----------

pub async fn run(app: &Arc<App>, req: &Value) -> Result<Value, ApiErr> {
    loopback_hostport().map_err(|e| ApiErr { status: 400, ..err("SafetyViolation", e) })?;
    {
        let mut ins = app.inspector.lock().unwrap();
        if ins.running {
            return Err(ApiErr { status: 409, ..err("InspectorBusy", "검사가 이미 실행 중입니다.") });
        }
        ins.running = true;
    }
    let res = run_inner(app, req).await;
    app.inspector.lock().unwrap().running = false;
    res
}

async fn run_inner(app: &Arc<App>, req: &Value) -> Result<Value, ApiErr> {
    let t0 = Instant::now();
    let run_id = uuid::Uuid::new_v4().simple().to_string()[..10].to_string();
    let tag = &run_id[..6];
    let use_llm = req["use_llm"] == true;
    let save_reg = req["save_regressions"] == true;
    let max_n = req["max_scenarios"].as_u64().map_or(MAX_SCENARIOS, |n| (n as usize).clamp(1, MAX_SCENARIOS));
    let timeout = Duration::from_secs(req["timeout_secs"].as_u64().map_or(MAX_TIMEOUT_SECS, |s| s.clamp(5, MAX_TIMEOUT_SECS)));

    let all_kinds = ["security", "chaos", "incident", "perf", "fuzz", "regression"];
    let wanted: Vec<String> = req["kinds"].as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .filter(|v: &Vec<String>| !v.is_empty())
        .unwrap_or_else(|| all_kinds.iter().map(|s| s.to_string()).collect());
    let has = |k: &str| wanted.iter().any(|x| x == k);

    let mut plan: Vec<(&'static str, &'static str)> = vec![];
    if has("security") {
        plan.extend([
            ("sec-admin-csrf", "security"),
            ("sec-iam-implicit-deny", "security"),
            ("sec-iam-explicit-deny", "security"),
            ("sec-s3-path-traversal", "security"),
            ("sec-missing-sigv4", "security"),
            ("sec-oversize-payload", "security"),
            ("sec-injection-input", "security"),
        ]);
    }
    if has("chaos") {
        plan.extend([("chaos-throttle-recovery", "chaos"), ("chaos-5xx-recovery", "chaos")]);
    }
    if has("incident") {
        plan.extend([("inc-dlq-buildup", "incident"), ("inc-lambda-repeated-fail", "incident")]);
    }
    if has("perf") {
        plan.push(("perf-concurrent-burst", "perf"));
    }
    if has("fuzz") {
        plan.push(("fuzz-random-inputs", "fuzz"));
    }

    let regressions = if has("regression") { load_regressions() } else { vec![] };
    let (llm_scenarios, llm_note) = if use_llm { generate_llm_scenarios(app).await } else { (vec![], None) };
    let total = (plan.len() + regressions.len() + llm_scenarios.len()).min(max_n);

    emit(app, json!({"ts": chrono::Utc::now().to_rfc3339(), "service": "inspector", "op": "RunStarted",
        "run_id": run_id, "total": total, "status": 200}));

    let mut results = vec![];
    let mut regs_saved = vec![];
    let mut timed_out = false;

    for (id, _) in plan {
        if results.len() >= max_n || t0.elapsed() >= timeout {
            timed_out = t0.elapsed() >= timeout;
            break;
        }
        let r = match id {
            "sec-admin-csrf" => sc_admin_csrf().await,
            "sec-iam-implicit-deny" => sc_iam_implicit_deny(tag).await,
            "sec-iam-explicit-deny" => sc_iam_explicit_deny(tag).await,
            "sec-s3-path-traversal" => sc_s3_path_traversal(tag).await,
            "sec-missing-sigv4" => sc_missing_sigv4().await,
            "sec-oversize-payload" => sc_oversize_payload().await,
            "sec-injection-input" => sc_injection_input(tag).await,
            "chaos-throttle-recovery" => sc_chaos_throttle(app).await,
            "chaos-5xx-recovery" => sc_chaos_5xx(app).await,
            "inc-dlq-buildup" => sc_dlq_buildup(tag).await,
            "inc-lambda-repeated-fail" => sc_lambda_repeated_fail(tag).await,
            "perf-concurrent-burst" => sc_perf_concurrent(tag).await,
            "fuzz-random-inputs" => sc_fuzz_random().await,
            _ => continue,
        };
        if save_reg && r["passed"] == false {
            if let Some(p) = save_regression(&r) {
                regs_saved.push(p);
            }
        }
        emit_scenario(app, &run_id, &r, results.len() + 1, total);
        results.push(r);
    }

    for sc in regressions.into_iter().chain(llm_scenarios.iter().cloned()) {
        if results.len() >= max_n || t0.elapsed() >= timeout {
            timed_out = t0.elapsed() >= timeout;
            break;
        }
        let r = run_custom_scenario(&sc).await;
        if save_reg && r["passed"] == false {
            if let Some(p) = save_regression(&r) {
                regs_saved.push(p);
            }
        }
        emit_scenario(app, &run_id, &r, results.len() + 1, total);
        results.push(r);
    }

    let passed = results.iter().filter(|r| r["passed"] == true).count();
    let failed = results.len() - passed;
    let mut by_sev = json!({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0});
    for r in &results {
        if r["passed"] == false {
            let s = r["severity"].as_str().unwrap_or("medium");
            by_sev[s] = json!(by_sev[s].as_u64().unwrap_or(0) + 1);
        }
    }
    let duration_ms = (t0.elapsed().as_secs_f64() * 10000.0).round() / 10.0;
    let report = json!({
        "id": run_id,
        "started_at": chrono::Utc::now().to_rfc3339(),
        "duration_ms": duration_ms,
        "enforce_iam": *ENFORCE,
        "timed_out": timed_out,
        "llm_generated": llm_scenarios.len(),
        "llm_note": llm_note,
        "regressions_saved": regs_saved,
        "summary": {"total": results.len(), "passed": passed, "failed": failed, "failed_by_severity": by_sev},
        "results": results,
    });
    {
        let mut ins = app.inspector.lock().unwrap();
        if ins.history.len() >= MAX_HISTORY {
            ins.history.remove(0);
        }
        ins.history.push(report.clone());
    }
    emit(app, json!({"ts": chrono::Utc::now().to_rfc3339(), "service": "inspector", "op": "RunFinished",
        "run_id": run_id, "passed": passed, "failed": failed, "total": results.len(), "duration_ms": duration_ms,
        "status": if failed == 0 { 200 } else { 500 }}));
    Ok(report)
}

fn emit_scenario(app: &App, run_id: &str, r: &Value, index: usize, total: usize) {
    emit(app, json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "service": "inspector",
        "op": "ScenarioDone",
        "run_id": run_id,
        "scenario": r["id"],
        "name": r["name"],
        "kind": r["kind"],
        "severity": r["severity"],
        "target_service": r["service"],
        "passed": r["passed"],
        "blocked": r["blocked"],
        "index": index,
        "total": total,
        "ms": r["elapsed_ms"],
        "status": if r["passed"] == true { 200 } else { 500 },
    }));
}

pub fn reports_summary(app: &App) -> Value {
    let ins = app.inspector.lock().unwrap();
    let runs: Vec<Value> = ins.history.iter().rev().map(|r| json!({
        "id": r["id"], "started_at": r["started_at"], "duration_ms": r["duration_ms"],
        "summary": r["summary"], "llm_generated": r["llm_generated"],
    })).collect();
    json!({"running": ins.running, "runs": runs, "latest": ins.history.last()})
}

pub fn get_report(app: &App, id: &str) -> Option<Value> {
    app.inspector.lock().unwrap().history.iter().find(|r| r["id"] == id).cloned()
}

// ---------- report export (Markdown / HTML) ----------

pub fn to_markdown(r: &Value) -> String {
    let mut s = format!("# rocalcloud 검증 리포트 ({})\n\n", r["id"].as_str().unwrap_or(""));
    s.push_str(&format!("- 실행 시각: {}\n- 소요 시간: {} ms\n- ENFORCE_IAM: {}\n- 결과: **통과 {} / 전체 {}** (실패 {})\n\n",
        r["started_at"].as_str().unwrap_or(""), r["duration_ms"], r["enforce_iam"],
        r["summary"]["passed"], r["summary"]["total"], r["summary"]["failed"]));
    s.push_str("| 심각도 | 분류 | 시나리오 | 결과 | ms | 상세 |\n|---|---|---|---|---|---|\n");
    for x in r["results"].as_array().into_iter().flatten() {
        let pass = if x["passed"] == true { "PASS" } else { "**FAIL**" };
        s.push_str(&format!("| {} | {} | {} | {} | {} | {} |\n",
            x["severity"].as_str().unwrap_or(""), x["kind"].as_str().unwrap_or(""),
            x["name"].as_str().unwrap_or(""), pass, x["elapsed_ms"],
            x["detail"].as_str().unwrap_or("").replace('|', "\\|")));
    }
    let fails: Vec<&Value> = r["results"].as_array().into_iter().flatten().filter(|x| x["passed"] == false).collect();
    if !fails.is_empty() {
        s.push_str("\n## 실패 시나리오 재현 요청\n\n");
        for f in fails {
            s.push_str(&format!("### {} ({})\n```json\n{}\n```\n\n",
                f["name"].as_str().unwrap_or(""), f["id"].as_str().unwrap_or(""),
                serde_json::to_string_pretty(&f["repro"]).unwrap_or_default()));
        }
    }
    s
}

pub fn to_html(r: &Value) -> String {
    let e = |v: &str| s3::esc(v);
    let mut rows = String::new();
    for x in r["results"].as_array().into_iter().flatten() {
        let ok = x["passed"] == true;
        rows.push_str(&format!(
            "<tr class=\"{}\"><td>{}</td><td>{}</td><td>{}</td><td><b>{}</b></td><td>{}</td><td>{}</td></tr>\n",
            if ok { "ok" } else { "bad" },
            e(x["severity"].as_str().unwrap_or("")), e(x["kind"].as_str().unwrap_or("")),
            e(x["name"].as_str().unwrap_or("")), if ok { "PASS" } else { "FAIL" },
            x["elapsed_ms"], e(x["detail"].as_str().unwrap_or(""))
        ));
    }
    format!(
        "<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\"><title>rocalcloud 검증 리포트 {}</title>\
         <style>body{{font:14px/1.5 ui-sans-serif,sans-serif;max-width:960px;margin:24px auto;padding:0 16px}}\
         table{{border-collapse:collapse;width:100%}}th,td{{border-bottom:1px solid #ddd;padding:6px 8px;text-align:left}}\
         tr.ok b{{color:#2f7d4f}}tr.bad b{{color:#b3261e}}</style></head><body>\
         <h1>rocalcloud 검증 리포트 ({})</h1>\
         <p>실행 시각: {} · 소요: {} ms · 통과 {}/{} (실패 {})</p>\
         <table><thead><tr><th>심각도</th><th>분류</th><th>시나리오</th><th>결과</th><th>ms</th><th>상세</th></tr></thead>\
         <tbody>{rows}</tbody></table></body></html>",
        e(r["id"].as_str().unwrap_or("")), e(r["id"].as_str().unwrap_or("")),
        e(r["started_at"].as_str().unwrap_or("")), r["duration_ms"],
        r["summary"]["passed"], r["summary"]["total"], r["summary"]["failed"]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_rules() {
        assert!(judge(&json!({"status": 403, "error_code": "AccessDenied"}), 403, Some("AccessDenied"), "").0);
        assert!(!judge(&json!({"status": 403, "error_code": "AccessDenied"}), 200, None, "").0);
        assert!(judge(&json!({"status_in": [400, 404]}), 404, None, "").0);
        assert!(judge(&json!({"status_lt": 500, "body_not_contains": "root:x:"}), 404, None, "NoSuchKey").0);
        assert!(!judge(&json!({"body_not_contains": "root:x:"}), 200, None, "root:x:0:0").0);
    }

    #[test]
    fn export_formats() {
        let rep = json!({
            "id": "abc123", "started_at": "2026-11-20T00:00:00Z", "duration_ms": 12.3, "enforce_iam": true,
            "summary": {"total": 1, "passed": 1, "failed": 0},
            "results": [{"id": "s1", "name": "테스트", "kind": "security", "severity": "high", "passed": true, "elapsed_ms": 1.2, "detail": "ok", "repro": []}]
        });
        assert!(to_markdown(&rep).contains("| high | security | 테스트 | PASS |"));
        assert!(to_html(&rep).contains("<h1>rocalcloud 검증 리포트 (abc123)</h1>"));
    }
}

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
                None if path.starts_with("/2015-03-31/") || path.starts_with("/2019-09-25/") => "lambda",
                None if path.starts_with("/v2/") => "apigateway",
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

// A bucket policy Deny binds even the account root, but the root can always remove the policy (no lockout).
async fn sc_bucket_policy_deny(tag: &str) -> Value {
    let t0 = Instant::now();
    let bucket = format!("{PREFIX}bp-{tag}");
    let _ = local_http("PUT", &format!("/{bucket}"), &[], b"").await;
    let _ = local_http("PUT", &format!("/{bucket}/locked.txt"), &[], b"x").await;
    let policy = json!({"Statement": [{"Sid": "LockAll", "Effect": "Deny", "Principal": "*", "Action": "s3:GetObject",
        "Resource": format!("arn:aws:s3:::{bucket}/*")}]}).to_string();
    let put = local_http("PUT", &format!("/{bucket}?policy"), &[], policy.as_bytes()).await;
    let get = local_http("GET", &format!("/{bucket}/locked.txt"), &[], b"").await;
    let del = local_http("DELETE", &format!("/{bucket}?policy"), &[], b"").await;
    let after = local_http("GET", &format!("/{bucket}/locked.txt"), &[], b"").await;
    let _ = local_http("DELETE", &format!("/{bucket}/locked.txt"), &[], b"").await;
    let _ = local_http("DELETE", &format!("/{bucket}"), &[], b"").await;
    let st = |r: &Result<HttpResp, String>| r.as_ref().map(|r| r.status).unwrap_or(0);
    let repro = vec![
        repro_step("PUT", &format!("/{bucket}?policy"), &[], &policy),
        repro_step("GET", &format!("/{bucket}/locked.txt"), &[], ""),
    ];
    let observed = json!({"put_policy": st(&put), "denied_get": st(&get), "delete_policy": st(&del), "get_after_delete": st(&after)});
    if !*ENFORCE {
        return make_result("sec-bucket-policy-deny", "버킷 정책 Deny·잠김 방지", "security", "info", "s3", true, false,
            "ENFORCE_IAM=0 모드라 거부가 보고만 됩니다. 강제 검증은 ENFORCE_IAM=1로 실행하세요.".into(),
            t0.elapsed().as_secs_f64() * 1000.0, json!({"enforced": false}), observed, repro);
    }
    let ok = st(&put) == 204 && st(&get) == 403 && st(&del) == 204 && st(&after) == 200;
    let detail = if ok {
        "버킷 정책의 Deny가 루트의 GetObject도 403으로 막았고, 루트는 정책을 지워 접근을 되찾았습니다.".into()
    } else {
        format!("기대: 정책 등록 204 → 읽기 403 → 정책 삭제 204 → 읽기 200, 실제: {observed}")
    };
    make_result("sec-bucket-policy-deny", "버킷 정책 Deny·잠김 방지", "security", "high", "s3", ok, ok, detail,
        t0.elapsed().as_secs_f64() * 1000.0, json!({"put_policy": 204, "denied_get": 403, "delete_policy": 204, "get_after_delete": 200}), observed, repro)
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

// ---------- added scenarios: latency, partial failure, dropped connections, recreate-under-load, flood, limits, memory ----------

fn ms_since(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

fn json_body(r: &Result<HttpResp, String>) -> Value {
    r.as_ref().ok().and_then(|r| serde_json::from_str(&r.body).ok()).unwrap_or_default()
}

async fn sc_chaos_latency(app: &App) -> Value {
    let t0 = Instant::now();
    let prev = app.chaos.lock().unwrap().clone();
    *app.chaos.lock().unwrap() = vec![json!({"service": "dynamodb", "op": "ListTables", "latency_ms": 300})];
    let s = Instant::now();
    let hit = call_json("dynamodb", "ListTables", &json!({}), None).await;
    let slow = ms_since(s);
    *app.chaos.lock().unwrap() = prev;
    let s = Instant::now();
    let rec = call_json("dynamodb", "ListTables", &json!({}), None).await;
    let fast = ms_since(s);
    let ok = hit.is_ok_and(|r| r.status == 200) && rec.is_ok_and(|r| r.status == 200) && slow >= 300.0 && fast < 300.0;
    make_result("chaos-latency", "장애 주입(지연 300ms) 및 해제 후 복구", "chaos", "low", "dynamodb", ok, false,
        format!("주입 중 {slow:.0}ms, 해제 후 {fast:.0}ms"), ms_since(t0),
        json!({"latency_ms_gte": 300, "recovered_ms_lt": 300}), json!({"slow_ms": slow.round(), "fast_ms": fast.round()}),
        vec![repro_step("POST", "/", &[("x-amz-target", "DynamoDB_20120810.ListTables")], "{}")])
}

async fn sc_chaos_partial(app: &App) -> Value {
    let t0 = Instant::now();
    let prev = app.chaos.lock().unwrap().clone();
    *app.chaos.lock().unwrap() = vec![json!({"service": "sqs", "op": "ListQueues", "error_rate": 0.5})];
    let (mut ok_n, mut err_n, mut other) = (0, 0, vec![]);
    for _ in 0..30 {
        match call_json("sqs", "ListQueues", &json!({}), None).await {
            Ok(r) if r.status == 200 => ok_n += 1,
            Ok(r) if r.status == 500 => err_n += 1,
            Ok(r) => other.push(r.status.to_string()),
            Err(e) => other.push(e),
        }
    }
    *app.chaos.lock().unwrap() = prev;
    let ok = ok_n > 0 && err_n > 0 && other.is_empty();
    make_result("chaos-partial-failure", "부분 실패(오류율 50%) 주입", "chaos", "medium", "sqs", ok, false,
        format!("30건 중 성공 {ok_n}, 500 {err_n}{}", if other.is_empty() { String::new() } else { format!(", 예상 밖 {}", other.join(",")) }),
        ms_since(t0), json!({"both_outcomes": true, "only": [200, 500]}), json!({"ok": ok_n, "err500": err_n, "other": other}),
        vec![repro_step("POST", "/", &[("x-amz-target", "AmazonSQS.ListQueues")], "{}")])
}

async fn sc_conn_drop() -> Value {
    let t0 = Instant::now();
    let Ok(hostport) = loopback_hostport() else {
        return make_result("chaos-conn-drop", "연결 끊김(요청 도중 종료) 내성", "chaos", "high", "dynamodb", false, false,
            "로컬 대상이 아닙니다".into(), 0.0, json!({}), json!({}), vec![]);
    };
    let partial = [
        format!("POST / HTTP/1.1\r\nHost: {hostport}\r\nX-Amz-Target: DynamoDB_20120810.ListTables\r\nContent-Length: 100\r\n\r\n{{\"Tab"),
        "GET / HT".to_string(),
        format!("POST / HTTP/1.1\r\nHost: {hostport}\r\nX-Amz-Target: DynamoDB_20120810.ListTables\r\nContent-Type: application/x-amz-json-1.0\r\nContent-Length: 2\r\n\r\n{{}}"),
    ];
    let mut dropped = 0;
    for i in 0..12 {
        if let Ok(Ok(mut s)) = tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(&hostport)).await {
            let _ = s.write_all(partial[i % 3].as_bytes()).await;
            drop(s); // close without reading the response
            dropped += 1;
        }
    }
    tokio::time::sleep(Duration::from_millis(150)).await;
    let alive = local_http("GET", "/_admin/state", &[], b"").await.is_ok_and(|r| r.status == 200)
        && call_json("dynamodb", "ListTables", &json!({}), None).await.is_ok_and(|r| r.status == 200);
    let ok = alive && dropped == 12;
    make_result("chaos-conn-drop", "연결 끊김(요청 도중 종료) 내성", "chaos", "high", "dynamodb", ok, false,
        if ok { "요청 도중 끊은 연결 12건 뒤에도 서버가 정상 응답했습니다.".into() } else { format!("끊은 연결 {dropped}/12, 생존={alive}") },
        ms_since(t0), json!({"alive": true}), json!({"dropped": dropped, "alive": alive}),
        vec![repro_step("POST", "/", &[("x-amz-target", "DynamoDB_20120810.ListTables"), ("content-length", "100")], "{\"Tab")])
}

fn ddb_table(name: &str) -> Value {
    json!({"TableName": name, "BillingMode": "PAY_PER_REQUEST",
           "KeySchema": [{"AttributeName": "id", "KeyType": "HASH"}],
           "AttributeDefinitions": [{"AttributeName": "id", "AttributeType": "S"}]})
}

// "Restart while serving": the prefixed table is deleted and recreated while writers hit it.
async fn sc_recreate_under_load(tag: &str) -> Value {
    let t0 = Instant::now();
    let tname = format!("{PREFIX}restart-{tag}");
    let _ = call_json("dynamodb", "CreateTable", &ddb_table(&tname), None).await;
    let mut writers = vec![];
    for w in 0..6 {
        let tn = tname.clone();
        writers.push(tokio::spawn(async move {
            let mut st = vec![];
            for i in 0..25 {
                let r = call_json("dynamodb", "PutItem", &json!({"TableName": tn, "Item": {"id": {"S": format!("w{w}-{i}")}}}), None).await;
                st.push(r.map(|r| (r.status, r.error_code.unwrap_or_default())).unwrap_or((0, "connection".into())));
            }
            st
        }));
    }
    tokio::time::sleep(Duration::from_millis(3)).await;
    let _ = call_json("dynamodb", "DeleteTable", &json!({"TableName": tname}), None).await;
    let _ = call_json("dynamodb", "CreateTable", &ddb_table(&tname), None).await;
    let mut bad = vec![];
    let (mut n200, mut n400) = (0, 0);
    for w in writers {
        for (s, c) in w.await.unwrap_or_default() {
            match s {
                200 => n200 += 1,
                400 if c == "ResourceNotFoundException" => n400 += 1,
                _ => bad.push(format!("{s} {c}")),
            }
        }
    }
    let after = call_json("dynamodb", "PutItem", &json!({"TableName": tname, "Item": {"id": {"S": "after"}}}), None).await.is_ok_and(|r| r.status == 200);
    let _ = call_json("dynamodb", "DeleteTable", &json!({"TableName": tname}), None).await;
    let ok = bad.is_empty() && after;
    make_result("chaos-recreate-under-load", "리소스 재생성(재시작) 중 요청 처리", "chaos", "high", "dynamodb", ok, false,
        format!("성공 {n200}, 테이블 없음 400 {n400}, 재생성 후 쓰기 {}{}", if after { "정상" } else { "실패" },
            if bad.is_empty() { String::new() } else { format!(", 예상 밖 {}", bad.join(",")) }),
        ms_since(t0), json!({"status_in": [200, 400], "after": true}), json!({"ok": n200, "not_found": n400, "unexpected": bad}), vec![])
}

async fn sc_queue_flood(tag: &str) -> Value {
    let t0 = Instant::now();
    let qn = format!("{PREFIX}flood-{tag}");
    let url = json_body(&call_json("sqs", "CreateQueue", &json!({"QueueName": qn}), None).await)["QueueUrl"].as_str().unwrap_or("").to_string();
    let mut failed = 0;
    for b in 0..100 {
        let entries: Vec<Value> = (0..10).map(|i| json!({"Id": format!("m{i}"), "MessageBody": format!("flood-{b}-{i}")})).collect();
        let r = call_json("sqs", "SendMessageBatch", &json!({"QueueUrl": url, "Entries": entries}), None).await;
        failed += json_body(&r)["Failed"].as_array().map_or(10, Vec::len);
    }
    let send_ms = ms_since(t0);
    let depth = json_body(&call_json("sqs", "GetQueueAttributes", &json!({"QueueUrl": url, "AttributeNames": ["ApproximateNumberOfMessages"]}), None).await)
        ["Attributes"]["ApproximateNumberOfMessages"].as_str().unwrap_or("0").to_string();
    let got = json_body(&call_json("sqs", "ReceiveMessage", &json!({"QueueUrl": url, "MaxNumberOfMessages": 10}), None).await)["Messages"].as_array().map_or(0, Vec::len);
    let _ = call_json("sqs", "DeleteQueue", &json!({"QueueUrl": url}), None).await;
    let ok = failed == 0 && depth == "1000" && got == 10;
    make_result("inc-queue-flood", "큐 폭주(메시지 1000건)", "incident", "medium", "sqs", ok, false,
        format!("전송 실패 {failed}, 적체 {depth}건, 수신 {got}건, 전송 {send_ms:.0}ms"), ms_since(t0),
        json!({"depth": 1000, "received": 10}), json!({"failed": failed, "depth": depth, "received": got, "send_ms": send_ms.round()}), vec![])
}

async fn sc_storage_limits(tag: &str) -> Value {
    let t0 = Instant::now();
    let tname = format!("{PREFIX}full-{tag}");
    let qn = format!("{PREFIX}full-{tag}");
    let _ = call_json("dynamodb", "CreateTable", &ddb_table(&tname), None).await;
    let url = json_body(&call_json("sqs", "CreateQueue", &json!({"QueueName": qn}), None).await)["QueueUrl"].as_str().unwrap_or("").to_string();
    let big = "x".repeat(410 * 1024);
    let item = call_json("dynamodb", "PutItem", &json!({"TableName": tname, "Item": {"id": {"S": "big"}, "v": {"S": big}}}), None).await;
    let msg = call_json("sqs", "SendMessage", &json!({"QueueUrl": url, "MessageBody": "y".repeat(300 * 1024)}), None).await;
    let small = call_json("dynamodb", "PutItem", &json!({"TableName": tname, "Item": {"id": {"S": "small"}}}), None).await;
    let _ = call_json("dynamodb", "DeleteTable", &json!({"TableName": tname}), None).await;
    let _ = call_json("sqs", "DeleteQueue", &json!({"QueueUrl": url}), None).await;
    let code = |r: &Result<HttpResp, String>| r.as_ref().map(|r| (r.status, r.error_code.clone().unwrap_or_default())).unwrap_or((0, String::new()));
    let (i, m, s) = (code(&item), code(&msg), code(&small));
    let ok = i == (400, "ValidationException".into()) && m == (400, "InvalidParameterValue".into()) && s.0 == 200;
    make_result("inc-storage-limits", "저장소 한도 초과(항목 400KB·메시지 256KiB)", "incident", "medium", "dynamodb", ok, false,
        format!("DynamoDB 410KB → {} {}, SQS 300KiB → {} {}, 이후 작은 쓰기 → {}", i.0, i.1, m.0, m.1, s.0), ms_since(t0),
        json!({"ddb": [400, "ValidationException"], "sqs": [400, "InvalidParameterValue"], "after": 200}),
        json!({"ddb": [i.0, i.1], "sqs": [m.0, m.1], "after": s.0}), vec![])
}

// Resident memory of this process in KiB (Linux /proc, otherwise ps).
fn rss_kib() -> Option<u64> {
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        return s.lines().find_map(|l| l.strip_prefix("VmRSS:")).and_then(|v| v.split_whitespace().next()?.parse().ok());
    }
    let o = std::process::Command::new("ps").args(["-o", "rss=", "-p", &std::process::id().to_string()]).output().ok()?;
    String::from_utf8_lossy(&o.stdout).trim().parse().ok()
}

async fn sc_memory_growth(tag: &str) -> Value {
    let t0 = Instant::now();
    let tname = format!("{PREFIX}mem-{tag}");
    let _ = call_json("dynamodb", "CreateTable", &ddb_table(&tname), None).await;
    let cycle = |tn: String, n: usize, w: usize| async move {
        for i in 0..n {
            let id = format!("w{w}-{i}");
            let _ = call_json("dynamodb", "PutItem", &json!({"TableName": tn, "Item": {"id": {"S": id}, "pad": {"S": "p".repeat(1024)}}}), None).await;
            let _ = call_json("dynamodb", "DeleteItem", &json!({"TableName": tn, "Key": {"id": {"S": id}}}), None).await;
        }
    };
    cycle(tname.clone(), 100, 99).await; // warm-up fills allocator pools and the 1000-event history
    let before = rss_kib();
    let ws: Vec<_> = (0..10).map(|w| tokio::spawn(cycle(tname.clone(), 100, w))).collect();
    for w in ws {
        let _ = w.await;
    }
    let after = rss_kib();
    let _ = call_json("dynamodb", "DeleteTable", &json!({"TableName": tname}), None).await;
    let (ok, detail, growth) = match (before, after) {
        (Some(b), Some(a)) => {
            let g = a as i64 - b as i64;
            (g < 32 * 1024, format!("쓰기·삭제 2000건 후 RSS {} → {} MiB (증가 {:.1} MiB, 한도 32 MiB)", b / 1024, a / 1024, g as f64 / 1024.0), json!(g))
        }
        // ponytail: no /proc and no ps (minimal containers) means the growth cannot be measured; reported, not failed.
        _ => (true, "RSS를 읽을 수 없어 메모리 증가를 측정하지 못했습니다(/proc·ps 없음). 판정에서 제외.".into(), Value::Null),
    };
    make_result("perf-memory-growth", "메모리 증가 측정(쓰기·삭제 2000건)", "perf", "medium", "dynamodb", ok, false, detail, ms_since(t0),
        json!({"growth_kib_lt": 32 * 1024}), json!({"before_kib": before, "after_kib": after, "growth_kib": growth}), vec![])
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

// Poll an SQS queue until a message arrives or max_tries (100ms each) elapses.
async fn poll_sqs_body(q_url: &str, max_tries: usize) -> Option<String> {
    if q_url.is_empty() {
        return None;
    }
    for _ in 0..max_tries {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Ok(r) = call_json("sqs", "ReceiveMessage", &json!({"QueueUrl": q_url, "MaxNumberOfMessages": 1}), None).await {
            let v: Value = serde_json::from_str(&r.body).unwrap_or_default();
            if let Some(b) = v["Messages"][0]["Body"].as_str() {
                return Some(b.to_string());
            }
        }
    }
    None
}

// Extract the text inside `<tag>...</tag>` from an XML response.
fn xml_tag(body: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let rest = body.split_once(&open)?.1;
    Some(rest.split_once(&close)?.0.to_string())
}

// Security: stale x-amz-date (>15 min clock skew) must be rejected with RequestTimeTooSkewed under VERIFY_SIGV4=1.
async fn sc_clock_skew() -> Value {
    let t0 = Instant::now();
    let hdrs = [
        ("x-amz-target", "DynamoDB_20120810.ListTables"),
        ("content-type", "application/x-amz-json-1.0"),
        ("x-amz-date", "20200101T000000Z"),
        ("authorization", "AWS4-HMAC-SHA256 Credential=test/20200101/us-east-1/dynamodb/aws4_request, SignedHeaders=host;x-amz-date, Signature=deadbeef"),
        ("x-rc-unsigned", "1"),
    ];
    let repro = vec![repro_step("POST", "/", &hdrs[..4], "{}")];
    match local_http("POST", "/", &hdrs, b"{}").await {
        Ok(r) => {
            let ok = if *crate::VERIFY {
                (r.status == 400 || r.status == 403) && r.error_code.as_deref() == Some("RequestTimeTooSkewed")
            } else {
                r.status < 500
            };
            let detail = if *crate::VERIFY {
                if ok { format!("15분 이상 어긋난 x-amz-date 요청이 HTTP {} RequestTimeTooSkewed로 거부됐습니다.", r.status) }
                else { format!("기대 400/403 RequestTimeTooSkewed, 실제 HTTP {} ({:?})", r.status, r.error_code) }
            } else {
                "VERIFY_SIGV4=0 모드에서는 5xx 없이 통과했습니다 (시계 오차 거부는 VERIFY_SIGV4=1에서 활성).".into()
            };
            make_result("sec-clock-skew", "SigV4 시계 오차(>15분) 거부", "security", "high", "iam", ok, *crate::VERIFY && ok,
                detail, t0.elapsed().as_secs_f64() * 1000.0,
                json!({"verify_sigv4": *crate::VERIFY, "error_code": "RequestTimeTooSkewed"}),
                json!({"status": r.status, "error_code": r.error_code}), repro)
        }
        Err(e) => make_result("sec-clock-skew", "SigV4 시계 오차(>15분) 거부", "security", "high", "iam", false, false, e,
            t0.elapsed().as_secs_f64() * 1000.0, json!({}), json!({}), repro),
    }
}

// Security: an expired STS AssumeRole session key must be rejected with ExpiredToken in both modes.
async fn sc_sts_expired(tag: &str) -> Value {
    let t0 = Instant::now();
    let role = format!("{PREFIX}exp-{tag}");
    let trust = json!({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": format!("arn:aws:iam::{ACCOUNT}:root")}, "Action": "sts:AssumeRole"}]}).to_string();
    let _ = call_query("iam", "2010-05-08", "CreateRole", &[("RoleName", &role), ("AssumeRolePolicyDocument", &trust)], Some("test")).await;
    let rarn = format!("arn:aws:iam::{ACCOUNT}:role/{role}");
    let ar = call_query("sts", "2011-06-15", "AssumeRole", &[("RoleArn", &rarn), ("RoleSessionName", "insp"), ("DurationSeconds", "-1")], Some("test")).await;
    let akid = ar.as_ref().ok().and_then(|r| xml_tag(&r.body, "AccessKeyId")).unwrap_or_default();
    let probe = if akid.is_empty() {
        Err("AssumeRole 임시 키 발급 실패".into())
    } else {
        call_json("dynamodb", "ListTables", &json!({}), Some(&akid)).await
    };
    let _ = call_query("iam", "2010-05-08", "DeleteRole", &[("RoleName", &role)], Some("test")).await;
    let repro = vec![repro_step("POST", "/", &[("x-amz-target", "DynamoDB_20120810.ListTables")], "{}")];
    match probe {
        Ok(r) => {
            let ok = (r.status == 400 || r.status == 403) && r.error_code.as_deref() == Some("ExpiredToken");
            make_result("sec-sts-expired", "만료된 STS 세션 키 거부", "security", "high", "iam", ok, ok,
                if ok { format!("만료된 STS AssumeRole 임시 키 요청이 HTTP {} ExpiredToken으로 거부됐습니다.", r.status) }
                else { format!("기대 400/403 ExpiredToken, 실제 HTTP {} ({:?})", r.status, r.error_code) },
                t0.elapsed().as_secs_f64() * 1000.0, json!({"status_in": [400, 403], "error_code": "ExpiredToken"}),
                json!({"status": r.status, "error_code": r.error_code}), repro)
        }
        Err(e) => make_result("sec-sts-expired", "만료된 STS 세션 키 거부", "security", "high", "iam", false, false, e,
            t0.elapsed().as_secs_f64() * 1000.0, json!({"status_in": [400, 403], "error_code": "ExpiredToken"}), json!({}), repro),
    }
}

// Security: SNS -> SQS delivery blocked by target queue policy (or missing policy under STRICT_DELIVERY=1).
async fn sc_strict_delivery(tag: &str) -> Value {
    let t0 = Instant::now();
    let q_name = format!("{PREFIX}sdq-{tag}");
    let t_name = format!("{PREFIX}sdt-{tag}");
    let q_r = call_json("sqs", "CreateQueue", &json!({"QueueName": q_name}), None).await;
    let q_url = q_r.as_ref().ok().and_then(|r| serde_json::from_str::<Value>(&r.body).ok()).and_then(|v| v["QueueUrl"].as_str().map(String::from)).unwrap_or_default();
    let q_arn = format!("arn:aws:sqs:{}:{ACCOUNT}:{q_name}", *REGION);
    let t_r = call_query("sns", "2010-03-31", "CreateTopic", &[("Name", &t_name)], Some("test")).await;
    let t_arn = t_r.as_ref().ok().and_then(|r| xml_tag(&r.body, "TopicArn")).unwrap_or_default();
    if !*crate::STRICT {
        // Default permissive mode allows policy-less targets, so attach an explicit Deny queue policy.
        let pol = json!({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": q_arn}]}).to_string();
        let _ = call_json("sqs", "SetQueueAttributes", &json!({"QueueUrl": q_url, "Attributes": {"Policy": pol}}), None).await;
    }
    let _ = call_query("sns", "2010-03-31", "Subscribe", &[("TopicArn", &t_arn), ("Protocol", "sqs"), ("Endpoint", &q_arn)], Some("test")).await;
    let _ = call_query("sns", "2010-03-31", "Publish", &[("TopicArn", &t_arn), ("Message", "should-be-blocked")], Some("test")).await;
    let arrived = poll_sqs_body(&q_url, 4).await.is_some();
    if !t_arn.is_empty() {
        let _ = call_query("sns", "2010-03-31", "DeleteTopic", &[("TopicArn", &t_arn)], Some("test")).await;
    }
    if !q_url.is_empty() {
        let _ = call_json("sqs", "DeleteQueue", &json!({"QueueUrl": q_url}), None).await;
    }
    let ok = !*ENFORCE || !arrived;
    let mode = if *crate::STRICT { "STRICT_DELIVERY=1 (정책 없음 거부)" } else { "기본 모드 (큐 정책 명시적 Deny 거부)" };
    let repro = vec![repro_step("POST", "/", &[("content-type", "application/x-www-form-urlencoded")], "Action=Publish&Version=2010-03-31")];
    make_result("sec-strict-delivery", "SNS → SQS 서비스 주체 배달 정책 차단", "security", "high", "sns", ok, *ENFORCE && ok,
        if ok { format!("{mode}: 허용되지 않은 SNS 배달이 대상 큐에 도착하지 못했습니다.") }
        else { format!("{mode}: 차단되어야 할 메시지가 대상 큐에 도착했습니다.") },
        t0.elapsed().as_secs_f64() * 1000.0, json!({"arrived": false, "strict_delivery": *crate::STRICT}),
        json!({"arrived": arrived}), repro)
}

// Security: API Gateway JWT authorizer must reject external issuers, missing tokens (401), and tampered tokens (403).
async fn sc_jwt_bypass(tag: &str) -> Value {
    let t0 = Instant::now();
    let gw_auth = sig_header("test", "apigateway");
    let lam_auth = sig_header("test", "lambda");
    let pname = format!("{PREFIX}jwt-{tag}");
    let fname = format!("{PREFIX}jwtfn-{tag}");
    let pool_r = call_json("cognito-idp", "CreateUserPool", &json!({"PoolName": pname}), None).await;
    let pool_id = pool_r.as_ref().ok().and_then(|r| serde_json::from_str::<Value>(&r.body).ok()).and_then(|v| v["UserPool"]["Id"].as_str().map(String::from)).unwrap_or_default();
    let z = make_py_zip("def handler(e, c):\n    return {'ok': True}\n").unwrap_or_default();
    let _ = local_http("POST", "/2015-03-31/functions", &[("content-type", "application/json"), ("authorization", &lam_auth)],
        json!({"FunctionName": fname, "Runtime": "python3.12", "Role": format!("arn:aws:iam::{ACCOUNT}:role/r"),
               "Handler": "index.handler", "Code": {"ZipFile": z}}).to_string().as_bytes()).await;
    let api_r = local_http("POST", "/v2/apis", &[("content-type", "application/json"), ("authorization", &gw_auth)],
        json!({"name": pname, "protocolType": "HTTP"}).to_string().as_bytes()).await;
    let api_id = api_r.as_ref().ok().and_then(|r| serde_json::from_str::<Value>(&r.body).ok()).and_then(|v| v["apiId"].as_str().map(String::from)).unwrap_or_default();

    let ext_r = local_http("POST", &format!("/v2/apis/{api_id}/authorizers"), &[("content-type", "application/json"), ("authorization", &gw_auth)],
        json!({"name": "ext", "authorizerType": "JWT", "identitySource": ["$request.header.Authorization"],
               "jwtConfiguration": {"issuer": "https://evil.example.com", "audience": ["c1"]}}).to_string().as_bytes()).await;
    let iss = format!("{}/_cognito/{pool_id}", endpoint());
    let auth_r = local_http("POST", &format!("/v2/apis/{api_id}/authorizers"), &[("content-type", "application/json"), ("authorization", &gw_auth)],
        json!({"name": "cog", "authorizerType": "JWT", "identitySource": ["$request.header.Authorization"],
               "jwtConfiguration": {"issuer": iss, "audience": ["c1"]}}).to_string().as_bytes()).await;
    let aid = auth_r.as_ref().ok().and_then(|r| serde_json::from_str::<Value>(&r.body).ok()).and_then(|v| v["authorizerId"].as_str().map(String::from)).unwrap_or_default();
    let integ_r = local_http("POST", &format!("/v2/apis/{api_id}/integrations"), &[("content-type", "application/json"), ("authorization", &gw_auth)],
        json!({"integrationType": "AWS_PROXY", "integrationUri": format!("arn:aws:lambda:{}:{ACCOUNT}:function:{fname}", *REGION), "payloadFormatVersion": "2.0"}).to_string().as_bytes()).await;
    let iid = integ_r.as_ref().ok().and_then(|r| serde_json::from_str::<Value>(&r.body).ok()).and_then(|v| v["integrationId"].as_str().map(String::from)).unwrap_or_default();
    let _ = local_http("POST", &format!("/v2/apis/{api_id}/routes"), &[("content-type", "application/json"), ("authorization", &gw_auth)],
        json!({"routeKey": "GET /secret", "target": format!("integrations/{iid}"), "authorizationType": "JWT", "authorizerId": aid}).to_string().as_bytes()).await;

    let no_tok = local_http("GET", &format!("/_api/{api_id}/secret"), &[("x-rc-unsigned", "1")], b"").await;
    let bad_tok = local_http("GET", &format!("/_api/{api_id}/secret"), &[("authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJldmlsIn0.AAAA"), ("x-rc-unsigned", "1")], b"").await;

    // cleanup
    if !api_id.is_empty() {
        let _ = local_http("DELETE", &format!("/v2/apis/{api_id}"), &[("authorization", &gw_auth)], b"").await;
    }
    let _ = local_http("DELETE", &format!("/2015-03-31/functions/{fname}"), &[("authorization", &lam_auth)], b"").await;
    if !pool_id.is_empty() {
        let _ = call_json("cognito-idp", "DeleteUserPool", &json!({"UserPoolId": pool_id}), None).await;
    }

    let ext_s = ext_r.as_ref().map(|r| r.status).unwrap_or(0);
    let no_s = no_tok.as_ref().map(|r| r.status).unwrap_or(0);
    let bad_s = bad_tok.as_ref().map(|r| r.status).unwrap_or(0);
    let ok = ext_s == 400 && no_s == 401 && bad_s == 403;
    let repro = vec![repro_step("GET", &format!("/_api/{api_id}/secret"), &[], "")];
    make_result("sec-jwt-bypass", "API Gateway JWT 인가자 우회 차단", "security", "high", "apigateway", ok, ok,
        if ok { "외부 issuer 거부(400), 토큰 누락 거부(401), 변조 토큰 거부(403)가 모두 확인됐습니다.".into() }
        else { format!("기대 (400, 401, 403), 실제 ({ext_s}, {no_s}, {bad_s})") },
        t0.elapsed().as_secs_f64() * 1000.0, json!({"ext_issuer": 400, "missing_token": 401, "tampered": 403}),
        json!({"ext_issuer": ext_s, "missing_token": no_s, "tampered": bad_s}), repro)
}

// Lambda Destinations: a failing async invoke delivers the failure envelope to the OnFailure SQS queue.
async fn sc_lambda_dest(tag: &str) -> Value {
    let t0 = Instant::now();
    let fname = format!("{PREFIX}dest-{tag}");
    let q_name = format!("{PREFIX}destq-{tag}");
    let z = match make_py_zip("def handler(event, ctx):\n    raise RuntimeError('inspector-dest-boom')\n") {
        Ok(z) => z,
        Err(e) => return make_result("inc-lambda-dest", "Lambda Destinations OnFailure 배달", "incident", "medium", "lambda", false, false, e, 0.0, json!({}), json!({}), vec![]),
    };
    let auth = sig_header("root", "lambda");
    let q_r = call_json("sqs", "CreateQueue", &json!({"QueueName": q_name}), None).await;
    let q_url = q_r.as_ref().ok().and_then(|r| serde_json::from_str::<Value>(&r.body).ok()).and_then(|v| v["QueueUrl"].as_str().map(String::from)).unwrap_or_default();
    let q_arn = format!("arn:aws:sqs:{}:{ACCOUNT}:{q_name}", *REGION);
    let cr = local_http("POST", "/2015-03-31/functions", &[("content-type", "application/json"), ("authorization", &auth)],
        json!({"FunctionName": fname, "Runtime": "python3.12", "Role": format!("arn:aws:iam::{ACCOUNT}:role/r"),
               "Handler": "index.handler", "Code": {"ZipFile": z}}).to_string().as_bytes()).await;
    let _ = local_http("PUT", &format!("/2019-09-25/functions/{fname}/event-invoke-config"), &[("content-type", "application/json"), ("authorization", &auth)],
        json!({"DestinationConfig": {"OnFailure": {"Destination": q_arn}}, "MaximumRetryAttempts": 0}).to_string().as_bytes()).await;
    let _ = local_http("POST", &format!("/2015-03-31/functions/{fname}/invocations"), &[("authorization", &auth), ("x-amz-invocation-type", "Event")], b"{}").await;

    let body = poll_sqs_body(&q_url, 30).await.unwrap_or_default();
    let arrived = !body.is_empty();
    let ok = cr.is_ok_and(|r| r.status < 300) && arrived && body.contains("inspector-dest-boom") && body.contains("RetriesExhausted");
    // cleanup
    let _ = local_http("DELETE", &format!("/2015-03-31/functions/{fname}"), &[("authorization", &auth)], b"").await;
    let _ = call_json("logs", "DeleteLogGroup", &json!({"logGroupName": format!("/aws/lambda/{fname}")}), None).await;
    if !q_url.is_empty() {
        let _ = call_json("sqs", "DeleteQueue", &json!({"QueueUrl": q_url}), None).await;
    }
    let repro = vec![repro_step("POST", &format!("/2015-03-31/functions/{fname}/invocations"), &[("x-amz-invocation-type", "Event")], "{}")];
    make_result("inc-lambda-dest", "Lambda Destinations OnFailure 배달", "incident", "medium", "lambda", ok, false,
        if ok { "실패한 비동기 호출이 OnFailure 대상 큐에 AWS 형식 봉투(에러·요청 페이로드 포함)로 도착했습니다.".into() }
        else { format!("도착={arrived}, 본문: {body}") },
        t0.elapsed().as_secs_f64() * 1000.0, json!({"arrived": true, "condition": "RetriesExhausted"}),
        json!({"arrived": arrived, "body": body}), repro)
}

// EventBridge: retries exhausted on a failing Lambda target land in the rule's SQS DLQ.
async fn sc_events_dlq(tag: &str) -> Value {
    let t0 = Instant::now();
    let fname = format!("{PREFIX}ev-{tag}");
    let q_name = format!("{PREFIX}evq-{tag}");
    let rule = format!("{PREFIX}rule-{tag}");
    let z = match make_py_zip("def handler(event, ctx):\n    raise RuntimeError('inspector-ev-boom')\n") {
        Ok(z) => z,
        Err(e) => return make_result("inc-events-dlq", "EventBridge 재시도 소진 → DLQ", "incident", "high", "events", false, false, e, 0.0, json!({}), json!({}), vec![]),
    };
    let auth = sig_header("root", "lambda");
    let q_r = call_json("sqs", "CreateQueue", &json!({"QueueName": q_name}), None).await;
    let q_url = q_r.as_ref().ok().and_then(|r| serde_json::from_str::<Value>(&r.body).ok()).and_then(|v| v["QueueUrl"].as_str().map(String::from)).unwrap_or_default();
    let q_arn = format!("arn:aws:sqs:{}:{ACCOUNT}:{q_name}", *REGION);
    let _ = local_http("POST", "/2015-03-31/functions", &[("content-type", "application/json"), ("authorization", &auth)],
        json!({"FunctionName": fname, "Runtime": "python3.12", "Role": format!("arn:aws:iam::{ACCOUNT}:role/r"),
               "Handler": "index.handler", "Code": {"ZipFile": z}}).to_string().as_bytes()).await;
    let _ = call_json("events", "PutRule", &json!({"Name": rule, "EventPattern": json!({"detail-type": ["inspector-ev"]}).to_string()}), None).await;
    let _ = call_json("events", "PutTargets", &json!({"Rule": rule, "Targets": [{
        "Id": "t", "Arn": format!("arn:aws:lambda:{}:{ACCOUNT}:function:{fname}", *REGION),
        "RetryPolicy": {"MaximumRetryAttempts": 0}, "DeadLetterConfig": {"Arn": q_arn}}]}), None).await;
    let _ = call_json("events", "PutEvents", &json!({"Entries": [{"Source": "inspector", "DetailType": "inspector-ev", "Detail": "{\"k\":1}"}]}), None).await;

    let body = poll_sqs_body(&q_url, 30).await.unwrap_or_default();
    let arrived = !body.is_empty();
    let ok = arrived && body.contains("inspector-ev");
    // cleanup
    let _ = call_json("events", "RemoveTargets", &json!({"Rule": rule, "Ids": ["t"]}), None).await;
    let _ = call_json("events", "DeleteRule", &json!({"Name": rule}), None).await;
    let _ = local_http("DELETE", &format!("/2015-03-31/functions/{fname}"), &[("authorization", &auth)], b"").await;
    let _ = call_json("logs", "DeleteLogGroup", &json!({"logGroupName": format!("/aws/lambda/{fname}")}), None).await;
    if !q_url.is_empty() {
        let _ = call_json("sqs", "DeleteQueue", &json!({"QueueUrl": q_url}), None).await;
    }
    let repro = vec![repro_step("POST", "/", &[("x-amz-target", "AWSEvents.PutEvents")],
        &json!({"Entries": [{"Source": "inspector", "DetailType": "inspector-ev", "Detail": "{}"}]}).to_string())];
    make_result("inc-events-dlq", "EventBridge 재시도 소진 → DLQ", "incident", "high", "events", ok, false,
        if ok { "MaximumRetryAttempts=0로 즉시 실패한 대상 배달이 SQS DLQ에 기록되었습니다.".into() }
        else { format!("도착={arrived}, 본문: {body}") },
        t0.elapsed().as_secs_f64() * 1000.0, json!({"arrived": true}),
        json!({"arrived": arrived, "body": body}), repro)
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
            ("sec-bucket-policy-deny", "security"),
            ("sec-s3-path-traversal", "security"),
            ("sec-missing-sigv4", "security"),
            ("sec-oversize-payload", "security"),
            ("sec-injection-input", "security"),
            ("sec-clock-skew", "security"),
            ("sec-sts-expired", "security"),
            ("sec-strict-delivery", "security"),
            ("sec-jwt-bypass", "security"),
        ]);
    }
    if has("chaos") {
        plan.extend([("chaos-throttle-recovery", "chaos"), ("chaos-5xx-recovery", "chaos"), ("chaos-latency", "chaos"),
            ("chaos-partial-failure", "chaos"), ("chaos-conn-drop", "chaos"), ("chaos-recreate-under-load", "chaos")]);
    }
    if has("incident") {
        plan.extend([("inc-dlq-buildup", "incident"), ("inc-lambda-repeated-fail", "incident"), ("inc-queue-flood", "incident"),
            ("inc-storage-limits", "incident"), ("inc-lambda-dest", "incident"), ("inc-events-dlq", "incident")]);
    }
    if has("perf") {
        plan.extend([("perf-concurrent-burst", "perf"), ("perf-memory-growth", "perf")]);
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
            "sec-bucket-policy-deny" => sc_bucket_policy_deny(tag).await,
            "sec-s3-path-traversal" => sc_s3_path_traversal(tag).await,
            "sec-missing-sigv4" => sc_missing_sigv4().await,
            "sec-oversize-payload" => sc_oversize_payload().await,
            "sec-injection-input" => sc_injection_input(tag).await,
            "sec-clock-skew" => sc_clock_skew().await,
            "sec-sts-expired" => sc_sts_expired(tag).await,
            "sec-strict-delivery" => sc_strict_delivery(tag).await,
            "sec-jwt-bypass" => sc_jwt_bypass(tag).await,
            "chaos-throttle-recovery" => sc_chaos_throttle(app).await,
            "chaos-5xx-recovery" => sc_chaos_5xx(app).await,
            "inc-dlq-buildup" => sc_dlq_buildup(tag).await,
            "inc-lambda-repeated-fail" => sc_lambda_repeated_fail(tag).await,
            "perf-concurrent-burst" => sc_perf_concurrent(tag).await,
            "fuzz-random-inputs" => sc_fuzz_random().await,
            "chaos-latency" => sc_chaos_latency(app).await,
            "chaos-partial-failure" => sc_chaos_partial(app).await,
            "chaos-conn-drop" => sc_conn_drop().await,
            "chaos-recreate-under-load" => sc_recreate_under_load(tag).await,
            "inc-queue-flood" => sc_queue_flood(tag).await,
            "inc-storage-limits" => sc_storage_limits(tag).await,
            "inc-lambda-dest" => sc_lambda_dest(tag).await,
            "inc-events-dlq" => sc_events_dlq(tag).await,
            "perf-memory-growth" => sc_memory_growth(tag).await,
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

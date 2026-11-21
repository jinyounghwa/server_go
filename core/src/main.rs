mod agent;
mod apigw;
mod cognito;
mod cfn;
mod ddb;
mod ecs;
mod elb;
mod events;
mod iam;
mod inspector;
mod kinesis;
mod kms;
mod lambda;
mod logs;
mod managed;
mod net;
mod route53;
mod s3;
mod ses;
mod sfn;
mod secrets;
mod sigv4;
mod sns;
mod sqs;
mod ssm;
mod storage;

use axum::response::IntoResponse;
use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, Method, Uri},
    response::{
        sse::{Event, Sse},
        Response,
    },
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::{
    convert::Infallible,
    sync::{Arc, LazyLock, Mutex},
    collections::HashMap,
    time::Instant,
};
use tokio::sync::broadcast;

pub const ACCOUNT: &str = "000000000000";
pub static REGION: LazyLock<String> =
    LazyLock::new(|| std::env::var("REGION").unwrap_or_else(|_| "us-east-1".into()));

pub(crate) static VERIFY: LazyLock<bool> = LazyLock::new(|| std::env::var("VERIFY_SIGV4").is_ok_and(|v| v == "1"));
// The running app, for the inspector's signing client.
pub(crate) static APP: std::sync::OnceLock<Arc<App>> = std::sync::OnceLock::new();
static BIND: LazyLock<String> = LazyLock::new(|| std::env::var("BIND").unwrap_or_else(|_| "127.0.0.1:4566".into()));
// URL that code running inside the emulator (Lambda) uses to reach it.
pub fn endpoint() -> String {
    format!("http://{}", BIND.replace("0.0.0.0", "127.0.0.1"))
}

// ENFORCE_IAM=1 rejects denied requests; otherwise decisions are only reported in events.
pub(crate) static ENFORCE: LazyLock<bool> = LazyLock::new(|| std::env::var("ENFORCE_IAM").is_ok_and(|v| v == "1"));

#[derive(Debug)]
pub struct ApiErr {
    pub status: u16,
    pub code: String,
    pub msg: String,
    pub extra: Option<Value>,
}

pub fn err(code: &str, msg: impl Into<String>) -> ApiErr {
    ApiErr { status: 400, code: code.into(), msg: msg.into(), extra: None }
}

// Required string field of a JSON request.
pub fn need<'a>(r: &'a Value, k: &str) -> Result<&'a str, ApiErr> {
    r[k].as_str().ok_or_else(|| err("ValidationException", format!("{k} is required")))
}
pub fn epoch() -> f64 {
    chrono::Utc::now().timestamp_millis() as f64 / 1000.0
}
pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
pub fn rand_bytes(n: usize) -> Vec<u8> {
    (0..n.div_ceil(16)).flat_map(|_| *uuid::Uuid::new_v4().as_bytes()).take(n).collect()
}
pub fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}
pub fn unb64(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

// State is in memory; RC_STATE_FILE (JSON snapshot) or RC_SQLITE_FILE persists it.
pub struct App {
    pub ddb: Mutex<ddb::Db>,
    pub s3: Mutex<s3::Store>,
    pub sqs: Mutex<sqs::Queues>,
    pub iam: Mutex<iam::Iam>,
    pub net: Mutex<net::Net>,
    pub secrets: Mutex<secrets::Secrets>,
    pub ssm: Mutex<ssm::Ssm>,
    pub kms: Mutex<kms::Kms>,
    pub logs: Mutex<logs::Logs>,
    pub sns: Mutex<sns::Sns>,
    pub lambda: Mutex<lambda::Lambda>,
    pub eb: Mutex<events::Events>,
    pub sfn: Mutex<sfn::Sfn>,
    pub apigw: Mutex<apigw::ApiGw>,
    pub cognito: Mutex<cognito::Cognito>,
    pub kinesis: Mutex<kinesis::Kinesis>,
    pub ses: Mutex<ses::Ses>,
    pub managed: Mutex<managed::Managed>,
    pub ecs: Mutex<ecs::Ecs>,
    pub elb: Mutex<elb::Elb>,
    pub route53: Mutex<route53::Route53>,
    pub cfn: Mutex<cfn::Cfn>,
    pub inspector: Mutex<inspector::Inspector>,
    pub(crate) chaos: Mutex<Vec<Value>>,
    events: broadcast::Sender<String>,
    pub recent: Mutex<std::collections::VecDeque<Value>>,
    pub store: Mutex<storage::SqliteStore>,
}

fn json_reply(prefix: &str, r: Result<Value, ApiErr>) -> Response {
    let (status, body, code) = match r {
        Ok(v) => (200, v, None),
        Err(e) => {
            let mut b = json!({"__type": format!("{prefix}#{}", e.code), "message": e.msg});
            if let Some(Value::Object(x)) = e.extra {
                b.as_object_mut().unwrap().extend(x);
            }
            (e.status, b, Some(e.code))
        }
    };
    let mut r = Response::builder().status(status).header("content-type", "application/x-amz-json-1.0");
    if let (Some(c), true) = (&code, prefix.ends_with("sqs")) {
        // SDKs map SQS errors through the legacy query error code in this header.
        let q = if c == "QueueDoesNotExist" { "AWS.SimpleQueueService.NonExistentQueue" } else { c };
        r = r.header("x-amzn-query-error", format!("{q};Sender"));
    }
    r.body(Body::from(body.to_string())).unwrap()
}

// Access key id and service name from SigV4 (header or presigned query).
// Only parsing here; VERIFY_SIGV4=1 checks the signature in sigv4::verify.
fn sigv4(h: &HeaderMap, uri: &Uri) -> (String, String) {
    let cred = h
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|a| a.split("Credential=").nth(1))
        .map(|c| c.split([',', ' ']).next().unwrap_or("").to_string())
        .or_else(|| uri.query()?.split('&').find_map(|p| p.strip_prefix("X-Amz-Credential=")).map(s3::pct_decode))
        .unwrap_or_default();
    let parts: Vec<&str> = cred.split('/').collect();
    (parts[0].to_string(), parts.get(3).unwrap_or(&"").to_string())
}

fn form(s: &str) -> impl Iterator<Item = (String, String)> + '_ {
    s.split('&').filter(|p| !p.is_empty()).map(|p| {
        let (k, v) = p.split_once('=').unwrap_or((p, ""));
        (s3::pct_decode(&k.replace('+', " ")), s3::pct_decode(&v.replace('+', " ")))
    })
}

const STS_OPS: &[&str] = &["GetCallerIdentity", "AssumeRole"];

const IAM_NS: &str = "https://iam.amazonaws.com/doc/2010-05-08/";
const STS_NS: &str = "https://sts.amazonaws.com/doc/2011-06-15/";
const SNS_NS: &str = "http://sns.amazonaws.com/doc/2010-03-31/";
const SES_NS: &str = "http://ses.amazonaws.com/doc/2010-12-01/";
const RDS_NS: &str = "http://rds.amazonaws.com/doc/2014-10-31/";
const CACHE_NS: &str = "http://elasticache.amazonaws.com/doc/2015-02-02/";
const CFN_NS: &str = "http://cloudformation.amazonaws.com/doc/2010-05-15/";
const ELB_NS: &str = "http://elasticloadbalancing.amazonaws.com/doc/2015-12-01/";

fn query_reply(ns: &str, action: &str, rid: &str, r: Result<Value, ApiErr>) -> Response {
    let (status, body) = match r {
        Ok(v) => (200, format!("<{action}Response xmlns=\"{ns}\"><{action}Result>{}</{action}Result><ResponseMetadata><RequestId>{rid}</RequestId></ResponseMetadata></{action}Response>", iam::to_xml(&v))),
        Err(e) => (e.status, format!("<ErrorResponse xmlns=\"{ns}\"><Error><Type>Sender</Type><Code>{}</Code><Message>{}</Message></Error><RequestId>{rid}</RequestId></ErrorResponse>", e.code, s3::esc(&e.msg))),
    };
    Response::builder().status(status).header("content-type", "text/xml").body(Body::from(body)).unwrap()
}

fn ec2_reply(action: &str, rid: &str, r: Result<Value, ApiErr>) -> Response {
    let (status, body) = match r {
        Ok(v) => (200, format!("<{action}Response xmlns=\"http://ec2.amazonaws.com/doc/2016-11-15/\"><requestId>{rid}</requestId>{}</{action}Response>", net::to_xml(&v))),
        Err(e) => (e.status, format!("<Response><Errors><Error><Code>{}</Code><Message>{}</Message></Error></Errors><RequestID>{rid}</RequestID></Response>", e.code, s3::esc(&e.msg))),
    };
    Response::builder().status(status).header("content-type", "text/xml").body(Body::from(body)).unwrap()
}

// JSON-protocol services routed by X-Amz-Target prefix: (prefix, IAM service name).
const JSON_TARGETS: &[(&str, &str)] = &[
    ("secretsmanager.", "secretsmanager"),
    ("AmazonSSM.", "ssm"),
    ("TrentService.", "kms"),
    ("Logs_20140328.", "logs"),
    ("AWSEvents.", "events"),
    ("AWSStepFunctions.", "states"),
    ("AWSCognitoIdentityProviderService.", "cognito-idp"),
    ("Kinesis_20131202.", "kinesis"),
    ("AmazonEC2ContainerServiceV20141113.", "ecs"),
];

pub fn emit(app: &App, ev: Value) {
    println!("{ev}");
    let _ = app.events.send(ev.to_string());
    app.store.lock().unwrap().record_event(&ev);
    // Recent history for the explanation agent.
    let mut r = app.recent.lock().unwrap();
    if r.len() >= 1000 {
        r.pop_front();
    }
    r.push_back(ev);
}

// Error code and message from a failed response body (JSON or XML), for events and explanations.
pub(crate) fn error_of(body: &[u8]) -> Option<Value> {
    let text = String::from_utf8_lossy(body);
    if let Ok(j) = serde_json::from_str::<Value>(&text) {
        let code = j["__type"].as_str().or(j["code"].as_str()).map(|c| c.rsplit('#').next().unwrap_or(c).to_string());
        let msg = j["message"].as_str().or(j["Message"].as_str()).unwrap_or("");
        return code.map(|c| json!({"code": c, "message": msg}));
    }
    let code = s3::tags(&text, "Code").into_iter().next()?;
    Some(json!({"code": code, "message": s3::tags(&text, "Message").concat()}))
}

const COGNITO_PUBLIC: &[&str] = &["SignUp", "ConfirmSignUp", "InitiateAuth", "RespondToAuthChallenge", "ForgotPassword",
    "ConfirmForgotPassword", "GetUser", "ChangePassword", "GlobalSignOut"];

enum Svc {
    Cfn(HashMap<String, String>),
    R53(String, String), // method, path after /2013-04-01/
    Elb(HashMap<String, String>),
    Rds(HashMap<String, String>),
    Cache(HashMap<String, String>),
    SesV1(HashMap<String, String>),
    SesV2(String, String), // method, path after /v2/email/
    ApiGw(String, String), // method, path after /v2/
    Lambda(&'static str, String, HashMap<String, String>), // op, path after the API version, query
    Json(&'static str, String),
    Sns(HashMap<String, String>),
    Ec2(HashMap<String, String>),
    Ddb(String),
    Sqs(String),
    Iam(HashMap<String, String>),
    S3(s3::Req),
}

fn arn(svc: &str, rest: &str) -> String {
    format!("arn:aws:{svc}:{}:{ACCOUNT}:{rest}", *REGION)
}

// (action, resource) pairs this request needs; all must be allowed.
fn checks(app: &App, svc: &Svc, body: &[u8]) -> Vec<(String, String)> {
    let j: Value = serde_json::from_slice(body).unwrap_or_default();
    match svc {
        Svc::Cfn(q) => vec![(format!("cloudformation:{}", q.get("Action").map_or("", String::as_str)), "*".into())],
        Svc::R53(m, path) => vec![(format!("route53:{m} {}", path.split('/').next().unwrap_or("")), "*".into())],
        Svc::Elb(q) => vec![(format!("elasticloadbalancing:{}", q.get("Action").map_or("", String::as_str)), "*".into())],
        Svc::Rds(q) => vec![(format!("rds:{}", q.get("Action").map_or("", String::as_str)),
                             q.get("DBInstanceIdentifier").map_or("*".into(), |i| arn("rds", &format!("db:{i}"))))],
        Svc::Cache(q) => vec![(format!("elasticache:{}", q.get("Action").map_or("", String::as_str)),
                               q.get("CacheClusterId").map_or("*".into(), |i| arn("elasticache", &format!("cluster:{i}"))))],
        Svc::SesV1(q) => vec![(format!("ses:{}", q.get("Action").map_or("", String::as_str)), "*".into())],
        Svc::SesV2(m, path) => vec![(format!("ses:{m} {}", path.split('/').next().unwrap_or("")), "*".into())],
        // API Gateway's IAM model: action = HTTP verb, resource = API path.
        Svc::ApiGw(m, path) => vec![(format!("apigateway:{m}"), format!("arn:aws:apigateway:{}::/{path}", *REGION))],
        Svc::Lambda(op, path, _) => {
            let res = lambda::path_name(path).or_else(|| j["FunctionName"].as_str().map(lambda::name_of)).map_or("*".into(), |n| lambda::arn(&n));
            // IAM names the Invoke API "lambda:InvokeFunction".
            vec![(format!("lambda:{}", if *op == "Invoke" { "InvokeFunction" } else { op }), res)]
        }
        // Cognito's end-user APIs are public (token- or client-id based), not IAM-authorized.
        Svc::Json("cognito-idp", op) if COGNITO_PUBLIC.contains(&op.as_str()) => vec![],
        Svc::Json(name, op) => {
            let res = match *name {
                "kinesis" => j["StreamARN"].as_str().map(String::from).or_else(|| j["StreamName"].as_str().map(|n| arn("kinesis", &format!("stream/{n}")))),
                "cognito-idp" => j["UserPoolId"].as_str().map(|p| arn("cognito-idp", &format!("userpool/{p}"))),
                "secretsmanager" => j["SecretId"].as_str().and_then(|id| app.secrets.lock().unwrap().arn_of(id))
                    .or_else(|| j["Name"].as_str().map(|n| arn("secretsmanager", &format!("secret:{n}")))),
                "ssm" => j["Name"].as_str().map(ssm::arn),
                "logs" => j["logGroupName"].as_str().map(|g| arn("logs", &format!("log-group:{g}"))),
                "states" => j["executionArn"].as_str().or(j["stateMachineArn"].as_str()).map(String::from),
                "kms" => j["KeyId"].as_str().map(|k| if k.starts_with("arn:") { k.to_string() } else if k.starts_with("alias/") { arn("kms", k) } else { arn("kms", &format!("key/{k}")) }),
                _ => None,
            };
            vec![(format!("{name}:{op}"), res.unwrap_or_else(|| "*".into()))]
        }
        Svc::Sns(q) => vec![(format!("sns:{}", q.get("Action").map_or("", String::as_str)),
                             q.get("TopicArn").or(q.get("TargetArn")).cloned().unwrap_or_else(|| "*".into()))],
        Svc::Ddb(op) => {
            let table = |t: &str| arn("dynamodb", &format!("table/{t}"));
            let mut res: Vec<String> = match &j["TableName"] {
                Value::String(t) => vec![match j["IndexName"].as_str() {
                    Some(ix) => format!("{}/index/{ix}", table(t)),
                    None => table(t),
                }],
                _ => j["RequestItems"].as_object().map(|m| m.keys().map(|t| table(t)).collect()).unwrap_or_default(),
            };
            for ti in j["TransactItems"].as_array().into_iter().flatten() {
                if let Some(t) = ti.as_object().and_then(|m| m.values().next()).and_then(|v| v["TableName"].as_str()) {
                    res.push(table(t));
                }
            }
            if res.is_empty() {
                res.push("*".into());
            }
            res.into_iter().map(|r| (format!("dynamodb:{op}"), r)).collect()
        }
        Svc::Sqs(op) => {
            let name = j["QueueUrl"].as_str().and_then(|u| u.rsplit('/').next()).or(j["QueueName"].as_str());
            vec![(format!("sqs:{op}"), name.map_or("*".into(), |n| arn("sqs", n)))]
        }
        Svc::Ec2(q) => vec![(format!("ec2:{}", q.get("Action").map_or("", String::as_str)), "*".into())],
        Svc::Iam(q) => {
            let a = q.get("Action").map_or("", String::as_str);
            if a == "GetCallerIdentity" {
                return vec![]; // needs no permission
            }
            let iam_arn = |kind: &str, n: &String| format!("arn:aws:iam::{ACCOUNT}:{kind}/{n}");
            let res = q.get("UserName").map(|n| iam_arn("user", n))
                .or_else(|| q.get("RoleName").map(|n| iam_arn("role", n)))
                .or_else(|| q.get("PolicyArn").or(q.get("RoleArn")).cloned())
                .unwrap_or_else(|| "*".into());
            vec![(format!("{}:{a}", if STS_OPS.contains(&a) { "sts" } else { "iam" }), res)]
        }
        Svc::S3(r) => {
            let (a, res) = r.iam();
            vec![(a.into(), res)]
        }
    }
}

async fn handle(State(app): State<Arc<App>>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    let t0 = Instant::now();
    let rid = uuid::Uuid::new_v4().to_string();
    let (akid, scope) = sigv4(&headers, &uri);
    let principal = app.iam.lock().unwrap().principal(&akid);
    let target = headers.get("x-amz-target").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let is_form = headers.get("content-type").and_then(|v| v.to_str().ok()).is_some_and(|c| c.starts_with("application/x-www-form-urlencoded"));
    let lambda_path = ["/2015-03-31/", "/2014-11-13/"].iter().find_map(|v| uri.path().strip_prefix(v)).filter(|_| scope == "lambda" || scope.is_empty());
    let svc = if let Some(path) = uri.path().strip_prefix("/2013-04-01/").filter(|_| scope == "route53") {
        Svc::R53(method.to_string(), path.to_string())
    } else if let Some(path) = uri.path().strip_prefix("/v2/email/").filter(|_| scope == "ses") {
        Svc::SesV2(method.to_string(), path.to_string())
    } else if let Some(path) = uri.path().strip_prefix("/v2/").filter(|_| scope == "apigateway") {
        Svc::ApiGw(method.to_string(), path.to_string())
    } else if let Some(path) = lambda_path {
        Svc::Lambda(lambda::op_of(method.as_str(), path), path.to_string(), form(uri.query().unwrap_or("")).collect())
    } else if let Some(op) = target.strip_prefix("DynamoDB_20120810.") {
        Svc::Ddb(op.into())
    } else if let Some(op) = target.strip_prefix("AmazonSQS.") {
        Svc::Sqs(op.into())
    } else if let Some((pre, name)) = JSON_TARGETS.iter().find(|(p, _)| target.starts_with(p)) {
        Svc::Json(name, target[pre.len()..].to_string())
    } else if scope == "iam" || scope == "sts" || (is_form && method == Method::POST) {
        let mut q: HashMap<String, String> = form(uri.query().unwrap_or("")).collect();
        q.extend(form(std::str::from_utf8(&body).unwrap_or("")));
        let version = q.get("Version").cloned().unwrap_or_default();
        if scope == "ec2" || version == "2016-11-15" {
            Svc::Ec2(q)
        } else if scope == "cloudformation" || version == "2010-05-15" {
            Svc::Cfn(q)
        } else if scope == "elasticloadbalancing" || version == "2015-12-01" {
            Svc::Elb(q)
        } else if scope == "rds" || version == "2014-10-31" {
            Svc::Rds(q)
        } else if scope == "elasticache" || version == "2015-02-02" {
            Svc::Cache(q)
        } else if scope == "ses" || version == "2010-12-01" {
            Svc::SesV1(q)
        } else if scope == "sns" || version == "2010-03-31" {
            Svc::Sns(q)
        } else {
            Svc::Iam(q)
        }
    } else {
        Svc::S3(s3::classify(&method, &uri, &headers))
    };
    let (service, op) = match &svc {
        Svc::Cfn(q) => ("cloudformation", q.get("Action").cloned().unwrap_or_default()),
        Svc::R53(m, path) => ("route53", format!("{m} /{}", path.split('/').filter(|p| !p.starts_with('Z') && !p.starts_with('C')).collect::<Vec<_>>().join("/"))),
        Svc::Elb(q) => ("elbv2", q.get("Action").cloned().unwrap_or_default()),
        Svc::Rds(q) => ("rds", q.get("Action").cloned().unwrap_or_default()),
        Svc::Cache(q) => ("elasticache", q.get("Action").cloned().unwrap_or_default()),
        Svc::SesV1(q) => ("ses", q.get("Action").cloned().unwrap_or_default()),
        Svc::SesV2(m, path) => ("ses", format!("{m} {}", path.split('/').next().unwrap_or(""))),
        Svc::Json(name, op) => (*name, op.clone()),
        Svc::Lambda(op, ..) => ("lambda", op.to_string()),
        Svc::ApiGw(_, path) => ("apigateway", format!("{method} /{}", path.split('/').take(3).collect::<Vec<_>>().join("/"))),
        Svc::Sns(q) => ("sns", q.get("Action").cloned().unwrap_or_default()),
        Svc::Ec2(q) => ("ec2", q.get("Action").cloned().unwrap_or_default()),
        Svc::Ddb(op) => ("dynamodb", op.clone()),
        Svc::Sqs(op) => ("sqs", op.clone()),
        Svc::Iam(q) => {
            let a = q.get("Action").cloned().unwrap_or_default();
            (if STS_OPS.contains(&a.as_str()) { "sts" } else { "iam" }, a)
        }
        Svc::S3(r) => ("s3", r.op.to_string()),
    };

    // Authorization: the first denied (action, resource) decides; otherwise the last allow explains.
    // Resource-based policy of the target, if any (S3 bucket policy, SQS queue policy).
    let resource_policy = match &svc {
        Svc::S3(r) if !r.bucket.is_empty() => app.s3.lock().unwrap().policy(&r.bucket).map(|p| ("bucket policy", p)),
        Svc::Sqs(_) => serde_json::from_slice::<Value>(&body).ok().and_then(|b| {
            let name = b["QueueUrl"].as_str()?.rsplit('/').next()?.to_string();
            app.sqs.lock().unwrap().policy(&name).map(|p| ("queue policy", p))
        }),
        Svc::Lambda(_, path, _) => lambda::path_name(path)
            .or_else(|| serde_json::from_slice::<Value>(&body).ok().and_then(|j| j["FunctionName"].as_str().map(lambda::name_of)))
            .and_then(|n| app.lambda.lock().unwrap().policy(&n))
            .map(|p| ("function policy", p)),
        Svc::Sns(q) => q.get("TopicArn").or(q.get("TargetArn")).and_then(|t| app.sns.lock().unwrap().policy(t)).map(|p| ("topic policy", p)),
        _ => None,
    };
    let decision = {
        let iam = app.iam.lock().unwrap();
        let mut last = None;
        for (a, r) in checks(&app, &svc, &body) {
            let d = iam.authorize_with(&principal, &a, &r, resource_policy.as_ref().map(|(k, p)| (*k, p)));
            let deny = !d.allowed;
            last = Some(d);
            if deny {
                break;
            }
        }
        last
    };
    // VERIFY_SIGV4=1: a bad or missing signature is refused before IAM (Cognito's public ops are unsigned).
    let json_proto = matches!(svc, Svc::Ddb(_) | Svc::Json(..) | Svc::Sqs(_));
    let sig_err = (*VERIFY && !(service == "cognito-idp" && COGNITO_PUBLIC.contains(&op.as_str())))
        .then(|| {
            let iam = app.iam.lock().unwrap();
            sigv4::verify(&method, &uri, &headers, &body, |k| iam.secret_of(k)).err()
        })
        .flatten()
        .map(|(code, msg)| {
            let code = match (code, json_proto, matches!(svc, Svc::S3(_))) {
                ("SignatureDoesNotMatch", true, _) => "InvalidSignatureException",
                ("MissingAuthenticationToken", true, _) => "MissingAuthenticationTokenException",
                ("MissingAuthenticationToken", _, true) => "AccessDenied",
                ("InvalidClientTokenId", true, _) => "UnrecognizedClientException",
                (c, ..) => c,
            };
            ApiErr { status: if json_proto { 400 } else { 403 }, ..err(code, msg) }
        });
    // A request either fails its signature or authorization, gets a chaos fault, or runs.
    let denied = sig_err.or(decision.as_ref().filter(|d| !d.allowed && *ENFORCE).map(|d| {
        let (status, code) = match &svc {
            Svc::Ddb(_) | Svc::Json(..) => (400, "AccessDeniedException"),
            Svc::Lambda(..) => (403, "AccessDeniedException"),
            Svc::Sns(_) => (403, "AuthorizationError"),
            Svc::Ec2(_) => (403, "UnauthorizedOperation"),
            _ => (403, "AccessDenied"),
        };
        ApiErr { status, ..err(code, d.reason.clone()) }
    }));
    let chaos = if denied.is_none() { chaos_fault(&app, service, &op).await } else { None };
    let fault = denied.or(chaos.as_ref().and_then(|(_, e)| e.as_ref().map(|e| ApiErr { status: e.status, code: e.code.clone(), msg: e.msg.clone(), extra: None })));

    let mut resp = match (svc, fault) {
        (Svc::Cfn(_), Some(e)) => query_reply(CFN_NS, &op, &rid, Err(e)),
        (Svc::Cfn(q), None) => {
            let r = app.cfn.lock().unwrap().handle(&q);
            let r = r.map(|(v, job)| {
                if let Some(j) = job {
                    tokio::spawn(cfn::run(app.clone(), j));
                }
                v
            });
            query_reply(CFN_NS, &op, &rid, r)
        }
        (Svc::R53(m, path), fault) => {
            let r = match fault {
                Some(e) => Err(e),
                None => app.route53.lock().unwrap().handle(&m, &path, &String::from_utf8_lossy(&body)),
            };
            let (status, xml) = r.unwrap_or_else(|e| (e.status, format!("<?xml version=\"1.0\"?>\n<ErrorResponse xmlns=\"https://route53.amazonaws.com/doc/2013-04-01/\"><Error><Type>Sender</Type><Code>{}</Code><Message>{}</Message></Error><RequestId>{rid}</RequestId></ErrorResponse>", e.code, s3::esc(&e.msg))));
            Response::builder().status(status).header("content-type", "text/xml").body(Body::from(xml)).unwrap()
        }
        (Svc::Elb(_), Some(e)) => query_reply(ELB_NS, &op, &rid, Err(e)),
        (Svc::Elb(q), None) => {
            let r = app.elb.lock().unwrap().handle(&q);
            let r = r.map(|(v, jobs)| {
                for j in jobs {
                    match j {
                        elb::Job::Listen(arn, sock) => elb::serve(app.clone(), arn, sock),
                        elb::Job::Close(arn) => elb::close(&app, &arn),
                    }
                }
                v
            });
            query_reply(ELB_NS, &op, &rid, r)
        }
        (Svc::Json("ecs", op), None) => {
            let r = serde_json::from_slice::<Value>(&body).map_err(|e| err("SerializationException", e.to_string())).and_then(|j| {
                let (v, jobs) = app.ecs.lock().unwrap().handle(&op, &j)?;
                for job in jobs {
                    match job {
                        ecs::Job::Run(id) => drop(tokio::spawn(ecs::run_task(app.clone(), id))),
                        ecs::Job::Reconcile(c, n) => drop(tokio::spawn(ecs::reconcile(app.clone(), c, n))),
                    }
                }
                Ok(v)
            });
            json_reply("ecs", r)
        }
        (Svc::Rds(_), Some(e)) => query_reply(RDS_NS, &op, &rid, Err(e)),
        (Svc::Cache(_), Some(e)) => query_reply(CACHE_NS, &op, &rid, Err(e)),
        (s @ (Svc::Rds(_) | Svc::Cache(_)), None) => {
            let is_rds = matches!(s, Svc::Rds(_));
            let r = match &s {
                Svc::Rds(q) => app.managed.lock().unwrap().rds(q),
                Svc::Cache(q) => app.managed.lock().unwrap().cache(q),
                _ => unreachable!(),
            };
            let r = r.map(|(v, job)| {
                if let Some((kind, id, job)) = job {
                    tokio::spawn(managed::run_job(app.clone(), kind, id, job));
                }
                v
            });
            query_reply(if is_rds { RDS_NS } else { CACHE_NS }, &op, &rid, r)
        }
        (Svc::SesV1(_), Some(e)) => query_reply(SES_NS, &op, &rid, Err(e)),
        (Svc::SesV1(q), None) => {
            let r = app.ses.lock().unwrap().handle_query(&q);
            query_reply(SES_NS, &op, &rid, r)
        }
        (Svc::SesV2(..), Some(e)) => lambda::error_reply(e),
        (Svc::SesV2(m, path), None) => {
            let j: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            match app.ses.lock().unwrap().handle_v2(&m, &path, &j) {
                Ok((s, v)) => Response::builder().status(s).header("content-type", "application/json").body(Body::from(v.to_string())).unwrap(),
                Err(e) => lambda::error_reply(e),
            }
        }
        (Svc::Lambda(..) | Svc::ApiGw(..), Some(e)) => lambda::error_reply(e),
        (Svc::ApiGw(_, path), None) => {
            let j: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
            match app.apigw.lock().unwrap().handle(method.as_str(), &path, &j) {
                Ok((204, _)) => Response::builder().status(204).body(Body::empty()).unwrap(),
                Ok((s, v)) => Response::builder().status(s).header("content-type", "application/json").body(Body::from(v.to_string())).unwrap(),
                Err(e) => lambda::error_reply(e),
            }
        }
        (Svc::Lambda(op, path, q), None) => lambda::api(&app, op, &path, &q, &headers, &body).await,
        (Svc::Json(name, _), Some(e)) => json_reply(name, Err(e)),
        (Svc::Json("events", op), None) => {
            let r = serde_json::from_slice::<Value>(&body).map_err(|e| err("SerializationException", e.to_string())).and_then(|j| {
                let (v, sends) = app.eb.lock().unwrap().handle(&op, &j)?;
                for (t, payload) in sends {
                    send_to_target(&app, &rid, t["Arn"].as_str().unwrap_or(""), payload, "events", t["_RuleArn"].as_str().unwrap_or(""));
                }
                if op == "PutRule" {
                    start_schedule(app.clone(), events::bus_of(&j), j["Name"].as_str().unwrap_or("").into());
                }
                Ok(v)
            });
            json_reply("events", r)
        }
        (Svc::Json("states", op), None) => {
            let r = serde_json::from_slice::<Value>(&body).map_err(|e| err("SerializationException", e.to_string())).and_then(|j| {
                let (v, start) = app.sfn.lock().unwrap().handle(&op, &j)?;
                if let Some(exec) = start {
                    tokio::spawn(sfn::run(app.clone(), exec));
                }
                Ok(v)
            });
            json_reply("states", r)
        }
        (Svc::Json("cognito-idp", op), None) => {
            let r = serde_json::from_slice::<Value>(&body).map_err(|e| err("SerializationException", e.to_string())).and_then(|j| {
                let mut c = app.cognito.lock().unwrap();
                let r = c.handle(&op, &j);
                let codes = c.take_codes();
                drop(c);
                // Verification codes would be emailed; locally they are published as events.
                for (user, code) in codes {
                    emit(&app, json!({"ts": chrono::Utc::now().to_rfc3339(), "service": "cognito-idp", "op": "CodeSent", "target": user, "code": code, "status": 200}));
                }
                r
            });
            json_reply("cognito-idp", r)
        }
        (Svc::Json(name, op), None) => {
            let r: Result<Value, ApiErr> = serde_json::from_slice::<Value>(&body)
                .map_err(|e| err("SerializationException", e.to_string()))
                .and_then(|j| match name {
                    "secretsmanager" => app.secrets.lock().unwrap().handle(&op, &j),
                    "ssm" => app.ssm.lock().unwrap().handle(&op, &j),
                    "kms" => app.kms.lock().unwrap().handle(&op, &j),
                    "kinesis" => app.kinesis.lock().unwrap().handle(&op, &j),
                    _ => app.logs.lock().unwrap().handle(&op, &j),
                });
            json_reply(name, r)
        }
        (Svc::Sns(_), Some(e)) => query_reply(SNS_NS, &op, &rid, Err(e)),
        (Svc::Sns(q), None) => {
            let r = app.sns.lock().unwrap().handle(&q);
            let r = r.map(|(v, deliveries)| {
                let topic = q.get("TopicArn").cloned().unwrap_or_default();
                for d in deliveries {
                    deliver(&app, &rid, &d, "sns", &topic);
                }
                v
            });
            query_reply(SNS_NS, &op, &rid, r)
        }
        (Svc::Ec2(_), Some(e)) => ec2_reply(&op, &rid, Err(e)),
        (Svc::Ec2(q), None) => {
            let r = app.net.lock().unwrap().handle(&q);
            ec2_reply(&op, &rid, r)
        }
        (Svc::Ddb(_), Some(e)) => json_reply("com.amazonaws.dynamodb.v20120810", Err(e)),
        (Svc::Sqs(_), Some(e)) => json_reply("com.amazonaws.sqs", Err(e)),
        (Svc::Iam(_), Some(e)) => query_reply(if service == "sts" { STS_NS } else { IAM_NS }, &op, &rid, Err(e)),
        (Svc::S3(_), Some(e)) => s3::error(&e),
        (Svc::Ddb(op), None) => json_reply("com.amazonaws.dynamodb.v20120810", ddb::handle(&app, &op, &body)),
        (Svc::Sqs(op), None) => {
            let host = headers.get("host").and_then(|v| v.to_str().ok()).unwrap_or("localhost");
            json_reply("com.amazonaws.sqs", sqs::handle(&app, &op, &body, host).await)
        }
        (Svc::Iam(q), None) => {
            let r = app.iam.lock().unwrap().handle(&principal, &q);
            query_reply(if service == "sts" { STS_NS } else { IAM_NS }, &op, &rid, r)
        }
        (Svc::S3(r), None) => {
            let resp = s3::handle(&app, &r, &headers, body);
            let notes = app.s3.lock().unwrap().take_notes();
            for n in notes {
                s3_note(&app, &rid, n);
            }
            resp
        }
    };
    let h = resp.headers_mut();
    h.insert("x-amzn-requestid", rid.parse().unwrap());
    h.insert("x-amz-request-id", rid.parse().unwrap());
    let mut ev = json!({
        "ts": chrono::Utc::now().to_rfc3339(), "request_id": rid, "service": service, "op": op,
        "status": resp.status().as_u16(), "ms": t0.elapsed().as_secs_f64() * 1000.0, "principal": principal.arn(),
    });
    if let Some((rule, e)) = &chaos {
        ev["chaos"] = json!({"rule": rule, "fault": e.as_ref().map(|e| e.code.clone())});
    }
    if let Some(d) = decision.filter(|_| principal != iam::Principal::Root) {
        // Which policy decided, as a fixed label (identity policy names are never exposed here).
        let source = match d.matched.first().map(String::as_str) {
            Some(k @ ("bucket policy" | "queue policy" | "topic policy" | "function policy")) => k,
            _ => "identity",
        };
        ev["auth"] = json!({"decision": d.kind, "reason": d.reason, "enforced": *ENFORCE, "source": source});
    }
    if resp.status().as_u16() >= 400 {
        let (parts, body) = resp.into_parts();
        let bytes = axum::body::to_bytes(body, 1 << 20).await.unwrap_or_default();
        if let Some(e) = error_of(&bytes) {
            ev["error"] = e;
        }
        resp = Response::from_parts(parts, Body::from(bytes));
    }
    emit(&app, ev);
    resp
}

// Deliver an S3 bucket notification to SQS, SNS or Lambda.
fn s3_note(app: &Arc<App>, rid: &str, n: s3::Note) {
    let body: Value = serde_json::from_str(&n.body).unwrap_or_default();
    let bucket = body["Records"][0]["s3"]["bucket"]["arn"].as_str().unwrap_or("").to_string();
    send_to_target(app, rid, &n.target, body, "s3", &bucket);
}

// With ENFORCE_IAM=1, a delivery from SNS, EventBridge or S3 must pass the target's resource policy (queue, function
// or topic policy) as that service's principal. Step Functions and others act with identity and are not gated here.
fn service_gate(app: &Arc<App>, rid: &str, from: &str, target: &str, src: &str) -> bool {
    if !*ENFORCE || !matches!(from, "sns" | "events" | "s3") {
        return true;
    }
    let (kind, action, doc) = if target.starts_with("arn:aws:lambda:") {
        ("function policy", "lambda:InvokeFunction", app.lambda.lock().unwrap().policy(&lambda::name_of(target)))
    } else if target.starts_with("arn:aws:sns:") {
        ("topic policy", "sns:Publish", app.sns.lock().unwrap().policy(target))
    } else {
        ("queue policy", "sqs:SendMessage", app.sqs.lock().unwrap().policy(target.rsplit(':').next().unwrap_or("")))
    };
    let Err(reason) = iam::service_may(doc.as_ref(), &format!("{from}.amazonaws.com"), action, target, src) else { return true };
    emit(app, json!({"ts": chrono::Utc::now().to_rfc3339(), "request_id": rid, "service": from, "op": "Deliver", "target": target, "status": 403,
                     "auth": {"decision": "explicitDeny", "reason": reason, "enforced": true, "source": kind}}));
    false
}

// Send a payload to an SQS queue, SNS topic or Lambda function by ARN. `src` is the sender's ARN (rule, bucket, topic).
fn send_to_target(app: &Arc<App>, rid: &str, arn: &str, payload: Value, from: &str, src: &str) {
    let text = match &payload {
        Value::String(s) => s.clone(),
        v => v.to_string(),
    };
    if !arn.starts_with("arn:aws:sqs:") && !service_gate(app, rid, from, arn, src) {
        return;
    }
    if arn.starts_with("arn:aws:lambda:") {
        let (app, name, from) = (app.clone(), arn.to_string(), from.to_string()); // keeps a :version / :alias qualifier
        tokio::spawn(async move { lambda::invoke_logged(&app, &name, payload, &from).await });
    } else if arn.starts_with("arn:aws:sns:") {
        let subject = if from == "s3" { "Amazon S3 Notification" } else { "" };
        let mut q: HashMap<String, String> = [("Action", "Publish"), ("TopicArn", arn), ("Message", text.as_str())].map(|(k, v)| (k.to_string(), v.to_string())).into();
        if !subject.is_empty() {
            q.insert("Subject".into(), subject.into());
        }
        let r = app.sns.lock().unwrap().handle(&q);
        for d in r.map(|(_, ds)| ds).unwrap_or_default() {
            deliver(app, rid, &d, "sns", arn);
        }
    } else {
        deliver(app, rid, &sns::Delivery { protocol: "sqs".into(), endpoint: arn.into(), body: text, attrs: Value::Null }, from, src);
    }
}

// Ticker for a rate() rule; it stops when the rule is replaced or deleted.
fn start_schedule(app: Arc<App>, bus: String, name: String) {
    let Some((expr, generation)) = app.eb.lock().unwrap().schedule_of(&bus, &name) else { return };
    tokio::spawn(async move {
        loop {
            let Some(wait) = events::next_delay(&expr) else { return };
            tokio::time::sleep(wait).await;
            let due = app.eb.lock().unwrap().scheduled(&bus, &name, generation);
            match due {
                None => return,
                Some(None) => continue, // disabled
                Some(Some((targets, rule_arn))) => {
                    let ev = events::envelope("aws.events", "Scheduled Event", json!({}), json!([rule_arn]));
                    for t in targets {
                        send_to_target(&app, "schedule", t["Arn"].as_str().unwrap_or(""), events::payload(&t, &ev), "events", &rule_arn);
                    }
                }
            }
        }
    });
}

// Push a message to its subscriber and report it as its own event.
fn deliver(app: &Arc<App>, rid: &str, d: &sns::Delivery, from: &str, src: &str) {
    if matches!(d.protocol.as_str(), "sqs" | "lambda") && !service_gate(app, rid, from, &d.endpoint, src) {
        return;
    }
    let ok = match d.protocol.as_str() {
        "sqs" => app.sqs.lock().unwrap().deliver(d.endpoint.rsplit(':').next().unwrap_or(""), d.body.clone(), &d.attrs),
        "lambda" => {
            let name = lambda::name_of(&d.endpoint);
            let env: Value = serde_json::from_str(&d.body).unwrap_or_default();
            let event = json!({"Records": [{"EventSource": "aws:sns", "EventVersion": "1.0", "EventSubscriptionArn": env["UnsubscribeURL"], "Sns": env}]});
            let ok = app.lambda.lock().unwrap().exists(&name);
            let app = app.clone();
            tokio::spawn(async move { lambda::invoke_logged(&app, &name, event, "sns").await });
            ok
        }
        _ => false, // ponytail: http/email/sms endpoints are not called
    };
    emit(app, json!({"ts": chrono::Utc::now().to_rfc3339(), "request_id": rid, "service": from, "op": "Deliver",
                     "target": d.endpoint, "protocol": d.protocol, "status": if ok { 200 } else { 404 }}));
}

// Chaos rules: [{"service": "s3", "op": "Get*", "latency_ms": 200, "error_rate": 0.1, "throttle_rate": 0.2}].
// Returns the matching rule and, if one was rolled, the fault to answer with. Latency is applied here.
async fn chaos_fault(app: &App, service: &str, op: &str) -> Option<(Value, Option<ApiErr>)> {
    let rule = app.chaos.lock().unwrap().iter().find(|r| {
        iam::glob(r["service"].as_str().unwrap_or("*"), service, true) && iam::glob(r["op"].as_str().unwrap_or("*"), op, true)
    }).cloned()?;
    if let Some(ms) = rule["latency_ms"].as_u64() {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }
    let roll = |k: &str| rule[k].as_f64().is_some_and(|p| (rand_bytes(4).iter().fold(0u32, |a, b| a << 8 | *b as u32) as f64 / u32::MAX as f64) < p);
    let fault = if roll("throttle_rate") {
        Some(match service {
            "dynamodb" => err("ProvisionedThroughputExceededException", "Chaos: throughput exceeded"),
            "s3" => ApiErr { status: 503, ..err("SlowDown", "Chaos: please reduce your request rate") },
            _ => err("ThrottlingException", "Chaos: rate exceeded"),
        })
    } else if roll("error_rate") {
        Some(ApiErr { status: 500, ..err(if service == "s3" { "InternalError" } else { "InternalFailure" }, "Chaos: injected internal error") })
    } else {
        None
    };
    Some((rule, fault))
}

async fn get_chaos(State(app): State<Arc<App>>) -> Json<Value> {
    Json(json!({ "rules": *app.chaos.lock().unwrap() }))
}

async fn set_chaos(State(app): State<Arc<App>>, h: HeaderMap, body: Bytes) -> axum::http::StatusCode {
    if !h.contains_key("x-rocalcloud") {
        return axum::http::StatusCode::FORBIDDEN;
    }
    let Ok(v) = serde_json::from_slice::<Value>(&body) else { return axum::http::StatusCode::BAD_REQUEST };
    *app.chaos.lock().unwrap() = v["rules"].as_array().cloned().unwrap_or_default();
    emit(&app, json!({"ts": chrono::Utc::now().to_rfc3339(), "service": "admin", "op": "SetChaos", "status": 200, "rules": v["rules"]}));
    axum::http::StatusCode::NO_CONTENT
}

// Event stream for GUI / character web / agents: one JSON event per request.
// The published town page (GitHub Pages) may read the local event stream. Only this one origin gets CORS,
// and its copy is scrubbed to an allowlist of visualization fields (dropping confirmation codes, principals,
// error details, policy reasons, etc.). RC_TOWN_ORIGIN overrides it; "off" or empty disables it.
fn parse_town_origin(raw: &str) -> Option<axum::http::HeaderValue> {
    let s = raw.trim().trim_end_matches('/');
    if s.is_empty() || s.eq_ignore_ascii_case("off") {
        return None;
    }
    if !(s.starts_with("https://") || s.starts_with("http://")) {
        return None;
    }
    axum::http::HeaderValue::from_str(s).ok()
}

static TOWN_ORIGIN: LazyLock<Option<axum::http::HeaderValue>> = LazyLock::new(|| {
    let raw = std::env::var("RC_TOWN_ORIGIN").unwrap_or_else(|_| "https://jinyounghwa.github.io".into());
    parse_town_origin(&raw)
});

fn town_view(s: String) -> String {
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&s) else { return "{}".into() };
    let mut out = serde_json::Map::new();
    for k in ["ts", "service", "op", "status", "trigger", "protocol", "target", "name", "target_service", "passed", "blocked", "total"] {
        if let Some(v) = map.get(k) {
            out.insert(k.into(), v.clone());
        }
    }
    if let Some(Value::Object(a)) = map.get("auth") {
        let mut ao = serde_json::Map::new();
        for k in ["decision", "enforced"] {
            if let Some(v) = a.get(k) { ao.insert(k.into(), v.clone()); }
        }
        // Only known labels pass, so nothing else can ride along in this field.
        if let Some(s) = a.get("source").filter(|s| ["identity", "bucket policy", "queue policy", "topic policy", "function policy"].iter().any(|k| *s == *k)) {
            ao.insert("source".into(), s.clone());
        }
        if !ao.is_empty() { out.insert("auth".into(), Value::Object(ao)); }
    }
    if let Some(Value::Object(c)) = map.get("chaos") {
        if let Some(f) = c.get("fault") {
            out.insert("chaos".into(), json!({"fault": f}));
        }
    }
    Value::Object(out).to_string()
}

fn is_shutdown_event(s: &str) -> bool {
    serde_json::from_str::<Value>(s)
        .ok()
        .is_some_and(|v| v["service"] == "admin" && v["op"] == "Shutdown")
}

async fn events(State(app): State<Arc<App>>, h: HeaderMap) -> Response {
    let cross = TOWN_ORIGIN.as_ref().is_some_and(|allowed| {
        h.get("origin").and_then(|o| o.to_str().ok()).is_some_and(|o| o == allowed.to_str().unwrap_or(""))
    });
    let sse = Sse::new(futures_util::stream::unfold((app.events.subscribe(), false), move |(mut rx, done)| async move {
        if done {
            return None;
        }
        loop {
            match rx.recv().await {
                Ok(s) => {
                    let closing = is_shutdown_event(&s);
                    let data = if cross { town_view(s) } else { s };
                    return Some((Ok::<_, Infallible>(Event::default().data(data)), (rx, closing)));
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => return None,
            }
        }
    }));
    let mut resp = sse.into_response();
    resp.headers_mut().insert("vary", axum::http::HeaderValue::from_static("Origin"));
    if cross {
        if let Some(allowed) = TOWN_ORIGIN.as_ref() {
            resp.headers_mut().insert("access-control-allow-origin", allowed.clone());
        }
    }
    resp
}

async fn state(State(app): State<Arc<App>>) -> Json<Value> {
    Json(json!({
        "dynamodb": app.ddb.lock().unwrap().admin(),
        "s3": app.s3.lock().unwrap().admin(),
        "sqs": app.sqs.lock().unwrap().admin(),
        "iam": app.iam.lock().unwrap().admin(),
        "vpc": app.net.lock().unwrap().admin(),
        "sns": app.sns.lock().unwrap().admin(),
        "lambda": app.lambda.lock().unwrap().admin(),
        "events": app.eb.lock().unwrap().admin(),
        "sfn": app.sfn.lock().unwrap().admin(),
        "apigw": app.apigw.lock().unwrap().admin(),
        "cognito": app.cognito.lock().unwrap().admin(),
        "kinesis": app.kinesis.lock().unwrap().admin(),
        "ses": app.ses.lock().unwrap().admin(),
        "managed": app.managed.lock().unwrap().admin(),
        "ecs": app.ecs.lock().unwrap().admin(),
        "elb": app.elb.lock().unwrap().admin(),
        "route53": app.route53.lock().unwrap().admin(),
        "cfn": app.cfn.lock().unwrap().admin(),
        "secrets": app.secrets.lock().unwrap().admin(),
        "ssm": app.ssm.lock().unwrap().admin(),
        "kms": app.kms.lock().unwrap().admin(),
        "logs": app.logs.lock().unwrap().admin(),
    }))
}

fn export_snapshot(app: &App) -> Value {
    json!({
        "version": 1,
        "saved_at": chrono::Utc::now().to_rfc3339(),
        "services": {
            "dynamodb": app.ddb.lock().unwrap().snap_save(),
            "s3": app.s3.lock().unwrap().snap_save(),
            "sqs": app.sqs.lock().unwrap().snap_save(),
            "sns": app.sns.lock().unwrap().snap_save(),
            "iam": app.iam.lock().unwrap().snap_save(),
            "ssm": app.ssm.lock().unwrap().snap_save(),
            "secrets": app.secrets.lock().unwrap().snap_save(),
            "kms": app.kms.lock().unwrap().snap_save(),
        }
    })
}

fn import_snapshot(app: &App, snap: &Value) {
    let s = &snap["services"];
    if s["dynamodb"].is_array() { app.ddb.lock().unwrap().snap_load(&s["dynamodb"]); }
    if s["s3"].is_array() { app.s3.lock().unwrap().snap_load(&s["s3"]); }
    if s["sqs"].is_array() { app.sqs.lock().unwrap().snap_load(&s["sqs"]); }
    if s["sns"].is_object() { app.sns.lock().unwrap().snap_load(&s["sns"]); }
    if s["iam"].is_object() { app.iam.lock().unwrap().snap_load(&s["iam"]); }
    if s["ssm"].is_array() { app.ssm.lock().unwrap().snap_load(&s["ssm"]); }
    if s["secrets"].is_array() { app.secrets.lock().unwrap().snap_load(&s["secrets"]); }
    if s["kms"].is_object() { app.kms.lock().unwrap().snap_load(&s["kms"]); }
}

async fn get_snapshot(State(app): State<Arc<App>>) -> Response {
    Response::builder()
        .header("content-type", "application/json")
        .header("content-disposition", "attachment; filename=\"rocalcloud-snapshot.json\"")
        .body(Body::from(export_snapshot(&app).to_string()))
        .unwrap()
}

async fn post_snapshot(State(app): State<Arc<App>>, h: HeaderMap, body: Bytes) -> Response {
    if !h.contains_key("x-rocalcloud") {
        return Response::builder().status(403).body(Body::empty()).unwrap();
    }
    let Ok(snap) = serde_json::from_slice::<Value>(&body) else {
        return Response::builder().status(400).body(Body::from("invalid snapshot JSON")).unwrap();
    };
    if !snap["services"].is_object() {
        return Response::builder().status(400).body(Body::from("missing services object")).unwrap();
    }
    import_snapshot(&app, &snap);
    emit(&app, json!({"ts": chrono::Utc::now().to_rfc3339(), "service": "admin", "op": "SnapshotLoaded", "status": 200}));
    Json(json!({"restored": true, "saved_at": snap["saved_at"]})).into_response()
}

async fn save_snapshot_file(State(app): State<Arc<App>>, h: HeaderMap) -> Response {
    if !h.contains_key("x-rocalcloud") {
        return Response::builder().status(403).body(Body::empty()).unwrap();
    }
    let Ok(path) = std::env::var("RC_STATE_FILE") else {
        return Response::builder().status(400).body(Body::from("RC_STATE_FILE is not set")).unwrap();
    };
    match std::fs::write(&path, serde_json::to_string_pretty(&export_snapshot(&app)).unwrap_or_default()) {
        Ok(()) => Json(json!({"saved": path})).into_response(),
        Err(e) => Response::builder().status(500).body(Body::from(e.to_string())).unwrap(),
    }
}

async fn sqlite_snapshots(State(app): State<Arc<App>>) -> Json<Value> {
    Json(app.store.lock().unwrap().list_snapshots())
}

async fn sqlite_save(State(app): State<Arc<App>>, h: HeaderMap, body: Bytes) -> Response {
    if !h.contains_key("x-rocalcloud") {
        return Response::builder().status(403).body(Body::empty()).unwrap();
    }
    let label = serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|v| v["label"].as_str().map(str::to_string))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "manual".into());
    let snap = export_snapshot(&app);
    let res = app.store.lock().unwrap().save_snapshot(&label, &snap);
    match res {
        Ok(id) => {
            emit(&app, json!({"ts": chrono::Utc::now().to_rfc3339(), "service": "sqlite", "op": "SnapshotSaved", "target": label, "status": 200}));
            Json(json!({"id": id, "label": label, "saved_at": snap["saved_at"]})).into_response()
        }
        Err(e) => Response::builder().status(500).body(Body::from(e)).unwrap(),
    }
}

async fn sqlite_restore(State(app): State<Arc<App>>, h: HeaderMap, body: Bytes) -> Response {
    if !h.contains_key("x-rocalcloud") {
        return Response::builder().status(403).body(Body::empty()).unwrap();
    }
    let id = serde_json::from_slice::<Value>(&body).ok().and_then(|v| v["id"].as_i64());
    let snap = match app.store.lock().unwrap().load_snapshot(id) {
        Ok(Some(s)) => s,
        Ok(None) => return Response::builder().status(404).body(Body::from("no snapshot found")).unwrap(),
        Err(e) => return Response::builder().status(500).body(Body::from(e)).unwrap(),
    };
    import_snapshot(&app, &snap);
    emit(&app, json!({"ts": chrono::Utc::now().to_rfc3339(), "service": "admin", "op": "SnapshotLoaded", "status": 200}));
    Json(json!({"restored": true, "saved_at": snap["saved_at"]})).into_response()
}

async fn admin_sql(State(app): State<Arc<App>>, h: HeaderMap, body: Bytes) -> Response {
    if !h.contains_key("x-rocalcloud") {
        return Response::builder().status(403).body(Body::empty()).unwrap();
    }
    let Ok(v) = serde_json::from_slice::<Value>(&body) else {
        return Response::builder().status(400).body(Body::from("invalid JSON")).unwrap();
    };
    let Some(sql) = v["sql"].as_str() else {
        return Response::builder().status(400).body(Body::from("missing sql field")).unwrap();
    };
    let limit = v["limit"].as_u64().unwrap_or(500) as usize;
    let res = app.store.lock().unwrap().query_readonly(sql, limit);
    match res {
        Ok(res) => {
            emit(&app, json!({"ts": chrono::Utc::now().to_rfc3339(), "service": "sqlite", "op": "SqlQuery", "status": 200}));
            Json(res).into_response()
        }
        Err(e) => Response::builder().status(400).body(Body::from(e)).unwrap(),
    }
}

// Custom header forces a CORS preflight, so other websites can't wipe state with a blind POST.
async fn reset(State(app): State<Arc<App>>, h: HeaderMap) -> axum::http::StatusCode {
    if !h.contains_key("x-rocalcloud") {
        return axum::http::StatusCode::FORBIDDEN;
    }
    *app.ddb.lock().unwrap() = Default::default();
    *app.s3.lock().unwrap() = Default::default();
    *app.sqs.lock().unwrap() = Default::default();
    *app.iam.lock().unwrap() = Default::default();
    *app.net.lock().unwrap() = Default::default();
    *app.secrets.lock().unwrap() = Default::default();
    *app.ssm.lock().unwrap() = Default::default();
    *app.kms.lock().unwrap() = Default::default();
    *app.logs.lock().unwrap() = Default::default();
    *app.sns.lock().unwrap() = Default::default();
    *app.lambda.lock().unwrap() = Default::default();
    *app.eb.lock().unwrap() = Default::default();
    *app.sfn.lock().unwrap() = Default::default();
    *app.apigw.lock().unwrap() = Default::default();
    *app.cognito.lock().unwrap() = Default::default();
    *app.kinesis.lock().unwrap() = Default::default();
    *app.ses.lock().unwrap() = Default::default();
    *app.managed.lock().unwrap() = Default::default();
    *app.ecs.lock().unwrap() = Default::default();
    elb::close_all(&app);
    *app.elb.lock().unwrap() = Default::default();
    *app.route53.lock().unwrap() = Default::default();
    *app.cfn.lock().unwrap() = Default::default();
    tokio::spawn(managed::cleanup());
    route53::serve_dns(app.clone());
    let _ = app.events.send(json!({"ts": chrono::Utc::now().to_rfc3339(), "service": "admin", "op": "Reset", "status": 200}).to_string());
    axum::http::StatusCode::NO_CONTENT
}

// Invoke URL for HTTP APIs: /_api/{apiId}/[{stage}/]path
async fn api_invoke(State(app): State<Arc<App>>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    let t0 = Instant::now();
    let rest = uri.path().strip_prefix("/_api/").unwrap_or("");
    let (api, path) = rest.split_once('/').map_or((rest, "/".to_string()), |(a, p)| (a, format!("/{p}")));
    let (status, hdrs, out, route) = apigw::invoke(&app, method.as_str(), api, &path, uri.query().unwrap_or(""), &headers, &body).await;
    emit(&app, json!({"ts": chrono::Utc::now().to_rfc3339(), "service": "apigateway", "op": "Invoke", "target": format!("{api} {route}"),
        "path": format!("{method} {path}"), "status": status, "ms": t0.elapsed().as_secs_f64() * 1000.0}));
    let mut r = Response::builder().status(status);
    for (k, v) in hdrs {
        r = r.header(k, v);
    }
    r.body(Body::from(out)).unwrap_or_else(|_| Response::builder().status(502).body(Body::from("bad response headers from function")).unwrap())
}

// OIDC discovery and JWKS for Cognito user pools: /_cognito/{pool}/.well-known/...
async fn cognito_wellknown(axum::extract::Path((pool, doc)): axum::extract::Path<(String, String)>) -> Json<Value> {
    Json(if doc == "jwks.json" { cognito::jwks() } else { cognito::openid_config(&pool) })
}

// GET /_admin/reach?from=internet|i-..&to=...&protocol=tcp&port=22
async fn reach(State(app): State<Arc<App>>, axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>) -> Json<Value> {
    let g = |k: &str, d: &str| q.get(k).cloned().unwrap_or_else(|| d.to_string());
    let port = q.get("port").and_then(|p| p.parse().ok()).unwrap_or(-1);
    Json(app.net.lock().unwrap().reach(&g("from", ""), &g("to", ""), &g("protocol", "tcp"), port))
}

// Explanation agent. POSTs need the x-rocalcloud header (blocks cross-site requests).
async fn agent_status() -> Json<Value> {
    Json(agent::status().await)
}
async fn agent_explain(State(app): State<Arc<App>>, h: HeaderMap, Json(b): Json<Value>) -> Response {
    if !h.contains_key("x-rocalcloud") {
        return Response::builder().status(403).body(Body::empty()).unwrap();
    }
    match agent::explain(&app, b["request_id"].as_str().unwrap_or(""), b["llm"] != false).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => Response::builder().status(e.status).body(Body::from(e.msg)).unwrap(),
    }
}
async fn agent_ask(State(app): State<Arc<App>>, h: HeaderMap, Json(b): Json<Value>) -> Response {
    if !h.contains_key("x-rocalcloud") {
        return Response::builder().status(403).body(Body::empty()).unwrap();
    }
    Json(agent::ask(&app, b["question"].as_str().unwrap_or(""), b["confirm"].as_str()).await).into_response()
}

async fn agent_template(State(app): State<Arc<App>>) -> Response {
    Response::builder().header("content-type", "text/yaml; charset=utf-8").body(Body::from(agent::template(&app))).unwrap()
}

// Verification agent (inspector). POSTs require x-rocalcloud header.
async fn inspect_run(State(app): State<Arc<App>>, h: HeaderMap, body: Bytes) -> Response {
    if !h.contains_key("x-rocalcloud") {
        return Response::builder().status(403).body(Body::empty()).unwrap();
    }
    let req: Value = if body.is_empty() { json!({}) } else { serde_json::from_slice(&body).unwrap_or(json!({})) };
    match inspector::run(&app, &req).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => Response::builder().status(e.status).body(Body::from(e.msg)).unwrap(),
    }
}

async fn inspect_reports(State(app): State<Arc<App>>) -> Json<Value> {
    Json(inspector::reports_summary(&app))
}

async fn inspect_report(
    State(app): State<Arc<App>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>,
) -> Response {
    let Some(rep) = inspector::get_report(&app, &id) else {
        return Response::builder().status(404).body(Body::from("리포트를 찾을 수 없습니다.")).unwrap();
    };
    match q.get("format").map(String::as_str) {
        Some("md") => Response::builder().header("content-type", "text/markdown; charset=utf-8").body(Body::from(inspector::to_markdown(&rep))).unwrap(),
        Some("html") => Response::builder().header("content-type", "text/html; charset=utf-8").body(Body::from(inspector::to_html(&rep))).unwrap(),
        _ => Json(rep).into_response(),
    }
}

async fn inspect_replay(h: HeaderMap, Json(sc): Json<Value>) -> Response {
    if !h.contains_key("x-rocalcloud") {
        return Response::builder().status(403).body(Body::empty()).unwrap();
    }
    Json(inspector::run_custom_scenario(&sc).await).into_response()
}

async fn town() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("town.html"))
}

async fn ui() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("ui.html"))
}

const MAX_BODY: usize = 256 << 20;

async fn reject_oversize(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    if req.headers().get("content-length").and_then(|v| v.to_str().ok()).and_then(|s| s.parse::<usize>().ok()).is_some_and(|n| n > MAX_BODY) {
        return Response::builder().status(413).body(Body::from("Payload Too Large")).unwrap();
    }
    next.run(req).await
}

// RC_CONFIG names a KEY=VALUE file (# comments). Variables already in the environment win. It is read before the
// runtime starts any thread, so setting the process environment here is safe.
fn load_config() {
    let Ok(path) = std::env::var("RC_CONFIG") else { return };
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("RC_CONFIG {path}: {e}"));
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let Some((k, v)) = line.split_once('=') else { panic!("RC_CONFIG {path}: not KEY=VALUE: {line}") };
        if std::env::var_os(k.trim()).is_none() {
            std::env::set_var(k.trim(), v.trim().trim_matches('"'));
        }
    }
}

const CONFIG_KEYS: &[&str] = &["ENFORCE_IAM", "VERIFY_SIGV4", "BIND", "REGION", "RC_CONFIG", "RC_STATE_FILE", "RC_SQLITE_FILE", "RC_TOWN_ORIGIN",
    "RC_LLM_URL", "RC_LLM_MODEL", "RC_DNS_PORT", "RC_DOCKER", "RC_CONTAINER_MEMORY", "RC_PYTHON", "RC_NODE"];

async fn get_config() -> Json<Value> {
    let vars: serde_json::Map<String, Value> = CONFIG_KEYS.iter().map(|k| (k.to_string(), json!(std::env::var(k).ok()))).collect();
    Json(json!({"vars": vars, "endpoint": endpoint(), "enforce_iam": *ENFORCE, "verify_sigv4": *VERIFY,
        "root_secret": if std::env::var_os("RC_ROOT_SECRET").is_some() { "설정됨" } else { "기본값(test)" }}))
}

async fn shutdown_signal(app: Arc<App>) {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            sig.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    let _ = app.events.send(json!({"ts": chrono::Utc::now().to_rfc3339(), "service": "admin", "op": "Shutdown", "status": 200}).to_string());
    // Give SSE subscribers a brief moment to receive the Shutdown event before the listener closes.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    eprintln!("rocalcloud shutting down");
    // Graceful shutdown waits for open connections (SQS long polls, keep-alives); never hold the port for long.
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        std::process::exit(0);
    });
}

fn main() {
    load_config();
    tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime").block_on(serve());
}

async fn serve() {
    let bind = BIND.clone();
    let app = Arc::new(App {
        ddb: Default::default(),
        s3: Default::default(),
        sqs: Default::default(),
        iam: Default::default(),
        net: Default::default(),
        secrets: Default::default(),
        ssm: Default::default(),
        kms: Default::default(),
        logs: Default::default(),
        sns: Default::default(),
        lambda: Default::default(),
        eb: Default::default(),
        sfn: Default::default(),
        apigw: Default::default(),
        cognito: Default::default(),
        kinesis: Default::default(),
        ses: Default::default(),
        managed: Default::default(),
        ecs: Default::default(),
        elb: Default::default(),
        route53: Default::default(),
        cfn: Default::default(),
        inspector: Default::default(),
        chaos: Default::default(),
        events: broadcast::channel(1024).0,
        recent: Default::default(),
        store: Mutex::new(
            storage::SqliteStore::open(std::env::var("RC_SQLITE_FILE").ok().as_deref())
                .expect("open sqlite store"),
        ),
    });
    let _ = APP.set(app.clone());
    let router = Router::new()
        .route("/_events", get(events))
        .route("/_ui", get(ui))
        .route("/_town", get(town))
        .route("/_agent/status", get(agent_status))
        .route("/_agent/explain", post(agent_explain))
        .route("/_agent/ask", post(agent_ask))
        .route("/_agent/template", get(agent_template))
        .route("/_inspect/run", post(inspect_run))
        .route("/_inspect/reports", get(inspect_reports))
        .route("/_inspect/report/{id}", get(inspect_report))
        .route("/_inspect/replay", post(inspect_replay))
        .route("/favicon.ico", get(|| async { axum::http::StatusCode::NO_CONTENT })) // keep browsers out of the S3 log
        .route("/_admin/state", get(state))
        .route("/_admin/config", get(get_config))
        .route("/_admin/snapshot", get(get_snapshot).post(post_snapshot))
        .route("/_admin/snapshot/save", post(save_snapshot_file))
        .route("/_admin/sqlite/snapshots", get(sqlite_snapshots))
        .route("/_admin/sqlite/save", post(sqlite_save))
        .route("/_admin/sqlite/restore", post(sqlite_restore))
        .route("/_admin/sql", post(admin_sql))
        .route("/_admin/reset", post(reset))
        .route("/_admin/reach", get(reach))
        .route("/_api/{*rest}", axum::routing::any(api_invoke))
        .route("/_cognito/{pool}/.well-known/{doc}", get(cognito_wellknown))
        .route("/_admin/chaos", get(get_chaos).post(set_chaos))
        .fallback(handle)
        .layer(DefaultBodyLimit::max(MAX_BODY)) // ponytail: 256 MiB per request, bodies are held in memory
        .layer(axum::middleware::from_fn(reject_oversize))
        .with_state(app.clone());
    if let Ok(path) = std::env::var("RC_STATE_FILE") {
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(snap) = serde_json::from_str::<Value>(&text) {
                import_snapshot(&app, &snap);
                eprintln!("rocalcloud restored snapshot from {path}");
            }
        }
    } else if std::env::var("RC_SQLITE_FILE").is_ok() {
        let restored = app.store.lock().unwrap().load_service_state();
        if let Some(snap) = restored {
            import_snapshot(&app, &snap);
            eprintln!("rocalcloud restored state from SQLite ({})", app.store.lock().unwrap().path);
        }
    }
    tokio::spawn(managed::cleanup());
    route53::serve_dns(app.clone());
    let l = tokio::net::TcpListener::bind(&bind).await.expect("bind");
    eprintln!("rocalcloud listening on http://{bind}  (GUI: /_ui, town: /_town, events: /_events, ENFORCE_IAM={})", *ENFORCE as u8);
    axum::serve(l, router).with_graceful_shutdown(shutdown_signal(app)).await.unwrap();
}

#[cfg(test)]
mod town_tests {
    #[test]
    fn town_view_scrubs_sensitive_fields() {
        let s = super::town_view(
            r#"{"ts":"2026-11-21T00:00:00Z","service":"cognito-idp","op":"CodeSent","code":"123456","target":"u","principal":"arn:aws:iam::000000000000:user/alice","request_id":"req-1","error":{"code":"AccessDenied","message":"secret"},"auth":{"decision":"explicitDeny","enforced":true,"reason":"Deny policy X"},"chaos":{"rule":"r1","fault":"ThrottlingException"}}"#.into()
        );
        assert!(!s.contains("123456"));
        assert!(!s.contains("alice"));
        assert!(!s.contains("req-1"));
        assert!(!s.contains("secret"));
        assert!(!s.contains("Deny policy X"));
        assert!(!s.contains("\"rule\""));
        assert!(s.contains("CodeSent") && s.contains("explicitDeny") && s.contains("ThrottlingException"));
        let p = super::town_view(r#"{"auth":{"decision":"explicitDeny","source":"bucket policy"}}"#.into());
        assert!(p.contains("bucket policy"));
        assert!(!super::town_view(r#"{"auth":{"source":"user/alice secret"}}"#.into()).contains("alice"));
        assert_eq!(super::town_view("{\"op\":\"x\"}".into()), "{\"op\":\"x\"}");
        assert_eq!(super::town_view("not-json".into()), "{}");
    }

    #[test]
    fn parse_town_origin_rejects_off_and_invalid() {
        assert!(super::parse_town_origin("off").is_none());
        assert!(super::parse_town_origin("OFF").is_none());
        assert!(super::parse_town_origin("").is_none());
        assert!(super::parse_town_origin("javascript:alert(1)").is_none());
        assert!(super::parse_town_origin("https://example.com\r\nX-Bad: 1").is_none());
        assert_eq!(
            super::parse_town_origin("https://jinyounghwa.github.io/").unwrap().to_str().unwrap(),
            "https://jinyounghwa.github.io"
        );
    }
}

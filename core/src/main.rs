mod apigw;
mod cognito;
mod ddb;
mod ecs;
mod elb;
mod events;
mod iam;
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
mod sns;
mod sqs;
mod ssm;

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

static BIND: LazyLock<String> = LazyLock::new(|| std::env::var("BIND").unwrap_or_else(|_| "127.0.0.1:4566".into()));
// URL that code running inside the emulator (Lambda) uses to reach it.
pub fn endpoint() -> String {
    format!("http://{}", BIND.replace("0.0.0.0", "127.0.0.1"))
}

// ENFORCE_IAM=1 rejects denied requests; otherwise decisions are only reported in events.
static ENFORCE: LazyLock<bool> = LazyLock::new(|| std::env::var("ENFORCE_IAM").is_ok_and(|v| v == "1"));

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

// ponytail: in-memory state only; SQLite + snapshots come with the persistence sprint.
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
    chaos: Mutex<Vec<Value>>,
    events: broadcast::Sender<String>,
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
// ponytail: signatures are parsed, not verified.
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
}

const COGNITO_PUBLIC: &[&str] = &["SignUp", "ConfirmSignUp", "InitiateAuth", "RespondToAuthChallenge", "ForgotPassword",
    "ConfirmForgotPassword", "GetUser", "ChangePassword", "GlobalSignOut"];

enum Svc {
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
            vec![(format!("lambda:{op}"), res)]
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
    let decision = {
        let iam = app.iam.lock().unwrap();
        let mut last = None;
        for (a, r) in checks(&app, &svc, &body) {
            let d = iam.authorize(&principal, &a, &r);
            let deny = !d.allowed;
            last = Some(d);
            if deny {
                break;
            }
        }
        last
    };
    // A request either fails authorization, gets a chaos fault, or runs.
    let denied = decision.as_ref().filter(|d| !d.allowed && *ENFORCE).map(|d| {
        let (status, code) = match &svc {
            Svc::Ddb(_) | Svc::Json(..) => (400, "AccessDeniedException"),
            Svc::Lambda(..) => (403, "AccessDeniedException"),
            Svc::Sns(_) => (403, "AuthorizationError"),
            Svc::Ec2(_) => (403, "UnauthorizedOperation"),
            _ => (403, "AccessDenied"),
        };
        ApiErr { status, ..err(code, d.reason.clone()) }
    });
    let chaos = if denied.is_none() { chaos_fault(&app, service, &op).await } else { None };
    let fault = denied.or(chaos.as_ref().and_then(|(_, e)| e.as_ref().map(|e| ApiErr { status: e.status, code: e.code.clone(), msg: e.msg.clone(), extra: None })));

    let mut resp = match (svc, fault) {
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
                    send_to_target(&app, &rid, t["Arn"].as_str().unwrap_or(""), payload, "events");
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
                for d in deliveries {
                    deliver(&app, &rid, &d, "sns");
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
        ev["auth"] = json!({"decision": d.kind, "reason": d.reason, "enforced": *ENFORCE});
    }
    emit(&app, ev);
    resp
}

// Deliver an S3 bucket notification to SQS, SNS or Lambda.
fn s3_note(app: &Arc<App>, rid: &str, n: s3::Note) {
    send_to_target(app, rid, &n.target, serde_json::from_str(&n.body).unwrap_or_default(), "s3");
}

// Send a payload to an SQS queue, SNS topic or Lambda function by ARN.
fn send_to_target(app: &Arc<App>, rid: &str, arn: &str, payload: Value, from: &str) {
    let text = match &payload {
        Value::String(s) => s.clone(),
        v => v.to_string(),
    };
    if arn.starts_with("arn:aws:lambda:") {
        let (app, name, from) = (app.clone(), lambda::name_of(arn), from.to_string());
        tokio::spawn(async move { lambda::invoke_logged(&app, &name, payload, &from).await });
    } else if arn.starts_with("arn:aws:sns:") {
        let subject = if from == "s3" { "Amazon S3 Notification" } else { "" };
        let mut q: HashMap<String, String> = [("Action", "Publish"), ("TopicArn", arn), ("Message", text.as_str())].map(|(k, v)| (k.to_string(), v.to_string())).into();
        if !subject.is_empty() {
            q.insert("Subject".into(), subject.into());
        }
        let r = app.sns.lock().unwrap().handle(&q);
        for d in r.map(|(_, ds)| ds).unwrap_or_default() {
            deliver(app, rid, &d, "sns");
        }
    } else {
        deliver(app, rid, &sns::Delivery { protocol: "sqs".into(), endpoint: arn.into(), body: text }, from);
    }
}

// Ticker for a rate() rule; it stops when the rule is replaced or deleted.
fn start_schedule(app: Arc<App>, bus: String, name: String) {
    let Some((secs, generation)) = app.eb.lock().unwrap().schedule_of(&bus, &name) else { return };
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
            let due = app.eb.lock().unwrap().scheduled(&bus, &name, generation);
            match due {
                None => return,
                Some(None) => continue, // disabled
                Some(Some((targets, rule_arn))) => {
                    let ev = events::envelope("aws.events", "Scheduled Event", json!({}), json!([rule_arn]));
                    for t in targets {
                        send_to_target(&app, "schedule", t["Arn"].as_str().unwrap_or(""), events::payload(&t, &ev), "events");
                    }
                }
            }
        }
    });
}

// Push a message to its subscriber and report it as its own event.
fn deliver(app: &Arc<App>, rid: &str, d: &sns::Delivery, from: &str) {
    let ok = match d.protocol.as_str() {
        "sqs" => app.sqs.lock().unwrap().deliver(d.endpoint.rsplit(':').next().unwrap_or(""), d.body.clone()),
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
async fn events(State(app): State<Arc<App>>) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    Sse::new(futures_util::stream::unfold(app.events.subscribe(), |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(s) => return Some((Ok(Event::default().data(s)), rx)),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => return None,
            }
        }
    }))
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
        "secrets": app.secrets.lock().unwrap().admin(),
        "ssm": app.ssm.lock().unwrap().admin(),
        "kms": app.kms.lock().unwrap().admin(),
        "logs": app.logs.lock().unwrap().admin(),
    }))
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

async fn ui() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("ui.html"))
}

#[tokio::main]
async fn main() {
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
        chaos: Default::default(),
        events: broadcast::channel(1024).0,
    });
    let router = Router::new()
        .route("/_events", get(events))
        .route("/_ui", get(ui))
        .route("/favicon.ico", get(|| async { axum::http::StatusCode::NO_CONTENT })) // keep browsers out of the S3 log
        .route("/_admin/state", get(state))
        .route("/_admin/reset", post(reset))
        .route("/_admin/reach", get(reach))
        .route("/_api/{*rest}", axum::routing::any(api_invoke))
        .route("/_cognito/{pool}/.well-known/{doc}", get(cognito_wellknown))
        .route("/_admin/chaos", get(get_chaos).post(set_chaos))
        .fallback(handle)
        .layer(DefaultBodyLimit::max(256 << 20)) // ponytail: 256 MiB per request, bodies are held in memory
        .with_state(app.clone());
    tokio::spawn(managed::cleanup());
    route53::serve_dns(app.clone());
    let l = tokio::net::TcpListener::bind(&bind).await.expect("bind");
    eprintln!("rocalcloud listening on http://{bind}  (GUI: /_ui, events: /_events, ENFORCE_IAM={})", *ENFORCE as u8);
    axum::serve(l, router).await.unwrap();
}

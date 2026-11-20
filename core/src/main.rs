mod ddb;
mod s3;
mod sqs;

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
    time::Instant,
};
use tokio::sync::broadcast;

pub const ACCOUNT: &str = "000000000000";
pub static REGION: LazyLock<String> =
    LazyLock::new(|| std::env::var("REGION").unwrap_or_else(|_| "us-east-1".into()));

pub struct ApiErr {
    pub status: u16,
    pub code: String,
    pub msg: String,
    pub extra: Option<Value>,
}

pub fn err(code: &str, msg: impl Into<String>) -> ApiErr {
    ApiErr { status: 400, code: code.into(), msg: msg.into(), extra: None }
}

// ponytail: in-memory state only; SQLite + snapshots come with the persistence sprint.
pub struct App {
    pub ddb: Mutex<ddb::Db>,
    pub s3: Mutex<s3::Store>,
    pub sqs: Mutex<sqs::Queues>,
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

async fn handle(State(app): State<Arc<App>>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    let t0 = Instant::now();
    let rid = uuid::Uuid::new_v4().to_string();
    let target = headers.get("x-amz-target").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let (service, op, mut resp) = if let Some(op) = target.strip_prefix("DynamoDB_20120810.") {
        ("dynamodb", op.to_string(), json_reply("com.amazonaws.dynamodb.v20120810", ddb::handle(&app, op, &body)))
    } else if let Some(op) = target.strip_prefix("AmazonSQS.") {
        let host = headers.get("host").and_then(|v| v.to_str().ok()).unwrap_or("localhost");
        ("sqs", op.to_string(), json_reply("com.amazonaws.sqs", sqs::handle(&app, op, &body, host).await))
    } else {
        let (op, r) = s3::handle(&app, &method, &uri, &headers, body);
        ("s3", op.to_string(), r)
    };
    let h = resp.headers_mut();
    h.insert("x-amzn-requestid", rid.parse().unwrap());
    h.insert("x-amz-request-id", rid.parse().unwrap());
    let ev = json!({
        "ts": chrono::Utc::now().to_rfc3339(), "request_id": rid, "service": service, "op": op,
        "status": resp.status().as_u16(), "ms": t0.elapsed().as_secs_f64() * 1000.0,
    });
    println!("{ev}");
    let _ = app.events.send(ev.to_string());
    resp
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
    let _ = app.events.send(json!({"ts": chrono::Utc::now().to_rfc3339(), "service": "admin", "op": "Reset", "status": 200}).to_string());
    axum::http::StatusCode::NO_CONTENT
}

async fn ui() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("ui.html"))
}

#[tokio::main]
async fn main() {
    let bind = std::env::var("BIND").unwrap_or_else(|_| "127.0.0.1:4566".into());
    let app = Arc::new(App {
        ddb: Default::default(),
        s3: Default::default(),
        sqs: Default::default(),
        events: broadcast::channel(1024).0,
    });
    let router = Router::new()
        .route("/_events", get(events))
        .route("/_ui", get(ui))
        .route("/_admin/state", get(state))
        .route("/_admin/reset", post(reset))
        .fallback(handle)
        .layer(DefaultBodyLimit::max(256 << 20)) // ponytail: 256 MiB per request, bodies are held in memory
        .with_state(app);
    let l = tokio::net::TcpListener::bind(&bind).await.expect("bind");
    eprintln!("rocalcloud listening on http://{bind}  (GUI: /_ui, events: /_events)");
    axum::serve(l, router).await.unwrap();
}

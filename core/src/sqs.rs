use crate::{err, ApiErr, App, ACCOUNT, REGION};
use md5::{Digest, Md5};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

// ponytail: FIFO queues behave like ordered standard queues (no dedup / group locking); message attributes are not stored.
struct Msg {
    id: String,
    body: String,
    md5: String,
    visible_at: Instant,
    receipt: Option<String>,
    receives: u64,
    sent: u128,
    first: Option<u128>,
}

struct Queue {
    attrs: BTreeMap<String, String>,
    msgs: Vec<Msg>,
}

#[derive(Default)]
pub struct Queues {
    q: BTreeMap<String, Queue>,
}

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()
}
fn s<'a>(r: &'a Value, k: &str) -> Result<&'a str, ApiErr> {
    r[k].as_str().ok_or_else(|| err("MissingParameter", format!("{k} is required")))
}
fn no_queue() -> ApiErr {
    err("QueueDoesNotExist", "The specified queue does not exist.")
}
fn queue<'a>(qs: &'a mut Queues, r: &Value) -> Result<&'a mut Queue, ApiErr> {
    let name = s(r, "QueueUrl")?.rsplit('/').next().unwrap_or("");
    qs.q.get_mut(name).ok_or_else(no_queue)
}
fn str_map(v: &Value) -> BTreeMap<String, String> {
    v.as_object()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string())).collect())
        .unwrap_or_default()
}
fn entries(r: &Value) -> impl Iterator<Item = &Value> {
    r["Entries"].as_array().into_iter().flatten()
}

pub async fn handle(app: &App, op: &str, body: &[u8], host: &str) -> Result<Value, ApiErr> {
    let req: Value = serde_json::from_slice(body).map_err(|e| err("SerializationException", e.to_string()))?;
    // Long polling: retry until a message shows up or WaitTimeSeconds passes.
    let wait = if op == "ReceiveMessage" { req["WaitTimeSeconds"].as_u64().unwrap_or(0).min(20) } else { 0 };
    let deadline = Instant::now() + Duration::from_secs(wait);
    loop {
        let r = call(&mut app.sqs.lock().unwrap(), op, &req, host)?;
        if op != "ReceiveMessage" || r.get("Messages").is_some() || Instant::now() >= deadline {
            return Ok(r);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn send(q: &mut Queue, e: &Value) -> Result<Value, ApiErr> {
    let body = s(e, "MessageBody")?.to_string();
    let max: usize = q.attrs["MaximumMessageSize"].parse().unwrap_or(262144);
    if body.len() > max {
        return Err(err("InvalidParameterValue", format!("Message must be shorter than {max} bytes.")));
    }
    let delay = e["DelaySeconds"].as_u64().unwrap_or_else(|| q.attrs["DelaySeconds"].parse().unwrap_or(0));
    let m = Msg {
        id: uuid::Uuid::new_v4().to_string(),
        md5: format!("{:x}", Md5::digest(body.as_bytes())),
        body,
        visible_at: Instant::now() + Duration::from_secs(delay),
        receipt: None,
        receives: 0,
        sent: now_ms(),
        first: None,
    };
    let out = json!({"MessageId": m.id, "MD5OfMessageBody": m.md5});
    q.msgs.push(m);
    Ok(out)
}

fn call(qs: &mut Queues, op: &str, r: &Value, host: &str) -> Result<Value, ApiErr> {
    let url = |n: &str| format!("http://{host}/{ACCOUNT}/{n}");
    match op {
        "CreateQueue" => {
            let n = s(r, "QueueName")?;
            let given = str_map(&r["Attributes"]);
            if let Some(q) = qs.q.get(n) {
                if given.iter().any(|(k, v)| q.attrs.get(k) != Some(v)) {
                    return Err(err("QueueAlreadyExists", "A queue already exists with the same name and a different value for attribute(s)."));
                }
                return Ok(json!({"QueueUrl": url(n)}));
            }
            let mut attrs = BTreeMap::from(
                [("VisibilityTimeout", "30"), ("DelaySeconds", "0"), ("MaximumMessageSize", "262144"),
                 ("MessageRetentionPeriod", "345600"), ("ReceiveMessageWaitTimeSeconds", "0")]
                    .map(|(k, v)| (k.to_string(), v.to_string())),
            );
            attrs.insert("QueueArn".into(), format!("arn:aws:sqs:{}:{ACCOUNT}:{n}", *REGION));
            attrs.insert("CreatedTimestamp".into(), (now_ms() / 1000).to_string());
            attrs.extend(given);
            qs.q.insert(n.into(), Queue { attrs, msgs: vec![] });
            Ok(json!({"QueueUrl": url(n)}))
        }
        "GetQueueUrl" => {
            let n = s(r, "QueueName")?;
            qs.q.contains_key(n).then(|| json!({"QueueUrl": url(n)})).ok_or_else(no_queue)
        }
        "ListQueues" => {
            let p = r["QueueNamePrefix"].as_str().unwrap_or("");
            let v: Vec<String> = qs.q.keys().filter(|k| k.starts_with(p)).map(|k| url(k)).collect();
            Ok(if v.is_empty() { json!({}) } else { json!({"QueueUrls": v}) })
        }
        "DeleteQueue" => {
            let name = s(r, "QueueUrl")?.rsplit('/').next().unwrap_or("").to_string();
            qs.q.remove(&name).ok_or_else(no_queue)?;
            Ok(json!({}))
        }
        "PurgeQueue" => {
            queue(qs, r)?.msgs.clear();
            Ok(json!({}))
        }
        "SetQueueAttributes" => {
            queue(qs, r)?.attrs.extend(str_map(&r["Attributes"]));
            Ok(json!({}))
        }
        "GetQueueAttributes" => {
            let q = queue(qs, r)?;
            let now = Instant::now();
            let visible = q.msgs.iter().filter(|m| m.visible_at <= now).count();
            let inflight = q.msgs.iter().filter(|m| m.visible_at > now && m.receipt.is_some()).count();
            let mut a = q.attrs.clone();
            a.insert("ApproximateNumberOfMessages".into(), visible.to_string());
            a.insert("ApproximateNumberOfMessagesNotVisible".into(), inflight.to_string());
            a.insert("ApproximateNumberOfMessagesDelayed".into(), (q.msgs.len() - visible - inflight).to_string());
            let names: Vec<&str> = r["AttributeNames"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
            if !names.contains(&"All") {
                a.retain(|k, _| names.contains(&k.as_str()));
            }
            Ok(json!({"Attributes": a}))
        }
        "SendMessage" => send(queue(qs, r)?, r),
        "SendMessageBatch" => {
            let q = queue(qs, r)?;
            let (mut ok, mut bad) = (vec![], vec![]);
            for e in entries(r) {
                match send(q, e) {
                    Ok(mut v) => {
                        v["Id"] = e["Id"].clone();
                        ok.push(v)
                    }
                    Err(x) => bad.push(json!({"Id": e["Id"], "Code": x.code, "Message": x.msg, "SenderFault": true})),
                }
            }
            Ok(json!({"Successful": ok, "Failed": bad}))
        }
        "ReceiveMessage" => {
            let name = s(r, "QueueUrl")?.rsplit('/').next().unwrap_or("").to_string();
            let q = qs.q.get_mut(&name).ok_or_else(no_queue)?;
            let max = r["MaxNumberOfMessages"].as_u64().unwrap_or(1).clamp(1, 10) as usize;
            let vt = r["VisibilityTimeout"].as_u64().unwrap_or_else(|| q.attrs["VisibilityTimeout"].parse().unwrap_or(30));
            let redrive = q.attrs.get("RedrivePolicy").and_then(|p| serde_json::from_str::<Value>(p).ok()).and_then(|p| {
                let dlq = p["deadLetterTargetArn"].as_str()?.rsplit(':').next()?.to_string();
                let max = p["maxReceiveCount"].as_u64().or_else(|| p["maxReceiveCount"].as_str()?.parse().ok())?;
                Some((dlq, max))
            });
            let want_attrs = ["AttributeNames", "MessageSystemAttributeNames"]
                .iter()
                .any(|k| r[*k].as_array().is_some_and(|a| !a.is_empty()));
            let now = Instant::now();
            let (mut out, mut dead) = (vec![], vec![]);
            let mut i = 0;
            while i < q.msgs.len() && out.len() < max {
                if q.msgs[i].visible_at > now {
                    i += 1;
                    continue;
                }
                if redrive.as_ref().is_some_and(|(_, mx)| q.msgs[i].receives >= *mx) {
                    dead.push(q.msgs.remove(i));
                    continue;
                }
                let m = &mut q.msgs[i];
                m.receives += 1;
                m.visible_at = now + Duration::from_secs(vt);
                let rh = uuid::Uuid::new_v4().to_string();
                m.receipt = Some(rh.clone());
                let first = *m.first.get_or_insert(now_ms());
                let mut j = json!({"MessageId": m.id, "ReceiptHandle": rh, "MD5OfBody": m.md5, "Body": m.body});
                if want_attrs {
                    j["Attributes"] = json!({
                        "ApproximateReceiveCount": m.receives.to_string(),
                        "SentTimestamp": m.sent.to_string(),
                        "ApproximateFirstReceiveTimestamp": first.to_string(),
                    });
                }
                out.push(j);
                i += 1;
            }
            // Messages that hit maxReceiveCount move to the dead-letter queue.
            if let Some((dlq, _)) = redrive {
                if let Some(d) = qs.q.get_mut(&dlq) {
                    for mut m in dead {
                        (m.receives, m.receipt, m.visible_at) = (0, None, now);
                        d.msgs.push(m);
                    }
                }
            }
            Ok(if out.is_empty() { json!({}) } else { json!({"Messages": out}) })
        }
        "DeleteMessage" => {
            let rh = s(r, "ReceiptHandle")?;
            queue(qs, r)?.msgs.retain(|m| m.receipt.as_deref() != Some(rh));
            Ok(json!({}))
        }
        "DeleteMessageBatch" => {
            let q = queue(qs, r)?;
            let mut ok = vec![];
            for e in entries(r) {
                let rh = e["ReceiptHandle"].as_str();
                q.msgs.retain(|m| m.receipt.as_deref() != rh);
                ok.push(json!({"Id": e["Id"]}));
            }
            Ok(json!({"Successful": ok, "Failed": []}))
        }
        "ChangeMessageVisibility" => {
            let rh = s(r, "ReceiptHandle")?;
            let vt = r["VisibilityTimeout"].as_u64().unwrap_or(0);
            let m = queue(qs, r)?.msgs.iter_mut().find(|m| m.receipt.as_deref() == Some(rh));
            let m = m.ok_or_else(|| err("MessageNotInflight", "The message referred to isn't in flight."))?;
            m.visible_at = Instant::now() + Duration::from_secs(vt);
            Ok(json!({}))
        }
        _ => Err(err("InvalidAction", format!("{op} is not supported yet"))),
    }
}

impl Queues {
    // Delivery from another service (SNS, S3 notifications). False if the queue is gone.
    // Receive for an event source mapping, shaped as Lambda SQS records.
    pub fn receive_batch(&mut self, name: &str, max: u64) -> Vec<Value> {
        let r = call(self, "ReceiveMessage", &json!({"QueueUrl": name, "MaxNumberOfMessages": max, "AttributeNames": ["All"]}), "local");
        r.ok().and_then(|v| v["Messages"].as_array().cloned()).unwrap_or_default().into_iter().map(|m| json!({
            "messageId": m["MessageId"], "receiptHandle": m["ReceiptHandle"], "body": m["Body"], "md5OfBody": m["MD5OfBody"],
            "attributes": m["Attributes"], "messageAttributes": {}})).collect()
    }
    pub fn delete_receipt(&mut self, name: &str, receipt: &str) {
        if let Some(q) = self.q.get_mut(name) {
            q.msgs.retain(|m| m.receipt.as_deref() != Some(receipt));
        }
    }
    pub fn deliver(&mut self, name: &str, body: String) -> bool {
        self.q.get_mut(name).is_some_and(|q| send(q, &json!({ "MessageBody": body })).is_ok())
    }

    // GUI view: every queue with counts and up to 100 messages (peek, no receive).
    pub fn admin(&self) -> Value {
        let now = Instant::now();
        self.q
            .iter()
            .map(|(n, q)| json!({"name": n, "count": q.msgs.len(),
                "messages": q.msgs.iter().take(100).map(|m| json!({"id": m.id, "body": m.body, "receives": m.receives,
                    "state": if m.visible_at <= now { "visible" } else if m.receipt.is_some() { "inflight" } else { "delayed" }})).collect::<Vec<_>>()}))
            .collect()
    }
}

impl Queues {
    // Queue name → non-default attributes (infrastructure-code draft).
    pub fn export(&self) -> Vec<(String, BTreeMap<String, String>)> {
        let defaults = [("VisibilityTimeout", "30"), ("DelaySeconds", "0"), ("MaximumMessageSize", "262144"), ("MessageRetentionPeriod", "345600"), ("ReceiveMessageWaitTimeSeconds", "0")];
        self.q.iter().map(|(n, q)| {
            let a = q.attrs.iter().filter(|(k, v)| !["QueueArn", "CreatedTimestamp"].contains(&k.as_str()) && !defaults.contains(&(k.as_str(), v.as_str())))
                .map(|(k, v)| (k.clone(), v.clone())).collect();
            (n.clone(), a)
        }).collect()
    }
}

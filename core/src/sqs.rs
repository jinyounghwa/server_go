use crate::{err, ApiErr, App, ACCOUNT, REGION};
use base64::Engine;
use md5::{Digest, Md5};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

// FIFO: MessageGroupId is required, a group with a message in flight is held back (strict per-group order),
// and duplicates (MessageDeduplicationId or ContentBasedDeduplication) within 5 minutes return the first MessageId.
// Message attributes are validated (≤10, AWS naming rules, String/Number/Binary types) and returned with the AWS MD5.
// SNS raw delivery forwards attributes. ponytail: FIFO high-throughput mode and per-message DelaySeconds rules are not emulated.
const DEDUP_WINDOW: Duration = Duration::from_secs(300);

struct Msg {
    group: Option<String>,
    dedup: Option<String>,
    seq: u64,
    id: String,
    body: String,
    md5: String,
    mattrs: Value,
    visible_at: Instant,
    receipt: Option<String>,
    receives: u64,
    sent: u128,
    first: Option<u128>,
}

struct Queue {
    attrs: BTreeMap<String, String>,
    msgs: Vec<Msg>,
    seen: BTreeMap<String, (Instant, String, u64)>, // FIFO dedup id -> (sent, MessageId, SequenceNumber)
    seq: u64,
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
fn bad(m: impl Into<String>) -> ApiErr {
    err("InvalidParameterValue", m.into())
}

// Validates message attributes and returns (attributes, AWS MD5 of them, bytes they add to the message size).
fn msg_attrs(v: &Value) -> Result<(Value, Option<String>, usize), ApiErr> {
    let Some(m) = v.as_object().filter(|m| !m.is_empty()) else { return Ok((json!({}), None, 0)) };
    if m.len() > 10 {
        return Err(bad(format!("Number of message attributes [{}] exceeds the allowed maximum [10].", m.len())));
    }
    let mut names: Vec<&String> = m.keys().collect();
    names.sort();
    let (mut buf, mut size, mut out) = (Vec::new(), 0, serde_json::Map::new());
    for n in names {
        let a = &m[n];
        let low = n.to_ascii_lowercase();
        let name_ok = !n.is_empty() && n.len() <= 256 && n.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
            && !n.starts_with('.') && !n.ends_with('.') && !n.contains("..") && !low.starts_with("aws.") && !low.starts_with("amazon.");
        if !name_ok {
            return Err(bad(format!("Message attribute name '{n}' is invalid.")));
        }
        let t = a["DataType"].as_str().unwrap_or("");
        let missing = || bad(format!("Message attribute '{n}' must contain a non-empty value of message attribute type '{t}'."));
        let (kind, val) = match t.split('.').next().unwrap_or("") {
            "String" | "Number" => (1u8, a["StringValue"].as_str().ok_or_else(missing)?.as_bytes().to_vec()),
            "Binary" => (2u8, base64::engine::general_purpose::STANDARD.decode(a["BinaryValue"].as_str().ok_or_else(missing)?).map_err(|_| missing())?),
            _ => return Err(bad(format!("The type of message attribute '{n}' is invalid. You must use only the following supported type prefixes: Binary, Number, String."))),
        };
        if val.is_empty() || t.len() > 256 {
            return Err(missing());
        }
        if t.starts_with("Number") && std::str::from_utf8(&val).ok().and_then(|s| s.parse::<f64>().ok()).is_none() {
            return Err(bad(format!("Can't cast the value of message (user) attribute '{n}' to a number.")));
        }
        for part in [n.as_bytes(), t.as_bytes()] {
            buf.extend((part.len() as u32).to_be_bytes());
            buf.extend(part);
        }
        buf.push(kind);
        buf.extend((val.len() as u32).to_be_bytes());
        buf.extend(&val);
        size += n.len() + t.len() + val.len();
        let key = if kind == 1 { "StringValue" } else { "BinaryValue" };
        out.insert(n.clone(), json!({"DataType": t, key: a[key]}));
    }
    Ok((Value::Object(out), Some(format!("{:x}", Md5::digest(&buf))), size))
}

// MessageAttributeNames: "All" / ".*", "prefix.*", or exact names.
fn pick_attrs(all: &Value, want: &Value) -> Value {
    let pats: Vec<&str> = want.as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    let keep = |k: &str| pats.iter().any(|p| *p == "All" || *p == ".*" || *p == k || p.strip_suffix(".*").is_some_and(|pre| k.starts_with(&format!("{pre}."))));
    Value::Object(all.as_object().into_iter().flatten().filter(|(k, _)| keep(k)).map(|(k, v)| (k.clone(), v.clone())).collect())
}

// A queue policy must be a valid resource policy; an empty string removes it.
fn check_policy(attrs: &BTreeMap<String, String>) -> Result<(), ApiErr> {
    match attrs.get("Policy").filter(|p| !p.is_empty()) {
        None => Ok(()),
        Some(p) => serde_json::from_str::<Value>(p)
            .map_err(|e| e.to_string())
            .and_then(|v| crate::iam::validate_resource_policy(&v))
            .map_err(|m| err("InvalidAttributeValue", format!("Invalid value for the parameter Policy. Reason: {m}"))),
    }
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
    let (mattrs, attr_md5, attr_size) = msg_attrs(&e["MessageAttributes"])?;
    if body.len() + attr_size > max {
        return Err(err("InvalidParameterValue", format!("Message must be shorter than {max} bytes.")));
    }
    let delay = e["DelaySeconds"].as_u64().unwrap_or_else(|| q.attrs["DelaySeconds"].parse().unwrap_or(0));
    let fifo = q.attrs.get("FifoQueue").is_some_and(|v| v == "true");
    let (group, dedup) = if fifo {
        let g = e["MessageGroupId"].as_str().ok_or_else(|| err("MissingParameter", "The request must contain the parameter MessageGroupId."))?;
        let d = match e["MessageDeduplicationId"].as_str() {
            Some(d) => d.to_string(),
            None if q.attrs.get("ContentBasedDeduplication").is_some_and(|v| v == "true") => crate::sigv4::sha256_hex(body.as_bytes()),
            None => return Err(err("InvalidParameterValue", "The queue should either have ContentBasedDeduplication enabled or MessageDeduplicationId provided explicitly")),
        };
        let now = Instant::now();
        q.seen.retain(|_, (t, ..)| now.duration_since(*t) < DEDUP_WINDOW);
        if let Some((_, id, seq)) = q.seen.get(&d) {
            let mut dup = json!({"MessageId": id, "MD5OfMessageBody": format!("{:x}", Md5::digest(body.as_bytes())), "SequenceNumber": seq.to_string()});
            if let Some(a) = &attr_md5 {
                dup["MD5OfMessageAttributes"] = json!(a);
            }
            return Ok(dup);
        }
        (Some(g.to_string()), Some(d))
    } else {
        (None, None)
    };
    q.seq += 1;
    let m = Msg {
        group,
        dedup,
        seq: q.seq,
        id: uuid::Uuid::new_v4().to_string(),
        md5: format!("{:x}", Md5::digest(body.as_bytes())),
        body,
        mattrs,
        visible_at: Instant::now() + Duration::from_secs(delay),
        receipt: None,
        receives: 0,
        sent: now_ms(),
        first: None,
    };
    let mut out = json!({"MessageId": m.id, "MD5OfMessageBody": m.md5});
    if let Some(a) = attr_md5 {
        out["MD5OfMessageAttributes"] = json!(a);
    }
    if let Some(d) = &m.dedup {
        out["SequenceNumber"] = json!(m.seq.to_string());
        q.seen.insert(d.clone(), (Instant::now(), m.id.clone(), m.seq));
    }
    q.msgs.push(m);
    Ok(out)
}

fn call(qs: &mut Queues, op: &str, r: &Value, host: &str) -> Result<Value, ApiErr> {
    let url = |n: &str| format!("http://{host}/{ACCOUNT}/{n}");
    match op {
        "CreateQueue" => {
            let n = s(r, "QueueName")?;
            let given = str_map(&r["Attributes"]);
            check_policy(&given)?;
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
            if attrs.get("FifoQueue").is_some_and(|v| v == "true") != n.ends_with(".fifo") {
                return Err(err("InvalidParameterValue", "The name of a FIFO queue can only include alphanumeric characters, hyphens, or underscores, must end with .fifo suffix."));
            }
            qs.q.insert(n.into(), Queue { attrs, msgs: vec![], seen: BTreeMap::new(), seq: 0 });
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
            let given = str_map(&r["Attributes"]);
            check_policy(&given)?;
            let q = queue(qs, r)?;
            if given.get("Policy").is_some_and(|p| p.is_empty()) {
                q.attrs.remove("Policy");
            }
            q.attrs.extend(given.into_iter().filter(|(k, v)| !(k == "Policy" && v.is_empty())));
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
            let mut held: Vec<String> = vec![]; // FIFO groups whose earlier message is in flight or delayed
            while i < q.msgs.len() && out.len() < max {
                if q.msgs[i].group.as_ref().is_some_and(|g| held.contains(g)) {
                    i += 1;
                    continue;
                }
                if q.msgs[i].visible_at > now {
                    held.extend(q.msgs[i].group.clone());
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
                let picked = pick_attrs(&m.mattrs, &r["MessageAttributeNames"]);
                if let Ok((a, Some(md5), _)) = msg_attrs(&picked) {
                    j["MessageAttributes"] = a;
                    j["MD5OfMessageAttributes"] = json!(md5);
                }
                if want_attrs {
                    j["Attributes"] = json!({
                        "ApproximateReceiveCount": m.receives.to_string(),
                        "SentTimestamp": m.sent.to_string(),
                        "ApproximateFirstReceiveTimestamp": first.to_string(),
                    });
                    if let (Some(g), Some(d)) = (&m.group, &m.dedup) {
                        j["Attributes"]["MessageGroupId"] = json!(g);
                        j["Attributes"]["MessageDeduplicationId"] = json!(d);
                        j["Attributes"]["SequenceNumber"] = json!(m.seq.to_string());
                    }
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

// Lambda's SQS event shape for message attributes.
fn lambda_attrs(v: &Value) -> Value {
    Value::Object(v.as_object().into_iter().flatten().map(|(k, a)| {
        let mut o = json!({"dataType": a["DataType"], "stringListValues": [], "binaryListValues": []});
        for (from, to) in [("StringValue", "stringValue"), ("BinaryValue", "binaryValue")] {
            if !a[from].is_null() {
                o[to] = a[from].clone();
            }
        }
        (k.clone(), o)
    }).collect())
}

impl Queues {
    // Delivery from another service (SNS, S3 notifications). False if the queue is gone.
    // Receive for an event source mapping, shaped as Lambda SQS records.
    pub fn receive_batch(&mut self, name: &str, max: u64) -> Vec<Value> {
        let r = call(self, "ReceiveMessage", &json!({"QueueUrl": name, "MaxNumberOfMessages": max, "AttributeNames": ["All"], "MessageAttributeNames": ["All"]}), "local");
        r.ok().and_then(|v| v["Messages"].as_array().cloned()).unwrap_or_default().into_iter().map(|m| json!({
            "messageId": m["MessageId"], "receiptHandle": m["ReceiptHandle"], "body": m["Body"], "md5OfBody": m["MD5OfBody"],
            "attributes": m["Attributes"], "messageAttributes": lambda_attrs(&m["MessageAttributes"])})).collect()
    }
    // Queue policy (the Policy attribute), consulted by the authorizer.
    pub fn policy(&self, name: &str) -> Option<Value> {
        self.q.get(name)?.attrs.get("Policy").and_then(|p| serde_json::from_str(p).ok())
    }

    pub fn exists(&self, name: &str) -> bool {
        self.q.contains_key(name)
    }
    pub fn delete_receipt(&mut self, name: &str, receipt: &str) {
        if let Some(q) = self.q.get_mut(name) {
            q.msgs.retain(|m| m.receipt.as_deref() != Some(receipt));
        }
    }
    pub fn deliver(&mut self, name: &str, body: String, attrs: &Value) -> bool {
        self.q.get_mut(name).is_some_and(|q| send(q, &json!({ "MessageBody": body, "MessageAttributes": attrs })).is_ok())
    }

    // GUI view: every queue with counts and up to 100 messages (peek, no receive).
    pub fn admin(&self) -> Value {
        let now = Instant::now();
        self.q
            .iter()
            .map(|(n, q)| json!({"name": n, "count": q.msgs.len(), "policy": q.attrs.get("Policy").and_then(|p| serde_json::from_str::<Value>(p).ok()),
                "messages": q.msgs.iter().take(100).map(|m| json!({"id": m.id, "body": m.body, "receives": m.receives,
                    "attrs": m.mattrs.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>().join(", ")).unwrap_or_default(),
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

    pub fn snap_save(&self) -> Value {
        let qs: Vec<Value> = self.q.iter().map(|(n, q)| {
            let msgs: Vec<Value> = q.msgs.iter().map(|m| json!({
                "id": m.id, "body": m.body, "md5": m.md5, "receives": m.receives, "sent": m.sent as u64,
                "group": m.group, "dedup": m.dedup, "seq": m.seq, "mattrs": m.mattrs,
            })).collect();
            json!({"name": n, "attrs": q.attrs, "msgs": msgs})
        }).collect();
        json!(qs)
    }

    pub fn snap_load(&mut self, v: &Value) {
        self.q.clear();
        let now = Instant::now();
        for q in v.as_array().into_iter().flatten() {
            let Some(name) = q["name"].as_str() else { continue };
            let attrs = str_map(&q["attrs"]);
            let msgs: Vec<Msg> = q["msgs"].as_array().into_iter().flatten().enumerate().map(|(i, m)| {
                let body = m["body"].as_str().unwrap_or("").to_string();
                let md5 = m["md5"].as_str().map(String::from).unwrap_or_else(|| format!("{:x}", Md5::digest(&body)));
                Msg {
                    group: m["group"].as_str().map(String::from),
                    dedup: m["dedup"].as_str().map(String::from),
                    seq: m["seq"].as_u64().unwrap_or(i as u64 + 1),
                    id: m["id"].as_str().map(String::from).unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                    body, md5, visible_at: now, receipt: None,
                    mattrs: msg_attrs(&m["mattrs"]).map(|(a, ..)| a).unwrap_or_else(|_| json!({})),
                    receives: m["receives"].as_u64().unwrap_or(0),
                    sent: m["sent"].as_u64().map_or_else(now_ms, |x| x as u128),
                    first: None,
                }
            }).collect();
            let seq = msgs.iter().map(|m| m.seq).max().unwrap_or(0);
            self.q.insert(name.into(), Queue { attrs, msgs, seen: BTreeMap::new(), seq });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const EXPECTED_KIND_ORDER: &str = "9e7e72847e5db084ff08f403da3c182b";
    #[test]
    fn message_attribute_md5_and_rules() {
        // Reference value from the AWS SQS developer guide algorithm, computed independently with Python.
        let (a, md5, size) = msg_attrs(&json!({"Kind": {"DataType": "String", "StringValue": "order"}})).unwrap();
        assert_eq!(md5.as_deref(), Some(EXPECTED_KIND_ORDER));
        assert_eq!(size, 4 + 6 + 5);
        assert_eq!(a["Kind"]["StringValue"], "order");
        for bad_name in ["AWS.x", "amazon.y", ".a", "a.", "a..b", "a b", ""] {
            assert!(msg_attrs(&json!({bad_name: {"DataType": "String", "StringValue": "v"}})).is_err(), "{bad_name}");
        }
        assert!(msg_attrs(&json!({"n": {"DataType": "Number", "StringValue": "abc"}})).is_err());
        assert!(msg_attrs(&json!({"n": {"DataType": "Date", "StringValue": "1"}})).is_err());
        assert!(msg_attrs(&json!({"n": {"DataType": "String", "StringValue": ""}})).is_err());
        let eleven: serde_json::Map<String, Value> = (0..11).map(|i| (format!("k{i}"), json!({"DataType": "String", "StringValue": "v"}))).collect();
        assert!(msg_attrs(&Value::Object(eleven)).is_err());
        let picked = pick_attrs(&json!({"a.b": 1, "a.c": 2, "ab": 3, "x": 4}), &json!(["a.*", "x"]));
        assert_eq!(picked, json!({"a.b": 1, "a.c": 2, "x": 4}));
    }
}

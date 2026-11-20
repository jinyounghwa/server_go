// SNS (Query protocol). Publish returns deliveries; main hands them to SQS / Lambda.
// ponytail: http(s)/email/sms endpoints are accepted but never called; no FIFO dedup.
use crate::{err, ApiErr, ACCOUNT, REGION};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};

type Q = HashMap<String, String>;

pub struct Delivery {
    pub protocol: String,
    pub endpoint: String,
    pub body: String,
}
struct Sub {
    topic: String,
    protocol: String,
    endpoint: String,
    attrs: BTreeMap<String, String>,
}

#[derive(Default)]
pub struct Sns {
    topics: BTreeMap<String, BTreeMap<String, String>>, // topic ARN -> attributes
    subs: BTreeMap<String, Sub>,
    published: BTreeMap<String, u64>,
}

fn p<'a>(q: &'a Q, k: &str) -> Result<&'a str, ApiErr> {
    q.get(k).map(String::as_str).ok_or_else(|| err("InvalidParameter", format!("Invalid parameter: {k} is required")))
}
fn not_found() -> ApiErr {
    ApiErr { status: 404, ..err("NotFound", "Topic does not exist") }
}
// `Attributes.entry.N.key/value` style map parameters.
fn entries(q: &Q, name: &str) -> BTreeMap<String, String> {
    (1..).map_while(|i| Some((q.get(&format!("{name}.entry.{i}.key"))?.clone(), q.get(&format!("{name}.entry.{i}.value")).cloned().unwrap_or_default()))).collect()
}
// Map → Query XML <entry><key/><value/></entry> (see iam::to_xml).
fn xml_map(m: &BTreeMap<String, String>) -> Value {
    json!({ "__entries": m })
}

// ponytail: filter policies support exact strings, numbers, prefix, exists and anything-but on message attributes.
fn filter_ok(policy: &str, attrs: &Map<String, Value>) -> bool {
    let Ok(Value::Object(pol)) = serde_json::from_str::<Value>(policy) else { return true };
    pol.iter().all(|(k, rules)| {
        let have = attrs.get(k).and_then(|a| a["Value"].as_str());
        rules.as_array().is_some_and(|rs| {
            rs.iter().any(|r| match (r, have) {
                (Value::String(s), Some(h)) => s == h,
                (Value::Number(n), Some(h)) => h.parse::<f64>().ok() == n.as_f64(),
                (Value::Object(o), h) => match o.iter().next() {
                    Some((op, v)) if op == "exists" => v.as_bool() == Some(h.is_some()),
                    Some((op, v)) if op == "prefix" => h.is_some_and(|h| v.as_str().is_some_and(|p| h.starts_with(p))),
                    Some((op, v)) if op == "anything-but" => h.is_some_and(|h| !crate::iam::strs(v).iter().any(|x| x == h)),
                    _ => false,
                },
                _ => false,
            })
        })
    })
}

impl Sns {
    fn sub_json(&self, arn: &str, s: &Sub) -> Value {
        json!({"SubscriptionArn": arn, "Owner": ACCOUNT, "Protocol": s.protocol, "Endpoint": s.endpoint, "TopicArn": s.topic})
    }

    pub fn handle(&mut self, q: &Q) -> Result<(Value, Vec<Delivery>), ApiErr> {
        let action = q.get("Action").map_or("", String::as_str);
        let topic = |k: &str| -> Result<String, ApiErr> {
            let t = p(q, k)?;
            if self.topics.contains_key(t) { Ok(t.to_string()) } else { Err(not_found()) }
        };
        let out = match action {
            "CreateTopic" => {
                let n = p(q, "Name")?;
                let arn = format!("arn:aws:sns:{}:{ACCOUNT}:{n}", *REGION);
                let mut attrs = entries(q, "Attributes");
                attrs.insert("TopicArn".into(), arn.clone());
                attrs.insert("DisplayName".into(), attrs.get("DisplayName").cloned().unwrap_or_default());
                self.topics.entry(arn.clone()).or_insert(attrs);
                json!({ "TopicArn": arn })
            }
            "ListTopics" => json!({"Topics": self.topics.keys().map(|a| json!({"TopicArn": a})).collect::<Vec<_>>()}),
            "DeleteTopic" => {
                let t = p(q, "TopicArn")?;
                self.topics.remove(t);
                self.subs.retain(|_, s| s.topic != t);
                json!({})
            }
            "GetTopicAttributes" => {
                let t = topic("TopicArn")?;
                let mut a = self.topics[&t].clone();
                a.insert("SubscriptionsConfirmed".into(), self.subs.values().filter(|s| s.topic == t).count().to_string());
                a.insert("SubscriptionsPending".into(), "0".into());
                a.insert("Owner".into(), ACCOUNT.into());
                json!({ "Attributes": xml_map(&a) })
            }
            "SetTopicAttributes" => {
                let t = topic("TopicArn")?;
                let (k, v) = (p(q, "AttributeName")?, q.get("AttributeValue").cloned().unwrap_or_default());
                self.topics.get_mut(&t).unwrap().insert(k.into(), v);
                json!({})
            }
            "Subscribe" => {
                let t = topic("TopicArn")?;
                let (proto, ep) = (p(q, "Protocol")?.to_string(), q.get("Endpoint").cloned().unwrap_or_default());
                if let Some((arn, _)) = self.subs.iter().find(|(_, s)| s.topic == t && s.protocol == proto && s.endpoint == ep) {
                    return Ok((json!({ "SubscriptionArn": arn }), vec![]));
                }
                let arn = format!("{t}:{}", uuid::Uuid::new_v4());
                self.subs.insert(arn.clone(), Sub { topic: t, protocol: proto, endpoint: ep, attrs: entries(q, "Attributes") });
                json!({ "SubscriptionArn": arn })
            }
            "Unsubscribe" => {
                self.subs.remove(p(q, "SubscriptionArn")?);
                json!({})
            }
            "ListSubscriptions" => json!({"Subscriptions": self.subs.iter().map(|(a, s)| self.sub_json(a, s)).collect::<Vec<_>>()}),
            "ListSubscriptionsByTopic" => {
                let t = topic("TopicArn")?;
                json!({"Subscriptions": self.subs.iter().filter(|(_, s)| s.topic == t).map(|(a, s)| self.sub_json(a, s)).collect::<Vec<_>>()})
            }
            "GetSubscriptionAttributes" => {
                let a = p(q, "SubscriptionArn")?;
                let s = self.subs.get(a).ok_or_else(|| ApiErr { status: 404, ..err("NotFound", "Subscription does not exist") })?;
                let mut m = s.attrs.clone();
                for (k, v) in [("SubscriptionArn", a), ("TopicArn", &s.topic), ("Protocol", &s.protocol), ("Endpoint", &s.endpoint), ("Owner", ACCOUNT)] {
                    m.insert(k.into(), v.into());
                }
                m.insert("PendingConfirmation".into(), "false".into());
                json!({ "Attributes": xml_map(&m) })
            }
            "SetSubscriptionAttributes" => {
                let a = p(q, "SubscriptionArn")?;
                let s = self.subs.get_mut(a).ok_or_else(|| ApiErr { status: 404, ..err("NotFound", "Subscription does not exist") })?;
                s.attrs.insert(p(q, "AttributeName")?.into(), q.get("AttributeValue").cloned().unwrap_or_default());
                json!({})
            }
            "Publish" => {
                let t = q.get("TopicArn").or(q.get("TargetArn")).cloned().ok_or_else(|| err("InvalidParameter", "TopicArn is required"))?;
                if !self.topics.contains_key(&t) {
                    return Err(not_found());
                }
                let msg = p(q, "Message")?;
                let id = uuid::Uuid::new_v4().to_string();
                let attrs: Map<String, Value> = (1..)
                    .map_while(|i| {
                        let pre = format!("MessageAttributes.entry.{i}");
                        let name = q.get(&format!("{pre}.Name"))?;
                        let ty = q.get(&format!("{pre}.Value.DataType")).cloned().unwrap_or("String".into());
                        let v = q.get(&format!("{pre}.Value.StringValue")).or(q.get(&format!("{pre}.Value.BinaryValue"))).cloned().unwrap_or_default();
                        Some((name.clone(), json!({"Type": ty, "Value": v})))
                    })
                    .collect();
                let mut env = json!({"Type": "Notification", "MessageId": id, "TopicArn": t, "Message": msg,
                    "Timestamp": chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(), "SignatureVersion": "1",
                    "Signature": "LOCAL", "SigningCertURL": "", "UnsubscribeURL": ""});
                if let Some(s) = q.get("Subject") {
                    env["Subject"] = s.clone().into();
                }
                if !attrs.is_empty() {
                    env["MessageAttributes"] = attrs.clone().into();
                }
                let deliveries = self.subs.iter()
                    .filter(|(_, s)| s.topic == t && s.attrs.get("FilterPolicy").is_none_or(|f| filter_ok(f, &attrs)))
                    .map(|(arn, s)| {
                        let raw = s.attrs.get("RawMessageDelivery").is_some_and(|v| v == "true");
                        let mut e = env.clone();
                        e["UnsubscribeURL"] = format!("local:unsubscribe:{arn}").into();
                        Delivery { protocol: s.protocol.clone(), endpoint: s.endpoint.clone(), body: if raw { msg.to_string() } else { e.to_string() } }
                    })
                    .collect();
                *self.published.entry(t).or_default() += 1;
                return Ok((json!({ "MessageId": id }), deliveries));
            }
            _ => return Err(err("InvalidAction", format!("{action} is not supported yet"))),
        };
        Ok((out, vec![]))
    }

    pub fn admin(&self) -> Value {
        self.topics
            .keys()
            .map(|t| {
                let rows: Vec<Value> = self.subs.iter().filter(|(_, s)| s.topic == *t)
                    .map(|(a, s)| json!([s.protocol, s.endpoint, s.attrs.get("FilterPolicy").cloned().unwrap_or_default(), a.rsplit(':').next()])).collect();
                json!({"name": t.rsplit(':').next(), "count": rows.len(), "sub": format!("{t} · 발행 {}건", self.published.get(t).unwrap_or(&0)),
                       "cols": ["프로토콜", "엔드포인트", "필터", "구독 ID"], "rows": rows})
            })
            .collect()
    }
}

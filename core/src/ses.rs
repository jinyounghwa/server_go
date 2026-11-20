// SES v1 (Query) and v2 (REST-JSON) over one local mailbox. Nothing is ever sent; mail lands in the GUI.
// Like the SES sandbox, the sender must be a verified identity; verification succeeds instantly.
use crate::{err, ApiErr};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};

struct Mail {
    id: String,
    from: String,
    to: Vec<String>,
    subject: String,
    body: String,
    at: String,
}

#[derive(Default)]
pub struct Ses {
    identities: BTreeSet<String>,
    outbox: Vec<Mail>,
}

fn rejected(from: &str) -> ApiErr {
    err("MessageRejected", format!("Email address is not verified. The following identities failed the check: {from}"))
}

impl Ses {
    // A sender is allowed if the address or its domain is verified.
    fn verified(&self, from: &str) -> bool {
        let addr = from.rsplit('<').next().unwrap_or(from).trim_end_matches('>').trim();
        self.identities.contains(addr) || addr.split_once('@').is_some_and(|(_, d)| self.identities.contains(d))
    }

    fn send(&mut self, from: &str, to: Vec<String>, subject: &str, body: &str) -> Result<String, ApiErr> {
        if !self.verified(from) {
            return Err(rejected(from));
        }
        if to.is_empty() {
            return Err(err("InvalidParameterValue", "Missing final '@domain'"));
        }
        let id = format!("{}-local", uuid::Uuid::new_v4());
        self.outbox.push(Mail { id: id.clone(), from: from.into(), to, subject: subject.into(), body: body.into(), at: chrono::Utc::now().to_rfc3339() });
        Ok(id)
    }

    // Subject and first text part of a raw MIME message (good enough to show in the mailbox).
    fn raw_parts(raw: &str) -> (String, String, Vec<String>, String) {
        let (head, body) = raw.split_once("\r\n\r\n").or_else(|| raw.split_once("\n\n")).unwrap_or((raw, ""));
        let h = |name: &str| head.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string())).unwrap_or_default();
        let to = h("To").split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        (h("From"), h("Subject"), to, body.to_string())
    }

    // v1 Query API.
    pub fn handle_query(&mut self, q: &HashMap<String, String>) -> Result<Value, ApiErr> {
        let list = |name: &str| (1..).map_while(|i| q.get(&format!("{name}.member.{i}")).cloned()).collect::<Vec<_>>();
        let p = |k: &str| q.get(k).cloned().ok_or_else(|| err("ValidationError", format!("{k} is required")));
        Ok(match q.get("Action").map_or("", String::as_str) {
            "VerifyEmailIdentity" | "VerifyEmailAddress" => {
                self.identities.insert(p("EmailAddress")?);
                json!({})
            }
            "VerifyDomainIdentity" => {
                self.identities.insert(p("Domain")?);
                json!({"VerificationToken": "local-verification-token"})
            }
            "ListIdentities" => json!({"Identities": self.identities.iter().collect::<Vec<_>>()}),
            "DeleteIdentity" => {
                self.identities.remove(&p("Identity")?);
                json!({})
            }
            "GetIdentityVerificationAttributes" => {
                let m: serde_json::Map<String, Value> = list("Identities").into_iter()
                    .map(|i| { let s = if self.identities.contains(&i) { "Success" } else { "NotStarted" }; (i, json!({"VerificationStatus": s})) }).collect();
                json!({"VerificationAttributes": {"__entries": m}})
            }
            "SendEmail" => {
                let to = [list("Destination.ToAddresses"), list("Destination.CcAddresses"), list("Destination.BccAddresses")].concat();
                let body = q.get("Message.Body.Text.Data").or(q.get("Message.Body.Html.Data")).cloned().unwrap_or_default();
                json!({"MessageId": self.send(&p("Source")?, to, &q.get("Message.Subject.Data").cloned().unwrap_or_default(), &body)?})
            }
            "SendRawEmail" => {
                let raw = String::from_utf8_lossy(&crate::unb64(&p("RawMessage.Data")?).unwrap_or_default()).into_owned();
                let (from, subject, to, body) = Self::raw_parts(&raw);
                let from = q.get("Source").cloned().unwrap_or(from);
                let to = if list("Destinations").is_empty() { to } else { list("Destinations") };
                json!({"MessageId": self.send(&from, to, &subject, &body)?})
            }
            "GetSendQuota" => json!({"Max24HourSend": 200.0, "MaxSendRate": 1.0, "SentLast24Hours": self.outbox.len() as f64}),
            a => return Err(err("InvalidAction", format!("{a} is not supported yet"))),
        })
    }

    // v2 REST API; `path` follows /v2/email/.
    pub fn handle_v2(&mut self, method: &str, path: &str, b: &Value) -> Result<(u16, Value), ApiErr> {
        let parts: Vec<String> = path.trim_matches('/').split('/').map(crate::s3::pct_decode).collect();
        let parts: Vec<&str> = parts.iter().map(String::as_str).collect();
        Ok(match (method, parts.as_slice()) {
            ("POST", ["identities"]) => {
                let id = b["EmailIdentity"].as_str().ok_or_else(|| err("BadRequestException", "EmailIdentity is required"))?;
                self.identities.insert(id.into());
                (200, json!({"IdentityType": if id.contains('@') { "EMAIL_ADDRESS" } else { "DOMAIN" }, "VerifiedForSendingStatus": true}))
            }
            ("GET", ["identities"]) => (200, json!({"EmailIdentities": self.identities.iter().map(|i| json!({"IdentityName": i,
                "IdentityType": if i.contains('@') { "EMAIL_ADDRESS" } else { "DOMAIN" }, "SendingEnabled": true, "VerificationStatus": "SUCCESS"})).collect::<Vec<_>>()})),
            ("GET", ["identities", id]) => {
                if !self.identities.contains(*id) {
                    return Err(ApiErr { status: 404, ..err("NotFoundException", format!("Email identity {id} does not exist.")) });
                }
                (200, json!({"IdentityType": if id.contains('@') { "EMAIL_ADDRESS" } else { "DOMAIN" }, "VerifiedForSendingStatus": true, "VerificationStatus": "SUCCESS"}))
            }
            ("DELETE", ["identities", id]) => {
                self.identities.remove(*id);
                (200, json!({}))
            }
            ("POST", ["outbound-emails"]) => {
                let d = &b["Destination"];
                let to: Vec<String> = ["ToAddresses", "CcAddresses", "BccAddresses"].iter()
                    .flat_map(|k| d[*k].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(String::from))).collect();
                let c = &b["Content"];
                let id = if let Some(raw) = c["Raw"]["Data"].as_str() {
                    let raw = String::from_utf8_lossy(&crate::unb64(raw).unwrap_or_default()).into_owned();
                    let (from, subject, rto, body) = Self::raw_parts(&raw);
                    self.send(b["FromEmailAddress"].as_str().unwrap_or(&from), if to.is_empty() { rto } else { to }, &subject, &body)?
                } else {
                    let s = &c["Simple"];
                    let body = s["Body"]["Text"]["Data"].as_str().or(s["Body"]["Html"]["Data"].as_str()).unwrap_or("");
                    let from = b["FromEmailAddress"].as_str().ok_or_else(|| err("BadRequestException", "FromEmailAddress is required"))?;
                    self.send(from, to, s["Subject"]["Data"].as_str().unwrap_or(""), body)?
                };
                (200, json!({ "MessageId": id }))
            }
            _ => return Err(ApiErr { status: 404, ..err("NotFoundException", "Unsupported SES v2 resource") }),
        })
    }

    pub fn admin(&self) -> Value {
        if self.outbox.is_empty() && self.identities.is_empty() {
            return json!([]);
        }
        let rows: Vec<Value> = self.outbox.iter().rev().take(100).map(|m| json!([m.at, m.from, m.to.join(", "), m.subject, m.body, m.id])).collect();
        json!([{"name": "보낸 메일함", "count": self.outbox.len(),
                "sub": format!("인증된 발신자: {}", self.identities.iter().cloned().collect::<Vec<_>>().join(", ")),
                "cols": ["시각", "보낸 사람", "받는 사람", "제목", "본문", "ID"], "rows": rows}])
    }
}

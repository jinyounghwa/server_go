// Secrets Manager (JSON 1.1).
use crate::{epoch, err, need, ApiErr, ACCOUNT, REGION};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

struct Version {
    id: String,
    string: Option<String>,
    binary: Option<String>,
    stages: Vec<String>,
    created: f64,
}
struct Secret {
    arn: String,
    description: Option<String>,
    versions: Vec<Version>,
    created: f64,
    changed: f64,
    deleted: Option<f64>,
}

#[derive(Default)]
pub struct Secrets {
    s: BTreeMap<String, Secret>,
}

fn not_found() -> ApiErr {
    err("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")
}

// New version from SecretString/SecretBinary; it becomes AWSCURRENT, the old current becomes AWSPREVIOUS.
fn add_version(sec: &mut Secret, r: &Value) -> Option<String> {
    let (string, binary) = (r["SecretString"].as_str().map(String::from), r["SecretBinary"].as_str().map(String::from));
    if string.is_none() && binary.is_none() {
        return None;
    }
    let id = r["ClientRequestToken"].as_str().map_or_else(|| uuid::Uuid::new_v4().to_string(), String::from);
    if sec.versions.iter().any(|v| v.id == id) {
        return Some(id); // idempotent retry
    }
    for v in &mut sec.versions {
        v.stages.retain(|s| s != "AWSPREVIOUS");
        if let Some(i) = v.stages.iter().position(|s| s == "AWSCURRENT") {
            v.stages[i] = "AWSPREVIOUS".into();
        }
    }
    sec.versions.push(Version { id: id.clone(), string, binary, stages: vec!["AWSCURRENT".into()], created: epoch() });
    sec.changed = epoch();
    Some(id)
}

impl Secrets {
    fn key(&self, id: &str) -> Option<String> {
        if self.s.contains_key(id) {
            return Some(id.into());
        }
        self.s.iter().find(|(_, x)| x.arn == id).map(|(k, _)| k.clone())
    }
    pub fn arn_of(&self, id: &str) -> Option<String> {
        self.key(id).map(|k| self.s[&k].arn.clone())
    }
    fn describe(&self, n: &str, x: &Secret) -> Value {
        let stages: Map<String, Value> = x.versions.iter().filter(|v| !v.stages.is_empty()).map(|v| (v.id.clone(), json!(v.stages))).collect();
        let mut d = json!({"ARN": x.arn, "Name": n, "CreatedDate": x.created, "LastChangedDate": x.changed, "VersionIdsToStages": stages});
        if let Some(desc) = &x.description {
            d["Description"] = desc.clone().into();
        }
        if let Some(t) = x.deleted {
            d["DeletedDate"] = t.into();
        }
        d
    }

    pub fn handle(&mut self, op: &str, r: &Value) -> Result<Value, ApiErr> {
        if op == "CreateSecret" {
            let n = need(r, "Name")?;
            if self.s.contains_key(n) {
                return Err(err("ResourceExistsException", format!("The operation failed because the secret {n} already exists.")));
            }
            let suffix: String = uuid::Uuid::new_v4().simple().to_string()[..6].into();
            let now = epoch();
            let mut sec = Secret {
                arn: format!("arn:aws:secretsmanager:{}:{ACCOUNT}:secret:{n}-{suffix}", *REGION),
                description: r["Description"].as_str().map(String::from),
                versions: vec![],
                created: now,
                changed: now,
                deleted: None,
            };
            let vid = add_version(&mut sec, r);
            let out = json!({"ARN": sec.arn, "Name": n, "VersionId": vid});
            self.s.insert(n.into(), sec);
            return Ok(out);
        }
        if op == "ListSecrets" {
            let all = r["IncludePlannedDeletion"].as_bool().unwrap_or(false);
            let list: Vec<Value> = self.s.iter().filter(|(_, x)| all || x.deleted.is_none()).map(|(n, x)| self.describe(n, x)).collect();
            return Ok(json!({ "SecretList": list }));
        }
        if op == "GetRandomPassword" {
            let len = r["PasswordLength"].as_u64().unwrap_or(32) as usize;
            let chars = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#$%&*+-=?@^_";
            let pw: String = crate::rand_bytes(len).iter().map(|b| chars[*b as usize % chars.len()] as char).collect();
            return Ok(json!({ "RandomPassword": pw }));
        }
        let n = self.key(need(r, "SecretId")?).ok_or_else(not_found)?;
        let deleted = self.s[&n].deleted.is_some();
        if deleted && op != "RestoreSecret" && op != "DescribeSecret" && op != "DeleteSecret" {
            return Err(err("InvalidRequestException", "You can't perform this operation on the secret because it was marked for deletion."));
        }
        let x = self.s.get_mut(&n).unwrap();
        Ok(match op {
            "GetSecretValue" => {
                let stage = r["VersionStage"].as_str().unwrap_or("AWSCURRENT");
                let v = match r["VersionId"].as_str() {
                    Some(id) => x.versions.iter().find(|v| v.id == id),
                    None => x.versions.iter().find(|v| v.stages.iter().any(|s| s == stage)),
                }
                .ok_or_else(|| err("ResourceNotFoundException", format!("Secrets Manager can't find the specified secret value for staging label: {stage}")))?;
                let mut out = json!({"ARN": x.arn, "Name": n, "VersionId": v.id, "VersionStages": v.stages, "CreatedDate": v.created});
                if let Some(s) = &v.string {
                    out["SecretString"] = s.clone().into();
                }
                if let Some(b) = &v.binary {
                    out["SecretBinary"] = b.clone().into();
                }
                out
            }
            "PutSecretValue" => {
                let vid = add_version(x, r).ok_or_else(|| err("InvalidParameterException", "You must provide either SecretString or SecretBinary."))?;
                json!({"ARN": x.arn, "Name": n, "VersionId": vid, "VersionStages": ["AWSCURRENT"]})
            }
            "UpdateSecret" => {
                if let Some(d) = r["Description"].as_str() {
                    x.description = Some(d.into());
                    x.changed = epoch();
                }
                let vid = add_version(x, r);
                json!({"ARN": x.arn, "Name": n, "VersionId": vid})
            }
            "DescribeSecret" => {
                let x = &self.s[&n];
                self.describe(&n, x)
            }
            "DeleteSecret" => {
                let arn = x.arn.clone();
                let when = if r["ForceDeleteWithoutRecovery"].as_bool() == Some(true) {
                    self.s.remove(&n);
                    epoch()
                } else {
                    let t = epoch() + 86400.0 * r["RecoveryWindowInDays"].as_f64().unwrap_or(30.0);
                    x.deleted = Some(t);
                    t
                };
                json!({"ARN": arn, "Name": n, "DeletionDate": when})
            }
            "RestoreSecret" => {
                x.deleted = None;
                json!({"ARN": x.arn, "Name": n})
            }
            _ => return Err(err("InvalidAction", format!("{op} is not supported yet"))),
        })
    }

    pub fn admin(&self) -> Value {
        self.s
            .iter()
            .map(|(n, x)| {
                json!({"name": n, "count": x.versions.len(), "sub": format!("{}{}", x.arn, if x.deleted.is_some() { " · 삭제 예정" } else { "" }),
                    "cols": ["버전", "단계", "값"],
                    "rows": x.versions.iter().rev().map(|v| json!([v.id, v.stages.join(", "), v.string.clone().unwrap_or("(바이너리)".into())])).collect::<Vec<_>>()})
            })
            .collect()
    }
}

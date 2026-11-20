// SSM Parameter Store (JSON 1.1).
use crate::{b64, epoch, err, need, ApiErr, ACCOUNT, REGION};
use serde_json::{json, Value};
use std::collections::BTreeMap;

struct Param {
    value: String,
    ty: String,
    version: i64,
    modified: f64,
    description: Option<String>,
}

#[derive(Default)]
pub struct Ssm {
    p: BTreeMap<String, Param>,
}

pub fn arn(n: &str) -> String {
    format!("arn:aws:ssm:{}:{ACCOUNT}:parameter{}{n}", *REGION, if n.starts_with('/') { "" } else { "/" })
}
fn not_found(n: &str) -> ApiErr {
    err("ParameterNotFound", format!("Parameter {n} not found."))
}

impl Ssm {
    fn pjson(n: &str, p: &Param, decrypt: bool) -> Value {
        // ponytail: an undecrypted SecureString is just base64-wrapped, not real ciphertext.
        let v = if p.ty == "SecureString" && !decrypt { b64(format!("kms:{}", p.value).as_bytes()) } else { p.value.clone() };
        json!({"Name": n, "Type": p.ty, "Value": v, "Version": p.version, "LastModifiedDate": p.modified, "ARN": arn(n), "DataType": "text"})
    }

    pub fn handle(&mut self, op: &str, r: &Value) -> Result<Value, ApiErr> {
        let dec = r["WithDecryption"].as_bool().unwrap_or(false);
        Ok(match op {
            "PutParameter" => {
                let (n, v) = (need(r, "Name")?, need(r, "Value")?);
                let old = self.p.get(n);
                if old.is_some() && r["Overwrite"].as_bool() != Some(true) {
                    return Err(err("ParameterAlreadyExists", "The parameter already exists. To overwrite this value, set the overwrite option in the request to true."));
                }
                let ty = r["Type"].as_str().or(old.map(|o| o.ty.as_str())).ok_or_else(|| err("ValidationException", "Type is required when creating a parameter"))?.to_string();
                let version = old.map_or(1, |o| o.version + 1);
                let description = r["Description"].as_str().map(String::from).or_else(|| old.and_then(|o| o.description.clone()));
                self.p.insert(n.into(), Param { value: v.into(), ty, version, modified: epoch(), description });
                json!({"Version": version, "Tier": "Standard"})
            }
            "GetParameter" => {
                let n = need(r, "Name")?;
                json!({"Parameter": Self::pjson(n, self.p.get(n).ok_or_else(|| not_found(n))?, dec)})
            }
            "GetParameters" => {
                let names: Vec<&str> = r["Names"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
                let found: Vec<Value> = names.iter().filter_map(|n| self.p.get(*n).map(|p| Self::pjson(n, p, dec))).collect();
                let missing: Vec<&&str> = names.iter().filter(|n| !self.p.contains_key(**n)).collect();
                json!({"Parameters": found, "InvalidParameters": missing})
            }
            "GetParametersByPath" => {
                let path = need(r, "Path")?;
                let pre = if path.ends_with('/') { path.to_string() } else { format!("{path}/") };
                let rec = r["Recursive"].as_bool().unwrap_or(false);
                let list: Vec<Value> = self.p.iter()
                    .filter(|(n, _)| n.strip_prefix(&pre).is_some_and(|rest| rec || !rest.contains('/')))
                    .map(|(n, p)| Self::pjson(n, p, dec)).collect();
                json!({ "Parameters": list })
            }
            "DeleteParameter" => {
                let n = need(r, "Name")?;
                self.p.remove(n).ok_or_else(|| not_found(n))?;
                json!({})
            }
            "DeleteParameters" => {
                let (mut ok, mut bad) = (vec![], vec![]);
                for n in r["Names"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                    if self.p.remove(n).is_some() { ok.push(n) } else { bad.push(n) }
                }
                json!({"DeletedParameters": ok, "InvalidParameters": bad})
            }
            "DescribeParameters" => {
                let list: Vec<Value> = self.p.iter().map(|(n, p)| json!({"Name": n, "ARN": arn(n), "Type": p.ty, "Version": p.version,
                    "LastModifiedDate": p.modified, "Description": p.description, "Tier": "Standard", "DataType": "text"})).collect();
                json!({ "Parameters": list })
            }
            _ => return Err(err("InvalidAction", format!("{op} is not supported yet"))),
        })
    }

    pub fn admin(&self) -> Value {
        let rows: Vec<Value> = self.p.iter().map(|(n, p)| json!([n, p.ty, if p.ty == "SecureString" { "••••".to_string() } else { p.value.clone() }, p.version])).collect();
        if rows.is_empty() {
            return json!([]);
        }
        json!([{"name": "파라미터", "count": rows.len(), "cols": ["이름", "타입", "값", "버전"], "rows": rows}])
    }
}

impl Ssm {
    // (name, type, value) for the infrastructure-code draft.
    pub fn export(&self) -> Vec<(String, String, String)> {
        self.p.iter().map(|(n, p)| (n.clone(), p.ty.clone(), p.value.clone())).collect()
    }

    pub fn snap_save(&self) -> Value {
        let items: Vec<Value> = self.p.iter().map(|(n, p)| json!({
            "name": n, "value": p.value, "ty": p.ty, "version": p.version,
            "modified": p.modified, "description": p.description,
        })).collect();
        json!(items)
    }

    pub fn snap_load(&mut self, v: &Value) {
        self.p.clear();
        for x in v.as_array().into_iter().flatten() {
            let Some(name) = x["name"].as_str() else { continue };
            self.p.insert(name.into(), Param {
                value: x["value"].as_str().unwrap_or("").into(),
                ty: x["ty"].as_str().unwrap_or("String").into(),
                version: x["version"].as_i64().unwrap_or(1),
                modified: x["modified"].as_f64().unwrap_or_else(epoch),
                description: x["description"].as_str().map(String::from),
            });
        }
    }
}

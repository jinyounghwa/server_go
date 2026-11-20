// EventBridge (JSON 1.1): buses, rules with event patterns or rate() schedules, targets.
// ponytail: cron() schedules, archives/replay, API destinations and input transformers are not supported.
use crate::{err, need, ApiErr, ACCOUNT, REGION};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub struct Rule {
    pattern: Option<Value>,
    pub schedule: Option<String>,
    pub enabled: bool,
    desc: String,
    targets: Vec<Value>,
    pub generation: u64,
}

#[derive(Default)]
pub struct Events {
    buses: BTreeSet<String>,
    rules: BTreeMap<(String, String), Rule>,
    generation: u64,
    sent: u64,
}

pub fn bus_of(r: &Value) -> String {
    r["EventBusName"].as_str().map_or("default".into(), |b| b.rsplit('/').next().unwrap_or(b).to_string())
}
fn rule_arn(bus: &str, name: &str) -> String {
    let path = if bus == "default" { name.to_string() } else { format!("{bus}/{name}") };
    format!("arn:aws:events:{}:{ACCOUNT}:rule/{path}", *REGION)
}
fn not_found(name: &str) -> ApiErr {
    err("ResourceNotFoundException", format!("Rule {name} does not exist."))
}

// Event pattern matching: nested objects recurse, arrays list accepted values.
pub fn matches(pattern: &Value, event: &Value) -> bool {
    let Some(p) = pattern.as_object() else { return false };
    p.iter().all(|(k, want)| {
        let have = event.get(k);
        match want {
            Value::Object(_) => have.is_some_and(|h| matches(want, h)),
            Value::Array(opts) => {
                let vals: Vec<&Value> = match have {
                    Some(Value::Array(a)) => a.iter().collect(),
                    Some(v) => vec![v],
                    None => vec![],
                };
                opts.iter().any(|o| match o {
                    Value::Object(m) => {
                        let (op, arg) = m.iter().next().map_or(("", &Value::Null), |(a, b)| (a.as_str(), b));
                        match op {
                            "exists" => arg.as_bool() == Some(!vals.is_empty()),
                            "prefix" => vals.iter().any(|v| matches!((v.as_str(), arg.as_str()), (Some(s), Some(p)) if s.starts_with(p))),
                            "suffix" => vals.iter().any(|v| matches!((v.as_str(), arg.as_str()), (Some(s), Some(p)) if s.ends_with(p))),
                            "anything-but" => !vals.is_empty() && vals.iter().all(|v| !crate::iam::strs(arg).contains(&v.as_str().map_or(v.to_string(), String::from))),
                            "numeric" => vals.iter().any(|v| numeric(arg, v.as_f64())),
                            _ => false,
                        }
                    }
                    lit => vals.iter().any(|v| *v == lit),
                })
            }
            lit => have == Some(lit),
        }
    })
}

// {"numeric": [">", 0, "<=", 5]}
fn numeric(arg: &Value, v: Option<f64>) -> bool {
    let (Some(a), Some(v)) = (arg.as_array(), v) else { return false };
    a.chunks(2).all(|c| match (c[0].as_str(), c.get(1).and_then(Value::as_f64)) {
        (Some("="), Some(n)) => v == n,
        (Some(">"), Some(n)) => v > n,
        (Some(">="), Some(n)) => v >= n,
        (Some("<"), Some(n)) => v < n,
        (Some("<="), Some(n)) => v <= n,
        _ => false,
    })
}

// What a target receives: the event, a constant Input, or a simple $.a.b InputPath.
pub fn payload(target: &Value, event: &Value) -> Value {
    if let Some(i) = target["Input"].as_str() {
        return serde_json::from_str(i).unwrap_or(Value::String(i.into()));
    }
    if let Some(p) = target["InputPath"].as_str() {
        return p.trim_start_matches('$').split('.').filter(|s| !s.is_empty()).fold(event.clone(), |v, k| v[k].clone());
    }
    event.clone()
}

// Seconds between runs for rate(N unit). None for anything else.
pub fn rate_secs(expr: &str) -> Option<u64> {
    let inner = expr.strip_prefix("rate(")?.strip_suffix(')')?;
    let (n, unit) = inner.trim().split_once(' ')?;
    let n: u64 = n.parse().ok()?;
    let mult = match unit.trim_end_matches('s') {
        "second" => 1, // not allowed by the real service; handy locally
        "minute" => 60,
        "hour" => 3600,
        "day" => 86400,
        _ => return None,
    };
    Some(n * mult)
}

pub fn envelope(source: &str, detail_type: &str, detail: Value, resources: Value) -> Value {
    json!({"version": "0", "id": uuid::Uuid::new_v4().to_string(), "detail-type": detail_type, "source": source,
           "account": ACCOUNT, "time": chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(), "region": *REGION,
           "resources": resources, "detail": detail})
}

impl Events {
    fn bus_ok(&self, bus: &str) -> Result<(), ApiErr> {
        if bus == "default" || self.buses.contains(bus) { Ok(()) } else { Err(err("ResourceNotFoundException", format!("Event bus {bus} does not exist."))) }
    }
    fn rule_json(bus: &str, name: &str, r: &Rule) -> Value {
        let mut v = json!({"Name": name, "Arn": rule_arn(bus, name), "State": if r.enabled { "ENABLED" } else { "DISABLED" },
                           "Description": r.desc, "EventBusName": bus});
        if let Some(p) = &r.pattern {
            v["EventPattern"] = p.to_string().into();
        }
        if let Some(s) = &r.schedule {
            v["ScheduleExpression"] = s.clone().into();
        }
        v
    }

    // (interval seconds, generation) of a rate() rule.
    pub fn schedule_of(&self, bus: &str, name: &str) -> Option<(u64, u64)> {
        let r = self.rules.get(&(bus.into(), name.into()))?;
        Some((rate_secs(r.schedule.as_deref()?)?, r.generation))
    }

    // Targets (with rule identity) that a scheduled rule should fire now, if it is still current.
    pub fn scheduled(&self, bus: &str, name: &str, generation: u64) -> Option<Option<(Vec<Value>, String)>> {
        let r = self.rules.get(&(bus.into(), name.into()))?;
        if r.generation != generation {
            return None; // replaced or deleted: stop the ticker
        }
        Some(r.enabled.then(|| (r.targets.clone(), rule_arn(bus, name))))
    }

    // Returns the response plus (target, event) pairs to dispatch.
    pub fn handle(&mut self, op: &str, r: &Value) -> Result<(Value, Vec<(Value, Value)>), ApiErr> {
        let bus = bus_of(r);
        let mut out = vec![];
        let v = match op {
            "CreateEventBus" => {
                let n = need(r, "Name")?;
                if n == "default" || !self.buses.insert(n.into()) {
                    return Err(err("ResourceAlreadyExistsException", format!("Event bus {n} already exists.")));
                }
                json!({"EventBusArn": format!("arn:aws:events:{}:{ACCOUNT}:event-bus/{n}", *REGION)})
            }
            "DeleteEventBus" => {
                let n = need(r, "Name")?;
                self.buses.remove(n);
                self.rules.retain(|(b, _), _| b != n);
                json!({})
            }
            "ListEventBuses" => {
                let all = std::iter::once("default".to_string()).chain(self.buses.iter().cloned());
                json!({"EventBuses": all.map(|b| json!({"Name": b, "Arn": format!("arn:aws:events:{}:{ACCOUNT}:event-bus/{b}", *REGION)})).collect::<Vec<_>>()})
            }
            "PutRule" => {
                self.bus_ok(&bus)?;
                let n = need(r, "Name")?;
                let pattern = r["EventPattern"].as_str().map(|p| serde_json::from_str::<Value>(p)).transpose()
                    .map_err(|e| err("InvalidEventPatternException", format!("Event pattern is not valid: {e}")))?;
                let schedule = r["ScheduleExpression"].as_str().map(String::from);
                if pattern.is_none() && schedule.is_none() {
                    return Err(err("ValidationException", "Parameter(s) EventPattern or ScheduleExpression must be specified."));
                }
                if let Some(s) = &schedule {
                    if rate_secs(s).is_none() {
                        return Err(err("ValidationException", format!("Unsupported ScheduleExpression {s} (only rate(...) locally)")));
                    }
                }
                self.generation += 1;
                let key = (bus.clone(), n.to_string());
                let targets = self.rules.remove(&key).map(|old| old.targets).unwrap_or_default();
                let enabled = r["State"].as_str() != Some("DISABLED");
                self.rules.insert(key, Rule { pattern, schedule, enabled, desc: r["Description"].as_str().unwrap_or("").into(), targets, generation: self.generation });
                json!({"RuleArn": rule_arn(&bus, n)})
            }
            "DescribeRule" => {
                let n = need(r, "Name")?;
                Self::rule_json(&bus, n, self.rules.get(&(bus.clone(), n.into())).ok_or_else(|| not_found(n))?)
            }
            "ListRules" => {
                let pre = r["NamePrefix"].as_str().unwrap_or("");
                json!({"Rules": self.rules.iter().filter(|((b, n), _)| *b == bus && n.starts_with(pre)).map(|((b, n), x)| Self::rule_json(b, n, x)).collect::<Vec<_>>()})
            }
            "DeleteRule" => {
                let n = need(r, "Name")?;
                if self.rules.get(&(bus.clone(), n.into())).is_some_and(|x| !x.targets.is_empty()) {
                    return Err(err("ValidationException", "Rule can't be deleted since it has targets."));
                }
                self.rules.remove(&(bus, n.into()));
                json!({})
            }
            "EnableRule" | "DisableRule" => {
                let n = need(r, "Name")?;
                self.rules.get_mut(&(bus, n.into())).ok_or_else(|| not_found(n))?.enabled = op == "EnableRule";
                json!({})
            }
            "PutTargets" => {
                let n = need(r, "Rule")?;
                let rule = self.rules.get_mut(&(bus, n.into())).ok_or_else(|| not_found(n))?;
                for t in r["Targets"].as_array().into_iter().flatten() {
                    rule.targets.retain(|x| x["Id"] != t["Id"]);
                    rule.targets.push(t.clone());
                }
                json!({"FailedEntryCount": 0, "FailedEntries": []})
            }
            "RemoveTargets" => {
                let n = need(r, "Rule")?;
                let rule = self.rules.get_mut(&(bus, n.into())).ok_or_else(|| not_found(n))?;
                let ids: Vec<&Value> = r["Ids"].as_array().into_iter().flatten().collect();
                rule.targets.retain(|x| !ids.contains(&&x["Id"]));
                json!({"FailedEntryCount": 0, "FailedEntries": []})
            }
            "ListTargetsByRule" => {
                let n = need(r, "Rule")?;
                json!({"Targets": self.rules.get(&(bus, n.into())).ok_or_else(|| not_found(n))?.targets})
            }
            "PutEvents" => {
                let mut results = vec![];
                let mut failed = 0;
                for e in r["Entries"].as_array().into_iter().flatten() {
                    let b = bus_of(e);
                    let detail: Option<Value> = e["Detail"].as_str().and_then(|d| serde_json::from_str(d).ok());
                    let (Some(src), Some(dt), Some(detail), true) = (e["Source"].as_str(), e["DetailType"].as_str(), detail, self.bus_ok(&b).is_ok()) else {
                        failed += 1;
                        results.push(json!({"ErrorCode": "MalformedDetail", "ErrorMessage": "Source, DetailType and a JSON Detail on an existing bus are required"}));
                        continue;
                    };
                    let ev = envelope(src, dt, detail, e["Resources"].clone().as_array().map_or(json!([]), |a| json!(a)));
                    for ((rb, _), rule) in &self.rules {
                        if *rb == b && rule.enabled && rule.pattern.as_ref().is_some_and(|p| matches(p, &ev)) {
                            out.extend(rule.targets.iter().map(|t| (t.clone(), payload(t, &ev))));
                        }
                    }
                    self.sent += 1;
                    results.push(json!({"EventId": ev["id"]}));
                }
                json!({"FailedEntryCount": failed, "Entries": results})
            }
            _ => return Err(err("UnknownOperationException", format!("{op} is not supported yet"))),
        };
        Ok((v, out))
    }

    pub fn admin(&self) -> Value {
        self.rules
            .iter()
            .map(|((b, n), r)| {
                let rows: Vec<Value> = r.targets.iter().map(|t| json!([t["Id"], t["Arn"], t["Input"].as_str().or(t["InputPath"].as_str()).unwrap_or("이벤트 전체")])).collect();
                let when = r.pattern.as_ref().map_or_else(|| r.schedule.clone().unwrap_or_default(), |p| p.to_string());
                json!({"name": if b == "default" { n.clone() } else { format!("{b}/{n}") }, "count": rows.len(),
                       "sub": format!("{} · {when}", if r.enabled { "켜짐" } else { "꺼짐" }), "cols": ["대상 ID", "ARN", "입력"], "rows": rows})
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns() {
        let ev = json!({"source": "shop", "detail-type": "Order", "detail": {"total": 120, "tier": "gold", "tags": ["a", "b"]}});
        assert!(matches(&json!({"source": ["shop"]}), &ev));
        assert!(!matches(&json!({"source": ["bank"]}), &ev));
        assert!(matches(&json!({"detail": {"total": [{"numeric": [">", 100, "<=", 200]}], "tags": ["b"]}}), &ev));
        assert!(!matches(&json!({"detail": {"total": [{"numeric": [">", 200]}]}}), &ev));
        assert!(matches(&json!({"detail": {"tier": [{"prefix": "go"}], "missing": [{"exists": false}]}}), &ev));
        assert!(matches(&json!({"detail": {"tier": [{"anything-but": ["silver"]}]}}), &ev));
        assert_eq!(rate_secs("rate(5 minutes)"), Some(300));
        assert_eq!(rate_secs("cron(0 12 * * ? *)"), None);
        assert_eq!(payload(&json!({"InputPath": "$.detail.tier"}), &ev), json!("gold"));
    }
}

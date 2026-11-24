// EventBridge (JSON 1.1): buses, rules with event patterns or rate()/cron() schedules (UTC), targets with Input,
// InputPath, InputTransformer, RetryPolicy and DeadLetterConfig (SQS), plus Archives and Replays.
// ponytail: cron L/W/# are rejected; API destinations are refused (no outbound HTTP).
use crate::{epoch, err, need, ApiErr, ACCOUNT, REGION};
use serde_json::{json, Value};
use chrono::{DateTime, Datelike, Duration, Timelike, Utc};
use std::collections::{BTreeMap, BTreeSet};

pub struct Rule {
    pattern: Option<Value>,
    pub schedule: Option<String>,
    pub enabled: bool,
    desc: String,
    targets: Vec<Value>,
    pub generation: u64,
}

struct Archive {
    name: String,
    source_arn: String,
    bus: String,
    pattern: Option<Value>,
    retention_days: u64,
    desc: String,
    created: f64,
    events: Vec<(f64, Value)>,
}

struct Replay {
    name: String,
    source_arn: String,
    dest: Value,
    start: f64,
    end: f64,
    started: f64,
    ended: f64,
    desc: String,
    state: &'static str,
}

#[derive(Default)]
pub struct Events {
    buses: BTreeSet<String>,
    rules: BTreeMap<(String, String), Rule>,
    archives: BTreeMap<String, Archive>,
    replays: BTreeMap<String, Replay>,
    generation: u64,
    sent: u64,
}

fn archive_arn(name: &str) -> String {
    format!("arn:aws:events:{}:{ACCOUNT}:archive/{name}", *REGION)
}
fn replay_arn(name: &str) -> String {
    format!("arn:aws:events:{}:{ACCOUNT}:replay/{name}", *REGION)
}
fn parse_ts(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str().and_then(|s| DateTime::parse_from_rfc3339(s).ok()).map(|t| t.timestamp_millis() as f64 / 1000.0))
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

// $.a.b[0] style path into the event.
fn path_get(event: &Value, p: &str) -> Value {
    p.trim_start_matches('$').split(['.', '[']).filter(|s| !s.is_empty()).fold(event.clone(), |v, k| match k.strip_suffix(']') {
        Some(i) => i.parse::<usize>().map_or(Value::Null, |i| v[i].clone()),
        None => v[k].clone(),
    })
}

// InputTransformer: <name> placeholders from InputPathsMap (plus aws.events.event / rule-arn / rule-name).
// Inside a JSON string a placeholder takes the raw text; outside it takes the JSON value.
fn transform(t: &Value, target: &Value, event: &Value) -> Value {
    let tpl = t["InputTemplate"].as_str().unwrap_or("");
    let rule = target["_RuleArn"].as_str().unwrap_or("");
    let lookup = |k: &str| -> Option<Value> {
        match k {
            "aws.events.event" | "aws.events.event.json" => Some(event.clone()),
            "aws.events.rule-arn" => Some(json!(rule)),
            "aws.events.rule-name" => Some(json!(rule.rsplit('/').next().unwrap_or(""))),
            "aws.events.event.ingestion-time" => Some(event["time"].clone()),
            _ => t["InputPathsMap"][k].as_str().map(|p| path_get(event, p)),
        }
    };
    let (mut out, mut in_str, mut rest) = (String::new(), false, tpl);
    while let Some(c) = rest.chars().next() {
        if c == '<' {
            if let Some(end) = rest.find('>') {
                if let Some(v) = lookup(&rest[1..end]) {
                    out += &if in_str {
                        let raw = v.as_str().map_or_else(|| if v.is_null() { String::new() } else { v.to_string() }, String::from);
                        let q = json!(raw).to_string();
                        q[1..q.len() - 1].to_string()
                    } else {
                        v.to_string()
                    };
                    rest = &rest[end + 1..];
                    continue;
                }
            }
        }
        if c == '"' && !out.ends_with('\\') {
            in_str = !in_str;
        }
        out.push(c);
        rest = &rest[c.len_utf8()..];
    }
    serde_json::from_str(&out).unwrap_or(Value::String(out))
}

// What a target receives: the event, a constant Input, an InputPath, or an InputTransformer result.
pub fn payload(target: &Value, event: &Value) -> Value {
    if let Some(i) = target["Input"].as_str() {
        return serde_json::from_str(i).unwrap_or(Value::String(i.into()));
    }
    if let Some(p) = target["InputPath"].as_str() {
        return path_get(event, p);
    }
    if target["InputTransformer"].is_object() {
        return transform(&target["InputTransformer"], target, event);
    }
    event.clone()
}

// One cron field ("*", "?", "5", "1-5", "MON,WED", "0/15", "*/10") as the allowed values in lo..=hi.
fn cron_field(spec: &str, lo: u32, hi: u32, names: &[&str]) -> Option<Vec<u32>> {
    let num = |s: &str| -> Option<u32> {
        let n = names.iter().position(|x| x.eq_ignore_ascii_case(s)).map(|i| i as u32 + lo).or_else(|| s.parse().ok())?;
        (lo..=hi).contains(&n).then_some(n)
    };
    let mut out = vec![];
    for part in spec.split(',') {
        let (base, step) = match part.split_once('/') {
            Some((b, s)) => (b, s.parse::<u32>().ok().filter(|s| *s > 0)?),
            None => (part, 1),
        };
        let (a, b) = match base {
            "*" | "?" => (lo, hi),
            _ => match base.split_once('-') {
                Some((a, b)) => (num(a)?, num(b)?),
                None => (num(base)?, if part.contains('/') { hi } else { num(base)? }),
            },
        };
        out.extend((a..=b).step_by(step as usize));
    }
    (!out.is_empty()).then_some(out)
}

// cron(minutes hours day-of-month month day-of-week year), UTC; one of the two day fields must be "?".
struct Cron {
    min: Vec<u32>,
    hour: Vec<u32>,
    dom: Option<Vec<u32>>,
    month: Vec<u32>,
    dow: Option<Vec<u32>>,
    year: Vec<u32>,
}

fn cron_parse(expr: &str) -> Option<Cron> {
    let f: Vec<&str> = expr.strip_prefix("cron(")?.strip_suffix(')')?.split_whitespace().collect();
    if f.len() != 6 || (f[2] == "?") == (f[4] == "?") {
        return None;
    }
    let months = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"];
    Some(Cron {
        min: cron_field(f[0], 0, 59, &[])?,
        hour: cron_field(f[1], 0, 23, &[])?,
        dom: if f[2] == "?" { None } else { Some(cron_field(f[2], 1, 31, &[])?) },
        month: cron_field(f[3], 1, 12, &months)?,
        dow: if f[4] == "?" { None } else { Some(cron_field(f[4], 1, 7, &["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"])?) },
        year: cron_field(f[5], 1970, 2199, &[])?,
    })
}

// First minute strictly after `after` that the cron expression selects (searched up to 5 years ahead).
fn cron_next(expr: &str, after: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let c = cron_parse(expr)?;
    let start = after.with_second(0)?.with_nanosecond(0)? + Duration::minutes(1);
    let first_day = start.date_naive();
    for d in 0..(366 * 5) {
        let day = first_day + Duration::days(d);
        let dow = day.weekday().num_days_from_sunday() + 1;
        if !c.year.contains(&(day.year() as u32)) || !c.month.contains(&day.month())
            || c.dom.as_ref().is_some_and(|v| !v.contains(&day.day())) || c.dow.as_ref().is_some_and(|v| !v.contains(&dow)) {
            continue;
        }
        for h in &c.hour {
            for m in &c.min {
                let t = day.and_hms_opt(*h, *m, 0)?.and_utc();
                if t >= start {
                    return Some(t);
                }
            }
        }
    }
    None
}

// Seconds until the next run of a rate() or cron() schedule.
pub fn next_delay(expr: &str) -> Option<std::time::Duration> {
    if let Some(s) = rate_secs(expr) {
        return Some(std::time::Duration::from_secs(s));
    }
    let now = Utc::now();
    (cron_next(expr, now)? - now).to_std().ok()
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

    // Whether a bus ARN's name is a real bus here (used by Lambda destination validation).
    pub fn bus_exists(&self, bus: &str) -> bool {
        self.bus_ok(bus).is_ok()
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

    // (schedule expression, generation) of a scheduled rule.
    pub fn schedule_of(&self, bus: &str, name: &str) -> Option<(String, u64)> {
        let r = self.rules.get(&(bus.into(), name.into()))?;
        Some((r.schedule.clone()?, r.generation))
    }

    // Targets (with rule identity) that a scheduled rule should fire now, if it is still current.
    pub fn scheduled(&self, bus: &str, name: &str, generation: u64) -> Option<Option<(Vec<Value>, String)>> {
        let r = self.rules.get(&(bus.into(), name.into()))?;
        if r.generation != generation {
            return None; // replaced or deleted: stop the ticker
        }
        let arn = rule_arn(bus, name);
        Some(r.enabled.then(|| (r.targets.iter().map(|t| { let mut t = t.clone(); t["_RuleArn"] = json!(arn); t }).collect(), arn.clone())))
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
                    if rate_secs(s).is_none() && cron_parse(s).is_none() {
                        return Err(err("ValidationException", "Parameter ScheduleExpression is not valid."));
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
                    let it = &t["InputTransformer"];
                    if !it.is_null() && (it["InputTemplate"].as_str().is_none()
                        || it["InputPathsMap"].as_object().is_some_and(|m| m.len() > 100 || m.values().any(|p| !p.as_str().is_some_and(|p| p.starts_with('$'))))) {
                        return Err(err("ValidationException", "InputTransformer needs an InputTemplate and InputPathsMap values that are $ paths (at most 100)."));
                    }
                    if let Some(rp) = t.get("RetryPolicy").filter(|v| !v.is_null()) {
                        if let Some(m) = rp.get("MaximumRetryAttempts").and_then(Value::as_i64) {
                            if !(0..=185).contains(&m) {
                                return Err(err("ValidationException", "MaximumRetryAttempts must be between 0 and 185."));
                            }
                        }
                        if let Some(age) = rp.get("MaximumEventAgeInSeconds").and_then(Value::as_i64) {
                            if !(60..=86400).contains(&age) {
                                return Err(err("ValidationException", "MaximumEventAgeInSeconds must be between 60 and 86400."));
                            }
                        }
                    }
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
                    let now = epoch();
                    for a in self.archives.values_mut() {
                        if a.bus == b && a.pattern.as_ref().is_none_or(|p| matches(p, &ev)) {
                            if a.retention_days > 0 {
                                let cutoff = now - (a.retention_days as f64) * 86400.0;
                                a.events.retain(|(t, _)| *t >= cutoff);
                            }
                            a.events.push((now, ev.clone()));
                        }
                    }
                    for ((rb, rn), rule) in &self.rules {
                        if *rb == b && rule.enabled && rule.pattern.as_ref().is_some_and(|p| matches(p, &ev)) {
                            out.extend(rule.targets.iter().map(|t| {
                                let mut t = t.clone();
                                t["_RuleArn"] = json!(rule_arn(&b, rn));
                                let p = payload(&t, &ev);
                                (t, p)
                            }));
                        }
                    }
                    self.sent += 1;
                    results.push(json!({"EventId": ev["id"]}));
                }
                json!({"FailedEntryCount": failed, "Entries": results})
            }
            "CreateArchive" => {
                let name = need(r, "ArchiveName")?;
                let src = need(r, "EventSourceArn")?;
                let bus_name = src.rsplit('/').next().unwrap_or("default").to_string();
                self.bus_ok(&bus_name)?;
                if self.archives.contains_key(name) {
                    return Err(err("ResourceAlreadyExistsException", format!("Archive {name} already exists.")));
                }
                let pattern = r["EventPattern"].as_str().map(serde_json::from_str::<Value>).transpose()
                    .map_err(|e| err("InvalidEventPatternException", format!("Event pattern is not valid: {e}")))?;
                let retention_days = r["RetentionDays"].as_u64().unwrap_or(0);
                let created = epoch();
                self.archives.insert(name.into(), Archive {
                    name: name.into(), source_arn: src.into(), bus: bus_name, pattern, retention_days,
                    desc: r["Description"].as_str().unwrap_or("").into(), created, events: vec![],
                });
                json!({"ArchiveArn": archive_arn(name), "State": "ENABLED", "CreationTime": created})
            }
            "DescribeArchive" => {
                let name = need(r, "ArchiveName")?;
                let a = self.archives.get(name).ok_or_else(|| err("ResourceNotFoundException", format!("Archive {name} does not exist.")))?;
                let size: usize = a.events.iter().map(|(_, e)| e.to_string().len()).sum();
                let mut v = json!({"ArchiveArn": archive_arn(&a.name), "ArchiveName": a.name, "EventSourceArn": a.source_arn,
                    "Description": a.desc, "State": "ENABLED", "RetentionDays": a.retention_days,
                    "SizeBytes": size, "EventCount": a.events.len(), "CreationTime": a.created});
                if let Some(p) = &a.pattern {
                    v["EventPattern"] = p.to_string().into();
                }
                v
            }
            "ListArchives" => {
                let pre = r["NamePrefix"].as_str().unwrap_or("");
                let src = r["EventSourceArn"].as_str();
                let list: Vec<Value> = self.archives.values()
                    .filter(|a| a.name.starts_with(pre) && src.is_none_or(|s| a.source_arn == s))
                    .map(|a| {
                        let size: usize = a.events.iter().map(|(_, e)| e.to_string().len()).sum();
                        json!({"ArchiveName": a.name, "EventSourceArn": a.source_arn, "State": "ENABLED",
                               "RetentionDays": a.retention_days, "SizeBytes": size, "EventCount": a.events.len(), "CreationTime": a.created})
                    })
                    .collect();
                json!({"Archives": list})
            }
            "DeleteArchive" => {
                let name = need(r, "ArchiveName")?;
                self.archives.remove(name).ok_or_else(|| err("ResourceNotFoundException", format!("Archive {name} does not exist.")))?;
                json!({})
            }
            "StartReplay" => {
                let name = need(r, "ReplayName")?;
                if self.replays.contains_key(name) {
                    return Err(err("ResourceAlreadyExistsException", format!("Replay {name} already exists.")));
                }
                let src = need(r, "EventSourceArn")?;
                let arch_name = src.rsplit('/').next().unwrap_or(src);
                let arch = self.archives.get(arch_name).ok_or_else(|| err("ResourceNotFoundException", format!("Archive {arch_name} does not exist.")))?;
                let start = parse_ts(&r["EventStartTime"]).ok_or_else(|| err("ValidationException", "EventStartTime is required"))?;
                let end = parse_ts(&r["EventEndTime"]).ok_or_else(|| err("ValidationException", "EventEndTime is required"))?;
                if end <= start {
                    return Err(err("ValidationException", "EventEndTime must be after EventStartTime"));
                }
                let dest = r["Destination"].clone();
                let dest_bus = dest["Arn"].as_str().map(|s| s.rsplit('/').next().unwrap_or("default")).unwrap_or(&arch.bus).to_string();
                self.bus_ok(&dest_bus)?;
                let filter_arns: Vec<String> = dest["FilterArns"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(String::from)).collect();
                let matched_events: Vec<Value> = arch.events.iter()
                    .filter(|(t, _)| *t >= start && *t <= end)
                    .map(|(_, ev)| {
                        let mut e = ev.clone();
                        e["replay-name"] = json!(name);
                        e
                    })
                    .collect();
                for ev in matched_events {
                    for ((rb, rn), rule) in &self.rules {
                        let rarn = rule_arn(&dest_bus, rn);
                        if *rb == dest_bus && rule.enabled
                            && (filter_arns.is_empty() || filter_arns.contains(&rarn))
                            && rule.pattern.as_ref().is_some_and(|p| matches(p, &ev))
                        {
                            out.extend(rule.targets.iter().map(|t| {
                                let mut t = t.clone();
                                t["_RuleArn"] = json!(rarn);
                                let p = payload(&t, &ev);
                                (t, p)
                            }));
                        }
                    }
                }
                let now = epoch();
                self.replays.insert(name.into(), Replay {
                    name: name.into(), source_arn: src.into(), dest, start, end,
                    started: now, ended: now, desc: r["Description"].as_str().unwrap_or("").into(), state: "COMPLETED",
                });
                json!({"ReplayArn": replay_arn(name), "State": "COMPLETED", "ReplayStartTime": now})
            }
            "DescribeReplay" => {
                let name = need(r, "ReplayName")?;
                let rp = self.replays.get(name).ok_or_else(|| err("ResourceNotFoundException", format!("Replay {name} does not exist.")))?;
                json!({"ReplayName": rp.name, "ReplayArn": replay_arn(&rp.name), "Description": rp.desc, "State": rp.state,
                       "EventSourceArn": rp.source_arn, "Destination": rp.dest, "EventStartTime": rp.start, "EventEndTime": rp.end,
                       "ReplayStartTime": rp.started, "ReplayEndTime": rp.ended})
            }
            "ListReplays" => {
                let pre = r["NamePrefix"].as_str().unwrap_or("");
                let src = r["EventSourceArn"].as_str();
                let list: Vec<Value> = self.replays.values()
                    .filter(|rp| rp.name.starts_with(pre) && src.is_none_or(|s| rp.source_arn == s))
                    .map(|rp| json!({"ReplayName": rp.name, "EventSourceArn": rp.source_arn, "State": rp.state,
                                     "EventStartTime": rp.start, "EventEndTime": rp.end, "ReplayStartTime": rp.started, "ReplayEndTime": rp.ended}))
                    .collect();
                json!({"Replays": list})
            }
            "CreateApiDestination" | "CreateConnection" => {
                return Err(err("UnsupportedOperationException", format!("{op} is not supported locally (outbound HTTP is disabled)")));
            }
            _ => return Err(err("UnknownOperationException", format!("{op} is not supported yet"))),
        };
        Ok((v, out))
    }

    pub fn snap_save(&self) -> Value {
        let archives: Vec<Value> = self.archives.values().map(|a| json!({
            "name": a.name, "source_arn": a.source_arn, "bus": a.bus, "pattern": a.pattern,
            "retention_days": a.retention_days, "desc": a.desc, "created": a.created,
            "events": a.events.iter().map(|(t, e)| json!([t, e])).collect::<Vec<_>>(),
        })).collect();
        json!({"buses": self.buses, "archives": archives})
    }

    pub fn snap_load(&mut self, v: &Value) {
        self.buses.clear();
        self.archives.clear();
        self.replays.clear();
        for b in v["buses"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            self.buses.insert(b.into());
        }
        for a in v["archives"].as_array().into_iter().flatten() {
            let (Some(name), Some(src), Some(bus)) = (a["name"].as_str(), a["source_arn"].as_str(), a["bus"].as_str()) else { continue };
            let events: Vec<(f64, Value)> = a["events"].as_array().into_iter().flatten().filter_map(|p| {
                Some((p[0].as_f64()?, p[1].clone()))
            }).collect();
            self.archives.insert(name.into(), Archive {
                name: name.into(), source_arn: src.into(), bus: bus.into(),
                pattern: (!a["pattern"].is_null()).then(|| a["pattern"].clone()),
                retention_days: a["retention_days"].as_u64().unwrap_or(0),
                desc: a["desc"].as_str().unwrap_or("").into(),
                created: a["created"].as_f64().unwrap_or(0.0),
                events,
            });
        }
    }

    pub fn admin(&self) -> Value {
        self.rules
            .iter()
            .map(|((b, n), r)| {
                let rows: Vec<Value> = r.targets.iter().map(|t| json!([t["Id"], t["Arn"], t["Input"].as_str().or(t["InputPath"].as_str()).or(t["InputTransformer"]["InputTemplate"].as_str()).unwrap_or("이벤트 전체")])).collect();
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
        assert_eq!(payload(&json!({"InputPath": "$.detail.tags[1]"}), &ev), json!("b"));
        let t = json!({"_RuleArn": "arn:aws:events:us-east-1:000000000000:rule/shop/big", "InputTransformer": {
            "InputPathsMap": {"tier": "$.detail.tier", "total": "$.detail.total", "tags": "$.detail.tags"},
            "InputTemplate": "{\"msg\": \"<tier> order of <total>\", \"total\": <total>, \"tags\": <tags>, \"rule\": \"<aws.events.rule-name>\"}"}});
        assert_eq!(payload(&t, &ev), json!({"msg": "gold order of 120", "total": 120, "tags": ["a", "b"], "rule": "big"}));
        let plain = json!({"InputTransformer": {"InputPathsMap": {"t": "$.detail.tier"}, "InputTemplate": "\"Tier is <t>\""}});
        assert_eq!(payload(&plain, &ev), json!("Tier is gold"));
    }

    #[test]
    fn cron_schedules() {
        let at = |s: &str| DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc);
        let next = |e: &str, s: &str| cron_next(e, at(s)).map(|t| t.to_rfc3339());
        assert_eq!(next("cron(0 12 * * ? *)", "2026-11-22T11:59:30Z").as_deref(), Some("2026-11-22T12:00:00+00:00"));
        assert_eq!(next("cron(0 12 * * ? *)", "2026-11-22T12:00:00Z").as_deref(), Some("2026-11-23T12:00:00+00:00"));
        assert_eq!(next("cron(0/15 * * * ? *)", "2026-11-22T10:07:00Z").as_deref(), Some("2026-11-22T10:15:00+00:00"));
        // 2026-11-22 is a Sunday: next MON-FRI 09:30 is Monday the 23rd.
        assert_eq!(next("cron(30 9 ? * MON-FRI *)", "2026-11-22T10:00:00Z").as_deref(), Some("2026-11-23T09:30:00+00:00"));
        assert_eq!(next("cron(0 0 1 JAN ? 2027)", "2026-11-22T00:00:00Z").as_deref(), Some("2027-01-01T00:00:00+00:00"));
        // Boundary cases: month-end (skip Feb 31 -> Mar 31), leap day Feb 29, Friday -> Monday MON-FRI, past year -> None.
        assert_eq!(next("cron(0 0 31 * ? *)", "2026-01-31T00:00:00Z").as_deref(), Some("2026-03-31T00:00:00+00:00"));
        assert_eq!(next("cron(0 0 29 2 ? *)", "2026-11-22T00:00:00Z").as_deref(), Some("2028-02-29T00:00:00+00:00"));
        assert_eq!(next("cron(0 9 ? * MON-FRI *)", "2026-11-20T09:00:00Z").as_deref(), Some("2026-11-23T09:00:00+00:00"));
        assert_eq!(next("cron(0 0 1 1 ? 2025)", "2026-01-01T00:00:00Z"), None, "past year never fires");
        assert_eq!(next("cron(0 0 31 2 ? *)", "2026-11-22T00:00:00Z"), None, "Feb 31 never comes");
        for bad in ["cron(0 12 * * * *)", "cron(0 12 ? * ? *)", "cron(61 * * * ? *)", "cron(0 12 L * ? *)", "cron(0 12 * *)"] {
            assert!(cron_parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn archives_and_replay() {
        let mut eb = Events::default();
        eb.handle("PutRule", &json!({"Name": "r1", "EventPattern": "{\"source\":[\"shop\"]}"})).unwrap();
        eb.handle("PutTargets", &json!({"Rule": "r1", "Targets": [{"Id": "t1", "Arn": "arn:aws:sqs:us-east-1:000000000000:q1"}]})).unwrap();
        let bus_arn = format!("arn:aws:events:{}:{ACCOUNT}:event-bus/default", *REGION);
        let (a, _) = eb.handle("CreateArchive", &json!({"ArchiveName": "a1", "EventSourceArn": bus_arn, "EventPattern": "{\"source\":[\"shop\"]}", "RetentionDays": 7})).unwrap();
        let aarn = a["ArchiveArn"].as_str().unwrap().to_string();
        assert!(eb.handle("CreateArchive", &json!({"ArchiveName": "a1", "EventSourceArn": bus_arn})).is_err());
        let t0 = epoch() - 5.0;
        eb.handle("PutEvents", &json!({"Entries": [
            {"Source": "shop", "DetailType": "Order", "Detail": "{\"n\":1}"},
            {"Source": "other", "DetailType": "Noise", "Detail": "{}"}
        ]})).unwrap();
        let t1 = epoch() + 5.0;
        let (desc, _) = eb.handle("DescribeArchive", &json!({"ArchiveName": "a1"})).unwrap();
        assert_eq!(desc["EventCount"], 1);
        // Snapshot round-trip preserves archived events
        let snap = eb.snap_save();
        let mut eb2 = Events::default();
        eb2.snap_load(&snap);
        let (desc2, _) = eb2.handle("DescribeArchive", &json!({"ArchiveName": "a1"})).unwrap();
        assert_eq!(desc2["EventCount"], 1);
        // Replay adds replay-name and dispatches matching rule targets
        let (rp, sends) = eb.handle("StartReplay", &json!({
            "ReplayName": "rep1", "EventSourceArn": aarn,
            "EventStartTime": t0, "EventEndTime": t1,
            "Destination": {"Arn": bus_arn}
        })).unwrap();
        assert_eq!(rp["State"], "COMPLETED");
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].1["replay-name"], "rep1");
        assert_eq!(sends[0].1["detail"]["n"], 1);
        assert!(eb.handle("CreateApiDestination", &json!({"Name": "x"})).is_err());
    }
}

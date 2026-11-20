// CloudWatch Logs (JSON 1.1).
use crate::{err, need, now_ms, ApiErr, ACCOUNT, REGION};
use serde_json::{json, Value};
use std::collections::BTreeMap;

struct Stream {
    created: i64,
    events: Vec<(i64, String, i64)>, // (timestamp, message, ingestion time)
}
struct Group {
    created: i64,
    retention: Option<i64>,
    streams: BTreeMap<String, Stream>,
}

#[derive(Default)]
pub struct Logs {
    g: BTreeMap<String, Group>,
}

fn group_arn(g: &str) -> String {
    format!("arn:aws:logs:{}:{ACCOUNT}:log-group:{g}", *REGION)
}
fn no_group() -> ApiErr {
    err("ResourceNotFoundException", "The specified log group does not exist.")
}
fn no_stream() -> ApiErr {
    err("ResourceNotFoundException", "The specified log stream does not exist.")
}

// ponytail: filter patterns are plain terms / "quoted phrases" that must all appear; JSON and ?OR patterns unsupported.
fn pattern_terms(p: &str) -> Vec<String> {
    let mut out = vec![];
    let mut rest = p.trim();
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix('"') {
            let (t, after) = r.split_once('"').unwrap_or((r, ""));
            out.push(t.to_string());
            rest = after.trim_start();
        } else {
            let (t, after) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
            out.push(t.to_string());
            rest = after.trim_start();
        }
    }
    out
}

impl Logs {
    // Used by other services (e.g. Lambda) to write logs, creating group/stream on demand.
    pub fn put(&mut self, group: &str, stream: &str, events: Vec<(i64, String)>) {
        let now = now_ms();
        let g = self.g.entry(group.into()).or_insert_with(|| Group { created: now, retention: None, streams: BTreeMap::new() });
        let s = g.streams.entry(stream.into()).or_insert_with(|| Stream { created: now, events: vec![] });
        s.events.extend(events.into_iter().map(|(t, m)| (t, m, now)));
    }

    fn stream_json(name: &str, group: &str, s: &Stream) -> Value {
        let bytes: usize = s.events.iter().map(|e| e.1.len()).sum();
        let mut v = json!({"logStreamName": name, "creationTime": s.created, "storedBytes": bytes,
                           "arn": format!("{}:log-stream:{name}", group_arn(group))});
        if let (Some(f), Some(l)) = (s.events.iter().map(|e| e.0).min(), s.events.iter().map(|e| e.0).max()) {
            v["firstEventTimestamp"] = f.into();
            v["lastEventTimestamp"] = l.into();
            v["lastIngestionTime"] = s.events.iter().map(|e| e.2).max().into();
        }
        v
    }

    pub fn handle(&mut self, op: &str, r: &Value) -> Result<Value, ApiErr> {
        if op == "DescribeLogGroups" {
            let pre = r["logGroupNamePrefix"].as_str().unwrap_or("");
            let list: Vec<Value> = self.g.iter().filter(|(n, _)| n.starts_with(pre)).map(|(n, g)| {
                let bytes: usize = g.streams.values().flat_map(|s| &s.events).map(|e| e.1.len()).sum();
                let mut v = json!({"logGroupName": n, "arn": format!("{}:*", group_arn(n)), "creationTime": g.created, "storedBytes": bytes});
                if let Some(d) = g.retention {
                    v["retentionInDays"] = d.into();
                }
                v
            }).collect();
            return Ok(json!({ "logGroups": list }));
        }
        let gn = need(r, "logGroupName")?;
        if op == "CreateLogGroup" {
            if self.g.contains_key(gn) {
                return Err(err("ResourceAlreadyExistsException", "The specified log group already exists"));
            }
            self.g.insert(gn.into(), Group { created: now_ms(), retention: None, streams: BTreeMap::new() });
            return Ok(json!({}));
        }
        if op == "DeleteLogGroup" {
            self.g.remove(gn).ok_or_else(no_group)?;
            return Ok(json!({}));
        }
        let g = self.g.get_mut(gn).ok_or_else(no_group)?;
        Ok(match op {
            "PutRetentionPolicy" => {
                g.retention = r["retentionInDays"].as_i64();
                json!({})
            }
            "DeleteRetentionPolicy" => {
                g.retention = None;
                json!({})
            }
            "CreateLogStream" => {
                let sn = need(r, "logStreamName")?;
                if g.streams.contains_key(sn) {
                    return Err(err("ResourceAlreadyExistsException", "The specified log stream already exists"));
                }
                g.streams.insert(sn.into(), Stream { created: now_ms(), events: vec![] });
                json!({})
            }
            "DeleteLogStream" => {
                g.streams.remove(need(r, "logStreamName")?).ok_or_else(no_stream)?;
                json!({})
            }
            "DescribeLogStreams" => {
                let pre = r["logStreamNamePrefix"].as_str().unwrap_or("");
                let mut list: Vec<(i64, Value)> = g.streams.iter().filter(|(n, _)| n.starts_with(pre))
                    .map(|(n, s)| (s.events.iter().map(|e| e.0).max().unwrap_or(0), Self::stream_json(n, gn, s))).collect();
                if r["orderBy"] == "LastEventTime" {
                    list.sort_by_key(|(t, _)| *t);
                }
                if r["descending"].as_bool() == Some(true) {
                    list.reverse();
                }
                json!({"logStreams": list.into_iter().map(|(_, v)| v).collect::<Vec<_>>()})
            }
            "PutLogEvents" => {
                let s = g.streams.get_mut(need(r, "logStreamName")?).ok_or_else(no_stream)?;
                let now = now_ms();
                for e in r["logEvents"].as_array().into_iter().flatten() {
                    s.events.push((e["timestamp"].as_i64().unwrap_or(now), e["message"].as_str().unwrap_or("").into(), now));
                }
                json!({"nextSequenceToken": s.events.len().to_string()})
            }
            "GetLogEvents" => {
                let s = g.streams.get(need(r, "logStreamName")?).ok_or_else(no_stream)?;
                let mut ev: Vec<&(i64, String, i64)> = s.events.iter()
                    .filter(|e| r["startTime"].as_i64().is_none_or(|t| e.0 >= t) && r["endTime"].as_i64().is_none_or(|t| e.0 < t)).collect();
                ev.sort_by_key(|e| e.0);
                // Tokens are "f/<index>"; returning the same token means "no more".
                let start = r["nextToken"].as_str().and_then(|t| t.strip_prefix("f/")).and_then(|n| n.parse().ok()).unwrap_or(0usize).min(ev.len());
                let limit = r["limit"].as_u64().map_or(10000, |l| l as usize);
                let page: Vec<Value> = ev[start..].iter().take(limit).map(|e| json!({"timestamp": e.0, "message": e.1, "ingestionTime": e.2})).collect();
                let end = start + page.len();
                json!({"events": page, "nextForwardToken": format!("f/{end}"), "nextBackwardToken": format!("b/{start}")})
            }
            "FilterLogEvents" => {
                let names: Vec<&str> = r["logStreamNames"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
                let terms = pattern_terms(r["filterPattern"].as_str().unwrap_or(""));
                let mut out = vec![];
                for (sn, s) in g.streams.iter().filter(|(n, _)| names.is_empty() || names.contains(&n.as_str())) {
                    for (i, e) in s.events.iter().enumerate() {
                        let in_time = r["startTime"].as_i64().is_none_or(|t| e.0 >= t) && r["endTime"].as_i64().is_none_or(|t| e.0 < t);
                        if in_time && terms.iter().all(|t| e.1.contains(t.as_str())) {
                            out.push(json!({"logStreamName": sn, "timestamp": e.0, "message": e.1, "ingestionTime": e.2, "eventId": format!("{sn}-{i}")}));
                        }
                    }
                }
                out.sort_by_key(|e| e["timestamp"].as_i64());
                let searched: Vec<Value> = g.streams.keys().map(|n| json!({"logStreamName": n, "searchedCompletely": true})).collect();
                json!({"events": out, "searchedLogStreams": searched})
            }
            _ => return Err(err("InvalidAction", format!("{op} is not supported yet"))),
        })
    }

    pub fn admin(&self) -> Value {
        self.g
            .iter()
            .map(|(n, g)| {
                let mut rows: Vec<(i64, Value)> = g.streams.iter()
                    .flat_map(|(sn, s)| s.events.iter().map(move |e| (e.0, json!([chrono::DateTime::from_timestamp_millis(e.0).map(|d| d.to_rfc3339()), sn, e.1]))))
                    .collect();
                rows.sort_by_key(|(t, _)| -*t);
                json!({"name": n, "count": g.streams.len(), "sub": format!("스트림 {}개 · 최근 이벤트 100개", g.streams.len()),
                       "cols": ["시각", "스트림", "메시지"], "rows": rows.into_iter().take(100).map(|(_, v)| v).collect::<Vec<_>>()})
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn terms() {
        assert_eq!(super::pattern_terms(r#"ERROR "user 42" db"#), vec!["ERROR", "user 42", "db"]);
        assert!(super::pattern_terms("  ").is_empty());
    }
}

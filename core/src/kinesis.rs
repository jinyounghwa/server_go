// Kinesis Data Streams (JSON 1.1): shards by MD5 hash range, sequence numbers, shard iterators.
// Lambda event source mappings read shards through positions()/read() (lambda.rs poll_kinesis).
// ponytail: no enhanced fan-out; resharding keeps closed shards readable at the end of their
// sequence range, as AWS does until retention expires (records past RetentionPeriodHours are hidden).
use crate::{b64, epoch, err, need, unb64, ApiErr, ACCOUNT, REGION};
use md5::{Digest, Md5};
use serde_json::{json, Value};
use std::collections::BTreeMap;

struct Rec {
    seq: String,
    data: String, // base64, as received
    key: String,
    at: f64,
}
struct Shard {
    id: String,
    start: u128,
    end: u128,
    closed: bool, // READ_ONLY after a split or merge; records stay readable
    recs: Vec<Rec>,
}
impl Shard {
    fn open(id: String, start: u128, end: u128) -> Self {
        Shard { id, start, end, closed: false, recs: vec![] }
    }
}
struct Stream {
    created: f64,
    shards: Vec<Shard>, // append-only ordering keeps poll_kinesis indices stable
    on_demand: bool,
    next: usize, // next shard counter for resharding children
    retention: u64, // RetentionPeriodHours; older records are hidden from reads
}

#[derive(Default)]
pub struct Kinesis {
    streams: BTreeMap<String, Stream>,
    seq: u128,
    clock: f64, // "now" for retention expiry; monotonic so tests can push it into the future
}

fn shard_id(i: usize) -> String {
    format!("shardId-{i:012}")
}
fn arn(n: &str) -> String {
    format!("arn:aws:kinesis:{}:{ACCOUNT}:stream/{n}", *REGION)
}
// Even split of the 128-bit hash key space.
fn range(i: usize, n: usize) -> (u128, u128) {
    let step = u128::MAX / n as u128;
    let start = step * i as u128;
    (start, if i + 1 == n { u128::MAX } else { start + step - 1 })
}
fn not_found(n: &str) -> ApiErr {
    err("ResourceNotFoundException", format!("Stream {n} under account {ACCOUNT} not found."))
}
// Stream name from StreamName or StreamARN.
fn stream_name(r: &Value) -> Result<String, ApiErr> {
    r["StreamName"].as_str().map(String::from)
        .or_else(|| r["StreamARN"].as_str().and_then(|a| a.rsplit('/').next()).map(String::from))
        .ok_or_else(|| err("ValidationException", "StreamName or StreamARN is required"))
}
fn iterator(stream: &str, shard: usize, pos: usize) -> String {
    b64(format!("{stream}|{shard}|{pos}").as_bytes())
}

impl Kinesis {
    pub fn exists(&self, name: &str) -> bool {
        self.streams.contains_key(name)
    }
    // Start position in each shard: 0 (TRIM_HORIZON) or the current end (LATEST). Empty if the stream is gone.
    pub fn positions(&self, name: &str, latest: bool) -> Vec<usize> {
        self.streams.get(name).map_or(vec![], |s| s.shards.iter().map(|sh| if latest { sh.recs.len() } else { 0 }).collect())
    }
    // Current shard count (open and closed) so event source mappings can follow resharding.
    pub fn shard_count(&self, name: &str) -> usize {
        self.streams.get(name).map_or(0, |s| s.shards.len())
    }
    // Up to `limit` records of a shard from `pos`, in the Lambda event "kinesis" shape.
    pub fn read(&self, name: &str, shard: usize, pos: usize, limit: usize) -> Vec<Value> {
        let Some(s) = self.streams.get(name) else { return vec![] };
        let Some(recs) = s.shards.get(shard).map(|sh| &sh.recs) else { return vec![] };
        let start = self.fresh_start(s, shard).max(pos);
        recs.iter().skip(start).take(limit).map(|x| json!({"kinesisSchemaVersion": "1.0", "partitionKey": x.key, "sequenceNumber": x.seq,
            "data": x.data, "approximateArrivalTimestamp": x.at})).collect()
    }

    // First record index of a shard that is still inside the retention window.
    fn fresh_start(&self, s: &Stream, i: usize) -> usize {
        let cutoff = self.clock - s.retention as f64 * 3600.0;
        s.shards.get(i).map_or(0, |sh| sh.recs.iter().position(|x| x.at >= cutoff).unwrap_or(sh.recs.len()))
    }

    fn describe(n: &str, s: &Stream, summary: bool) -> Value {
        let mut d = json!({"StreamName": n, "StreamARN": arn(n), "StreamStatus": "ACTIVE", "RetentionPeriodHours": s.retention,
            "StreamCreationTimestamp": s.created, "EncryptionType": "NONE", "OpenShardCount": s.shards.iter().filter(|sh| !sh.closed).count(),
            "StreamModeDetails": {"StreamMode": if s.on_demand { "ON_DEMAND" } else { "PROVISIONED" }}, "EnhancedMonitoring": [{"ShardLevelMetrics": []}]});
        if !summary {
            d["Shards"] = Self::shards(s).into();
            d["HasMoreShards"] = false.into();
        }
        d
    }
    fn shards(s: &Stream) -> Vec<Value> {
        s.shards.iter().map(|sh| {
            let mut v = json!({"ShardId": sh.id, "HashKeyRange": {"StartingHashKey": sh.start.to_string(), "EndingHashKey": sh.end.to_string()},
                   "SequenceNumberRange": {"StartingSequenceNumber": sh.recs.first().map(|r| r.seq.clone()).unwrap_or_else(|| format!("{:056}", 0))}});
            if sh.closed {
                v["SequenceNumberRange"]["EndingSequenceNumber"] = json!(sh.recs.last().map(|r| r.seq.clone()).unwrap_or_else(|| format!("{:056}", 0)));
            }
            v
        }).collect()
    }

    fn put(&mut self, name: &str, r: &Value) -> Result<Value, ApiErr> {
        let data = need(r, "Data")?;
        if unb64(data).is_none_or(|d| d.len() > 1 << 20) {
            return Err(err("ValidationException", "Data must be base64 and at most 1 MiB"));
        }
        let key = need(r, "PartitionKey")?;
        let s = self.streams.get_mut(name).ok_or_else(|| not_found(name))?;
        let hash = match r["ExplicitHashKey"].as_str() {
            Some(h) => h.parse::<u128>().map_err(|_| err("ValidationException", "ExplicitHashKey must be a 128-bit integer"))?,
            None => u128::from_be_bytes(Md5::digest(key.as_bytes()).into()),
        };
        let i = (0..s.shards.len()).find(|i| { let sh = &s.shards[*i]; !sh.closed && sh.start <= hash && hash <= sh.end })
            .unwrap_or(s.shards.len() - 1);
        self.seq += 1;
        let seq = format!("{:056}", self.seq);
        s.shards[i].recs.push(Rec { seq: seq.clone(), data: data.into(), key: key.into(), at: epoch() });
        Ok(json!({"ShardId": s.shards[i].id.clone(), "SequenceNumber": seq}))
    }

    pub fn handle(&mut self, op: &str, r: &Value) -> Result<Value, ApiErr> {
        self.clock = self.clock.max(epoch());
        Ok(match op {
            "CreateStream" => {
                let n = need(r, "StreamName")?;
                if self.streams.contains_key(n) {
                    return Err(err("ResourceInUseException", format!("Stream {n} under account {ACCOUNT} already exists.")));
                }
                let on_demand = r["StreamModeDetails"]["StreamMode"] == "ON_DEMAND";
                let count = r["ShardCount"].as_u64().unwrap_or(if on_demand { 4 } else { 1 }).clamp(1, 64) as usize;
                let shards = (0..count).map(|i| { let (a, b) = range(i, count); Shard::open(shard_id(i), a, b) }).collect();
                self.streams.insert(n.into(), Stream { created: epoch(), shards, on_demand, next: count, retention: 24 });
                json!({})
            }
            "DescribeStream" | "DescribeStreamSummary" => {
                let n = stream_name(r)?;
                let d = Self::describe(&n, self.streams.get(&n).ok_or_else(|| not_found(&n))?, op.ends_with("Summary"));
                if op.ends_with("Summary") { json!({"StreamDescriptionSummary": d}) } else { json!({"StreamDescription": d}) }
            }
            "ListStreams" => json!({"StreamNames": self.streams.keys().collect::<Vec<_>>(), "HasMoreStreams": false,
                "StreamSummaries": self.streams.iter().map(|(n, s)| json!({"StreamName": n, "StreamARN": arn(n), "StreamStatus": "ACTIVE", "StreamCreationTimestamp": s.created})).collect::<Vec<_>>()}),
            "DeleteStream" => {
                let n = stream_name(r)?;
                self.streams.remove(&n).ok_or_else(|| not_found(&n))?;
                json!({})
            }
            "ListShards" => {
                let n = stream_name(r)?;
                json!({"Shards": Self::shards(self.streams.get(&n).ok_or_else(|| not_found(&n))?)})
            }
            "PutRecord" => self.put(&stream_name(r)?, r)?,
            "PutRecords" => {
                let n = stream_name(r)?;
                let (mut out, mut failed) = (vec![], 0);
                for rec in r["Records"].as_array().into_iter().flatten() {
                    match self.put(&n, rec) {
                        Ok(v) => out.push(v),
                        Err(e) if e.code == "ResourceNotFoundException" => return Err(e),
                        Err(e) => {
                            failed += 1;
                            out.push(json!({"ErrorCode": e.code, "ErrorMessage": e.msg}));
                        }
                    }
                }
                json!({"FailedRecordCount": failed, "Records": out})
            }
            "SplitShard" => {
                let n = stream_name(r)?;
                let sid = need(r, "ShardToSplit").or_else(|_| need(r, "ShardId"))?;
                let nsk: u128 = need(r, "NewStartingHashKey")?.parse().map_err(|_| err("InvalidArgumentException", "NewStartingHashKey must be a 128-bit integer"))?;
                let s = self.streams.get_mut(&n).ok_or_else(|| not_found(&n))?;
                let sh = s.shards.iter().find(|sh| sh.id == sid)
                    .ok_or_else(|| err("ResourceNotFoundException", format!("Shard {sid} in stream {n} under account {ACCOUNT} does not exist")))?;
                if sh.closed || nsk <= sh.start || nsk > sh.end {
                    return Err(err("InvalidArgumentException", format!("NewStartingHashKey {nsk} must be greater than {} and at most {} of an open shard", sh.start, sh.end)));
                }
                let (a, b) = (sh.start, sh.end);
                let idx = s.shards.iter().position(|sh| sh.id == sid).unwrap();
                s.shards[idx].closed = true;
                let (id1, id2) = (shard_id(s.next), shard_id(s.next + 1));
                s.next += 2;
                s.shards.push(Shard::open(id1, a, nsk - 1)); // appended: existing indices stay stable
                s.shards.push(Shard::open(id2, nsk, b));
                json!({})
            }
            "MergeShards" => {
                let n = stream_name(r)?;
                let (a_id, b_id) = (need(r, "ShardToMerge")?, need(r, "AdjacentShardToMerge")?);
                let s = self.streams.get_mut(&n).ok_or_else(|| not_found(&n))?;
                let find = |id: &str| s.shards.iter().position(|sh| sh.id == id)
                    .ok_or_else(|| err("ResourceNotFoundException", format!("Shard {id} in stream {n} under account {ACCOUNT} does not exist")));
                let (ia, ib) = (find(a_id)?, find(b_id)?);
                if s.shards[ia].closed || s.shards[ib].closed {
                    return Err(err("InvalidArgumentException", format!("Shards {a_id} and {b_id} must both be open")));
                }
                let (sa, sb) = (&s.shards[ia], &s.shards[ib]);
                // Adjacency without u128 overflow (sb.end may be u128::MAX).
                let adjacent = (sa.end < sb.start && sa.end + 1 == sb.start) || (sb.end < sa.start && sb.end + 1 == sa.start);
                if !adjacent {
                    return Err(err("InvalidArgumentException", format!("Shards {a_id} and {b_id} are not adjacent")));
                }
                let (lo, hi) = (sa.start.min(sb.start), sa.end.max(sb.end));
                s.shards[ia].closed = true;
                s.shards[ib].closed = true;
                let id = shard_id(s.next);
                s.next += 1;
                s.shards.push(Shard::open(id, lo, hi));
                json!({})
            }
            "IncreaseStreamRetentionPeriod" | "DecreaseStreamRetentionPeriod" => {
                let n = stream_name(r)?;
                let want = r["NewRetentionPeriodHours"].as_u64().or_else(|| r["RetentionPeriodHours"].as_u64()).unwrap_or(0);
                let s = self.streams.get_mut(&n).ok_or_else(|| not_found(&n))?;
                if !(24..=8760).contains(&want) {
                    return Err(err("InvalidArgumentException", "NewRetentionPeriodHours must be between 24 and 8760"));
                }
                let increasing = op.starts_with("Increase");
                if want == s.retention || (increasing && want < s.retention) || (!increasing && want > s.retention) {
                    return Err(err("InvalidArgumentException", format!("NewRetentionPeriodHours {want} must be {} than the current {}", if increasing { "greater" } else { "less" }, s.retention)));
                }
                s.retention = want;
                json!({})
            }
            "UpdateShardCount" => {
                let n = stream_name(r)?;
                if need(r, "ScalingType")? != "UNIFORM_SCALING" {
                    return Err(err("ValidationException", "Only UNIFORM_SCALING is supported locally"));
                }
                let target = r["TargetShardCount"].as_u64().unwrap_or(0);
                if !(1..=64).contains(&target) {
                    return Err(err("InvalidArgumentException", "TargetShardCount must be between 1 and 64"));
                }
                let s = self.streams.get_mut(&n).ok_or_else(|| not_found(&n))?;
                let open = s.shards.iter().filter(|sh| !sh.closed).count() as u64;
                if target == open {
                    return Err(err("InvalidArgumentException", "TargetShardCount must differ from the current open shard count"));
                }
                // UNIFORM_SCALING: close every open shard, then open `target` even ones. Old records stay readable.
                for sh in s.shards.iter_mut() {
                    sh.closed = true;
                }
                let next = s.next;
                for i in 0..target as usize {
                    let (a, b) = range(i, target as usize);
                    s.shards.push(Shard::open(shard_id(next + i), a, b));
                }
                s.next = next + target as usize;
                json!({"StreamARN": arn(&n), "StreamStatus": "ACTIVE", "CurrentShardCount": open, "TargetShardCount": target})
            }
            "GetShardIterator" => {
                let n = stream_name(r)?;
                let s = self.streams.get(&n).ok_or_else(|| not_found(&n))?;
                let sid = need(r, "ShardId")?;
                let i = s.shards.iter().position(|sh| sh.id == sid)
                    .ok_or_else(|| err("ResourceNotFoundException", format!("Shard {sid} in stream {n} under account {ACCOUNT} does not exist")))?;
                let recs = &s.shards[i].recs;
                let at_seq = |after: bool| -> Result<usize, ApiErr> {
                    let q = need(r, "StartingSequenceNumber")?;
                    let p = recs.iter().position(|x| x.seq.as_str() >= q).unwrap_or(recs.len());
                    Ok(if after && recs.get(p).is_some_and(|x| x.seq == q) { p + 1 } else { p })
                };
                let pos = match need(r, "ShardIteratorType")? {
                    "TRIM_HORIZON" => self.fresh_start(s, i),
                    "LATEST" => recs.len(),
                    "AT_SEQUENCE_NUMBER" => at_seq(false)?,
                    "AFTER_SEQUENCE_NUMBER" => at_seq(true)?,
                    "AT_TIMESTAMP" => {
                        let t = r["Timestamp"].as_f64().unwrap_or(0.0);
                        recs.iter().position(|x| x.at >= t).unwrap_or(recs.len())
                    }
                    other => return Err(err("ValidationException", format!("Invalid ShardIteratorType {other}"))),
                };
                json!({"ShardIterator": iterator(&n, i, pos)})
            }
            "GetRecords" => {
                let bad = || err("InvalidArgumentException", "Invalid ShardIterator.");
                let raw = String::from_utf8(unb64(need(r, "ShardIterator")?).ok_or_else(bad)?).map_err(|_| bad())?;
                let mut it = raw.splitn(3, '|');
                let (n, i, pos) = (it.next().unwrap_or(""), it.next().and_then(|x| x.parse::<usize>().ok()).ok_or_else(bad)?, it.next().and_then(|x| x.parse::<usize>().ok()).ok_or_else(bad)?);
                let s = self.streams.get(n).ok_or_else(|| not_found(n))?;
                let recs = s.shards.get(i).map(|sh| &sh.recs).ok_or_else(bad)?;
                let start = self.fresh_start(s, i).max(pos);
                let limit = r["Limit"].as_u64().unwrap_or(10000) as usize;
                let page: Vec<Value> = recs.iter().skip(start).take(limit)
                    .map(|x| json!({"SequenceNumber": x.seq, "ApproximateArrivalTimestamp": x.at, "Data": x.data, "PartitionKey": x.key})).collect();
                let next = start.min(recs.len()) + page.len();
                json!({"Records": page, "NextShardIterator": iterator(n, i, next), "MillisBehindLatest": 0})
            }
            _ => return Err(err("UnknownOperationException", format!("{op} is not supported yet"))),
        })
    }

    pub fn admin(&self) -> Value {
        self.streams
            .iter()
            .map(|(n, s)| {
                let open = s.shards.iter().filter(|sh| !sh.closed).count();
                let mut recs: Vec<(String, Value)> = s.shards.iter().flat_map(|sh| sh.recs.iter().map(move |x| {
                    let text = unb64(&x.data).map(|d| String::from_utf8_lossy(&d).into_owned()).unwrap_or_default();
                    (x.seq.clone(), json!([sh.id, x.key, text, x.seq.trim_start_matches('0')]))
                })).collect();
                recs.sort_by(|a, b| b.0.cmp(&a.0));
                json!({"name": n, "count": recs.len(), "sub": format!("샤드 {}개(열림 {}) · 최근 레코드 100개", s.shards.len(), open),
                       "cols": ["샤드", "파티션 키", "데이터", "시퀀스"], "rows": recs.into_iter().take(100).map(|(_, v)| v).collect::<Vec<_>>()})
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rec(k: &Kinesis, n: &str) -> usize {
        k.streams[n].shards.iter().flat_map(|sh| sh.recs.iter()).count()
    }

    #[test]
    fn retention_hides_expired_records() {
        let mut k = Kinesis::default();
        k.handle("CreateStream", &json!({"StreamName": "s", "ShardCount": 1})).unwrap();
        for i in 0..3 {
            k.handle("PutRecord", &json!({"StreamName": "s", "Data": b64(format!("{i}").as_bytes()), "PartitionKey": "p"})).unwrap();
        }
        assert_eq!(rec(&k, "s"), 3);
        // Retention bounds and direction are validated.
        assert!(k.handle("IncreaseStreamRetentionPeriod", &json!({"StreamName": "s", "NewRetentionPeriodHours": 24})).is_err());
        k.handle("IncreaseStreamRetentionPeriod", &json!({"StreamName": "s", "NewRetentionPeriodHours": 48})).unwrap();
        assert_eq!(k.handle("DescribeStreamSummary", &json!({"StreamName": "s"})).unwrap()["StreamDescriptionSummary"]["RetentionPeriodHours"], 48);
        assert!(k.handle("DecreaseStreamRetentionPeriod", &json!({"StreamName": "s", "NewRetentionPeriodHours": 48})).is_err());
        k.handle("DecreaseStreamRetentionPeriod", &json!({"StreamName": "s", "NewRetentionPeriodHours": 24})).unwrap();
        // 25 hours later with the 24h window: records are gone from reads (but not from storage).
        k.clock += 25.0 * 3600.0;
        let it = k.handle("GetShardIterator", &json!({"StreamName": "s", "ShardId": "shardId-000000000000", "ShardIteratorType": "TRIM_HORIZON"})).unwrap();
        let out = k.handle("GetRecords", &json!({"ShardIterator": it["ShardIterator"]})).unwrap();
        assert_eq!(out["Records"].as_array().unwrap().len(), 0, "expired records must be hidden");
        assert_eq!(rec(&k, "s"), 3, "records stay in storage until the stream is deleted");
        // The lambda poll path hides them too.
        assert!(k.read("s", 0, 0, 10).is_empty());
    }

    #[test]
    fn update_shard_count_keeps_records() {
        let mut k = Kinesis::default();
        k.handle("CreateStream", &json!({"StreamName": "s", "ShardCount": 1})).unwrap();
        for i in 0..3 {
            k.handle("PutRecord", &json!({"StreamName": "s", "Data": b64(format!("{i}").as_bytes()), "PartitionKey": "p"})).unwrap();
        }
        // 1 -> 2: old shard closes, two new even ones open, records survive in the closed shard.
        let r = k.handle("UpdateShardCount", &json!({"StreamName": "s", "TargetShardCount": 2, "ScalingType": "UNIFORM_SCALING"})).unwrap();
        assert_eq!(r["CurrentShardCount"], 1);
        assert_eq!(r["TargetShardCount"], 2);
        let d = k.handle("DescribeStreamSummary", &json!({"StreamName": "s"})).unwrap();
        assert_eq!(d["StreamDescriptionSummary"]["OpenShardCount"], 2);
        let it = k.handle("GetShardIterator", &json!({"StreamName": "s", "ShardId": "shardId-000000000000", "ShardIteratorType": "TRIM_HORIZON"})).unwrap();
        let out = k.handle("GetRecords", &json!({"ShardIterator": it["ShardIterator"]})).unwrap();
        assert_eq!(out["Records"].as_array().unwrap().len(), 3, "records must not be lost in a reshard");
        // 2 -> 1 again; new puts land in the open shard.
        k.handle("UpdateShardCount", &json!({"StreamName": "s", "TargetShardCount": 1, "ScalingType": "UNIFORM_SCALING"})).unwrap();
        k.handle("PutRecord", &json!({"StreamName": "s", "Data": b64(b"new"), "PartitionKey": "p"})).unwrap();
        assert_eq!(rec(&k, "s"), 4);
        assert_eq!(k.handle("ListShards", &json!({"StreamName": "s"})).unwrap()["Shards"].as_array().unwrap().len(), 4, "1 closed + 2 closed + 1 open");
        assert_eq!(k.handle("UpdateShardCount", &json!({"StreamName": "s", "TargetShardCount": 1, "ScalingType": "UNIFORM_SCALING"})).unwrap_err().code, "InvalidArgumentException");
        assert_eq!(k.handle("UpdateShardCount", &json!({"StreamName": "s", "TargetShardCount": 2, "ScalingType": "something"})).unwrap_err().code, "ValidationException");
    }
}

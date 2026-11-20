// Kinesis Data Streams (JSON 1.1): shards by MD5 hash range, sequence numbers, shard iterators.
// ponytail: no resharding, enhanced fan-out, retention expiry or Lambda event source mappings yet.
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
struct Stream {
    created: f64,
    shards: Vec<Vec<Rec>>,
    on_demand: bool,
}

#[derive(Default)]
pub struct Kinesis {
    streams: BTreeMap<String, Stream>,
    seq: u128,
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
    fn describe(n: &str, s: &Stream, summary: bool) -> Value {
        let mut d = json!({"StreamName": n, "StreamARN": arn(n), "StreamStatus": "ACTIVE", "RetentionPeriodHours": 24,
            "StreamCreationTimestamp": s.created, "EncryptionType": "NONE", "OpenShardCount": s.shards.len(),
            "StreamModeDetails": {"StreamMode": if s.on_demand { "ON_DEMAND" } else { "PROVISIONED" }}, "EnhancedMonitoring": [{"ShardLevelMetrics": []}]});
        if !summary {
            d["Shards"] = Self::shards(s).into();
            d["HasMoreShards"] = false.into();
        }
        d
    }
    fn shards(s: &Stream) -> Vec<Value> {
        let n = s.shards.len();
        (0..n).map(|i| {
            let (a, b) = range(i, n);
            json!({"ShardId": shard_id(i), "HashKeyRange": {"StartingHashKey": a.to_string(), "EndingHashKey": b.to_string()},
                   "SequenceNumberRange": {"StartingSequenceNumber": format!("{:056}", 0)}})
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
        let n = s.shards.len();
        let i = (0..n).find(|i| { let (a, b) = range(*i, n); a <= hash && hash <= b }).unwrap_or(n - 1);
        self.seq += 1;
        let seq = format!("{:056}", self.seq);
        s.shards[i].push(Rec { seq: seq.clone(), data: data.into(), key: key.into(), at: epoch() });
        Ok(json!({"ShardId": shard_id(i), "SequenceNumber": seq}))
    }

    pub fn handle(&mut self, op: &str, r: &Value) -> Result<Value, ApiErr> {
        Ok(match op {
            "CreateStream" => {
                let n = need(r, "StreamName")?;
                if self.streams.contains_key(n) {
                    return Err(err("ResourceInUseException", format!("Stream {n} under account {ACCOUNT} already exists.")));
                }
                let on_demand = r["StreamModeDetails"]["StreamMode"] == "ON_DEMAND";
                let count = r["ShardCount"].as_u64().unwrap_or(if on_demand { 4 } else { 1 }).clamp(1, 64) as usize;
                self.streams.insert(n.into(), Stream { created: epoch(), shards: (0..count).map(|_| vec![]).collect(), on_demand });
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
            "GetShardIterator" => {
                let n = stream_name(r)?;
                let s = self.streams.get(&n).ok_or_else(|| not_found(&n))?;
                let sid = need(r, "ShardId")?;
                let i = s.shards.iter().enumerate().map(|(i, _)| i).find(|i| shard_id(*i) == sid)
                    .ok_or_else(|| err("ResourceNotFoundException", format!("Shard {sid} in stream {n} under account {ACCOUNT} does not exist")))?;
                let recs = &s.shards[i];
                let at_seq = |after: bool| -> Result<usize, ApiErr> {
                    let q = need(r, "StartingSequenceNumber")?;
                    let p = recs.iter().position(|x| x.seq.as_str() >= q).unwrap_or(recs.len());
                    Ok(if after && recs.get(p).is_some_and(|x| x.seq == q) { p + 1 } else { p })
                };
                let pos = match need(r, "ShardIteratorType")? {
                    "TRIM_HORIZON" => 0,
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
                let recs = s.shards.get(i).ok_or_else(bad)?;
                let limit = r["Limit"].as_u64().unwrap_or(10000) as usize;
                let page: Vec<Value> = recs.iter().skip(pos).take(limit)
                    .map(|x| json!({"SequenceNumber": x.seq, "ApproximateArrivalTimestamp": x.at, "Data": x.data, "PartitionKey": x.key})).collect();
                let next = pos.min(recs.len()) + page.len();
                json!({"Records": page, "NextShardIterator": iterator(n, i, next), "MillisBehindLatest": 0})
            }
            _ => return Err(err("UnknownOperationException", format!("{op} is not supported yet"))),
        })
    }

    pub fn admin(&self) -> Value {
        self.streams
            .iter()
            .map(|(n, s)| {
                let mut recs: Vec<(String, Value)> = s.shards.iter().enumerate().flat_map(|(i, sh)| sh.iter().map(move |x| {
                    let text = unb64(&x.data).map(|d| String::from_utf8_lossy(&d).into_owned()).unwrap_or_default();
                    (x.seq.clone(), json!([shard_id(i), x.key, text, x.seq.trim_start_matches('0')]))
                })).collect();
                recs.sort_by(|a, b| b.0.cmp(&a.0));
                json!({"name": n, "count": recs.len(), "sub": format!("샤드 {}개 · 최근 레코드 100개", s.shards.len()),
                       "cols": ["샤드", "파티션 키", "데이터", "시퀀스"], "rows": recs.into_iter().take(100).map(|(_, v)| v).collect::<Vec<_>>()})
            })
            .collect()
    }
}

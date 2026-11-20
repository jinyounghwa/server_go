use crate::App;
use axum::{
    body::{Body, Bytes},
    http::{response::Builder, HeaderMap, Method, Uri},
    response::Response,
};
use chrono::{DateTime, Utc};
use md5::{Digest, Md5};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Bound::{Excluded, Unbounded};

#[derive(Clone)]
pub struct Obj {
    data: Bytes,
    etag: String,
    ctype: String,
    modified: DateTime<Utc>,
    meta: Vec<(String, String)>,
}
pub struct Bucket {
    created: DateTime<Utc>,
    objs: BTreeMap<String, Obj>,
    notif: Vec<Notif>,
    notif_xml: String,
}
// One bucket notification target (QueueConfiguration / TopicConfiguration / CloudFunctionConfiguration).
struct Notif {
    id: String,
    kind: &'static str,
    target: String,
    events: Vec<String>,
    prefix: String,
    suffix: String,
}
// A notification waiting to be delivered by main (which owns the other services).
pub struct Note {
    pub kind: &'static str, // sqs | sns | lambda
    pub target: String,
    pub body: String,
}
struct Upload {
    bucket: String,
    key: String,
    ctype: String,
    meta: Vec<(String, String)>,
    parts: BTreeMap<u32, Bytes>,
}
#[derive(Default)]
pub struct Store {
    buckets: BTreeMap<String, Bucket>,
    uploads: HashMap<String, Upload>,
    pending: Vec<Note>,
}

const NS: &str = r#" xmlns="http://s3.amazonaws.com/doc/2006-03-01/""#;
// Sub-resources we don't emulate yet: answer 501 instead of pretending.
const UNSUPPORTED: &[&str] = &[
    "acl", "policy", "tagging", "versioning", "versions", "cors", "lifecycle", "website",
    "encryption", "logging", "replication", "location", "ownershipControls", "publicAccessBlock",
    "object-lock", "legal-hold", "retention", "attributes", "accelerate", "requestPayment", "torrent",
];

fn resp(status: u16) -> Builder {
    Response::builder().status(status)
}
fn xml(status: u16, body: String) -> Response {
    resp(status)
        .header("content-type", "application/xml")
        .body(Body::from(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{body}")))
        .unwrap()
}
fn empty(status: u16) -> Response {
    resp(status).body(Body::empty()).unwrap()
}
fn fail(status: u16, code: &str, msg: &str) -> Response {
    xml(status, format!("<Error><Code>{code}</Code><Message>{}</Message></Error>", esc(msg)))
}
fn no_bucket() -> Response {
    fail(404, "NoSuchBucket", "The specified bucket does not exist")
}
fn no_key() -> Response {
    fail(404, "NoSuchKey", "The specified key does not exist.")
}
pub(crate) fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}
fn unesc(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}
fn iso(t: &DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}
fn etag_of(b: &[u8]) -> String {
    format!("\"{:x}\"", Md5::digest(b))
}

pub fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ponytail: string-scanning XML reader; enough for DeleteObjects / CompleteMultipartUpload bodies.
pub(crate) fn tags(x: &str, tag: &str) -> Vec<String> {
    let (o, c) = (format!("<{tag}>"), format!("</{tag}>"));
    x.split(o.as_str()).skip(1).filter_map(|s| s.split_once(c.as_str()).map(|(v, _)| unesc(v))).collect()
}

fn hdr<'a>(h: &'a HeaderMap, k: &str) -> Option<&'a str> {
    h.get(k).and_then(|v| v.to_str().ok())
}

fn meta_from(h: &HeaderMap) -> Vec<(String, String)> {
    h.iter()
        .filter_map(|(k, v)| Some((k.as_str().strip_prefix("x-amz-meta-")?.to_string(), v.to_str().ok()?.to_string())))
        .collect()
}

// SDKs stream uploads as aws-chunked (size;sig\r\ndata\r\n ... 0\r\ntrailers). Strip the framing.
fn dechunk(h: &HeaderMap, body: Bytes) -> Bytes {
    let chunked = hdr(h, "x-amz-content-sha256").is_some_and(|v| v.starts_with("STREAMING-"))
        || hdr(h, "content-encoding").is_some_and(|v| v.contains("aws-chunked"));
    if !chunked {
        return body;
    }
    let mut out = Vec::new();
    let mut rest = &body[..];
    while let Some(nl) = rest.windows(2).position(|w| w == b"\r\n") {
        let line = std::str::from_utf8(&rest[..nl]).unwrap_or("");
        let n = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
        let start = nl + 2;
        if n == 0 || start + n > rest.len() {
            break;
        }
        out.extend_from_slice(&rest[start..start + n]);
        rest = &rest[(start + n + 2).min(rest.len())..];
    }
    out.into()
}

fn obj_headers(o: &Obj, status: u16, len: usize) -> Builder {
    let mut r = resp(status)
        .header("etag", &o.etag)
        .header("content-type", &o.ctype)
        .header("content-length", len)
        .header("accept-ranges", "bytes")
        .header("last-modified", o.modified.format("%a, %d %b %Y %H:%M:%S GMT").to_string());
    for (k, v) in &o.meta {
        r = r.header(format!("x-amz-meta-{k}"), v);
    }
    r
}

pub struct Req {
    pub op: &'static str,
    pub bucket: String,
    pub key: String,
    q: HashMap<String, String>,
}

impl Req {
    // IAM action and resource ARN this request is checked against.
    pub fn iam(&self) -> (&'static str, String) {
        let action = match self.op {
            "ListBuckets" => "s3:ListAllMyBuckets",
            "HeadBucket" | "ListObjects" | "ListObjectsV2" => "s3:ListBucket",
            "HeadObject" | "GetObject" => "s3:GetObject",
            "DeleteObjects" | "DeleteObject" => "s3:DeleteObject",
            "CopyObject" | "CreateMultipartUpload" | "UploadPart" | "CompleteMultipartUpload" | "PutObject" => "s3:PutObject",
            "AbortMultipartUpload" => "s3:AbortMultipartUpload",
            "CreateBucket" => "s3:CreateBucket",
            "PutBucketNotificationConfiguration" => "s3:PutBucketNotification",
            "GetBucketNotificationConfiguration" => "s3:GetBucketNotification",
            "DeleteBucket" => "s3:DeleteBucket",
            _ => "s3:Unsupported",
        };
        let res = match (self.bucket.is_empty(), self.key.is_empty() || action == "s3:ListBucket") {
            (true, _) => "*".to_string(),
            (false, true) => format!("arn:aws:s3:::{}", self.bucket),
            (false, false) => format!("arn:aws:s3:::{}/{}", self.bucket, self.key),
        };
        (action, res)
    }
}

pub fn classify(m: &Method, uri: &Uri, h: &HeaderMap) -> Req {
    let q: HashMap<String, String> = uri
        .query()
        .unwrap_or("")
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (pct_decode(k), pct_decode(v))
        })
        .collect();
    let path = uri.path().trim_start_matches('/');
    // Virtual-host style (bucket.localhost:4566) or path style (/bucket/key).
    let host = hdr(h, "host").unwrap_or("").split(':').next().unwrap_or("");
    let (bucket, key) = match host.strip_suffix(".localhost") {
        Some(b) if !b.is_empty() => (b.to_string(), pct_decode(path)),
        _ => {
            let (b, k) = path.split_once('/').unwrap_or((path, ""));
            (pct_decode(b), pct_decode(k))
        }
    };
    let has = |k: &str| q.contains_key(k);
    let op = match (m.as_str(), bucket.is_empty(), key.is_empty()) {
        _ if UNSUPPORTED.iter().any(|k| has(k)) => "Unsupported",
        ("GET", true, _) => "ListBuckets",
        (_, true, _) => "Unsupported",
        ("PUT", _, true) if has("notification") => "PutBucketNotificationConfiguration",
        ("GET", _, true) if has("notification") => "GetBucketNotificationConfiguration",
        ("PUT", _, true) => "CreateBucket",
        ("HEAD", _, true) => "HeadBucket",
        ("DELETE", _, true) => "DeleteBucket",
        ("GET", _, true) if has("uploads") => "Unsupported",
        ("GET", _, true) => if q.get("list-type").is_some_and(|v| v == "2") { "ListObjectsV2" } else { "ListObjects" },
        ("POST", _, true) if has("delete") => "DeleteObjects",
        ("POST", _, false) if has("uploads") => "CreateMultipartUpload",
        ("POST", _, false) if has("uploadId") => "CompleteMultipartUpload",
        ("PUT", _, false) if has("uploadId") => "UploadPart",
        ("DELETE", _, false) if has("uploadId") => "AbortMultipartUpload",
        ("PUT", _, false) if h.contains_key("x-amz-copy-source") => "CopyObject",
        ("PUT", _, false) => "PutObject",
        ("GET", _, false) => "GetObject",
        ("HEAD", _, false) => "HeadObject",
        ("DELETE", _, false) => "DeleteObject",
        _ => "Unsupported",
    };
    Req { op, bucket, key, q }
}

pub fn handle(app: &App, r: &Req, h: &HeaderMap, body: Bytes) -> Response {
    let body = dechunk(h, body);
    let mut st = app.s3.lock().unwrap();
    exec(&mut st, r.op, &r.bucket, &r.key, &r.q, h, body).unwrap_or_else(|e| e)
}

pub fn error(e: &crate::ApiErr) -> Response {
    fail(e.status, &e.code, &e.msg)
}

fn exec(
    st: &mut Store,
    op: &str,
    b: &str,
    k: &str,
    q: &HashMap<String, String>,
    h: &HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let ctype = || hdr(h, "content-type").unwrap_or("binary/octet-stream").to_string();
    Ok(match op {
        "ListBuckets" => {
            let list: String = st
                .buckets
                .iter()
                .map(|(n, b)| format!("<Bucket><Name>{}</Name><CreationDate>{}</CreationDate></Bucket>", esc(n), iso(&b.created)))
                .collect();
            xml(200, format!("<ListAllMyBucketsResult{NS}><Owner><ID>local</ID><DisplayName>local</DisplayName></Owner><Buckets>{list}</Buckets></ListAllMyBucketsResult>"))
        }
        "CreateBucket" => {
            if st.buckets.contains_key(b) {
                return Err(fail(409, "BucketAlreadyOwnedByYou", "Your previous request to create the named bucket succeeded and you already own it."));
            }
            st.buckets.insert(b.into(), Bucket { created: Utc::now(), objs: BTreeMap::new(), notif: vec![], notif_xml: String::new() });
            resp(200).header("location", format!("/{b}")).body(Body::empty()).unwrap()
        }
        "HeadBucket" => {
            st.buckets.get(b).ok_or_else(|| empty(404))?;
            resp(200).header("x-amz-bucket-region", crate::REGION.as_str()).body(Body::empty()).unwrap()
        }
        "DeleteBucket" => {
            let bk = st.buckets.get(b).ok_or_else(no_bucket)?;
            if !bk.objs.is_empty() {
                return Err(fail(409, "BucketNotEmpty", "The bucket you tried to delete is not empty"));
            }
            st.buckets.remove(b);
            empty(204)
        }
        "ListObjects" | "ListObjectsV2" => {
            let bk = st.buckets.get(b).ok_or_else(no_bucket)?;
            let v2 = op == "ListObjectsV2";
            let prefix = q.get("prefix").map_or("", |s| s.as_str());
            let delim = q.get("delimiter").filter(|d| !d.is_empty());
            let max: usize = q.get("max-keys").and_then(|v| v.parse().ok()).unwrap_or(1000);
            let start = if v2 { q.get("continuation-token").or(q.get("start-after")) } else { q.get("marker") };
            let lower = start.map_or(Unbounded, |s| Excluded(s.clone()));
            let (mut contents, mut prefixes) = (String::new(), BTreeSet::new());
            let (mut count, mut next, mut truncated) = (0, None::<String>, false);
            for (key, o) in bk.objs.range::<String, _>((lower, Unbounded)) {
                if !key.starts_with(prefix) {
                    continue;
                }
                let cp = delim.and_then(|d| key[prefix.len()..].find(d.as_str()).map(|i| &key[..prefix.len() + i + d.len()]));
                if cp.is_some_and(|cp| prefixes.contains(cp)) {
                    continue;
                }
                if count == max {
                    truncated = true;
                    break;
                }
                count += 1;
                if let Some(cp) = cp {
                    prefixes.insert(cp.to_string());
                    // ponytail: resume token skips the whole prefix by appending the highest char.
                    next = Some(format!("{cp}\u{10FFFF}"));
                } else {
                    next = Some(key.clone());
                    contents += &format!(
                        "<Contents><Key>{}</Key><LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>",
                        esc(key), iso(&o.modified), esc(&o.etag), o.data.len()
                    );
                }
            }
            let cps: String = prefixes.iter().map(|p| format!("<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>", esc(p))).collect();
            let mut x = format!("<ListBucketResult{NS}><Name>{}</Name><Prefix>{}</Prefix><MaxKeys>{max}</MaxKeys><IsTruncated>{truncated}</IsTruncated>", esc(b), esc(prefix));
            if let Some(d) = delim {
                x += &format!("<Delimiter>{}</Delimiter>", esc(d));
            }
            if v2 {
                x += &format!("<KeyCount>{count}</KeyCount>");
                if let Some(t) = q.get("continuation-token") {
                    x += &format!("<ContinuationToken>{}</ContinuationToken>", esc(t));
                }
            }
            if truncated {
                let tag = if v2 { "NextContinuationToken" } else { "NextMarker" };
                x += &format!("<{tag}>{}</{tag}>", esc(&next.unwrap_or_default()));
            }
            xml(200, format!("{x}{contents}{cps}</ListBucketResult>"))
        }
        "DeleteObjects" => {
            let bk = st.buckets.get_mut(b).ok_or_else(no_bucket)?;
            let mut out = String::new();
            let keys = tags(&String::from_utf8_lossy(&body), "Key");
            for key in &keys {
                bk.objs.remove(key);
                out += &format!("<Deleted><Key>{}</Key></Deleted>", esc(key));
            }
            for key in &keys {
                notify(st, b, "ObjectRemoved:Delete", key, 0, "");
            }
            xml(200, format!("<DeleteResult{NS}>{out}</DeleteResult>"))
        }
        "PutObject" => {
            let bk = st.buckets.get_mut(b).ok_or_else(no_bucket)?;
            let o = Obj { etag: etag_of(&body), data: body, ctype: ctype(), modified: Utc::now(), meta: meta_from(h) };
            let (etag, size) = (o.etag.clone(), o.data.len());
            bk.objs.insert(k.into(), o);
            notify(st, b, "ObjectCreated:Put", k, size, &etag);
            resp(200).header("etag", etag).body(Body::empty()).unwrap()
        }
        "CopyObject" => {
            let raw = hdr(h, "x-amz-copy-source").unwrap_or("");
            let src = pct_decode(raw.split('?').next().unwrap_or(""));
            let (sb, sk) = src.trim_start_matches('/').split_once('/').ok_or_else(|| fail(400, "InvalidArgument", "Invalid copy source"))?;
            let mut o = st.buckets.get(sb).ok_or_else(no_bucket)?.objs.get(sk).ok_or_else(no_key)?.clone();
            o.modified = Utc::now();
            if hdr(h, "x-amz-metadata-directive") == Some("REPLACE") {
                (o.meta, o.ctype) = (meta_from(h), ctype());
            }
            let bk = st.buckets.get_mut(b).ok_or_else(no_bucket)?;
            let x = format!("<CopyObjectResult><ETag>{}</ETag><LastModified>{}</LastModified></CopyObjectResult>", esc(&o.etag), iso(&o.modified));
            let (etag, size) = (o.etag.clone(), o.data.len());
            bk.objs.insert(k.into(), o);
            notify(st, b, "ObjectCreated:Copy", k, size, &etag);
            xml(200, x)
        }
        "GetObject" | "HeadObject" => {
            let o = st.buckets.get(b).ok_or_else(no_bucket)?.objs.get(k).ok_or_else(no_key)?;
            let len = o.data.len();
            let (status, s, e) = match hdr(h, "range").and_then(|v| v.strip_prefix("bytes=")) {
                None => (200, 0, len),
                Some(r) => {
                    let (a, z) = r.split_once('-').unwrap_or((r, ""));
                    let (s, e) = if a.is_empty() {
                        (len.saturating_sub(z.parse().unwrap_or(0)), len)
                    } else {
                        (a.parse().unwrap_or(0), z.parse::<usize>().map_or(len, |e| (e + 1).min(len)))
                    };
                    if s >= e {
                        return Err(fail(416, "InvalidRange", "The requested range is not satisfiable"));
                    }
                    (206, s, e)
                }
            };
            let mut r = obj_headers(o, status, e - s);
            if status == 206 {
                r = r.header("content-range", format!("bytes {s}-{}/{len}", e - 1));
            }
            let data = if op == "HeadObject" { Body::empty() } else { Body::from(o.data.slice(s..e)) };
            r.body(data).unwrap()
        }
        "DeleteObject" => {
            st.buckets.get_mut(b).ok_or_else(no_bucket)?.objs.remove(k);
            notify(st, b, "ObjectRemoved:Delete", k, 0, "");
            empty(204)
        }
        "CreateMultipartUpload" => {
            st.buckets.get(b).ok_or_else(no_bucket)?;
            let id = uuid::Uuid::new_v4().simple().to_string();
            st.uploads.insert(id.clone(), Upload { bucket: b.into(), key: k.into(), ctype: ctype(), meta: meta_from(h), parts: BTreeMap::new() });
            xml(200, format!("<InitiateMultipartUploadResult{NS}><Bucket>{}</Bucket><Key>{}</Key><UploadId>{id}</UploadId></InitiateMultipartUploadResult>", esc(b), esc(k)))
        }
        "UploadPart" => {
            let n: u32 = q.get("partNumber").and_then(|v| v.parse().ok()).ok_or_else(|| fail(400, "InvalidArgument", "partNumber required"))?;
            let up = st.uploads.get_mut(&q["uploadId"]).ok_or_else(no_upload)?;
            let etag = etag_of(&body);
            up.parts.insert(n, body);
            resp(200).header("etag", etag).body(Body::empty()).unwrap()
        }
        "CompleteMultipartUpload" => {
            let id = &q["uploadId"];
            let up = st.uploads.get(id).ok_or_else(no_upload)?;
            let mut nums: Vec<u32> = tags(&String::from_utf8_lossy(&body), "PartNumber").iter().filter_map(|n| n.parse().ok()).collect();
            if nums.is_empty() {
                nums = up.parts.keys().copied().collect();
            }
            let (mut data, mut digests) = (Vec::new(), Vec::new());
            for n in &nums {
                let p = up.parts.get(n).ok_or_else(|| fail(400, "InvalidPart", "One or more of the specified parts could not be found."))?;
                data.extend_from_slice(p);
                digests.extend_from_slice(&Md5::digest(p));
            }
            let up = st.uploads.remove(id).unwrap();
            let etag = format!("\"{:x}-{}\"", Md5::digest(&digests), nums.len());
            let bk = st.buckets.get_mut(&up.bucket).ok_or_else(no_bucket)?;
            let size = data.len();
            bk.objs.insert(up.key.clone(), Obj { data: data.into(), etag: etag.clone(), ctype: up.ctype, modified: Utc::now(), meta: up.meta });
            notify(st, &up.bucket, "ObjectCreated:CompleteMultipartUpload", &up.key, size, &etag);
            xml(200, format!("<CompleteMultipartUploadResult{NS}><Location>/{0}/{1}</Location><Bucket>{0}</Bucket><Key>{1}</Key><ETag>{2}</ETag></CompleteMultipartUploadResult>", esc(&up.bucket), esc(&up.key), esc(&etag)))
        }
        "PutBucketNotificationConfiguration" => {
            let bk = st.buckets.get_mut(b).ok_or_else(no_bucket)?;
            let x = String::from_utf8_lossy(&body).to_string();
            bk.notif = parse_notif(&x);
            bk.notif_xml = x;
            empty(200)
        }
        "GetBucketNotificationConfiguration" => {
            let bk = st.buckets.get(b).ok_or_else(no_bucket)?;
            let x = if bk.notif_xml.is_empty() { format!("<NotificationConfiguration{NS}/>") } else { bk.notif_xml.clone() };
            resp(200).header("content-type", "application/xml").body(Body::from(x)).unwrap()
        }
        "AbortMultipartUpload" => {
            st.uploads.remove(&q["uploadId"]).ok_or_else(no_upload)?;
            empty(204)
        }
        _ => fail(501, "NotImplemented", "This S3 operation is not supported yet"),
    })
}

// ponytail: destinations are not validated when the configuration is saved.
fn parse_notif(x: &str) -> Vec<Notif> {
    let mut out = vec![];
    for (block, tgt, kind) in [("QueueConfiguration", "Queue", "sqs"), ("TopicConfiguration", "Topic", "sns"), ("CloudFunctionConfiguration", "CloudFunction", "lambda")] {
        for c in tags(x, block) {
            let rules: Vec<(String, String)> = tags(&c, "FilterRule").iter()
                .map(|r| (tags(r, "Name").concat().to_lowercase(), tags(r, "Value").concat())).collect();
            let rule = |n: &str| rules.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone()).unwrap_or_default();
            out.push(Notif {
                id: tags(&c, "Id").pop().unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                kind,
                target: tags(&c, tgt).concat(),
                events: tags(&c, "Event"),
                prefix: rule("prefix"),
                suffix: rule("suffix"),
            });
        }
    }
    out
}

// Queue an S3 event record for every matching notification on the bucket.
fn notify(st: &mut Store, b: &str, event: &str, key: &str, size: usize, etag: &str) {
    let Some(bk) = st.buckets.get(b) else { return };
    for n in &bk.notif {
        let hit = n.events.iter().any(|e| crate::iam::glob(e, &format!("s3:{event}"), false));
        if !hit || !key.starts_with(&n.prefix) || !key.ends_with(&n.suffix) {
            continue;
        }
        let enc_key = crate::iam::pct_encode(key).replace("%2F", "/").replace("%20", "+");
        let rec = serde_json::json!({"Records": [{
            "eventVersion": "2.1", "eventSource": "aws:s3", "awsRegion": crate::REGION.as_str(), "eventTime": iso(&Utc::now()),
            "eventName": event, "userIdentity": {"principalId": "local"}, "requestParameters": {"sourceIPAddress": "127.0.0.1"},
            "responseElements": {"x-amz-request-id": "local"},
            "s3": {"s3SchemaVersion": "1.0", "configurationId": n.id,
                   "bucket": {"name": b, "ownerIdentity": {"principalId": "local"}, "arn": format!("arn:aws:s3:::{b}")},
                   "object": {"key": enc_key, "size": size, "eTag": etag.trim_matches('"'), "sequencer": format!("{:016X}", crate::now_ms())}}}]});
        st.pending.push(Note { kind: n.kind, target: n.target.clone(), body: rec.to_string() });
    }
}

impl Store {
    pub fn bucket_names(&self) -> Vec<String> {
        self.buckets.keys().cloned().collect()
    }
    pub fn object(&self, b: &str, k: &str) -> Option<Bytes> {
        self.buckets.get(b)?.objs.get(k).map(|o| o.data.clone())
    }
    pub fn take_notes(&mut self) -> Vec<Note> {
        std::mem::take(&mut self.pending)
    }
}

fn no_upload() -> Response {
    fail(404, "NoSuchUpload", "The specified multipart upload does not exist.")
}

impl Store {
    // GUI view: every bucket with up to 100 objects (metadata only).
    pub fn admin(&self) -> serde_json::Value {
        self.buckets
            .iter()
            .map(|(n, b)| serde_json::json!({"name": n, "count": b.objs.len(),
                "objects": b.objs.iter().take(100).map(|(k, o)| serde_json::json!({"key": k, "size": o.data.len(), "type": o.ctype, "modified": iso(&o.modified)})).collect::<Vec<_>>()}))
            .collect()
    }
}

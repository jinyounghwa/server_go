// SigV4 signing and (optional, VERIFY_SIGV4=1) verification. HMAC-SHA256 is built on sha2.
// Signed aws-chunked bodies (STREAMING-AWS4-HMAC-SHA256-PAYLOAD) have every chunk signature checked, and a hex
// x-amz-content-sha256 must match the body. With ...-PAYLOAD-TRAILER the x-amz-trailer-signature over the trailing headers is
// checked too. Header-signed requests are rejected when x-amz-date is more than 15 minutes off (RequestTimeTooSkewed);
// presigned URLs keep their X-Amz-Expires rule instead. ponytail: SigV4a is not checked; trailer checksum values are not recomputed.
use axum::http::{HeaderMap, Method, Uri};
use sha2::{Digest, Sha256};

fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let inner = Sha256::new().chain_update(k.map(|b| b ^ 0x36)).chain_update(msg).finalize();
    Sha256::new().chain_update(k.map(|b| b ^ 0x5c)).chain_update(inner).finalize().into()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

// RFC 3986 encoding with SigV4's unreserved set; '/' kept when encoding a path.
fn enc(s: &str, keep_slash: bool) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => o.push(b as char),
            b'/' if keep_slash => o.push('/'),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

fn canonical_query(q: &str) -> String {
    let mut ps: Vec<(String, String)> = q
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (enc(&crate::s3::pct_decode(k), false), enc(&crate::s3::pct_decode(v), false))
        })
        .filter(|(k, _)| k != "X-Amz-Signature")
        .collect();
    ps.sort();
    ps.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&")
}

// S3 signs the path as sent; every other service signs it URI-encoded once more.
fn canonical_uri(path: &str, service: &str) -> String {
    let p = if path.is_empty() { "/" } else { path };
    if service == "s3" { p.to_string() } else { enc(p, true) }
}

fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    [date, region, service, "aws4_request"].iter().fold(format!("AWS4{secret}").into_bytes(), |k, p| hmac(&k, p.as_bytes()).to_vec())
}

// Walks "size;chunk-signature=sig\r\ndata\r\n" chunks, each signed over the previous signature, up to the final 0-size chunk.
fn verify_chunks(body: &[u8], seed: &str, key: &[u8], amz_date: &str, scope: &str, trailer: bool) -> Result<(), String> {
    let (mut rest, mut prev, empty) = (body, seed.to_string(), sha256_hex(b""));
    loop {
        let nl = rest.windows(2).position(|w| w == b"\r\n").ok_or("chunk header is missing")?;
        let line = std::str::from_utf8(&rest[..nl]).map_err(|_| "chunk header is not text")?;
        let (size, sig) = line.split_once(";chunk-signature=").ok_or("chunk signature is missing")?;
        let n = usize::from_str_radix(size.trim(), 16).map_err(|_| "chunk size is invalid")?;
        let data = rest.get(nl + 2..nl + 2 + n).ok_or("chunk is shorter than its declared size")?;
        let sts = format!("AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{scope}\n{prev}\n{empty}\n{}", sha256_hex(data));
        if hex(&hmac(key, sts.as_bytes())) != sig.trim() {
            return Err("chunk signature does not match".into());
        }
        if n == 0 {
            return if trailer { verify_trailer(&rest[nl + 2..], sig.trim(), key, amz_date, scope) } else { Ok(()) };
        }
        prev = sig.trim().to_string();
        rest = rest.get(nl + 2 + n + 2..).ok_or("chunk is not terminated")?;
    }
}

// Trailing headers ("name:value\r\n" ... "x-amz-trailer-signature:sig\r\n\r\n") signed over the final chunk signature.
fn verify_trailer(rest: &[u8], prev: &str, key: &[u8], amz_date: &str, scope: &str) -> Result<(), String> {
    let text = std::str::from_utf8(rest).map_err(|_| "trailer is not text")?;
    let mut hs = vec![];
    let mut sig = None;
    for l in text.split('\n').map(|l| l.trim_end_matches('\r')).take_while(|l| !l.is_empty()) {
        let (k, v) = l.split_once(':').ok_or("trailer header is malformed")?;
        let k = k.trim().to_ascii_lowercase();
        if k == "x-amz-trailer-signature" { sig = Some(v.trim().to_string()) } else { hs.push(format!("{k}:{}\n", v.trim())) }
    }
    let sig = sig.ok_or("trailer signature is missing")?;
    hs.sort();
    let sts = format!("AWS4-HMAC-SHA256-TRAILER\n{amz_date}\n{scope}\n{prev}\n{}", sha256_hex(hs.concat().as_bytes()));
    if hex(&hmac(key, sts.as_bytes())) != sig { Err("trailer signature does not match".into()) } else { Ok(()) }
}

pub fn signature(secret: &str, date: &str, region: &str, service: &str, amz_date: &str, creq: &str) -> String {
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let sts = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", sha256_hex(creq.as_bytes()));
    let k = [date, region, service, "aws4_request"].iter().fold(format!("AWS4{secret}").into_bytes(), |k, p| hmac(&k, p.as_bytes()).to_vec());
    hex(&hmac(&k, sts.as_bytes()))
}

fn canonical_request(method: &str, path: &str, query: &str, service: &str, signed: &[&str], get: &dyn Fn(&str) -> String, payload: &str) -> String {
    let hdrs: String = signed.iter().map(|h| format!("{h}:{}\n", get(h).split_whitespace().collect::<Vec<_>>().join(" "))).collect();
    format!("{method}\n{}\n{}\n{hdrs}\n{}\n{payload}", canonical_uri(path, service), canonical_query(query), signed.join(";"))
}

// Checks the request's signature. `secret_of` maps an access key to (secret, session token).
pub fn verify(method: &Method, uri: &Uri, h: &HeaderMap, body: &[u8], secret_of: impl Fn(&str) -> (String, Option<String>)) -> Result<(), (&'static str, String)> {
    let hv = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).map(str::to_string);
    let query = uri.query().unwrap_or("");
    let qv = |k: &str| query.split('&').find_map(|p| p.strip_prefix(&format!("{k}="))).map(crate::s3::pct_decode);
    let (cred, signed, sig, amz_date, payload, token) = if let Some(a) = hv("authorization") {
        let part = |k: &str| a.split(k).nth(1).map(|s| s.split([',', ' ']).next().unwrap_or("").to_string());
        if !a.starts_with("AWS4-HMAC-SHA256") {
            return Err(("IncompleteSignature", "Only AWS4-HMAC-SHA256 signatures are supported.".into()));
        }
        let (Some(c), Some(sh), Some(sg)) = (part("Credential="), part("SignedHeaders="), part("Signature=")) else {
            return Err(("IncompleteSignature", "Authorization header is missing Credential, SignedHeaders or Signature.".into()));
        };
        let payload = hv("x-amz-content-sha256").unwrap_or_else(|| sha256_hex(body));
        (c, sh, sg, hv("x-amz-date").unwrap_or_default(), payload, hv("x-amz-security-token"))
    } else if let Some(c) = qv("X-Amz-Credential") {
        let exp: i64 = qv("X-Amz-Expires").and_then(|e| e.parse().ok()).unwrap_or(0);
        let d = qv("X-Amz-Date").unwrap_or_default();
        let t = chrono::NaiveDateTime::parse_from_str(&d, "%Y%m%dT%H%M%SZ").map_err(|_| ("AuthorizationQueryParametersError", "X-Amz-Date is invalid.".to_string()))?;
        if chrono::Utc::now().naive_utc() > t + chrono::Duration::seconds(exp) {
            return Err(("AccessDenied", "Request has expired".into()));
        }
        (c, qv("X-Amz-SignedHeaders").unwrap_or_default(), qv("X-Amz-Signature").unwrap_or_default(), d, "UNSIGNED-PAYLOAD".into(), qv("X-Amz-Security-Token"))
    } else if qv("AWSAccessKeyId").is_some() {
        return Err(("AccessDenied", "SigV2 presigned URLs are not supported with VERIFY_SIGV4=1; presign with signature_version='s3v4'.".into()));
    } else {
        return Err(("MissingAuthenticationToken", "Request is missing Authentication Token".into()));
    };
    // AWS rejects header-signed requests whose x-amz-date is more than ~15 minutes off the server clock.
    // Presigned URLs are exempt: their X-Amz-Date is creation time and only X-Amz-Expires bounds them.
    if hv("authorization").is_some() {
        if let Ok(t) = chrono::NaiveDateTime::parse_from_str(&amz_date, "%Y%m%dT%H%M%SZ") {
            if (chrono::Utc::now().naive_utc() - t).num_seconds().abs() > 900 {
                return Err(("RequestTimeTooSkewed", "The difference between the request time and the server's time is too large.".into()));
            }
        }
    }
    let parts: Vec<&str> = cred.split('/').collect();
    if parts.len() != 5 {
        return Err(("IncompleteSignature", format!("Credential is malformed: {cred}")));
    }
    let (secret, need_token) = secret_of(parts[0]);
    if need_token.is_some() && token != need_token {
        return Err(("InvalidClientTokenId", "The security token included in the request is invalid.".into()));
    }
    let signed: Vec<&str> = signed.split(';').collect();
    let get = |k: &str| hv(k).unwrap_or_default();
    let creq = canonical_request(method.as_str(), uri.path(), query, parts[3], &signed, &get, &payload);
    if signature(&secret, parts[1], parts[2], parts[3], &amz_date, &creq) != sig {
        return Err(("SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided.".into()));
    }
    if payload.starts_with("STREAMING-AWS4-HMAC-SHA256-PAYLOAD") {
        let scope = format!("{}/{}/{}/aws4_request", parts[1], parts[2], parts[3]);
        verify_chunks(body, &sig, &signing_key(&secret, parts[1], parts[2], parts[3]), &amz_date, &scope, payload.ends_with("-TRAILER"))
            .map_err(|m| ("SignatureDoesNotMatch", format!("aws-chunked body rejected: {m}")))?;
    } else if payload.len() == 64 && payload.bytes().all(|b| b.is_ascii_hexdigit()) && !payload.eq_ignore_ascii_case(&sha256_hex(body)) {
        return Err(("XAmzContentSHA256Mismatch", "The provided 'x-amz-content-sha256' header does not match what was computed.".into()));
    }
    Ok(())
}

// Headers that sign a request (host, x-amz-date, x-amz-content-sha256 and any x-amz-* given).
pub fn sign(method: &str, path_query: &str, host: &str, extra: &[(&str, &str)], body: &[u8], akid: &str, secret: &str, region: &str, service: &str) -> Vec<(String, String)> {
    let now = chrono::Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let payload = sha256_hex(body);
    let mut hs: Vec<(String, String)> = vec![("host".into(), host.into()), ("x-amz-date".into(), amz_date.clone()), ("x-amz-content-sha256".into(), payload.clone())];
    hs.extend(extra.iter().filter(|(k, _)| k.to_ascii_lowercase().starts_with("x-amz-")).map(|(k, v)| (k.to_ascii_lowercase(), v.to_string())));
    hs.sort();
    let (path, query) = path_query.split_once('?').unwrap_or((path_query, ""));
    let signed: Vec<&str> = hs.iter().map(|(k, _)| k.as_str()).collect();
    let get = |k: &str| hs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap_or_default();
    let creq = canonical_request(method, path, query, service, &signed, &get, &payload);
    let date = &amz_date[..8];
    let sig = signature(secret, date, region, service, &amz_date, &creq);
    let auth = format!("AWS4-HMAC-SHA256 Credential={akid}/{date}/{region}/{service}/aws4_request, SignedHeaders={}, Signature={sig}", signed.join(";"));
    let mut out: Vec<(String, String)> = hs.into_iter().filter(|(k, _)| k == "x-amz-date" || k == "x-amz-content-sha256").collect();
    out.push(("authorization".into(), auth));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_chunked_example_and_tamper() {
        let key = signing_key("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "20130524", "us-east-1", "s3");
        let (d, sc) = ("20130524T000000Z", "20130524/us-east-1/s3/aws4_request");
        let seed = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";
        let mut body = Vec::new();
        for (n, sig) in [(65536, "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648"),
                         (1024, "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497"),
                         (0, "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9")] {
            body.extend(format!("{n:x};chunk-signature={sig}\r\n").into_bytes());
            body.extend(vec![b'a'; n]);
            body.extend(b"\r\n");
        }
        assert!(verify_chunks(&body, seed, &key, d, sc, false).is_ok());
        let mut bad = body.clone();
        bad[200] = b'b';
        assert!(verify_chunks(&bad, seed, &key, d, sc, false).is_err());
        assert!(verify_chunks(&body[..body.len() - 120], seed, &key, d, sc, false).is_err(), "truncated body");
        // Signed trailer after the final chunk (format of the AWS SDK for Java's AwsS3V4ChunkSigner.signChecksumChunk).
        let last = "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9";
        let sts = format!("AWS4-HMAC-SHA256-TRAILER\n{d}\n{sc}\n{last}\n{}", sha256_hex(b"x-amz-checksum-crc32:sOO8/Q==\n"));
        let tsig = hex(&hmac(&key, sts.as_bytes()));
        let mut tb = body[..body.len() - 2].to_vec();
        tb.extend(format!("X-Amz-Checksum-Crc32: sOO8/Q==\r\nx-amz-trailer-signature:{tsig}\r\n\r\n").into_bytes());
        assert!(verify_chunks(&tb, seed, &key, d, sc, true).is_ok());
        let forged = String::from_utf8(tb.clone()).unwrap().replace("sOO8/Q==", "AAAAAA==");
        assert!(verify_chunks(forged.as_bytes(), seed, &key, d, sc, true).is_err(), "changed trailer value");
        assert!(verify_chunks(&body, seed, &key, d, sc, true).is_err(), "trailer signature missing");
    }

    // AWS SigV4 test suite "get-vanilla".
    #[test]
    fn aws_get_vanilla_vector() {
        let creq = "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let s = signature("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1", "service", "20150830T123600Z", creq);
        assert_eq!(s, "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
    }

    // Property: for random paths, queries and bodies, a signed request verifies, and flipping any one body byte breaks it.
    #[test]
    fn prop_random_requests_verify_and_tamper_fails() {
        use rand::{Rng, RngCore};
        let mut rng = rand::thread_rng();
        let chars = b"abcXYZ019-_.~ /%+=&?!:";
        for _ in 0..200 {
            let mut seg = |n: usize| (0..n).map(|_| chars[rng.gen_range(0..chars.len())] as char).collect::<String>();
            let path = format!("/{}", enc(&seg(12), true));
            let (k, v) = (enc(&seg(5), false), enc(&seg(7), false));
            let pq = format!("{path}?{k}={v}&b=2");
            let mut body = vec![0u8; rand::thread_rng().gen_range(1..300)];
            rand::thread_rng().fill_bytes(&mut body);
            let svc = if rand::thread_rng().gen_bool(0.5) { "s3" } else { "lambda" };
            let hs = sign("PUT", &pq, "127.0.0.1:4566", &[], &body, "AK", "sk", "us-east-1", svc);
            let mut h = HeaderMap::new();
            h.insert("host", "127.0.0.1:4566".parse().unwrap());
            for (k, v) in &hs {
                h.insert(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
            }
            let uri: Uri = pq.parse().unwrap();
            assert!(verify(&Method::PUT, &uri, &h, &body, |_| ("sk".into(), None)).is_ok(), "{pq}");
            // The signed payload hash header must match the body; a changed body changes it.
            let i = rand::thread_rng().gen_range(0..body.len());
            body[i] ^= 1;
            h.insert("x-amz-content-sha256", sha256_hex(&body).parse().unwrap());
            assert!(verify(&Method::PUT, &uri, &h, &body, |_| ("sk".into(), None)).is_err());
        }
    }

    #[test]
    fn sign_then_verify_roundtrip_and_tamper() {
        let body = br#"{"TableName":"t"}"#;
        let hs = sign("POST", "/", "127.0.0.1:4566", &[("x-amz-target", "DynamoDB_20120810.DescribeTable")], body, "AKID", "sec", "us-east-1", "dynamodb");
        let mut h = HeaderMap::new();
        h.insert("host", "127.0.0.1:4566".parse().unwrap());
        h.insert("x-amz-target", "DynamoDB_20120810.DescribeTable".parse().unwrap());
        for (k, v) in &hs {
            h.insert(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
        }
        let uri: Uri = "/".parse().unwrap();
        assert!(verify(&Method::POST, &uri, &h, body, |_| ("sec".into(), None)).is_ok());
        assert_eq!(verify(&Method::POST, &uri, &h, body, |_| ("other".into(), None)).err().unwrap().0, "SignatureDoesNotMatch");
        h.insert("x-amz-target", "DynamoDB_20120810.DeleteTable".parse().unwrap());
        assert_eq!(verify(&Method::POST, &uri, &h, body, |_| ("sec".into(), None)).err().unwrap().0, "SignatureDoesNotMatch");
    }

    #[test]
    fn clock_skew_rejects_stale_header_dates() {
        let (host, body) = ("127.0.0.1:4566", b"");
        let payload = sha256_hex(body);
        let signed_at = |mins: i64| {
            let d = (chrono::Utc::now() + chrono::Duration::minutes(mins)).format("%Y%m%dT%H%M%SZ").to_string();
            let hs = [("host", host), ("x-amz-date", d.as_str()), ("x-amz-content-sha256", payload.as_str())];
            let names = ["host", "x-amz-date", "x-amz-content-sha256"];
            let get = |k: &str| hs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string()).unwrap_or_default();
            let creq = canonical_request("GET", "/", "", "s3", &names, &get, &payload);
            let sig = signature("sec", &d[..8], "us-east-1", "s3", &d, &creq);
            let mut h = HeaderMap::new();
            h.insert("host", host.parse().unwrap());
            for (k, v) in hs {
                h.insert(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
            }
            h.insert("authorization", format!("AWS4-HMAC-SHA256 Credential=AKID/{}/us-east-1/s3/aws4_request, SignedHeaders={}, Signature={sig}", &d[..8], names.join(";")).parse().unwrap());
            h
        };
        let uri: Uri = "/".parse().unwrap();
        assert_eq!(verify(&Method::GET, &uri, &signed_at(-20), body, |_| ("sec".into(), None)).err().unwrap().0, "RequestTimeTooSkewed");
        assert_eq!(verify(&Method::GET, &uri, &signed_at(20), body, |_| ("sec".into(), None)).err().unwrap().0, "RequestTimeTooSkewed");
        assert!(verify(&Method::GET, &uri, &signed_at(5), body, |_| ("sec".into(), None)).is_ok(), "within the 15-minute window");
    }
}

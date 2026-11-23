// IAM + STS (Query protocol) and the policy evaluator that gates every request.
use crate::{err, ApiErr, ACCOUNT, REGION};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Debug, PartialEq)]
pub enum Principal {
    Root,
    User(String),
    Role { role: String, session: String },
}

impl Principal {
    pub fn arn(&self) -> String {
        match self {
            Principal::Root => format!("arn:aws:iam::{ACCOUNT}:root"),
            Principal::User(u) => user_arn(u),
            Principal::Role { role, session } => format!("arn:aws:sts::{ACCOUNT}:assumed-role/{role}/{session}"),
        }
    }
}

fn user_arn(n: &str) -> String {
    format!("arn:aws:iam::{ACCOUNT}:user/{n}")
}
pub fn role_arn(n: &str) -> String {
    format!("arn:aws:iam::{ACCOUNT}:role/{n}")
}
fn policy_arn(n: &str) -> String {
    format!("arn:aws:iam::{ACCOUNT}:policy/{n}")
}
fn now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
fn gen_id(prefix: &str) -> String {
    format!("{prefix}{}", &uuid::Uuid::new_v4().simple().to_string().to_uppercase()[..16])
}

struct Entity {
    id: String,
    created: String,
    attached: Vec<String>,
    inline: BTreeMap<String, Value>,
    trust: Value, // roles only
}
struct Policy {
    name: String,
    id: String,
    created: String,
    doc: Value,
}
struct Key {
    secret: String,
    owner: Principal,
    created: String,
    token: Option<String>,
}

#[derive(Default)]
pub struct Iam {
    users: BTreeMap<String, Entity>,
    roles: BTreeMap<String, Entity>,
    policies: BTreeMap<String, Policy>, // by ARN
    keys: HashMap<String, Key>,
}

pub struct Decision {
    pub allowed: bool,
    pub kind: &'static str, // allowed | explicitDeny | implicitDeny
    pub reason: String,
    pub matched: Vec<String>,
}

// ---------- policy evaluation ----------

pub fn strs(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => a.iter().flat_map(strs).collect(),
        Value::String(s) => vec![s.clone()],
        Value::Null => vec![],
        other => vec![other.to_string()],
    }
}

fn statements(doc: &Value) -> Vec<&Value> {
    match &doc["Statement"] {
        Value::Array(a) => a.iter().collect(),
        Value::Object(_) => vec![&doc["Statement"]],
        _ => vec![],
    }
}

pub fn glob(p: &str, s: &str, ci: bool) -> bool {
    let (p, s) = if ci { (p.to_lowercase(), s.to_lowercase()) } else { (p.to_string(), s.to_string()) };
    let (p, s): (Vec<char>, Vec<char>) = (p.chars().collect(), s.chars().collect());
    let (mut pi, mut si, mut star, mut mark) = (0, 0, None, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

// Numeric*, Date* and IpAddress operators are handled here alongside String*/Arn*/Bool and
// the ForAnyValue/ForAllValues qualifiers. ponytail: request context keys are single-valued, so the
// qualifiers only change the missing-key rule (ForAllValues passes on a missing key); multivalued
// semantics need a list-valued context. Date accepts epoch seconds or ISO 8601 (RFC 3339, YYYY-MM-DD,
// UTC assumed when no offset); IpAddress parses IPv4/IPv6 CIDRs (no zone index).
fn cond_ok(c: &Value, ctx: &HashMap<String, String>) -> bool {
    let Some(m) = c.as_object() else { return true };
    m.iter().all(|(op, kv)| {
        kv.as_object().is_some_and(|kv| {
            kv.iter().all(|(k, want)| {
                let mut all = None; // Some(false) = ForAnyValue, Some(true) = ForAllValues
                let mut rest = op.as_str();
                if let Some(b) = rest.strip_prefix("ForAnyValue:") {
                    rest = b;
                    all = Some(false);
                } else if let Some(b) = rest.strip_prefix("ForAllValues:") {
                    rest = b;
                    all = Some(true);
                }
                let (base, if_exists) = rest.strip_suffix("IfExists").map_or((rest, false), |b| (b, true));
                let wants = strs(want);
                let Some(h) = ctx.iter().find(|(ck, _)| ck.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str()) else {
                    // Missing key: IfExists passes, ForAllValues passes (empty set), negated single-valued operators pass.
                    return if_exists || all == Some(true) || base.contains("Not");
                };
                let num = |f: fn(std::cmp::Ordering) -> bool| {
                    cmp_op(h, &wants, |s| s.trim().parse::<f64>().ok(), f)
                };
                let date = |f: fn(std::cmp::Ordering) -> bool| cmp_op(h, &wants, date_secs, f);
                match base {
                    "StringEquals" | "ArnEquals" => wants.iter().any(|w| w == h),
                    "StringNotEquals" | "ArnNotEquals" => !wants.iter().any(|w| w == h),
                    "StringEqualsIgnoreCase" => wants.iter().any(|w| w.eq_ignore_ascii_case(h)),
                    "StringNotEqualsIgnoreCase" => !wants.iter().any(|w| w.eq_ignore_ascii_case(h)),
                    "StringLike" | "ArnLike" => wants.iter().any(|w| glob(w, h, false)),
                    "StringNotLike" | "ArnNotLike" => !wants.iter().any(|w| glob(w, h, false)),
                    "Bool" => wants.iter().any(|w| w.eq_ignore_ascii_case(h)),
                    "NumericEquals" => num(|o| o == std::cmp::Ordering::Equal),
                    "NumericNotEquals" => num(|o| o != std::cmp::Ordering::Equal),
                    "NumericLessThan" => num(|o| o == std::cmp::Ordering::Less),
                    "NumericLessThanEquals" => num(|o| o != std::cmp::Ordering::Greater),
                    "NumericGreaterThan" => num(|o| o == std::cmp::Ordering::Greater),
                    "NumericGreaterThanEquals" => num(|o| o != std::cmp::Ordering::Less),
                    "DateEquals" => date(|o| o == std::cmp::Ordering::Equal),
                    "DateNotEquals" => date(|o| o != std::cmp::Ordering::Equal),
                    "DateLessThan" => date(|o| o == std::cmp::Ordering::Less),
                    "DateLessThanEquals" => date(|o| o != std::cmp::Ordering::Greater),
                    "DateGreaterThan" => date(|o| o == std::cmp::Ordering::Greater),
                    "DateGreaterThanEquals" => date(|o| o != std::cmp::Ordering::Less),
                    "IpAddress" => wants.iter().any(|w| ip_in(w, h)),
                    "NotIpAddress" => !wants.iter().any(|w| ip_in(w, h)),
                    _ => false,
                }
            })
        })
    })
}

fn cmp_op<T: PartialOrd>(h: &str, wants: &[String], parse: impl Fn(&str) -> Option<T>, f: fn(std::cmp::Ordering) -> bool) -> bool {
    let Some(hv) = parse(h) else { return false };
    wants.iter().any(|w| parse(w).is_some_and(|wv| hv.partial_cmp(&wv).is_some_and(f)))
}

// Epoch seconds, RFC 3339 ("2026-11-23T10:00:00Z", "+09:00" offset) or a date-only "2026-11-23" (UTC).
fn date_secs(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Ok(n) = s.parse::<i64>() {
        return Some(n);
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(dt.timestamp());
    }
    chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok().and_then(|d| d.and_hms_opt(0, 0, 0)).map(|t| t.and_utc().timestamp())
}

// IPv4 or IPv6; IPv4-mapped IPv6 literals (::ffff:a.b.c.d) count as IPv4, as AWS does. No zone index (%eth0).
enum Ip {
    V4([u8; 4]),
    V6([u8; 16]),
}

fn parse_ip(s: &str) -> Option<Ip> {
    let s = s.trim();
    if !s.contains(':') {
        let q: Vec<u8> = s.split('.').map(|x| x.parse::<u8>().ok()).collect::<Option<Vec<_>>>()?;
        return (q.len() == 4).then(|| Ip::V4(q.try_into().unwrap()));
    }
    let (head, tail) = s.split_once("::").map_or((s, None), |(h, t)| (h, Some(t)));
    let push = |g: &str, v: &mut Vec<u16>| -> Option<()> {
        if g.contains('.') {
            let q: Vec<u8> = g.split('.').map(|x| x.parse::<u8>().ok()).collect::<Option<Vec<_>>>()?;
            if q.len() != 4 {
                return None;
            }
            v.push(((q[0] as u16) << 8) | q[1] as u16);
            v.push(((q[2] as u16) << 8) | q[3] as u16);
        } else {
            v.push(u16::from_str_radix(g, 16).ok()?);
        }
        Some(())
    };
    let mut groups = vec![];
    for g in head.split(':').filter(|g| !g.is_empty()) {
        push(g, &mut groups)?;
    }
    if let Some(t) = tail {
        let mut right = vec![];
        for g in t.split(':').filter(|g| !g.is_empty()) {
            push(g, &mut right)?;
        }
        if groups.len() + right.len() > 7 {
            return None; // "::" must stand for at least one zero group
        }
        let zeros = vec![0u16; 8 - groups.len() - right.len()]; // fill between head and tail
        groups.extend(zeros);
        groups.extend(right);
    } else if groups.len() != 8 {
        return None;
    }
    let mut b = [0u8; 16];
    for (i, g) in groups.iter().enumerate() {
        b[i * 2] = (g >> 8) as u8;
        b[i * 2 + 1] = (g & 0xff) as u8;
    }
    if b[..10].iter().all(|&x| x == 0) && b[10] == 0xff && b[11] == 0xff {
        Some(Ip::V4([b[12], b[13], b[14], b[15]]))
    } else {
        Some(Ip::V6(b))
    }
}

// Prefix length is relative to the written family (32 for IPv4, 128 for IPv6); families must match.
fn ip_in(want: &str, ip: &str) -> bool {
    let (net_s, bits_s) = match want.split_once('/') {
        Some((n, b)) => (n, Some(b)),
        None => (want, None),
    };
    let (Some(net), Some(ipb)) = (parse_ip(net_s), parse_ip(ip)) else { return false };
    let (n, i, max) = match (&net, &ipb) {
        (Ip::V4(n), Ip::V4(i)) => (&n[..], &i[..], 32u32),
        (Ip::V6(n), Ip::V6(i)) => (&n[..], &i[..], 128u32),
        _ => return false,
    };
    let bits = if let Some(b) = bits_s {
        let Ok(b) = b.trim().parse::<u32>() else { return false };
        b
    } else {
        max // bare address = full-length prefix
    };
    if bits > max || n[..(bits / 8) as usize] != i[..(bits / 8) as usize] {
        return false;
    }
    bits % 8 == 0 || (n[(bits / 8) as usize] & (0xffu8 << (8 - bits % 8))) == (i[(bits / 8) as usize] & (0xffu8 << (8 - bits % 8)))
}

fn stmt_matches(st: &Value, action: &str, resource: &str, ctx: &HashMap<String, String>) -> bool {
    let any = |k: &str, s: &str, ci: bool| strs(&st[k]).iter().any(|p| glob(p, s, ci));
    let act = if st.get("NotAction").is_some() { !any("NotAction", action, true) } else { any("Action", action, true) };
    let res = if st.get("NotResource").is_some() {
        !any("NotResource", resource, false)
    } else {
        st.get("Resource").is_none() || any("Resource", resource, false)
    };
    act && res && cond_ok(&st["Condition"], ctx)
}

fn req_ctx(p: &Principal, ip: &str) -> HashMap<String, String> {
    let now = chrono::Utc::now();
    let mut ctx = HashMap::from([
        ("aws:PrincipalArn".to_string(), match p { Principal::Role { role, .. } => role_arn(role), _ => p.arn() }),
        ("aws:PrincipalAccount".to_string(), ACCOUNT.to_string()),
        ("aws:RequestedRegion".to_string(), REGION.clone()),
        ("aws:SecureTransport".to_string(), "false".to_string()),
        ("aws:SourceIp".to_string(), ip.to_string()),
        ("aws:EpochTime".to_string(), now.timestamp().to_string()),
        ("aws:CurrentTime".to_string(), now.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
    ]);
    if let Principal::User(u) = p {
        ctx.insert("aws:username".into(), u.clone());
    }
    ctx
}

// Shape check for resource-based policies (bucket policies): every statement needs Effect, Principal and Action.
pub fn validate_resource_policy(doc: &Value) -> Result<(), String> {
    let sts = statements(doc);
    if sts.is_empty() {
        return Err("Policy has no statements".into());
    }
    for st in sts {
        if !matches!(st["Effect"].as_str(), Some("Allow" | "Deny")) {
            return Err("Policy statement Effect must be Allow or Deny".into());
        }
        if st.get("Principal").is_none() && st.get("NotPrincipal").is_none() {
            return Err("Policy statement must contain a Principal".into());
        }
        if st.get("Action").is_none() && st.get("NotAction").is_none() {
            return Err("Policy statement must contain actions".into());
        }
    }
    Ok(())
}

fn principal_match(p: &Value, c: &Principal) -> bool {
    if p == "*" {
        return true;
    }
    let carn = c.arn();
    strs(&p["AWS"]).iter().any(|a| {
        a == "*" || a == ACCOUNT || *a == Principal::Root.arn() || glob(a, &carn, false)
            || matches!(c, Principal::Role { role, .. } if *a == role_arn(role))
    })
}

// For Allow statements in resource policies: naming the account (or its root ARN) delegates to the account's own
// identity policies, as in AWS, so it only grants the root itself, never every user in the account.
fn principal_grants(p: &Value, c: &Principal) -> bool {
    if p == "*" {
        return true;
    }
    let carn = c.arn();
    strs(&p["AWS"]).iter().any(|a| {
        let account_wide = a == ACCOUNT || *a == Principal::Root.arn();
        a == "*" || (account_wide && matches!(c, Principal::Root)) || (!account_wide && glob(a, &carn, false))
            || matches!(c, Principal::Role { role, .. } if *a == role_arn(role))
    })
}

// Service-to-service delivery (SNS → SQS, EventBridge → Lambda, S3 → SNS ...) against the target's resource policy,
// as the service principal (e.g. sns.amazonaws.com) with aws:SourceArn / aws:SourceAccount. Deny wins, an Allow is needed.
// With strict=true (STRICT_DELIVERY=1) a target with no policy is refused, as AWS does; the default stays lenient.
pub fn service_may(doc: Option<&Value>, service: &str, action: &str, resource: &str, source: &str, strict: bool) -> Result<(), String> {
    let Some(doc) = doc else {
        return if strict {
            Err(format!("{service} is not authorized to perform: {action} on resource: {resource} because the resource-based policy does not exist"))
        } else {
            Ok(())
        };
    };
    let ctx = HashMap::from([("aws:SourceArn".to_string(), source.to_string()), ("aws:SourceAccount".to_string(), ACCOUNT.to_string())]);
    let mut allowed = false;
    for st in statements(doc) {
        let p = &st["Principal"];
        let who = p == "*" || p["AWS"] == "*" || strs(&p["Service"]).iter().any(|s| s == service);
        if !who || !stmt_matches(st, action, resource, &ctx) {
            continue;
        }
        if st["Effect"] == "Deny" {
            return Err(format!("{service} is not authorized to perform: {action} on resource: {resource} with an explicit deny in a resource-based policy"));
        }
        allowed = true;
    }
    if allowed { Ok(()) } else { Err(format!("{service} is not authorized to perform: {action} on resource: {resource} because the resource-based policy does not allow {service}")) }
}

impl Iam {
    // Secret and session token for SigV4 verification; unregistered keys are root and sign with RC_ROOT_SECRET.
    pub fn secret_of(&self, akid: &str) -> (String, Option<String>) {
        self.keys.get(akid).map_or_else(|| (std::env::var("RC_ROOT_SECRET").unwrap_or_else(|_| "test".into()), None), |k| (k.secret.clone(), k.token.clone()))
    }

    pub fn principal(&self, akid: &str) -> Principal {
        self.keys.get(akid).map_or(Principal::Root, |k| k.owner.clone())
    }

    fn entity(&self, p: &Principal) -> Option<(&str, &Entity)> {
        match p {
            Principal::User(u) => self.users.get(u).map(|e| ("user", e)),
            Principal::Role { role, .. } => self.roles.get(role).map(|e| ("role", e)),
            Principal::Root => None,
        }
    }

    // (label, document) for every identity policy that applies to the principal.
    fn docs<'a>(&'a self, e: &'a Entity) -> Vec<(String, &'a Value)> {
        let managed = e.attached.iter().filter_map(|a| self.policies.get(a)).map(|p| (p.name.clone(), &p.doc));
        managed.chain(e.inline.iter().map(|(n, d)| (n.clone(), d))).collect()
    }

    pub fn authorize(&self, p: &Principal, action: &str, resource: &str) -> Decision {
        self.authorize_ip(p, action, resource, "127.0.0.1")
    }

    pub fn authorize_ip(&self, p: &Principal, action: &str, resource: &str, ip: &str) -> Decision {
        let Some((_, e)) = self.entity(p) else {
            return Decision { allowed: true, kind: "allowed", reason: "account root (unregistered access key) is always allowed".into(), matched: vec![] };
        };
        let ctx = req_ctx(p, ip);
        let mut allow = None;
        for (label, doc) in self.docs(e) {
            for (i, st) in statements(doc).into_iter().enumerate() {
                if !stmt_matches(st, action, resource, &ctx) {
                    continue;
                }
                let sid = st["Sid"].as_str().map_or(format!("#{i}"), String::from);
                if st["Effect"] == "Deny" {
                    return Decision {
                        allowed: false,
                        kind: "explicitDeny",
                        reason: format!("User: {} is not authorized to perform: {action} on resource: {resource} with an explicit deny in an identity-based policy ({label}, statement {sid})", p.arn()),
                        matched: vec![label],
                    };
                }
                allow.get_or_insert((label.clone(), sid));
            }
        }
        match allow {
            Some((label, sid)) => Decision { allowed: true, kind: "allowed", reason: format!("allowed by {label}, statement {sid}"), matched: vec![label] },
            None => Decision {
                allowed: false,
                kind: "implicitDeny",
                reason: format!("User: {} is not authorized to perform: {action} on resource: {resource} because no identity-based policy allows the {action} action", p.arn()),
                matched: vec![],
            },
        }
    }

    // Same-account evaluation with a resource-based policy (bucket policy): an explicit Deny in either policy wins,
    // otherwise an Allow in either grants. The account root can always manage the bucket policy itself, as in AWS,
    // so a Deny-everyone policy can't lock the bucket for good.
    // The root can likewise always rewrite a queue or topic policy.
    // Covers S3 bucket, SQS queue, SNS topic and Lambda function (AddPermission) policies.
    pub fn authorize_with(&self, p: &Principal, action: &str, resource: &str, rp: Option<(&str, &Value)>) -> Decision {
        self.authorize_with_ip(p, action, resource, rp, "127.0.0.1")
    }

    pub fn authorize_with_ip(&self, p: &Principal, action: &str, resource: &str, rp: Option<(&str, &Value)>, ip: &str) -> Decision {
        let id = self.authorize_ip(p, action, resource, ip);
        let Some((kind, doc)) = rp else { return id };
        if id.kind == "explicitDeny" || (matches!(p, Principal::Root) && (action.ends_with("BucketPolicy") || action == "sqs:SetQueueAttributes" || action == "sns:SetTopicAttributes" || action == "lambda:RemovePermission" || action == "lambda:AddPermission")) {
            return id;
        }
        let ctx = req_ctx(p, ip);
        let mut allow = None;
        for (i, st) in statements(doc).into_iter().enumerate() {
            let deny = st["Effect"] == "Deny";
            let who = match st.get("NotPrincipal") {
                Some(np) => !principal_match(np, p),
                None if deny => principal_match(&st["Principal"], p),
                None => principal_grants(&st["Principal"], p),
            };
            if !who || !stmt_matches(st, action, resource, &ctx) {
                continue;
            }
            let sid = st["Sid"].as_str().map_or(format!("#{i}"), String::from);
            if deny {
                return Decision {
                    allowed: false,
                    kind: "explicitDeny",
                    reason: format!("User: {} is not authorized to perform: {action} on resource: {resource} with an explicit deny in a resource-based policy ({kind}, statement {sid})", p.arn()),
                    matched: vec![kind.into()],
                };
            }
            allow.get_or_insert(sid);
        }
        match (id.allowed, allow) {
            (true, _) => id,
            (false, Some(sid)) => Decision { allowed: true, kind: "allowed", reason: format!("allowed by resource-based policy ({kind}, statement {sid})"), matched: vec![kind.into()] },
            (false, None) => Decision {
                reason: format!("User: {} is not authorized to perform: {action} on resource: {resource} because no identity-based policy or {kind} allows the {action} action", p.arn()),
                ..id
            },
        }
    }

    // ---------- API ----------

    fn user_json(&self, n: &str, e: &Entity) -> Value {
        json!({"Path": "/", "UserName": n, "UserId": e.id, "Arn": user_arn(n), "CreateDate": e.created})
    }
    fn role_json(&self, n: &str, e: &Entity) -> Value {
        json!({"Path": "/", "RoleName": n, "RoleId": e.id, "Arn": role_arn(n), "CreateDate": e.created,
               "AssumeRolePolicyDocument": pct_encode(&e.trust.to_string()), "MaxSessionDuration": 3600})
    }
    fn policy_json(&self, arn: &str, p: &Policy) -> Value {
        let n = self.users.values().chain(self.roles.values()).filter(|e| e.attached.iter().any(|a| a == arn)).count();
        json!({"PolicyName": p.name, "PolicyId": p.id, "Arn": arn, "Path": "/", "DefaultVersionId": "v1",
               "AttachmentCount": n, "IsAttachable": true, "CreateDate": p.created, "UpdateDate": p.created})
    }

    pub fn handle(&mut self, caller: &Principal, q: &HashMap<String, String>) -> Result<Value, ApiErr> {
        let action = q.get("Action").map_or("", String::as_str);
        let p = |k: &str| q.get(k).map(String::as_str).ok_or_else(|| err("ValidationError", format!("{k} is required")));
        let missing = |what: &str, n: &str| ApiErr { status: 404, ..err("NoSuchEntity", format!("The {what} with name {n} cannot be found.")) };
        let exists = |what: &str, n: &str| ApiErr { status: 409, ..err("EntityAlreadyExists", format!("{what} with name {n} already exists.")) };
        let doc = |k: &str| -> Result<Value, ApiErr> {
            let v: Value = serde_json::from_str(p(k)?).map_err(|e| err("MalformedPolicyDocument", format!("Syntax errors in policy: {e}")))?;
            if statements(&v).is_empty() {
                return Err(err("MalformedPolicyDocument", "Policy document must contain a Statement"));
            }
            Ok(v)
        };
        let new_entity = |prefix: &str, trust: Value| Entity { id: gen_id(prefix), created: now(), attached: vec![], inline: BTreeMap::new(), trust };
        // Users and roles share attach/inline handling; `kind` picks the map.
        let is_user = action.contains("User") || action == "CreateAccessKey" || action == "ListAccessKeys" || action == "DeleteAccessKey";
        let (kind, name_key) = if is_user { ("user", "UserName") } else { ("role", "RoleName") };

        Ok(match action {
            "CreateUser" => {
                let n = p("UserName")?;
                if self.users.contains_key(n) {
                    return Err(exists("User", n));
                }
                let e = new_entity("AIDA", Value::Null);
                let out = json!({"User": self.user_json(n, &e)});
                self.users.insert(n.into(), e);
                out
            }
            "GetUser" => {
                let n = match q.get("UserName") {
                    Some(n) => n.clone(),
                    None => match caller {
                        Principal::User(u) => u.clone(),
                        _ => return Err(err("ValidationError", "UserName is required for non-user callers")),
                    },
                };
                let e = self.users.get(&n).ok_or_else(|| missing("user", &n))?;
                json!({"User": self.user_json(&n, e)})
            }
            "ListUsers" => json!({"Users": self.users.iter().map(|(n, e)| self.user_json(n, e)).collect::<Vec<_>>(), "IsTruncated": false}),
            "CreateRole" => {
                let n = p("RoleName")?;
                if self.roles.contains_key(n) {
                    return Err(exists("Role", n));
                }
                let e = new_entity("AROA", doc("AssumeRolePolicyDocument")?);
                let out = json!({"Role": self.role_json(n, &e)});
                self.roles.insert(n.into(), e);
                out
            }
            "GetRole" => {
                let n = p("RoleName")?;
                json!({"Role": self.role_json(n, self.roles.get(n).ok_or_else(|| missing("role", n))?)})
            }
            "ListRoles" => json!({"Roles": self.roles.iter().map(|(n, e)| self.role_json(n, e)).collect::<Vec<_>>(), "IsTruncated": false}),
            "DeleteUser" | "DeleteRole" => {
                let n = p(name_key)?;
                let map = if is_user { &self.users } else { &self.roles };
                let e = map.get(n).ok_or_else(|| missing(kind, n))?;
                let has_keys = self.keys.values().any(|k| k.owner == Principal::User(n.into()) && k.token.is_none());
                if !e.attached.is_empty() || !e.inline.is_empty() || (is_user && has_keys) {
                    return Err(ApiErr { status: 409, ..err("DeleteConflict", format!("Cannot delete entity, must detach all policies and delete access keys first ({n}).")) });
                }
                if is_user { self.users.remove(n) } else { self.roles.remove(n) };
                json!({})
            }
            "CreatePolicy" => {
                let n = p("PolicyName")?;
                let arn = policy_arn(n);
                if self.policies.contains_key(&arn) {
                    return Err(exists("A policy", n));
                }
                let pol = Policy { name: n.into(), id: gen_id("ANPA"), created: now(), doc: doc("PolicyDocument")? };
                let out = json!({"Policy": self.policy_json(&arn, &pol)});
                self.policies.insert(arn, pol);
                out
            }
            "GetPolicy" => {
                let a = p("PolicyArn")?;
                json!({"Policy": self.policy_json(a, self.policies.get(a).ok_or_else(|| missing("policy", a))?)})
            }
            "ListPolicies" => json!({"Policies": self.policies.iter().map(|(a, p)| self.policy_json(a, p)).collect::<Vec<_>>(), "IsTruncated": false}),
            "GetPolicyVersion" => {
                let a = p("PolicyArn")?;
                let pol = self.policies.get(a).ok_or_else(|| missing("policy", a))?;
                json!({"PolicyVersion": {"Document": pct_encode(&pol.doc.to_string()), "VersionId": "v1", "IsDefaultVersion": true, "CreateDate": pol.created}})
            }
            "DeletePolicy" => {
                let a = p("PolicyArn")?;
                if self.users.values().chain(self.roles.values()).any(|e| e.attached.iter().any(|x| x == a)) {
                    return Err(ApiErr { status: 409, ..err("DeleteConflict", "Cannot delete a policy attached to entities.") });
                }
                self.policies.remove(a).ok_or_else(|| missing("policy", a))?;
                json!({})
            }
            "AttachUserPolicy" | "AttachRolePolicy" | "DetachUserPolicy" | "DetachRolePolicy" => {
                let (n, a) = (p(name_key)?, p("PolicyArn")?);
                if !self.policies.contains_key(a) {
                    return Err(missing("policy", a));
                }
                let e = if is_user { self.users.get_mut(n) } else { self.roles.get_mut(n) }.ok_or_else(|| missing(kind, n))?;
                if action.starts_with("Attach") {
                    if !e.attached.iter().any(|x| x == a) {
                        e.attached.push(a.into());
                    }
                } else {
                    let before = e.attached.len();
                    e.attached.retain(|x| x != a);
                    if before == e.attached.len() {
                        return Err(missing("policy attachment", a));
                    }
                }
                json!({})
            }
            "ListAttachedUserPolicies" | "ListAttachedRolePolicies" => {
                let n = p(name_key)?;
                let e = if is_user { self.users.get(n) } else { self.roles.get(n) }.ok_or_else(|| missing(kind, n))?;
                let list: Vec<Value> = e.attached.iter().map(|a| json!({"PolicyArn": a, "PolicyName": a.rsplit('/').next()})).collect();
                json!({"AttachedPolicies": list, "IsTruncated": false})
            }
            "PutUserPolicy" | "PutRolePolicy" => {
                let (n, pn, d) = (p(name_key)?, p("PolicyName")?, doc("PolicyDocument")?);
                let e = if is_user { self.users.get_mut(n) } else { self.roles.get_mut(n) }.ok_or_else(|| missing(kind, n))?;
                e.inline.insert(pn.into(), d);
                json!({})
            }
            "GetUserPolicy" | "GetRolePolicy" => {
                let (n, pn) = (p(name_key)?, p("PolicyName")?);
                let e = if is_user { self.users.get(n) } else { self.roles.get(n) }.ok_or_else(|| missing(kind, n))?;
                let d = e.inline.get(pn).ok_or_else(|| missing("policy", pn))?;
                json!({name_key: n, "PolicyName": pn, "PolicyDocument": pct_encode(&d.to_string())})
            }
            "DeleteUserPolicy" | "DeleteRolePolicy" => {
                let (n, pn) = (p(name_key)?, p("PolicyName")?);
                let e = if is_user { self.users.get_mut(n) } else { self.roles.get_mut(n) }.ok_or_else(|| missing(kind, n))?;
                e.inline.remove(pn).ok_or_else(|| missing("policy", pn))?;
                json!({})
            }
            "ListUserPolicies" | "ListRolePolicies" => {
                let n = p(name_key)?;
                let e = if is_user { self.users.get(n) } else { self.roles.get(n) }.ok_or_else(|| missing(kind, n))?;
                json!({"PolicyNames": e.inline.keys().collect::<Vec<_>>(), "IsTruncated": false})
            }
            "CreateAccessKey" => {
                let n = match (q.get("UserName"), caller) {
                    (Some(n), _) => n.clone(),
                    (None, Principal::User(u)) => u.clone(),
                    _ => return Err(err("ValidationError", "UserName is required")),
                };
                self.users.get(&n).ok_or_else(|| missing("user", &n))?;
                let (id, secret) = (gen_id("AKIA"), uuid::Uuid::new_v4().simple().to_string());
                let created = now();
                self.keys.insert(id.clone(), Key { secret: secret.clone(), owner: Principal::User(n.clone()), created: created.clone(), token: None });
                json!({"AccessKey": {"UserName": n, "AccessKeyId": id, "SecretAccessKey": secret, "Status": "Active", "CreateDate": created}})
            }
            "ListAccessKeys" => {
                let n = p("UserName")?;
                let list: Vec<Value> = self.keys.iter()
                    .filter(|(_, k)| k.owner == Principal::User(n.into()) && k.token.is_none())
                    .map(|(id, k)| json!({"UserName": n, "AccessKeyId": id, "Status": "Active", "CreateDate": k.created}))
                    .collect();
                json!({"AccessKeyMetadata": list, "IsTruncated": false})
            }
            "DeleteAccessKey" => {
                let id = p("AccessKeyId")?;
                self.keys.remove(id).ok_or_else(|| missing("access key", id))?;
                json!({})
            }
            "SimulatePrincipalPolicy" => {
                let src = p("PolicySourceArn")?;
                let who = if let Some(u) = src.strip_prefix(&format!("arn:aws:iam::{ACCOUNT}:user/")) {
                    Principal::User(u.into())
                } else if let Some(r) = src.strip_prefix(&format!("arn:aws:iam::{ACCOUNT}:role/")) {
                    Principal::Role { role: r.into(), session: "simulation".into() }
                } else {
                    return Err(err("InvalidInput", format!("Unsupported PolicySourceArn {src}")));
                };
                if self.entity(&who).is_none() {
                    return Err(missing("entity", src));
                }
                let mut resources = members(q, "ResourceArns");
                if resources.is_empty() {
                    resources.push("*".into());
                }
                let mut out = vec![];
                for a in members(q, "ActionNames") {
                    for r in &resources {
                        let d = self.authorize(&who, &a, r);
                        out.push(json!({"EvalActionName": a, "EvalResourceName": r, "EvalDecision": d.kind,
                            "MatchedStatements": d.matched.iter().map(|m| json!({"SourcePolicyId": m, "SourcePolicyType": "IAM Policy"})).collect::<Vec<_>>(),
                            "MissingContextValues": []}));
                    }
                }
                json!({"EvaluationResults": out, "IsTruncated": false})
            }
            // ----- STS -----
            "GetCallerIdentity" => {
                let id = match caller {
                    Principal::User(u) => self.users.get(u).map_or(String::new(), |e| e.id.clone()),
                    Principal::Role { role, session } => format!("{}:{session}", self.roles.get(role).map_or("", |e| e.id.as_str())),
                    Principal::Root => ACCOUNT.into(),
                };
                json!({"Arn": caller.arn(), "UserId": id, "Account": ACCOUNT})
            }
            "AssumeRole" => {
                let (ra, session) = (p("RoleArn")?, p("RoleSessionName")?);
                let rn = ra.rsplit('/').next().unwrap_or("");
                let role = self.roles.get(rn).filter(|_| ra == role_arn(rn)).ok_or_else(|| missing("role", ra))?;
                let trusted = statements(&role.trust).into_iter().any(|st| {
                    st["Effect"] == "Allow" && strs(&st["Action"]).iter().any(|a| glob(a, "sts:AssumeRole", true)) && principal_match(&st["Principal"], caller)
                });
                if !trusted {
                    return Err(ApiErr { status: 403, ..err("AccessDenied", format!("User: {} is not authorized to perform: sts:AssumeRole on resource: {ra} because the role's trust policy does not allow it", caller.arn())) });
                }
                let secs: i64 = q.get("DurationSeconds").and_then(|d| d.parse().ok()).unwrap_or(3600);
                let exp = (chrono::Utc::now() + chrono::Duration::seconds(secs)).format("%Y-%m-%dT%H:%M:%SZ").to_string();
                let (id, secret, token) = (gen_id("ASIA"), uuid::Uuid::new_v4().simple().to_string(), uuid::Uuid::new_v4().simple().to_string());
                let owner = Principal::Role { role: rn.into(), session: session.into() };
                let out = json!({
                    "Credentials": {"AccessKeyId": id, "SecretAccessKey": secret, "SessionToken": token, "Expiration": exp},
                    "AssumedRoleUser": {"AssumedRoleId": format!("{}:{session}", role.id), "Arn": owner.arn()},
                });
                // ponytail: session keys never expire inside the emulator.
                self.keys.insert(id, Key { secret, owner, created: now(), token: Some(token) });
                out
            }
            _ => return Err(err("InvalidAction", format!("{action} is not supported yet"))),
        })
    }

    // Session credentials for a service acting as a role (e.g. a Lambda execution role). None if the role is unknown.
    pub fn session_for_role(&mut self, role_arn: &str, session: &str) -> Option<(String, String, String)> {
        let rn = role_arn.rsplit('/').next()?;
        if role_arn != self::role_arn(rn) || !self.roles.contains_key(rn) {
            return None;
        }
        let (id, secret, token) = (gen_id("ASIA"), uuid::Uuid::new_v4().simple().to_string(), uuid::Uuid::new_v4().simple().to_string());
        let owner = Principal::Role { role: rn.into(), session: session.into() };
        self.keys.insert(id.clone(), Key { secret: secret.clone(), owner, created: now(), token: Some(token.clone()) });
        Some((id, secret, token))
    }

    pub fn admin(&self) -> Value {
        let ent = |n: &String, e: &Entity, arn: String| {
            json!({"name": n, "arn": arn, "attached": e.attached, "inline": e.inline,
                   "keys": self.keys.iter().filter(|(_, k)| matches!(&k.owner, Principal::User(u) if u == n) && k.token.is_none()).map(|(id, _)| id).collect::<Vec<_>>()})
        };
        json!({
            "users": self.users.iter().map(|(n, e)| ent(n, e, user_arn(n))).collect::<Vec<_>>(),
            "roles": self.roles.iter().map(|(n, e)| { let mut v = ent(n, e, role_arn(n)); v["trust"] = e.trust.clone(); v }).collect::<Vec<_>>(),
            "policies": self.policies.iter().map(|(a, p)| json!({"name": p.name, "arn": a, "document": p.doc})).collect::<Vec<_>>(),
        })
    }
}

// `Name.member.N` list parameters, ordered by N.
fn members(q: &HashMap<String, String>, name: &str) -> Vec<String> {
    let pre = format!("{name}.member.");
    let mut v: Vec<(u32, String)> = q.iter().filter_map(|(k, v)| Some((k.strip_prefix(&pre)?.parse().ok()?, v.clone()))).collect();
    v.sort();
    v.into_iter().map(|(_, v)| v).collect()
}

pub fn pct_encode(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

// JSON → Query-protocol XML body (arrays become <member> lists).
pub fn to_xml(v: &Value) -> String {
    match v {
        Value::Object(m) => m
            .iter()
            .map(|(k, v)| match v {
                // "Outer|Item" names list items explicitly (RDS/ElastiCache), otherwise <member>.
                Value::Array(a) => {
                    let (outer, item) = k.split_once('|').unwrap_or((k.as_str(), "member"));
                    format!("<{outer}>{}</{outer}>", a.iter().map(|x| format!("<{item}>{}</{item}>", to_xml(x))).collect::<String>())
                }
                Value::Object(o) if o.is_empty() => String::new(),
                // {"__entries": {k: v}} renders a Query-protocol map.
                Value::Object(o) if o.contains_key("__entries") => format!("<{k}>{}</{k}>", o["__entries"].as_object().into_iter().flatten()
                    .map(|(ek, ev)| format!("<entry><key>{}</key><value>{}</value></entry>", crate::s3::esc(ek), to_xml(ev))).collect::<String>()),
                _ => format!("<{k}>{}</{k}>", to_xml(v)),
            })
            .collect(),
        Value::String(s) => crate::s3::esc(s),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

impl Iam {
    pub fn snap_save(&self) -> Value {
        let ent = |m: &BTreeMap<String, Entity>| -> Vec<Value> {
            m.iter().map(|(n, e)| json!({
                "name": n, "id": e.id, "created": e.created, "attached": e.attached, "inline": e.inline, "trust": e.trust,
            })).collect()
        };
        let policies: Vec<Value> = self.policies.iter().map(|(arn, p)| json!({
            "arn": arn, "name": p.name, "id": p.id, "created": p.created, "doc": p.doc,
        })).collect();
        let keys: Vec<Value> = self.keys.iter().map(|(akid, k)| {
            let (kind, a, b) = match &k.owner {
                Principal::Root => ("root", "", ""),
                Principal::User(u) => ("user", u.as_str(), ""),
                Principal::Role { role, session } => ("role", role.as_str(), session.as_str()),
            };
            json!({"akid": akid, "secret": k.secret, "kind": kind, "a": a, "b": b, "created": k.created, "token": k.token})
        }).collect();
        json!({"users": ent(&self.users), "roles": ent(&self.roles), "policies": policies, "keys": keys})
    }

    pub fn snap_load(&mut self, v: &Value) {
        self.users.clear();
        self.roles.clear();
        self.policies.clear();
        self.keys.clear();
        let load_ent = |arr: &Value, dst: &mut BTreeMap<String, Entity>| {
            for e in arr.as_array().into_iter().flatten() {
                let Some(name) = e["name"].as_str() else { continue };
                let attached = e["attached"].as_array().into_iter().flatten().filter_map(|s| s.as_str().map(String::from)).collect();
                let inline = e["inline"].as_object().into_iter().flatten().map(|(k, v)| (k.clone(), v.clone())).collect();
                dst.insert(name.into(), Entity {
                    id: e["id"].as_str().unwrap_or("").into(),
                    created: e["created"].as_str().map(String::from).unwrap_or_else(now),
                    attached, inline, trust: e["trust"].clone(),
                });
            }
        };
        load_ent(&v["users"], &mut self.users);
        load_ent(&v["roles"], &mut self.roles);
        for p in v["policies"].as_array().into_iter().flatten() {
            let (Some(arn), Some(name)) = (p["arn"].as_str(), p["name"].as_str()) else { continue };
            self.policies.insert(arn.into(), Policy {
                name: name.into(), id: p["id"].as_str().unwrap_or("").into(),
                created: p["created"].as_str().map(String::from).unwrap_or_else(now),
                doc: p["doc"].clone(),
            });
        }
        for k in v["keys"].as_array().into_iter().flatten() {
            let Some(akid) = k["akid"].as_str() else { continue };
            let owner = match k["kind"].as_str().unwrap_or("root") {
                "user" => Principal::User(k["a"].as_str().unwrap_or("").into()),
                "role" => Principal::Role { role: k["a"].as_str().unwrap_or("").into(), session: k["b"].as_str().unwrap_or("").into() },
                _ => Principal::Root,
            };
            self.keys.insert(akid.into(), Key {
                secret: k["secret"].as_str().unwrap_or("").into(), owner,
                created: k["created"].as_str().map(String::from).unwrap_or_else(now),
                token: k["token"].as_str().map(String::from),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_principal_delivery() {
        let (q, topic) = ("arn:aws:sqs:us-east-1:000000000000:q", "arn:aws:sns:us-east-1:000000000000:t");
        let allow = json!({"Statement": [{"Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage",
                                          "Resource": q, "Condition": {"ArnEquals": {"aws:SourceArn": topic}}}]});
        assert!(service_may(None, "sns.amazonaws.com", "sqs:SendMessage", q, topic, false).is_ok(), "no policy: lenient");
        assert!(service_may(None, "sns.amazonaws.com", "sqs:SendMessage", q, topic, true).is_err(), "no policy: strict refuses");
        assert!(service_may(Some(&allow), "sns.amazonaws.com", "sqs:SendMessage", q, topic, true).is_ok());
        assert!(service_may(Some(&allow), "sns.amazonaws.com", "sqs:SendMessage", q, "arn:aws:sns:us-east-1:000000000000:other", true).is_err(), "wrong source");
        assert!(service_may(Some(&allow), "events.amazonaws.com", "sqs:SendMessage", q, topic, true).is_err(), "other service");
        let deny = json!({"Statement": [allow["Statement"][0].clone(), {"Effect": "Deny", "Principal": "*", "Action": "sqs:*", "Resource": q}]});
        assert!(service_may(Some(&deny), "sns.amazonaws.com", "sqs:SendMessage", q, topic, true).is_err(), "deny wins");
    }

    #[test]
    fn bucket_policy_combines_with_identity() {
        let mut iam = Iam::default();
        iam.handle(&Principal::Root, &HashMap::from([("Action".to_string(), "CreateUser".to_string()), ("UserName".to_string(), "bob".to_string())])).unwrap();
        let bob = Principal::User("bob".into());
        let obj = "arn:aws:s3:::b/k";
        let pol = |eff: &str, who: Value, act: &str| json!({"Statement": [{"Sid": "S", "Effect": eff, "Principal": who, "Action": act, "Resource": "arn:aws:s3:::b/*"}]});
        assert!(!iam.authorize_with(&bob, "s3:GetObject", obj, None).allowed);
        assert!(iam.authorize_with(&bob, "s3:GetObject", obj, Some(("bucket policy", &pol("Allow", json!({"AWS": user_arn("bob")}), "s3:GetObject")))).allowed);
        assert!(iam.authorize_with(&bob, "s3:GetObject", obj, Some(("bucket policy", &pol("Allow", json!("*"), "s3:Get*")))).allowed);
        // Naming the account delegates to identity policies: bob still has none.
        assert!(!iam.authorize_with(&bob, "s3:GetObject", obj, Some(("bucket policy", &pol("Allow", json!({"AWS": ACCOUNT}), "s3:GetObject")))).allowed);
        // Deny applies to everyone it names, root included, except root managing the policy itself.
        let deny_all = pol("Deny", json!("*"), "s3:*");
        assert_eq!(iam.authorize_with(&Principal::Root, "s3:GetObject", obj, Some(("bucket policy", &deny_all))).kind, "explicitDeny");
        assert!(iam.authorize_with(&Principal::Root, "s3:DeleteBucketPolicy", "arn:aws:s3:::b", Some(("bucket policy", &deny_all))).allowed);
        assert!(!iam.authorize_with(&bob, "s3:DeleteBucketPolicy", "arn:aws:s3:::b", Some(("bucket policy", &deny_all))).allowed);
        let not_bob = json!({"Statement": [{"Effect": "Deny", "NotPrincipal": {"AWS": user_arn("bob")}, "Action": "s3:*", "Resource": "*"}]});
        assert_eq!(iam.authorize_with(&Principal::Root, "s3:GetObject", obj, Some(("bucket policy", &not_bob))).kind, "explicitDeny");
        assert!(validate_resource_policy(&json!({"Statement": [{"Effect": "Allow", "Action": "s3:*"}]})).is_err());
        assert!(validate_resource_policy(&json!({"Statement": []})).is_err());
    }

    #[test]
    fn glob_and_conditions() {
        assert!(glob("s3:Get*", "s3:GetObject", true));
        assert!(glob("arn:aws:s3:::b/*", "arn:aws:s3:::b/x/y", false));
        assert!(!glob("arn:aws:s3:::b/*", "arn:aws:s3:::c/x", false));
        assert!(glob("a?c", "abc", false) && !glob("a?c", "ac", false));
        let ctx = HashMap::from([("aws:username".to_string(), "kim".to_string())]);
        assert!(cond_ok(&json!({"StringEquals": {"aws:username": "kim"}}), &ctx));
        assert!(!cond_ok(&json!({"StringEquals": {"aws:username": ["lee", "park"]}}), &ctx));
        assert!(cond_ok(&json!({"StringNotEquals": {"aws:missing": "x"}}), &ctx));
        assert!(!cond_ok(&json!({"StringEquals": {"aws:missing": "x"}}), &ctx));
    }

    #[test]
    fn condition_operators() {
        let now = chrono::Utc::now().timestamp();
        let ctx = HashMap::from([
            ("aws:SourceIp".to_string(), "127.0.0.1".to_string()),
            ("aws:EpochTime".to_string(), now.to_string()),
        ]);
        // Numeric*
        assert!(cond_ok(&json!({"NumericGreaterThan": {"aws:EpochTime": "1000000000"}}), &ctx));
        assert!(cond_ok(&json!({"NumericLessThanEquals": {"aws:EpochTime": now + 1}}), &ctx));
        assert!(!cond_ok(&json!({"NumericLessThan": {"aws:EpochTime": "1000000000"}}), &ctx));
        assert!(!cond_ok(&json!({"NumericEquals": {"aws:EpochTime": ["1", "2"]}}), &ctx));
        assert!(cond_ok(&json!({"NumericNotEquals": {"aws:EpochTime": "0"}}), &ctx));
        assert!(!cond_ok(&json!({"NumericEquals": {"aws:EpochTime": "not-a-number"}}), &ctx));
        // Date*: epoch seconds, RFC 3339 and date-only forms
        assert!(cond_ok(&json!({"DateGreaterThan": {"aws:EpochTime": "2020-01-01T00:00:00Z"}}), &ctx));
        assert!(cond_ok(&json!({"DateGreaterThan": {"aws:EpochTime": "2020-01-01"}}), &ctx));
        assert!(cond_ok(&json!({"DateLessThan": {"aws:EpochTime": "9999-01-01T00:00:00Z"}}), &ctx));
        // 2000-01-01T09:00+09:00 == 2000-01-01T00:00Z
        assert!(cond_ok(&json!({"DateEquals": {"x": "2000-01-01T09:00:00+09:00"}}), &HashMap::from([("x".to_string(), "946684800".to_string())])));
        assert!(!cond_ok(&json!({"DateLessThan": {"aws:EpochTime": "garbage"}}), &ctx));
        // IpAddress / NotIpAddress
        assert!(cond_ok(&json!({"IpAddress": {"aws:SourceIp": ["10.0.0.0/8", "127.0.0.0/8"]}}), &ctx));
        assert!(cond_ok(&json!({"IpAddress": {"aws:SourceIp": "127.0.0.1"}}), &ctx)); // bare IP = /32
        assert!(!cond_ok(&json!({"IpAddress": {"aws:SourceIp": "127.0.0.2/32"}}), &ctx));
        assert!(cond_ok(&json!({"NotIpAddress": {"aws:SourceIp": "10.0.0.0/8"}}), &ctx));
        assert!(!cond_ok(&json!({"IpAddress": {"aws:SourceIp": "::1/128"}}), &ctx), "v4 and v6 never overlap");
        assert!(cond_ok(&json!({"IpAddress": {"aws:SourceIp": "::1/128"}}), &HashMap::from([("aws:SourceIp".to_string(), "::1".to_string())])));
        assert!(cond_ok(&json!({"IpAddress": {"aws:SourceIp": "2001:db8::/32"}}), &HashMap::from([("aws:SourceIp".to_string(), "2001:DB8::abcd".to_string())])));
        assert!(cond_ok(&json!({"IpAddress": {"aws:SourceIp": "::ffff:127.0.0.1"}}), &ctx), "v4-mapped v6 counts as v4");
        // Qualifiers: single-valued context makes them equal to the base operator, except on missing keys.
        assert!(cond_ok(&json!({"ForAnyValue:StringEquals": {"aws:SourceIp": "127.0.0.1"}}), &ctx));
        assert!(cond_ok(&json!({"ForAllValues:StringEquals": {"aws:SourceIp": "127.0.0.1"}}), &ctx));
        assert!(!cond_ok(&json!({"ForAnyValue:StringEquals": {"aws:missing": "x"}}), &ctx));
        assert!(cond_ok(&json!({"ForAllValues:StringEquals": {"aws:missing": "x"}}), &ctx));
        assert!(cond_ok(&json!({"ForAllValues:StringEqualsIfExists": {"aws:missing": "x"}}), &ctx));
        // req_ctx carries the new keys
        let c = req_ctx(&Principal::Root, "192.168.0.5");
        assert_eq!(c["aws:SourceIp"], "192.168.0.5");
        assert!(c["aws:EpochTime"].parse::<i64>().unwrap() + 60 > now);
    }
}

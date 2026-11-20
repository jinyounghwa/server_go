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

// ponytail: String*/Arn*/Bool operators (+IfExists); others never match. ForAnyValue/ForAllValues not supported.
fn cond_ok(c: &Value, ctx: &HashMap<String, String>) -> bool {
    let Some(m) = c.as_object() else { return true };
    m.iter().all(|(op, kv)| {
        kv.as_object().is_some_and(|kv| {
            kv.iter().all(|(k, want)| {
                let (base, if_exists) = op.strip_suffix("IfExists").map_or((op.as_str(), false), |b| (b, true));
                let wants = strs(want);
                let Some(h) = ctx.iter().find(|(ck, _)| ck.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str()) else {
                    return if_exists || base.contains("Not");
                };
                match base {
                    "StringEquals" | "ArnEquals" => wants.iter().any(|w| w == h),
                    "StringNotEquals" | "ArnNotEquals" => !wants.iter().any(|w| w == h),
                    "StringEqualsIgnoreCase" => wants.iter().any(|w| w.eq_ignore_ascii_case(h)),
                    "StringNotEqualsIgnoreCase" => !wants.iter().any(|w| w.eq_ignore_ascii_case(h)),
                    "StringLike" | "ArnLike" => wants.iter().any(|w| glob(w, h, false)),
                    "StringNotLike" | "ArnNotLike" => !wants.iter().any(|w| glob(w, h, false)),
                    "Bool" => wants.iter().any(|w| w.eq_ignore_ascii_case(h)),
                    _ => false,
                }
            })
        })
    })
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
        let Some((_, e)) = self.entity(p) else {
            return Decision { allowed: true, kind: "allowed", reason: "account root (unregistered access key) is always allowed".into(), matched: vec![] };
        };
        let mut ctx = HashMap::from([
            ("aws:PrincipalArn".to_string(), match p { Principal::Role { role, .. } => role_arn(role), _ => p.arn() }),
            ("aws:PrincipalAccount".to_string(), ACCOUNT.to_string()),
            ("aws:RequestedRegion".to_string(), REGION.clone()),
            ("aws:SecureTransport".to_string(), "false".to_string()),
        ]);
        if let Principal::User(u) = p {
            ctx.insert("aws:username".into(), u.clone());
        }
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
}

// Cognito user pools (JSON 1.1): users, app clients, groups, password auth, RS256 JWTs (JWKS endpoint) and
// Lambda triggers (PreSignUp before creation, PostConfirmation after, PreTokenGeneration at issue).
// Issuer: {endpoint}/_cognito/{poolId}  (JWKS at /.well-known/jwks.json, discovery at /.well-known/openid-configuration)
// USER_SRP_AUTH: PASSWORD_VERIFIER over the RFC 5054 3072-bit group, same math as amazon-cognito-identity-js (see srp_* below).
// CUSTOM_AUTH runs DefineAuthChallenge/CreateAuthChallenge/VerifyAuthChallengeResponse (orchestrated by main.rs).
// ponytail: no device SRP (DEVICE_SRP_AUTH is refused) or hosted UI/OAuth flows; MFA is software-token TOTP only (no SMS).
// Verification codes are published as events; trigger failures on PostConfirmation/PreToken are best-effort like AWS retries.
use crate::{b64, epoch, err, need, ApiErr, ACCOUNT, REGION};
use base64::Engine;
use rsa::{BigUint, pkcs1v15::{SigningKey, VerifyingKey}, signature::{SignatureEncoding, Signer, Verifier}, traits::PublicKeyParts, RsaPrivateKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::LazyLock;

const KID: &str = "rocalcloud-1";
// One signing key per emulator process, generated on first use.
static KEY: LazyLock<RsaPrivateKey> = LazyLock::new(|| RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("RSA key generation"));

fn b64url(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

pub fn issuer(pool: &str) -> String {
    format!("{}/_cognito/{pool}", crate::endpoint())
}

pub fn jwks() -> Value {
    let k = KEY.to_public_key();
    json!({"keys": [{"kid": KID, "alg": "RS256", "kty": "RSA", "use": "sig", "n": b64url(&k.n().to_bytes_be()), "e": b64url(&k.e().to_bytes_be())}]})
}

fn sign(claims: &Value) -> String {
    let msg = format!("{}.{}", b64url(json!({"kid": KID, "alg": "RS256"}).to_string().as_bytes()), b64url(claims.to_string().as_bytes()));
    let sig = SigningKey::<Sha256>::new(KEY.clone()).sign(msg.as_bytes());
    format!("{msg}.{}", b64url(&sig.to_bytes()))
}

// Claims of a valid, unexpired token we issued.
pub fn verify(token: &str) -> Option<Value> {
    let (msg, sig) = token.rsplit_once('.')?;
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig).ok()?;
    VerifyingKey::<Sha256>::new(KEY.to_public_key()).verify(msg.as_bytes(), &rsa::pkcs1v15::Signature::try_from(sig.as_slice()).ok()?).ok()?;
    let claims: Value = serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(msg.split('.').nth(1)?).ok()?).ok()?;
    (claims["exp"].as_f64()? > epoch()).then_some(claims)
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut k = if key.len() > 64 { Sha256::digest(key).to_vec() } else { key.to_vec() };
    k.resize(64, 0);
    let pad = |b: u8| k.iter().map(|x| x ^ b).collect::<Vec<u8>>();
    let inner = Sha256::new().chain_update(pad(0x36)).chain_update(msg).finalize();
    Sha256::new().chain_update(pad(0x5c)).chain_update(inner).finalize().to_vec()
}

// --- SRP (USER_SRP_AUTH). Hex strings use the client libraries' "padHex": even length, "00" prefix when the top bit is set.
// The RFC 3526/5054 3072-bit prime (checked against its pi formula), g = 2.
const SRP_N: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
static N_G_K: LazyLock<(BigUint, BigUint, BigUint)> = LazyLock::new(|| {
    let (n, g) = (BigUint::parse_bytes(SRP_N.as_bytes(), 16).unwrap(), BigUint::from(2u8));
    let k = hex_hash(&format!("{}{}", pad_hex(&n), pad_hex(&g)));
    (n, g, k)
});
fn pad_hex(n: &BigUint) -> String {
    let h = n.to_str_radix(16);
    let h = if h.len() % 2 == 1 { format!("0{h}") } else { h };
    if h.as_bytes()[0] >= b'8' { format!("00{h}") } else { h }
}
fn unhex(h: &str) -> Vec<u8> {
    (0..h.len() / 2).filter_map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).ok()).collect()
}
// SHA-256 of the bytes a hex string encodes, as a number.
fn hex_hash(h: &str) -> BigUint {
    BigUint::from_bytes_be(&Sha256::digest(unhex(h)))
}
fn pool_name(pool: &str) -> &str {
    pool.split_once('_').map_or(pool, |(_, n)| n)
}
// x = H(salt | H(poolName | user ":" | password)); poolName is the pool id after the region underscore.
fn srp_x(pool: &str, user: &str, pw: &str, salt: &BigUint) -> BigUint {
    let inner: String = Sha256::digest(format!("{}{user}:{pw}", pool_name(pool))).iter().map(|b| format!("{b:02x}")).collect();
    hex_hash(&format!("{}{inner}", pad_hex(salt)))
}
fn srp_verifier(pool: &str, user: &str, pw: &str, salt_hex: &str) -> BigUint {
    let (n, g, _) = &*N_G_K;
    g.modpow(&srp_x(pool, user, pw, &BigUint::parse_bytes(salt_hex.as_bytes(), 16).unwrap_or_default()), n)
}
// 16-byte HKDF-SHA256 key from the shared secret S and scrambler u ("Caldera Derived Key").
fn srp_key(s: &BigUint, u: &BigUint) -> Vec<u8> {
    let prk = hmac_sha256(&unhex(&pad_hex(u)), &unhex(&pad_hex(s)));
    hmac_sha256(&prk, b"Caldera Derived Key\x01")[..16].to_vec()
}
// Base64 HMAC the client must send as PASSWORD_CLAIM_SIGNATURE.
fn srp_signature(key: &[u8], pool: &str, user: &str, secret_block: &[u8], timestamp: &str) -> String {
    b64(&hmac_sha256(key, &[pool_name(pool).as_bytes(), user.as_bytes(), secret_block, timestamp.as_bytes()].concat()))
}
// Server half of the handshake: B = k*v + g^b, u = H(A | B), S = (A * v^u)^b. None for a degenerate A or u.
fn srp_server(a_hex: &str, v: &BigUint) -> Option<(BigUint, Vec<u8>)> {
    let (n, g, k) = &*N_G_K;
    let a = BigUint::parse_bytes(a_hex.as_bytes(), 16)?;
    if (&a % n) == BigUint::default() {
        return None;
    }
    let b = BigUint::from_bytes_be(&crate::rand_bytes(32));
    let big_b = (k * v + g.modpow(&b, n)) % n;
    let u = hex_hash(&format!("{}{}", pad_hex(&a), pad_hex(&big_b)));
    if u == BigUint::default() {
        return None;
    }
    let s = (a * v.modpow(&u, n)).modpow(&b, n);
    Some((big_b, srp_key(&s, &u)))
}
// LambdaConfig keys we store (CustomMessage/PostAuthentication are kept but never invoked).
const TRIGGERS: [&str; 8] = ["PreSignUp", "PostConfirmation", "PreTokenGeneration", "CustomMessage", "PostAuthentication",
                             "DefineAuthChallenge", "CreateAuthChallenge", "VerifyAuthChallengeResponse"];

// CUSTOM_AUTH: main.rs runs Define/Create/Verify (async Lambda calls) with this context, then hands the
// outcome back to handle() as "__rcCustom" so the sync code issues tokens or the next challenge.
pub struct CustomCtx {
    pub define: String,
    pub create: String,
    pub verify: String,
    pub base: Value,          // event fields shared by the three triggers
    pub session: Vec<Value>,  // [{challengeName, challengeResult, challengeMetadata}]
    pub private: Value,       // privateChallengeParameters of the pending challenge
    pub metadata: Value,      // its challengeMetadata
}
struct CustomState {
    pool: String,
    user: String,
    client: String,
    session: Vec<Value>,
    private: Value,
    metadata: Value,
}
struct SrpPending {
    pool: String,
    user: String,
    client: String,
    key: Vec<u8>,
    expires: f64,
}

fn hash_pw(salt: &str, pw: &str) -> String {
    b64(&Sha256::new().chain_update(salt).chain_update(pw).finalize())
}

struct User {
    sub: String,
    salt: String,
    pw: String,
    srp_v: BigUint, // SRP verifier g^x for USER_SRP_AUTH, kept in step with pw
    attrs: BTreeMap<String, String>,
    status: &'static str, // UNCONFIRMED | CONFIRMED | FORCE_CHANGE_PASSWORD
    enabled: bool,
    created: f64,
    code: Option<String>,
    totp: Option<Totp>, // software token MFA enrollment
}

// RFC 6238 TOTP over the stored raw secret (hex); verified users can answer the MFA challenge.
impl User {
    fn set_pw(&mut self, pool: &str, uname: &str, pw: &str) {
        (self.pw, self.srp_v) = (hash_pw(&self.salt, pw), srp_verifier(pool, uname, pw, &self.salt));
    }
}

struct Totp {
    secret: String, // 16 random bytes as hex
    verified: bool,
    preferred: bool, // the user turned it on (needed when the pool is OPTIONAL)
}
struct Group {
    description: String,
    precedence: i64,
    role_arn: String,
    members: BTreeSet<String>,
}

impl Group {
    fn json(&self, name: &str, pool: &str) -> Value {
        json!({"GroupName": name, "UserPoolId": pool, "Description": self.description, "RoleArn": self.role_arn,
               "Precedence": self.precedence, "CreationDate": epoch(), "LastModifiedDate": epoch()})
    }
}

struct Pool {
    name: String,
    created: f64,
    users: BTreeMap<String, User>,
    policy: Value,
    username_attrs: Vec<String>,
    auto_verified: Vec<String>,
    groups: BTreeMap<String, Group>,
    lambda_config: BTreeMap<String, String>, // trigger name -> Lambda function ARN
    mfa: &'static str, // OFF | OPTIONAL | ON (SetUserPoolMfaConfig)
}

// A pending Lambda trigger: main.rs runs the function and applies the result.
pub struct Trigger {
    pub kind: &'static str, // "PreSignUp" | "PostConfirmation" | "PreTokenGeneration"
    pub fn_name: String,
    pub event: Value,
    pub pool: String,
    pub user: String,
    pub client: String,
    pub with_refresh: bool,
}
struct Client {
    name: String,
    pool: String,
    secret: Option<String>,
}

#[derive(Default)]
pub struct Cognito {
    pools: BTreeMap<String, Pool>,
    clients: BTreeMap<String, Client>,
    refresh: HashMap<String, (String, String, String)>, // token -> (pool, username, client)
    sessions: HashMap<String, (String, String, String)>, // challenge session -> same
    custom: HashMap<String, CustomState>,               // CUSTOM_CHALLENGE session -> state
    srp: HashMap<String, SrpPending>,                   // SECRET_BLOCK (base64) -> handshake awaiting PASSWORD_VERIFIER
    codes: Vec<(String, String)>,                       // (username, code) to publish as events
    pub triggers: Vec<Trigger>,                         // pending triggers for main.rs
}

fn e(code: &str, msg: &str) -> ApiErr {
    err(code, msg)
}

// HMAC-SHA1 on top of the hand-rolled SHA-1 in sigv4 (RFC 6238 needs it for TOTP).
fn hmac_sha1(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..20].copy_from_slice(&crate::sigv4::sha1(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    crate::sigv4::sha1(&[opad, crate::sigv4::sha1(&[ipad, msg.to_vec()].concat()).to_vec()].concat()).to_vec()
}

// RFC 6238: 6 digits, 30-second step. The caller checks the +/-1 step window.
fn totp_at(secret: &[u8], counter: u64) -> String {
    let mac = hmac_sha1(secret, &counter.to_be_bytes());
    let off = (mac[19] & 0xf) as usize;
    let bin = (((mac[off] as u32) & 0x7f) << 24) | ((mac[off + 1] as u32) << 16) | ((mac[off + 2] as u32) << 8) | mac[off + 3] as u32;
    format!("{:06}", bin % 1_000_000)
}

// A code matches within the current or neighbouring 30-second step.
fn totp_matches(secret: &str, code: &str) -> bool {
    let raw = (0..secret.len() / 2)
        .filter_map(|i| u8::from_str_radix(&secret[i * 2..i * 2 + 2], 16).ok())
        .collect::<Vec<u8>>();
    let now = epoch() as u64;
    ((now / 30).saturating_sub(1)..=(now / 30) + 1)
        .map(|c| totp_at(&raw, c))
        .any(|c| c == code)
}

// Standard base32 (A-Z, 2-7, RFC 4648 padding) used for SecretCode.
fn base32(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut buf, mut bits) = (0u64, 0u32);
    for &b in data {
        buf = (buf << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(CHARS[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(CHARS[((buf << (5 - bits)) & 31) as usize] as char);
    }
    while out.len() % 8 != 0 {
        out.push('=');
    }
    out
}
fn bad_login() -> ApiErr {
    e("NotAuthorizedException", "Incorrect username or password.")
}
fn attrs_of(v: &Value) -> BTreeMap<String, String> {
    v.as_array().into_iter().flatten().filter_map(|a| Some((a["Name"].as_str()?.to_string(), a["Value"].as_str().unwrap_or("").to_string()))).collect()
}
fn attrs_json(u: &User) -> Vec<Value> {
    std::iter::once(json!({"Name": "sub", "Value": u.sub})).chain(u.attrs.iter().map(|(k, v)| json!({"Name": k, "Value": v}))).collect()
}
fn new_code() -> String {
    format!("{:06}", u32::from_le_bytes(crate::rand_bytes(4).try_into().unwrap()) % 1_000_000)
}

impl Pool {
    fn find(&self, name: &str) -> Option<String> {
        if self.users.contains_key(name) {
            return Some(name.into());
        }
        let alias = |attr: &str| self.users.iter().find(|(_, u)| u.attrs.get(attr).map(String::as_str) == Some(name)).map(|(k, _)| k.clone());
        self.username_attrs.iter().find_map(|a| alias(a.trim_end_matches("_number"))).or_else(|| alias("email"))
            .filter(|_| !self.username_attrs.is_empty())
    }
    fn check_policy(&self, pw: &str) -> Result<(), ApiErr> {
        let p = &self.policy;
        let min = p["MinimumLength"].as_u64().unwrap_or(8) as usize;
        let need = |k: &str| p[k].as_bool().unwrap_or(true);
        let ok = pw.chars().count() >= min
            && (!need("RequireUppercase") || pw.chars().any(|c| c.is_uppercase()))
            && (!need("RequireLowercase") || pw.chars().any(|c| c.is_lowercase()))
            && (!need("RequireNumbers") || pw.chars().any(|c| c.is_ascii_digit()))
            && (!need("RequireSymbols") || pw.chars().any(|c| !c.is_alphanumeric()));
        if ok { Ok(()) } else { Err(e("InvalidPasswordException", "Password did not conform with policy")) }
    }
}

impl Cognito {
    pub fn pool_exists(&self, pool_id: &str) -> bool {
        self.pools.contains_key(pool_id)
    }

    pub fn take_codes(&mut self) -> Vec<(String, String)> {
        std::mem::take(&mut self.codes)
    }

    pub fn take_triggers(&mut self) -> Vec<Trigger> {
        std::mem::take(&mut self.triggers)
    }

    // PreSignUp event for a SignUp request, if the pool has that trigger configured.
    pub fn presignup_event(&self, r: &Value) -> Option<Trigger> {
        let cid = r["ClientId"].as_str()?;
        let c = self.clients.get(cid)?;
        let pool = &c.pool;
        let p = self.pools.get(pool)?;
        let fn_name = p.lambda_config.get("PreSignUp")?.clone();
        let uname = r["Username"].as_str()?;
        let attrs: Map<String, Value> = attrs_of(&r["UserAttributes"]).into_iter().map(|(k, v)| (k, v.into())).collect();
        Some(Trigger {
            kind: "PreSignUp",
            fn_name,
            event: json!({"version": "1", "triggerSource": "PreSignUp_SignUp", "region": *REGION, "userPoolId": pool,
                          "userName": uname, "callerContext": {"clientId": cid},
                          "request": {"userAttributes": attrs, "validationData": {}},
                          "response": {"autoConfirmUser": false, "autoVerifyEmail": false, "autoVerifyPhone": false}}),
            pool: pool.clone(), user: uname.into(), client: cid.into(), with_refresh: false,
        })
    }

    // Context for main.rs to run the custom-auth triggers, or None when the request is not a CUSTOM_AUTH step.
    pub fn custom_ctx(&self, op: &str, r: &Value) -> Result<Option<CustomCtx>, ApiErr> {
        let respond = op == "RespondToAuthChallenge" && r["ChallengeName"] == "CUSTOM_CHALLENGE";
        if !(op == "InitiateAuth" && r["AuthFlow"] == "CUSTOM_AUTH") && !respond {
            return Ok(None);
        }
        let (cid, c) = self.client(r)?;
        let (pool, user, session, private, metadata) = if respond {
            let st = self.custom.get(need(r, "Session")?).filter(|s| s.client == cid).ok_or_else(|| e("NotAuthorizedException", "Invalid session for the user."))?;
            (st.pool.clone(), st.user.clone(), st.session.clone(), st.private.clone(), st.metadata.clone())
        } else {
            let name = r["AuthParameters"]["USERNAME"].as_str().ok_or_else(|| e("InvalidParameterException", "Missing required parameter USERNAME"))?;
            Self::check_secret(c, &cid, name, r["AuthParameters"]["SECRET_HASH"].as_str())?;
            let uname = self.pools[&c.pool].find(name).ok_or_else(|| e("UserNotFoundException", "User does not exist."))?;
            let u = &self.pools[&c.pool].users[&uname];
            if !u.enabled {
                return Err(e("NotAuthorizedException", "User is disabled."));
            }
            if u.status == "UNCONFIRMED" {
                return Err(e("UserNotConfirmedException", "User is not confirmed."));
            }
            (c.pool.clone(), uname, vec![], Value::Null, Value::Null)
        };
        let p = &self.pools[&pool];
        let fns: Vec<String> = ["DefineAuthChallenge", "CreateAuthChallenge", "VerifyAuthChallengeResponse"].iter().filter_map(|t| p.lambda_config.get(*t).cloned()).collect();
        let [define, create, verify] = <[String; 3]>::try_from(fns)
            .map_err(|_| e("InvalidParameterException", "CUSTOM_AUTH needs DefineAuthChallenge, CreateAuthChallenge and VerifyAuthChallengeResponse triggers"))?;
        let u = &p.users[&user];
        let mut attrs = json!({"sub": u.sub, "cognito:user_status": u.status});
        for (k, v) in &u.attrs {
            attrs[k.as_str()] = v.as_str().into();
        }
        let base = json!({"version": "1", "region": *REGION, "userPoolId": pool, "userName": user, "callerContext": {"clientId": cid},
                          "request": {"userAttributes": attrs, "userNotFound": false}});
        Ok(Some(CustomCtx { define, create, verify, base, session, private, metadata }))
    }

    // Applies what main.rs learned from the triggers: {"session": [...], "define": response, "create": response}.
    fn custom_step(&mut self, r: &Value) -> Result<Value, ApiErr> {
        let out = &r["__rcCustom"];
        let (cid, _) = self.client(r)?;
        let (pool, user) = if r["ChallengeName"] == "CUSTOM_CHALLENGE" {
            let st = self.custom.remove(need(r, "Session")?).ok_or_else(|| e("NotAuthorizedException", "Invalid session for the user."))?;
            (st.pool, st.user)
        } else {
            let name = r["AuthParameters"]["USERNAME"].as_str().unwrap_or("");
            let pool = self.clients[&cid].pool.clone();
            let uname = self.pools[&pool].find(name).ok_or_else(|| e("UserNotFoundException", "User does not exist."))?;
            (pool, uname)
        };
        let d = &out["define"];
        if d["failAuthentication"] == true {
            return Err(e("NotAuthorizedException", "Incorrect username or password."));
        }
        if d["issueTokens"] == true {
            return Ok(self.tokens(&pool, &user, &cid, true));
        }
        if d["challengeName"] != "CUSTOM_CHALLENGE" {
            // ponytail: Define may only pick CUSTOM_CHALLENGE locally (no PASSWORD_VERIFIER/SMS_MFA mixed into custom auth).
            return Err(e("InvalidLambdaResponseException", "DefineAuthChallenge must fail, issue tokens or pick CUSTOM_CHALLENGE locally"));
        }
        let c = &out["create"];
        let session = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
        let mut params = c["publicChallengeParameters"].as_object().cloned().unwrap_or_default();
        params.insert("USERNAME".into(), user.clone().into());
        self.custom.insert(session.clone(), CustomState { pool, user, client: cid, session: out["session"].as_array().cloned().unwrap_or_default(),
                                                          private: c["privateChallengeParameters"].clone(), metadata: c["challengeMetadata"].clone() });
        Ok(json!({"ChallengeName": "CUSTOM_CHALLENGE", "Session": session, "ChallengeParameters": params}))
    }

    // Re-issue tokens with PreTokenGeneration claim overrides applied (no new trigger).
    pub fn reissue_tokens(&mut self, t: &Trigger, add: Option<Map<String, Value>>, suppress: &[String]) -> Value {
        self.tokens_inner(&t.pool, &t.user, &t.client, t.with_refresh, add.as_ref(), suppress, false)
    }

    // Queue a PostConfirmation trigger for a newly confirmed user.
    fn push_post_confirmation(&mut self, pool: &str, uname: &str) {
        let Some(p) = self.pools.get(pool) else { return };
        let Some(fn_name) = p.lambda_config.get("PostConfirmation") else { return };
        let u = &p.users.get(uname).unwrap();
        let attrs: Map<String, Value> = u.attrs.iter().map(|(k, v)| (k.clone(), v.as_str().into())).collect();
        let mut user_attrs = json!({"sub": u.sub.clone(), "cognito:username": uname});
        for (k, v) in attrs {
            user_attrs[k.as_str()] = v;
        }
        let client = "".to_string();
        self.triggers.push(Trigger {
            kind: "PostConfirmation",
            fn_name: fn_name.clone(),
            event: json!({"version": "1", "triggerSource": "PostConfirmation_ConfirmSignUp", "region": *REGION, "userPoolId": pool,
                          "userName": uname, "callerContext": {"clientId": client},
                          "request": {"userAttributes": user_attrs}, "response": {}}),
            pool: pool.into(), user: uname.into(), client, with_refresh: false,
        });
    }

    fn client(&self, r: &Value) -> Result<(String, &Client), ApiErr> {
        let id = need(r, "ClientId")?;
        let c = self.clients.get(id).ok_or_else(|| e("ResourceNotFoundException", "User pool client does not exist."))?;
        Ok((id.into(), c))
    }

    // Apps with a client secret must send SECRET_HASH = Base64(HMAC_SHA256(secret, username + clientId)).
    fn check_secret(c: &Client, client_id: &str, username: &str, hash: Option<&str>) -> Result<(), ApiErr> {
        let Some(secret) = &c.secret else { return Ok(()) };
        let want = b64(&hmac_sha256(secret.as_bytes(), format!("{username}{client_id}").as_bytes()));
        if hash == Some(want.as_str()) { Ok(()) } else { Err(e("NotAuthorizedException", format!("Client {client_id} is configured with secret but SECRET_HASH was not received or is wrong").as_str())) }
    }

    fn tokens(&mut self, pool: &str, username: &str, client: &str, with_refresh: bool) -> Value {
        self.tokens_inner(pool, username, client, with_refresh, None, &[], true)
    }

    // Groups a user belongs to (sorted, like the token claim).
    fn groups_of(&self, pool: &str, user: &str) -> Vec<String> {
        self.pools.get(pool).map(|p| p.groups.iter().filter(|(_, g)| g.members.contains(user)).map(|(n, _)| n.clone()).collect()).unwrap_or_default()
    }

    fn tokens_inner(&mut self, pool: &str, username: &str, client: &str, with_refresh: bool,
                    add: Option<&Map<String, Value>>, suppress: &[String], emit_trigger: bool) -> Value {
        let u = &self.pools[pool].users[username];
        let now = epoch().floor();
        let groups = self.groups_of(pool, username);
        let mut id = json!({"sub": u.sub, "aud": client, "iss": issuer(pool), "token_use": "id", "cognito:username": username,
                            "cognito:groups": groups, "auth_time": now, "iat": now, "exp": now + 3600.0, "event_id": uuid::Uuid::new_v4().to_string()});
        for (k, v) in &u.attrs {
            id[k] = if k.ends_with("_verified") { json!(v == "true") } else { json!(v) };
        }
        // PreTokenGeneration claim overrides touch the ID token.
        if let Some(add) = add {
            for (k, v) in add {
                id[k.as_str()] = v.clone();
            }
        }
        for k in suppress {
            id.as_object_mut().unwrap().remove(k);
        }
        let access = json!({"sub": u.sub, "client_id": client, "iss": issuer(pool), "token_use": "access", "scope": "aws.cognito.signin.user.admin",
                            "username": username, "cognito:groups": self.groups_of(pool, username),
                            "auth_time": now, "iat": now, "exp": now + 3600.0, "jti": uuid::Uuid::new_v4().to_string()});
        let mut out = json!({"AccessToken": sign(&access), "IdToken": sign(&id), "ExpiresIn": 3600, "TokenType": "Bearer"});
        if with_refresh {
            let rt = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
            self.refresh.insert(rt.clone(), (pool.into(), username.into(), client.into()));
            out["RefreshToken"] = rt.into();
        }
        if emit_trigger && self.pools[pool].lambda_config.contains_key("PreTokenGeneration") {
            let fn_name = self.pools[pool].lambda_config["PreTokenGeneration"].clone();
            let sub = u.sub.clone();
            let attrs: Map<String, Value> = u.attrs.iter().map(|(k, v)| (k.clone(), v.as_str().into())).collect();
            let groups = self.groups_of(pool, username);
            let mut user_attrs = json!({"sub": sub, "cognito:username": username});
            for (k, v) in attrs {
                user_attrs[k.as_str()] = v;
            }
            self.triggers.push(Trigger {
                kind: "PreTokenGeneration",
                fn_name,
                event: json!({"version": "1", "triggerSource": "TokenGeneration_HostedAuth", "region": *REGION, "userPoolId": pool,
                              "userName": username, "callerContext": {"clientId": client},
                              "request": {"groupConfiguration": {"groupsToOverride": groups, "iamRolesToOverride": [], "preferredRole": null},
                                          "userAttributes": user_attrs},
                              "response": {"claimsOverrideDetails": {}}}),
                pool: pool.into(), user: username.into(), client: client.into(), with_refresh,
            });
        }
        json!({ "AuthenticationResult": out })
    }

    // Password check shared by InitiateAuth and AdminInitiateAuth.
    fn password_auth(&mut self, pool: &str, client: &str, name: &str, pw: &str) -> Result<Value, ApiErr> {
        let p = &self.pools[pool];
        let uname = p.find(name).ok_or_else(|| e("UserNotFoundException", "User does not exist."))?;
        let u = &p.users[&uname];
        if hash_pw(&u.salt, pw) != u.pw {
            return Err(bad_login());
        }
        self.after_password(pool, client, uname)
    }

    // What follows a proven password (plain or SRP): status checks, NEW_PASSWORD_REQUIRED, MFA, then tokens.
    fn after_password(&mut self, pool: &str, client: &str, uname: String) -> Result<Value, ApiErr> {
        let p = &self.pools[pool];
        let u = &p.users[&uname];
        if !u.enabled {
            return Err(e("NotAuthorizedException", "User is disabled."));
        }
        match u.status {
            "UNCONFIRMED" => Err(e("UserNotConfirmedException", "User is not confirmed.")),
            "FORCE_CHANGE_PASSWORD" => {
                let session = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
                self.sessions.insert(session.clone(), (pool.into(), uname.clone(), client.into()));
                Ok(json!({"ChallengeName": "NEW_PASSWORD_REQUIRED", "Session": session,
                          "ChallengeParameters": {"USER_ID_FOR_SRP": uname, "requiredAttributes": "[]", "userAttributes": "{}"}}))
            }
            _ => {
                // MFA: required when the pool is ON (enrolled users) or the user enabled it under OPTIONAL.
                // ponytail: a pool set to ON with an unenrolled user still lets the password through.
                let need = u.totp.as_ref().is_some_and(|t| t.verified && (p.mfa == "ON" || t.preferred));
                if need {
                    let session = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
                    self.sessions.insert(session.clone(), (pool.into(), uname.clone(), client.into()));
                    Ok(json!({"ChallengeName": "SOFTWARE_TOKEN_MFA", "Session": session,
                              "ChallengeParameters": {"USER_ID_FOR_SRP": uname}}))
                } else {
                    Ok(self.tokens(pool, &uname, client, true))
                }
            }
        }
    }

    fn user_from_token(&self, r: &Value) -> Result<(String, String), ApiErr> {
        let c = verify(need(r, "AccessToken")?).filter(|c| c["token_use"] == "access").ok_or_else(|| e("NotAuthorizedException", "Invalid Access Token"))?;
        let pool = c["iss"].as_str().unwrap_or("").rsplit('/').next().unwrap_or("").to_string();
        let user = c["username"].as_str().unwrap_or("").to_string();
        if !self.pools.get(&pool).is_some_and(|p| p.users.contains_key(&user)) {
            return Err(e("NotAuthorizedException", "Access Token has been revoked"));
        }
        Ok((pool, user))
    }

    fn pool_json(id: &str, p: &Pool) -> Value {
        json!({"Id": id, "Name": p.name, "Arn": format!("arn:aws:cognito-idp:{}:{ACCOUNT}:userpool/{id}", *REGION), "CreationDate": p.created,
               "LastModifiedDate": p.created, "Policies": {"PasswordPolicy": p.policy}, "UsernameAttributes": p.username_attrs,
               "AutoVerifiedAttributes": p.auto_verified, "EstimatedNumberOfUsers": p.users.len(), "MfaConfiguration": p.mfa})
    }
    fn user_json(name: &str, u: &User) -> Value {
        json!({"Username": name, "Attributes": attrs_json(u), "UserCreateDate": u.created, "UserLastModifiedDate": u.created,
               "Enabled": u.enabled, "UserStatus": u.status})
    }

    fn new_user(&mut self, pool: &str, name: &str, pw: &str, attrs: BTreeMap<String, String>, status: &'static str) -> Result<String, ApiErr> {
        let p = self.pools.get_mut(pool).ok_or_else(|| e("ResourceNotFoundException", "User pool does not exist."))?;
        let sub = uuid::Uuid::new_v4().to_string();
        // With email/phone as username attributes, the given name is that attribute and the username is the sub.
        let (uname, mut attrs) = (if p.username_attrs.is_empty() { name.to_string() } else { sub.clone() }, attrs);
        if let Some(a) = p.username_attrs.first() {
            attrs.entry(a.clone()).or_insert_with(|| name.into());
        }
        if p.find(name).is_some() || p.users.contains_key(&uname) {
            return Err(e("UsernameExistsException", "An account with the given username already exists."));
        }
        let salt = uuid::Uuid::new_v4().simple().to_string();
        let mut u = User { sub, pw: String::new(), srp_v: BigUint::default(), salt, attrs, status, enabled: true, created: epoch(), code: None, totp: None };
        u.set_pw(pool, &uname, pw);
        p.users.insert(uname.clone(), u);
        Ok(uname)
    }

    pub fn handle(&mut self, op: &str, r: &Value) -> Result<Value, ApiErr> {
        let pool_id = r["UserPoolId"].as_str().unwrap_or("").to_string();
        let no_pool = || e("ResourceNotFoundException", "User pool does not exist.");
        let no_user = || e("UserNotFoundException", "User does not exist.");
        Ok(match op {
            "CreateUserPool" => {
                let id = format!("{}_{}", *REGION, &uuid::Uuid::new_v4().simple().to_string()[..9]);
                let strs = |k: &str| r[k].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>();
                let lambda_config = TRIGGERS.iter().filter_map(|t| r["LambdaConfig"][t].as_str().map(|v| (t.to_string(), v.to_string()))).collect();
                let mfa: &'static str = match r["MfaConfiguration"].as_str().unwrap_or("OFF") {
                    "OFF" => "OFF",
                    "OPTIONAL" => "OPTIONAL",
                    "ON" => "ON",
                    _ => return Err(e("InvalidParameterException", "MfaConfiguration must be OFF, OPTIONAL or ON")),
                };
                let p = Pool { name: need(r, "PoolName")?.into(), created: epoch(), users: BTreeMap::new(),
                    policy: r["Policies"]["PasswordPolicy"].clone().as_object().map_or(json!({"MinimumLength": 8}), |o| json!(o)),
                    username_attrs: strs("UsernameAttributes"), auto_verified: strs("AutoVerifiedAttributes"),
                    groups: BTreeMap::new(), lambda_config, mfa };
                let out = json!({"UserPool": Self::pool_json(&id, &p)});
                self.pools.insert(id, p);
                out
            }
            "UpdateUserPool" => {
                let p = self.pools.get_mut(&pool_id).ok_or_else(no_pool)?;
                for t in TRIGGERS {
                    match r["LambdaConfig"][t].as_str() {
                        Some(v) => { p.lambda_config.insert(t.into(), v.into()); }
                        None if r["LambdaConfig"].as_object().is_some_and(|o| o.contains_key(t)) => { p.lambda_config.remove(t); }
                        None => {}
                    }
                }
                json!({})
            }
            "DescribeUserPool" => json!({"UserPool": Self::pool_json(&pool_id, self.pools.get(&pool_id).ok_or_else(no_pool)?)}),
            "ListUserPools" => json!({"UserPools": self.pools.iter().map(|(i, p)| json!({"Id": i, "Name": p.name, "CreationDate": p.created})).collect::<Vec<_>>()}),
            "DeleteUserPool" => {
                self.pools.remove(&pool_id).ok_or_else(no_pool)?;
                self.clients.retain(|_, c| c.pool != pool_id);
                json!({})
            }
            "CreateUserPoolClient" => {
                self.pools.get(&pool_id).ok_or_else(no_pool)?;
                let id = uuid::Uuid::new_v4().simple().to_string()[..26].to_string();
                let secret = (r["GenerateSecret"] == true).then(|| b64(&crate::rand_bytes(36)).replace(['+', '/', '='], "x"));
                let c = Client { name: need(r, "ClientName")?.into(), pool: pool_id.clone(), secret: secret.clone() };
                let mut out = json!({"ClientId": id, "ClientName": c.name, "UserPoolId": pool_id, "ExplicitAuthFlows": r["ExplicitAuthFlows"]});
                if let Some(s) = secret {
                    out["ClientSecret"] = s.into();
                }
                self.clients.insert(id, c);
                json!({ "UserPoolClient": out })
            }
            "DescribeUserPoolClient" => {
                let (id, c) = self.client(r)?;
                let mut out = json!({"ClientId": id, "ClientName": c.name, "UserPoolId": c.pool});
                if let Some(s) = &c.secret {
                    out["ClientSecret"] = s.clone().into();
                }
                json!({ "UserPoolClient": out })
            }
            "ListUserPoolClients" => json!({"UserPoolClients": self.clients.iter().filter(|(_, c)| c.pool == pool_id)
                .map(|(i, c)| json!({"ClientId": i, "ClientName": c.name, "UserPoolId": c.pool})).collect::<Vec<_>>()}),
            "DeleteUserPoolClient" => {
                self.clients.remove(need(r, "ClientId")?);
                json!({})
            }
            "SignUp" => {
                let (cid, c) = self.client(r)?;
                let pool = c.pool.clone();
                let (name, pw) = (need(r, "Username")?, need(r, "Password")?);
                Self::check_secret(c, &cid, name, r["SecretHash"].as_str())?;
                self.pools[&pool].check_policy(pw)?;
                let uname = self.new_user(&pool, name, pw, attrs_of(&r["UserAttributes"]), "UNCONFIRMED")?;
                let code = new_code();
                let u = self.pools.get_mut(&pool).unwrap().users.get_mut(&uname).unwrap();
                u.code = Some(code.clone());
                let dest = u.attrs.get("email").cloned().unwrap_or_default();
                let sub = u.sub.clone();
                self.codes.push((name.into(), code));
                // PreSignUp response markers (set by main.rs after running the trigger).
                let mut confirmed = false;
                if r["__rcConfirm"] == true {
                    (u.status, u.code) = ("CONFIRMED", None);
                    if u.attrs.contains_key("email") {
                        u.attrs.insert("email_verified".into(), "true".into());
                    }
                    confirmed = true;
                }
                if r["__rcVerifyEmail"] == true && u.attrs.contains_key("email") {
                    u.attrs.insert("email_verified".into(), "true".into());
                }
                if confirmed {
                    self.push_post_confirmation(&pool, &uname);
                }
                json!({"UserConfirmed": confirmed, "UserSub": sub, "CodeDeliveryDetails": {"Destination": dest, "DeliveryMedium": "EMAIL", "AttributeName": "email"}})
            }
            "ConfirmSignUp" | "ConfirmForgotPassword" => {
                let (_, c) = self.client(r)?;
                let pool = c.pool.clone();
                let p = self.pools.get_mut(&pool).ok_or_else(no_pool)?;
                let uname = p.find(need(r, "Username")?).ok_or_else(no_user)?;
                let u = p.users.get_mut(&uname).unwrap();
                if u.code.as_deref() != Some(need(r, "ConfirmationCode")?) {
                    return Err(e("CodeMismatchException", "Invalid verification code provided, please try again."));
                }
                if op == "ConfirmForgotPassword" {
                    let pw = need(r, "Password")?;
                    self.pools[&pool].check_policy(pw)?;
                    let u = self.pools.get_mut(&pool).unwrap().users.get_mut(&uname).unwrap();
                    u.set_pw(&pool, &uname, pw);
                    u.code = None;
                } else {
                    (u.status, u.code) = ("CONFIRMED", None);
                    if u.attrs.contains_key("email") {
                        u.attrs.insert("email_verified".into(), "true".into());
                    }
                    let pool_c = pool.clone();
                    let uname_c = uname.clone();
                    self.push_post_confirmation(&pool_c, &uname_c);
                }
                json!({})
            }
            "ForgotPassword" => {
                let (_, c) = self.client(r)?;
                let pool = c.pool.clone();
                let name = need(r, "Username")?;
                let p = self.pools.get_mut(&pool).ok_or_else(no_pool)?;
                let uname = p.find(name).ok_or_else(no_user)?;
                let code = new_code();
                let u = p.users.get_mut(&uname).unwrap();
                u.code = Some(code.clone());
                let dest = u.attrs.get("email").cloned().unwrap_or_default();
                self.codes.push((name.into(), code));
                json!({"CodeDeliveryDetails": {"Destination": dest, "DeliveryMedium": "EMAIL", "AttributeName": "email"}})
            }
            "AdminConfirmSignUp" => {
                let p = self.pools.get_mut(&pool_id).ok_or_else(no_pool)?;
                let uname = p.find(need(r, "Username")?).ok_or_else(no_user)?;
                p.users.get_mut(&uname).unwrap().status = "CONFIRMED";
                json!({})
            }
            "AdminCreateUser" => {
                let name = need(r, "Username")?;
                let temp = r["TemporaryPassword"].as_str().map_or_else(|| format!("Tmp-{}a1!", &uuid::Uuid::new_v4().simple().to_string()[..8]), String::from);
                let uname = self.new_user(&pool_id, name, &temp, attrs_of(&r["UserAttributes"]), "FORCE_CHANGE_PASSWORD")?;
                json!({"User": Self::user_json(&uname, &self.pools[&pool_id].users[&uname])})
            }
            "AdminSetUserPassword" => {
                let p = self.pools.get_mut(&pool_id).ok_or_else(no_pool)?;
                let uname = p.find(need(r, "Username")?).ok_or_else(no_user)?;
                let pw = need(r, "Password")?;
                p.check_policy(pw)?;
                let u = p.users.get_mut(&uname).unwrap();
                u.set_pw(&pool_id, &uname, pw);
                u.status = if r["Permanent"] == true { "CONFIRMED" } else { "FORCE_CHANGE_PASSWORD" };
                json!({})
            }
            "AdminGetUser" => {
                let p = self.pools.get(&pool_id).ok_or_else(no_pool)?;
                let uname = p.find(need(r, "Username")?).ok_or_else(no_user)?;
                let mut v = Self::user_json(&uname, &p.users[&uname]);
                v["UserAttributes"] = v["Attributes"].take();
                v.as_object_mut().unwrap().remove("Attributes");
                v
            }
            "AdminDeleteUser" => {
                let p = self.pools.get_mut(&pool_id).ok_or_else(no_pool)?;
                let uname = p.find(need(r, "Username")?).ok_or_else(no_user)?;
                p.users.remove(&uname);
                json!({})
            }
            "AdminDisableUser" | "AdminEnableUser" => {
                let p = self.pools.get_mut(&pool_id).ok_or_else(no_pool)?;
                let uname = p.find(need(r, "Username")?).ok_or_else(no_user)?;
                p.users.get_mut(&uname).unwrap().enabled = op == "AdminEnableUser";
                json!({})
            }
            "AdminUpdateUserAttributes" => {
                let p = self.pools.get_mut(&pool_id).ok_or_else(no_pool)?;
                let uname = p.find(need(r, "Username")?).ok_or_else(no_user)?;
                p.users.get_mut(&uname).unwrap().attrs.extend(attrs_of(&r["UserAttributes"]));
                json!({})
            }
            "ListUsers" => {
                let p = self.pools.get(&pool_id).ok_or_else(no_pool)?;
                json!({"Users": p.users.iter().map(|(n, u)| Self::user_json(n, u)).collect::<Vec<_>>()})
            }
            "CreateGroup" => {
                let p = self.pools.get_mut(&pool_id).ok_or_else(no_pool)?;
                let name = need(r, "GroupName")?;
                if p.groups.contains_key(name) {
                    return Err(e("GroupExistsException", "A group with the same name already exists."));
                }
                let g = Group { description: r["Description"].as_str().unwrap_or("").into(), precedence: r["Precedence"].as_i64().unwrap_or(0),
                                role_arn: r["RoleArn"].as_str().unwrap_or("").into(), members: BTreeSet::new() };
                let out = json!({"Group": g.json(name, &pool_id)});
                p.groups.insert(name.into(), g);
                out
            }
            "GetGroup" => {
                let p = self.pools.get(&pool_id).ok_or_else(no_pool)?;
                let g = p.groups.get(need(r, "GroupName")?).ok_or_else(|| e("ResourceNotFoundException", "Group does not exist."))?;
                json!({"Group": g.json(need(r, "GroupName")?, &pool_id)})
            }
            "ListGroups" => {
                let p = self.pools.get(&pool_id).ok_or_else(no_pool)?;
                json!({"Groups": p.groups.iter().map(|(n, g)| g.json(n, &pool_id)).collect::<Vec<_>>()})
            }
            "DeleteGroup" => {
                let p = self.pools.get_mut(&pool_id).ok_or_else(no_pool)?;
                p.groups.remove(need(r, "GroupName")?).ok_or_else(|| e("ResourceNotFoundException", "Group does not exist."))?;
                json!({})
            }
            "AdminAddUserToGroup" | "AdminRemoveUserFromGroup" => {
                let p = self.pools.get_mut(&pool_id).ok_or_else(no_pool)?;
                let uname = p.find(need(r, "Username")?).ok_or_else(no_user)?;
                let g = p.groups.get_mut(need(r, "GroupName")?).ok_or_else(|| e("ResourceNotFoundException", "Group does not exist."))?;
                if op == "AdminAddUserToGroup" { g.members.insert(uname); } else { g.members.remove(&uname); }
                json!({})
            }
            "AdminListGroupsForUser" => {
                let p = self.pools.get(&pool_id).ok_or_else(no_pool)?;
                let uname = p.find(need(r, "Username")?).ok_or_else(no_user)?;
                json!({"Groups": p.groups.iter().filter(|(_, g)| g.members.contains(&uname)).map(|(n, g)| g.json(n, &pool_id)).collect::<Vec<_>>()})
            }
            "InitiateAuth" | "RespondToAuthChallenge" if r.get("__rcCustom").is_some() => self.custom_step(r)?,
            "InitiateAuth" | "AdminInitiateAuth" => {
                let (cid, c) = self.client(r)?;
                let pool = c.pool.clone();
                if op == "AdminInitiateAuth" && pool != pool_id {
                    return Err(e("ResourceNotFoundException", "User pool client does not belong to this pool."));
                }
                let p = &r["AuthParameters"];
                match r["AuthFlow"].as_str().unwrap_or("") {
                    "USER_PASSWORD_AUTH" | "ADMIN_USER_PASSWORD_AUTH" | "ADMIN_NO_SRP_AUTH" => {
                        let name = p["USERNAME"].as_str().ok_or_else(|| e("InvalidParameterException", "Missing required parameter USERNAME"))?;
                        Self::check_secret(c, &cid, name, p["SECRET_HASH"].as_str())?;
                        self.password_auth(&pool, &cid, name, p["PASSWORD"].as_str().unwrap_or(""))?
                    }
                    "USER_SRP_AUTH" if op == "InitiateAuth" => {
                        let name = p["USERNAME"].as_str().ok_or_else(|| e("InvalidParameterException", "Missing required parameter USERNAME"))?;
                        let a = p["SRP_A"].as_str().ok_or_else(|| e("InvalidParameterException", "Missing required parameter SRP_A"))?;
                        Self::check_secret(c, &cid, name, p["SECRET_HASH"].as_str())?;
                        let uname = self.pools[&pool].find(name).ok_or_else(|| e("UserNotFoundException", "User does not exist."))?;
                        let u = &self.pools[&pool].users[&uname];
                        let (b, key) = srp_server(a, &u.srp_v).ok_or_else(|| e("InvalidParameterException", "SRP_A is not a valid SRP public value"))?;
                        let salt = u.salt.clone();
                        let block = b64(&crate::rand_bytes(64));
                        let now = epoch();
                        self.srp.retain(|_, s| s.expires > now);
                        self.srp.insert(block.clone(), SrpPending { pool: pool.clone(), user: uname.clone(), client: cid.clone(), key, expires: now + 300.0 });
                        json!({"ChallengeName": "PASSWORD_VERIFIER", "ChallengeParameters": {"SALT": salt, "SRP_B": b.to_str_radix(16),
                               "SECRET_BLOCK": block, "USER_ID_FOR_SRP": uname, "USERNAME": uname}})
                    }
                    "DEVICE_SRP_AUTH" => return Err(e("InvalidParameterException", "DEVICE_SRP_AUTH is not supported locally (no device tracking)")),
                    "REFRESH_TOKEN_AUTH" | "REFRESH_TOKEN" => {
                        let rt = p["REFRESH_TOKEN"].as_str().unwrap_or("");
                        let (pool, user, client) = self.refresh.get(rt).cloned().filter(|(_, _, c)| *c == cid)
                            .ok_or_else(|| e("NotAuthorizedException", "Invalid Refresh Token"))?;
                        if !self.pools.get(&pool).is_some_and(|p| p.users.contains_key(&user)) {
                            return Err(e("NotAuthorizedException", "Refresh Token has been revoked"));
                        }
                        self.tokens(&pool, &user, &client, false)
                    }
                    f => return Err(e("InvalidParameterException", &format!("Auth flow {f} is not supported locally"))),
                }
            }
            "RespondToAuthChallenge" if r["ChallengeName"] == "PASSWORD_VERIFIER" => {
                // The SECRET_BLOCK identifies the handshake (clients send no Session here); one try per block.
                let cr = &r["ChallengeResponses"];
                let block = cr["PASSWORD_CLAIM_SECRET_BLOCK"].as_str().unwrap_or("");
                let st = self.srp.remove(block).filter(|s| s.expires > epoch()).ok_or_else(|| e("NotAuthorizedException", "Invalid session for the user."))?;
                let (cid, c) = self.client(r)?;
                if cid != st.client {
                    return Err(e("NotAuthorizedException", "Invalid session for the user."));
                }
                Self::check_secret(c, &cid, cr["USERNAME"].as_str().unwrap_or(&st.user), cr["SECRET_HASH"].as_str())?;
                let raw = base64::engine::general_purpose::STANDARD.decode(block).unwrap_or_default();
                let want = srp_signature(&st.key, &st.pool, &st.user, &raw, cr["TIMESTAMP"].as_str().unwrap_or(""));
                if cr["PASSWORD_CLAIM_SIGNATURE"].as_str() != Some(want.as_str()) {
                    return Err(bad_login());
                }
                // ponytail: TIMESTAMP is signed but its clock value is not checked; the 5-minute block expiry bounds replays.
                self.after_password(&st.pool, &st.client, st.user)?
            }
            "RespondToAuthChallenge" | "AdminRespondToAuthChallenge" => {
                let (pool, user, client) = self.sessions.remove(need(r, "Session")?).ok_or_else(|| e("NotAuthorizedException", "Invalid session for the user."))?;
                if r["ChallengeName"] == "SOFTWARE_TOKEN_MFA" {
                    let code = r["ChallengeResponses"]["SOFTWARE_MFA_CODE"].as_str().ok_or_else(|| e("InvalidParameterException", "SOFTWARE_MFA_CODE is required"))?;
                    let session = need(r, "Session")?.to_string();
                    let ok = self.pools[&pool].users.get(&user).is_some_and(|u| u.totp.as_ref().is_some_and(|t| totp_matches(&t.secret, code)));
                    if !ok {
                        // keep the session so the client can retry with a fresh code
                        self.sessions.insert(session, (pool, user, client));
                        return Err(e("CodeMismatchException", "Invalid code or authentication failed."));
                    }
                    return Ok(self.tokens(&pool, &user, &client, true));
                }
                if r["ChallengeName"] != "NEW_PASSWORD_REQUIRED" {
                    return Err(e("InvalidParameterException", "Only NEW_PASSWORD_REQUIRED and SOFTWARE_TOKEN_MFA are supported locally"));
                }
                let pw = r["ChallengeResponses"]["NEW_PASSWORD"].as_str().ok_or_else(|| e("InvalidParameterException", "NEW_PASSWORD is required"))?;
                self.pools[&pool].check_policy(pw)?;
                let u = self.pools.get_mut(&pool).unwrap().users.get_mut(&user).unwrap();
                u.set_pw(&pool, &user, pw);
                u.status = "CONFIRMED";
                self.tokens(&pool, &user, &client, true)
            }
            "AssociateSoftwareToken" | "AdminAssociateSoftwareToken" => {
                let (pool, user) = if op == "AssociateSoftwareToken" {
                    self.user_from_token(r)?
                } else {
                    let pool = pool_id.to_string();
                    let name = need(r, "Username")?;
                    let uname = self.pools.get(&pool).ok_or_else(|| e("ResourceNotFoundException", "User pool does not exist."))?.find(name).ok_or_else(|| e("UserNotFoundException", "User does not exist."))?.to_string();
                    (pool, uname)
                };
                // A fresh secret replaces any old enrollment (unverified until VerifySoftwareToken).
                let secret: String = (0..2).map(|_| uuid::Uuid::new_v4().simple().to_string()).collect();
                let raw: Vec<u8> = (0..secret.len() / 2).map(|i| u8::from_str_radix(&secret[i * 2..i * 2 + 2], 16).unwrap_or(0)).collect();
                let u = self.pools.get_mut(&pool).unwrap().users.get_mut(&user).unwrap();
                u.totp = Some(Totp { secret, verified: false, preferred: false });
                json!({"SecretCode": base32(&raw)})
            }
            "VerifySoftwareToken" | "AdminVerifySoftwareToken" => {
                let (pool, user) = self.user_from_token(r)?;
                let code = need(r, "UserCode")?;
                let u = self.pools.get_mut(&pool).unwrap().users.get_mut(&user).unwrap();
                let t = u.totp.as_mut().ok_or_else(|| e("InvalidParameterException", "No software token is associated"))?;
                if !totp_matches(&t.secret, code) {
                    return Err(e("CodeMismatchException", "Invalid code or authentication failed."));
                }
                t.verified = true;
                json!({"Status": "SUCCESS"})
            }
            "SetUserMFAPreference" | "AdminSetUserMFAPreference" => {
                let (pool, user) = if op == "SetUserMFAPreference" {
                    self.user_from_token(r)?
                } else {
                    let pool = pool_id.to_string();
                    let name = need(r, "Username")?;
                    let uname = self.pools.get(&pool).ok_or_else(|| e("ResourceNotFoundException", "User pool does not exist."))?.find(name).ok_or_else(|| e("UserNotFoundException", "User does not exist."))?.to_string();
                    (pool, uname)
                };
                // botocore sends SoftwareTokenMfaSettings (lowercase "fa"); accept both spellings.
                let s = r.get("SoftwareTokenMfaSettings").or_else(|| r.get("SoftwareTokenMFASettings")).unwrap_or(&Value::Null);
                let enabled = s["Enabled"].as_bool().unwrap_or(false);
                let preferred = s.get("PreferredMfa").or(s.get("PreferredMFA")).and_then(Value::as_bool).unwrap_or(false);
                let u = self.pools.get_mut(&pool).unwrap().users.get_mut(&user).unwrap();
                match u.totp.as_mut() {
                    Some(t) => {
                        if enabled {
                            // enabling implies the token is usable (AWS requires verification first)
                            if !t.verified && preferred {
                                return Err(e("InvalidParameterException", "Software token must be verified before becoming the preferred MFA"));
                            }
                            t.preferred = preferred || enabled;
                        } else {
                            t.preferred = false;
                        }
                    }
                    None => return Err(e("InvalidParameterException", "No software token is associated")),
                }
                json!({})
            }
            "SetUserPoolMfaConfig" => {
                let p = self.pools.get_mut(&pool_id).ok_or_else(|| e("ResourceNotFoundException", "User pool does not exist."))?;
                let m: &'static str = match r["MfaConfiguration"].as_str().unwrap_or("OFF") {
                    "OFF" => "OFF",
                    "OPTIONAL" => "OPTIONAL",
                    "ON" => "ON",
                    _ => return Err(e("InvalidParameterException", "MfaConfiguration must be OFF, OPTIONAL or ON")),
                };
                p.mfa = m;
                json!({"MfaConfiguration": p.mfa, "SoftwareTokenMfaConfiguration": {"Enabled": p.mfa != "OFF"}})
            }
            "GetUserPoolMfaConfig" => {
                let p = self.pools.get(&pool_id).ok_or_else(|| e("ResourceNotFoundException", "User pool does not exist."))?;
                json!({"MfaConfiguration": p.mfa, "SoftwareTokenMfaConfiguration": {"Enabled": p.mfa != "OFF"}})
            }
            "GetUser" => {
                let (pool, user) = self.user_from_token(r)?;
                json!({"Username": user, "UserAttributes": attrs_json(&self.pools[&pool].users[&user])})
            }
            "ChangePassword" => {
                let (pool, user) = self.user_from_token(r)?;
                let (old, new) = (need(r, "PreviousPassword")?, need(r, "ProposedPassword")?);
                self.pools[&pool].check_policy(new)?;
                let u = self.pools.get_mut(&pool).unwrap().users.get_mut(&user).unwrap();
                if hash_pw(&u.salt, old) != u.pw {
                    return Err(bad_login());
                }
                u.set_pw(&pool, &user, new);
                json!({})
            }
            "GlobalSignOut" => {
                let (pool, user) = self.user_from_token(r)?;
                self.refresh.retain(|_, (p, u, _)| !(*p == pool && *u == user));
                json!({})
            }
            _ => return Err(err("UnknownOperationException", format!("{op} is not supported yet"))),
        })
    }

    pub fn admin(&self) -> Value {
        self.pools
            .iter()
            .map(|(id, p)| {
                let rows: Vec<Value> = p.users.iter().map(|(n, u)| {
                    let label = u.attrs.get("email").map_or(n.clone(), |m| format!("{m} ({n})"));
                    json!([label, u.status, if u.enabled { "사용" } else { "중지" }, u.code.clone().unwrap_or_default()])
                }).collect();
                let clients: Vec<&str> = self.clients.iter().filter(|(_, c)| c.pool == *id).map(|(_, c)| c.name.as_str()).collect();
                json!({"name": p.name, "count": rows.len(), "sub": format!("{id} · 앱 클라이언트 {} · 발급자 {}", clients.join(", "), issuer(id)),
                       "cols": ["사용자", "상태", "활성", "대기 중인 확인 코드"], "rows": rows})
            })
            .collect()
    }
}

// Discovery document so OIDC/JWT libraries can find the JWKS.
pub fn openid_config(pool: &str) -> Value {
    let iss = issuer(pool);
    json!({"issuer": iss, "jwks_uri": format!("{iss}/.well-known/jwks.json"), "id_token_signing_alg_values_supported": ["RS256"],
           "response_types_supported": ["code", "token"], "subject_types_supported": ["public"]})
}

#[cfg(test)]
mod tests {
    #[test]
    fn hmac_known_vector() {
        // RFC 4231 test case 2
        let mac = super::hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(mac.iter().map(|b| format!("{b:02x}")).collect::<String>(), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    // RFC 6238 test vectors (SHA-1, truncated to 6 digits as Cognito uses).
    #[test]
    fn totp_rfc6238_vectors() {
        use super::{base32, totp_at};
        let secret = b"12345678901234567890";
        assert_eq!(totp_at(secret, 59 / 30), "287082");
        assert_eq!(totp_at(secret, 1111111109 / 30), "081804");
        assert_eq!(totp_at(secret, 1111111111 / 30), "050471");
        assert_eq!(totp_at(secret, 1234567890 / 30), "005924");
        assert_eq!(totp_at(secret, 2000000000 / 30), "279037");
        assert_eq!(totp_at(secret, 20000000000 / 30), "353130");
        assert_eq!(base32(&[0xf8, 0x1d, 0x4f, 0xa8]), "7AOU7KA=");
    }

    #[test]
    fn jwt_sign_and_verify() {
        let now = crate::epoch().floor();
        let tok = super::sign(&serde_json::json!({"sub": "u1", "aud": "c1", "iss": super::issuer("p1"), "exp": now + 60.0}));
        let c = super::verify(&tok).expect("valid token");
        assert_eq!(c["sub"], "u1");
        // Tampered payload must fail
        let mut parts: Vec<&str> = tok.split('.').collect();
        let bad_payload = super::b64url(br#"{"sub":"evil","exp":9999999999}"#);
        parts[1] = &bad_payload;
        assert!(super::verify(&parts.join(".")).is_none());
        // Expired token must fail
        let exp = super::sign(&serde_json::json!({"sub": "u1", "exp": now - 10.0}));
        assert!(super::verify(&exp).is_none());
    }

    #[test]
    fn groups_triggers_and_tokens() {
        use serde_json::json;
        let mut c = super::Cognito::default();
        let pool = c.handle("CreateUserPool", &json!({"PoolName": "p", "LambdaConfig": {"PreSignUp": "fn:pre", "PreTokenGeneration": "fn:tok"}}))
            .unwrap()["UserPool"]["Id"].as_str().unwrap().to_string();
        let cid = c.handle("CreateUserPoolClient", &json!({"UserPoolId": pool, "ClientName": "web"}))
            .unwrap()["UserPoolClient"]["ClientId"].as_str().unwrap().to_string();

        // Groups CRUD
        assert_eq!(c.handle("CreateGroup", &json!({"UserPoolId": pool, "GroupName": "admins", "Precedence": 1})).unwrap()["Group"]["GroupName"], "admins");
        assert_eq!(c.handle("CreateGroup", &json!({"UserPoolId": pool, "GroupName": "admins"})).unwrap_err().code, "GroupExistsException");
        assert_eq!(c.handle("GetGroup", &json!({"UserPoolId": pool, "GroupName": "admins"})).unwrap()["Group"]["Precedence"], 1);
        assert_eq!(c.handle("ListGroups", &json!({"UserPoolId": pool})).unwrap()["Groups"].as_array().unwrap().len(), 1);

        // User → group → token claim
        c.handle("SignUp", &json!({"ClientId": cid, "Username": "u1", "Password": "Str0ng!pass", "UserAttributes": []})).unwrap();
        c.handle("AdminConfirmSignUp", &json!({"UserPoolId": pool, "Username": "u1"})).unwrap();
        assert_eq!(c.triggers.len(), 0, "no PostConfirmation configured → no trigger from confirm");
        c.handle("AdminAddUserToGroup", &json!({"UserPoolId": pool, "Username": "u1", "GroupName": "admins"})).unwrap();
        assert_eq!(c.handle("AdminListGroupsForUser", &json!({"UserPoolId": pool, "Username": "u1"})).unwrap()["Groups"][0]["GroupName"], "admins");
        let auth = c.handle("InitiateAuth", &json!({"ClientId": cid, "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"USERNAME": "u1", "PASSWORD": "Str0ng!pass"}})).unwrap();
        let claims = super::verify(auth["AuthenticationResult"]["IdToken"].as_str().unwrap()).unwrap();
        assert_eq!(claims["cognito:groups"], json!(["admins"]));
        let tok_trigger = c.take_triggers();
        assert_eq!(tok_trigger[0].kind, "PreTokenGeneration");
        assert_eq!(tok_trigger[0].event["request"]["groupConfiguration"]["groupsToOverride"], json!(["admins"]));

        // Claim overrides via reissue: add + suppress
        let fresh = c.reissue_tokens(&tok_trigger[0], Some(json!({"department": "eng"}).as_object().unwrap().clone()), &["cognito:username".to_string()]);
        let fresh_claims = super::verify(fresh["AuthenticationResult"]["IdToken"].as_str().unwrap()).unwrap();
        assert_eq!(fresh_claims["department"], "eng");
        assert!(fresh_claims.get("cognito:username").is_none());

        // Leaving the group drops the claim; PreSignUp event shape
        c.handle("AdminRemoveUserFromGroup", &json!({"UserPoolId": pool, "Username": "u1", "GroupName": "admins"})).unwrap();
        let auth2 = c.handle("InitiateAuth", &json!({"ClientId": cid, "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"USERNAME": "u1", "PASSWORD": "Str0ng!pass"}})).unwrap();
        assert_eq!(super::verify(auth2["AuthenticationResult"]["IdToken"].as_str().unwrap()).unwrap()["cognito:groups"], json!([]));
        c.handle("DeleteGroup", &json!({"UserPoolId": pool, "GroupName": "admins"})).unwrap();
        assert_eq!(c.handle("ListGroups", &json!({"UserPoolId": pool})).unwrap()["Groups"].as_array().unwrap().len(), 0);

        let pre = c.presignup_event(&json!({"ClientId": cid, "Username": "new", "UserAttributes": []})).unwrap();
        assert_eq!((pre.kind, pre.fn_name.as_str(), pre.event["triggerSource"].as_str().unwrap()), ("PreSignUp", "fn:pre", "PreSignUp_SignUp"));
    }

    // USER_SRP_AUTH end to end with a client-side SRP computed here (the amazon-cognito-identity-js formulas).
    #[test]
    fn srp_password_verifier() {
        use super::*;
        let mut c = Cognito::default();
        let pool = c.handle("CreateUserPool", &json!({"PoolName": "p"})).unwrap()["UserPool"]["Id"].as_str().unwrap().to_string();
        let cid = c.handle("CreateUserPoolClient", &json!({"UserPoolId": pool, "ClientName": "web"})).unwrap()["UserPoolClient"]["ClientId"].as_str().unwrap().to_string();
        c.handle("AdminCreateUser", &json!({"UserPoolId": pool, "Username": "srp1"})).unwrap();
        c.handle("AdminSetUserPassword", &json!({"UserPoolId": pool, "Username": "srp1", "Password": "Str0ng!pass", "Permanent": true})).unwrap();
        let login = |c: &mut Cognito, pw: &str| {
            let (n, g, k) = &*N_G_K;
            let a = BigUint::from_bytes_be(&crate::rand_bytes(32));
            let big_a = g.modpow(&a, n);
            let ch = c.handle("InitiateAuth", &json!({"ClientId": cid, "AuthFlow": "USER_SRP_AUTH",
                "AuthParameters": {"USERNAME": "srp1", "SRP_A": big_a.to_str_radix(16)}})).unwrap();
            assert_eq!(ch["ChallengeName"], "PASSWORD_VERIFIER");
            let p = &ch["ChallengeParameters"];
            let b = BigUint::parse_bytes(p["SRP_B"].as_str().unwrap().as_bytes(), 16).unwrap();
            let salt = BigUint::parse_bytes(p["SALT"].as_str().unwrap().as_bytes(), 16).unwrap();
            let user = p["USER_ID_FOR_SRP"].as_str().unwrap();
            let u = hex_hash(&format!("{}{}", pad_hex(&big_a), pad_hex(&b)));
            let x = srp_x(&pool, user, pw, &salt);
            let s = ((&b + n - (k * g.modpow(&x, n)) % n) % n).modpow(&(&a + &u * &x), n);
            let block = p["SECRET_BLOCK"].as_str().unwrap().to_string();
            let raw = base64::engine::general_purpose::STANDARD.decode(&block).unwrap();
            let ts = "Mon Dec 1 09:05:07 UTC 2026";
            let resp = json!({"ClientId": cid, "ChallengeName": "PASSWORD_VERIFIER", "ChallengeResponses": {"USERNAME": user,
                "PASSWORD_CLAIM_SECRET_BLOCK": block, "TIMESTAMP": ts,
                "PASSWORD_CLAIM_SIGNATURE": srp_signature(&srp_key(&s, &u), &pool, user, &raw, ts)}});
            (c.handle("RespondToAuthChallenge", &resp), resp)
        };
        let (ok, resp) = login(&mut c, "Str0ng!pass");
        assert!(verify(ok.unwrap()["AuthenticationResult"]["IdToken"].as_str().unwrap()).is_some());
        // the secret block is single use, a wrong password fails the signature
        assert_eq!(c.handle("RespondToAuthChallenge", &resp).unwrap_err().code, "NotAuthorizedException");
        assert_eq!(login(&mut c, "wrong").0.unwrap_err().code, "NotAuthorizedException");
        // A = 0 (mod N) is rejected before any handshake
        let zero = c.handle("InitiateAuth", &json!({"ClientId": cid, "AuthFlow": "USER_SRP_AUTH", "AuthParameters": {"USERNAME": "srp1", "SRP_A": SRP_N}}));
        assert_eq!(zero.unwrap_err().code, "InvalidParameterException");
    }

    // CUSTOM_AUTH bookkeeping: what handle() does with the trigger outcomes main.rs injects.
    #[test]
    fn custom_auth_steps() {
        use super::*;
        let mut c = Cognito::default();
        let pool = c.handle("CreateUserPool", &json!({"PoolName": "p", "LambdaConfig": {"DefineAuthChallenge": "fn:d", "CreateAuthChallenge": "fn:c",
            "VerifyAuthChallengeResponse": "fn:v"}})).unwrap()["UserPool"]["Id"].as_str().unwrap().to_string();
        let cid = c.handle("CreateUserPoolClient", &json!({"UserPoolId": pool, "ClientName": "web"})).unwrap()["UserPoolClient"]["ClientId"].as_str().unwrap().to_string();
        c.handle("AdminCreateUser", &json!({"UserPoolId": pool, "Username": "q"})).unwrap();
        let init = json!({"ClientId": cid, "AuthFlow": "CUSTOM_AUTH", "AuthParameters": {"USERNAME": "q"}});
        let ctx = c.custom_ctx("InitiateAuth", &init).unwrap().unwrap();
        assert_eq!((ctx.define.as_str(), ctx.session.len()), ("fn:d", 0));
        assert!(c.custom_ctx("InitiateAuth", &json!({"ClientId": cid, "AuthFlow": "USER_PASSWORD_AUTH"})).unwrap().is_none());

        let mut step = init.clone();
        step["__rcCustom"] = json!({"session": [], "define": {"challengeName": "CUSTOM_CHALLENGE"},
                                    "create": {"publicChallengeParameters": {"q": "2+2"}, "privateChallengeParameters": {"a": "4"}, "challengeMetadata": "M"}});
        let ch = c.handle("InitiateAuth", &step).unwrap();
        assert_eq!((ch["ChallengeName"].as_str(), ch["ChallengeParameters"]["q"].as_str()), (Some("CUSTOM_CHALLENGE"), Some("2+2")));
        let resp = json!({"ClientId": cid, "ChallengeName": "CUSTOM_CHALLENGE", "Session": ch["Session"], "ChallengeResponses": {"ANSWER": "4"}});
        let ctx = c.custom_ctx("RespondToAuthChallenge", &resp).unwrap().unwrap();
        assert_eq!((ctx.private["a"].as_str(), ctx.metadata.as_str()), (Some("4"), Some("M")));
        let mut ok = resp.clone();
        ok["__rcCustom"] = json!({"session": [{"challengeResult": true}], "define": {"issueTokens": true}});
        assert!(c.handle("RespondToAuthChallenge", &ok).unwrap()["AuthenticationResult"]["IdToken"].is_string());
        // the session was consumed
        assert_eq!(c.custom_ctx("RespondToAuthChallenge", &resp).err().unwrap().code, "NotAuthorizedException");
        let mut fail = init.clone();
        fail["__rcCustom"] = json!({"define": {"failAuthentication": true}});
        assert_eq!(c.handle("InitiateAuth", &fail).unwrap_err().code, "NotAuthorizedException");
        let mut odd = init;
        odd["__rcCustom"] = json!({"define": {"challengeName": "SMS_MFA"}});
        assert_eq!(c.handle("InitiateAuth", &odd).unwrap_err().code, "InvalidLambdaResponseException");
    }
}

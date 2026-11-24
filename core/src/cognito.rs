// Cognito user pools (JSON 1.1): users, app clients, password auth and RS256 JWTs with a JWKS endpoint.
// Issuer: {endpoint}/_cognito/{poolId}  (JWKS at /.well-known/jwks.json, discovery at /.well-known/openid-configuration)
// ponytail: no SRP, MFA, hosted UI/OAuth flows, Lambda triggers or groups. Verification codes are published as events.
use crate::{b64, epoch, err, need, ApiErr, ACCOUNT, REGION};
use base64::Engine;
use rsa::{pkcs1v15::{SigningKey, VerifyingKey}, signature::{SignatureEncoding, Signer, Verifier}, traits::PublicKeyParts, RsaPrivateKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
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

fn hash_pw(salt: &str, pw: &str) -> String {
    b64(&Sha256::new().chain_update(salt).chain_update(pw).finalize())
}

struct User {
    sub: String,
    salt: String,
    pw: String,
    attrs: BTreeMap<String, String>,
    status: &'static str, // UNCONFIRMED | CONFIRMED | FORCE_CHANGE_PASSWORD
    enabled: bool,
    created: f64,
    code: Option<String>,
}
struct Pool {
    name: String,
    created: f64,
    users: BTreeMap<String, User>,
    policy: Value,
    username_attrs: Vec<String>,
    auto_verified: Vec<String>,
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
    codes: Vec<(String, String)>,                       // (username, code) to publish as events
}

fn e(code: &str, msg: &str) -> ApiErr {
    err(code, msg)
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
        let u = &self.pools[pool].users[username];
        let now = epoch().floor();
        let mut id = json!({"sub": u.sub, "aud": client, "iss": issuer(pool), "token_use": "id", "cognito:username": username,
                            "auth_time": now, "iat": now, "exp": now + 3600.0, "event_id": uuid::Uuid::new_v4().to_string()});
        for (k, v) in &u.attrs {
            id[k] = if k.ends_with("_verified") { json!(v == "true") } else { json!(v) };
        }
        let access = json!({"sub": u.sub, "client_id": client, "iss": issuer(pool), "token_use": "access", "scope": "aws.cognito.signin.user.admin",
                            "username": username, "auth_time": now, "iat": now, "exp": now + 3600.0, "jti": uuid::Uuid::new_v4().to_string()});
        let mut out = json!({"AccessToken": sign(&access), "IdToken": sign(&id), "ExpiresIn": 3600, "TokenType": "Bearer"});
        if with_refresh {
            let rt = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
            self.refresh.insert(rt.clone(), (pool.into(), username.into(), client.into()));
            out["RefreshToken"] = rt.into();
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
            _ => Ok(self.tokens(pool, &uname, client, true)),
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
               "AutoVerifiedAttributes": p.auto_verified, "EstimatedNumberOfUsers": p.users.len()})
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
        p.users.insert(uname.clone(), User { sub, pw: hash_pw(&salt, pw), salt, attrs, status, enabled: true, created: epoch(), code: None });
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
                let p = Pool { name: need(r, "PoolName")?.into(), created: epoch(), users: BTreeMap::new(),
                    policy: r["Policies"]["PasswordPolicy"].clone().as_object().map_or(json!({"MinimumLength": 8}), |o| json!(o)),
                    username_attrs: strs("UsernameAttributes"), auto_verified: strs("AutoVerifiedAttributes") };
                let out = json!({"UserPool": Self::pool_json(&id, &p)});
                self.pools.insert(id, p);
                out
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
                self.codes.push((name.into(), code));
                json!({"UserConfirmed": false, "UserSub": u.sub, "CodeDeliveryDetails": {"Destination": dest, "DeliveryMedium": "EMAIL", "AttributeName": "email"}})
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
                    u.pw = hash_pw(&u.salt, pw);
                    u.code = None;
                } else {
                    (u.status, u.code) = ("CONFIRMED", None);
                    if u.attrs.contains_key("email") {
                        u.attrs.insert("email_verified".into(), "true".into());
                    }
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
                u.pw = hash_pw(&u.salt, pw);
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
                    "REFRESH_TOKEN_AUTH" | "REFRESH_TOKEN" => {
                        let rt = p["REFRESH_TOKEN"].as_str().unwrap_or("");
                        let (pool, user, client) = self.refresh.get(rt).cloned().filter(|(_, _, c)| *c == cid)
                            .ok_or_else(|| e("NotAuthorizedException", "Invalid Refresh Token"))?;
                        if !self.pools.get(&pool).is_some_and(|p| p.users.contains_key(&user)) {
                            return Err(e("NotAuthorizedException", "Refresh Token has been revoked"));
                        }
                        self.tokens(&pool, &user, &client, false)
                    }
                    f => return Err(e("InvalidParameterException", &format!("Auth flow {f} is not supported locally (no SRP)"))),
                }
            }
            "RespondToAuthChallenge" | "AdminRespondToAuthChallenge" => {
                let (pool, user, client) = self.sessions.remove(need(r, "Session")?).ok_or_else(|| e("NotAuthorizedException", "Invalid session for the user."))?;
                if r["ChallengeName"] != "NEW_PASSWORD_REQUIRED" {
                    return Err(e("InvalidParameterException", "Only NEW_PASSWORD_REQUIRED is supported locally"));
                }
                let pw = r["ChallengeResponses"]["NEW_PASSWORD"].as_str().ok_or_else(|| e("InvalidParameterException", "NEW_PASSWORD is required"))?;
                self.pools[&pool].check_policy(pw)?;
                let u = self.pools.get_mut(&pool).unwrap().users.get_mut(&user).unwrap();
                (u.pw, u.status) = (hash_pw(&u.salt, pw), "CONFIRMED");
                self.tokens(&pool, &user, &client, true)
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
                u.pw = hash_pw(&u.salt, new);
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
}

// API Gateway HTTP APIs (apigatewayv2, REST-JSON) with Lambda proxy integrations and JWT/Lambda authorizers.
// Invoke URL: {endpoint}/_api/{apiId}/[{stage}/]path
// ponytail: REST APIs (v1), HTTP_PROXY integrations and CORS config are not emulated yet.
use crate::{err, ApiErr, App};
use serde_json::{json, Map, Value};
use std::{collections::BTreeMap, sync::Arc};

struct Integ {
    ty: String,
    uri: String,
    fmt: String,
}

#[derive(Clone)]
pub struct Authorizer {
    pub id: String,
    pub name: String,
    pub ty: String, // "JWT" | "REQUEST"
    pub identity_source: Vec<String>,
    pub jwt_issuer: Option<String>,
    pub jwt_audience: Vec<String>,
    pub authorizer_uri: Option<String>,
    pub payload_format: String,
    pub enable_simple_responses: bool,
    pub ttl: u64,
}

struct Route {
    key: String,
    target: String,
    auth_type: String, // "NONE" | "JWT" | "CUSTOM" | "AWS_IAM"
    authorizer_id: Option<String>,
}

struct Api {
    name: String,
    protocol: String,
    created: String,
    routes: BTreeMap<String, Route>,
    integrations: BTreeMap<String, Integ>,
    authorizers: BTreeMap<String, Authorizer>,
    stages: BTreeMap<String, bool>, // name -> auto deploy
}

#[derive(Default)]
pub struct ApiGw {
    apis: BTreeMap<String, Api>,
}

fn short_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..10].to_string()
}
fn nf(what: &str) -> ApiErr {
    ApiErr { status: 404, ..err("NotFoundException", format!("Invalid {what} identifier specified")) }
}
fn api_json(id: &str, a: &Api) -> Value {
    json!({"apiId": id, "name": a.name, "protocolType": a.protocol, "createdDate": a.created,
           "apiEndpoint": format!("{}/_api/{id}", crate::endpoint()), "routeSelectionExpression": "$request.method $request.path"})
}
fn integ_json(id: &str, i: &Integ) -> Value {
    json!({"integrationId": id, "integrationType": i.ty, "integrationUri": i.uri, "payloadFormatVersion": i.fmt, "integrationMethod": "POST"})
}
fn route_json(id: &str, r: &Route) -> Value {
    let mut out = json!({"routeId": id, "routeKey": r.key, "target": r.target, "authorizationType": r.auth_type});
    if let Some(aid) = &r.authorizer_id {
        out["authorizerId"] = json!(aid);
    }
    out
}
fn auth_json(a: &Authorizer) -> Value {
    let mut out = json!({"authorizerId": a.id, "name": a.name, "authorizerType": a.ty, "identitySource": a.identity_source});
    if a.ty == "JWT" {
        out["jwtConfiguration"] = json!({"issuer": a.jwt_issuer.as_deref().unwrap_or(""), "audience": a.jwt_audience});
    } else {
        out["authorizerUri"] = json!(a.authorizer_uri.as_deref().unwrap_or(""));
        out["authorizerPayloadFormatVersion"] = json!(a.payload_format);
        out["enableSimpleResponses"] = json!(a.enable_simple_responses);
        out["authorizerResultTtlInSeconds"] = json!(a.ttl);
    }
    out
}

// Accept only local Cognito pool issuers: http://127.0.0.1:<port>/_cognito/<poolId> or localhost.
// External issuer URLs are never fetched.
pub(crate) fn local_cognito_pool(issuer: &str) -> Option<&str> {
    let s = issuer.trim_end_matches('/');
    let rest = s.strip_prefix("http://127.0.0.1:").or_else(|| s.strip_prefix("http://localhost:"))?;
    let (port, path) = rest.split_once('/')?;
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let pool = path.strip_prefix("_cognito/")?;
    if pool.is_empty() || pool.contains('/') || pool.contains('?') || pool.contains('#') || pool.contains("..") {
        return None;
    }
    Some(pool)
}

// Extract Lambda function name from either a Lambda ARN/name or an API Gateway invoke URI.
fn lambda_fn_of(uri: &str) -> String {
    let inner = uri.strip_suffix("/invocations").unwrap_or(uri);
    let inner = inner.rsplit_once("/functions/").map_or(inner, |(_, f)| f);
    crate::lambda::name_of(inner)
}

fn str_list(v: &Value) -> Vec<String> {
    v.as_array().into_iter().flatten().filter_map(|x| x.as_str().map(String::from)).collect()
}

fn validate_authorizer(a: &Authorizer) -> Result<(), ApiErr> {
    if a.name.is_empty() {
        return Err(err("BadRequestException", "name is required"));
    }
    match a.ty.as_str() {
        "JWT" => {
            let iss = a.jwt_issuer.as_deref().unwrap_or("");
            if iss.is_empty() {
                return Err(err("BadRequestException", "jwtConfiguration.issuer is required"));
            }
            if local_cognito_pool(iss).is_none() {
                return Err(err("BadRequestException", "Only local Cognito issuers ({endpoint}/_cognito/{poolId}) are supported; external issuer URLs are not fetched"));
            }
            if a.jwt_audience.is_empty() {
                return Err(err("BadRequestException", "jwtConfiguration.audience must be non-empty"));
            }
            if a.identity_source.is_empty() {
                return Err(err("BadRequestException", "identitySource is required for JWT authorizer"));
            }
        }
        "REQUEST" => {
            if a.authorizer_uri.as_deref().unwrap_or("").is_empty() {
                return Err(err("BadRequestException", "authorizerUri is required for REQUEST authorizer"));
            }
            if a.payload_format != "2.0" {
                return Err(err("BadRequestException", "Only authorizerPayloadFormatVersion 2.0 is supported locally"));
            }
        }
        other => return Err(err("BadRequestException", format!("Unsupported authorizerType: {other}"))),
    }
    Ok(())
}

fn validate_route_auth(a: &Api, auth_type: &str, authorizer_id: Option<&str>) -> Result<(), ApiErr> {
    match auth_type {
        "NONE" | "AWS_IAM" => Ok(()),
        "JWT" | "CUSTOM" => {
            let aid = authorizer_id.filter(|s| !s.is_empty()).ok_or_else(|| err("BadRequestException", "authorizerId is required when authorizationType is JWT or CUSTOM"))?;
            let auth = a.authorizers.get(aid).ok_or_else(|| nf("Authorizer"))?;
            let want = if auth_type == "JWT" { "JWT" } else { "REQUEST" };
            if auth.ty != want {
                return Err(err("BadRequestException", format!("AuthorizationType {auth_type} requires a {want} authorizer")));
            }
            Ok(())
        }
        other => Err(err("BadRequestException", format!("Unsupported authorizationType: {other}"))),
    }
}

fn extract_identity(sources: &[String], hdrs: &Map<String, Value>, qs: &Map<String, Value>) -> Option<Vec<String>> {
    let mut out = Vec::with_capacity(sources.len());
    for src in sources {
        let val = if let Some(name) = src.strip_prefix("$request.header.") {
            hdrs.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).and_then(|(_, v)| v.as_str())
        } else if let Some(name) = src.strip_prefix("$request.querystring.") {
            qs.get(name).and_then(Value::as_str)
        } else {
            None
        };
        let v = val.map(str::trim).filter(|s| !s.is_empty())?;
        out.push(v.to_string());
    }
    Some(out)
}

// Path params for `pattern` against `path`, or None. Supports {name} and a trailing {name+}.
fn match_path(pattern: &str, path: &str) -> Option<Map<String, Value>> {
    let (pp, sp): (Vec<&str>, Vec<&str>) = (pattern.trim_matches('/').split('/').collect(), path.trim_matches('/').split('/').collect());
    let mut params = Map::new();
    for (i, p) in pp.iter().enumerate() {
        if let Some(name) = p.strip_prefix('{').and_then(|x| x.strip_suffix("+}")) {
            params.insert(name.into(), sp.get(i..).filter(|r| !r.is_empty() && !r[0].is_empty())?.join("/").into());
            return Some(params);
        }
        let s = sp.get(i)?;
        match p.strip_prefix('{').and_then(|x| x.strip_suffix('}')) {
            Some(name) => {
                if s.is_empty() {
                    return None;
                }
                params.insert(name.into(), crate::s3::pct_decode(s).into());
            }
            None if p == s => {}
            None => return None,
        }
    }
    (pp.len() == sp.len()).then_some(params)
}

pub struct Target {
    pub route_key: String,
    pub stage: String,
    pub path: String,
    pub function: Option<String>,
    pub params: Map<String, Value>,
    pub authorizer: Option<Authorizer>,
}

impl ApiGw {
    // Pick the most specific route for a request under /_api/{api}/...
    pub fn resolve(&self, api: &str, method: &str, rest: &str) -> Option<Target> {
        let a = self.apis.get(api)?;
        let first = rest.trim_start_matches('/').split('/').next().unwrap_or("");
        let (stage, path) = if !first.is_empty() && first != "$default" && a.stages.contains_key(first) {
            (first.to_string(), rest.trim_start_matches('/')[first.len()..].to_string())
        } else {
            ("$default".to_string(), rest.to_string())
        };
        let path = if path.is_empty() { "/".to_string() } else { path };
        let mut best: Option<((usize, bool, bool), &Route, Map<String, Value>)> = None;
        for route in a.routes.values() {
            let key = &route.key;
            let (score, params) = if key == "$default" {
                ((0, false, false), Map::new())
            } else {
                let (m, p) = key.split_once(' ').unwrap_or(("ANY", key));
                if m != "ANY" && !m.eq_ignore_ascii_case(method) {
                    continue;
                }
                let Some(params) = match_path(p, &path) else { continue };
                let literals = p.split('/').filter(|s| !s.is_empty() && !s.starts_with('{')).count();
                ((literals + 1, !p.contains("+}"), m != "ANY"), params)
            };
            if best.as_ref().is_none_or(|b| score > b.0) {
                best = Some((score, route, params));
            }
        }
        let (_, route, params) = best?;
        let function = route.target.strip_prefix("integrations/").and_then(|i| a.integrations.get(i)).filter(|i| i.ty == "AWS_PROXY").map(|i| lambda_fn_of(&i.uri));
        let authorizer = if matches!(route.auth_type.as_str(), "JWT" | "CUSTOM") {
            route.authorizer_id.as_deref().and_then(|aid| a.authorizers.get(aid)).cloned()
        } else {
            None
        };
        Some(Target { route_key: route.key.clone(), stage, path, function, params, authorizer })
    }

    // Control plane. `path` is what follows /v2/.
    pub fn handle(&mut self, method: &str, path: &str, b: &Value) -> Result<(u16, Value), ApiErr> {
        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        let s = |k: &str| b[k].as_str().map(String::from);
        Ok(match (method, parts.as_slice()) {
            ("POST", ["apis"]) => {
                let id = short_id();
                let mut a = Api { name: s("name").unwrap_or_default(), protocol: s("protocolType").unwrap_or("HTTP".into()), created: chrono::Utc::now().to_rfc3339(),
                    routes: BTreeMap::new(), integrations: BTreeMap::new(), authorizers: BTreeMap::new(), stages: BTreeMap::new() };
                if a.protocol != "HTTP" {
                    return Err(err("BadRequestException", "Only HTTP APIs are supported locally"));
                }
                // Quick create: target → integration + $default route + auto-deployed $default stage.
                if let Some(t) = s("target") {
                    let iid = short_id();
                    a.integrations.insert(iid.clone(), Integ { ty: "AWS_PROXY".into(), uri: t, fmt: "2.0".into() });
                    a.routes.insert(short_id(), Route { key: s("routeKey").unwrap_or("$default".into()), target: format!("integrations/{iid}"), auth_type: "NONE".into(), authorizer_id: None });
                    a.stages.insert("$default".into(), true);
                }
                let out = api_json(&id, &a);
                self.apis.insert(id, a);
                (201, out)
            }
            ("GET", ["apis"]) => (200, json!({"items": self.apis.iter().map(|(i, a)| api_json(i, a)).collect::<Vec<_>>()})),
            ("GET", ["apis", id]) => (200, api_json(id, self.apis.get(*id).ok_or_else(|| nf("API"))?)),
            ("DELETE", ["apis", id]) => {
                self.apis.remove(*id).ok_or_else(|| nf("API"))?;
                (204, Value::Null)
            }
            (_, ["apis", id, rest @ ..]) => {
                let a = self.apis.get_mut(*id).ok_or_else(|| nf("API"))?;
                match (method, rest) {
                    ("POST", ["integrations"]) => {
                        let i = Integ { ty: s("integrationType").unwrap_or_default(), uri: s("integrationUri").unwrap_or_default(), fmt: s("payloadFormatVersion").unwrap_or("2.0".into()) };
                        if i.ty != "AWS_PROXY" {
                            return Err(err("BadRequestException", "Only AWS_PROXY (Lambda) integrations are supported locally"));
                        }
                        let iid = short_id();
                        let out = integ_json(&iid, &i);
                        a.integrations.insert(iid, i);
                        (201, out)
                    }
                    ("GET", ["integrations"]) => (200, json!({"items": a.integrations.iter().map(|(k, i)| integ_json(k, i)).collect::<Vec<_>>()})),
                    ("GET", ["integrations", iid]) => (200, integ_json(iid, a.integrations.get(*iid).ok_or_else(|| nf("Integration"))?)),
                    ("DELETE", ["integrations", iid]) => {
                        a.integrations.remove(*iid).ok_or_else(|| nf("Integration"))?;
                        (204, Value::Null)
                    }
                    ("POST", ["authorizers"]) => {
                        let aid = short_id();
                        let jc = &b["jwtConfiguration"];
                        let id_src = str_list(&b["identitySource"]);
                        let auth = Authorizer {
                            id: aid.clone(),
                            name: s("name").unwrap_or_default(),
                            ty: s("authorizerType").unwrap_or_default(),
                            identity_source: if id_src.is_empty() { vec!["$request.header.Authorization".into()] } else { id_src },
                            jwt_issuer: jc["issuer"].as_str().map(String::from),
                            jwt_audience: str_list(&jc["audience"]),
                            authorizer_uri: s("authorizerUri"),
                            payload_format: s("authorizerPayloadFormatVersion").unwrap_or_else(|| "2.0".into()),
                            enable_simple_responses: b["enableSimpleResponses"].as_bool().unwrap_or(false),
                            ttl: b["authorizerResultTtlInSeconds"].as_u64().unwrap_or(0),
                        };
                        validate_authorizer(&auth)?;
                        let out = auth_json(&auth);
                        a.authorizers.insert(aid, auth);
                        (201, out)
                    }
                    ("GET", ["authorizers"]) => (200, json!({"items": a.authorizers.values().map(auth_json).collect::<Vec<_>>()})),
                    ("GET", ["authorizers", aid]) => (200, auth_json(a.authorizers.get(*aid).ok_or_else(|| nf("Authorizer"))?)),
                    ("PATCH", ["authorizers", aid]) => {
                        let mut updated = a.authorizers.get(*aid).ok_or_else(|| nf("Authorizer"))?.clone();
                        if let Some(n) = s("name") { updated.name = n; }
                        if let Some(t) = s("authorizerType") { updated.ty = t; }
                        if b.get("identitySource").is_some() { updated.identity_source = str_list(&b["identitySource"]); }
                        if let Some(jc) = b.get("jwtConfiguration") {
                            if let Some(iss) = jc["issuer"].as_str() { updated.jwt_issuer = Some(iss.into()); }
                            if jc.get("audience").is_some() { updated.jwt_audience = str_list(&jc["audience"]); }
                        }
                        if let Some(u) = s("authorizerUri") { updated.authorizer_uri = Some(u); }
                        if let Some(f) = s("authorizerPayloadFormatVersion") { updated.payload_format = f; }
                        if let Some(sr) = b["enableSimpleResponses"].as_bool() { updated.enable_simple_responses = sr; }
                        if let Some(ttl) = b["authorizerResultTtlInSeconds"].as_u64() { updated.ttl = ttl; }
                        validate_authorizer(&updated)?;
                        let out = auth_json(&updated);
                        a.authorizers.insert((*aid).to_string(), updated);
                        (200, out)
                    }
                    ("DELETE", ["authorizers", aid]) => {
                        a.authorizers.remove(*aid).ok_or_else(|| nf("Authorizer"))?;
                        (204, Value::Null)
                    }
                    ("POST", ["routes"]) => {
                        let key = s("routeKey").ok_or_else(|| err("BadRequestException", "routeKey is required"))?;
                        if a.routes.values().any(|r| r.key == key) {
                            return Err(ApiErr { status: 409, ..err("ConflictException", format!("Route with key {key} already exists for this API")) });
                        }
                        let auth_type = s("authorizationType").unwrap_or_else(|| "NONE".into());
                        let authorizer_id = s("authorizerId");
                        validate_route_auth(a, &auth_type, authorizer_id.as_deref())?;
                        let rid = short_id();
                        let route = Route { key, target: s("target").unwrap_or_default(), auth_type, authorizer_id };
                        let out = route_json(&rid, &route);
                        a.routes.insert(rid, route);
                        (201, out)
                    }
                    ("GET", ["routes"]) => (200, json!({"items": a.routes.iter().map(|(r, rt)| route_json(r, rt)).collect::<Vec<_>>()})),
                    ("GET", ["routes", rid]) => (200, route_json(rid, a.routes.get(*rid).ok_or_else(|| nf("Route"))?)),
                    ("PATCH", ["routes", rid]) => {
                        let cur = a.routes.get(*rid).ok_or_else(|| nf("Route"))?;
                        let key = s("routeKey").unwrap_or_else(|| cur.key.clone());
                        if key != cur.key && a.routes.values().any(|r| r.key == key) {
                            return Err(ApiErr { status: 409, ..err("ConflictException", format!("Route with key {key} already exists for this API")) });
                        }
                        let target = s("target").unwrap_or_else(|| cur.target.clone());
                        let auth_type = s("authorizationType").unwrap_or_else(|| cur.auth_type.clone());
                        let authorizer_id = if auth_type == "NONE" {
                            None
                        } else {
                            s("authorizerId").or_else(|| cur.authorizer_id.clone())
                        };
                        validate_route_auth(a, &auth_type, authorizer_id.as_deref())?;
                        let updated = Route { key, target, auth_type, authorizer_id };
                        let out = route_json(rid, &updated);
                        a.routes.insert((*rid).to_string(), updated);
                        (200, out)
                    }
                    ("DELETE", ["routes", rid]) => {
                        a.routes.remove(*rid).ok_or_else(|| nf("Route"))?;
                        (204, Value::Null)
                    }
                    ("POST", ["stages"]) => {
                        let n = s("stageName").ok_or_else(|| err("BadRequestException", "stageName is required"))?;
                        let auto = b["autoDeploy"].as_bool().unwrap_or(false);
                        a.stages.insert(n.clone(), auto);
                        (201, json!({"stageName": n, "autoDeploy": auto}))
                    }
                    ("GET", ["stages"]) => (200, json!({"items": a.stages.iter().map(|(n, d)| json!({"stageName": n, "autoDeploy": d})).collect::<Vec<_>>()})),
                    ("DELETE", ["stages", n]) => {
                        a.stages.remove(*n).ok_or_else(|| nf("Stage"))?;
                        (204, Value::Null)
                    }
                    // ponytail: every change is live immediately, so deployments are no-ops.
                    ("POST", ["deployments"]) => (201, json!({"deploymentId": short_id(), "deploymentStatus": "DEPLOYED"})),
                    _ => return Err(nf("resource")),
                }
            }
            _ => return Err(nf("resource")),
        })
    }

    pub fn admin(&self) -> Value {
        self.apis
            .iter()
            .map(|(id, a)| {
                let rows: Vec<Value> = a.routes.values().map(|r| {
                    let fname = r.target.strip_prefix("integrations/").and_then(|i| a.integrations.get(i)).map(|i| lambda_fn_of(&i.uri)).unwrap_or_default();
                    json!([r.key, fname])
                }).collect();
                json!({"name": a.name, "count": rows.len(), "sub": format!("{}/_api/{id} · 스테이지 {} · 인가자 {}", crate::endpoint(), a.stages.keys().cloned().collect::<Vec<_>>().join(", "), a.authorizers.len()),
                       "cols": ["라우트", "Lambda"], "rows": rows})
            })
            .collect()
    }
}

// Data plane: turn an HTTP request into a payload-v2 Lambda event and the result into a response.
pub async fn invoke(app: &Arc<App>, method: &str, api: &str, rest: &str, query: &str, headers: &axum::http::HeaderMap, body: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>, String) {
    let json_err = |st: u16, m: &str, rk: String| (st, vec![("content-type".into(), "application/json".into())], json!({"message": m}).to_string().into_bytes(), rk);
    let Some(t) = app.apigw.lock().unwrap().resolve(api, method, rest) else { return json_err(404, "Not Found", String::new()) };
    let Some(func) = t.function.clone() else { return json_err(404, "Not Found", String::new()) };
    let hdrs: Map<String, Value> = headers.iter().filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.into()))).collect();
    let qs: Map<String, Value> = query.split('&').filter(|p| !p.is_empty())
        .map(|p| { let (k, v) = p.split_once('=').unwrap_or((p, "")); (crate::s3::pct_decode(k), crate::s3::pct_decode(v).into()) }).collect();
    let text = std::str::from_utf8(body);
    let now = chrono::Utc::now();
    let mut event = json!({"version": "2.0", "routeKey": t.route_key, "rawPath": t.path, "rawQueryString": query, "headers": hdrs,
        "requestContext": {"accountId": crate::ACCOUNT, "apiId": api, "domainName": "localhost", "domainPrefix": api, "stage": t.stage,
            "requestId": uuid::Uuid::new_v4().to_string(), "routeKey": t.route_key, "time": now.format("%d/%b/%Y:%H:%M:%S +0000").to_string(),
            "timeEpoch": now.timestamp_millis(),
            "http": {"method": method, "path": t.path, "protocol": "HTTP/1.1", "sourceIp": "127.0.0.1",
                     "userAgent": headers.get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("")}},
        "isBase64Encoded": text.is_err()});
    if !qs.is_empty() {
        event["queryStringParameters"] = qs.clone().into();
    }
    if !t.params.is_empty() {
        event["pathParameters"] = t.params.clone().into();
    }
    if !body.is_empty() {
        event["body"] = text.map_or_else(|_| crate::b64(body), String::from).into();
    }

    // Run route authorizer (JWT or Lambda REQUEST) before invoking the integration.
    if let Some(auth) = t.authorizer {
        let Some(id_vals) = extract_identity(&auth.identity_source, &hdrs, &qs) else {
            return json_err(401, "Unauthorized", t.route_key);
        };
        if auth.ty == "JWT" {
            let raw = id_vals.first().map(String::as_str).unwrap_or("");
            let tok = raw.get(..7).filter(|p| p.eq_ignore_ascii_case("bearer ")).map_or(raw, |_| raw[7..].trim());
            if tok.is_empty() {
                return json_err(401, "Unauthorized", t.route_key);
            }
            let iss = auth.jwt_issuer.as_deref().unwrap_or("");
            let pool_ok = local_cognito_pool(iss).is_some_and(|p| app.cognito.lock().unwrap().pool_exists(p));
            let Some(claims) = (if pool_ok { crate::cognito::verify(tok) } else { None }) else {
                return json_err(403, "Forbidden", t.route_key);
            };
            let iss_ok = claims["iss"].as_str().map(|x| x.trim_end_matches('/')) == Some(iss.trim_end_matches('/'));
            let aud = claims["aud"].as_str().or_else(|| claims["client_id"].as_str());
            let aud_ok = aud.is_some_and(|x| auth.jwt_audience.iter().any(|w| w == x));
            if !iss_ok || !aud_ok {
                return json_err(403, "Forbidden", t.route_key);
            }
            let scopes: Vec<&str> = claims["scope"].as_str().map(|sc| sc.split_whitespace().collect()).unwrap_or_default();
            event["requestContext"]["authorizer"] = json!({"jwt": {"claims": claims, "scopes": scopes}});
        } else if auth.ty == "REQUEST" {
            let auth_fn = lambda_fn_of(auth.authorizer_uri.as_deref().unwrap_or(""));
            let mut auth_ev = json!({
                "version": "2.0",
                "type": "REQUEST",
                "routeArn": format!("arn:aws:execute-api:{}:{}:{}/{}/{}", *crate::REGION, crate::ACCOUNT, api, t.stage, t.route_key),
                "identitySource": id_vals,
                "routeKey": t.route_key,
                "rawPath": t.path,
                "rawQueryString": query,
                "headers": hdrs,
                "requestContext": event["requestContext"],
            });
            if !qs.is_empty() {
                auth_ev["queryStringParameters"] = qs.into();
            }
            if !t.params.is_empty() {
                auth_ev["pathParameters"] = t.params.into();
            }
            match crate::lambda::invoke(app, &auth_fn, auth_ev).await {
                Ok(inv) if inv.error.is_none() && inv.payload["isAuthorized"].as_bool() == Some(true) => {
                    let ctx = inv.payload.get("context").cloned().unwrap_or_else(|| json!({}));
                    event["requestContext"]["authorizer"] = json!({"lambda": ctx});
                }
                _ => return json_err(403, "Forbidden", t.route_key),
            }
        }
    }

    match crate::lambda::invoke(app, &func, event).await {
        Ok(inv) if inv.error.is_none() => {
            let p = inv.payload;
            // A result with statusCode is a full response; anything else becomes a 200 JSON body.
            if p.get("statusCode").is_some() {
                let mut h: Vec<(String, String)> = p["headers"].as_object().into_iter().flatten()
                    .map(|(k, v)| (k.clone(), v.as_str().map_or(v.to_string(), String::from))).collect();
                if !h.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
                    h.push(("content-type".into(), "application/json".into()));
                }
                let raw = p["body"].as_str().unwrap_or("");
                let b = if p["isBase64Encoded"] == true { crate::unb64(raw).unwrap_or_default() } else { raw.as_bytes().to_vec() };
                (p["statusCode"].as_u64().unwrap_or(200) as u16, h, b, t.route_key)
            } else {
                (200, vec![("content-type".into(), "application/json".into())], p.to_string().into_bytes(), t.route_key)
            }
        }
        _ => json_err(500, "Internal Server Error", t.route_key),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(match_path("/items/{id}", "/items/42").unwrap()["id"], "42");
        assert!(match_path("/items/{id}", "/items").is_none() && match_path("/items", "/items/1").is_none());
        assert_eq!(match_path("/files/{rest+}", "/files/a/b.txt").unwrap()["rest"], "a/b.txt");
        assert!(match_path("/", "/").is_some());
    }

    #[test]
    fn authorizer_crud_and_guards() {
        let mut gw = ApiGw::default();
        let (_, api) = gw.handle("POST", "apis", &json!({"name": "a", "protocolType": "HTTP"})).unwrap();
        let id = api["apiId"].as_str().unwrap();

        // External issuer must be rejected
        let err = gw.handle("POST", &format!("apis/{id}/authorizers"), &json!({
            "name": "ext", "authorizerType": "JWT",
            "identitySource": ["$request.header.Authorization"],
            "jwtConfiguration": {"issuer": "https://evil.example.com", "audience": ["c1"]}
        })).unwrap_err();
        assert_eq!(err.code, "BadRequestException");

        // Local Cognito JWT authorizer succeeds
        let (st, a) = gw.handle("POST", &format!("apis/{id}/authorizers"), &json!({
            "name": "cog", "authorizerType": "JWT",
            "identitySource": ["$request.header.Authorization"],
            "jwtConfiguration": {"issuer": "http://127.0.0.1:4566/_cognito/us-east-1_abc", "audience": ["c1"]}
        })).unwrap();
        assert_eq!(st, 201);
        let aid = a["authorizerId"].as_str().unwrap().to_string();

        // UpdateAuthorizer updates audience
        let (st, u) = gw.handle("PATCH", &format!("apis/{id}/authorizers/{aid}"), &json!({
            "jwtConfiguration": {"audience": ["c1", "c2"]}
        })).unwrap();
        assert_eq!(st, 200);
        assert_eq!(u["jwtConfiguration"]["audience"], json!(["c1", "c2"]));

        // Attach to route and verify resolve()
        let (_, rt) = gw.handle("POST", &format!("apis/{id}/routes"), &json!({
            "routeKey": "GET /secret", "authorizationType": "JWT", "authorizerId": aid
        })).unwrap();
        assert_eq!(rt["authorizationType"], "JWT");
        let tgt = gw.resolve(id, "GET", "/secret").unwrap();
        assert_eq!(tgt.authorizer.as_ref().unwrap().id, aid);

        // Lambda URI extraction & identity source extraction
        assert_eq!(
            lambda_fn_of("arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:000000000000:function:my-auth/invocations"),
            "my-auth"
        );
        let mut h = Map::new();
        h.insert("authorization".into(), json!("Bearer tok123"));
        let q = Map::new();
        assert_eq!(extract_identity(&["$request.header.Authorization".into()], &h, &q).unwrap(), vec!["Bearer tok123"]);
        assert!(extract_identity(&["$request.header.X-Missing".into()], &h, &q).is_none());

        assert_eq!(gw.handle("DELETE", &format!("apis/{id}/authorizers/{aid}"), &json!({})).unwrap().0, 204);
    }
}

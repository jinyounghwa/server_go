// API Gateway HTTP APIs (apigatewayv2, REST-JSON) with Lambda proxy integrations, JWT/Lambda authorizers,
// CORS configuration and HTTP_PROXY integrations (loopback targets only).
// Invoke URL: {endpoint}/_api/{apiId}/[{stage}/]path
// REST APIs (v1): resources/methods/integrations under /restapis, invoke URL /_restapi/{apiId}/{stage}/path.
// Unlike HTTP APIs (deploy is a no-op), a v1 CreateDeployment snapshots the resource tree; a stage serves
// that snapshot, so post-deploy edits stay invisible until the next deployment.
// ponytail: v1 has no mapping templates (VTL) and no AWS (non-proxy) or HTTP integrations - rejected, not faked;
// HTTP_PROXY forwards method/path/query/headers and reads the reply
// to connection close (no chunked decoding, 5s timeout); stage variables are substituted in integration URIs only.
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

struct Stage {
    auto: bool,
    vars: BTreeMap<String, String>, // ${stageVariables.x} substitutions for integration URIs
}

#[derive(Clone)]
struct Cors {
    allow_origins: Vec<String>,
    allow_methods: Vec<String>,
    allow_headers: Vec<String>,
    expose_headers: Vec<String>,
    max_age: u64,
    credentials: bool,
}

fn parse_cors(b: &Value) -> Cors {
    // The v2 control plane speaks lowerCamelCase on the wire (botocore sends/accepts lowerCamel keys).
    let l = |k: &str| str_list(&b[k]);
    Cors {
        allow_origins: l("allowOrigins"),
        allow_methods: l("allowMethods"),
        allow_headers: l("allowHeaders"),
        expose_headers: l("exposeHeaders"),
        max_age: b["maxAge"].as_u64().unwrap_or(0),
        credentials: b["allowCredentials"].as_bool().unwrap_or(false),
    }
}

fn cors_json(c: &Cors) -> Value {
    json!({"allowOrigins": c.allow_origins, "allowMethods": c.allow_methods, "allowHeaders": c.allow_headers,
           "exposeHeaders": c.expose_headers, "maxAge": c.max_age, "allowCredentials": c.credentials})
}

// Whether an Origin is allowed. `*` matches any origin (never with credentials, as in AWS).
fn cors_allows(c: &Cors, origin: &str) -> bool {
    !origin.is_empty() && c.allow_origins.iter().any(|o| o == "*" || o == origin)
}

// Headers for an actual response with an allowed origin (preflight adds more below).
fn cors_response_headers(c: &Cors, origin: &str) -> Vec<(String, String)> {
    let mut h = vec![("Access-Control-Allow-Origin".to_string(), if c.allow_origins.iter().any(|o| o == "*") { "*".to_string() } else { origin.to_string() })];
    if c.credentials {
        h.push(("Access-Control-Allow-Credentials".into(), "true".into()));
    }
    if !c.expose_headers.is_empty() {
        h.push(("Access-Control-Expose-Headers".into(), c.expose_headers.join(", ")));
    }
    h
}

fn stage_json(n: &str, s: &Stage) -> Value {
    json!({"stageName": n, "autoDeploy": s.auto, "stageVariables": s.vars})
}

fn stage_of(b: &Value, auto: bool) -> Stage {
    let vars = b["stageVariables"].as_object().into_iter().flatten()
        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect();
    Stage { auto, vars }
}

struct Api {
    name: String,
    protocol: String,
    created: String,
    routes: BTreeMap<String, Route>,
    integrations: BTreeMap<String, Integ>,
    authorizers: BTreeMap<String, Authorizer>,
    stages: BTreeMap<String, Stage>,
    cors: Option<Cors>,
}

#[derive(Default)]
pub struct ApiGw {
    apis: BTreeMap<String, Api>,
    rests: BTreeMap<String, RestApi>,
}

// ---------- REST APIs (v1) ----------
#[derive(Clone)]
struct Res1 {
    id: String,
    parent: String, // "" for the root
    part: String,   // pathPart; "" for the root
    methods: BTreeMap<String, Method1>,
}
#[derive(Clone)]
struct Method1 {
    auth: String,                       // NONE | AWS_IAM (authorization is day 21)
    #[allow(dead_code)] // enforced from day 21 (authorizers)
    params: BTreeMap<String, bool>,     // requestParameters -> required
    integration: Option<Integ1>,
    responses: BTreeMap<String, Value>, // method responses, keyed by status code
    integ_responses: BTreeMap<String, Value>,
}
#[derive(Clone)]
struct Integ1 {
    ty: String,  // AWS_PROXY | MOCK
    uri: String, // Lambda function ARN (parsed out of the apigateway URI)
}
struct RestApi {
    name: String,
    resources: BTreeMap<String, Res1>,
    deployments: BTreeMap<String, BTreeMap<String, Res1>>, // deploymentId -> snapshot
    stages: BTreeMap<String, String>,                      // stage -> deploymentId
}

fn short_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..10].to_string()
}

// ---------- REST v1 helpers ----------
fn root_of(ra: &RestApi) -> String {
    ra.resources.values().find(|r| r.parent.is_empty()).map(|r| r.id.clone()).unwrap_or_default()
}
fn res1_path(resources: &BTreeMap<String, Res1>, rid: &str) -> String {
    let mut parts = vec![];
    let mut cur = rid;
    while let Some(r) = resources.get(cur) {
        if !r.part.is_empty() {
            parts.push(r.part.clone());
        }
        cur = &r.parent;
    }
    if parts.is_empty() {
        "/".into()
    } else {
        format!("/{}", parts.iter().rev().cloned().collect::<Vec<_>>().join("/"))
    }
}
fn res1_path_snap(snap: &BTreeMap<String, Res1>, rid: &str) -> String {
    res1_path(snap, rid)
}
fn res1_json(ra: &RestApi, r: &Res1) -> Value {
    let mut out = json!({"id": r.id, "parentId": if r.parent.is_empty() { Value::Null } else { json!(r.parent) }, "path": res1_path(&ra.resources, &r.id)});
    if !r.part.is_empty() {
        out["pathPart"] = r.part.clone().into();
    }
    if !r.methods.is_empty() {
        let mut m = Map::new();
        for (k, v) in &r.methods {
            m.insert(k.clone(), json!({"httpMethod": k, "authorizationType": v.auth}));
        }
        out["resourceMethods"] = m.into();
    }
    out
}
fn method1_json(m: &str, md: &Method1) -> Value {
    let mut out = json!({"httpMethod": m, "authorizationType": md.auth, "apiKeyRequired": false});
    if let Some(i) = &md.integration {
        out["methodIntegration"] = integ1_json(i);
    }
    if !md.responses.is_empty() {
        out["methodResponses"] = md.responses.iter().map(|(k, v)| (k.clone(), v.clone())).collect::<Map<String, Value>>().into();
    }
    out
}
fn integ1_json(i: &Integ1) -> Value {
    json!({"type": i.ty, "httpMethod": "POST", "uri": i.uri, "integrationResponses": {"200": {"statusCode": "200"}},
        "requestTemplates": {}, "passthroughBehavior": "WHEN_NO_MATCH", "cacheNamespace": short_id(), "timeoutInMillis": 29000})
}
fn nf(what: &str) -> ApiErr {
    ApiErr { status: 404, ..err("NotFoundException", format!("Invalid {what} identifier specified")) }
}
fn api_json(id: &str, a: &Api) -> Value {
    let mut out = json!({"apiId": id, "name": a.name, "protocolType": a.protocol, "createdDate": a.created,
           "apiEndpoint": format!("{}/_api/{id}", crate::endpoint()), "routeSelectionExpression": "$request.method $request.path"});
    if let Some(c) = &a.cors {
        out["corsConfiguration"] = cors_json(c);
    }
    out
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

// HTTP_PROXY target check at save time: only loopback http URIs (or URIs that still contain a
// ${stageVariables.x} placeholder, re-checked after substitution at invoke time) are stored.
fn loopback_uri(uri: &str) -> bool {
    if uri.contains("${") {
        return true;
    }
    let Some(rest) = uri.strip_prefix("http://") else { return false };
    let authority = rest.split('/').next().unwrap_or("");
    let Some((host, port)) = authority.rsplit_once(':') else { return false };
    (host == "127.0.0.1" || host == "localhost") && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())
}

// Substitute ${stageVariables.x} in an integration URI.
fn sub_stage_vars(uri: &str, vars: &BTreeMap<String, String>) -> String {
    let mut out = uri.to_string();
    for (k, v) in vars {
        out = out.replace(&format!("${{stageVariables.{k}}}"), v);
    }
    out
}

// Minimal HTTP/1.1 client for loopback HTTP_PROXY integrations. Sends method, path+query and
// headers, reads the reply to connection close. ponytail: no TLS, no chunked decoding, 5s timeout.
async fn http_proxy(
    uri: &str, method: &str, path: &str, query: &str, hdrs: &[(String, String)], body: &[u8],
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    let rest = uri.strip_prefix("http://").ok_or("HTTP_PROXY integration URI must use http://")?;
    let authority = rest.split('/').next().unwrap_or("");
    let (host, port) = authority.rsplit_once(':').ok_or("HTTP_PROXY URI needs a port")?;
    if host != "127.0.0.1" && host != "localhost" {
        return Err("HTTP_PROXY integration targets must be 127.0.0.1 or localhost".into());
    }
    let port: u16 = port.parse().map_err(|_| "bad HTTP_PROXY port")?;
    let mut req = format!("{method} {path}");
    if !query.is_empty() {
        req.push('?');
        req.push_str(query);
    }
    req.push_str(&format!(" HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nContent-Length: {}\r\n", body.len()));
    for (k, v) in hdrs {
        let skip = ["host", "connection", "content-length", "transfer-encoding", "keep-alive"];
        if !skip.iter().any(|s| k.eq_ignore_ascii_case(s)) {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
    }
    req.push_str("\r\n");

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect((host, port)).await.map_err(|e| e.to_string())?;
    let io = async {
        stream.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
        stream.write_all(body).await.map_err(|e| e.to_string())?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
        Ok::<Vec<u8>, String>(buf)
    };
    let buf = tokio::time::timeout(std::time::Duration::from_secs(5), io).await.map_err(|_| "HTTP_PROXY timeout".to_string())??;

    let text_end = buf.windows(4).position(|w| w == b"\r\n\r\n").ok_or("malformed HTTP_PROXY response")?;
    let head = String::from_utf8_lossy(&buf[..text_end]).to_string();
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or("").split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok()).ok_or("malformed HTTP_PROXY status")?;
    let out_hdrs: Vec<(String, String)> = lines.filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))).collect();
    Ok((status, out_hdrs, buf[text_end + 4..].to_vec()))
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
    pub function: Option<String>,    // AWS_PROXY: Lambda function name
    pub proxy_uri: Option<String>,   // HTTP_PROXY: loopback URI after stage-variable substitution
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
        let stage_vars = a.stages.get(&stage).map(|s| s.vars.clone()).unwrap_or_default();
        let (function, proxy_uri) = route.target.strip_prefix("integrations/").and_then(|i| a.integrations.get(i)).map(|i| {
            if i.ty == "AWS_PROXY" {
                (Some(lambda_fn_of(&i.uri)), None)
            } else if i.ty == "HTTP_PROXY" {
                (None, Some(sub_stage_vars(&i.uri, &stage_vars)))
            } else {
                (None, None)
            }
        }).unwrap_or((None, None));
        let authorizer = if matches!(route.auth_type.as_str(), "JWT" | "CUSTOM") {
            route.authorizer_id.as_deref().and_then(|aid| a.authorizers.get(aid)).cloned()
        } else {
            None
        };
        Some(Target { route_key: route.key.clone(), stage, path, function, proxy_uri, params, authorizer })
    }

    // CORS configuration of an API, for preflight handling and response headers.
    fn cors(&self, api: &str) -> Option<Cors> {
        self.apis.get(api).and_then(|a| a.cors.clone())
    }

    // Control plane. `path` is what follows /v2/.
    pub fn handle(&mut self, method: &str, path: &str, b: &Value) -> Result<(u16, Value), ApiErr> {
        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        let s = |k: &str| b[k].as_str().map(String::from);
        Ok(match (method, parts.as_slice()) {
            ("POST", ["apis"]) => {
                let id = short_id();
                let mut a = Api { name: s("name").unwrap_or_default(), protocol: s("protocolType").unwrap_or("HTTP".into()), created: chrono::Utc::now().to_rfc3339(),
                    routes: BTreeMap::new(), integrations: BTreeMap::new(), authorizers: BTreeMap::new(), stages: BTreeMap::new(), cors: None };
                if a.protocol != "HTTP" {
                    return Err(err("BadRequestException", "Only HTTP APIs are supported locally"));
                }
                if let Some(cc) = b.get("corsConfiguration") {
                    a.cors = Some(parse_cors(cc));
                }
                // Quick create: target → integration + $default route + auto-deployed $default stage.
                if let Some(t) = s("target") {
                    let iid = short_id();
                    a.integrations.insert(iid.clone(), Integ { ty: "AWS_PROXY".into(), uri: t, fmt: "2.0".into() });
                    a.routes.insert(short_id(), Route { key: s("routeKey").unwrap_or("$default".into()), target: format!("integrations/{iid}"), auth_type: "NONE".into(), authorizer_id: None });
                    a.stages.insert("$default".into(), Stage { auto: true, vars: BTreeMap::new() });
                }
                let out = api_json(&id, &a);
                self.apis.insert(id, a);
                (201, out)
            }            ("GET", ["apis"]) => (200, json!({"items": self.apis.iter().map(|(i, a)| api_json(i, a)).collect::<Vec<_>>()})),
            ("GET", ["apis", id]) => (200, api_json(id, self.apis.get(*id).ok_or_else(|| nf("API"))?)),
            ("DELETE", ["apis", id]) => {
                self.apis.remove(*id).ok_or_else(|| nf("API"))?;
                (204, Value::Null)
            }
            ("PATCH" | "PUT", ["apis", id]) => {
                let a = self.apis.get_mut(*id).ok_or_else(|| nf("API"))?;
                if let Some(n) = s("name") {
                    a.name = n;
                }
                if let Some(cc) = b.get("corsConfiguration") {
                    a.cors = cc.as_object().map(|_| parse_cors(cc)); // explicit null removes the config
                }
                (200, api_json(id, a))
            }
            (_, ["apis", id, rest @ ..]) => {
                let a = self.apis.get_mut(*id).ok_or_else(|| nf("API"))?;
                match (method, rest) {
                    ("POST", ["integrations"]) => {
                        let i = Integ { ty: s("integrationType").unwrap_or_default(), uri: s("integrationUri").unwrap_or_default(), fmt: s("payloadFormatVersion").unwrap_or("2.0".into()) };
                        match i.ty.as_str() {
                            "AWS_PROXY" => {}
                            "HTTP_PROXY" => {
                                if !loopback_uri(&i.uri) {
                                    return Err(err("BadRequestException", "HTTP_PROXY integration URIs must target http://127.0.0.1 or http://localhost (SSRF protection); use ${stageVariables.x} placeholders for the host/port"));
                                }
                            }
                            other => return Err(err("BadRequestException", format!("Unsupported integrationType: {other} (only AWS_PROXY and HTTP_PROXY)"))),
                        }
                        let iid = short_id();
                        let out = integ_json(&iid, &i);
                        a.integrations.insert(iid, i);
                        (201, out)
                    }
                    ("PUT", ["cors"]) => {
                        let c = parse_cors(b);
                        if c.credentials && c.allow_origins.iter().any(|o| o == "*") {
                            return Err(err("BadRequestException", "AllowCredentials cannot be used with the wildcard origin"));
                        }
                        let out = cors_json(&c);
                        a.cors = Some(c);
                        (200, out)
                    }
                    ("GET", ["cors"]) => {
                        let c = a.cors.as_ref().ok_or_else(|| nf("CorsConfiguration"))?;
                        (200, cors_json(c))
                    }
                    ("DELETE", ["cors"]) => {
                        a.cors = None;
                        (204, Value::Null)
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
                        let st = stage_of(b, auto);
                        let out = stage_json(&n, &st);
                        a.stages.insert(n, st);
                        (201, out)
                    }
                    ("GET", ["stages"]) => (200, json!({"items": a.stages.iter().map(|(n, s)| stage_json(n, s)).collect::<Vec<_>>()})),
                    ("GET", ["stages", n]) => (200, stage_json(n, a.stages.get(*n).ok_or_else(|| nf("Stage"))?)),
                    ("PATCH", ["stages", n]) => {
                        let cur = a.stages.get(*n).ok_or_else(|| nf("Stage"))?;
                        let updated = Stage {
                            auto: b["autoDeploy"].as_bool().unwrap_or(cur.auto),
                            vars: if b.get("stageVariables").is_some() { stage_of(b, cur.auto).vars } else { cur.vars.clone() },
                        };
                        let out = stage_json(n, &updated);
                        a.stages.insert((*n).to_string(), updated);
                        (200, out)
                    }
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

    // REST v1 control plane. `path` is what follows /restapis.
    pub fn handle_rest(&mut self, method: &str, path: &str, b: &Value) -> Result<(u16, Value), ApiErr> {
        let p: Vec<&str> = path.trim_matches('/').split('/').filter(|x| !x.is_empty()).collect();
        let strv = |k: &str| b[k].as_str().map(String::from);
        let bad = |m: &str| err("BadRequestException", m);
        // POST /restapis creates an API; everything else needs an API id first.
        if method == "POST" && p.is_empty() {
            let name = strv("name").ok_or_else(|| bad("name is required"))?;
            let id = short_id();
            let root = format!("r{}", short_id());
            let mut resources = BTreeMap::new();
            resources.insert(root.clone(), Res1 { id: root.clone(), parent: String::new(), part: String::new(), methods: BTreeMap::new() });
            let r = RestApi { name, resources, deployments: BTreeMap::new(), stages: BTreeMap::new() };
            let out = json!({"id": id, "name": r.name, "createdDate": chrono::Utc::now().to_rfc3339(),
                "endpointConfiguration": {"types": ["REGIONAL"]}, "rootResourceId": root, "tags": {}});
            self.rests.insert(id, r);
            return Ok((201, out));
        }
        let api = p.first().copied().ok_or_else(|| nf("API")).map(|x| x.to_string())?;
        let rest: Vec<&str> = p[1..].to_vec();
        let ra = self.rests.get_mut(&api).ok_or_else(|| nf("API"))?;
        Ok(match (method, rest.as_slice()) {
            ("GET", []) => (200, json!({"id": api, "name": ra.name, "createdDate": chrono::Utc::now().to_rfc3339(),
                "endpointConfiguration": {"types": ["REGIONAL"]}, "rootResourceId": root_of(ra)})),
            ("DELETE", []) => {
                self.rests.remove(&api);
                (200, json!({"id": api}))
            }
            // the wire name is "item" (the shape's serialization name), not "items"
            ("GET", ["resources"]) => (200, json!({"item": ra.resources.values().map(|r| res1_json(ra, r)).collect::<Vec<_>>()})),
            // CreateResource carries the parent id in the path: POST /restapis/{api}/resources/{parent}
            ("POST", ["resources", parent]) => {
                let parent = parent.to_string();
                let part = strv("pathPart").ok_or_else(|| bad("pathPart is required"))?;
                if !ra.resources.contains_key(&parent) {
                    return Err(nf("parent resource"));
                }
                if ra.resources.values().any(|r| r.parent == parent && r.part == part) {
                    return Err(err("ConflictException", format!("A resource already exists at path {part}")));
                }
                let id = format!("r{}", short_id());
                let r = Res1 { id: id.clone(), parent, part, methods: BTreeMap::new() };
                ra.resources.insert(id.clone(), r);
                let out = res1_json(ra, ra.resources.get(&id).unwrap());
                (201, out)
            }
            ("GET", ["resources", rid]) => (200, res1_json(ra, ra.resources.get(*rid).ok_or_else(|| nf("resource"))?)),
            ("DELETE", ["resources", rid]) => {
                let r = ra.resources.get(*rid).ok_or_else(|| nf("resource"))?;
                if r.parent.is_empty() {
                    return Err(bad("Cannot delete the root resource"));
                }
                if ra.resources.values().any(|x| x.parent == *rid) {
                    return Err(bad("Resource has child resources; delete them first"));
                }
                ra.resources.remove(*rid);
                (200, json!({"id": rid}))
            }
            ("PUT", ["resources", rid, "methods", m]) => {
                let r = ra.resources.get_mut(*rid).ok_or_else(|| nf("resource"))?;
                let auth = strv("authorizationType").unwrap_or_else(|| "NONE".into());
                if !["NONE", "AWS_IAM"].contains(&auth.as_str()) {
                    return Err(bad("authorizationType must be NONE or AWS_IAM (authorizers arrive later)"));
                }
                let params: BTreeMap<String, bool> = b.get("requestParameters").and_then(Value::as_object)
                    .map(|m| m.iter().map(|(k, v)| (k.clone(), v.as_bool().unwrap_or(false))).collect()).unwrap_or_default();
                let md = Method1 { auth, params, integration: None, responses: BTreeMap::new(), integ_responses: BTreeMap::new() };
                let out = method1_json(m, &md);
                r.methods.insert(m.to_string(), md);
                (200, out)
            }
            ("GET", ["resources", rid, "methods", m]) => {
                let r = ra.resources.get(*rid).ok_or_else(|| nf("resource"))?;
                (200, method1_json(m, r.methods.get(*m).ok_or_else(|| nf("method"))?))
            }
            ("DELETE", ["resources", rid, "methods", m]) => {
                let r = ra.resources.get_mut(*rid).ok_or_else(|| nf("resource"))?;
                r.methods.remove(*m).ok_or_else(|| nf("method"))?;
                (200, json!({"httpMethod": m}))
            }
            ("PUT", ["resources", rid, "methods", m, "responses", code]) => {
                let r = ra.resources.get_mut(*rid).ok_or_else(|| nf("resource"))?;
                let md = r.methods.get_mut(*m).ok_or_else(|| nf("method"))?;
                md.responses.insert(code.to_string(), json!({"statusCode": code}));
                (200, json!({"statusCode": code}))
            }
            ("PUT", ["resources", rid, "methods", m, "integration", "responses", code]) => {
                let r = ra.resources.get_mut(*rid).ok_or_else(|| nf("resource"))?;
                let md = r.methods.get_mut(*m).ok_or_else(|| nf("method"))?;
                md.integ_responses.insert(code.to_string(), json!({"statusCode": code}));
                (200, json!({"statusCode": code}))
            }
            ("PUT", ["resources", rid, "methods", m, "integration"]) => {
                let ty = strv("type").ok_or_else(|| bad("type is required"))?;
                if ty != "AWS_PROXY" && ty != "MOCK" {
                    return Err(bad("Only AWS_PROXY and MOCK integrations are supported locally (no AWS/HTTP integrations)"));
                }
                if b.get("requestTemplates").is_some_and(|t| t.as_object().is_some_and(|o| !o.is_empty())) {
                    return Err(bad("Mapping templates (VTL) are not supported locally"));
                }
                let uri = strv("uri").unwrap_or_default();
                let uri = if ty == "AWS_PROXY" {
                    if uri.is_empty() {
                        return Err(bad("uri is required for AWS_PROXY integrations"));
                    }
                    if lambda_fn_of(&uri).is_empty() {
                        return Err(bad("uri must address a local Lambda function"));
                    }
                    uri
                } else {
                    uri
                };
                let i = Integ1 { ty, uri };
                let out = integ1_json(&i);
                let r = ra.resources.get_mut(*rid).ok_or_else(|| nf("resource"))?;
                let md = r.methods.get_mut(*m).ok_or_else(|| nf("method"))?;
                md.integration = Some(i);
                (200, out)
            }
            ("GET", ["resources", rid, "methods", m, "integration"]) => {
                let r = ra.resources.get(*rid).ok_or_else(|| nf("resource"))?;
                let md = r.methods.get(*m).ok_or_else(|| nf("method"))?;
                (200, integ1_json(md.integration.as_ref().ok_or_else(|| nf("integration"))?))
            }
            ("DELETE", ["resources", rid, "methods", m, "integration"]) => {
                let r = ra.resources.get_mut(*rid).ok_or_else(|| nf("resource"))?;
                let md = r.methods.get_mut(*m).ok_or_else(|| nf("method"))?;
                md.integration.take().ok_or_else(|| nf("integration"))?;
                (200, json!({"type": "AWS_PROXY"}))
            }
            ("POST", ["deployments"]) => {
                // The snapshot is the point: a stage serves this exact tree.
                let id = short_id();
                let snap = ra.resources.clone();
                let out = json!({"id": id, "createdDate": chrono::Utc::now().to_rfc3339()});
                ra.deployments.insert(id, snap);
                (201, out)
            }
            ("GET", ["deployments"]) => (200, json!({"item": ra.deployments.iter().map(|(id, _)| json!({"id": id, "createdDate": chrono::Utc::now().to_rfc3339()})).collect::<Vec<_>>()})),
            ("GET", ["deployments", did]) => {
                ra.deployments.get(*did).ok_or_else(|| nf("deployment"))?;
                (200, json!({"id": did, "createdDate": chrono::Utc::now().to_rfc3339()}))
            }
            ("POST", ["stages"]) => {
                let stage = strv("stageName").ok_or_else(|| bad("stageName is required"))?;
                let dep = strv("deploymentId").ok_or_else(|| bad("deploymentId is required"))?;
                if !ra.deployments.contains_key(&dep) {
                    return Err(nf("deployment"));
                }
                let out = json!({"stageName": stage, "deploymentId": dep});
                ra.stages.insert(stage, dep);
                (201, out)
            }
            ("GET", ["stages"]) => (200, json!({"item": ra.stages.iter().map(|(s, d)| json!({"stageName": s, "deploymentId": d})).collect::<Vec<_>>()})),
            ("GET", ["stages", st]) => {
                let d = ra.stages.get(*st).ok_or_else(|| nf("stage"))?;
                (200, json!({"stageName": st, "deploymentId": d}))
            }
            ("DELETE", ["stages", st]) => {
                ra.stages.remove(*st).ok_or_else(|| nf("stage"))?;
                (200, json!({"stageName": st}))
            }
            _ => return Err(err("NotFoundException", format!("{method} /restapis/{api}/{} is not supported yet", rest.join("/")))),
        })
    }

    // Resolve a REST v1 request against the stage's deployment snapshot:
    // (resource path, resource id, integration, path parameters).
    fn rest_target(&self, api: &str, stage: &str, method: &str, path: &str) -> Option<(String, String, Integ1, Map<String, Value>)> {
        let ra = self.rests.get(api)?;
        let dep = ra.stages.get(stage)?;
        let snap = ra.deployments.get(dep)?;
        let segs: Vec<&str> = path.trim_matches('/').split('/').filter(|x| !x.is_empty()).collect();
        let root = snap.values().find(|r| r.parent.is_empty())?.id.clone();
        let mut found: Option<(String, Map<String, Value>)> = None;
        let mut queue: Vec<(String, usize, Map<String, Value>)> = vec![(root, 0, Map::new())];
        while let Some((rid, at, params)) = queue.pop() {
            let r = snap.get(&rid)?;
            if at == segs.len() {
                if r.methods.contains_key(method) {
                    found = Some((rid, params));
                    break;
                }
                continue;
            }
            for child in snap.values().filter(|c| c.parent == rid) {
                let seg = segs[at];
                let mut p = params.clone();
                if let Some(name) = child.part.strip_prefix('{').and_then(|x| x.strip_suffix("+}")) {
                    // greedy {proxy+} consumes the rest of the path
                    p.insert(name.into(), segs[at..].join("/").into());
                    queue.push((child.id.clone(), segs.len(), p));
                } else if child.part == seg {
                    queue.push((child.id.clone(), at + 1, p));
                } else if let Some(name) = child.part.strip_prefix('{').and_then(|x| x.strip_suffix('}')) {
                    p.insert(name.into(), seg.into());
                    queue.push((child.id.clone(), at + 1, p));
                }
            }
        }
        let (rid, params) = found?;
        let r = snap.get(&rid)?;
        let i = r.methods.get(method)?.integration.clone()?;
        Some((res1_path_snap(snap, &rid), r.id.clone(), i, params))
    }

    pub fn admin(&self) -> Value {
        let http: Vec<Value> = self.apis
            .iter()
            .map(|(id, a)| {
                let rows: Vec<Value> = a.routes.values().map(|r| {
                    let target = r.target.strip_prefix("integrations/").and_then(|i| a.integrations.get(i)).map(|i| {
                        if i.ty == "HTTP_PROXY" { format!("{} (HTTP_PROXY)", i.uri) } else { lambda_fn_of(&i.uri) }
                    }).unwrap_or_default();
                    json!([r.key, target])
                }).collect();
                json!({"name": a.name, "count": rows.len(), "sub": format!("{}/_api/{id} · 스테이지 {} · 인가자 {}", crate::endpoint(), a.stages.keys().cloned().collect::<Vec<_>>().join(", "), a.authorizers.len()),
                       "cols": ["라우트", "Lambda"], "rows": rows})
            })
            .collect();
        // REST v1: one row per resource path with its methods
        let rest: Vec<Value> = self.rests.iter().map(|(id, r)| {
            let rows: Vec<Value> = r.resources.values().map(|res| {
                let ms = res.methods.keys().cloned().collect::<Vec<_>>().join(",");
                let i = res.methods.values().filter_map(|m| m.integration.as_ref()).map(|i| i.ty.clone()).collect::<Vec<_>>().join("/");
                json!([res1_path(&r.resources, &res.id), ms, i])
            }).collect();
            json!({"name": r.name, "count": rows.len(), "sub": format!("{id} · /_restapi/{id}/{{stage}}/ · 스테이지 {} · 배포 {}", r.stages.keys().cloned().collect::<Vec<_>>().join(", "), r.deployments.len()),
                   "cols": ["리소스", "메서드", "통합"], "rows": rows})
        }).collect();
        http.into_iter().chain(rest).collect()
    }
}

// Preflight headers: everything the browser needs for an OPTIONS call with an allowed origin.
fn preflight_headers(c: &Cors, origin: &str) -> Vec<(String, String)> {
    let mut h = cors_response_headers(c, origin);
    if !c.allow_methods.is_empty() {
        h.push(("Access-Control-Allow-Methods".into(), c.allow_methods.join(", ")));
    }
    if !c.allow_headers.is_empty() {
        h.push(("Access-Control-Allow-Headers".into(), c.allow_headers.join(", ")));
    }
    h.push(("Access-Control-Max-Age".into(), c.max_age.to_string()));
    h
}

// Append CORS headers to a real response (never duplicating one the handler already set).
fn apply_cors(h: &mut Vec<(String, String)>, cors: Option<&Cors>, origin: &str) {
    if let Some(c) = cors.filter(|c| cors_allows(c, origin)) {
        for (k, v) in cors_response_headers(c, origin) {
            if !h.iter().any(|(hk, _)| hk.eq_ignore_ascii_case(&k)) {
                h.push((k, v));
            }
        }
    }
}

// Data plane: turn an HTTP request into a payload-v2 Lambda event and the result into a response,
// or forward it to a loopback HTTP_PROXY target. CORS headers ride on both kinds.
pub async fn invoke(app: &Arc<App>, method: &str, api: &str, rest: &str, query: &str, headers: &axum::http::HeaderMap, body: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>, String) {
    let json_err = |st: u16, m: &str, rk: String| (st, vec![("content-type".into(), "application/json".into())], json!({"message": m}).to_string().into_bytes(), rk);
    let (t, cors) = {
        let gw = app.apigw.lock().unwrap();
        (gw.resolve(api, method, rest), gw.cors(api))
    };
    let origin = headers.get("origin").and_then(|v| v.to_str().ok()).unwrap_or("");
    // Preflight: an allowed Origin answers OPTIONS directly, without needing a matching route.
    if method == "OPTIONS" {
        if let Some(c) = cors.as_ref().filter(|c| cors_allows(c, origin)) {
            return (204, preflight_headers(c, origin), Vec::new(), String::new());
        }
    }
    let Some(t) = t else { return json_err(404, "Not Found", String::new()) };
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

    // HTTP_PROXY: forward method, path, query and headers to the loopback target.
    let hdr_pairs: Vec<(String, String)> = headers.iter().map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string())).collect();
    if let Some(uri) = t.proxy_uri.clone() {
        let (status, mut h, b, rk) = match http_proxy(&uri, method, &t.path, query, &hdr_pairs, body).await {
            // Hop-by-hop headers belong to the emulator's own connection, not to the caller.
            Ok((s, h, b)) => (s, h.into_iter().filter(|(k, _)| !matches!(k.to_ascii_lowercase().as_str(), "connection" | "keep-alive" | "transfer-encoding" | "content-length")).collect(), b, t.route_key),
            Err(_) => json_err(502, "Bad Gateway", t.route_key),
        };
        apply_cors(&mut h, cors.as_ref(), origin);
        return (status, h, b, rk);
    }
    let Some(func) = t.function.clone() else { return json_err(404, "Not Found", String::new()) };
    match crate::lambda::invoke(app, &func, event).await {
        Ok(inv) if inv.error.is_none() => {
            let p = inv.payload;
            // A result with statusCode is a full response; anything else becomes a 200 JSON body.
            let (mut h, b) = if p.get("statusCode").is_some() {
                let h: Vec<(String, String)> = p["headers"].as_object().into_iter().flatten()
                    .map(|(k, v)| (k.clone(), v.as_str().map_or(v.to_string(), String::from))).collect();
                let raw = p["body"].as_str().unwrap_or("");
                let b = if p["isBase64Encoded"] == true { crate::unb64(raw).unwrap_or_default() } else { raw.as_bytes().to_vec() };
                (h, b)
            } else {
                (vec![], p.to_string().into_bytes())
            };
            if !h.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
                h.push(("content-type".into(), "application/json".into()));
            }
            apply_cors(&mut h, cors.as_ref(), origin);
            (p["statusCode"].as_u64().unwrap_or(200) as u16, h, b, t.route_key)
        }
        _ => json_err(500, "Internal Server Error", t.route_key),
    }
}

// REST v1 data plane: /_restapi/{apiId}/{stage}/path. AWS_PROXY builds the v1 proxy event; MOCK answers
// a fixed 200 with an empty body (no VTL).
pub async fn rest_invoke(app: &Arc<App>, method: &str, api: &str, stage: &str, rest: &str, query: &str, headers: &axum::http::HeaderMap, body: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>, String) {
    let json_err = |st: u16, m: &str| (st, vec![("content-type".into(), "application/json".into())], json!({"message": m}).to_string().into_bytes(), String::new());
    let t = {
        let gw = app.apigw.lock().unwrap();
        if gw.rests.contains_key(api) { gw.rest_target(api, stage, method, &rest) } else { None }
    };
    let Some((resource, rid, integ, params)) = t else {
        // v1's quirk: an unmatched route is a 403 "Missing Authentication Token".
        return json_err(403, "Missing Authentication Token");
    };
    if integ.ty == "MOCK" {
        return (200, vec![("content-type".into(), "application/json".into())], Vec::new(), resource);
    }
    let func = lambda_fn_of(&integ.uri);
    if func.is_empty() {
        return json_err(500, "Internal Server Error");
    }
    let hdrs: Map<String, Value> = headers.iter().filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.into()))).collect();
    let qs: Map<String, Value> = query.split('&').filter(|p| !p.is_empty())
        .map(|p| { let (k, v) = p.split_once('=').unwrap_or((p, "")); (crate::s3::pct_decode(k), crate::s3::pct_decode(v).into()) }).collect();
    let text = std::str::from_utf8(body);
    let now = chrono::Utc::now();
    let mut event = json!({
        "resource": resource, "path": rest, "httpMethod": method,
        "headers": hdrs, "requestContext": {
            "resourceId": rid, "resourcePath": resource, "httpMethod": method,
            "requestId": uuid::Uuid::new_v4().to_string(), "accountId": crate::ACCOUNT, "apiId": api, "stage": stage,
            "identity": {"sourceIp": "127.0.0.1", "userAgent": headers.get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("")},
            "path": rest, "protocol": "HTTP/1.1",
            "requestTime": now.format("%d/%b/%Y:%H:%M:%S +0000").to_string(), "requestTimeEpoch": now.timestamp_millis()},
        "isBase64Encoded": text.is_err()});
    if !qs.is_empty() {
        event["queryStringParameters"] = qs.into();
    }
    if !params.is_empty() {
        event["pathParameters"] = params.into();
    }
    if !body.is_empty() {
        event["body"] = text.map_or_else(|_| crate::b64(body), String::from).into();
    }
    match crate::lambda::invoke(app, &func, event).await {
        Ok(inv) if inv.error.is_none() => {
            let p = inv.payload;
            let (mut h, b) = if p.get("statusCode").is_some() {
                let h: Vec<(String, String)> = p["headers"].as_object().into_iter().flatten()
                    .map(|(k, v)| (k.clone(), v.as_str().map_or(v.to_string(), String::from))).collect();
                let raw = p["body"].as_str().unwrap_or("");
                let b = if p["isBase64Encoded"] == true { crate::unb64(raw).unwrap_or_default() } else { raw.as_bytes().to_vec() };
                (h, b)
            } else {
                (vec![], p.to_string().into_bytes())
            };
            if !h.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
                h.push(("content-type".into(), "application/json".into()));
            }
            (p["statusCode"].as_u64().unwrap_or(200) as u16, h, b, resource)
        }
        _ => json_err(500, "Internal Server Error"),
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

    #[test]
    fn cors_and_loopback_rules() {
        let mut gw = ApiGw::default();
        let (_, api) = gw.handle("POST", "apis", &json!({"name": "a", "corsConfiguration": {"allowOrigins": ["https://good.example"], "allowMethods": ["GET"]}})).unwrap();
        let id = api["apiId"].as_str().unwrap().to_string();
        assert_eq!(api["corsConfiguration"]["allowOrigins"], json!(["https://good.example"]));

        // PUT/GET/DELETE cors round trip
        let (_, c) = gw.handle("PUT", &format!("apis/{id}/cors"), &json!({"allowOrigins": ["https://a.example", "https://b.example"], "allowHeaders": ["content-type"], "maxAge": 600, "allowCredentials": true})).unwrap();
        assert_eq!(c["maxAge"], 600);
        assert_eq!(gw.handle("GET", &format!("apis/{id}/cors"), &json!({})).unwrap().1["allowHeaders"], json!(["content-type"]));

        let cors = gw.cors(&id).unwrap();
        assert!(cors_allows(&cors, "https://a.example") && !cors_allows(&cors, "https://evil.example"));
        assert!(!cors_allows(&cors, ""));
        let h = preflight_headers(&cors, "https://a.example");
        assert!(h.contains(&("Access-Control-Allow-Origin".into(), "https://a.example".into())));
        assert!(h.iter().any(|(k, v)| k == "Access-Control-Max-Age" && v == "600"));

        // AllowCredentials + wildcard origin is refused
        let e = gw.handle("PUT", &format!("apis/{id}/cors"), &json!({"allowOrigins": ["*"], "allowCredentials": true})).unwrap_err();
        assert_eq!(e.code, "BadRequestException");
        assert_eq!(gw.handle("DELETE", &format!("apis/{id}/cors"), &json!({})).unwrap().0, 204);
        assert!(gw.cors(&id).is_none());

        // HTTP_PROXY integrations: loopback only at save time
        assert_eq!(gw.handle("POST", &format!("apis/{id}/integrations"), &json!({"integrationType": "HTTP_PROXY", "integrationUri": "http://example.com/x"})).unwrap_err().code, "BadRequestException");
        assert_eq!(gw.handle("POST", &format!("apis/{id}/integrations"), &json!({"integrationType": "HTTP_PROXY", "integrationUri": "https://127.0.0.1:80/x"})).unwrap_err().code, "BadRequestException");
        let (_, i) = gw.handle("POST", &format!("apis/{id}/integrations"), &json!({"integrationType": "HTTP_PROXY", "integrationUri": "http://${stageVariables.h}:${stageVariables.p}"})).unwrap();
        let iid = i["integrationId"].as_str().unwrap();
        let (_, rt) = gw.handle("POST", &format!("apis/{id}/routes"), &json!({"routeKey": "GET /{p+}", "target": format!("integrations/{iid}")})).unwrap();
        assert_eq!(rt["target"], format!("integrations/{iid}"));
        let (_, st) = gw.handle("POST", &format!("apis/{id}/stages"), &json!({"stageName": "s1", "autoDeploy": true, "stageVariables": {"h": "127.0.0.1", "p": "8123"}})).unwrap();
        assert_eq!(st["stageVariables"]["p"], "8123");
        let t = gw.resolve(&id, "GET", "/s1/anything").unwrap();
        assert_eq!(t.stage, "s1");
        assert_eq!(t.proxy_uri.as_deref(), Some("http://127.0.0.1:8123"));
        assert!(t.function.is_none());
        // $default stage has no variables: the placeholder survives and fails the loopback check at invoke time
        let d = gw.resolve(&id, "GET", "/anything").unwrap();
        assert_eq!(d.proxy_uri.as_deref(), Some("http://${stageVariables.h}:${stageVariables.p}"));
    }

    #[tokio::test]
    async fn http_proxy_roundtrip() {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut all = Vec::new();
            let mut buf = [0u8; 4096];
            // Read the whole request (headers + Content-Length body) so closing never resets the client.
            loop {
                let n = s.read(&mut buf).unwrap();
                if n == 0 { break }
                all.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&all).to_string();
                if let Some((h, b)) = text.split_once("\r\n\r\n") {
                    let want: usize = h.lines().find(|l| l.to_ascii_lowercase().starts_with("content-length:")).and_then(|l| l.split(':').nth(1)).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
                    if b.len() >= want { break }
                }
            }
            let req = String::from_utf8_lossy(&all).to_string();
            let body = if req.starts_with("POST /echo?a=1") {
                format!("saw {} {}", req.lines().find(|l| l.to_ascii_lowercase().starts_with("x-fwd:")).map(String::from).unwrap_or_default().trim(), req.split("\r\n\r\n").nth(1).unwrap_or(""))
            } else { String::new() };
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Backend: yes\r\nContent-Length: {}\r\n\r\n{body}", body.len());
            s.write_all(resp.as_bytes()).unwrap();
        });
        let (status, h, b) = http_proxy(&format!("http://127.0.0.1:{port}"), "POST", "/echo", "a=1", &[("x-fwd".to_string(), "hi".to_string())], b"pay").await.unwrap();
        assert_eq!(status, 200);
        assert!(h.contains(&("X-Backend".to_string(), "yes".to_string())));
        assert_eq!(String::from_utf8(b).unwrap(), "saw x-fwd: hi pay");
        assert!(http_proxy("http://example.com", "GET", "/", "", &[], b"").await.is_err());
    }
}

// API Gateway HTTP APIs (apigatewayv2, REST-JSON) with Lambda proxy integrations.
// Invoke URL: {endpoint}/_api/{apiId}/[{stage}/]path
// ponytail: REST APIs (v1), HTTP_PROXY integrations, authorizers and CORS config are not emulated yet.
use crate::{err, ApiErr, App};
use serde_json::{json, Map, Value};
use std::{collections::BTreeMap, sync::Arc};

struct Integ {
    ty: String,
    uri: String,
    fmt: String,
}
struct Api {
    name: String,
    protocol: String,
    created: String,
    routes: BTreeMap<String, (String, String)>, // id -> (route key, target)
    integrations: BTreeMap<String, Integ>,
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
        let mut best: Option<((usize, bool, bool), &str, &str, Map<String, Value>)> = None;
        for (key, target) in a.routes.values() {
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
                best = Some((score, key, target, params));
            }
        }
        let (_, key, target, params) = best?;
        let function = target.strip_prefix("integrations/").and_then(|i| a.integrations.get(i)).filter(|i| i.ty == "AWS_PROXY").map(|i| crate::lambda::name_of(&i.uri));
        Some(Target { route_key: key.into(), stage, path, function, params })
    }

    // Control plane. `path` is what follows /v2/.
    pub fn handle(&mut self, method: &str, path: &str, b: &Value) -> Result<(u16, Value), ApiErr> {
        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        let s = |k: &str| b[k].as_str().map(String::from);
        Ok(match (method, parts.as_slice()) {
            ("POST", ["apis"]) => {
                let id = short_id();
                let mut a = Api { name: s("name").unwrap_or_default(), protocol: s("protocolType").unwrap_or("HTTP".into()), created: chrono::Utc::now().to_rfc3339(),
                    routes: BTreeMap::new(), integrations: BTreeMap::new(), stages: BTreeMap::new() };
                if a.protocol != "HTTP" {
                    return Err(err("BadRequestException", "Only HTTP APIs are supported locally"));
                }
                // Quick create: target → integration + $default route + auto-deployed $default stage.
                if let Some(t) = s("target") {
                    let iid = short_id();
                    a.integrations.insert(iid.clone(), Integ { ty: "AWS_PROXY".into(), uri: t, fmt: "2.0".into() });
                    a.routes.insert(short_id(), (s("routeKey").unwrap_or("$default".into()), format!("integrations/{iid}")));
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
                    ("POST", ["routes"]) => {
                        let key = s("routeKey").ok_or_else(|| err("BadRequestException", "routeKey is required"))?;
                        if a.routes.values().any(|(k, _)| *k == key) {
                            return Err(ApiErr { status: 409, ..err("ConflictException", format!("Route with key {key} already exists for this API")) });
                        }
                        let rid = short_id();
                        let target = s("target").unwrap_or_default();
                        a.routes.insert(rid.clone(), (key.clone(), target.clone()));
                        (201, json!({"routeId": rid, "routeKey": key, "target": target, "authorizationType": "NONE"}))
                    }
                    ("GET", ["routes"]) => (200, json!({"items": a.routes.iter().map(|(r, (k, t))| json!({"routeId": r, "routeKey": k, "target": t})).collect::<Vec<_>>()})),
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
                let rows: Vec<Value> = a.routes.values().map(|(k, t)| {
                    let fname = t.strip_prefix("integrations/").and_then(|i| a.integrations.get(i)).map(|i| crate::lambda::name_of(&i.uri)).unwrap_or_default();
                    json!([k, fname])
                }).collect();
                json!({"name": a.name, "count": rows.len(), "sub": format!("{}/_api/{id} · 스테이지 {}", crate::endpoint(), a.stages.keys().cloned().collect::<Vec<_>>().join(", ")),
                       "cols": ["라우트", "Lambda"], "rows": rows})
            })
            .collect()
    }
}

// Data plane: turn an HTTP request into a payload-v2 Lambda event and the result into a response.
pub async fn invoke(app: &Arc<App>, method: &str, api: &str, rest: &str, query: &str, headers: &axum::http::HeaderMap, body: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>, String) {
    let not_found = |m: &str| (404, vec![("content-type".into(), "application/json".into())], json!({"message": m}).to_string().into_bytes(), String::new());
    let Some(t) = app.apigw.lock().unwrap().resolve(api, method, rest) else { return not_found("Not Found") };
    let Some(func) = t.function.clone() else { return not_found("Not Found") };
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
        event["queryStringParameters"] = qs.into();
    }
    if !t.params.is_empty() {
        event["pathParameters"] = t.params.clone().into();
    }
    if !body.is_empty() {
        event["body"] = text.map_or_else(|_| crate::b64(body), String::from).into();
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
        _ => (500, vec![("content-type".into(), "application/json".into())], json!({"message": "Internal Server Error"}).to_string().into_bytes(), t.route_key),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn paths() {
        use super::match_path;
        assert_eq!(match_path("/items/{id}", "/items/42").unwrap()["id"], "42");
        assert!(match_path("/items/{id}", "/items").is_none() && match_path("/items", "/items/1").is_none());
        assert_eq!(match_path("/files/{rest+}", "/files/a/b.txt").unwrap()["rest"], "a/b.txt");
        assert!(match_path("/", "/").is_some());
    }
}

// CloudFormation (Query): JSON/YAML templates (short tags included), parameters, conditions, mappings, intrinsic
// functions, dependency ordering, outputs, create/update/delete with rollback. Resources are created by calling the
// emulator's own services.
// Nested stacks (AWS::CloudFormation::Stack) read TemplateURL from this emulator's S3 only and deploy depth-first.
// ponytail: no change sets, macros/transforms (SAM), custom resources or drift.
use crate::{err, ApiErr, App, ACCOUNT, REGION};
use axum::http::{HeaderMap, Method, Uri};
use serde_json::{json, Map, Value};
use std::{collections::{BTreeMap, HashMap, HashSet}, future::Future, pin::Pin, sync::Arc};

const NOVALUE: &str = "__rocalcloud_novalue__";

#[derive(Clone)]
struct Res {
    logical: String,
    ty: String,
    phys: String,
    attrs: Map<String, Value>,
    props: Value,
    status: String,
}
struct Stack {
    id: String,
    status: String,
    reason: String,
    created: String,
    template: String,
    params: Vec<(String, String)>,
    outputs: Vec<(String, String, String)>,
    exports: Vec<(String, String, String)>, // (output key, export name, value) for Fn::ImportValue
    resources: Vec<Res>,
    events: Vec<Value>,
    parent: Option<String>, // nested stacks: ParentId / RootId (stack ids) and nesting depth
    root: Option<String>,
    depth: u8,
}

#[derive(Default)]
pub struct Cfn {
    stacks: BTreeMap<String, Stack>,
}

pub enum Job {
    Deploy(String, bool), // stack name, is update
    Delete(String),
}

// ---------- template parsing ----------

fn yaml_to_json(v: serde_yaml::Value) -> Value {
    use serde_yaml::Value as Y;
    match v {
        Y::Null => Value::Null,
        Y::Bool(b) => b.into(),
        Y::Number(n) => n.as_i64().map(Value::from).or_else(|| n.as_f64().map(Value::from)).unwrap_or(Value::Null),
        Y::String(s) => s.into(),
        Y::Sequence(a) => a.into_iter().map(yaml_to_json).collect(),
        Y::Mapping(m) => Value::Object(m.into_iter().map(|(k, v)| (k.as_str().map_or_else(|| format!("{k:?}"), String::from), yaml_to_json(v))).collect()),
        // Short-form intrinsics: !Ref X → {"Ref": X}, !GetAtt A.B → {"Fn::GetAtt": [A, B]}, !Sub → {"Fn::Sub": ...}
        Y::Tagged(t) => {
            let tag = t.tag.to_string().trim_start_matches('!').to_string();
            let inner = yaml_to_json(t.value);
            match tag.as_str() {
                "Ref" => json!({ "Ref": inner }),
                "Condition" => json!({ "Condition": inner }),
                "GetAtt" => {
                    let parts = inner.as_str().and_then(|s| s.split_once('.')).map(|(a, b)| json!([a, b])).unwrap_or(inner);
                    json!({ "Fn::GetAtt": parts })
                }
                _ => json!({ format!("Fn::{tag}"): inner }),
            }
        }
    }
}

fn parse(body: &str) -> Result<Value, ApiErr> {
    let t: Value = serde_yaml::from_str::<serde_yaml::Value>(body).map(yaml_to_json).map_err(|e| err("ValidationError", format!("Template format error: {e}")))?;
    if !t["Resources"].is_object() {
        return Err(err("ValidationError", "Template format error: At least one Resources member must be defined."));
    }
    Ok(t)
}

// Logical resource ids a value depends on.
fn deps(v: &Value, names: &HashSet<String>, out: &mut HashSet<String>) {
    match v {
        Value::Object(m) => {
            if let Some(Value::String(r)) = m.get("Ref") {
                if names.contains(r) {
                    out.insert(r.clone());
                }
            }
            if let Some(a) = m.get("Fn::GetAtt").and_then(|g| g[0].as_str()) {
                if names.contains(a) {
                    out.insert(a.into());
                }
            }
            if let Some(s) = m.get("Fn::Sub").and_then(|s| s.as_str().or(s[0].as_str())) {
                for part in s.split("${").skip(1) {
                    let n = part.split(['}', '.']).next().unwrap_or("");
                    if names.contains(n) {
                        out.insert(n.into());
                    }
                }
            }
            m.values().for_each(|x| deps(x, names, out));
        }
        Value::Array(a) => a.iter().for_each(|x| deps(x, names, out)),
        _ => {}
    }
}

// Creation order (dependencies first); errors on cycles.
fn order(t: &Value) -> Result<Vec<String>, String> {
    let res = t["Resources"].as_object().cloned().unwrap_or_default();
    let names: HashSet<String> = res.keys().cloned().collect();
    let mut need: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    for (k, r) in &res {
        let mut d = HashSet::new();
        deps(&r["Properties"], &names, &mut d);
        for x in crate::iam::strs(&r["DependsOn"]) {
            d.insert(x);
        }
        need.insert(k.clone(), d);
    }
    let mut out = vec![];
    while !need.is_empty() {
        let ready: Vec<String> = need.iter().filter(|(_, d)| d.iter().all(|x| out.contains(x))).map(|(k, _)| k.clone()).collect();
        if ready.is_empty() {
            return Err(format!("Circular dependency between resources: {:?}", need.keys().collect::<Vec<_>>()));
        }
        for k in ready {
            need.remove(&k);
            out.push(k);
        }
    }
    Ok(out)
}

// ---------- intrinsic functions ----------

struct Ctx<'a> {
    t: &'a Value,
    stack: String,
    stack_id: String,
    params: HashMap<String, Value>,
    res: HashMap<String, (String, Map<String, Value>)>,
    conds: HashMap<String, bool>,
    imports: HashMap<String, String>, // exported name -> value, from already deployed stacks
}

fn text(v: &Value) -> String {
    v.as_str().map_or_else(|| v.to_string(), String::from)
}

impl Ctx<'_> {
    fn reference(&self, n: &str) -> Result<Value, String> {
        Ok(match n {
            "AWS::Region" => REGION.as_str().into(),
            "AWS::AccountId" => ACCOUNT.into(),
            "AWS::StackName" => self.stack.clone().into(),
            "AWS::StackId" => self.stack_id.clone().into(),
            "AWS::Partition" => "aws".into(),
            "AWS::URLSuffix" => "amazonaws.com".into(),
            "AWS::NoValue" => NOVALUE.into(),
            _ => match (self.params.get(n), self.res.get(n)) {
                (Some(p), _) => p.clone(),
                (_, Some((phys, _))) => phys.clone().into(),
                _ => return Err(format!("Unresolved resource dependency [{n}]")),
            },
        })
    }
    fn getatt(&self, r: &str, a: &str) -> Result<Value, String> {
        self.res.get(r).and_then(|(_, attrs)| attrs.get(a).cloned()).ok_or_else(|| format!("Attribute {a} of {r} is not available"))
    }
    fn cond(&self, v: &Value) -> Result<bool, String> {
        if let Some(n) = v["Condition"].as_str() {
            return self.conds.get(n).copied().ok_or_else(|| format!("Unknown condition {n}"));
        }
        let args = |k: &str| v[k].as_array().cloned().unwrap_or_default();
        if v.get("Fn::Equals").is_some() {
            let a = args("Fn::Equals");
            return Ok(self.resolve(&a[0])? == self.resolve(&a[1])?);
        }
        if v.get("Fn::Not").is_some() {
            return Ok(!self.cond(&args("Fn::Not")[0])?);
        }
        if v.get("Fn::And").is_some() {
            return args("Fn::And").iter().try_fold(true, |acc, c| Ok(acc && self.cond(c)?));
        }
        if v.get("Fn::Or").is_some() {
            return args("Fn::Or").iter().try_fold(false, |acc, c| Ok(acc || self.cond(c)?));
        }
        Err(format!("Invalid condition {v}"))
    }

    fn sub(&self, s: &str, vars: &Map<String, Value>) -> Result<String, String> {
        let mut out = String::new();
        let mut rest = s;
        while let Some(i) = rest.find("${") {
            out += &rest[..i];
            let after = &rest[i + 2..];
            let end = after.find('}').ok_or("Unclosed ${ in Fn::Sub")?;
            let name = &after[..end];
            if let Some(lit) = name.strip_prefix('!') {
                out += &format!("${{{lit}}}");
            } else if let Some(v) = vars.get(name) {
                out += &text(&self.resolve(v)?);
            } else if let Some((r, a)) = name.split_once('.').filter(|(r, _)| !r.starts_with("AWS::")) {
                out += &text(&self.getatt(r, a)?);
            } else {
                out += &text(&self.reference(name)?);
            }
            rest = &after[end + 1..];
        }
        Ok(out + rest)
    }

    fn resolve(&self, v: &Value) -> Result<Value, String> {
        Ok(match v {
            Value::Object(m) if m.len() == 1 => {
                let (k, a) = m.iter().next().unwrap();
                let arr = || a.as_array().cloned().unwrap_or_default();
                match k.as_str() {
                    "Ref" => self.reference(a.as_str().unwrap_or(""))?,
                    "Fn::GetAtt" => {
                        let a = arr();
                        self.getatt(a.first().and_then(Value::as_str).unwrap_or(""), &text(&self.resolve(a.get(1).unwrap_or(&Value::Null))?))?
                    }
                    "Fn::Sub" => match a {
                        Value::String(s) => self.sub(s, &Map::new())?.into(),
                        _ => self.sub(a[0].as_str().unwrap_or(""), a[1].as_object().unwrap_or(&Map::new()))?.into(),
                    },
                    "Fn::Join" => {
                        let a = arr();
                        let items = self.resolve(&a[1])?;
                        items.as_array().into_iter().flatten().filter(|x| x.as_str() != Some(NOVALUE)).map(text).collect::<Vec<_>>().join(a[0].as_str().unwrap_or("")).into()
                    }
                    "Fn::ImportValue" => {
                        let name = text(a);
                        self.imports.get(&name).cloned().map(Value::String).ok_or_else(|| format!("Fn::ImportValue: {name} not found"))?
                    }
                    "Fn::Select" => {
                        let a = arr();
                        let i = text(&self.resolve(&a[0])?).parse::<usize>().map_err(|_| "Fn::Select index must be a number")?;
                        self.resolve(&a[1])?.get(i).cloned().ok_or("Fn::Select index out of range")?
                    }
                    "Fn::Split" => {
                        let a = arr();
                        text(&self.resolve(&a[1])?).split(a[0].as_str().unwrap_or(",")).map(|s| Value::String(s.into())).collect()
                    }
                    "Fn::If" => {
                        let a = arr();
                        let c = *self.conds.get(a[0].as_str().unwrap_or("")).ok_or("Unknown condition in Fn::If")?;
                        self.resolve(&a[if c { 1 } else { 2 }])?
                    }
                    "Fn::GetAZs" => json!([format!("{}a", *REGION), format!("{}b", *REGION), format!("{}c", *REGION)]),
                    "Fn::Base64" => crate::b64(text(&self.resolve(a)?).as_bytes()).into(),
                    "Fn::FindInMap" => {
                        let a: Vec<String> = arr().iter().map(|x| self.resolve(x).map(|v| text(&v))).collect::<Result<_, _>>()?;
                        self.t["Mappings"][&a[0]][&a[1]][&a[2]].clone()
                    }
                    "Fn::Equals" | "Fn::Not" | "Fn::And" | "Fn::Or" | "Condition" => self.cond(v)?.into(),
                    _ => Value::Object(Map::from_iter([(k.clone(), self.resolve(a)?)])),
                }
            }
            Value::Object(m) => {
                let mut o = Map::new();
                for (k, x) in m {
                    let r = self.resolve(x)?;
                    if r.as_str() != Some(NOVALUE) {
                        o.insert(k.clone(), r);
                    }
                }
                Value::Object(o)
            }
            Value::Array(a) => a.iter().map(|x| self.resolve(x)).collect::<Result<Vec<_>, _>>()?.into_iter().filter(|x| x.as_str() != Some(NOVALUE)).collect(),
            other => other.clone(),
        })
    }
}

// ---------- resources via the emulator's own services ----------

fn gen_name(stack: &str, logical: &str, max: usize, lower: bool) -> String {
    let n = format!("{stack}-{logical}-{}", &uuid::Uuid::new_v4().simple().to_string()[..8].to_uppercase());
    let n: String = n.chars().take(max).collect();
    if lower { n.to_lowercase() } else { n }
}
fn s(v: &Value) -> String {
    match v {
        Value::String(x) => x.clone(),
        Value::Null => String::new(),
        o => o.to_string(),
    }
}
fn q(pairs: &[(&str, String)]) -> HashMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}
fn api<T>(r: Result<T, ApiErr>) -> Result<T, String> {
    r.map_err(|e| format!("{}: {}", e.code, e.msg))
}

async fn s3_call(app: &App, method: Method, path: &str) -> Result<(), String> {
    let uri: Uri = path.parse().map_err(|_| "bad path")?;
    let h = HeaderMap::new();
    let r = crate::s3::handle(app, &crate::s3::classify(&method, &uri, &h), &h, Default::default());
    if r.status().is_success() { Ok(()) } else {
        let b = axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap_or_default();
        Err(crate::s3::tags(&String::from_utf8_lossy(&b), "Message").concat())
    }
}
// Call the REST v1 control plane in-process (no HTTP round-trip).
async fn apigw_call(app: &Arc<App>, method: &str, path: &str, body: Value) -> Result<Value, String> {
    let r = app.apigw.lock().unwrap().handle_rest(method, path, &body);
    match r {
        Ok((_, v)) => Ok(v),
        Err(e) => Err(e.msg),
    }
}

async fn lambda_call(app: &Arc<App>, op: &str, path: &str, body: Value) -> Result<Value, String> {
    let r = crate::lambda::api(app, op, path, &HashMap::new(), &HeaderMap::new(), body.to_string().as_bytes()).await;
    let ok = r.status().is_success();
    let b = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap_or_default();
    let v: Value = serde_json::from_slice(&b).unwrap_or_default();
    if ok { Ok(v) } else { Err(text(&v["message"])) }
}
fn zip_inline(file: &str, src: &str) -> String {
    use std::io::Write;
    let mut buf = std::io::Cursor::new(Vec::new());
    let mut z = zip::ZipWriter::new(&mut buf);
    let _ = z.start_file(file, zip::write::SimpleFileOptions::default());
    let _ = z.write_all(src.as_bytes());
    let _ = z.finish();
    crate::b64(buf.get_ref())
}

// Apply an in-place property update to a live resource (same physical id).
async fn update_res(app: &Arc<App>, prev: &Res, p: &Value) -> Result<(), String> {
    match prev.ty.as_str() {
        "AWS::SQS::Queue" => {
            let a: Map<String, Value> = p.as_object().into_iter().flatten()
                .filter(|(k, _)| in_place_keys("AWS::SQS::Queue").contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), Value::String(s(v)))).collect();
            api(crate::sqs::handle(app, "SetQueueAttributes", json!({"QueueUrl": prev.phys, "Attributes": a}).to_string().as_bytes(), "local").await).map(drop)
        }
        "AWS::Lambda::Function" => {
            let mut req = json!({"FunctionName": prev.phys});
            for k in ["Environment", "MemorySize", "Timeout", "Description"] {
                if !p[k].is_null() {
                    req[k] = p[k].clone();
                }
            }
            lambda_call(app, "UpdateFunctionConfiguration", &format!("/functions/{}/configuration", prev.phys), req).await.map(drop)
        }
        "AWS::SNS::Topic" => {
            let val = p["DisplayName"].as_str().or_else(|| prev.props["DisplayName"].as_str()).unwrap_or("");
            api(app.sns.lock().unwrap().handle(&q(&[("Action", "SetTopicAttributes".into()), ("TopicArn", prev.phys.clone()), ("AttributeName", "DisplayName".into()), ("AttributeValue", val.into())]))).map(drop)
        }
        "AWS::DynamoDB::Table" => {
            let mut req = json!({"TableName": prev.phys});
            if !p["ProvisionedThroughput"].is_null() {
                req["ProvisionedThroughput"] = p["ProvisionedThroughput"].clone();
            }
            api(crate::ddb::handle(app, "UpdateTable", req.to_string().as_bytes())).map(drop)
        }
        _ => Err(format!("no in-place update for {}", prev.ty)),
    }
}

// Create one resource; returns its physical id (Ref value) and attributes (Fn::GetAtt).
// Template body of a nested stack: only objects in this emulator's S3 (s3://bucket/key or {endpoint}/bucket/key).
fn template_location(url: &str, ep: &str) -> Result<(String, String), String> {
    let rest = url.strip_prefix("s3://")
        .or_else(|| url.strip_prefix(&format!("{ep}/")))
        .or_else(|| url.strip_prefix(&format!("{}/", ep.replace("127.0.0.1", "localhost"))))
        .ok_or_else(|| format!("TemplateURL must be an object in this emulator's S3 (s3://bucket/key or {ep}/bucket/key), got {url}"))?;
    let (b, k) = rest.split_once('/').filter(|(b, k)| !b.is_empty() && !k.is_empty()).ok_or("TemplateURL needs a bucket and a key")?;
    Ok((b.into(), k.into()))
}
fn local_template(app: &App, url: &str) -> Result<String, String> {
    let (b, k) = template_location(url, &crate::endpoint())?;
    let body = app.s3.lock().unwrap().object(&b, &crate::s3::pct_decode(&k)).ok_or_else(|| format!("TemplateURL object s3://{b}/{k} does not exist"))?;
    String::from_utf8(body.to_vec()).map_err(|_| "TemplateURL object is not UTF-8 text".to_string())
}

type Made = Result<(String, Map<String, Value>), String>;
// Boxed so deploy -> create -> nested deploy can recurse. The child's Outputs become "Outputs.X" attributes.
// ponytail: a nested stack whose properties change is replaced (deleted and re-created), not updated in place.
fn nested_create<'a>(app: &'a Arc<App>, parent: &'a str, logical: &'a str, p: &'a Value) -> Pin<Box<dyn Future<Output = Made> + Send + 'a>> {
    Box::pin(async move {
        let body = local_template(app, p["TemplateURL"].as_str().unwrap_or(""))?;
        parse(&body).map_err(|e| e.msg)?;
        let params = p["Parameters"].as_object().into_iter().flatten().map(|(k, v)| (k.clone(), text(v))).collect();
        let child = gen_name(parent, logical, 128, false);
        let id = {
            let mut c = app.cfn.lock().unwrap();
            let ps = &c.stacks[parent];
            let (pid, root, depth) = (ps.id.clone(), ps.root.clone().unwrap_or_else(|| ps.id.clone()), ps.depth + 1);
            if depth > 5 {
                return Err("Nested stacks are limited to 5 levels (is the TemplateURL circular?)".into());
            }
            let id = format!("arn:aws:cloudformation:{}:{ACCOUNT}:stack/{child}/{}", *REGION, uuid::Uuid::new_v4());
            c.stacks.insert(child.clone(), Stack { id: id.clone(), status: "CREATE_IN_PROGRESS".into(), reason: String::new(), created: chrono::Utc::now().to_rfc3339(),
                template: body, params, outputs: vec![], exports: vec![], resources: vec![], events: vec![], parent: Some(pid), root: Some(root), depth });
            id
        };
        deploy(app, &child, false).await;
        let (status, reason, outs) = {
            let c = app.cfn.lock().unwrap();
            let st = &c.stacks[&child];
            (st.status.clone(), st.reason.clone(), st.outputs.clone())
        };
        if status != "CREATE_COMPLETE" {
            destroy(app, &child).await; // its resources were already rolled back
            return Err(format!("Embedded stack {id} was not successfully created: {reason}"));
        }
        Ok((id, outs.into_iter().map(|(k, v, _)| (format!("Outputs.{k}"), Value::String(v))).collect()))
    })
}
fn nested_delete<'a>(app: &'a Arc<App>, id: &'a str) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        let name = app.cfn.lock().unwrap().stacks.iter().find(|(_, s)| s.id == id).map(|(n, _)| n.clone());
        let Some(name) = name else { return Ok(()) };
        destroy(app, &name).await;
        let left = app.cfn.lock().unwrap().stacks.get(&name).map(|s| s.reason.clone());
        left.map_or(Ok(()), Err)
    })
}

async fn create(app: &Arc<App>, stack: &str, logical: &str, ty: &str, p: &Value) -> Result<(String, Map<String, Value>), String> {
    let name = |key: &str, max: usize, lower: bool| p[key].as_str().map_or_else(|| gen_name(stack, logical, max, lower), String::from);
    let attrs = |pairs: Vec<(&str, Value)>| pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect::<Map<String, Value>>();
    let arn = |svc: &str, rest: &str| format!("arn:aws:{svc}:{}:{ACCOUNT}:{rest}", *REGION);
    let root = crate::iam::Principal::Root;
    Ok(match ty {
        "AWS::CloudFormation::Stack" => nested_create(app, stack, logical, p).await?,
        "AWS::S3::Bucket" => {
            let n = name("BucketName", 63, true);
            s3_call(app, Method::PUT, &format!("/{n}")).await?;
            (n.clone(), attrs(vec![("Arn", format!("arn:aws:s3:::{n}").into()), ("DomainName", format!("{n}.s3.amazonaws.com").into()),
                                   ("RegionalDomainName", format!("{n}.s3.{}.amazonaws.com", *REGION).into())]))
        }
        "AWS::SQS::Queue" => {
            let mut n = name("QueueName", 80, false);
            if p["FifoQueue"] == true && !n.ends_with(".fifo") {
                n += ".fifo";
            }
            let a: Map<String, Value> = p.as_object().into_iter().flatten().filter(|(k, _)| *k != "QueueName" && *k != "Tags")
                .map(|(k, v)| (k.clone(), Value::String(s(v)))).collect();
            let r = api(crate::sqs::handle(app, "CreateQueue", json!({"QueueName": n, "Attributes": a}).to_string().as_bytes(), &crate::endpoint()[7..]).await)?;
            let url = s(&r["QueueUrl"]);
            (url.clone(), attrs(vec![("Arn", arn("sqs", &n).into()), ("QueueName", n.into()), ("QueueUrl", url.into())]))
        }
        "AWS::SNS::Topic" => {
            let n = name("TopicName", 256, false);
            let (r, _) = api(app.sns.lock().unwrap().handle(&q(&[("Action", "CreateTopic".into()), ("Name", n.clone())])))?;
            let t = s(&r["TopicArn"]);
            for sub in p["Subscription"].as_array().into_iter().flatten() {
                api(app.sns.lock().unwrap().handle(&q(&[("Action", "Subscribe".into()), ("TopicArn", t.clone()), ("Protocol", s(&sub["Protocol"])), ("Endpoint", s(&sub["Endpoint"]))])))?;
            }
            (t.clone(), attrs(vec![("TopicArn", t.into()), ("TopicName", n.into())]))
        }
        "AWS::SNS::Subscription" => {
            let mut a = vec![("Action", "Subscribe".to_string()), ("TopicArn", s(&p["TopicArn"])), ("Protocol", s(&p["Protocol"])), ("Endpoint", s(&p["Endpoint"]))];
            let mut i = 1;
            for k in ["RawMessageDelivery", "FilterPolicy"] {
                if !p[k].is_null() {
                    a.push((["Attributes.entry.1.key", "Attributes.entry.2.key"][i - 1], k.to_string()));
                    a.push((["Attributes.entry.1.value", "Attributes.entry.2.value"][i - 1], s(&p[k])));
                    i += 1;
                }
            }
            let (r, _) = api(app.sns.lock().unwrap().handle(&q(&a)))?;
            (s(&r["SubscriptionArn"]), Map::new())
        }
        "AWS::DynamoDB::Table" => {
            let n = name("TableName", 255, false);
            let mut req = p.clone();
            req["TableName"] = n.clone().into();
            api(crate::ddb::handle(app, "CreateTable", req.to_string().as_bytes()))?;
            (n.clone(), attrs(vec![("Arn", arn("dynamodb", &format!("table/{n}")).into())]))
        }
        "AWS::IAM::Role" => {
            let n = name("RoleName", 64, false);
            let mut iam = app.iam.lock().unwrap();
            let r = api(iam.handle(&root, &q(&[("Action", "CreateRole".into()), ("RoleName", n.clone()), ("AssumeRolePolicyDocument", s(&p["AssumeRolePolicyDocument"]))])))?;
            for a in p["ManagedPolicyArns"].as_array().into_iter().flatten() {
                // AWS-managed policies don't exist locally; only attach ones created in the emulator.
                let _ = iam.handle(&root, &q(&[("Action", "AttachRolePolicy".into()), ("RoleName", n.clone()), ("PolicyArn", s(a))]));
            }
            for pol in p["Policies"].as_array().into_iter().flatten() {
                api(iam.handle(&root, &q(&[("Action", "PutRolePolicy".into()), ("RoleName", n.clone()), ("PolicyName", s(&pol["PolicyName"])), ("PolicyDocument", s(&pol["PolicyDocument"]))])))?;
            }
            (n, attrs(vec![("Arn", r["Role"]["Arn"].clone()), ("RoleId", r["Role"]["RoleId"].clone())]))
        }
        "AWS::IAM::ManagedPolicy" | "AWS::IAM::Policy" => {
            let n = name(if ty.ends_with("ManagedPolicy") { "ManagedPolicyName" } else { "PolicyName" }, 128, false);
            let doc = s(&p["PolicyDocument"]);
            let mut iam = app.iam.lock().unwrap();
            let id = if ty.ends_with("ManagedPolicy") {
                let r = api(iam.handle(&root, &q(&[("Action", "CreatePolicy".into()), ("PolicyName", n.clone()), ("PolicyDocument", doc.clone())])))?;
                let a = s(&r["Policy"]["Arn"]);
                for role in p["Roles"].as_array().into_iter().flatten() {
                    api(iam.handle(&root, &q(&[("Action", "AttachRolePolicy".into()), ("RoleName", s(role)), ("PolicyArn", a.clone())])))?;
                }
                a
            } else {
                for role in p["Roles"].as_array().into_iter().flatten() {
                    api(iam.handle(&root, &q(&[("Action", "PutRolePolicy".into()), ("RoleName", s(role)), ("PolicyName", n.clone()), ("PolicyDocument", doc.clone())])))?;
                }
                n
            };
            (id, Map::new())
        }
        "AWS::Lambda::Function" => {
            let n = name("FunctionName", 64, false);
            let code = &p["Code"];
            let zip = if let Some(src) = code["ZipFile"].as_str() {
                let file = if s(&p["Runtime"]).starts_with("python") { "index.py" } else { "index.js" };
                zip_inline(file, src)
            } else {
                let obj = app.s3.lock().unwrap().object(&s(&code["S3Bucket"]), &s(&code["S3Key"])).ok_or("Code S3 object not found")?;
                crate::b64(&obj)
            };
            let mut req = json!({"FunctionName": n, "Runtime": p["Runtime"], "Handler": p["Handler"], "Role": p["Role"], "Code": {"ZipFile": zip}});
            for k in ["Environment", "Timeout", "MemorySize", "Description"] {
                if !p[k].is_null() {
                    req[k] = p[k].clone();
                }
            }
            let r = lambda_call(app, "CreateFunction", "/functions", req).await?;
            (n, attrs(vec![("Arn", r["FunctionArn"].clone())]))
        }
        // REST v1 (Day 21): the CFN types call the /restapis control plane directly.
        "AWS::ApiGateway::RestApi" => {
            let n = name("Name", 64, false);
            let r = apigw_call(app, "POST", "/restapis", json!({"name": n})).await?;
            let id = s(&r["id"]);
            (id.clone(), attrs(vec![("RootResourceId", r["rootResourceId"].clone()), ("RestApiId", id.into())]))
        }
        "AWS::ApiGateway::Resource" => {
            let api = s(&p["RestApiId"]);
            let parent = s(&p["ParentId"]);
            let part = s(&p["PathPart"]);
            let r = apigw_call(app, "POST", &format!("/restapis/{api}/resources/{parent}"), json!({"pathPart": part})).await?;
            (s(&r["id"]), Map::new())
        }
        "AWS::ApiGateway::Method" => {
            let api = s(&p["RestApiId"]);
            let res = s(&p["ResourceId"]);
            let m = s(&p["HttpMethod"]);
            let mut body = json!({"authorizationType": p["AuthorizationType"].as_str().unwrap_or("NONE"), "apiKeyRequired": p["ApiKeyRequired"].as_bool().unwrap_or(false)});
            if let Some(a) = p["AuthorizerId"].as_str() {
                body["authorizerId"] = a.into();
            }
            apigw_call(app, "PUT", &format!("/restapis/{api}/resources/{res}/methods/{m}"), body).await?;
            // The Method resource carries its integration inline.
            if let Some(i) = p["Integration"].as_object() {
                let mut ib = json!({"type": i["Type"].as_str().unwrap_or("AWS_PROXY")});
                if let Some(u) = i["Uri"].as_str() {
                    ib["uri"] = u.into();
                }
                apigw_call(app, "PUT", &format!("/restapis/{api}/resources/{res}/methods/{m}/integration"), ib).await?;
            }
            (uuid::Uuid::new_v4().to_string(), Map::new())
        }
        "AWS::ApiGateway::Deployment" => {
            let api = s(&p["RestApiId"]);
            let r = apigw_call(app, "POST", &format!("/restapis/{api}/deployments"), json!({})).await?;
            (s(&r["id"]), Map::new())
        }
        "AWS::ApiGateway::Stage" => {
            let api = s(&p["RestApiId"]);
            let stage = s(&p["StageName"]);
            let dep = s(&p["DeploymentId"]);
            apigw_call(app, "POST", &format!("/restapis/{api}/stages"), json!({"stageName": stage, "deploymentId": dep})).await?;
            (stage, Map::new())
        }
        "AWS::Lambda::Permission" => (uuid::Uuid::new_v4().to_string(), Map::new()),
        "AWS::Lambda::EventSourceMapping" => {
            let r = lambda_call(app, "CreateEventSourceMapping", "/event-source-mappings", p.clone()).await?;
            (s(&r["UUID"]), Map::new())
        }
        "AWS::Logs::LogGroup" => {
            let n = name("LogGroupName", 512, false);
            let mut l = app.logs.lock().unwrap();
            api(l.handle("CreateLogGroup", &json!({"logGroupName": n})))?;
            if let Some(d) = p["RetentionInDays"].as_i64() {
                api(l.handle("PutRetentionPolicy", &json!({"logGroupName": n, "retentionInDays": d})))?;
            }
            (n.clone(), attrs(vec![("Arn", arn("logs", &format!("log-group:{n}:*")).into())]))
        }
        "AWS::SSM::Parameter" => {
            let n = name("Name", 1011, false);
            api(app.ssm.lock().unwrap().handle("PutParameter", &json!({"Name": n, "Value": s(&p["Value"]), "Type": p["Type"].as_str().unwrap_or("String"), "Overwrite": true})))?;
            (n, attrs(vec![("Type", p["Type"].clone()), ("Value", p["Value"].clone())]))
        }
        "AWS::SecretsManager::Secret" => {
            let n = name("Name", 512, false);
            let g = &p["GenerateSecretString"];
            let value = if !g.is_null() {
                let pw = api(app.secrets.lock().unwrap().handle("GetRandomPassword", &json!({"PasswordLength": g["PasswordLength"].as_u64().unwrap_or(32)})))?;
                let pw = s(&pw["RandomPassword"]);
                match (g["SecretStringTemplate"].as_str().and_then(|t| serde_json::from_str::<Value>(t).ok()), g["GenerateStringKey"].as_str()) {
                    (Some(mut t), Some(k)) => {
                        t[k] = pw.into();
                        t.to_string()
                    }
                    _ => pw,
                }
            } else {
                s(&p["SecretString"])
            };
            let r = api(app.secrets.lock().unwrap().handle("CreateSecret", &json!({"Name": n, "SecretString": value, "Description": p["Description"]})))?;
            (s(&r["ARN"]), attrs(vec![("Id", r["ARN"].clone())]))
        }
        "AWS::KMS::Key" => {
            let r = api(app.kms.lock().unwrap().handle("CreateKey", &json!({"Description": p["Description"]})))?;
            (s(&r["KeyMetadata"]["KeyId"]), attrs(vec![("Arn", r["KeyMetadata"]["Arn"].clone()), ("KeyId", r["KeyMetadata"]["KeyId"].clone())]))
        }
        "AWS::KMS::Alias" => {
            api(app.kms.lock().unwrap().handle("CreateAlias", &json!({"AliasName": p["AliasName"], "TargetKeyId": p["TargetKeyId"]})))?;
            (s(&p["AliasName"]), Map::new())
        }
        "AWS::Events::Rule" => {
            let n = name("Name", 64, false);
            let mut req = json!({"Name": n, "State": p["State"].as_str().unwrap_or("ENABLED"), "EventBusName": p["EventBusName"]});
            if !p["EventPattern"].is_null() {
                req["EventPattern"] = s(&p["EventPattern"]).into();
            }
            if !p["ScheduleExpression"].is_null() {
                req["ScheduleExpression"] = p["ScheduleExpression"].clone();
            }
            let (r, _) = api(app.eb.lock().unwrap().handle("PutRule", &req))?;
            if let Some(t) = p["Targets"].as_array() {
                api(app.eb.lock().unwrap().handle("PutTargets", &json!({"Rule": n, "EventBusName": p["EventBusName"], "Targets": t})))?;
            }
            crate::start_schedule(app.clone(), crate::events::bus_of(&req), n.clone());
            (n, attrs(vec![("Arn", r["RuleArn"].clone())]))
        }
        "AWS::StepFunctions::StateMachine" => {
            let n = name("StateMachineName", 80, false);
            let def = if p["DefinitionString"].is_null() { s(&p["Definition"]) } else { s(&p["DefinitionString"]) };
            let (r, _) = api(app.sfn.lock().unwrap().handle("CreateStateMachine", &json!({"name": n, "definition": def, "roleArn": p["RoleArn"]})))?;
            let a = s(&r["stateMachineArn"]);
            (a.clone(), attrs(vec![("Arn", a.into()), ("Name", n.into())]))
        }
        other => return Err(format!("Resource type {other} is not supported locally")),
    })
}

async fn delete(app: &Arc<App>, r: &Res) -> Result<(), String> {
    let root = crate::iam::Principal::Root;
    let p = &r.phys;
    match r.ty.as_str() {
        "AWS::CloudFormation::Stack" => nested_delete(app, p).await,
        "AWS::S3::Bucket" => s3_call(app, Method::DELETE, &format!("/{p}")).await,
        "AWS::SQS::Queue" => api(crate::sqs::handle(app, "DeleteQueue", json!({"QueueUrl": p}).to_string().as_bytes(), "local").await).map(drop),
        "AWS::SNS::Topic" => api(app.sns.lock().unwrap().handle(&q(&[("Action", "DeleteTopic".into()), ("TopicArn", p.clone())]))).map(drop),
        "AWS::SNS::Subscription" => api(app.sns.lock().unwrap().handle(&q(&[("Action", "Unsubscribe".into()), ("SubscriptionArn", p.clone())]))).map(drop),
        "AWS::DynamoDB::Table" => api(crate::ddb::handle(app, "DeleteTable", json!({"TableName": p}).to_string().as_bytes())).map(drop),
        "AWS::IAM::Role" => {
            let mut iam = app.iam.lock().unwrap();
            if let Ok(a) = iam.handle(&root, &q(&[("Action", "ListAttachedRolePolicies".into()), ("RoleName", p.clone())])) {
                for x in a["AttachedPolicies"].as_array().into_iter().flatten() {
                    let _ = iam.handle(&root, &q(&[("Action", "DetachRolePolicy".into()), ("RoleName", p.clone()), ("PolicyArn", s(&x["PolicyArn"]))]));
                }
            }
            if let Ok(a) = iam.handle(&root, &q(&[("Action", "ListRolePolicies".into()), ("RoleName", p.clone())])) {
                for n in a["PolicyNames"].as_array().into_iter().flatten() {
                    let _ = iam.handle(&root, &q(&[("Action", "DeleteRolePolicy".into()), ("RoleName", p.clone()), ("PolicyName", s(n))]));
                }
            }
            api(iam.handle(&root, &q(&[("Action", "DeleteRole".into()), ("RoleName", p.clone())]))).map(drop)
        }
        "AWS::IAM::ManagedPolicy" => {
            let mut iam = app.iam.lock().unwrap();
            for role in r.props["Roles"].as_array().into_iter().flatten() {
                let _ = iam.handle(&root, &q(&[("Action", "DetachRolePolicy".into()), ("RoleName", s(role)), ("PolicyArn", p.clone())]));
            }
            api(iam.handle(&root, &q(&[("Action", "DeletePolicy".into()), ("PolicyArn", p.clone())]))).map(drop)
        }
        "AWS::IAM::Policy" => {
            let mut iam = app.iam.lock().unwrap();
            for role in r.props["Roles"].as_array().into_iter().flatten() {
                let _ = iam.handle(&root, &q(&[("Action", "DeleteRolePolicy".into()), ("RoleName", s(role)), ("PolicyName", p.clone())]));
            }
            Ok(())
        }
        "AWS::Lambda::Function" => lambda_call(app, "DeleteFunction", &format!("/functions/{p}"), json!({})).await.map(drop),
        "AWS::Lambda::EventSourceMapping" => lambda_call(app, "DeleteEventSourceMapping", &format!("/event-source-mappings/{p}"), json!({})).await.map(drop),
        "AWS::ApiGateway::RestApi" => apigw_call(app, "DELETE", &format!("/restapis/{p}"), json!({})).await.map(drop),
        "AWS::ApiGateway::Resource" | "AWS::ApiGateway::Method" | "AWS::ApiGateway::Deployment" | "AWS::ApiGateway::Stage" => Ok(()),
        "AWS::Logs::LogGroup" => api(app.logs.lock().unwrap().handle("DeleteLogGroup", &json!({"logGroupName": p}))).map(drop),
        "AWS::SSM::Parameter" => api(app.ssm.lock().unwrap().handle("DeleteParameter", &json!({"Name": p}))).map(drop),
        "AWS::SecretsManager::Secret" => api(app.secrets.lock().unwrap().handle("DeleteSecret", &json!({"SecretId": p, "ForceDeleteWithoutRecovery": true}))).map(drop),
        "AWS::KMS::Key" => api(app.kms.lock().unwrap().handle("ScheduleKeyDeletion", &json!({"KeyId": p, "PendingWindowInDays": 7}))).map(drop),
        "AWS::KMS::Alias" => api(app.kms.lock().unwrap().handle("DeleteAlias", &json!({"AliasName": p}))).map(drop),
        "AWS::Events::Rule" => {
            let mut eb = app.eb.lock().unwrap();
            let bus = r.props["EventBusName"].clone();
            let ids: Vec<Value> = r.props["Targets"].as_array().into_iter().flatten().map(|t| t["Id"].clone()).collect();
            let _ = eb.handle("RemoveTargets", &json!({"Rule": p, "EventBusName": bus, "Ids": ids}));
            api(eb.handle("DeleteRule", &json!({"Name": p, "EventBusName": bus}))).map(drop)
        }
        "AWS::StepFunctions::StateMachine" => api(app.sfn.lock().unwrap().handle("DeleteStateMachine", &json!({"stateMachineArn": p}))).map(drop),
        _ => Ok(()),
    }
}

// ---------- stack lifecycle ----------

fn event(app: &App, stack: &str, logical: &str, ty: &str, phys: &str, status: &str, reason: &str) {
    let mut c = app.cfn.lock().unwrap();
    if let Some(st) = c.stacks.get_mut(stack) {
        st.events.push(json!({"StackId": st.id, "StackName": stack, "EventId": uuid::Uuid::new_v4().to_string(), "LogicalResourceId": logical,
            "PhysicalResourceId": phys, "ResourceType": ty, "ResourceStatus": status, "ResourceStatusReason": reason, "Timestamp": chrono::Utc::now().to_rfc3339()}));
    }
    drop(c);
    crate::emit(app, json!({"ts": chrono::Utc::now().to_rfc3339(), "service": "cloudformation", "op": "ResourceStatus", "target": format!("{stack}/{logical}"),
        "result": status, "status": if status.contains("FAILED") { 500 } else { 200 }}));
}
fn set_status(app: &App, stack: &str, status: &str, reason: &str) {
    if let Some(st) = app.cfn.lock().unwrap().stacks.get_mut(stack) {
        (st.status, st.reason) = (status.into(), reason.into());
    }
    let ty = "AWS::CloudFormation::Stack";
    event(app, stack, stack, ty, stack, status, reason);
}

// Properties each resource type can update in place (same physical id); anything else replaces.
// ponytail: DynamoDB billing-mode/GSI changes and S3 property changes still replace.
fn in_place_keys(ty: &str) -> &'static [&'static str] {
    match ty {
        "AWS::SQS::Queue" => &["VisibilityTimeout", "DelaySeconds", "MaximumMessageSize", "MessageRetentionPeriod", "ReceiveMessageWaitTimeSeconds"],
        "AWS::Lambda::Function" => &["Environment", "MemorySize", "Timeout", "Description"],
        "AWS::SNS::Topic" => &["DisplayName"],
        "AWS::DynamoDB::Table" => &["ProvisionedThroughput"],
        _ => &[],
    }
}

// Whether every property change between two templates is in the in-place set (and at least one changed).
fn in_place_change(ty: &str, old: &Value, new: &Value) -> bool {
    let ok = in_place_keys(ty);
    let mut any = false;
    for k in old.as_object().into_iter().flatten().map(|(k, _)| k.as_str())
        .chain(new.as_object().into_iter().flatten().map(|(k, _)| k.as_str())) {
        if old.get(k) != new.get(k) {
            if !ok.contains(&k) {
                return false;
            }
            any = true;
        }
    }
    any
}

// Collect every Fn::ImportValue name in a template.
fn collect_imports(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            if m.len() == 1 {
                if let Some(iv) = m.get("Fn::ImportValue") {
                    out.push(text(iv));
                }
            }
            for v in m.values() {
                collect_imports(v, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|v| collect_imports(v, out)),
        _ => {}
    }
}

// Stack names whose template imports `export`.
fn stacks_importing(c: &Cfn, export: &str, skip: &str) -> Vec<String> {
    c.stacks.iter().filter_map(|(n, st)| {
        (n != skip && parse(&st.template).ok().map(|t| {
            let mut names = vec![];
            collect_imports(&t, &mut names);
            names.iter().any(|x| x == export)
        }).unwrap_or(false)).then(|| n.clone())
    }).collect()
}

// Create or update: walk resources in dependency order, reusing unchanged ones; roll back on failure.
async fn deploy(app: &Arc<App>, name: &str, update: bool) {
    let (template, params, id, old, imports, old_exports) = {
        let c = app.cfn.lock().unwrap();
        let st = &c.stacks[name];
        (st.template.clone(), st.params.clone(), st.id.clone(), st.resources.clone(),
         c.stacks.values().flat_map(|s| s.exports.iter().map(|(_, n, v)| (n.clone(), v.clone()))).collect::<HashMap<String, String>>(), st.exports.clone())
    };
    let (prefix, done, rollback) = if update { ("UPDATE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE") } else { ("CREATE", "CREATE_COMPLETE", "ROLLBACK_COMPLETE") };
    let t = match parse(&template) {
        Ok(t) => t,
        Err(e) => return set_status(app, name, rollback, &e.msg),
    };
    let mut ctx = Ctx { t: &t, stack: name.into(), stack_id: id, params: HashMap::new(), res: HashMap::new(), conds: HashMap::new(), imports };
    let result: Result<(Vec<Res>, Vec<(String, String, String)>, Vec<(String, String, String)>), (String, Vec<Res>)> = async {
        for (k, def) in t["Parameters"].as_object().into_iter().flatten() {
            let v = params.iter().find(|(p, _)| p == k).map(|(_, v)| v.clone()).or_else(|| def["Default"].as_str().map(String::from).or(def["Default"].as_i64().map(|n| n.to_string())))
                .ok_or_else(|| (format!("Parameters: [{k}] must have values"), vec![]))?;
            if let Some(allowed) = def["AllowedValues"].as_array() {
                if !allowed.iter().any(|a| text(a) == v) {
                    return Err((format!("Parameter '{k}' must be one of AllowedValues"), vec![]));
                }
            }
            let v = if def["Type"].as_str().is_some_and(|t| t.starts_with("List<") || t == "CommaDelimitedList") {
                v.split(',').map(|x| Value::String(x.trim().into())).collect()
            } else {
                Value::String(v)
            };
            ctx.params.insert(k.clone(), v);
        }
        for (k, c) in t["Conditions"].as_object().into_iter().flatten() {
            let b = ctx.cond(c).map_err(|e| (e, vec![]))?;
            ctx.conds.insert(k.clone(), b);
        }
        let ord = order(&t).map_err(|e| (e, vec![]))?;
        let mut made: Vec<Res> = vec![];
        for logical in ord {
            let def = &t["Resources"][&logical];
            if def["Condition"].as_str().is_some_and(|c| !ctx.conds.get(c).copied().unwrap_or(true)) {
                continue;
            }
            let ty = def["Type"].as_str().unwrap_or("").to_string();
            let props = ctx.resolve(&def["Properties"]).map_err(|e| (e, made.clone()))?;
            if let Some(prev) = old.iter().find(|r| r.logical == logical && r.ty == ty && r.props == props) {
                ctx.res.insert(logical.clone(), (prev.phys.clone(), prev.attrs.clone()));
                made.push(prev.clone());
                continue;
            }
            if let Some(prev) = old.iter().find(|r| r.logical == logical && r.ty == ty && in_place_change(&ty, &r.props, &props)) {
                // In-place update: properties the service can change keep the same physical id.
                event(app, name, &logical, &ty, &prev.phys, "UPDATE_IN_PROGRESS", "");
                match update_res(app, prev, &props).await {
                    Ok(()) => {
                        event(app, name, &logical, &ty, &prev.phys, "UPDATE_COMPLETE", "");
                        ctx.res.insert(logical.clone(), (prev.phys.clone(), prev.attrs.clone()));
                        made.push(Res { logical, ty, phys: prev.phys.clone(), attrs: prev.attrs.clone(), props, status: "UPDATE_COMPLETE".into() });
                        continue;
                    }
                    Err(e) => {
                        event(app, name, &logical, &ty, &prev.phys, "UPDATE_FAILED", &e);
                        return Err((format!("Resource {logical} failed: {e}"), made));
                    }
                }
            }
            if let Some(prev) = old.iter().find(|r| r.logical == logical) {
                event(app, name, &logical, &prev.ty, &prev.phys, "DELETE_IN_PROGRESS", "Requested update requires the replacement of the existing resource");
                let _ = delete(app, prev).await;
            }
            event(app, name, &logical, &ty, "", &format!("{prefix}_IN_PROGRESS"), "");
            match create(app, name, &logical, &ty, &props).await {
                Ok((phys, attrs)) => {
                    event(app, name, &logical, &ty, &phys, &format!("{prefix}_COMPLETE"), "");
                    ctx.res.insert(logical.clone(), (phys.clone(), attrs.clone()));
                    made.push(Res { logical, ty, phys, attrs, props, status: format!("{prefix}_COMPLETE") });
                }
                Err(e) => {
                    event(app, name, &logical, &ty, "", &format!("{prefix}_FAILED"), &e);
                    return Err((format!("Resource {logical} failed: {e}"), made));
                }
            }
        }
        let mut outs = vec![];
        let mut exports = vec![];
        for (k, o) in t["Outputs"].as_object().into_iter().flatten() {
            if o["Condition"].as_str().is_some_and(|c| !ctx.conds.get(c).copied().unwrap_or(true)) {
                continue;
            }
            let v = ctx.resolve(&o["Value"]).map_err(|e| (e, made.clone()))?;
            outs.push((k.clone(), text(&v), o["Description"].as_str().unwrap_or("").to_string()));
            if let Some(en) = o["Export"]["Name"].as_str() {
                exports.push((k.clone(), en.to_string(), text(&v)));
            }
        }
        // An exported value that another stack imports must not change.
        for (_, en, ev) in &exports {
            if old_exports.iter().any(|(_, n, v)| n == en && v != ev) {
                let importers = {
                    let c = app.cfn.lock().unwrap();
                    stacks_importing(&c, en, name)
                };
                if !importers.is_empty() {
                    return Err((format!("Export {en} cannot be changed because it is in use by {}", importers.join(", ")), made));
                }
            }
        }
        Ok((made, outs, exports))
    }.await;
    match result {
        Ok((made, outs, exports)) => {
            // Old resources that are no longer in the template.
            for r in old.iter().rev().filter(|r| !made.iter().any(|m| m.logical == r.logical && m.phys == r.phys)) {
                if made.iter().any(|m| m.logical == r.logical) {
                    continue; // already replaced above
                }
                event(app, name, &r.logical, &r.ty, &r.phys, "DELETE_IN_PROGRESS", "");
                let _ = delete(app, r).await;
                event(app, name, &r.logical, &r.ty, &r.phys, "DELETE_COMPLETE", "");
            }
            if let Some(st) = app.cfn.lock().unwrap().stacks.get_mut(name) {
                (st.resources, st.outputs, st.exports) = (made, outs, exports);
            }
            set_status(app, name, done, "");
        }
        Err((reason, made)) => {
            // ponytail: rollback deletes what this attempt created; an update does not restore replaced resources.
            set_status(app, name, &format!("{}ROLLBACK_IN_PROGRESS", if update { "UPDATE_" } else { "" }), &reason);
            for r in made.iter().rev().filter(|r| !old.iter().any(|o| o.phys == r.phys)) {
                let _ = delete(app, r).await;
                event(app, name, &r.logical, &r.ty, &r.phys, "DELETE_COMPLETE", "Rollback");
            }
            if let Some(st) = app.cfn.lock().unwrap().stacks.get_mut(name) {
                st.resources = made.into_iter().filter(|r| old.iter().any(|o| o.phys == r.phys)).collect();
            }
            set_status(app, name, rollback, &reason);
        }
    }
}

async fn destroy(app: &Arc<App>, name: &str) {
    let res = app.cfn.lock().unwrap().stacks.get(name).map(|s| s.resources.clone()).unwrap_or_default();
    for r in res.iter().rev() {
        event(app, name, &r.logical, &r.ty, &r.phys, "DELETE_IN_PROGRESS", "");
        match delete(app, r).await {
            Ok(()) => event(app, name, &r.logical, &r.ty, &r.phys, "DELETE_COMPLETE", ""),
            Err(e) => {
                event(app, name, &r.logical, &r.ty, &r.phys, "DELETE_FAILED", &e);
                return set_status(app, name, "DELETE_FAILED", &format!("{} could not be deleted: {e}", r.logical));
            }
        }
    }
    set_status(app, name, "DELETE_COMPLETE", "");
    app.cfn.lock().unwrap().stacks.remove(name);
}

pub async fn run(app: Arc<App>, job: Job) {
    match job {
        Job::Deploy(name, update) => deploy(&app, &name, update).await,
        Job::Delete(name) => destroy(&app, &name).await,
    }
}

// ---------- API ----------

impl Cfn {
    fn stack_json(&self, name: &str, s: &Stack) -> Value {
        json!({"StackId": s.id, "StackName": name, "StackStatus": s.status, "StackStatusReason": s.reason, "CreationTime": s.created,
            "ParentId": s.parent, "RootId": s.root,
            "Parameters": s.params.iter().map(|(k, v)| json!({"ParameterKey": k, "ParameterValue": v})).collect::<Vec<_>>(),
            "Outputs": s.outputs.iter().map(|(k, v, d)| {
                let mut o = json!({"OutputKey": k, "OutputValue": v, "Description": d});
                if let Some((_, en, _)) = s.exports.iter().find(|(ok, _, _)| ok == k) {
                    o["ExportName"] = en.as_str().into();
                }
                o
            }).collect::<Vec<_>>()})
    }
    fn find(&self, id: &str) -> Result<(String, &Stack), ApiErr> {
        self.stacks.iter().find(|(n, s)| *n == id || s.id == id).map(|(n, s)| (n.clone(), s))
            .ok_or_else(|| err("ValidationError", format!("Stack with id {id} does not exist")))
    }

    pub fn handle(&mut self, qs: &HashMap<String, String>) -> Result<(Value, Option<Job>), ApiErr> {
        let p = |k: &str| qs.get(k).cloned().ok_or_else(|| err("ValidationError", format!("{k} is required")));
        let params = || (1..).map_while(|i| Some((qs.get(&format!("Parameters.member.{i}.ParameterKey"))?.clone(),
            qs.get(&format!("Parameters.member.{i}.ParameterValue")).cloned().unwrap_or_default()))).collect::<Vec<_>>();
        let action = qs.get("Action").map_or("", String::as_str);
        Ok(match action {
            "CreateStack" => {
                let n = p("StackName")?;
                if self.stacks.contains_key(&n) {
                    return Err(err("AlreadyExistsException", format!("Stack [{n}] already exists")));
                }
                let body = p("TemplateBody").map_err(|_| err("ValidationError", "TemplateBody is required (TemplateURL is not supported locally)"))?;
                let t = parse(&body)?;
                order(&t).map_err(|e| err("ValidationError", e))?;
                let id = format!("arn:aws:cloudformation:{}:{ACCOUNT}:stack/{n}/{}", *REGION, uuid::Uuid::new_v4());
                self.stacks.insert(n.clone(), Stack { id: id.clone(), status: "CREATE_IN_PROGRESS".into(), reason: String::new(), created: chrono::Utc::now().to_rfc3339(),
                    template: body, params: params(), outputs: vec![], exports: vec![], resources: vec![], events: vec![], parent: None, root: None, depth: 0 });
                (json!({ "StackId": id }), Some(Job::Deploy(n, false)))
            }
            "UpdateStack" => {
                let (n, s) = self.find(&p("StackName")?)?;
                if s.status.ends_with("_IN_PROGRESS") {
                    return Err(err("ValidationError", format!("Stack:{} is in {} state and can not be updated.", s.id, s.status)));
                }
                let body = if qs.get("UsePreviousTemplate").is_some_and(|v| v == "true") { s.template.clone() } else { p("TemplateBody")? };
                parse(&body)?;
                let mut new_params = params();
                for (k, v) in &mut new_params {
                    if qs.iter().any(|(qk, qv)| qk.ends_with("UsePreviousValue") && qv == "true" && qs.get(&qk.replace("UsePreviousValue", "ParameterKey")) == Some(k)) {
                        *v = s.params.iter().find(|(o, _)| o == k).map(|(_, x)| x.clone()).unwrap_or_default();
                    }
                }
                if body == s.template && new_params == s.params {
                    return Err(err("ValidationError", "No updates are to be performed."));
                }
                let id = s.id.clone();
                let st = self.stacks.get_mut(&n).unwrap();
                (st.template, st.params, st.status) = (body, new_params, "UPDATE_IN_PROGRESS".into());
                (json!({ "StackId": id }), Some(Job::Deploy(n, true)))
            }
            "DeleteStack" => {
                let n = p("StackName")?;
                let Ok((n, _)) = self.find(&n) else { return Ok((json!({}), None)) };
                // A stack whose exports are imported by other stacks cannot be deleted.
                for (_, en, _) in self.stacks[&n].exports.clone() {
                    let importers = stacks_importing(self, &en, &n);
                    if !importers.is_empty() {
                        return Err(err("ValidationError", format!("Export {en} is in use by {}", importers.join(", "))));
                    }
                }
                self.stacks.get_mut(&n).unwrap().status = "DELETE_IN_PROGRESS".into();
                (json!({}), Some(Job::Delete(n)))
            }
            "ListExports" => {
                let mut items: Vec<Value> = self.stacks.iter()
                    .flat_map(|(n, st)| st.exports.iter().map(move |(_, en, ev)| json!({"ExportingStackName": n, "ExportingStackId": st.id, "Name": en, "Value": ev})))
                    .collect();
                items.sort_by(|a, b| a["Name"].as_str().unwrap_or("").cmp(b["Name"].as_str().unwrap_or("")));
                (json!({"Exports": items}), None)
            }
            "ListImports" => {
                let en = p("ExportName")?;
                (json!({"Imports": stacks_importing(self, &en, "")}), None)
            }
            "DescribeStacks" => {
                let list: Vec<Value> = match qs.get("StackName") {
                    Some(id) => { let (n, s) = self.find(id)?; vec![self.stack_json(&n, s)] }
                    None => self.stacks.iter().map(|(n, s)| self.stack_json(n, s)).collect(),
                };
                (json!({ "Stacks": list }), None)
            }
            "ListStacks" => (json!({"StackSummaries": self.stacks.iter().map(|(n, s)| json!({"StackId": s.id, "StackName": n, "StackStatus": s.status, "CreationTime": s.created,
                "ParentId": s.parent, "RootId": s.root})).collect::<Vec<_>>()}), None),
            "DescribeStackResources" | "ListStackResources" => {
                let (n, s) = self.find(&p("StackName")?)?;
                let list: Vec<Value> = s.resources.iter().map(|r| json!({"StackName": n, "StackId": s.id, "LogicalResourceId": r.logical, "PhysicalResourceId": r.phys,
                    "ResourceType": r.ty, "ResourceStatus": r.status, "Timestamp": s.created, "LastUpdatedTimestamp": s.created})).collect();
                let key = if action == "ListStackResources" { "StackResourceSummaries" } else { "StackResources" };
                (json!({ key: list }), None)
            }
            "DescribeStackEvents" => {
                let (_, s) = self.find(&p("StackName")?)?;
                (json!({"StackEvents": s.events.iter().rev().cloned().collect::<Vec<_>>()}), None)
            }
            "GetTemplate" => {
                let (_, s) = self.find(&p("StackName")?)?;
                (json!({"TemplateBody": s.template}), None)
            }
            "ValidateTemplate" => {
                let t = parse(&p("TemplateBody")?)?;
                order(&t).map_err(|e| err("ValidationError", e))?;
                let ps: Vec<Value> = t["Parameters"].as_object().into_iter().flatten()
                    .map(|(k, d)| json!({"ParameterKey": k, "DefaultValue": d["Default"].as_str(), "NoEcho": d["NoEcho"] == true, "Description": d["Description"]})).collect();
                (json!({"Parameters": ps, "Description": t["Description"]}), None)
            }
            a => return Err(err("InvalidAction", format!("{a} is not supported yet"))),
        })
    }

    pub fn admin(&self) -> Value {
        // Tree order: each nested stack right under its parent, indented by depth.
        fn path<'a>(all: &'a BTreeMap<String, Stack>, mut s: &'a Stack, n: &str) -> Vec<String> {
            let mut p = vec![n.to_string()];
            while let Some((pn, ps)) = s.parent.as_ref().and_then(|id| all.iter().find(|(_, x)| &x.id == id)) {
                p.insert(0, pn.clone());
                s = ps;
            }
            p
        }
        let mut list: Vec<(&String, &Stack)> = self.stacks.iter().collect();
        list.sort_by_cached_key(|(n, s)| path(&self.stacks, s, n));
        list.into_iter()
            .map(|(n, s)| {
                let n = &format!("{}{n}", "↳ ".repeat(s.depth as usize));
                let rows: Vec<Value> = s.resources.iter().map(|r| json!([r.logical, r.ty, r.phys, r.status])).collect();
                let outs: Vec<String> = s.outputs.iter().map(|(k, v, _)| format!("{k}={v}")).collect();
                json!({"name": n, "count": rows.len(), "sub": format!("{}{} · 출력: {}", s.status, if s.reason.is_empty() { String::new() } else { format!(" ({})", s.reason) }, outs.join(", ")),
                       "cols": ["논리 ID", "타입", "물리 ID", "상태"], "rows": rows})
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_tags_and_order() {
        let t = parse("Resources:\n  B:\n    Type: X\n    Properties:\n      Q: !GetAtt A.Arn\n      S: !Sub '${A}-x'\n  A:\n    Type: X\n").unwrap();
        assert_eq!(t["Resources"]["B"]["Properties"]["Q"], json!({"Fn::GetAtt": ["A", "Arn"]}));
        assert_eq!(order(&t).unwrap(), vec!["A", "B"]);
        let cyc = parse("Resources:\n  A:\n    Type: X\n    DependsOn: B\n  B:\n    Type: X\n    DependsOn: A\n").unwrap();
        assert!(order(&cyc).is_err());
    }

    #[test]
    fn intrinsics() {
        let t = json!({"Mappings": {"M": {"dev": {"size": "1"}}}});
        let mut c = Ctx { t: &t, stack: "s".into(), stack_id: "id".into(), params: HashMap::from([("Env".into(), json!("dev"))]), res: HashMap::new(), conds: HashMap::new(), imports: HashMap::from([("shared".into(), "value-of-shared".into())]) };
        c.res.insert("Q".into(), ("url".into(), Map::from_iter([("Arn".to_string(), json!("arn:q"))])));
        c.conds.insert("IsDev".into(), true);
        let v = json!({"a": {"Fn::Sub": "${AWS::Region}/${Env}/${Q.Arn}/${!x}"}, "b": {"Fn::Join": ["-", ["x", {"Ref": "Q"}]]},
                       "c": {"Fn::If": ["IsDev", "yes", {"Ref": "AWS::NoValue"}]}, "d": {"Fn::FindInMap": ["M", {"Ref": "Env"}, "size"]},
                       "e": {"Fn::Select": [1, {"Fn::Split": [",", "a,b,c"]}]}});
        assert_eq!(c.resolve(&v).unwrap(), json!({"a": format!("{}/dev/arn:q/${{x}}", *REGION), "b": "x-url", "c": "yes", "d": "1", "e": "b"}));
        c.conds.insert("IsDev".into(), false);
        assert!(c.resolve(&v).unwrap().get("c").is_none());
        // Fn::ImportValue resolves from already deployed exports.
        assert_eq!(c.resolve(&json!({"Fn::ImportValue": "shared"})).unwrap(), "value-of-shared");
        assert!(c.resolve(&json!({"Fn::ImportValue": "missing"})).is_err());
    }

    #[test]
    fn nested_template_urls() {
        let ep = "http://127.0.0.1:4566";
        let ok = |u: &str| super::template_location(u, ep).unwrap();
        assert_eq!(ok("s3://b/dir/t.yaml"), ("b".into(), "dir/t.yaml".into()));
        assert_eq!(ok("http://127.0.0.1:4566/b/t.json"), ("b".into(), "t.json".into()));
        assert_eq!(ok("http://localhost:4566/b/t.json").0, "b");
        for bad in ["https://b.s3.amazonaws.com/t.json", "http://127.0.0.1:9999/b/t", "http://127.0.0.1:4566.evil.com/b/t", "s3://b", "s3:///t"] {
            assert!(super::template_location(bad, ep).is_err(), "{bad}");
        }
    }

    #[test]
    fn in_place_rules() {
        let old = json!({"QueueName": "q", "VisibilityTimeout": 30, "DelaySeconds": 0});
        let same_id = json!({"QueueName": "q", "VisibilityTimeout": 60, "DelaySeconds": 0});
        let renamed = json!({"QueueName": "q2", "VisibilityTimeout": 30, "DelaySeconds": 0});
        let fn_new = json!({"FunctionName": "f", "Timeout": 5});
        let fn_code = json!({"FunctionName": "f", "Timeout": 5, "Code": {"ZipFile": "x"}});
        assert!(in_place_change("AWS::SQS::Queue", &old, &same_id));
        assert!(!in_place_change("AWS::SQS::Queue", &old, &renamed));
        assert!(in_place_change("AWS::Lambda::Function", &fn_new, &json!({"FunctionName": "f", "Timeout": 30, "MemorySize": 512})));
        assert!(!in_place_change("AWS::Lambda::Function", &fn_new, &fn_code));
        assert!(!in_place_change("AWS::SQS::Queue", &old, &old), "no change → not an in-place update");
        let mut names = vec![];
        collect_imports(&json!({"Fn::ImportValue": "e1"}), &mut names);
        collect_imports(&json!({"Fn::Join": ["-", [{"Fn::ImportValue": "e2"}, {"Fn::ImportValue": "e1"}]]}), &mut names);
        collect_imports(&json!({"Outputs": {"o": {"Value": {"Fn::ImportValue": "e3"}}}}), &mut names);
        assert_eq!(names, vec!["e1", "e2", "e1", "e3"]);
    }
}

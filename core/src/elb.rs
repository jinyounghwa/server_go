// Application Load Balancer (elbv2, Query): load balancers, target groups, listeners that really listen.
// Each listener binds 127.0.0.1:{Port} and forwards connections round-robin to healthy ip targets
// (ECS service tasks register themselves). Listener ports must be >= 1024 locally.
// Listener rules (path-pattern / host-header, by priority) are matched on the first request of each connection.
// ponytail: later requests on a keep-alive connection reuse that choice; no TLS, sticky sessions or Lambda targets.
use crate::{err, ApiErr, App, ACCOUNT, REGION};
use serde_json::{json, Value};
use std::{collections::{BTreeMap, HashMap}, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Lb {
    name: String,
    created: String,
    scheme: String,
}
struct Tg {
    name: String,
    protocol: String,
    port: u64,
    vpc: String,
    target_type: String,
    targets: Vec<(String, u16)>,
}
struct Listener {
    lb: String,
    port: u16,
    protocol: String,
    action: Value,
}
struct Rule {
    listener: String,
    priority: u32,
    paths: Vec<String>,
    hosts: Vec<String>,
    action: Value,
}

#[derive(Default)]
pub struct Elb {
    lbs: BTreeMap<String, Lb>,
    tgs: BTreeMap<String, Tg>,
    listeners: BTreeMap<String, Listener>,
    rules: BTreeMap<String, Rule>,
    handles: HashMap<String, tokio::task::AbortHandle>,
    rr: HashMap<String, usize>,
}

pub enum Job {
    Listen(String, std::net::TcpListener),
    Close(String),
}

type Q = HashMap<String, String>;

fn arn(rest: &str) -> String {
    format!("arn:aws:elasticloadbalancing:{}:{ACCOUNT}:{rest}", *REGION)
}
fn id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..16].to_string()
}
fn list(q: &Q, name: &str) -> Vec<String> {
    (1..).map_while(|i| q.get(&format!("{name}.member.{i}")).cloned()).collect()
}
// One action from the Query form (prefix like "Actions.member.1."), validated against known target groups.
fn parse_action(q: &Q, pre: &str, tgs: &BTreeMap<String, Tg>) -> Result<Value, ApiErr> {
    let ty = q.get(&format!("{pre}Type")).cloned().unwrap_or("forward".into());
    if ty == "fixed-response" {
        return Ok(json!({"Type": ty, "FixedResponseConfig": {"StatusCode": q.get(&format!("{pre}FixedResponseConfig.StatusCode")),
            "MessageBody": q.get(&format!("{pre}FixedResponseConfig.MessageBody")), "ContentType": q.get(&format!("{pre}FixedResponseConfig.ContentType"))}}));
    }
    if ty != "forward" {
        return Err(err("ValidationError", format!("Action type '{ty}' is not supported locally (forward, fixed-response)")));
    }
    let tg = q.get(&format!("{pre}TargetGroupArn")).cloned().ok_or_else(|| err("ValidationError", "A forward action needs TargetGroupArn"))?;
    if !tgs.contains_key(&tg) {
        return Err(err("TargetGroupNotFound", "One or more target groups not found"));
    }
    Ok(json!({"Type": "forward", "TargetGroupArn": tg}))
}

// Request line path and Host header of the first request on a connection.
fn request_head(buf: &[u8]) -> (String, String) {
    let text = String::from_utf8_lossy(buf);
    let mut lines = text.split("\r\n");
    let path = lines.next().and_then(|l| l.split(' ').nth(1)).unwrap_or("/").split('?').next().unwrap_or("/").to_string();
    let host = lines.find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("host")).map(|(_, v)| v.trim().to_string()))
        .unwrap_or_default();
    (path, host.rsplit_once(':').map_or(host.clone(), |(h, p)| if p.bytes().all(|b| b.is_ascii_digit()) { h.to_string() } else { host.clone() }))
}

fn healthy(host: &str, port: u16) -> bool {
    format!("{host}:{port}").parse().ok().is_some_and(|a| std::net::TcpStream::connect_timeout(&a, Duration::from_millis(200)).is_ok())
}

impl Elb {
    fn lb_json(&self, a: &str, l: &Lb) -> Value {
        json!({"LoadBalancerArn": a, "LoadBalancerName": l.name, "DNSName": "127.0.0.1", "CanonicalHostedZoneId": "LOCAL", "CreatedTime": l.created,
               "Scheme": l.scheme, "Type": "application", "State": {"Code": "active"}, "IpAddressType": "ipv4", "VpcId": "vpc-local"})
    }
    fn tg_json(&self, a: &str, t: &Tg) -> Value {
        json!({"TargetGroupArn": a, "TargetGroupName": t.name, "Protocol": t.protocol, "Port": t.port, "VpcId": t.vpc, "TargetType": t.target_type,
               "HealthCheckProtocol": t.protocol, "HealthCheckPath": "/", "HealthCheckEnabled": true,
               "LoadBalancerArns": self.listeners.iter().filter(|(la, l)| self.uses(la, l, a)).map(|(_, l)| l.lb.clone()).collect::<Vec<_>>()})
    }
    // Does this listener (default action or any rule) forward to the target group?
    fn uses(&self, la: &str, l: &Listener, tg: &str) -> bool {
        l.action["TargetGroupArn"] == tg || self.rules.values().any(|r| r.listener == la && r.action["TargetGroupArn"] == tg)
    }
    fn rule_json(&self, a: &str, r: &Rule) -> Value {
        let mut conds = vec![];
        if !r.paths.is_empty() {
            conds.push(json!({"Field": "path-pattern", "Values": r.paths, "PathPatternConfig": {"Values": r.paths}}));
        }
        if !r.hosts.is_empty() {
            conds.push(json!({"Field": "host-header", "Values": r.hosts, "HostHeaderConfig": {"Values": r.hosts}}));
        }
        json!({"RuleArn": a, "Priority": r.priority.to_string(), "Conditions": conds, "Actions": [r.action], "IsDefault": false})
    }
    fn listener_json(&self, a: &str, l: &Listener) -> Value {
        json!({"ListenerArn": a, "LoadBalancerArn": l.lb, "Port": l.port, "Protocol": l.protocol, "DefaultActions": [l.action]})
    }

    // Used by ECS to add/remove a running task's host port.
    pub fn set_target(&mut self, tg: &str, host: &str, port: u16, on: bool) {
        if let Some(t) = self.tgs.get_mut(tg) {
            t.targets.retain(|x| *x != (host.to_string(), port));
            if on {
                t.targets.push((host.into(), port));
            }
        }
    }

    pub fn has_rules(&self, listener: &str) -> bool {
        self.rules.values().any(|r| r.listener == listener)
    }

    // Next healthy target for a listener (rules by priority, then the default action), or the fixed response to give.
    fn pick(&mut self, listener: &str, path: &str, host: &str) -> Result<(String, u16), String> {
        let l = self.listeners.get(listener).ok_or("listener gone")?;
        let mut rules: Vec<&Rule> = self.rules.values().filter(|r| r.listener == listener).collect();
        rules.sort_by_key(|r| r.priority);
        let hit = rules.into_iter().find(|r| {
            (r.paths.is_empty() || r.paths.iter().any(|p| crate::iam::glob(p, path, false)))
                && (r.hosts.is_empty() || r.hosts.iter().any(|h| crate::iam::glob(h, host, true)))
        });
        let action = hit.map_or(&l.action, |r| &r.action);
        if action["Type"] == "fixed-response" {
            let c = &action["FixedResponseConfig"];
            return Err(format!("{} {}", c["StatusCode"].as_str().unwrap_or("200"), c["MessageBody"].as_str().unwrap_or("")));
        }
        let tg = action["TargetGroupArn"].as_str().unwrap_or("").to_string();
        let targets = self.tgs.get(&tg).map(|t| t.targets.clone()).unwrap_or_default();
        let n = targets.len();
        let start = self.rr.entry(tg).or_insert(0);
        for k in 0..n {
            let t = &targets[(*start + k) % n];
            if healthy(&t.0, t.1) {
                *start = (*start + k + 1) % n;
                return Ok(t.clone());
            }
        }
        Err("503 no healthy targets".into())
    }

    pub fn handle(&mut self, q: &Q) -> Result<(Value, Vec<Job>), ApiErr> {
        let p = |k: &str| q.get(k).cloned().ok_or_else(|| err("ValidationError", format!("{k} is required")));
        let action = q.get("Action").map_or("", String::as_str);
        let mut jobs = vec![];
        let v = match action {
            "CreateLoadBalancer" => {
                let n = p("Name")?;
                if let Some((a, l)) = self.lbs.iter().find(|(_, l)| l.name == n) {
                    return Ok((json!({"LoadBalancers": [self.lb_json(a, l)]}), jobs));
                }
                let a = arn(&format!("loadbalancer/app/{n}/{}", id()));
                let l = Lb { name: n, created: chrono::Utc::now().to_rfc3339(), scheme: q.get("Scheme").cloned().unwrap_or("internet-facing".into()) };
                let out = json!({"LoadBalancers": [self.lb_json(&a, &l)]});
                self.lbs.insert(a, l);
                out
            }
            "DescribeLoadBalancers" => {
                let (arns, names) = (list(q, "LoadBalancerArns"), list(q, "Names"));
                let found: Vec<Value> = self.lbs.iter().filter(|(a, l)| (arns.is_empty() || arns.contains(a)) && (names.is_empty() || names.contains(&l.name)))
                    .map(|(a, l)| self.lb_json(a, l)).collect();
                if found.is_empty() && !(arns.is_empty() && names.is_empty()) {
                    return Err(ApiErr { status: 400, ..err("LoadBalancerNotFound", "One or more load balancers not found") });
                }
                json!({ "LoadBalancers": found })
            }
            "DeleteLoadBalancer" => {
                let a = p("LoadBalancerArn")?;
                self.lbs.remove(&a);
                let gone: Vec<String> = self.listeners.iter().filter(|(_, l)| l.lb == a).map(|(k, _)| k.clone()).collect();
                for k in gone {
                    self.listeners.remove(&k);
                    self.rules.retain(|_, r| r.listener != k);
                    jobs.push(Job::Close(k));
                }
                json!({})
            }
            "CreateTargetGroup" => {
                let n = p("Name")?;
                if let Some((a, t)) = self.tgs.iter().find(|(_, t)| t.name == n) {
                    return Ok((json!({"TargetGroups": [self.tg_json(a, t)]}), jobs));
                }
                let a = arn(&format!("targetgroup/{n}/{}", id()));
                let t = Tg { name: n, protocol: q.get("Protocol").cloned().unwrap_or("HTTP".into()), port: q.get("Port").and_then(|x| x.parse().ok()).unwrap_or(80),
                    vpc: q.get("VpcId").cloned().unwrap_or_default(), target_type: q.get("TargetType").cloned().unwrap_or("instance".into()), targets: vec![] };
                let out = json!({"TargetGroups": [self.tg_json(&a, &t)]});
                self.tgs.insert(a, t);
                out
            }
            "DescribeTargetGroups" => {
                let (arns, names, lb) = (list(q, "TargetGroupArns"), list(q, "Names"), q.get("LoadBalancerArn"));
                json!({"TargetGroups": self.tgs.iter().filter(|(a, t)| (arns.is_empty() || arns.contains(a)) && (names.is_empty() || names.contains(&t.name))
                    && lb.is_none_or(|lb| self.listeners.iter().any(|(la, l)| l.lb == *lb && self.uses(la, l, a))))
                    .map(|(a, t)| self.tg_json(a, t)).collect::<Vec<_>>()})
            }
            "DeleteTargetGroup" => {
                let a = p("TargetGroupArn")?;
                if self.listeners.iter().any(|(la, l)| self.uses(la, l, &a)) {
                    return Err(err("ResourceInUse", format!("Target group '{a}' is currently in use by a listener or a rule")));
                }
                self.tgs.remove(&a);
                json!({})
            }
            "RegisterTargets" | "DeregisterTargets" => {
                let a = p("TargetGroupArn")?;
                let t = self.tgs.get_mut(&a).ok_or_else(|| err("TargetGroupNotFound", "One or more target groups not found"))?;
                let default_port = t.port as u16;
                for i in 1.. {
                    let Some(tid) = q.get(&format!("Targets.member.{i}.Id")) else { break };
                    let port = q.get(&format!("Targets.member.{i}.Port")).and_then(|x| x.parse().ok()).unwrap_or(default_port);
                    t.targets.retain(|x| *x != (tid.clone(), port));
                    if action == "RegisterTargets" {
                        t.targets.push((tid.clone(), port));
                    }
                }
                json!({})
            }
            "DescribeTargetHealth" => {
                let a = p("TargetGroupArn")?;
                let t = self.tgs.get(&a).ok_or_else(|| err("TargetGroupNotFound", "One or more target groups not found"))?;
                json!({"TargetHealthDescriptions": t.targets.iter().map(|(h, port)| {
                    let ok = healthy(h, *port);
                    json!({"Target": {"Id": h, "Port": port}, "HealthCheckPort": port.to_string(),
                           "TargetHealth": if ok { json!({"State": "healthy"}) } else { json!({"State": "unhealthy", "Reason": "Target.FailedHealthChecks", "Description": "Connection refused"}) }})
                }).collect::<Vec<_>>()})
            }
            "CreateListener" => {
                let lb = p("LoadBalancerArn")?;
                if !self.lbs.contains_key(&lb) {
                    return Err(err("LoadBalancerNotFound", "One or more load balancers not found"));
                }
                let port: u16 = p("Port")?.parse().map_err(|_| err("ValidationError", "Port must be a number"))?;
                if self.listeners.values().any(|l| l.port == port) {
                    return Err(err("DuplicateListener", "A listener already exists on this port for this load balancer"));
                }
                let action = parse_action(q, "DefaultActions.member.1.", &self.tgs)?;
                let sock = std::net::TcpListener::bind(("127.0.0.1", port))
                    .map_err(|e| err("InvalidConfigurationRequest", format!("Cannot listen on 127.0.0.1:{port} locally ({e}); use a free port >= 1024")))?;
                let a = arn(&format!("listener/app/{}/{}", self.lbs[&lb].name, id()));
                let l = Listener { lb, port, protocol: q.get("Protocol").cloned().unwrap_or("HTTP".into()), action };
                let out = json!({"Listeners": [self.listener_json(&a, &l)]});
                self.listeners.insert(a.clone(), l);
                jobs.push(Job::Listen(a, sock));
                out
            }
            "DescribeListeners" => {
                let lb = q.get("LoadBalancerArn");
                let arns = list(q, "ListenerArns");
                json!({"Listeners": self.listeners.iter().filter(|(a, l)| lb.is_none_or(|x| *x == l.lb) && (arns.is_empty() || arns.contains(a)))
                    .map(|(a, l)| self.listener_json(a, l)).collect::<Vec<_>>()})
            }
            "CreateRule" => {
                let l = p("ListenerArn")?;
                if !self.listeners.contains_key(&l) {
                    return Err(err("ListenerNotFound", "One or more listeners not found"));
                }
                let priority: u32 = p("Priority")?.parse().ok().filter(|n| (1..=50000).contains(n))
                    .ok_or_else(|| err("ValidationError", "Priority must be between 1 and 50000"))?;
                if self.rules.values().any(|r| r.listener == l && r.priority == priority) {
                    return Err(err("PriorityInUse", format!("Priority '{priority}' is currently in use")));
                }
                let (mut paths, mut hosts) = (vec![], vec![]);
                for i in 1.. {
                    let pre = format!("Conditions.member.{i}.");
                    let Some(field) = q.get(&format!("{pre}Field")) else { break };
                    let cfg = if field == "path-pattern" { "PathPatternConfig" } else { "HostHeaderConfig" };
                    let mut vals = list(q, &format!("{pre}Values"));
                    vals.extend(list(q, &format!("{pre}{cfg}.Values")));
                    if vals.is_empty() || vals.len() > 5 || vals.iter().any(|v| v.is_empty() || v.len() > 128) {
                        return Err(err("ValidationError", "Each condition needs 1 to 5 values of at most 128 characters"));
                    }
                    match field.as_str() {
                        "path-pattern" => paths.extend(vals),
                        "host-header" => hosts.extend(vals),
                        f => return Err(err("ValidationError", format!("Condition field '{f}' is not supported locally (path-pattern, host-header)"))),
                    }
                }
                if paths.is_empty() && hosts.is_empty() {
                    return Err(err("ValidationError", "A rule needs at least one condition"));
                }
                let action = parse_action(q, "Actions.member.1.", &self.tgs)?;
                let a = arn(&format!("listener-rule/app/{}/{}", l.rsplit('/').nth(1).unwrap_or("lb"), id()));
                let r = Rule { listener: l, priority, paths, hosts, action };
                let out = json!({"Rules": [self.rule_json(&a, &r)]});
                self.rules.insert(a, r);
                out
            }
            "DescribeRules" => {
                let (l, arns) = (q.get("ListenerArn"), list(q, "RuleArns"));
                let mut rules: Vec<(&String, &Rule)> = self.rules.iter().filter(|(a, r)| l.is_none_or(|l| *l == r.listener) && (arns.is_empty() || arns.contains(a))).collect();
                rules.sort_by_key(|(_, r)| r.priority);
                let mut out: Vec<Value> = rules.into_iter().map(|(a, r)| self.rule_json(a, r)).collect();
                if let Some(x) = l.and_then(|l| self.listeners.get(l)) {
                    out.push(json!({"RuleArn": format!("{}/default", l.unwrap()), "Priority": "default", "Conditions": [], "Actions": [x.action], "IsDefault": true}));
                }
                json!({ "Rules": out })
            }
            "DeleteRule" => {
                let a = p("RuleArn")?;
                self.rules.remove(&a).ok_or_else(|| err("RuleNotFound", "One or more rules not found"))?;
                json!({})
            }
            "DeleteListener" => {
                let a = p("ListenerArn")?;
                self.listeners.remove(&a).ok_or_else(|| err("ListenerNotFound", "One or more listeners not found"))?;
                self.rules.retain(|_, r| r.listener != a);
                jobs.push(Job::Close(a));
                json!({})
            }
            a => return Err(err("InvalidAction", format!("{a} is not supported yet"))),
        };
        Ok((v, jobs))
    }

    pub fn admin(&self) -> Value {
        self.lbs
            .iter()
            .map(|(a, l)| {
                let rows: Vec<Value> = self.listeners.iter().filter(|(_, x)| x.lb == *a).map(|(la, x)| {
                    let nrules = self.rules.values().filter(|r| r.listener == *la).count();
                    let targets = self.tgs.get(x.action["TargetGroupArn"].as_str().unwrap_or("")).map(|t| {
                        format!("{} → {}", t.name, t.targets.iter().map(|(h, p)| format!("{h}:{p}")).collect::<Vec<_>>().join(", "))
                    }).unwrap_or_else(|| format!("고정 응답 {}", x.action["FixedResponseConfig"]["StatusCode"].as_str().unwrap_or("")));
                    json!([format!("http://127.0.0.1:{}", x.port), if nrules > 0 { format!("{targets} (규칙 {nrules}개)") } else { targets }])
                }).collect();
                json!({"name": l.name, "count": rows.len(), "sub": a, "cols": ["리스너", "대상"], "rows": rows})
            })
            .collect()
    }
}

// Accept loop for one listener: proxy each connection to the next healthy target.
pub fn serve(app: Arc<App>, listener: String, sock: std::net::TcpListener) {
    let l2 = listener.clone();
    let a2 = app.clone();
    let h = tokio::spawn(async move {
        let _ = sock.set_nonblocking(true);
        let Ok(sock) = tokio::net::TcpListener::from_std(sock) else { return };
        loop {
            let Ok((mut client, _)) = sock.accept().await else { continue };
            let (app, listener) = (app.clone(), listener.clone());
            tokio::spawn(async move {
                // With rules, read the first request head (at most 8 KiB, 5 s) to route on path and Host.
                let mut head = vec![];
                if app.elb.lock().unwrap().has_rules(&listener) {
                    let mut buf = [0u8; 2048];
                    let read = tokio::time::timeout(Duration::from_secs(5), async {
                        while head.len() < 8192 && !head.windows(4).any(|w| w == b"\r\n\r\n") {
                            match client.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => head.extend_from_slice(&buf[..n]),
                            }
                        }
                    }).await;
                    if read.is_err() || head.is_empty() {
                        return;
                    }
                }
                let (path, host) = request_head(&head);
                let pick = app.elb.lock().unwrap().pick(&listener, &path, &host);
                let target = match pick {
                    Ok((h, p)) => format!("{h}:{p}"),
                    Err(fixed) => {
                        let (code, body) = fixed.split_once(' ').unwrap_or((&fixed, ""));
                        let reason = if code == "503" { "Service Unavailable" } else { "OK" };
                        let _ = client.write_all(format!("HTTP/1.1 {code} {reason}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).await;
                        crate::emit(&app, json!({"ts": chrono::Utc::now().to_rfc3339(), "service": "elbv2", "op": "Forward", "target": body, "status": code.parse::<u16>().unwrap_or(200)}));
                        return;
                    }
                };
                crate::emit(&app, json!({"ts": chrono::Utc::now().to_rfc3339(), "service": "elbv2", "op": "Forward", "target": target, "status": 200}));
                if let Ok(mut up) = tokio::net::TcpStream::connect(&target).await {
                    if !head.is_empty() && up.write_all(&head).await.is_err() {
                        return;
                    }
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
                }
            });
        }
    });
    a2.elb.lock().unwrap().handles.insert(l2, h.abort_handle());
}

pub fn close_all(app: &App) {
    for (_, h) in app.elb.lock().unwrap().handles.drain() {
        h.abort();
    }
}

pub fn close(app: &App, listener: &str) {
    if let Some(h) = app.elb.lock().unwrap().handles.remove(listener) {
        h.abort();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn request_head_parses_path_and_host() {
        let (p, h) = super::request_head(b"GET /api/x?y=1 HTTP/1.1\r\nHost: Admin.Local:8080\r\nAccept: */*\r\n\r\n");
        assert_eq!((p.as_str(), h.as_str()), ("/api/x", "Admin.Local"));
        assert_eq!(super::request_head(b"garbage"), ("/".to_string(), String::new()));
    }
}

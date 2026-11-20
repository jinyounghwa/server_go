// Application Load Balancer (elbv2, Query): load balancers, target groups, listeners that really listen.
// Each listener binds 127.0.0.1:{Port} and forwards connections round-robin to healthy ip targets
// (ECS service tasks register themselves). Listener ports must be >= 1024 locally.
// ponytail: L4 per-connection balancing — no listener rules (path/host routing), TLS, sticky sessions or Lambda targets.
use crate::{err, ApiErr, App, ACCOUNT, REGION};
use serde_json::{json, Value};
use std::{collections::{BTreeMap, HashMap}, sync::Arc, time::Duration};
use tokio::io::AsyncWriteExt;

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

#[derive(Default)]
pub struct Elb {
    lbs: BTreeMap<String, Lb>,
    tgs: BTreeMap<String, Tg>,
    listeners: BTreeMap<String, Listener>,
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
               "LoadBalancerArns": self.listeners.values().filter(|l| l.action["TargetGroupArn"] == a).map(|l| l.lb.clone()).collect::<Vec<_>>()})
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

    // Next healthy target for a listener, or the fixed response it should give.
    fn pick(&mut self, listener: &str) -> Result<(String, u16), String> {
        let l = self.listeners.get(listener).ok_or("listener gone")?;
        if l.action["Type"] == "fixed-response" {
            let c = &l.action["FixedResponseConfig"];
            return Err(format!("{} {}", c["StatusCode"].as_str().unwrap_or("200"), c["MessageBody"].as_str().unwrap_or("")));
        }
        let tg = l.action["TargetGroupArn"].as_str().unwrap_or("").to_string();
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
                    && lb.is_none_or(|lb| self.listeners.values().any(|l| l.lb == *lb && l.action["TargetGroupArn"] == a.as_str())))
                    .map(|(a, t)| self.tg_json(a, t)).collect::<Vec<_>>()})
            }
            "DeleteTargetGroup" => {
                let a = p("TargetGroupArn")?;
                if self.listeners.values().any(|l| l.action["TargetGroupArn"] == a.as_str()) {
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
                let pre = "DefaultActions.member.1.";
                let ty = q.get(&format!("{pre}Type")).cloned().unwrap_or("forward".into());
                let action = if ty == "fixed-response" {
                    json!({"Type": ty, "FixedResponseConfig": {"StatusCode": q.get(&format!("{pre}FixedResponseConfig.StatusCode")),
                        "MessageBody": q.get(&format!("{pre}FixedResponseConfig.MessageBody")), "ContentType": q.get(&format!("{pre}FixedResponseConfig.ContentType"))}})
                } else {
                    let tg = q.get(&format!("{pre}TargetGroupArn")).cloned().ok_or_else(|| err("ValidationError", "A forward action needs TargetGroupArn"))?;
                    if !self.tgs.contains_key(&tg) {
                        return Err(err("TargetGroupNotFound", "One or more target groups not found"));
                    }
                    json!({"Type": "forward", "TargetGroupArn": tg})
                };
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
            "DeleteListener" => {
                let a = p("ListenerArn")?;
                self.listeners.remove(&a).ok_or_else(|| err("ListenerNotFound", "One or more listeners not found"))?;
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
                let rows: Vec<Value> = self.listeners.values().filter(|x| x.lb == *a).map(|x| {
                    let targets = self.tgs.get(x.action["TargetGroupArn"].as_str().unwrap_or("")).map(|t| {
                        format!("{} → {}", t.name, t.targets.iter().map(|(h, p)| format!("{h}:{p}")).collect::<Vec<_>>().join(", "))
                    }).unwrap_or_else(|| format!("고정 응답 {}", x.action["FixedResponseConfig"]["StatusCode"].as_str().unwrap_or("")));
                    json!([format!("http://127.0.0.1:{}", x.port), targets])
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
            let pick = app.elb.lock().unwrap().pick(&listener);
            let app = app.clone();
            tokio::spawn(async move {
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

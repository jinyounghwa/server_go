// ECS (JSON 1.1): clusters, task definitions, tasks as real Docker containers, services that keep desiredCount.
// Task containers publish ports on 127.0.0.1 and reach the emulator at host.docker.internal.
// ponytail: no capacity providers, deployments/rollouts, health checks, volumes, secrets or service discovery;
// for task code to call the emulator, run it with BIND=0.0.0.0:4566 (containers can't reach 127.0.0.1 on the host).
use crate::managed::{docker_ok, free_port};
use crate::{epoch, err, need, ApiErr, App, ACCOUNT, REGION};
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

struct TaskDef {
    family: String,
    revision: u32,
    containers: Vec<Value>,
    task_role: Option<String>,
    cpu: Option<String>,
    memory: Option<String>,
    active: bool,
}
#[derive(Clone)]
struct Cont {
    name: String,
    docker: String,
    last: String,
    exit: Option<i64>,
    bindings: Vec<(u64, u16)>,
    log_lines: usize,
}
struct Task {
    cluster: String,
    def: String, // family:revision
    group: String,
    last: String,
    desired: String,
    containers: Vec<Cont>,
    created: f64,
    started: Option<f64>,
    stopped: Option<f64>,
    reason: Option<String>,
    overrides: Value,
}
struct Service {
    def: String,
    desired: u64,
    lbs: Vec<Value>,
    created: f64,
    deleting: bool,
}

#[derive(Default)]
pub struct Ecs {
    clusters: BTreeMap<String, f64>,
    defs: BTreeMap<String, TaskDef>, // family:revision
    tasks: BTreeMap<String, Task>,   // task id
    services: BTreeMap<(String, String), Service>,
}

pub enum Job {
    Run(String),
    Reconcile(String, String),
}

fn arn(rest: &str) -> String {
    format!("arn:aws:ecs:{}:{ACCOUNT}:{rest}", *REGION)
}
fn tail(s: &str) -> String {
    s.rsplit('/').next().unwrap_or(s).to_string()
}
fn not_found(what: &str) -> ApiErr {
    err(if what == "cluster" { "ClusterNotFoundException" } else if what == "service" { "ServiceNotFoundException" } else { "InvalidParameterException" },
        format!("The specified {what} was not found."))
}

impl Ecs {
    fn cluster_of(&mut self, r: &Value) -> String {
        let c = r["cluster"].as_str().map_or("default".to_string(), tail);
        if c == "default" {
            self.clusters.entry(c.clone()).or_insert_with(epoch);
        }
        c
    }
    // "family", "family:rev" or an ARN → registered "family:rev" (latest active when no revision).
    fn def_key(&self, id: &str) -> Result<String, ApiErr> {
        let id = tail(id);
        if self.defs.contains_key(&id) {
            return Ok(id);
        }
        self.defs.iter().filter(|(_, d)| d.family == id && d.active).max_by_key(|(_, d)| d.revision).map(|(k, _)| k.clone())
            .ok_or_else(|| err("ClientException", format!("Unable to describe task definition {id}.")))
    }
    fn def_json(&self, key: &str) -> Value {
        let d = &self.defs[key];
        json!({"taskDefinitionArn": arn(&format!("task-definition/{key}")), "family": d.family, "revision": d.revision,
               "containerDefinitions": d.containers, "taskRoleArn": d.task_role, "cpu": d.cpu, "memory": d.memory,
               "status": if d.active { "ACTIVE" } else { "INACTIVE" }, "networkMode": "bridge", "requiresCompatibilities": ["EC2", "FARGATE"]})
    }
    fn task_json(&self, id: &str, t: &Task) -> Value {
        let tarn = arn(&format!("task/{}/{id}", t.cluster));
        let mut v = json!({"taskArn": tarn, "clusterArn": arn(&format!("cluster/{}", t.cluster)), "taskDefinitionArn": arn(&format!("task-definition/{}", t.def)),
            "lastStatus": t.last, "desiredStatus": t.desired, "group": t.group, "launchType": "FARGATE", "createdAt": t.created, "overrides": t.overrides,
            "containers": t.containers.iter().map(|c| json!({"containerArn": arn(&format!("container/{}/{id}/{}", t.cluster, c.name)), "taskArn": tarn,
                "name": c.name, "lastStatus": c.last, "exitCode": c.exit,
                "networkBindings": c.bindings.iter().map(|(cp, hp)| json!({"bindIP": "127.0.0.1", "containerPort": cp, "hostPort": hp, "protocol": "tcp"})).collect::<Vec<_>>()})).collect::<Vec<_>>()});
        if let Some(s) = t.started {
            v["startedAt"] = s.into();
        }
        if let Some(s) = t.stopped {
            v["stoppedAt"] = s.into();
            v["stoppedReason"] = t.reason.clone().into();
            v["stopCode"] = "EssentialContainerExited".into();
        }
        v
    }
    fn service_json(&self, c: &str, n: &str, s: &Service) -> Value {
        let group = format!("service:{n}");
        let running = self.tasks.values().filter(|t| t.cluster == c && t.group == group && t.last == "RUNNING").count();
        let pending = self.tasks.values().filter(|t| t.cluster == c && t.group == group && t.last == "PROVISIONING").count();
        json!({"serviceArn": arn(&format!("service/{c}/{n}")), "serviceName": n, "clusterArn": arn(&format!("cluster/{c}")),
               "taskDefinition": arn(&format!("task-definition/{}", s.def)), "desiredCount": s.desired, "runningCount": running, "pendingCount": pending,
               "status": if s.deleting { "DRAINING" } else { "ACTIVE" }, "launchType": "FARGATE", "loadBalancers": s.lbs, "createdAt": s.created,
               "deployments": [{"id": "ecs-svc/local", "status": "PRIMARY", "taskDefinition": arn(&format!("task-definition/{}", s.def)),
                                "desiredCount": s.desired, "runningCount": running, "pendingCount": pending, "rolloutState": "COMPLETED"}]})
    }

    fn new_task(&mut self, cluster: &str, def: &str, group: String, overrides: Value) -> String {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let containers = self.defs[def].containers.iter().map(|c| {
            let name = c["name"].as_str().unwrap_or("app").to_string();
            Cont { docker: format!("rocalcloud-ecs-{}-{name}", &id[..12]), name, last: "PENDING".into(), exit: None, bindings: vec![], log_lines: 0 }
        }).collect();
        self.tasks.insert(id.clone(), Task { cluster: cluster.into(), def: def.into(), group, last: "PROVISIONING".into(), desired: "RUNNING".into(),
            containers, created: epoch(), started: None, stopped: None, reason: None, overrides });
        id
    }

    pub fn handle(&mut self, op: &str, r: &Value) -> Result<(Value, Vec<Job>), ApiErr> {
        let mut jobs = vec![];
        let v = match op {
            "CreateCluster" => {
                let n = r["clusterName"].as_str().unwrap_or("default").to_string();
                self.clusters.entry(n.clone()).or_insert_with(epoch);
                json!({"cluster": {"clusterArn": arn(&format!("cluster/{n}")), "clusterName": n, "status": "ACTIVE"}})
            }
            "ListClusters" => json!({"clusterArns": self.clusters.keys().map(|c| arn(&format!("cluster/{c}"))).collect::<Vec<_>>()}),
            "DescribeClusters" => {
                let names: Vec<String> = r["clusters"].as_array().map_or(vec!["default".into()], |a| a.iter().filter_map(|c| c.as_str().map(tail)).collect());
                let found: Vec<Value> = names.iter().filter(|n| self.clusters.contains_key(*n)).map(|n| {
                    let running = self.tasks.values().filter(|t| t.cluster == *n && t.last == "RUNNING").count();
                    let services = self.services.keys().filter(|(c, _)| c == n).count();
                    json!({"clusterArn": arn(&format!("cluster/{n}")), "clusterName": n, "status": "ACTIVE", "runningTasksCount": running, "activeServicesCount": services})
                }).collect();
                let failures: Vec<Value> = names.iter().filter(|n| !self.clusters.contains_key(*n)).map(|n| json!({"arn": arn(&format!("cluster/{n}")), "reason": "MISSING"})).collect();
                json!({"clusters": found, "failures": failures})
            }
            "DeleteCluster" => {
                let c = tail(need(r, "cluster")?);
                if self.services.keys().any(|(k, _)| *k == c) || self.tasks.values().any(|t| t.cluster == c && t.last != "STOPPED") {
                    return Err(err("ClusterContainsServicesException", "The Cluster cannot be deleted while Services or Tasks are active."));
                }
                self.clusters.remove(&c).ok_or_else(|| not_found("cluster"))?;
                json!({"cluster": {"clusterArn": arn(&format!("cluster/{c}")), "clusterName": c, "status": "INACTIVE"}})
            }
            "RegisterTaskDefinition" => {
                let family = need(r, "family")?.to_string();
                let containers = r["containerDefinitions"].as_array().cloned().filter(|a| !a.is_empty())
                    .ok_or_else(|| err("ClientException", "Container list cannot be empty."))?;
                if containers.iter().any(|c| c["name"].as_str().is_none() || c["image"].as_str().is_none()) {
                    return Err(err("ClientException", "Every container needs a name and an image."));
                }
                let revision = self.defs.values().filter(|d| d.family == family).map(|d| d.revision).max().unwrap_or(0) + 1;
                let key = format!("{family}:{revision}");
                self.defs.insert(key.clone(), TaskDef { family, revision, containers, task_role: r["taskRoleArn"].as_str().map(String::from),
                    cpu: r["cpu"].as_str().map(String::from), memory: r["memory"].as_str().map(String::from), active: true });
                json!({"taskDefinition": self.def_json(&key)})
            }
            "DescribeTaskDefinition" => json!({"taskDefinition": self.def_json(&self.def_key(need(r, "taskDefinition")?)?)}),
            "ListTaskDefinitions" => json!({"taskDefinitionArns": self.defs.iter().filter(|(_, d)| d.active && r["familyPrefix"].as_str().is_none_or(|p| d.family.starts_with(p)))
                .map(|(k, _)| arn(&format!("task-definition/{k}"))).collect::<Vec<_>>()}),
            "DeregisterTaskDefinition" => {
                let k = self.def_key(need(r, "taskDefinition")?)?;
                self.defs.get_mut(&k).unwrap().active = false;
                json!({"taskDefinition": self.def_json(&k)})
            }
            "RunTask" => {
                let c = self.cluster_of(r);
                if !self.clusters.contains_key(&c) {
                    return Err(not_found("cluster"));
                }
                let def = self.def_key(need(r, "taskDefinition")?)?;
                let family = self.defs[&def].family.clone();
                let mut out = vec![];
                for _ in 0..r["count"].as_u64().unwrap_or(1).clamp(1, 10) {
                    let id = self.new_task(&c, &def, r["group"].as_str().map_or(format!("family:{family}"), String::from), r["overrides"].clone());
                    out.push(self.task_json(&id, &self.tasks[&id]));
                    jobs.push(Job::Run(id));
                }
                json!({"tasks": out, "failures": []})
            }
            "DescribeTasks" => {
                let ids: Vec<String> = r["tasks"].as_array().into_iter().flatten().filter_map(|t| t.as_str().map(tail)).collect();
                let found: Vec<Value> = ids.iter().filter_map(|i| self.tasks.get(i).map(|t| self.task_json(i, t))).collect();
                let failures: Vec<Value> = ids.iter().filter(|i| !self.tasks.contains_key(*i)).map(|i| json!({"arn": i, "reason": "MISSING"})).collect();
                json!({"tasks": found, "failures": failures})
            }
            "ListTasks" => {
                let c = self.cluster_of(r);
                let svc = r["serviceName"].as_str().map(|s| format!("service:{}", tail(s)));
                let want = r["desiredStatus"].as_str().unwrap_or("RUNNING");
                json!({"taskArns": self.tasks.iter().filter(|(_, t)| t.cluster == c && t.desired == want && svc.as_ref().is_none_or(|g| *g == t.group))
                    .map(|(i, t)| arn(&format!("task/{}/{i}", t.cluster))).collect::<Vec<_>>()})
            }
            "StopTask" => {
                let id = tail(need(r, "task")?);
                let t = self.tasks.get_mut(&id).ok_or_else(|| err("InvalidParameterException", "The referenced task was not found."))?;
                t.desired = "STOPPED".into();
                t.reason = Some(r["reason"].as_str().unwrap_or("Task stopped by user").into());
                json!({"task": self.task_json(&id, &self.tasks[&id])})
            }
            "CreateService" => {
                let c = self.cluster_of(r);
                if !self.clusters.contains_key(&c) {
                    return Err(not_found("cluster"));
                }
                let n = need(r, "serviceName")?.to_string();
                if self.services.contains_key(&(c.clone(), n.clone())) {
                    return Err(err("InvalidParameterException", "Creation of service was not idempotent."));
                }
                let def = self.def_key(need(r, "taskDefinition")?)?;
                let s = Service { def, desired: r["desiredCount"].as_u64().unwrap_or(1), lbs: r["loadBalancers"].as_array().cloned().unwrap_or_default(), created: epoch(), deleting: false };
                let out = json!({"service": self.service_json(&c, &n, &s)});
                self.services.insert((c.clone(), n.clone()), s);
                jobs.push(Job::Reconcile(c, n));
                out
            }
            "UpdateService" => {
                let c = self.cluster_of(r);
                let n = tail(need(r, "service")?);
                let new_def = r["taskDefinition"].as_str().map(|d| self.def_key(d)).transpose()?;
                let s = self.services.get_mut(&(c.clone(), n.clone())).ok_or_else(|| not_found("service"))?;
                if let Some(d) = r["desiredCount"].as_u64() {
                    s.desired = d;
                }
                let replaced = new_def.filter(|d| *d != s.def);
                if let Some(d) = &replaced {
                    s.def = d.clone();
                }
                // ponytail: a new task definition replaces all tasks at once (no rolling deployment).
                if let Some(d) = replaced {
                    for t in self.tasks.values_mut().filter(|t| t.cluster == c && t.group == format!("service:{n}") && t.def != d) {
                        t.desired = "STOPPED".into();
                        t.reason = Some("Deployment replaced the task".into());
                    }
                }
                json!({"service": self.service_json(&c, &n, &self.services[&(c.clone(), n.clone())])})
            }
            "DescribeServices" => {
                let c = self.cluster_of(r);
                let names: Vec<String> = r["services"].as_array().into_iter().flatten().filter_map(|s| s.as_str().map(tail)).collect();
                json!({"services": names.iter().filter_map(|n| self.services.get(&(c.clone(), n.clone())).map(|s| self.service_json(&c, n, s))).collect::<Vec<_>>(),
                       "failures": names.iter().filter(|n| !self.services.contains_key(&(c.clone(), (*n).clone()))).map(|n| json!({"arn": n, "reason": "MISSING"})).collect::<Vec<_>>()})
            }
            "ListServices" => {
                let c = self.cluster_of(r);
                json!({"serviceArns": self.services.keys().filter(|(k, _)| *k == c).map(|(k, n)| arn(&format!("service/{k}/{n}"))).collect::<Vec<_>>()})
            }
            "DeleteService" => {
                let c = self.cluster_of(r);
                let n = tail(need(r, "service")?);
                let s = self.services.get_mut(&(c.clone(), n.clone())).ok_or_else(|| not_found("service"))?;
                if s.desired > 0 && r["force"] != true {
                    return Err(err("InvalidParameterException", "The service cannot be stopped while it is scaled above 0."));
                }
                (s.desired, s.deleting) = (0, true);
                json!({"service": self.service_json(&c, &n, &self.services[&(c.clone(), n.clone())])})
            }
            _ => return Err(err("UnknownOperationException", format!("{op} is not supported yet"))),
        };
        Ok((v, jobs))
    }

    pub fn admin(&self) -> Value {
        self.clusters
            .keys()
            .map(|c| {
                let rows: Vec<Value> = self.tasks.iter().filter(|(_, t)| t.cluster == *c).rev().take(100).map(|(id, t)| {
                    let ports: Vec<String> = t.containers.iter().flat_map(|x| x.bindings.iter().map(|(cp, hp)| format!("{cp}→127.0.0.1:{hp}"))).collect();
                    json!([&id[..12], t.group, t.def, t.last, ports.join(", "), t.reason.clone().unwrap_or_default()])
                }).collect();
                let svcs: Vec<String> = self.services.iter().filter(|((k, _), _)| k == c).map(|((_, n), s)| format!("{n}({})", s.desired)).collect();
                json!({"name": c, "count": rows.len(), "sub": format!("서비스: {}", if svcs.is_empty() { "없음".into() } else { svcs.join(", ") }),
                       "cols": ["태스크", "그룹", "정의", "상태", "포트", "중지 사유"], "rows": rows})
            })
            .collect()
    }
}

fn set_task(app: &App, id: &str, f: impl FnOnce(&mut Task)) {
    if let Some(t) = app.ecs.lock().unwrap().tasks.get_mut(id) {
        f(t);
    }
}

// Launch every container of a task, then watch it until it stops.
pub async fn run_task(app: Arc<App>, id: String) {
    let Some((def, overrides, role)) = ({
        let e = app.ecs.lock().unwrap();
        e.tasks.get(&id).map(|t| (e.defs[&t.def].containers.clone(), t.overrides.clone(), e.defs[&t.def].task_role.clone()))
    }) else { return };
    let creds = role.and_then(|r| app.iam.lock().unwrap().session_for_role(&r, &format!("ecs-{}", &id[..12])));
    let port = crate::endpoint().rsplit(':').next().unwrap_or("4566").to_string();
    let mut failure = None;
    for c in &def {
        let name = c["name"].as_str().unwrap_or("app");
        let docker = format!("rocalcloud-ecs-{}-{name}", &id[..12]);
        let ov = overrides["containerOverrides"].as_array().into_iter().flatten().find(|o| o["name"] == name).cloned().unwrap_or_default();
        let mem = c["memory"].as_u64().or(c["memoryReservation"].as_u64()).map_or_else(|| std::env::var("RC_CONTAINER_MEMORY").unwrap_or("512m".into()), |m| format!("{m}m"));
        let mut args: Vec<String> = ["run", "-d", "--name", &docker, "--memory", &mem, "--cpus", "1", "--label", "rocalcloud=1",
            "--add-host", "host.docker.internal:host-gateway"].iter().map(|s| s.to_string()).collect();
        let mut bindings = vec![];
        for pm in c["portMappings"].as_array().into_iter().flatten() {
            let cp = pm["containerPort"].as_u64().unwrap_or(80);
            let hp = free_port();
            args.extend(["-p".into(), format!("127.0.0.1:{hp}:{cp}")]);
            bindings.push((cp, hp));
        }
        let mut env: Vec<(String, String)> = vec![("AWS_REGION".into(), REGION.clone()), ("AWS_DEFAULT_REGION".into(), REGION.clone()),
            ("AWS_ENDPOINT_URL".into(), format!("http://host.docker.internal:{port}")), ("ECS_CONTAINER_METADATA_URI".into(), String::new())];
        let (ak, sk, tok) = creds.clone().unwrap_or(("test".into(), "test".into(), String::new()));
        env.extend([("AWS_ACCESS_KEY_ID".into(), ak), ("AWS_SECRET_ACCESS_KEY".into(), sk), ("AWS_SESSION_TOKEN".into(), tok)]);
        for e in c["environment"].as_array().into_iter().flatten().chain(ov["environment"].as_array().into_iter().flatten()) {
            env.push((e["name"].as_str().unwrap_or("").into(), e["value"].as_str().unwrap_or("").into()));
        }
        for (k, v) in env {
            args.extend(["-e".into(), format!("{k}={v}")]);
        }
        if let Some(ep) = c["entryPoint"].as_array().and_then(|a| a.first()).and_then(Value::as_str) {
            args.extend(["--entrypoint".into(), ep.into()]);
        }
        args.push(c["image"].as_str().unwrap_or("").into());
        let ep_rest = c["entryPoint"].as_array().map(|a| a.iter().skip(1).filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>()).unwrap_or_default();
        args.extend(ep_rest);
        let cmd = ov["command"].as_array().or(c["command"].as_array());
        args.extend(cmd.into_iter().flatten().filter_map(|x| x.as_str().map(String::from)));
        match docker_ok(&args.iter().map(String::as_str).collect::<Vec<_>>()).await {
            Ok(_) => set_task(&app, &id, |t| {
                if let Some(x) = t.containers.iter_mut().find(|x| x.name == name) {
                    (x.last, x.bindings) = ("RUNNING".into(), bindings);
                }
            }),
            Err(e) => {
                failure = Some(format!("CannotStartContainerError: {}", e.lines().last().unwrap_or(&e)));
                break;
            }
        }
    }
    match failure {
        Some(reason) => finish(&app, &id, reason).await,
        None => {
            set_task(&app, &id, |t| (t.last, t.started) = ("RUNNING".into(), Some(epoch())));
            register_targets(&app, &id, true);
            event(&app, &id, "RUNNING");
            watch(app, id).await;
        }
    }
}

fn event(app: &App, id: &str, status: &str) {
    let group = app.ecs.lock().unwrap().tasks.get(id).map(|t| t.group.clone()).unwrap_or_default();
    crate::emit(app, json!({"ts": chrono::Utc::now().to_rfc3339(), "service": "ecs", "op": "TaskStateChange", "target": format!("{group} {}", &id[..12]),
        "result": status, "status": if status == "STOPPED" { 299 } else { 200 }}));
}

// Service tasks join their service's ALB target groups while running.
fn register_targets(app: &App, id: &str, on: bool) {
    let targets: Vec<(String, u16)> = {
        let e = app.ecs.lock().unwrap();
        let Some(t) = e.tasks.get(id) else { return };
        let Some(svc) = t.group.strip_prefix("service:").and_then(|n| e.services.get(&(t.cluster.clone(), n.to_string()))) else { return };
        svc.lbs.iter().filter_map(|lb| {
            let tg = lb["targetGroupArn"].as_str()?.to_string();
            let c = t.containers.iter().find(|c| lb["containerName"].as_str() == Some(c.name.as_str()))?;
            let hp = c.bindings.iter().find(|(cp, _)| Some(*cp) == lb["containerPort"].as_u64())?.1;
            Some((tg, hp))
        }).collect()
    };
    let mut elb = app.elb.lock().unwrap();
    for (tg, hp) in targets {
        elb.set_target(&tg, "127.0.0.1", hp, on);
    }
}

// Copy new container output lines into CloudWatch Logs (awslogs driver options).
async fn ship_logs(app: &App, id: &str) {
    let (conts, defs) = {
        let e = app.ecs.lock().unwrap();
        let Some(t) = e.tasks.get(id) else { return };
        (t.containers.clone(), e.defs[&t.def].containers.clone())
    };
    for c in conts {
        let Some(d) = defs.iter().find(|d| d["name"] == c.name.as_str()) else { continue };
        let opts = &d["logConfiguration"]["options"];
        let Some(group) = opts["awslogs-group"].as_str() else { continue };
        let Ok(out) = tokio::process::Command::new(std::env::var("RC_DOCKER").unwrap_or("docker".into())).args(["logs", &c.docker]).output().await else { continue };
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        let lines: Vec<&str> = text.lines().collect();
        if lines.len() <= c.log_lines {
            continue;
        }
        let stream = format!("{}/{}/{id}", opts["awslogs-stream-prefix"].as_str().unwrap_or("ecs"), c.name);
        let now = crate::now_ms();
        app.logs.lock().unwrap().put(group, &stream, lines[c.log_lines..].iter().map(|l| (now, l.to_string())).collect());
        let n = lines.len();
        set_task(app, id, |t| {
            if let Some(x) = t.containers.iter_mut().find(|x| x.name == c.name) {
                x.log_lines = n;
            }
        });
    }
}

async fn watch(app: Arc<App>, id: String) {
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        ship_logs(&app, &id).await;
        let Some((desired, conts)) = app.ecs.lock().unwrap().tasks.get(&id).map(|t| (t.desired.clone(), t.containers.clone())) else { return };
        if desired == "STOPPED" {
            let reason = app.ecs.lock().unwrap().tasks.get(&id).and_then(|t| t.reason.clone()).unwrap_or_default();
            return finish(&app, &id, reason).await;
        }
        let defs = { let e = app.ecs.lock().unwrap(); e.defs[&e.tasks[&id].def].containers.clone() };
        for c in conts {
            let state = docker_ok(&["inspect", "-f", "{{.State.Running}} {{.State.ExitCode}}", &c.docker]).await.unwrap_or_else(|_| "false -1".into());
            let (running, code) = state.split_once(' ').map_or((false, -1), |(r, x)| (r == "true", x.parse().unwrap_or(-1)));
            if running {
                continue;
            }
            set_task(&app, &id, |t| {
                if let Some(x) = t.containers.iter_mut().find(|x| x.name == c.name) {
                    (x.last, x.exit) = ("STOPPED".into(), Some(code));
                }
            });
            let essential = defs.iter().find(|d| d["name"] == c.name.as_str()).is_none_or(|d| d["essential"] != false);
            if essential {
                return finish(&app, &id, format!("Essential container in task exited ({} exit code {code})", c.name)).await;
            }
        }
    }
}

async fn finish(app: &Arc<App>, id: &str, reason: String) {
    ship_logs(app, id).await;
    register_targets(app, id, false);
    let conts = app.ecs.lock().unwrap().tasks.get(id).map(|t| t.containers.clone()).unwrap_or_default();
    for c in &conts {
        if c.exit.is_none() {
            let code = docker_ok(&["inspect", "-f", "{{.State.ExitCode}}", &c.docker]).await.ok().and_then(|s| s.parse().ok());
            set_task(app, id, |t| {
                if let Some(x) = t.containers.iter_mut().find(|x| x.name == c.name) {
                    x.exit = code;
                }
            });
        }
        let _ = docker_ok(&["rm", "-f", &c.docker]).await;
    }
    set_task(app, id, |t| {
        (t.last, t.desired, t.stopped) = ("STOPPED".into(), "STOPPED".into(), Some(epoch()));
        t.reason.get_or_insert(reason);
        for c in &mut t.containers {
            c.last = "STOPPED".into();
        }
    });
    event(app, id, "STOPPED");
}

// Keep a service at desiredCount: start replacements, stop extras; ends when a deleted service has no tasks left.
pub async fn reconcile(app: Arc<App>, cluster: String, name: String) {
    loop {
        let (start, done) = {
            let mut e = app.ecs.lock().unwrap();
            let Some(s) = e.services.get(&(cluster.clone(), name.clone())) else { return };
            let (desired, def, deleting) = (s.desired as usize, s.def.clone(), s.deleting);
            let group = format!("service:{name}");
            let live: Vec<String> = e.tasks.iter().filter(|(_, t)| t.cluster == cluster && t.group == group && t.desired == "RUNNING").map(|(i, _)| i.clone()).collect();
            let stop: Vec<String> = live.iter().skip(desired).cloned().collect();
            for i in &stop {
                let t = e.tasks.get_mut(i).unwrap();
                t.desired = "STOPPED".into();
                t.reason = Some("Scaling activity initiated by (deployment ecs-svc/local)".into());
            }
            let start: Vec<String> = (live.len()..desired).map(|_| e.new_task(&cluster, &def, group.clone(), Value::Null)).collect();
            let running = e.tasks.values().any(|t| t.cluster == cluster && t.group == group && t.last != "STOPPED");
            (start, deleting && !running)
        };
        for id in start {
            tokio::spawn(run_task(app.clone(), id));
        }
        if done {
            app.ecs.lock().unwrap().services.remove(&(cluster.clone(), name.clone()));
            return;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

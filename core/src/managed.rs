// RDS (Postgres/MySQL/MariaDB) and ElastiCache (Redis/Valkey/Memcached) backed by real Docker containers.
// Containers publish on 127.0.0.1 only and are capped (RC_CONTAINER_MEMORY, default 512m; 1 CPU).
// ponytail: single-node only — no Aurora clusters, replicas, replication groups, snapshots or parameter groups.
use crate::{err, ApiErr, App, ACCOUNT, REGION};
use serde_json::{json, Value};
use std::{collections::{BTreeMap, HashMap}, sync::Arc, time::Duration};
use tokio::process::Command;

#[derive(Clone)]
pub struct Node {
    engine: String,
    version: String,
    image: String,
    inner: u16,
    port: Option<u16>,
    status: String,
    user: String,
    password: String,
    db: String,
    class: String,
    storage: u64,
    created: String,
}

#[derive(Default)]
pub struct Managed {
    nodes: BTreeMap<(String, String), Node>, // (kind "rds" | "cache", id)
}

pub enum Job {
    Create,
    Start,
    Stop,
    Delete,
}

pub fn container(kind: &str, id: &str) -> String {
    format!("rocalcloud-{kind}-{id}")
}
fn docker() -> String {
    std::env::var("RC_DOCKER").unwrap_or_else(|_| "docker".into())
}
async fn docker_ok(args: &[&str]) -> Result<String, String> {
    let out = Command::new(docker()).args(args).output().await.map_err(|e| format!("cannot run {}: {e}", docker()))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).map(|a| a.port()).unwrap_or(0)
}

// Remove containers left over from a previous run (their state lived only in memory).
pub async fn cleanup() {
    if let Ok(ids) = docker_ok(&["ps", "-aq", "--filter", "name=rocalcloud-"]).await {
        for id in ids.lines().filter(|l| !l.is_empty()) {
            let _ = docker_ok(&["rm", "-f", id]).await;
        }
    }
}

fn readiness(kind: &str, n: &Node) -> Vec<String> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    match (kind, n.engine.as_str()) {
        ("rds", "postgres") => s(&["pg_isready", "-h", "127.0.0.1", "-U", &n.user, "-d", &n.db]),
        ("rds", e) => s(&[if e == "mariadb" { "mariadb" } else { "mysql" }, "-h127.0.0.1", &format!("-u{}", n.user), &format!("-p{}", n.password), "-e", "select 1"]),
        (_, "memcached") => vec![],
        (_, e) => s(&[if e == "valkey" { "valkey-cli" } else { "redis-cli" }, "ping"]),
    }
}

// Background work for a node: start/stop/remove its container and track readiness.
pub async fn run_job(app: Arc<App>, kind: String, id: String, job: Job) {
    let name = container(&kind, &id);
    let set = |status: &str, port: Option<u16>| {
        if let Some(n) = app.managed.lock().unwrap().nodes.get_mut(&(kind.clone(), id.clone())) {
            n.status = status.into();
            if port.is_some() {
                n.port = port;
            }
        }
        crate::emit(&app, json!({"ts": chrono::Utc::now().to_rfc3339(), "service": if kind == "rds" { "rds" } else { "elasticache" },
            "op": "StatusChanged", "target": id, "result": status, "status": if status == "failed" { 500 } else { 200 }}));
    };
    let node = app.managed.lock().unwrap().nodes.get(&(kind.clone(), id.clone())).cloned();
    let result: Result<(), String> = async {
        match job {
            Job::Delete => {
                docker_ok(&["rm", "-f", &name]).await.map(|_| ())
            }
            Job::Stop => {
                docker_ok(&["stop", &name]).await?;
                set("stopped", None);
                Ok(())
            }
            Job::Create | Job::Start => {
                let n = node.ok_or("node vanished")?;
                if matches!(job, Job::Start) {
                    docker_ok(&["start", &name]).await?;
                } else {
                    let port = free_port();
                    let mem = std::env::var("RC_CONTAINER_MEMORY").unwrap_or_else(|_| "512m".into());
                    let publish = format!("127.0.0.1:{port}:{}", n.inner);
                    let mut args: Vec<String> = ["run", "-d", "--name", &name, "--memory", &mem, "--cpus", "1", "-p", &publish, "--label", "rocalcloud=1"]
                        .iter().map(|s| s.to_string()).collect();
                    let env: Vec<(&str, &str)> = match n.engine.as_str() {
                        "postgres" => vec![("POSTGRES_USER", &n.user), ("POSTGRES_PASSWORD", &n.password), ("POSTGRES_DB", &n.db)],
                        "mysql" | "mariadb" => {
                            let mut e = vec![("MYSQL_ROOT_PASSWORD", n.password.as_str()), ("MYSQL_DATABASE", n.db.as_str()), ("MARIADB_ROOT_PASSWORD", n.password.as_str())];
                            if n.user != "root" {
                                e.extend([("MYSQL_USER", n.user.as_str()), ("MYSQL_PASSWORD", n.password.as_str())]);
                            }
                            e
                        }
                        _ => vec![],
                    };
                    for (k, v) in env {
                        args.extend(["-e".to_string(), format!("{k}={v}")]);
                    }
                    args.push(n.image.clone());
                    docker_ok(&args.iter().map(String::as_str).collect::<Vec<_>>()).await?;
                    set("creating", Some(port));
                }
                // Wait until the engine accepts TCP connections (init servers listen on a socket only).
                let probe = readiness(&kind, &n);
                for _ in 0..180 {
                    if probe.is_empty() {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        break;
                    }
                    let mut cmd = vec!["exec".to_string(), name.clone()];
                    cmd.extend(probe.iter().cloned());
                    if docker_ok(&cmd.iter().map(String::as_str).collect::<Vec<_>>()).await.is_ok() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                set("available", None);
                Ok(())
            }
        }
    }.await;
    if let Err(e) = result {
        eprintln!("{kind} {id}: {e}");
        set("failed", None);
    }
}

fn rds_arn(id: &str) -> String {
    format!("arn:aws:rds:{}:{ACCOUNT}:db:{id}", *REGION)
}
fn cache_arn(id: &str) -> String {
    format!("arn:aws:elasticache:{}:{ACCOUNT}:cluster:{id}", *REGION)
}

fn rds_json(id: &str, n: &Node) -> Value {
    let mut v = json!({"DBInstanceIdentifier": id, "DBInstanceArn": rds_arn(id), "DBInstanceClass": n.class, "Engine": n.engine,
        "EngineVersion": n.version, "DBInstanceStatus": n.status, "MasterUsername": n.user, "DBName": n.db, "AllocatedStorage": n.storage,
        "InstanceCreateTime": n.created, "AvailabilityZone": format!("{}a", *REGION), "MultiAZ": false, "PubliclyAccessible": false,
        "StorageType": "gp3", "DbiResourceId": format!("db-{}", id.to_uppercase())});
    if let Some(p) = n.port {
        v["Endpoint"] = json!({"Address": "127.0.0.1", "Port": p, "HostedZoneId": "LOCAL"});
    }
    v
}
fn cache_json(id: &str, n: &Node, nodes: bool) -> Value {
    let mut v = json!({"CacheClusterId": id, "ARN": cache_arn(id), "CacheClusterStatus": n.status, "Engine": n.engine, "EngineVersion": n.version,
        "CacheNodeType": n.class, "NumCacheNodes": 1, "CacheClusterCreateTime": n.created, "PreferredAvailabilityZone": format!("{}a", *REGION)});
    if let (true, Some(p)) = (nodes, n.port) {
        v["CacheNodes|CacheNode"] = json!([{"CacheNodeId": "0001", "CacheNodeStatus": n.status, "CacheNodeCreateTime": n.created,
                                             "Endpoint": {"Address": "127.0.0.1", "Port": p}}]);
    }
    if n.engine == "memcached" {
        if let Some(p) = n.port {
            v["ConfigurationEndpoint"] = json!({"Address": "127.0.0.1", "Port": p});
        }
    }
    v
}

type Q = HashMap<String, String>;
pub type Reply = (Value, Option<(String, String, Job)>);

impl Managed {
    pub fn rds(&mut self, q: &Q) -> Result<Reply, ApiErr> {
        let p = |k: &str| q.get(k).cloned().ok_or_else(|| err("InvalidParameterValue", format!("{k} is required")));
        let nf = |id: &str| ApiErr { status: 404, ..err("DBInstanceNotFound", format!("DBInstance {id} not found.")) };
        let action = q.get("Action").map_or("", String::as_str);
        Ok(match action {
            "CreateDBInstance" => {
                let id = p("DBInstanceIdentifier")?;
                let key = ("rds".to_string(), id.clone());
                if self.nodes.contains_key(&key) {
                    return Err(err("DBInstanceAlreadyExists", format!("DB instance already exists: {id}")));
                }
                let engine = p("Engine")?.replace("aurora-", "");
                let (image, inner, default_v) = match engine.as_str() {
                    "postgres" | "postgresql" => ("postgres", 5432, "16"),
                    "mysql" => ("mysql", 3306, "8.4"),
                    "mariadb" => ("mariadb", 3306, "11"),
                    e => return Err(err("InvalidParameterCombination", format!("Engine {e} is not supported locally (postgres, mysql, mariadb)"))),
                };
                let engine = if engine == "postgresql" { "postgres".to_string() } else { engine };
                let version = q.get("EngineVersion").cloned().unwrap_or(default_v.into());
                let major: String = if engine == "postgres" { version.split('.').next().unwrap_or("16").into() } else { version.split('.').take(2).collect::<Vec<_>>().join(".") };
                let pw = p("MasterUserPassword")?;
                if pw.len() < 8 {
                    return Err(err("InvalidParameterValue", "The parameter MasterUserPassword is not a valid password because it is shorter than 8 characters."));
                }
                let n = Node { image: format!("{image}:{major}{}", if engine == "postgres" { "-alpine" } else { "" }), inner, port: None,
                    status: "creating".into(), user: p("MasterUsername")?, password: pw,
                    db: q.get("DBName").cloned().unwrap_or(if engine == "postgres" { "postgres".into() } else { "mysql".into() }),
                    class: q.get("DBInstanceClass").cloned().unwrap_or("db.t3.micro".into()),
                    storage: q.get("AllocatedStorage").and_then(|s| s.parse().ok()).unwrap_or(20), created: chrono::Utc::now().to_rfc3339(),
                    engine, version };
                let out = json!({"DBInstance": rds_json(&id, &n)});
                self.nodes.insert(key, n);
                (out, Some(("rds".into(), id, Job::Create)))
            }
            "DescribeDBInstances" => {
                let list: Vec<Value> = match q.get("DBInstanceIdentifier") {
                    Some(id) => vec![rds_json(id, self.nodes.get(&("rds".into(), id.clone())).ok_or_else(|| nf(id))?)],
                    None => self.nodes.iter().filter(|((k, _), _)| k == "rds").map(|((_, id), n)| rds_json(id, n)).collect(),
                };
                (json!({ "DBInstances|DBInstance": list }), None)
            }
            "DeleteDBInstance" | "StopDBInstance" | "StartDBInstance" | "RebootDBInstance" => {
                let id = p("DBInstanceIdentifier")?;
                let key = ("rds".to_string(), id.clone());
                let n = self.nodes.get_mut(&key).ok_or_else(|| nf(&id))?;
                let (status, job) = match action {
                    "DeleteDBInstance" => ("deleting", Job::Delete),
                    "StopDBInstance" => ("stopping", Job::Stop),
                    _ => ("starting", Job::Start),
                };
                if action == "StopDBInstance" && n.status != "available" {
                    return Err(err("InvalidDBInstanceState", format!("Instance {id} is not in available state.")));
                }
                n.status = status.into();
                let out = json!({ "DBInstance": rds_json(&id, n) });
                if matches!(job, Job::Delete) {
                    self.nodes.remove(&key);
                }
                (out, Some(("rds".into(), id, if action == "RebootDBInstance" { Job::Start } else { job })))
            }
            a => return Err(err("InvalidAction", format!("{a} is not supported yet"))),
        })
    }

    pub fn cache(&mut self, q: &Q) -> Result<Reply, ApiErr> {
        let p = |k: &str| q.get(k).cloned().ok_or_else(|| err("InvalidParameterValue", format!("{k} is required")));
        let nf = |id: &str| ApiErr { status: 404, ..err("CacheClusterNotFound", format!("CacheCluster not found: {id}")) };
        let action = q.get("Action").map_or("", String::as_str);
        Ok(match action {
            "CreateCacheCluster" => {
                let id = p("CacheClusterId")?;
                let key = ("cache".to_string(), id.clone());
                if self.nodes.contains_key(&key) {
                    return Err(err("CacheClusterAlreadyExists", format!("Cache cluster {id} already exists.")));
                }
                let engine = q.get("Engine").cloned().unwrap_or("redis".into());
                let (image, inner, default_v) = match engine.as_str() {
                    "redis" => ("redis", 6379, "7"),
                    "valkey" => ("valkey/valkey", 6379, "8"),
                    "memcached" => ("memcached", 11211, "1.6"),
                    e => return Err(err("InvalidParameterValue", format!("Engine {e} is not supported"))),
                };
                let version = q.get("EngineVersion").cloned().unwrap_or(default_v.into());
                let major = if engine == "memcached" { version.split('.').take(2).collect::<Vec<_>>().join(".") } else { version.split('.').next().unwrap_or(default_v).to_string() };
                let n = Node { image: format!("{image}:{major}-alpine"), inner, port: None, status: "creating".into(), user: String::new(), password: String::new(),
                    db: String::new(), class: q.get("CacheNodeType").cloned().unwrap_or("cache.t3.micro".into()), storage: 0,
                    created: chrono::Utc::now().to_rfc3339(), engine, version };
                let out = json!({"CacheCluster": cache_json(&id, &n, false)});
                self.nodes.insert(key, n);
                (out, Some(("cache".into(), id, Job::Create)))
            }
            "DescribeCacheClusters" => {
                let show = q.get("ShowCacheNodeInfo").is_some_and(|v| v == "true");
                let list: Vec<Value> = match q.get("CacheClusterId") {
                    Some(id) => vec![cache_json(id, self.nodes.get(&("cache".into(), id.clone())).ok_or_else(|| nf(id))?, show)],
                    None => self.nodes.iter().filter(|((k, _), _)| k == "cache").map(|((_, id), n)| cache_json(id, n, show)).collect(),
                };
                (json!({ "CacheClusters|CacheCluster": list }), None)
            }
            "DeleteCacheCluster" => {
                let id = p("CacheClusterId")?;
                let mut n = self.nodes.remove(&("cache".into(), id.clone())).ok_or_else(|| nf(&id))?;
                n.status = "deleting".into();
                (json!({"CacheCluster": cache_json(&id, &n, false)}), Some(("cache".into(), id, Job::Delete)))
            }
            a => return Err(err("InvalidAction", format!("{a} is not supported yet"))),
        })
    }

    pub fn admin(&self) -> Value {
        self.nodes
            .iter()
            .map(|((k, id), n)| {
                let url = match (k.as_str(), n.port) {
                    (_, None) => "(준비 중)".to_string(),
                    ("rds", Some(p)) => format!("{}://{}:****@127.0.0.1:{p}/{}", if n.engine == "postgres" { "postgresql" } else { "mysql" }, n.user, n.db),
                    (_, Some(p)) => format!("{}://127.0.0.1:{p}", if n.engine == "memcached" { "memcached" } else { "redis" }),
                };
                json!({"name": id, "count": 1, "sub": format!("{} · {} {} · 컨테이너 {}", if k == "rds" { "RDS" } else { "ElastiCache" }, n.engine, n.version, container(k, id)),
                       "cols": ["상태", "접속", "이미지", "클래스"], "rows": [[n.status, url, n.image, n.class]]})
            })
            .collect()
    }
}

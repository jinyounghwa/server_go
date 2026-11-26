// Route 53 (REST-XML) hosted zones, record sets, loopback-only TCP/HTTP health checks, and a tiny DNS server on
// 127.0.0.1:{RC_DNS_PORT or 10053} (UDP + TCP; UDP truncates >512B with TC=1) answering A, AAAA, CNAME and TXT.
// Routing policies: weighted (random by Weight; 0 never wins), failover (PRIMARY beats SECONDARY, gated by HealthCheckId)
// and latency (first set — the client's region is unknown). ponytail: no DNSSEC or zone transfers; RequestInterval is validated (>=10) but probed every 2s locally.
use crate::s3::{esc, tags};
use crate::{err, ApiErr, App};
use std::{collections::BTreeMap, net::{Ipv4Addr, Ipv6Addr}, sync::Arc};

const NS: &str = "https://route53.amazonaws.com/doc/2013-04-01/";

#[derive(Clone)]
struct RecordSet {
    name: String,
    ty: String,
    ttl: u32,
    values: Vec<String>,
    alias: Option<String>, // alias DNS name
    set_id: Option<String>, // routing-policy set identifier
    weight: Option<u64>,
    region: Option<String>,
    failover: Option<String>, // PRIMARY | SECONDARY
    health: Option<String>,   // HealthCheckId gate
}
struct Zone {
    name: String,
    caller: String,
    comment: String,
    private: bool,
    records: Vec<RecordSet>,
}

#[derive(Default)]
pub struct Route53 {
    zones: BTreeMap<String, Zone>,
    checks: BTreeMap<String, HealthCheck>,
}

struct HealthCheck {
    kind: String,   // TCP | HTTP
    host: String,   // loopback only (SSRF guard)
    port: u16,
    path: String,   // HTTP resource path
    #[allow(dead_code)]
    period: u64,    // RequestInterval (validated >= 10, not enforced locally)
    status: String, // Healthy | Unhealthy | Unknown
    created: String,
}

fn health_xml(id: &str, h: &HealthCheck) -> String {
    format!("<HealthCheck><Id>{id}</Id><CallerReference>{id}</CallerReference><HealthCheckConfig><Type>{}</Type><IPAddress>{}</IPAddress><Port>{}</Port>{}</HealthCheckConfig><HealthCheckVersion>1</HealthCheckVersion></HealthCheck>",
        esc(&h.kind), esc(&h.host), h.port,
        if h.kind == "HTTP" { format!("<ResourcePath>{}</ResourcePath>", esc(&h.path)) } else { String::new() })
}

fn is_loopback(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn fqdn(n: &str) -> String {
    let n = n.to_lowercase();
    if n.ends_with('.') { n } else { format!("{n}.") }
}
fn first(x: &str, tag: &str) -> String {
    tags(x, tag).into_iter().next().unwrap_or_default()
}
fn change_info() -> String {
    format!("<ChangeInfo><Id>/change/C{}</Id><Status>INSYNC</Status><SubmittedAt>{}</SubmittedAt></ChangeInfo>",
            &uuid::Uuid::new_v4().simple().to_string()[..13].to_uppercase(), chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ"))
}
fn nf(id: &str) -> ApiErr {
    ApiErr { status: 404, ..err("NoSuchHostedZone", format!("No hosted zone found with ID: {id}")) }
}

impl Zone {
    fn xml(&self, id: &str) -> String {
        format!("<HostedZone><Id>/hostedzone/{id}</Id><Name>{}</Name><CallerReference>{}</CallerReference><Config><Comment>{}</Comment><PrivateZone>{}</PrivateZone></Config><ResourceRecordSetCount>{}</ResourceRecordSetCount></HostedZone>",
                esc(&self.name), esc(&self.caller), esc(&self.comment), self.private, self.records.len())
    }
}
fn rrset_xml(r: &RecordSet) -> String {
    let body = match &r.alias {
        Some(a) => format!("<AliasTarget><HostedZoneId>LOCAL</HostedZoneId><DNSName>{}</DNSName><EvaluateTargetHealth>false</EvaluateTargetHealth></AliasTarget>", esc(a)),
        None => format!("<TTL>{}</TTL><ResourceRecords>{}</ResourceRecords>", r.ttl,
                        r.values.iter().map(|v| format!("<ResourceRecord><Value>{}</Value></ResourceRecord>", esc(v))).collect::<String>()),
    };
    let pol = r.set_id.as_ref().map_or(String::new(), |s| format!("<SetIdentifier>{}</SetIdentifier>", esc(s))
        + &r.weight.map_or(String::new(), |w| format!("<Weight>{w}</Weight>"))
        + &r.region.as_ref().map_or(String::new(), |g| format!("<Region>{}</Region>", esc(g)))
        + &r.failover.as_ref().map_or(String::new(), |f| format!("<Failover>{}</Failover>", esc(f)))
        + &r.health.as_ref().map_or(String::new(), |h| format!("<HealthCheckId>{}</HealthCheckId>", esc(h))));
    format!("<ResourceRecordSet><Name>{}</Name><Type>{}</Type>{pol}{body}</ResourceRecordSet>", esc(&r.name), r.ty)
}
const DELEGATION: &str = "<DelegationSet><NameServers><NameServer>ns1.rocalcloud.local</NameServer><NameServer>ns2.rocalcloud.local</NameServer></NameServers></DelegationSet>";

impl Route53 {
    // REST control plane; `path` follows /2013-04-01/. Returns (status, XML body).
    pub fn handle(&mut self, method: &str, path: &str, body: &str) -> Result<(u16, String), ApiErr> {
        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        let wrap = |name: &str, inner: String| format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<{name} xmlns=\"{NS}\">{inner}</{name}>");
        Ok(match (method, parts.as_slice()) {
            ("POST", ["hostedzone"]) => {
                let name = fqdn(&first(body, "Name"));
                if name == "." {
                    return Err(err("InvalidDomainName", "Name is required"));
                }
                let caller = first(body, "CallerReference");
                if self.zones.values().any(|z| z.caller == caller && !caller.is_empty()) {
                    return Err(ApiErr { status: 409, ..err("HostedZoneAlreadyExists", format!("A hosted zone has already been created with the specified caller reference {caller}")) });
                }
                let id = format!("Z{}", &uuid::Uuid::new_v4().simple().to_string()[..20].to_uppercase());
                let soa = RecordSet { name: name.clone(), ty: "SOA".into(), ttl: 900, values: vec![format!("ns1.rocalcloud.local. hostmaster.{name} 1 7200 900 1209600 86400")], alias: None, set_id: None, weight: None, region: None, failover: None, health: None };
                let ns = RecordSet { name: name.clone(), ty: "NS".into(), ttl: 172800, values: vec!["ns1.rocalcloud.local.".into(), "ns2.rocalcloud.local.".into()], alias: None, set_id: None, weight: None, region: None, failover: None, health: None };
                let z = Zone { name, caller, comment: first(body, "Comment"), private: first(body, "PrivateZone") == "true", records: vec![soa, ns] };
                let out = wrap("CreateHostedZoneResponse", format!("{}{}{DELEGATION}", z.xml(&id), change_info()));
                self.zones.insert(id, z);
                (201, out)
            }
            ("GET", ["hostedzone"]) => {
                let zs: String = self.zones.iter().map(|(id, z)| z.xml(id)).collect();
                (200, wrap("ListHostedZonesResponse", format!("<HostedZones>{zs}</HostedZones><IsTruncated>false</IsTruncated><MaxItems>100</MaxItems>")))
            }
            ("GET", ["hostedzonesbyname"]) => {
                let zs: String = self.zones.iter().map(|(id, z)| z.xml(id)).collect();
                (200, wrap("ListHostedZonesByNameResponse", format!("<HostedZones>{zs}</HostedZones><IsTruncated>false</IsTruncated><MaxItems>100</MaxItems>")))
            }
            ("GET", ["hostedzone", id]) => {
                let z = self.zones.get(*id).ok_or_else(|| nf(id))?;
                (200, wrap("GetHostedZoneResponse", format!("{}{DELEGATION}", z.xml(id))))
            }
            ("DELETE", ["hostedzone", id]) => {
                let z = self.zones.get(*id).ok_or_else(|| nf(id))?;
                if z.records.iter().any(|r| r.ty != "SOA" && r.ty != "NS") {
                    return Err(err("HostedZoneNotEmpty", "The specified hosted zone contains non-required resource record sets and so cannot be deleted."));
                }
                self.zones.remove(*id);
                (200, wrap("DeleteHostedZoneResponse", change_info()))
            }
            ("POST", ["hostedzone", id, "rrset"]) => {
                let z = self.zones.get_mut(*id).ok_or_else(|| nf(id))?;
                // Validate the whole batch first: it applies atomically.
                let mut recs = z.records.clone();
                for c in tags(body, "Change") {
                    let action = first(&c, "Action");
                    let set = first(&c, "ResourceRecordSet");
                    let ne = |s: String| if s.is_empty() { None } else { Some(s) };
                    let r = RecordSet {
                        name: fqdn(&first(&set, "Name")),
                        ty: first(&set, "Type"),
                        ttl: first(&set, "TTL").parse().unwrap_or(300),
                        values: tags(&set, "Value"),
                        alias: tags(&set, "AliasTarget").first().map(|a| fqdn(&first(a, "DNSName"))),
                        set_id: ne(first(&set, "SetIdentifier")),
                        weight: first(&set, "Weight").parse().ok(),
                        region: ne(first(&set, "Region")),
                        failover: ne(first(&set, "Failover")),
                        health: ne(first(&set, "HealthCheckId")),
                    };
                    if let Some(h) = &r.health {
                        if !self.checks.contains_key(h) {
                            return Err(err("InvalidInput", format!("No health check exists with the specified ID {h}")));
                        }
                    }
                    if !r.name.ends_with(&z.name) {
                        return Err(err("InvalidChangeBatch", format!("RRSet with DNS name {} is not permitted in zone {}", r.name, z.name)));
                    }
                    let pos = recs.iter().position(|x| x.name == r.name && x.ty == r.ty && x.set_id == r.set_id);
                    match (action.as_str(), pos) {
                        ("CREATE", Some(_)) => return Err(err("InvalidChangeBatch", format!("Tried to create resource record set [name='{}', type='{}'] but it already exists", r.name, r.ty))),
                        ("DELETE", None) => return Err(err("InvalidChangeBatch", format!("Tried to delete resource record set [name='{}', type='{}'] but it was not found", r.name, r.ty))),
                        ("DELETE", Some(i)) => drop(recs.remove(i)),
                        ("UPSERT", Some(i)) => recs[i] = r,
                        ("CREATE" | "UPSERT", None) => recs.push(r),
                        (a, _) => return Err(err("InvalidInput", format!("Unknown change action {a}"))),
                    }
                }
                z.records = recs;
                (200, wrap("ChangeResourceRecordSetsResponse", change_info()))
            }
            ("POST", ["healthcheck"]) => {
                let cfg = first(body, "HealthCheckConfig");
                let kind = first(&cfg, "Type");
                if kind != "TCP" && kind != "HTTP" {
                    return Err(err("InvalidInput", format!("Type must be TCP or HTTP, not {kind}")));
                }
                let raw_host = first(&cfg, "IPAddress");
                let host = (if raw_host.is_empty() { first(&cfg, "FullyQualifiedDomainName") } else { raw_host }).to_lowercase();
                if !is_loopback(&host) {
                    return Err(err("InvalidInput", format!("IPAddress {host} is not permitted: health check targets must be loopback addresses locally")));
                }
                let port = first(&cfg, "Port").parse::<u16>().unwrap_or(80);
                let period = first(&cfg, "RequestInterval").parse::<u64>().unwrap_or(30);
                if period < 10 {
                    return Err(err("InvalidInput", "RequestInterval must be at least 10 seconds"));
                }
                let raw_path = first(&cfg, "ResourcePath");
                let path = if raw_path.is_empty() {
                    "/".into()
                } else if raw_path.starts_with('/') {
                    raw_path
                } else {
                    format!("/{raw_path}")
                };
                let id = uuid::Uuid::new_v4().simple().to_string()[..12].to_string();
                let h = HealthCheck { kind, host, port, path, period, status: "Unknown".into(), created: chrono::Utc::now().to_rfc3339() };
                let out = wrap("CreateHealthCheckResponse", format!("{}{}", health_xml(&id, &h), change_info()));
                self.checks.insert(id, h);
                (201, out)
            }
            ("GET", ["healthcheck"]) => {
                let hs: String = self.checks.iter().map(|(id, h)| health_xml(id, h)).collect::<String>();
                (200, wrap("ListHealthChecksResponse", format!("<HealthChecks>{hs}</HealthChecks><IsTruncated>false</IsTruncated><MaxItems>100</MaxItems>")))
            }
            ("GET", ["healthcheck", id]) => {
                let h = self.checks.get(*id).ok_or_else(|| ApiErr { status: 404, ..err("NoSuchHealthCheck", format!("No health check found with ID: {id}")) })?;
                (200, wrap("GetHealthCheckResponse", health_xml(id, h)))
            }
            ("DELETE", ["healthcheck", id]) => {
                if !self.checks.contains_key(*id) {
                    return Err(ApiErr { status: 404, ..err("NoSuchHealthCheck", format!("No health check found with ID: {id}")) });
                }
                if self.zones.values().any(|z| z.records.iter().any(|r| r.health.as_deref() == Some(*id))) {
                    return Err(err("InvalidInput", format!("Health check {id} is in use by one or more resource record sets")));
                }
                self.checks.remove(*id);
                (200, wrap("DeleteHealthCheckResponse", change_info()))
            }
            ("GET", ["healthcheck", id, "status"]) => {
                let h = self.checks.get(*id).ok_or_else(|| ApiErr { status: 404, ..err("NoSuchHealthCheck", format!("No health check found with ID: {id}")) })?;
                let status = if h.status == "Healthy" { "Healthy" } else { "Unhealthy" };
                (200, wrap("GetHealthCheckStatusResponse", format!(
                    "<HealthCheckObservations><HealthCheckObservation><Region>{}</Region><IPAddress>{}</IPAddress><StatusReport><Status>{status}</Status><CheckedTime>{}</CheckedTime></StatusReport></HealthCheckObservation></HealthCheckObservations>",
                    *crate::REGION, esc(&h.host), esc(&h.created))))
            }
            ("GET", ["hostedzone", id, "rrset"]) => {
                let z = self.zones.get(*id).ok_or_else(|| nf(id))?;
                let rs: String = z.records.iter().map(rrset_xml).collect();
                (200, wrap("ListResourceRecordSetsResponse", format!("<ResourceRecordSets>{rs}</ResourceRecordSets><IsTruncated>false</IsTruncated><MaxItems>300</MaxItems>")))
            }
            ("GET", ["change", _]) => (200, wrap("GetChangeResponse", change_info())),
            _ => return Err(ApiErr { status: 404, ..err("InvalidInput", "Unsupported Route 53 resource") }),
        })
    }

    // Records answering a DNS question, following CNAMEs and aliases within the zones.
    fn answer(&self, name: &str, qtype: &str, depth: u8) -> Vec<RecordSet> {
        if depth > 8 {
            return vec![];
        }
        let all: Vec<&RecordSet> = self.zones.values().flat_map(|z| &z.records).collect();
        let exact: Vec<&RecordSet> = all.iter().copied().filter(|r| r.name == name).collect();
        let found: Vec<&RecordSet> = if exact.is_empty() {
            // *.example.com. covers one or more labels.
            all.iter().copied().filter(|r| r.name.strip_prefix("*.").is_some_and(|base| name.ends_with(&format!(".{base}")))).collect()
        } else {
            exact
        };
        // Records gated by a HealthCheckId only answer while the check is Healthy (failover flips to
        // SECONDARY, weighted/latency sets skip the unhealthy one).
        let found: Vec<&RecordSet> = found.into_iter()
            .filter(|r| r.health.as_deref().map_or(true, |h| self.checks.get(h).is_some_and(|c| c.status == "Healthy")))
            .collect();
        let mut out = vec![];
        // Routing policies: among same name+type sets carrying a SetIdentifier, weighted picks by Weight
        // (0 never wins), failover prefers PRIMARY, latency takes the first set (client region unknown).
        let typed: Vec<&RecordSet> = found.iter().copied().filter(|r| r.ty == qtype).collect();
        let candidates: Vec<RecordSet> = if typed.len() > 1 && typed.iter().any(|r| r.set_id.is_some()) {
            let routed: Vec<&RecordSet> = typed.into_iter().filter(|r| r.set_id.is_some()).collect();
            let chosen: Vec<RecordSet> = if routed.iter().any(|r| r.failover.as_deref() == Some("PRIMARY")) {
                routed.iter().filter(|r| r.failover.as_deref() == Some("PRIMARY")).map(|r| (*r).clone()).collect()
            } else {
                let weights: Vec<u64> = routed.iter().map(|r| r.weight.unwrap_or(0)).collect();
                let total: u64 = weights.iter().sum();
                if total > 0 {
                    let (mut acc, x) = (0u64, rand::random::<u64>() % total);
                    match routed.iter().zip(weights).find(|&(_, w)| {
                        acc += w;
                        x < acc
                    }) {
                        Some((r, _)) => vec![(**r).clone()],
                        None => vec![routed[0].clone()],
                    }
                } else {
                    vec![routed[0].clone()] // latency, or all-zero weights
                }
            };
            found.into_iter().filter(|r| r.ty != qtype).map(|r| (*r).clone()).chain(chosen).collect()
        } else {
            found.into_iter().map(|r| (*r).clone()).collect()
        };
        for r in candidates {
            let r = RecordSet { name: name.into(), ..r };
            if r.ty == qtype && r.alias.is_none() {
                out.push(r);
            } else if r.ty == qtype {
                let target = r.alias.clone().unwrap_or_default();
                let inner = self.answer(&target, qtype, depth + 1);
                if inner.is_empty() && qtype == "A" {
                    // Aliases to resources outside the zones (e.g. a local ALB) point at this host.
                    out.push(RecordSet { values: vec!["127.0.0.1".into()], alias: None, ttl: 60, ..r });
                } else {
                    out.extend(inner.into_iter().map(|x| RecordSet { name: name.into(), ..x }));
                }
            } else if r.ty == "CNAME" && qtype != "CNAME" {
                let target = fqdn(r.values.first().map_or("", String::as_str));
                out.push(r);
                out.extend(self.answer(&target, qtype, depth + 1));
            }
        }
        out
    }

    pub fn admin(&self) -> serde_json::Value {
        self.zones
            .iter()
            .map(|(id, z)| {
                let rows: Vec<serde_json::Value> = z.records.iter()
                    .map(|r| serde_json::json!([r.name, r.ty, r.alias.as_ref().map_or_else(|| r.values.join(", "), |a| format!("alias → {a}")), r.ttl])).collect();
                serde_json::json!({"name": z.name, "count": rows.len(), "sub": format!("{id} · dig @127.0.0.1 -p {} <이름>", dns_port()), "cols": ["이름", "타입", "값", "TTL"], "rows": rows})
            })
            .collect()
    }
}

pub fn dns_port() -> u16 {
    std::env::var("RC_DNS_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(10053)
}

const TYPES: &[(&str, u16)] = &[("A", 1), ("NS", 2), ("CNAME", 5), ("SOA", 6), ("MX", 15), ("TXT", 16), ("AAAA", 28)];

fn encode_name(n: &str) -> Vec<u8> {
    let mut out = vec![];
    for l in n.trim_end_matches('.').split('.').filter(|l| !l.is_empty()) {
        out.push(l.len() as u8);
        out.extend(l.as_bytes());
    }
    out.push(0);
    out
}

// Build a DNS response for one query packet; None for packets we can't parse.
fn respond(app: &App, q: &[u8]) -> Option<(Vec<u8>, usize)> {
    if q.len() < 12 {
        return None;
    }
    let (mut i, mut labels) = (12, vec![]);
    while *q.get(i)? != 0 {
        let n = q[i] as usize;
        labels.push(String::from_utf8_lossy(q.get(i + 1..i + 1 + n)?).to_lowercase());
        i += 1 + n;
    }
    let qend = i + 5;
    let qtype_n = u16::from_be_bytes([*q.get(i + 1)?, *q.get(i + 2)?]);
    let name = format!("{}.", labels.join("."));
    let qtype = TYPES.iter().find(|(_, n)| *n == qtype_n).map_or("?", |(t, _)| *t);
    let (records, nxdomain) = {
        let r = app.route53.lock().unwrap();
        let in_zone = r.zones.values().any(|z| name.ends_with(&z.name));
        let exists = r.zones.values().flat_map(|z| &z.records)
            .any(|x| x.name == name || x.name.strip_prefix("*.").is_some_and(|b| name.ends_with(&format!(".{b}"))));
        (r.answer(&name, qtype, 0), in_zone && !exists)
    };
    let mut answers = vec![];
    for r in &records {
        let rtype = TYPES.iter().find(|(t, _)| *t == r.ty).map_or(1, |(_, n)| *n);
        for v in &r.values {
            let rdata = match r.ty.as_str() {
                "A" => v.parse::<Ipv4Addr>().ok().map(|a| a.octets().to_vec()),
                "AAAA" => v.parse::<Ipv6Addr>().ok().map(|a| a.octets().to_vec()),
                "CNAME" | "NS" => Some(encode_name(v)),
                "TXT" => {
                    let t = v.trim_matches('"').as_bytes();
                    Some([&[t.len().min(255) as u8], &t[..t.len().min(255)]].concat())
                }
                _ => None,
            };
            if let Some(d) = rdata {
                answers.extend(encode_name(&r.name));
                answers.extend(rtype.to_be_bytes());
                answers.extend(1u16.to_be_bytes());
                answers.extend(r.ttl.to_be_bytes());
                answers.extend((d.len() as u16).to_be_bytes());
                answers.extend(d);
            }
        }
    }
    let count = records.iter().map(|r| r.values.len()).sum::<usize>() as u16;
    // QR + AA + RD + RA; NXDOMAIN when the name is in one of our zones but has no records at all.
    let rcode = if nxdomain { 3 } else { 0 };
    let mut out = vec![q[0], q[1], 0x84 | (q[2] & 1), 0x80 | rcode];
    out.extend(1u16.to_be_bytes());
    out.extend(count.to_be_bytes());
    out.extend([0, 0, 0, 0]);
    out.extend(q.get(12..qend)?);
    let at = out.len();
    out.extend(answers);
    Some((out, at))
}

// Probe every health check (loopback only) every 2s; RequestInterval is stored but not enforced
// locally (ponytail) to keep failover tests quick. Spawned once per process.
pub fn serve_health(app: Arc<App>) {
    static STARTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    tokio::spawn(async move {
        loop {
            let checks: Vec<(String, String, String, String)> = {
                let r = app.route53.lock().unwrap();
                r.checks.iter().map(|(id, h)| (id.clone(), format!("{}:{}", h.host, h.port), h.kind.clone(), h.path.clone())).collect()
            };
            for (id, addr, kind, path) in checks {
                let ok = probe(&addr, &kind, &path).await;
                if let Some(h) = app.route53.lock().unwrap().checks.get_mut(&id) {
                    h.status = if ok { "Healthy".into() } else { "Unhealthy".into() };
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    });
}

async fn probe(addr: &str, kind: &str, path: &str) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let Ok(Ok(mut s)) = tokio::time::timeout(std::time::Duration::from_secs(2), tokio::net::TcpStream::connect(addr)).await else { return false };
    if kind == "HTTP" {
        let p = if path.is_empty() { "/" } else { path };
        let req = format!("GET {p} HTTP/1.0\r\nHost: health.rocalcloud\r\nConnection: close\r\n\r\n");
        if s.write_all(req.as_bytes()).await.is_err() {
            return false;
        }
        let mut buf = [0u8; 128];
        return match tokio::time::timeout(std::time::Duration::from_secs(2), s.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                let head = String::from_utf8_lossy(&buf[..n]);
                let status = head.lines().next().and_then(|l| l.split_whitespace().nth(1)).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
                (200..400).contains(&status)
            }
            _ => false,
        };
    }
    true
}

pub fn serve_dns(app: Arc<App>) {
    serve_health(app.clone());
    let app2 = app.clone();
    tokio::spawn(async move {
        let app = app2;
        let Ok(sock) = tokio::net::UdpSocket::bind(("127.0.0.1", dns_port())).await else {
            eprintln!("DNS: cannot bind 127.0.0.1:{} (set RC_DNS_PORT)", dns_port());
            return;
        };
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else { continue };
            if let Some((mut resp, at)) = respond(&app, &buf[..n]) {
                if resp.len() > 512 {
                    // classic DNS truncation: TC bit set, answer counts zeroed
                    resp.truncate(at);
                    resp[2] |= 0x02;
                    resp[6..8].copy_from_slice(&0u16.to_be_bytes());
                }
                let _ = sock.send_to(&resp, from).await;
            }
        }
    });
    tokio::spawn(async move {
        // DNS over TCP on the same port: 2-byte length prefix per message, no 512-byte cap.
        let app = app;
        let Ok(l) = tokio::net::TcpListener::bind(("127.0.0.1", dns_port())).await else { return };
        loop {
            let Ok((mut s, _)) = l.accept().await else { continue };
            let app = app.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut len = [0u8; 2];
                while s.read_exact(&mut len).await.is_ok() {
                    let n = u16::from_be_bytes(len) as usize;
                    let mut q = vec![0u8; n];
                    if s.read_exact(&mut q).await.is_err() {
                        return;
                    }
                    if let Some((resp, _)) = respond(&app, &q) {
                        let mut out = (resp.len() as u16).to_be_bytes().to_vec();
                        out.extend(resp);
                        if s.write_all(&out).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_check_and_failover_gate() {
        assert!(is_loopback("127.0.0.1") && is_loopback("::1") && is_loopback("localhost"));
        assert!(!is_loopback("93.184.216.34") && !is_loopback("example.com") && !is_loopback(""));

        let mut r = Route53::default();
        // External IP rejected
        let err = r.handle("POST", "healthcheck", "<HealthCheckConfig><Type>HTTP</Type><IPAddress>93.184.216.34</IPAddress><Port>80</Port></HealthCheckConfig>").unwrap_err();
        assert_eq!(err.code, "InvalidInput");
        // Interval < 10 rejected
        let err = r.handle("POST", "healthcheck", "<HealthCheckConfig><Type>TCP</Type><IPAddress>127.0.0.1</IPAddress><Port>8080</Port><RequestInterval>5</RequestInterval></HealthCheckConfig>").unwrap_err();
        assert_eq!(err.code, "InvalidInput");

        let (st, xml) = r.handle("POST", "healthcheck", "<HealthCheckConfig><Type>HTTP</Type><IPAddress>127.0.0.1</IPAddress><Port>8080</Port><ResourcePath>ok</ResourcePath><RequestInterval>10</RequestInterval></HealthCheckConfig>").unwrap();
        assert_eq!(st, 201);
        let hc_id = first(&xml, "Id");
        assert_eq!(r.checks[&hc_id].path, "/ok");

        let (_, zxml) = r.handle("POST", "hostedzone", "<Name>ex.test</Name><CallerReference>c1</CallerReference>").unwrap();
        let zid = first(&zxml, "Id").trim_start_matches("/hostedzone/").to_string();
        let batch = format!(
            "<ChangeBatch><Changes>\
             <Change><Action>CREATE</Action><ResourceRecordSet><Name>a.ex.test</Name><Type>A</Type><TTL>60</TTL><SetIdentifier>p</SetIdentifier><Failover>PRIMARY</Failover><HealthCheckId>{hc_id}</HealthCheckId><ResourceRecords><ResourceRecord><Value>127.0.0.1</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></Change>\
             <Change><Action>CREATE</Action><ResourceRecordSet><Name>a.ex.test</Name><Type>A</Type><TTL>60</TTL><SetIdentifier>s</SetIdentifier><Failover>SECONDARY</Failover><ResourceRecords><ResourceRecord><Value>127.0.0.2</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></Change>\
             </Changes></ChangeBatch>"
        );
        r.handle("POST", &format!("hostedzone/{zid}/rrset"), &batch).unwrap();

        // Unknown/Unhealthy PRIMARY -> SECONDARY
        assert_eq!(r.answer("a.ex.test.", "A", 0)[0].values, vec!["127.0.0.2"]);
        // Healthy PRIMARY -> PRIMARY
        r.checks.get_mut(&hc_id).unwrap().status = "Healthy".into();
        assert_eq!(r.answer("a.ex.test.", "A", 0)[0].values, vec!["127.0.0.1"]);
        // In-use delete rejected
        assert_eq!(r.handle("DELETE", &format!("healthcheck/{hc_id}"), "").unwrap_err().code, "InvalidInput");
        // Missing delete returns NoSuchHealthCheck
        assert_eq!(r.handle("DELETE", "healthcheck/missing", "").unwrap_err().code, "NoSuchHealthCheck");
    }
}

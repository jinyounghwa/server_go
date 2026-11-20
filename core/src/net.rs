// VPC network model (EC2 Query API subset) and a reachability analyzer over it.
// ponytail: no NACLs, peering, NAT gateways, IPv6 or tags yet; instances are records that never run anything.
use crate::{err, ApiErr, ACCOUNT, REGION};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;

type Q = HashMap<String, String>;

// Stand-in address for "the internet" when checking routes and rules.
const INTERNET_IP: &str = "203.0.113.10";

fn ipv4(s: &str) -> Option<u32> {
    s.parse::<Ipv4Addr>().ok().map(u32::from)
}
fn cidr(s: &str) -> Option<(u32, u32)> {
    let (ip, n) = s.split_once('/')?;
    let n: u32 = n.parse().ok().filter(|n| *n <= 32)?;
    let mask = if n == 0 { 0 } else { u32::MAX << (32 - n) };
    Some((ipv4(ip)? & mask, mask))
}
fn in_cidr(c: &str, ip: &str) -> bool {
    matches!((cidr(c), ipv4(ip)), (Some((net, mask)), Some(ip)) if ip & mask == net)
}
// `sub` lies entirely inside `sup`.
fn covers(sup: &str, sub: &str) -> bool {
    matches!((cidr(sup), cidr(sub)), (Some((a, am)), Some((b, bm))) if bm & am == am && b & am == a)
}

#[derive(Clone)]
struct Rule {
    proto: String,
    from: i64,
    to: i64,
    cidrs: Vec<String>,
    groups: Vec<String>,
}
struct Vpc {
    cidr: String,
    main_rt: String,
    default_sg: String,
}
struct Subnet {
    vpc: String,
    cidr: String,
    az: String,
    public_ip: bool,
    next: u32,
}
struct Rt {
    vpc: String,
    routes: Vec<(String, String)>, // (destination CIDR, target)
    assoc: Vec<(String, String)>,  // (association id, subnet id)
}
struct Sg {
    name: String,
    desc: String,
    vpc: String,
    ingress: Vec<Rule>,
    egress: Vec<Rule>,
}
struct Inst {
    subnet: String,
    sgs: Vec<String>,
    ip: String,
    public: Option<String>,
    image: String,
    itype: String,
    launched: String,
    state: &'static str,
}

#[derive(Default)]
pub struct Net {
    vpcs: BTreeMap<String, Vpc>,
    subnets: BTreeMap<String, Subnet>,
    igws: BTreeMap<String, Option<String>>, // igw id -> attached VPC
    rts: BTreeMap<String, Rt>,
    sgs: BTreeMap<String, Sg>,
    insts: BTreeMap<String, Inst>,
    public_seq: u32,
}

fn id(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().simple().to_string()[..17])
}
fn not_found(kind: &str, v: &str) -> ApiErr {
    err(&format!("Invalid{kind}ID.NotFound"), format!("The {kind} ID '{v}' does not exist"))
}
fn p<'a>(q: &'a Q, k: &str) -> Result<&'a str, ApiErr> {
    q.get(k).map(String::as_str).ok_or_else(|| err("MissingParameter", format!("The request must contain the parameter {k}")))
}
// `Name.1`, `Name.2`, ... list parameters.
fn ids(q: &Q, name: &str) -> Vec<String> {
    (1..).map_while(|i| q.get(&format!("{name}.{i}")).cloned()).collect()
}
fn fields(q: &Q, prefix: &str, field: &str) -> Vec<String> {
    (1..).map_while(|i| q.get(&format!("{prefix}.{i}.{field}")).cloned()).collect()
}
// Values of `Filter.N.Value.M` for the filter named `name`.
fn filter(q: &Q, name: &str) -> Option<Vec<String>> {
    (1..).map_while(|i| q.get(&format!("Filter.{i}.Name")).map(|n| (i, n))).find(|(_, n)| *n == name).map(|(i, _)| ids(q, &format!("Filter.{i}.Value")))
}
fn want(sel: &[String], f: Option<&Vec<String>>, id: &str, vpc: &str) -> bool {
    (sel.is_empty() || sel.iter().any(|s| s == id)) && f.is_none_or(|v| v.iter().any(|x| x == vpc))
}

fn perms(q: &Q) -> Vec<Rule> {
    let proto = |p: &str| match p { "6" => "tcp", "17" => "udp", "1" => "icmp", x => x }.to_string();
    let num = |v: Option<&String>| v.and_then(|v| v.parse().ok()).unwrap_or(-1);
    if let Some(pr) = q.get("IpProtocol") {
        // Flat form: IpProtocol / FromPort / ToPort / CidrIp / SourceSecurityGroupName.
        return vec![Rule { proto: proto(pr), from: num(q.get("FromPort")), to: num(q.get("ToPort")), cidrs: q.get("CidrIp").into_iter().cloned().collect(), groups: vec![] }];
    }
    (1..)
        .map_while(|i| {
            let pre = format!("IpPermissions.{i}");
            let pr = q.get(&format!("{pre}.IpProtocol"))?;
            Some(Rule {
                proto: proto(pr),
                from: num(q.get(&format!("{pre}.FromPort"))),
                to: num(q.get(&format!("{pre}.ToPort"))),
                cidrs: fields(q, &format!("{pre}.IpRanges"), "CidrIp"),
                groups: fields(q, &format!("{pre}.Groups"), "GroupId").into_iter().chain(fields(q, &format!("{pre}.UserIdGroupPairs"), "GroupId")).collect(),
            })
        })
        .collect()
}

fn rule_json(r: &Rule) -> Value {
    json!({"ipProtocol": r.proto, "fromPort": r.from, "toPort": r.to,
           "ipRanges": r.cidrs.iter().map(|c| json!({"cidrIp": c})).collect::<Vec<_>>(),
           "groups": r.groups.iter().map(|g| json!({"groupId": g, "userId": ACCOUNT})).collect::<Vec<_>>()})
}
fn rule_text(r: &Rule) -> String {
    let ports = if r.proto == "-1" || r.from == -1 { "all".to_string() } else if r.from == r.to { r.from.to_string() } else { format!("{}-{}", r.from, r.to) };
    let src: Vec<&String> = r.cidrs.iter().chain(&r.groups).collect();
    format!("{}/{} {:?}", if r.proto == "-1" { "all" } else { &r.proto }, ports, src)
}
fn rule_allows(r: &Rule, proto: &str, port: i64, peer_ip: &str, peer_sgs: &[String]) -> bool {
    let p = r.proto == "-1" || r.proto == proto;
    let ports = r.proto == "-1" || r.from == -1 || (r.from <= port && port <= r.to);
    let src = r.cidrs.iter().any(|c| in_cidr(c, peer_ip)) || r.groups.iter().any(|g| peer_sgs.contains(g));
    p && ports && src
}
fn all_traffic(cidrs: Vec<String>, groups: Vec<String>) -> Rule {
    Rule { proto: "-1".into(), from: -1, to: -1, cidrs, groups }
}

impl Net {
    fn rt_of(&self, subnet: &str) -> Option<(&String, &Rt)> {
        let vpc = &self.subnets.get(subnet)?.vpc;
        self.rts.iter().find(|(_, r)| r.assoc.iter().any(|(_, s)| s == subnet)).or_else(|| self.rts.get_key_value(&self.vpcs.get(vpc)?.main_rt))
    }

    fn sg_json(&self, id: &str, g: &Sg) -> Value {
        json!({"groupId": id, "groupName": g.name, "groupDescription": g.desc, "vpcId": g.vpc, "ownerId": ACCOUNT,
               "ipPermissions": g.ingress.iter().map(rule_json).collect::<Vec<_>>(),
               "ipPermissionsEgress": g.egress.iter().map(rule_json).collect::<Vec<_>>()})
    }
    fn rt_json(&self, id: &str, r: &Rt) -> Value {
        let main = self.vpcs.get(&r.vpc).is_some_and(|v| v.main_rt == id);
        let mut assoc: Vec<Value> = r.assoc.iter().map(|(a, s)| json!({"routeTableAssociationId": a, "routeTableId": id, "subnetId": s, "main": false})).collect();
        if main {
            assoc.push(json!({"routeTableAssociationId": format!("rtbassoc-main{}", &id[4..]), "routeTableId": id, "main": true}));
        }
        let routes: Vec<Value> = r.routes.iter().map(|(c, t)| json!({"destinationCidrBlock": c, "gatewayId": t, "state": "active", "origin": if t == "local" { "CreateRouteTable" } else { "CreateRoute" }})).collect();
        json!({"routeTableId": id, "vpcId": r.vpc, "ownerId": ACCOUNT, "routeSet": routes, "associationSet": assoc})
    }
    fn inst_json(&self, id: &str, i: &Inst) -> Value {
        let code = match i.state { "running" => 16, "terminated" => 48, _ => 80 };
        let mut v = json!({"instanceId": id, "imageId": i.image, "instanceType": i.itype, "launchTime": i.launched,
            "instanceState": {"code": code, "name": i.state}, "privateIpAddress": i.ip, "subnetId": i.subnet,
            "vpcId": self.subnets.get(&i.subnet).map(|s| s.vpc.clone()),
            "placement": {"availabilityZone": self.subnets.get(&i.subnet).map(|s| s.az.clone())},
            "groupSet": i.sgs.iter().map(|g| json!({"groupId": g, "groupName": self.sgs.get(g).map(|s| s.name.clone())})).collect::<Vec<_>>()});
        if let Some(ip) = &i.public {
            v["ipAddress"] = ip.clone().into();
        }
        v
    }

    pub fn handle(&mut self, q: &Q) -> Result<Value, ApiErr> {
        let action = q.get("Action").map_or("", String::as_str);
        let vpc_filter = filter(q, "vpc-id");
        Ok(match action {
            "CreateVpc" => {
                let c = p(q, "CidrBlock")?;
                if cidr(c).is_none_or(|(_, m)| m.count_ones() < 16 || m.count_ones() > 28) {
                    return Err(err("InvalidVpc.Range", format!("The CIDR '{c}' is invalid (use /16 to /28).")));
                }
                let (vid, rt, sg) = (id("vpc"), id("rtb"), id("sg"));
                self.rts.insert(rt.clone(), Rt { vpc: vid.clone(), routes: vec![(c.into(), "local".into())], assoc: vec![] });
                // Default SG: members talk to each other, all egress allowed.
                self.sgs.insert(sg.clone(), Sg { name: "default".into(), desc: "default VPC security group".into(), vpc: vid.clone(),
                    ingress: vec![all_traffic(vec![], vec![sg.clone()])], egress: vec![all_traffic(vec!["0.0.0.0/0".into()], vec![])] });
                self.vpcs.insert(vid.clone(), Vpc { cidr: c.into(), main_rt: rt, default_sg: sg });
                json!({"vpc": {"vpcId": vid, "cidrBlock": c, "state": "available", "isDefault": false, "ownerId": ACCOUNT, "instanceTenancy": "default"}})
            }
            "DescribeVpcs" => {
                let sel = ids(q, "VpcId");
                if let Some(m) = sel.iter().find(|v| !self.vpcs.contains_key(*v)) {
                    return Err(not_found("Vpc", m));
                }
                let list: Vec<Value> = self.vpcs.iter().filter(|(i, _)| want(&sel, vpc_filter.as_ref(), i, i))
                    .map(|(i, v)| json!({"vpcId": i, "cidrBlock": v.cidr, "state": "available", "isDefault": false, "ownerId": ACCOUNT, "instanceTenancy": "default"})).collect();
                json!({"vpcSet": list})
            }
            "DeleteVpc" => {
                let v = p(q, "VpcId")?;
                let vpc = self.vpcs.get(v).ok_or_else(|| not_found("Vpc", v))?;
                let busy = self.subnets.values().any(|s| s.vpc == v) || self.igws.values().any(|g| g.as_deref() == Some(v))
                    || self.sgs.iter().any(|(i, g)| g.vpc == v && *i != vpc.default_sg) || self.rts.iter().any(|(i, r)| r.vpc == v && *i != vpc.main_rt);
                if busy {
                    return Err(err("DependencyViolation", format!("The vpc '{v}' has dependencies and cannot be deleted.")));
                }
                let vpc = self.vpcs.remove(v).unwrap();
                self.rts.remove(&vpc.main_rt);
                self.sgs.remove(&vpc.default_sg);
                json!({"return": true})
            }
            "CreateSubnet" => {
                let (v, c) = (p(q, "VpcId")?, p(q, "CidrBlock")?);
                let vpc = self.vpcs.get(v).ok_or_else(|| not_found("Vpc", v))?;
                if !covers(&vpc.cidr, c) || cidr(c).is_some_and(|(_, m)| m.count_ones() > 28) {
                    return Err(err("InvalidSubnet.Range", format!("The CIDR '{c}' is invalid for VPC {} ({}).", v, vpc.cidr)));
                }
                if let Some((sid, _)) = self.subnets.iter().find(|(_, s)| s.vpc == v && (covers(&s.cidr, c) || covers(c, &s.cidr))) {
                    return Err(err("InvalidSubnet.Conflict", format!("The CIDR '{c}' conflicts with another subnet ({sid}).")));
                }
                let az = q.get("AvailabilityZone").cloned().unwrap_or_else(|| format!("{}a", *REGION));
                let sid = id("subnet");
                let s = Subnet { vpc: v.into(), cidr: c.into(), az, public_ip: false, next: 4 };
                let out = json!({"subnet": self.subnet_json(&sid, &s)});
                self.subnets.insert(sid, s);
                out
            }
            "DescribeSubnets" => {
                let sel = ids(q, "SubnetId");
                if let Some(m) = sel.iter().find(|v| !self.subnets.contains_key(*v)) {
                    return Err(not_found("Subnet", m));
                }
                json!({"subnetSet": self.subnets.iter().filter(|(i, s)| want(&sel, vpc_filter.as_ref(), i, &s.vpc)).map(|(i, s)| self.subnet_json(i, s)).collect::<Vec<_>>()})
            }
            "ModifySubnetAttribute" => {
                let s = p(q, "SubnetId")?;
                let sub = self.subnets.get_mut(s).ok_or_else(|| not_found("Subnet", s))?;
                if let Some(v) = q.get("MapPublicIpOnLaunch.Value") {
                    sub.public_ip = v == "true";
                }
                json!({"return": true})
            }
            "DeleteSubnet" => {
                let s = p(q, "SubnetId")?;
                if self.insts.values().any(|i| i.subnet == s && i.state != "terminated") {
                    return Err(err("DependencyViolation", format!("The subnet '{s}' has dependencies and cannot be deleted.")));
                }
                self.subnets.remove(s).ok_or_else(|| not_found("Subnet", s))?;
                for r in self.rts.values_mut() {
                    r.assoc.retain(|(_, x)| x != s);
                }
                json!({"return": true})
            }
            "CreateInternetGateway" => {
                let g = id("igw");
                self.igws.insert(g.clone(), None);
                json!({"internetGateway": {"internetGatewayId": g, "ownerId": ACCOUNT, "attachmentSet": []}})
            }
            "AttachInternetGateway" | "DetachInternetGateway" => {
                let (g, v) = (p(q, "InternetGatewayId")?, p(q, "VpcId")?);
                if !self.vpcs.contains_key(v) {
                    return Err(not_found("Vpc", v));
                }
                let slot = self.igws.get_mut(g).ok_or_else(|| not_found("InternetGateway", g))?;
                if action.starts_with("Attach") {
                    if slot.is_some() {
                        return Err(err("Resource.AlreadyAssociated", format!("resource {g} is already attached")));
                    }
                    *slot = Some(v.into());
                } else {
                    *slot = None;
                }
                json!({"return": true})
            }
            "DescribeInternetGateways" => {
                let sel = ids(q, "InternetGatewayId");
                let list: Vec<Value> = self.igws.iter().filter(|(i, _)| sel.is_empty() || sel.contains(i))
                    .map(|(i, v)| json!({"internetGatewayId": i, "ownerId": ACCOUNT,
                        "attachmentSet": v.iter().map(|v| json!({"vpcId": v, "state": "available"})).collect::<Vec<_>>()})).collect();
                json!({"internetGatewaySet": list})
            }
            "DeleteInternetGateway" => {
                let g = p(q, "InternetGatewayId")?;
                if self.igws.get(g).ok_or_else(|| not_found("InternetGateway", g))?.is_some() {
                    return Err(err("DependencyViolation", format!("The internetGateway '{g}' has dependencies and cannot be deleted.")));
                }
                self.igws.remove(g);
                json!({"return": true})
            }
            "CreateRouteTable" => {
                let v = p(q, "VpcId")?;
                let vpc = self.vpcs.get(v).ok_or_else(|| not_found("Vpc", v))?;
                let r = Rt { vpc: v.into(), routes: vec![(vpc.cidr.clone(), "local".into())], assoc: vec![] };
                let rid = id("rtb");
                let out = json!({"routeTable": self.rt_json(&rid, &r)});
                self.rts.insert(rid, r);
                out
            }
            "DescribeRouteTables" => {
                let sel = ids(q, "RouteTableId");
                json!({"routeTableSet": self.rts.iter().filter(|(i, r)| want(&sel, vpc_filter.as_ref(), i, &r.vpc)).map(|(i, r)| self.rt_json(i, r)).collect::<Vec<_>>()})
            }
            "CreateRoute" => {
                let (r, c) = (p(q, "RouteTableId")?, p(q, "DestinationCidrBlock")?);
                let target = p(q, "GatewayId")?;
                if !self.igws.contains_key(target) {
                    return Err(not_found("InternetGateway", target));
                }
                let rt = self.rts.get_mut(r).ok_or_else(|| not_found("RouteTable", r))?;
                if rt.routes.iter().any(|(x, _)| x == c) {
                    return Err(err("RouteAlreadyExists", format!("The route identified by {c} already exists.")));
                }
                rt.routes.push((c.into(), target.into()));
                json!({"return": true})
            }
            "AssociateRouteTable" => {
                let (r, s) = (p(q, "RouteTableId")?, p(q, "SubnetId")?);
                if !self.subnets.contains_key(s) {
                    return Err(not_found("Subnet", s));
                }
                for rt in self.rts.values_mut() {
                    rt.assoc.retain(|(_, x)| x != s);
                }
                let a = id("rtbassoc");
                self.rts.get_mut(r).ok_or_else(|| not_found("RouteTable", r))?.assoc.push((a.clone(), s.into()));
                json!({"associationId": a})
            }
            "DeleteRouteTable" => {
                let r = p(q, "RouteTableId")?;
                let rt = self.rts.get(r).ok_or_else(|| not_found("RouteTable", r))?;
                if !rt.assoc.is_empty() || self.vpcs.values().any(|v| v.main_rt == r) {
                    return Err(err("DependencyViolation", format!("The routeTable '{r}' has dependencies and cannot be deleted.")));
                }
                self.rts.remove(r);
                json!({"return": true})
            }
            "CreateSecurityGroup" => {
                let (n, d) = (p(q, "GroupName")?, p(q, "GroupDescription")?);
                let v = p(q, "VpcId")?;
                if !self.vpcs.contains_key(v) {
                    return Err(not_found("Vpc", v));
                }
                if self.sgs.values().any(|g| g.vpc == v && g.name == n) {
                    return Err(err("InvalidGroup.Duplicate", format!("The security group '{n}' already exists for VPC '{v}'")));
                }
                let g = id("sg");
                self.sgs.insert(g.clone(), Sg { name: n.into(), desc: d.into(), vpc: v.into(), ingress: vec![], egress: vec![all_traffic(vec!["0.0.0.0/0".into()], vec![])] });
                json!({"groupId": g})
            }
            "AuthorizeSecurityGroupIngress" | "AuthorizeSecurityGroupEgress" | "RevokeSecurityGroupIngress" | "RevokeSecurityGroupEgress" => {
                let g = p(q, "GroupId")?;
                let rules = perms(q);
                if let Some(bad) = rules.iter().flat_map(|r| &r.groups).find(|x| !self.sgs.contains_key(*x)) {
                    return Err(not_found("Group", bad));
                }
                let sg = self.sgs.get_mut(g).ok_or_else(|| err("InvalidGroup.NotFound", format!("The security group '{g}' does not exist")))?;
                let list = if action.ends_with("Ingress") { &mut sg.ingress } else { &mut sg.egress };
                let same = |a: &Rule, b: &Rule| a.proto == b.proto && a.from == b.from && a.to == b.to;
                for r in rules {
                    if action.starts_with("Authorize") {
                        list.push(r);
                    } else {
                        // Remove the listed sources from rules with the same protocol/ports.
                        for x in list.iter_mut().filter(|x| same(x, &r)) {
                            x.cidrs.retain(|c| !r.cidrs.contains(c));
                            x.groups.retain(|c| !r.groups.contains(c));
                        }
                        list.retain(|x| !x.cidrs.is_empty() || !x.groups.is_empty());
                    }
                }
                json!({"return": true})
            }
            "DescribeSecurityGroups" => {
                let sel = ids(q, "GroupId");
                if let Some(m) = sel.iter().find(|v| !self.sgs.contains_key(*v)) {
                    return Err(err("InvalidGroup.NotFound", format!("The security group '{m}' does not exist")));
                }
                let names = filter(q, "group-name");
                let list: Vec<Value> = self.sgs.iter()
                    .filter(|(i, g)| want(&sel, vpc_filter.as_ref(), i, &g.vpc) && names.as_ref().is_none_or(|n| n.contains(&g.name)))
                    .map(|(i, g)| self.sg_json(i, g)).collect();
                json!({"securityGroupInfo": list})
            }
            "DeleteSecurityGroup" => {
                let g = p(q, "GroupId")?;
                if self.insts.values().any(|i| i.state != "terminated" && i.sgs.iter().any(|x| x == g)) || self.vpcs.values().any(|v| v.default_sg == g) {
                    return Err(err("DependencyViolation", format!("resource {g} has a dependent object")));
                }
                self.sgs.remove(g).ok_or_else(|| err("InvalidGroup.NotFound", format!("The security group '{g}' does not exist")))?;
                json!({"return": true})
            }
            "RunInstances" => {
                let s = p(q, "SubnetId")?.to_string();
                let n: usize = q.get("MinCount").and_then(|v| v.parse().ok()).unwrap_or(1);
                let sub = self.subnets.get(&s).ok_or_else(|| not_found("Subnet", &s))?;
                let mut sgs = ids(q, "SecurityGroupId");
                if sgs.is_empty() {
                    sgs.push(self.vpcs[&sub.vpc].default_sg.clone());
                }
                if let Some(bad) = sgs.iter().find(|g| self.sgs.get(*g).is_none_or(|x| x.vpc != sub.vpc)) {
                    return Err(err("InvalidGroup.NotFound", format!("The security group '{bad}' does not exist in VPC '{}'", sub.vpc)));
                }
                let (base, mask) = cidr(&sub.cidr).unwrap();
                let mut out = vec![];
                for _ in 0..n {
                    let sub = self.subnets.get_mut(&s).unwrap();
                    if sub.next >= !mask {
                        return Err(err("InsufficientFreeAddressesInSubnet", format!("No free addresses in {s}")));
                    }
                    let ip = Ipv4Addr::from(base + sub.next).to_string();
                    sub.next += 1;
                    let public = sub.public_ip.then(|| {
                        self.public_seq += 1;
                        Ipv4Addr::from(u32::from(Ipv4Addr::new(198, 51, 100, 0)) + self.public_seq).to_string()
                    });
                    let iid = id("i");
                    let inst = Inst { subnet: s.clone(), sgs: sgs.clone(), ip, public, image: q.get("ImageId").cloned().unwrap_or_default(),
                        itype: q.get("InstanceType").cloned().unwrap_or("t3.micro".into()), launched: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S.000Z").to_string(), state: "running" };
                    out.push(self.inst_json(&iid, &inst));
                    self.insts.insert(iid, inst);
                }
                json!({"reservationId": id("r"), "ownerId": ACCOUNT, "groupSet": [], "instancesSet": out})
            }
            "DescribeInstances" => {
                let sel = ids(q, "InstanceId");
                if let Some(m) = sel.iter().find(|v| !self.insts.contains_key(*v)) {
                    return Err(not_found("Instance", m));
                }
                let list: Vec<Value> = self.insts.iter().filter(|(i, _)| sel.is_empty() || sel.contains(i))
                    .map(|(i, x)| json!({"reservationId": format!("r-{}", &i[2..]), "ownerId": ACCOUNT, "groupSet": [], "instancesSet": [self.inst_json(i, x)]})).collect();
                json!({"reservationSet": list})
            }
            "TerminateInstances" | "StopInstances" | "StartInstances" => {
                let mut out = vec![];
                for i in ids(q, "InstanceId") {
                    let x = self.insts.get_mut(&i).ok_or_else(|| not_found("Instance", &i))?;
                    let prev = x.state;
                    x.state = match action { "TerminateInstances" => "terminated", "StopInstances" if prev != "terminated" => "stopped", "StartInstances" if prev != "terminated" => "running", _ => prev };
                    out.push(json!({"instanceId": i, "previousState": {"name": prev}, "currentState": {"name": x.state}}));
                }
                json!({"instancesSet": out})
            }
            "DescribeAvailabilityZones" => {
                {
                let zones: Vec<Value> = ["a", "b", "c"].iter().map(|z| json!({"zoneName": format!("{}{z}", *REGION), "state": "available", "regionName": *REGION})).collect();
                json!({ "availabilityZoneInfo": zones })
            }
            }
            _ => return Err(err("InvalidAction", format!("The action {action} is not valid for this web service."))),
        })
    }

    fn subnet_json(&self, id: &str, s: &Subnet) -> Value {
        let free = cidr(&s.cidr).map_or(0, |(_, m)| (!m).saturating_sub(4).saturating_sub(s.next - 4));
        json!({"subnetId": id, "vpcId": s.vpc, "cidrBlock": s.cidr, "availabilityZone": s.az, "state": "available",
               "mapPublicIpOnLaunch": s.public_ip, "availableIpAddressCount": free, "ownerId": ACCOUNT})
    }

    // Does any rule in these groups let `proto/port` traffic to/from `peer` through?
    fn sg_allows(&self, sgs: &[String], ingress: bool, proto: &str, port: i64, peer_ip: &str, peer_sgs: &[String]) -> (bool, String) {
        for g in sgs {
            let Some(sg) = self.sgs.get(g) else { continue };
            let rules = if ingress { &sg.ingress } else { &sg.egress };
            if let Some(r) = rules.iter().find(|r| rule_allows(r, proto, port, peer_ip, peer_sgs)) {
                return (true, format!("{g} ({}) allows {}", sg.name, rule_text(r)));
            }
        }
        let dir = if ingress { "from" } else { "to" };
        (false, format!("no rule in {sgs:?} allows {proto}/{port} {dir} {peer_ip}"))
    }

    fn igw_route(&self, subnet: &str) -> (bool, String) {
        let Some((rid, rt)) = self.rt_of(subnet) else { return (false, format!("{subnet} has no route table")) };
        let vpc = &self.subnets[subnet].vpc;
        match rt.routes.iter().find(|(c, t)| in_cidr(c, INTERNET_IP) && self.igws.get(t).is_some_and(|g| g.as_ref() == Some(vpc))) {
            Some((c, t)) => (true, format!("{rid} routes {c} to {t}")),
            None => (false, format!("{rid} has no route to an internet gateway attached to {vpc}")),
        }
    }

    // Reachability between "internet" and/or instance ids, step by step.
    pub fn reach(&self, from: &str, to: &str, proto: &str, port: i64) -> Value {
        let mut hops: Vec<Value> = vec![];
        let mut step = |name: &str, (ok, detail): (bool, String)| hops.push(json!({"step": name, "ok": ok, "detail": detail}));
        let inst = |x: &str| self.insts.get(x).filter(|i| i.state == "running");
        match (from, to) {
            ("internet", "internet") => step("endpoints", (false, "pick at least one instance".into())),
            ("internet", b) | (b, "internet") => {
                let inbound = from == "internet";
                let Some(i) = inst(b) else {
                    step("instance", (false, format!("{b} is not a running instance")));
                    return json!({"reachable": false, "hops": hops});
                };
                if inbound {
                    step("route", self.igw_route(&i.subnet));
                    step("public IP", (i.public.is_some(), i.public.as_ref().map_or(format!("{b} has no public IP (subnet MapPublicIpOnLaunch is off)"), |p| format!("{b} has public IP {p}"))));
                    step("security group (inbound)", self.sg_allows(&i.sgs, true, proto, port, INTERNET_IP, &[]));
                } else {
                    step("security group (outbound)", self.sg_allows(&i.sgs, false, proto, port, INTERNET_IP, &[]));
                    step("route", self.igw_route(&i.subnet));
                    step("public IP", (i.public.is_some(), i.public.as_ref().map_or(format!("{b} has no public IP"), |p| format!("{b} uses public IP {p}"))));
                }
            }
            (a, b) => {
                let (Some(x), Some(y)) = (inst(a), inst(b)) else {
                    step("instances", (false, format!("{a} and {b} must both be running instances")));
                    return json!({"reachable": false, "hops": hops});
                };
                let (vx, vy) = (&self.subnets[&x.subnet].vpc, &self.subnets[&y.subnet].vpc);
                if vx != vy {
                    step("route", (false, format!("{a} is in {vx} and {b} is in {vy}; VPC peering is not modeled")));
                } else {
                    step("route", (true, format!("local route {} inside {vx}", self.vpcs[vx].cidr)));
                    step("security group (outbound)", self.sg_allows(&x.sgs, false, proto, port, &y.ip, &y.sgs));
                    step("security group (inbound)", self.sg_allows(&y.sgs, true, proto, port, &x.ip, &x.sgs));
                }
            }
        }
        let ok = hops.iter().all(|h| h["ok"] == true);
        json!({"from": from, "to": to, "protocol": proto, "port": port, "reachable": ok, "hops": hops})
    }

    pub fn admin(&self) -> Value {
        self.vpcs
            .iter()
            .map(|(vid, v)| {
                json!({"name": vid, "cidr": v.cidr,
                    "count": self.insts.values().filter(|i| i.state != "terminated" && self.subnets.get(&i.subnet).is_some_and(|s| s.vpc == *vid)).count(),
                    "subnets": self.subnets.iter().filter(|(_, s)| s.vpc == *vid).map(|(i, s)| json!({"id": i, "cidr": s.cidr, "az": s.az, "public_ip": s.public_ip,
                        "route_table": self.rt_of(i).map(|(r, _)| r.clone()), "internet": self.igw_route(i).0})).collect::<Vec<_>>(),
                    "security_groups": self.sgs.iter().filter(|(_, g)| g.vpc == *vid).map(|(i, g)| json!({"id": i, "name": g.name,
                        "ingress": g.ingress.iter().map(rule_text).collect::<Vec<_>>(), "egress": g.egress.iter().map(rule_text).collect::<Vec<_>>()})).collect::<Vec<_>>(),
                    "instances": self.insts.iter().filter(|(_, i)| self.subnets.get(&i.subnet).is_some_and(|s| s.vpc == *vid))
                        .map(|(id, i)| json!({"id": id, "ip": i.ip, "public": i.public, "subnet": i.subnet, "sgs": i.sgs, "state": i.state})).collect::<Vec<_>>()})
            })
            .collect()
    }
}

// JSON → EC2-protocol XML body (arrays become <item> lists).
pub fn to_xml(v: &Value) -> String {
    match v {
        Value::Object(m) => m
            .iter()
            .map(|(k, v)| match v {
                Value::Array(a) => format!("<{k}>{}</{k}>", a.iter().map(|x| format!("<item>{}</item>", to_xml(x))).collect::<String>()),
                Value::Null => String::new(),
                _ => format!("<{k}>{}</{k}>", to_xml(v)),
            })
            .collect(),
        Value::String(s) => crate::s3::esc(s),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_math() {
        assert!(in_cidr("10.0.0.0/16", "10.0.255.1") && !in_cidr("10.0.0.0/16", "10.1.0.1"));
        assert!(in_cidr("0.0.0.0/0", INTERNET_IP));
        assert!(covers("10.0.0.0/16", "10.0.1.0/24") && !covers("10.0.1.0/24", "10.0.0.0/16") && !covers("10.0.0.0/16", "10.1.0.0/24"));
        let r = Rule { proto: "tcp".into(), from: 20, to: 25, cidrs: vec!["10.0.0.0/8".into()], groups: vec!["sg-a".into()] };
        assert!(rule_allows(&r, "tcp", 22, "10.1.2.3", &[]) && rule_allows(&r, "tcp", 22, "1.1.1.1", &["sg-a".into()]));
        assert!(!rule_allows(&r, "tcp", 80, "10.1.2.3", &[]) && !rule_allows(&r, "udp", 22, "10.1.2.3", &[]));
    }
}

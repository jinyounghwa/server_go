use crate::{err, ApiErr, App, ACCOUNT, REGION};
use serde_json::{json, Map, Value};
use std::cmp::Ordering::{self, Equal, Greater, Less};
use std::collections::BTreeMap;

pub type Item = Map<String, Value>;

// Sortable key part. ponytail: N keys are f64 (loses precision past ~15 digits); B keys sort by base64 text.
#[derive(Clone, Debug)]
pub enum K {
    N(f64),
    S(String),
}
impl Ord for K {
    fn cmp(&self, o: &Self) -> Ordering {
        match (self, o) {
            (K::N(a), K::N(b)) => a.total_cmp(b),
            (K::S(a), K::S(b)) => a.cmp(b),
            (K::N(_), _) => Less,
            _ => Greater,
        }
    }
}
impl PartialOrd for K {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl PartialEq for K {
    fn eq(&self, o: &Self) -> bool {
        self.cmp(o) == Equal
    }
}
impl Eq for K {}

fn kpart(av: &Value) -> Option<K> {
    if let Some(s) = av.get("S").and_then(Value::as_str) {
        return Some(K::S(s.into()));
    }
    if let Some(n) = av.get("N").and_then(Value::as_str) {
        return n.parse().ok().map(K::N);
    }
    av.get("B").and_then(Value::as_str).map(|b| K::S(b.into()))
}

type PK = (K, Option<K>);

#[derive(Clone)]
pub struct Table {
    desc: Value,
    hash: String,
    range: Option<String>,
    items: BTreeMap<PK, Item>,
}

#[derive(Default)]
pub struct Db {
    tables: BTreeMap<String, Table>,
}

fn verr(m: impl Into<String>) -> ApiErr {
    err("ValidationException", m)
}
fn s<'a>(r: &'a Value, k: &str) -> Result<&'a str, ApiErr> {
    r[k].as_str().ok_or_else(|| verr(format!("{k} is required")))
}
fn obj<'a>(r: &'a Value, k: &str) -> Result<&'a Item, ApiErr> {
    r[k].as_object().ok_or_else(|| verr(format!("{k} is required")))
}
fn not_found() -> ApiErr {
    err("ResourceNotFoundException", "Requested resource not found")
}

impl Table {
    fn key_of(&self, m: &Item) -> Result<PK, ApiErr> {
        let part = |n: &String| m.get(n).and_then(kpart).ok_or_else(|| verr(format!("Missing or invalid key attribute: {n}")));
        Ok((part(&self.hash)?, self.range.as_ref().map(part).transpose()?))
    }
    // A `Key` parameter must hold exactly the key attributes.
    fn exact_key(&self, m: &Item) -> Result<PK, ApiErr> {
        if m.len() != 1 + self.range.is_some() as usize {
            return Err(verr("The provided key element does not match the schema"));
        }
        self.key_of(m)
    }
    fn key_names(&self) -> impl Iterator<Item = &String> {
        std::iter::once(&self.hash).chain(self.range.as_ref())
    }
    fn index_keys(&self, ix: &str) -> Result<(String, Option<String>), ApiErr> {
        let found = ["GlobalSecondaryIndexes", "LocalSecondaryIndexes"]
            .iter()
            .flat_map(|k| self.desc[*k].as_array().into_iter().flatten())
            .find(|i| i["IndexName"] == ix)
            .ok_or_else(|| verr(format!("The table does not have the specified index: {ix}")))?;
        let (h, r) = schema(&found["KeySchema"])?;
        Ok((h, r))
    }
}

fn schema(ks: &Value) -> Result<(String, Option<String>), ApiErr> {
    let (mut h, mut r) = (None, None);
    for k in ks.as_array().into_iter().flatten() {
        let n = k["AttributeName"].as_str().map(String::from);
        match k["KeyType"].as_str() {
            Some("HASH") => h = n,
            Some("RANGE") => r = n,
            _ => return Err(verr("Invalid KeySchema")),
        }
    }
    Ok((h.ok_or_else(|| verr("KeySchema needs a HASH key"))?, r))
}

// ---------- expressions ----------

#[derive(Clone)]
enum Opd {
    Path(Vec<String>),
    Val(Value),
    Size(Vec<String>),
}
enum C {
    And(Box<C>, Box<C>),
    Or(Box<C>, Box<C>),
    Not(Box<C>),
    Cmp(Opd, String, Opd),
    Between(Opd, Opd, Opd),
    In(Opd, Vec<Opd>),
    F(String, Vec<Opd>),
}
enum T {
    O(Opd),
    F(String, Vec<T>),
}
enum Upd {
    Set(Vec<String>, T, Option<(char, T)>),
    Remove(Vec<String>),
    Add(Vec<String>, Value),
    Delete(Vec<String>, Value),
}

fn tokens(s: &str) -> Vec<String> {
    let cs: Vec<char> = s.chars().collect();
    let (mut out, mut i) = (vec![], 0);
    while i < cs.len() {
        let c = cs[i];
        if c.is_whitespace() {
            i += 1;
        } else if "(),+-".contains(c) {
            out.push(c.to_string());
            i += 1;
        } else if "=<>".contains(c) {
            let two = cs.get(i + 1).is_some_and(|n| *n == '=' || (c == '<' && *n == '>'));
            out.push(cs[i..i + 1 + two as usize].iter().collect());
            i += 1 + two as usize;
        } else {
            let st = i;
            while i < cs.len() && !cs[i].is_whitespace() && !"(),+-=<>".contains(cs[i]) {
                i += 1;
            }
            out.push(cs[st..i].iter().collect());
        }
    }
    out
}

const COND_FNS: &[&str] = &["attribute_exists", "attribute_not_exists", "attribute_type", "begins_with", "contains"];

// Document paths: a.b[0].c, with #names; a list index is kept as a "[n]" segment.
struct P<'a> {
    t: Vec<String>,
    i: usize,
    names: Option<&'a Item>,
    vals: Option<&'a Item>,
}
impl<'a> P<'a> {
    fn new(expr: &str, req: &'a Value) -> Self {
        P { t: tokens(expr), i: 0, names: req["ExpressionAttributeNames"].as_object(), vals: req["ExpressionAttributeValues"].as_object() }
    }
    fn peek(&self) -> Option<&str> {
        self.t.get(self.i).map(String::as_str)
    }
    fn kw(&self, k: &str) -> bool {
        self.peek().is_some_and(|t| t.eq_ignore_ascii_case(k))
    }
    fn next(&mut self) -> Result<String, ApiErr> {
        let t = self.t.get(self.i).cloned().ok_or_else(|| verr("Invalid expression: unexpected end"))?;
        self.i += 1;
        Ok(t)
    }
    fn expect(&mut self, s: &str) -> Result<(), ApiErr> {
        let t = self.next()?;
        if t.eq_ignore_ascii_case(s) { Ok(()) } else { Err(verr(format!("Invalid expression: expected {s}, got {t}"))) }
    }
    fn done(&self) -> Result<(), ApiErr> {
        match self.peek() {
            None => Ok(()),
            Some(t) => Err(verr(format!("Invalid expression: unexpected token {t}"))),
        }
    }
    fn call_next(&self) -> bool {
        self.t.get(self.i + 1).is_some_and(|s| s == "(")
    }
    fn path(&self, t: &str) -> Result<Vec<String>, ApiErr> {
        let mut out = vec![];
        for part in t.split('.') {
            let (name, idx) = part.split_at(part.find('[').unwrap_or(part.len()));
            if name.is_empty() {
                return Err(verr(format!("Invalid document path: {t}")));
            }
            out.push(if name.starts_with('#') {
                self.names.and_then(|m| m.get(name)).and_then(Value::as_str).map(String::from).ok_or_else(|| verr(format!("Expression attribute name {name} is not defined")))?
            } else {
                name.to_string()
            });
            let mut rest = idx;
            while !rest.is_empty() {
                let close = rest.find(']').filter(|c| rest.starts_with('[') && rest[1..*c].parse::<usize>().is_ok()).ok_or_else(|| verr(format!("Invalid document path: {t}")))?;
                out.push(rest[..=close].to_string());
                rest = &rest[close + 1..];
            }
        }
        Ok(out)
    }
    fn opd(&mut self) -> Result<Opd, ApiErr> {
        if self.kw("size") && self.call_next() {
            self.i += 2;
            let t = self.next()?;
            let p = self.path(&t)?;
            self.expect(")")?;
            return Ok(Opd::Size(p));
        }
        let t = self.next()?;
        if t.starts_with(':') {
            return self.vals.and_then(|m| m.get(&t)).cloned().map(Opd::Val).ok_or_else(|| verr(format!("Expression attribute value {t} is not defined")));
        }
        Ok(Opd::Path(self.path(&t)?))
    }
    fn opds(&mut self) -> Result<Vec<Opd>, ApiErr> {
        let mut v = vec![self.opd()?];
        while self.peek() == Some(",") {
            self.i += 1;
            v.push(self.opd()?);
        }
        self.expect(")")?;
        Ok(v)
    }
    fn or(&mut self) -> Result<C, ApiErr> {
        let mut l = self.and()?;
        while self.kw("OR") {
            self.i += 1;
            l = C::Or(Box::new(l), Box::new(self.and()?));
        }
        Ok(l)
    }
    fn and(&mut self) -> Result<C, ApiErr> {
        let mut l = self.not()?;
        while self.kw("AND") {
            self.i += 1;
            l = C::And(Box::new(l), Box::new(self.not()?));
        }
        Ok(l)
    }
    fn not(&mut self) -> Result<C, ApiErr> {
        if self.kw("NOT") {
            self.i += 1;
            return Ok(C::Not(Box::new(self.not()?)));
        }
        if self.peek() == Some("(") {
            self.i += 1;
            let c = self.or()?;
            self.expect(")")?;
            return Ok(c);
        }
        if self.call_next() && !self.kw("size") {
            let f = self.next()?.to_lowercase();
            if !COND_FNS.contains(&f.as_str()) {
                return Err(verr(format!("Invalid function name: {f}")));
            }
            self.i += 1;
            return Ok(C::F(f, self.opds()?));
        }
        let a = self.opd()?;
        let op = self.next()?;
        match op.to_uppercase().as_str() {
            "BETWEEN" => {
                let lo = self.opd()?;
                self.expect("AND")?;
                Ok(C::Between(a, lo, self.opd()?))
            }
            "IN" => {
                self.expect("(")?;
                Ok(C::In(a, self.opds()?))
            }
            "=" | "<>" | "<" | "<=" | ">" | ">=" => Ok(C::Cmp(a, op, self.opd()?)),
            _ => Err(verr(format!("Invalid expression: unexpected token {op}"))),
        }
    }
    fn term(&mut self) -> Result<T, ApiErr> {
        if self.call_next() {
            let f = self.next()?.to_lowercase();
            if f != "if_not_exists" && f != "list_append" {
                return Err(verr(format!("Invalid function name: {f}")));
            }
            self.i += 1;
            let mut a = vec![self.term()?];
            while self.peek() == Some(",") {
                self.i += 1;
                a.push(self.term()?);
            }
            self.expect(")")?;
            return Ok(T::F(f, a));
        }
        Ok(T::O(self.opd()?))
    }
}

fn parse_cond(expr: &str, req: &Value) -> Result<C, ApiErr> {
    let mut p = P::new(expr, req);
    let c = p.or()?;
    p.done()?;
    Ok(c)
}

fn parse_update(expr: &str, req: &Value) -> Result<Vec<Upd>, ApiErr> {
    let mut p = P::new(expr, req);
    let (mut out, mut mode) = (vec![], String::new());
    while let Some(t) = p.peek().map(str::to_uppercase) {
        if ["SET", "REMOVE", "ADD", "DELETE"].contains(&t.as_str()) {
            mode = t;
            p.i += 1;
            continue;
        }
        if t == "," {
            p.i += 1;
            continue;
        }
        let tok = p.next()?;
        let path = p.path(&tok)?;
        match mode.as_str() {
            "SET" => {
                p.expect("=")?;
                let a = p.term()?;
                let rest = match p.peek() {
                    Some(o @ ("+" | "-")) => {
                        let o = o.chars().next().unwrap();
                        p.i += 1;
                        Some((o, p.term()?))
                    }
                    _ => None,
                };
                out.push(Upd::Set(path, a, rest));
            }
            "REMOVE" => out.push(Upd::Remove(path)),
            "ADD" | "DELETE" => {
                let Opd::Val(v) = p.opd()? else { return Err(verr("ADD and DELETE need a value operand")) };
                out.push(if mode == "ADD" { Upd::Add(path, v) } else { Upd::Delete(path, v) });
            }
            _ => return Err(verr("Invalid UpdateExpression: expected SET, REMOVE, ADD or DELETE")),
        }
    }
    Ok(out)
}

fn index(k: &str) -> Option<usize> {
    k.strip_prefix('[')?.strip_suffix(']')?.parse().ok()
}

fn get<'a>(item: &'a Item, p: &[String]) -> Option<&'a Value> {
    let mut v = item.get(&p[0])?;
    for k in &p[1..] {
        v = match index(k) {
            Some(i) => v.get("L")?.get(i)?,
            None => v.get("M")?.get(k)?,
        };
    }
    Some(v)
}

fn child_mut<'a>(v: &'a mut Value, k: &str) -> Option<&'a mut Value> {
    match index(k) {
        Some(i) => v.get_mut("L")?.as_array_mut()?.get_mut(i),
        None => v.get_mut("M")?.as_object_mut()?.get_mut(k),
    }
}

// The container holding the last path segment (None for a top-level attribute or a missing parent).
fn parent_mut<'a>(item: &'a mut Item, p: &[String]) -> Option<&'a mut Value> {
    let mut v = item.get_mut(&p[0])?;
    for k in &p[1..p.len() - 1] {
        v = child_mut(v, k)?;
    }
    Some(v)
}

fn resolve(o: &Opd, it: &Item) -> Option<Value> {
    match o {
        Opd::Val(v) => Some(v.clone()),
        Opd::Path(p) => get(it, p).cloned(),
        Opd::Size(p) => {
            let (t, x) = get(it, p)?.as_object()?.iter().next()?;
            let n = match t.as_str() {
                "S" | "B" => x.as_str()?.len(),
                "L" | "SS" | "NS" | "BS" => x.as_array()?.len(),
                "M" => x.as_object()?.len(),
                _ => return None,
            };
            Some(json!({"N": n.to_string()}))
        }
    }
}

fn num(av: &Value) -> Option<f64> {
    av.get("N")?.as_str()?.parse().ok()
}
fn fmt_num(f: f64) -> String {
    if f.fract() == 0.0 && f.abs() < 1e15 { format!("{}", f as i64) } else { f.to_string() }
}

fn cmp_av(a: &Value, b: &Value) -> Option<Ordering> {
    if let (Some(x), Some(y)) = (num(a), num(b)) {
        return x.partial_cmp(&y);
    }
    for t in ["S", "B"] {
        if let (Some(x), Some(y)) = (a.get(t).and_then(Value::as_str), b.get(t).and_then(Value::as_str)) {
            return Some(x.cmp(y));
        }
    }
    (a == b).then_some(Equal)
}

fn contains(v: &Value, x: &Value) -> bool {
    if let (Some(a), Some(b)) = (v.get("S").and_then(Value::as_str), x.get("S").and_then(Value::as_str)) {
        return a.contains(b);
    }
    for (set, el) in [("SS", "S"), ("NS", "N"), ("BS", "B")] {
        if let (Some(a), Some(e)) = (v.get(set).and_then(Value::as_array), x.get(el)) {
            return a.contains(e);
        }
    }
    v.get("L").and_then(Value::as_array).is_some_and(|l| l.iter().any(|e| cmp_av(e, x) == Some(Equal)))
}

fn eval(c: &C, it: &Item) -> bool {
    match c {
        C::And(a, b) => eval(a, it) && eval(b, it),
        C::Or(a, b) => eval(a, it) || eval(b, it),
        C::Not(a) => !eval(a, it),
        C::Cmp(a, op, b) => {
            let (Some(x), Some(y)) = (resolve(a, it), resolve(b, it)) else { return false };
            let o = cmp_av(&x, &y);
            match op.as_str() {
                "=" => o == Some(Equal),
                "<>" => o != Some(Equal),
                "<" => o == Some(Less),
                "<=" => matches!(o, Some(Less | Equal)),
                ">" => o == Some(Greater),
                _ => matches!(o, Some(Greater | Equal)),
            }
        }
        C::Between(a, l, h) => match (resolve(a, it), resolve(l, it), resolve(h, it)) {
            (Some(x), Some(lo), Some(hi)) => matches!(cmp_av(&x, &lo), Some(Greater | Equal)) && matches!(cmp_av(&x, &hi), Some(Less | Equal)),
            _ => false,
        },
        C::In(a, list) => resolve(a, it).is_some_and(|x| list.iter().any(|o| resolve(o, it).is_some_and(|y| cmp_av(&x, &y) == Some(Equal)))),
        C::F(f, args) => {
            let r = |i: usize| args.get(i).and_then(|o| resolve(o, it));
            match (f.as_str(), r(0), r(1)) {
                ("attribute_exists", v, _) => v.is_some(),
                ("attribute_not_exists", v, _) => v.is_none(),
                ("attribute_type", Some(v), Some(t)) => t["S"].as_str().is_some_and(|t| v.get(t).is_some()),
                ("begins_with", Some(v), Some(p)) => ["S", "B"].iter().any(|t| {
                    matches!((v.get(*t).and_then(Value::as_str), p.get(*t).and_then(Value::as_str)), (Some(a), Some(b)) if a.starts_with(b))
                }),
                ("contains", Some(v), Some(x)) => contains(&v, &x),
                _ => false,
            }
        }
    }
}

fn eval_t(t: &T, it: &Item) -> Option<Value> {
    match t {
        T::O(o) => resolve(o, it),
        T::F(f, a) if f == "if_not_exists" => eval_t(a.first()?, it).or_else(|| eval_t(a.get(1)?, it)),
        T::F(_, a) => {
            let (x, y) = (eval_t(a.first()?, it)?, eval_t(a.get(1)?, it)?);
            let mut l = x["L"].as_array()?.clone();
            l.extend(y["L"].as_array()?.iter().cloned());
            Some(json!({ "L": l }))
        }
    }
}

// SET a.b[i] = v: past the end of a list appends, as in DynamoDB.
fn set_path(item: &mut Item, p: &[String], v: Value) -> Result<(), ApiErr> {
    if p.len() == 1 {
        item.insert(p[0].clone(), v);
        return Ok(());
    }
    let bad = || verr("The document path provided in the update expression is invalid for update");
    let parent = parent_mut(item, p).ok_or_else(bad)?;
    let last = &p[p.len() - 1];
    match index(last) {
        Some(i) => {
            let l = parent.get_mut("L").and_then(Value::as_array_mut).ok_or_else(bad)?;
            if i < l.len() { l[i] = v } else { l.push(v) }
        }
        None => {
            parent.get_mut("M").and_then(Value::as_object_mut).ok_or_else(bad)?.insert(last.clone(), v);
        }
    }
    Ok(())
}

fn remove_path(item: &mut Item, p: &[String]) {
    if p.len() == 1 {
        item.remove(&p[0]);
        return;
    }
    let Some(parent) = parent_mut(item, p) else { return };
    let last = &p[p.len() - 1];
    match index(last) {
        Some(i) => {
            if let Some(l) = parent.get_mut("L").and_then(Value::as_array_mut).filter(|l| i < l.len()) {
                l.remove(i);
            }
        }
        None => {
            if let Some(m) = parent.get_mut("M").and_then(Value::as_object_mut) {
                m.remove(last);
            }
        }
    }
}

// Set union (add) or difference (!add) for SS/NS/BS.
fn set_op(cur: &Value, v: &Value, add: bool) -> Option<Value> {
    let t = ["SS", "NS", "BS"].into_iter().find(|t| v.get(*t).is_some())?;
    let mut a = cur.get(t)?.as_array()?.clone();
    for e in v[t].as_array()? {
        if add && !a.contains(e) {
            a.push(e.clone());
        } else if !add {
            a.retain(|x| x != e);
        }
    }
    Some(json!({ t: a }))
}

fn apply(ups: &[Upd], old: &Item, new: &mut Item) -> Result<(), ApiErr> {
    let bad = || verr("An operand in the update expression has an incorrect data type or refers to a missing attribute");
    let mut removes = vec![];
    for u in ups {
        match u {
            Upd::Set(p, a, rest) => {
                let x = eval_t(a, old).ok_or_else(bad)?;
                let v = match rest {
                    None => x,
                    Some((o, b)) => {
                        let (x, y) = (num(&x).ok_or_else(bad)?, eval_t(b, old).as_ref().and_then(num).ok_or_else(bad)?);
                        json!({"N": fmt_num(if *o == '+' { x + y } else { x - y })})
                    }
                };
                set_path(new, p, v)?;
            }
            Upd::Remove(p) => removes.push(p),
            Upd::Add(p, v) => {
                let nv = match get(old, p) {
                    None => v.clone(),
                    Some(c) => match (num(c), num(v)) {
                        (Some(x), Some(y)) => json!({"N": fmt_num(x + y)}),
                        _ => set_op(c, v, true).ok_or_else(bad)?,
                    },
                };
                set_path(new, p, nv)?;
            }
            Upd::Delete(p, v) => {
                if let Some(c) = get(old, p) {
                    let nv = set_op(c, v, false).ok_or_else(bad)?;
                    if nv.as_object().and_then(|m| m.values().next()).and_then(Value::as_array).is_some_and(|a| a.is_empty()) {
                        remove_path(new, p);
                    } else {
                        set_path(new, p, nv)?;
                    }
                }
            }
        }
    }
    // REMOVE a[0], a[2] names indexes of the original list: drop higher indexes first.
    removes.sort_by_key(|p| std::cmp::Reverse(p.last().and_then(|k| index(k))));
    for p in removes {
        remove_path(new, p);
    }
    Ok(())
}

// ---------- item operations (shared by single calls and transactions) ----------

fn check(t: &Table, key: &PK, r: &Value) -> Result<(), ApiErr> {
    let Some(expr) = r["ConditionExpression"].as_str() else { return Ok(()) };
    let empty = Item::new();
    if !eval(&parse_cond(expr, r)?, t.items.get(key).unwrap_or(&empty)) {
        return Err(err("ConditionalCheckFailedException", "The conditional request failed"));
    }
    Ok(())
}

// DynamoDB's 400 KB item limit. ponytail: measured as the item's JSON length, which slightly overcounts
// type tags and quotes compared with DynamoDB's name+value bytes.
fn fits(item: &Item) -> Result<(), ApiErr> {
    if serde_json::to_string(item).map_or(0, |s| s.len()) > 400 * 1024 {
        return Err(verr("Item size has exceeded the maximum allowed size"));
    }
    Ok(())
}

fn put(t: &mut Table, r: &Value) -> Result<Option<Item>, ApiErr> {
    let item = obj(r, "Item")?.clone();
    fits(&item)?;
    let k = t.key_of(&item)?;
    check(t, &k, r)?;
    Ok(t.items.insert(k, item))
}

fn delete(t: &mut Table, r: &Value) -> Result<Option<Item>, ApiErr> {
    let k = t.exact_key(obj(r, "Key")?)?;
    check(t, &k, r)?;
    Ok(t.items.remove(&k))
}

fn update(t: &mut Table, r: &Value) -> Result<(Option<Item>, Item), ApiErr> {
    let key = obj(r, "Key")?;
    let k = t.exact_key(key)?;
    check(t, &k, r)?;
    let old = t.items.get(&k).cloned();
    let mut new = old.clone().unwrap_or_else(|| key.clone());
    if let Some(e) = r["UpdateExpression"].as_str() {
        apply(&parse_update(e, r)?, old.as_ref().unwrap_or(key), &mut new)?;
    }
    if t.key_of(&new)? != k {
        return Err(verr("Cannot update attribute that is part of the key"));
    }
    fits(&new)?;
    t.items.insert(k, new.clone());
    Ok((old, new))
}

// Puts a projected value back under its path: maps keep their keys, list elements are compacted in order.
// ponytail: two projected paths under the same list element (a[0].x, a[0].y) become two elements.
fn graft(out: &mut Item, p: &[String], v: Value) {
    let shell = |k: &String| if index(k).is_some() { json!({"L": []}) } else { json!({"M": {}}) };
    if p.len() == 1 {
        out.insert(p[0].clone(), v);
        return;
    }
    let mut cur = out.entry(p[0].clone()).or_insert_with(|| shell(&p[1]));
    for (n, k) in p[1..].iter().enumerate() {
        let next = p.get(n + 2);
        let val = next.map_or_else(|| v.clone(), shell);
        cur = if index(k).is_some() {
            let Some(l) = cur.get_mut("L").and_then(Value::as_array_mut) else { return };
            l.push(val);
            l.last_mut().unwrap()
        } else {
            let Some(m) = cur.get_mut("M").and_then(Value::as_object_mut) else { return };
            m.entry(k.clone()).or_insert(val)
        };
    }
}

fn project(item: &Item, r: &Value) -> Result<Item, ApiErr> {
    let Some(pe) = r["ProjectionExpression"].as_str() else { return Ok(item.clone()) };
    let p = P::new("", r);
    let mut out = Item::new();
    for part in pe.split(',') {
        let path = p.path(part.trim())?;
        if let Some(v) = get(item, &path) {
            graft(&mut out, &path, v.clone());
        }
    }
    Ok(out)
}

fn ret(rv: &Value, old: Option<Item>, new: Option<Item>) -> Value {
    match (rv.as_str(), old, new) {
        (Some("ALL_OLD"), Some(o), _) => json!({ "Attributes": o }),
        (Some("ALL_NEW" | "UPDATED_NEW"), _, Some(n)) => json!({ "Attributes": n }),
        _ => json!({}),
    }
}

fn query(t: &Table, r: &Value, scan: bool) -> Result<Value, ApiErr> {
    let (h, rk) = match r["IndexName"].as_str() {
        Some(ix) => t.index_keys(ix)?,
        None => (t.hash.clone(), t.range.clone()),
    };
    let sk = |i: &Item| (i.get(&h).and_then(kpart), rk.as_ref().and_then(|n| i.get(n)).and_then(kpart), t.key_of(i).ok());
    let mut items: Vec<&Item> = t.items.values().filter(|i| i.contains_key(&h) && rk.as_ref().is_none_or(|n| i.contains_key(n))).collect();
    items.sort_by_cached_key(|i| sk(i));
    // ponytail: Query scans the whole table/index linearly; fine for local data sizes.
    if !scan {
        let kc = parse_cond(s(r, "KeyConditionExpression")?, r)?;
        items.retain(|i| eval(&kc, i));
    }
    let fwd = r["ScanIndexForward"].as_bool().unwrap_or(true);
    if !fwd {
        items.reverse();
    }
    if let Some(esk) = r["ExclusiveStartKey"].as_object() {
        let e = sk(esk);
        items.retain(|i| if fwd { sk(i) > e } else { sk(i) < e });
    }
    let mut lek = None;
    if let Some(l) = r["Limit"].as_u64().map(|n| n as usize) {
        if items.len() > l && l > 0 {
            items.truncate(l);
            let last = items[l - 1];
            let names = t.key_names().chain(std::iter::once(&h)).chain(rk.as_ref());
            lek = Some(names.filter_map(|n| Some((n.clone(), last.get(n)?.clone()))).collect::<Item>());
        }
    }
    let scanned = items.len();
    if let Some(fe) = r["FilterExpression"].as_str() {
        let f = parse_cond(fe, r)?;
        items.retain(|i| eval(&f, i));
    }
    let mut out = json!({"Count": items.len(), "ScannedCount": scanned});
    if r["Select"] != "COUNT" {
        out["Items"] = items.into_iter().map(|i| project(i, r).map(Value::Object)).collect::<Result<Vec<_>, _>>()?.into();
    }
    if let Some(k) = lek {
        out["LastEvaluatedKey"] = k.into();
    }
    Ok(out)
}

fn tbl<'a>(db: &'a mut Db, r: &Value) -> Result<&'a mut Table, ApiErr> {
    db.tables.get_mut(s(r, "TableName")?).ok_or_else(not_found)
}

fn describe(t: &Table) -> Value {
    let mut d = t.desc.clone();
    d["ItemCount"] = t.items.len().into();
    d["TableSizeBytes"] = t.items.values().map(|i| Value::Object(i.clone()).to_string().len()).sum::<usize>().into();
    d
}

pub fn handle(app: &App, op: &str, body: &[u8]) -> Result<Value, ApiErr> {
    let r: Value = serde_json::from_slice(body).map_err(|e| err("SerializationException", e.to_string()))?;
    let mut db = app.ddb.lock().unwrap();
    let db = &mut *db;
    match op {
        "CreateTable" => {
            let name = s(&r, "TableName")?;
            if db.tables.contains_key(name) {
                return Err(err("ResourceInUseException", format!("Table already exists: {name}")));
            }
            let (hash, range) = schema(&r["KeySchema"])?;
            let now = chrono::Utc::now().timestamp_millis() as f64 / 1000.0;
            let arn = format!("arn:aws:dynamodb:{}:{ACCOUNT}:table/{name}", *REGION);
            let mut desc = json!({
                "TableName": name, "TableArn": arn, "TableId": uuid::Uuid::new_v4().to_string(),
                "KeySchema": r["KeySchema"], "AttributeDefinitions": r["AttributeDefinitions"],
                "TableStatus": "ACTIVE", "CreationDateTime": now,
                "BillingModeSummary": {"BillingMode": r["BillingMode"].as_str().unwrap_or("PROVISIONED")},
                "ProvisionedThroughput": r.get("ProvisionedThroughput").cloned().unwrap_or(json!({"ReadCapacityUnits": 0, "WriteCapacityUnits": 0})),
            });
            for k in ["GlobalSecondaryIndexes", "LocalSecondaryIndexes"] {
                if let Some(ixs) = r[k].as_array() {
                    desc[k] = ixs
                        .iter()
                        .map(|i| {
                            let mut i = i.clone();
                            i["IndexArn"] = format!("{arn}/index/{}", i["IndexName"].as_str().unwrap_or("")).into();
                            i["IndexStatus"] = "ACTIVE".into();
                            i
                        })
                        .collect();
                }
            }
            let t = Table { desc, hash, range, items: BTreeMap::new() };
            let out = json!({"TableDescription": describe(&t)});
            db.tables.insert(name.into(), t);
            Ok(out)
        }
        "DescribeTable" => Ok(json!({"Table": describe(tbl(db, &r)?)})),
        "DeleteTable" => {
            let t = db.tables.remove(s(&r, "TableName")?).ok_or_else(not_found)?;
            let mut d = describe(&t);
            d["TableStatus"] = "DELETING".into();
            Ok(json!({"TableDescription": d}))
        }
        "ListTables" => {
            let start = r["ExclusiveStartTableName"].as_str().unwrap_or("");
            let names: Vec<&String> = db.tables.keys().filter(|n| n.as_str() > start).collect();
            Ok(json!({"TableNames": names}))
        }
        "PutItem" => {
            let old = put(tbl(db, &r)?, &r)?;
            Ok(ret(&r["ReturnValues"], old, None))
        }
        "GetItem" => {
            let t = tbl(db, &r)?;
            let k = t.exact_key(obj(&r, "Key")?)?;
            Ok(match t.items.get(&k) {
                Some(i) => json!({"Item": project(i, &r)?}),
                None => json!({}),
            })
        }
        "DeleteItem" => {
            let old = delete(tbl(db, &r)?, &r)?;
            Ok(ret(&r["ReturnValues"], old, None))
        }
        "UpdateItem" => {
            let (old, new) = update(tbl(db, &r)?, &r)?;
            Ok(ret(&r["ReturnValues"], old, Some(new)))
        }
        "Query" => query(tbl(db, &r)?, &r, false),
        "Scan" => query(tbl(db, &r)?, &r, true),
        "BatchWriteItem" => {
            for (name, reqs) in obj(&r, "RequestItems")? {
                let t = db.tables.get_mut(name).ok_or_else(not_found)?;
                for w in reqs.as_array().into_iter().flatten() {
                    if let Some(p) = w.get("PutRequest") {
                        put(t, p)?;
                    } else if let Some(d) = w.get("DeleteRequest") {
                        delete(t, d)?;
                    }
                }
            }
            Ok(json!({"UnprocessedItems": {}}))
        }
        "BatchGetItem" => {
            let mut resp = Map::new();
            for (name, spec) in obj(&r, "RequestItems")? {
                let t = db.tables.get(name).ok_or_else(not_found)?;
                let mut found = vec![];
                for k in spec["Keys"].as_array().into_iter().flatten().filter_map(Value::as_object) {
                    if let Some(i) = t.items.get(&t.exact_key(k)?) {
                        found.push(Value::Object(project(i, spec)?));
                    }
                }
                resp.insert(name.clone(), found.into());
            }
            Ok(json!({"Responses": resp, "UnprocessedKeys": {}}))
        }
        "TransactWriteItems" => {
            let ops = r["TransactItems"].as_array().ok_or_else(|| verr("TransactItems is required"))?;
            // All-or-nothing: snapshot touched tables, restore them if anything fails.
            let mut backup: BTreeMap<String, Table> = BTreeMap::new();
            for op in ops {
                let n = op.as_object().and_then(|m| m.values().next()).map(|v| s(v, "TableName")).transpose()?.unwrap_or("");
                backup.insert(n.into(), db.tables.get(n).cloned().ok_or_else(not_found)?);
            }
            let mut reasons = vec![json!({"Code": "None"}); ops.len()];
            for (i, op) in ops.iter().enumerate() {
                let (kind, inner) = op.as_object().and_then(|m| m.iter().next()).ok_or_else(|| verr("Empty transact item"))?;
                let t = tbl(db, inner)?;
                let res = match kind.as_str() {
                    "Put" => put(t, inner).map(drop),
                    "Delete" => delete(t, inner).map(drop),
                    "Update" => update(t, inner).map(drop),
                    "ConditionCheck" => t.exact_key(obj(inner, "Key")?).and_then(|k| check(t, &k, inner)),
                    _ => Err(verr(format!("Unknown transact item {kind}"))),
                };
                if let Err(e) = res {
                    db.tables.extend(backup);
                    if e.code != "ConditionalCheckFailedException" {
                        return Err(e);
                    }
                    reasons[i] = json!({"Code": "ConditionalCheckFailed", "Message": e.msg});
                    let codes: Vec<&str> = reasons.iter().map(|x| x["Code"].as_str().unwrap()).collect();
                    let mut e = err("TransactionCanceledException", format!("Transaction cancelled, please refer cancellation reasons for specific reasons [{}]", codes.join(", ")));
                    e.extra = Some(json!({ "CancellationReasons": reasons }));
                    return Err(e);
                }
            }
            Ok(json!({}))
        }
        "TransactGetItems" => {
            let mut out = vec![];
            for g in r["TransactItems"].as_array().into_iter().flatten() {
                let g = &g["Get"];
                let t = db.tables.get(s(g, "TableName")?).ok_or_else(not_found)?;
                out.push(match t.items.get(&t.exact_key(obj(g, "Key")?)?) {
                    Some(i) => json!({"Item": project(i, g)?}),
                    None => json!({}),
                });
            }
            Ok(json!({ "Responses": out }))
        }
        _ => Err(err("UnknownOperationException", format!("{op} is not supported yet"))),
    }
}

impl Db {
    // GUI view: every table with its schema and up to 100 items.
    pub fn admin(&self) -> Value {
        self.tables
            .iter()
            .map(|(n, t)| json!({"name": n, "keys": t.key_names().collect::<Vec<_>>(), "count": t.items.len(),
                                 "items": t.items.values().take(100).collect::<Vec<_>>()}))
            .collect()
    }
}

impl Db {
    // CloudFormation properties for every table (infrastructure-code draft).
    pub fn export(&self) -> Vec<(String, Value)> {
        self.tables.iter().map(|(n, t)| {
            let d = &t.desc;
            let mode = d["BillingModeSummary"]["BillingMode"].as_str().unwrap_or("PAY_PER_REQUEST");
            let mut p = json!({"TableName": n, "KeySchema": d["KeySchema"], "AttributeDefinitions": d["AttributeDefinitions"], "BillingMode": mode});
            if mode == "PROVISIONED" {
                p["ProvisionedThroughput"] = json!({"ReadCapacityUnits": d["ProvisionedThroughput"]["ReadCapacityUnits"], "WriteCapacityUnits": d["ProvisionedThroughput"]["WriteCapacityUnits"]});
            }
            for k in ["GlobalSecondaryIndexes", "LocalSecondaryIndexes"] {
                if let Some(ix) = d[k].as_array() {
                    p[k] = ix.iter().map(|i| { let mut i = i.clone(); if let Some(o) = i.as_object_mut() { o.remove("IndexStatus"); o.remove("IndexArn"); } i }).collect();
                }
            }
            (n.clone(), p)
        }).collect()
    }

    pub fn snap_save(&self) -> Value {
        let tables: Vec<Value> = self.tables.iter().map(|(n, t)| json!({
            "name": n, "desc": t.desc, "hash": t.hash, "range": t.range,
            "items": t.items.values().cloned().collect::<Vec<_>>(),
        })).collect();
        json!(tables)
    }

    pub fn snap_load(&mut self, v: &Value) {
        self.tables.clear();
        for t in v.as_array().into_iter().flatten() {
            let Some(name) = t["name"].as_str() else { continue };
            let Some(hash) = t["hash"].as_str() else { continue };
            let range = t["range"].as_str().map(String::from);
            let mut items = BTreeMap::new();
            for it in t["items"].as_array().into_iter().flatten() {
                if let Some(m) = it.as_object() {
                    if let Some(hk) = m.get(hash).and_then(kpart) {
                        let rk = range.as_deref().and_then(|r| m.get(r).and_then(kpart));
                        items.insert((hk, rk), m.clone());
                    }
                }
            }
            self.tables.insert(name.into(), Table { desc: t["desc"].clone(), hash: hash.into(), range, items });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_index_paths() {
        let item: Item = serde_json::from_value(json!({"id": {"S": "1"}, "tags": {"L": [{"S": "a"}, {"S": "b"}, {"S": "c"}]},
            "m": {"M": {"rows": {"L": [{"M": {"n": {"N": "1"}}}, {"M": {"n": {"N": "2"}}}]}}}})).unwrap();
        let req = json!({"ExpressionAttributeNames": {"#t": "tags"}, "ExpressionAttributeValues": {":x": {"S": "z"}, ":b": {"S": "b"}, ":two": {"N": "2"}}});
        assert!(eval(&parse_cond("#t[1] = :b AND m.rows[1].n = :two", &req).unwrap(), &item));
        assert!(!eval(&parse_cond("attribute_exists(#t[5])", &req).unwrap(), &item));
        let mut new = item.clone();
        apply(&parse_update("SET #t[0] = :x, #t[9] = :x, m.rows[0].n = m.rows[0].n + :two REMOVE #t[1], #t[2]", &req).unwrap(), &item, &mut new).unwrap();
        assert_eq!(new["tags"], json!({"L": [{"S": "z"}, {"S": "z"}]}), "set, append past end, then remove original [1] and [2]");
        assert_eq!(new["m"]["M"]["rows"]["L"][0], json!({"M": {"n": {"N": "3"}}}));
        let p = project(&item, &json!({"ProjectionExpression": "tags[2], m.rows[1].n"})).unwrap();
        assert_eq!(Value::Object(p), json!({"tags": {"L": [{"S": "c"}]}, "m": {"M": {"rows": {"L": [{"M": {"n": {"N": "2"}}}]}}}}));
        assert!(parse_cond("tags[x] = :b", &req).is_err() && parse_cond("[0] = :b", &req).is_err());
    }
}

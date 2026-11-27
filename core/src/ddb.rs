use crate::{err, ApiErr, App, ACCOUNT, REGION};
use serde_json::{json, Map, Value};
use std::cmp::Ordering::{self, Equal, Greater, Less};
use std::collections::{BTreeMap, BTreeSet};

pub type Item = Map<String, Value>;

// Sortable key part. N keys keep their exact decimal string (no f64 rounding, so 17+ digit keys stay distinct);
// comparison is sign, then integer width, then digit order, with exponents normalized (1e3 == 1000).
// Numbers with more than 38 significant digits are refused (DynamoDB's precision limit) when used as keys.
// DynamoDB Streams (StreamViewType record shapes) ride the same change log; iterators are "table|index"
// strings (ponytail: not opaque, no retention/trimming).
#[derive(Clone, Debug)]
pub enum K {
    N(String),
    S(String),
}
impl Ord for K {
    fn cmp(&self, o: &Self) -> Ordering {
        match (self, o) {
            (K::N(a), K::N(b)) => dec_cmp(a, b),
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

fn kpart(av: &Value) -> Result<K, ApiErr> {
    if let Some(s) = av.get("S").and_then(Value::as_str) {
        return Ok(K::S(s.into()));
    }
    if let Some(n) = av.get("N").and_then(Value::as_str) {
        normalize(n)?; // rejects > 38 significant digits (and malformed numbers)
        return Ok(K::N(n.into()));
    }
    av.get("B").and_then(Value::as_str).map(|b| K::S(b.into())).ok_or_else(|| verr("Invalid attribute value type"))
}

// (negative, integer digits without leading zeros, fraction digits without trailing zeros)
fn dec_parts(s: &str) -> Option<(bool, String, String)> {
    let (neg, s) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let (mant, exp) = match s.split_once(['e', 'E']) {
        Some((m, e)) => (m, e.parse::<i32>().ok()?),
        None => (s, 0),
    };
    let (mut int, mut frac) = match mant.split_once('.') {
        Some((i, f)) => (i.to_string(), f.to_string()),
        None => (mant.to_string(), String::new()),
    };
    if !int.bytes().chain(frac.bytes()).all(|b| b.is_ascii_digit()) || int.is_empty() && frac.is_empty() {
        return None;
    }
    // Shift the decimal point by the exponent (base-10 slide between int and frac).
    let exp = exp.clamp(-100_000, 100_000) as i64;
    match exp {
        e if e > 0 => {
            let take = (e as usize).min(frac.len());
            int += &frac[..take];
            frac = frac[take..].to_string();
            if e as usize > take {
                int += &"0".repeat(e as usize - take);
            }
        }
        e if e < 0 => {
            let drop = ((-e) as usize).min(int.len());
            frac = format!("{}{}", &int[int.len() - drop..], frac);
            int = int[..int.len() - drop].to_string();
            if (-e) as usize > drop {
                let zeros = (-e) as usize - drop; // zeros that move in front of the fraction
                int = String::new();
                frac = format!("{}{}", "0".repeat(zeros), frac);
            }
        }
        _ => {}
    }
    let int = int.trim_start_matches('0').to_string();
    let frac = frac.trim_end_matches('0').to_string();
    Some((neg, int, frac))
}

// Parse and validate a number string: reject > 38 significant digits.
fn normalize(s: &str) -> Result<(), ApiErr> {
    let Some((_, int, frac)) = dec_parts(s) else {
        return Err(err("ValidationException", format!("Supplied AttributeValue is empty or has an invalid number: {s}")));
    };
    if int.len() + frac.len() > 38 {
        return Err(err("ValidationException", format!("Number overflow. Attempting to store more than 38 significant digits in {s}")));
    }
    Ok(())
}

// Exact decimal comparison of two number strings ("1e3" == "1000").
fn dec_cmp(a: &str, b: &str) -> Ordering {
    let (na, ia, fa) = dec_parts(a).unwrap_or((false, String::new(), String::new()));
    let (nb, ib, fb) = dec_parts(b).unwrap_or((false, String::new(), String::new()));
    let zero = |i: &str, f: &str| i.is_empty() && f.is_empty();
    if zero(&ia, &fa) || zero(&ib, &fb) {
        // zero sits between the negatives and the positives ("-0" == "0")
        return match (zero(&ia, &fa), zero(&ib, &fb)) {
            (true, true) => Equal,
            (true, false) => if nb { Greater } else { Less },
            (false, true) => if na { Less } else { Greater },
            _ => unreachable!(),
        };
    }
    if na != nb {
        return if na { Less } else { Greater };
    }
    let ord = ia.len().cmp(&ib.len()).then_with(|| ia.cmp(&ib));
    let ord = if na { ord.reverse() } else { ord };
    ord.then_with(|| {
        let n = fa.len().max(fb.len());
        (0..n).map(|i| {
            let x = fa.as_bytes().get(i).map_or(b'0', |b| *b);
            let y = fb.as_bytes().get(i).map_or(b'0', |b| *b);
            x.cmp(&y)
        }).find(|o| *o != Equal).unwrap_or(Equal)
    })
}

type PK = (K, Option<K>);

#[derive(Clone)]
pub struct Table {
    desc: Value,
    hash: String,
    range: Option<String>,
    items: BTreeMap<PK, Item>,
    stream: Option<String>, // StreamViewType when the stream is enabled
    seq: u64,
    log: Vec<Rec>, // change log feeding GetRecords
}
#[derive(Clone)]
struct Rec {
    ev: String, // INSERT | MODIFY | REMOVE
    key: Item,
    old: Option<Item>,
    new: Option<Item>,
    at: f64,
    seq: u64,
}

#[derive(Default)]
pub struct Db {
    tables: BTreeMap<String, Table>,
    tx_tokens: BTreeMap<String, (i64, String)>, // ClientRequestToken -> (expires epoch secs, canonical TransactItems)
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
        let part = |n: &String| m.get(n).ok_or_else(|| verr(format!("Missing or invalid key attribute: {n}"))).and_then(kpart);
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

fn cmp_av(a: &Value, b: &Value) -> Option<Ordering> {
    // Key conditions and BETWEEN compare numbers exactly (no f64 rounding), like the sort keys themselves.
    if let (Some(x), Some(y)) = (a.get("N").and_then(Value::as_str), b.get("N").and_then(Value::as_str)) {
        return Some(dec_cmp(x, y));
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
                        let y = eval_t(b, old).ok_or_else(bad)?;
                        let (x, y) = (x.get("N").and_then(Value::as_str).ok_or_else(bad)?, y.get("N").and_then(Value::as_str).ok_or_else(bad)?);
                        json!({"N": dec_add(x, y, *o == '-')?})
                    }
                };
                set_path(new, p, v)?;
            }
            Upd::Remove(p) => removes.push(p),
            Upd::Add(p, v) => {
                let nv = match get(old, p) {
                    None => v.clone(),
                    Some(c) => match (c.get("N").and_then(Value::as_str), v.get("N").and_then(Value::as_str)) {
                        (Some(x), Some(y)) => json!({"N": dec_add(x, y, false)?}),
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
    for v in item.values() {
        check_numbers(v)?;
    }
    if serde_json::to_string(item).map_or(0, |s| s.len()) > 400 * 1024 {
        return Err(verr("Item size has exceeded the maximum allowed size"));
    }
    Ok(())
}

// Every N (and NS member, nested in L/M) is limited to 38 significant digits, keys and values alike.
fn check_numbers(v: &Value) -> Result<(), ApiErr> {
    if let Some(n) = v.get("N").and_then(Value::as_str) {
        normalize(n)?;
    }
    if let Some(ns) = v.get("NS").and_then(Value::as_array) {
        for n in ns {
            if let Some(x) = n.as_str() {
                normalize(x)?;
            }
        }
    }
    for t in ["L", "M"] {
        for x in v.get(t).and_then(Value::as_array).into_iter().flatten() {
            check_numbers(x)?;
        }
    }
    for x in v.get("M").and_then(Value::as_object).into_iter().flat_map(|m| m.values()) {
        check_numbers(x)?;
    }
    Ok(())
}

// Exact decimal add/sub of two number strings; the result is canonical and length-checked (38 digits).
fn dec_add(a: &str, b: &str, minus: bool) -> Result<String, ApiErr> {
    let (mut nb, ib, fb) = dec_parts(b).ok_or_else(|| verr(format!("Invalid number: {b}")))?;
    if minus {
        nb = !nb;
    }
    let (na, ia, fa) = dec_parts(a).ok_or_else(|| verr(format!("Invalid number: {a}")))?;
    let n = fa.len().max(fb.len());
    let xa = format!("{ia}{}{}", fa, "0".repeat(n - fa.len()));
    let xb = format!("{ib}{}{}", fb, "0".repeat(n - fb.len()));
    let (neg, out) = if na == nb {
        (na, add_digits(&xa, &xb))
    } else {
        // opposite signs: subtract the smaller magnitude from the larger, keep the larger's sign
        if mag_cmp(&xa, &xb) == Greater {
            (na, sub_digits(&xa, &xb).trim_start_matches('0').to_string())
        } else {
            (nb, sub_digits(&xb, &xa).trim_start_matches('0').to_string())
        }
    };
    let (int, frac) = out.split_at(out.len().saturating_sub(n));
    let int = int.trim_start_matches('0');
    let int = if int.is_empty() && !frac.is_empty() { "0" } else { int };
    let frac = frac.trim_end_matches('0');
    if int.is_empty() && frac.is_empty() {
        return Ok("0".into());
    }
    let res = format!("{}{}.{}", neg.then_some("-").unwrap_or(""), int, frac);
    let res = res.trim_end_matches('.').to_string();
    normalize(&res)?;
    Ok(res)
}
// Digit-string helpers: right-aligned (i counts from the units digit), a >= b for sub_digits.
fn add_digits(a: &str, b: &str) -> String {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut out = Vec::with_capacity(a.len().max(b.len()) + 1);
    let mut c = 0u8;
    for i in 0..a.len().max(b.len()) {
        let x = if i < a.len() { a[a.len() - 1 - i] } else { b'0' };
        let y = if i < b.len() { b[b.len() - 1 - i] } else { b'0' };
        let s = x + y - 2 * b'0' + c;
        out.push(s % 10 + b'0');
        c = s / 10;
    }
    if c > 0 {
        out.push(b'1');
    }
    out.reverse();
    String::from_utf8(out).unwrap()
}
fn sub_digits(a: &str, b: &str) -> String {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut out = Vec::with_capacity(a.len());
    let mut borrow = 0i16;
    for i in 0..a.len() {
        let x = a[a.len() - 1 - i] as i16;
        let y = if i < b.len() { b[b.len() - 1 - i] as i16 } else { b'0' as i16 };
        let mut d = x - y - borrow;
        if d < 0 {
            d += 10;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out.push(d as u8 + b'0');
    }
    out.reverse();
    String::from_utf8(out).unwrap()
}
fn mag_cmp(a: &str, b: &str) -> Ordering {
    a.trim_start_matches('0').len().cmp(&b.trim_start_matches('0').len()).then_with(|| a.cmp(b))
}

// Stream ARN (label fixed; single shard per table).
fn stream_arn(name: &str) -> String {
    format!("arn:aws:dynamodb:{}:{ACCOUNT}:table/{name}/stream/2026-11-26T00:00:00.000", *REGION)
}
fn stream_of(arn: &str) -> Option<String> {
    let t = arn.split("table/").nth(1)?;
    t.split_once("/stream/").map(|(n, _)| n.to_string())
}
fn key_item(t: &Table, k: &PK) -> Item {
    let mut m = Item::new();
    let kv = |k: &K| match k {
        K::S(s) => json!({"S": s}),
        K::N(n) => json!({"N": n}),
    };
    m.insert(t.hash.clone(), kv(&k.0));
    if let (Some(r), Some(v)) = (&t.range, &k.1) {
        m.insert(r.clone(), kv(v));
    }
    m
}
fn note(t: &mut Table, ev: &str, key: Item, old: Option<Item>, new: Option<Item>) {
    if t.stream.is_some() {
        t.seq += 1;
        let seq = t.seq;
        t.log.push(Rec { ev: ev.into(), key, old, new, at: chrono::Utc::now().timestamp() as f64, seq });
    }
}
fn rec_json(name: &str, t: &Table, rec: &Rec) -> Value {
    let view = t.stream.clone().unwrap_or_default();
    let mut d = json!({
        "ApproximateCreationDateTime": rec.at,
        "Keys": rec.key,
        "SequenceNumber": format!("{:0>21}", rec.seq),
        "SizeBytes": rec.new.as_ref().or(rec.old.as_ref()).map_or(0, |i| Value::Object(i.clone()).to_string().len()),
        "StreamViewType": view,
    });
    match view.as_str() {
        "KEYS_ONLY" => {}
        "NEW_IMAGE" => d["NewImage"] = rec.new.clone().into(),
        "OLD_IMAGE" => d["OldImage"] = rec.old.clone().into(),
        _ => {
            d["NewImage"] = rec.new.clone().into();
            d["OldImage"] = rec.old.clone().into();
        }
    }
    json!({
        "eventID": uuid::Uuid::new_v4().to_string(),
        "eventName": rec.ev, "eventVersion": "1.1", "eventSource": "aws:dynamodb",
        "awsRegion": *REGION, "dynamodb": d, "eventSourceARN": stream_arn(name),
    })
}

fn put(t: &mut Table, r: &Value) -> Result<Option<Item>, ApiErr> {
    let item = obj(r, "Item")?.clone();
    fits(&item)?;
    let k = t.key_of(&item)?;
    check(t, &k, r)?;
    let old = t.items.insert(k.clone(), item.clone());
    note(t, if old.is_some() { "MODIFY" } else { "INSERT" }, key_item(t, &k), old.clone(), Some(item));
    Ok(old)
}

fn delete(t: &mut Table, r: &Value) -> Result<Option<Item>, ApiErr> {
    let k = t.exact_key(obj(r, "Key")?)?;
    check(t, &k, r)?;
    let old = t.items.remove(&k);
    note(t, "REMOVE", key_item(t, &k), old.clone(), None);
    Ok(old)
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
    t.items.insert(k.clone(), new.clone());
    note(t, if old.is_some() { "MODIFY" } else { "INSERT" }, key_item(t, &k), old.clone(), Some(new.clone()));
    Ok((old, new))
}

// Puts a projected value back under its path: maps keep their keys; list index a[0].x and a[0].y merge into
// ONE element (AWS behavior), a later bare a[0] replaces the merged element, and past-the-end indexes
// compact in order (projected lists are not null-padded).
fn graft(out: &mut Item, p: &[String], v: Value) {
    let shell = |k: &String| if index(k).is_some() { json!({"L": []}) } else { json!({"M": {}}) };
    if p.len() == 1 {
        out.insert(p[0].clone(), v);
        return;
    }
    let mut cur = out.entry(p[0].clone()).or_insert_with(|| shell(&p[1]));
    for (n, k) in p[1..].iter().enumerate() {
        let next = p.get(n + 2);
        let leaf = next.is_none();
        let val = next.map_or_else(|| v.clone(), shell);
        cur = if let Some(i) = index(k) {
            let Some(l) = cur.get_mut("L").and_then(Value::as_array_mut) else { return };
            if i < l.len() {
                if leaf {
                    l[i] = v.clone(); // a[i] after a[i].x: the whole element replaces the merged shell
                }
                &mut l[i]
            } else {
                l.push(val);
                l.last_mut().unwrap()
            }
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
    let sk = |i: &Item| (i.get(&h).and_then(|v| kpart(v).ok()), rk.as_ref().and_then(|n| i.get(n)).and_then(|v| kpart(v).ok()), t.key_of(i).ok());
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

// StreamSpecification {StreamEnabled, StreamViewType}: None when absent or disabled; 4 valid views.
fn stream_spec(r: &Value) -> Option<String> {
    let sp = r.get("StreamSpecification")?;
    if sp["StreamEnabled"].as_bool() != Some(true) {
        return None;
    }
    let v = sp["StreamViewType"].as_str()?;
    ["NEW_IMAGE", "OLD_IMAGE", "NEW_AND_OLD_IMAGES", "KEYS_ONLY"].contains(&v).then(|| v.to_string())
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
            let stream = stream_spec(&r);
            if let Some(v) = &stream {
                desc["LatestStreamArn"] = stream_arn(name).into();
                desc["LatestStreamLabel"] = "2026-11-26T00:00:00.000".into();
                desc["StreamSpecification"] = json!({"StreamEnabled": true, "StreamViewType": v});
            }
            let t = Table { desc, hash, range, items: BTreeMap::new(), stream, seq: 0, log: vec![] };
            let out = json!({"TableDescription": describe(&t)});
            db.tables.insert(name.into(), t);
            Ok(out)
        }
        "DescribeTable" => Ok(json!({"Table": describe(tbl(db, &r)?)})),
        "UpdateTable" => {
            // ponytail: only ProvisionedThroughput is applied; billing mode / GSI changes replace-style are not emulated.
            let n = s(&r, "TableName")?;
            let t = db.tables.get_mut(n).ok_or_else(not_found)?;
            if let Some(pt) = r.get("ProvisionedThroughput") {
                t.desc["ProvisionedThroughput"] = pt.clone();
            }
            if r.get("StreamSpecification").is_some() {
                let v = stream_spec(&r);
                match &v {
                    Some(view) => {
                        t.desc["LatestStreamArn"] = stream_arn(n).into();
                        t.desc["LatestStreamLabel"] = "2026-11-26T00:00:00.000".into();
                        t.desc["StreamSpecification"] = json!({"StreamEnabled": true, "StreamViewType": view});
                    }
                    None => {
                        t.desc.as_object_mut().map(|d| {
                            d.remove("LatestStreamArn");
                            d.remove("LatestStreamLabel");
                            d.remove("StreamSpecification");
                        });
                    }
                }
                t.stream = v;
            }
            Ok(json!({"TableDescription": describe(t)}))
        }
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
            // One operation per item: every (table, key) may appear at most once.
            let mut seen: BTreeSet<(String, PK)> = BTreeSet::new();
            for op in ops {
                let (kind, inner) = op.as_object().and_then(|m| m.iter().next()).ok_or_else(|| verr("Empty transact item"))?;
                let n = s(inner, "TableName")?.to_string();
                let t = backup.get(&n).ok_or_else(not_found)?;
                let k = match kind.as_str() {
                    "Put" => t.key_of(obj(inner, "Item")?)?,
                    _ => t.exact_key(obj(inner, "Key")?)?,
                };
                if !seen.insert((n, k)) {
                    return Err(verr("Transaction request cannot include multiple operations on one item"));
                }
            }
            // ClientRequestToken: 10-minute idempotency (same params replay as no-op).
            let token = r["ClientRequestToken"].as_str().unwrap_or("").to_string();
            let canon = serde_json::to_string(&ops).unwrap_or_default();
            if !token.is_empty() {
                let now = chrono::Utc::now().timestamp();
                db.tx_tokens.retain(|_, (exp, _)| *exp > now);
                if let Some((_, prev)) = db.tx_tokens.get(&token) {
                    if *prev != canon {
                        return Err(err("ValidationException", format!("The ClientRequestToken {token} cannot be used with the given parameters")));
                    }
                    return Ok(json!({}));
                }
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
            if !token.is_empty() {
                db.tx_tokens.insert(token, (chrono::Utc::now().timestamp() + 600, canon));
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
        "ListStreams" => {
            let ss: Vec<Value> = db.tables.iter()
                .filter(|(_, t)| t.stream.is_some())
                .map(|(n, t)| json!({"StreamArn": stream_arn(n), "TableName": n, "StreamLabel": "2026-11-26T00:00:00.000", "StreamStatus": "ENABLED", "StreamViewType": t.stream}))
                .collect();
            Ok(json!({"Streams": ss}))
        }
        "DescribeStream" => {
            let arn = s(&r, "StreamArn")?;
            let name = stream_of(arn).ok_or_else(|| err("ResourceNotFoundException", format!("Stream {arn} not found")))?;
            let t = db.tables.get(name.as_str()).ok_or_else(|| err("ResourceNotFoundException", format!("Stream {arn} not found")))?;
            Ok(json!({"StreamDescription": {
                "StreamArn": arn, "StreamStatus": "ENABLED", "StreamViewType": t.stream,
                "TableName": name, "CreationRequestDateTime": t.desc["CreationDateTime"].clone(),
                "Shards": [{"ShardId": "shardId-00000000000000000000000000", "SequenceNumberRange": {"StartingSequenceNumber": "1"}}],
            }}))
        }
        "GetShardIterator" => {
            let arn = s(&r, "StreamArn")?;
            let name = stream_of(arn).ok_or_else(|| err("ResourceNotFoundException", format!("Stream {arn} not found")))?;
            let t = db.tables.get(name.as_str()).ok_or_else(|| err("ResourceNotFoundException", format!("Stream {arn} not found")))?;
            if t.stream.is_none() {
                return Err(err("ValidationException", format!("Stream {arn} is not enabled")));
            }
            let pos = match s(&r, "ShardIteratorType")? {
                "LATEST" => t.log.len(),
                "TRIM_HORIZON" => 0,
                "AT_SEQUENCE_NUMBER" => {
                    let sn = r["SequenceNumber"].as_str().unwrap_or("").trim_start_matches('0');
                    let sn = if sn.is_empty() { "0" } else { sn };
                    let n: u64 = sn.parse().map_err(|_| verr("Invalid SequenceNumber"))?;
                    t.log.iter().position(|x| x.seq == n).ok_or_else(|| verr("Invalid SequenceNumber"))?
                }
                "AFTER_SEQUENCE_NUMBER" => {
                    let sn = r["SequenceNumber"].as_str().unwrap_or("").trim_start_matches('0');
                    let sn = if sn.is_empty() { "0" } else { sn };
                    let n: u64 = sn.parse().map_err(|_| verr("Invalid SequenceNumber"))?;
                    t.log.iter().position(|x| x.seq == n).map(|i| i + 1).unwrap_or(t.log.len())
                }
                x => return Err(verr(format!("Invalid ShardIteratorType {x}"))),
            };
            Ok(json!({"ShardIterator": format!("{name}|{pos}")}))
        }
        "GetRecords" => {
            let it = s(&r, "ShardIterator")?;
            let (name, pos) = it.split_once('|').ok_or_else(|| verr("Invalid ShardIterator"))?;
            let t = db.tables.get(name).ok_or_else(not_found)?;
            if t.stream.is_none() {
                return Err(err("ValidationException", format!("Stream on table {name} is not enabled")));
            }
            let pos: usize = pos.parse().map_err(|_| verr("Invalid ShardIterator"))?;
            let take = r["Limit"].as_u64().unwrap_or(100).clamp(1, 1000) as usize;
            let end = (pos + take).min(t.log.len());
            let recs: Vec<Value> = t.log[pos..end].iter().map(|x| rec_json(name, t, x)).collect();
            Ok(json!({"Records": recs, "NextShardIterator": format!("{name}|{end}")}))
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
            "stream": t.stream, "seq": t.seq,
            "log": t.log.iter().map(|x| json!({"ev": x.ev, "key": x.key, "old": x.old, "new": x.new, "at": x.at, "seq": x.seq})).collect::<Vec<_>>(),
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
                    if let Some(hk) = m.get(hash).and_then(|v| kpart(v).ok()) {
                        let rk = range.as_deref().and_then(|r| m.get(r)).and_then(|v| kpart(v).ok());
                        items.insert((hk, rk), m.clone());
                    }
                }
            }
            let stream = t["stream"].as_str().map(String::from);
            let seq = t["seq"].as_u64().unwrap_or(0);
            let log = t["log"].as_array().map(|a| a.iter().filter_map(|x| {
                Some(Rec {
                    ev: x["ev"].as_str()?.to_string(),
                    key: x["key"].as_object()?.clone(),
                    old: x["old"].as_object().cloned(),
                    new: x["new"].as_object().cloned(),
                    at: x["at"].as_f64()?,
                    seq: x["seq"].as_u64()?,
                })
            }).collect()).unwrap_or_default();
            self.tables.insert(name.into(), Table { desc: t["desc"].clone(), hash: hash.into(), range, items, stream, seq, log });
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

    #[test]
    fn decimal_arithmetic_exact() {
        assert_eq!(dec_add("9007199254740993", "1", false).unwrap(), "9007199254740994");
        assert_eq!(dec_add("1.5", "2.25", false).unwrap(), "3.75");
        assert_eq!(dec_add("10", "3.5", true).unwrap(), "6.5");
        assert_eq!(dec_add("3.5", "10", true).unwrap(), "-6.5");
        assert_eq!(dec_add("-3.5", "3.5", false).unwrap(), "0");
        assert_eq!(dec_add("-2", "-3", false).unwrap(), "-5");
        assert_eq!(dec_add("0.1", "0.2", false).unwrap(), "0.3");
        assert!(dec_add("1e38", "9e37", false).is_err(), "39 digits must be refused");
    }

    #[test]
    fn decimal_key_precision() {
        let c = dec_cmp;
        assert_eq!(c("12345678901234567", "12345678901234568"), Less, "17 digits stay distinct");
        assert_eq!(c("12345678901234568", "12345678901234567"), Greater);
        assert_eq!(c("12345678901234567", "12345678901234567"), Equal);
        assert_eq!(c("1e3", "1000"), Equal);
        assert_eq!(c("1e-3", "0.001"), Equal);
        assert_eq!(c("0.10", "0.1"), Equal);
        assert_eq!(c("-0", "0"), Equal);
        assert_eq!(c("0", "1"), Less);
        assert_eq!(c("0", "-1"), Greater);
        assert_eq!(c("-2", "0"), Less);
        assert_eq!(c("0", "0.0001"), Less);
        assert_eq!(c("1000", "999"), Greater);
        assert_eq!(c("-1", "2"), Less);
        assert_eq!(c("-5", "-2"), Less);
        assert_eq!(c("0.1", "0.2"), Less);
        assert_eq!(c("1.5", "1.05"), Greater);
        assert_eq!(c("0.5", "1"), Less);
        assert!(K::N("5".into()) > K::N("-5".into()));
        assert!(normalize("12345678901234567890123456789012345678").is_ok(), "38 digits fit");
        assert!(normalize("123456789012345678901234567890123456789").is_err(), "39 digits overflow");
        assert!(normalize("1.25e2").is_ok());
    }

    #[test]
    fn projection_merges_same_element() {
        let item: Item = serde_json::from_value(json!({"a": {"L": [{"M": {"x": {"N": "1"}, "y": {"N": "2"}}}]}})).unwrap();
        let out = project(&item, &json!({"ProjectionExpression": "a[0].x, a[0].y"})).unwrap();
        let l = out["a"]["L"].as_array().unwrap();
        assert_eq!(l.len(), 1, "same-index paths merge into one element");
        assert_eq!(l[0]["M"]["x"]["N"], "1");
        assert_eq!(l[0]["M"]["y"]["N"], "2");
        // a bare a[0] after a[0].x replaces the merged element with the whole value.
        let out = project(&item, &json!({"ProjectionExpression": "a[0].x, a[0]"})).unwrap();
        assert_eq!(out["a"]["L"].as_array().unwrap().len(), 1);
        assert_eq!(out["a"]["L"][0]["M"]["y"]["N"], "2", "whole element keeps its siblings");
    }
}

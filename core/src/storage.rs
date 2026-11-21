//! SQLite-backed persistence (service snapshots + event history) and read-only SQL query engine.
//! Enabled on disk via `RC_SQLITE_FILE=/path/to/state.db`; otherwise runs in-memory so `/_admin/sql`
//! works out of the box for querying live events and snapshots.

use rusqlite::{types::ValueRef, Connection, params};
use serde_json::{json, Value};
use std::time::Instant;

const MAX_EVENTS: i64 = 20_000;

pub struct SqliteStore {
    conn: Connection,
    pub path: String,
    pub persistent: bool,
}

impl SqliteStore {
    pub fn open(path: Option<&str>) -> Result<Self, String> {
        let (conn, label, persistent) = match path.map(str::trim).filter(|s| !s.is_empty()) {
            Some(":memory:") | None => (
                Connection::open_in_memory().map_err(|e| format!("sqlite memory open: {e}"))?,
                ":memory:".to_string(),
                false,
            ),
            Some(p) => {
                if let Some(parent) = std::path::Path::new(p).parent() {
                    if !parent.as_os_str().is_empty() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                }
                let c = Connection::open(p).map_err(|e| format!("sqlite open {p}: {e}"))?;
                let _ = c.pragma_update(None, "journal_mode", "WAL");
                let _ = c.pragma_update(None, "synchronous", "NORMAL");
                (c, p.to_string(), true)
            }
        };
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS service_state (
                service TEXT PRIMARY KEY,
                updated_at TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                saved_at TEXT NOT NULL,
                label TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                request_id TEXT,
                service TEXT NOT NULL,
                op TEXT NOT NULL,
                status INTEGER NOT NULL,
                ms REAL,
                principal TEXT,
                decision TEXT,
                error_code TEXT,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_service ON events(service);
            CREATE INDEX IF NOT EXISTS idx_events_status ON events(status);",
        )
        .map_err(|e| format!("sqlite init schema: {e}"))?;
        Ok(Self { conn, path: label, persistent })
    }

    pub fn record_event(&self, ev: &Value) {
        let ts = ev["ts"].as_str().unwrap_or("");
        let rid = ev["request_id"].as_str();
        let svc = ev["service"].as_str().unwrap_or("");
        let op = ev["op"].as_str().unwrap_or("");
        let status = ev["status"].as_i64().unwrap_or(0);
        let ms = ev["ms"].as_f64();
        let principal = ev["principal"].as_str();
        let decision = ev["auth"]["decision"].as_str();
        let error_code = ev["error"]["code"].as_str();
        let payload = ev.to_string();
        let _ = self.conn.execute(
            "INSERT INTO events (ts, request_id, service, op, status, ms, principal, decision, error_code, payload)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![ts, rid, svc, op, status, ms, principal, decision, error_code, payload],
        );
        // Trim oldest rows periodically to keep in-memory / disk footprint bounded.
        if let Ok(last_id) = self.conn.query_row("SELECT last_insert_rowid()", [], |r| r.get::<_, i64>(0)) {
            if last_id % 500 == 0 && last_id > MAX_EVENTS {
                let cutoff = last_id - MAX_EVENTS;
                let _ = self.conn.execute("DELETE FROM events WHERE id <= ?1", params![cutoff]);
            }
        }
    }

    pub fn save_snapshot(&self, label: &str, snap: &Value) -> Result<i64, String> {
        let saved_at = snap["saved_at"].as_str().unwrap_or("");
        let payload = snap.to_string();
        self.conn
            .execute(
                "INSERT INTO snapshots (saved_at, label, payload) VALUES (?1, ?2, ?3)",
                params![saved_at, label, payload],
            )
            .map_err(|e| e.to_string())?;
        let id = self.conn.last_insert_rowid();
        if let Some(svcs) = snap["services"].as_object() {
            for (svc, val) in svcs {
                self.conn
                    .execute(
                        "INSERT INTO service_state (service, updated_at, payload) VALUES (?1, ?2, ?3)
                         ON CONFLICT(service) DO UPDATE SET updated_at = excluded.updated_at, payload = excluded.payload",
                        params![svc, saved_at, val.to_string()],
                    )
                    .map_err(|e| e.to_string())?;
            }
        }
        Ok(id)
    }

    pub fn list_snapshots(&self) -> Value {
        let mut rows = Vec::new();
        if let Ok(mut stmt) = self.conn.prepare(
            "SELECT id, saved_at, label, length(payload) FROM snapshots ORDER BY id DESC LIMIT 50",
        ) {
            if let Ok(iter) = stmt.query_map([], |r| {
                Ok(json!({
                    "id": r.get::<_, i64>(0)?,
                    "saved_at": r.get::<_, String>(1)?,
                    "label": r.get::<_, String>(2)?,
                    "size_bytes": r.get::<_, i64>(3)?,
                }))
            }) {
                for item in iter.flatten() {
                    rows.push(item);
                }
            }
        }
        let event_count: i64 = self
            .conn
            .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
            .unwrap_or(0);
        json!({
            "path": self.path,
            "persistent": self.persistent,
            "event_count": event_count,
            "snapshots": rows,
        })
    }

    pub fn load_snapshot(&self, id: Option<i64>) -> Result<Option<Value>, String> {
        let res: Result<String, rusqlite::Error> = match id {
            Some(i) => self.conn.query_row("SELECT payload FROM snapshots WHERE id = ?1", params![i], |r| r.get(0)),
            None => self.conn.query_row("SELECT payload FROM snapshots ORDER BY id DESC LIMIT 1", [], |r| r.get(0)),
        };
        match res {
            Ok(s) => serde_json::from_str(&s).map(Some).map_err(|e| e.to_string()),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn load_service_state(&self) -> Option<Value> {
        let mut stmt = self.conn.prepare("SELECT service, payload FROM service_state").ok()?;
        let mut svcs = serde_json::Map::new();
        let iter = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .ok()?;
        for pair in iter.flatten() {
            if let Ok(v) = serde_json::from_str::<Value>(&pair.1) {
                svcs.insert(pair.0, v);
            }
        }
        if svcs.is_empty() {
            return None;
        }
        Some(json!({"version": 1, "services": Value::Object(svcs)}))
    }

    /// Execute a strictly read-only SQL query against the SQLite store.
    pub fn query_readonly(&self, sql: &str, limit: usize) -> Result<Value, String> {
        let trimmed = sql.trim().trim_end_matches(';').trim();
        if trimmed.is_empty() {
            return Err("SQL query is empty".into());
        }
        if trimmed.contains(';') {
            return Err("Multiple SQL statements are not allowed".into());
        }
        let upper = trimmed.to_ascii_uppercase();
        let allowed_prefix = upper.starts_with("SELECT ")
            || upper.starts_with("SELECT\n")
            || upper.starts_with("WITH ")
            || upper.starts_with("EXPLAIN ")
            || upper.starts_with("PRAGMA TABLE_INFO")
            || upper.starts_with("PRAGMA TABLE_LIST")
            || upper.starts_with("PRAGMA INDEX_LIST");
        if !allowed_prefix {
            return Err("Only read-only SELECT / WITH / EXPLAIN / PRAGMA table_info queries are allowed".into());
        }
        let t0 = Instant::now();
        let mut stmt = self.conn.prepare(trimmed).map_err(|e| e.to_string())?;
        if !stmt.readonly() {
            return Err("Statement is not read-only".into());
        }
        let cols: Vec<String> = stmt.column_names().iter().map(|c| c.to_string()).collect();
        let cap = limit.clamp(1, 1000);
        let mut rows_out: Vec<Vec<Value>> = Vec::new();
        let mut truncated = false;
        let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            if rows_out.len() >= cap {
                truncated = true;
                break;
            }
            let mut vals = Vec::with_capacity(cols.len());
            for i in 0..cols.len() {
                let v = match row.get_ref(i).map_err(|e| e.to_string())? {
                    ValueRef::Null => Value::Null,
                    ValueRef::Integer(n) => json!(n),
                    ValueRef::Real(f) => json!(f),
                    ValueRef::Text(b) => json!(String::from_utf8_lossy(b)),
                    ValueRef::Blob(b) => json!(format!("<blob {} bytes>", b.len())),
                };
                vals.push(v);
            }
            rows_out.push(vals);
        }
        Ok(json!({
            "columns": cols,
            "rows": rows_out,
            "row_count": rows_out.len(),
            "truncated": truncated,
            "elapsed_ms": (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_snapshot_and_events_roundtrip() {
        let store = SqliteStore::open(None).unwrap();
        let snap = json!({
            "version": 1,
            "saved_at": "2026-11-21T00:00:00Z",
            "services": {"s3": [{"name": "bkt1"}]}
        });
        let id = store.save_snapshot("v1", &snap).unwrap();
        assert_eq!(id, 1);
        let loaded = store.load_snapshot(Some(id)).unwrap().unwrap();
        assert_eq!(loaded["services"]["s3"][0]["name"], "bkt1");
        let svc_state = store.load_service_state().unwrap();
        assert_eq!(svc_state["services"]["s3"][0]["name"], "bkt1");

        store.record_event(&json!({
            "ts": "2026-11-21T00:00:01Z", "request_id": "r1", "service": "s3",
            "op": "PutObject", "status": 200, "ms": 1.2, "principal": "root"
        }));
        let q = store.query_readonly("SELECT service, op, status FROM events", 10).unwrap();
        assert_eq!(q["row_count"], 1);
        assert_eq!(q["rows"][0][0], "s3");
        assert_eq!(q["rows"][0][2], 200);
    }

    #[test]
    fn sqlite_rejects_mutating_and_multi_statement_sql() {
        let store = SqliteStore::open(None).unwrap();
        assert!(store.query_readonly("DELETE FROM events", 10).is_err());
        assert!(store.query_readonly("DROP TABLE events", 10).is_err());
        assert!(store.query_readonly("SELECT 1; DROP TABLE events", 10).is_err());
        assert!(store.query_readonly("PRAGMA journal_mode = OFF", 10).is_err());
        assert!(store.query_readonly("PRAGMA table_info(events)", 50).is_ok());
    }
}

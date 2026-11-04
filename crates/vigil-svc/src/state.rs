//! Live service state: process and connection tables, mode, health and settings.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use rusqlite::{Connection, params};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::broadcast;
use vigil_ipc::proto::{INVALID_PARAMS, INVALID_STATE, NOT_FOUND, RpcError};

use crate::enforce::{Desired, FilterEngine};
use crate::events::Event;

pub const SERVICE_VERSION: &str = env!("CARGO_PKG_VERSION");
const POLICY_TOML: &str = include_str!("../../../config/default-policy.toml");

/// Current time as RFC 3339 (UTC).
#[must_use]
pub fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// A running process as shown to clients.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcRow {
    pub pid: u32,
    pub start_time: String,
    pub ppid: u32,
    pub name: String,
    pub path: Option<String>,
    pub parent_path: Option<String>,
    pub identity_id: Option<String>,
    pub verdict: Option<String>,
    pub score: Option<u8>,
}

impl ProcRow {
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "pid": self.pid, "start_time": self.start_time, "ppid": self.ppid,
            "name": self.name, "path": self.path, "identity_id": self.identity_id,
            "verdict": self.verdict, "score": self.score,
        })
    }
}

/// A TCP endpoint pair as shown to clients.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnRow {
    pub id: String,
    pub pid: u32,
    pub direction: &'static str,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: Option<String>,
    pub remote_port: Option<u16>,
    pub state: &'static str,
    pub verdict: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
}

impl ConnRow {
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id, "pid": self.pid, "proto": "tcp", "direction": self.direction,
            "local_addr": self.local_addr, "local_port": self.local_port,
            "remote_addr": self.remote_addr, "remote_port": self.remote_port,
            "state": self.state, "verdict": self.verdict, "blocked": false,
            "country": self.remote_addr.as_deref().and_then(|a| a.parse().ok()).and_then(vigil_core::analysis::geo::country),
            "first_seen": self.first_seen, "last_seen": self.last_seen,
        })
    }
}

struct Inner {
    mode: &'static str,
    health: &'static str,
    health_detail: Option<String>,
    learning_started_at: Option<String>,
    processes: BTreeMap<u32, ProcRow>,
    connections: BTreeMap<String, ConnRow>,
    settings: Value,
}

/// Start-up inputs that are computed once by the host.
pub struct Options {
    pub store: Option<Connection>,
    pub rules: Value,
    pub trust: Vec<Value>,
    pub rule_pack_version: String,
    /// Canonical path patterns of processes that must stay permitted (`network_critical`).
    pub network_critical: Vec<String>,
    /// Image names SG-001 protects (`never_kill` entries and pseudo-processes).
    pub never_kill: Vec<String>,
}

/// Everything shared between the observer and the connection handlers.
pub struct Shared {
    inner: Mutex<Inner>,
    store: Mutex<Option<Connection>>,
    bus: broadcast::Sender<Event>,
    rules: Value,
    trust: Vec<Value>,
    rule_pack_version: String,
    network_critical: Vec<String>,
    pub(crate) never_kill: vigil_core::kill::NeverKill,
    pub(crate) control: Mutex<Option<Arc<dyn crate::kill::ProcessControl>>>,
    engine: Mutex<Option<Arc<dyn FilterEngine>>>,
    last_applied: Mutex<Option<(Desired, bool)>>,
    armed: AtomicBool,
    once: Mutex<Vec<(String, Instant)>>,
    pub(crate) ai: Mutex<Option<Arc<dyn crate::ai::AiBackend>>>,
    pub(crate) ai_inflight: Mutex<std::collections::HashSet<i64>>,
    pub(crate) ai_slots: tokio::sync::Semaphore,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn default_settings() -> Value {
    toml::from_str::<toml::Value>(POLICY_TOML)
        .ok()
        .and_then(|v| serde_json::to_value(v).ok())
        .unwrap_or_else(|| Value::Object(Map::new()))
}

/// Merge `patch` into `current`, allowing only existing keys of the same JSON kind.
fn merge_settings(current: &mut Value, patch: &Value) -> Result<(), String> {
    let (Some(cur), Some(p)) = (current.as_object_mut(), patch.as_object()) else {
        return Err("settings must be an object".into());
    };
    for (k, v) in p {
        let Some(slot) = cur.get_mut(k) else {
            return Err(format!("unknown setting {k}"));
        };
        if slot.is_object() {
            merge_settings(slot, v).map_err(|e| format!("{k}.{e}"))?;
        } else if std::mem::discriminant(slot) != std::mem::discriminant(v) {
            return Err(format!("{k} has the wrong type"));
        } else {
            *slot = v.clone();
        }
    }
    Ok(())
}

fn page(mut items: Vec<Value>, params: &Value) -> Result<Value, RpcError> {
    let bad = |m: &str| RpcError::new(INVALID_PARAMS, m);
    let limit = match params.get("limit") {
        None => 200,
        Some(v) => v
            .as_u64()
            .filter(|n| (1..=1000).contains(n))
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| bad("limit must be 1..1000"))?,
    };
    let offset = match params.get("cursor") {
        None => 0,
        Some(v) => v
            .as_str()
            .and_then(|s| s.parse::<usize>().ok())
            .ok_or_else(|| bad("invalid cursor"))?,
    };
    let rest = items.split_off(offset.min(items.len()));
    let more = rest.len() > limit;
    let items: Vec<Value> = rest.into_iter().take(limit).collect();
    Ok(json!({ "items": items, "next_cursor": more.then(|| (offset + limit).to_string()) }))
}

fn text_matches(filter: &Value, haystacks: &[&str]) -> bool {
    filter.get("text").and_then(Value::as_str).is_none_or(|t| {
        let t = t.to_lowercase();
        haystacks.iter().any(|h| h.to_lowercase().contains(&t))
    })
}

fn verdict_matches(filter: &Value, verdict: Option<&str>) -> bool {
    filter
        .get("verdict")
        .and_then(Value::as_str)
        .is_none_or(|v| verdict == Some(v))
}

impl Shared {
    #[must_use]
    pub fn new(opts: Options) -> Self {
        let mut settings = default_settings();
        let (mut mode, mut learning) = ("observe", None);
        if let Some(conn) = &opts.store {
            let get = |k: &str| -> Option<String> {
                conn.query_row("SELECT value FROM settings WHERE key = ?1", [k], |r| {
                    r.get::<_, Vec<u8>>(0)
                })
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
            };
            if let Some(p) = get("policy").and_then(|s| serde_json::from_str::<Value>(&s).ok()) {
                let _ = merge_settings(&mut settings, &p);
            }
            mode = match get("mode").as_deref() {
                Some("learning") => "learning",
                Some("enforce") => "enforce",
                _ => "observe",
            };
            learning = get("learning_started_at");
        }
        let (bus, _) = broadcast::channel(4096);
        Self {
            inner: Mutex::new(Inner {
                mode,
                health: "healthy",
                health_detail: None,
                learning_started_at: learning,
                processes: BTreeMap::new(),
                connections: BTreeMap::new(),
                settings,
            }),
            store: Mutex::new(opts.store),
            bus,
            rules: opts.rules,
            trust: opts.trust,
            rule_pack_version: opts.rule_pack_version,
            network_critical: opts.network_critical,
            never_kill: vigil_core::kill::NeverKill::new(opts.never_kill),
            control: Mutex::new(None),
            engine: Mutex::new(None),
            last_applied: Mutex::new(None),
            armed: AtomicBool::new(false),
            once: Mutex::new(Vec::new()),
            ai: Mutex::new(None),
            ai_inflight: Mutex::new(std::collections::HashSet::new()),
            ai_slots: tokio::sync::Semaphore::new(2),
        }
    }

    #[must_use]
    pub fn subscribe_bus(&self) -> broadcast::Receiver<Event> {
        self.bus.subscribe()
    }

    pub fn emit(&self, topic: &'static str, method: &'static str, params: Value) {
        let _ = self.bus.send(Event {
            topic,
            method,
            params,
        });
    }

    /// Run `f` against the database, when one is open.
    pub fn with_store<R>(&self, f: impl FnOnce(&Connection) -> R) -> Option<R> {
        lock(&self.store).as_ref().map(f)
    }

    fn persist(&self, key: &str, value: &str) {
        let r = self.with_store(|c| {
            c.execute(
                "INSERT INTO settings (key, value) VALUES (?1, ?2)
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                params![key, value.as_bytes()],
            )
        });
        if let Some(Err(e)) = r {
            tracing::warn!(key, error = %e, "could not persist setting");
        }
    }

    pub fn set_health(&self, health: &'static str, detail: Option<&str>) {
        let detail = detail.map(str::to_string);
        let changed = {
            let mut g = lock(&self.inner);
            let changed = g.health != health || g.health_detail != detail;
            g.health = health;
            g.health_detail = detail;
            changed
        };
        if changed {
            self.emit_health();
        }
    }

    pub fn emit_health(&self) {
        let (state, details) = {
            let g = lock(&self.inner);
            (g.health, g.health_detail.clone())
        };
        self.emit(
            "health",
            "event.health",
            json!({ "state": state, "details": details, "ts": now() }),
        );
    }

    #[must_use]
    pub fn mode_and_health(&self) -> (&'static str, &'static str) {
        let g = lock(&self.inner);
        (g.mode, g.health)
    }

    #[must_use]
    pub fn status(&self) -> Value {
        let pending = self
            .with_store(vigil_store::repo::pending_count)
            .and_then(Result::ok)
            .unwrap_or(0);
        let g = lock(&self.inner);
        let count = |v: &str| {
            g.processes
                .values()
                .filter(|p| p.verdict.as_deref() == Some(v))
                .count()
        };
        json!({
            "protocol": vigil_ipc::PROTOCOL, "service_version": SERVICE_VERSION,
            "mode": g.mode, "health": g.health, "health_detail": g.health_detail,
            "filters_armed": self.armed.load(Ordering::SeqCst),
            "counts": { "safe": count("safe"), "unknown": count("unknown"),
                        "malicious": count("malicious"), "pending": pending },
            "rule_pack_version": self.rule_pack_version,
            "ai": self.ai_status(),
            "learning_started_at": g.learning_started_at,
        })
    }

    /// `mode.set`. Entering `enforce` needs a filter engine and (unless overridden) enough learning.
    pub fn set_mode(&self, mode: &str, override_minimum: bool) -> Result<Value, RpcError> {
        let mode: &'static str = match mode {
            "observe" => "observe",
            "learning" => "learning",
            "enforce" => "enforce",
            _ => return Err(RpcError::new(INVALID_PARAMS, "unknown mode")),
        };
        if mode == "enforce" {
            self.check_enforce(override_minimum)?;
        }
        let prev = self.mode_and_health().0;
        self.apply_mode(mode, "mode.set");
        if let Err(e) = self.resync_enforcement() {
            self.fail_enforcement(&e);
            return Err(RpcError::new(
                vigil_ipc::proto::ENFORCEMENT_OFF,
                "the filter engine could not be armed; back in observe mode",
            ));
        }
        self.audit(
            "user",
            vigil_core::audit::AuditKind::ModeChange,
            None,
            &json!({ "from": prev, "to": mode, "override_learning_minimum": override_minimum }),
        );
        Ok(self.status())
    }

    /// Set the mode without validation (also used for fail-open fallbacks) and announce it.
    pub(crate) fn apply_mode(&self, mode: &'static str, reason: &str) {
        let started = {
            let mut g = lock(&self.inner);
            g.mode = mode;
            if mode == "learning" && g.learning_started_at.is_none() {
                g.learning_started_at = Some(now());
            }
            g.learning_started_at.clone()
        };
        self.persist("mode", mode);
        if let Some(s) = started {
            self.persist("learning_started_at", &s);
        }
        self.emit(
            "enforcement",
            "event.enforcement_changed",
            json!({ "mode": mode, "filters_armed": self.armed.load(Ordering::SeqCst), "reason": reason }),
        );
    }

    pub(crate) fn force_mode(&self, mode: &'static str, reason: &str) {
        self.apply_mode(mode, reason);
    }

    pub(crate) fn engine_slot(&self) -> MutexGuard<'_, Option<Arc<dyn FilterEngine>>> {
        lock(&self.engine)
    }

    pub(crate) fn last_applied_slot(&self) -> MutexGuard<'_, Option<(Desired, bool)>> {
        lock(&self.last_applied)
    }

    pub(crate) fn set_armed(&self, armed: bool) {
        if self.armed.swap(armed, Ordering::SeqCst) != armed {
            let mode = self.mode_and_health().0;
            self.emit(
                "enforcement",
                "event.enforcement_changed",
                json!({ "mode": mode, "filters_armed": armed, "reason": "sync" }),
            );
        }
    }

    /// Paths of the parents of every running process of identity `id`.
    pub(crate) fn parent_paths_of(&self, id: i64) -> Vec<String> {
        let id = id.to_string();
        let g = lock(&self.inner);
        let mut v: Vec<String> = g
            .processes
            .values()
            .filter(|p| p.identity_id.as_deref() == Some(id.as_str()))
            .filter_map(|p| p.parent_path.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    pub(crate) fn learning_started(&self) -> Option<String> {
        lock(&self.inner).learning_started_at.clone()
    }

    pub(crate) fn network_critical_patterns(&self) -> Vec<String> {
        self.network_critical.clone()
    }

    pub(crate) fn add_once_permit(&self, path: Option<String>, until: Instant) {
        if let Some(p) = path {
            lock(&self.once).push((p, until));
        }
    }

    pub(crate) fn live_once_permits(&self) -> Vec<String> {
        let mut g = lock(&self.once);
        let now = Instant::now();
        g.retain(|(_, until)| *until > now);
        g.iter().map(|(p, _)| p.clone()).collect()
    }

    #[must_use]
    pub fn settings(&self) -> Value {
        lock(&self.inner).settings.clone()
    }

    pub fn update_settings(&self, patch: &Value) -> Result<Value, RpcError> {
        let mut next = self.settings();
        merge_settings(&mut next, patch).map_err(|m| RpcError::new(INVALID_PARAMS, m))?;
        lock(&self.inner).settings.clone_from(&next);
        self.persist("policy", &next.to_string());
        Ok(next)
    }

    #[must_use]
    pub fn rules(&self) -> Value {
        json!({ "rule_pack_version": self.rule_pack_version, "rules": self.rules })
    }

    #[must_use]
    pub fn trust(&self) -> Value {
        json!({ "publishers": self.trust })
    }

    // ---- processes ----

    /// Insert or replace a process row and announce it.
    pub fn put_process(&self, row: ProcRow) {
        let json = row.to_json();
        lock(&self.inner).processes.insert(row.pid, row);
        self.emit("processes", "event.process_started", json);
    }

    /// Remove `pid` if it is still the process that started at `start_time`.
    pub fn remove_process(&self, pid: u32, start_time: &str) {
        let removed = {
            let mut g = lock(&self.inner);
            if g.processes
                .get(&pid)
                .is_some_and(|p| p.start_time == start_time)
            {
                g.processes.remove(&pid)
            } else {
                None
            }
        };
        if removed.is_some() {
            self.emit(
                "processes",
                "event.process_exited",
                json!({ "pid": pid, "start_time": start_time, "exit_time": now() }),
            );
        }
    }

    #[must_use]
    pub fn process_keys(&self) -> Vec<(u32, String)> {
        lock(&self.inner)
            .processes
            .values()
            .map(|p| (p.pid, p.start_time.clone()))
            .collect()
    }

    /// Apply an evaluation to every process running `path` under `parent_path`.
    /// Returns the rows whose verdict changed or was set for the first time.
    pub fn apply_evaluation(
        &self,
        path: &str,
        parent_path: Option<&str>,
        identity: &str,
        verdict: &str,
        score: u8,
    ) -> Vec<(ProcRow, Option<String>)> {
        let mut changed = Vec::new();
        let mut g = lock(&self.inner);
        for p in g.processes.values_mut() {
            let same = p
                .path
                .as_deref()
                .is_some_and(|x| x.eq_ignore_ascii_case(path))
                && p.parent_path.as_deref().map(str::to_lowercase)
                    == parent_path.map(str::to_lowercase);
            if same && (p.verdict.as_deref() != Some(verdict) || p.score != Some(score)) {
                let old = p.verdict.replace(verdict.to_string());
                p.score = Some(score);
                p.identity_id = Some(identity.to_string());
                changed.push((p.clone(), old));
            }
        }
        changed
    }

    pub(crate) fn process_row(&self, pid: u32, start_time: &str) -> Option<ProcRow> {
        lock(&self.inner)
            .processes
            .get(&pid)
            .filter(|p| p.start_time == start_time)
            .cloned()
    }

    pub(crate) fn rows_with_verdict(&self, verdict: &str) -> Vec<ProcRow> {
        lock(&self.inner)
            .processes
            .values()
            .filter(|p| p.verdict.as_deref() == Some(verdict))
            .cloned()
            .collect()
    }

    pub fn list_processes(&self, params: &Value) -> Result<Value, RpcError> {
        let filter = params.get("filter").cloned().unwrap_or(Value::Null);
        let g = lock(&self.inner);
        let with_conn: std::collections::HashSet<u32> =
            g.connections.values().map(|c| c.pid).collect();
        let rows: Vec<Value> = g
            .processes
            .values()
            .filter(|p| verdict_matches(&filter, p.verdict.as_deref()))
            .filter(|p| text_matches(&filter, &[&p.name, p.path.as_deref().unwrap_or("")]))
            .filter(|p| {
                filter
                    .get("has_connections")
                    .and_then(Value::as_bool)
                    .is_none_or(|w| with_conn.contains(&p.pid) == w)
            })
            .map(ProcRow::to_json)
            .collect();
        drop(g);
        page(rows, params)
    }

    /// `process.get`: the row, its identity and latest evaluation, parent chain and connections.
    pub fn get_process(&self, pid: u32, start_time: &str) -> Result<Value, RpcError> {
        let (row, chain, conns) = {
            let g = lock(&self.inner);
            let row = g
                .processes
                .get(&pid)
                .filter(|p| p.start_time == start_time)
                .cloned()
                .ok_or_else(|| RpcError::new(NOT_FOUND, "no such process"))?;
            let mut chain = Vec::new();
            let mut next = row.ppid;
            while let Some(p) = g.processes.get(&next).filter(|p| p.pid != 0) {
                if chain.len() >= 16 || p.start_time > row.start_time {
                    break; // pid reuse or a loop: the recorded parent is not an ancestor
                }
                chain.push(p.to_json());
                next = p.ppid;
            }
            let conns: Vec<Value> = g
                .connections
                .values()
                .filter(|c| c.pid == pid)
                .map(ConnRow::to_json)
                .collect();
            (row, chain, conns)
        };
        let no_eval = || RpcError::new(INVALID_STATE, "process has not been evaluated yet");
        let id: i64 = row
            .identity_id
            .as_deref()
            .and_then(|s| s.parse().ok())
            .ok_or_else(no_eval)?;
        let (exe, ev) = self
            .with_store(|c| {
                Ok::<_, vigil_store::StoreError>((
                    vigil_store::repo::executable_by_id(c, id)?,
                    vigil_store::repo::latest_evaluation(c, id)?,
                ))
            })
            .and_then(Result::ok)
            .and_then(|(e, v)| Some((e?, v?)))
            .ok_or_else(no_eval)?;
        let signals: Value = serde_json::from_str(&ev.signals_json).unwrap_or_else(|_| json!([]));
        Ok(json!({
            "process": row.to_json(),
            "identity": {
                "id": id.to_string(), "sha256": exe.sha256, "path": exe.path,
                "signer_thumbprint": exe.signer_thumbprint, "publisher": exe.publisher,
                "company": exe.company, "product": exe.product,
                "original_filename": exe.original_filename,
                "signature_status": exe.signature_status,
            },
            "evaluation": {
                "score": ev.score, "verdict": ev.verdict, "signals": signals,
                "hard_rule": ev.hard_rule, "rule_pack_version": ev.rule_pack_version,
                "source": ev.source, "evaluated_at": ev.evaluated_at,
            },
            "parent_chain": chain,
            "connections": conns,
            "ai_opinion": self.ai_opinion_json(id),
        }))
    }

    // ---- connections ----

    /// Replace the connection table with `current`, emitting opened/closed events for the diff.
    pub fn sync_connections(&self, current: Vec<ConnRow>) {
        let mut opened = Vec::new();
        let mut closed = Vec::new();
        {
            let mut g = lock(&self.inner);
            let mut next = BTreeMap::new();
            for mut c in current {
                match g.connections.get(&c.id) {
                    Some(old) => {
                        c.first_seen.clone_from(&old.first_seen);
                        if old.state != c.state {
                            opened.push(c.clone());
                        }
                    }
                    None => opened.push(c.clone()),
                }
                next.insert(c.id.clone(), c);
            }
            for (id, old) in &g.connections {
                if !next.contains_key(id) {
                    closed.push(old.clone());
                }
            }
            g.connections = next;
        }
        for c in opened {
            self.emit("connections", "event.connection_opened", c.to_json());
        }
        for c in closed {
            self.emit(
                "connections",
                "event.connection_closed",
                json!({ "id": c.id, "last_seen": now() }),
            );
        }
    }

    pub fn list_connections(&self, params: &Value) -> Result<Value, RpcError> {
        let filter = params.get("filter").cloned().unwrap_or(Value::Null);
        let g = lock(&self.inner);
        let rows: Vec<Value> = g
            .connections
            .values()
            .filter(|c| verdict_matches(&filter, c.verdict.as_deref()))
            .filter(|c| {
                let name = g.processes.get(&c.pid).map_or("", |p| p.name.as_str());
                text_matches(
                    &filter,
                    &[name, c.remote_addr.as_deref().unwrap_or(""), &c.local_addr],
                )
            })
            .map(ConnRow::to_json)
            .collect();
        drop(g);
        page(rows, params)
    }

    /// Verdict of the owning process for connection rows (set by the observer before `sync`).
    #[must_use]
    pub fn process_verdict(&self, pid: u32) -> Option<String> {
        lock(&self.inner)
            .processes
            .get(&pid)
            .and_then(|p| p.verdict.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared() -> Shared {
        Shared::new(Options {
            store: Some(vigil_store::open_in_memory().unwrap()),
            rules: json!([]),
            trust: vec![],
            rule_pack_version: "t".into(),
            network_critical: Vec::new(),
            never_kill: Vec::new(),
        })
    }

    fn proc(pid: u32) -> ProcRow {
        ProcRow {
            pid,
            start_time: "2026-01-01T00:00:00Z".into(),
            ppid: 1,
            name: format!("p{pid}.exe"),
            path: Some(format!("C:\\x\\p{pid}.exe")),
            parent_path: None,
            identity_id: None,
            verdict: None,
            score: None,
        }
    }

    #[test]
    fn enforce_is_refused_and_modes_persist() {
        let s = shared();
        assert_eq!(
            s.set_mode("enforce", false).unwrap_err().code,
            vigil_ipc::proto::ENFORCEMENT_OFF
        );
        s.set_mode("learning", false).unwrap();
        assert_eq!(s.status()["mode"], "learning");
        assert!(s.status()["learning_started_at"].is_string());
    }

    #[test]
    fn settings_reject_unknown_keys_and_wrong_types() {
        let s = shared();
        assert!(s.update_settings(&json!({"nope": {"x": 1}})).is_err());
        assert!(
            s.update_settings(&json!({"general": {"log_level": 3}}))
                .is_err()
        );
        let v = s
            .update_settings(&json!({"general": {"log_level": "debug"}}))
            .unwrap();
        assert_eq!(v["general"]["log_level"], "debug");
    }

    #[test]
    fn paging_and_filters() {
        let s = shared();
        for pid in 1..=5 {
            s.put_process(proc(pid));
        }
        let p1 = s.list_processes(&json!({"limit": 2})).unwrap();
        assert_eq!(p1["items"].as_array().unwrap().len(), 2);
        let cur = p1["next_cursor"].as_str().unwrap().to_string();
        let p2 = s
            .list_processes(&json!({"limit": 10, "cursor": cur}))
            .unwrap();
        assert_eq!(p2["items"].as_array().unwrap().len(), 3);
        assert!(p2["next_cursor"].is_null());
        let hit = s
            .list_processes(&json!({"filter": {"text": "P3"}}))
            .unwrap();
        assert_eq!(hit["items"].as_array().unwrap().len(), 1);
        assert!(s.list_processes(&json!({"limit": 0})).is_err());
    }

    #[test]
    fn evaluation_updates_matching_rows_once() {
        let s = shared();
        s.put_process(proc(7));
        let first = s.apply_evaluation("c:\\X\\P7.exe", None, "1", "safe", 90);
        assert_eq!(first.len(), 1);
        assert!(first[0].1.is_none());
        let again = s.apply_evaluation("C:\\x\\p7.exe", None, "1", "safe", 90);
        assert_eq!(again.len(), 0);
    }

    #[test]
    fn exited_pid_reuse_is_not_removed_by_stale_exit() {
        let s = shared();
        s.put_process(proc(9));
        s.remove_process(9, "2000-01-01T00:00:00Z");
        let code = |s: &Shared| s.get_process(9, "2026-01-01T00:00:00Z").unwrap_err().code;
        assert_eq!(code(&s), INVALID_STATE, "still present, just not evaluated");
        s.remove_process(9, "2026-01-01T00:00:00Z");
        assert_eq!(code(&s), NOT_FOUND);
    }
}

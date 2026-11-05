//! Root-cause handling of respawn floods (`docs/18 §5`): find who keeps starting a killed program,
//! stop the busy-work, and ask the user once about the launcher.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use vigil_core::audit::AuditKind;
use vigil_ipc::proto::{INVALID_PARAMS, NOT_FOUND, RpcError};

use crate::state::Shared;

const FAST_WINDOW: Duration = Duration::from_secs(60);
const FAST_HITS: usize = 5;
const SLOW_WINDOW: Duration = Duration::from_secs(600);
const SLOW_HITS: usize = 3;
/// A launcher is asked about at most once in this long.
const ASK_EVERY: Duration = Duration::from_secs(24 * 3600);

struct Asked {
    block_id: i64,
    child: String,
}

/// Flood bookkeeping; lives in [`Shared`].
#[derive(Default)]
pub(crate) struct Launchers {
    hits: HashMap<String, VecDeque<Instant>>,
    /// Blocks whose respawns are now killed silently (one counter, no audit row or AI call each).
    cooling: HashSet<i64>,
    asked: HashMap<String, Instant>,
    waiting: HashMap<String, Asked>,
}

impl Shared {
    /// Record one non-interactive respawn of block `block_id` started by `launcher`.
    /// Returns `true` while the block is in cool-down (the caller then kills without audit noise).
    pub(crate) fn note_respawn(&self, launcher: Option<&str>, child: &str, block_id: i64) -> bool {
        let now = Instant::now();
        let mut ask = None;
        let cooling = {
            let mut g = self
                .launchers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(l) = launcher {
                let key = l.to_lowercase();
                let q = g.hits.entry(key.clone()).or_default();
                q.push_back(now);
                while q
                    .front()
                    .is_some_and(|t| now.duration_since(*t) > SLOW_WINDOW)
                {
                    q.pop_front();
                }
                let fast = q
                    .iter()
                    .filter(|t| now.duration_since(**t) <= FAST_WINDOW)
                    .count();
                let total = q.len();
                if fast >= FAST_HITS || total >= SLOW_HITS {
                    g.cooling.insert(block_id);
                    let fresh = g
                        .asked
                        .get(&key)
                        .is_none_or(|t| now.duration_since(*t) >= ASK_EVERY);
                    if fresh && !self.launcher_untouchable(l) {
                        g.asked.insert(key.clone(), now);
                        g.waiting.insert(
                            key,
                            Asked {
                                block_id,
                                child: child.to_owned(),
                            },
                        );
                        ask = Some((l.to_owned(), total));
                    }
                }
            }
            g.cooling.contains(&block_id)
        };
        if let Some((l, n)) = ask {
            self.emit_launcher_prompt(&l, child, n);
        }
        cooling
    }

    /// Vigil itself and the never-kill set are not launchers the user can be asked to stop.
    fn launcher_untouchable(&self, path: &str) -> bool {
        self.never_kill.check(path, None).is_err()
            || path.rsplit(['\\', '/']).next().is_some_and(|n| {
                crate::kill::SELF_IMAGES
                    .iter()
                    .any(|s| n.eq_ignore_ascii_case(s))
            })
    }

    fn emit_launcher_prompt(&self, launcher: &str, child: &str, count: usize) {
        let autostart = self
            .persistence_scan(Some(launcher))
            .ok()
            .and_then(|v| v["findings"].as_array().map(Vec::len))
            .unwrap_or(0);
        let decision = self
            .kill_decision_for(child)
            .map(|d| self.decision_detail(&d));
        self.emit(
            "enforcement",
            "event.launcher_prompt",
            json!({
                "launcher": launcher, "child": child, "count": count,
                "window_secs": SLOW_WINDOW.as_secs(), "autostart_entries": autostart,
                "decision": decision,
            }),
        );
        self.audit(
            "service",
            AuditKind::RespawnKill,
            Some(launcher),
            &json!({ "launcher": launcher, "child": child, "count": count, "action": "launcher_prompt" }),
        );
    }

    /// `launcher.answer`: `allow` (lift the child's kill), `stop` (kill the launcher), `disable`
    /// (turn off its autostart, reversible) or `wait` (nothing; not asked again for 24 h).
    pub fn launcher_answer(&self, params: &Value) -> Result<Value, RpcError> {
        let bad = || RpcError::new(INVALID_PARAMS, "launcher and action are required");
        let launcher = params["launcher"].as_str().ok_or_else(bad)?;
        let action = params["action"]
            .as_str()
            .filter(|a| ["allow", "stop", "disable", "wait"].contains(a))
            .ok_or_else(bad)?;
        let w = self
            .launchers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .waiting
            .remove(&launcher.to_lowercase())
            .ok_or_else(|| RpcError::new(NOT_FOUND, "no such question (already answered)"))?;
        match action {
            "allow" => {
                if let Some(d) = self.kill_decision_for(&w.child) {
                    self.decision_exception(&json!({ "decision_id": d.id.to_string() }))?;
                }
                self.launchers
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .cooling
                    .remove(&w.block_id);
            }
            "stop" => self.stop_launcher(launcher),
            "disable" => self.disable_autostart(launcher)?,
            _ => {}
        }
        self.audit(
            "user",
            AuditKind::Decision,
            Some(launcher),
            &json!({ "launcher_answer": action, "child": w.child }),
        );
        Ok(json!({}))
    }

    fn stop_launcher(&self, launcher: &str) {
        let Some(ctl) = self.control() else { return };
        for s in ctl.list() {
            if s.image
                .as_deref()
                .is_some_and(|i| i.eq_ignore_ascii_case(launcher))
            {
                // `kill_process` applies every protection (never-kill, Vigil's own, hard rules).
                let _ = self.kill_process(
                    &json!({ "pid": s.pid, "start_time": s.start_time, "block": true }),
                    "user",
                );
            }
        }
    }

    fn disable_autostart(&self, launcher: &str) -> Result<(), RpcError> {
        let found = self.persistence_scan(Some(launcher))?;
        for f in found["findings"].as_array().into_iter().flatten() {
            if let Some(id) = f["id"].as_str() {
                self.persistence_apply(&json!({ "item_id": id, "action": "disable" }), "user")?;
            }
        }
        Ok(())
    }
}

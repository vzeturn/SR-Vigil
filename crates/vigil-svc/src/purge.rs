//! Lockdown (`docs/21`): on demand, stop every untrusted background process and keep them off for a
//! window. A program that keeps coming back is put to the advisor, which says what it is and whether
//! the cause deserves an investigation. Nothing is deleted and no permanent rule is written: the hold is
//! in memory and ends by itself, so a crashed service never leaves the machine locked.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use vigil_core::audit::AuditKind;
use vigil_ipc::proto::{INVALID_STATE, RpcError};
use vigil_store::{decisions, repo};

use crate::kill::{KillOutcome, is_self};
use crate::state::{ProcRow, Shared, now};

/// Default and maximum hold, in minutes.
const DEFAULT_MINUTES: u64 = 5;
const MAX_MINUTES: u64 = 30;
/// Comebacks after which a program is treated as persistent and sent to the advisor.
const FLAG_AT: u32 = 3;
const KEPT_LISTED: usize = 40;

/// Facts about one running process that decide whether lockdown leaves it alone.
#[derive(Default, Clone, Copy)]
#[allow(clippy::struct_excessive_bools)] // independent facts about one process, named at the call site
pub(crate) struct Facts<'a> {
    pub own: bool,
    pub never_kill: bool,
    pub classified: bool,
    pub verdict: Option<&'a str>,
    /// A user allow decision bound to this exact file (identity = hash + path + signer).
    pub allowed: bool,
    pub user_started: bool,
    /// Valid signature and a stored advisor opinion `safe` with enough confidence for this exact file.
    pub ai_cleared: bool,
    /// Started by a signed AI-developer agent (`docs/18 §3`).
    pub agent: bool,
}

/// Why a running process is left alone; `None` means it is stopped. A low score alone never makes a
/// process dangerous: it only means "not proven", and unproven programs are stopped, not blocked.
#[must_use]
pub(crate) fn spare_reason(f: Facts<'_>) -> Option<&'static str> {
    let flagged = f.verdict == Some("malicious");
    if f.own {
        Some("self")
    } else if f.never_kill {
        Some("never_kill")
    } else if !f.classified {
        Some("unclassified")
    } else if f.verdict == Some("safe") {
        Some("safe")
    } else if f.allowed {
        Some("allowed")
    } else if f.user_started && !flagged {
        Some("user")
    } else if f.ai_cleared && !flagged {
        Some("ai_cleared")
    } else if f.agent && !flagged {
        Some("agent")
    } else {
        None
    }
}

/// Advisor confidence at which a `safe` opinion counts as clearing a signed program.
const AI_CLEAR_AT: f64 = 0.75;

struct Held {
    name: String,
    path: String,
    identity: Option<String>,
    verdict: Option<String>,
    score: Option<u8>,
    publisher: Option<String>,
    parent: Option<String>,
    origin: Option<&'static str>,
    killed_at: String,
    respawns: u32,
    last_respawn: Option<String>,
    flagged: bool,
    ai: Option<Value>,
}

struct Run {
    started_at: String,
    began: Instant,
    window: Duration,
    spared: HashMap<&'static str, u32>,
    kept: Vec<Value>,
    held: HashMap<String, Held>,
}

/// State of the current (or most recently finished) lockdown.
#[derive(Default)]
pub(crate) struct Purge {
    run: Option<Run>,
    last: Option<Value>,
}

fn key(path: &str) -> String {
    path.to_lowercase()
}

impl Run {
    fn report(&self, active: bool) -> Value {
        let left = self.window.saturating_sub(self.began.elapsed()).as_secs();
        let mut held: Vec<&Held> = self.held.values().collect();
        held.sort_by(|a, b| b.respawns.cmp(&a.respawns).then(a.name.cmp(&b.name)));
        let respawns: u32 = held.iter().map(|h| h.respawns).sum();
        json!({
            "active": active, "started_at": self.started_at,
            "window_s": self.window.as_secs(), "remaining_s": if active { left } else { 0 },
            "stopped": held.len(), "respawns": respawns,
            "flagged": held.iter().filter(|h| h.flagged).count(),
            "spared": self.spared, "kept": self.kept,
            "held": held.iter().map(|h| json!({
                "name": h.name, "path": h.path, "identity_id": h.identity,
                "verdict": h.verdict, "score": h.score, "publisher": h.publisher,
                "parent": h.parent, "origin": h.origin, "killed_at": h.killed_at,
                "respawns": h.respawns, "last_respawn": h.last_respawn,
                "flagged": h.flagged, "ai": h.ai,
            })).collect::<Vec<_>>(),
        })
    }
}

impl Shared {
    fn purge_state(&self) -> std::sync::MutexGuard<'_, Purge> {
        self.purge.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `purge.status`: the live run, else the last finished one, else `{active:false}`.
    pub fn purge_status(&self) -> Value {
        let p = self.purge_state();
        match (&p.run, &p.last) {
            (Some(r), _) => r.report(true),
            (None, Some(l)) => l.clone(),
            (None, None) => json!({ "active": false, "held": [], "kept": [], "spared": {} }),
        }
    }

    fn allowed_identities(&self) -> HashSet<i64> {
        self.with_store(|c| {
            decisions::list_active(c, time::OffsetDateTime::now_utc()).map(|d| {
                d.into_iter()
                    .filter(|d| d.action == decisions::Action::Allow)
                    .map(|d| d.executable_id)
                    .collect()
            })
        })
        .and_then(Result::ok)
        .unwrap_or_default()
    }

    /// `(validly signed, advisor says safe)` for one identity. Both are bound to that exact file hash.
    fn trust_of(&self, id: i64) -> (bool, bool) {
        self.with_store(|c| {
            let signed = repo::executable_by_id(c, id)?
                .is_some_and(|e| e.signature_status.starts_with("valid"));
            let safe = vigil_store::ai::latest_opinion(c, id)?
                .is_some_and(|o| o.verdict == "safe" && o.confidence >= AI_CLEAR_AT);
            Ok::<_, vigil_store::StoreError>((signed, safe))
        })
        .and_then(Result::ok)
        .unwrap_or_default()
    }

    fn publisher_of(&self, identity: Option<&str>) -> Option<String> {
        let id: i64 = identity?.parse().ok()?;
        self.with_store(|c| repo::executable_by_id(c, id))
            .and_then(Result::ok)
            .flatten()
            .and_then(|e| e.publisher)
    }

    /// `purge.start`: stop everything untrusted and begin the hold.
    pub fn purge_start(&self, params: &Value, actor: &str) -> Result<Value, RpcError> {
        if self.protection_paused() {
            return Err(RpcError::new(
                INVALID_STATE,
                "protection is paused; turn it on to use lockdown",
            ));
        }
        let ctl = self
            .control()
            .ok_or_else(|| RpcError::new(INVALID_STATE, "process control unavailable"))?;
        if self.purge_state().run.is_some() {
            return Ok(self.purge_status());
        }
        let minutes = params
            .get("minutes")
            .and_then(Value::as_u64)
            .map_or(DEFAULT_MINUTES, |m| m.clamp(1, MAX_MINUTES));
        let allowed = self.allowed_identities();
        let snaps = ctl.list();
        let mut run = Run {
            started_at: now(),
            began: Instant::now(),
            window: Duration::from_secs(minutes * 60),
            spared: HashMap::new(),
            kept: Vec::new(),
            held: HashMap::new(),
        };
        for row in self.all_rows() {
            let Some(snap) = snaps
                .iter()
                .find(|s| s.pid == row.pid && s.start_time == row.start_time)
            else {
                continue;
            };
            let identity_id = row
                .identity_id
                .as_deref()
                .and_then(|s| s.parse::<i64>().ok());
            let (signed, ai_safe) = identity_id.map_or((false, false), |i| self.trust_of(i));
            let why = spare_reason(Facts {
                own: is_self(snap),
                never_kill: self.never_kill.check(&row.name, None).is_err(),
                classified: identity_id.is_some(),
                verdict: row.verdict.as_deref(),
                allowed: identity_id.is_some_and(|i| allowed.contains(&i)),
                user_started: row.origin == Some("user"),
                ai_cleared: signed && ai_safe,
                agent: row.origin == Some("agent"),
            });
            if let Some(why) = why {
                *run.spared.entry(why).or_default() += 1;
                if why != "safe" && run.kept.len() < KEPT_LISTED {
                    run.kept
                        .push(json!({ "name": row.name, "path": row.path, "why": why }));
                }
                continue;
            }
            if ctl.terminate(snap.pid, snap.started) == KillOutcome::Terminated {
                let path = row.path.clone().unwrap_or_else(|| row.name.clone());
                let publisher = self.publisher_of(row.identity_id.as_deref());
                let at = now();
                run.held
                    .entry(key(&path))
                    .and_modify(|h| h.killed_at.clone_from(&at))
                    .or_insert_with(|| held_from(&row, path, publisher, at));
            }
        }
        self.audit(
            actor,
            AuditKind::Kill,
            None,
            &json!({ "phase": "purge", "minutes": minutes, "stopped": run.held.len(), "spared": run.spared }),
        );
        let out = run.report(true);
        self.purge_state().run = Some(run);
        self.emit("enforcement", "event.purge", out.clone());
        Ok(out)
    }

    /// `purge.stop`: end the hold early.
    pub fn purge_stop(&self, actor: &str) -> Value {
        self.purge_finish();
        self.audit(
            actor,
            AuditKind::Kill,
            None,
            &json!({ "phase": "purge_end", "early": true }),
        );
        self.purge_status()
    }

    pub(crate) fn purge_finish(&self) {
        let mut p = self.purge_state();
        if let Some(run) = p.run.take() {
            let out = run.report(false);
            p.last = Some(out.clone());
            drop(p);
            self.emit("enforcement", "event.purge", out);
        }
    }

    /// Observer tick: end an expired hold, else stop whatever the hold is keeping out.
    /// Returns the programs that just became persistent, for the advisor.
    pub fn purge_scan(&self) -> Vec<(String, i64)> {
        let expired = self
            .purge_state()
            .run
            .as_ref()
            .is_some_and(|r| r.began.elapsed() >= r.window);
        if expired {
            self.purge_finish();
            return Vec::new();
        }
        let Some(ctl) = self.control() else {
            return Vec::new();
        };
        if self.purge_state().run.is_none() {
            return Vec::new();
        }
        let mut flagged = Vec::new();
        for snap in ctl.list() {
            let Some(image) = snap.image.as_deref() else {
                continue;
            };
            if is_self(&snap) || self.never_kill.check(image, None).is_err() {
                continue;
            }
            let hit = self
                .purge_state()
                .run
                .as_ref()
                .is_some_and(|r| r.held.contains_key(&key(image)));
            if !hit || ctl.terminate(snap.pid, snap.started) != KillOutcome::Terminated {
                continue;
            }
            let parent = self
                .process_row(snap.pid, &snap.start_time)
                .and_then(|r| r.parent_path);
            let mut p = self.purge_state();
            let Some(h) = p.run.as_mut().and_then(|r| r.held.get_mut(&key(image))) else {
                continue;
            };
            h.respawns += 1;
            h.last_respawn = Some(now());
            if parent.is_some() {
                h.parent = parent;
            }
            if h.respawns >= FLAG_AT && !h.flagged {
                h.flagged = true;
                if let Some(id) = h.identity.as_deref().and_then(|s| s.parse().ok()) {
                    flagged.push((key(image), id));
                }
            }
        }
        flagged
    }

    /// Ask the advisor what a persistent program is; the answer is stored on its row.
    pub async fn purge_review(self: Arc<Self>, k: String, identity: i64) {
        let opinion = match self.ai_assess(identity, true).await {
            Ok((a, ..)) => crate::ai::opinion_json(&a.opinion, a.cached),
            Err(f) => json!({ "unavailable": f.code() }),
        };
        let mut p = self.purge_state();
        let slot = p
            .run
            .as_mut()
            .and_then(|r| r.held.get_mut(&k))
            .map(|h| &mut h.ai);
        if let Some(slot) = slot {
            *slot = Some(opinion);
        }
    }
}

fn held_from(row: &ProcRow, path: String, publisher: Option<String>, at: String) -> Held {
    Held {
        name: row.name.clone(),
        path,
        identity: row.identity_id.clone(),
        verdict: row.verdict.clone(),
        score: row.score,
        publisher,
        parent: row.parent_path.clone(),
        origin: row.origin,
        killed_at: at,
        respawns: 0,
        last_respawn: None,
        flagged: false,
        ai: None,
    }
}

#[cfg(test)]
mod tests {
    use super::{Facts, spare_reason};

    #[test]
    fn only_untrusted_unproven_processes_are_stopped() {
        let base = Facts {
            classified: true,
            verdict: Some("unknown"),
            ..Facts::default()
        };
        let r = |f: Facts<'_>| spare_reason(f);
        assert_eq!(r(Facts { own: true, ..base }), Some("self"));
        assert_eq!(
            r(Facts {
                never_kill: true,
                ..base
            }),
            Some("never_kill")
        );
        assert_eq!(
            r(Facts {
                classified: false,
                ..base
            }),
            Some("unclassified")
        );
        assert_eq!(
            r(Facts {
                verdict: Some("safe"),
                ..base
            }),
            Some("safe")
        );
        assert_eq!(
            r(Facts {
                allowed: true,
                ..base
            }),
            Some("allowed")
        );
        assert_eq!(
            r(Facts {
                user_started: true,
                ..base
            }),
            Some("user")
        );
        assert_eq!(
            r(Facts {
                ai_cleared: true,
                ..base
            }),
            Some("ai_cleared")
        );
        assert_eq!(
            r(Facts {
                agent: true,
                ..base
            }),
            Some("agent")
        );
        assert_eq!(r(base), None);
        // Only real evidence of harm defeats the soft reasons.
        let bad = Facts {
            verdict: Some("malicious"),
            ..base
        };
        for soft in [
            Facts {
                user_started: true,
                ..bad
            },
            Facts {
                ai_cleared: true,
                ..bad
            },
            Facts { agent: true, ..bad },
        ] {
            assert_eq!(r(soft), None);
        }
    }
}

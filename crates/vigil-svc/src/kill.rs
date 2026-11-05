//! Kill, anti-respawn and enforce-mode auto-kill (docs/04 §3-§4).
//!
//! Platform access goes through [`ProcessControl`] so the policy is testable with a fake.

use std::collections::HashSet;
use std::sync::{Arc, PoisonError};

use serde_json::{Value, json};
use vigil_core::analysis::path::basename;
use vigil_core::audit::AuditKind;
use vigil_core::kill::{Node, Refusal, tree_order};
use vigil_core::storm;
use vigil_ipc::proto::{INVALID_PARAMS, NOT_FOUND, RpcError};
use vigil_store::{blocks, repo};

use crate::state::{ProcRow, Shared, now};

/// Names of Vigil's own binaries; these are never killed (HA-001).
const SELF_IMAGES: [&str; 4] = ["vigil-svc.exe", "vigil.exe", "vigilctl.exe", "vigil-ui.exe"];

/// A live process as the kill logic sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snap {
    pub pid: u32,
    pub ppid: u32,
    /// Creation time, 100 ns ticks since 1601.
    pub started: u64,
    /// RFC 3339 form of `started` (the identity clients pass back).
    pub start_time: String,
    pub image: Option<String>,
}

/// Result of one terminate attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillOutcome {
    Terminated,
    Gone,
    AccessDenied,
    Failed,
}

/// Platform process operations.
pub trait ProcessControl: Send + Sync {
    fn list(&self) -> Vec<Snap>;
    /// Terminate `pid` only if its start time still equals `started`.
    fn terminate(&self, pid: u32, started: u64) -> KillOutcome;
    fn sha256(&self, path: &str) -> Option<String>;
    /// Modules loaded by `pid`; `None` when the platform refuses (protected process, missing privilege).
    fn modules(&self, _pid: u32) -> Option<Vec<String>> {
        None
    }
    /// Persistence entries currently present on the machine.
    fn persist_scan(&self) -> Vec<vigil_store::persistence::Found>;
    /// Disable an entry; returns the backup that [`Self::persist_restore`] needs.
    fn persist_disable(&self, kind: &str, location: &str) -> Result<String, String>;
    fn persist_restore(&self, kind: &str, location: &str, backup: &str) -> Result<(), String>;
    fn persist_delete(&self, kind: &str, location: &str) -> Result<(), String>;
}

fn action(ok: bool, code: Option<&str>, detail: &str) -> Value {
    json!({ "ok": ok, "error_code": code, "detail": detail })
}

fn is_self(snap: &Snap) -> bool {
    snap.pid == std::process::id()
        || snap.image.as_deref().is_some_and(|i| {
            SELF_IMAGES
                .iter()
                .any(|n| basename(i).eq_ignore_ascii_case(n))
        })
}

/// Unix seconds of an RFC 3339 start time, `0` when it cannot be read.
fn storm_procs(rows: &[ProcRow]) -> Vec<storm::Proc<'_>> {
    rows.iter()
        .map(|r| storm::Proc {
            pid: r.pid,
            ppid: r.ppid,
            name: &r.name,
            path: r.path.as_deref(),
            born: born_secs(&r.start_time),
        })
        .collect()
}

fn born_secs(start_time: &str) -> i64 {
    time::OffsetDateTime::parse(start_time, &time::format_description::well_known::Rfc3339)
        .map_or(0, time::OffsetDateTime::unix_timestamp)
}

impl Shared {
    pub fn attach_control(&self, c: Arc<dyn ProcessControl>) {
        *self
            .control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(c);
    }

    pub(crate) fn control(&self) -> Option<Arc<dyn ProcessControl>> {
        self.control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Whether the process image carries a valid Authenticode signature.
    fn is_signed(&self, row: &ProcRow) -> bool {
        let Some(id) = row
            .identity_id
            .as_deref()
            .and_then(|s| s.parse::<i64>().ok())
        else {
            return false;
        };
        self.with_store(|c| repo::executable_by_id(c, id))
            .and_then(Result::ok)
            .flatten()
            .is_some_and(|e| e.signature_status.starts_with("valid"))
    }

    /// Hard rule that fired for this identity, if any.
    fn hard_rule_of(&self, identity: Option<&str>) -> Option<String> {
        let id: i64 = identity?.parse().ok()?;
        self.with_store(|c| repo::latest_evaluation(c, id))?
            .ok()??
            .hard_rule
    }

    /// SG-001 and self-protection for one live process.
    fn refusal(&self, snap: &Snap, hard_rule: Option<&str>) -> Option<Refusal> {
        if is_self(snap) {
            return Some(Refusal::SelfProcess);
        }
        let name = snap.image.as_deref().unwrap_or("");
        self.never_kill.check(name, hard_rule).err()
    }

    /// `process.modules`: files loaded by one live process, on demand and capped, so it costs nothing at idle.
    pub fn process_modules(&self, params: &Value) -> Result<Value, RpcError> {
        const CAP: usize = 200;
        let bad = |m: &str| RpcError::new(INVALID_PARAMS, m);
        let pid = params
            .get("pid")
            .and_then(Value::as_u64)
            .and_then(|p| u32::try_from(p).ok())
            .ok_or_else(|| bad("pid is required"))?;
        let start = params
            .get("start_time")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("start_time is required"))?;
        self.process_row(pid, start)
            .ok_or_else(|| RpcError::new(NOT_FOUND, "no such process"))?;
        let Some(mut paths) = self.control().and_then(|c| c.modules(pid)) else {
            return Ok(json!({ "access": "denied", "items": [], "truncated": false }));
        };
        let truncated = paths.len() > CAP;
        paths.truncate(CAP);
        let items: Vec<Value> = paths
            .iter()
            .map(|p| json!({ "name": basename(p), "path": p }))
            .collect();
        Ok(json!({ "access": "ok", "items": items, "truncated": truncated }))
    }

    /// `process.kill`: kill (optionally the tree), then persist a deny and a respawn watch.
    pub fn kill_process(&self, params: &Value, actor: &str) -> Result<Value, RpcError> {
        let bad = |m: &str| RpcError::new(INVALID_PARAMS, m);
        let pid = params
            .get("pid")
            .and_then(Value::as_u64)
            .and_then(|p| u32::try_from(p).ok())
            .ok_or_else(|| bad("pid is required"))?;
        let start = params
            .get("start_time")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("start_time is required"))?;
        let tree = params.get("tree").and_then(Value::as_bool).unwrap_or(false);
        let block = params.get("block").and_then(Value::as_bool).unwrap_or(true);
        let ctl = self.control().ok_or_else(|| {
            RpcError::new(
                vigil_ipc::proto::INVALID_STATE,
                "process control unavailable",
            )
        })?;
        let snaps = ctl.list();
        let root = snaps
            .iter()
            .find(|s| s.pid == pid && s.start_time == start)
            .ok_or_else(|| RpcError::new(NOT_FOUND, "no such process"))?;
        let row = self.process_row(pid, start);
        let identity = row.as_ref().and_then(|r| r.identity_id.clone());
        let hard = self.hard_rule_of(identity.as_deref());
        let image = root.image.clone().unwrap_or_default();

        if let Some(why) = self.refusal(root, hard.as_deref()) {
            self.audit(
                actor,
                AuditKind::Kill,
                Some(&image),
                &json!({ "pid": pid, "result": "refused", "reason": format!("{why:?}") }),
            );
            return Ok(action(
                false,
                Some("protected_target"),
                "process is protected",
            ));
        }

        let nodes: Vec<Node> = snaps
            .iter()
            .map(|s| Node {
                pid: s.pid,
                ppid: s.ppid,
                started: s.started,
            })
            .collect();
        let order = if tree {
            tree_order(pid, &nodes)
        } else {
            vec![pid]
        };
        self.audit(
            actor,
            AuditKind::Kill,
            Some(&image),
            &json!({ "pid": pid, "tree": tree, "block": block, "targets": order, "phase": "before" }),
        );
        let mut denied = false;
        let mut failed = false;
        for p in &order {
            let Some(s) = snaps.iter().find(|s| s.pid == *p) else {
                continue;
            };
            // A tree member that is itself protected is skipped, never killed.
            if *p != pid && self.refusal(s, None).is_some() {
                continue;
            }
            match ctl.terminate(*p, s.started) {
                KillOutcome::Terminated | KillOutcome::Gone => {}
                KillOutcome::AccessDenied => denied = true,
                KillOutcome::Failed => failed = true,
            }
        }
        if block {
            self.deny_identity(identity.as_deref(), &image, ctl.as_ref());
        }
        self.audit(
            actor,
            AuditKind::Kill,
            Some(&image),
            &json!({ "pid": pid, "phase": "after", "access_denied": denied, "failed": failed }),
        );
        Ok(if denied {
            action(
                false,
                Some("protected_target"),
                "access denied; deny rule added",
            )
        } else if failed {
            action(false, Some("internal"), "terminate failed")
        } else {
            action(true, None, "terminated")
        })
    }

    /// Persistent deny (`kill`, forever) plus a respawn-watch record for this image.
    fn deny_identity(&self, identity: Option<&str>, path: &str, ctl: &dyn ProcessControl) {
        let id: Option<i64> = identity.and_then(|i| i.parse().ok());
        let sha = id
            .and_then(|i| {
                self.with_store(|c| repo::executable_by_id(c, i))
                    .and_then(Result::ok)
                    .flatten()
                    .map(|e| e.sha256)
            })
            .or_else(|| ctl.sha256(path));
        if let Some(sha) = sha {
            let ts = now();
            let _ = self.with_store(|c| blocks::upsert(c, id, &sha, path, "kill", &ts));
        }
        if id.is_some() {
            let r = self.submit_decision(&json!({
                "identity_id": identity, "action": "kill", "scope": "forever",
                "apply_to": "file", "note": "process.kill",
            }));
            if let Err(e) = r {
                tracing::warn!(error = %e.message, "could not record kill decision");
            }
        }
    }

    /// Kill any running copy of a blocked image (matched by path or hash). Returns kill count.
    pub fn respawn_scan(&self) -> usize {
        let Some(ctl) = self.control() else { return 0 };
        let ids: Vec<i64> = self
            .with_store(|c| blocks::active(c).map(|b| b.iter().map(|b| b.id).collect()))
            .and_then(Result::ok)
            .unwrap_or_default();
        if ids.is_empty() {
            return 0;
        }
        let mut killed = 0;
        let snaps = ctl.list();
        {
            // Forget exited processes so the memo stays the size of the process table.
            let live: HashSet<(u32, u64)> = snaps.iter().map(|s| (s.pid, s.started)).collect();
            let mut seen = self
                .respawn_seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            seen.1.retain(|k| live.contains(k));
        }
        for s in snaps {
            let Some(image) = s.image.clone() else {
                continue;
            };
            if is_self(&s) {
                continue;
            }
            // A process is checked once per block set: a new block clears the memo, a new process is new.
            let fresh = {
                let mut seen = self
                    .respawn_seen
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                if seen.0 != ids {
                    *seen = (ids.clone(), HashSet::new());
                }
                seen.1.insert((s.pid, s.started))
            };
            if !fresh {
                continue;
            }
            let hit = self
                .with_store(|c| {
                    let by_path = blocks::find(c, &image, None)?;
                    if by_path.is_some() {
                        return Ok(by_path);
                    }
                    blocks::find(c, &image, ctl.sha256(&image).as_deref())
                })
                .and_then(|r: Result<_, vigil_store::StoreError>| r.ok())
                .flatten();
            let Some(b) = hit else { continue };
            if self.never_kill.check(&image, None).is_err() {
                continue;
            }
            if ctl.terminate(s.pid, s.started) == KillOutcome::Terminated {
                killed += 1;
                let _ = self.with_store(|c| blocks::count_respawn_kill(c, b.id));
                self.audit(
                    "service",
                    AuditKind::RespawnKill,
                    Some(&image),
                    &json!({ "pid": s.pid, "block_id": b.id }),
                );
            }
        }
        killed
    }

    /// In `enforce`, kill processes whose *rule-based* verdict is Malicious (never AI-only).
    pub fn auto_kill_malicious(&self) -> usize {
        if self.mode_and_health().0 != "enforce" {
            return 0;
        }
        let mut n = 0;
        for row in self.rows_with_verdict("malicious") {
            if !self.rule_based_malicious(&row) {
                continue;
            }
            let ok = self
                .kill_process(
                    &json!({ "pid": row.pid, "start_time": row.start_time, "block": true }),
                    "service",
                )
                .ok()
                .and_then(|v| v["ok"].as_bool())
                .unwrap_or(false);
            n += usize::from(ok);
        }
        n
    }

    /// Not-yet-Safe parents with a few copies or script hosts: below every kill threshold, so the
    /// advisor decides case by case (`storm_review`). Safe and never-kill programs are not asked about.
    pub(crate) fn storm_suspects(&self) -> Vec<(ProcRow, usize)> {
        let rows = self.all_rows();
        let procs = storm_procs(&rows);
        let signed_clones = storm::detect(&procs)
            .into_iter()
            .filter(|(pid, kind)| {
                *kind == storm::Storm::Replication
                    && rows.iter().any(|r| r.pid == *pid && self.is_signed(r))
            })
            .map(|(pid, _)| (pid, storm::SUSPECT_CHILDREN as usize));
        storm::suspects(&procs)
            .into_iter()
            .chain(signed_clones)
            .filter_map(|(pid, n)| {
                let row = rows.iter().find(|r| r.pid == pid)?;
                (row.verdict.as_deref() != Some("safe")
                    && self.never_kill.check(&row.name, None).is_ok())
                .then(|| (row.clone(), n))
            })
            .collect()
    }

    /// In every mode, stop programs that clone themselves or flood the machine with script hosts:
    /// reclassify them Malicious (a hijacked Safe program included), kill the whole tree and block
    /// the image. Sibling clones of a verified-safe program (browsers) and the never-kill set are exempt.
    pub fn storm_scan(&self) -> usize {
        let rows = self.all_rows();
        let procs = storm_procs(&rows);
        let mut n = 0;
        for (pid, kind) in storm::detect(&procs) {
            let Some(row) = rows.iter().find(|r| r.pid == pid) else {
                continue;
            };
            let safe = row.verdict.as_deref() == Some("safe");
            // Electron/Chromium apps legitimately fork many copies of themselves: a validly signed
            // image is left to the advisor review (`storm_suspects`), never killed on count alone.
            if (kind == storm::Storm::Replication && (safe || self.is_signed(row)))
                || self.never_kill.check(&row.name, None).is_err()
            {
                continue;
            }
            self.reclassify_storm(row, &format!("{kind:?}"));
            let ok = self
                .kill_process(
                    &json!({ "pid": row.pid, "start_time": row.start_time, "tree": true, "block": true }),
                    "service",
                )
                .ok()
                .and_then(|v| v["ok"].as_bool())
                .unwrap_or(false);
            if ok {
                tracing::warn!(pid, ?kind, "stopped a process storm");
            }
            n += usize::from(ok);
        }
        n
    }

    /// Behaviour overrides reputation: record a Malicious rule-sourced evaluation for the identity.
    pub(crate) fn reclassify_storm(&self, row: &ProcRow, detail: &str) {
        if row.verdict.as_deref() == Some("malicious") {
            return;
        }
        let Some(identity) = row.identity_id.as_deref() else {
            return;
        };
        let Ok(id) = identity.parse::<i64>() else {
            return;
        };
        let signal = json!([{ "id": "STM-001", "name": "Process storm", "delta": -50,
                              "detail": detail }]);
        let stored = self.with_store(|c| {
            repo::insert_evaluation(
                c,
                id,
                &repo::NewEvaluation {
                    score: 0,
                    verdict: "malicious".into(),
                    hard_rule: None,
                    signals_json: signal.to_string(),
                    rule_pack_version: "behavior".into(),
                    source: "rules".into(),
                },
                &now(),
            )
        });
        if stored.is_some_and(|r| r.is_ok()) {
            let _ = self.apply_evaluation(
                row.path.as_deref().unwrap_or(&row.name),
                row.parent_path.as_deref(),
                identity,
                "malicious",
                0,
                None,
            );
            self.raise_malicious(identity);
        }
    }

    fn rule_based_malicious(&self, row: &ProcRow) -> bool {
        let Some(id) = row
            .identity_id
            .as_deref()
            .and_then(|i| i.parse::<i64>().ok())
        else {
            return false;
        };
        self.with_store(|c| repo::latest_evaluation(c, id))
            .and_then(Result::ok)
            .flatten()
            .is_some_and(|e| e.source == "rules" && e.verdict == "malicious")
    }
}

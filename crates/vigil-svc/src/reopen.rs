//! Re-open of a killed program by the user (`docs/18 §4`): freeze it, ask once, then resume or kill.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use time::OffsetDateTime;
use vigil_core::audit::AuditKind;
use vigil_ipc::proto::{INVALID_PARAMS, NOT_FOUND, RpcError};
use vigil_store::decisions;

use crate::kill::{KillOutcome, Snap};
use crate::state::Shared;

/// Seconds the user has to answer before the frozen copy is killed (fail closed).
pub const ANSWER_SECS: u64 = 60;
/// Same program is never asked about twice within this window.
const PER_PROGRAM: Duration = Duration::from_secs(600);
/// Never more than one prompt in this window, whatever the program.
const GLOBAL: Duration = Duration::from_secs(5);
/// "Keep stopped" silences that program's prompt for this long.
const SILENCE: Duration = Duration::from_secs(24 * 3600);

struct Waiting {
    started: u64,
    block_id: i64,
    image: String,
    #[cfg_attr(not(windows), allow(dead_code))]
    deadline: Instant,
}

/// Prompt bookkeeping; lives in [`Shared`].
#[derive(Default)]
pub(crate) struct Reopen {
    waiting: HashMap<(u32, String), Waiting>,
    asked: HashMap<i64, Instant>,
    silenced: HashMap<i64, Instant>,
    last: Option<Instant>,
}

impl Reopen {
    fn may_ask(&self, block_id: i64, now: Instant) -> bool {
        let within =
            |t: Option<&Instant>, d: Duration| t.is_some_and(|t| now.duration_since(*t) < d);
        !within(self.silenced.get(&block_id), SILENCE)
            && !within(self.asked.get(&block_id), PER_PROGRAM)
            && !within(self.last.as_ref(), GLOBAL)
    }
}

impl Shared {
    /// Freeze a user-launched copy of a killed program and ask. `false` = not eligible, caller kills it.
    pub(crate) fn ask_reopen(&self, s: &Snap, image: &str, block_id: i64) -> bool {
        let Some(ctl) = self.control() else {
            return false;
        };
        let row = self
            .all_rows()
            .into_iter()
            .find(|r| r.pid == s.pid && r.start_time == s.start_time);
        if row.is_none_or(|r| r.origin != Some("user")) {
            return false;
        }
        let now = Instant::now();
        let key = (s.pid, s.start_time.clone());
        {
            let mut g = self
                .reopen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !g.may_ask(block_id, now) {
                return false;
            }
            if !ctl.suspend(s.pid, s.started) {
                return false;
            }
            g.last = Some(now);
            g.asked.insert(block_id, now);
            g.waiting.insert(
                key,
                Waiting {
                    started: s.started,
                    block_id,
                    image: image.to_owned(),
                    deadline: now + Duration::from_secs(ANSWER_SECS),
                },
            );
        }
        let decision = self
            .kill_decision_for(image)
            .map(|d| self.decision_detail(&d));
        self.emit(
            "enforcement",
            "event.reopen_prompt",
            json!({
                "pid": s.pid, "start_time": s.start_time, "path": image,
                "answer_within_secs": ANSWER_SECS, "decision": decision,
            }),
        );
        self.audit(
            "service",
            AuditKind::RespawnKill,
            Some(image),
            &json!({ "pid": s.pid, "block_id": block_id, "action": "suspended_for_prompt" }),
        );
        true
    }

    pub(crate) fn kill_decision_for(&self, image: &str) -> Option<decisions::Decision> {
        self.with_store(|c| {
            let all = decisions::list_active(c, OffsetDateTime::now_utc())?;
            for d in all {
                if d.action.as_str() != "kill" {
                    continue;
                }
                if vigil_store::repo::executable_by_id(c, d.executable_id)?
                    .is_some_and(|e| e.path.eq_ignore_ascii_case(image))
                {
                    return Ok(Some(d));
                }
            }
            Ok::<_, vigil_store::StoreError>(None)
        })
        .and_then(Result::ok)
        .flatten()
    }

    /// `reopen.answer`: `allow` lifts the kill and resumes; otherwise the copy is killed and silenced.
    pub fn reopen_answer(&self, params: &Value) -> Result<Value, RpcError> {
        let bad = || RpcError::new(INVALID_PARAMS, "pid, start_time and allow are required");
        let pid = params["pid"]
            .as_u64()
            .and_then(|p| u32::try_from(p).ok())
            .ok_or_else(bad)?;
        let start = params["start_time"].as_str().ok_or_else(bad)?.to_owned();
        let allow = params["allow"].as_bool().ok_or_else(bad)?;
        let w = self
            .reopen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .waiting
            .remove(&(pid, start))
            .ok_or_else(|| RpcError::new(NOT_FOUND, "no such prompt (answered or timed out)"))?;
        let ctl = self
            .control()
            .ok_or_else(|| RpcError::new(NOT_FOUND, "no process control"))?;
        if allow {
            if let Some(d) = self.kill_decision_for(&w.image) {
                self.decision_exception(&json!({ "decision_id": d.id.to_string() }))?;
            }
            ctl.resume(pid, w.started);
            self.audit(
                "user",
                AuditKind::DecisionRevoked,
                Some(&w.image),
                &json!({ "reopen": "allow" }),
            );
        } else {
            self.kill_waiting(&*ctl, pid, &w);
            self.reopen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .silenced
                .insert(w.block_id, Instant::now());
        }
        Ok(json!({}))
    }

    fn kill_waiting(&self, ctl: &dyn crate::kill::ProcessControl, pid: u32, w: &Waiting) {
        if self.protection_paused() {
            return;
        }
        if ctl.terminate(pid, w.started) == KillOutcome::Terminated {
            let _ = self.with_store(|c| vigil_store::blocks::count_respawn_kill(c, w.block_id));
            self.audit(
                "service",
                AuditKind::RespawnKill,
                Some(&w.image),
                &json!({ "pid": pid, "block_id": w.block_id }),
            );
        }
    }

    /// Kill prompts nobody answered in time. Called every tick.
    #[cfg(windows)]
    pub(crate) fn reopen_sweep(&self) {
        let Some(ctl) = self.control() else { return };
        let now = Instant::now();
        let expired: Vec<_> = {
            let mut g = self
                .reopen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let keys: Vec<_> = g
                .waiting
                .iter()
                .filter(|(_, w)| w.deadline <= now)
                .map(|(k, _)| k.clone())
                .collect();
            keys.into_iter()
                .filter_map(|k| g.waiting.remove(&k).map(|w| (k.0, w)))
                .collect()
        };
        for (pid, w) in expired {
            self.kill_waiting(&*ctl, pid, &w);
        }
    }
}

//! PRC-001 in the service (`docs/15 §2`): a process start from ETW whose child is a script host
//! or shell is checked against its parent; a new finding re-evaluates the parent and is audited.

use serde_json::json;
use vigil_core::analysis::path::basename;
use vigil_core::analysis::spawn;
use vigil_core::audit::AuditKind;

use crate::state::Shared;

fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Shared {
    /// `ppid` started `child_image` with `cmdline` (read right after the start event; `None` when
    /// the child already exited or could not be opened). Untrusted strings, compared only.
    pub fn note_spawn(&self, ppid: u32, child_image: &str, cmdline: Option<&str>) {
        let Some(parent) = self.row_by_pid(ppid).and_then(|r| r.path) else {
            return;
        };
        if !spawn::suspicious_child(&parent, child_image, cmdline) {
            return;
        }
        if !lock(&self.spawn_seen).insert(parent.to_ascii_lowercase()) {
            return;
        }
        self.queue_rejudge(&parent);
        // The command line stays out of the audit row: it can carry secrets.
        self.audit(
            "service",
            AuditKind::Verdict,
            Some(&parent),
            &json!({ "signals": ["PRC-001"], "child": basename(child_image) }),
        );
    }

    /// Whether `path` started a suspicious child this run.
    #[must_use]
    pub fn spawned_suspicious_child(&self, path: &str) -> bool {
        lock(&self.spawn_seen).contains(&path.to_ascii_lowercase())
    }
}

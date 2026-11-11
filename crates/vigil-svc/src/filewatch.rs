//! FIL-001/002 and RES-001 in the service (`docs/15 §2`): pre-filtered Kernel-File events are
//! attributed to the program behind the pid; a new finding re-evaluates it once and is audited.

use serde_json::{Value, json};
use vigil_core::analysis::fileact::{self, Access};
use vigil_core::analysis::path::basename;
use vigil_core::audit::AuditKind;
use vigil_core::observe::FileSeen;

use crate::state::Shared;

fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Shared {
    /// `pid` created the executable or script `path` in a user-writable folder (FIL-001).
    pub fn note_file_drop(&self, pid: u32, path: &str) {
        self.mark_file(
            pid,
            "FIL-001",
            |f| &mut f.dropped_executable,
            || json!({ "file": basename(path) }),
        );
    }

    /// `pid` renamed a user file to the double extension `.ext` at `at_ms` (FIL-002 candidate).
    pub fn note_rename(&self, pid: u32, ext: &str, at_ms: u64) {
        if lock(&self.mass_change).note(pid, ext, at_ms) {
            self.mark_file(
                pid,
                "FIL-002",
                |f| &mut f.mass_renamed,
                || json!({ "extension": ext }),
            );
        }
    }

    /// `pid` opened credential store `store` (RES-001 candidate).
    pub fn note_credential_open(&self, pid: u32, store: usize) {
        let Some(path) = self.row_by_pid(pid).and_then(|r| r.path) else {
            return;
        };
        let audit = || json!({ "store": fileact::store_name(store) });
        match fileact::access(store, &path) {
            Access::Allowed => {}
            // Counted by the evaluation only if this program's signature is not valid.
            Access::OwnerNamed => {
                self.mark_path(
                    &path,
                    "RES-001",
                    |f| &mut f.credential_store_as_owner,
                    audit,
                    false,
                );
            }
            Access::Foreign => {
                self.mark_path(
                    &path,
                    "RES-001",
                    |f| &mut f.foreign_credential_store,
                    audit,
                    true,
                );
            }
        }
    }

    /// File findings for `path` this run.
    #[must_use]
    pub fn files_seen(&self, path: &str) -> FileSeen {
        lock(&self.file_seen)
            .get(&path.to_ascii_lowercase())
            .copied()
            .unwrap_or_default()
    }

    fn mark_file(
        &self,
        pid: u32,
        signal: &str,
        flag: fn(&mut FileSeen) -> &mut bool,
        detail: impl FnOnce() -> Value,
    ) {
        if let Some(path) = self.row_by_pid(pid).and_then(|r| r.path) {
            self.mark_path(&path, signal, flag, detail, true);
        }
    }

    /// Set `flag` for `path`; the first time, re-evaluate it and (when `audited`) write a row.
    fn mark_path(
        &self,
        path: &str,
        signal: &str,
        flag: fn(&mut FileSeen) -> &mut bool,
        detail: impl FnOnce() -> Value,
        audited: bool,
    ) {
        {
            let mut seen = lock(&self.file_seen);
            let f = flag(seen.entry(path.to_ascii_lowercase()).or_default());
            if *f {
                return;
            }
            *f = true;
        }
        self.queue_rejudge(path);
        if audited {
            let mut row = detail();
            row["signals"] = json!([signal]);
            self.audit("service", AuditKind::Verdict, Some(path), &row);
        }
    }
}

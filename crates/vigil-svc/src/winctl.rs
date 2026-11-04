//! Windows [`ProcessControl`]: snapshot via `ToolHelp`, terminate via `vigil-win`.

use std::path::Path;

use vigil_store::persistence::Found;
use vigil_win::hash::HashCache;
use vigil_win::kill::{Outcome, terminate};
use vigil_win::{persist, process};

use crate::kill::{KillOutcome, ProcessControl, Snap};
use crate::observer::start_time;

#[derive(Default)]
pub struct WinControl {
    hashes: HashCache,
}

impl ProcessControl for WinControl {
    fn list(&self) -> Vec<Snap> {
        process::snapshot()
            .unwrap_or_default()
            .into_iter()
            .map(|p| Snap {
                pid: p.pid,
                ppid: p.ppid,
                started: p.start_time.unwrap_or(0),
                start_time: start_time(p.start_time),
                image: p.image,
            })
            .collect()
    }

    fn terminate(&self, pid: u32, started: u64) -> KillOutcome {
        match terminate(pid, started) {
            Outcome::Terminated => KillOutcome::Terminated,
            Outcome::Gone => KillOutcome::Gone,
            Outcome::AccessDenied => KillOutcome::AccessDenied,
            Outcome::Failed => KillOutcome::Failed,
        }
    }

    fn sha256(&self, path: &str) -> Option<String> {
        self.hashes.sha256(Path::new(path)).ok()
    }

    fn persist_scan(&self) -> Vec<Found> {
        persist::scan()
            .into_iter()
            .map(|f| Found {
                kind: f.kind.into(),
                location: f.location,
                image_path: f.image_path,
                command: f.command,
                risk_note: f.risk_note,
            })
            .collect()
    }

    fn persist_disable(&self, kind: &str, location: &str) -> Result<String, String> {
        persist::disable(kind, location)
    }

    fn persist_restore(&self, kind: &str, location: &str, backup: &str) -> Result<(), String> {
        persist::restore(kind, location, backup)
    }

    fn persist_delete(&self, kind: &str, location: &str) -> Result<(), String> {
        persist::delete(kind, location)
    }
}

//! Windows [`ProcessControl`]: snapshot via `ToolHelp`, terminate via `vigil-win`.

use std::path::Path;

use vigil_store::persistence::Found;
use vigil_win::hash::HashCache;
use vigil_win::kill::{Outcome, resume, suspend, terminate};
use vigil_win::{persist, process};

use crate::kill::{KillOutcome, ProcessControl, Snap};
use crate::observer::start_time;

/// DPAPI (machine scope + per-install entropy) key sealing for the AI key.
pub struct DpapiVault;

impl crate::ai::KeyVault for DpapiVault {
    fn seal(&self, plain: &[u8], entropy: &[u8]) -> Result<Vec<u8>, String> {
        vigil_win::dpapi::protect(plain, entropy).map_err(|e| e.to_string())
    }
    fn unseal(&self, cipher: &[u8], entropy: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
        vigil_win::dpapi::unprotect(cipher, entropy)
            .map(zeroize::Zeroizing::new)
            .map_err(|e| e.to_string())
    }
}

#[derive(Default)]
pub struct WinControl {
    hashes: HashCache,
    /// Image path and start time are resolved once per process, so a listing is cheap.
    watcher: std::sync::Mutex<process::Watcher>,
    /// Signature validity of each `ServiceDll`, checked once per path.
    dll_signed: std::sync::Mutex<std::collections::HashMap<String, bool>>,
}

impl ProcessControl for WinControl {
    fn list(&self) -> Vec<Snap> {
        self.watcher
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .poll()
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

    fn suspend(&self, pid: u32, started: u64) -> bool {
        suspend(pid, started)
    }

    fn resume(&self, pid: u32, started: u64) -> bool {
        resume(pid, started)
    }

    fn modules(&self, pid: u32) -> Option<Vec<String>> {
        vigil_win::modules::module_paths(pid)
    }

    fn cpu_ticks(&self, pid: u32) -> Option<u64> {
        Some(vigil_win::process::usage(pid).1).filter(|t| *t > 0)
    }

    fn sha256(&self, path: &str) -> Option<String> {
        self.hashes.sha256(Path::new(path)).ok()
    }

    fn services(&self) -> Vec<vigil_core::service::HostedService> {
        let Ok(ctx) = vigil_win::observe::env_context() else {
            return Vec::new();
        };
        let mut cache = self
            .dll_signed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        vigil_win::services::hosted(&ctx.path_env, &mut |dll| {
            *cache
                .entry(dll.to_lowercase())
                .or_insert_with(|| vigil_win::services::is_signed(dll))
        })
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

//! WFP-backed [`FilterEngine`]: permits and the catch-all live in a dynamic session (they vanish
//! if the service dies), explicit denies in a persistent one (docs/04 §1).

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::mpsc::UnboundedSender;
use vigil_win::wfp::Engine;
use vigil_win::wfp::ids::{self, FilterKind};

use crate::enforce::{DropInfo, FilterEngine};

pub struct WfpEngine {
    dynamic: Arc<Engine>,
    persistent: Engine,
    permitted: Mutex<BTreeSet<PathBuf>>,
    denied: Mutex<BTreeSet<PathBuf>>,
}

impl WfpEngine {
    /// Open both sessions; fails without administrator rights.
    pub fn open() -> Result<Self, String> {
        Ok(Self {
            dynamic: Arc::new(Engine::open_dynamic().map_err(|e| e.to_string())?),
            persistent: Engine::open_persistent().map_err(|e| e.to_string())?,
            permitted: Mutex::new(BTreeSet::new()),
            denied: Mutex::new(BTreeSet::new()),
        })
    }
}

impl FilterEngine for WfpEngine {
    fn set_denies(&self, denies: &[PathBuf]) -> Result<(), String> {
        let want: BTreeSet<PathBuf> = denies.iter().cloned().collect();
        let mut have = self.denied.lock().unwrap_or_else(PoisonError::into_inner);
        self.persistent
            .transaction(|tx| {
                for p in want.difference(&have) {
                    tx.put_deny(p)?;
                }
                Ok(())
            })
            .map_err(|e| e.to_string())?;
        for p in have.difference(&want) {
            self.persistent
                .remove_identity(&ids::path_identity_key(p), FilterKind::Deny)
                .map_err(|e| e.to_string())?;
        }
        *have = want;
        Ok(())
    }

    fn arm(&self, permits: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
        let report = self
            .dynamic
            .rebuild_then_arm(permits)
            .map_err(|e| e.to_string())?;
        let want: BTreeSet<PathBuf> = permits
            .iter()
            .filter(|p| !report.skipped.contains(p))
            .cloned()
            .collect();
        let mut have = self
            .permitted
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for p in have.difference(&want) {
            self.dynamic
                .remove_identity(&ids::path_identity_key(p), FilterKind::Permit)
                .map_err(|e| e.to_string())?;
        }
        *have = want;
        Ok(report.skipped)
    }

    fn disarm(&self) -> Result<(), String> {
        self.dynamic
            .remove_all_dynamic()
            .map_err(|e| e.to_string())?;
        self.permitted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        Ok(())
    }

    fn panic(&self) -> usize {
        let r = self.dynamic.panic_remove_all();
        self.permitted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        self.denied
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        r.removed
    }

    fn watch_drops(&self, tx: UnboundedSender<DropInfo>) -> Result<(), String> {
        let engine = Arc::clone(&self.dynamic);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("vigil-net-events".into())
            .spawn(move || match engine.subscribe_drops() {
                Ok((_subscription, mut rx)) => {
                    let _ = ready_tx.send(Ok(()));
                    while let Some(e) = rx.blocking_recv() {
                        let info = DropInfo {
                            app_path: e.app_path,
                            remote_addr: e.remote_addr.to_string(),
                            remote_port: e.remote_port,
                        };
                        if tx.send(info).is_err() {
                            break;
                        }
                    }
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e.to_string()));
                }
            })
            .map_err(|e| e.to_string())?;
        ready_rx.recv().map_err(|e| e.to_string())?
    }
}

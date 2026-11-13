//! WFP-backed [`FilterEngine`]: permits and the catch-all live in a dynamic session (they vanish
//! if the service dies), explicit denies in a persistent one (docs/04 §1).

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::mpsc::UnboundedSender;
use vigil_win::wfp::ids::{self, FilterKind};
use vigil_win::wfp::{Engine, Scope};

use crate::enforce::{DropInfo, FilterEngine, Tampered};

pub struct WfpEngine {
    dynamic: Arc<Engine>,
    persistent: Engine,
    held: Arc<Held>,
}

/// What Vigil believes it has installed. Vigil updates it under the same lock as its own filter
/// removals, so a deletion of a key still listed here was made by another program.
#[derive(Default)]
struct Held {
    permitted: Mutex<BTreeSet<PathBuf>>,
    /// `None` until the first sync: persistent denies from an earlier run are still installed.
    /// The flag says whether the inbound denies (FR-017) are installed too.
    denied: Mutex<Option<(BTreeSet<PathBuf>, bool)>>,
    /// Per-service denies `(name, SID)`; `None` until the first sync, like `denied`.
    services: Mutex<Option<BTreeSet<(String, String)>>>,
    /// Catch-all and loopback filters are installed.
    armed: AtomicBool,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Which of `kinds` has a filter for `identity` with this `key`.
fn kind_of(key: &[u8; 16], identity: &str, kinds: &[FilterKind]) -> Option<FilterKind> {
    kinds
        .iter()
        .copied()
        .find(|k| ids::filter_keys(identity, *k).contains(key))
}

impl Held {
    /// If `key` belongs to a filter Vigil still holds, forget that item (so the next sync puts it
    /// back) and describe it.
    fn claim(&self, key: &[u8; 16]) -> Option<Tampered> {
        let tampered = |kind: FilterKind, target: String| Tampered {
            filter: kind.tag(),
            target,
        };
        if self.armed.load(Ordering::Acquire) {
            for (identity, kind) in [
                (ids::CATCH_ALL_IDENTITY, FilterKind::CatchAll),
                (ids::LOOPBACK_IDENTITY, FilterKind::Loopback),
            ] {
                if kind_of(key, identity, &[kind]).is_some() {
                    return Some(tampered(kind, String::new()));
                }
            }
        }
        if let Some((denied, inbound)) = lock(&self.denied).as_mut() {
            let kinds: &[FilterKind] = if *inbound {
                &[FilterKind::Deny, FilterKind::InboundDeny]
            } else {
                &[FilterKind::Deny]
            };
            let found = denied.iter().find_map(|p| {
                kind_of(key, &ids::path_identity_key(p), kinds).map(|k| (p.clone(), k))
            });
            if let Some((p, kind)) = found {
                denied.remove(&p);
                return Some(tampered(kind, p.display().to_string()));
            }
        }
        if let Some(services) = lock(&self.services).as_mut() {
            let found = services
                .iter()
                .find(|(name, _)| {
                    let identity = ids::service_identity_key(name);
                    kind_of(key, &identity, &[FilterKind::ServiceDeny]).is_some()
                })
                .cloned();
            if let Some(item) = found {
                services.remove(&item);
                return Some(tampered(FilterKind::ServiceDeny, item.0));
            }
        }
        let mut permitted = lock(&self.permitted);
        let found = permitted
            .iter()
            .find(|p| kind_of(key, &ids::path_identity_key(p), &[FilterKind::Permit]).is_some())
            .cloned();
        found.map(|p| {
            permitted.remove(&p);
            tampered(FilterKind::Permit, p.display().to_string())
        })
    }
}

/// `%SystemRoot%\System32\svchost.exe`, the host every shared service runs in.
fn svchost() -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    PathBuf::from(root).join("System32").join("svchost.exe")
}

impl WfpEngine {
    /// Open both sessions; fails without administrator rights.
    pub fn open() -> Result<Self, String> {
        Ok(Self {
            dynamic: Arc::new(Engine::open_dynamic().map_err(|e| e.to_string())?),
            persistent: Engine::open_persistent().map_err(|e| e.to_string())?,
            held: Arc::default(),
        })
    }
}

impl FilterEngine for WfpEngine {
    fn set_denies(&self, denies: &[PathBuf], inbound: bool) -> Result<(), String> {
        let want: BTreeSet<PathBuf> = denies.iter().cloned().collect();
        let mut slot = lock(&self.held.denied);
        if slot.is_none() {
            // Denies outlive the process: drop the ones a previous run left behind (a revoked
            // block must not keep an app offline after a restart).
            let stale = self
                .persistent
                .list_filters(Scope::Persistent)
                .map_err(|e| e.to_string())?;
            let ours = |name: &str| {
                name.starts_with("Vigil Deny") || name.starts_with("Vigil InboundDeny")
            };
            for f in stale.iter().filter(|f| ours(&f.name)) {
                self.persistent
                    .remove_filter(&f.key)
                    .map_err(|e| e.to_string())?;
            }
        }
        let (have, had_inbound) = slot.get_or_insert_with(|| (BTreeSet::new(), false));
        // Paths whose inbound filter must appear: new denies, or every deny when just turned on.
        let add_inbound: Vec<&PathBuf> = match (inbound, *had_inbound) {
            (false, _) => Vec::new(),
            (true, true) => want.difference(have).collect(),
            (true, false) => want.iter().collect(),
        };
        self.persistent
            .transaction(|tx| {
                for p in want.difference(have) {
                    tx.put_deny(p)?;
                }
                for p in &add_inbound {
                    tx.put_inbound_deny(p)?;
                }
                Ok(())
            })
            .map_err(|e| e.to_string())?;
        for p in have.difference(&want) {
            self.persistent
                .remove_identity(&ids::path_identity_key(p), FilterKind::Deny)
                .map_err(|e| e.to_string())?;
        }
        // Inbound filters to drop: revoked denies, or all of them when just turned off.
        let drop_inbound: Vec<&PathBuf> = match (inbound, *had_inbound) {
            (_, false) => Vec::new(),
            (true, true) => have.difference(&want).collect(),
            (false, true) => have.iter().collect(),
        };
        for p in drop_inbound {
            self.persistent
                .remove_identity(&ids::path_identity_key(p), FilterKind::InboundDeny)
                .map_err(|e| e.to_string())?;
        }
        *have = want;
        *had_inbound = inbound;
        Ok(())
    }

    fn set_service_denies(&self, services: &[(String, String)]) -> Result<(), String> {
        let want: BTreeSet<(String, String)> = services.iter().cloned().collect();
        let mut slot = lock(&self.held.services);
        if slot.is_none() {
            let stale = self
                .persistent
                .list_filters(Scope::Persistent)
                .map_err(|e| e.to_string())?;
            for f in stale
                .iter()
                .filter(|f| f.name.starts_with("Vigil ServiceDeny"))
            {
                self.persistent
                    .remove_filter(&f.key)
                    .map_err(|e| e.to_string())?;
            }
        }
        let have = slot.get_or_insert_with(BTreeSet::new);
        let host = svchost();
        self.persistent
            .transaction(|tx| {
                for (name, sid) in want.difference(have) {
                    tx.put_service_deny(&host, name, sid)?;
                }
                Ok(())
            })
            .map_err(|e| e.to_string())?;
        for (name, _) in have.difference(&want) {
            self.persistent
                .remove_identity(&ids::service_identity_key(name), FilterKind::ServiceDeny)
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
        let mut have = lock(&self.held.permitted);
        for p in have.difference(&want) {
            self.dynamic
                .remove_identity(&ids::path_identity_key(p), FilterKind::Permit)
                .map_err(|e| e.to_string())?;
        }
        *have = want;
        self.held.armed.store(true, Ordering::Release);
        Ok(report.skipped)
    }

    fn disarm(&self) -> Result<(), String> {
        // Forget first, holding the lock: the removals below are Vigil's own, not tampering.
        self.held.armed.store(false, Ordering::Release);
        let mut permitted = lock(&self.held.permitted);
        permitted.clear();
        self.dynamic
            .remove_all_dynamic()
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn panic(&self) -> usize {
        self.held.armed.store(false, Ordering::Release);
        let mut permitted = lock(&self.held.permitted);
        let mut denied = lock(&self.held.denied);
        let mut services = lock(&self.held.services);
        permitted.clear();
        *denied = None;
        *services = None;
        self.dynamic.panic_remove_all().removed
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

    fn watch_tamper(&self, tx: UnboundedSender<Tampered>) -> Result<(), String> {
        let engine = Arc::clone(&self.dynamic);
        let held = Arc::clone(&self.held);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("vigil-filter-changes".into())
            .spawn(move || match engine.subscribe_filter_deletes() {
                Ok((_subscription, mut rx)) => {
                    let _ = ready_tx.send(Ok(()));
                    while let Some(key) = rx.blocking_recv() {
                        if let Some(t) = held.claim(&key)
                            && tx.send(t).is_err()
                        {
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

//! `service.list` / `service.block_network` and the suspicious-`ServiceDll` alert (FR-021,
//! `docs/04 §3`). A blocked service loses outbound network through a persistent WFP filter keyed
//! on its service SID; the list of blocked names lives in the `settings` table (not the policy, so
//! `settings.set` cannot change it).

use std::collections::{BTreeSet, HashMap};

use serde_json::{Value, json};
use vigil_core::audit::AuditKind;
use vigil_core::service::{HostedService, block_refusal};
use vigil_ipc::proto::{INVALID_PARAMS, RpcError};

use crate::state::Shared;

const BLOCKS_KEY: &str = "service_blocks";
/// Longest service key name the SCM accepts.
const MAX_NAME: usize = 256;

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && !name
            .chars()
            .any(|c| c == '/' || c == '\\' || c.is_control())
}

fn result(ok: bool, code: Option<&str>, detail: &str) -> Value {
    json!({ "ok": ok, "error_code": code, "detail": detail })
}

fn contains(set: &BTreeSet<String>, name: &str) -> bool {
    set.iter().any(|n| n.eq_ignore_ascii_case(name))
}

impl Shared {
    /// Names of services whose network the user blocked.
    pub(crate) fn service_blocks(&self) -> BTreeSet<String> {
        self.with_store(|c| vigil_store::ai::setting_get(c, BLOCKS_KEY))
            .and_then(Result::ok)
            .flatten()
            .and_then(|raw| serde_json::from_slice::<Vec<String>>(&raw).ok())
            .map(|v| v.into_iter().filter(|n| valid_name(n)).collect())
            .unwrap_or_default()
    }

    fn store_service_blocks(&self, blocks: &BTreeSet<String>) -> Result<(), String> {
        let raw = serde_json::to_vec(blocks).map_err(|e| e.to_string())?;
        self.with_store(|c| vigil_store::ai::setting_put(c, BLOCKS_KEY, &raw))
            .ok_or_else(|| "storage unavailable".to_owned())?
            .map_err(|e| e.to_string())
    }

    fn hosted_services(&self) -> Vec<HostedService> {
        self.control().map(|c| c.services()).unwrap_or_default()
    }

    /// Running services (and blocked ones that are not running) with their block state.
    pub fn service_list(&self) -> Value {
        let running = self.hosted_services();
        let blocks = self.service_blocks();
        let mut by_pid: HashMap<u32, Vec<&str>> = HashMap::new();
        for s in running.iter().filter(|s| s.pid != 0) {
            by_pid.entry(s.pid).or_default().push(&s.name);
        }
        let mut items: Vec<Value> = running
            .iter()
            .map(|s| {
                let shared_with: Vec<&str> = by_pid
                    .get(&s.pid)
                    .map(|v| v.iter().copied().filter(|n| *n != s.name).collect())
                    .unwrap_or_default();
                json!({
                    "pid": (s.pid != 0).then_some(s.pid), "name": s.name,
                    "display_name": s.display_name, "dll": s.dll, "suspicious": s.suspicious,
                    "refusal": block_refusal(&s.name, s.sid_type),
                    "network_blocked": contains(&blocks, &s.name), "shared_with": shared_with,
                })
            })
            .collect();
        for name in blocks
            .iter()
            .filter(|b| !running.iter().any(|s| s.name.eq_ignore_ascii_case(b)))
        {
            items.push(json!({
                "pid": null, "name": name, "display_name": name, "dll": null, "suspicious": null,
                "refusal": null, "network_blocked": true, "shared_with": [],
            }));
        }
        json!({ "items": items })
    }

    /// Block or unblock one service's outbound network. Blocking needs the service running (its
    /// SID type is read from the live list) and never touches the network-essential set.
    pub fn service_block_network(&self, params: &Value, actor: &str) -> Result<Value, RpcError> {
        let bad = |m: &str| RpcError::new(INVALID_PARAMS, m);
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .filter(|n| valid_name(n))
            .ok_or_else(|| bad("name must be a service name"))?;
        let block = params
            .get("block")
            .and_then(Value::as_bool)
            .ok_or_else(|| bad("block must be true or false"))?;
        let mut blocks = self.service_blocks();
        let canonical = if block {
            let Some(svc) = self
                .hosted_services()
                .into_iter()
                .find(|s| s.name.eq_ignore_ascii_case(name))
            else {
                return Ok(result(
                    false,
                    Some("not_found"),
                    "the service is not running",
                ));
            };
            if let Some(code) = block_refusal(&svc.name, svc.sid_type) {
                return Ok(result(false, Some(code), "this service cannot be blocked"));
            }
            blocks.insert(svc.name.clone());
            svc.name
        } else {
            let Some(found) = blocks
                .iter()
                .find(|b| b.eq_ignore_ascii_case(name))
                .cloned()
            else {
                return Ok(result(true, None, "not blocked"));
            };
            blocks.remove(&found);
            found
        };
        if let Err(e) = self.store_service_blocks(&blocks) {
            tracing::error!(error = %e, "could not store service blocks");
            return Ok(result(
                false,
                Some("internal"),
                "the change could not be saved",
            ));
        }
        let applied = self.resync_enforcement();
        let kind = if block {
            AuditKind::FilterAdd
        } else {
            AuditKind::FilterRemove
        };
        self.audit(
            actor,
            kind,
            Some(&canonical),
            &json!({ "service": canonical, "block_network": block, "applied": applied.is_ok() }),
        );
        Ok(match applied {
            Ok(()) => result(true, None, if block { "blocked" } else { "unblocked" }),
            Err(e) => {
                tracing::error!(error = %e, service = %canonical, "service filter change failed");
                result(
                    false,
                    Some("internal"),
                    "the filter engine rejected the change",
                )
            }
        })
    }

    /// Report each service whose `ServiceDll` is unsigned or in a writable place, once per run.
    pub fn service_alert_scan(&self) -> usize {
        let mut n = 0;
        for s in self.hosted_services() {
            let (Some(reason), Some(dll)) = (s.suspicious, s.dll.as_deref()) else {
                continue;
            };
            let first = self
                .service_alerted
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(s.name.to_lowercase());
            if first {
                tracing::warn!(service = %s.name, reason, "suspicious service DLL");
                self.emit(
                    "enforcement",
                    "event.service_alert",
                    json!({ "service": s.name, "display_name": s.display_name,
                            "dll": dll, "reason": reason }),
                );
                n += 1;
            }
        }
        n
    }
}

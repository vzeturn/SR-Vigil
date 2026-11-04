//! `persistence.scan` / `persistence.apply` (docs/04 §5): reversible, audited, user-approved.

use serde_json::{Value, json};
use vigil_core::audit::AuditKind;
use vigil_ipc::proto::{INTERNAL_ERROR, INVALID_PARAMS, INVALID_STATE, NOT_FOUND, RpcError};
use vigil_store::persistence::{self, Item};

use crate::state::{Shared, now};

fn store_err(e: impl std::fmt::Display) -> RpcError {
    tracing::error!(error = %e, "store error");
    RpcError::new(INTERNAL_ERROR, "storage error")
}

fn unavailable() -> RpcError {
    RpcError::new(INVALID_STATE, "storage or process control unavailable")
}

fn item_json(i: &Item) -> Value {
    json!({
        "id": i.id.to_string(), "kind": i.kind, "location": i.location,
        "image_path": i.image_path, "command": i.command, "status": i.status,
        "risk_note": i.risk_note, "first_seen": i.first_seen,
    })
}

fn result(ok: bool, code: Option<&str>, detail: &str) -> Value {
    json!({ "ok": ok, "error_code": code, "detail": detail })
}

impl Shared {
    /// Run the scanners, store the findings and return them (optionally for one image).
    pub fn persistence_scan(&self, target: Option<&str>) -> Result<Value, RpcError> {
        let ctl = self.control().ok_or_else(unavailable)?;
        let ts = now();
        let needle = target.map(str::to_lowercase);
        let mut out = Vec::new();
        for f in ctl.persist_scan() {
            if let Some(n) = &needle {
                let hit = f
                    .image_path
                    .as_deref()
                    .is_some_and(|p| p.to_lowercase() == *n)
                    || f.command
                        .as_deref()
                        .is_some_and(|c| c.to_lowercase().contains(n));
                if !hit {
                    continue;
                }
            }
            let item = self
                .with_store(|c| persistence::upsert(c, &f, &ts))
                .ok_or_else(unavailable)?
                .map_err(store_err)?;
            out.push(item_json(&item));
        }
        Ok(json!({ "findings": out }))
    }

    /// Disable / Restore / Delete one finding. Delete only follows Disable.
    pub fn persistence_apply(&self, params: &Value, actor: &str) -> Result<Value, RpcError> {
        let bad = |m: &str| RpcError::new(INVALID_PARAMS, m);
        let id: i64 = params
            .get("item_id")
            .and_then(Value::as_str)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| bad("item_id is required"))?;
        let action = params
            .get("action")
            .and_then(Value::as_str)
            .filter(|a| ["disable", "restore", "delete"].contains(a))
            .ok_or_else(|| bad("action must be disable, restore or delete"))?;
        let ctl = self.control().ok_or_else(unavailable)?;
        let item = self
            .with_store(|c| persistence::get(c, id))
            .ok_or_else(unavailable)?
            .map_err(store_err)?
            .ok_or_else(|| RpcError::new(NOT_FOUND, "no such item"))?;

        if action != "restore"
            && item
                .image_path
                .as_deref()
                .is_some_and(|img| self.never_kill.check(img, None).is_err())
        {
            return Ok(result(false, Some("protected_target"), "system component"));
        }
        let (kind, loc) = (item.kind.as_str(), item.location.as_str());
        let (allowed, next): (&[&str], &str) = match action {
            "disable" => (&["found", "restored"], "disabled"),
            "restore" => (&["disabled"], "restored"),
            _ => (&["disabled"], "deleted"),
        };
        if !allowed.contains(&item.status.as_str()) {
            return if action == "delete" {
                Err(RpcError::new(
                    INVALID_STATE,
                    "disable the item before deleting it",
                ))
            } else {
                Ok(result(
                    false,
                    Some("invalid_state"),
                    "item is not in a valid state",
                ))
            };
        }
        let ts = now();
        let outcome: Result<(), String> = match action {
            "disable" => ctl.persist_disable(kind, loc).and_then(|backup| {
                self.with_store(|c| persistence::add_backup(c, id, &backup, &ts))
                    .ok_or_else(|| "storage unavailable".to_string())?
                    .map_err(|e| e.to_string())
            }),
            "restore" => self
                .with_store(|c| persistence::latest_backup(c, id))
                .and_then(Result::ok)
                .flatten()
                .ok_or_else(|| "no backup stored".to_string())
                .and_then(|b| ctl.persist_restore(kind, loc, &b)),
            _ => ctl.persist_delete(kind, loc),
        };
        let ok = outcome.is_ok();
        if ok {
            let _ = self.with_store(|c| persistence::set_status(c, id, next, &ts));
        }
        self.audit(
            actor,
            AuditKind::PersistenceAction,
            Some(loc),
            &json!({ "item_id": id, "kind": kind, "action": action, "ok": ok }),
        );
        Ok(match outcome {
            Ok(()) => result(true, None, next),
            Err(e) => {
                tracing::warn!(error = %e, kind, action, "persistence action failed");
                result(false, Some("internal"), "the action could not be completed")
            }
        })
    }
}

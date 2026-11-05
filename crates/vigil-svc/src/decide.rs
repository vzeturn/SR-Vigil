//! Pending/decision/audit RPCs: the user-facing side of the Unknown flow (docs/04 §2).

use std::fmt::Write as _;

use serde_json::{Value, json};
use time::OffsetDateTime;
use vigil_core::audit::{AuditEntry, AuditKind};
use vigil_ipc::proto::{INVALID_PARAMS, NOT_FOUND, RpcError};
use vigil_store::decisions::{
    self, Action, ApplyTo, DecidedBy, Decision, NewDecision, Pending, Scope,
};

use crate::state::{Shared, now};

const AUDIT_PAGE: u32 = 200;

fn hex(b: &[u8]) -> String {
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

fn store_err(e: impl std::fmt::Display) -> RpcError {
    tracing::error!(error = %e, "store error");
    RpcError::new(vigil_ipc::proto::INTERNAL_ERROR, "storage error")
}

fn no_store() -> RpcError {
    RpcError::new(vigil_ipc::proto::INVALID_STATE, "storage is unavailable")
}

fn id_param(params: &Value, key: &str) -> Result<Option<i64>, RpcError> {
    match params.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_str()
            .and_then(|s| s.parse().ok())
            .or_else(|| v.as_i64())
            .map(Some)
            .ok_or_else(|| RpcError::new(INVALID_PARAMS, format!("{key} must be an id"))),
    }
}

fn enum_param<T>(
    params: &Value,
    key: &str,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<T, RpcError> {
    params
        .get(key)
        .and_then(Value::as_str)
        .and_then(parse)
        .ok_or_else(|| RpcError::new(INVALID_PARAMS, format!("{key} is missing or invalid")))
}

fn decision_json(d: &Decision) -> Value {
    json!({
        "id": d.id.to_string(), "identity_id": d.executable_id.to_string(),
        "action": d.action.as_str(), "scope": d.scope.as_str(), "apply_to": d.apply_to.as_str(),
        "expires_at": d.expires_at, "by": d.by.as_str(), "note": d.note,
        "created_at": d.created_at, "revoked_at": d.revoked_at,
    })
}

fn audit_json(e: &AuditEntry) -> Value {
    json!({
        "seq": e.seq, "ts": e.ts, "actor": e.actor, "kind": e.kind.as_str(),
        "target": e.target, "details": e.details, "hash": hex(&e.hash),
    })
}

impl Shared {
    /// Append a hash-chained audit row; failures are logged, never fatal to the caller.
    pub fn audit(&self, actor: &str, kind: AuditKind, target: Option<&str>, details: &Value) {
        let r = self
            .with_store(|c| vigil_store::audit::append(c, &now(), actor, kind, target, details));
        if let Some(Err(e)) = r {
            tracing::error!(error = %e, kind = kind.as_str(), "audit append failed");
        }
    }

    pub(crate) fn pending_item(&self, p: &Pending) -> Option<Value> {
        let (exe, ev) = self
            .with_store(|c| {
                Ok::<_, vigil_store::StoreError>((
                    vigil_store::repo::executable_by_id(c, p.executable_id)?,
                    vigil_store::repo::latest_evaluation(c, p.executable_id)?,
                ))
            })?
            .ok()?;
        let (exe, ev) = (exe?, ev?);
        let signals: Value = serde_json::from_str(&ev.signals_json).unwrap_or_else(|_| json!([]));
        Some(json!({
            "id": p.id.to_string(),
            "identity": {
                "id": p.executable_id.to_string(), "sha256": exe.sha256, "path": exe.path,
                "signer_thumbprint": exe.signer_thumbprint, "publisher": exe.publisher,
                "company": exe.company, "product": exe.product,
                "original_filename": exe.original_filename,
                "signature_status": exe.signature_status,
            },
            "evaluation": {
                "score": ev.score, "verdict": ev.verdict, "signals": signals,
                "hard_rule": ev.hard_rule, "rule_pack_version": ev.rule_pack_version,
                "source": ev.source, "evaluated_at": ev.evaluated_at,
            },
            "process": null,
            "destination": {
                "addr": p.dest_addr, "port": p.dest_port, "dns_name": p.dns_name,
                "dest_class": p.dest_class.as_str(),
            },
            "ai_opinion": self.ai_opinion_json(p.executable_id),
            "created_at": p.created_at,
            // Only an established incident (hard rule, or the advisor escalates) interrupts the user.
            "alert": ev.verdict == "malicious" && ev.hard_rule.is_some(),
        }))
    }

    /// Escalate an open pending item to an alert once the advisor confidently calls it malicious.
    pub(crate) fn escalate_pending(&self, exe_id: i64) {
        let rows = self
            .with_store(decisions::list_pending)
            .and_then(Result::ok);
        let item = rows
            .into_iter()
            .flatten()
            .find(|p| p.executable_id == exe_id && p.resolved_at.is_none())
            .and_then(|p| self.pending_item(&p));
        if let Some(mut item) = item {
            item["alert"] = json!(true);
            self.emit("pending", "event.pending_created", item);
        }
    }

    /// `pending.list`: unresolved items, oldest first.
    pub fn list_pending(&self) -> Result<Value, RpcError> {
        let rows = self
            .with_store(decisions::list_pending)
            .ok_or_else(no_store)?
            .map_err(store_err)?;
        let items: Vec<Value> = rows
            .iter()
            .filter(|p| p.resolved_at.is_none())
            .filter_map(|p| self.pending_item(p))
            .collect();
        Ok(json!({ "items": items }))
    }

    /// `decision.list`: active (unrevoked, unexpired) decisions.
    pub fn list_decisions(&self) -> Result<Value, RpcError> {
        let rows = self
            .with_store(|c| decisions::list_active(c, OffsetDateTime::now_utc()))
            .ok_or_else(no_store)?
            .map_err(store_err)?;
        let items: Vec<Value> = rows.iter().map(|d| self.decision_detail(d)).collect();
        Ok(json!({ "items": items }))
    }

    /// A decision plus what the user needs to judge a kill: the program, why it scored as it did,
    /// the advisor's view and how often the respawn guard had to act.
    fn decision_detail(&self, d: &Decision) -> Value {
        let mut v = decision_json(d);
        let (exe, ev, kills) = self
            .with_store(|c| {
                let exe = vigil_store::repo::executable_by_id(c, d.executable_id)?;
                let ev = vigil_store::repo::latest_evaluation(c, d.executable_id)?;
                let kills = match &exe {
                    Some(e) => vigil_store::blocks::find(c, &e.path, Some(&e.sha256))?
                        .map_or(0, |b| b.respawn_kills),
                    None => 0,
                };
                Ok::<_, vigil_store::StoreError>((exe, ev, kills))
            })
            .and_then(Result::ok)
            .unwrap_or((None, None, 0));
        v["identity"] = exe.map_or(Value::Null, |e| {
            json!({ "path": e.path, "publisher": e.publisher, "product": e.product,
                    "signature_status": e.signature_status })
        });
        v["evaluation"] = ev.map_or(Value::Null, |e| {
            let signals: Value =
                serde_json::from_str(&e.signals_json).unwrap_or_else(|_| json!([]));
            json!({ "score": e.score, "verdict": e.verdict, "hard_rule": e.hard_rule,
                    "signals": signals })
        });
        v["ai_opinion"] = self.ai_opinion_json(d.executable_id);
        v["respawn_kills"] = json!(kills);
        v
    }

    /// `decision.exception`: lift a kill and pin an `allow` for the same program.
    /// Hard rules and Vigil's own protections still apply on top of the exception.
    pub fn decision_exception(&self, params: &Value) -> Result<Value, RpcError> {
        let id = id_param(params, "decision_id")?
            .ok_or_else(|| RpcError::new(INVALID_PARAMS, "decision_id is required"))?;
        let exe_id = self
            .with_store(|c| decisions::get_decision(c, id))
            .ok_or_else(no_store)?
            .map_err(store_err)?
            .filter(|d| d.revoked_at.is_none())
            .map(|d| d.executable_id)
            .ok_or_else(|| RpcError::new(NOT_FOUND, "no such active decision"))?;
        self.revoke_decision(&json!({ "decision_id": id }))?;
        self.submit_decision(&json!({
            "identity_id": exe_id.to_string(), "action": "allow", "scope": "forever",
            "apply_to": "file", "note": "exception: kill lifted by the user",
        }))
    }

    /// `decision.submit`: record the decision, resolve matching pending items, audit it.
    pub fn submit_decision(&self, params: &Value) -> Result<Value, RpcError> {
        let action = enum_param(params, "action", Action::parse)?;
        let scope = enum_param(params, "scope", Scope::parse)?;
        let apply_to = enum_param(params, "apply_to", ApplyTo::parse)?;
        let pending_id = id_param(params, "pending_id")?;
        let identity_id = id_param(params, "identity_id")?;
        let note = params
            .get("note")
            .and_then(Value::as_str)
            .map(|s| s.chars().take(500).collect::<String>());
        let now = OffsetDateTime::now_utc();

        let out = self
            .with_store(
                |c| -> Result<Result<(Decision, usize), RpcError>, vigil_store::StoreError> {
                    let exe_id = match (pending_id, identity_id) {
                        (Some(pid), _) => match decisions::get_pending(c, pid)? {
                            Some(p) => p.executable_id,
                            None => {
                                return Ok(Err(RpcError::new(NOT_FOUND, "no such pending item")));
                            }
                        },
                        (None, Some(id)) => id,
                        (None, None) => {
                            return Ok(Err(RpcError::new(
                                INVALID_PARAMS,
                                "pending_id or identity_id is required",
                            )));
                        }
                    };
                    let Some(exe) = vigil_store::repo::executable_by_id(c, exe_id)? else {
                        return Ok(Err(RpcError::new(NOT_FOUND, "no such identity")));
                    };
                    let thumb = exe.signer_thumbprint.clone();
                    if apply_to == ApplyTo::Publisher && thumb.is_none() {
                        return Ok(Err(RpcError::new(
                            INVALID_PARAMS,
                            "publisher scope needs a signed executable",
                        )));
                    }
                    let id = decisions::insert_decision(
                        c,
                        &NewDecision {
                            executable_id: exe_id,
                            action,
                            scope,
                            apply_to,
                            publisher_thumbprint: if apply_to == ApplyTo::Publisher {
                                thumb
                            } else {
                                None
                            },
                            publisher_product: if apply_to == ApplyTo::Publisher {
                                exe.product
                            } else {
                                None
                            },
                            by: DecidedBy::User,
                            actor: "user".into(),
                            note: note.clone(),
                        },
                        now,
                    )?;
                    let resolved = decisions::resolve_pending_for_executable(c, exe_id, id, now)?;
                    let d = decisions::get_decision(c, id)?
                        .ok_or_else(|| vigil_store::StoreError::Corrupt("decision".into()))?;
                    Ok(Ok((d, resolved)))
                },
            )
            .ok_or_else(no_store)?
            .map_err(store_err)??;

        let (d, resolved) = out;
        self.audit(
            "user",
            AuditKind::Decision,
            Some(&d.executable_id.to_string()),
            &json!({ "decision_id": d.id, "action": d.action.as_str(), "scope": d.scope.as_str(),
                     "apply_to": d.apply_to.as_str(), "resolved_pending": resolved }),
        );
        self.emit(
            "pending",
            "event.pending_resolved",
            json!({ "pending_id": pending_id.map(|p| p.to_string()), "action": d.action.as_str(), "by": "user" }),
        );
        let (applied, warnings) = self.enforce_decision(&d);
        Ok(json!({ "decision": decision_json(&d), "applied": applied, "warnings": warnings }))
    }

    /// `decision.revoke`
    pub fn revoke_decision(&self, params: &Value) -> Result<Value, RpcError> {
        let id = id_param(params, "decision_id")?
            .ok_or_else(|| RpcError::new(INVALID_PARAMS, "decision_id is required"))?;
        let revoked = self
            .with_store(|c| {
                let now = OffsetDateTime::now_utc();
                let exe = decisions::get_decision(c, id)?
                    .and_then(|d| {
                        vigil_store::repo::executable_by_id(c, d.executable_id).transpose()
                    })
                    .transpose()?;
                let done = decisions::revoke_decision(c, id, now)?;
                // A kill's respawn block lives until the user lifts it: revoking releases it too.
                if done && let Some(exe) = exe {
                    let ts = crate::state::now();
                    for b in vigil_store::blocks::active(c)? {
                        if b.sha256 == exe.sha256 || b.path.eq_ignore_ascii_case(&exe.path) {
                            vigil_store::blocks::remove(c, b.id, &ts)?;
                        }
                    }
                }
                Ok::<_, vigil_store::StoreError>(done)
            })
            .ok_or_else(no_store)?
            .map_err(store_err)?;
        if !revoked {
            return Err(RpcError::new(NOT_FOUND, "no such active decision"));
        }
        self.audit(
            "user",
            AuditKind::DecisionRevoked,
            Some(&id.to_string()),
            &json!({ "decision_id": id }),
        );
        if let Err(e) = self.resync_enforcement() {
            self.fail_enforcement(&e);
        }
        Ok(json!({}))
    }

    /// `audit.query`: a page of rows plus chain verification for that page.
    pub fn audit_query(&self, params: &Value) -> Result<Value, RpcError> {
        let from = params
            .get("cursor")
            .and_then(Value::as_str)
            .map_or(Some(0), |s| s.parse::<u64>().ok())
            .ok_or_else(|| RpcError::new(INVALID_PARAMS, "cursor is invalid"))?;
        let limit = params
            .get("limit")
            .and_then(Value::as_u64)
            .map_or(AUDIT_PAGE, |l| {
                u32::try_from(l).unwrap_or(AUDIT_PAGE).clamp(1, AUDIT_PAGE)
            });
        let page = self
            .with_store(|c| vigil_store::audit::query(c, from, limit))
            .ok_or_else(no_store)?
            .map_err(store_err)?;
        let next = (page.items.len() == limit as usize)
            .then(|| page.items.last().map(|e| (e.seq + 1).to_string()))
            .flatten();
        Ok(json!({
            "items": page.items.iter().map(audit_json).collect::<Vec<_>>(),
            "next_cursor": next, "chain_ok": page.chain_ok, "first_bad_seq": page.first_bad_seq,
        }))
    }
}

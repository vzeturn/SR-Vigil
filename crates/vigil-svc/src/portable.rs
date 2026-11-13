//! FR-018: export and import of user decisions (TOML) and audit export (JSON / CSV).
//!
//! Content travels inline over IPC so the service never writes to a caller-chosen path.
//! Imported documents are untrusted: every field is validated, sizes are capped, and SQL goes
//! through bound parameters in `vigil-store`.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;
use vigil_core::audit::AuditKind;
use vigil_ipc::proto::{INVALID_PARAMS, RpcError};
use vigil_store::decisions::{self, Action, ApplyTo, DecidedBy, NewDecision, Scope};
use vigil_store::repo::{self, Executable};

use crate::state::Shared;

const MAX_DOC_BYTES: usize = 1 << 20;
const MAX_ENTRIES: usize = 5000;
const FORMAT_VERSION: u32 = 1;
const SIGNATURE_STATUSES: [&str; 7] = [
    "valid_embedded",
    "valid_catalog",
    "unsigned",
    "invalid",
    "expired",
    "revoked",
    "untrusted_root",
];

#[derive(Serialize, Deserialize)]
struct Doc {
    version: u32,
    #[serde(default)]
    decision: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    sha256: String,
    path: String,
    signer_thumbprint: Option<String>,
    publisher: Option<String>,
    product: Option<String>,
    signature_status: String,
    action: String,
    scope: String,
    apply_to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    package_family: Option<String>,
    note: Option<String>,
}

impl Entry {
    /// Shape checks on an imported entry; the file itself is untrusted input.
    fn is_valid(&self, apply_to: ApplyTo) -> bool {
        let thumb_ok = self
            .signer_thumbprint
            .as_deref()
            .is_none_or(|t| !t.is_empty() && t.len() <= 128);
        let family_ok = match (apply_to, self.package_family.as_deref()) {
            (ApplyTo::PackageSource, Some(f)) => !f.is_empty() && f.len() <= 600,
            (ApplyTo::PackageSource, None) => false,
            _ => true,
        };
        family_ok
            && thumb_ok
            && valid_sha256(&self.sha256)
            && !self.path.is_empty()
            && self.path.len() <= 520
            && SIGNATURE_STATUSES.contains(&self.signature_status.as_str())
    }
}

fn bad(msg: impl Into<String>) -> RpcError {
    RpcError::new(INVALID_PARAMS, msg)
}

fn store_err(e: &vigil_store::StoreError) -> RpcError {
    tracing::error!(error = %e, "portable store error");
    RpcError::new(vigil_ipc::proto::INTERNAL_ERROR, "store error")
}

fn valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Shared {
    /// `decision.export`: active, portable (non-`once`) decisions as a TOML document.
    pub fn decisions_export(&self) -> Result<Value, RpcError> {
        let entries = self
            .with_store(|c| -> Result<Vec<Entry>, vigil_store::StoreError> {
                let mut out = Vec::new();
                for d in decisions::list_active(c, OffsetDateTime::now_utc())? {
                    if d.scope == Scope::Once {
                        continue;
                    }
                    let Some(e) = repo::executable_by_id(c, d.executable_id)? else {
                        continue;
                    };
                    out.push(Entry {
                        sha256: e.sha256,
                        path: e.path,
                        signer_thumbprint: e.signer_thumbprint,
                        publisher: e.publisher,
                        product: e.product,
                        signature_status: e.signature_status,
                        action: d.action.as_str().into(),
                        scope: d.scope.as_str().into(),
                        apply_to: d.apply_to.as_str().into(),
                        package_family: d.package_family,
                        note: d.note,
                    });
                }
                Ok(out)
            })
            .ok_or_else(|| RpcError::new(vigil_ipc::proto::INVALID_STATE, "store unavailable"))?
            .map_err(|e| store_err(&e))?;
        let count = entries.len();
        let content = toml::to_string_pretty(&Doc {
            version: FORMAT_VERSION,
            decision: entries,
        })
        .map_err(|e| bad(e.to_string()))?;
        self.audit("user", AuditKind::Decision, None, &json!({"export": count}));
        Ok(json!({ "content": content, "count": count }))
    }

    /// `decision.import`: validate a TOML document and record each decision as a user decision.
    pub fn decisions_import(&self, params: &Value, actor: &str) -> Result<Value, RpcError> {
        let content = params
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("content is required"))?;
        if content.len() > MAX_DOC_BYTES {
            return Err(bad("document is too large"));
        }
        let doc: Doc = toml::from_str(content).map_err(|e| bad(format!("invalid TOML: {e}")))?;
        if doc.version != FORMAT_VERSION {
            return Err(bad("unsupported format version"));
        }
        if doc.decision.len() > MAX_ENTRIES {
            return Err(bad("too many entries"));
        }
        let now = OffsetDateTime::now_utc();
        let (mut imported, mut skipped) = (0usize, 0usize);
        for e in &doc.decision {
            let parsed = (
                Action::parse(&e.action),
                Scope::parse(&e.scope),
                ApplyTo::parse(&e.apply_to),
            );
            let (Some(action), Some(scope), Some(apply_to)) = parsed else {
                skipped += 1;
                continue;
            };
            if scope == Scope::Once || !e.is_valid(apply_to) {
                skipped += 1;
                continue;
            }
            let exe = Executable {
                sha256: e.sha256.to_ascii_lowercase(),
                path: e.path.clone(),
                signer_thumbprint: e.signer_thumbprint.clone(),
                publisher: e.publisher.clone(),
                company: None,
                product: e.product.clone(),
                original_filename: None,
                signature_status: e.signature_status.clone(),
            };
            let note = e.note.as_ref().map(|n| n.chars().take(500).collect());
            let added = self
                .with_store(|c| -> Result<bool, vigil_store::StoreError> {
                    let ts = decisions::format_ts(now)?;
                    let id = repo::upsert_executable(c, &exe, &ts)?;
                    let family = (apply_to == ApplyTo::PackageSource)
                        .then(|| e.package_family.clone())
                        .flatten();
                    if let Some(f) = &family {
                        repo::set_package_family(c, id, Some(f))?;
                    }
                    let dup = decisions::list_active(c, now)?.iter().any(|d| {
                        d.executable_id == id && d.action == action && d.apply_to == apply_to
                    });
                    if dup {
                        return Ok(false);
                    }
                    decisions::insert_decision(
                        c,
                        &NewDecision {
                            executable_id: id,
                            action,
                            scope,
                            apply_to,
                            publisher_thumbprint: e.signer_thumbprint.clone(),
                            publisher_product: e.product.clone(),
                            package_family: family,
                            by: DecidedBy::User,
                            actor: actor.to_string(),
                            note,
                        },
                        now,
                    )?;
                    Ok(true)
                })
                .ok_or_else(|| RpcError::new(vigil_ipc::proto::INVALID_STATE, "store unavailable"))?
                .map_err(|e| store_err(&e))?;
            if added {
                imported += 1;
            } else {
                skipped += 1;
            }
        }
        self.audit(
            actor,
            AuditKind::Decision,
            None,
            &json!({"import": imported, "skipped": skipped}),
        );
        Ok(json!({ "imported": imported, "skipped": skipped }))
    }

    /// `audit.export`: the whole chain as JSON or CSV, optionally limited by `since`/`until`
    /// (RFC 3339 timestamps compare lexicographically).
    pub fn audit_export(&self, params: &Value) -> Result<Value, RpcError> {
        let format = params
            .get("format")
            .and_then(Value::as_str)
            .unwrap_or("json");
        if !matches!(format, "json" | "csv") {
            return Err(bad("format must be json or csv"));
        }
        let since = params.get("since").and_then(Value::as_str);
        let until = params.get("until").and_then(Value::as_str);
        let mut rows: Vec<Value> = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut q = json!({"limit": 1000});
            if let Some(c) = &cursor {
                q["cursor"] = json!(c);
            }
            let page = self.audit_query(&q)?;
            rows.extend(page["items"].as_array().cloned().unwrap_or_default());
            match page["next_cursor"].as_str() {
                Some(c) => cursor = Some(c.to_owned()),
                None => break,
            }
        }
        rows.retain(|r| {
            let ts = r["ts"].as_str().unwrap_or_default();
            since.is_none_or(|s| ts >= s) && until.is_none_or(|u| ts <= u)
        });
        let content = if format == "json" {
            serde_json::to_string_pretty(&rows).map_err(|e| bad(e.to_string()))?
        } else {
            to_csv(&rows)
        };
        Ok(json!({ "format": format, "content": content, "count": rows.len() }))
    }
}

/// CSV with RFC 4180 quoting. Cells starting with a formula trigger are prefixed with `'` so a
/// spreadsheet never evaluates host-controlled text (CSV injection).
fn to_csv(rows: &[Value]) -> String {
    let mut out = String::from("seq,ts,actor,kind,target,details,hash\r\n");
    for r in rows {
        let cells = [
            r["seq"].to_string(),
            r["ts"].as_str().unwrap_or_default().to_string(),
            r["actor"].as_str().unwrap_or_default().to_string(),
            r["kind"].as_str().unwrap_or_default().to_string(),
            r["target"].as_str().unwrap_or_default().to_string(),
            r["details"].to_string(),
            r["hash"].as_str().unwrap_or_default().to_string(),
        ];
        let line: Vec<String> = cells.iter().map(|c| csv_cell(c)).collect();
        let _ = write!(out, "{}\r\n", line.join(","));
    }
    out
}

fn csv_cell(raw: &str) -> String {
    let guarded = if raw.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{raw}")
    } else {
        raw.to_string()
    };
    format!("\"{}\"", guarded.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::csv_cell;

    #[test]
    fn formula_triggers_are_neutralised_and_quotes_escaped() {
        for t in ["=1+1", "+1", "-1", "@SUM(A1)", "\tx", "\rx"] {
            assert!(csv_cell(t).starts_with("\"'"), "{t:?}");
        }
        assert_eq!(csv_cell("a\"b"), "\"a\"\"b\"");
    }
}

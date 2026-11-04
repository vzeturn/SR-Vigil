//! Audit hash chain (docs/09 section 4): entry kinds, canonical JSON, hashing and chain verification.
//!
//! `hash_n = SHA-256(prev || seq_be64 || field(ts) || field(actor) || field(kind) || opt(target) ||
//! field(canonical_json(details)))`. Text fields are length-prefixed (u32 big-endian) so field
//! boundaries are unambiguous; `target` carries a presence byte so `None` and `""` differ.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Hash of the (non-existent) row before `seq = 1`.
pub const GENESIS_HASH: [u8; 32] = [0; 32];

/// Audit entry kinds; mirrors the `CHECK` list of `audit_log.kind` in `schemas/db.sql`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    ServiceStart,
    ServiceStop,
    ModeChange,
    Verdict,
    Decision,
    DecisionRevoked,
    Kill,
    RespawnKill,
    FilterAdd,
    FilterRemove,
    Panic,
    AiDecision,
    AiConfig,
    RuleChange,
    TrustChange,
    PersistenceAction,
    ClientConnect,
    ConfigChange,
    Health,
    /// Written by retention purge so the chain stays verifiable.
    AuditCheckpoint,
}

impl AuditKind {
    pub const ALL: [AuditKind; 20] = [
        Self::ServiceStart,
        Self::ServiceStop,
        Self::ModeChange,
        Self::Verdict,
        Self::Decision,
        Self::DecisionRevoked,
        Self::Kill,
        Self::RespawnKill,
        Self::FilterAdd,
        Self::FilterRemove,
        Self::Panic,
        Self::AiDecision,
        Self::AiConfig,
        Self::RuleChange,
        Self::TrustChange,
        Self::PersistenceAction,
        Self::ClientConnect,
        Self::ConfigChange,
        Self::Health,
        Self::AuditCheckpoint,
    ];

    /// The `snake_case` wire/database name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ServiceStart => "service_start",
            Self::ServiceStop => "service_stop",
            Self::ModeChange => "mode_change",
            Self::Verdict => "verdict",
            Self::Decision => "decision",
            Self::DecisionRevoked => "decision_revoked",
            Self::Kill => "kill",
            Self::RespawnKill => "respawn_kill",
            Self::FilterAdd => "filter_add",
            Self::FilterRemove => "filter_remove",
            Self::Panic => "panic",
            Self::AiDecision => "ai_decision",
            Self::AiConfig => "ai_config",
            Self::RuleChange => "rule_change",
            Self::TrustChange => "trust_change",
            Self::PersistenceAction => "persistence_action",
            Self::ClientConnect => "client_connect",
            Self::ConfigChange => "config_change",
            Self::Health => "health",
            Self::AuditCheckpoint => "audit_checkpoint",
        }
    }

    /// Parse the `snake_case` name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// One stored audit row.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditEntry {
    pub seq: u64,
    pub ts: String,
    pub actor: String,
    pub kind: AuditKind,
    pub target: Option<String>,
    pub details: Value,
    pub prev_hash: [u8; 32],
    pub hash: [u8; 32],
}

/// Canonical JSON (RFC 8785 style): object keys sorted by UTF-16 code units, no whitespace,
/// `serde_json` string/number rendering (shortest round-trip numbers, minimal escapes).
#[must_use]
pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                write_canonical(&map[k], out);
            }
            out.push('}');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

fn put_text(h: &mut Sha256, s: &str) {
    let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
    h.update(len.to_be_bytes());
    h.update(s.as_bytes());
}

/// Hash of one entry given the previous entry's hash.
#[must_use]
pub fn hash_entry(
    prev: [u8; 32],
    seq: u64,
    ts: &str,
    actor: &str,
    kind: AuditKind,
    target: Option<&str>,
    details: &Value,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prev);
    h.update(seq.to_be_bytes());
    put_text(&mut h, ts);
    put_text(&mut h, actor);
    put_text(&mut h, kind.as_str());
    match target {
        Some(t) => {
            h.update([1u8]);
            put_text(&mut h, t);
        }
        None => h.update([0u8]),
    }
    put_text(&mut h, &canonical_json(details));
    h.finalize().into()
}

/// Verify consecutive entries. `start_prev` is the hash of the row before the first entry
/// ([`GENESIS_HASH`] when the first entry is `seq = 1`). Returns the first bad `seq`: a gap,
/// a wrong `prev_hash`, or a `hash` that does not match the content.
pub fn verify_chain(start_prev: [u8; 32], entries: &[AuditEntry]) -> Result<(), u64> {
    let mut prev = start_prev;
    let mut expect_seq = entries.first().map(|e| e.seq);
    for e in entries {
        let computed = hash_entry(
            prev,
            e.seq,
            &e.ts,
            &e.actor,
            e.kind,
            e.target.as_deref(),
            &e.details,
        );
        if Some(e.seq) != expect_seq || e.prev_hash != prev || e.hash != computed {
            return Err(e.seq);
        }
        prev = e.hash;
        expect_seq = Some(e.seq + 1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TS: &str = "2026-01-01T00:00:00Z";

    fn chain(n: u64) -> Vec<AuditEntry> {
        let mut prev = GENESIS_HASH;
        (1..=n)
            .map(|seq| {
                let details = json!({"b": seq, "a": [1, "x"]});
                let hash = hash_entry(
                    prev,
                    seq,
                    TS,
                    "svc",
                    AuditKind::Decision,
                    Some("exe:1"),
                    &details,
                );
                let e = AuditEntry {
                    seq,
                    ts: TS.into(),
                    actor: "svc".into(),
                    kind: AuditKind::Decision,
                    target: Some("exe:1".into()),
                    details,
                    prev_hash: prev,
                    hash,
                };
                prev = hash;
                e
            })
            .collect()
    }

    #[test]
    fn canonical_sorts_keys_and_strips_whitespace() {
        let v = json!({"b": 1, "a": {"z": [true, null], "y": "e\n"}});
        assert_eq!(
            canonical_json(&v),
            r#"{"a":{"y":"e\n","z":[true,null]},"b":1}"#
        );
    }

    #[test]
    fn canonical_is_key_order_independent() {
        let a: Value = serde_json::from_str(r#"{"x":1,"y":2}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"y":2,"x":1}"#).unwrap();
        assert_eq!(canonical_json(&a), canonical_json(&b));
    }

    #[test]
    fn hash_is_deterministic_and_field_sensitive() {
        let d = json!({});
        let h = |target| {
            hash_entry(
                GENESIS_HASH,
                1,
                TS,
                "svc",
                AuditKind::ServiceStart,
                target,
                &d,
            )
        };
        assert_eq!(h(None), h(None));
        assert_ne!(h(None), h(Some("")));
    }

    #[test]
    fn field_boundaries_are_unambiguous() {
        let d = json!({});
        let a = hash_entry(GENESIS_HASH, 1, "ab", "c", AuditKind::Panic, None, &d);
        let b = hash_entry(GENESIS_HASH, 1, "a", "bc", AuditKind::Panic, None, &d);
        assert_ne!(a, b);
    }

    #[test]
    fn valid_chain_verifies() {
        assert_eq!(verify_chain(GENESIS_HASH, &chain(5)), Ok(()));
        assert_eq!(verify_chain(GENESIS_HASH, &[]), Ok(()));
    }

    #[test]
    fn edited_row_is_detected_at_its_seq() {
        let mut c = chain(5);
        c[2].actor = "attacker".into();
        assert_eq!(verify_chain(GENESIS_HASH, &c), Err(3));
        let mut c = chain(5);
        c[3].details = json!({"b": 999});
        assert_eq!(verify_chain(GENESIS_HASH, &c), Err(4));
    }

    #[test]
    fn deleted_row_is_detected() {
        let mut c = chain(5);
        c.remove(2);
        assert_eq!(verify_chain(GENESIS_HASH, &c), Err(4));
    }

    #[test]
    fn rewritten_hash_breaks_the_link() {
        let mut c = chain(4);
        c[1].hash = [7; 32];
        assert_eq!(verify_chain(GENESIS_HASH, &c), Err(2));
    }

    #[test]
    fn range_verification_uses_row_before() {
        let c = chain(5);
        assert_eq!(verify_chain(c[1].hash, &c[2..]), Ok(()));
        assert_eq!(verify_chain(GENESIS_HASH, &c[2..]), Err(3));
    }

    #[test]
    fn kinds_round_trip() {
        for k in AuditKind::ALL {
            assert_eq!(AuditKind::parse(k.as_str()), Some(k));
            assert_eq!(serde_json::to_value(k).unwrap(), json!(k.as_str()));
        }
        assert_eq!(AuditKind::parse("nope"), None);
    }
}

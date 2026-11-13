//! Windows Event Log export of audit rows (`docs/09 §4.1`): one event per row, source `Vigil`,
//! Application log, so Windows Event Forwarding or any SIEM agent can collect them.
//!
//! The text is one JSON object with the row's `seq`, `hash` and fields. Host strings stay data:
//! JSON escapes quotes and control characters, and `%` is written as `\u0025` so Event Viewer
//! never treats `%1`/`%%1` inside a process name as an insertion or parameter reference.

use std::fmt::Write as _;

use serde_json::{Value, json};

use crate::audit::{AuditEntry, AuditKind};

/// Event source registered under `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application`.
pub const SOURCE: &str = "Vigil";
/// Event ids are `BASE + position in AuditKind::ALL`; the message table maps 1..=1000 to `%1`.
pub const BASE: u32 = 100;
/// Largest text sent; longer `details` are replaced by a marker (the full row stays in the DB).
pub const MAX_TEXT: usize = 16 * 1024;

/// Event Log severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Information,
    Warning,
}

/// One event, ready for `ReportEventW`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub id: u32,
    pub level: Level,
    pub text: String,
}

/// Stable event id for `kind` (documented in `docs/09 §4.1`).
#[must_use]
pub fn event_id(kind: AuditKind) -> u32 {
    let pos = AuditKind::ALL.iter().position(|k| *k == kind).unwrap_or(0);
    BASE + u32::try_from(pos).unwrap_or(0)
}

fn level(kind: AuditKind) -> Level {
    match kind {
        AuditKind::Kill | AuditKind::RespawnKill | AuditKind::Panic | AuditKind::Health => {
            Level::Warning
        }
        _ => Level::Information,
    }
}

fn text(e: &AuditEntry, details: &Value) -> String {
    let hash = e.hash.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    });
    json!({
        "seq": e.seq, "ts": e.ts, "actor": e.actor, "kind": e.kind.as_str(),
        "target": e.target, "details": details, "hash": hash,
    })
    .to_string()
    .replace('%', "\\u0025")
}

/// The event for one audit row.
#[must_use]
pub fn event(e: &AuditEntry) -> Event {
    let mut t = text(e, &e.details);
    if t.len() > MAX_TEXT {
        t = text(e, &json!({ "truncated": true }));
    }
    Event {
        id: event_id(e.kind),
        level: level(e.kind),
        text: t,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(kind: AuditKind, details: Value) -> AuditEntry {
        AuditEntry {
            seq: 7,
            ts: "2026-11-13T00:00:00Z".into(),
            actor: "rule".into(),
            kind,
            target: Some("C:\\Temp\\%1%%2.exe".into()),
            details,
            prev_hash: [0; 32],
            hash: [0xab; 32],
        }
    }

    #[test]
    fn ids_are_unique_stable_and_inside_the_message_table() {
        let ids: Vec<u32> = AuditKind::ALL.iter().map(|k| event_id(*k)).collect();
        let mut sorted = ids.clone();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len());
        assert!(ids.iter().all(|i| (1..=1000).contains(i)));
        assert_eq!(event_id(AuditKind::ServiceStart), 100);
        assert_eq!(event_id(AuditKind::Kill), 106);
    }

    #[test]
    fn host_strings_stay_data() {
        let e = event(&row(AuditKind::Kill, json!({"cmd": "a \"b\"\n%3"})));
        assert!(!e.text.contains('%'), "{}", e.text);
        assert!(!e.text.contains('\n'));
        let back: Value = serde_json::from_str(&e.text).unwrap();
        assert_eq!(back["target"], "C:\\Temp\\%1%%2.exe");
        assert_eq!(back["details"]["cmd"], "a \"b\"\n%3");
        assert_eq!(back["hash"], "ab".repeat(32));
        assert_eq!(e.level, Level::Warning);
    }

    #[test]
    fn oversized_details_are_replaced_not_cut() {
        let e = event(&row(
            AuditKind::ConfigChange,
            json!({"x": "y".repeat(MAX_TEXT)}),
        ));
        assert!(e.text.len() <= MAX_TEXT);
        let back: Value = serde_json::from_str(&e.text).unwrap();
        assert_eq!(back["details"], json!({"truncated": true}));
        assert_eq!(back["seq"], 7);
        assert_eq!(e.level, Level::Information);
    }
}

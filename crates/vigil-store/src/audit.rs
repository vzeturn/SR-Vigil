//! Hash-chained audit log (`audit_log`, docs/09 section 4). Append-only; every statement uses
//! bound parameters and host strings are stored as data.

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::Value;
use vigil_core::audit::{
    AuditEntry, AuditKind, GENESIS_HASH, canonical_json, hash_entry, verify_chain,
};

use crate::StoreError;

/// Result of [`query`]: the requested rows plus chain verification over exactly that range.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditPage {
    pub items: Vec<AuditEntry>,
    pub chain_ok: bool,
    /// First `seq` that fails verification when `chain_ok` is false.
    pub first_bad_seq: Option<u64>,
}

fn corrupt(what: &str) -> StoreError {
    StoreError::Corrupt(format!("audit_log: {what}"))
}

fn to_hash(blob: &[u8]) -> Result<[u8; 32], StoreError> {
    blob.try_into().map_err(|_| corrupt("hash is not 32 bytes"))
}

/// Append one entry in its own immediate transaction (do not call inside another transaction).
/// The new row chains to the last hash (32 zero bytes for the first row).
pub fn append(
    conn: &Connection,
    ts: &str,
    actor: &str,
    kind: AuditKind,
    target: Option<&str>,
    details: &Value,
) -> Result<AuditEntry, StoreError> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    let last: Option<(i64, Vec<u8>)> = tx
        .query_row(
            "SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (seq, prev_hash) = match last {
        Some((s, h)) => (
            u64::try_from(s).map_err(|_| corrupt("negative seq"))? + 1,
            to_hash(&h)?,
        ),
        None => (1, GENESIS_HASH),
    };
    let hash = hash_entry(prev_hash, seq, ts, actor, kind, target, details);
    let details_json = canonical_json(details);
    tx.execute(
        "INSERT INTO audit_log (seq, ts, actor, kind, target, details_json, prev_hash, hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            i64::try_from(seq).map_err(|_| corrupt("seq overflow"))?,
            ts,
            actor,
            kind.as_str(),
            target,
            details_json,
            prev_hash.as_slice(),
            hash.as_slice()
        ],
    )?;
    tx.commit()?;
    Ok(AuditEntry {
        seq,
        ts: ts.to_owned(),
        actor: actor.to_owned(),
        kind,
        target: target.map(str::to_owned),
        details: serde_json::from_str(&details_json).map_err(|_| corrupt("details"))?,
        prev_hash,
        hash,
    })
}

/// Rows with `seq >= from_seq` (at most `limit`), verified against the row before the range
/// (the first row's own `prev_hash` is the anchor when that predecessor was purged).
pub fn query(conn: &Connection, from_seq: u64, limit: u32) -> Result<AuditPage, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT seq, ts, actor, kind, target, details_json, prev_hash, hash
         FROM audit_log WHERE seq >= ?1 ORDER BY seq LIMIT ?2",
    )?;
    let from = i64::try_from(from_seq).unwrap_or(i64::MAX);
    let mut items = Vec::new();
    let mut rows = stmt.query(params![from, limit])?;
    while let Some(r) = rows.next()? {
        let seq: i64 = r.get(0)?;
        let kind: String = r.get(3)?;
        let details_json: String = r.get(5)?;
        let prev: Vec<u8> = r.get(6)?;
        let hash: Vec<u8> = r.get(7)?;
        items.push(AuditEntry {
            seq: u64::try_from(seq).map_err(|_| corrupt("negative seq"))?,
            ts: r.get(1)?,
            actor: r.get(2)?,
            kind: AuditKind::parse(&kind).ok_or_else(|| corrupt("unknown kind"))?,
            target: r.get(4)?,
            details: serde_json::from_str(&details_json).map_err(|_| corrupt("details_json"))?,
            prev_hash: to_hash(&prev)?,
            hash: to_hash(&hash)?,
        });
    }
    let Some(first) = items.first() else {
        return Ok(AuditPage {
            items,
            chain_ok: true,
            first_bad_seq: None,
        });
    };
    let before: Option<Vec<u8>> = conn
        .query_row(
            "SELECT hash FROM audit_log WHERE seq = ?1",
            [i64::try_from(first.seq).unwrap_or(i64::MAX) - 1],
            |r| r.get(0),
        )
        .optional()?;
    let start_prev = match before {
        Some(h) => to_hash(&h)?,
        None if first.seq == 1 => GENESIS_HASH,
        None => first.prev_hash,
    };
    let verdict = verify_chain(start_prev, &items);
    Ok(AuditPage {
        items,
        chain_ok: verdict.is_ok(),
        first_bad_seq: verdict.err(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn seeded(n: u32) -> Connection {
        let conn = crate::open_in_memory().unwrap();
        for i in 0..n {
            append(
                &conn,
                "2026-01-01T00:00:00Z",
                "svc",
                AuditKind::Decision,
                Some("exe:1"),
                &json!({"i": i}),
            )
            .unwrap();
        }
        conn
    }

    #[test]
    fn append_chains_from_genesis() {
        let conn = seeded(3);
        let page = query(&conn, 1, 100).unwrap();
        assert_eq!(page.items.len(), 3);
        assert_eq!(page.items[0].prev_hash, GENESIS_HASH);
        assert_eq!(page.items[1].prev_hash, page.items[0].hash);
        assert!(page.chain_ok);
        assert_eq!(page.first_bad_seq, None);
    }

    #[test]
    fn range_query_verifies_against_previous_row() {
        let conn = seeded(5);
        let page = query(&conn, 3, 2).unwrap();
        assert_eq!(page.items.iter().map(|e| e.seq).collect::<Vec<_>>(), [3, 4]);
        assert!(page.chain_ok);
    }

    #[test]
    fn empty_log_is_ok() {
        let page = query(&seeded(0), 1, 10).unwrap();
        assert!(page.items.is_empty() && page.chain_ok);
    }

    #[test]
    fn edited_row_reports_its_seq() {
        let conn = seeded(5);
        conn.execute_batch("DROP TRIGGER trg_audit_no_update")
            .unwrap();
        conn.execute(
            "UPDATE audit_log SET actor = ?1 WHERE seq = 3",
            ["attacker"],
        )
        .unwrap();
        let page = query(&conn, 1, 100).unwrap();
        assert!(!page.chain_ok);
        assert_eq!(page.first_bad_seq, Some(3));
        // A range that excludes the edited row stays clean.
        assert!(query(&conn, 4, 10).unwrap().chain_ok);
    }

    #[test]
    fn deleted_row_is_detected() {
        let conn = seeded(5);
        conn.execute_batch("DROP TRIGGER trg_audit_no_delete")
            .unwrap();
        conn.execute("DELETE FROM audit_log WHERE seq = 3", [])
            .unwrap();
        let page = query(&conn, 1, 100).unwrap();
        assert_eq!(page.first_bad_seq, Some(4));
    }

    #[test]
    fn update_and_delete_are_blocked_by_triggers() {
        let conn = seeded(1);
        assert!(conn.execute("UPDATE audit_log SET actor='x'", []).is_err());
        assert!(conn.execute("DELETE FROM audit_log", []).is_err());
    }

    #[test]
    fn hostile_strings_are_stored_as_data() {
        let conn = crate::open_in_memory().unwrap();
        let evil = "x'); DROP TABLE audit_log;--";
        append(
            &conn,
            "2026-01-01T00:00:00Z",
            evil,
            AuditKind::Kill,
            Some(evil),
            &json!({"p": evil}),
        )
        .unwrap();
        let page = query(&conn, 1, 10).unwrap();
        assert!(page.chain_ok);
        assert_eq!(page.items[0].actor, evil);
    }
}

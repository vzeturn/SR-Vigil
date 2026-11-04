//! Settings blobs, the AI response cache and stored opinions.

use rusqlite::{Connection, OptionalExtension, params};
use time::{Duration, OffsetDateTime};

use crate::StoreError;
use crate::decisions::format_ts;

/// Read a `settings` value.
pub fn setting_get(conn: &Connection, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
    Ok(conn
        .query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| r.get(0))
        .optional()?)
}

/// Insert or replace a `settings` value.
pub fn setting_put(conn: &Connection, key: &str, value: &[u8]) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?1, ?2)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

/// Delete a `settings` value.
pub fn setting_delete(conn: &Connection, key: &str) -> Result<(), StoreError> {
    conn.execute("DELETE FROM settings WHERE key = ?1", [key])?;
    Ok(())
}

/// A cached, still-valid opinion JSON for `key`.
pub fn cache_get(
    conn: &Connection,
    key: &str,
    now: OffsetDateTime,
) -> Result<Option<String>, StoreError> {
    Ok(conn
        .query_row(
            "SELECT opinion_json FROM ai_cache WHERE cache_key = ?1 AND expires_at > ?2",
            params![key, format_ts(now)?],
            |r| r.get(0),
        )
        .optional()?)
}

/// Store an opinion for `ttl` and drop expired rows.
pub fn cache_put(
    conn: &Connection,
    key: &str,
    opinion_json: &str,
    model: &str,
    ttl: Duration,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    let now_s = format_ts(now)?;
    conn.execute("DELETE FROM ai_cache WHERE expires_at <= ?1", [&now_s])?;
    conn.execute(
        "INSERT INTO ai_cache (cache_key, opinion_json, model, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT (cache_key) DO UPDATE SET opinion_json = excluded.opinion_json,
           model = excluded.model, created_at = excluded.created_at, expires_at = excluded.expires_at",
        params![key, opinion_json, model, now_s, format_ts(now + ttl)?],
    )?;
    Ok(())
}

/// Drop the whole cache (rule pack, trust list or signature change).
pub fn cache_clear(conn: &Connection) -> Result<(), StoreError> {
    conn.execute("DELETE FROM ai_cache", [])?;
    Ok(())
}

/// An opinion to persist.
#[derive(Debug, Clone, PartialEq)]
pub struct NewOpinion {
    pub executable_id: i64,
    pub verdict: String,
    pub confidence: f64,
    pub recommended_action: String,
    pub reasons_json: String,
    pub indicators_json: String,
    pub model: String,
    pub payload_sha256: String,
}

/// A stored opinion.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredOpinion {
    pub id: i64,
    pub verdict: String,
    pub confidence: f64,
    pub recommended_action: String,
    pub reasons_json: String,
    pub indicators_json: String,
    pub model: String,
    pub payload_sha256: String,
    pub created_at: String,
}

pub fn insert_opinion(
    conn: &Connection,
    o: &NewOpinion,
    now: OffsetDateTime,
) -> Result<i64, StoreError> {
    conn.execute(
        "INSERT INTO ai_opinions (executable_id, verdict, confidence, recommended_action,
           reasons_json, indicators_json, model, payload_sha256, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            o.executable_id,
            o.verdict,
            o.confidence,
            o.recommended_action,
            o.reasons_json,
            o.indicators_json,
            o.model,
            o.payload_sha256,
            format_ts(now)?
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn latest_opinion(
    conn: &Connection,
    executable_id: i64,
) -> Result<Option<StoredOpinion>, StoreError> {
    Ok(conn
        .query_row(
            "SELECT id, verdict, confidence, recommended_action, reasons_json, indicators_json,
                    model, payload_sha256, created_at
             FROM ai_opinions WHERE executable_id = ?1 ORDER BY id DESC LIMIT 1",
            [executable_id],
            |r| {
                Ok(StoredOpinion {
                    id: r.get(0)?,
                    verdict: r.get(1)?,
                    confidence: r.get(2)?,
                    recommended_action: r.get(3)?,
                    reasons_json: r.get(4)?,
                    indicators_json: r.get(5)?,
                    model: r.get(6)?,
                    payload_sha256: r.get(7)?,
                    created_at: r.get(8)?,
                })
            },
        )
        .optional()?)
}

/// Link an applied decision to the opinion that caused it.
pub fn link_decision(conn: &Connection, opinion_id: i64, decision_id: i64) -> Result<(), StoreError> {
    conn.execute(
        "UPDATE ai_opinions SET applied_decision_id = ?2 WHERE id = ?1",
        params![opinion_id, decision_id],
    )?;
    Ok(())
}

/// True when the AI already made a decision for this identity within `window` whose action differs
/// from `action` (allow↔block flip-flopping).
pub fn flipped_within(
    conn: &Connection,
    executable_id: i64,
    action: &str,
    window: Duration,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let since = format_ts(now - window)?;
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM decisions
         WHERE executable_id = ?1 AND by = 'ai' AND action <> ?2 AND created_at >= ?3",
        params![executable_id, action, since],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_and_cache_round_trip_with_expiry() {
        let c = crate::open_in_memory().unwrap();
        let now = OffsetDateTime::now_utc();
        setting_put(&c, "k", b"v1").unwrap();
        setting_put(&c, "k", b"v2").unwrap();
        assert_eq!(setting_get(&c, "k").unwrap().unwrap(), b"v2");
        setting_delete(&c, "k").unwrap();
        assert!(setting_get(&c, "k").unwrap().is_none());

        cache_put(&c, "a", "{}", "m", Duration::hours(1), now).unwrap();
        assert!(cache_get(&c, "a", now).unwrap().is_some());
        assert!(cache_get(&c, "a", now + Duration::hours(2)).unwrap().is_none());
        cache_clear(&c).unwrap();
        assert!(cache_get(&c, "a", now).unwrap().is_none());
    }
}

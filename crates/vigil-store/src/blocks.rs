//! Anti-respawn block records (`docs/04 §4`): matched by path or sha256.

use rusqlite::{Connection, OptionalExtension, params};

use crate::StoreError;

/// An active block record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub id: i64,
    pub sha256: String,
    pub path: String,
    pub respawn_kills: u32,
}

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Block> {
    Ok(Block {
        id: r.get(0)?,
        sha256: r.get(1)?,
        path: r.get(2)?,
        respawn_kills: r.get(3)?,
    })
}

const COLS: &str = "id, sha256, path, respawn_kills";

/// Create a record, or return the existing active one for the same sha256.
pub fn upsert(
    conn: &Connection,
    executable_id: Option<i64>,
    sha256: &str,
    path: &str,
    reason: &str,
    now: &str,
) -> Result<i64, StoreError> {
    if let Some(id) = conn
        .query_row(
            "SELECT id FROM block_records WHERE sha256 = ?1 AND removed_at IS NULL",
            params![sha256],
            |r| r.get(0),
        )
        .optional()?
    {
        return Ok(id);
    }
    conn.execute(
        "INSERT INTO block_records (executable_id, sha256, path, reason, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![executable_id, sha256, path, reason, now],
    )?;
    Ok(conn.last_insert_rowid())
}

/// All active records.
pub fn active(conn: &Connection) -> Result<Vec<Block>, StoreError> {
    let mut st = conn.prepare(&format!(
        "SELECT {COLS} FROM block_records WHERE removed_at IS NULL ORDER BY id"
    ))?;
    let rows = st.query_map([], row)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// The active record matching this image by case-insensitive path or by hash.
pub fn find(
    conn: &Connection,
    path: &str,
    sha256: Option<&str>,
) -> Result<Option<Block>, StoreError> {
    Ok(conn
        .query_row(
            &format!(
                "SELECT {COLS} FROM block_records
                 WHERE removed_at IS NULL AND (lower(path) = lower(?1) OR sha256 = ?2) LIMIT 1"
            ),
            params![path, sha256.unwrap_or("")],
            row,
        )
        .optional()?)
}

pub fn count_respawn_kill(conn: &Connection, id: i64) -> Result<(), StoreError> {
    conn.execute(
        "UPDATE block_records SET respawn_kills = respawn_kills + 1 WHERE id = ?1",
        params![id],
    )?;
    Ok(())
}

/// Lift a block. Returns false when it was not active.
pub fn remove(conn: &Connection, id: i64, now: &str) -> Result<bool, StoreError> {
    Ok(conn.execute(
        "UPDATE block_records SET removed_at = ?2 WHERE id = ?1 AND removed_at IS NULL",
        params![id, now],
    )? == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: &str = "2026-01-01T00:00:00Z";

    #[test]
    fn matches_by_path_or_hash_and_counts_respawns() {
        let c = crate::open_in_memory().unwrap();
        let id = upsert(&c, None, "aa", r"C:\Temp\Bad.exe", "user", T).unwrap();
        assert_eq!(
            upsert(&c, None, "aa", r"C:\other.exe", "user", T).unwrap(),
            id
        );
        assert_eq!(find(&c, r"c:\temp\bad.EXE", None).unwrap().unwrap().id, id);
        assert_eq!(
            find(&c, r"D:\renamed.exe", Some("aa")).unwrap().unwrap().id,
            id
        );
        assert!(find(&c, r"D:\renamed.exe", Some("bb")).unwrap().is_none());
        count_respawn_kill(&c, id).unwrap();
        assert_eq!(active(&c).unwrap()[0].respawn_kills, 1);
        assert!(remove(&c, id, T).unwrap());
        assert!(!remove(&c, id, T).unwrap());
        assert!(find(&c, r"C:\Temp\Bad.exe", Some("aa")).unwrap().is_none());
    }
}

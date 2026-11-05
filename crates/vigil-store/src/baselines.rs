//! Local baselines (`docs/18 §2`): how often a parent image started a child image here.

use rusqlite::{Connection, params};

use crate::StoreError;

/// Count one start of `child_key` by `parent_key` (the parent's sha256, the child's lower-case name).
pub fn record(
    conn: &Connection,
    parent_key: &str,
    child_key: &str,
    now: &str,
) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO baselines (parent_key, child_key, first_seen, last_seen) VALUES (?1, ?2, ?3, ?3)
         ON CONFLICT (parent_key, child_key) DO UPDATE SET count = count + 1, last_seen = ?3",
        params![parent_key, child_key, now],
    )?;
    Ok(())
}

/// Total children this parent has started.
pub fn spawns(conn: &Connection, parent_key: &str) -> Result<u32, StoreError> {
    Ok(conn.query_row(
        "SELECT COALESCE(SUM(count), 0) FROM baselines WHERE parent_key = ?1",
        params![parent_key],
        |r| r.get(0),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_every_child_of_a_parent() {
        let c = crate::open_in_memory().unwrap();
        for child in ["cmd.exe", "cmd.exe", "git.exe"] {
            record(&c, "p1", child, "2026-01-01T00:00:00Z").unwrap();
        }
        record(&c, "p2", "cmd.exe", "2026-01-01T00:00:00Z").unwrap();
        assert_eq!(spawns(&c, "p1").unwrap(), 3);
        assert_eq!(spawns(&c, "none").unwrap(), 0);
    }
}

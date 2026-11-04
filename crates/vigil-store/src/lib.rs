#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]
//! SQLite persistence: connection setup, schema migrations and repositories.

pub mod repo;

use rusqlite::Connection;

/// Migration 0001 (`schemas/db.sql`), embedded.
pub const SCHEMA_0001: &str = include_str!("../../../schemas/db.sql");

/// Schema version this build expects (`PRAGMA user_version`).
pub const SCHEMA_VERSION: i64 = 1;

/// Store failures.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("database schema version {found} is newer than supported version {SCHEMA_VERSION}")]
    TooNew { found: i64 },
}

/// Open an in-memory database with connection pragmas applied and the schema migrated.
pub fn open_in_memory() -> Result<Connection, StoreError> {
    let mut conn = Connection::open_in_memory()?;
    configure(&conn)?;
    migrate(&mut conn)?;
    Ok(conn)
}

/// Open (or create) the database file, apply pragmas and migrate.
pub fn open(path: &std::path::Path) -> Result<Connection, StoreError> {
    let mut conn = Connection::open(path)?;
    configure(&conn)?;
    migrate(&mut conn)?;
    Ok(conn)
}

/// Connection-level pragmas, set on every open (not part of the migration).
pub fn configure(conn: &Connection) -> Result<(), StoreError> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    Ok(())
}

/// Bring the database to [`SCHEMA_VERSION`], transactionally. No-op when already current.
pub fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    let found: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if found > SCHEMA_VERSION {
        return Err(StoreError::TooNew { found });
    }
    if found < 1 {
        let tx = conn.transaction()?;
        tx.execute_batch(SCHEMA_0001)?;
        tx.commit()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tables(conn: &Connection) -> Vec<String> {
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
            .unwrap();
        stmt.query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    #[test]
    fn schema_applies_to_in_memory_sqlite() {
        let conn = open_in_memory().unwrap();
        let t = tables(&conn);
        for expected in [
            "audit_log",
            "decisions",
            "evaluations",
            "executables",
            "meta",
            "pending",
            "settings",
        ] {
            assert!(
                t.iter().any(|n| n == expected),
                "missing table {expected}: {t:?}"
            );
        }
        let v: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        let schema: String = conn
            .query_row("SELECT value FROM meta WHERE key='schema'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(schema, "1");
    }

    #[test]
    fn migrate_is_idempotent() {
        let mut conn = open_in_memory().unwrap();
        let before = tables(&conn);
        migrate(&mut conn).unwrap();
        assert_eq!(tables(&conn), before);
    }

    #[test]
    fn newer_schema_is_refused() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", 99).unwrap();
        assert!(matches!(
            migrate(&mut conn),
            Err(StoreError::TooNew { found: 99 })
        ));
    }

    #[test]
    fn audit_log_is_append_only() {
        let conn = open_in_memory().unwrap();
        let cols: Vec<String> = conn
            .prepare("PRAGMA table_info(audit_log)")
            .unwrap()
            .query_map([], |r| r.get(1))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(cols.len() >= 2, "audit_log columns: {cols:?}");
        let triggers: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='trigger' AND tbl_name='audit_log'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(triggers, 2);
    }
}

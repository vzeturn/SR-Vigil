//! Persistence findings and reversible-change backups (`docs/04 §5`).

use rusqlite::{Connection, OptionalExtension, params};

use crate::StoreError;

/// A stored finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub id: i64,
    pub kind: String,
    pub location: String,
    pub image_path: Option<String>,
    pub command: Option<String>,
    pub status: String,
    pub risk_note: Option<String>,
    pub first_seen: String,
}

/// A finding as reported by a scanner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub kind: String,
    pub location: String,
    pub image_path: Option<String>,
    pub command: Option<String>,
    pub risk_note: Option<String>,
}

const COLS: &str = "id, kind, location, image_path, command, status, risk_note, first_seen";

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Item> {
    Ok(Item {
        id: r.get(0)?,
        kind: r.get(1)?,
        location: r.get(2)?,
        image_path: r.get(3)?,
        command: r.get(4)?,
        status: r.get(5)?,
        risk_note: r.get(6)?,
        first_seen: r.get(7)?,
    })
}

/// Record a scan result. A known `(kind, location)` keeps its `first_seen`; an item that was
/// already disabled/deleted keeps its stored details so Restore stays exact.
pub fn upsert(conn: &Connection, f: &Found, now: &str) -> Result<Item, StoreError> {
    conn.execute(
        "INSERT INTO persistence_items (kind, location, image_path, command, risk_note, first_seen, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
         ON CONFLICT (kind, location) DO UPDATE SET
           image_path = excluded.image_path, command = excluded.command,
           risk_note = excluded.risk_note, updated_at = excluded.updated_at
         WHERE status IN ('found', 'restored')",
        params![f.kind, f.location, f.image_path, f.command, f.risk_note, now],
    )?;
    Ok(conn.query_row(
        &format!("SELECT {COLS} FROM persistence_items WHERE kind = ?1 AND location = ?2"),
        params![f.kind, f.location],
        row,
    )?)
}

pub fn get(conn: &Connection, id: i64) -> Result<Option<Item>, StoreError> {
    Ok(conn
        .query_row(
            &format!("SELECT {COLS} FROM persistence_items WHERE id = ?1"),
            params![id],
            row,
        )
        .optional()?)
}

pub fn set_status(conn: &Connection, id: i64, status: &str, now: &str) -> Result<(), StoreError> {
    conn.execute(
        "UPDATE persistence_items SET status = ?2, updated_at = ?3 WHERE id = ?1",
        params![id, status, now],
    )?;
    Ok(())
}

pub fn add_backup(conn: &Connection, id: i64, json: &str, now: &str) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO persistence_backups (item_id, backup_json, created_at) VALUES (?1, ?2, ?3)",
        params![id, json, now],
    )?;
    Ok(())
}

pub fn latest_backup(conn: &Connection, id: i64) -> Result<Option<String>, StoreError> {
    Ok(conn
        .query_row(
            "SELECT backup_json FROM persistence_backups WHERE item_id = ?1 ORDER BY id DESC LIMIT 1",
            params![id],
            |r| r.get(0),
        )
        .optional()?)
}

/// Whether this image is listed as an autostart entry (any kind that is not deleted).
pub fn is_autostart_image(conn: &Connection, path: &str) -> Result<bool, StoreError> {
    Ok(conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM persistence_items
                        WHERE lower(image_path) = lower(?1) AND status != 'deleted')",
        [path],
        |r| r.get(0),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: &str = "2026-01-01T00:00:00Z";

    fn f(cmd: &str) -> Found {
        Found {
            kind: "run_key".into(),
            location: r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\x".into(),
            image_path: Some(r"C:\Temp\x.exe".into()),
            command: Some(cmd.into()),
            risk_note: None,
        }
    }

    #[test]
    fn rescan_keeps_first_seen_and_disabled_items_keep_their_original() {
        let c = crate::open_in_memory().unwrap();
        let a = upsert(&c, &f("a"), T).unwrap();
        assert_eq!(a.status, "found");
        set_status(&c, a.id, "disabled", T).unwrap();
        add_backup(&c, a.id, r#"{"v":1}"#, T).unwrap();
        let b = upsert(&c, &f("changed"), "2026-02-01T00:00:00Z").unwrap();
        assert_eq!((b.id, b.status.as_str()), (a.id, "disabled"));
        assert_eq!(b.command.as_deref(), Some("a"));
        assert_eq!(b.first_seen, T);
        assert_eq!(
            latest_backup(&c, a.id).unwrap().as_deref(),
            Some(r#"{"v":1}"#)
        );
    }
}

//! Pending decisions and stored decisions (`pending`, `decisions`). All timestamps derive from an
//! injected `now`; there is no clock access here. Every statement uses bound parameters.

use rusqlite::{Connection, OptionalExtension, Row, params};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime, UtcOffset};

use crate::StoreError;

macro_rules! text_enum {
    ($(#[$m:meta])* $name:ident { $($variant:ident => $s:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name { $($variant),+ }
        impl $name {
            #[must_use]
            pub fn as_str(self) -> &'static str { match self { $(Self::$variant => $s),+ } }
            #[must_use]
            pub fn parse(s: &str) -> Option<Self> { match s { $($s => Some(Self::$variant),)+ _ => None } }
        }
    };
}

text_enum!(/// What a decision does.
    Action { Allow => "allow", Block => "block", Kill => "kill" });
text_enum!(/// How long a decision lasts. `once` is applied by the caller at submit time and is never
    /// returned as active afterwards (its `expires_at` equals its creation time).
    Scope { Once => "once", OneHour => "1h", Day => "24h", Forever => "forever" });
text_enum!(/// What a decision covers.
    ApplyTo { File => "file", Publisher => "publisher", PackageSource => "package_source" });
text_enum!(/// Who made the decision.
    DecidedBy { User => "user", Ai => "ai", Rule => "rule" });
text_enum!(/// Destination class of a pending connection.
    DestClass { Private => "private", Public => "public", Loopback => "loopback" });

/// Canonical timestamp text: UTC, whole seconds, so string comparison orders chronologically.
pub fn format_ts(t: OffsetDateTime) -> Result<String, StoreError> {
    t.to_offset(UtcOffset::UTC)
        .replace_nanosecond(0)
        .map_err(|e| StoreError::Time(e.to_string()))?
        .format(&Rfc3339)
        .map_err(|e| StoreError::Time(e.to_string()))
}

/// `expires_at` for a scope created at `now`; `None` means never.
#[must_use]
pub fn expiry(scope: Scope, now: OffsetDateTime) -> Option<OffsetDateTime> {
    match scope {
        Scope::Once => Some(now),
        Scope::OneHour => Some(now + Duration::hours(1)),
        Scope::Day => Some(now + Duration::hours(24)),
        Scope::Forever => None,
    }
}

// ---------------------------------------------------------------- pending

/// A connection awaiting a user/AI decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPending {
    pub executable_id: i64,
    pub dest_class: DestClass,
    pub dest_addr: String,
    pub dest_port: u16,
    pub dns_name: Option<String>,
}

/// A stored pending row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub id: i64,
    pub executable_id: i64,
    pub dest_class: DestClass,
    pub dest_addr: String,
    pub dest_port: u16,
    pub dns_name: Option<String>,
    pub created_at: String,
    pub resolved_at: Option<String>,
    pub resolution_decision_id: Option<i64>,
}

const PENDING_COLS: &str = "id, executable_id, dest_class, dest_addr, dest_port, dns_name, created_at, resolved_at, resolution_decision_id";

fn pending_row(r: &Row<'_>) -> Result<Pending, StoreError> {
    let class: String = r.get(2)?;
    Ok(Pending {
        id: r.get(0)?,
        executable_id: r.get(1)?,
        dest_class: DestClass::parse(&class)
            .ok_or_else(|| StoreError::Corrupt("pending.dest_class".into()))?,
        dest_addr: r.get(3)?,
        dest_port: r.get(4)?,
        dns_name: r.get(5)?,
        created_at: r.get(6)?,
        resolved_at: r.get(7)?,
        resolution_decision_id: r.get(8)?,
    })
}

/// Create a pending row, deduplicated by `(executable_id, dest_class)` while unresolved.
/// Returns `(id, created)`; when a row is already open its id is returned with `created = false`.
pub fn create_pending(
    conn: &Connection,
    p: &NewPending,
    now: OffsetDateTime,
) -> Result<(i64, bool), StoreError> {
    let changed = conn.execute(
        "INSERT INTO pending (executable_id, dest_class, dest_addr, dest_port, dns_name, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (executable_id, dest_class) WHERE resolved_at IS NULL DO NOTHING",
        params![
            p.executable_id,
            p.dest_class.as_str(),
            p.dest_addr,
            p.dest_port,
            p.dns_name,
            format_ts(now)?
        ],
    )?;
    if changed == 1 {
        return Ok((conn.last_insert_rowid(), true));
    }
    let id = conn.query_row(
        "SELECT id FROM pending WHERE executable_id = ?1 AND dest_class = ?2 AND resolved_at IS NULL",
        params![p.executable_id, p.dest_class.as_str()],
        |r| r.get(0),
    )?;
    Ok((id, false))
}

/// Unresolved pending rows, oldest first.
pub fn list_pending(conn: &Connection) -> Result<Vec<Pending>, StoreError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {PENDING_COLS} FROM pending WHERE resolved_at IS NULL ORDER BY id"
    ))?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(pending_row(r)?);
    }
    Ok(out)
}

/// One pending row by id (resolved or not).
pub fn get_pending(conn: &Connection, id: i64) -> Result<Option<Pending>, StoreError> {
    let mut stmt = conn.prepare(&format!("SELECT {PENDING_COLS} FROM pending WHERE id = ?1"))?;
    let mut rows = stmt.query([id])?;
    rows.next()?.map(pending_row).transpose()
}

/// Mark one pending row resolved by a decision. Returns false when it was already resolved or is unknown.
pub fn resolve_pending(
    conn: &Connection,
    pending_id: i64,
    decision_id: i64,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let n = conn.execute(
        "UPDATE pending SET resolved_at = ?1, resolution_decision_id = ?2
         WHERE id = ?3 AND resolved_at IS NULL",
        params![format_ts(now)?, decision_id, pending_id],
    )?;
    Ok(n == 1)
}

/// Resolve every open pending row of an executable (a decision covers all its destinations).
pub fn resolve_pending_for_executable(
    conn: &Connection,
    executable_id: i64,
    decision_id: i64,
    now: OffsetDateTime,
) -> Result<usize, StoreError> {
    Ok(conn.execute(
        "UPDATE pending SET resolved_at = ?1, resolution_decision_id = ?2
         WHERE executable_id = ?3 AND resolved_at IS NULL",
        params![format_ts(now)?, decision_id, executable_id],
    )?)
}

// -------------------------------------------------------------- decisions

/// A decision to persist. `publisher_thumbprint` is required when `apply_to` is `Publisher`,
/// `package_family` when it is `PackageSource`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDecision {
    pub executable_id: i64,
    pub action: Action,
    pub scope: Scope,
    pub apply_to: ApplyTo,
    pub publisher_thumbprint: Option<String>,
    pub publisher_product: Option<String>,
    pub package_family: Option<String>,
    pub by: DecidedBy,
    pub actor: String,
    pub note: Option<String>,
}

/// A stored decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub id: i64,
    pub executable_id: i64,
    pub action: Action,
    pub scope: Scope,
    pub apply_to: ApplyTo,
    pub publisher_thumbprint: Option<String>,
    pub publisher_product: Option<String>,
    pub package_family: Option<String>,
    pub expires_at: Option<String>,
    pub by: DecidedBy,
    pub actor: String,
    pub note: Option<String>,
    pub created_at: String,
    pub revoked_at: Option<String>,
}

const DECISION_COLS: &str = "d.id, d.executable_id, d.action, d.scope, d.apply_to, d.publisher_thumbprint, d.publisher_product, d.expires_at, d.by, d.actor, d.note, d.created_at, d.revoked_at, d.package_family";

fn decision_row(r: &Row<'_>) -> Result<Decision, StoreError> {
    let bad = |c: &str| StoreError::Corrupt(format!("decisions.{c}"));
    let s = |i: usize| r.get::<_, String>(i);
    Ok(Decision {
        id: r.get(0)?,
        executable_id: r.get(1)?,
        action: Action::parse(&s(2)?).ok_or_else(|| bad("action"))?,
        scope: Scope::parse(&s(3)?).ok_or_else(|| bad("scope"))?,
        apply_to: ApplyTo::parse(&s(4)?).ok_or_else(|| bad("apply_to"))?,
        publisher_thumbprint: r.get(5)?,
        publisher_product: r.get(6)?,
        expires_at: r.get(7)?,
        by: DecidedBy::parse(&s(8)?).ok_or_else(|| bad("by"))?,
        actor: r.get(9)?,
        note: r.get(10)?,
        created_at: r.get(11)?,
        revoked_at: r.get(12)?,
        package_family: r.get(13)?,
    })
}

/// Insert a decision; `expires_at` is computed from `now` and the scope. Returns the new id.
pub fn insert_decision(
    conn: &Connection,
    d: &NewDecision,
    now: OffsetDateTime,
) -> Result<i64, StoreError> {
    let expires = expiry(d.scope, now).map(format_ts).transpose()?;
    conn.execute(
        "INSERT INTO decisions (executable_id, action, scope, apply_to, publisher_thumbprint,
                                publisher_product, expires_at, by, actor, note, created_at,
                                package_family)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            d.executable_id,
            d.action.as_str(),
            d.scope.as_str(),
            d.apply_to.as_str(),
            d.publisher_thumbprint,
            d.publisher_product,
            expires,
            d.by.as_str(),
            d.actor,
            d.note,
            format_ts(now)?,
            d.package_family
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Revoke a decision. Returns false when unknown or already revoked.
pub fn revoke_decision(
    conn: &Connection,
    decision_id: i64,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let n = conn.execute(
        "UPDATE decisions SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
        params![format_ts(now)?, decision_id],
    )?;
    Ok(n == 1)
}

/// One decision by id.
pub fn get_decision(conn: &Connection, id: i64) -> Result<Option<Decision>, StoreError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {DECISION_COLS} FROM decisions d WHERE d.id = ?1"
    ))?;
    let mut rows = stmt.query([id])?;
    rows.next()?.map(decision_row).transpose()
}

fn collect(
    conn: &Connection,
    sql: &str,
    p: impl rusqlite::Params,
) -> Result<Vec<Decision>, StoreError> {
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query(p)?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(decision_row(r)?);
    }
    Ok(out)
}

/// Decisions neither revoked nor expired at `now`, newest first.
pub fn list_active(conn: &Connection, now: OffsetDateTime) -> Result<Vec<Decision>, StoreError> {
    collect(
        conn,
        &format!(
            "SELECT {DECISION_COLS} FROM decisions d
             WHERE d.revoked_at IS NULL AND (d.expires_at IS NULL OR d.expires_at > ?1)
             ORDER BY d.id DESC"
        ),
        [format_ts(now)?],
    )
}

/// Active decisions that apply to an executable: its own file decisions plus publisher decisions
/// matching its signer thumbprint and package-family decisions matching its recorded family. Newest first; resolving conflicts is the caller's policy.
pub fn active_for(
    conn: &Connection,
    executable_id: i64,
    now: OffsetDateTime,
) -> Result<Vec<Decision>, StoreError> {
    collect(
        conn,
        &format!(
            "SELECT {DECISION_COLS} FROM decisions d
             WHERE d.revoked_at IS NULL AND (d.expires_at IS NULL OR d.expires_at > ?2)
               AND ((d.apply_to = 'file' AND d.executable_id = ?1)
                 OR (d.apply_to = 'publisher' AND d.publisher_thumbprint =
                     (SELECT signer_thumbprint FROM executables WHERE id = ?1))
                 OR (d.apply_to = 'package_source' AND d.package_family =
                     (SELECT package_family FROM executables WHERE id = ?1)))
             ORDER BY d.id DESC"
        ),
        params![executable_id, format_ts(now)?],
    )
}

/// Whether the executable id exists (guard before inserting rows that reference it).
pub fn executable_exists(conn: &Connection, id: i64) -> Result<bool, StoreError> {
    Ok(conn
        .query_row("SELECT 1 FROM executables WHERE id = ?1", [id], |_| Ok(()))
        .optional()?
        .is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::{Executable, upsert_executable};
    use time::macros::datetime;

    const T0: OffsetDateTime = datetime!(2026-01-01 00:00:00 UTC);

    fn exe(conn: &Connection, sha_char: char, thumb: Option<&str>) -> i64 {
        let e = Executable {
            sha256: sha_char.to_string().repeat(64),
            path: format!("C:\\app\\{sha_char}.exe"),
            signer_thumbprint: thumb.map(str::to_owned),
            publisher: None,
            company: None,
            product: None,
            original_filename: None,
            signature_status: "unsigned".into(),
        };
        upsert_executable(conn, &e, &format_ts(T0).unwrap()).unwrap()
    }

    fn file_decision(id: i64, scope: Scope) -> NewDecision {
        NewDecision {
            executable_id: id,
            action: Action::Allow,
            scope,
            apply_to: ApplyTo::File,
            publisher_thumbprint: None,
            publisher_product: None,
            package_family: None,
            by: DecidedBy::User,
            actor: "alice".into(),
            note: None,
        }
    }

    fn pend(id: i64, class: DestClass, addr: &str) -> NewPending {
        NewPending {
            executable_id: id,
            dest_class: class,
            dest_addr: addr.into(),
            dest_port: 443,
            dns_name: None,
        }
    }

    #[test]
    fn pending_is_deduped_while_open_then_reopens_after_resolve() {
        let conn = crate::open_in_memory().unwrap();
        let id = exe(&conn, 'a', None);
        let (p1, c1) = create_pending(&conn, &pend(id, DestClass::Public, "1.1.1.1"), T0).unwrap();
        let (p2, c2) = create_pending(&conn, &pend(id, DestClass::Public, "8.8.8.8"), T0).unwrap();
        assert!(c1 && !c2 && p1 == p2);
        let (p3, c3) =
            create_pending(&conn, &pend(id, DestClass::Private, "10.0.0.1"), T0).unwrap();
        assert!(c3 && p3 != p1);
        assert_eq!(list_pending(&conn).unwrap().len(), 2);

        let d = insert_decision(&conn, &file_decision(id, Scope::Forever), T0).unwrap();
        assert!(resolve_pending(&conn, p1, d, T0).unwrap());
        assert!(!resolve_pending(&conn, p1, d, T0).unwrap());
        assert_eq!(
            get_pending(&conn, p1)
                .unwrap()
                .unwrap()
                .resolution_decision_id,
            Some(d)
        );
        assert_eq!(list_pending(&conn).unwrap().len(), 1);
        let (p4, c4) = create_pending(&conn, &pend(id, DestClass::Public, "1.1.1.1"), T0).unwrap();
        assert!(c4 && p4 != p1);
        assert_eq!(resolve_pending_for_executable(&conn, id, d, T0).unwrap(), 2);
        assert_eq!(list_pending(&conn).unwrap().len(), 0);
    }

    #[test]
    fn scope_expiry_uses_injected_clock() {
        let conn = crate::open_in_memory().unwrap();
        let id = exe(&conn, 'a', None);
        let once = insert_decision(&conn, &file_decision(id, Scope::Once), T0).unwrap();
        let h1 = insert_decision(&conn, &file_decision(id, Scope::OneHour), T0).unwrap();
        let h24 = insert_decision(&conn, &file_decision(id, Scope::Day), T0).unwrap();
        let fv = insert_decision(&conn, &file_decision(id, Scope::Forever), T0).unwrap();
        let ids = |now| -> Vec<i64> {
            let mut v: Vec<i64> = active_for(&conn, id, now)
                .unwrap()
                .iter()
                .map(|d| d.id)
                .collect();
            v.sort_unstable();
            v
        };
        assert_eq!(ids(T0), [h1, h24, fv]);
        assert_eq!(ids(T0 + Duration::minutes(59)), [h1, h24, fv]);
        assert_eq!(ids(T0 + Duration::hours(1)), [h24, fv]);
        assert_eq!(ids(T0 + Duration::hours(24)), [fv]);
        assert_eq!(ids(T0 + Duration::days(3650)), [fv]);
        assert_eq!(
            get_decision(&conn, once)
                .unwrap()
                .unwrap()
                .expires_at
                .as_deref(),
            Some("2026-01-01T00:00:00Z")
        );
        assert_eq!(get_decision(&conn, fv).unwrap().unwrap().expires_at, None);
    }

    #[test]
    fn revoke_removes_from_active_once() {
        let conn = crate::open_in_memory().unwrap();
        let id = exe(&conn, 'a', None);
        let d = insert_decision(&conn, &file_decision(id, Scope::Forever), T0).unwrap();
        assert_eq!(list_active(&conn, T0).unwrap().len(), 1);
        assert!(revoke_decision(&conn, d, T0).unwrap());
        assert!(!revoke_decision(&conn, d, T0).unwrap());
        assert_eq!(list_active(&conn, T0).unwrap().len(), 0);
        assert_eq!(active_for(&conn, id, T0).unwrap().len(), 0);
        assert!(
            get_decision(&conn, d)
                .unwrap()
                .unwrap()
                .revoked_at
                .is_some()
        );
    }

    #[test]
    fn publisher_decision_covers_same_signer_only() {
        let conn = crate::open_in_memory().unwrap();
        let pub_a = exe(&conn, 'a', Some("AA11"));
        let pub_b = exe(&conn, 'b', Some("AA11"));
        let pub_c = exe(&conn, 'c', Some("CC33"));
        let unsigned = exe(&conn, 'd', None);
        let mut nd = file_decision(pub_a, Scope::Forever);
        nd.apply_to = ApplyTo::Publisher;
        nd.publisher_thumbprint = Some("AA11".into());
        let d = insert_decision(&conn, &nd, T0).unwrap();
        assert_eq!(active_for(&conn, pub_a, T0).unwrap()[0].id, d);
        assert_eq!(active_for(&conn, pub_b, T0).unwrap()[0].id, d);
        assert_eq!(active_for(&conn, pub_c, T0).unwrap().len(), 0);
        assert_eq!(active_for(&conn, unsigned, T0).unwrap().len(), 0);
    }

    #[test]
    fn package_decision_covers_the_same_family_only() {
        let conn = crate::open_in_memory().unwrap();
        let fam = "https://github.com/awslabs/|c:\\uv\\tools";
        let a = exe(&conn, 'a', None);
        let b = exe(&conn, 'b', None);
        let other_folder = exe(&conn, 'c', None);
        let plain = exe(&conn, 'd', None);
        crate::repo::set_package_family(&conn, a, Some(fam)).unwrap();
        crate::repo::set_package_family(&conn, b, Some(fam)).unwrap();
        crate::repo::set_package_family(
            &conn,
            other_folder,
            Some("https://github.com/awslabs/|d:\\venv"),
        )
        .unwrap();
        let mut nd = file_decision(a, Scope::Forever);
        nd.apply_to = ApplyTo::PackageSource;
        nd.package_family = Some(fam.into());
        let d = insert_decision(&conn, &nd, T0).unwrap();
        assert_eq!(active_for(&conn, a, T0).unwrap()[0].id, d);
        assert_eq!(active_for(&conn, b, T0).unwrap()[0].id, d);
        assert_eq!(active_for(&conn, other_folder, T0).unwrap().len(), 0);
        assert_eq!(active_for(&conn, plain, T0).unwrap().len(), 0);
        assert_eq!(
            crate::repo::paths_by_package_family(&conn, fam)
                .unwrap()
                .len(),
            2
        );
        // Leaving the family (metadata no longer trusted) drops the cover at once.
        crate::repo::set_package_family(&conn, b, None).unwrap();
        assert_eq!(active_for(&conn, b, T0).unwrap().len(), 0);
        nd.package_family = None;
        assert!(insert_decision(&conn, &nd, T0).is_err());
    }

    #[test]
    fn publisher_scope_requires_thumbprint() {
        let conn = crate::open_in_memory().unwrap();
        let id = exe(&conn, 'a', None);
        let mut nd = file_decision(id, Scope::Forever);
        nd.apply_to = ApplyTo::Publisher;
        assert!(insert_decision(&conn, &nd, T0).is_err());
    }

    #[test]
    fn hostile_strings_are_data() {
        let conn = crate::open_in_memory().unwrap();
        let id = exe(&conn, 'a', None);
        let mut nd = file_decision(id, Scope::Forever);
        nd.note = Some("'); DROP TABLE decisions;--".into());
        let d = insert_decision(&conn, &nd, T0).unwrap();
        assert_eq!(get_decision(&conn, d).unwrap().unwrap().note, nd.note);
    }

    #[test]
    fn timestamps_are_normalised_to_utc_seconds() {
        let t = datetime!(2026-01-01 07:00:00.987 +7);
        assert_eq!(format_ts(t).unwrap(), "2026-01-01T00:00:00Z");
    }
}

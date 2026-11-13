//! Repositories for executables and evaluations. Every statement uses bound parameters; host
//! strings (paths, names) are data only.

use rusqlite::{Connection, OptionalExtension, params};

use crate::StoreError;

/// An executable identity: `(sha256, lower(path), signer thumbprint)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Executable {
    pub sha256: String,
    pub path: String,
    pub signer_thumbprint: Option<String>,
    pub publisher: Option<String>,
    pub company: Option<String>,
    pub product: Option<String>,
    pub original_filename: Option<String>,
    /// One of the `signature_status` values of `schemas/db.sql`.
    pub signature_status: String,
}

/// An evaluation result to persist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEvaluation {
    pub score: u8,
    pub verdict: String,
    pub hard_rule: Option<String>,
    pub signals_json: String,
    pub rule_pack_version: String,
    /// `rules`, `ai`, `user` or `cache`.
    pub source: String,
}

/// A stored evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvaluation {
    pub id: i64,
    pub executable_id: i64,
    pub score: u8,
    pub verdict: String,
    pub hard_rule: Option<String>,
    pub signals_json: String,
    pub rule_pack_version: String,
    pub source: String,
    pub evaluated_at: String,
}

/// Insert the identity, or refresh `last_seen` and metadata when it already exists. Returns its id.
pub fn upsert_executable(
    conn: &Connection,
    exe: &Executable,
    now: &str,
) -> Result<i64, StoreError> {
    conn.execute(
        "INSERT INTO executables (sha256, path, signer_thumbprint, publisher, company, product,
                                  original_filename, signature_status, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
         ON CONFLICT (sha256, lower(path), COALESCE(signer_thumbprint, 'unsigned'))
         DO UPDATE SET last_seen = excluded.last_seen,
                       publisher = excluded.publisher,
                       company = excluded.company,
                       product = excluded.product,
                       original_filename = excluded.original_filename,
                       signature_status = excluded.signature_status",
        params![
            exe.sha256,
            exe.path,
            exe.signer_thumbprint,
            exe.publisher,
            exe.company,
            exe.product,
            exe.original_filename,
            exe.signature_status,
            now
        ],
    )?;
    let id = conn.query_row(
        "SELECT id FROM executables
         WHERE sha256 = ?1 AND lower(path) = lower(?2)
           AND COALESCE(signer_thumbprint, 'unsigned') = COALESCE(?3, 'unsigned')",
        params![exe.sha256, exe.path, exe.signer_thumbprint],
        |r| r.get(0),
    )?;
    Ok(id)
}

/// Append an evaluation for `executable_id`.
pub fn insert_evaluation(
    conn: &Connection,
    executable_id: i64,
    ev: &NewEvaluation,
    now: &str,
) -> Result<i64, StoreError> {
    conn.execute(
        "INSERT INTO evaluations (executable_id, score, verdict, hard_rule, signals_json,
                                  rule_pack_version, source, evaluated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            executable_id,
            ev.score,
            ev.verdict,
            ev.hard_rule,
            ev.signals_json,
            ev.rule_pack_version,
            ev.source,
            now
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// The executable identity stored under `id`.
pub fn executable_by_id(conn: &Connection, id: i64) -> Result<Option<Executable>, StoreError> {
    Ok(conn
        .query_row(
            "SELECT sha256, path, signer_thumbprint, publisher, company, product,
                    original_filename, signature_status
             FROM executables WHERE id = ?1",
            params![id],
            |r| {
                Ok(Executable {
                    sha256: r.get(0)?,
                    path: r.get(1)?,
                    signer_thumbprint: r.get(2)?,
                    publisher: r.get(3)?,
                    company: r.get(4)?,
                    product: r.get(5)?,
                    original_filename: r.get(6)?,
                    signature_status: r.get(7)?,
                })
            },
        )
        .optional()?)
}

/// Most recent evaluation of an executable.
pub fn latest_evaluation(
    conn: &Connection,
    executable_id: i64,
) -> Result<Option<StoredEvaluation>, StoreError> {
    Ok(conn
        .query_row(
            "SELECT id, executable_id, score, verdict, hard_rule, signals_json,
                    rule_pack_version, source, evaluated_at
             FROM evaluations WHERE executable_id = ?1
             ORDER BY evaluated_at DESC, id DESC LIMIT 1",
            params![executable_id],
            |r| {
                Ok(StoredEvaluation {
                    id: r.get(0)?,
                    executable_id: r.get(1)?,
                    score: r.get(2)?,
                    verdict: r.get(3)?,
                    hard_rule: r.get(4)?,
                    signals_json: r.get(5)?,
                    rule_pack_version: r.get(6)?,
                    source: r.get(7)?,
                    evaluated_at: r.get(8)?,
                })
            },
        )
        .optional()?)
}

/// Id of the most recently seen executable stored under `path` (case-insensitive).
pub fn executable_id_by_path(conn: &Connection, path: &str) -> Result<Option<i64>, StoreError> {
    Ok(conn
        .query_row(
            "SELECT id FROM executables WHERE lower(path) = lower(?1) ORDER BY last_seen DESC LIMIT 1",
            params![path],
            |r| r.get(0),
        )
        .optional()?)
}

fn paths(
    conn: &Connection,
    sql: &str,
    p: impl rusqlite::Params,
) -> Result<Vec<String>, StoreError> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(p, |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Record the package family of an executable (`docs/19 §5.1`); `None` clears it, so a launcher
/// whose metadata no longer names a trusted source leaves the family.
pub fn set_package_family(
    conn: &Connection,
    id: i64,
    family: Option<&str>,
) -> Result<(), StoreError> {
    conn.execute(
        "UPDATE executables SET package_family = ?2 WHERE id = ?1",
        params![id, family],
    )?;
    Ok(())
}

/// The package family recorded for an executable, if any.
pub fn package_family(conn: &Connection, id: i64) -> Result<Option<String>, StoreError> {
    Ok(conn
        .query_row(
            "SELECT package_family FROM executables WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )
        .optional()?
        .flatten())
}

/// Paths of every known executable of a package family.
pub fn paths_by_package_family(conn: &Connection, family: &str) -> Result<Vec<String>, StoreError> {
    paths(
        conn,
        "SELECT DISTINCT path FROM executables WHERE package_family = ?1",
        params![family],
    )
}

/// Paths of every known executable signed by `thumbprint`.
pub fn paths_by_thumbprint(conn: &Connection, thumbprint: &str) -> Result<Vec<String>, StoreError> {
    paths(
        conn,
        "SELECT DISTINCT path FROM executables WHERE signer_thumbprint = ?1",
        params![thumbprint],
    )
}

/// Paths of every known executable whose latest evaluation has `verdict`.
pub fn paths_with_verdict(conn: &Connection, verdict: &str) -> Result<Vec<String>, StoreError> {
    paths(
        conn,
        "SELECT DISTINCT e.path FROM executables e WHERE
           (SELECT v.verdict FROM evaluations v WHERE v.executable_id = e.id
            ORDER BY v.evaluated_at DESC, v.id DESC LIMIT 1) = ?1",
        params![verdict],
    )
}

/// Number of unresolved pending items.
pub fn pending_count(conn: &Connection) -> Result<u32, StoreError> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM pending WHERE resolved_at IS NULL",
        [],
        |r| r.get(0),
    )?)
}

/// SHA-256 of every unsigned executable whose latest evaluation has `verdict`.
pub fn unsigned_shas_with_verdict(
    conn: &Connection,
    verdict: &str,
) -> Result<Vec<String>, StoreError> {
    paths(
        conn,
        "SELECT DISTINCT e.sha256 FROM executables e WHERE e.signature_status = 'unsigned' AND
           (SELECT v.verdict FROM evaluations v WHERE v.executable_id = e.id
            ORDER BY v.evaluated_at DESC, v.id DESC LIMIT 1) = ?1",
        params![verdict],
    )
}

/// Every recorded path of the file with this SHA-256.
pub fn paths_with_sha(conn: &Connection, sha256: &str) -> Result<Vec<String>, StoreError> {
    paths(
        conn,
        "SELECT DISTINCT path FROM executables WHERE lower(sha256) = lower(?1)",
        params![sha256],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exe(path: &str, thumb: Option<&str>) -> Executable {
        Executable {
            sha256: "a".repeat(64),
            path: path.into(),
            signer_thumbprint: thumb.map(Into::into),
            publisher: None,
            company: None,
            product: None,
            original_filename: None,
            signature_status: "unsigned".into(),
        }
    }

    fn ev(score: u8, verdict: &str) -> NewEvaluation {
        NewEvaluation {
            score,
            verdict: verdict.into(),
            hard_rule: None,
            signals_json: "[]".into(),
            rule_pack_version: "1".into(),
            source: "rules".into(),
        }
    }

    #[test]
    fn upsert_is_idempotent_case_insensitive_on_path_and_refreshes_last_seen() {
        let c = crate::open_in_memory().unwrap();
        let a = upsert_executable(&c, &exe("C:\\A\\x.exe", None), "t1").unwrap();
        let b = upsert_executable(&c, &exe("c:\\a\\X.EXE", None), "t2").unwrap();
        assert_eq!(a, b);
        let (first, last): (String, String) = c
            .query_row(
                "SELECT first_seen, last_seen FROM executables WHERE id = ?1",
                [a],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((first.as_str(), last.as_str()), ("t1", "t2"));
        let other = upsert_executable(&c, &exe("C:\\A\\x.exe", Some("AB")), "t3").unwrap();
        assert_ne!(a, other, "a different signer is a different identity");
    }

    #[test]
    fn latest_evaluation_wins_and_hostile_strings_stay_data() {
        let c = crate::open_in_memory().unwrap();
        let hostile = "C:\\x'); DROP TABLE executables;--.exe";
        let id = upsert_executable(&c, &exe(hostile, None), "t1").unwrap();
        insert_evaluation(&c, id, &ev(40, "unknown"), "t1").unwrap();
        insert_evaluation(&c, id, &ev(10, "malicious"), "t2").unwrap();
        let got = latest_evaluation(&c, id).unwrap().unwrap();
        assert_eq!((got.score, got.verdict.as_str()), (10, "malicious"));
        let path: String = c
            .query_row("SELECT path FROM executables WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(path, hostile);
        assert!(latest_evaluation(&c, id + 99).unwrap().is_none());
    }
}

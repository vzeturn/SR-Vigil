//! Reclaimable junk (temp files, crash dumps, caches). Scanning is read-only; deleting happens only
//! when the caller passes explicit category ids after the user approved them (CLAUDE.md rule 4).
//!
//! Only plain files inside fixed per-user/system cache folders are ever removed; reparse points
//! (symlinks, junctions) are never followed or deleted, and recent files are left alone.

use std::fs;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const REPARSE_POINT: u32 = 0x400;
const DAY: Duration = Duration::from_secs(24 * 3600);

/// One cleanable category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Category {
    pub id: &'static str,
    pub files: u64,
    pub bytes: u64,
}

struct Spec {
    id: &'static str,
    roots: Vec<PathBuf>,
    /// File-name prefix filter (thumbnail caches share a folder with user-visible state).
    prefix: Option<&'static str>,
    min_age: Duration,
}

fn env_path(k: &str) -> Option<PathBuf> {
    std::env::var_os(k).map(PathBuf::from)
}

fn specs() -> Vec<Spec> {
    let local = env_path("LOCALAPPDATA");
    let under = |rel: &str| local.iter().map(|l| l.join(rel)).collect::<Vec<_>>();
    vec![
        Spec {
            id: "user_temp",
            roots: env_path("TEMP").into_iter().collect(),
            prefix: None,
            min_age: DAY,
        },
        Spec {
            id: "windows_temp",
            roots: env_path("SystemRoot")
                .map(|r| r.join("Temp"))
                .into_iter()
                .collect(),
            prefix: None,
            min_age: DAY,
        },
        Spec {
            id: "crash_dumps",
            roots: under("CrashDumps"),
            prefix: None,
            min_age: DAY,
        },
        Spec {
            id: "error_reports",
            roots: [
                r"Microsoft\Windows\WER\ReportArchive",
                r"Microsoft\Windows\WER\ReportQueue",
            ]
            .iter()
            .flat_map(|r| under(r))
            .collect(),
            prefix: None,
            min_age: DAY,
        },
        Spec {
            id: "thumbnails",
            roots: under(r"Microsoft\Windows\Explorer"),
            prefix: Some("thumbcache_"),
            min_age: Duration::ZERO,
        },
        Spec {
            id: "web_cache",
            roots: under(r"Microsoft\Windows\INetCache"),
            prefix: None,
            min_age: DAY,
        },
    ]
}

/// Files of `root` (recursive, no reparse points) that qualify as junk.
fn collect(root: &Path, prefix: Option<&str>, min_age: Duration, out: &mut Vec<(PathBuf, u64)>) {
    let Ok(rd) = fs::read_dir(root) else { return };
    let now = SystemTime::now();
    for e in rd.flatten() {
        let Ok(md) = fs::symlink_metadata(e.path()) else {
            continue;
        };
        if md.file_attributes() & REPARSE_POINT != 0 {
            continue;
        }
        if md.is_dir() {
            collect(&e.path(), prefix, min_age, out);
        } else if md.is_file() {
            let name_ok = prefix.is_none_or(|p| {
                e.file_name()
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .starts_with(p)
            });
            let old = md
                .modified()
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .is_some_and(|age| age >= min_age);
            if name_ok && old {
                out.push((e.path(), md.len()));
            }
        }
    }
}

fn gather(spec: &Spec) -> Vec<(PathBuf, u64)> {
    let mut files = Vec::new();
    for r in &spec.roots {
        collect(r, spec.prefix, spec.min_age, &mut files);
    }
    files
}

/// Read-only survey of every category.
#[must_use]
pub fn scan() -> Vec<Category> {
    specs()
        .iter()
        .map(|s| {
            let f = gather(s);
            Category {
                id: s.id,
                files: f.len() as u64,
                bytes: f.iter().map(|(_, n)| n).sum(),
            }
        })
        .collect()
}

/// Delete the files of the approved categories; returns bytes freed. Files in use are skipped.
#[must_use]
pub fn clean(ids: &[String]) -> u64 {
    let mut freed = 0;
    for s in specs().iter().filter(|s| ids.iter().any(|i| i == s.id)) {
        for (path, len) in gather(s) {
            if fs::remove_file(&path).is_ok() {
                freed += len;
            }
        }
        tracing::info!(category = s.id, "junk category cleaned");
    }
    freed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vigil-junk-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("sub")).unwrap();
        d
    }

    #[test]
    fn collects_old_files_only_and_honours_prefix() {
        let d = tmp("collect");
        fs::write(d.join("sub").join("a.tmp"), b"1234").unwrap();
        fs::write(d.join("thumbcache_32.db"), b"12").unwrap();
        let mut all = Vec::new();
        collect(&d, None, Duration::ZERO, &mut all);
        assert_eq!(all.len(), 2);
        let mut pre = Vec::new();
        collect(&d, Some("thumbcache_"), Duration::ZERO, &mut pre);
        assert_eq!(pre.len(), 1);
        let mut recent = Vec::new();
        collect(&d, None, DAY, &mut recent);
        assert!(recent.is_empty(), "fresh files must survive");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn scan_never_deletes_and_clean_ignores_unknown_ids() {
        let d = tmp("ids");
        fs::write(d.join("keep.tmp"), b"x").unwrap();
        assert_eq!(clean(&["../etc".to_owned(), String::new()]), 0);
        let _ = scan();
        assert!(d.join("keep.tmp").exists());
        let _ = fs::remove_dir_all(&d);
    }
}

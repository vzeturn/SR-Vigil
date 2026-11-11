//! File and credential-store activity (`docs/15 §2`): FIL-001 executable drops, FIL-002 mass
//! renames and RES-001 credential-store opens, from the embedded `rules/files.toml`. Paths are
//! untrusted host strings, compared only. These run on the ETW callback for every matching file
//! event, so the common path (no match) allocates nothing.

use std::collections::{HashMap, VecDeque};
use std::sync::OnceLock;

use serde::Deserialize;

use super::path::basename;

const SOURCE: &str = include_str!("../../../../rules/files.toml");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    drop: Drop,
    mass_change: MassChangeRule,
    sensitive: Sensitive,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Drop {
    extensions: Vec<String>,
    folders: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MassChangeRule {
    window_secs: u64,
    threshold: usize,
    under: String,
    not_under: Vec<String>,
    ignored_extensions: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sensitive {
    always_allowed: Vec<String>,
    store: Vec<Store>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Store {
    name: String,
    contains: String,
    tails: Vec<String>,
    owners: Vec<String>,
}

fn data() -> &'static File {
    static F: OnceLock<File> = OnceLock::new();
    F.get_or_init(|| toml::from_str(SOURCE).expect("rules/files.toml is validated by tests"))
}

fn ends_with_ci(s: &str, tail: &str) -> bool {
    s.len() >= tail.len()
        && s.as_bytes()[s.len() - tail.len()..].eq_ignore_ascii_case(tail.as_bytes())
}

fn listed(list: &[String], name: &str) -> bool {
    list.iter().any(|n| n.eq_ignore_ascii_case(name))
}

/// Final extension of `path`'s last segment, if any.
fn extension(path: &str) -> Option<&str> {
    let name = basename(path);
    name.rsplit_once('.')
        .map(|(_, e)| e)
        .filter(|e| !e.is_empty())
}

/// FIL-001: `path` is a newly created executable or script in a user-writable folder.
#[must_use]
pub fn is_executable_drop(path: &str) -> bool {
    let d = &data().drop;
    if !extension(path).is_some_and(|e| listed(&d.extensions, e)) {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    d.folders.iter().any(|f| lower.contains(f.as_str()))
}

/// FIL-002 candidate: `new_path` (the name after a rename) is a user file given a double
/// extension (`report.docx.locked`). Returns the lower-cased final extension to group by.
#[must_use]
pub fn rename_extension(new_path: &str) -> Option<String> {
    let m = &data().mass_change;
    let name = basename(new_path);
    let (stem, ext) = name.rsplit_once('.')?;
    let inner = stem.rsplit_once('.').map(|(_, e)| e)?;
    let plausible =
        |e: &str| (1..=16).contains(&e.len()) && e.bytes().all(|b| b.is_ascii_alphanumeric());
    if !plausible(inner)
        || !plausible(ext)
        || ext.bytes().all(|b| b.is_ascii_digit())
        || listed(&m.ignored_extensions, ext)
    {
        return None;
    }
    let lower = new_path.to_ascii_lowercase();
    (lower.contains(m.under.as_str()) && !m.not_under.iter().any(|n| lower.contains(n.as_str())))
        .then(|| ext.to_ascii_lowercase())
}

/// RES-001: index of the credential store `path` belongs to.
#[must_use]
pub fn sensitive_store(path: &str) -> Option<usize> {
    data().sensitive.store.iter().position(|s| {
        s.tails.iter().any(|t| ends_with_ci(path, t))
            && path.to_ascii_lowercase().contains(s.contains.as_str())
    })
}

/// Name of a store from [`sensitive_store`].
#[must_use]
pub fn store_name(store: usize) -> &'static str {
    data()
        .sensitive
        .store
        .get(store)
        .map_or("", |s| s.name.as_str())
}

/// How opening `store` by `image` counts for RES-001.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Anti-malware, the search indexer or Vigil: never counted.
    Allowed,
    /// Named like the store's owner: counted only if its signature turns out not to be valid.
    OwnerNamed,
    /// Any other program.
    Foreign,
}

/// Classify `image` opening `store`.
#[must_use]
pub fn access(store: usize, image: &str) -> Access {
    let s = &data().sensitive;
    let name = basename(image);
    if listed(&s.always_allowed, name) {
        Access::Allowed
    } else if s
        .store
        .get(store)
        .is_some_and(|st| listed(&st.owners, name))
    {
        Access::OwnerNamed
    } else {
        Access::Foreign
    }
}

/// Sliding-window counter for FIL-002, keyed by (pid, final extension). Bounded memory.
#[derive(Debug, Default)]
pub struct MassChange {
    hits: HashMap<(u32, String), VecDeque<u64>>,
}

impl MassChange {
    /// Keys kept at most; past this, keys idle for a full window are dropped (all if none are).
    const MAX_KEYS: usize = 4096;

    /// Record one rename; `true` exactly when this one reaches the threshold.
    pub fn note(&mut self, pid: u32, ext: &str, at_ms: u64) -> bool {
        let m = &data().mass_change;
        let window = m.window_secs * 1000;
        if self.hits.len() >= Self::MAX_KEYS {
            self.hits
                .retain(|_, q| q.back().is_some_and(|t| at_ms.saturating_sub(*t) < window));
            if self.hits.len() >= Self::MAX_KEYS {
                self.hits.clear();
            }
        }
        let q = self.hits.entry((pid, ext.to_owned())).or_default();
        while q
            .front()
            .is_some_and(|t| at_ms.saturating_sub(*t) >= window)
        {
            q.pop_front();
        }
        if q.len() >= m.threshold {
            return false; // already reported for this burst
        }
        q.push_back(at_ms);
        q.len() == m.threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DL: &str = r"\Device\HarddiskVolume3\Users\a\Downloads";

    #[test]
    fn data_parses() {
        assert_ne!(data().sensitive.store.len(), 0);
    }

    #[test]
    fn executables_in_user_folders_are_drops() {
        assert!(is_executable_drop(&format!(r"{DL}\setup.EXE")));
        assert!(is_executable_drop(r"C:\Users\a\AppData\Local\Temp\x.ps1"));
        assert!(!is_executable_drop(&format!(r"{DL}\notes.txt")));
        assert!(!is_executable_drop(r"C:\Program Files\App\app.exe"));
    }

    #[test]
    fn only_double_extensions_on_user_files_are_rename_candidates() {
        let docs = r"C:\Users\a\Documents";
        assert_eq!(
            rename_extension(&format!(r"{docs}\q3.docx.LOCKED")).as_deref(),
            Some("locked")
        );
        for p in [
            format!(r"{docs}\q3.docx"),
            format!(r"{docs}\q3.docx.bak"),
            format!(r"{docs}\app.log.1"),
            format!(r"{docs}\photo.2024.jpg"),
            r"C:\Users\a\AppData\Roaming\x\state.json.enc".to_string(),
            r"C:\Data\q3.docx.locked".to_string(),
        ] {
            assert_eq!(rename_extension(&p), None, "{p}");
        }
    }

    #[test]
    fn credential_stores_and_owners() {
        let login = r"C:\Users\a\AppData\Local\Google\Chrome\User Data\Profile 1\Login Data";
        let s = sensitive_store(login).expect("chromium store");
        assert_eq!(store_name(s), "chromium_credentials");
        assert_eq!(
            access(s, r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            Access::OwnerNamed
        );
        assert_eq!(
            access(s, r"C:\Users\a\AppData\Local\Temp\steal.exe"),
            Access::Foreign
        );
        assert_eq!(
            access(s, r"C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe"),
            Access::Allowed
        );
        assert_eq!(sensitive_store(r"C:\Users\a\.ssh\id_ed25519.pub"), None);
        assert!(sensitive_store(r"\Device\HarddiskVolume3\Windows\System32\config\SAM").is_some());
        assert_eq!(sensitive_store(r"C:\Users\a\Documents\Cookies"), None);
    }

    #[test]
    fn mass_change_fires_once_per_burst() {
        let mut m = MassChange::default();
        let threshold = data().mass_change.threshold;
        let fired: Vec<bool> = (0..threshold * 2)
            .map(|i| m.note(7, "locked", i as u64))
            .collect();
        assert_eq!(fired.iter().filter(|f| **f).count(), 1);
        assert!(fired[threshold - 1]);
        assert!(!m.note(8, "locked", 0), "other pids count separately");
        let late = data().mass_change.window_secs * 1000 * 3;
        assert!(
            !m.note(7, "locked", late),
            "an old burst does not carry over"
        );
    }
}

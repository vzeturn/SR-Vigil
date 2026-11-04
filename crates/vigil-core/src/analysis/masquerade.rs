//! Name ↔ path and name ↔ parent checks against `system_processes.toml` (`docs/03 §5.1-5.2`).

use std::collections::HashMap;

use super::path::{basename, expand, matches_pattern, normalize};
use crate::rules::SystemProcesses;

/// Facts derived for HR-002, HR-003 and SG-001.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Masquerade {
    pub name_in_canonical_set: bool,
    pub at_canonical_path: bool,
    pub parent_check_applies: bool,
    pub parent_ok: bool,
    pub never_kill_set: bool,
}

/// Defaults for a process outside the canonical table (nothing fires).
impl Default for Masquerade {
    fn default() -> Self {
        Self {
            name_in_canonical_set: false,
            at_canonical_path: true,
            parent_check_applies: false,
            parent_ok: true,
            never_kill_set: false,
        }
    }
}

/// Evaluate a process image. `path` and `parent_image` must already be [`normalize`]d paths;
/// `parent_image` is `None` when the parent is unknown or has exited (then HR-003 cannot fire).
#[must_use]
pub fn check(
    table: &SystemProcesses,
    vars: &HashMap<String, String>,
    path: &str,
    parent_image: Option<&str>,
) -> Masquerade {
    let name = basename(path);
    let Some(entry) = table
        .processes
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case(name))
    else {
        return Masquerade::default();
    };
    let at_canonical_path = entry
        .canonical_paths
        .iter()
        .any(|p| matches_pattern(path, &normalize(&expand(p, vars))));
    let parent_ok = !entry.parent_check
        || parent_image.is_none_or(|img| {
            let pn = basename(img);
            entry
                .parent
                .iter()
                .chain(&entry.parent_alternates)
                .any(|p| p.eq_ignore_ascii_case(pn))
        });
    Masquerade {
        name_in_canonical_set: true,
        at_canonical_path,
        parent_check_applies: entry.parent_check,
        parent_ok,
        never_kill_set: entry.never_kill,
    }
}

/// True for names in the `[pseudo]` table (no image file; never evaluated by path).
#[must_use]
pub fn is_pseudo(table: &SystemProcesses, name: &str) -> bool {
    table
        .pseudo
        .names
        .iter()
        .any(|n| n.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> SystemProcesses {
        SystemProcesses::parse("t", include_str!("../../../../rules/system_processes.toml"))
            .unwrap()
    }

    fn vars() -> HashMap<String, String> {
        HashMap::from([("systemroot".to_string(), "c:\\windows".to_string())])
    }

    #[test]
    fn svchost_at_canonical_path_with_services_parent() {
        let m = check(
            &table(),
            &vars(),
            "c:\\windows\\system32\\svchost.exe",
            Some("c:\\windows\\system32\\services.exe"),
        );
        assert!(m.name_in_canonical_set && m.at_canonical_path && m.parent_ok && m.never_kill_set);
    }

    #[test]
    fn svchost_in_temp_fails_path_check() {
        let m = check(
            &table(),
            &vars(),
            "c:\\users\\x\\appdata\\local\\temp\\svchost.exe",
            None,
        );
        assert!(m.name_in_canonical_set && !m.at_canonical_path);
    }

    #[test]
    fn svchost_with_wrong_parent_fails_parent_check() {
        let m = check(
            &table(),
            &vars(),
            "c:\\windows\\system32\\svchost.exe",
            Some("c:\\users\\x\\evil.exe"),
        );
        assert!(m.parent_check_applies && !m.parent_ok);
    }

    #[test]
    fn unknown_parent_never_triggers_hr003() {
        let m = check(
            &table(),
            &vars(),
            "c:\\windows\\system32\\svchost.exe",
            None,
        );
        assert!(m.parent_ok);
    }

    #[test]
    fn other_names_are_untouched_and_pseudo_detected() {
        assert_eq!(
            check(&table(), &vars(), "c:\\tools\\a.exe", None),
            Masquerade::default()
        );
        assert!(is_pseudo(&table(), "system idle process"));
    }
}

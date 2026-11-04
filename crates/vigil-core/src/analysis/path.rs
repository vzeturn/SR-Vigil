//! Path normalisation, path classes and canonical-path matching (`docs/03 §5.1`, `§7`).

use std::collections::HashMap;

use crate::rules::PathClass;

/// Machine facts needed to classify paths. All paths are in normalised form (see [`normalize`]).
#[derive(Debug, Clone, Default)]
pub struct PathEnv {
    pub system_root: String,
    pub program_files: Vec<String>,
    /// Extra user-writable roots (for example the real `%TEMP%`, `%ProgramData%`).
    pub user_writable: Vec<String>,
    /// Vigil's own data directory, excluded from `user_writable`.
    pub vigil_data_dir: String,
    /// Drive letters (lower case) of removable media.
    pub removable_drives: Vec<char>,
}

/// Case-fold, use `\`, strip `\\?\`, trailing dots/spaces and duplicate separators.
#[must_use]
pub fn normalize(path: &str) -> String {
    let mut p = path.trim().replace('/', "\\");
    if let Some(rest) = p.strip_prefix("\\\\?\\UNC\\") {
        p = format!("\\\\{rest}");
    } else if let Some(rest) = p
        .strip_prefix("\\\\?\\")
        .or_else(|| p.strip_prefix("\\??\\"))
    {
        p = rest.to_string();
    }
    let unc = p.starts_with("\\\\");
    let body: Vec<&str> = p
        .split('\\')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches(['.', ' ']))
        .collect();
    let joined = body.join("\\").to_lowercase();
    if unc { format!("\\\\{joined}") } else { joined }
}

fn under(path: &str, root: &str) -> bool {
    !root.is_empty()
        && path.len() > root.len()
        && path.starts_with(root)
        && path.as_bytes()[root.len()] == b'\\'
}

/// Classify a normalised path.
#[must_use]
pub fn classify(path: &str, env: &PathEnv) -> PathClass {
    if path.starts_with("\\\\") {
        return PathClass::NetworkShare;
    }
    let drive = path
        .chars()
        .next()
        .filter(|_| path.as_bytes().get(1) == Some(&b':'));
    if drive.is_some_and(|d| env.removable_drives.contains(&d)) {
        return PathClass::Removable;
    }
    if under(path, &env.vigil_data_dir) {
        return PathClass::Other;
    }
    if under(path, &env.system_root) {
        return PathClass::System;
    }
    if env.program_files.iter().any(|r| under(path, r)) || path.contains("\\windowsapps\\") {
        return PathClass::ProgramFiles;
    }
    if defender_platform(path) {
        return PathClass::ProgramFiles;
    }
    if env.user_writable.iter().any(|r| under(path, r)) || user_profile_writable(path) {
        return PathClass::UserWritable;
    }
    PathClass::Other
}

/// Microsoft Defender keeps its engine under `ProgramData\Microsoft\Windows Defender\Platform`, a
/// SYSTEM/TrustedInstaller-only location although it sits below the writable `ProgramData` root.
fn defender_platform(path: &str) -> bool {
    const ROOT: &str = r"\programdata\microsoft\windows defender";
    path.get(2..).is_some_and(|r| {
        r.strip_prefix(ROOT).is_some_and(|t| {
            t.starts_with(r"\platform\") || t.starts_with(r" advanced threat protection\platform\")
        })
    })
}

/// `X:\users\<name>\{appdata,downloads,desktop}\…` and `X:\users\public\…`.
fn user_profile_writable(path: &str) -> bool {
    let mut seg = path.split('\\').skip(1);
    if seg.next() != Some("users") {
        return false;
    }
    match (seg.next(), seg.next()) {
        (Some("public"), Some(_)) => true,
        (Some(_), Some(dir)) => matches!(dir, "appdata" | "downloads" | "desktop"),
        _ => false,
    }
}

/// Expand `%NAME%` (case-insensitive) using `vars`; unknown variables stay unexpanded.
#[must_use]
pub fn expand(pattern: &str, vars: &HashMap<String, String>) -> String {
    let mut out = String::new();
    let mut rest = pattern;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let tail = &rest[i + 1..];
        let Some(j) = tail.find('%') else {
            out.push('%');
            rest = tail;
            continue;
        };
        let key = &tail[..j];
        if let Some(v) = vars.get(&key.to_lowercase()) {
            out.push_str(v);
        } else {
            out.push('%');
            out.push_str(key);
            out.push('%');
        }
        rest = &tail[j + 1..];
    }
    out.push_str(rest);
    out
}

/// True when normalised `path` equals the normalised `pattern`; `*` matches exactly one segment.
#[must_use]
pub fn matches_pattern(path: &str, pattern: &str) -> bool {
    let (mut a, mut b) = (path.split('\\'), pattern.split('\\'));
    loop {
        match (a.next(), b.next()) {
            (None, None) => return true,
            (Some(x), Some(y)) if y == "*" || x == y => {}
            _ => return false,
        }
    }
}

/// Last path segment.
#[must_use]
pub fn basename(path: &str) -> &str {
    path.rsplit('\\').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defender_platform_is_not_user_writable() {
        let e = env();
        let p = normalize(r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe");
        assert_ne!(classify(&p, &e), PathClass::UserWritable);
    }

    fn env() -> PathEnv {
        PathEnv {
            system_root: normalize("C:\\Windows"),
            program_files: vec![
                normalize("C:\\Program Files"),
                normalize("C:\\Program Files (x86)"),
            ],
            user_writable: vec![normalize("C:\\ProgramData")],
            vigil_data_dir: normalize("C:\\ProgramData\\Vigil"),
            removable_drives: vec!['e'],
        }
    }

    #[test]
    fn normalizes_prefixes_case_and_trailing_dots() {
        assert_eq!(
            normalize("\\\\?\\C:\\Windows\\System32\\"),
            "c:\\windows\\system32"
        );
        assert_eq!(normalize("C:/Windows//Temp./x. "), "c:\\windows\\temp\\x");
        assert_eq!(
            normalize("\\\\?\\UNC\\srv\\share\\a.exe"),
            "\\\\srv\\share\\a.exe"
        );
    }

    #[test]
    fn classifies_every_class() {
        let e = env();
        let c = |p: &str| classify(&normalize(p), &e);
        assert_eq!(c("C:\\Windows\\System32\\svchost.exe"), PathClass::System);
        assert_eq!(
            c("C:\\Program Files\\Google\\a.exe"),
            PathClass::ProgramFiles
        );
        assert_eq!(
            c("C:\\Users\\x\\AppData\\Local\\Temp\\a.exe"),
            PathClass::UserWritable
        );
        assert_eq!(c("C:\\Users\\x\\Downloads\\a.exe"), PathClass::UserWritable);
        assert_eq!(c("C:\\Users\\Public\\a.exe"), PathClass::UserWritable);
        assert_eq!(c("C:\\ProgramData\\Foo\\a.exe"), PathClass::UserWritable);
        assert_eq!(c("C:\\ProgramData\\Vigil\\a.exe"), PathClass::Other);
        assert_eq!(c("\\\\srv\\s\\a.exe"), PathClass::NetworkShare);
        assert_eq!(c("E:\\a.exe"), PathClass::Removable);
        assert_eq!(c("D:\\tools\\a.exe"), PathClass::Other);
    }

    #[test]
    fn prefix_lookalikes_do_not_classify_as_system() {
        let e = env();
        assert_eq!(
            classify(&normalize("C:\\Windows.old\\a.exe"), &e),
            PathClass::Other
        );
    }

    #[test]
    fn expands_variables_and_matches_wildcards() {
        let vars = HashMap::from([("systemroot".to_string(), "c:\\windows".to_string())]);
        let p = normalize(&expand("%SystemRoot%\\System32\\smss.exe", &vars));
        assert!(matches_pattern("c:\\windows\\system32\\smss.exe", &p));
        assert!(!matches_pattern("c:\\users\\x\\smss.exe", &p));
        assert!(matches_pattern(
            "c:\\programdata\\microsoft\\windows defender\\platform\\4.18\\msmpeng.exe",
            "c:\\programdata\\microsoft\\windows defender\\platform\\*\\msmpeng.exe"
        ));
        assert_eq!(expand("%NOPE%\\a", &vars), "%NOPE%\\a");
    }
}

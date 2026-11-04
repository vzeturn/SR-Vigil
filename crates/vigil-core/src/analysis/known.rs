//! Recognition of well-known desktop software (`rules/known_software.toml`).

use std::sync::OnceLock;

use serde::Deserialize;

use crate::rules::VersionStatus;

const EMBEDDED: &str = include_str!("../../../../rules/known_software.toml");

/// One catalogue entry.
#[derive(Debug, Clone, Deserialize)]
pub struct Known {
    pub label: String,
    pub what: String,
    names: Vec<String>,
    #[serde(default)]
    vendors: Vec<String>,
    /// Newest known release (`docs/16`); all version fields are optional catalogue data.
    #[serde(default)]
    latest: Option<String>,
    /// Oldest release still supported by the vendor: older is `far_behind`.
    #[serde(default)]
    min_supported: Option<String>,
    /// Releases below this carry a serious known vulnerability: `vulnerable`.
    #[serde(default)]
    vulnerable_below: Option<String>,
}

impl Known {
    /// How far `installed` is behind this entry's release data. Anything unparsable, or an entry
    /// without release data, reports `Unknown` so no penalty can fire on guesswork.
    #[must_use]
    pub fn version_status(&self, installed: &str) -> VersionStatus {
        let Some(have) = parse_version(installed) else {
            return VersionStatus::Unknown;
        };
        let below = |limit: &Option<String>| {
            limit
                .as_deref()
                .and_then(parse_version)
                .is_some_and(|l| cmp_version(&have, &l).is_lt())
        };
        if below(&self.vulnerable_below) {
            VersionStatus::Vulnerable
        } else if below(&self.min_supported) {
            VersionStatus::FarBehind
        } else if below(&self.latest) {
            VersionStatus::Outdated
        } else {
            VersionStatus::Unknown
        }
    }
}

/// Leading dotted numbers of `text` (`"1.2.3 (build 9)"` → `[1, 2, 3]`); `None` without any.
fn parse_version(text: &str) -> Option<Vec<u64>> {
    let parts: Vec<u64> = text
        .trim()
        .split('.')
        .map_while(|p| {
            let digits: String = p.chars().take_while(char::is_ascii_digit).collect();
            digits.parse().ok()
        })
        .collect();
    (!parts.is_empty()).then_some(parts)
}

/// Numeric comparison where missing trailing components count as zero (`1.2` == `1.2.0`).
fn cmp_version(a: &[u64], b: &[u64]) -> std::cmp::Ordering {
    let n = a.len().max(b.len());
    (0..n)
        .map(|i| {
            a.get(i)
                .copied()
                .unwrap_or(0)
                .cmp(&b.get(i).copied().unwrap_or(0))
        })
        .find(|o| o.is_ne())
        .unwrap_or(std::cmp::Ordering::Equal)
}

#[derive(Deserialize)]
struct File {
    software: Vec<Known>,
}

fn catalogue() -> &'static [Known] {
    static CATALOGUE: OnceLock<Vec<Known>> = OnceLock::new();
    CATALOGUE.get_or_init(|| {
        toml::from_str::<File>(EMBEDDED)
            .map(|f| f.software)
            .unwrap_or_default()
    })
}

/// The catalogue entry for `file_name`, if its version text (when it has any) agrees.
#[must_use]
pub fn lookup(file_name: &str, version_text: &[&str]) -> Option<&'static Known> {
    let file = file_name.to_lowercase();
    let text = version_text.join(" ").to_lowercase();
    catalogue().iter().find(|k| {
        k.names.iter().any(|n| n.eq_ignore_ascii_case(&file))
            && (k.vendors.is_empty()
                || text.trim().is_empty()
                || k.vendors.iter().any(|v| text.contains(v.as_str())))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_parses_and_matches_by_name_and_vendor() {
        assert!(!catalogue().is_empty());
        assert_eq!(
            lookup("ShareX.exe", &["ShareX Team", "ShareX"]).map(|k| k.label.as_str()),
            Some("ShareX")
        );
        assert!(lookup("sharex.exe", &["Acme Corp"]).is_none());
        assert!(lookup("UniKeyNT.exe", &[]).is_some());
        assert!(lookup("unknown.exe", &[]).is_none());
        assert!(lookup("igfxem.exe", &["Intel Corporation"]).is_some());
        assert!(lookup("igfxem.exe", &["Acme"]).is_none());
    }

    fn entry() -> Known {
        Known {
            label: "X".into(),
            what: "x".into(),
            names: vec![],
            vendors: vec![],
            latest: Some("10.2.0".into()),
            min_supported: Some("8.0".into()),
            vulnerable_below: Some("7.5.1".into()),
        }
    }

    #[test]
    fn version_status_tiers() {
        let k = entry();
        assert_eq!(k.version_status("10.2.0"), VersionStatus::Unknown);
        assert_eq!(k.version_status("10.2"), VersionStatus::Unknown);
        assert_eq!(k.version_status("11.0"), VersionStatus::Unknown);
        assert_eq!(k.version_status("10.1.9"), VersionStatus::Outdated);
        assert_eq!(k.version_status("9.9"), VersionStatus::Outdated);
        assert_eq!(k.version_status("7.9"), VersionStatus::FarBehind);
        assert_eq!(k.version_status("7.5.0"), VersionStatus::Vulnerable);
        assert_eq!(k.version_status("7.5.1"), VersionStatus::FarBehind);
        assert_eq!(
            k.version_status("10.0.0 (build 5)"),
            VersionStatus::Outdated
        );
    }

    #[test]
    fn unreadable_or_absent_data_never_penalises() {
        let k = entry();
        assert_eq!(k.version_status(""), VersionStatus::Unknown);
        assert_eq!(k.version_status("beta"), VersionStatus::Unknown);
        let bare = Known {
            latest: None,
            min_supported: None,
            vulnerable_below: None,
            ..entry()
        };
        assert_eq!(bare.version_status("1.0"), VersionStatus::Unknown);
    }
}

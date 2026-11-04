//! Recognition of well-known desktop software (`rules/known_software.toml`).

use std::sync::OnceLock;

use serde::Deserialize;

const EMBEDDED: &str = include_str!("../../../../rules/known_software.toml");

/// One catalogue entry.
#[derive(Debug, Clone, Deserialize)]
pub struct Known {
    pub label: String,
    pub what: String,
    names: Vec<String>,
    #[serde(default)]
    vendors: Vec<String>,
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
}

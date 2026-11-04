//! Typed models of the data files next to `default.toml`.

use serde::Deserialize;

use super::RuleError;

fn parse<T: for<'de> Deserialize<'de>>(source_name: &str, text: &str) -> Result<T, RuleError> {
    toml::from_str(text).map_err(|e| RuleError::Parse {
        source_name: source_name.into(),
        message: e.to_string(),
    })
}

/// `rules/system_processes.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemProcesses {
    pub pseudo: Pseudo,
    #[serde(rename = "process")]
    pub processes: Vec<SystemProcess>,
}

/// Pseudo-processes with no image file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pseudo {
    pub names: Vec<String>,
}

/// One canonical Windows system process.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemProcess {
    pub name: String,
    pub canonical_paths: Vec<String>,
    pub parent: Option<String>,
    #[serde(default)]
    pub parent_alternates: Vec<String>,
    pub parent_check: bool,
    #[serde(default)]
    pub never_kill: bool,
    #[serde(default)]
    pub network_critical: bool,
}

impl SystemProcesses {
    pub fn parse(source_name: &str, text: &str) -> Result<Self, RuleError> {
        let v: Self = parse(source_name, text)?;
        for p in &v.processes {
            let bad = |reason: &str| RuleError::Invalid {
                source_name: source_name.into(),
                id: p.name.clone(),
                reason: reason.into(),
            };
            if p.canonical_paths.is_empty() {
                return Err(bad("canonical_paths is empty"));
            }
            if p.parent_check && p.parent.is_none() {
                return Err(bad("parent_check requires `parent`"));
            }
        }
        Ok(v)
    }
}

/// `rules/lolbins.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lolbins {
    pub lolbins: LolbinNames,
    #[serde(default, rename = "context_allow")]
    pub context_allow: Vec<ContextAllow>,
}

/// The `LOLBin` image names.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LolbinNames {
    pub names: Vec<String>,
}

/// Administrative parent chain that exempts children from BEH-001.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextAllow {
    pub id: String,
    pub description: String,
    pub parent_images: Vec<String>,
    pub applies_to: Vec<String>,
    pub max_depth: u32,
    pub requires_parent_verdict: Option<String>,
}

impl Lolbins {
    pub fn parse(source_name: &str, text: &str) -> Result<Self, RuleError> {
        parse(source_name, text)
    }
}

/// `rules/publishers.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publishers {
    #[serde(rename = "publisher")]
    pub publishers: Vec<Publisher>,
}

/// A built-in trusted publisher.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publisher {
    pub id: String,
    pub subject_org: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub match_mode: String,
    #[serde(default)]
    pub required_roots: Vec<String>,
    #[serde(default)]
    pub bootstrap_from: Vec<String>,
}

impl Publishers {
    pub fn parse(source_name: &str, text: &str) -> Result<Self, RuleError> {
        let v: Self = parse(source_name, text)?;
        for p in &v.publishers {
            let bad = |reason: &str| RuleError::Invalid {
                source_name: source_name.into(),
                id: p.id.clone(),
                reason: reason.into(),
            };
            match p.match_mode.as_str() {
                "subject_and_root" if p.required_roots.is_empty() => {
                    return Err(bad("subject_and_root requires required_roots"));
                }
                "subject_and_root" | "thumbprint" => {}
                _ => return Err(bad("match_mode must be subject_and_root or thumbprint")),
            }
        }
        Ok(v)
    }
}

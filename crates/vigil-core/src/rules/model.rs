use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use thiserror::Error;

use crate::consts::{MALICIOUS_MAX, SAFE_MIN, SCORE_BASELINE};

/// Why a rule pack was rejected.
#[derive(Debug, Error)]
pub enum RuleError {
    #[error("{source_name}: invalid TOML: {message}")]
    Parse {
        source_name: String,
        message: String,
    },
    #[error("{source_name}: rule {id}: {reason}")]
    Invalid {
        source_name: String,
        id: String,
        reason: String,
    },
    #[error("{source_name}: {reason}")]
    Pack { source_name: String, reason: String },
    #[error("cannot read {path}: {message}")]
    Io { path: String, message: String },
}

/// Rule categories (`kind` in `docs/03 §8`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Signal,
    HardRule,
    HardAllow,
    Guard,
}

/// Verdict forced by a terminal rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Safe,
    Unknown,
    Malicious,
}

/// Signature states a predicate can test (`valid` = embedded or catalog).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureState {
    ValidEmbedded,
    ValidCatalog,
    Valid,
    Unsigned,
    Invalid,
    Expired,
    Revoked,
    UntrustedRoot,
}

/// Path classes from `docs/03 §7`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathClass {
    System,
    ProgramFiles,
    UserWritable,
    NetworkShare,
    Removable,
    Other,
}

/// A single value or a list of alternatives ("any of").
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T: PartialEq + Copy> OneOrMany<T> {
    /// True when `value` is one of the alternatives.
    pub fn matches(&self, value: T) -> bool {
        match self {
            Self::One(v) => *v == value,
            Self::Many(vs) => vs.contains(&value),
        }
    }

    fn is_empty(&self) -> bool {
        matches!(self, Self::Many(vs) if vs.is_empty())
    }
}

/// Conjunction of predicates. Unknown keys are rejected at parse time.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct When {
    pub signature: Option<OneOrMany<SignatureState>>,
    pub path_class: Option<OneOrMany<PathClass>>,
    pub signer_pinned: Option<bool>,
    pub signer_ms_root: Option<bool>,
    pub os_signed: Option<bool>,
    pub at_canonical_path: Option<bool>,
    pub name_in_canonical_set: Option<bool>,
    pub parent_ok: Option<bool>,
    pub parent_check_applies: Option<bool>,
    pub never_kill_set: Option<bool>,
    pub company_matches_signer: Option<bool>,
    pub company_conflicts_signer: Option<bool>,
    pub claims_pinned_publisher: Option<bool>,
    pub lolbin: Option<bool>,
    pub has_outbound: Option<bool>,
    pub dest_public: Option<bool>,
    pub beaconing: Option<bool>,
    pub public_dest_no_dns: Option<bool>,
    pub risky_port_or_tld: Option<bool>,
    pub typosquat: Option<bool>,
    pub unbacked_exec_memory: Option<bool>,
    pub vt_detections_gte: Option<u32>,
    pub vt_detections_lte: Option<u32>,
    pub vt_first_seen_days_gte: Option<u32>,
    pub user_denylisted: Option<bool>,
    pub user_allowed: Option<bool>,
    pub vigil_self: Option<bool>,
}

impl When {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    fn has_empty_list(&self) -> bool {
        self.signature.as_ref().is_some_and(OneOrMany::is_empty)
            || self.path_class.as_ref().is_some_and(OneOrMany::is_empty)
    }
}

/// One rule as written in TOML (`docs/03 §8`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub description: String,
    pub when: When,
    pub score: Option<i32>,
    pub cap: Option<u8>,
    pub verdict: Option<Verdict>,
    #[serde(default)]
    pub terminal: bool,
    pub exclusive_group: Option<String>,
    pub priority: Option<u32>,
    pub guard: Option<String>,
}

/// `[pack]` table: version and thresholds, which must equal the fixed constants.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackMeta {
    pub rule_pack_version: String,
    pub baseline: u8,
    pub safe_min: u8,
    pub malicious_max: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBase {
    pack: PackMeta,
    #[serde(default, rename = "rule")]
    rules: Vec<Rule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOverride {
    #[serde(default, rename = "rule")]
    rules: Vec<Rule>,
}

/// Rule ids an override file may never replace (non-negotiable authority order).
const PROTECTED_IDS: [&str; 2] = ["HA-001", "SG-001"];

/// A validated, merged rule pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulePack {
    pub meta: PackMeta,
    pub rules: Vec<Rule>,
}

impl RulePack {
    /// Parse and validate a base pack (`[pack]` + `[[rule]]`).
    pub fn parse(source_name: &str, text: &str) -> Result<Self, RuleError> {
        let raw: RawBase = toml::from_str(text).map_err(|e| RuleError::Parse {
            source_name: source_name.into(),
            message: e.to_string(),
        })?;
        let pack_err = |reason: &str| RuleError::Pack {
            source_name: source_name.into(),
            reason: reason.into(),
        };
        if raw.pack.baseline != SCORE_BASELINE
            || raw.pack.safe_min != SAFE_MIN
            || raw.pack.malicious_max != MALICIOUS_MAX
        {
            return Err(pack_err(
                "baseline/safe_min/malicious_max differ from vigil_core::consts",
            ));
        }
        if raw.pack.rule_pack_version.trim().is_empty() {
            return Err(pack_err("rule_pack_version is empty"));
        }
        let pack = Self {
            meta: raw.pack,
            rules: raw.rules,
        };
        pack.validate(source_name)?;
        Ok(pack)
    }

    /// Apply one override file: rules replace same-id rules (same kind) or are appended.
    /// `self` is untouched; on error nothing is returned.
    pub fn with_override(&self, source_name: &str, text: &str) -> Result<Self, RuleError> {
        let raw: RawOverride = toml::from_str(text).map_err(|e| RuleError::Parse {
            source_name: source_name.into(),
            message: e.to_string(),
        })?;
        let mut merged = self.clone();
        for rule in raw.rules {
            let invalid = |reason: &str| RuleError::Invalid {
                source_name: source_name.into(),
                id: rule.id.clone(),
                reason: reason.into(),
            };
            if PROTECTED_IDS.contains(&rule.id.as_str()) {
                return Err(invalid("rule is protected and cannot be overridden"));
            }
            match merged.rules.iter_mut().find(|r| r.id == rule.id) {
                Some(existing) if existing.kind != rule.kind => {
                    return Err(invalid("override cannot change the rule kind"));
                }
                Some(existing) => *existing = rule,
                None => merged.rules.push(rule),
            }
        }
        merged.validate(source_name)?;
        Ok(merged)
    }

    /// Look up a rule by id.
    #[must_use]
    pub fn rule(&self, id: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == id)
    }

    fn validate(&self, source_name: &str) -> Result<(), RuleError> {
        let mut seen = BTreeSet::new();
        let mut group_priorities: BTreeMap<&str, BTreeSet<u32>> = BTreeMap::new();
        for r in &self.rules {
            let bad = |reason: &str| RuleError::Invalid {
                source_name: source_name.into(),
                id: r.id.clone(),
                reason: reason.into(),
            };
            if r.id.trim().is_empty() || r.name.trim().is_empty() || r.description.trim().is_empty()
            {
                return Err(bad("id, name and description are required"));
            }
            if !seen.insert(r.id.as_str()) {
                return Err(bad("duplicate id"));
            }
            if r.when.is_empty() || r.when.has_empty_list() {
                return Err(bad(
                    "`when` needs at least one predicate and no empty lists",
                ));
            }
            if r.terminal && r.verdict.is_none() {
                return Err(bad("terminal rule requires a verdict"));
            }
            if r.exclusive_group.is_some() != r.priority.is_some() {
                return Err(bad("exclusive_group and priority must be set together"));
            }
            match r.kind {
                Kind::Signal => {
                    if r.score.is_none() {
                        return Err(bad("signal requires a score"));
                    }
                    if r.verdict.is_some() || r.terminal || r.guard.is_some() {
                        return Err(bad("signal cannot set verdict, terminal or guard"));
                    }
                }
                Kind::HardRule | Kind::HardAllow => {
                    let expected = if r.kind == Kind::HardRule {
                        Verdict::Malicious
                    } else {
                        Verdict::Safe
                    };
                    if r.verdict != Some(expected) || !r.terminal {
                        return Err(bad(
                            "hard rules must be terminal with verdict malicious; hard allows terminal with safe",
                        ));
                    }
                    if r.score.is_some() || r.cap.is_some() || r.guard.is_some() {
                        return Err(bad("hard rule cannot set score, cap or guard"));
                    }
                }
                Kind::Guard => {
                    if r.guard.is_none() {
                        return Err(bad("guard rule requires `guard`"));
                    }
                    if r.score.is_some() || r.verdict.is_some() || r.terminal {
                        return Err(bad("guard cannot set score, verdict or terminal"));
                    }
                }
            }
            if let (Some(group), Some(priority)) = (&r.exclusive_group, r.priority) {
                if !group_priorities.entry(group).or_default().insert(priority) {
                    return Err(bad("priority already used in this exclusive_group"));
                }
            }
        }
        Ok(())
    }
}

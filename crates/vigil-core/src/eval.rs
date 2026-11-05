//! Facts → signals → score → verdict (`docs/03 §1`), driven entirely by the rule pack.

use std::collections::HashMap;

use crate::rules::{Kind, PathClass, Rule, RulePack, SignatureState, Verdict, VersionStatus, When};

/// Everything the rules can test. The platform layer fills these in; the rules never see raw strings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct Facts {
    pub signature: SignatureState,
    pub path_class: PathClass,
    pub signer_pinned: bool,
    pub signer_ms_root: bool,
    pub os_signed: bool,
    pub at_canonical_path: bool,
    pub name_in_canonical_set: bool,
    pub parent_ok: bool,
    pub parent_check_applies: bool,
    pub never_kill_set: bool,
    pub company_matches_signer: bool,
    pub company_conflicts_signer: bool,
    pub claims_pinned_publisher: bool,
    pub known_software: bool,
    pub version_status: VersionStatus,
    pub lolbin: bool,
    pub has_outbound: bool,
    pub dest_public: bool,
    pub beaconing: bool,
    pub public_dest_no_dns: bool,
    pub risky_port_or_tld: bool,
    pub typosquat: bool,
    pub unbacked_exec_memory: bool,
    pub unsigned_writable_module: bool,
    pub package_source_trusted: bool,
    pub from_internet: bool,
    pub hash_known_good: bool,
    /// `None` when `VirusTotal` is disabled or has no result.
    pub vt_detections: Option<u32>,
    pub vt_first_seen_days: Option<u32>,
    pub user_denylisted: bool,
    pub user_allowed: bool,
    pub vigil_self: bool,
}

impl Default for Facts {
    /// An unsigned file in an unclassified path with no behaviour: nothing fires except `SIG-011`.
    fn default() -> Self {
        Self {
            signature: SignatureState::Unsigned,
            path_class: PathClass::Other,
            signer_pinned: false,
            signer_ms_root: false,
            os_signed: false,
            at_canonical_path: true,
            name_in_canonical_set: false,
            parent_ok: true,
            parent_check_applies: false,
            never_kill_set: false,
            company_matches_signer: false,
            company_conflicts_signer: false,
            claims_pinned_publisher: false,
            known_software: false,
            version_status: VersionStatus::Unknown,
            lolbin: false,
            has_outbound: false,
            dest_public: false,
            beaconing: false,
            public_dest_no_dns: false,
            risky_port_or_tld: false,
            typosquat: false,
            unbacked_exec_memory: false,
            unsigned_writable_module: false,
            package_source_trusted: false,
            from_internet: false,
            hash_known_good: false,
            vt_detections: None,
            vt_first_seen_days: None,
            user_denylisted: false,
            user_allowed: false,
            vigil_self: false,
        }
    }
}

/// A rule that fired for an evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fired {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    /// Score delta for signals; `None` for terminal rules and guards.
    pub delta: Option<i32>,
}

/// Result of evaluating one identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub score: u8,
    pub verdict: Verdict,
    /// Every signal, hard rule, hard allow and guard that fired, in pack order.
    pub signals: Vec<Fired>,
    /// SG-001: kill/deny actions must be refused for this identity.
    pub never_kill: bool,
    pub rule_pack_version: String,
}

fn flag(want: Option<bool>, have: bool) -> bool {
    want.is_none_or(|w| w == have)
}

fn signature_matches(want: SignatureState, have: SignatureState) -> bool {
    match want {
        SignatureState::Valid => {
            matches!(
                have,
                SignatureState::ValidEmbedded | SignatureState::ValidCatalog
            )
        }
        other => other == have,
    }
}

fn matches(w: &When, f: &Facts) -> bool {
    w.signature
        .as_ref()
        .is_none_or(|s| s.any(|v| signature_matches(v, f.signature)))
        && w.path_class
            .as_ref()
            .is_none_or(|p| p.matches(f.path_class))
        && flag(w.signer_pinned, f.signer_pinned)
        && flag(w.signer_ms_root, f.signer_ms_root)
        && flag(w.os_signed, f.os_signed)
        && flag(w.at_canonical_path, f.at_canonical_path)
        && flag(w.name_in_canonical_set, f.name_in_canonical_set)
        && flag(w.parent_ok, f.parent_ok)
        && flag(w.parent_check_applies, f.parent_check_applies)
        && flag(w.never_kill_set, f.never_kill_set)
        && flag(w.company_matches_signer, f.company_matches_signer)
        && flag(w.company_conflicts_signer, f.company_conflicts_signer)
        && flag(w.claims_pinned_publisher, f.claims_pinned_publisher)
        && flag(w.known_software, f.known_software)
        && w.version_status.is_none_or(|s| s == f.version_status)
        && flag(w.lolbin, f.lolbin)
        && flag(w.has_outbound, f.has_outbound)
        && flag(w.dest_public, f.dest_public)
        && flag(w.beaconing, f.beaconing)
        && flag(w.public_dest_no_dns, f.public_dest_no_dns)
        && flag(w.risky_port_or_tld, f.risky_port_or_tld)
        && flag(w.typosquat, f.typosquat)
        && flag(w.unbacked_exec_memory, f.unbacked_exec_memory)
        && flag(w.unsigned_writable_module, f.unsigned_writable_module)
        && flag(w.package_source_trusted, f.package_source_trusted)
        && flag(w.from_internet, f.from_internet)
        && flag(w.hash_known_good, f.hash_known_good)
        && w.vt_detections_gte
            .is_none_or(|n| f.vt_detections.is_some_and(|d| d >= n))
        && w.vt_detections_lte
            .is_none_or(|n| f.vt_detections.is_some_and(|d| d <= n))
        && w.vt_first_seen_days_gte
            .is_none_or(|n| f.vt_first_seen_days.is_some_and(|d| d >= n))
        && flag(w.user_denylisted, f.user_denylisted)
        && flag(w.user_allowed, f.user_allowed)
        && flag(w.vigil_self, f.vigil_self)
}

/// Rules that can lift the never-kill guard (`docs/03 §2.4`).
const GUARD_LIFTED_BY: [&str; 3] = ["HR-001", "HR-002", "HR-003"];
/// Exclusive group of the VER-* signals; their delta is applied after the 0–100 clamp.
const FRESHNESS_GROUP: &str = "version_freshness";
/// Vigil's own binaries beat every other rule (`CLAUDE.md` authority order).
const SELF_ALLOW: &str = "HA-001";

/// Keep only the highest-priority match per exclusive group.
fn winners(fired: Vec<&Rule>) -> Vec<&Rule> {
    let mut best: HashMap<&str, u32> = HashMap::new();
    for r in &fired {
        if let (Some(g), Some(p)) = (r.exclusive_group.as_deref(), r.priority) {
            let e = best.entry(g).or_insert(p);
            *e = (*e).max(p);
        }
    }
    fired
        .into_iter()
        .filter(|r| match (r.exclusive_group.as_deref(), r.priority) {
            (Some(g), Some(p)) => best.get(g) == Some(&p),
            _ => true,
        })
        .collect()
}

/// Evaluate `facts` against `pack`.
#[must_use]
pub fn evaluate(pack: &RulePack, facts: &Facts) -> Evaluation {
    let fired = winners(
        pack.rules
            .iter()
            .filter(|r| matches(&r.when, facts))
            .collect(),
    );
    let has = |id: &str| fired.iter().any(|r| r.id == id);
    let hard_rule = fired.iter().any(|r| r.kind == Kind::HardRule);
    let hard_allow = fired.iter().any(|r| r.kind == Kind::HardAllow);

    let is_freshness = |r: &Rule| r.exclusive_group.as_deref() == Some(FRESHNESS_GROUP);
    let sum: i32 = fired
        .iter()
        .filter(|r| !is_freshness(r))
        .filter_map(|r| r.score)
        .sum();
    let mut score = (i32::from(pack.meta.baseline) + sum).clamp(0, 100);
    if let Some(cap) = fired.iter().filter_map(|r| r.cap).min() {
        score = score.min(i32::from(cap));
    }
    // Age is applied after the clamp so a strongly trusted app cannot absorb it, but it can never
    // by itself push a program into Malicious (`docs/16 §5`).
    let age: i32 = fired
        .iter()
        .filter(|r| is_freshness(r))
        .filter_map(|r| r.score)
        .sum();
    let floor = score.min(i32::from(pack.meta.malicious_max) + 1);
    score = (score + age).max(floor);

    let (score, verdict) = if has(SELF_ALLOW) {
        (100, Verdict::Safe)
    } else if hard_rule {
        (0, Verdict::Malicious)
    } else if hard_allow {
        (100, Verdict::Safe)
    } else {
        let s = u8::try_from(score).unwrap_or(100);
        // A low score is "not proven", never "malicious": only a hard rule (or, elsewhere, real
        // evidence such as an advisor/reputation verdict) makes a program Malicious.
        let v = if s >= pack.meta.safe_min {
            Verdict::Safe
        } else {
            Verdict::Unknown
        };
        (s, v)
    };

    let guarded =
        fired.iter().any(|r| r.kind == Kind::Guard) && !GUARD_LIFTED_BY.iter().any(|id| has(id));

    Evaluation {
        score,
        verdict,
        signals: fired
            .iter()
            .map(|r| Fired {
                id: r.id.clone(),
                name: r.name.clone(),
                kind: r.kind,
                delta: if r.kind == Kind::Signal {
                    r.score
                } else {
                    None
                },
            })
            .collect(),
        never_kill: guarded,
        rule_pack_version: pack.meta.rule_pack_version.clone(),
    }
}

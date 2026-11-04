//! Raw host observations → rule `Facts`. Everything here is pure; the platform layer only fills
//! [`Observation`] and builds a [`Context`] once.

use std::collections::{HashMap, HashSet};

use crate::analysis::masquerade;
use crate::analysis::names::{claims_publisher, compare_company, is_typosquat, normalize_org};
use crate::analysis::path::{PathEnv, basename, classify, normalize};
use crate::eval::Facts;
use crate::rules::{Lolbins, Publisher, Publishers, SignatureState, SystemProcesses};

/// Result of signature verification for one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerInfo {
    pub state: SignatureState,
    /// Subject organisation of the signing leaf certificate.
    pub org: Option<String>,
    /// Common names of the certificates in the chain (root last).
    pub chain_names: Vec<String>,
    /// SHA-1 thumbprints (upper-case hex) of the chain certificates.
    pub thumbprints: Vec<String>,
    pub ms_root: bool,
    /// Signed with the Windows OS certificate or listed in an OS catalog.
    pub os_signed: bool,
}

impl SignerInfo {
    /// The "not signed at all" value.
    #[must_use]
    pub fn unsigned() -> Self {
        Self {
            state: SignatureState::Unsigned,
            org: None,
            chain_names: Vec::new(),
            thumbprints: Vec::new(),
            ms_root: false,
            os_signed: false,
        }
    }

    /// Embedded or catalog signature verified.
    #[must_use]
    pub fn valid(&self) -> bool {
        matches!(
            self.state,
            SignatureState::ValidEmbedded | SignatureState::ValidCatalog
        )
    }
}

/// `VersionInfo` strings of the image.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VersionInfo {
    pub company: String,
    pub product: String,
    pub original_filename: String,
    pub legal_copyright: String,
}

/// Behaviour seen for the identity (all `false` for a static scan).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct Behaviour {
    pub has_outbound: bool,
    pub dest_public: bool,
    pub beaconing: bool,
    pub public_dest_no_dns: bool,
    pub risky_port_or_tld: bool,
    pub unbacked_exec_memory: bool,
    /// A module loaded from a user-writable path has no valid signature (T14).
    pub unsigned_writable_module: bool,
}

/// Everything known about one running or candidate image.
#[derive(Debug, Clone)]
pub struct Observation {
    /// Image path as reported by the OS (normalised internally).
    pub path: String,
    pub parent_path: Option<String>,
    pub signer: SignerInfo,
    pub version: VersionInfo,
    pub behaviour: Behaviour,
    pub vt_detections: Option<u32>,
    pub vt_first_seen_days: Option<u32>,
    pub user_denylisted: bool,
    pub user_allowed: bool,
    pub vigil_self: bool,
}

/// Machine- and rule-derived lookup data, built once per rule pack.
#[derive(Debug, Clone)]
pub struct Context {
    pub path_env: PathEnv,
    /// Lower-case environment variables for `%NAME%` expansion.
    pub vars: HashMap<String, String>,
    pub system: SystemProcesses,
    pub lolbins: Lolbins,
    pub publishers: Publishers,
    /// Leaf and intermediate thumbprints from `publishers.lock`, keyed by publisher id.
    pub locked_thumbprints: HashMap<String, HashSet<String>>,
}

impl Context {
    fn canonical_names(&self) -> Vec<String> {
        self.system
            .processes
            .iter()
            .map(|p| p.name.clone())
            .collect()
    }

    fn pinned(&self, signer: &SignerInfo) -> bool {
        let Some(org) = signer.org.as_deref().map(normalize_org) else {
            return false;
        };
        signer.valid()
            && self.publishers.publishers.iter().any(|p| {
                publisher_names(p).iter().any(|n| normalize_org(n) == org)
                    && self.chain_ok(p, signer)
            })
    }

    fn chain_ok(&self, p: &Publisher, s: &SignerInfo) -> bool {
        if p.match_mode == "thumbprint" {
            self.locked_thumbprints
                .get(&p.id)
                .is_some_and(|pins| s.thumbprints.iter().any(|t| pins.contains(t)))
        } else {
            p.required_roots
                .iter()
                .any(|r| s.chain_names.iter().any(|c| c.eq_ignore_ascii_case(r)))
        }
    }

    /// Names of publishers that can actually be pinned. A thumbprint-mode publisher without any
    /// bootstrapped pin cannot be impersonated *against*, so claiming it is not a signal.
    fn all_publisher_names(&self) -> Vec<String> {
        self.publishers
            .publishers
            .iter()
            .filter(|p| {
                p.match_mode != "thumbprint"
                    || self
                        .locked_thumbprints
                        .get(&p.id)
                        .is_some_and(|t| !t.is_empty())
            })
            .flat_map(publisher_names)
            .collect()
    }
}

fn publisher_names(p: &Publisher) -> Vec<String> {
    std::iter::once(p.subject_org.clone())
        .chain(p.aliases.iter().cloned())
        .collect()
}

/// Derive the rule inputs for `obs`.
#[must_use]
pub fn build_facts(ctx: &Context, obs: &Observation) -> Facts {
    let path = normalize(&obs.path);
    let parent = obs.parent_path.as_deref().map(normalize);
    let name = basename(&path).to_string();
    let masq = masquerade::check(&ctx.system, &ctx.vars, &path, parent.as_deref());
    let signer = &obs.signer;
    let known = crate::analysis::known::lookup(
        &name,
        &[
            obs.version.company.as_str(),
            obs.version.product.as_str(),
            obs.version.original_filename.as_str(),
        ],
    )
    .is_some();
    let company = if signer.valid() && !known {
        compare_company(&obs.version.company, signer.org.as_deref().unwrap_or(""))
    } else {
        crate::analysis::names::CompanyCheck::default()
    };
    let metadata = [
        obs.version.company.as_str(),
        obs.version.product.as_str(),
        obs.version.legal_copyright.as_str(),
    ];
    let signer_pinned = ctx.pinned(signer);
    Facts {
        signature: signer.state,
        path_class: classify(&path, &ctx.path_env),
        signer_pinned,
        signer_ms_root: signer.ms_root,
        os_signed: signer.os_signed,
        at_canonical_path: masq.at_canonical_path,
        name_in_canonical_set: masq.name_in_canonical_set,
        parent_ok: masq.parent_ok,
        parent_check_applies: masq.parent_check_applies,
        never_kill_set: masq.never_kill_set,
        company_matches_signer: company.matches,
        company_conflicts_signer: company.conflicts,
        known_software: known,
        claims_pinned_publisher: claims_publisher(&metadata, &ctx.all_publisher_names()),
        lolbin: ctx
            .lolbins
            .lolbins
            .names
            .iter()
            .any(|n| n.eq_ignore_ascii_case(&name)),
        has_outbound: obs.behaviour.has_outbound,
        dest_public: obs.behaviour.dest_public,
        beaconing: obs.behaviour.beaconing,
        public_dest_no_dns: obs.behaviour.public_dest_no_dns,
        risky_port_or_tld: obs.behaviour.risky_port_or_tld,
        typosquat: !signer.valid() && is_typosquat(&name, &ctx.canonical_names()),
        unbacked_exec_memory: obs.behaviour.unbacked_exec_memory,
        unsigned_writable_module: obs.behaviour.unsigned_writable_module,
        vt_detections: obs.vt_detections,
        vt_first_seen_days: obs.vt_first_seen_days,
        user_denylisted: obs.user_denylisted,
        user_allowed: obs.user_allowed,
        vigil_self: obs.vigil_self,
    }
}

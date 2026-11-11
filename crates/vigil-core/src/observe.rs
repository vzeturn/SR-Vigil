//! Raw host observations → rule `Facts`. Everything here is pure; the platform layer only fills
//! [`Observation`] and builds a [`Context`] once.

use std::collections::{HashMap, HashSet};

use crate::analysis::masquerade;
use crate::analysis::names::{claims_publisher, compare_company, is_typosquat, normalize_org};
use crate::analysis::path::{PathEnv, basename, classify, normalize};
use crate::eval::Facts;
use crate::rules::{
    Lolbins, Publisher, Publishers, SignatureState, SystemProcesses, VersionStatus,
};

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
    /// `FileVersion` (dotted numbers); empty when the file declares none.
    pub file_version: String,
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
    /// A destination it reached is on the offline or URL-filter bad list (NET-001).
    pub bad_destination: bool,
    /// A destination name it resolved looks machine-generated (NET-002).
    pub generated_dest_name: bool,
    /// It started a script host with an encoded/hidden command line, or (Office/browser) a shell (PRC-001).
    pub spawned_suspicious_child: bool,
    /// File and credential-store activity (FIL-001/002, RES-001).
    pub files: FileSeen,
    pub unbacked_exec_memory: bool,
    /// A module loaded from a user-writable path has no valid signature (T14).
    pub unsigned_writable_module: bool,
    /// A uv/pip console script whose package metadata names a source from `rules/app_profiles.toml`.
    pub package_source_trusted: bool,
    /// The file carries a Mark of the Web for the Internet or a restricted zone (`docs/20 s2`).
    pub from_internet: bool,
    /// The file hash is listed as known-good by the hash reputation service (`docs/20 s5`).
    pub hash_known_good: bool,
}

/// File findings accumulated for a program while it runs (`docs/15 §2`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct FileSeen {
    /// It created an executable or script in a user-writable folder (FIL-001).
    pub dropped_executable: bool,
    /// It renamed many user files to one new double extension in a short window (FIL-002).
    pub mass_renamed: bool,
    /// It opened a credential store it does not own (RES-001).
    pub foreign_credential_store: bool,
    /// It opened a credential store under the owner's name; RES-001 only without a valid signature.
    pub credential_store_as_owner: bool,
}

/// Network findings accumulated for a program while it runs (`docs/15 §2`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct NetSeen {
    /// It opened an outbound connection to a public address.
    pub public_outbound: bool,
    pub bad: bool,
    pub generated_name: bool,
    pub no_dns: bool,
    pub risky_port_or_tld: bool,
}

impl NetSeen {
    /// Fold in one public outbound connection; `true` when this adds a finding.
    pub fn absorb(&mut self, a: &crate::analysis::reputation::DestAssessment) -> bool {
        let before = *self;
        self.public_outbound = true;
        self.bad |= a.bad;
        self.generated_name |= a.generated_name;
        self.no_dns |= a.no_dns;
        self.risky_port_or_tld |= a.risky_port_or_tld;
        *self != before
    }
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
    let entry = crate::analysis::known::lookup(
        &name,
        &[
            obs.version.company.as_str(),
            obs.version.product.as_str(),
            obs.version.original_filename.as_str(),
        ],
    );
    let known = entry.is_some();
    let version_status = entry.map_or(VersionStatus::Unknown, |k| {
        k.version_status(&obs.version.file_version)
    });
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
        version_status,
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
        bad_destination: obs.behaviour.bad_destination,
        generated_dest_name: obs.behaviour.generated_dest_name,
        suspicious_child: obs.behaviour.spawned_suspicious_child,
        drops_executable: obs.behaviour.files.dropped_executable,
        mass_file_change: obs.behaviour.files.mass_renamed,
        // A program named like the store's owner counts only when its signature is not valid,
        // so a fake chrome.exe reading Chrome's logins still fires.
        sensitive_resource: obs.behaviour.files.foreign_credential_store
            || (obs.behaviour.files.credential_store_as_owner && !signer.valid()),
        typosquat: !signer.valid() && is_typosquat(&name, &ctx.canonical_names()),
        unbacked_exec_memory: obs.behaviour.unbacked_exec_memory,
        unsigned_writable_module: obs.behaviour.unsigned_writable_module,
        package_source_trusted: obs.behaviour.package_source_trusted,
        from_internet: obs.behaviour.from_internet,
        hash_known_good: obs.behaviour.hash_known_good,
        vt_detections: obs.vt_detections,
        vt_first_seen_days: obs.vt_first_seen_days,
        user_denylisted: obs.user_denylisted,
        user_allowed: obs.user_allowed,
        vigil_self: obs.vigil_self,
    }
}

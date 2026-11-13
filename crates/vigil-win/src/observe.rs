//! Static classification of an image on this machine: builds the rule `Context` from the
//! environment and evaluates a binary with signature, version and parent facts.

use std::collections::{HashMap, HashSet};

use vigil_core::analysis::hashrep;
use vigil_core::analysis::path::{PathEnv, expand, normalize};
use vigil_core::eval::{Evaluation, evaluate};
use vigil_core::observe::{Behaviour, Context, Observation, SignerInfo, VersionInfo, build_facts};
use vigil_core::rules::{Lolbins, Publishers, RulePack, SignatureState, SystemProcesses};

use crate::{trust, version};

/// Build the evaluation context (embedded aux rules, environment paths, bootstrapped pins).
pub fn env_context() -> Result<Context, vigil_core::rules::RuleError> {
    let vars: HashMap<String, String> = std::env::vars()
        .map(|(k, v)| (k.to_lowercase(), v))
        .collect();
    let var = |k: &str| vars.get(k).cloned();
    let program_data = var("programdata").unwrap_or_else(|| r"C:\ProgramData".into());
    let path_env = PathEnv {
        system_root: normalize(&var("systemroot").unwrap_or_else(|| r"C:\Windows".into())),
        program_files: ["programfiles", "programfiles(x86)", "programw6432"]
            .iter()
            .filter_map(|k| var(k))
            .map(|p| normalize(&p))
            .collect(),
        user_writable: [Some(program_data.clone()), var("temp")]
            .into_iter()
            .flatten()
            .map(|p| normalize(&p))
            .collect(),
        vigil_data_dir: normalize(&format!(r"{program_data}\Vigil")),
        removable_drives: Vec::new(),
    };
    let publishers = Publishers::parse(
        "publishers.toml",
        include_str!("../../../rules/publishers.toml"),
    )?;
    let locked_thumbprints = bootstrap_pins(&publishers, &vars);
    Ok(Context {
        path_env,
        vars,
        system: SystemProcesses::parse(
            "system_processes.toml",
            include_str!("../../../rules/system_processes.toml"),
        )?,
        lolbins: Lolbins::parse("lolbins.toml", include_str!("../../../rules/lolbins.toml"))?,
        publishers,
        locked_thumbprints,
    })
}

/// In-memory equivalent of `vigilctl trust bootstrap`: pin the chain thumbprints observed on each
/// publisher's reference binaries (docs/03), only when the signature is valid and the org matches.
fn bootstrap_pins(
    publishers: &Publishers,
    vars: &HashMap<String, String>,
) -> HashMap<String, HashSet<String>> {
    let mut pins: HashMap<String, HashSet<String>> = HashMap::new();
    for p in publishers
        .publishers
        .iter()
        .filter(|p| p.match_mode == "thumbprint")
    {
        for file in &p.bootstrap_from {
            let path = expand(file, vars);
            let signer = trust::verify(&path);
            let org_ok = signer.org.as_deref().is_some_and(|o| {
                o.eq_ignore_ascii_case(&p.subject_org)
                    || p.aliases.iter().any(|a| o.eq_ignore_ascii_case(a))
            });
            if org_ok
                && matches!(
                    signer.state,
                    SignatureState::ValidEmbedded | SignatureState::ValidCatalog
                )
            {
                pins.entry(p.id.clone())
                    .or_default()
                    .extend(signer.thumbprints);
            }
        }
    }
    pins
}

/// What the service has learned about a program while it runs, beyond the file itself.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Live {
    /// An active user allow decision covers this file (HA-002, never outranks a hard rule).
    pub user_allowed: bool,
    /// It calls the same public destination at a machine-regular interval (BEH-002).
    pub beaconing: bool,
    /// What its outbound connections looked like (BEH-001, BEH-003/004, NET-001/002).
    pub net: vigil_core::observe::NetSeen,
    /// It started a suspicious child process this run (PRC-001).
    pub spawned_suspicious_child: bool,
    /// File and credential-store activity this run (FIL-001/002, RES-001).
    pub files: vigil_core::observe::FileSeen,
}

/// Evaluate `path` (child of `parent`) against `pack`, with what was observed live.
#[must_use]
pub fn evaluate_image(
    ctx: &Context,
    pack: &RulePack,
    path: &str,
    parent: Option<&str>,
    pid: Option<u32>,
    live: Live,
) -> Evaluation {
    let (ev, ..) = evaluate_with(ctx, pack, path, parent, pid, live);
    ev
}

/// Like [`evaluate_image`], but also returns the signature and version evidence it was based on.
#[must_use]
pub fn evaluate_image_detailed(
    ctx: &Context,
    pack: &RulePack,
    path: &str,
    parent: Option<&str>,
    pid: Option<u32>,
) -> (Evaluation, SignerInfo, VersionInfo) {
    evaluate_with(ctx, pack, path, parent, pid, Live::default())
}

fn evaluate_with(
    ctx: &Context,
    pack: &RulePack,
    path: &str,
    parent: Option<&str>,
    pid: Option<u32>,
    live: Live,
) -> (Evaluation, SignerInfo, VersionInfo) {
    let signer = trust::verify(path);
    let version = version::read(path).unwrap_or_default();
    let scan_memory = crate::memory::enabled() && !signer.valid();
    let rep = hash_facts(path, signer.valid());
    let obs = Observation {
        path: path.to_string(),
        parent_path: parent.map(str::to_string),
        version: version.clone(),
        behaviour: Behaviour {
            unsigned_writable_module: pid
                .is_some_and(|p| crate::modules::has_unsigned_writable_module(ctx, p, path)),
            unbacked_exec_memory: scan_memory
                && pid.is_some_and(crate::memory::has_unbacked_exec_memory),
            package_source_trusted: package_family(path).is_some(),
            from_internet: from_internet(path),
            hash_known_good: rep.known_good,
            hash_known_malware: rep.malware,
            beaconing: live.beaconing,
            has_outbound: live.net.public_outbound,
            dest_public: live.net.public_outbound,
            public_dest_no_dns: live.net.no_dns,
            risky_port_or_tld: live.net.risky_port_or_tld,
            bad_destination: live.net.bad,
            generated_dest_name: live.net.generated_name,
            unusual_upload: live.net.unusual_upload,
            spawned_suspicious_child: live.spawned_suspicious_child,
            files: live.files,
        },
        signer: signer.clone(),
        vt_detections: rep.vt.map(|r| r.detections),
        vt_first_seen_days: rep.vt.map(|r| r.first_seen_days(unix_now())),
        user_denylisted: false,
        user_allowed: live.user_allowed,
        vigil_self: crate::selfpin::is_vigil_self(path),
    };
    (evaluate(pack, &build_facts(ctx, &obs)), signer, version)
}

/// The package family of a uv/pip console script whose package metadata names a trusted source
/// (`docs/19 §5`); `None` for anything else. The metadata is author-written: this is evidence of
/// origin, never proof.
#[must_use]
pub fn package_family(image: &str) -> Option<String> {
    const MAX_METADATA: u64 = 64 * 1024;
    let pkg = vigil_core::profile::dev_package(image)?;
    let site = std::path::Path::new(&pkg.env)
        .join("Lib")
        .join("site-packages");
    std::fs::read_dir(site)
        .ok()?
        .flatten()
        .filter(|e| pkg.owns_dist_info(&e.file_name().to_string_lossy()))
        .find_map(|e| {
            let file = e.path().join("METADATA");
            if !std::fs::metadata(&file).is_ok_and(|m| m.len() <= MAX_METADATA) {
                return None;
            }
            let text = std::fs::read_to_string(file).ok()?;
            pkg.family(vigil_core::profile::trusted_source(&text)?)
        })
}

/// Whether the file's `Zone.Identifier` stream marks it as downloaded (`docs/20 s2`). Reads at most
/// 4 KiB; a file without the stream (the usual case) fails to open at once.
fn from_internet(path: &str) -> bool {
    use std::io::Read as _;
    let Ok(f) = std::fs::File::open(format!("{path}:Zone.Identifier")) else {
        return false;
    };
    let mut text = String::new();
    f.take(4096).read_to_string(&mut text).is_ok()
        && vigil_core::analysis::motw::from_internet(&text)
}

/// What the hash reputation services said about the unsigned file at `path` (`docs/20 §5`).
#[derive(Default)]
struct HashFacts {
    known_good: bool,
    malware: bool,
    vt: Option<hashrep::VtReport>,
}

/// Reputation answers for the unsigned file at `path`. Signed files are judged by their
/// signature (the services are only asked about unsigned ones), and nothing is hashed until
/// some answer is held.
fn hash_facts(path: &str, signed: bool) -> HashFacts {
    static HASHES: std::sync::OnceLock<crate::hash::HashCache> = std::sync::OnceLock::new();
    if signed || !(hashrep::any() || hashrep::any_keyed()) {
        return HashFacts::default();
    }
    HASHES
        .get_or_init(crate::hash::HashCache::new)
        .sha256(std::path::Path::new(path))
        .map(|h| HashFacts {
            known_good: hashrep::is_known(&h),
            malware: hashrep::is_malware(&h),
            vt: hashrep::vt_of(&h),
        })
        .unwrap_or_default()
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

//! Static classification of an image on this machine: builds the rule `Context` from the
//! environment and evaluates a binary with signature, version and parent facts.

use std::collections::{HashMap, HashSet};

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

/// Evaluate `path` (child of `parent`) against `pack`.
#[must_use]
pub fn evaluate_image(
    ctx: &Context,
    pack: &RulePack,
    path: &str,
    parent: Option<&str>,
    pid: Option<u32>,
) -> Evaluation {
    evaluate_image_detailed(ctx, pack, path, parent, pid).0
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
    let signer = trust::verify(path);
    let version = version::read(path).unwrap_or_default();
    let scan_memory = crate::memory::enabled() && !signer.valid();
    let obs = Observation {
        path: path.to_string(),
        parent_path: parent.map(str::to_string),
        version: version.clone(),
        behaviour: Behaviour {
            unsigned_writable_module: pid
                .is_some_and(|p| crate::modules::has_unsigned_writable_module(ctx, p, path)),
            unbacked_exec_memory: scan_memory
                && pid.is_some_and(crate::memory::has_unbacked_exec_memory),
            package_source_trusted: package_source_trusted(path),
            from_internet: from_internet(path),
            hash_known_good: hash_known_good(path, signer.valid()),
            ..Behaviour::default()
        },
        signer: signer.clone(),
        vt_detections: None,
        vt_first_seen_days: None,
        user_denylisted: false,
        user_allowed: false,
        vigil_self: false,
    };
    (evaluate(pack, &build_facts(ctx, &obs)), signer, version)
}

/// Whether `image` is a uv/pip console script whose package metadata names a trusted source
/// (`docs/19 §5`). The metadata is author-written: this is evidence of origin, never proof.
fn package_source_trusted(image: &str) -> bool {
    const MAX_METADATA: u64 = 64 * 1024;
    let Some(pkg) = vigil_core::profile::dev_package(image) else {
        return false;
    };
    let site = std::path::Path::new(&pkg.env)
        .join("Lib")
        .join("site-packages");
    let Ok(dir) = std::fs::read_dir(site) else {
        return false;
    };
    dir.flatten()
        .filter(|e| pkg.owns_dist_info(&e.file_name().to_string_lossy()))
        .any(|e| {
            let file = e.path().join("METADATA");
            std::fs::metadata(&file).is_ok_and(|m| m.len() <= MAX_METADATA)
                && std::fs::read_to_string(file)
                    .is_ok_and(|t| vigil_core::profile::trusted_source(&t).is_some())
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

/// Whether the unsigned file at `path` has a hash the reputation service reported as known-good.
/// Signed files are judged by their signature, and nothing is hashed until a hash is known.
fn hash_known_good(path: &str, signed: bool) -> bool {
    static HASHES: std::sync::OnceLock<crate::hash::HashCache> = std::sync::OnceLock::new();
    !signed
        && vigil_core::analysis::hashrep::any()
        && HASHES
            .get_or_init(crate::hash::HashCache::new)
            .sha256(std::path::Path::new(path))
            .is_ok_and(|h| vigil_core::analysis::hashrep::is_known(&h))
}

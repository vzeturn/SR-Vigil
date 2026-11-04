//! Static classification of an image on this machine: builds the rule `Context` from the
//! environment and evaluates a binary with signature, version and parent facts.

use std::collections::{HashMap, HashSet};

use vigil_core::analysis::path::{PathEnv, expand, normalize};
use vigil_core::eval::{Evaluation, evaluate};
use vigil_core::observe::{Behaviour, Context, Observation, build_facts};
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
    let signer = trust::verify(path);
    let scan_memory = crate::memory::enabled() && !signer.valid();
    let obs = Observation {
        path: path.to_string(),
        parent_path: parent.map(str::to_string),
        version: version::read(path).unwrap_or_default(),
        behaviour: Behaviour {
            unsigned_writable_module: pid
                .is_some_and(|p| crate::modules::has_unsigned_writable_module(ctx, p)),
            unbacked_exec_memory: scan_memory
                && pid.is_some_and(crate::memory::has_unbacked_exec_memory),
            ..Behaviour::default()
        },
        signer,
        vt_detections: None,
        vt_first_seen_days: None,
        user_denylisted: false,
        user_allowed: false,
        vigil_self: false,
    };
    evaluate(pack, &build_facts(ctx, &obs))
}

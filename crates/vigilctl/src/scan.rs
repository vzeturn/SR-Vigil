//! `vigilctl scan`: one-shot static classification of running processes.

use std::collections::{HashMap, HashSet};

use anyhow::Context as _;
use vigil_core::analysis::path::{PathEnv, expand, normalize};
use vigil_core::eval::{Evaluation, evaluate};
use vigil_core::observe::{Behaviour, Context, Observation, build_facts};
use vigil_core::rules::{Lolbins, Publishers, RuleStore, SignatureState, SystemProcesses, Verdict};
use vigil_win::{process, trust, version};

fn env_context() -> anyhow::Result<Context> {
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
fn bootstrap_pins(publishers: &Publishers, vars: &HashMap<String, String>) -> HashSet<String> {
    let mut pins = HashSet::new();
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
                pins.extend(signer.thumbprints);
            }
        }
    }
    pins
}

const fn verdict_name(v: Verdict) -> &'static str {
    match v {
        Verdict::Safe => "safe",
        Verdict::Unknown => "unknown",
        Verdict::Malicious => "malicious",
    }
}

fn evaluate_image(
    ctx: &Context,
    pack: &vigil_core::rules::RulePack,
    path: &str,
    parent: Option<&str>,
) -> Evaluation {
    let obs = Observation {
        path: path.to_string(),
        parent_path: parent.map(str::to_string),
        signer: trust::verify(path),
        version: version::read(path).unwrap_or_default(),
        behaviour: Behaviour::default(),
        vt_detections: None,
        vt_first_seen_days: None,
        user_denylisted: false,
        user_allowed: false,
        vigil_self: false,
    };
    evaluate(pack, &build_facts(ctx, &obs))
}

pub fn run(json: bool) -> anyhow::Result<()> {
    let ctx = env_context().context("load rule data")?;
    let pack = RuleStore::from_embedded()?.active();
    let procs = process::snapshot().context("enumerate processes")?;
    let parents = process::parent_of(&procs);

    let mut cache: HashMap<(String, Option<String>), Evaluation> = HashMap::new();
    let mut rows = Vec::new();
    let mut skipped = 0usize;
    for p in &procs {
        let Some(image) = p.image.as_deref() else {
            skipped += 1;
            continue;
        };
        let parent = parents.get(&p.pid).and_then(|pp| pp.image.clone());
        let ev = cache
            .entry((normalize(image), parent.clone()))
            .or_insert_with(|| evaluate_image(&ctx, &pack, image, parent.as_deref()));
        rows.push((p.pid, p.name.clone(), image.to_string(), ev.clone()));
    }
    rows.sort_by(|a, b| a.3.score.cmp(&b.3.score).then(a.0.cmp(&b.0)));

    if json {
        let out: Vec<_> = rows
            .iter()
            .map(|(pid, name, image, ev)| {
                serde_json::json!({
                    "pid": pid, "name": name, "image": image,
                    "score": ev.score, "verdict": verdict_name(ev.verdict),
                    "signals": ev.signals.iter().map(|s| &s.id).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "processes": out, "skipped_inaccessible": skipped,
                "rule_pack_version": pack_version(&rows),
            }))?
        );
    } else {
        for (pid, name, _, ev) in &rows {
            let ids: Vec<&str> = ev.signals.iter().map(|s| s.id.as_str()).collect();
            println!(
                "{:>6}  {:<28} {:>3}  {:<9} {}",
                pid,
                name,
                ev.score,
                verdict_name(ev.verdict),
                ids.join(",")
            );
        }
        let count = |v| rows.iter().filter(|r| r.3.verdict == v).count();
        println!(
            "\n{} safe, {} unknown, {} malicious; {} inaccessible (run elevated to include them)",
            count(Verdict::Safe),
            count(Verdict::Unknown),
            count(Verdict::Malicious),
            skipped
        );
    }
    Ok(())
}

fn pack_version(rows: &[(u32, String, String, Evaluation)]) -> String {
    rows.first()
        .map(|r| r.3.rule_pack_version.clone())
        .unwrap_or_default()
}

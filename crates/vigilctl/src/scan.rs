//! `vigilctl scan`: one-shot static classification of running processes.

use std::collections::HashMap;

use anyhow::Context as _;
use vigil_core::analysis::path::normalize;
use vigil_core::eval::Evaluation;
use vigil_core::rules::{RuleStore, Verdict};
use vigil_win::observe::{env_context, evaluate_image};
use vigil_win::process;

const fn verdict_name(v: Verdict) -> &'static str {
    match v {
        Verdict::Safe => "safe",
        Verdict::Unknown => "unknown",
        Verdict::Malicious => "malicious",
    }
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

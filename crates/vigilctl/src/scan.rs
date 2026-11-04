//! `vigilctl scan`: one-shot static classification of running processes.

use anyhow::anyhow;
use vigil_core::rules::Verdict;
use vigil_win::scan::{self, verdict_name};

pub fn run(json: bool) -> anyhow::Result<()> {
    let scan = scan::run().map_err(|e| anyhow!(e))?;
    if json {
        let out: Vec<_> = scan
            .rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "pid": r.pid, "name": r.name, "image": r.image,
                    "score": r.eval.score, "verdict": verdict_name(r.eval.verdict),
                    "signals": r.eval.signals.iter().map(|s| &s.id).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "processes": out, "skipped_inaccessible": scan.skipped,
                "rule_pack_version": scan.rule_pack_version,
            }))?
        );
    } else {
        for r in &scan.rows {
            let ids: Vec<&str> = r.eval.signals.iter().map(|s| s.id.as_str()).collect();
            println!(
                "{:>6}  {:<28} {:>3}  {:<9} {}",
                r.pid,
                r.name,
                r.eval.score,
                verdict_name(r.eval.verdict),
                ids.join(",")
            );
        }
        println!(
            "\n{} safe, {} unknown, {} malicious; {} inaccessible (run elevated to include them)",
            scan.count(Verdict::Safe),
            scan.count(Verdict::Unknown),
            scan.count(Verdict::Malicious),
            scan.skipped
        );
    }
    Ok(())
}

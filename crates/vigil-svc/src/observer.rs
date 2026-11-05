//! Unprivileged observer: polls processes and the TCP table, classifies new images, and keeps
//! [`Shared`] current. ETW (DNS names, instant connect events) needs elevation and is added in M3.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use vigil_core::analysis::path::normalize;
use vigil_core::rules::{RulePack, SignatureState, Verdict};
use vigil_store::repo::{Executable, NewEvaluation, insert_evaluation, upsert_executable};
use vigil_win::hash::HashCache;
use vigil_win::observe::{env_context, evaluate_image};
use vigil_win::process::{self, ProcessInfo};
use vigil_win::{net, trust, version};

use crate::state::{ConnRow, ProcRow, Shared, now};

const POLL: Duration = Duration::from_millis(500);
/// More new images than this in one tick counts as a burst (first scan, installer, build).
const BURST: usize = 8;
const BURST_PAUSE: Duration = Duration::from_millis(40);
const HEARTBEAT: Duration = Duration::from_secs(15);

type Key = (String, Option<String>);

#[derive(Clone)]
struct Verdicted {
    verdict: &'static str,
    score: u8,
    identity: String,
    signals: Vec<serde_json::Value>,
    freshness: Option<serde_json::Value>,
}

const fn verdict_name(v: Verdict) -> &'static str {
    match v {
        Verdict::Safe => "safe",
        Verdict::Unknown => "unknown",
        Verdict::Malicious => "malicious",
    }
}

const fn sig_status(s: SignatureState) -> &'static str {
    match s {
        SignatureState::ValidEmbedded | SignatureState::Valid => "valid_embedded",
        SignatureState::ValidCatalog => "valid_catalog",
        SignatureState::Unsigned => "unsigned",
        SignatureState::Invalid => "invalid",
        SignatureState::Expired => "expired",
        SignatureState::Revoked => "revoked",
        SignatureState::UntrustedRoot => "untrusted_root",
    }
}

fn signals_of(ev: &vigil_core::eval::Evaluation) -> Vec<serde_json::Value> {
    ev.signals
        .iter()
        .map(|s| serde_json::json!({"id": s.id, "name": s.name, "delta": s.delta.unwrap_or(0)}))
        .collect()
}

/// `FILETIME` ticks (100 ns since 1601) to RFC 3339.
pub(crate) fn start_time(ticks: Option<u64>) -> String {
    const EPOCH_DIFF_SECS: i64 = 11_644_473_600;
    let secs = ticks.map_or(0, |t| i64::try_from(t / 10_000_000).unwrap_or(0)) - EPOCH_DIFF_SECS;
    time::OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|d| {
            d.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

/// "Installed X, latest Y" for `path` when it is a recognised program that is behind.
fn freshness_note(path: &str) -> Option<serde_json::Value> {
    let ver = version::read(path)?;
    let name = Path::new(path).file_name()?.to_str()?;
    let f = vigil_core::analysis::known::freshness(
        name,
        &[&ver.company, &ver.product, &ver.original_filename],
        &ver.file_version,
    )?;
    Some(serde_json::json!({
        "product": f.label, "installed": f.installed, "latest": f.latest,
        "status": match f.status {
            vigil_core::rules::VersionStatus::Outdated => "outdated",
            vigil_core::rules::VersionStatus::FarBehind => "far_behind",
            _ => "vulnerable",
        },
    }))
}

fn persist(
    shared: &Shared,
    hashes: &HashCache,
    path: &str,
    ev: &vigil_core::eval::Evaluation,
) -> String {
    let signer = trust::verify(path);
    let ver = version::read(path).unwrap_or_default();
    let Ok(sha256) = hashes.sha256(Path::new(path)) else {
        return String::new();
    };
    let exe = Executable {
        sha256,
        path: path.to_string(),
        signer_thumbprint: signer.thumbprints.first().cloned(),
        publisher: signer.org.clone(),
        company: Some(ver.company).filter(|s| !s.is_empty()),
        product: Some(ver.product).filter(|s| !s.is_empty()),
        original_filename: Some(ver.original_filename).filter(|s| !s.is_empty()),
        signature_status: sig_status(signer.state).into(),
    };
    let new = NewEvaluation {
        score: ev.score,
        verdict: verdict_name(ev.verdict).into(),
        hard_rule: ev
            .signals
            .iter()
            .find(|s| s.id.starts_with("HR-"))
            .map(|s| s.id.clone()),
        signals_json: serde_json::Value::Array(signals_of(ev)).to_string(),
        rule_pack_version: ev.rule_pack_version.clone(),
        source: "rules".into(),
    };
    let ts = now();
    shared
        .with_store(|c| {
            upsert_executable(c, &exe, &ts)
                .and_then(|id| insert_evaluation(c, id, &new, &ts).map(|_| id))
        })
        .and_then(Result::ok)
        .map(|id| id.to_string())
        .unwrap_or_default()
}

/// Run until the task is dropped.
pub async fn run(shared: Arc<Shared>, pack: Arc<RulePack>) -> anyhow::Result<()> {
    let ctx = Arc::new(env_context()?);
    let hashes = Arc::new(HashCache::new());
    let mut cache: HashMap<Key, Verdicted> = HashMap::new();
    let mut tick = tokio::time::interval(POLL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_beat = tokio::time::Instant::now();

    loop {
        tick.tick().await;
        let procs = match tokio::task::spawn_blocking(process::snapshot).await? {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "process snapshot failed");
                shared.set_health("degraded", Some("process snapshot failed"));
                continue;
            }
        };
        sync_processes(&shared, &procs);

        let mut pending: Vec<(Key, String, Option<String>, u32)> = Vec::new();
        {
            let parents = process::parent_of(&procs);
            for p in &procs {
                let Some(image) = p.image.as_deref() else {
                    continue;
                };
                let parent = parents.get(&p.pid).and_then(|pp| pp.image.clone());
                let key = (normalize(image), parent.as_deref().map(normalize));
                if !cache.contains_key(&key) && !pending.iter().any(|(k, ..)| *k == key) {
                    pending.push((key, image.to_string(), parent, p.pid));
                }
            }
        }
        // A big first scan is spread out so it never hogs a core; steady state has 0-2 new images.
        let burst = pending.len() > BURST;
        for (key, image, parent, pid) in pending {
            if burst {
                tokio::time::sleep(BURST_PAUSE).await;
            }
            let (ctx, pack, hashes, sh) = (
                Arc::clone(&ctx),
                Arc::clone(&pack),
                Arc::clone(&hashes),
                Arc::clone(&shared),
            );
            let img = image.clone();
            let par = parent.clone();
            let v = tokio::task::spawn_blocking(move || {
                let ev = evaluate_image(&ctx, &pack, &img, par.as_deref(), Some(pid));
                let identity = persist(&sh, &hashes, &img, &ev);
                Verdicted {
                    verdict: verdict_name(ev.verdict),
                    score: ev.score,
                    identity,
                    signals: signals_of(&ev),
                    freshness: freshness_note(&img),
                }
            })
            .await?;
            for (row, old) in shared.apply_evaluation(
                &image,
                parent.as_deref(),
                &v.identity,
                v.verdict,
                v.score,
                v.freshness.as_ref(),
            ) {
                announce(&shared, &row, old, &v.signals);
            }
            if v.verdict == "malicious" && shared.raise_malicious(&v.identity) {
                tokio::spawn(Arc::clone(&shared).ai_assess_open_pending());
            } else if v.verdict == "unknown"
                && let Ok(id) = v.identity.parse::<i64>()
            {
                tokio::spawn(Arc::clone(&shared).ai_prefetch(id));
            }
            cache.insert(key, v);
        }

        sync_connections(&shared);
        for (row, n) in shared.storm_suspects() {
            tokio::spawn(Arc::clone(&shared).storm_review(row, n));
        }
        let sh = Arc::clone(&shared);
        tokio::task::spawn_blocking(move || {
            sh.storm_scan();
            sh.respawn_scan();
            sh.auto_kill_malicious();
        })
        .await?;

        if last_beat.elapsed() >= HEARTBEAT {
            shared.emit_health();
            last_beat = tokio::time::Instant::now();
        }
    }
}

fn announce(shared: &Shared, row: &ProcRow, old: Option<String>, signals: &[serde_json::Value]) {
    match (old, row.verdict.as_deref()) {
        (Some(old), Some(new)) if old != new => shared.emit(
            "verdicts",
            "event.verdict_changed",
            serde_json::json!({
                "identity_id": row.identity_id, "old": old, "new": new,
                "score": row.score, "signals": signals,
            }),
        ),
        // First verdict: refresh the row as an upsert (docs/05).
        _ => shared.emit("processes", "event.process_started", row.to_json()),
    }
}

fn sync_processes(shared: &Shared, procs: &[ProcessInfo]) {
    let parents = process::parent_of(procs);
    let live: HashMap<u32, String> = procs
        .iter()
        .map(|p| (p.pid, start_time(p.start_time)))
        .collect();
    for (pid, st) in shared.process_keys() {
        if live.get(&pid) != Some(&st) {
            shared.remove_process(pid, &st);
        }
    }
    let known: HashMap<u32, String> = shared.process_keys().into_iter().collect();
    for p in procs {
        let st = &live[&p.pid];
        if known.get(&p.pid) == Some(st) {
            continue;
        }
        shared.put_process(ProcRow {
            pid: p.pid,
            start_time: st.clone(),
            ppid: p.ppid,
            name: p.name.clone(),
            path: p.image.clone(),
            parent_path: parents.get(&p.pid).and_then(|pp| pp.image.clone()),
            identity_id: None,
            verdict: None,
            score: None,
            freshness: None,
        });
    }
}

fn sync_connections(shared: &Shared) {
    let Ok(conns) = net::tcp_connections() else {
        shared.set_health("degraded", Some("connection table unavailable"));
        return;
    };
    let ts = now();
    let rows = conns
        .into_iter()
        .filter(|c| c.state != "time_wait" && c.state != "delete_tcb")
        .map(|c| {
            let listening = c.state == "listen";
            let id = format!(
                "{}:{}:{}:{}:{}",
                c.pid, c.local, c.local_port, c.remote, c.remote_port
            );
            ConnRow {
                id,
                pid: c.pid,
                direction: if listening || c.local_port < c.remote_port && c.local_port < 1024 {
                    "inbound"
                } else {
                    "outbound"
                },
                local_addr: c.local.to_string(),
                local_port: c.local_port,
                remote_addr: (!listening).then(|| c.remote.to_string()),
                remote_port: (!listening).then_some(c.remote_port),
                state: c.state,
                verdict: shared.process_verdict(c.pid),
                first_seen: ts.clone(),
                last_seen: ts.clone(),
            }
        })
        .collect();
    shared.sync_connections(rows);
}

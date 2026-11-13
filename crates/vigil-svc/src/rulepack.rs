//! Daily fetch of the signed remote rule pack (`docs/03 §8.1`). Opt-in, GET only, nothing uploaded.
//! A pack may only add score-lowering signals; it is layered between the embedded defaults and the
//! local `rules.d` overrides. The verified pack is cached and re-verified at start; switching the
//! setting off drops it again.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use vigil_core::audit::AuditKind;
use vigil_core::rules::{RemoteError, RemotePack, RuleStore, remote};

use crate::state::Shared;

/// Rule-pack endpoint baked in at build time; local builds default to the project Worker.
pub const URL: &str = match option_env!("VIGIL_RULEPACK_URL") {
    Some(u) => u,
    None => "https://vigil-catalogue.vutq-sense.workers.dev/v1/rulepack",
};
const FILE: &str = "rulepack.json";
const MAX_BYTES: usize = 256 * 1024;
const EVERY: Duration = Duration::from_secs(24 * 3600);

/// Local administrator overrides, applied last.
#[must_use]
pub fn overrides(dir: &Path) -> PathBuf {
    dir.join("rules.d")
}

/// The cached pack, if present and it verifies.
fn cached(dir: &Path) -> Option<RemotePack> {
    let bytes = std::fs::read(dir.join(FILE)).ok()?;
    remote::verify(&bytes, None)
        .inspect_err(|e| tracing::warn!(error = %e, "cached rule pack ignored"))
        .ok()
}

/// Verify `bytes`, make them part of the active rules and cache them. Nothing is written or applied
/// unless verification and the rebuild both pass. `Ok(false)` means the pack is the one in use.
pub fn accept(
    dir: &Path,
    store: &RuleStore,
    current: Option<&str>,
    bytes: &[u8],
) -> Result<Option<RemotePack>, RemoteError> {
    let pack = remote::verify(bytes, current)?;
    if current == Some(pack.issued.as_str()) {
        return Ok(None);
    }
    store.reload_with(&overrides(dir), Some(&pack))?;
    if let Err(e) = std::fs::write(dir.join(FILE), bytes) {
        tracing::warn!(error = %e, "could not cache the rule pack");
    }
    Ok(Some(pack))
}

async fn download(client: &reqwest::Client) -> anyhow::Result<Vec<u8>> {
    let resp = client.get(URL).send().await?.error_for_status()?;
    anyhow::ensure!(
        resp.content_length().is_none_or(|n| n <= MAX_BYTES as u64),
        "rule pack too large"
    );
    let bytes = resp.bytes().await?;
    anyhow::ensure!(bytes.len() <= MAX_BYTES, "rule pack too large");
    Ok(bytes.to_vec())
}

fn enabled(shared: &Shared) -> bool {
    shared.settings()["rulepack"]["enabled"].as_bool() == Some(true)
}

fn announce(shared: &Shared, store: &RuleStore) {
    let version = store.active().meta.rule_pack_version.clone();
    tracing::info!(version = %version, "rule pack in use");
    shared.audit(
        "service",
        AuditKind::ConfigChange,
        None,
        &serde_json::json!({ "rule_pack": version }),
    );
    shared.set_rule_pack_version(version);
}

/// Background task: while the setting is on, apply the cached pack and fetch once a day; when it is
/// switched off, go back to embedded defaults plus local overrides.
pub async fn run(shared: Arc<Shared>, store: Arc<RuleStore>, dir: PathBuf) {
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("vigil-rulepack")
        .build()
    else {
        return;
    };
    let mut current: Option<String> = None;
    let mut last: Option<tokio::time::Instant> = None;
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        if !enabled(&shared) {
            if current.take().is_some() {
                match store.reload(&overrides(&dir)) {
                    Ok(_) => announce(&shared, &store),
                    Err(e) => {
                        tracing::warn!(error = %e, "rules not rebuilt after turning the rule pack off");
                    }
                }
            }
            last = None;
            continue;
        }
        if current.is_none()
            && let Some(pack) = cached(&dir)
        {
            match store.reload_with(&overrides(&dir), Some(&pack)) {
                Ok(_) => {
                    current = Some(pack.issued);
                    announce(&shared, &store);
                }
                Err(e) => tracing::warn!(error = %e, "cached rule pack not applied"),
            }
        }
        if last.is_some_and(|t| t.elapsed() < EVERY) {
            continue;
        }
        last = Some(tokio::time::Instant::now());
        match download(&client).await {
            Ok(bytes) => match accept(&dir, &store, current.as_deref(), &bytes) {
                Ok(Some(pack)) => {
                    current = Some(pack.issued);
                    announce(&shared, &store);
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, "downloaded rule pack refused"),
            },
            Err(e) => tracing::warn!(error = %e, "rule pack download failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unverified_bytes_are_never_cached_or_applied() {
        let dir = std::env::temp_dir().join(format!("vigil-rp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = RuleStore::from_embedded().unwrap();
        let before = store.active().meta.rule_pack_version.clone();
        let forged = br#"{"kid":"k1","payload":"{\"v\":1,\"type\":\"rulepack\",\"issued\":\"2026-11-13T00:00:00Z\",\"pack\":\"\"}","sig":"AAAA"}"#;
        assert!(accept(&dir, &store, None, forged).is_err());
        assert!(!dir.join(FILE).exists());
        assert!(cached(&dir).is_none());
        assert_eq!(store.active().meta.rule_pack_version, before);
        std::fs::remove_dir_all(&dir).ok();
    }
}

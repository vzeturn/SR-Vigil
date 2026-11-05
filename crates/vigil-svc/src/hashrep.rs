//! Known-good hash lookups (`docs/20 §5`). One GET per unknown unsigned file to the CIRCL
//! hashlookup service (NIST NSRL and vendor package hashes). Only the SHA-256 is sent: no path,
//! name, user or machine data. Answers are cached in the data directory, so each hash is asked
//! about once. Disabled with the `hash_reputation.enabled` setting.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use vigil_core::analysis::hashrep;

use crate::state::Shared;

const URL: &str = "https://hashlookup.circl.lu/lookup/sha256/";
const FILE: &str = "hashrep.json";
const PER_ROUND: usize = 20;
const MAX_BODY: usize = 64 * 1024;

fn enabled(shared: &Shared) -> bool {
    shared.settings()["hash_reputation"]["enabled"].as_bool() == Some(true)
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Load cached answers into the scoring set; returns the cache (hash to trusted).
fn load(dir: &Path) -> HashMap<String, bool> {
    let cache: HashMap<String, bool> = std::fs::read(dir.join(FILE))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    cache
        .iter()
        .filter(|(h, t)| **t && is_sha256(h))
        .for_each(|(h, _)| hashrep::mark_known(h));
    cache
}

async fn lookup(client: &reqwest::Client, sha: &str) -> anyhow::Result<bool> {
    let resp = client.get(format!("{URL}{sha}")).send().await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(false);
    }
    let resp = resp.error_for_status()?;
    anyhow::ensure!(
        resp.content_length().is_none_or(|n| n <= MAX_BODY as u64),
        "answer too large"
    );
    let body = resp.bytes().await?;
    anyhow::ensure!(body.len() <= MAX_BODY, "answer too large");
    Ok(hashrep::circl_trusts(&String::from_utf8_lossy(&body)))
}

/// Background task: ask about not-yet-seen hashes of unknown unsigned files, a few per minute.
pub async fn run(shared: Arc<Shared>, dir: std::path::PathBuf) {
    let mut cache = load(&dir);
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("vigil-hashrep")
        .build()
    else {
        return;
    };
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        if !enabled(&shared) {
            continue;
        }
        let todo: Vec<String> = shared
            .with_store(|c| vigil_store::repo::unsigned_shas_with_verdict(c, "unknown"))
            .and_then(Result::ok)
            .unwrap_or_default()
            .into_iter()
            .filter(|h| is_sha256(h) && !cache.contains_key(&h.to_ascii_lowercase()))
            .take(PER_ROUND)
            .collect();
        for sha in todo {
            match lookup(&client, &sha).await {
                Ok(trusted) => {
                    if trusted {
                        hashrep::mark_known(&sha);
                    }
                    cache.insert(sha.to_ascii_lowercase(), trusted);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "hash lookup failed; trying again later");
                    break;
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        if let Ok(json) = serde_json::to_vec(&cache)
            && let Err(e) = std::fs::write(dir.join(FILE), json)
        {
            tracing::warn!(error = %e, "could not cache hash answers");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_full_hex_digest_is_ever_sent() {
        assert!(is_sha256(&"a".repeat(64)));
        for bad in ["", "abc", &"g".repeat(64), &"a".repeat(65), "../x"] {
            assert!(!is_sha256(bad), "{bad}");
        }
    }
}

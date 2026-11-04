//! Daily fetch of the signed version catalogue (`docs/16`). Opt-in, GET only, nothing uploaded.
//! The verified snapshot is cached next to the database and re-verified on every start; a bad or
//! missing file simply leaves the embedded data in use.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use vigil_core::analysis::catalogue;

use crate::state::Shared;

/// Snapshot endpoint baked in at build time; local builds default to the project Worker.
pub const URL: &str = match option_env!("VIGIL_CATALOGUE_URL") {
    Some(u) => u,
    None => "https://vigil-catalogue.vutq-sense.workers.dev/v1/catalogue",
};
const FILE: &str = "catalogue.json";
const MAX_BYTES: usize = 256 * 1024;
const EVERY: Duration = Duration::from_secs(24 * 3600);

/// Apply the cached snapshot if it is present and verifies. Returns whether one was applied.
pub fn load_cached(dir: &Path) -> bool {
    let Ok(bytes) = std::fs::read(dir.join(FILE)) else {
        return false;
    };
    match catalogue::verify(&bytes).and_then(catalogue::apply) {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(error = %e, "cached catalogue ignored");
            false
        }
    }
}

/// Verify `bytes`, apply them and cache them. Nothing is written unless verification and apply pass.
pub fn accept(dir: &Path, bytes: &[u8]) -> Result<(), catalogue::Error> {
    catalogue::apply(catalogue::verify(bytes)?)?;
    if let Err(e) = std::fs::write(dir.join(FILE), bytes) {
        tracing::warn!(error = %e, "could not cache the catalogue");
    }
    Ok(())
}

async fn download(client: &reqwest::Client) -> anyhow::Result<Vec<u8>> {
    let resp = client.get(URL).send().await?.error_for_status()?;
    anyhow::ensure!(
        resp.content_length().is_none_or(|n| n <= MAX_BYTES as u64),
        "snapshot too large"
    );
    let bytes = resp.bytes().await?;
    anyhow::ensure!(bytes.len() <= MAX_BYTES, "snapshot too large");
    Ok(bytes.to_vec())
}

fn enabled(shared: &Shared) -> bool {
    shared.settings()["catalogue"]["enabled"].as_bool() == Some(true)
}

/// Background task: load the cache at start, then fetch once a day while the setting is on.
pub async fn run(shared: Arc<Shared>, dir: std::path::PathBuf) {
    if load_cached(&dir) {
        tracing::info!(issued = ?catalogue::issued(), "version catalogue loaded from cache");
    }
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("vigil-catalogue")
        .build()
    else {
        return;
    };
    let mut last: Option<tokio::time::Instant> = None;
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        if !enabled(&shared) || last.is_some_and(|t| t.elapsed() < EVERY) {
            continue;
        }
        last = Some(tokio::time::Instant::now());
        match download(&client).await {
            Ok(bytes) => match accept(&dir, &bytes) {
                Ok(()) => {
                    tracing::info!(issued = ?catalogue::issued(), "version catalogue updated");
                }
                Err(e) => tracing::warn!(error = %e, "downloaded catalogue refused"),
            },
            Err(e) => tracing::warn!(error = %e, "catalogue download failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unverified_bytes_are_never_cached() {
        let dir = std::env::temp_dir().join(format!("vigil-cat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(
            accept(
                &dir,
                b"{\"kid\":\"k1\",\"payload\":\"{}\",\"sig\":\"AAAA\"}"
            )
            .is_err()
        );
        assert!(!dir.join(FILE).exists());
        assert!(!load_cached(&dir));
        std::fs::remove_dir_all(&dir).ok();
    }
}

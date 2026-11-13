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

/// The body of a successful answer, refused when larger than `max` bytes; `None` for a 404.
async fn read_capped(resp: reqwest::Response, max: usize) -> anyhow::Result<Option<String>> {
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let resp = resp.error_for_status()?;
    anyhow::ensure!(
        resp.content_length().is_none_or(|n| n <= max as u64),
        "answer too large"
    );
    let body = resp.bytes().await?;
    anyhow::ensure!(body.len() <= max, "answer too large");
    Ok(Some(String::from_utf8_lossy(&body).into_owned()))
}

async fn lookup(client: &reqwest::Client, sha: &str) -> anyhow::Result<bool> {
    let resp = client.get(format!("{URL}{sha}")).send().await?;
    Ok(read_capped(resp, MAX_BODY)
        .await?
        .is_some_and(|b| hashrep::circl_trusts(&b)))
}

/// Ask a keyed service again after this long, so new detections reach old files.
const REASK_SECS: i64 = 7 * 86_400;
/// Longest accepted `VirusTotal` file report.
const VT_MAX_BODY: usize = 2 * 1024 * 1024;

/// An optional service that needs the user's own key (`docs/20 §5`). Only a SHA-256 is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keyed {
    VirusTotal,
    MalwareBazaar,
}

/// A keyed service's cached answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Answer {
    /// Unix seconds when it was asked.
    at: i64,
    #[serde(default)]
    vt: Option<hashrep::VtReport>,
    #[serde(default)]
    listed: bool,
}

impl Answer {
    fn is_hit(&self) -> bool {
        self.listed || self.vt.is_some()
    }
    fn apply(&self, sha: &str) {
        if let Some(r) = self.vt {
            hashrep::record_vt(sha, r);
        }
        if self.listed {
            hashrep::mark_malware(sha);
        }
    }
}

fn unix_now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

impl Keyed {
    pub const ALL: [Self; 2] = [Self::VirusTotal, Self::MalwareBazaar];

    /// Settings section and IPC name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::VirusTotal => "virustotal",
            Self::MalwareBazaar => "malwarebazaar",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == s)
    }

    fn secret(self) -> &'static str {
        match self {
            Self::VirusTotal => "rep.virustotal.key",
            Self::MalwareBazaar => "rep.malwarebazaar.key",
        }
    }

    fn file(self) -> &'static str {
        match self {
            Self::VirusTotal => "hashrep-virustotal.json",
            Self::MalwareBazaar => "hashrep-malwarebazaar.json",
        }
    }

    /// Pause between two questions: the free `VirusTotal` key allows 4 a minute.
    fn gap(self) -> Duration {
        match self {
            Self::VirusTotal => Duration::from_secs(16),
            Self::MalwareBazaar => Duration::from_secs(1),
        }
    }

    fn per_round(self) -> usize {
        match self {
            Self::VirusTotal => 3,
            Self::MalwareBazaar => 20,
        }
    }

    fn setting_enabled(self, shared: &Shared) -> bool {
        shared.settings()[self.name()]["enabled"].as_bool() == Some(true)
    }

    /// Questions still allowed today (`virustotal.daily_lookup_budget`; no cap for the other).
    fn budget_left(self, shared: &Shared, answers: &HashMap<String, Answer>, now: i64) -> usize {
        if self != Self::VirusTotal {
            return usize::MAX;
        }
        let budget = shared.settings()["virustotal"]["daily_lookup_budget"]
            .as_u64()
            .unwrap_or(0);
        let today = answers
            .values()
            .filter(|a| a.at.div_euclid(86_400) == now.div_euclid(86_400))
            .count() as u64;
        usize::try_from(budget.saturating_sub(today)).unwrap_or(usize::MAX)
    }

    fn load(self, dir: &Path) -> HashMap<String, Answer> {
        let cache: HashMap<String, Answer> = std::fs::read(dir.join(self.file()))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        cache
            .iter()
            .filter(|(h, _)| is_sha256(h))
            .for_each(|(h, a)| a.apply(h));
        cache
    }

    async fn ask(
        self,
        client: &reqwest::Client,
        key: &secrecy::SecretString,
        sha: &str,
    ) -> anyhow::Result<Answer> {
        use secrecy::ExposeSecret;
        anyhow::ensure!(is_sha256(sha), "not a SHA-256");
        let mut auth = reqwest::header::HeaderValue::from_str(key.expose_secret())?;
        auth.set_sensitive(true);
        let at = unix_now();
        Ok(match self {
            Self::VirusTotal => {
                let resp = client
                    .get(format!("https://www.virustotal.com/api/v3/files/{sha}"))
                    .header("x-apikey", auth)
                    .send()
                    .await?;
                let vt = match read_capped(resp, VT_MAX_BODY).await? {
                    Some(b) => Some(
                        hashrep::vt_parse(&b)
                            .ok_or_else(|| anyhow::anyhow!("unreadable answer"))?,
                    ),
                    None => None,
                };
                Answer {
                    at,
                    vt,
                    listed: false,
                }
            }
            Self::MalwareBazaar => {
                let resp = client
                    .post("https://mb-api.abuse.ch/api/v1/")
                    .header("Auth-Key", auth)
                    .header(
                        reqwest::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(format!("query=get_info&hash={sha}"))
                    .send()
                    .await?;
                let listed = read_capped(resp, MAX_BODY)
                    .await?
                    .is_some_and(|b| hashrep::bazaar_lists(&b));
                Answer {
                    at,
                    vt: None,
                    listed,
                }
            }
        })
    }

    /// One round: ask about hashes never asked (or asked over a week ago), within the budget;
    /// a hit queues every path of that file for re-scoring. Any failure ends the round.
    async fn round(
        self,
        shared: &Shared,
        client: &reqwest::Client,
        answers: &mut HashMap<String, Answer>,
        dir: &Path,
    ) {
        if !self.setting_enabled(shared) {
            return;
        }
        let Some(key) = shared.open_named_secret(self.secret()) else {
            return;
        };
        let now = unix_now();
        let todo: Vec<String> = candidates(shared)
            .into_iter()
            .filter(|h| answers.get(h).is_none_or(|a| now - a.at >= REASK_SECS))
            .take(self.per_round().min(self.budget_left(shared, answers, now)))
            .collect();
        if todo.is_empty() {
            return;
        }
        for sha in todo {
            match self.ask(client, &key, &sha).await {
                Ok(a) => {
                    a.apply(&sha);
                    if a.is_hit() {
                        for p in shared
                            .with_store(|c| vigil_store::repo::paths_with_sha(c, &sha))
                            .and_then(Result::ok)
                            .unwrap_or_default()
                        {
                            shared.queue_rejudge(&p);
                        }
                    }
                    answers.insert(sha, a);
                }
                Err(e) => {
                    tracing::warn!(service = self.name(), error = %e, "hash lookup failed; trying again later");
                    break;
                }
            }
            tokio::time::sleep(self.gap()).await;
        }
        if let Ok(json) = serde_json::to_vec(&*answers)
            && let Err(e) = std::fs::write(dir.join(self.file()), json)
        {
            tracing::warn!(service = self.name(), error = %e, "could not cache hash answers");
        }
    }
}

/// A key as the services issue them: printable ASCII, no spaces, at most 200 characters.
fn valid_key(k: &str) -> bool {
    !k.is_empty() && k.len() <= 200 && k.bytes().all(|b| b.is_ascii_graphic())
}

impl Shared {
    /// `reputation.config.get`: whether each keyed service is on and has a key. Never the key.
    #[must_use]
    pub fn reputation_config_get(&self) -> serde_json::Value {
        let mut out = serde_json::Map::new();
        for k in Keyed::ALL {
            out.insert(
                k.name().into(),
                serde_json::json!({
                    "enabled": k.setting_enabled(self),
                    "has_key": self.has_named_secret(k.secret()),
                }),
            );
        }
        serde_json::Value::Object(out)
    }

    /// `reputation.config.set`: store or remove a service's key (write-only) and turn it on or
    /// off. An empty key removes it and turns the service off; turning on needs a key.
    pub fn reputation_config_set(
        &self,
        params: &serde_json::Value,
        actor: &str,
    ) -> Result<serde_json::Value, vigil_ipc::proto::RpcError> {
        use vigil_ipc::proto::{INVALID_PARAMS, INVALID_STATE, RpcError};
        let bad = |m: &str| RpcError::new(INVALID_PARAMS, m);
        let obj = params
            .as_object()
            .ok_or_else(|| bad("params must be an object"))?;
        if let Some(extra) = obj
            .keys()
            .find(|k| !["service", "enabled", "api_key"].contains(&k.as_str()))
        {
            return Err(bad(&format!("unknown field {extra}")));
        }
        let k = obj
            .get("service")
            .and_then(serde_json::Value::as_str)
            .and_then(Keyed::parse)
            .ok_or_else(|| bad("service must be virustotal or malwarebazaar"))?;
        let enabled = obj
            .get("enabled")
            .map(|v| v.as_bool().ok_or_else(|| bad("enabled must be a boolean")))
            .transpose()?;
        let key = obj
            .get("api_key")
            .map(|v| v.as_str().ok_or_else(|| bad("api_key must be a string")))
            .transpose()?;
        if key.is_some_and(|s| !s.is_empty() && !valid_key(s)) {
            return Err(bad("api_key is not a valid key"));
        }
        let will_have_key =
            key.map_or_else(|| self.has_named_secret(k.secret()), |s| !s.is_empty());
        if enabled == Some(true) && !will_have_key {
            return Err(RpcError::new(INVALID_STATE, "an API key is needed first"));
        }
        let mut changed: Vec<&str> = Vec::new();
        let mut turn_on = enabled;
        match key {
            Some("") => {
                self.delete_named_secret(k.secret());
                changed.push("api_key_removed");
                turn_on = Some(false);
            }
            Some(key) => {
                self.seal_named_secret(k.secret(), key)?;
                changed.push("api_key");
            }
            None => {}
        }
        if let Some(on) = turn_on
            && on != k.setting_enabled(self)
        {
            self.update_settings(&serde_json::json!({ k.name(): { "enabled": on } }))?;
            changed.push("enabled");
        }
        if !changed.is_empty() {
            self.audit(
                actor,
                vigil_core::audit::AuditKind::ConfigChange,
                None,
                &serde_json::json!({ "reputation": k.name(), "changed": changed }),
            );
        }
        Ok(self.reputation_config_get())
    }
}

/// Hashes of unknown unsigned files, lowercased, full digests only.
fn candidates(shared: &Shared) -> Vec<String> {
    shared
        .with_store(|c| vigil_store::repo::unsigned_shas_with_verdict(c, "unknown"))
        .and_then(Result::ok)
        .unwrap_or_default()
        .into_iter()
        .filter(|h| is_sha256(h))
        .map(|h| h.to_ascii_lowercase())
        .collect()
}

/// Background task: ask about not-yet-seen hashes of unknown unsigned files, a few per minute.
pub async fn run(shared: Arc<Shared>, dir: std::path::PathBuf) {
    let mut cache = load(&dir);
    let mut keyed: Vec<(Keyed, HashMap<String, Answer>)> =
        Keyed::ALL.into_iter().map(|k| (k, k.load(&dir))).collect();
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
        for (k, answers) in &mut keyed {
            k.round(&shared, &client, answers, &dir).await;
        }
        if !enabled(&shared) {
            continue;
        }
        let todo: Vec<String> = candidates(&shared)
            .into_iter()
            .filter(|h| !cache.contains_key(h))
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

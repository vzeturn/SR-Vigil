//! AI advisor integration (docs/06): settings, redacted payloads, caching, advice and Auto mode.
//!
//! The network client lives in `vigil-ai`; this module owns policy. The key is sealed by an
//! [`AiBackend`] (DPAPI on Windows), stored only as ciphertext and never returned over IPC.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use vigil_ai::{Advisor, AiError, Opinion};
use vigil_core::audit::AuditKind;
use vigil_core::auto::{self, Outcome};
use vigil_core::redact;
use vigil_ipc::proto::{AI_UNAVAILABLE, INVALID_PARAMS, INVALID_STATE, NOT_FOUND, RpcError};
use vigil_store::ai as store;
use vigil_store::decisions::{self, ApplyTo, DecidedBy, NewDecision, Scope};
use zeroize::Zeroizing;

use crate::state::{ProcRow, Shared, now};

const KEY: &str = "ai.key";
const TOKEN: &str = "ai.token";
const ENTROPY: &str = "ai.entropy";
const CONFIG: &str = "ai.config";
const TTL_DECIDED: Duration = Duration::days(7);
const TTL_UNKNOWN: Duration = Duration::hours(24);
/// A decided verdict is remembered offline for this long and reused on an identical match.
const TTL_MEMORY: Duration = Duration::days(365);
fn cache_ttl(verdict: &str, sure: bool) -> Duration {
    match (verdict, sure) {
        ("unknown", _) => TTL_UNKNOWN,
        (_, true) => TTL_DECIDED,
        _ => TTL_WEAK,
    }
}

/// A verdict below the auto threshold is re-asked (with the deeper model) after this long.
const TTL_WEAK: Duration = Duration::minutes(30);
const FLIP_WINDOW: Duration = Duration::days(7);

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Everything the service needs from the outside world for AI: key sealing and the model call.
pub trait AiBackend: Send + Sync {
    /// Seal `plain` for storage (DPAPI machine scope + `entropy` on Windows).
    fn seal(&self, plain: &[u8], entropy: &[u8]) -> Result<Vec<u8>, String>;
    fn unseal(&self, cipher: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>, String>;
    fn assess<'a>(
        &'a self,
        cfg: &'a AiSettings,
        key: &'a SecretString,
        payload: &'a Value,
        present: &'a [String],
    ) -> BoxFut<'a, Result<(Opinion, String), AiError>>;
    fn calls_today(&self) -> u32;
    /// Tokens `(input, output)` used since the previous call to this method.
    fn token_delta(&self) -> (u64, u64) {
        (0, 0)
    }
    /// Assess through the shared endpoint with an install token (no API key on this machine).
    fn assess_shared<'a>(
        &'a self,
        _cfg: &'a AiSettings,
        _token: &'a SecretString,
        _payload: &'a Value,
        _present: &'a [String],
    ) -> BoxFut<'a, Result<(Opinion, String), AiError>> {
        Box::pin(async { Err(AiError::NoKey) })
    }
    /// Obtain this installation's token from the shared endpoint.
    fn register_shared(&self) -> BoxFut<'_, Result<SecretString, AiError>> {
        Box::pin(async { Err(AiError::NoKey) })
    }
}

/// Shared endpoint baked in at release build time (`VIGIL_PROXY_URL`); `None` for local builds.
pub const SHARED_URL: Option<&str> = option_env!("VIGIL_PROXY_URL");

/// Key sealing primitive supplied by the platform.
pub trait KeyVault: Send + Sync {
    fn seal(&self, plain: &[u8], entropy: &[u8]) -> Result<Vec<u8>, String>;
    fn unseal(&self, cipher: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>, String>;
}

type Built = ((String, Option<String>, u64, u32), Arc<Advisor>);

/// The real backend: `vigil-ai` over HTTPS, keys sealed by `vault`.
pub struct LiveBackend {
    vault: Arc<dyn KeyVault>,
    advisor: Mutex<Option<Built>>,
    /// Token totals already reported through `token_delta` (the client resets when settings change).
    seen: Mutex<(u64, u64)>,
}

impl LiveBackend {
    #[must_use]
    pub fn new(vault: Arc<dyn KeyVault>) -> Self {
        Self {
            vault,
            advisor: Mutex::new(None),
            seen: Mutex::new((0, 0)),
        }
    }

    fn advisor(&self, s: &AiSettings) -> Result<Arc<Advisor>, AiError> {
        let id = (
            s.model.clone(),
            Some(s.escalation_model.clone()),
            s.escalate_below.to_bits(),
            s.daily_call_budget,
        );
        let mut g = self.advisor.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((k, a)) = g.as_ref() {
            if *k == id {
                return Ok(Arc::clone(a));
            }
        }
        let a = Arc::new(Advisor::new(vigil_ai::Config {
            model: s.model.clone(),
            escalation_model: (!s.escalation_model.is_empty()).then(|| s.escalation_model.clone()),
            escalate_below: s.escalate_below,
            daily_budget: s.daily_call_budget,
            proxy_url: SHARED_URL.map(str::to_string),
            ..vigil_ai::Config::default()
        })?);
        *g = Some((id, Arc::clone(&a)));
        Ok(a)
    }
}

impl AiBackend for LiveBackend {
    fn seal(&self, plain: &[u8], entropy: &[u8]) -> Result<Vec<u8>, String> {
        self.vault.seal(plain, entropy)
    }
    fn unseal(&self, cipher: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        self.vault.unseal(cipher, entropy)
    }
    fn assess<'a>(
        &'a self,
        cfg: &'a AiSettings,
        key: &'a SecretString,
        payload: &'a Value,
        present: &'a [String],
    ) -> BoxFut<'a, Result<(Opinion, String), AiError>> {
        Box::pin(async move { self.advisor(cfg)?.assess(key, payload, present).await })
    }
    fn calls_today(&self) -> u32 {
        self.advisor
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map_or(0, |(_, a)| a.calls_today())
    }
    fn token_delta(&self) -> (u64, u64) {
        let now = self
            .advisor
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map_or((0, 0), |(_, a)| a.tokens());
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        let d = (
            now.0
                .saturating_sub(if now.0 < seen.0 { 0 } else { seen.0 }),
            now.1
                .saturating_sub(if now.1 < seen.1 { 0 } else { seen.1 }),
        );
        *seen = now;
        d
    }
    fn assess_shared<'a>(
        &'a self,
        cfg: &'a AiSettings,
        token: &'a SecretString,
        payload: &'a Value,
        present: &'a [String],
    ) -> BoxFut<'a, Result<(Opinion, String), AiError>> {
        Box::pin(async move {
            self.advisor(cfg)?
                .assess_shared(token, payload, present)
                .await
        })
    }
    fn register_shared(&self) -> BoxFut<'_, Result<SecretString, AiError>> {
        Box::pin(async move {
            self.advisor(&AiSettings::default())?
                .register_shared()
                .await
        })
    }
}

/// Persisted AI settings (the key is stored separately, sealed).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
#[allow(clippy::struct_excessive_bools)] // mirrors the wire config, one flag per setting
pub struct AiSettings {
    pub enabled: bool,
    pub mode: String,
    pub model: String,
    pub escalation_model: String,
    pub auto_threshold: f64,
    pub escalate_below: f64,
    pub auto_kill: bool,
    pub send_cmdline: bool,
    pub daily_call_budget: u32,
    pub acknowledged: bool,
    /// `own_key` (the user's Anthropic key) or `shared` (the project's endpoint, no key needed).
    pub source: String,
}

impl Default for AiSettings {
    fn default() -> Self {
        Self {
            // Builds that carry the project endpoint ship with the AI on (opt-out in Settings).
            enabled: SHARED_URL.is_some(),
            mode: "auto".into(),
            model: "claude-haiku-5-5".into(),
            escalation_model: "claude-sonnet-5-5".into(),
            auto_threshold: 0.90,
            escalate_below: 0.90,
            auto_kill: false,
            send_cmdline: false,
            daily_call_budget: 500,
            acknowledged: SHARED_URL.is_some(),
            source: if SHARED_URL.is_some() {
                "shared"
            } else {
                "own_key"
            }
            .into(),
        }
    }
}

impl AiSettings {
    fn active(&self) -> bool {
        self.enabled && self.mode != "off"
    }

    fn shared(&self) -> bool {
        self.source == "shared"
    }
}

/// Why an assessment produced no opinion; the item then simply stays Pending.
#[derive(Debug)]
pub enum AiFail {
    Disabled,
    NoKey,
    NoData,
    Ai(AiError),
}

impl AiFail {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Disabled => "ai_disabled",
            Self::NoKey => "ai_no_key",
            Self::NoData => "no_data",
            Self::Ai(e) => e.code(),
        }
    }

    /// One-word cause shown to the user (`rate_limited`, `network`, ...).
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Ai(e) => e.reason(),
            Self::Disabled => "off",
            Self::NoKey => "no_key",
            Self::NoData => "no_data",
        }
    }
}

/// An opinion together with how it was obtained.
#[derive(Debug, Clone)]
pub struct Assessed {
    pub opinion: store::StoredOpinion,
    pub cached: bool,
}

struct Payload {
    value: Value,
    present: Vec<String>,
    hash: String,
    score: i32,
    hard_rule: bool,
    cache_key: String,
    /// Exact-match key (file identity, rule pack, signals) for the long-lived offline memory.
    memory_key: String,
}

fn bad(m: &str) -> RpcError {
    RpcError::new(INVALID_PARAMS, m)
}

fn user_from_path(path: &str) -> String {
    let low = path.to_lowercase();
    low.find(r"\users\")
        .map(|i| i + 7)
        .and_then(|i| path.get(i..))
        .and_then(|r| r.split(['\\', '/']).next())
        .unwrap_or_default()
        .to_string()
}

fn opinion_json(o: &store::StoredOpinion, cached: bool) -> Value {
    let list = |s: &str| serde_json::from_str::<Value>(s).unwrap_or_else(|_| json!([]));
    json!({
        "verdict": o.verdict, "confidence": o.confidence,
        "recommended_action": o.recommended_action,
        "reasons": list(&o.reasons_json), "indicators": list(&o.indicators_json),
        "model": o.model, "created_at": o.created_at, "cached": cached,
    })
}

impl Shared {
    pub fn attach_ai(&self, b: Arc<dyn AiBackend>) {
        *self.ai.lock().unwrap_or_else(PoisonError::into_inner) = Some(b);
    }

    fn ai_backend(&self) -> Option<Arc<dyn AiBackend>> {
        self.ai
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    #[must_use]
    pub fn ai_settings(&self) -> AiSettings {
        let mut s: AiSettings = self
            .with_store(|c| store::setting_get(c, CONFIG))
            .and_then(Result::ok)
            .flatten()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        // No personal key stored and the build has the project endpoint: use it.
        if SHARED_URL.is_some() && !s.shared() && !self.ai_has_key() {
            s.source = "shared".into();
        }
        s
    }

    fn ai_has_key(&self) -> bool {
        self.with_store(|c| store::setting_get(c, KEY))
            .and_then(Result::ok)
            .flatten()
            .is_some()
    }

    /// Whether the configured source can be used right now.
    fn ai_ready(&self, s: &AiSettings) -> bool {
        if s.shared() {
            SHARED_URL.is_some()
        } else {
            self.ai_has_key()
        }
    }

    pub(crate) fn ai_status(&self) -> Value {
        let s = self.ai_settings();
        json!({ "enabled": s.active(), "mode": if s.active() { s.mode.as_str() } else { "off" } })
    }

    /// The latest stored opinion for an identity, in wire form, or `null`.
    pub(crate) fn ai_opinion_json(&self, exe_id: i64) -> Value {
        self.with_store(|c| store::latest_opinion(c, exe_id))
            .and_then(Result::ok)
            .flatten()
            .map_or(Value::Null, |o| opinion_json(&o, false))
    }

    /// `ai.config.get`
    pub fn ai_config_get(&self) -> Value {
        let s = self.ai_settings();
        json!({
            "enabled": s.enabled, "mode": s.mode, "model": s.model,
            "escalation_model": s.escalation_model, "has_key": self.ai_has_key(),
            "auto_threshold": s.auto_threshold, "escalate_below": s.escalate_below,
            "auto_kill": s.auto_kill, "send_cmdline": s.send_cmdline,
            "daily_call_budget": s.daily_call_budget,
            "source": s.source, "shared_available": SHARED_URL.is_some(),
            "calls_today": self.ai_backend().map_or(0, |b| b.calls_today()),
        })
    }

    /// `ai.config.set`: partial update; the key is write-only and only its presence is audited.
    #[allow(clippy::too_many_lines)] // flat field-by-field validation reads best in one place
    pub fn ai_config_set(&self, params: &Value, actor: &str) -> Result<Value, RpcError> {
        let Some(obj) = params.as_object() else {
            return Err(bad("params must be an object"));
        };
        let mut s = self.ai_settings();
        let before = s.clone();
        let mut changed: Vec<&str> = Vec::new();
        let flag = |k: &str| -> Result<Option<bool>, RpcError> {
            obj.get(k)
                .map(|v| {
                    v.as_bool()
                        .ok_or_else(|| bad(&format!("{k} must be a boolean")))
                })
                .transpose()
        };
        let unit = |k: &str| -> Result<Option<f64>, RpcError> {
            obj.get(k)
                .map(|v| {
                    v.as_f64()
                        .filter(|x| (0.0..=1.0).contains(x))
                        .ok_or_else(|| bad(&format!("{k} must be between 0 and 1")))
                })
                .transpose()
        };
        let model = |k: &str| -> Result<Option<String>, RpcError> {
            obj.get(k)
                .map(|v| {
                    v.as_str()
                        .filter(|m| {
                            m.len() <= 100
                                && m.chars()
                                    .all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c))
                        })
                        .map(str::to_string)
                        .ok_or_else(|| bad(&format!("{k} is not a valid model id")))
                })
                .transpose()
        };
        if let Some(v) = flag("enabled")? {
            s.enabled = v;
        }
        if let Some(v) = flag("auto_kill")? {
            s.auto_kill = v;
        }
        if let Some(v) = flag("send_cmdline")? {
            s.send_cmdline = v;
        }
        if let Some(v) = unit("auto_threshold")? {
            s.auto_threshold = v;
        }
        if let Some(v) = unit("escalate_below")? {
            s.escalate_below = v;
        }
        if let Some(v) = model("model")? {
            s.model = v;
        }
        if let Some(v) = model("escalation_model")? {
            s.escalation_model = v;
        }
        if let Some(v) = obj.get("mode") {
            let m = v
                .as_str()
                .filter(|m| ["off", "advisor", "auto"].contains(m))
                .ok_or_else(|| bad("mode must be off, advisor or auto"))?;
            s.mode = m.to_string();
        }
        if let Some(v) = obj.get("source") {
            let src = v
                .as_str()
                .filter(|m| ["own_key", "shared"].contains(m))
                .ok_or_else(|| bad("source must be own_key or shared"))?;
            if src == "shared" && SHARED_URL.is_none() {
                return Err(RpcError::new(
                    INVALID_STATE,
                    "this build has no shared AI endpoint",
                ));
            }
            s.source = src.to_string();
        }
        if let Some(v) = obj.get("daily_call_budget") {
            s.daily_call_budget = v
                .as_u64()
                .filter(|n| (1..=100_000).contains(n))
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| bad("daily_call_budget must be 1..100000"))?;
        }
        if flag("acknowledge_data_categories")? == Some(true) {
            s.acknowledged = true;
        }
        let key_change = match obj.get("api_key") {
            None => None,
            Some(Value::String(k)) => Some(k.trim().to_string()),
            Some(_) => return Err(bad("api_key must be a string")),
        };
        for (name, differs) in [
            ("enabled", s.enabled != before.enabled),
            ("mode", s.mode != before.mode),
            ("model", s.model != before.model),
            (
                "escalation_model",
                s.escalation_model != before.escalation_model,
            ),
            (
                "auto_threshold",
                s.auto_threshold.to_bits() != before.auto_threshold.to_bits(),
            ),
            (
                "escalate_below",
                s.escalate_below.to_bits() != before.escalate_below.to_bits(),
            ),
            ("auto_kill", s.auto_kill != before.auto_kill),
            ("send_cmdline", s.send_cmdline != before.send_cmdline),
            (
                "daily_call_budget",
                s.daily_call_budget != before.daily_call_budget,
            ),
            ("acknowledged", s.acknowledged != before.acknowledged),
            ("source", s.source != before.source),
        ] {
            if differs {
                changed.push(name);
            }
        }
        match &key_change {
            Some(k) if !k.is_empty() => {
                let b = self.ai_backend().ok_or_else(|| {
                    RpcError::new(INVALID_STATE, "AI is not available in this build")
                })?;
                self.store_key(&*b, k)?;
                changed.push("api_key");
            }
            Some(_) => {
                self.with_store(|c| store::setting_delete(c, KEY));
                changed.push("api_key_removed");
            }
            None => {}
        }
        if s.enabled && !self.ai_ready(&s) {
            return Err(RpcError::new(
                INVALID_STATE,
                "an API key is required to enable AI",
            ));
        }
        if s.enabled && !s.acknowledged {
            return Err(RpcError::new(
                INVALID_STATE,
                "the data categories sent to the API must be acknowledged first",
            ));
        }
        let bytes = serde_json::to_vec(&s)
            .map_err(|_| RpcError::new(vigil_ipc::proto::INTERNAL_ERROR, "storage error"))?;
        self.with_store(|c| store::setting_put(c, CONFIG, &bytes));
        if !changed.is_empty() {
            self.audit(
                actor,
                AuditKind::AiConfig,
                None,
                &json!({ "changed": changed }),
            );
        }
        Ok(self.ai_config_get())
    }

    fn store_key(&self, b: &dyn AiBackend, key: &str) -> Result<(), RpcError> {
        self.store_secret(b, KEY, key)
    }

    fn store_secret(&self, b: &dyn AiBackend, name: &str, key: &str) -> Result<(), RpcError> {
        let fail = |e: String| {
            tracing::error!(error = %e, "could not seal the AI key");
            RpcError::new(vigil_ipc::proto::INTERNAL_ERROR, "could not store the key")
        };
        let existing = self
            .with_store(|c| store::setting_get(c, ENTROPY))
            .and_then(Result::ok)
            .flatten();
        let entropy = existing.unwrap_or_else(|| {
            let e = uuid::Uuid::new_v4().as_bytes().to_vec();
            self.with_store(|c| store::setting_put(c, ENTROPY, &e));
            e
        });
        let sealed = b.seal(key.as_bytes(), &entropy).map_err(fail)?;
        self.with_store(|c| store::setting_put(c, name, &sealed));
        Ok(())
    }

    /// The credential for the configured source: the user's key, or this install's token
    /// (registered lazily on first use and sealed like a key).
    async fn credential(&self, b: &dyn AiBackend, s: &AiSettings) -> Result<SecretString, AiFail> {
        if !s.shared() {
            return self.unseal_secret(b, KEY);
        }
        if let Ok(t) = self.unseal_secret(b, TOKEN) {
            return Ok(t);
        }
        let token = b.register_shared().await.map_err(AiFail::Ai)?;
        {
            use secrecy::ExposeSecret;
            self.store_secret(b, TOKEN, token.expose_secret())
                .map_err(|_| AiFail::NoKey)?;
        }
        Ok(token)
    }

    fn unseal_secret(&self, b: &dyn AiBackend, name: &str) -> Result<SecretString, AiFail> {
        let (cipher, entropy) = self
            .with_store(|c| {
                Ok::<_, vigil_store::StoreError>((
                    store::setting_get(c, name)?,
                    store::setting_get(c, ENTROPY)?,
                ))
            })
            .and_then(Result::ok)
            .ok_or(AiFail::NoKey)?;
        let (Some(cipher), Some(entropy)) = (cipher, entropy) else {
            return Err(AiFail::NoKey);
        };
        let plain = b.unseal(&cipher, &entropy).map_err(|_| AiFail::NoKey)?;
        let text = String::from_utf8(plain.to_vec()).map_err(|_| AiFail::NoKey)?;
        Ok(SecretString::from(text))
    }

    /// Kinds of autostart entries that launch `path`.
    fn autostart_kinds(&self, path: &str) -> Vec<String> {
        self.with_store(|c| -> Result<Vec<String>, rusqlite::Error> {
            c.prepare(
                "SELECT kind FROM persistence_items WHERE lower(image_path) = lower(?1) LIMIT 5",
            )?
            .query_map([path], |r| r.get(0))?
            .collect()
        })
        .and_then(Result::ok)
        .unwrap_or_default()
    }

    fn first_seen_of(&self, exe_id: i64) -> Option<String> {
        self.with_store(|c| {
            c.query_row(
                "SELECT first_seen FROM executables WHERE id = ?1",
                [exe_id],
                |r| r.get::<_, String>(0),
            )
        })
        .and_then(Result::ok)
    }

    /// Redacted payload for an identity; also what `ai.preview` shows.
    fn ai_payload(&self, exe_id: i64, s: &AiSettings) -> Result<Payload, AiFail> {
        let (exe, ev, pending) = self
            .with_store(|c| {
                let exe = vigil_store::repo::executable_by_id(c, exe_id)?;
                let ev = vigil_store::repo::latest_evaluation(c, exe_id)?;
                let p = decisions::list_pending(c)?
                    .into_iter()
                    .find(|p| p.executable_id == exe_id);
                Ok::<_, vigil_store::StoreError>((exe, ev, p))
            })
            .and_then(Result::ok)
            .ok_or(AiFail::NoData)?;
        let (Some(exe), Some(ev)) = (exe, ev) else {
            return Err(AiFail::NoData);
        };
        let sigs: Vec<Value> = serde_json::from_str(&ev.signals_json).unwrap_or_default();
        let signals: Vec<(String, i32)> = sigs
            .iter()
            .filter_map(|v| {
                Some((
                    v.get("id")?.as_str()?.to_string(),
                    i32::try_from(v.get("delta")?.as_i64()?).ok()?,
                ))
            })
            .collect();
        let present: Vec<String> = signals.iter().map(|(i, _)| i.clone()).collect();
        let input = redact::Input {
            image_path: exe.path.clone(),
            sha256: exe.sha256.clone(),
            signature: redact::Signature {
                status: exe.signature_status.clone(),
                org: exe.publisher.clone(),
                ..redact::Signature::default()
            },
            company: exe.company.clone().unwrap_or_default(),
            product: exe.product.clone().unwrap_or_default(),
            original_filename: exe.original_filename.clone().unwrap_or_default(),
            parents: self
                .parent_paths_of(exe_id)
                .into_iter()
                .map(|image| redact::Parent {
                    verdict: self.verdict_of_image(&image),
                    image,
                    signer_org: None,
                })
                .collect(),
            dest: pending.as_ref().map(|p| redact::Dest {
                ip: Some(p.dest_addr.clone()),
                dns: p.dns_name.clone(),
                port: p.dest_port,
            }),
            score: i32::from(ev.score),
            signals,
            hard_rules: ev.hard_rule.iter().cloned().collect(),
            connection_count: self.live_context(&exe.path).1,
            children: self.live_children(&exe.path),
            persistence: self.autostart_kinds(&exe.path),
            first_seen: self.first_seen_of(exe_id),
            known: vigil_core::analysis::known::lookup(
                exe.path.rsplit(['\\', '/']).next().unwrap_or_default(),
                &[
                    exe.company.as_deref().unwrap_or_default(),
                    exe.product.as_deref().unwrap_or_default(),
                ],
            )
            .map(|k| (k.label.clone(), k.what.clone())),
            username: user_from_path(&exe.path),
            hostnames: ["COMPUTERNAME", "USERDOMAIN"]
                .iter()
                .filter_map(|k| std::env::var(k).ok())
                .collect(),
            ..redact::Input::default()
        };
        let value = redact::build(&input, s.send_cmdline);
        let dest_class = pending.as_ref().map_or("none", |p| p.dest_class.as_str());
        let identity = format!(
            "{}|{}",
            exe.sha256,
            exe.signer_thumbprint.as_deref().unwrap_or("")
        );
        let cache_key = redact::sha256_hex(
            format!(
                "{identity}|{}|{dest_class}|{}",
                ev.rule_pack_version, s.model
            )
            .as_bytes(),
        );
        let mut ids = present.clone();
        ids.sort();
        let memory_key = redact::sha256_hex(
            format!("mem|{identity}|{}|{}", ev.rule_pack_version, ids.join(",")).as_bytes(),
        );
        Ok(Payload {
            memory_key,
            hash: redact::payload_sha256(&value),
            value,
            present,
            score: i32::from(ev.score),
            hard_rule: ev.hard_rule.is_some(),
            cache_key,
        })
    }

    /// `ai.preview`: exactly what would be sent for this identity, and its hash.
    pub fn ai_preview(&self, params: &Value) -> Result<Value, RpcError> {
        let id = params
            .get("identity_id")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<i64>().ok())
            .ok_or_else(|| bad("identity_id is required"))?;
        let p = self
            .ai_payload(id, &self.ai_settings())
            .map_err(|_| RpcError::new(NOT_FOUND, "no such evaluated identity"))?;
        Ok(json!({ "payload": p.value, "payload_sha256": p.hash }))
    }

    /// Obtain an opinion: cache first (unless `force`), then the model; persists the result.
    pub async fn ai_assess(
        &self,
        exe_id: i64,
        force: bool,
    ) -> Result<(Assessed, i32, bool), AiFail> {
        let s = self.ai_settings();
        if !s.active() {
            return Err(AiFail::Disabled);
        }
        let b = self.ai_backend().ok_or(AiFail::Disabled)?;
        let p = self.ai_payload(exe_id, &s)?;
        let now = OffsetDateTime::now_utc();
        let hit = if force {
            None
        } else {
            self.with_store(|c| {
                store::cache_get(c, &p.cache_key, now).and_then(|h| {
                    h.map_or_else(|| store::cache_get(c, &p.memory_key, now), |h| Ok(Some(h)))
                })
            })
            .and_then(Result::ok)
            .flatten()
        };
        let (op, model, cached) =
            if let Some(j) = hit.and_then(|j| serde_json::from_str::<(Opinion, String)>(&j).ok()) {
                (j.0, j.1, true)
            } else {
                let key = self.credential(&*b, &s).await?;
                let _slot = self
                    .ai_slots
                    .acquire()
                    .await
                    .map_err(|_| AiFail::Disabled)?;
                let (op, model) = if s.shared() {
                    b.assess_shared(&s, &key, &p.value, &p.present).await
                } else {
                    b.assess(&s, &key, &p.value, &p.present).await
                }
                .map_err(AiFail::Ai)?;
                let sure = op.confidence >= s.auto_threshold;
                let ttl = cache_ttl(&op.verdict, sure);
                if let Ok(j) = serde_json::to_string(&(&op, &model)) {
                    self.with_store(|c| {
                        store::cache_put(c, &p.cache_key, &j, &model, ttl, now)?;
                        if op.verdict != "unknown" && sure {
                            store::cache_put(c, &p.memory_key, &j, &model, TTL_MEMORY, now)?;
                        }
                        Ok::<_, vigil_store::StoreError>(())
                    });
                }
                (op, model, false)
            };
        let (tin, tout) = if cached { (0, 0) } else { b.token_delta() };
        self.ai_tally(|d| {
            if cached {
                d.cached += 1;
            } else {
                d.calls += 1;
            }
            d.tokens_in += tin;
            d.tokens_out += tout;
        });
        let stored = self
            .with_store(|c| -> Result<_, vigil_store::StoreError> {
                let id = store::insert_opinion(
                    c,
                    &store::NewOpinion {
                        executable_id: exe_id,
                        verdict: op.verdict.clone(),
                        confidence: op.confidence,
                        recommended_action: op.recommended_action.clone(),
                        reasons_json: serde_json::to_string(&op.reasons).unwrap_or_default(),
                        indicators_json: serde_json::to_string(&op.indicators).unwrap_or_default(),
                        model: model.clone(),
                        payload_sha256: p.hash.clone(),
                    },
                    now,
                )?;
                store::latest_opinion(c, exe_id).map(|o| o.filter(|o| o.id == id))
            })
            .and_then(Result::ok)
            .flatten()
            .ok_or(AiFail::NoData)?;
        self.audit(
            "ai",
            AuditKind::AiDecision,
            Some(&exe_id.to_string()),
            &json!({ "outcome": "advice", "verdict": stored.verdict, "confidence": stored.confidence,
                     "recommended_action": stored.recommended_action, "model": stored.model,
                     "cached": cached, "payload_sha256": p.hash }),
        );
        Ok((
            Assessed {
                opinion: stored,
                cached,
            },
            p.score,
            p.hard_rule,
        ))
    }

    /// `ai.explain`: an on-demand, uncached assessment for the UI.
    pub async fn ai_explain(&self, params: &Value) -> Result<Value, RpcError> {
        let id = params
            .get("identity_id")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<i64>().ok())
            .ok_or_else(|| bad("identity_id is required"))?;
        match self.ai_assess(id, true).await {
            Ok((a, ..)) => Ok(opinion_json(&a.opinion, a.cached)),
            Err(AiFail::Disabled) => Err(RpcError::new(INVALID_STATE, "off")),
            Err(AiFail::NoData) => Err(RpcError::new(NOT_FOUND, "no such evaluated identity")),
            Err(f) => {
                tracing::warn!(error = ?f, identity = id, "ai assessment failed");
                self.audit(
                    "ai",
                    AuditKind::AiDecision,
                    Some(&id.to_string()),
                    &json!({ "outcome": "unavailable", "reason": f.code(), "cause": f.reason() }),
                );
                Err(RpcError::new(AI_UNAVAILABLE, f.reason()))
            }
        }
    }

    /// `ai.test`: one harmless call to verify the key and the network path.
    pub async fn ai_test(&self) -> Value {
        let s = self.ai_settings();
        let t0 = Instant::now();
        let (ok, model) = match self.ai_backend() {
            Some(b) => match self.credential(&*b, &s).await {
                Ok(key) => {
                    let probe = json!({ "image_name": "notepad.exe", "signature": { "status": "valid_embedded", "org": "Microsoft Corporation" },
                                        "rule_result": { "score": 90, "verdict": "safe", "signals": [] } });
                    let r = if s.shared() {
                        b.assess_shared(&s, &key, &probe, &[]).await
                    } else {
                        b.assess(&s, &key, &probe, &[]).await
                    };
                    match r {
                        Ok((_, m)) => (true, m),
                        Err(e) => {
                            tracing::warn!(code = e.code(), "AI connection test failed");
                            (false, s.model.clone())
                        }
                    }
                }
                Err(_) => (false, s.model.clone()),
            },
            None => (false, s.model.clone()),
        };
        json!({ "ok": ok, "latency_ms": u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX), "model": model })
    }

    /// Background hook: assess every open pending item that has no opinion yet.
    pub async fn ai_assess_open_pending(self: Arc<Self>) {
        let s = self.ai_settings();
        if !s.active() {
            return;
        }
        let ids: Vec<i64> = self
            .with_store(|c| -> Result<Vec<i64>, vigil_store::StoreError> {
                let mut out = Vec::new();
                for p in decisions::list_pending(c)? {
                    let stale = match store::latest_opinion(c, p.executable_id)? {
                        None => true,
                        Some(o) => {
                            o.confidence < s.auto_threshold
                                && OffsetDateTime::parse(
                                    &o.created_at,
                                    &time::format_description::well_known::Rfc3339,
                                )
                                .is_ok_and(|t| OffsetDateTime::now_utc() - t >= TTL_WEAK)
                        }
                    };
                    if stale && !out.contains(&p.executable_id) {
                        out.push(p.executable_id);
                    }
                }
                Ok(out)
            })
            .and_then(Result::ok)
            .unwrap_or_default();
        for id in ids {
            if !self
                .ai_inflight
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(id)
            {
                continue;
            }
            self.ai_pending_one(id, &s).await;
            self.ai_inflight
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&id);
        }
    }

    /// Proactive second opinion for a newly seen Unknown program, so the answer is ready (and cached)
    /// by the time it connects. Uses at most half the daily budget; never decides anything.
    pub async fn ai_prefetch(self: Arc<Self>, exe_id: i64) {
        let s = self.ai_settings();
        let used = self.ai_backend().map_or(u32::MAX, |b| b.calls_today());
        if !s.active() || !self.ai_ready(&s) || used >= s.daily_call_budget / 2 {
            return;
        }
        if !self
            .ai_inflight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(exe_id)
        {
            return;
        }
        let _ = self.ai_assess(exe_id, false).await;
        self.ai_inflight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&exe_id);
    }

    /// Case-by-case judgement for a parent whose children sit below every kill threshold: record the
    /// behaviour as STM-002, ask the advisor once, and stop the tree only in enforce mode when the
    /// advisor is confident it is malicious. Otherwise the opinion simply rides on the item.
    pub async fn storm_review(self: Arc<Self>, row: ProcRow, children: usize) {
        let s = self.ai_settings();
        let Some(id) = row
            .identity_id
            .as_deref()
            .and_then(|i| i.parse::<i64>().ok())
        else {
            return;
        };
        if !s.active() || !self.ai_ready(&s) {
            return;
        }
        if !self
            .storm_reviewed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id)
        {
            return;
        }
        let detail = format!("{children} child processes started by this program");
        let signal = json!([{ "id": "STM-002", "name": "Repeated child launches", "delta": -10,
                              "detail": detail }]);
        let stored = self.with_store(|c| {
            vigil_store::repo::insert_evaluation(
                c,
                id,
                &vigil_store::repo::NewEvaluation {
                    score: row.score.unwrap_or(50).min(60),
                    verdict: row.verdict.clone().unwrap_or_else(|| "unknown".into()),
                    hard_rule: None,
                    signals_json: signal.to_string(),
                    rule_pack_version: "behavior".into(),
                    source: "rules".into(),
                },
                &now(),
            )
        });
        if stored.is_none_or(|r| r.is_err()) {
            return;
        }
        let Ok((a, _, _)) = self.ai_assess(id, true).await else {
            return;
        };
        let confident =
            a.opinion.verdict == "malicious" && a.opinion.confidence >= s.auto_threshold;
        let acts = s.mode == "auto" && self.mode_and_health().0 == "enforce" && confident;
        self.audit(
            "ai",
            AuditKind::AiDecision,
            Some(&id.to_string()),
            &json!({ "outcome": if acts { "storm_kill" } else { "storm_noted" },
                     "children": children, "verdict": a.opinion.verdict }),
        );
        if acts {
            let tree = tokio::task::spawn_blocking(move || {
                self.reclassify_storm(&row, "advisor judged repeated launches malicious");
                self.kill_process(
                    &json!({ "pid": row.pid, "start_time": row.start_time, "tree": true, "block": true }),
                    "ai",
                )
            });
            let _ = tree.await;
        }
    }

    async fn ai_pending_one(&self, exe_id: i64, s: &AiSettings) {
        match self.ai_assess(exe_id, false).await {
            Err(AiFail::Disabled | AiFail::NoData) => {}
            Err(f) => self.audit(
                "ai",
                AuditKind::AiDecision,
                Some(&exe_id.to_string()),
                &json!({ "outcome": "pending", "reason": f.code(), "cause": f.reason() }),
            ),
            Ok((a, score, hard_rule)) => {
                // Authority follows the service mode: observe warns, learning suggests (the
                // opinion rides on the pending item), enforce executes within the gates.
                // Only a confident malicious opinion interrupts the user; the rest stays quiet.
                if a.opinion.verdict == "malicious" && a.opinion.confidence >= s.auto_threshold {
                    self.escalate_pending(exe_id);
                }
                if s.mode == "auto" && self.mode_and_health().0 == "enforce" {
                    self.ai_auto(exe_id, s, &a, score, hard_rule);
                }
            }
        }
    }

    /// Apply Auto mode (docs/06 §4). Every gate lives in `vigil_core::auto`.
    #[allow(clippy::too_many_lines)] // gate inputs, decision, audit and event stay in one place
    fn ai_auto(&self, exe_id: i64, s: &AiSettings, a: &Assessed, score: i32, hard_rule: bool) {
        let now = OffsetDateTime::now_utc();
        let Some((exe, flipped)) = self
            .with_store(|c| {
                let exe = vigil_store::repo::executable_by_id(c, exe_id)?;
                let dir = if a.opinion.recommended_action == "allow" {
                    "allow"
                } else {
                    "block"
                };
                let flipped = store::flipped_within(c, exe_id, dir, FLIP_WINDOW, now)?;
                Ok::<_, vigil_store::StoreError>((exe, flipped))
            })
            .and_then(Result::ok)
            .and_then(|(e, f)| Some((e?, f)))
        else {
            return;
        };
        let image = exe
            .path
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or_default()
            .to_string();
        let learning_hours = (self.mode_and_health().0 == "learning")
            .then(|| self.learning_started())
            .flatten()
            .and_then(|t| {
                OffsetDateTime::parse(&t, &time::format_description::well_known::Rfc3339).ok()
            })
            .map(|t| u64::try_from((now - t).whole_hours()).unwrap_or(0));
        let outcome = auto::decide(&auto::Inputs {
            hard_rule_fired: hard_rule,
            score,
            verdict: &a.opinion.verdict,
            confidence: a.opinion.confidence,
            recommended_action: &a.opinion.recommended_action,
            auto_threshold: s.auto_threshold,
            auto_kill: s.auto_kill,
            never_kill: self.never_kill.check(&image, None).is_err(),
            learning_hours,
            flipped_recently: flipped,
            active_threat: {
                let (running, conns) = self.live_context(&exe.path);
                running > 0 && conns > 0
            },
        });
        let Outcome::Decide { action, scope } = outcome else {
            let Outcome::Skip(why) = outcome else { return };
            self.ai_tally(|t| t.left_to_user += 1);
            self.audit(
                "ai",
                AuditKind::AiDecision,
                Some(&exe_id.to_string()),
                &json!({ "outcome": "pending", "reason": format!("{why:?}") }),
            );
            return;
        };
        let action = match action {
            auto::Action::Allow => decisions::Action::Allow,
            auto::Action::Block => decisions::Action::Block,
            auto::Action::Kill => decisions::Action::Kill,
        };
        let Some(scope_kind) = Scope::parse(scope) else {
            return;
        };
        let made = self.with_store(|c| -> Result<_, vigil_store::StoreError> {
            let id = decisions::insert_decision(
                c,
                &NewDecision {
                    executable_id: exe_id,
                    action,
                    scope: scope_kind,
                    apply_to: ApplyTo::File,
                    publisher_thumbprint: None,
                    publisher_product: None,
                    by: DecidedBy::Ai,
                    actor: "ai".into(),
                    note: Some(format!(
                        "auto: {} ({:.2})",
                        a.opinion.model, a.opinion.confidence
                    )),
                },
                now,
            )?;
            let open: Vec<i64> = decisions::list_pending(c)?
                .into_iter()
                .filter(|p| p.executable_id == exe_id)
                .map(|p| p.id)
                .collect();
            decisions::resolve_pending_for_executable(c, exe_id, id, now)?;
            store::link_decision(c, a.opinion.id, id)?;
            Ok((decisions::get_decision(c, id)?, open))
        });
        let Some(Ok((Some(d), open))) = made else {
            return;
        };
        self.audit(
            "ai",
            AuditKind::AiDecision,
            Some(&exe_id.to_string()),
            &json!({ "outcome": "decided", "decision_id": d.id, "action": d.action.as_str(),
                     "scope": d.scope.as_str(), "confidence": a.opinion.confidence, "model": a.opinion.model }),
        );
        let act = d.action;
        self.ai_tally(|t| match act {
            decisions::Action::Allow => t.allow += 1,
            decisions::Action::Block => t.block += 1,
            decisions::Action::Kill => t.kill += 1,
        });
        for pid in open {
            self.emit(
                "pending",
                "event.pending_resolved",
                json!({ "pending_id": pid.to_string(), "action": d.action.as_str(), "by": "ai" }),
            );
        }
        let _ = self.enforce_decision(&d);
    }
}

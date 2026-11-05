use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};

use crate::opinion::tool_schema;
use crate::{AiError, Limiter, Opinion, validate};

/// System prompt (`docs/06 §5`).
pub const SYSTEM_PROMPT: &str = include_str!("prompt/system.txt");
const API_VERSION: &str = "2023-06-01";
const TOOL: &str = "submit_verdict";

/// Client configuration; models and URL are settings, not constants.
#[derive(Debug, Clone)]
pub struct Config {
    pub base_url: String,
    pub model: String,
    pub escalation_model: Option<String>,
    pub escalate_below: f64,
    pub timeout: Duration,
    pub daily_budget: u32,
    pub per_minute: u32,
    /// Shared endpoint (https only). `None` means this build has no shared key.
    pub proxy_url: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            base_url: "https://api.anthropic.com".into(),
            model: "claude-haiku-5-5".into(),
            escalation_model: Some("claude-sonnet-5-5".into()),
            escalate_below: 0.75,
            timeout: Duration::from_secs(8),
            daily_budget: 500,
            per_minute: 10,
            proxy_url: None,
        }
    }
}

/// The exact user message for a payload: untrusted JSON inside one delimiter block.
#[must_use]
pub fn user_message(payload: &Value) -> String {
    let json = serde_json::to_string(payload).unwrap_or_default();
    format!(
        "<untrusted_telemetry>\n{json}\n</untrusted_telemetry>\nAssess this executable and call submit_verdict."
    )
}

/// What the shared endpoint (`proxy/`) must send upstream; `proxy/src/spec.json` mirrors this
/// exactly and a gate test fails when they drift.
#[must_use]
pub fn proxy_spec() -> Value {
    json!({
        "system": SYSTEM_PROMPT,
        "tool": TOOL,
        "tool_schema": tool_schema(),
        "user_template": user_message(&Value::String("{payload}".into()))
            .replace("\"{payload}\"", "{payload}"),
    })
}

/// Messages API client with local budgets.
#[derive(Debug)]
pub struct Advisor {
    cfg: Config,
    http: reqwest::Client,
    limiter: Mutex<Limiter>,
    tokens_in: AtomicU64,
    tokens_out: AtomicU64,
    /// Unix second until which the shared endpoint is left alone after it answered 429.
    cooldown_until: AtomicU64,
}

/// The shared endpoint admits 6 quota units a minute per install (a deep call costs 2); stay under.
const SHARED_PER_MINUTE: u32 = 5;
/// How long to leave the shared endpoint alone after a 429.
const COOLDOWN_SECS: u64 = 300;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Advisor {
    /// # Errors
    /// [`AiError::Transport`] if the HTTP client cannot be built.
    pub fn new(cfg: Config) -> Result<Self, AiError> {
        let http = reqwest::Client::builder()
            .timeout(cfg.timeout)
            .build()
            .map_err(|_| AiError::Transport)?;
        let per_minute = if cfg.proxy_url.is_some() {
            cfg.per_minute.min(SHARED_PER_MINUTE)
        } else {
            cfg.per_minute
        };
        let limiter = Mutex::new(Limiter::new(cfg.daily_budget, per_minute));
        Ok(Self {
            cfg,
            http,
            limiter,
            tokens_in: AtomicU64::new(0),
            tokens_out: AtomicU64::new(0),
            cooldown_until: AtomicU64::new(0),
        })
    }

    /// Cumulative `(input, output)` tokens reported by the API since this client was built.
    #[must_use]
    pub fn tokens(&self) -> (u64, u64) {
        (
            self.tokens_in.load(Ordering::Relaxed),
            self.tokens_out.load(Ordering::Relaxed),
        )
    }

    #[must_use]
    pub fn calls_today(&self) -> u32 {
        self.limiter.lock().map_or(0, |l| l.calls_today())
    }

    /// Ask for an opinion. Escalates to the second model when confidence is low.
    ///
    /// # Errors
    /// Any [`AiError`]; callers fall back to Pending.
    pub async fn assess(
        &self,
        key: &SecretString,
        payload: &Value,
        present: &[String],
    ) -> Result<(Opinion, String), AiError> {
        let first = self.call(key, &self.cfg.model, payload, present).await?;
        if self.needs_escalation(&first)
            && let Some(m) = self
                .cfg
                .escalation_model
                .as_ref()
                .filter(|m| **m != self.cfg.model)
            && let Ok(second) = self.call(key, m, payload, present).await
        {
            return Ok((second, m.clone()));
        }
        Ok((first, self.cfg.model.clone()))
    }

    /// A stronger model gets a second look when the first is unsure or undecided.
    fn needs_escalation(&self, first: &Opinion) -> bool {
        first.confidence < self.cfg.escalate_below || first.verdict == "unknown"
    }

    /// Same assessment through the project's shared endpoint (`docs/06 §10`): no API key on this
    /// machine, only an install token. The endpoint owns the prompt, schema and models; the answer is
    /// still validated here exactly like a direct one.
    ///
    /// # Errors
    /// [`AiError::NoKey`] when no shared endpoint is configured, otherwise any [`AiError`].
    pub async fn assess_shared(
        &self,
        token: &SecretString,
        payload: &Value,
        present: &[String],
    ) -> Result<(Opinion, String), AiError> {
        let first = self.call_shared(token, "fast", payload, present).await?;
        if self.needs_escalation(&first.0)
            && let Ok(second) = self.call_shared(token, "deep", payload, present).await
        {
            return Ok(second);
        }
        Ok(first)
    }

    async fn call_shared(
        &self,
        token: &SecretString,
        tier: &str,
        payload: &Value,
        present: &[String],
    ) -> Result<(Opinion, String), AiError> {
        let base = self.cfg.proxy_url.as_deref().ok_or(AiError::NoKey)?;
        if !base.starts_with("https://") {
            return Err(AiError::NoKey);
        }
        let now = now_secs();
        if now < self.cooldown_until.load(Ordering::Relaxed) {
            return Err(AiError::Budget);
        }
        {
            // A deep call costs two quota units at the endpoint, so it takes two local slots.
            let mut limiter = self.limiter.lock().map_err(|_| AiError::Budget)?;
            limiter.acquire(now)?;
            if tier == "deep" {
                limiter.acquire(now)?;
            }
        }
        let resp = self
            .http
            .post(format!("{}/v1/assess", base.trim_end_matches('/')))
            .bearer_auth(token.expose_secret())
            .json(&json!({ "tier": tier, "payload": payload }))
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    AiError::Timeout
                } else {
                    AiError::Transport
                }
            })?;
        let status = resp.status().as_u16();
        if status == 429 {
            self.cooldown_until
                .store(now_secs() + COOLDOWN_SECS, Ordering::Relaxed);
        }
        if status != 200 {
            return Err(AiError::Status(status));
        }
        let v: Value = resp
            .json()
            .await
            .map_err(|_| AiError::InvalidOutput("body".into()))?;
        let model = v["model"].as_str().unwrap_or("shared").to_string();
        Ok((validate(&v["verdict"], present)?, model))
    }

    /// Obtain an install token from the shared endpoint (one per installation).
    ///
    /// # Errors
    /// Any [`AiError`]; a refusal (rate limit, disabled endpoint) is a [`AiError::Status`].
    pub async fn register_shared(&self) -> Result<SecretString, AiError> {
        let base = self.cfg.proxy_url.as_deref().ok_or(AiError::NoKey)?;
        if !base.starts_with("https://") {
            return Err(AiError::NoKey);
        }
        let resp = self
            .http
            .post(format!("{}/v1/register", base.trim_end_matches('/')))
            .send()
            .await
            .map_err(|_| AiError::Transport)?;
        if resp.status().as_u16() != 200 {
            return Err(AiError::Status(resp.status().as_u16()));
        }
        let v: Value = resp
            .json()
            .await
            .map_err(|_| AiError::InvalidOutput("body".into()))?;
        v["token"]
            .as_str()
            .filter(|t| (20..=200).contains(&t.len()))
            .map(|t| SecretString::from(t.to_string()))
            .ok_or_else(|| AiError::InvalidOutput("token".into()))
    }

    async fn call(
        &self,
        key: &SecretString,
        model: &str,
        payload: &Value,
        present: &[String],
    ) -> Result<Opinion, AiError> {
        let body = json!({
            "model": model,
            "max_tokens": 400,
            "system": SYSTEM_PROMPT,
            "tools": [{"name": TOOL, "description": "Submit the verdict for this executable.",
                       "input_schema": tool_schema()}],
            "tool_choice": {"type": "tool", "name": TOOL},
            "messages": [{"role": "user", "content": user_message(payload)}],
        });
        let mut attempt = 0;
        loop {
            self.limiter
                .lock()
                .map_err(|_| AiError::Budget)?
                .acquire(now_secs())?;
            let sent = self
                .http
                .post(format!(
                    "{}/v1/messages",
                    self.cfg.base_url.trim_end_matches('/')
                ))
                .header("x-api-key", key.expose_secret())
                .header("anthropic-version", API_VERSION)
                .json(&body)
                .send()
                .await;
            let resp = match sent {
                Ok(r) => r,
                Err(e) if e.is_timeout() => return Err(AiError::Timeout),
                Err(_) => return Err(AiError::Transport),
            };
            let status = resp.status().as_u16();
            if (status == 429 || status >= 500) && attempt == 0 {
                attempt += 1;
                let jitter = u64::from(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_or(0, |d| d.subsec_millis())
                        % 250,
                );
                tokio::time::sleep(Duration::from_millis(200 + jitter)).await;
                continue;
            }
            if status != 200 {
                return Err(AiError::Status(status));
            }
            let v: Value = resp
                .json()
                .await
                .map_err(|_| AiError::InvalidOutput("body".into()))?;
            self.tokens_in.fetch_add(
                v["usage"]["input_tokens"].as_u64().unwrap_or(0),
                Ordering::Relaxed,
            );
            self.tokens_out.fetch_add(
                v["usage"]["output_tokens"].as_u64().unwrap_or(0),
                Ordering::Relaxed,
            );
            return parse(&v, present);
        }
    }
}

fn parse(v: &Value, present: &[String]) -> Result<Opinion, AiError> {
    let blocks = v["content"]
        .as_array()
        .ok_or_else(|| AiError::InvalidOutput("no content".into()))?;
    let mut tools = blocks.iter().filter(|b| b["type"] == "tool_use");
    let (Some(t), None) = (tools.next(), tools.next()) else {
        return Err(AiError::InvalidOutput(
            "expected exactly one tool_use".into(),
        ));
    };
    if t["name"] != TOOL {
        return Err(AiError::InvalidOutput("wrong tool".into()));
    }
    validate(&t["input"], present)
}

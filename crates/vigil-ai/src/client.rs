use std::sync::Mutex;
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

/// Messages API client with local budgets.
#[derive(Debug)]
pub struct Advisor {
    cfg: Config,
    http: reqwest::Client,
    limiter: Mutex<Limiter>,
}

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
        let limiter = Mutex::new(Limiter::new(cfg.daily_budget, cfg.per_minute));
        Ok(Self { cfg, http, limiter })
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
        if first.confidence < self.cfg.escalate_below
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

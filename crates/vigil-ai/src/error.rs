/// Why no opinion was produced. Every variant means "fall back to Pending".
#[derive(Debug, thiserror::Error)]
pub enum AiError {
    #[error("no API key configured")]
    NoKey,
    #[error("daily budget or rate cap reached")]
    Budget,
    #[error("request timed out")]
    Timeout,
    #[error("transport error")]
    Transport,
    #[error("API returned status {0}")]
    Status(u16),
    #[error("invalid model output: {0}")]
    InvalidOutput(String),
}

impl AiError {
    /// Audit/telemetry code (`ai_invalid_output`, `ai_unavailable`).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidOutput(_) => "ai_invalid_output",
            _ => "ai_unavailable",
        }
    }
}

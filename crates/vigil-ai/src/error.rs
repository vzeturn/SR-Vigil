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

    /// Why, in one word the UI can explain: `rate_limited`, `network`, `service`, `unauthorized`,
    /// `no_key`, `invalid_output`.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::NoKey => "no_key",
            Self::Budget | Self::Status(429) => "rate_limited",
            Self::Timeout | Self::Transport => "network",
            Self::Status(401 | 403) => "unauthorized",
            Self::Status(_) => "service",
            Self::InvalidOutput(_) => "invalid_output",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AiError;

    #[test]
    fn reasons_tell_the_user_what_to_do() {
        assert_eq!(AiError::Status(429).reason(), "rate_limited");
        assert_eq!(AiError::Budget.reason(), "rate_limited");
        assert_eq!(AiError::Timeout.reason(), "network");
        assert_eq!(AiError::Status(503).reason(), "service");
        assert_eq!(AiError::Status(401).reason(), "unauthorized");
        assert_eq!(AiError::NoKey.reason(), "no_key");
    }
}

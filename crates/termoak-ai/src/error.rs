use thiserror::Error;

/// AI engine errors.
#[derive(Debug, Error)]
pub enum AiError {
    #[error("provider \"{0}\" is not configured or has no credentials")]
    NotConfigured(String),
    #[error("provider \"{provider}\" returned {status}: {message}")]
    Http {
        provider: String,
        status: u16,
        message: String,
    },
    #[error("network ({provider}): {message}")]
    Network { provider: String, message: String },
    #[error("invalid response from \"{provider}\": {message}")]
    Protocol { provider: String, message: String },
    #[error("\"{provider}\" refused the request for safety reasons{}", .category.as_ref().map(|c| format!(" ({c})")).unwrap_or_default())]
    Refusal {
        provider: String,
        category: Option<String>,
    },
    #[error("\"{0}\" timed out")]
    Timeout(String),
    #[error("\"{provider}\" failed: {message}")]
    Process { provider: String, message: String },
    /// An external agent is not installed (its executable was not found).
    #[error("\"{provider}\" is not installed: {message}")]
    NotInstalled { provider: String, message: String },
    /// An external agent is installed but not signed in.
    #[error("\"{provider}\" is not signed in: {message}")]
    NotLoggedIn { provider: String, message: String },
    #[error("cancelled")]
    Cancelled,
    #[error("{0}")]
    Invalid(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("access denied: {0}")]
    Forbidden(String),
    /// The monthly AI spending cap of the account was reached.
    #[error("{0}")]
    BudgetExceeded(String),
    /// The plan does not include the server's AI and the user has no API key
    /// of their own that could be used.
    #[error("{0}")]
    KeyRequired(String),
    #[error(transparent)]
    Core(#[from] termoak_core::CoreError),
}

impl AiError {
    /// Is it worth trying the next provider in the chain?
    pub fn should_fallback(&self) -> bool {
        matches!(
            self,
            AiError::Http { .. }
                | AiError::NotConfigured(_)
                | AiError::Network { .. }
                | AiError::Protocol { .. }
                | AiError::Refusal { .. }
                | AiError::Timeout(_)
                | AiError::Process { .. }
                | AiError::NotInstalled { .. }
                | AiError::NotLoggedIn { .. }
        )
    }

    /// Stable code of the error, for clients that translate it:
    /// `not_installed`, `not_logged_in`, `timeout`, `key_rejected`,
    /// `rate_limited`, `network`, `cancelled`, `ai_budget_exceeded`,
    /// `ai_key_required`, `not_configured` or `ai_error`.
    pub fn code(&self) -> &'static str {
        match self {
            AiError::NotInstalled { .. } => "not_installed",
            AiError::NotLoggedIn { .. } => "not_logged_in",
            AiError::Timeout(_) => "timeout",
            AiError::Http {
                status: 401 | 403, ..
            } => "key_rejected",
            AiError::Http { status: 429, .. } => "rate_limited",
            AiError::Network { .. } => "network",
            AiError::Cancelled => "cancelled",
            AiError::BudgetExceeded(_) => "ai_budget_exceeded",
            AiError::KeyRequired(_) => "ai_key_required",
            // The availability checks only have a text.
            AiError::NotConfigured(m) => {
                let m = m.to_lowercase();
                if m.contains("not found") || m.contains("not installed") {
                    "not_installed"
                } else if m.contains("not signed in") || m.contains("login") {
                    "not_logged_in"
                } else {
                    "not_configured"
                }
            }
            _ => "ai_error",
        }
    }

    /// Is this a transient error worth retrying with the same provider?
    pub fn is_transient(&self) -> bool {
        matches!(self, AiError::Http { status, .. } if *status == 429 || *status == 408 || *status >= 500)
            || matches!(self, AiError::Network { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes() {
        let http = |status| AiError::Http {
            provider: "claude".into(),
            status,
            message: "x".into(),
        };
        assert_eq!(http(401).code(), "key_rejected");
        assert_eq!(http(429).code(), "rate_limited");
        assert_eq!(http(500).code(), "ai_error");
        assert_eq!(
            AiError::NotConfigured("codex: executable \"codex\" not found".into()).code(),
            "not_installed"
        );
        assert_eq!(
            AiError::NotConfigured("codex: not signed in: run codex login".into()).code(),
            "not_logged_in"
        );
        assert_eq!(AiError::Timeout("agy".into()).code(), "timeout");
        let e = AiError::NotLoggedIn {
            provider: "claude-code".into(),
            message: "run claude".into(),
        };
        assert_eq!(e.code(), "not_logged_in");
        assert!(e.should_fallback());
    }
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("not signed in to any server")]
    NotLoggedIn,
    #[error("the session has expired: sign in again")]
    SessionExpired,
    #[error("the server responded {status} ({code}): {message}")]
    Api {
        status: u16,
        code: String,
        message: String,
    },
    #[error("network: {0}")]
    Network(String),
    #[error("WebSocket: {0}")]
    WebSocket(String),
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Core(#[from] termoak_core::CoreError),
    #[error(transparent)]
    Ssh(#[from] termoak_ssh::SshError),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    /// The system keychain did not give the vault key (access denied,
    /// locked, no Secret Service...) and the local database needs it.
    /// Nothing was changed: show it with a "Try again" button (allowing
    /// access in the keychain prompt or unlocking it fixes it).
    #[error(
        "the system keychain did not give the vault key ({0}); allow access to it and try again"
    )]
    KeychainUnavailable(String),
}

impl From<reqwest::Error> for ClientError {
    fn from(e: reqwest::Error) -> Self {
        ClientError::Network(e.to_string())
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for ClientError {
    fn from(e: tokio_tungstenite::tungstenite::Error) -> Self {
        match e {
            // The server responded, but not with the WebSocket: same as the API.
            tokio_tungstenite::tungstenite::Error::Http(resp) => {
                let v: serde_json::Value = resp
                    .body()
                    .as_deref()
                    .and_then(|b| serde_json::from_slice(b).ok())
                    .unwrap_or_default();
                ClientError::Api {
                    status: resp.status().as_u16(),
                    code: v["error"]["code"].as_str().unwrap_or("http").to_string(),
                    message: v["error"]["message"]
                        .as_str()
                        .map(String::from)
                        .unwrap_or_else(|| resp.status().to_string()),
                }
            }
            other => ClientError::WebSocket(other.to_string()),
        }
    }
}

impl ClientError {
    /// The server's error code, if any.
    pub fn api_code(&self) -> Option<&str> {
        match self {
            ClientError::Api { code, .. } => Some(code),
            _ => None,
        }
    }

    /// The account has two-factor authentication and the code is missing.
    pub fn is_totp_required(&self) -> bool {
        self.api_code() == Some("totp_required")
    }

    /// The system keychain refused the vault key: retrying may work.
    pub fn is_keychain_unavailable(&self) -> bool {
        matches!(self, ClientError::KeychainUnavailable(_))
    }

    /// The two-factor authentication code is wrong.
    pub fn is_totp_invalid(&self) -> bool {
        self.api_code() == Some("totp_invalid")
    }

    /// The server requires a verified email and the account has not
    /// verified it: show the screen to enter the code from the email
    /// ([`ApiClient::verify_code`](crate::api::ApiClient::verify_code)).
    pub fn is_email_not_verified(&self) -> bool {
        self.api_code() == Some("email_not_verified")
    }

    /// The email verification code is wrong, expired or used up.
    pub fn is_invalid_code(&self) -> bool {
        self.api_code() == Some("invalid_code")
    }

    /// The plan does not include the server's AI and there is no API key of
    /// the user's own: show "add your API key in Settings → AI".
    pub fn is_ai_key_required(&self) -> bool {
        self.api_code() == Some("ai_key_required")
    }

    /// This month's AI credit for the server's providers is spent.
    pub fn is_ai_budget_exceeded(&self) -> bool {
        self.api_code() == Some("ai_budget_exceeded")
    }
}

pub type Result<T, E = ClientError> = std::result::Result<T, E>;

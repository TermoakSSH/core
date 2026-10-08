//! The FFI layer's single error type, with messages ready to show.

use termoak_client::ClientError;
use termoak_core::CoreError;
use termoak_ssh::SshError;

/// Termoak error as seen from Swift (`TermoakError`) and Kotlin
/// (`TermoakException`).
///
/// It is a "flat" error: each variant only carries the message, in English
/// and ready to show; the variant tells the app what to do (e.g. ask for the
/// login again on `SessionExpired`).
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum TermoakError {
    /// Invalid data (empty required field, malformed id, unreadable SSH key...).
    #[error("{0}")]
    Invalid(String),
    /// The record does not exist (or is not yours).
    #[error("{0}")]
    NotFound(String),
    /// Conflict with another record.
    #[error("{0}")]
    Conflict(String),
    /// You are not allowed to do that.
    #[error("{0}")]
    Forbidden(String),
    /// Vault: wrong key or tampered data.
    #[error("{0}")]
    Vault(String),
    /// Not signed in to any server.
    #[error("{0}")]
    NotLoggedIn(String),
    /// The session expired or was revoked: sign in again.
    #[error("{0}")]
    SessionExpired(String),
    /// The account has two-factor authentication: ask for the code and call
    /// `login` again with it.
    #[error("{0}")]
    TotpRequired(String),
    /// The two-factor authentication code is wrong.
    #[error("{0}")]
    TotpInvalid(String),
    /// The server returned an error (the message includes the HTTP status).
    #[error("{0}")]
    Server(String),
    /// Network error (offline, DNS, TLS, WebSocket...).
    #[error("{0}")]
    Network(String),
    /// Could not connect over SSH (network, timeout, negotiation, channel).
    #[error("{0}")]
    Connection(String),
    /// The SSH server's key changed, is unknown or was rejected.
    #[error("{0}")]
    HostKey(String),
    /// SSH authentication failed.
    #[error("{0}")]
    Auth(String),
    /// An SFTP operation failed.
    #[error("{0}")]
    Sftp(String),
    /// The connection, terminal or tunnel is already closed.
    #[error("{0}")]
    Closed(String),
    /// Local I/O error (device files).
    #[error("{0}")]
    Io(String),
    /// Unexpected internal error.
    #[error("{0}")]
    Internal(String),
    /// The plan does not include the server's AI and there is no API key of
    /// your own that can be used: show "add your API key in Settings → AI"
    /// (`set_ai_key`).
    #[error("{0}")]
    AiKeyRequired(String),
    /// This month's AI credit for the server's providers is spent (your own
    /// API keys keep working).
    #[error("{0}")]
    AiBudgetExceeded(String),
    /// The server requires a verified email and this account has not
    /// verified it yet: show the screen to enter the six-digit code from the
    /// email (`verify_code`, `resend_code`). The account's email is
    /// `server_user`.
    #[error("{0}")]
    EmailNotVerified(String),
    /// Use-only vault: you can use its items but not change them.
    #[error("{0}")]
    VaultReadOnly(String),
    /// Use-only vault: its secrets are never shown (hide reveal, copy and
    /// export).
    #[error("{0}")]
    SecretHidden(String),
    /// Strict vault: Use-only members only connect through the server: open
    /// a server session for this host instead.
    #[error("{0}")]
    UseOnlyStrict(String),
    /// A Use-only host needs its server (offline, or signed out): connect
    /// when online, or through a server session.
    #[error("{0}")]
    UseOnlyNeedsServer(String),
    /// The host is a Telnet host and this needs SSH (SFTP, tunnels,
    /// commands, OS detection, an SSH connection with `connect`): hide or
    /// disable it for Telnet hosts (`SshHost.protocol`,
    /// `TerminalHandle::is_telnet`).
    #[error("{0}")]
    NotSupportedForTelnet(String),
}

/// Variant of a vault rule's stable code (core or server).
fn vault_code(code: &str, msg: String) -> Option<TermoakError> {
    use termoak_core::error::codes;
    Some(match code {
        codes::VAULT_READ_ONLY => TermoakError::VaultReadOnly(msg),
        codes::SECRET_HIDDEN => TermoakError::SecretHidden(msg),
        codes::USE_ONLY_STRICT => TermoakError::UseOnlyStrict(msg),
        codes::USE_ONLY_NEEDS_SERVER => TermoakError::UseOnlyNeedsServer(msg),
        _ => return None,
    })
}

pub type Result<T, E = TermoakError> = std::result::Result<T, E>;

impl From<CoreError> for TermoakError {
    fn from(e: CoreError) -> Self {
        let msg = e.to_string();
        match e {
            CoreError::NotFound(_) => Self::NotFound(msg),
            CoreError::Conflict(_) => Self::Conflict(msg),
            CoreError::Invalid(_) => Self::Invalid(msg),
            CoreError::Forbidden(_) => Self::Forbidden(msg),
            CoreError::Crypto(_) => Self::Vault(msg),
            CoreError::Io(_) => Self::Io(msg),
            CoreError::Db(_) | CoreError::Json(_) | CoreError::Join(_) => Self::Internal(msg),
            CoreError::Vault { code, .. } if vault_code(code, String::new()).is_some() => {
                vault_code(code, msg).expect("checked")
            }
            CoreError::Vault { code, .. } => match code {
                termoak_core::error::codes::VAULT_NOT_FOUND => Self::NotFound(msg),
                termoak_core::error::codes::INVALID_ROLE
                | termoak_core::error::codes::CROSS_VAULT_REFERENCE => Self::Invalid(msg),
                termoak_core::error::codes::MEMBER_EXISTS
                | termoak_core::error::codes::ID_IN_USE
                | termoak_core::error::codes::USE_TRANSFER
                | termoak_core::error::codes::STILL_REFERENCED => Self::Conflict(msg),
                _ => Self::Forbidden(msg),
            },
        }
    }
}

impl From<SshError> for TermoakError {
    fn from(e: SshError) -> Self {
        let msg = e.to_string();
        match e {
            SshError::Connect { .. }
            | SshError::Timeout(_)
            | SshError::Channel(_)
            | SshError::Forward(_)
            | SshError::Russh(_) => Self::Connection(msg),
            SshError::HostKeyChanged { .. }
            | SshError::HostKeyUnknown { .. }
            | SshError::HostKeyRejected { .. } => Self::HostKey(msg),
            SshError::Auth { .. } => Self::Auth(msg),
            SshError::Key(_) | SshError::Unsupported(_) => Self::Invalid(msg),
            SshError::Sftp(_) => Self::Sftp(msg),
            SshError::Closed => Self::Closed(msg),
            SshError::Io(_) => Self::Io(msg),
            SshError::Core(c) => c.into(),
        }
    }
}

impl From<ClientError> for TermoakError {
    fn from(e: ClientError) -> Self {
        let msg = e.to_string();
        match e {
            ClientError::NotLoggedIn => Self::NotLoggedIn(msg),
            ClientError::SessionExpired => Self::SessionExpired(msg),
            ClientError::Api { .. } if e.is_totp_required() => Self::TotpRequired(msg),
            ClientError::Api { .. } if e.is_totp_invalid() => Self::TotpInvalid(msg),
            ClientError::Api { .. } if e.is_ai_key_required() => Self::AiKeyRequired(msg),
            ClientError::Api { .. } if e.is_ai_budget_exceeded() => Self::AiBudgetExceeded(msg),
            ClientError::Api { .. } if e.is_email_not_verified() => Self::EmailNotVerified(msg),
            ClientError::Api { ref code, .. } if vault_code(code, String::new()).is_some() => {
                vault_code(code, msg).expect("checked")
            }
            ClientError::Api { status, .. } => match status {
                401 => Self::SessionExpired(msg),
                403 => Self::Forbidden(msg),
                404 => Self::NotFound(msg),
                409 => Self::Conflict(msg),
                400 | 422 => Self::Invalid(msg),
                _ => Self::Server(msg),
            },
            ClientError::Network(_) | ClientError::WebSocket(_) => Self::Network(msg),
            ClientError::Invalid(_) | ClientError::KeychainUnavailable(_) => Self::Invalid(msg),
            ClientError::Core(c) => c.into(),
            ClientError::Ssh(s) => s.into(),
            ClientError::Io(_) => Self::Io(msg),
        }
    }
}

impl From<std::io::Error> for TermoakError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(format!("I/O: {e}"))
    }
}

impl From<serde_json::Error> for TermoakError {
    fn from(e: serde_json::Error) -> Self {
        Self::Invalid(format!("invalid JSON: {e}"))
    }
}

impl From<reqwest::Error> for TermoakError {
    fn from(e: reqwest::Error) -> Self {
        Self::Network(format!("network: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api(status: u16, code: &str) -> TermoakError {
        ClientError::Api {
            status,
            code: code.into(),
            message: "m".into(),
        }
        .into()
    }

    #[test]
    fn api_codes_map_to_variants() {
        assert!(matches!(
            api(403, "email_not_verified"),
            TermoakError::EmailNotVerified(_)
        ));
        assert!(matches!(api(403, "forbidden"), TermoakError::Forbidden(_)));
        assert!(matches!(api(400, "invalid_code"), TermoakError::Invalid(_)));
        assert!(matches!(
            api(401, "totp_required"),
            TermoakError::TotpRequired(_)
        ));
        assert!(matches!(
            api(429, "too_many_attempts"),
            TermoakError::Server(_)
        ));
        assert!(matches!(
            api(403, "use_only_strict"),
            TermoakError::UseOnlyStrict(_)
        ));
        assert!(matches!(
            api(403, "secret_hidden"),
            TermoakError::SecretHidden(_)
        ));
        let core: TermoakError = CoreError::vault("vault_read_only", "x").into();
        assert!(matches!(core, TermoakError::VaultReadOnly(_)));
    }
}

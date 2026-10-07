use thiserror::Error;

/// SSH engine errors.
#[derive(Debug, Error)]
pub enum SshError {
    #[error("could not connect to {target}: {reason}")]
    Connect { target: String, reason: String },
    #[error("timed out: {0}")]
    Timeout(String),
    #[error(
        "the host key of {host} has CHANGED (expected {expected}, got {actual}). Possible man-in-the-middle attack"
    )]
    HostKeyChanged {
        host: String,
        expected: String,
        actual: String,
    },
    #[error(
        "unknown host {host} with fingerprint {fingerprint}: it must be confirmed before connecting"
    )]
    HostKeyUnknown {
        host: String,
        fingerprint: String,
        key_type: String,
    },
    #[error("host key rejected by the user ({host})")]
    HostKeyRejected { host: String },
    #[error("authentication failed for {user}@{host}: {reason}")]
    Auth {
        user: String,
        host: String,
        reason: String,
    },
    #[error("invalid SSH key: {0}")]
    Key(String),
    #[error("SSH channel: {0}")]
    Channel(String),
    #[error("SFTP: {0}")]
    Sftp(String),
    #[error("tunnel: {0}")]
    Forward(String),
    #[error("the connection is closed")]
    Closed,
    /// Not available for this host or protocol (e.g. SFTP or jump hosts
    /// with Telnet).
    #[error("{0}")]
    Unsupported(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("SSH: {0}")]
    Russh(#[from] russh::Error),
    #[error(transparent)]
    Core(#[from] termoak_core::CoreError),
}

impl From<russh::keys::Error> for SshError {
    fn from(e: russh::keys::Error) -> Self {
        SshError::Key(e.to_string())
    }
}

impl From<russh_sftp::client::error::Error> for SshError {
    fn from(e: russh_sftp::client::error::Error) -> Self {
        SshError::Sftp(e.to_string())
    }
}

pub type Result<T, E = SshError> = std::result::Result<T, E>;

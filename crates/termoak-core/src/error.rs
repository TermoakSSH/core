use thiserror::Error;

/// Core error.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("invalid data: {0}")]
    Invalid(String),
    #[error("access denied: {0}")]
    Forbidden(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("serialization: {0}")]
    Json(#[from] serde_json::Error),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("internal task: {0}")]
    Join(String),
}

pub type Result<T, E = CoreError> = std::result::Result<T, E>;

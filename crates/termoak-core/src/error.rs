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
    /// Vault access or vault rule: `code` is one of [`codes`] (stable,
    /// snake_case; the server sends it as the API error code).
    #[error("{message}")]
    Vault {
        code: &'static str,
        message: String,
        /// Extra data (for example the `field` of a cross-vault reference).
        detail: Option<serde_json::Value>,
    },
}

impl CoreError {
    /// Vault error with a stable code.
    pub fn vault(code: &'static str, message: impl Into<String>) -> Self {
        CoreError::Vault {
            code,
            message: message.into(),
            detail: None,
        }
    }

    /// Vault error with extra data.
    pub fn vault_detail(
        code: &'static str,
        message: impl Into<String>,
        detail: serde_json::Value,
    ) -> Self {
        CoreError::Vault {
            code,
            message: message.into(),
            detail: Some(detail),
        }
    }

    /// The stable code of a vault error.
    pub fn vault_code(&self) -> Option<&'static str> {
        match self {
            CoreError::Vault { code, .. } => Some(code),
            _ => None,
        }
    }
}

/// Stable codes of [`CoreError::Vault`].
pub mod codes {
    /// The vault does not exist or you cannot see it.
    pub const VAULT_NOT_FOUND: &str = "vault_not_found";
    /// You can use the vault but not change it (Use-only).
    pub const VAULT_READ_ONLY: &str = "vault_read_only";
    /// Use-only members never see secrets.
    pub const SECRET_HIDDEN: &str = "secret_hidden";
    /// The personal vault cannot be shared, deleted or left.
    pub const VAULT_PERSONAL: &str = "vault_personal";
    /// Changing the vault of an item goes through `transfer`.
    pub const USE_TRANSFER: &str = "use_transfer";
    /// A reference points to an item of another vault.
    pub const CROSS_VAULT_REFERENCE: &str = "cross_vault_reference";
    /// Moving a key or identity that other items still use.
    pub const STILL_REFERENCED: &str = "still_referenced";
    /// Strict vault: Use-only members only connect through the server.
    pub const USE_ONLY_STRICT: &str = "use_only_strict";
    /// Use-only items need the server (clients).
    pub const USE_ONLY_NEEDS_SERVER: &str = "use_only_needs_server";
    /// A session closed because its user lost access to the vault.
    pub const VAULT_ACCESS_REVOKED: &str = "vault_access_revoked";
    /// Only `editor` and `use_only` can be granted.
    pub const INVALID_ROLE: &str = "invalid_role";
    /// That user or team already has a grant on the vault.
    pub const MEMBER_EXISTS: &str = "member_exists";
    /// The id belongs to an item you cannot see.
    pub const ID_IN_USE: &str = "id_in_use";
    /// Sharing with a team you are not a member of.
    pub const NOT_TEAM_MEMBER: &str = "not_team_member";
    /// Managing the vault needs the manager role.
    pub const VAULT_MANAGER_ONLY: &str = "vault_manager_only";
}

pub type Result<T, E = CoreError> = std::result::Result<T, E>;

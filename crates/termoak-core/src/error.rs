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
    /// Grantable roles: `connect_only`, `use_only`, `editor`, `manager`.
    pub const INVALID_ROLE: &str = "invalid_role";
    /// That user or team already has a grant on the vault.
    pub const MEMBER_EXISTS: &str = "member_exists";
    /// The id belongs to an item you cannot see.
    pub const ID_IN_USE: &str = "id_in_use";
    /// Sharing with a team you are not a member of.
    pub const NOT_TEAM_MEMBER: &str = "not_team_member";
    /// Managing the vault needs the manager role.
    pub const VAULT_MANAGER_ONLY: &str = "vault_manager_only";
    /// A host (or its group) uses a private network that is not in its
    /// vault (deleted, or never synced).
    pub const NETWORK_NOT_FOUND: &str = "network_not_found";
    /// Private networks are not available here: the server has no
    /// `termoak-netd` (or it is down), the account's server does not
    /// support them, or the host is not in an account vault.
    pub const NETWORK_UNAVAILABLE: &str = "network_unavailable";
    /// The network could not reach the host (`termoak-netd` dial failed).
    pub const NETWORK_DIAL_FAILED: &str = "network_dial_failed";
    /// A snippet template with malformed typed tags (`{{select:X}}` without
    /// options...): detail `issues` (docs/SSH-PRO.md §7.1).
    pub const INVALID_SNIPPET: &str = "invalid_snippet";
    /// Security keys (FIDO2, docs/SSH-PRO.md §3.6).
    pub const SECURITY_KEY_REQUIRED: &str = "security_key_required";
    pub const SECURITY_KEY_NO_DEVICE: &str = "security_key_no_device";
    pub const SECURITY_KEY_TIMEOUT: &str = "security_key_timeout";
    pub const SECURITY_KEY_CANCELLED: &str = "security_key_cancelled";
    pub const SECURITY_KEY_NOT_FOUND: &str = "security_key_not_found";
    pub const SECURITY_KEY_PIN_REQUIRED: &str = "security_key_pin_required";
    pub const SECURITY_KEY_PIN_INVALID: &str = "security_key_pin_invalid";
    pub const SECURITY_KEY_WRONG_KEY: &str = "security_key_wrong_key";
    pub const SECURITY_KEY_UNSUPPORTED: &str = "security_key_unsupported";
    pub const SECURITY_KEY_INVALID: &str = "security_key_invalid";
    pub const SECURITY_KEY_FAILED: &str = "security_key_failed";
    /// Teams security (docs-next/TEAMS-SECURITY.md §7).
    /// Connect only members never get secrets, not even just in time.
    pub const CONNECT_ONLY: &str = "connect_only";
    /// The team forbids revealing or exporting secrets (Editors).
    pub const SECRET_REVEAL_FORBIDDEN: &str = "secret_reveal_forbidden";
    /// The host needs an approved access window (detail: target, policy).
    pub const ACCESS_APPROVAL_REQUIRED: &str = "access_approval_required";
    /// The host has access policies and the server cannot be reached (client).
    pub const ACCESS_NEEDS_SERVER: &str = "access_needs_server";
    pub const ACCESS_REQUEST_EXISTS: &str = "access_request_exists";
    pub const ACCESS_REQUEST_NOT_NEEDED: &str = "access_request_not_needed";
    pub const ACCESS_REQUEST_CLOSED: &str = "access_request_closed";
    pub const ACCESS_DURATION_TOO_LONG: &str = "access_duration_too_long";
    pub const SELF_APPROVAL_FORBIDDEN: &str = "self_approval_forbidden";
    pub const NOT_AN_APPROVER: &str = "not_an_approver";
    pub const CA_NOT_CONFIGURED: &str = "ca_not_configured";
    pub const CA_EXISTS: &str = "ca_exists";
    pub const CERTIFICATE_KEY_NOT_OWNED: &str = "certificate_key_not_owned";
    pub const CERTIFICATE_PROOF_INVALID: &str = "certificate_proof_invalid";
    pub const CERTIFICATE_NO_PRINCIPALS: &str = "certificate_no_principals";
    /// The team requires 2FA (grace period over, or turning 2FA off).
    pub const TEAM_2FA_REQUIRED: &str = "team_2fa_required";
    /// Turning on "require 2FA" without 2FA yourself.
    pub const POLICY_REQUIRES_2FA: &str = "policy_requires_2fa";
    pub const AI_FORBIDDEN_BY_POLICY: &str = "ai_forbidden_by_policy";
    pub const NETWORKS_FORBIDDEN_BY_POLICY: &str = "networks_forbidden_by_policy";
    /// Recording is mandatory and this client does not record.
    pub const RECORDING_REQUIRED: &str = "recording_required";
    /// A session closed because its access window ended or was revoked.
    pub const ACCESS_EXPIRED: &str = "access_expired";
    pub const ACCESS_REVOKED: &str = "access_revoked";

    // End-to-end encrypted vaults (0.7 phase 5a, docs/E2EE-SSO-AUDIT.md §2).
    /// The secret is end-to-end encrypted and this device (or the server)
    /// does not have the vault key: unlock E2EE on the device.
    pub const E2EE_LOCKED: &str = "e2ee_locked";
    pub const E2EE_DECRYPT_FAILED: &str = "e2ee_decrypt_failed";
    pub const E2EE_PASSPHRASE_INVALID: &str = "e2ee_passphrase_invalid";
    pub const E2EE_PASSPHRASE_TOO_SHORT: &str = "e2ee_passphrase_too_short";
    pub const E2EE_RECOVERY_KEY_INVALID: &str = "e2ee_recovery_key_invalid";
    /// A sealed private key opened but does not match the published key.
    pub const E2EE_KEY_MISMATCH: &str = "e2ee_key_mismatch";
    /// The user has no E2EE key yet (set it up first).
    pub const E2EE_NOT_SET_UP: &str = "e2ee_not_set_up";
    pub const E2EE_KEY_EXISTS: &str = "e2ee_key_exists";
    /// A plaintext secret sent for an end-to-end encrypted vault.
    pub const E2EE_PLAINTEXT_REJECTED: &str = "e2ee_plaintext_rejected";
    /// A secret sealed with an older vault key version (re-encrypt it).
    pub const E2EE_KEY_OUTDATED: &str = "e2ee_key_outdated";
    /// The server cannot do this for an end-to-end encrypted vault
    /// (reveal, just-in-time credentials, server-side copies...).
    pub const E2EE_VAULT: &str = "e2ee_vault";
    /// A server session/test/exec needs secrets of an E2EE vault: send them
    /// for this session (`unlock`).
    pub const E2EE_UNLOCK_REQUIRED: &str = "e2ee_unlock_required";
    /// An enable/rotate/disable payload does not cover every secret or
    /// every member that must get the key.
    pub const E2EE_INCOMPLETE: &str = "e2ee_incomplete";
    pub const E2EE_NOT_ENABLED: &str = "e2ee_not_enabled";
    pub const E2EE_ALREADY_ENABLED: &str = "e2ee_already_enabled";
    /// Only clients that declare `e2ee` can use this vault.
    pub const E2EE_CLIENT_REQUIRED: &str = "e2ee_client_required";
    /// A wrap for someone who may not have the vault key, or for an old
    /// public key.
    pub const E2EE_WRAP_INVALID: &str = "e2ee_wrap_invalid";
    pub const E2EE_PAIRING_CLOSED: &str = "e2ee_pairing_closed";
    // SSO (0.7 phase 5a, docs/E2EE-SSO-AUDIT.md §3).
    /// Another team verified (or recently claimed) this domain.
    pub const SSO_DOMAIN_TAKEN: &str = "sso_domain_taken";
    /// The vault key changed meanwhile (`from_version` is old): reload.
    pub const E2EE_STALE: &str = "e2ee_stale";
}

pub type Result<T, E = CoreError> = std::result::Result<T, E>;

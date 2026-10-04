//! Vault types as Swift and Kotlin see them: flat records with simple types
//! (ids as `String`, optionals, lists) and their conversion to the core
//! models.
//!
//! Conventions:
//! - An empty `id` on save = new record (it gets a UUID v7).
//! - Secrets (passwords, private keys) never travel in these records: they
//!   are passed separately with [`SecretChange`], and `has_*` tells whether
//!   one is stored.
//! - Fields marked "read-only" are ignored on save.

use std::collections::HashMap;

use termoak_core::model as cm;
use termoak_core::model::{Record, SecretUpdate};
use termoak_core::{Id, Store};

use crate::error::{Result, TermoakError};

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Parses a text id; empty = nil (new record).
pub(crate) fn parse_id_or_nil(s: &str) -> Result<Id> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Id::nil());
    }
    parse_id(s)
}

/// Parses a required text id.
pub(crate) fn parse_id(s: &str) -> Result<Id> {
    s.trim()
        .parse::<Id>()
        .map_err(|_| TermoakError::Invalid(format!("invalid id: \"{s}\"")))
}

pub(crate) fn parse_opt_id(s: &Option<String>) -> Result<Option<Id>> {
    match s.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(v) => parse_id(v).map(Some),
    }
}

fn ids_to_strings(ids: &[Id]) -> Vec<String> {
    ids.iter().map(Id::to_string).collect()
}

fn port_from(v: u32, field: &str) -> Result<u16> {
    u16::try_from(v)
        .map_err(|_| TermoakError::Invalid(format!("field \"{field}\" is not a valid port")))
}

/// Where a record can live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SyncMode {
    /// Synced with the server (encrypted at rest). Server sessions and the
    /// background AI can use it.
    Synced,
    /// Never leaves this device.
    DeviceOnly,
}

impl From<cm::SyncMode> for SyncMode {
    fn from(m: cm::SyncMode) -> Self {
        match m {
            cm::SyncMode::Synced => SyncMode::Synced,
            cm::SyncMode::DeviceOnly => SyncMode::DeviceOnly,
        }
    }
}

impl From<SyncMode> for cm::SyncMode {
    fn from(m: SyncMode) -> Self {
        match m {
            SyncMode::Synced => cm::SyncMode::Synced,
            SyncMode::DeviceOnly => cm::SyncMode::DeviceOnly,
        }
    }
}

/// What to do with a secret (password, passphrase) on save.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SecretChange {
    /// Leave the stored secret untouched.
    Keep,
    /// Replace it with `value`.
    Set { value: String },
    /// Delete it.
    Clear,
}

impl SecretChange {
    /// Applies the change to an existing optional value.
    pub(crate) fn apply(self, current: Option<String>) -> Option<String> {
        match self {
            SecretChange::Keep => current,
            SecretChange::Set { value } => Some(value),
            SecretChange::Clear => None,
        }
    }

    pub(crate) fn is_keep(&self) -> bool {
        matches!(self, SecretChange::Keep)
    }
}

// ---------------------------------------------------------------------------
// Inheritable settings
// ---------------------------------------------------------------------------

/// Connection settings a host inherits from its group (and parent groups).
/// `nil`/`null` means "inherit".
#[derive(Debug, Clone, Default, PartialEq, uniffi::Record)]
pub struct HostSettings {
    #[uniffi(default)]
    pub port: Option<u32>,
    #[uniffi(default)]
    pub username: Option<String>,
    /// Identity (user + password and/or key) to use.
    #[uniffi(default)]
    pub identity_id: Option<String>,
    /// Specific SSH key (takes precedence over the identity's).
    #[uniffi(default)]
    pub key_id: Option<String>,
    /// Jump chain (ProxyJump), from first to last.
    #[uniffi(default)]
    pub jump_host_ids: Option<Vec<String>>,
    /// Snippet run when a terminal opens.
    #[uniffi(default)]
    pub startup_snippet_id: Option<String>,
    /// Environment variables (merged with the inherited ones).
    #[uniffi(default)]
    pub env: HashMap<String, String>,
    /// Keep-alive interval in seconds (0 = off).
    #[uniffi(default)]
    pub keepalive_secs: Option<u32>,
    #[uniffi(default)]
    pub agent_forwarding: Option<bool>,
    /// Terminal type (`TERM`), `xterm-256color` by default.
    #[uniffi(default)]
    pub term: Option<String>,
    /// Preferred terminal theme for this host.
    #[uniffi(default)]
    pub theme: Option<String>,
    /// Automatically record this host's sessions.
    #[uniffi(default)]
    pub record_sessions: Option<bool>,
    /// Proxy for the first connection (to the first jump if there is a
    /// chain). The password is set separately: `setHostProxyPassword`.
    #[uniffi(default)]
    pub proxy: Option<HostProxy>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, uniffi::Enum)]
pub enum ProxyKind {
    /// SOCKS5, with or without user and password.
    #[default]
    Socks5,
    /// SOCKS4 (SOCKS4a if the address is a name).
    Socks4,
    /// HTTP with `CONNECT`.
    Http,
}

#[derive(Debug, Clone, Default, PartialEq, uniffi::Record)]
pub struct HostProxy {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u32,
    #[uniffi(default)]
    pub username: Option<String>,
}

impl From<cm::ProxySettings> for HostProxy {
    fn from(p: cm::ProxySettings) -> Self {
        Self {
            kind: match p.kind {
                cm::ProxyKind::Socks5 => ProxyKind::Socks5,
                cm::ProxyKind::Socks4 => ProxyKind::Socks4,
                cm::ProxyKind::Http => ProxyKind::Http,
            },
            host: p.host,
            port: u32::from(p.port),
            username: p.username,
        }
    }
}

impl TryFrom<HostProxy> for cm::ProxySettings {
    type Error = TermoakError;
    fn try_from(p: HostProxy) -> Result<Self> {
        Ok(Self {
            kind: match p.kind {
                ProxyKind::Socks5 => cm::ProxyKind::Socks5,
                ProxyKind::Socks4 => cm::ProxyKind::Socks4,
                ProxyKind::Http => cm::ProxyKind::Http,
            },
            host: p.host.trim().to_string(),
            port: port_from(p.port, "proxy.port")?,
            username: p.username.filter(|u| !u.trim().is_empty()),
        })
    }
}

impl From<cm::HostSettings> for HostSettings {
    fn from(s: cm::HostSettings) -> Self {
        Self {
            port: s.port.map(u32::from),
            username: s.username,
            identity_id: s.identity_id.map(|i| i.to_string()),
            key_id: s.key_id.map(|i| i.to_string()),
            jump_host_ids: s.jump_host_ids.map(|ids| ids_to_strings(&ids)),
            startup_snippet_id: s.startup_snippet_id.map(|i| i.to_string()),
            env: s.env.into_iter().collect(),
            keepalive_secs: s.keepalive_secs,
            agent_forwarding: s.agent_forwarding,
            term: s.term,
            theme: s.theme,
            record_sessions: s.record_sessions,
            proxy: s.proxy.map(Into::into),
        }
    }
}

impl TryFrom<HostSettings> for cm::HostSettings {
    type Error = TermoakError;
    fn try_from(s: HostSettings) -> Result<Self> {
        Ok(Self {
            port: s.port.map(|p| port_from(p, "port")).transpose()?,
            username: s.username.filter(|u| !u.trim().is_empty()),
            identity_id: parse_opt_id(&s.identity_id)?,
            key_id: parse_opt_id(&s.key_id)?,
            jump_host_ids: s
                .jump_host_ids
                .map(|ids| ids.iter().map(|i| parse_id(i)).collect::<Result<Vec<_>>>())
                .transpose()?,
            startup_snippet_id: parse_opt_id(&s.startup_snippet_id)?,
            env: s.env.into_iter().collect(),
            keepalive_secs: s.keepalive_secs,
            agent_forwarding: s.agent_forwarding,
            term: s.term.filter(|t| !t.trim().is_empty()),
            theme: s.theme,
            record_sessions: s.record_sessions,
            proxy: s
                .proxy
                .filter(|p| !p.host.trim().is_empty())
                .map(TryInto::try_into)
                .transpose()?,
        })
    }
}

// ---------------------------------------------------------------------------
// Entities
// ---------------------------------------------------------------------------

/// Server to connect to.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct SshHost {
    /// Empty when creating.
    #[uniffi(default)]
    pub id: String,
    pub label: String,
    /// DNS name or IP.
    pub address: String,
    #[uniffi(default)]
    pub group_id: Option<String>,
    #[uniffi(default)]
    pub tags: Vec<String>,
    #[uniffi(default)]
    pub settings: HostSettings,
    #[uniffi(default)]
    pub notes: String,
    #[uniffi(default)]
    pub color: Option<String>,
    /// Detected system (linux, ubuntu, debian, freebsd, macos, windows...).
    #[uniffi(default)]
    pub os: Option<String>,
    /// Full name of the detected system (`Ubuntu 24.04.1 LTS`).
    #[uniffi(default)]
    pub os_version: Option<String>,
    #[uniffi(default)]
    pub favorite: bool,
    /// `nil` on save = keep the current one (or `Synced` if new).
    #[uniffi(default)]
    pub sync_mode: Option<SyncMode>,
    /// Read-only: a password is stored.
    #[uniffi(default)]
    pub has_password: bool,
    /// Read-only: last modification (ms since 1970).
    #[uniffi(default)]
    pub updated_at: i64,
}

impl From<Record<cm::Host>> for SshHost {
    fn from(r: Record<cm::Host>) -> Self {
        let h = r.data;
        Self {
            id: h.id.to_string(),
            label: h.label,
            address: h.address,
            group_id: h.group_id.map(|i| i.to_string()),
            tags: h.tags,
            settings: h.settings.into(),
            notes: h.notes,
            color: h.color,
            os: h.os,
            os_version: h.os_version,
            favorite: h.favorite,
            sync_mode: Some(r.meta.sync_mode.into()),
            has_password: r.meta.has_secret,
            updated_at: r.meta.updated_at,
        }
    }
}

impl SshHost {
    pub(crate) fn into_core(self) -> Result<(cm::Host, Option<cm::SyncMode>)> {
        Ok((
            cm::Host {
                id: parse_id_or_nil(&self.id)?,
                label: self.label.trim().to_string(),
                address: self.address.trim().to_string(),
                group_id: parse_opt_id(&self.group_id)?,
                tags: self.tags,
                settings: self.settings.try_into()?,
                notes: self.notes,
                color: self.color,
                os: self.os,
                os_version: self.os_version,
                favorite: self.favorite,
            },
            self.sync_mode.map(Into::into),
        ))
    }
}

/// Host group (can be nested).
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct HostGroup {
    #[uniffi(default)]
    pub id: String,
    pub name: String,
    #[uniffi(default)]
    pub parent_id: Option<String>,
    #[uniffi(default)]
    pub color: Option<String>,
    #[uniffi(default)]
    pub settings: HostSettings,
    #[uniffi(default)]
    pub sync_mode: Option<SyncMode>,
    /// Read-only.
    #[uniffi(default)]
    pub updated_at: i64,
}

impl From<Record<cm::Group>> for HostGroup {
    fn from(r: Record<cm::Group>) -> Self {
        let g = r.data;
        Self {
            id: g.id.to_string(),
            name: g.name,
            parent_id: g.parent_id.map(|i| i.to_string()),
            color: g.color,
            settings: g.settings.into(),
            sync_mode: Some(r.meta.sync_mode.into()),
            updated_at: r.meta.updated_at,
        }
    }
}

impl HostGroup {
    pub(crate) fn into_core(self) -> Result<(cm::Group, Option<cm::SyncMode>)> {
        Ok((
            cm::Group {
                id: parse_id_or_nil(&self.id)?,
                name: self.name.trim().to_string(),
                parent_id: parse_opt_id(&self.parent_id)?,
                color: self.color,
                settings: self.settings.try_into()?,
            },
            self.sync_mode.map(Into::into),
        ))
    }
}

/// Reusable identity: user + password and/or key.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct SshIdentity {
    #[uniffi(default)]
    pub id: String,
    pub label: String,
    pub username: String,
    #[uniffi(default)]
    pub key_id: Option<String>,
    #[uniffi(default)]
    pub sync_mode: Option<SyncMode>,
    /// Read-only: a password is stored.
    #[uniffi(default)]
    pub has_password: bool,
    /// Read-only.
    #[uniffi(default)]
    pub updated_at: i64,
}

impl From<Record<cm::Identity>> for SshIdentity {
    fn from(r: Record<cm::Identity>) -> Self {
        let i = r.data;
        Self {
            id: i.id.to_string(),
            label: i.label,
            username: i.username,
            key_id: i.key_id.map(|k| k.to_string()),
            sync_mode: Some(r.meta.sync_mode.into()),
            has_password: r.meta.has_secret,
            updated_at: r.meta.updated_at,
        }
    }
}

impl SshIdentity {
    pub(crate) fn into_core(self) -> Result<(cm::Identity, Option<cm::SyncMode>)> {
        Ok((
            cm::Identity {
                id: parse_id_or_nil(&self.id)?,
                label: self.label.trim().to_string(),
                username: self.username.trim().to_string(),
                key_id: parse_opt_id(&self.key_id)?,
            },
            self.sync_mode.map(Into::into),
        ))
    }
}

/// SSH key from the keychain (without the private part).
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct SshKey {
    #[uniffi(default)]
    pub id: String,
    pub label: String,
    /// Algorithm (`ssh-ed25519`, `rsa-sha2-512`, `ecdsa-sha2-nistp256`...).
    #[uniffi(default)]
    pub algorithm: String,
    /// Public key in OpenSSH format (to copy into `authorized_keys`).
    #[uniffi(default)]
    pub public_key: String,
    /// `SHA256:...` fingerprint.
    #[uniffi(default)]
    pub fingerprint: String,
    #[uniffi(default)]
    pub comment: String,
    /// The private key is protected by a passphrase.
    #[uniffi(default)]
    pub has_passphrase: bool,
    /// Associated OpenSSH certificate (optional).
    #[uniffi(default)]
    pub certificate: Option<String>,
    #[uniffi(default)]
    pub sync_mode: Option<SyncMode>,
    /// Read-only: the private key is stored in the vault.
    #[uniffi(default)]
    pub has_private_key: bool,
    /// Read-only.
    #[uniffi(default)]
    pub updated_at: i64,
}

impl From<Record<cm::SshKey>> for SshKey {
    fn from(r: Record<cm::SshKey>) -> Self {
        let k = r.data;
        Self {
            id: k.id.to_string(),
            label: k.label,
            algorithm: k.algorithm,
            public_key: k.public_key,
            fingerprint: k.fingerprint,
            comment: k.comment,
            has_passphrase: k.has_passphrase,
            certificate: k.certificate,
            sync_mode: Some(r.meta.sync_mode.into()),
            has_private_key: r.meta.has_secret,
            updated_at: r.meta.updated_at,
        }
    }
}

impl SshKey {
    pub(crate) fn into_core(self) -> Result<(cm::SshKey, Option<cm::SyncMode>)> {
        Ok((
            cm::SshKey {
                id: parse_id_or_nil(&self.id)?,
                label: self.label.trim().to_string(),
                algorithm: self.algorithm,
                public_key: self.public_key.trim().to_string(),
                fingerprint: self.fingerprint,
                comment: self.comment,
                has_passphrase: self.has_passphrase,
                certificate: self
                    .certificate
                    .map(|c| c.trim().to_string())
                    .filter(|c| !c.is_empty()),
            },
            self.sync_mode.map(Into::into),
        ))
    }
}

/// Type of key to generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum KeyType {
    Ed25519,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
}

impl From<KeyType> for termoak_ssh::keys::KeyType {
    fn from(k: KeyType) -> Self {
        use termoak_ssh::keys::KeyType as K;
        match k {
            KeyType::Ed25519 => K::Ed25519,
            KeyType::Rsa2048 => K::Rsa2048,
            KeyType::Rsa3072 => K::Rsa3072,
            KeyType::Rsa4096 => K::Rsa4096,
            KeyType::EcdsaP256 => K::EcdsaP256,
            KeyType::EcdsaP384 => K::EcdsaP384,
            KeyType::EcdsaP521 => K::EcdsaP521,
        }
    }
}

/// Public data of a private key (preview when importing).
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct KeyDetails {
    pub algorithm: String,
    pub public_key: String,
    pub fingerprint: String,
    pub comment: String,
    /// The key is encrypted with a passphrase.
    pub encrypted: bool,
}

impl From<&termoak_ssh::keys::KeyMaterial> for KeyDetails {
    fn from(k: &termoak_ssh::keys::KeyMaterial) -> Self {
        Self {
            algorithm: k.algorithm.clone(),
            public_key: k.public_openssh.clone(),
            fingerprint: k.fingerprint.clone(),
            comment: k.comment.clone(),
            encrypted: k.encrypted,
        }
    }
}

/// Reusable command snippet. Supports `{{name}}` variables.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct Snippet {
    #[uniffi(default)]
    pub id: String,
    pub name: String,
    pub script: String,
    #[uniffi(default)]
    pub description: String,
    #[uniffi(default)]
    pub tags: Vec<String>,
    #[uniffi(default)]
    pub sync_mode: Option<SyncMode>,
    /// Read-only.
    #[uniffi(default)]
    pub updated_at: i64,
}

impl From<Record<cm::Snippet>> for Snippet {
    fn from(r: Record<cm::Snippet>) -> Self {
        let s = r.data;
        Self {
            id: s.id.to_string(),
            name: s.name,
            script: s.script,
            description: s.description,
            tags: s.tags,
            sync_mode: Some(r.meta.sync_mode.into()),
            updated_at: r.meta.updated_at,
        }
    }
}

impl Snippet {
    pub(crate) fn into_core(self) -> Result<(cm::Snippet, Option<cm::SyncMode>)> {
        Ok((
            cm::Snippet {
                id: parse_id_or_nil(&self.id)?,
                name: self.name.trim().to_string(),
                script: self.script,
                description: self.description,
                tags: self.tags,
            },
            self.sync_mode.map(Into::into),
        ))
    }
}

/// Tunnel type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ForwardKind {
    /// `-L`: local port → destination through the server.
    Local,
    /// `-R`: server port → local destination.
    Remote,
    /// `-D`: local SOCKS5 proxy.
    Dynamic,
}

impl From<cm::ForwardKind> for ForwardKind {
    fn from(k: cm::ForwardKind) -> Self {
        match k {
            cm::ForwardKind::Local => ForwardKind::Local,
            cm::ForwardKind::Remote => ForwardKind::Remote,
            cm::ForwardKind::Dynamic => ForwardKind::Dynamic,
        }
    }
}

impl From<ForwardKind> for cm::ForwardKind {
    fn from(k: ForwardKind) -> Self {
        match k {
            ForwardKind::Local => cm::ForwardKind::Local,
            ForwardKind::Remote => cm::ForwardKind::Remote,
            ForwardKind::Dynamic => cm::ForwardKind::Dynamic,
        }
    }
}

/// Port forwarding rule.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct PortForward {
    #[uniffi(default)]
    pub id: String,
    pub label: String,
    pub host_id: String,
    pub kind: ForwardKind,
    #[uniffi(default = "127.0.0.1")]
    pub bind_address: String,
    /// 0 = free port chosen automatically.
    #[uniffi(default)]
    pub bind_port: u32,
    /// Destination (unused in dynamic tunnels).
    #[uniffi(default)]
    pub dest_host: Option<String>,
    #[uniffi(default)]
    pub dest_port: Option<u32>,
    /// Start automatically when connecting to the host.
    #[uniffi(default)]
    pub auto_start: bool,
    #[uniffi(default)]
    pub sync_mode: Option<SyncMode>,
    /// Read-only.
    #[uniffi(default)]
    pub updated_at: i64,
}

impl From<Record<cm::PortForward>> for PortForward {
    fn from(r: Record<cm::PortForward>) -> Self {
        let f = r.data;
        Self {
            id: f.id.to_string(),
            label: f.label,
            host_id: f.host_id.to_string(),
            kind: f.kind.into(),
            bind_address: f.bind_address,
            bind_port: f.bind_port.into(),
            dest_host: f.dest_host,
            dest_port: f.dest_port.map(u32::from),
            auto_start: f.auto_start,
            sync_mode: Some(r.meta.sync_mode.into()),
            updated_at: r.meta.updated_at,
        }
    }
}

impl PortForward {
    pub(crate) fn into_core(self) -> Result<(cm::PortForward, Option<cm::SyncMode>)> {
        let bind_address = match self.bind_address.trim() {
            "" => "127.0.0.1".to_string(),
            other => other.to_string(),
        };
        Ok((
            cm::PortForward {
                id: parse_id_or_nil(&self.id)?,
                label: self.label.trim().to_string(),
                host_id: parse_id(&self.host_id)?,
                kind: self.kind.into(),
                bind_address,
                bind_port: port_from(self.bind_port, "bind_port")?,
                dest_host: self
                    .dest_host
                    .map(|h| h.trim().to_string())
                    .filter(|h| !h.is_empty()),
                dest_port: self
                    .dest_port
                    .map(|p| port_from(p, "dest_port"))
                    .transpose()?,
                auto_start: self.auto_start,
            },
            self.sync_mode.map(Into::into),
        ))
    }
}

/// Known host key (equivalent to `known_hosts`).
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct KnownHost {
    pub id: String,
    /// Name or IP as used to connect.
    pub host: String,
    pub port: u32,
    /// Key algorithm (`ssh-ed25519`...).
    pub key_type: String,
    /// Public key in OpenSSH format.
    pub public_key: String,
    /// `SHA256:...` fingerprint.
    pub fingerprint: String,
    pub updated_at: i64,
}

impl From<Record<cm::KnownHost>> for KnownHost {
    fn from(r: Record<cm::KnownHost>) -> Self {
        let k = r.data;
        Self {
            id: k.id.to_string(),
            host: k.host,
            port: k.port.into(),
            key_type: k.key_type,
            public_key: k.public_key,
            fingerprint: k.fingerprint,
            updated_at: r.meta.updated_at,
        }
    }
}

/// Fact the AI remembers about your infrastructure.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct AiMemory {
    #[uniffi(default)]
    pub id: String,
    pub content: String,
    /// Host it refers to (optional).
    #[uniffi(default)]
    pub host_id: Option<String>,
    /// Read-only.
    #[uniffi(default)]
    pub updated_at: i64,
}

impl From<Record<cm::Memory>> for AiMemory {
    fn from(r: Record<cm::Memory>) -> Self {
        let m = r.data;
        Self {
            id: m.id.to_string(),
            content: m.content,
            host_id: m.host_id.map(|i| i.to_string()),
            updated_at: r.meta.updated_at,
        }
    }
}

impl AiMemory {
    pub(crate) fn into_core(self) -> Result<cm::Memory> {
        Ok(cm::Memory {
            id: parse_id_or_nil(&self.id)?,
            content: self.content.trim().to_string(),
            host_id: parse_opt_id(&self.host_id)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

/// Translates a password [`SecretChange`] into the core's `SecretUpdate`.
pub(crate) fn password_update<S, F>(change: SecretChange, make: F) -> SecretUpdate<S>
where
    F: FnOnce(Option<String>) -> S,
{
    match change {
        SecretChange::Keep => SecretUpdate::Keep,
        SecretChange::Set { value } => SecretUpdate::Set(make(Some(value))),
        SecretChange::Clear => SecretUpdate::Clear,
    }
}

/// Reads the secret of an existing entity (empty if new).
pub(crate) async fn current_secret<T: cm::Entity>(
    store: &Store,
    owner: Id,
    id: Id,
) -> Result<T::Secret> {
    if id.is_nil() {
        return Ok(T::Secret::default());
    }
    match store.secret::<T>(owner, id).await {
        Ok(s) => Ok(s),
        Err(termoak_core::CoreError::NotFound(_)) => Ok(T::Secret::default()),
        Err(e) => Err(e.into()),
    }
}

//! Data models.
//!
//! There are two families:
//! - **Syncable entities** (hosts, groups, identities, keys, snippets,
//!   forwards, known hosts, AI memories). They are stored generically in the
//!   `entities` table and synced across devices. Each entity keeps its public
//!   part (`data`) apart from its secret part (`Secret`), which is always
//!   stored encrypted.
//! - **Server records** (users, devices, persistent sessions, invites, AI
//!   tasks, audit log).

use std::collections::BTreeMap;
use uuid::Uuid;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::Id;
use crate::error::{CoreError, Result};

// ---------------------------------------------------------------------------
// Syncable entities
// ---------------------------------------------------------------------------

/// Kind of syncable entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Group,
    Host,
    Identity,
    Key,
    Snippet,
    Forward,
    KnownHost,
    Memory,
}

impl EntityKind {
    pub const ALL: [EntityKind; 8] = [
        EntityKind::Group,
        EntityKind::Host,
        EntityKind::Identity,
        EntityKind::Key,
        EntityKind::Snippet,
        EntityKind::Forward,
        EntityKind::KnownHost,
        EntityKind::Memory,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            EntityKind::Group => "group",
            EntityKind::Host => "host",
            EntityKind::Identity => "identity",
            EntityKind::Key => "key",
            EntityKind::Snippet => "snippet",
            EntityKind::Forward => "forward",
            EntityKind::KnownHost => "known_host",
            EntityKind::Memory => "memory",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// Where a record with secrets may live.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SyncMode {
    /// Synced with the server (encrypted at rest). Server sessions and the
    /// background AI can use it.
    #[default]
    Synced,
    /// Never leaves this device.
    DeviceOnly,
}

impl SyncMode {
    pub fn as_str(self) -> &'static str {
        match self {
            SyncMode::Synced => "synced",
            SyncMode::DeviceOnly => "device_only",
        }
    }

    pub fn parse(s: &str) -> Self {
        if s == "device_only" {
            SyncMode::DeviceOnly
        } else {
            SyncMode::Synced
        }
    }
}

/// Common contract of syncable entities.
pub trait Entity: Serialize + DeserializeOwned + Clone + Send + Sync + 'static {
    const KIND: EntityKind;
    /// Secret part; stored encrypted and never included in listings.
    type Secret: Serialize + DeserializeOwned + Default + Clone + Send + Sync + 'static;

    fn id(&self) -> Id;
    fn set_id(&mut self, id: Id);

    /// Business validation before saving.
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}

/// Empty secret for entities that have none.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NoSecret {}

/// Metadata the store adds to each entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RecordMeta {
    pub owner_id: Uuid,
    pub sync_mode: SyncMode,
    /// Sync revision (monotonic per database).
    pub rev: i64,
    /// Last modification, in ms.
    pub updated_at: i64,
    pub deleted: bool,
    /// Whether the record has a stored secret.
    pub has_secret: bool,
}

/// Entity with its metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record<T> {
    #[serde(flatten)]
    pub data: T,
    #[serde(flatten)]
    pub meta: RecordMeta,
}

/// What to do with the secret when saving an entity.
#[derive(Debug, Clone, Default)]
pub enum SecretUpdate<S> {
    /// Leave the existing secret untouched.
    #[default]
    Keep,
    /// Replace it.
    Set(S),
    /// Delete it.
    Clear,
}

/// Connection settings a host inherits from its group (and parent groups).
/// `None` means "inherit".
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(default)]
pub struct HostSettings {
    pub port: Option<u16>,
    pub username: Option<String>,
    /// Identity (username + password and/or key) to use.
    pub identity_id: Option<Uuid>,
    /// Specific SSH key (takes precedence over the identity's).
    pub key_id: Option<Uuid>,
    /// Jump chain (ProxyJump), from first to last.
    pub jump_host_ids: Option<Vec<Uuid>>,
    /// Snippet run when a terminal opens.
    pub startup_snippet_id: Option<Uuid>,
    /// Environment variables (merged with the inherited ones).
    pub env: BTreeMap<String, String>,
    /// Keep-alive interval in seconds (0 = disabled).
    pub keepalive_secs: Option<u32>,
    pub agent_forwarding: Option<bool>,
    /// Terminal type (`TERM`), `xterm-256color` by default.
    pub term: Option<String>,
    /// Preferred terminal theme for this host.
    pub theme: Option<String>,
    /// Record this host's sessions automatically.
    pub record_sessions: Option<bool>,
    /// Proxy for the first TCP connection (to the first jump if there is a chain).
    pub proxy: Option<ProxySettings>,
}

/// Proxy type.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    /// SOCKS5, with or without username and password.
    #[default]
    Socks5,
    /// SOCKS4 (SOCKS4a if the address is a hostname).
    Socks4,
    /// HTTP with `CONNECT` (optional basic authentication).
    Http,
}

/// Proxy the connection goes through. The password, if needed, is stored
/// encrypted in the host secret (`HostSecret::proxy_password`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(default)]
pub struct ProxySettings {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
}

impl HostSettings {
    /// Applies `over` on top of `self` (values in `over` win).
    pub fn overlay(&self, over: &HostSettings) -> HostSettings {
        let mut env = self.env.clone();
        env.extend(over.env.iter().map(|(k, v)| (k.clone(), v.clone())));
        HostSettings {
            port: over.port.or(self.port),
            username: over.username.clone().or_else(|| self.username.clone()),
            identity_id: over.identity_id.or(self.identity_id),
            key_id: over.key_id.or(self.key_id),
            jump_host_ids: over
                .jump_host_ids
                .clone()
                .or_else(|| self.jump_host_ids.clone()),
            startup_snippet_id: over.startup_snippet_id.or(self.startup_snippet_id),
            env,
            keepalive_secs: over.keepalive_secs.or(self.keepalive_secs),
            agent_forwarding: over.agent_forwarding.or(self.agent_forwarding),
            term: over.term.clone().or_else(|| self.term.clone()),
            theme: over.theme.clone().or_else(|| self.theme.clone()),
            record_sessions: over.record_sessions.or(self.record_sessions),
            proxy: over.proxy.clone().or_else(|| self.proxy.clone()),
        }
    }
}

/// Host group (can be nested).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Group {
    #[serde(default)]
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub parent_id: Option<Uuid>,
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default)]
    pub settings: HostSettings,
}

impl Entity for Group {
    const KIND: EntityKind = EntityKind::Group;
    type Secret = NoSecret;
    fn id(&self) -> Id {
        self.id
    }
    fn set_id(&mut self, id: Id) {
        self.id = id;
    }
    fn validate(&self) -> Result<()> {
        non_empty("name", &self.name)?;
        if self.parent_id == Some(self.id) {
            return Err(CoreError::Invalid(
                "a group cannot be its own parent".into(),
            ));
        }
        Ok(())
    }
}

/// Server to connect to.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Host {
    #[serde(default)]
    pub id: Uuid,
    pub label: String,
    /// DNS name or IP.
    pub address: String,
    #[serde(default)]
    pub group_id: Option<Uuid>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub settings: HostSettings,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub color: Option<String>,
    /// Detected system (linux, ubuntu, debian, freebsd, macos, windows...).
    #[serde(default)]
    pub os: Option<String>,
    /// System version or full name (`Ubuntu 24.04.1 LTS`).
    #[serde(default)]
    pub os_version: Option<String>,
    #[serde(default)]
    pub favorite: bool,
}

/// Host secret: direct password (optional).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct HostSecret {
    #[serde(default)]
    pub password: Option<String>,
    /// Proxy password (`HostSettings::proxy`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_password: Option<String>,
}

impl Entity for Host {
    const KIND: EntityKind = EntityKind::Host;
    type Secret = HostSecret;
    fn id(&self) -> Id {
        self.id
    }
    fn set_id(&mut self, id: Id) {
        self.id = id;
    }
    fn validate(&self) -> Result<()> {
        non_empty("label", &self.label)?;
        non_empty("address", &self.address)?;
        if self.address.chars().any(|c| c.is_whitespace()) {
            return Err(CoreError::Invalid(
                "the address cannot contain spaces".into(),
            ));
        }
        if let Some(jumps) = &self.settings.jump_host_ids
            && jumps.contains(&self.id)
        {
            return Err(CoreError::Invalid(
                "a host cannot jump through itself".into(),
            ));
        }
        Ok(())
    }
}

/// Reusable identity: username + password and/or key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Identity {
    #[serde(default)]
    pub id: Uuid,
    pub label: String,
    pub username: String,
    #[serde(default)]
    pub key_id: Option<Uuid>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IdentitySecret {
    #[serde(default)]
    pub password: Option<String>,
}

impl Entity for Identity {
    const KIND: EntityKind = EntityKind::Identity;
    type Secret = IdentitySecret;
    fn id(&self) -> Id {
        self.id
    }
    fn set_id(&mut self, id: Id) {
        self.id = id;
    }
    fn validate(&self) -> Result<()> {
        non_empty("label", &self.label)?;
        non_empty("username", &self.username)
    }
}

/// SSH key from the keychain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SshKey {
    #[serde(default)]
    pub id: Uuid,
    pub label: String,
    /// Algorithm (`ssh-ed25519`, `rsa-sha2-512`, `ecdsa-sha2-nistp256`...).
    pub algorithm: String,
    /// Public key in OpenSSH format.
    pub public_key: String,
    /// `SHA256:...` fingerprint.
    pub fingerprint: String,
    #[serde(default)]
    pub comment: String,
    /// The private key is protected by a passphrase.
    #[serde(default)]
    pub has_passphrase: bool,
    /// Associated OpenSSH certificate (optional).
    #[serde(default)]
    pub certificate: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SshKeySecret {
    /// Private key in OpenSSH/PEM format.
    #[serde(default)]
    pub private_key: Option<String>,
    /// Passphrase (if the user chose to store it).
    #[serde(default)]
    pub passphrase: Option<String>,
}

impl Entity for SshKey {
    const KIND: EntityKind = EntityKind::Key;
    type Secret = SshKeySecret;
    fn id(&self) -> Id {
        self.id
    }
    fn set_id(&mut self, id: Id) {
        self.id = id;
    }
    fn validate(&self) -> Result<()> {
        non_empty("label", &self.label)?;
        non_empty("public_key", &self.public_key)
    }
}

/// Reusable command snippet. Supports `{{name}}` variables.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Snippet {
    #[serde(default)]
    pub id: Uuid,
    pub name: String,
    pub script: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl Snippet {
    /// `{{name}}` variables in the script, deduplicated and in order.
    pub fn variables(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut rest = self.script.as_str();
        while let Some(start) = rest.find("{{") {
            let after = &rest[start + 2..];
            let Some(end) = after.find("}}") else { break };
            let name = after[..end].trim();
            if !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                && !out.iter().any(|v| v == name)
            {
                out.push(name.to_string());
            }
            rest = &after[end + 2..];
        }
        out
    }

    /// Substitutes the variables. Fails if any is missing.
    pub fn render(&self, values: &BTreeMap<String, String>) -> Result<String> {
        let mut script = self.script.clone();
        for var in self.variables() {
            let value = values
                .get(&var)
                .ok_or_else(|| CoreError::Invalid(format!("missing variable \"{var}\"")))?;
            script = replace_var(&script, &var, value);
        }
        Ok(script)
    }
}

fn replace_var(script: &str, var: &str, value: &str) -> String {
    let mut out = String::with_capacity(script.len());
    let mut rest = script;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find("}}") {
            Some(end) if after[..end].trim() == var => {
                out.push_str(value);
                rest = &after[end + 2..];
            }
            _ => {
                out.push_str("{{");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

impl Entity for Snippet {
    const KIND: EntityKind = EntityKind::Snippet;
    type Secret = NoSecret;
    fn id(&self) -> Id {
        self.id
    }
    fn set_id(&mut self, id: Id) {
        self.id = id;
    }
    fn validate(&self) -> Result<()> {
        non_empty("name", &self.name)?;
        non_empty("script", &self.script)
    }
}

/// Forward type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ForwardKind {
    /// `-L`: local port → destination through the server.
    Local,
    /// `-R`: server port → local destination.
    Remote,
    /// `-D`: local SOCKS5 proxy.
    Dynamic,
}

/// Port forwarding rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PortForward {
    #[serde(default)]
    pub id: Uuid,
    pub label: String,
    pub host_id: Uuid,
    pub kind: ForwardKind,
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    pub bind_port: u16,
    /// Destination (unused for dynamic forwards).
    #[serde(default)]
    pub dest_host: Option<String>,
    #[serde(default)]
    pub dest_port: Option<u16>,
    /// Start automatically when connecting to the host.
    #[serde(default)]
    pub auto_start: bool,
}

fn default_bind_address() -> String {
    "127.0.0.1".into()
}

impl Entity for PortForward {
    const KIND: EntityKind = EntityKind::Forward;
    type Secret = NoSecret;
    fn id(&self) -> Id {
        self.id
    }
    fn set_id(&mut self, id: Id) {
        self.id = id;
    }
    fn validate(&self) -> Result<()> {
        non_empty("label", &self.label)?;
        if self.kind != ForwardKind::Dynamic
            && (self.dest_host.as_deref().unwrap_or("").is_empty() || self.dest_port.is_none())
        {
            return Err(CoreError::Invalid(
                "local and remote forwards need a destination (host and port)".into(),
            ));
        }
        Ok(())
    }
}

/// Known host key (equivalent to `known_hosts`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct KnownHost {
    #[serde(default)]
    pub id: Uuid,
    /// Name or IP as used to connect.
    pub host: String,
    pub port: u16,
    /// Key algorithm (`ssh-ed25519`...).
    pub key_type: String,
    /// Public key in OpenSSH format (`type base64`).
    pub public_key: String,
    /// `SHA256:...` fingerprint.
    pub fingerprint: String,
}

impl Entity for KnownHost {
    const KIND: EntityKind = EntityKind::KnownHost;
    type Secret = NoSecret;
    fn id(&self) -> Id {
        self.id
    }
    fn set_id(&mut self, id: Id) {
        self.id = id;
    }
    fn validate(&self) -> Result<()> {
        non_empty("host", &self.host)?;
        non_empty("public_key", &self.public_key)
    }
}

/// Fact the AI remembers about your infrastructure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Memory {
    #[serde(default)]
    pub id: Uuid,
    pub content: String,
    /// Host it refers to (optional).
    #[serde(default)]
    pub host_id: Option<Uuid>,
}

impl Entity for Memory {
    const KIND: EntityKind = EntityKind::Memory;
    type Secret = NoSecret;
    fn id(&self) -> Id {
        self.id
    }
    fn set_id(&mut self, id: Id) {
        self.id = id;
    }
    fn validate(&self) -> Result<()> {
        non_empty("content", &self.content)?;
        if self.content.chars().count() > 1000 {
            return Err(CoreError::Invalid(
                "a memory cannot exceed 1000 characters".into(),
            ));
        }
        Ok(())
    }
}

/// Generic record for syncing across devices.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SyncRecord {
    pub id: Uuid,
    pub kind: EntityKind,
    /// Public entity data (JSON).
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub data: serde_json::Value,
    /// Plaintext secret (only travels over TLS and only for `synced` records).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<Object>))]
    pub secret: Option<serde_json::Value>,
    pub sync_mode: SyncMode,
    pub updated_at: i64,
    pub deleted: bool,
    /// Server revision (assigned by the server).
    #[serde(default)]
    pub rev: i64,
}

// ---------------------------------------------------------------------------
// Server records
// ---------------------------------------------------------------------------

/// Server user.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub is_admin: bool,
    pub created_at: i64,
    pub disabled: bool,
    /// Two-factor authentication is enabled.
    #[serde(default)]
    pub totp_enabled: bool,
    /// Subscribed plan (id from the server catalog; `free` by default).
    #[serde(default = "default_plan")]
    pub plan: String,
    /// Has confirmed their email (always `true` if the server sends no email).
    #[serde(default = "default_true")]
    pub email_verified: bool,
    /// Preferred language (BCP 47, e.g. `en`, `es`); the server uses it for emails.
    #[serde(default = "default_locale")]
    pub locale: String,
}

/// Default language.
pub const DEFAULT_LOCALE: &str = "en";

pub fn default_locale() -> String {
    DEFAULT_LOCALE.to_string()
}

/// Default plan.
pub const DEFAULT_PLAN: &str = "free";

pub fn default_plan() -> String {
    DEFAULT_PLAN.to_string()
}

fn default_true() -> bool {
    true
}

/// Signed-in device (one token pair per device).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Device {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    /// `desktop-windows`, `desktop-macos`, `desktop-linux`, `ios`, `android`, `cli`...
    pub platform: String,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub access_expires_at: i64,
    pub refresh_expires_at: i64,
    /// Receives push notifications (`apns` or `fcm`), if enabled.
    #[serde(default)]
    pub push: Option<String>,
}

/// Token pair issued on sign-in or refresh.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TokenPair {
    pub access_token: String,
    pub access_expires_at: i64,
    pub refresh_token: String,
    pub refresh_expires_at: i64,
    pub device_id: Uuid,
}

/// Status of a persistent server session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Connecting,
    Running,
    Closed,
    Failed,
}

impl SessionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionStatus::Connecting => "connecting",
            SessionStatus::Running => "running",
            SessionStatus::Closed => "closed",
            SessionStatus::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "connecting" => SessionStatus::Connecting,
            "running" => SessionStatus::Running,
            "failed" => SessionStatus::Failed,
            _ => SessionStatus::Closed,
        }
    }
}

/// Record of a terminal session that lives on the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SessionInfo {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub host_id: Option<Uuid>,
    pub title: String,
    pub status: SessionStatus,
    /// `server` (the session runs on the server) or `relay` (local session shared through the server).
    pub kind: String,
    pub created_at: i64,
    pub ended_at: Option<i64>,
    pub error: Option<String>,
    pub recording: bool,
}

/// Guest permission on a shared session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SharePermission {
    /// View only.
    View,
    /// View and type (while holding control).
    Control,
}

impl SharePermission {
    pub fn as_str(self) -> &'static str {
        match self {
            SharePermission::View => "view",
            SharePermission::Control => "control",
        }
    }

    pub fn parse(s: &str) -> Self {
        if s == "control" {
            SharePermission::Control
        } else {
            SharePermission::View
        }
    }
}

/// Invitation to a shared session (to a user or through a link).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SessionShare {
    pub id: Uuid,
    pub session_id: Uuid,
    pub created_by: Uuid,
    /// Invited user (for a direct invitation).
    pub user_id: Option<Uuid>,
    /// Invited team (all its members).
    #[serde(default)]
    pub team_id: Option<Uuid>,
    /// The invitation is a link with a token.
    pub is_link: bool,
    pub permission: SharePermission,
    pub expires_at: Option<i64>,
    pub revoked: bool,
    pub created_at: i64,
}

/// Role within a team.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum TeamRole {
    /// Sees and uses what is shared with the team.
    Member,
    /// Also manages members.
    Admin,
    /// Can also delete the team and appoint admins.
    Owner,
}

impl TeamRole {
    pub fn as_str(self) -> &'static str {
        match self {
            TeamRole::Member => "member",
            TeamRole::Admin => "admin",
            TeamRole::Owner => "owner",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "owner" => TeamRole::Owner,
            "admin" => TeamRole::Admin,
            _ => TeamRole::Member,
        }
    }

    /// Can add and remove members.
    pub fn can_manage(self) -> bool {
        self >= TeamRole::Admin
    }
}

/// Team of users.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Team {
    pub id: Uuid,
    pub name: String,
    pub created_by: Uuid,
    pub created_at: i64,
    /// Your role in the team (in the user's listings).
    #[serde(default)]
    pub role: Option<TeamRole>,
    #[serde(default)]
    pub member_count: i64,
    /// Team plan (id from the server catalog).
    #[serde(default = "default_plan")]
    pub plan: String,
}

/// Team member.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TeamMember {
    pub user_id: Uuid,
    pub email: String,
    pub name: String,
    pub role: TeamRole,
    pub added_at: i64,
}

/// Invitation to create an account (even when registration is closed).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Invite {
    pub id: Uuid,
    /// Only this email can use it (if set).
    pub email: Option<String>,
    pub is_admin: bool,
    /// Team joined on registration.
    pub team_id: Option<Uuid>,
    /// Role in that team (member if not set).
    #[serde(default)]
    pub team_role: Option<TeamRole>,
    pub created_by: Uuid,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub used_by: Option<Uuid>,
    pub used_at: Option<i64>,
    pub revoked: bool,
}

/// Audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuditEntry {
    pub id: i64,
    pub owner_id: Uuid,
    /// Who: `user:<id>`, `ai:<task>`, `guest:<id>`...
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub detail: serde_json::Value,
    pub created_at: i64,
}

fn non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(CoreError::Invalid(format!("field \"{field}\" is required")))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snippet_variables_and_render() {
        let s = Snippet {
            id: Id::nil(),
            name: "logs".into(),
            script: "journalctl -u {{service}} -n {{ lines }} | grep {{service}}".into(),
            description: String::new(),
            tags: vec![],
        };
        assert_eq!(s.variables(), vec!["service", "lines"]);
        let mut v = BTreeMap::new();
        v.insert("service".to_string(), "nginx".to_string());
        assert!(s.render(&v).is_err());
        v.insert("lines".to_string(), "50".to_string());
        assert_eq!(
            s.render(&v).unwrap(),
            "journalctl -u nginx -n 50 | grep nginx"
        );
    }

    #[test]
    fn settings_overlay() {
        let mut base = HostSettings {
            port: Some(2222),
            username: Some("root".into()),
            ..Default::default()
        };
        base.env.insert("A".into(), "1".into());
        let mut over = HostSettings {
            username: Some("deploy".into()),
            ..Default::default()
        };
        over.env.insert("B".into(), "2".into());
        let merged = base.overlay(&over);
        assert_eq!(merged.port, Some(2222));
        assert_eq!(merged.username.as_deref(), Some("deploy"));
        assert_eq!(merged.env.len(), 2);
    }
}

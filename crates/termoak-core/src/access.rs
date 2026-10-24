//! Teams security (0.7 phase 4b, docs-next/TEAMS-SECURITY.md): team
//! policies, the effective policy of a vault for one member, access
//! policies with temporary access requests, and the SSH certificate
//! authority's public records.
//!
//! Times are milliseconds since the epoch, as in the rest of the model.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, Result};

// ---------------------------------------------------------------------------
// Team policy
// ---------------------------------------------------------------------------

/// Team-wide security rules (`teams.policy`). Every field has a default, so
/// an empty object (the column default) is the permissive policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(default)]
pub struct TeamPolicy {
    /// Members need two-factor authentication to reach the team's vaults.
    pub require_2fa: bool,
    /// When `require_2fa` was turned on (set by the server).
    pub require_2fa_since: Option<i64>,
    /// Days a member without 2FA keeps access (0-90).
    pub grace_days: u32,
    /// Editors may reveal, export and receive the secrets of the team's
    /// vaults. `false`: only managers do.
    pub allow_reveal: bool,
    pub ai: AiPolicy,
    /// Hosts of the team's vaults may use private networks.
    pub networks_allowed: bool,
    /// Every session on a host of the team's vaults is recorded.
    pub record_sessions: bool,
    /// Defaults of the team's certificates.
    pub ca: CaPolicy,
    /// Default push preferences for members' devices that never chose
    /// (stored; applied in a later phase).
    pub notifications: Option<BTreeMap<String, bool>>,
}

impl Default for TeamPolicy {
    fn default() -> Self {
        Self {
            require_2fa: false,
            require_2fa_since: None,
            grace_days: 7,
            allow_reveal: true,
            ai: AiPolicy::default(),
            networks_allowed: true,
            record_sessions: false,
            ca: CaPolicy::default(),
            notifications: None,
        }
    }
}

impl TeamPolicy {
    /// Checks the values (ranges, principal templates, extensions...).
    pub fn validate(&self) -> Result<()> {
        if self.grace_days > 90 {
            return Err(CoreError::Invalid("grace_days must be 0-90".into()));
        }
        self.ca.validate()?;
        if let Some(n) = &self.notifications
            && n.keys().any(|k| !crate::push::KINDS.contains(&k.as_str()))
        {
            return Err(CoreError::Invalid(
                "notifications: unknown notification kind".into(),
            ));
        }
        Ok(())
    }

    /// End of the 2FA grace period of a member who joined at `joined_at`
    /// (`None`: the policy is off).
    pub fn twofa_deadline(&self, joined_at: i64) -> Option<i64> {
        if !self.require_2fa {
            return None;
        }
        let since = self.require_2fa_since.unwrap_or(0).max(joined_at);
        Some(since + i64::from(self.grace_days) * 86_400_000)
    }
}

/// What the server's AI may do with the team's hosts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(default)]
pub struct AiPolicy {
    pub allowed: bool,
    pub approval: AiApproval,
}

impl Default for AiPolicy {
    fn default() -> Self {
        Self {
            allowed: true,
            approval: AiApproval::Default,
        }
    }
}

/// Approval level of AI actions on the team's hosts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AiApproval {
    /// The task's own mode.
    #[default]
    Default,
    /// Everything that runs on a host needs an approval.
    Always,
    /// From a later version: treated as `always`.
    #[serde(other)]
    Unknown,
}

impl AiApproval {
    pub fn always(self) -> bool {
        self != AiApproval::Default
    }
}

/// Certificate extensions a policy may grant (OpenSSH names).
pub const CERT_EXTENSIONS: [&str; 5] = [
    "permit-pty",
    "permit-port-forwarding",
    "permit-agent-forwarding",
    "permit-X11-forwarding",
    "permit-user-rc",
];

/// Longest certificate TTL a team may allow (24 h).
pub const MAX_CERT_TTL_MINUTES: u32 = 1440;

/// Defaults of the certificates of a CA owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(default)]
pub struct CaPolicy {
    pub default_ttl_minutes: u32,
    pub max_ttl_minutes: u32,
    /// Principal templates (`{login}`, `{member}`, `{email}`, `{user_id}`
    /// or literal names).
    pub principals: Vec<String>,
    pub extensions: Vec<String>,
    /// `source-address` critical option (comma-separated CIDRs).
    pub source_address: Option<String>,
}

impl Default for CaPolicy {
    fn default() -> Self {
        Self {
            default_ttl_minutes: 60,
            max_ttl_minutes: 480,
            principals: vec!["{login}".into()],
            extensions: vec![
                "permit-pty".into(),
                "permit-port-forwarding".into(),
                "permit-agent-forwarding".into(),
            ],
            source_address: None,
        }
    }
}

impl CaPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.max_ttl_minutes == 0 || self.max_ttl_minutes > MAX_CERT_TTL_MINUTES {
            return Err(CoreError::Invalid(format!(
                "ca.max_ttl_minutes must be 1-{MAX_CERT_TTL_MINUTES}"
            )));
        }
        if self.default_ttl_minutes == 0 || self.default_ttl_minutes > self.max_ttl_minutes {
            return Err(CoreError::Invalid(
                "ca.default_ttl_minutes must be between 1 and max_ttl_minutes".into(),
            ));
        }
        validate_templates(&self.principals, "ca.principals")?;
        validate_extensions(&self.extensions, "ca.extensions")?;
        if let Some(s) = &self.source_address {
            validate_source_address(s)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Effective policy of a vault (for one member)
// ---------------------------------------------------------------------------

/// What the team's policies mean for one member in one vault (computed by
/// the server; `Vault.policy`). The server enforces all of it anyway; apps
/// use it to hide what cannot be done.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(default)]
pub struct VaultPolicy {
    /// The team whose policy applies (team vaults).
    pub team_id: Option<Uuid>,
    /// You may reveal, export and receive the secrets of this vault (as far
    /// as your role allows).
    pub reveal_allowed: bool,
    pub ai_allowed: bool,
    pub ai_approval: AiApproval,
    pub networks_allowed: bool,
    /// Every session on hosts of this vault is recorded.
    pub record_sessions: bool,
    pub require_2fa: bool,
    /// Some hosts, groups or the vault itself have access policies (ask
    /// `GET /hosts/{id}/access` before connecting).
    pub access_policies: bool,
    /// The vault's owner (team or user) has an active SSH CA.
    pub certificates: bool,
}

impl Default for VaultPolicy {
    fn default() -> Self {
        Self {
            team_id: None,
            reveal_allowed: true,
            ai_allowed: true,
            ai_approval: AiApproval::Default,
            networks_allowed: true,
            record_sessions: false,
            require_2fa: false,
            access_policies: false,
            certificates: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Access policies and requests
// ---------------------------------------------------------------------------

/// How members get access to a target.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    /// Members use it per their role.
    #[default]
    Direct,
    /// A member asks for a time window and an approver grants it.
    Approval,
    /// From a later version: treated as `approval` (fail closed).
    #[serde(other)]
    Unknown,
}

impl AccessMode {
    pub fn requires_approval(self) -> bool {
        self != AccessMode::Direct
    }
}

/// What an access policy or a request applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AccessTargetKind {
    Vault,
    Group,
    Host,
    #[serde(other)]
    Unknown,
}

impl AccessTargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AccessTargetKind::Vault => "vault",
            AccessTargetKind::Group => "group",
            AccessTargetKind::Host => "host",
            AccessTargetKind::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "vault" => AccessTargetKind::Vault,
            "group" => AccessTargetKind::Group,
            "host" => AccessTargetKind::Host,
            _ => AccessTargetKind::Unknown,
        }
    }
}

/// Longest access window a policy may allow (7 days).
pub const MAX_ACCESS_MINUTES: u32 = 10_080;

/// Rules for a host, a group (its hosts) or a whole vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(default)]
pub struct AccessPolicy {
    pub mode: AccessMode,
    /// Who approves (users with access to the vault); empty: the vault's
    /// managers.
    pub approvers: Vec<Uuid>,
    /// Longest window a request may ask for.
    pub max_minutes: u32,
    /// A pending request expires after this many minutes.
    pub request_ttl_minutes: u32,
    /// The requester may approve their own request if they are an approver
    /// (single-person teams).
    pub allow_self_approval: bool,
    /// Vault managers need a request too.
    pub require_for_managers: bool,
    /// Certificate principals for these hosts (templates); `None`: the
    /// team's.
    pub principals: Option<Vec<String>>,
    /// Certificate TTL cap for these hosts.
    pub cert_ttl_minutes: Option<u32>,
    pub extensions: Option<Vec<String>>,
    pub source_address: Option<String>,
    pub force_command: Option<String>,
    /// Sessions on these hosts are always recorded.
    pub record_sessions: bool,
}

impl Default for AccessPolicy {
    fn default() -> Self {
        Self {
            mode: AccessMode::Direct,
            approvers: Vec::new(),
            max_minutes: 60,
            request_ttl_minutes: 240,
            allow_self_approval: false,
            require_for_managers: false,
            principals: None,
            cert_ttl_minutes: None,
            extensions: None,
            source_address: None,
            force_command: None,
            record_sessions: false,
        }
    }
}

impl AccessPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.max_minutes == 0 || self.max_minutes > MAX_ACCESS_MINUTES {
            return Err(CoreError::Invalid(format!(
                "max_minutes must be 1-{MAX_ACCESS_MINUTES}"
            )));
        }
        if !(5..=MAX_ACCESS_MINUTES).contains(&self.request_ttl_minutes) {
            return Err(CoreError::Invalid(format!(
                "request_ttl_minutes must be 5-{MAX_ACCESS_MINUTES}"
            )));
        }
        if self.approvers.len() > 50 {
            return Err(CoreError::Invalid("at most 50 approvers".into()));
        }
        if let Some(p) = &self.principals {
            validate_templates(p, "principals")?;
        }
        if let Some(t) = self.cert_ttl_minutes
            && (t == 0 || t > MAX_CERT_TTL_MINUTES)
        {
            return Err(CoreError::Invalid(format!(
                "cert_ttl_minutes must be 1-{MAX_CERT_TTL_MINUTES}"
            )));
        }
        if let Some(e) = &self.extensions {
            validate_extensions(e, "extensions")?;
        }
        if let Some(s) = &self.source_address {
            validate_source_address(s)?;
        }
        if let Some(c) = &self.force_command
            && (c.trim().is_empty() || c.len() > 1024 || c.contains('\0'))
        {
            return Err(CoreError::Invalid(
                "force_command must be 1-1024 characters".into(),
            ));
        }
        Ok(())
    }
}

/// An access policy as stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AccessPolicyRecord {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub target_kind: AccessTargetKind,
    pub target_id: Uuid,
    pub policy: AccessPolicy,
    pub updated_by: Uuid,
    pub updated_at: i64,
}

/// State of an access request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AccessRequestStatus {
    Pending,
    Approved,
    Denied,
    Expired,
    Cancelled,
    Revoked,
    #[serde(other)]
    Unknown,
}

impl AccessRequestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            AccessRequestStatus::Pending => "pending",
            AccessRequestStatus::Approved => "approved",
            AccessRequestStatus::Denied => "denied",
            AccessRequestStatus::Expired => "expired",
            AccessRequestStatus::Cancelled => "cancelled",
            AccessRequestStatus::Revoked => "revoked",
            AccessRequestStatus::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "pending" => AccessRequestStatus::Pending,
            "approved" => AccessRequestStatus::Approved,
            "denied" => AccessRequestStatus::Denied,
            "expired" => AccessRequestStatus::Expired,
            "cancelled" => AccessRequestStatus::Cancelled,
            "revoked" => AccessRequestStatus::Revoked,
            _ => AccessRequestStatus::Unknown,
        }
    }
}

/// A member's request for temporary access.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AccessRequest {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub target_kind: AccessTargetKind,
    pub target_id: Uuid,
    /// Name of the host, group or vault when it was asked.
    pub target_label: String,
    pub requester_id: Uuid,
    #[serde(default)]
    pub requester_name: String,
    #[serde(default)]
    pub requester_email: String,
    pub reason: String,
    /// Requested (or, once approved, granted) window length.
    pub minutes: u32,
    pub status: AccessRequestStatus,
    pub created_at: i64,
    /// A pending request expires at this time.
    pub expires_at: i64,
    #[serde(default)]
    pub decided_by: Option<Uuid>,
    #[serde(default)]
    pub decided_by_name: Option<String>,
    #[serde(default)]
    pub decided_at: Option<i64>,
    #[serde(default)]
    pub decision_reason: Option<String>,
    /// Window of an approved request.
    #[serde(default)]
    pub starts_at: Option<i64>,
    #[serde(default)]
    pub ends_at: Option<i64>,
    #[serde(default)]
    pub self_approved: bool,
    /// Approved and inside its window right now (computed).
    #[serde(default)]
    pub active: bool,
}

impl AccessRequest {
    /// Approved and inside its window at `now`.
    pub fn is_active(&self, now: i64) -> bool {
        self.status == AccessRequestStatus::Approved
            && self.starts_at.is_some_and(|s| s <= now)
            && self.ends_at.is_some_and(|e| e > now)
    }
}

/// What a member can do with one host (`GET /hosts/{id}/access`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct HostAccess {
    pub host_id: Uuid,
    pub vault_id: Uuid,
    pub mode: AccessMode,
    /// The effective policy and what it is set on (`None`: no policy).
    #[serde(default)]
    pub policy: Option<AccessPolicyRecord>,
    /// Allowed without a request (direct, or a manager exempt from it).
    pub exempt: bool,
    /// Your active window on it, if any.
    #[serde(default)]
    pub grant: Option<AccessRequest>,
    /// Your pending request on it, if any.
    #[serde(default)]
    pub pending: Option<AccessRequest>,
    /// You may ask for access now.
    pub can_request: bool,
    /// Access is allowed right now (exempt or an active window).
    pub allowed: bool,
    /// The vault's owner has an active CA.
    pub certificates: bool,
    /// The host (or its group) uses team certificates.
    pub team_certificate: bool,
    pub record_required: bool,
    pub ai_allowed: bool,
    pub reveal_allowed: bool,
    /// Longest window you may ask for.
    pub max_minutes: u32,
}

/// A team that requires 2FA from you (login and `/me`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Team2fa {
    pub team_id: Uuid,
    pub team_name: String,
    /// End of your grace period.
    pub deadline: i64,
    /// The grace period is over: the team's vaults are hidden until you
    /// enable 2FA.
    pub blocked: bool,
}

// ---------------------------------------------------------------------------
// SSH certificate authority (public records)
// ---------------------------------------------------------------------------

/// State of a CA key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum CaStatus {
    /// Signs new certificates.
    Active,
    /// Replaced by a rotation: still published until `retire_at`.
    Retiring,
    Retired,
    #[serde(other)]
    Unknown,
}

impl CaStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            CaStatus::Active => "active",
            CaStatus::Retiring => "retiring",
            CaStatus::Retired => "retired",
            CaStatus::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "active" => CaStatus::Active,
            "retiring" => CaStatus::Retiring,
            "retired" => CaStatus::Retired,
            _ => CaStatus::Unknown,
        }
    }
}

/// Public part of a CA key (the private key never leaves the server).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CaInfo {
    pub id: Uuid,
    #[serde(default)]
    pub owner_team_id: Option<Uuid>,
    #[serde(default)]
    pub owner_user_id: Option<Uuid>,
    /// `ssh-ed25519` or `ecdsa-sha2-nistp256`.
    pub algorithm: String,
    /// OpenSSH public key line.
    pub public_key: String,
    pub fingerprint: String,
    pub status: CaStatus,
    pub created_by: Uuid,
    pub created_at: i64,
    #[serde(default)]
    pub retire_at: Option<i64>,
    #[serde(default)]
    pub retired_at: Option<i64>,
}

/// A certificate the server issued (its record, not the certificate).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IssuedCertificate {
    pub serial: i64,
    pub ca_id: Uuid,
    pub user_id: Uuid,
    #[serde(default)]
    pub user_email: Option<String>,
    #[serde(default)]
    pub vault_id: Option<Uuid>,
    #[serde(default)]
    pub host_id: Option<Uuid>,
    #[serde(default)]
    pub request_id: Option<Uuid>,
    #[serde(default)]
    pub device_id: Option<Uuid>,
    /// `device`, `server` or `credentials`.
    pub purpose: String,
    pub key_fingerprint: String,
    pub key_id: String,
    pub principals: Vec<String>,
    pub valid_after: i64,
    pub valid_before: i64,
    pub created_at: i64,
    #[serde(default)]
    pub revoked_at: Option<i64>,
    #[serde(default)]
    pub revoked_by: Option<Uuid>,
    #[serde(default)]
    pub revoke_reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Principals
// ---------------------------------------------------------------------------

/// Most principals in one certificate.
pub const MAX_PRINCIPALS: usize = 16;

/// Values for the principal templates.
#[derive(Debug, Clone, Default)]
pub struct PrincipalContext {
    /// The host's effective username.
    pub login: Option<String>,
    /// The member's principal (`team_members.principal` or from the email).
    pub member: String,
    pub email: String,
    pub user_id: Uuid,
}

/// Default principal of a member: the email's local part, lowercase, with
/// every character outside `[a-z0-9._-]` replaced by `_` (at most 64).
pub fn member_principal(email: &str) -> String {
    let local = email.split('@').next().unwrap_or(email).to_lowercase();
    let p: String = local
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if p.is_empty() { "user".into() } else { p }
}

/// A principal as it goes in a certificate: 1-64 of `[A-Za-z0-9._@+-]`.
pub fn validate_principal(p: &str) -> Result<()> {
    let ok = !p.is_empty()
        && p.len() <= 64
        && p.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '+' | '-'));
    if ok {
        Ok(())
    } else {
        Err(CoreError::Invalid(format!(
            "invalid principal \"{p}\": 1-64 letters, digits or . _ @ + -"
        )))
    }
}

const PLACEHOLDERS: [&str; 4] = ["{login}", "{member}", "{email}", "{user_id}"];

fn validate_templates(list: &[String], field: &str) -> Result<()> {
    if list.is_empty() || list.len() > MAX_PRINCIPALS {
        return Err(CoreError::Invalid(format!(
            "{field}: 1-{MAX_PRINCIPALS} principals"
        )));
    }
    for t in list {
        // Placeholders are replaced by valid values; check the rest.
        let mut rest = t.clone();
        for p in PLACEHOLDERS {
            rest = rest.replace(p, "x");
        }
        if rest.contains('{') || rest.contains('}') {
            return Err(CoreError::Invalid(format!(
                "{field}: unknown placeholder in \"{t}\" (use {{login}}, {{member}}, {{email}} or {{user_id}})"
            )));
        }
        validate_principal(&rest).map_err(|_| {
            CoreError::Invalid(format!("{field}: invalid principal template \"{t}\""))
        })?;
    }
    Ok(())
}

/// Expands principal templates: invalid or empty results are dropped,
/// duplicates removed, at most [`MAX_PRINCIPALS`].
pub fn expand_principals(templates: &[String], ctx: &PrincipalContext) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in templates {
        if t.contains("{login}") && ctx.login.as_deref().is_none_or(str::is_empty) {
            continue;
        }
        let p = t
            .replace("{login}", ctx.login.as_deref().unwrap_or(""))
            .replace("{member}", &ctx.member)
            .replace("{email}", &ctx.email)
            .replace("{user_id}", &ctx.user_id.to_string());
        if validate_principal(&p).is_ok() && !out.contains(&p) {
            out.push(p);
        }
        if out.len() == MAX_PRINCIPALS {
            break;
        }
    }
    out
}

fn validate_extensions(list: &[String], field: &str) -> Result<()> {
    for e in list {
        if !CERT_EXTENSIONS.contains(&e.as_str()) {
            return Err(CoreError::Invalid(format!(
                "{field}: unknown extension \"{e}\" (allowed: {})",
                CERT_EXTENSIONS.join(", ")
            )));
        }
    }
    Ok(())
}

/// A `source-address` list: comma-separated addresses or CIDRs.
pub fn validate_source_address(s: &str) -> Result<()> {
    let bad = || CoreError::Invalid(format!("invalid source_address \"{s}\""));
    let items: Vec<&str> = s.split(',').map(str::trim).collect();
    if items.is_empty() || items.len() > 32 {
        return Err(bad());
    }
    for item in items {
        let (addr, prefix) = match item.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (item, None),
        };
        let ip: IpAddr = addr.parse().map_err(|_| bad())?;
        if let Some(p) = prefix {
            let p: u8 = p.parse().map_err(|_| bad())?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            if p > max {
                return Err(bad());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principals_expand_and_validate() {
        let ctx = PrincipalContext {
            login: Some("deploy".into()),
            member: member_principal("Ana.Pérez+ops@Example.com"),
            email: "ana@example.com".into(),
            user_id: Uuid::nil(),
        };
        assert_eq!(ctx.member, "ana.p_rez_ops");
        let t = vec![
            "{login}".to_string(),
            "prod-{member}".into(),
            "{login}".into(),
            "{email}".into(),
        ];
        assert_eq!(
            expand_principals(&t, &ctx),
            vec!["deploy", "prod-ana.p_rez_ops", "ana@example.com"]
        );
        // No login: templates with {login} are skipped.
        let ctx2 = PrincipalContext {
            login: None,
            ..ctx.clone()
        };
        assert_eq!(
            expand_principals(&["{login}".into()], &ctx2),
            Vec::<String>::new()
        );
        assert!(validate_templates(&["{bad}".into()], "p").is_err());
        assert!(validate_templates(&["a b".into()], "p").is_err());
        assert!(validate_templates(&[], "p").is_err());
        assert!(validate_templates(&["root".into(), "{member}-x".into()], "p").is_ok());
    }

    #[test]
    fn policies_validate_and_default() {
        let p: TeamPolicy = serde_json::from_str("{}").unwrap();
        assert_eq!(p, TeamPolicy::default());
        assert!(p.allow_reveal && p.ai.allowed && p.networks_allowed);
        p.validate().unwrap();
        let mut bad = p.clone();
        bad.ca.max_ttl_minutes = 2000;
        assert!(bad.validate().is_err());
        let mut bad = p.clone();
        bad.ca.extensions = vec!["permit-everything".into()];
        assert!(bad.validate().is_err());
        assert!(validate_source_address("10.0.0.0/8, 192.168.1.5,2001:db8::/32").is_ok());
        assert!(validate_source_address("10.0.0.0/33").is_err());
        assert!(validate_source_address("example.com").is_err());
        // Unknown values from a later version fail closed.
        let a: AccessPolicy = serde_json::from_str(r#"{"mode":"quorum"}"#).unwrap();
        assert!(a.mode.requires_approval());
        let ai: AiPolicy = serde_json::from_str(r#"{"approval":"twice"}"#).unwrap();
        assert!(ai.approval.always());
        let mut ap = AccessPolicy::default();
        ap.validate().unwrap();
        ap.max_minutes = 0;
        assert!(ap.validate().is_err());
    }

    #[test]
    fn twofa_deadline() {
        let mut p = TeamPolicy::default();
        assert_eq!(p.twofa_deadline(1000), None);
        p.require_2fa = true;
        p.require_2fa_since = Some(10_000);
        p.grace_days = 1;
        assert_eq!(p.twofa_deadline(1000), Some(10_000 + 86_400_000));
        assert_eq!(p.twofa_deadline(20_000), Some(20_000 + 86_400_000));
    }
}

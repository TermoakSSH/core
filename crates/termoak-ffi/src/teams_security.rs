//! Teams security for the apps (0.7 phase 4b, docs-next/TEAMS-SECURITY.md
//! §9): the team SSH CA, certificates, team policies and 2FA compliance,
//! access policies and temporary access requests, mandatory recordings.
//!
//! Every call is on `TermoakCore` (the current or bound account) and on
//! `AccountHandle`. Team CA calls take `team_id: None` for the personal CA.
//! Servers without the feature answer `NotFound` (check `/info`
//! `features.teams_security` with `server_features`).

use std::sync::Arc;

use serde_json::{Value, json};
use termoak_core::access as ac;

use crate::accounts::AccountHandle;
use crate::error::{Result, TermoakError};
use crate::models::{parse_id, parse_opt_id};
use crate::runtime::run;
use crate::vault::TermoakCore;

fn from_value<T: serde::de::DeserializeOwned>(v: Value) -> Result<T> {
    serde_json::from_value(v)
        .map_err(|e| TermoakError::Server(format!("unexpected server response: {e}")))
}

fn ids(v: &[uuid::Uuid]) -> Vec<String> {
    v.iter().map(|i| i.to_string()).collect()
}

fn parse_ids(v: &[String]) -> Result<Vec<uuid::Uuid>> {
    v.iter().map(|s| parse_id(s)).collect()
}

/// `/api/v1/teams/{id}/ca` or `/api/v1/me/ca`.
fn ca_base(team_id: &Option<String>) -> Result<String> {
    Ok(match parse_opt_id(team_id)? {
        Some(t) => format!("/api/v1/teams/{t}/ca"),
        None => "/api/v1/me/ca".into(),
    })
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

/// Approval level of AI actions on a team's hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AiApprovalLevel {
    /// The task's own mode.
    Default,
    /// Every action on a host needs an approval.
    Always,
}

impl From<ac::AiApproval> for AiApprovalLevel {
    fn from(a: ac::AiApproval) -> Self {
        if a.always() {
            Self::Always
        } else {
            Self::Default
        }
    }
}

impl From<AiApprovalLevel> for ac::AiApproval {
    fn from(a: AiApprovalLevel) -> Self {
        match a {
            AiApprovalLevel::Default => Self::Default,
            AiApprovalLevel::Always => Self::Always,
        }
    }
}

/// What the team's policies mean for you in a vault (`VaultInfo.policy`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultPolicyInfo {
    pub team_id: Option<String>,
    /// You may reveal, copy and export secrets (as far as your role allows).
    pub reveal_allowed: bool,
    /// AI actions are allowed on these hosts.
    pub ai_allowed: bool,
    pub ai_approval: AiApprovalLevel,
    /// Hosts may use private networks.
    pub networks_allowed: bool,
    /// Every session on these hosts is recorded.
    pub record_sessions: bool,
    pub require_2fa: bool,
    /// Some hosts need approval or have rules (`host_access`).
    pub access_policies: bool,
    /// The vault's owner has an SSH CA ("Team certificate" available).
    pub certificates: bool,
}

impl From<&ac::VaultPolicy> for VaultPolicyInfo {
    fn from(p: &ac::VaultPolicy) -> Self {
        Self {
            team_id: p.team_id.map(|t| t.to_string()),
            reveal_allowed: p.reveal_allowed,
            ai_allowed: p.ai_allowed,
            ai_approval: p.ai_approval.into(),
            networks_allowed: p.networks_allowed,
            record_sessions: p.record_sessions,
            require_2fa: p.require_2fa,
            access_policies: p.access_policies,
            certificates: p.certificates,
        }
    }
}

/// Defaults of a CA owner's certificates.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CertificatePolicy {
    pub default_ttl_minutes: u32,
    pub max_ttl_minutes: u32,
    /// Templates: `{login}`, `{member}`, `{email}`, `{user_id}` or names.
    pub principals: Vec<String>,
    /// `permit-pty`, `permit-port-forwarding`, `permit-agent-forwarding`,
    /// `permit-X11-forwarding`, `permit-user-rc`.
    pub extensions: Vec<String>,
    /// `source-address` (comma-separated CIDRs).
    pub source_address: Option<String>,
}

impl From<ac::CaPolicy> for CertificatePolicy {
    fn from(p: ac::CaPolicy) -> Self {
        Self {
            default_ttl_minutes: p.default_ttl_minutes,
            max_ttl_minutes: p.max_ttl_minutes,
            principals: p.principals,
            extensions: p.extensions,
            source_address: p.source_address,
        }
    }
}

impl From<CertificatePolicy> for ac::CaPolicy {
    fn from(p: CertificatePolicy) -> Self {
        Self {
            default_ttl_minutes: p.default_ttl_minutes,
            max_ttl_minutes: p.max_ttl_minutes,
            principals: p.principals,
            extensions: p.extensions,
            source_address: p.source_address.filter(|s| !s.trim().is_empty()),
        }
    }
}

/// A team's security policy.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TeamSecurityPolicy {
    pub require_2fa: bool,
    /// When `require_2fa` was turned on (set by the server).
    pub require_2fa_since: Option<i64>,
    /// Days a member without 2FA keeps access (0-90).
    pub grace_days: u32,
    /// Editors may reveal and export secrets.
    pub allow_reveal: bool,
    pub ai_allowed: bool,
    pub ai_approval: AiApprovalLevel,
    pub networks_allowed: bool,
    pub record_sessions: bool,
    pub certificates: CertificatePolicy,
}

impl From<ac::TeamPolicy> for TeamSecurityPolicy {
    fn from(p: ac::TeamPolicy) -> Self {
        Self {
            require_2fa: p.require_2fa,
            require_2fa_since: p.require_2fa_since,
            grace_days: p.grace_days,
            allow_reveal: p.allow_reveal,
            ai_allowed: p.ai.allowed,
            ai_approval: p.ai.approval.into(),
            networks_allowed: p.networks_allowed,
            record_sessions: p.record_sessions,
            certificates: p.ca.into(),
        }
    }
}

impl From<TeamSecurityPolicy> for ac::TeamPolicy {
    fn from(p: TeamSecurityPolicy) -> Self {
        Self {
            require_2fa: p.require_2fa,
            require_2fa_since: p.require_2fa_since,
            grace_days: p.grace_days,
            allow_reveal: p.allow_reveal,
            ai: ac::AiPolicy {
                allowed: p.ai_allowed,
                approval: p.ai_approval.into(),
            },
            networks_allowed: p.networks_allowed,
            record_sessions: p.record_sessions,
            ca: p.certificates.into(),
            notifications: None,
        }
    }
}

/// A member's 2FA state under the team's policy.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TeamComplianceMember {
    pub user_id: String,
    pub email: String,
    pub name: String,
    pub role: crate::TeamRole,
    pub totp_enabled: bool,
    /// End of the member's grace period (if 2FA is required and missing).
    pub deadline: Option<i64>,
    /// Over the grace period: the team's vaults are hidden for them.
    pub blocked: bool,
    /// Certificate principal set by an admin.
    pub principal: Option<String>,
}

/// A team that requires 2FA from you (`team_2fa` of sign-in and `/me`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Team2faRequirement {
    pub team_id: String,
    pub team_name: String,
    pub deadline: i64,
    pub blocked: bool,
}

// ---------------------------------------------------------------------------
// CA and certificates
// ---------------------------------------------------------------------------

/// A CA key (public part).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CaKeyInfo {
    pub id: String,
    /// `ssh-ed25519` or `ecdsa-sha2-nistp256`.
    pub algorithm: String,
    pub public_key: String,
    pub fingerprint: String,
    /// `active`, `retiring` (still published until `retire_at`) or `retired`.
    pub status: String,
    pub created_at: i64,
    pub retire_at: Option<i64>,
}

impl From<ac::CaInfo> for CaKeyInfo {
    fn from(c: ac::CaInfo) -> Self {
        Self {
            id: c.id.to_string(),
            algorithm: c.algorithm,
            public_key: c.public_key,
            fingerprint: c.fingerprint,
            status: c.status.as_str().into(),
            created_at: c.created_at,
            retire_at: c.retire_at,
        }
    }
}

/// A CA owner's certificate authority and how hosts trust it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CaOverview {
    /// The active CA (`None`: not configured).
    pub ca: Option<CaKeyInfo>,
    /// Retiring CAs still published.
    pub previous: Vec<CaKeyInfo>,
    /// Content of the `TrustedUserCAKeys` file (every published key).
    pub keys_file: String,
    /// Lines for `sshd_config`.
    pub sshd_config: Vec<String>,
    /// Optional lines (`RevokedKeys`, `AuthorizedPrincipalsFile`).
    pub sshd_config_optional: Vec<String>,
    /// Public URLs of the keys file and the KRL; the install script's URL
    /// (needs a manager's token: `ca_install_script`).
    pub keys_url: String,
    pub krl_url: String,
    pub install_url: String,
    pub policy: CertificatePolicy,
    /// You can change it (team owner/admin, or your personal CA).
    pub can_manage: bool,
}

fn overview(v: &Value) -> Result<CaOverview> {
    let ca: Option<ac::CaInfo> = from_value(v["ca"].clone())?;
    let previous: Vec<ac::CaInfo> = from_value(v["previous"].clone()).unwrap_or_default();
    let policy: ac::CaPolicy = from_value(v["policy"].clone()).unwrap_or_default();
    let strings = |k: &str| -> Vec<String> {
        v[k].as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    Ok(CaOverview {
        ca: ca.map(Into::into),
        previous: previous.into_iter().map(Into::into).collect(),
        keys_file: v["keys_file"].as_str().unwrap_or_default().into(),
        sshd_config: strings("sshd_config"),
        sshd_config_optional: strings("sshd_config_optional"),
        keys_url: v["urls"]["keys"].as_str().unwrap_or_default().into(),
        krl_url: v["urls"]["krl"].as_str().unwrap_or_default().into(),
        install_url: v["urls"]["install"].as_str().unwrap_or_default().into(),
        policy: policy.into(),
        can_manage: v["can_manage"].as_bool().unwrap_or(false),
    })
}

/// A certificate the server issued (its record).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IssuedCertificateInfo {
    pub serial: i64,
    pub user_id: String,
    pub user_email: Option<String>,
    pub host_id: Option<String>,
    pub vault_id: Option<String>,
    pub request_id: Option<String>,
    /// `device`, `server` or `credentials`.
    pub purpose: String,
    pub key_fingerprint: String,
    pub key_id: String,
    pub principals: Vec<String>,
    pub valid_after: i64,
    pub valid_before: i64,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
    pub revoke_reason: Option<String>,
}

impl From<ac::IssuedCertificate> for IssuedCertificateInfo {
    fn from(c: ac::IssuedCertificate) -> Self {
        Self {
            serial: c.serial,
            user_id: c.user_id.to_string(),
            user_email: c.user_email,
            host_id: c.host_id.map(|i| i.to_string()),
            vault_id: c.vault_id.map(|i| i.to_string()),
            request_id: c.request_id.map(|i| i.to_string()),
            purpose: c.purpose,
            key_fingerprint: c.key_fingerprint,
            key_id: c.key_id,
            principals: c.principals,
            valid_after: c.valid_after,
            valid_before: c.valid_before,
            created_at: c.created_at,
            revoked_at: c.revoked_at,
            revoke_reason: c.revoke_reason,
        }
    }
}

/// What to revoke.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum RevokeTarget {
    /// One certificate.
    Serial { serial: i64 },
    /// Every unexpired certificate of a user.
    User { user_id: String },
    /// A public key, forever (also in the KRL).
    PublicKey { public_key: String },
}

/// A new certificate (normally the engine asks for them by itself when a
/// host uses "Team certificate").
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct NewCertificate {
    /// OpenSSH certificate line.
    pub certificate: String,
    pub serial: i64,
    pub key_id: String,
    pub principals: Vec<String>,
    pub valid_after: i64,
    pub valid_before: i64,
    pub request_id: Option<String>,
}

/// What an OpenSSH certificate says.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CertificateDetails {
    pub key_id: String,
    pub serial: u64,
    /// `user` or `host`.
    pub cert_type: String,
    pub principals: Vec<String>,
    /// Milliseconds since the epoch.
    pub valid_after: i64,
    pub valid_before: i64,
    pub extensions: Vec<String>,
    pub critical_options: Vec<String>,
    pub key_fingerprint: String,
    pub ca_fingerprint: String,
}

/// Reads an OpenSSH certificate (principals, validity, key id, CA).
#[uniffi::export]
pub fn parse_certificate(text: String) -> Result<CertificateDetails> {
    let d = termoak_ssh::ca::parse_certificate(&text)
        .map_err(|e| TermoakError::Invalid(e.to_string()))?;
    Ok(CertificateDetails {
        key_id: d.key_id,
        serial: d.serial,
        cert_type: d.cert_type,
        principals: d.principals,
        valid_after: (d.valid_after as i64).saturating_mul(1000),
        valid_before: (d.valid_before.min(i64::MAX as u64 / 1000) as i64) * 1000,
        extensions: d.extensions,
        critical_options: d.critical_options,
        key_fingerprint: d.key_fingerprint,
        ca_fingerprint: d.ca_fingerprint,
    })
}

// ---------------------------------------------------------------------------
// Access policies and requests
// ---------------------------------------------------------------------------

/// How members reach a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AccessMode {
    Direct,
    /// A member asks for a time window; an approver grants it.
    Approval,
}

impl From<ac::AccessMode> for AccessMode {
    fn from(m: ac::AccessMode) -> Self {
        if m.requires_approval() {
            Self::Approval
        } else {
            Self::Direct
        }
    }
}

/// What a policy or request is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AccessTargetKind {
    Vault,
    Group,
    Host,
    Unknown,
}

impl From<ac::AccessTargetKind> for AccessTargetKind {
    fn from(k: ac::AccessTargetKind) -> Self {
        match k {
            ac::AccessTargetKind::Vault => Self::Vault,
            ac::AccessTargetKind::Group => Self::Group,
            ac::AccessTargetKind::Host => Self::Host,
            ac::AccessTargetKind::Unknown => Self::Unknown,
        }
    }
}

impl AccessTargetKind {
    fn as_str(self) -> Result<&'static str> {
        match self {
            Self::Vault => Ok("vault"),
            Self::Group => Ok("group"),
            Self::Host => Ok("host"),
            Self::Unknown => Err(TermoakError::Invalid(
                "choose a host, group or vault".into(),
            )),
        }
    }
}

/// Rules for a host, a group or a vault.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccessPolicyInfo {
    pub mode: AccessMode,
    /// User ids; empty: the vault's managers.
    #[uniffi(default)]
    pub approvers: Vec<String>,
    #[uniffi(default = 60)]
    pub max_minutes: u32,
    #[uniffi(default = 240)]
    pub request_ttl_minutes: u32,
    #[uniffi(default = false)]
    pub allow_self_approval: bool,
    #[uniffi(default = false)]
    pub require_for_managers: bool,
    #[uniffi(default)]
    pub principals: Option<Vec<String>>,
    #[uniffi(default)]
    pub cert_ttl_minutes: Option<u32>,
    #[uniffi(default)]
    pub extensions: Option<Vec<String>>,
    #[uniffi(default)]
    pub source_address: Option<String>,
    #[uniffi(default)]
    pub force_command: Option<String>,
    #[uniffi(default = false)]
    pub record_sessions: bool,
}

impl From<ac::AccessPolicy> for AccessPolicyInfo {
    fn from(p: ac::AccessPolicy) -> Self {
        Self {
            mode: p.mode.into(),
            approvers: ids(&p.approvers),
            max_minutes: p.max_minutes,
            request_ttl_minutes: p.request_ttl_minutes,
            allow_self_approval: p.allow_self_approval,
            require_for_managers: p.require_for_managers,
            principals: p.principals,
            cert_ttl_minutes: p.cert_ttl_minutes,
            extensions: p.extensions,
            source_address: p.source_address,
            force_command: p.force_command,
            record_sessions: p.record_sessions,
        }
    }
}

impl AccessPolicyInfo {
    fn to_core(&self) -> Result<ac::AccessPolicy> {
        Ok(ac::AccessPolicy {
            mode: match self.mode {
                AccessMode::Direct => ac::AccessMode::Direct,
                AccessMode::Approval => ac::AccessMode::Approval,
            },
            approvers: parse_ids(&self.approvers)?,
            max_minutes: self.max_minutes,
            request_ttl_minutes: self.request_ttl_minutes,
            allow_self_approval: self.allow_self_approval,
            require_for_managers: self.require_for_managers,
            principals: self.principals.clone(),
            cert_ttl_minutes: self.cert_ttl_minutes,
            extensions: self.extensions.clone(),
            source_address: self.source_address.clone().filter(|s| !s.trim().is_empty()),
            force_command: self.force_command.clone().filter(|s| !s.trim().is_empty()),
            record_sessions: self.record_sessions,
        })
    }
}

/// A stored access policy.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccessPolicyRecord {
    pub id: String,
    pub vault_id: String,
    pub target_kind: AccessTargetKind,
    pub target_id: String,
    pub policy: AccessPolicyInfo,
    pub updated_by: String,
    pub updated_at: i64,
}

impl From<ac::AccessPolicyRecord> for AccessPolicyRecord {
    fn from(r: ac::AccessPolicyRecord) -> Self {
        Self {
            id: r.id.to_string(),
            vault_id: r.vault_id.to_string(),
            target_kind: r.target_kind.into(),
            target_id: r.target_id.to_string(),
            policy: r.policy.into(),
            updated_by: r.updated_by.to_string(),
            updated_at: r.updated_at,
        }
    }
}

/// State of an access request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AccessRequestStatus {
    Pending,
    Approved,
    Denied,
    Expired,
    Cancelled,
    Revoked,
    Unknown,
}

impl From<ac::AccessRequestStatus> for AccessRequestStatus {
    fn from(s: ac::AccessRequestStatus) -> Self {
        use ac::AccessRequestStatus as S;
        match s {
            S::Pending => Self::Pending,
            S::Approved => Self::Approved,
            S::Denied => Self::Denied,
            S::Expired => Self::Expired,
            S::Cancelled => Self::Cancelled,
            S::Revoked => Self::Revoked,
            S::Unknown => Self::Unknown,
        }
    }
}

/// A request for temporary access.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccessRequestInfo {
    pub id: String,
    pub vault_id: String,
    pub target_kind: AccessTargetKind,
    pub target_id: String,
    pub target_label: String,
    pub requester_id: String,
    pub requester_name: String,
    pub requester_email: String,
    pub reason: String,
    /// Asked for (or, once approved, granted) minutes.
    pub minutes: u32,
    pub status: AccessRequestStatus,
    pub created_at: i64,
    /// A pending request expires then.
    pub expires_at: i64,
    pub decided_by: Option<String>,
    pub decided_by_name: Option<String>,
    pub decided_at: Option<i64>,
    pub decision_reason: Option<String>,
    pub starts_at: Option<i64>,
    pub ends_at: Option<i64>,
    pub self_approved: bool,
    /// Approved and inside its window now.
    pub active: bool,
    /// You may approve or deny it (pending) / revoke it (active).
    pub can_decide: bool,
}

fn request_info(v: &Value) -> Result<AccessRequestInfo> {
    let r: ac::AccessRequest = from_value(v.clone())?;
    Ok(AccessRequestInfo {
        id: r.id.to_string(),
        vault_id: r.vault_id.to_string(),
        target_kind: r.target_kind.into(),
        target_id: r.target_id.to_string(),
        target_label: r.target_label,
        requester_id: r.requester_id.to_string(),
        requester_name: r.requester_name,
        requester_email: r.requester_email,
        reason: r.reason,
        minutes: r.minutes,
        status: r.status.into(),
        created_at: r.created_at,
        expires_at: r.expires_at,
        decided_by: r.decided_by.map(|i| i.to_string()),
        decided_by_name: r.decided_by_name,
        decided_at: r.decided_at,
        decision_reason: r.decision_reason,
        starts_at: r.starts_at,
        ends_at: r.ends_at,
        self_approved: r.self_approved,
        active: r.active,
        can_decide: v["can_decide"].as_bool().unwrap_or(false),
    })
}

/// Which requests to list.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum AccessRequestScope {
    /// Yours.
    Mine,
    /// The ones you can approve.
    Approvals,
    /// Every request of a vault you manage.
    Vault { vault_id: String },
}

/// What you can do with one host now (`host_access`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HostAccessInfo {
    pub host_id: String,
    pub vault_id: String,
    pub mode: AccessMode,
    /// The policy that applies and what it is set on.
    pub policy: Option<AccessPolicyRecord>,
    /// Allowed without a request (direct, or an exempt manager).
    pub exempt: bool,
    /// Allowed right now (exempt or inside a window).
    pub allowed: bool,
    pub grant: Option<AccessRequestInfo>,
    pub pending: Option<AccessRequestInfo>,
    pub can_request: bool,
    pub max_minutes: u32,
    /// The vault's owner has a CA.
    pub certificates: bool,
    /// The host uses team certificates.
    pub team_certificate: bool,
    pub record_required: bool,
    pub ai_allowed: bool,
    pub reveal_allowed: bool,
}

fn host_access_info(a: ac::HostAccess) -> Result<HostAccessInfo> {
    let req = |r: Option<ac::AccessRequest>| -> Result<Option<AccessRequestInfo>> {
        r.map(|r| request_info(&serde_json::to_value(r)?))
            .transpose()
    };
    Ok(HostAccessInfo {
        host_id: a.host_id.to_string(),
        vault_id: a.vault_id.to_string(),
        mode: a.mode.into(),
        policy: a.policy.map(Into::into),
        exempt: a.exempt,
        allowed: a.allowed,
        grant: req(a.grant)?,
        pending: req(a.pending)?,
        can_request: a.can_request,
        max_minutes: a.max_minutes,
        certificates: a.certificates,
        team_certificate: a.team_certificate,
        record_required: a.record_required,
        ai_allowed: a.ai_allowed,
        reveal_allowed: a.reveal_allowed,
    })
}

/// A recording of a session in a vault (managers).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultRecording {
    pub session_id: String,
    pub owner_id: String,
    pub owner_email: Option<String>,
    pub host_id: Option<String>,
    pub title: String,
    /// `server` or `device` (uploaded by an app).
    pub kind: String,
    pub created_at: i64,
    pub ended_at: Option<i64>,
}

// ---------------------------------------------------------------------------
// Calls
// ---------------------------------------------------------------------------

impl TermoakCore {
    /// The account of a host (bound, the host's, or the current one).
    async fn account_of_host(&self, host_id: uuid::Uuid) -> Result<Arc<termoak_client::Account>> {
        if let Some(a) = self.pinned {
            return Ok(self.ws.require_account(a)?);
        }
        let ws = self.ws.clone();
        let found = run(async move { Ok(ws.locate(host_id).await.ok()) })
            .await?
            .and_then(|i| i.scope.account());
        match found {
            Some(a) => Ok(self.ws.require_account(a)?),
            None => self.account_now(),
        }
    }
}

#[uniffi::export]
impl TermoakCore {
    // ----- CA -----

    /// The SSH CA of a team (`None`: your personal CA) and how hosts trust
    /// it.
    pub async fn ca_info(&self, team_id: Option<String>) -> Result<CaOverview> {
        let base = ca_base(&team_id)?;
        self.with_api(move |api| async move { overview(&api.get::<Value>(&base).await?) })
            .await
    }

    /// Creates the CA (`algorithm`: `ed25519` by default, or `ecdsa-p256`).
    pub async fn create_ca(
        &self,
        team_id: Option<String>,
        algorithm: Option<String>,
    ) -> Result<CaOverview> {
        let base = ca_base(&team_id)?;
        self.with_api(move |api| async move {
            overview(
                &api.post::<Value>(&base, &json!({"algorithm": algorithm}))
                    .await?,
            )
        })
        .await
    }

    /// Rotates the CA: the new one signs from now on; the old one stays
    /// published for `overlap_hours` (24 by default).
    pub async fn rotate_ca(
        &self,
        team_id: Option<String>,
        overlap_hours: Option<u32>,
    ) -> Result<CaOverview> {
        let base = ca_base(&team_id)?;
        self.with_api(move |api| async move {
            overview(
                &api.post::<Value>(
                    &format!("{base}/rotate"),
                    &json!({"overlap_hours": overlap_hours}),
                )
                .await?,
            )
        })
        .await
    }

    /// Turns the CA off (every key retired at once; no more certificates).
    /// `confirm`: the team's name (`personal` for your own CA).
    pub async fn disable_ca(&self, team_id: Option<String>, confirm: String) -> Result<()> {
        let base = ca_base(&team_id)?;
        self.with_api(move |api| async move {
            let q: String = url::form_urlencoded::byte_serialize(confirm.as_bytes()).collect();
            api.delete(&format!("{base}?confirm={q}")).await?;
            Ok(())
        })
        .await
    }

    /// The install script for hosts (run as root: `sh install.sh`).
    pub async fn ca_install_script(
        &self,
        team_id: Option<String>,
        krl: bool,
        principals: bool,
        refresh: bool,
    ) -> Result<String> {
        let base = ca_base(&team_id)?;
        self.with_api(move |api| async move {
            Ok(api
                .get_text(&format!(
                    "{base}/install.sh?krl={}&principals={}&refresh={}",
                    krl as u8, principals as u8, refresh as u8
                ))
                .await?)
        })
        .await
    }

    /// Certificates issued by the CA (`active_only`: not expired or revoked).
    pub async fn ca_certificates(
        &self,
        team_id: Option<String>,
        user_id: Option<String>,
        active_only: bool,
    ) -> Result<Vec<IssuedCertificateInfo>> {
        let base = ca_base(&team_id)?;
        let user = parse_opt_id(&user_id)?;
        self.with_api(move |api| async move {
            let mut path = format!("{base}/certificates?active={}", active_only as u8);
            if let Some(u) = user {
                path.push_str(&format!("&user_id={u}"));
            }
            let list: Vec<ac::IssuedCertificate> = from_value(api.get(&path).await?)?;
            Ok(list.into_iter().map(Into::into).collect())
        })
        .await
    }

    /// Revokes certificates (or a key). Returns the revoked serials.
    pub async fn revoke_certificates(
        &self,
        team_id: Option<String>,
        target: RevokeTarget,
        reason: Option<String>,
    ) -> Result<Vec<i64>> {
        let base = ca_base(&team_id)?;
        let mut body = json!({"reason": reason});
        match target {
            RevokeTarget::Serial { serial } => body["serial"] = json!(serial),
            RevokeTarget::User { user_id } => body["user_id"] = json!(parse_id(&user_id)?),
            RevokeTarget::PublicKey { public_key } => body["public_key"] = json!(public_key),
        }
        self.with_api(move |api| async move {
            let v: Value = api.post(&format!("{base}/revoke"), &body).await?;
            Ok(from_value(v["revoked"].clone()).unwrap_or_default())
        })
        .await
    }

    /// Asks for a certificate for a key of your vaults (`key_id`) or, without
    /// one, for this device's ephemeral key, to connect to `host_id`. The
    /// engine does this by itself for hosts with "Team certificate".
    pub async fn request_certificate(
        &self,
        host_id: String,
        key_id: Option<String>,
        ttl_minutes: Option<u32>,
    ) -> Result<NewCertificate> {
        let host = parse_id(&host_id)?;
        let key = parse_opt_id(&key_id)?;
        let acc = self.account_of_host(host).await?;
        run(async move {
            let c = match key {
                Some(k) => {
                    acc.request_certificate(
                        host,
                        termoak_client::team_security::CertKey::VaultKey(k),
                        ttl_minutes,
                    )
                    .await?
                }
                None => {
                    let (private, _) = termoak_ssh::ca::ephemeral_key("termoak-ephemeral")
                        .map_err(termoak_client::ClientError::from)?;
                    acc.request_certificate(
                        host,
                        termoak_client::team_security::CertKey::Private {
                            private_key: &private,
                            passphrase: None,
                        },
                        ttl_minutes,
                    )
                    .await?
                }
            };
            Ok(NewCertificate {
                certificate: c.certificate,
                serial: c.serial,
                key_id: c.key_id,
                principals: c.principals,
                valid_after: c.valid_after,
                valid_before: c.valid_before,
                request_id: c.request_id.map(|i| i.to_string()),
            })
        })
        .await
    }

    /// Your recent certificates.
    pub async fn my_certificates(&self) -> Result<Vec<IssuedCertificateInfo>> {
        self.with_api(|api| async move {
            let list: Vec<ac::IssuedCertificate> =
                from_value(api.get("/api/v1/certificates").await?)?;
            Ok(list.into_iter().map(Into::into).collect())
        })
        .await
    }

    // ----- Team policy -----

    pub async fn team_policy(&self, team_id: String) -> Result<TeamSecurityPolicy> {
        let id = parse_id(&team_id)?;
        self.with_api(move |api| async move {
            let p: ac::TeamPolicy =
                from_value(api.get(&format!("/api/v1/teams/{id}/policy")).await?)?;
            Ok(p.into())
        })
        .await
    }

    /// Saves a team's policy (owners and admins). Turning on 2FA needs 2FA
    /// yourself (`policy_requires_2fa`).
    pub async fn set_team_policy(
        &self,
        team_id: String,
        policy: TeamSecurityPolicy,
    ) -> Result<TeamSecurityPolicy> {
        let id = parse_id(&team_id)?;
        let body = serde_json::to_value(ac::TeamPolicy::from(policy))?;
        self.with_api(move |api| async move {
            let p: ac::TeamPolicy = from_value(
                api.put(&format!("/api/v1/teams/{id}/policy"), &body)
                    .await?,
            )?;
            Ok(p.into())
        })
        .await
    }

    /// Members and their 2FA state (owners and admins).
    pub async fn team_compliance(&self, team_id: String) -> Result<Vec<TeamComplianceMember>> {
        let id = parse_id(&team_id)?;
        self.with_api(move |api| async move {
            let v: Value = api.get(&format!("/api/v1/teams/{id}/compliance")).await?;
            let mut out = Vec::new();
            for m in v["members"].as_array().cloned().unwrap_or_default() {
                out.push(TeamComplianceMember {
                    user_id: m["user_id"].as_str().unwrap_or_default().into(),
                    email: m["email"].as_str().unwrap_or_default().into(),
                    name: m["name"].as_str().unwrap_or_default().into(),
                    role: termoak_core::model::TeamRole::parse(
                        m["role"].as_str().unwrap_or("member"),
                    )
                    .into(),
                    totp_enabled: m["totp_enabled"].as_bool().unwrap_or(false),
                    deadline: m["deadline"].as_i64(),
                    blocked: m["blocked"].as_bool().unwrap_or(false),
                    principal: m["principal"].as_str().map(String::from),
                });
            }
            Ok(out)
        })
        .await
    }

    /// Sets (or clears) a member's certificate principal (`{member}`).
    pub async fn set_member_principal(
        &self,
        team_id: String,
        user_id: String,
        principal: Option<String>,
    ) -> Result<()> {
        let (t, u) = (parse_id(&team_id)?, parse_id(&user_id)?);
        self.with_api(move |api| async move {
            let _: Value = api
                .patch(
                    &format!("/api/v1/teams/{t}/members/{u}"),
                    &json!({"principal": principal.unwrap_or_default()}),
                )
                .await?;
            Ok(())
        })
        .await
    }

    /// Teams that require 2FA from you (deadline, blocked).
    pub async fn team_2fa_requirements(&self) -> Result<Vec<Team2faRequirement>> {
        self.with_api(|api| async move {
            let v: Value = api.get("/api/v1/me").await?;
            let list: Vec<ac::Team2fa> = from_value(v["team_2fa"].clone()).unwrap_or_default();
            Ok(list
                .into_iter()
                .map(|t| Team2faRequirement {
                    team_id: t.team_id.to_string(),
                    team_name: t.team_name,
                    deadline: t.deadline,
                    blocked: t.blocked,
                })
                .collect())
        })
        .await
    }

    // ----- Access policies -----

    pub async fn access_policies(&self, vault_id: String) -> Result<Vec<AccessPolicyRecord>> {
        let id = parse_id(&vault_id)?;
        self.with_api(move |api| async move {
            let list: Vec<ac::AccessPolicyRecord> = from_value(
                api.get(&format!("/api/v1/vaults/{id}/access-policies"))
                    .await?,
            )?;
            Ok(list.into_iter().map(Into::into).collect())
        })
        .await
    }

    /// Sets the policy of a host, group or the vault itself (managers).
    pub async fn set_access_policy(
        &self,
        vault_id: String,
        target_kind: AccessTargetKind,
        target_id: String,
        policy: AccessPolicyInfo,
    ) -> Result<AccessPolicyRecord> {
        let id = parse_id(&vault_id)?;
        let body = json!({
            "target_kind": target_kind.as_str()?,
            "target_id": parse_id(&target_id)?,
            "policy": policy.to_core()?,
        });
        self.with_api(move |api| async move {
            let r: ac::AccessPolicyRecord = from_value(
                api.put(&format!("/api/v1/vaults/{id}/access-policies"), &body)
                    .await?,
            )?;
            Ok(r.into())
        })
        .await
    }

    pub async fn delete_access_policy(&self, vault_id: String, policy_id: String) -> Result<()> {
        let (v, p) = (parse_id(&vault_id)?, parse_id(&policy_id)?);
        self.with_api(move |api| async move {
            api.delete(&format!("/api/v1/vaults/{v}/access-policies/{p}"))
                .await?;
            Ok(())
        })
        .await
    }

    /// What you can do with a host now (mode, window, pending request,
    /// recording, certificates).
    pub async fn host_access(&self, host_id: String) -> Result<HostAccessInfo> {
        let host = parse_id(&host_id)?;
        let acc = self.account_of_host(host).await?;
        let a = run(async move { Ok(acc.host_access(host, true).await?) }).await?;
        host_access_info(a)
    }

    // ----- Access requests -----

    pub async fn access_requests(
        &self,
        scope: AccessRequestScope,
        status: Option<AccessRequestStatus>,
    ) -> Result<Vec<AccessRequestInfo>> {
        let mut path = match scope {
            AccessRequestScope::Mine => "/api/v1/access-requests?scope=mine".to_string(),
            AccessRequestScope::Approvals => "/api/v1/access-requests?scope=approvals".to_string(),
            AccessRequestScope::Vault { vault_id } => {
                format!(
                    "/api/v1/access-requests?scope=vault&vault_id={}",
                    parse_id(&vault_id)?
                )
            }
        };
        if let Some(s) = status {
            let s = match s {
                AccessRequestStatus::Pending => "pending",
                AccessRequestStatus::Approved => "approved",
                AccessRequestStatus::Denied => "denied",
                AccessRequestStatus::Expired => "expired",
                AccessRequestStatus::Cancelled => "cancelled",
                AccessRequestStatus::Revoked => "revoked",
                AccessRequestStatus::Unknown => "",
            };
            if !s.is_empty() {
                path.push_str(&format!("&status={s}"));
            }
        }
        self.with_api(move |api| async move {
            let v: Value = api.get(&path).await?;
            v.as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(request_info)
                .collect()
        })
        .await
    }

    pub async fn access_request(&self, request_id: String) -> Result<AccessRequestInfo> {
        let id = parse_id(&request_id)?;
        self.with_api(move |api| async move {
            request_info(
                &api.get::<Value>(&format!("/api/v1/access-requests/{id}"))
                    .await?,
            )
        })
        .await
    }

    /// Asks for access to a host, group or vault for `minutes`.
    pub async fn create_access_request(
        &self,
        target_kind: AccessTargetKind,
        target_id: String,
        minutes: u32,
        reason: String,
    ) -> Result<AccessRequestInfo> {
        let key = match target_kind {
            AccessTargetKind::Host => "host_id",
            AccessTargetKind::Group => "group_id",
            AccessTargetKind::Vault => "vault_id",
            AccessTargetKind::Unknown => {
                return Err(TermoakError::Invalid(
                    "choose a host, group or vault".into(),
                ));
            }
        };
        let body = json!({key: parse_id(&target_id)?, "minutes": minutes, "reason": reason});
        let r = self
            .with_api(move |api| async move {
                request_info(&api.post::<Value>("/api/v1/access-requests", &body).await?)
            })
            .await?;
        if let Ok(acc) = self.account_now() {
            acc.forget_access();
        }
        Ok(r)
    }

    /// Approves a request; `minutes` may shorten the window.
    pub async fn approve_access_request(
        &self,
        request_id: String,
        minutes: Option<u32>,
        reason: Option<String>,
    ) -> Result<AccessRequestInfo> {
        self.decide(
            request_id,
            "approve",
            json!({"minutes": minutes, "reason": reason}),
        )
        .await
    }

    pub async fn deny_access_request(
        &self,
        request_id: String,
        reason: Option<String>,
    ) -> Result<AccessRequestInfo> {
        self.decide(request_id, "deny", json!({"reason": reason}))
            .await
    }

    /// Cancels your request (or ends your window early).
    pub async fn cancel_access_request(&self, request_id: String) -> Result<AccessRequestInfo> {
        self.decide(request_id, "cancel", json!({})).await
    }

    /// Ends someone's window early (approvers and managers).
    pub async fn revoke_access_request(
        &self,
        request_id: String,
        reason: Option<String>,
    ) -> Result<AccessRequestInfo> {
        self.decide(request_id, "revoke", json!({"reason": reason}))
            .await
    }

    // ----- Recordings -----

    /// Uploads the recording (asciicast) of a local session on a host of an
    /// account. The engine does it by itself for hosts with mandatory
    /// recording; returns the new session id.
    pub async fn upload_recording(
        &self,
        host_id: String,
        path: String,
        started_at: i64,
        title: String,
    ) -> Result<String> {
        let host = parse_id(&host_id)?;
        let acc = self.account_of_host(host).await?;
        run(async move {
            Ok(acc
                .upload_recording(host, std::path::Path::new(&path), started_at, &title)
                .await?
                .to_string())
        })
        .await
    }

    /// Forgets the cached host answers and team certificates of the current
    /// (or bound) account; see `AccountHandle::forget_access`.
    pub fn forget_access(&self) {
        if let Ok(acc) = self.account_now() {
            acc.forget_access();
        }
    }

    /// Recorded sessions of a vault (managers).
    pub async fn vault_recordings(&self, vault_id: String) -> Result<Vec<VaultRecording>> {
        let id = parse_id(&vault_id)?;
        self.with_api(move |api| async move {
            let v: Value = api.get(&format!("/api/v1/vaults/{id}/recordings")).await?;
            Ok(v.as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|r| VaultRecording {
                    session_id: r["session_id"].as_str().unwrap_or_default().into(),
                    owner_id: r["owner_id"].as_str().unwrap_or_default().into(),
                    owner_email: r["owner_email"].as_str().map(String::from),
                    host_id: r["host_id"].as_str().map(String::from),
                    title: r["title"].as_str().unwrap_or_default().into(),
                    kind: r["kind"].as_str().unwrap_or_default().into(),
                    created_at: r["created_at"].as_i64().unwrap_or(0),
                    ended_at: r["ended_at"].as_i64(),
                })
                .collect())
        })
        .await
    }
}

impl TermoakCore {
    async fn decide(
        &self,
        request_id: String,
        action: &'static str,
        body: Value,
    ) -> Result<AccessRequestInfo> {
        let id = parse_id(&request_id)?;
        let r = self
            .with_api(move |api| async move {
                request_info(
                    &api.post::<Value>(&format!("/api/v1/access-requests/{id}/{action}"), &body)
                        .await?,
                )
            })
            .await?;
        if let Ok(acc) = self.account_now() {
            acc.forget_access();
        }
        Ok(r)
    }
}

#[uniffi::export]
impl AccountHandle {
    pub async fn ca_info(&self, team_id: Option<String>) -> Result<CaOverview> {
        self.core().ca_info(team_id).await
    }

    pub async fn create_ca(
        &self,
        team_id: Option<String>,
        algorithm: Option<String>,
    ) -> Result<CaOverview> {
        self.core().create_ca(team_id, algorithm).await
    }

    pub async fn rotate_ca(
        &self,
        team_id: Option<String>,
        overlap_hours: Option<u32>,
    ) -> Result<CaOverview> {
        self.core().rotate_ca(team_id, overlap_hours).await
    }

    pub async fn disable_ca(&self, team_id: Option<String>, confirm: String) -> Result<()> {
        self.core().disable_ca(team_id, confirm).await
    }

    pub async fn ca_install_script(
        &self,
        team_id: Option<String>,
        krl: bool,
        principals: bool,
        refresh: bool,
    ) -> Result<String> {
        self.core()
            .ca_install_script(team_id, krl, principals, refresh)
            .await
    }

    pub async fn ca_certificates(
        &self,
        team_id: Option<String>,
        user_id: Option<String>,
        active_only: bool,
    ) -> Result<Vec<IssuedCertificateInfo>> {
        self.core()
            .ca_certificates(team_id, user_id, active_only)
            .await
    }

    pub async fn revoke_certificates(
        &self,
        team_id: Option<String>,
        target: RevokeTarget,
        reason: Option<String>,
    ) -> Result<Vec<i64>> {
        self.core()
            .revoke_certificates(team_id, target, reason)
            .await
    }

    pub async fn request_certificate(
        &self,
        host_id: String,
        key_id: Option<String>,
        ttl_minutes: Option<u32>,
    ) -> Result<NewCertificate> {
        self.core()
            .request_certificate(host_id, key_id, ttl_minutes)
            .await
    }

    pub async fn my_certificates(&self) -> Result<Vec<IssuedCertificateInfo>> {
        self.core().my_certificates().await
    }

    pub async fn team_policy(&self, team_id: String) -> Result<TeamSecurityPolicy> {
        self.core().team_policy(team_id).await
    }

    pub async fn set_team_policy(
        &self,
        team_id: String,
        policy: TeamSecurityPolicy,
    ) -> Result<TeamSecurityPolicy> {
        self.core().set_team_policy(team_id, policy).await
    }

    pub async fn team_compliance(&self, team_id: String) -> Result<Vec<TeamComplianceMember>> {
        self.core().team_compliance(team_id).await
    }

    pub async fn set_member_principal(
        &self,
        team_id: String,
        user_id: String,
        principal: Option<String>,
    ) -> Result<()> {
        self.core()
            .set_member_principal(team_id, user_id, principal)
            .await
    }

    pub async fn team_2fa_requirements(&self) -> Result<Vec<Team2faRequirement>> {
        self.core().team_2fa_requirements().await
    }

    pub async fn access_policies(&self, vault_id: String) -> Result<Vec<AccessPolicyRecord>> {
        self.core().access_policies(vault_id).await
    }

    pub async fn set_access_policy(
        &self,
        vault_id: String,
        target_kind: AccessTargetKind,
        target_id: String,
        policy: AccessPolicyInfo,
    ) -> Result<AccessPolicyRecord> {
        self.core()
            .set_access_policy(vault_id, target_kind, target_id, policy)
            .await
    }

    pub async fn delete_access_policy(&self, vault_id: String, policy_id: String) -> Result<()> {
        self.core().delete_access_policy(vault_id, policy_id).await
    }

    pub async fn host_access(&self, host_id: String) -> Result<HostAccessInfo> {
        self.core().host_access(host_id).await
    }

    pub async fn access_requests(
        &self,
        scope: AccessRequestScope,
        status: Option<AccessRequestStatus>,
    ) -> Result<Vec<AccessRequestInfo>> {
        self.core().access_requests(scope, status).await
    }

    pub async fn access_request(&self, request_id: String) -> Result<AccessRequestInfo> {
        self.core().access_request(request_id).await
    }

    pub async fn create_access_request(
        &self,
        target_kind: AccessTargetKind,
        target_id: String,
        minutes: u32,
        reason: String,
    ) -> Result<AccessRequestInfo> {
        self.core()
            .create_access_request(target_kind, target_id, minutes, reason)
            .await
    }

    pub async fn approve_access_request(
        &self,
        request_id: String,
        minutes: Option<u32>,
        reason: Option<String>,
    ) -> Result<AccessRequestInfo> {
        self.core()
            .approve_access_request(request_id, minutes, reason)
            .await
    }

    pub async fn deny_access_request(
        &self,
        request_id: String,
        reason: Option<String>,
    ) -> Result<AccessRequestInfo> {
        self.core().deny_access_request(request_id, reason).await
    }

    pub async fn cancel_access_request(&self, request_id: String) -> Result<AccessRequestInfo> {
        self.core().cancel_access_request(request_id).await
    }

    pub async fn revoke_access_request(
        &self,
        request_id: String,
        reason: Option<String>,
    ) -> Result<AccessRequestInfo> {
        self.core().revoke_access_request(request_id, reason).await
    }

    pub async fn upload_recording(
        &self,
        host_id: String,
        path: String,
        started_at: i64,
        title: String,
    ) -> Result<String> {
        self.core()
            .upload_recording(host_id, path, started_at, title)
            .await
    }

    pub async fn vault_recordings(&self, vault_id: String) -> Result<Vec<VaultRecording>> {
        self.core().vault_recordings(vault_id).await
    }

    /// Forgets the engine's cached answers about hosts (`host_access`) and
    /// its team certificates for this account: call it on every
    /// `access_request` event (a window opened, ended or was revoked), as
    /// the desktop does. The next connection asks the server again.
    pub fn forget_access(&self) {
        self.core().forget_access();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_round_trip_and_certificate_details() {
        let p = TeamSecurityPolicy::from(ac::TeamPolicy::default());
        assert!(p.allow_reveal && p.ai_allowed && p.networks_allowed);
        assert_eq!(p.certificates.principals, vec!["{login}"]);
        let back = ac::TeamPolicy::from(p);
        assert_eq!(back, ac::TeamPolicy::default());

        let ca = termoak_ssh::ca::generate_ca(termoak_ssh::ca::CaAlgorithm::Ed25519, "t").unwrap();
        let (_, public) = termoak_ssh::ca::ephemeral_key("e").unwrap();
        let line = termoak_ssh::ca::sign_user_certificate(
            &ca.private_key,
            &termoak_ssh::ca::parse_public_key(&public).unwrap(),
            &termoak_ssh::ca::UserCertificate {
                serial: 9,
                key_id: "termoak:a@b:x:direct:9".into(),
                principals: vec!["deploy".into()],
                valid_after: 1_000,
                valid_before: 2_000,
                extensions: vec!["permit-pty".into()],
                source_address: None,
                force_command: None,
            },
        )
        .unwrap();
        let d = parse_certificate(line).unwrap();
        assert_eq!(
            (d.serial, d.valid_after, d.valid_before),
            (9, 1_000_000, 2_000_000)
        );
        assert_eq!(d.principals, vec!["deploy"]);
        assert!(parse_certificate("nope".into()).is_err());

        let a = AccessPolicyInfo::from(ac::AccessPolicy::default());
        assert_eq!(a.mode, AccessMode::Direct);
        assert_eq!(a.to_core().unwrap(), ac::AccessPolicy::default());
    }
}

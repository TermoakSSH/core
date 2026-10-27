//! End-to-end encrypted vaults, single sign-on and the extended audit for
//! the apps (0.7 phase 5a, docs/E2EE-SSO-AUDIT.md §5, §6).
//!
//! Every call is on `TermoakCore` (the current or bound account) and on
//! `AccountHandle`. Check `server_features`: `e2ee`, `sso`, `audit_v2`.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use parking_lot::Mutex;
use serde_json::{Value, json};
use termoak_client::audit::AuditOf;
use termoak_core::e2ee;
use termoak_core::model as cm;
use termoak_core::store::audit as au;
use zeroize::Zeroizing;

use crate::account::AuditEvent;
use crate::accounts::{AccountHandle, AccountInfo, ServerChoice, account_info};
use crate::error::{Result, TermoakError};
use crate::models::{parse_id, parse_opt_id};
use crate::runtime::run;
use crate::vault::TermoakCore;

fn ids(v: &Option<Vec<String>>) -> Result<Option<Vec<uuid::Uuid>>> {
    v.as_ref()
        .map(|l| l.iter().map(|s| parse_id(s)).collect::<Result<Vec<_>>>())
        .transpose()
}

/// Pairing keys of new devices waiting for approval (memory only).
static PAIRING_KEYS: LazyLock<Mutex<HashMap<uuid::Uuid, Zeroizing<[u8; 32]>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

// ---------------------------------------------------------------------------
// E2EE records
// ---------------------------------------------------------------------------

/// Your published E2EE key.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct E2eeKeyInfo {
    pub id: String,
    /// Compare it with other devices or members (eight groups of four).
    pub fingerprint: String,
    pub created_at: i64,
}

impl From<&cm::UserKeyInfo> for E2eeKeyInfo {
    fn from(k: &cm::UserKeyInfo) -> Self {
        Self {
            id: k.id.to_string(),
            fingerprint: k.fingerprint.clone(),
            created_at: k.created_at,
        }
    }
}

/// End-to-end encryption of the account on this device.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct E2eeStatus {
    /// The account has an E2EE key (set up on some device).
    pub set_up: bool,
    /// This device holds it (it can open E2EE vaults it has wraps for).
    pub unlocked: bool,
    pub key: Option<E2eeKeyInfo>,
    /// An E2EE passphrase can unlock new devices.
    pub has_passphrase: bool,
    pub has_recovery_key: bool,
    /// Devices of yours waiting for approval (`e2ee_pairings`).
    pub pending_pairings: u32,
    /// Secrets of E2EE vaults still sealed on this device.
    pub locked_secrets: u64,
}

/// What `e2ee_setup` creates. Show `recovery_key` (the recovery phrase: 24
/// lowercase BIP39 English words separated by spaces) once, numbered, and
/// ask the person to keep it safe: it is the way back if every device is
/// lost.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct E2eeSetupResult {
    pub key: E2eeKeyInfo,
    pub recovery_key: String,
}

/// A new device waiting for another one (`e2ee_pairing_start`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct E2eePairingStart {
    pub id: String,
    /// Six digits: the approving device shows the same.
    pub code: String,
    pub expires_at: i64,
}

/// One of your devices asking for your E2EE key (`e2ee_pairings`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct E2eePairingRequest {
    pub id: String,
    pub device_name: String,
    /// Approve only if the new device shows the same code.
    pub code: String,
    pub created_at: i64,
    pub expires_at: i64,
}

/// An E2EE vault as you see it (`VaultInfo.e2ee`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultE2eeInfo {
    pub key_version: u32,
    /// Your role and the team's policy let you hold the key.
    pub may_hold_key: bool,
    /// The server has your wrap of the key (this device opens it once
    /// unlocked).
    pub has_wrap: bool,
    /// Someone lost access: rotate the key (`e2ee_rotate_vault`).
    pub rekey_needed: bool,
    /// Members waiting for you to give them the key (`e2ee_pending_members`).
    pub pending_members: u32,
    /// Members who may hold the key but have not set up E2EE.
    pub members_without_key: i64,
}

impl From<&cm::VaultE2ee> for VaultE2eeInfo {
    fn from(e: &cm::VaultE2ee) -> Self {
        Self {
            key_version: e.key_version,
            may_hold_key: e.may_hold_key,
            has_wrap: e.wrap.is_some(),
            rekey_needed: e.rekey_needed,
            pending_members: e.pending.len() as u32,
            members_without_key: e.without_key,
        }
    }
}

/// A member's E2EE key (to give them a vault key).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct E2eeMember {
    pub user_id: String,
    pub email: String,
    pub name: String,
    /// Empty when they have no E2EE key yet.
    pub fingerprint: String,
    /// This device gave them a key before and their key changed since: ask
    /// them before going on.
    pub key_changed: bool,
}

/// What turning E2EE on (or rotating) covers (`e2ee_vault_state`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct E2eeVaultState {
    pub e2ee: bool,
    pub key_version: u32,
    /// Members who may hold the key and have an E2EE key.
    pub recipients: Vec<E2eeMember>,
    /// Members who may hold the key but have not set up E2EE.
    pub without_key: Vec<E2eeMember>,
    /// Items with a secret that will be sealed on this device.
    pub items: u32,
    pub rekey_needed: bool,
}

// ---------------------------------------------------------------------------
// SSO records
// ---------------------------------------------------------------------------

/// Whether an email signs in through its team's SSO (`sso_discover`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SsoHint {
    pub sso: bool,
    /// Password sign-in is refused for this email: only offer SSO.
    pub enforced: bool,
    pub team_id: Option<String>,
    pub team_name: Option<String>,
}

/// A single sign-on in progress: open `authorize_url` in the system
/// browser (Custom Tab, `ASWebAuthenticationSession`); keep the rest for
/// `sso_complete`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SsoFlow {
    pub authorize_url: String,
    pub server_url: String,
    pub state: String,
    pub verifier: String,
    pub redirect_uri: String,
}

impl SsoFlow {
    fn pending(&self) -> termoak_core::sso::SsoPending {
        termoak_core::sso::SsoPending {
            server_url: self.server_url.clone(),
            state: self.state.clone(),
            verifier: self.verifier.clone(),
            redirect_uri: self.redirect_uri.clone(),
        }
    }

    fn new(url: String, p: termoak_core::sso::SsoPending) -> Self {
        Self {
            authorize_url: url,
            server_url: p.server_url,
            state: p.state,
            verifier: p.verifier,
            redirect_uri: p.redirect_uri,
        }
    }
}

/// A team's SSO settings (team owners and admins).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SsoSettings {
    pub enabled: bool,
    /// `google`, `microsoft`, `keycloak`, `authentik` or `generic`.
    pub preset: String,
    pub issuer: String,
    pub tenant: Option<String>,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub email_claim: Option<String>,
    pub require_email_verified: bool,
    pub enforce: bool,
    pub owner_password_allowed: bool,
    pub auto_create: bool,
    pub auto_join: bool,
    pub satisfies_2fa: bool,
    /// Read-only: a client secret is stored.
    #[uniffi(default)]
    pub has_client_secret: bool,
    /// Read-only: the URL to register at the identity provider.
    #[uniffi(default)]
    pub redirect_uri: String,
}

/// A domain of a team and its DNS proof.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TeamDomainInfo {
    pub domain: String,
    /// TXT record to create.
    pub record_name: String,
    pub record_value: String,
    pub verified: bool,
    pub verified_at: Option<i64>,
    pub last_error: Option<String>,
}

impl From<termoak_core::sso::TeamDomain> for TeamDomainInfo {
    fn from(d: termoak_core::sso::TeamDomain) -> Self {
        Self {
            verified: d.verified_at.is_some(),
            domain: d.domain,
            record_name: d.record_name,
            record_value: d.record_value,
            verified_at: d.verified_at,
            last_error: d.last_error,
        }
    }
}

// ---------------------------------------------------------------------------
// Audit records
// ---------------------------------------------------------------------------

/// Whose audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AuditScope {
    Me,
    Vault,
    Team,
    Server,
}

/// Filters of an audit search (all optional).
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct AuditQuery {
    /// Comma-separated actions; `access.*` is a prefix.
    #[uniffi(default)]
    pub action: Option<String>,
    #[uniffi(default)]
    pub actor: Option<String>,
    #[uniffi(default)]
    pub vault_id: Option<String>,
    #[uniffi(default)]
    pub target: Option<String>,
    /// ms since the epoch.
    #[uniffi(default)]
    pub since: Option<i64>,
    #[uniffi(default)]
    pub until: Option<i64>,
    /// Text anywhere in the entry.
    #[uniffi(default)]
    pub text: Option<String>,
    #[uniffi(default)]
    pub before: Option<i64>,
    #[uniffi(default)]
    pub limit: Option<u32>,
}

impl AuditQuery {
    fn filter(&self) -> Result<au::AuditFilter> {
        Ok(au::AuditFilter {
            action: self.action.clone(),
            actor: self.actor.clone(),
            vault_id: parse_opt_id(&self.vault_id)?,
            target: self.target.clone(),
            since: self.since,
            until: self.until,
            q: self.text.clone(),
            before: self.before,
            after: None,
            limit: self.limit.map(i64::from),
        })
    }
}

fn audit_of(scope: AuditScope, id: &Option<String>) -> Result<AuditOf> {
    let need = || -> Result<uuid::Uuid> {
        parse_opt_id(id)?.ok_or_else(|| TermoakError::Invalid("this audit needs an id".into()))
    };
    Ok(match scope {
        AuditScope::Me => AuditOf::Me,
        AuditScope::Vault => AuditOf::Vault(need()?),
        AuditScope::Team => AuditOf::Team(need()?),
        AuditScope::Server => AuditOf::Server,
    })
}

/// An audit sink (SIEM).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AuditSinkInfo {
    pub id: String,
    /// `webhook` or `syslog`.
    pub kind: String,
    pub name: String,
    /// Webhook URL.
    pub url: Option<String>,
    /// Syslog host, port and `tls`/`tcp`.
    pub host: Option<String>,
    pub port: Option<u16>,
    pub transport: Option<String>,
    pub actions: Vec<String>,
    pub enabled: bool,
    pub failures: i64,
    pub last_error: Option<String>,
    pub last_success_at: Option<i64>,
}

impl From<au::AuditSink> for AuditSinkInfo {
    fn from(s: au::AuditSink) -> Self {
        Self {
            id: s.id.to_string(),
            kind: s.kind.as_str().into(),
            name: s.name,
            url: s.config.url,
            host: s.config.host,
            port: s.config.port,
            transport: s.config.transport,
            actions: s.actions,
            enabled: s.enabled,
            failures: s.failures,
            last_error: s.last_error,
            last_success_at: s.last_success_at,
        }
    }
}

/// A new sink: `kind` `webhook` (with `url`) or `syslog` (with `host`,
/// `port`, `transport` `tls`/`tcp` and optionally `ca_pem`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AuditSinkInput {
    pub kind: String,
    pub name: String,
    #[uniffi(default)]
    pub url: Option<String>,
    #[uniffi(default)]
    pub host: Option<String>,
    #[uniffi(default)]
    pub port: Option<u16>,
    #[uniffi(default)]
    pub transport: Option<String>,
    #[uniffi(default)]
    pub ca_pem: Option<String>,
    /// Action patterns (`access.*`); empty: every entry.
    #[uniffi(default)]
    pub actions: Vec<String>,
}

/// A created sink and, for webhooks, its signing secret (shown once).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AuditSinkCreated {
    pub sink: AuditSinkInfo,
    pub secret: Option<String>,
}

/// The result of a test delivery.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AuditSinkTest {
    pub ok: bool,
    pub error: Option<String>,
}

fn from_value<T: serde::de::DeserializeOwned>(v: Value) -> Result<T> {
    serde_json::from_value(v)
        .map_err(|e| TermoakError::Server(format!("unexpected server response: {e}")))
}

fn settings_from(c: termoak_core::sso::SsoConfig, redirect: String) -> SsoSettings {
    SsoSettings {
        enabled: c.enabled,
        preset: serde_json::to_value(c.preset)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "generic".into()),
        issuer: c.issuer,
        tenant: c.tenant,
        client_id: c.client_id,
        scopes: c.scopes,
        email_claim: c.email_claim,
        require_email_verified: c.require_email_verified,
        enforce: c.enforce,
        owner_password_allowed: c.owner_password_allowed,
        auto_create: c.auto_create,
        auto_join: c.auto_join,
        satisfies_2fa: c.satisfies_2fa,
        has_client_secret: c.has_client_secret,
        redirect_uri: redirect,
    }
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// The fingerprint of an E2EE public key (base64), as members compare it.
#[uniffi::export]
pub fn e2ee_fingerprint(public_key: String) -> Result<String> {
    Ok(e2ee::fingerprint(&e2ee::parse_public_key(&public_key)?))
}

/// Whether `text` is a well-formed recovery phrase (24 known words whose
/// BIP39 checksum matches): for live feedback while the person types it.
#[uniffi::export]
pub fn e2ee_recovery_key_valid(text: String) -> bool {
    e2ee::RecoveryKey::parse(&text).is_ok()
}

/// What is wrong with a typed recovery phrase, for a precise message.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct E2eeRecoveryKeyCheck {
    pub valid: bool,
    /// Empty when valid; otherwise `word_count`, `unknown_word`,
    /// `checksum` or `old_format` (a 56-character key of the first format,
    /// no longer accepted).
    pub reason: String,
    /// Words found (24 expected).
    pub words: u32,
    /// The first unknown word's position (1-based), 0 when none.
    pub word: u32,
}

/// Checks a typed recovery phrase: case, numbering, punctuation and line
/// breaks are ignored, and a word can be shortened to its first four
/// letters.
#[uniffi::export]
pub fn e2ee_recovery_key_check(text: String) -> E2eeRecoveryKeyCheck {
    let words = text
        .split(|c: char| !c.is_alphabetic())
        .filter(|t| !t.is_empty())
        .count() as u32;
    match e2ee::RecoveryKey::parse(&text) {
        Ok(_) => E2eeRecoveryKeyCheck {
            valid: true,
            reason: String::new(),
            words,
            word: 0,
        },
        Err(termoak_core::CoreError::Vault { detail, .. }) => {
            let d = detail.unwrap_or_default();
            E2eeRecoveryKeyCheck {
                valid: false,
                reason: d["reason"].as_str().unwrap_or_default().to_string(),
                words,
                word: d["word"].as_u64().unwrap_or(0) as u32,
            }
        }
        Err(_) => E2eeRecoveryKeyCheck {
            valid: false,
            reason: String::new(),
            words,
            word: 0,
        },
    }
}

/// The BIP39 English word list (2048 words, sorted), for suggestions while
/// the person types the recovery phrase.
#[uniffi::export]
pub fn e2ee_recovery_wordlist() -> Vec<String> {
    e2ee::recovery_wordlist()
        .iter()
        .map(|w| w.to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// Calls
// ---------------------------------------------------------------------------

#[uniffi::export]
impl TermoakCore {
    // ----- E2EE -----

    /// End-to-end encryption of the account on this device.
    pub async fn e2ee_status(&self) -> Result<E2eeStatus> {
        let acc = self.account_now()?;
        run(async move {
            let st = acc.e2ee_status().await?;
            let unlocked = match acc.e2ee_user_key().await? {
                Some(k) => st.key.as_ref().is_some_and(|p| p.id == k.id),
                None => false,
            };
            Ok(E2eeStatus {
                set_up: st.key.is_some(),
                unlocked,
                key: st.key.as_ref().map(Into::into),
                has_passphrase: st
                    .seals
                    .iter()
                    .any(|s| s.kind == e2ee::SealKind::Passphrase),
                has_recovery_key: st.seals.iter().any(|s| s.kind == e2ee::SealKind::Recovery),
                pending_pairings: st.pairings.len() as u32,
                locked_secrets: termoak_client::e2ee::locked_count(&acc.store).await? as u64,
            })
        })
        .await
    }

    /// Sets up end-to-end encryption for the account (once): a key for this
    /// device, a recovery key (shown once) and, optionally, a passphrase
    /// (at least 8 characters) to unlock other devices. Never the login
    /// password: the server sees that one.
    #[uniffi::method(default(passphrase))]
    pub async fn e2ee_setup(&self, passphrase: Option<String>) -> Result<E2eeSetupResult> {
        let acc = self.account_now()?;
        run(async move {
            let (info, rk) = acc.e2ee_setup(passphrase.as_deref()).await?;
            Ok(E2eeSetupResult {
                key: (&info).into(),
                recovery_key: rk.to_string(),
            })
        })
        .await
    }

    /// Unlocks this device with the E2EE passphrase. Returns how many
    /// stored secrets it opened; sync afterwards.
    pub async fn e2ee_unlock_with_passphrase(&self, passphrase: String) -> Result<u64> {
        let acc = self.account_now()?;
        run(async move { Ok(acc.e2ee_unlock_passphrase(&passphrase).await? as u64) }).await
    }

    /// Unlocks this device with the recovery key.
    pub async fn e2ee_unlock_with_recovery_key(&self, recovery_key: String) -> Result<u64> {
        let acc = self.account_now()?;
        run(async move { Ok(acc.e2ee_unlock_recovery(&recovery_key).await? as u64) }).await
    }

    /// Locks this device (forgets the key and the opened secrets of E2EE
    /// vaults; unlock again to use them).
    pub async fn e2ee_lock(&self) -> Result<()> {
        let acc = self.account_now()?;
        run(async move { Ok(acc.e2ee_lock().await?) }).await
    }

    /// Sets or changes the E2EE passphrase (unlocked devices).
    pub async fn e2ee_set_passphrase(&self, passphrase: String) -> Result<()> {
        let acc = self.account_now()?;
        run(async move { Ok(acc.e2ee_set_passphrase(&passphrase).await?) }).await
    }

    /// Replaces the recovery key (shown once; the old one stops working).
    pub async fn e2ee_new_recovery_key(&self) -> Result<String> {
        let acc = self.account_now()?;
        run(async move { Ok(acc.e2ee_new_recovery_key().await?.to_string()) }).await
    }

    /// Removes the E2EE passphrase. Returns whether there was one.
    pub async fn e2ee_remove_passphrase(&self) -> Result<bool> {
        let acc = self.account_now()?;
        run(async move { Ok(acc.e2ee_remove_passphrase().await?) }).await
    }

    /// Replaces the account's E2EE key (a lost or stolen device): a new key
    /// with a new recovery phrase (shown once) and an optional passphrase;
    /// every vault key the old key held is wrapped again on this device.
    /// Your other devices lock and unlock again.
    #[uniffi::method(default(passphrase))]
    pub async fn e2ee_rotate_user_key(
        &self,
        passphrase: Option<String>,
    ) -> Result<E2eeSetupResult> {
        let acc = self.account_now()?;
        run(async move {
            let (info, rk) = acc.e2ee_rotate_user_key(passphrase.as_deref()).await?;
            Ok(E2eeSetupResult {
                key: (&info).into(),
                recovery_key: rk.to_string(),
            })
        })
        .await
    }

    /// Everything lost: without `confirm` lists the vaults nobody else
    /// could open any more (show them); with it forgets the account's E2EE
    /// key, seals, pairings and wraps. Returns those vault ids.
    pub async fn e2ee_reset(&self, confirm: bool) -> Result<Vec<String>> {
        let acc = self.account_now()?;
        run(async move {
            Ok(acc
                .e2ee_reset(confirm)
                .await?
                .into_iter()
                .map(|id| id.to_string())
                .collect())
        })
        .await
    }

    /// New device: asks your unlocked devices for the key. Show the code;
    /// then call `e2ee_pairing_finish` (after the `e2ee` `pairing` event,
    /// or every few seconds).
    pub async fn e2ee_pairing_start(&self) -> Result<E2eePairingStart> {
        let acc = self.account_now()?;
        run(async move {
            let (p, key) = acc.e2ee_pairing_start().await?;
            PAIRING_KEYS.lock().insert(p.id, key);
            Ok(E2eePairingStart {
                id: p.id.to_string(),
                code: p.code,
                expires_at: p.expires_at,
            })
        })
        .await
    }

    /// New device: `Some(opened secrets)` once approved (this device is
    /// unlocked), `None` while it waits.
    pub async fn e2ee_pairing_finish(&self, pairing_id: String) -> Result<Option<u64>> {
        let id = parse_id(&pairing_id)?;
        let key = PAIRING_KEYS.lock().get(&id).cloned().ok_or_else(|| {
            TermoakError::NotFound("start the pairing on this device again".into())
        })?;
        let acc = self.account_now()?;
        let r = run(async move { Ok(acc.e2ee_pairing_finish(id, &key).await?) }).await;
        if !matches!(r, Ok(None)) {
            PAIRING_KEYS.lock().remove(&id);
        }
        Ok(r?.map(|n| n as u64))
    }

    /// Unlocked device: your devices waiting for approval.
    pub async fn e2ee_pairings(&self) -> Result<Vec<E2eePairingRequest>> {
        let acc = self.account_now()?;
        run(async move {
            Ok(acc
                .e2ee_pairings()
                .await?
                .into_iter()
                .map(|r| E2eePairingRequest {
                    id: r.pairing.id.to_string(),
                    device_name: r.pairing.device_name,
                    code: r.code,
                    created_at: r.pairing.created_at,
                    expires_at: r.pairing.expires_at,
                })
                .collect())
        })
        .await
    }

    /// Unlocked device: approve (only if the codes match) or deny.
    pub async fn e2ee_pairing_decide(&self, pairing_id: String, approve: bool) -> Result<()> {
        let id = parse_id(&pairing_id)?;
        let acc = self.account_now()?;
        run(async move { Ok(acc.e2ee_pairing_decide(id, approve).await?) }).await
    }

    /// What turning E2EE on (or rotating) covers in a vault.
    pub async fn e2ee_vault_state(&self, vault_id: String) -> Result<E2eeVaultState> {
        let vault = parse_id(&vault_id)?;
        let acc = self.account_now()?;
        run(async move {
            let st = acc.e2ee_vault_state(vault).await?;
            let member = |r: &cm::E2eeRecipient| E2eeMember {
                user_id: r.user_id.to_string(),
                email: r.email.clone(),
                name: r.name.clone(),
                fingerprint: r.fingerprint.clone(),
                key_changed: false,
            };
            Ok(E2eeVaultState {
                e2ee: st.crypto == cm::VaultCrypto::E2ee,
                key_version: st.key_version,
                recipients: st.recipients.iter().map(member).collect(),
                without_key: st
                    .without_key
                    .iter()
                    .map(|m| E2eeMember {
                        user_id: m.user_id.to_string(),
                        email: m.email.clone(),
                        name: m.name.clone(),
                        fingerprint: String::new(),
                        key_changed: false,
                    })
                    .collect(),
                items: st.items.len() as u32,
                rekey_needed: st.rekey_needed,
            })
        })
        .await
    }

    /// Turns end-to-end encryption on for a vault you manage: its secrets
    /// are sealed on this device and the server can no longer read them.
    /// `include`: members (user ids from `e2ee_vault_state().recipients`)
    /// who get the key now; `None`: all of them. Server sessions, the
    /// server AI and just-in-time credentials stop using its secrets.
    #[uniffi::method(default(include))]
    pub async fn e2ee_enable_vault(
        &self,
        vault_id: String,
        include: Option<Vec<String>>,
    ) -> Result<u32> {
        let vault = parse_id(&vault_id)?;
        let include = ids(&include)?;
        let acc = self.account_now()?;
        run(async move { Ok(acc.e2ee_enable_vault(vault, include).await?) }).await
    }

    /// Turns end-to-end encryption off (this device sends the secrets to
    /// the server, which can read them again).
    pub async fn e2ee_disable_vault(&self, vault_id: String) -> Result<()> {
        let vault = parse_id(&vault_id)?;
        let acc = self.account_now()?;
        run(async move { Ok(acc.e2ee_disable_vault(vault).await?) }).await
    }

    /// Rotates a vault's key (after someone lost access: `rekey_needed`).
    pub async fn e2ee_rotate_vault(&self, vault_id: String) -> Result<u32> {
        let vault = parse_id(&vault_id)?;
        let acc = self.account_now()?;
        run(async move { Ok(acc.e2ee_rotate_vault(vault).await?) }).await
    }

    /// Members waiting for a vault's key, with their fingerprints.
    pub async fn e2ee_pending_members(&self, vault_id: String) -> Result<Vec<E2eeMember>> {
        let vault = parse_id(&vault_id)?;
        let acc = self.account_now()?;
        run(async move {
            Ok(acc
                .e2ee_pending_members(vault)
                .await?
                .into_iter()
                .map(|p| E2eeMember {
                    user_id: p.recipient.user_id.to_string(),
                    email: p.recipient.email,
                    name: p.recipient.name,
                    fingerprint: p.recipient.fingerprint,
                    key_changed: p.key_changed,
                })
                .collect())
        })
        .await
    }

    /// Gives a vault's key to waiting members (`user_ids`, or all).
    #[uniffi::method(default(user_ids))]
    pub async fn e2ee_add_members(
        &self,
        vault_id: String,
        user_ids: Option<Vec<String>>,
    ) -> Result<u32> {
        let vault = parse_id(&vault_id)?;
        let users = ids(&user_ids)?;
        let acc = self.account_now()?;
        run(async move { Ok(acc.e2ee_add_members(vault, users).await? as u32) }).await
    }

    /// Opens a server session to a host of an E2EE vault, sending its
    /// credentials (resolved on this device) for this one session: the
    /// server uses them to connect and does not keep them. Ask first ("The
    /// server will use this host's password for this session").
    #[uniffi::method(default(title = None, record = None))]
    pub async fn open_server_session_unlocked(
        &self,
        host_id: String,
        cols: u32,
        rows: u32,
        title: Option<String>,
        record: Option<bool>,
    ) -> Result<crate::server::ServerSession> {
        let hid = parse_id(&host_id)?;
        let ws = self.ws.clone();
        let acc = self.account_now()?;
        run(async move {
            let item = ws.locate(hid).await?;
            let mut resolved = ws.resolve_item(item).await?;
            let unlock = acc.e2ee_unlock_for(&resolved).await;
            resolved.zeroize_secrets();
            let v: Value = acc
                .api
                .post(
                    "/api/v1/sessions",
                    &json!({"host_id": hid, "cols": cols.min(1000), "rows": rows.min(500), "title": title, "record": record, "unlock": unlock}),
                )
                .await?;
            Ok(crate::server::ServerSession::from_json(&v))
        })
        .await
    }

    /// Tests a host of an E2EE vault from the server (`POST
    /// /hosts/{id}/test`, `?trust=true` to accept and remember a new host
    /// key), sending its credentials (resolved on this device) for this one
    /// test, as `open_server_session_unlocked` does for a session. Ask
    /// first. Returns the server's answer as JSON (`ok`, `latency_ms`,
    /// `fingerprint`, `error`, `error_code`, `network`...).
    #[uniffi::method(default(trust = false))]
    pub async fn test_host_unlocked(&self, host_id: String, trust: bool) -> Result<String> {
        let hid = parse_id(&host_id)?;
        let ws = self.ws.clone();
        let acc = self.account_now()?;
        run(async move {
            let item = ws.locate(hid).await?;
            let mut resolved = ws.resolve_item(item).await?;
            let unlock = acc.e2ee_unlock_for(&resolved).await;
            resolved.zeroize_secrets();
            let path = format!(
                "/api/v1/hosts/{hid}/test{}",
                if trust { "?trust=true" } else { "" }
            );
            let v: Value = acc.api.post(&path, &json!({"unlock": unlock})).await?;
            Ok(v.to_string())
        })
        .await
    }

    // ----- SSO -----

    /// Whether `email` signs in through its team's SSO on `server` (before
    /// showing the password field).
    pub async fn sso_discover(&self, server: ServerChoice, email: String) -> Result<SsoHint> {
        let url = termoak_client::ServerChoice::from(server).url()?;
        run(async move {
            let api = termoak_client::ApiClient::new(&url)?;
            let h = termoak_client::sso::discover(&api, &email).await?;
            Ok(SsoHint {
                sso: h.sso,
                enforced: h.enforced,
                team_id: h.team_id.map(|t| t.to_string()),
                team_name: h.team_name,
            })
        })
        .await
    }

    /// Starts a single sign-on: open `authorize_url` in the system browser;
    /// it comes back to `redirect_uri` (default `termoak://sso`; desktop
    /// apps use `sso_start_loopback`). `email` finds the team by its
    /// verified domain, `team_id` names it.
    #[uniffi::method(default(email = None, team_id = None, redirect_uri = None))]
    pub async fn sso_start(
        &self,
        server: ServerChoice,
        email: Option<String>,
        team_id: Option<String>,
        redirect_uri: Option<String>,
    ) -> Result<SsoFlow> {
        let team = parse_opt_id(&team_id)?;
        let ws = self.ws.clone();
        let redirect = redirect_uri.unwrap_or_else(|| termoak_client::sso::MOBILE_REDIRECT.into());
        run(async move {
            let (url, p) = ws
                .sso_start(server.into(), email.as_deref(), team, &redirect)
                .await?;
            Ok(SsoFlow::new(url, p))
        })
        .await
    }

    /// Finishes a single sign-on with the URL the browser came back to:
    /// the account is signed in (and becomes current). With two-step
    /// verification it fails with `TotpRequired`: call again with the code.
    #[uniffi::method(default(totp_code))]
    pub async fn sso_complete(
        &self,
        flow: SsoFlow,
        callback_url: String,
        totp_code: Option<String>,
    ) -> Result<AccountInfo> {
        crate::vault::install_crypto_provider();
        let ws = self.ws.clone();
        run(async move {
            let acc = ws
                .sso_complete(&flow.pending(), &callback_url, totp_code.as_deref())
                .await?;
            Ok(account_info(&ws, acc.info()))
        })
        .await
    }

    /// Desktop and CLI: starts a single sign-on whose browser comes back to
    /// a loopback listener of this process.
    #[uniffi::method(default(email = None, team_id = None))]
    pub async fn sso_start_loopback(
        &self,
        server: ServerChoice,
        email: Option<String>,
        team_id: Option<String>,
    ) -> Result<Arc<SsoLoopback>> {
        let team = parse_opt_id(&team_id)?;
        let ws = self.ws.clone();
        run(async move {
            let lb = termoak_client::sso::Loopback::bind().await?;
            let redirect = lb.redirect_uri().to_string();
            let (url, p) = ws
                .sso_start(server.into(), email.as_deref(), team, &redirect)
                .await?;
            Ok(Arc::new(SsoLoopback {
                flow: SsoFlow::new(url, p),
                listener: Mutex::new(Some(lb)),
            }))
        })
        .await
    }

    /// A team's SSO settings (`None`: not configured).
    pub async fn team_sso(&self, team_id: String) -> Result<Option<SsoSettings>> {
        let team = parse_id(&team_id)?;
        self.with_api(move |api| async move {
            let v: Value = api.get(&format!("/api/v1/teams/{team}/sso")).await?;
            let redirect = v["redirect_uri"].as_str().unwrap_or_default().to_string();
            if v["config"].is_null() {
                return Ok(None);
            }
            Ok(Some(settings_from(
                from_value(v["config"].clone())?,
                redirect,
            )))
        })
        .await
    }

    /// Saves a team's SSO settings. `client_secret`: `None` keeps the
    /// stored one, `Some("")` removes it.
    #[uniffi::method(default(client_secret))]
    pub async fn set_team_sso(
        &self,
        team_id: String,
        settings: SsoSettings,
        client_secret: Option<String>,
    ) -> Result<SsoSettings> {
        let team = parse_id(&team_id)?;
        self.with_api(move |api| async move {
            let body = json!({
                "config": {
                    "enabled": settings.enabled, "preset": settings.preset, "issuer": settings.issuer,
                    "tenant": settings.tenant, "client_id": settings.client_id, "scopes": settings.scopes,
                    "email_claim": settings.email_claim, "require_email_verified": settings.require_email_verified,
                    "enforce": settings.enforce, "owner_password_allowed": settings.owner_password_allowed,
                    "auto_create": settings.auto_create, "auto_join": settings.auto_join,
                    "satisfies_2fa": settings.satisfies_2fa,
                },
                "client_secret": client_secret,
            });
            let v: Value = api.put(&format!("/api/v1/teams/{team}/sso"), &body).await?;
            let redirect = v["redirect_uri"].as_str().unwrap_or_default().to_string();
            Ok(settings_from(from_value(v["config"].clone())?, redirect))
        })
        .await
    }

    pub async fn delete_team_sso(&self, team_id: String) -> Result<()> {
        let team = parse_id(&team_id)?;
        self.with_api(move |api| async move {
            api.delete(&format!("/api/v1/teams/{team}/sso")).await?;
            Ok(())
        })
        .await
    }

    pub async fn team_domains(&self, team_id: String) -> Result<Vec<TeamDomainInfo>> {
        let team = parse_id(&team_id)?;
        self.with_api(move |api| async move {
            let list: Vec<termoak_core::sso::TeamDomain> =
                from_value(api.get(&format!("/api/v1/teams/{team}/domains")).await?)?;
            Ok(list.into_iter().map(Into::into).collect())
        })
        .await
    }

    /// Claims a domain: create the TXT record it shows, then verify.
    pub async fn add_team_domain(&self, team_id: String, domain: String) -> Result<TeamDomainInfo> {
        let team = parse_id(&team_id)?;
        self.with_api(move |api| async move {
            let d: termoak_core::sso::TeamDomain = from_value(
                api.post(
                    &format!("/api/v1/teams/{team}/domains"),
                    &json!({"domain": domain}),
                )
                .await?,
            )?;
            Ok(d.into())
        })
        .await
    }

    /// Checks the TXT record now.
    pub async fn verify_team_domain(
        &self,
        team_id: String,
        domain: String,
    ) -> Result<TeamDomainInfo> {
        let team = parse_id(&team_id)?;
        self.with_api(move |api| async move {
            let d: termoak_core::sso::TeamDomain = from_value(
                api.post(
                    &format!("/api/v1/teams/{team}/domains/{domain}/verify"),
                    &json!({}),
                )
                .await?,
            )?;
            Ok(d.into())
        })
        .await
    }

    pub async fn remove_team_domain(&self, team_id: String, domain: String) -> Result<()> {
        let team = parse_id(&team_id)?;
        self.with_api(move |api| async move {
            api.delete(&format!("/api/v1/teams/{team}/domains/{domain}"))
                .await?;
            Ok(())
        })
        .await
    }

    // ----- Audit -----

    /// Audit entries matching `query`, newest first. `id`: the vault or
    /// team for those scopes.
    #[uniffi::method(default(id))]
    pub async fn audit_search(
        &self,
        scope: AuditScope,
        query: AuditQuery,
        id: Option<String>,
    ) -> Result<Vec<AuditEvent>> {
        let of = audit_of(scope, &id)?;
        let filter = query.filter()?;
        let acc = self.account_now()?;
        run(async move {
            Ok(acc
                .audit_search(of, &filter)
                .await?
                .into_iter()
                .map(Into::into)
                .collect())
        })
        .await
    }

    /// Downloads the matching entries to `local_path` (`format`: `csv`,
    /// `json` or `ndjson`). Returns the bytes written.
    #[uniffi::method(default(id))]
    pub async fn audit_export(
        &self,
        scope: AuditScope,
        query: AuditQuery,
        format: String,
        local_path: String,
        id: Option<String>,
    ) -> Result<u64> {
        let of = audit_of(scope, &id)?;
        let filter = query.filter()?;
        let acc = self.account_now()?;
        run(async move {
            Ok(acc
                .audit_export(of, &filter, &format, std::path::Path::new(&local_path))
                .await?)
        })
        .await
    }

    /// How long a team keeps its audit (`None`: the server's default).
    pub async fn team_audit_retention(&self, team_id: String) -> Result<Option<u32>> {
        let team = parse_id(&team_id)?;
        let acc = self.account_now()?;
        run(async move { Ok(acc.audit_settings(team).await?.retention_days) }).await
    }

    pub async fn set_team_audit_retention(
        &self,
        team_id: String,
        days: Option<u32>,
    ) -> Result<Option<u32>> {
        let team = parse_id(&team_id)?;
        let acc = self.account_now()?;
        run(async move {
            Ok(acc
                .set_audit_settings(
                    team,
                    &au::AuditSettings {
                        retention_days: days,
                    },
                )
                .await?
                .retention_days)
        })
        .await
    }

    /// SIEM sinks of a team (`scope` `Team` with `id`) or of the server.
    #[uniffi::method(default(id))]
    pub async fn audit_sinks(
        &self,
        scope: AuditScope,
        id: Option<String>,
    ) -> Result<Vec<AuditSinkInfo>> {
        let of = audit_of(scope, &id)?;
        let acc = self.account_now()?;
        run(async move {
            Ok(acc
                .audit_sinks(of)
                .await?
                .into_iter()
                .map(Into::into)
                .collect())
        })
        .await
    }

    #[uniffi::method(default(id))]
    pub async fn create_audit_sink(
        &self,
        scope: AuditScope,
        sink: AuditSinkInput,
        id: Option<String>,
    ) -> Result<AuditSinkCreated> {
        let of = audit_of(scope, &id)?;
        let kind = au::AuditSinkKind::parse(&sink.kind)
            .ok_or_else(|| TermoakError::Invalid("kind must be webhook or syslog".into()))?;
        let config = au::AuditSinkConfig {
            url: sink.url,
            host: sink.host,
            port: sink.port,
            transport: sink.transport,
            ca_pem: sink.ca_pem,
            ..Default::default()
        };
        let acc = self.account_now()?;
        run(async move {
            let v = acc
                .create_audit_sink(of, kind, &sink.name, &config, &sink.actions)
                .await?;
            let s: au::AuditSink = from_value(v["sink"].clone())?;
            Ok(AuditSinkCreated {
                sink: s.into(),
                secret: v["secret"].as_str().map(str::to_string),
            })
        })
        .await
    }

    /// Turns a sink on or off, renames it or changes its actions.
    #[uniffi::method(default(id = None, name = None, actions = None, enabled = None))]
    pub async fn update_audit_sink(
        &self,
        scope: AuditScope,
        sink_id: String,
        id: Option<String>,
        name: Option<String>,
        actions: Option<Vec<String>>,
        enabled: Option<bool>,
    ) -> Result<AuditSinkInfo> {
        let of = audit_of(scope, &id)?;
        let sid = parse_id(&sink_id)?;
        let acc = self.account_now()?;
        run(async move {
            let mut patch = serde_json::Map::new();
            if let Some(n) = name {
                patch.insert("name".into(), json!(n));
            }
            if let Some(a) = actions {
                patch.insert("actions".into(), json!(a));
            }
            if let Some(e) = enabled {
                patch.insert("enabled".into(), json!(e));
            }
            Ok(acc
                .update_audit_sink(of, sid, &Value::Object(patch))
                .await?
                .into())
        })
        .await
    }

    #[uniffi::method(default(id))]
    pub async fn delete_audit_sink(
        &self,
        scope: AuditScope,
        sink_id: String,
        id: Option<String>,
    ) -> Result<()> {
        let of = audit_of(scope, &id)?;
        let sid = parse_id(&sink_id)?;
        let acc = self.account_now()?;
        run(async move { Ok(acc.delete_audit_sink(of, sid).await?) }).await
    }

    #[uniffi::method(default(id))]
    pub async fn test_audit_sink(
        &self,
        scope: AuditScope,
        sink_id: String,
        id: Option<String>,
    ) -> Result<AuditSinkTest> {
        let of = audit_of(scope, &id)?;
        let sid = parse_id(&sink_id)?;
        let acc = self.account_now()?;
        run(async move {
            let v = acc.test_audit_sink(of, sid).await?;
            Ok(AuditSinkTest {
                ok: v["ok"].as_bool().unwrap_or(false),
                error: v["error"].as_str().map(str::to_string),
            })
        })
        .await
    }
}

/// A desktop or CLI single sign-on waiting for the browser.
#[derive(uniffi::Object)]
pub struct SsoLoopback {
    flow: SsoFlow,
    listener: Mutex<Option<termoak_client::sso::Loopback>>,
}

#[uniffi::export]
impl SsoLoopback {
    /// The flow (open `authorize_url` in the browser).
    pub fn flow(&self) -> SsoFlow {
        self.flow.clone()
    }

    /// Waits for the browser (at most `timeout_secs`) and returns the
    /// callback URL for `sso_complete`. Once.
    pub async fn wait_callback(&self, timeout_secs: u32) -> Result<String> {
        let lb = self
            .listener
            .lock()
            .take()
            .ok_or_else(|| TermoakError::Closed("this sign-in already finished".into()))?;
        run(async move {
            Ok(lb
                .wait(std::time::Duration::from_secs(timeout_secs.max(5) as u64))
                .await?)
        })
        .await
    }
}

// ----- the same, per account -----

#[uniffi::export]
impl AccountHandle {
    pub async fn e2ee_status(&self) -> Result<E2eeStatus> {
        self.core().e2ee_status().await
    }

    #[uniffi::method(default(passphrase))]
    pub async fn e2ee_setup(&self, passphrase: Option<String>) -> Result<E2eeSetupResult> {
        self.core().e2ee_setup(passphrase).await
    }

    pub async fn e2ee_unlock_with_passphrase(&self, passphrase: String) -> Result<u64> {
        self.core().e2ee_unlock_with_passphrase(passphrase).await
    }

    pub async fn e2ee_unlock_with_recovery_key(&self, recovery_key: String) -> Result<u64> {
        self.core()
            .e2ee_unlock_with_recovery_key(recovery_key)
            .await
    }

    pub async fn e2ee_lock(&self) -> Result<()> {
        self.core().e2ee_lock().await
    }

    pub async fn e2ee_set_passphrase(&self, passphrase: String) -> Result<()> {
        self.core().e2ee_set_passphrase(passphrase).await
    }

    pub async fn e2ee_new_recovery_key(&self) -> Result<String> {
        self.core().e2ee_new_recovery_key().await
    }

    pub async fn e2ee_remove_passphrase(&self) -> Result<bool> {
        self.core().e2ee_remove_passphrase().await
    }

    #[uniffi::method(default(passphrase))]
    pub async fn e2ee_rotate_user_key(
        &self,
        passphrase: Option<String>,
    ) -> Result<E2eeSetupResult> {
        self.core().e2ee_rotate_user_key(passphrase).await
    }

    pub async fn e2ee_reset(&self, confirm: bool) -> Result<Vec<String>> {
        self.core().e2ee_reset(confirm).await
    }

    pub async fn e2ee_pairing_start(&self) -> Result<E2eePairingStart> {
        self.core().e2ee_pairing_start().await
    }

    pub async fn e2ee_pairing_finish(&self, pairing_id: String) -> Result<Option<u64>> {
        self.core().e2ee_pairing_finish(pairing_id).await
    }

    pub async fn e2ee_pairings(&self) -> Result<Vec<E2eePairingRequest>> {
        self.core().e2ee_pairings().await
    }

    pub async fn e2ee_pairing_decide(&self, pairing_id: String, approve: bool) -> Result<()> {
        self.core().e2ee_pairing_decide(pairing_id, approve).await
    }

    pub async fn e2ee_vault_state(&self, vault_id: String) -> Result<E2eeVaultState> {
        self.core().e2ee_vault_state(vault_id).await
    }

    #[uniffi::method(default(include))]
    pub async fn e2ee_enable_vault(
        &self,
        vault_id: String,
        include: Option<Vec<String>>,
    ) -> Result<u32> {
        self.core().e2ee_enable_vault(vault_id, include).await
    }

    pub async fn e2ee_disable_vault(&self, vault_id: String) -> Result<()> {
        self.core().e2ee_disable_vault(vault_id).await
    }

    pub async fn e2ee_rotate_vault(&self, vault_id: String) -> Result<u32> {
        self.core().e2ee_rotate_vault(vault_id).await
    }

    pub async fn e2ee_pending_members(&self, vault_id: String) -> Result<Vec<E2eeMember>> {
        self.core().e2ee_pending_members(vault_id).await
    }

    #[uniffi::method(default(user_ids))]
    pub async fn e2ee_add_members(
        &self,
        vault_id: String,
        user_ids: Option<Vec<String>>,
    ) -> Result<u32> {
        self.core().e2ee_add_members(vault_id, user_ids).await
    }

    #[uniffi::method(default(title = None, record = None))]
    pub async fn open_server_session_unlocked(
        &self,
        host_id: String,
        cols: u32,
        rows: u32,
        title: Option<String>,
        record: Option<bool>,
    ) -> Result<crate::server::ServerSession> {
        self.core()
            .open_server_session_unlocked(host_id, cols, rows, title, record)
            .await
    }

    #[uniffi::method(default(trust = false))]
    pub async fn test_host_unlocked(&self, host_id: String, trust: bool) -> Result<String> {
        self.core().test_host_unlocked(host_id, trust).await
    }

    pub async fn team_sso(&self, team_id: String) -> Result<Option<SsoSettings>> {
        self.core().team_sso(team_id).await
    }

    #[uniffi::method(default(client_secret))]
    pub async fn set_team_sso(
        &self,
        team_id: String,
        settings: SsoSettings,
        client_secret: Option<String>,
    ) -> Result<SsoSettings> {
        self.core()
            .set_team_sso(team_id, settings, client_secret)
            .await
    }

    pub async fn delete_team_sso(&self, team_id: String) -> Result<()> {
        self.core().delete_team_sso(team_id).await
    }

    pub async fn team_domains(&self, team_id: String) -> Result<Vec<TeamDomainInfo>> {
        self.core().team_domains(team_id).await
    }

    pub async fn add_team_domain(&self, team_id: String, domain: String) -> Result<TeamDomainInfo> {
        self.core().add_team_domain(team_id, domain).await
    }

    pub async fn verify_team_domain(
        &self,
        team_id: String,
        domain: String,
    ) -> Result<TeamDomainInfo> {
        self.core().verify_team_domain(team_id, domain).await
    }

    pub async fn remove_team_domain(&self, team_id: String, domain: String) -> Result<()> {
        self.core().remove_team_domain(team_id, domain).await
    }

    #[uniffi::method(default(id))]
    pub async fn audit_search(
        &self,
        scope: AuditScope,
        query: AuditQuery,
        id: Option<String>,
    ) -> Result<Vec<AuditEvent>> {
        self.core().audit_search(scope, query, id).await
    }

    #[uniffi::method(default(id))]
    pub async fn audit_export(
        &self,
        scope: AuditScope,
        query: AuditQuery,
        format: String,
        local_path: String,
        id: Option<String>,
    ) -> Result<u64> {
        self.core()
            .audit_export(scope, query, format, local_path, id)
            .await
    }

    pub async fn team_audit_retention(&self, team_id: String) -> Result<Option<u32>> {
        self.core().team_audit_retention(team_id).await
    }

    pub async fn set_team_audit_retention(
        &self,
        team_id: String,
        days: Option<u32>,
    ) -> Result<Option<u32>> {
        self.core().set_team_audit_retention(team_id, days).await
    }

    #[uniffi::method(default(id))]
    pub async fn audit_sinks(
        &self,
        scope: AuditScope,
        id: Option<String>,
    ) -> Result<Vec<AuditSinkInfo>> {
        self.core().audit_sinks(scope, id).await
    }

    #[uniffi::method(default(id))]
    pub async fn create_audit_sink(
        &self,
        scope: AuditScope,
        sink: AuditSinkInput,
        id: Option<String>,
    ) -> Result<AuditSinkCreated> {
        self.core().create_audit_sink(scope, sink, id).await
    }

    #[uniffi::method(default(id = None, name = None, actions = None, enabled = None))]
    pub async fn update_audit_sink(
        &self,
        scope: AuditScope,
        sink_id: String,
        id: Option<String>,
        name: Option<String>,
        actions: Option<Vec<String>>,
        enabled: Option<bool>,
    ) -> Result<AuditSinkInfo> {
        self.core()
            .update_audit_sink(scope, sink_id, id, name, actions, enabled)
            .await
    }

    #[uniffi::method(default(id))]
    pub async fn delete_audit_sink(
        &self,
        scope: AuditScope,
        sink_id: String,
        id: Option<String>,
    ) -> Result<()> {
        self.core().delete_audit_sink(scope, sink_id, id).await
    }

    #[uniffi::method(default(id))]
    pub async fn test_audit_sink(
        &self,
        scope: AuditScope,
        sink_id: String,
        id: Option<String>,
    ) -> Result<AuditSinkTest> {
        self.core().test_audit_sink(scope, sink_id, id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers_and_error_variants() {
        let k = e2ee::UserKeyPair::generate();
        assert_eq!(e2ee_fingerprint(k.public_b64()).unwrap(), k.fingerprint());
        assert!(e2ee_fingerprint("not base64".into()).is_err());
        let rk = e2ee::RecoveryKey::generate();
        assert!(e2ee_recovery_key_valid(rk.display().to_string()));
        assert!(!e2ee_recovery_key_valid("AAAA-BBBB".into()));
        let ok = e2ee_recovery_key_check(rk.display().to_uppercase());
        assert!(ok.valid && ok.words == 24 && ok.reason.is_empty());
        let mut words: Vec<String> = rk.display().split(' ').map(String::from).collect();
        words[2] = "notaword".into();
        let bad = e2ee_recovery_key_check(words.join(" "));
        assert_eq!((bad.reason.as_str(), bad.word), ("unknown_word", 3));
        let old = e2ee_recovery_key_check("A".repeat(56));
        assert_eq!(old.reason, "old_format");
        assert_eq!(e2ee_recovery_wordlist().len(), 2048);
        // The codes the apps branch on have their own variants.
        let locked: TermoakError =
            termoak_core::CoreError::vault(termoak_core::error::codes::E2EE_LOCKED, "locked")
                .into();
        assert!(matches!(locked, TermoakError::E2eeLocked(_)));
        assert_eq!(
            crate::error::api_error_info(locked.to_string())
                .unwrap()
                .code,
            "e2ee_locked"
        );
        let sso: TermoakError = termoak_client::ClientError::Api {
            status: 403,
            code: "sso_required".into(),
            message: "Corp signs in through single sign-on".into(),
            details: serde_json::json!({"team_name": "Corp"}),
        }
        .into();
        assert!(matches!(sso, TermoakError::SsoRequired(_)));
        let info = crate::error::api_error_info(sso.to_string()).unwrap();
        assert!(info.details_json.contains("Corp"));
        // A query maps to the audit filter.
        let q = AuditQuery {
            action: Some("e2ee.*".into()),
            text: Some("db".into()),
            limit: Some(10),
            ..Default::default()
        };
        let f = q.filter().unwrap();
        assert_eq!(
            (f.action.as_deref(), f.q.as_deref(), f.limit),
            (Some("e2ee.*"), Some("db"), Some(10))
        );
        assert!(matches!(
            audit_of(AuditScope::Team, &None),
            Err(TermoakError::Invalid(_))
        ));
    }
}

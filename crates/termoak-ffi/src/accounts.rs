//! Several accounts (servers) on one device, vaults and moving items
//! between them.
//!
//! - [`TermoakCore`] works with the **current account** (legacy methods:
//!   `login`, `sync_now`, `api_*`, `open_server_session`...) and lists items
//!   of the current view (`set_account_view`).
//! - [`AccountHandle`] (`TermoakCore::account`) is one account: its sync,
//!   API, server sessions, AI, events and vault management.
//! - Item records carry `account_id` (`None`: This device), `vault_id`,
//!   `access` and `secret_hidden`.

use std::sync::Arc;

use serde_json::{Value, json};
use termoak_client::accounts as ca;
use termoak_client::{AccountView, LocalTransfer, Scope, servers};
use termoak_core::model as cm;
use termoak_core::transfer as ct;
use termoak_core::{Id, store::DirtySummary};

use crate::account::AuditEvent;
use crate::error::{Result, TermoakError};
use crate::models::{parse_id, parse_opt_id};
use crate::runtime::{block_on, run};
use crate::server::SyncReport;
use crate::vault::TermoakCore;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Which server to sign in to.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ServerChoice {
    /// The official server ([`official_server_url`]).
    Official,
    /// Your own server.
    Custom { url: String },
}

impl From<ServerChoice> for servers::ServerChoice {
    fn from(c: ServerChoice) -> Self {
        match c {
            ServerChoice::Official => servers::ServerChoice::Official,
            ServerChoice::Custom { url } => servers::ServerChoice::Custom(url),
        }
    }
}

/// State of an account on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AccountStatus {
    Active,
    /// The session ended: its data stays readable; show "Sign in again to
    /// sync" with the sign-in form prefilled.
    NeedsSignIn,
    /// The email is not verified yet: show the code screen
    /// (`verify_account`, `resend_account_code`).
    Unverified,
    Unknown,
}

impl From<ca::AccountStatus> for AccountStatus {
    fn from(s: ca::AccountStatus) -> Self {
        match s {
            ca::AccountStatus::Active => Self::Active,
            ca::AccountStatus::NeedsSignIn => Self::NeedsSignIn,
            ca::AccountStatus::Unverified => Self::Unverified,
            ca::AccountStatus::Unknown => Self::Unknown,
        }
    }
}

/// An account signed in on this device.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct AccountInfo {
    pub id: String,
    /// Canonical server URL.
    pub server_url: String,
    /// The server's host, to show it ("ssh.example.com").
    pub server_name: String,
    /// It is the official server (hide its address).
    pub official: bool,
    /// The connection is not encrypted (`http://`): show a warning.
    pub insecure: bool,
    pub email: String,
    pub name: String,
    /// The user's id on that server (also the id of their personal vault).
    pub user_id: Option<String>,
    pub status: AccountStatus,
    pub color: Option<String>,
    /// The current account.
    pub is_current: bool,
    /// The server has vaults; otherwise hide the vault UI for this account
    /// ("Update the server to use vaults").
    pub vaults_supported: bool,
    /// Last successful sync (ms).
    pub last_sync_at: Option<i64>,
}

/// Kind of vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum VaultKind {
    /// Yours alone (translate "Personal"); it cannot be shared or deleted.
    Personal,
    /// Owned by a user, shared with members.
    Shared,
    /// Owned by a team.
    Team,
    Unknown,
}

impl From<cm::VaultKind> for VaultKind {
    fn from(k: cm::VaultKind) -> Self {
        match k {
            cm::VaultKind::Personal => Self::Personal,
            cm::VaultKind::Shared => Self::Shared,
            cm::VaultKind::Team => Self::Team,
            cm::VaultKind::Unknown => Self::Unknown,
        }
    }
}

/// Role in a vault (`UseOnly` < `Editor` < `Manager`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum VaultRole {
    /// Uses the items, never sees their secrets nor changes them.
    UseOnly,
    Editor,
    /// Owner, or a team owner/admin of a team vault.
    Manager,
    Unknown,
}

impl From<cm::VaultRole> for VaultRole {
    fn from(r: cm::VaultRole) -> Self {
        match r {
            cm::VaultRole::UseOnly => Self::UseOnly,
            cm::VaultRole::Editor => Self::Editor,
            cm::VaultRole::Manager => Self::Manager,
            cm::VaultRole::Unknown => Self::Unknown,
        }
    }
}

impl VaultRole {
    fn to_core(self) -> Result<cm::VaultRole> {
        match self {
            VaultRole::UseOnly => Ok(cm::VaultRole::UseOnly),
            VaultRole::Editor => Ok(cm::VaultRole::Editor),
            VaultRole::Manager => Ok(cm::VaultRole::Manager),
            VaultRole::Unknown => Err(TermoakError::Invalid("choose a role".into())),
        }
    }
}

/// A vault of an account.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct VaultInfo {
    pub id: String,
    pub account_id: String,
    pub name: String,
    pub description: String,
    pub kind: VaultKind,
    /// Your role.
    pub role: VaultRole,
    pub team_id: Option<String>,
    /// Team vaults: the team's name.
    pub team_name: Option<String>,
    /// Name of the owner (user or team).
    pub owner_name: Option<String>,
    pub color: Option<String>,
    pub icon: Option<String>,
    /// Explicit grants (users and teams).
    pub member_count: i64,
    pub host_count: i64,
    /// Strict: Use-only members only connect through the server.
    pub strict: bool,
    /// Team vaults: role of plain team members (`None`: no access).
    pub team_member_role: Option<VaultRole>,
}

impl VaultInfo {
    fn from_core(account: Id, v: &cm::Vault) -> Self {
        let team = v.kind == cm::VaultKind::Team;
        VaultInfo {
            id: v.id.to_string(),
            account_id: account.to_string(),
            name: v.name.clone(),
            description: v.description.clone(),
            kind: v.kind.into(),
            role: v.role.unwrap_or(cm::VaultRole::Unknown).into(),
            team_id: v.owner_team_id.map(|t| t.to_string()),
            team_name: if team { v.owner_name.clone() } else { None },
            owner_name: v.owner_name.clone(),
            color: v.color.clone(),
            icon: v.icon.clone(),
            member_count: v.member_count,
            host_count: v.item_counts.get("host").copied().unwrap_or(0),
            strict: !v.settings.use_only_local,
            team_member_role: v.team_member_role.map(Into::into),
        }
    }
}

/// Which items a listing shows.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ItemFilter {
    /// Accounts (`None`: every account; empty: none).
    #[uniffi(default)]
    pub account_ids: Option<Vec<String>>,
    /// Vaults (`None`: every vault).
    #[uniffi(default)]
    pub vault_ids: Option<Vec<String>>,
    /// Include This-device items.
    #[uniffi(default = true)]
    pub include_device: bool,
}

impl ItemFilter {
    pub(crate) fn into_client(self) -> Result<termoak_client::ItemFilter> {
        let ids = |v: Option<Vec<String>>| -> Result<Option<Vec<Id>>> {
            v.map(|l| l.iter().map(|s| parse_id(s)).collect::<Result<Vec<_>>>())
                .transpose()
        };
        Ok(termoak_client::ItemFilter {
            accounts: ids(self.account_ids)?,
            vaults: ids(self.vault_ids)?,
            include_device: self.include_device,
        })
    }
}

/// An item to move or copy.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ItemRef {
    /// `None`: This device.
    #[uniffi(default)]
    pub account_id: Option<String>,
    pub id: String,
}

/// What signing out did.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SignOutReport {
    /// Signed out and its data deleted. `false` when there are changes not
    /// uploaded yet: ask "N changes are not uploaded yet: Sync now /
    /// Discard" and call again with `discard_unsynced` (or sync first).
    pub signed_out: bool,
    pub unsynced: u64,
    pub discarded: u64,
}

impl From<ca::SignOutReport> for SignOutReport {
    fn from(r: ca::SignOutReport) -> Self {
        Self {
            signed_out: r.signed_out,
            unsynced: r.unsynced as u64,
            discarded: r.discarded as u64,
        }
    }
}

/// Move (same ids) or copy (new ids).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TransferMode {
    Move,
    Copy,
}

/// An item that moved.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TransferredItem {
    /// `host`, `group`, `identity`, `key`, `snippet`, `forward`,
    /// `known_host` or `memory`.
    pub kind: String,
    pub id: String,
}

/// An item copied (or reused) with a new id.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CopiedItem {
    pub kind: String,
    pub from_id: String,
    pub to_id: String,
}

/// A reference cleared by the transfer.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DetachedReference {
    pub kind: String,
    pub id: String,
    pub field: String,
}

/// A remark about a transferred item.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TransferWarning {
    pub code: String,
    pub kind: String,
    pub id: String,
}

/// Outcome of a move or copy (or its plan, with `dry_run`: show "This will
/// also copy key `deploy`" before confirming).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TransferResult {
    pub moved: Vec<TransferredItem>,
    pub copied: Vec<CopiedItem>,
    /// Existing items of the target used instead of a copy (same key).
    pub reused: Vec<CopiedItem>,
    pub detached: Vec<DetachedReference>,
    pub warnings: Vec<TransferWarning>,
    pub dry_run: bool,
}

impl From<ct::TransferResult> for TransferResult {
    fn from(r: ct::TransferResult) -> Self {
        let copied = |c: &ct::CopiedItem| CopiedItem {
            kind: c.kind.as_str().into(),
            from_id: c.from.to_string(),
            to_id: c.to.to_string(),
        };
        Self {
            moved: r
                .moved
                .iter()
                .map(|m| TransferredItem {
                    kind: m.kind.as_str().into(),
                    id: m.id.to_string(),
                })
                .collect(),
            copied: r.copied.iter().map(copied).collect(),
            reused: r.reused.iter().map(copied).collect(),
            detached: r
                .detached
                .iter()
                .map(|d| DetachedReference {
                    kind: d.kind.as_str().into(),
                    id: d.id.to_string(),
                    field: d.field.clone(),
                })
                .collect(),
            warnings: r
                .warnings
                .iter()
                .map(|w| TransferWarning {
                    code: w.code.clone(),
                    kind: w.kind.as_str().into(),
                    id: w.id.to_string(),
                })
                .collect(),
            dry_run: r.dry_run,
        }
    }
}

/// Who a vault member is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum VaultMemberKind {
    User,
    Team,
    Unknown,
}

/// A member of a vault.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct VaultMember {
    /// Grant id (for implicit members, the user id).
    pub id: String,
    pub kind: VaultMemberKind,
    pub user_id: Option<String>,
    pub email: Option<String>,
    pub name: String,
    pub team_id: Option<String>,
    pub role: VaultRole,
    /// The owner or a team admin: cannot be changed or removed.
    pub implicit: bool,
    pub added_at: i64,
}

impl From<cm::VaultMember> for VaultMember {
    fn from(m: cm::VaultMember) -> Self {
        let (kind, user_id, email, name, team_id) = match m.principal {
            cm::VaultPrincipal::User { id, email, name } => (
                VaultMemberKind::User,
                Some(id.to_string()),
                Some(email),
                name,
                None,
            ),
            cm::VaultPrincipal::Team { id, name } => (
                VaultMemberKind::Team,
                None,
                None,
                name,
                Some(id.to_string()),
            ),
            cm::VaultPrincipal::Unknown => {
                (VaultMemberKind::Unknown, None, None, String::new(), None)
            }
        };
        Self {
            id: m.id.to_string(),
            kind,
            user_id,
            email,
            name,
            team_id,
            role: m.role.into(),
            implicit: m.implicit,
            added_at: m.added_at,
        }
    }
}

/// Who to share a vault with.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum VaultMemberTarget {
    /// A user of the same server.
    User { email: String },
    /// A team you belong to.
    Team { team_id: String },
}

/// A new vault.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct NewVault {
    pub name: String,
    #[uniffi(default)]
    pub description: Option<String>,
    #[uniffi(default)]
    pub color: Option<String>,
    #[uniffi(default)]
    pub icon: Option<String>,
    /// Owned by this team (you must be a team owner or admin).
    #[uniffi(default)]
    pub team_id: Option<String>,
    /// Team vaults: role of plain team members (default `Editor`).
    #[uniffi(default)]
    pub team_member_role: Option<VaultRole>,
    /// Use-only members only connect through the server.
    #[uniffi(default)]
    pub strict: bool,
}

/// Changes to a vault (`None`: unchanged).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultChanges {
    #[uniffi(default)]
    pub name: Option<String>,
    #[uniffi(default)]
    pub description: Option<String>,
    #[uniffi(default)]
    pub color: Option<String>,
    #[uniffi(default)]
    pub clear_color: bool,
    #[uniffi(default)]
    pub icon: Option<String>,
    #[uniffi(default)]
    pub clear_icon: bool,
    #[uniffi(default)]
    pub strict: Option<bool>,
    /// Team vaults: role of plain team members.
    #[uniffi(default)]
    pub team_member_role: Option<VaultRole>,
    /// Team vaults: plain team members get no access.
    #[uniffi(default)]
    pub no_team_access: bool,
}

/// Local changes lost in a vault (show "2 unsynced changes were
/// discarded").
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DiscardedChanges {
    pub vault_id: String,
    pub vault_name: String,
    pub count: u64,
}

/// A vault by id and name.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultRef {
    pub id: String,
    pub name: String,
}

/// Pending local changes of an account.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UnsyncedChanges {
    pub total: u64,
}

impl From<DirtySummary> for UnsyncedChanges {
    fn from(d: DirtySummary) -> Self {
        Self {
            total: d.total as u64,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn account_info(ws: &termoak_client::Workspace, i: ca::AccountInfo) -> AccountInfo {
    let current = ws.current().map(|a| a.id);
    AccountInfo {
        id: i.id.to_string(),
        server_name: i.server_host(),
        insecure: servers::is_insecure(&i.server_url),
        official: i.official,
        email: i.email.clone(),
        name: i.name.clone(),
        user_id: i.user_id.map(|u| u.to_string()),
        status: i.status.into(),
        color: i.color.clone(),
        is_current: current == Some(i.id),
        vaults_supported: i.vaults_supported(),
        last_sync_at: i.last_sync_at,
        server_url: i.server_url,
    }
}

/// The canonical URL of the official server (`https://termoak.com`, or
/// the build's override). Show it as "Termoak (termoak.com)".
#[uniffi::export]
pub fn official_server_url() -> String {
    servers::official_server()
}

/// The canonical form of a server URL as the accounts store it (trimmed,
/// `https://` added, no path). Fails if it is not a valid address.
#[uniffi::export]
pub fn canonical_server_url(url: String) -> Result<String> {
    Ok(servers::canonical(&url)?)
}

// ---------------------------------------------------------------------------
// TermoakCore: accounts, views, vaults and transfers
// ---------------------------------------------------------------------------

#[uniffi::export]
impl TermoakCore {
    /// The accounts on this device, in order.
    pub fn accounts(&self) -> Vec<AccountInfo> {
        self.ws
            .accounts()
            .into_iter()
            .map(|i| account_info(&self.ws, i))
            .collect()
    }

    /// The current account (the one of the view; in the "all accounts"
    /// view, the first active one).
    pub fn current_account(&self) -> Option<AccountInfo> {
        self.ws.current().map(|a| account_info(&self.ws, a.info()))
    }

    /// Shows one account (`Some`) or every account together (`None`). No
    /// network needed; saved for the next start.
    pub fn set_account_view(&self, account_id: Option<String>) -> Result<()> {
        let view = match parse_opt_id(&account_id)? {
            Some(id) => AccountView::One(id),
            None => AccountView::All,
        };
        Ok(block_on(self.ws.set_view(view))?)
    }

    /// The account shown (`None`: all of them).
    pub fn account_view(&self) -> Option<String> {
        match self.ws.view() {
            AccountView::One(id) => Some(id.to_string()),
            AccountView::All => None,
        }
    }

    /// Signs in (adds the account, or signs the same account in again) and
    /// makes it current. With two-factor authentication and no code it
    /// fails with `TotpRequired`. Then sync it (`account(id).sync_now()`).
    #[uniffi::method(default(totp_code))]
    pub async fn sign_in(
        &self,
        server: ServerChoice,
        email: String,
        password: String,
        totp_code: Option<String>,
    ) -> Result<AccountInfo> {
        crate::vault::install_crypto_provider();
        let ws = self.ws.clone();
        let code = totp_code
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty());
        run(async move {
            let acc = ws
                .sign_in(server.into(), &email, &password, code.as_deref())
                .await?;
            Ok(account_info(&ws, acc.info()))
        })
        .await
    }

    /// Creates an account (official server, or your own with open
    /// registration or an invitation). If the server verifies emails, the
    /// account is `Unverified` until `verify_account`.
    #[uniffi::method(default(invite))]
    pub async fn sign_up(
        &self,
        server: ServerChoice,
        email: String,
        name: String,
        password: String,
        invite: Option<String>,
    ) -> Result<AccountInfo> {
        crate::vault::install_crypto_provider();
        let ws = self.ws.clone();
        let invite = invite
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty());
        run(async move {
            let acc = ws
                .sign_up(server.into(), &email, &name, &password, invite.as_deref())
                .await?;
            Ok(account_info(&ws, acc.info()))
        })
        .await
    }

    /// Verifies an account's email with the six-digit code.
    #[uniffi::method(default(totp_code))]
    pub async fn verify_account(
        &self,
        account_id: String,
        code: String,
        totp_code: Option<String>,
    ) -> Result<AccountInfo> {
        let id = parse_id(&account_id)?;
        let ws = self.ws.clone();
        let code: String = code.chars().filter(char::is_ascii_digit).collect();
        let totp = totp_code
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty());
        run(async move {
            let acc = ws.verify_account(id, &code, totp.as_deref()).await?;
            Ok(account_info(&ws, acc.info()))
        })
        .await
    }

    /// Emails a new verification code to an account.
    pub async fn resend_account_code(&self, account_id: String) -> Result<()> {
        let id = parse_id(&account_id)?;
        let ws = self.ws.clone();
        run(async move { Ok(ws.resend_account_code(id).await?) }).await
    }

    /// Signs out of one account and deletes its data on this device (other
    /// accounts and This-device items stay). Unregister the push token on
    /// that server first. With unsynced changes and `discard_unsynced =
    /// false`, nothing happens: see [`SignOutReport::signed_out`].
    pub async fn sign_out_account(
        &self,
        account_id: String,
        discard_unsynced: bool,
    ) -> Result<SignOutReport> {
        let id = parse_id(&account_id)?;
        let ws = self.ws.clone();
        run(async move { Ok(ws.sign_out(id, discard_unsynced).await?.into()) }).await
    }

    /// Changes not uploaded yet of an account.
    pub fn unsynced_changes(&self, account_id: String) -> Result<UnsyncedChanges> {
        let acc = self.ws.require_account(parse_id(&account_id)?)?;
        Ok(block_on(acc.store.dirty_summary())?.into())
    }

    /// One account: its sync, API, server sessions, AI, events and vaults.
    pub fn account(&self, account_id: String) -> Result<Arc<AccountHandle>> {
        let id = parse_id(&account_id)?;
        self.ws.require_account(id)?;
        Ok(Arc::new(AccountHandle {
            id,
            core: Arc::new(TermoakCore {
                ws: self.ws.clone(),
                pinned: Some(id),
            }),
        }))
    }

    /// The vaults of the accounts of `filter` (default: the current view),
    /// as of their last sync.
    #[uniffi::method(default(filter))]
    pub fn vaults(&self, filter: Option<ItemFilter>) -> Result<Vec<VaultInfo>> {
        let f = self.filter_of(filter)?;
        let mut out = Vec::new();
        for acc in self.ws.account_list() {
            if f.accounts
                .as_ref()
                .is_some_and(|ids| !ids.contains(&acc.id))
            {
                continue;
            }
            for v in block_on(acc.store.local_vault_list())? {
                if f.vaults.as_ref().is_some_and(|ids| !ids.contains(&v.id)) {
                    continue;
                }
                out.push(VaultInfo::from_core(acc.id, &v));
            }
        }
        Ok(out)
    }

    /// Moves or copies items (all from the same place) to an account's vault
    /// (`target_account` + `target_vault`, default: its personal vault) or
    /// to This device (`target_account = None`). Inside one account it is
    /// an online operation; between This device and an account, or across
    /// accounts, it happens here and syncs. `dry_run` returns the plan.
    #[uniffi::method(default(dry_run))]
    pub async fn transfer(
        &self,
        items: Vec<ItemRef>,
        target_account: Option<String>,
        target_vault: Option<String>,
        mode: TransferMode,
        dry_run: bool,
    ) -> Result<TransferResult> {
        let mut refs = Vec::with_capacity(items.len());
        for it in &items {
            refs.push(termoak_client::ItemRef {
                scope: Scope::from_account(parse_opt_id(&it.account_id)?),
                id: parse_id(&it.id)?,
            });
        }
        let to = Scope::from_account(parse_opt_id(&target_account)?);
        let vault = parse_opt_id(&target_vault)?;
        let ws = self.ws.clone();
        run(async move {
            Ok(ws
                .transfer(LocalTransfer {
                    items: refs,
                    to,
                    vault,
                    mode: match mode {
                        TransferMode::Move => ct::TransferMode::Move,
                        TransferMode::Copy => ct::TransferMode::Copy,
                    },
                    dependencies: ct::Dependencies::Auto,
                    dry_run,
                    force: false,
                })
                .await?
                .into())
        })
        .await
    }

    /// Syncs an account shortly after its items change on this device, and
    /// when its server announces changes (off by default).
    pub fn set_auto_sync(&self, enabled: bool) {
        self.ws.set_auto_sync(enabled);
    }
}

// ---------------------------------------------------------------------------
// AccountHandle
// ---------------------------------------------------------------------------

/// One account: everything that talks to its server.
#[derive(uniffi::Object)]
pub struct AccountHandle {
    id: Id,
    core: Arc<TermoakCore>,
}

impl AccountHandle {
    fn account(&self) -> Result<Arc<termoak_client::Account>> {
        Ok(self.core.ws.require_account(self.id)?)
    }

    async fn with_api<T, F, Fut>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(termoak_client::ApiClient) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<T>> + Send,
    {
        self.core.with_api(f).await
    }

    /// Syncs in the background after a vault change (errors are logged).
    fn sync_later(&self) {
        if let Ok(acc) = self.account() {
            crate::runtime::runtime().spawn(async move {
                if let Err(e) = acc.sync_once().await {
                    tracing::warn!(error = %e, "sync after a vault change failed");
                }
            });
        }
    }
}

#[uniffi::export]
impl AccountHandle {
    pub fn id(&self) -> String {
        self.id.to_string()
    }

    pub fn info(&self) -> Result<AccountInfo> {
        Ok(account_info(&self.core.ws, self.account()?.info()))
    }

    /// Asks the server for its features and your user data again.
    pub async fn refresh_info(&self) -> Result<AccountInfo> {
        let acc = self.account()?;
        let ws = self.core.ws.clone();
        run(async move { Ok(account_info(&ws, acc.refresh_info().await?)) }).await
    }

    /// One sync round of this account (vaults: sync v2; older servers: the
    /// legacy sync). Show a notice when `discarded`, `vaults_added` or
    /// `vaults_lost` is not empty.
    pub async fn sync_now(&self) -> Result<SyncReport> {
        self.core.sync_now().await
    }

    // ----- Generic API -----

    pub async fn api_request(
        &self,
        method: crate::server::HttpMethod,
        path: String,
        body_json: Option<String>,
    ) -> Result<String> {
        self.core.api_request(method, path, body_json).await
    }

    pub async fn api_get(&self, path: String) -> Result<String> {
        self.core.api_get(path).await
    }

    pub async fn api_post(&self, path: String, body_json: Option<String>) -> Result<String> {
        self.core.api_post(path, body_json).await
    }

    pub async fn api_put(&self, path: String, body_json: Option<String>) -> Result<String> {
        self.core.api_put(path, body_json).await
    }

    pub async fn api_patch(&self, path: String, body_json: Option<String>) -> Result<String> {
        self.core.api_patch(path, body_json).await
    }

    pub async fn api_delete(&self, path: String) -> Result<String> {
        self.core.api_delete(path).await
    }

    // ----- Server sessions -----

    pub async fn list_server_sessions(&self) -> Result<crate::server::ServerSessionList> {
        self.core.list_server_sessions().await
    }

    /// Opens a persistent terminal on this account's server.
    pub async fn open_server_session(
        &self,
        host_id: String,
        cols: u32,
        rows: u32,
        title: Option<String>,
        record: Option<bool>,
    ) -> Result<crate::server::ServerSession> {
        self.core
            .open_server_session(host_id, cols, rows, title, record, Some(self.id()))
            .await
    }

    pub async fn get_server_session(
        &self,
        session_id: String,
    ) -> Result<crate::server::ServerSession> {
        self.core.get_server_session(session_id).await
    }

    pub async fn close_server_session(&self, session_id: String) -> Result<()> {
        self.core.close_server_session(session_id).await
    }

    pub async fn session_activity(
        &self,
        session_id: String,
    ) -> Result<Option<crate::server::SessionActivity>> {
        self.core.session_activity(session_id).await
    }

    pub async fn attach_server_session(
        &self,
        session_id: String,
        listener: Arc<dyn crate::remote::ServerTerminalListener>,
    ) -> Result<Arc<crate::remote::ServerTerminalHandle>> {
        self.core.attach_server_session(session_id, listener).await
    }

    // ----- Events -----

    /// This account's events (`"account_id"` is in every event).
    pub async fn subscribe_events(
        &self,
        listener: Arc<dyn crate::remote::ServerEventListener>,
    ) -> Result<Arc<crate::remote::EventSubscription>> {
        self.core.subscribe_events(listener).await
    }

    // ----- Background AI -----

    pub async fn create_ai_task(
        &self,
        request: crate::server::AiTaskRequest,
    ) -> Result<crate::server::AiTask> {
        self.core.create_ai_task(request).await
    }

    pub async fn list_ai_tasks(&self, limit: u32) -> Result<Vec<crate::server::AiTask>> {
        self.core.list_ai_tasks(limit).await
    }

    pub async fn get_ai_task(&self, task_id: String) -> Result<crate::server::AiTask> {
        self.core.get_ai_task(task_id).await
    }

    pub async fn send_ai_message(
        &self,
        task_id: String,
        text: String,
    ) -> Result<crate::server::AiTask> {
        self.core.send_ai_message(task_id, text).await
    }

    pub async fn cancel_ai_task(&self, task_id: String) -> Result<()> {
        self.core.cancel_ai_task(task_id).await
    }

    pub async fn set_ai_task_mode(
        &self,
        task_id: String,
        mode: crate::server::AiPermissionMode,
    ) -> Result<()> {
        self.core.set_ai_task_mode(task_id, mode).await
    }

    pub async fn list_pending_approvals(&self) -> Result<Vec<crate::server::AiApproval>> {
        self.core.list_pending_approvals().await
    }

    pub async fn decide_approval(
        &self,
        task_id: String,
        approval_id: String,
        approve: bool,
        always: bool,
    ) -> Result<()> {
        self.core
            .decide_approval(task_id, approval_id, approve, always)
            .await
    }

    pub async fn ai_access(&self) -> Result<crate::server::AiAccessInfo> {
        self.core.ai_access().await
    }

    // ----- Files through the server -----

    pub async fn server_sftp_home(&self, host_id: String) -> Result<String> {
        self.core.server_sftp_home(host_id, Some(self.id())).await
    }

    pub async fn server_sftp_list(
        &self,
        host_id: String,
        path: String,
    ) -> Result<Vec<crate::ssh::RemoteFile>> {
        self.core
            .server_sftp_list(host_id, path, Some(self.id()))
            .await
    }

    // ----- Vaults -----

    /// This account's vaults from the server (with your role, owner and
    /// counts).
    pub async fn list_vaults(&self) -> Result<Vec<VaultInfo>> {
        let id = self.id;
        self.with_api(move |api| async move {
            Ok(api
                .vaults()
                .await?
                .iter()
                .map(|v| VaultInfo::from_core(id, v))
                .collect())
        })
        .await
    }

    /// Creates a vault (for a team: as a team owner or admin).
    pub async fn create_vault(&self, vault: NewVault) -> Result<VaultInfo> {
        let id = self.id;
        let team = parse_opt_id(&vault.team_id)?;
        let role = vault.team_member_role.map(VaultRole::to_core).transpose()?;
        let body = json!({
            "name": vault.name.trim(),
            "description": vault.description,
            "color": vault.color,
            "icon": vault.icon,
            "team_id": team,
            "team_member_role": role,
            "settings": {"use_only_local": !vault.strict},
        });
        let v = self
            .with_api(move |api| async move { Ok(api.create_vault(&body).await?) })
            .await?;
        self.sync_later();
        Ok(VaultInfo::from_core(id, &v))
    }

    /// Changes a vault (managers; the personal vault: only name, color and
    /// icon).
    pub async fn update_vault(&self, vault_id: String, changes: VaultChanges) -> Result<VaultInfo> {
        let id = self.id;
        let vault = parse_id(&vault_id)?;
        let mut body = serde_json::Map::new();
        if let Some(n) = changes.name {
            body.insert("name".into(), json!(n.trim()));
        }
        if let Some(d) = changes.description {
            body.insert("description".into(), json!(d));
        }
        if changes.clear_color {
            body.insert("color".into(), Value::Null);
        } else if let Some(c) = changes.color {
            body.insert("color".into(), json!(c));
        }
        if changes.clear_icon {
            body.insert("icon".into(), Value::Null);
        } else if let Some(i) = changes.icon {
            body.insert("icon".into(), json!(i));
        }
        if let Some(strict) = changes.strict {
            body.insert("settings".into(), json!({"use_only_local": !strict}));
        }
        if changes.no_team_access {
            body.insert("team_member_role".into(), Value::Null);
        } else if let Some(r) = changes.team_member_role {
            body.insert("team_member_role".into(), json!(r.to_core()?));
        }
        let body = Value::Object(body);
        let v = self
            .with_api(move |api| async move { Ok(api.update_vault(vault, &body).await?) })
            .await?;
        self.sync_later();
        Ok(VaultInfo::from_core(id, &v))
    }

    /// Deletes a vault and its items (managers). `confirm_name` is the
    /// vault's name, typed by the user.
    pub async fn delete_vault(&self, vault_id: String, confirm_name: String) -> Result<()> {
        let vault = parse_id(&vault_id)?;
        self.with_api(move |api| async move { Ok(api.delete_vault(vault, &confirm_name).await?) })
            .await?;
        self.sync_later();
        Ok(())
    }

    /// Gives up your own grant on a vault.
    pub async fn leave_vault(&self, vault_id: String) -> Result<()> {
        let vault = parse_id(&vault_id)?;
        self.with_api(move |api| async move { Ok(api.leave_vault(vault).await?) })
            .await?;
        self.sync_later();
        Ok(())
    }

    /// Members of a vault, owners and team admins included (`implicit`).
    pub async fn vault_members(&self, vault_id: String) -> Result<Vec<VaultMember>> {
        let vault = parse_id(&vault_id)?;
        self.with_api(move |api| async move {
            Ok(api
                .vault_members(vault)
                .await?
                .into_iter()
                .map(Into::into)
                .collect())
        })
        .await
    }

    /// Shares a vault with a user (by email) or a team, as `Editor` or
    /// `UseOnly`.
    pub async fn add_vault_member(
        &self,
        vault_id: String,
        target: VaultMemberTarget,
        role: VaultRole,
    ) -> Result<VaultMember> {
        let vault = parse_id(&vault_id)?;
        let role = role.to_core()?;
        let body = match target {
            VaultMemberTarget::User { email } => json!({"email": email.trim(), "role": role}),
            VaultMemberTarget::Team { team_id } => {
                json!({"team_id": parse_id(&team_id)?, "role": role})
            }
        };
        self.with_api(
            move |api| async move { Ok(api.add_vault_member(vault, &body).await?.into()) },
        )
        .await
    }

    pub async fn set_vault_member_role(
        &self,
        vault_id: String,
        member_id: String,
        role: VaultRole,
    ) -> Result<VaultMember> {
        let vault = parse_id(&vault_id)?;
        let member = parse_id(&member_id)?;
        let role = role.to_core()?;
        self.with_api(move |api| async move {
            Ok(api.set_vault_member_role(vault, member, role).await?.into())
        })
        .await
    }

    pub async fn remove_vault_member(&self, vault_id: String, member_id: String) -> Result<()> {
        let vault = parse_id(&vault_id)?;
        let member = parse_id(&member_id)?;
        self.with_api(move |api| async move { Ok(api.remove_vault_member(vault, member).await?) })
            .await
    }

    /// Audit of a vault (managers), newest first.
    #[uniffi::method(default(before))]
    pub async fn vault_audit(
        &self,
        vault_id: String,
        limit: u32,
        before: Option<i64>,
    ) -> Result<Vec<AuditEvent>> {
        let vault = parse_id(&vault_id)?;
        self.with_api(move |api| async move {
            Ok(api
                .vault_audit(vault, before, limit)
                .await?
                .into_iter()
                .map(Into::into)
                .collect())
        })
        .await
    }
}

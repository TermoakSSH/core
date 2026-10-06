//! Local workspace: the device store ("This device" items, settings, the
//! account registry), one store per signed-in account, the local SSH
//! engine and the connection to each account's server.
//!
//! Layout of the data directory (layout 2, see [`crate::layout`]):
//!
//! ```text
//! termoak.db                  device store
//! accounts/<account_id>.db    one store per account (same schema)
//! termoak.db.pre-accounts     backup made by the layout migration (30 days)
//! recordings/…
//! ```
//!
//! Every store uses the same device key. The legacy single-server API
//! (`server`, `login`, `logout`, `sync_engine`...) is kept and works on the
//! current account.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;
use serde_json::Value;
use termoak_core::Store;
use termoak_core::crypto::MasterKey;
use termoak_core::model::TokenPair;
use termoak_core::time::now_ms;
use termoak_core::{Id, resolve::ResolvedHost};
use termoak_ssh::prompt::AuthPrompter;
use termoak_ssh::recording::Recorder;
use termoak_ssh::{
    ConnectOptions, Connection, HostKeyPolicy, PtyOptions, StoreVerifier, TerminalSession,
};
use tokio::sync::broadcast;

use crate::LOCAL_OWNER;
use crate::accounts::{
    self, Account, AccountInfo, AccountStatus, SignOutReport, open_account_store,
};
use crate::api::{self, ApiClient, AuthResponse};
use crate::error::{ClientError, Result};
use crate::items::{ItemRef, Scope};
use crate::layout;
use crate::servers::{self, ServerChoice};
use crate::sync::SyncEngine;
use crate::vault;

const DEVICE_NAME: &str = "device.name";

/// Which accounts the apps show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountView {
    /// One account (plus This device items).
    One(Id),
    /// Every account together.
    All,
}

struct State {
    accounts: RwLock<Vec<Arc<Account>>>,
    view: RwLock<AccountView>,
    /// Account chosen for this process only (CLI `--account`).
    pinned: RwLock<Option<Id>>,
    events: broadcast::Sender<Value>,
    /// Sync soon after local changes of an account.
    auto_sync: std::sync::atomic::AtomicBool,
}

/// The device's workspace. Cheap to clone.
#[derive(Clone)]
pub struct Workspace {
    /// The device store: "This device" items, settings, command history and
    /// the account registry.
    pub store: Store,
    pub dir: PathBuf,
    state: Arc<State>,
}

/// Path of the device store. The first time, it renames the database left
/// by AceitunoakSSH (the project's former name); if that fails, the old
/// database keeps being used in place.
pub fn database_path(dir: &Path) -> PathBuf {
    let new = |suffix: &str| dir.join(format!("termoak.db{suffix}"));
    let old = |suffix: &str| dir.join(format!("aceitunoak.db{suffix}"));
    if new("").exists() || !old("").exists() {
        return new("");
    }
    let mut moved = Vec::new();
    // The main file goes last: if anything fails, nothing is half renamed.
    for suffix in ["-wal", "-shm", ""] {
        if !old(suffix).exists() {
            continue;
        }
        if let Err(e) = std::fs::rename(old(suffix), new(suffix)) {
            tracing::warn!(error = %e, "could not rename the old database; using it in place");
            for suffix in moved {
                let _ = std::fs::rename(new(suffix), old(suffix));
            }
            return old("");
        }
        moved.push(suffix);
    }
    new("")
}

impl Workspace {
    /// Opens the user's default workspace.
    pub fn open_default() -> Result<Self> {
        let dir = vault::data_dir();
        std::fs::create_dir_all(&dir)?;
        let key = vault::load_or_create_key(&dir)?;
        Self::open(&dir, key)
    }

    /// Opens a workspace in `dir` with the given key: migrates the data
    /// layout if needed and opens every account store.
    pub fn open(dir: &Path, key: MasterKey) -> Result<Self> {
        let store = Store::open(&database_path(dir), key)?;
        layout::migrate(dir, &store)?;
        let mut accounts = Vec::new();
        for (info, tokens) in accounts::load_registry(&store)? {
            let acc_store = open_account_store(dir, &store, info.id)?;
            accounts.push(Account::new(info, tokens, acc_store, store.clone())?);
        }
        let view = store
            .call_blocking(|c, _| {
                Ok(c.query_row(
                    "SELECT value FROM meta WHERE key = ?1",
                    [layout::VIEW_KEY],
                    |r| r.get::<_, String>(0),
                )
                .ok())
            })?
            .and_then(|v| v.parse::<Id>().ok())
            .filter(|id| accounts.iter().any(|a| a.id == *id))
            .map(AccountView::One)
            .unwrap_or(AccountView::All);
        let (events, _) = broadcast::channel(256);
        Ok(Self {
            store,
            dir: dir.to_path_buf(),
            state: Arc::new(State {
                accounts: RwLock::new(accounts),
                view: RwLock::new(view),
                pinned: RwLock::new(None),
                events,
                auto_sync: std::sync::atomic::AtomicBool::new(false),
            }),
        })
    }

    /// Owner of the records of every local store.
    pub fn owner(&self) -> Id {
        LOCAL_OWNER
    }

    // ----- Accounts -----

    /// The signed-in accounts, in order.
    pub fn accounts(&self) -> Vec<AccountInfo> {
        self.state
            .accounts
            .read()
            .iter()
            .map(|a| a.info())
            .collect()
    }

    /// Every account object.
    pub fn account_list(&self) -> Vec<Arc<Account>> {
        self.state.accounts.read().clone()
    }

    pub fn account(&self, id: Id) -> Option<Arc<Account>> {
        self.state
            .accounts
            .read()
            .iter()
            .find(|a| a.id == id)
            .cloned()
    }

    /// An account, or `not_found`.
    pub fn require_account(&self, id: Id) -> Result<Arc<Account>> {
        self.account(id)
            .ok_or_else(|| ClientError::Invalid(format!("there is no account {id} on this device")))
    }

    /// The current account: the pinned one (CLI `--account`), the one of
    /// the view, or in the "all accounts" view the first active one.
    pub fn current(&self) -> Option<Arc<Account>> {
        if let Some(id) = *self.state.pinned.read()
            && let Some(a) = self.account(id)
        {
            return Some(a);
        }
        if let AccountView::One(id) = *self.state.view.read()
            && let Some(a) = self.account(id)
        {
            return Some(a);
        }
        let list = self.state.accounts.read();
        list.iter()
            .find(|a| a.status() == AccountStatus::Active)
            .or_else(|| list.first())
            .cloned()
    }

    pub fn view(&self) -> AccountView {
        *self.state.view.read()
    }

    /// Shows one account or all of them (saved for the next start).
    pub async fn set_view(&self, view: AccountView) -> Result<()> {
        let value = match view {
            AccountView::One(id) => {
                let acc = self.require_account(id)?;
                acc.touch();
                id.to_string()
            }
            AccountView::All => "all".to_string(),
        };
        *self.state.view.write() = view;
        self.store.meta_set(layout::VIEW_KEY, &value).await?;
        Ok(())
    }

    /// Uses `account` as the current one in this process only (not saved).
    pub fn pin(&self, account: Option<Id>) -> Result<()> {
        if let Some(id) = account {
            self.require_account(id)?;
        }
        *self.state.pinned.write() = account;
        Ok(())
    }

    /// The account pinned with [`pin`](Self::pin), if any.
    pub fn pinned(&self) -> Option<Id> {
        *self.state.pinned.read()
    }

    /// Finds an account by id, email or server (`ana@x.com`,
    /// `ana@x.com@ssh.example.com`, the id, or a prefix of the id).
    pub fn find_account(&self, query: &str) -> Result<Arc<Account>> {
        let q = query.trim();
        let list = self.account_list();
        if let Ok(id) = q.parse::<Id>()
            && let Some(a) = list.iter().find(|a| a.id == id)
        {
            return Ok(a.clone());
        }
        let found: Vec<_> = list
            .iter()
            .filter(|a| {
                let i = a.info();
                let host = i.server_host();
                i.id.to_string().starts_with(q)
                    || i.email.eq_ignore_ascii_case(q)
                    || format!("{}@{host}", i.email).eq_ignore_ascii_case(q)
                    || host.eq_ignore_ascii_case(q)
            })
            .cloned()
            .collect();
        match found.len() {
            1 => Ok(found.into_iter().next().expect("one")),
            0 => Err(ClientError::Invalid(format!(
                "there is no account \"{q}\" on this device"
            ))),
            _ => Err(ClientError::Invalid(format!(
                "there are several accounts \"{q}\": use email@server or the id"
            ))),
        }
    }

    /// Events of every account (with `"account_id"`), once
    /// [`start_events`](Self::start_events) runs.
    pub fn subscribe_events(&self) -> broadcast::Receiver<Value> {
        self.state.events.subscribe()
    }

    /// Starts the events WebSocket of every signed-in account (reconnects
    /// with backoff; `vault` events trigger a sync).
    pub fn start_events(&self) {
        for a in self.account_list() {
            if a.is_signed_in() {
                crate::events::start(&a, self.state.events.clone());
            }
        }
    }

    /// Stops every events WebSocket.
    pub fn stop_events(&self) {
        for a in self.account_list() {
            crate::events::stop(&a);
        }
    }

    /// Sync an account soon after its items change locally (off by default).
    pub fn set_auto_sync(&self, enabled: bool) {
        self.state
            .auto_sync
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn changed(&self, scope: Scope) {
        if let Scope::Account(id) = scope
            && self
                .state
                .auto_sync
                .load(std::sync::atomic::Ordering::Relaxed)
            && let Some(a) = self.account(id)
        {
            a.sync_soon();
        }
    }

    /// Account matching a server and user, if there is one: same instance
    /// (or canonical URL) and same user id (or email, for accounts that do
    /// not know their user id yet).
    fn existing_account(
        &self,
        url: &str,
        instance: Option<&str>,
        user: Id,
        email: &str,
    ) -> Option<Arc<Account>> {
        self.account_list().into_iter().find(|a| {
            let i = a.info();
            let same_server = i.server_url == url
                || matches!((i.instance_id.as_deref(), instance), (Some(x), Some(y)) if x == y);
            let same_user = match i.user_id {
                Some(u) => u == user,
                None => i.email.eq_ignore_ascii_case(email),
            };
            same_server && same_user
        })
    }

    /// Registers the result of a sign-in (new account, or the same account
    /// signed in again) and makes it current.
    async fn adopt(&self, url: &str, auth: AuthResponse) -> Result<Arc<Account>> {
        let info_json = ApiClient::new(url)?.info().await.ok();
        let instance = info_json
            .as_ref()
            .and_then(|v| v["instance_id"].as_str())
            .map(str::to_string);
        let features = info_json
            .as_ref()
            .map(|v| v["features"].clone())
            .filter(Value::is_object)
            .unwrap_or_else(|| serde_json::json!({}));
        let status = if auth.verification_required {
            AccountStatus::Unverified
        } else {
            AccountStatus::Active
        };
        let account =
            match self.existing_account(url, instance.as_deref(), auth.user.id, &auth.user.email) {
                Some(acc) => {
                    acc.set_tokens(auth.tokens.clone());
                    acc.update(|i| {
                        i.user_id = Some(auth.user.id);
                        i.email = auth.user.email.clone();
                        i.name = auth.user.name.clone();
                        i.status = status;
                        if instance.is_some() {
                            i.instance_id = instance.clone();
                        }
                        if features.as_object().is_some_and(|f| !f.is_empty()) {
                            i.features = features.clone();
                        }
                        i.last_used_at = Some(now_ms());
                    })?;
                    acc
                }
                None => {
                    let id = termoak_core::new_id();
                    let position = self
                        .accounts()
                        .iter()
                        .map(|a| a.position + 1)
                        .max()
                        .unwrap_or(0);
                    let info = AccountInfo {
                        id,
                        server_url: url.to_string(),
                        instance_id: instance,
                        official: servers::is_official(url),
                        user_id: Some(auth.user.id),
                        email: auth.user.email.clone(),
                        name: auth.user.name.clone(),
                        status,
                        features,
                        color: None,
                        position,
                        added_at: now_ms(),
                        last_used_at: Some(now_ms()),
                        last_sync_at: None,
                    };
                    accounts::save_registry(&self.store, &info, Some(&auth.tokens))?;
                    let store = open_account_store(&self.dir, &self.store, id)?;
                    let acc =
                        Account::new(info, Some(auth.tokens.clone()), store, self.store.clone())?;
                    self.state.accounts.write().push(acc.clone());
                    acc
                }
            };
        self.set_view(AccountView::One(account.id)).await?;
        Ok(account)
    }

    /// Signs in to a server: a new account, or the same account again
    /// (same server and user). It becomes the current account. Without a
    /// two-factor code, an account that has it fails with
    /// `is_totp_required()`.
    pub async fn sign_in(
        &self,
        server: ServerChoice,
        email: &str,
        password: &str,
        totp_code: Option<&str>,
    ) -> Result<Arc<Account>> {
        let url = server.url()?;
        let api = ApiClient::new(&url)?;
        let device = self.device_name().await?;
        let auth = api
            .login_with_code(email.trim(), password, totp_code, &device, &api::platform())
            .await?;
        self.adopt(&url, auth).await
    }

    /// Creates an account on a server (with an invitation code when its
    /// registration is closed). On servers that verify emails it stays
    /// `Unverified` until [`verify_account`](Self::verify_account).
    pub async fn sign_up(
        &self,
        server: ServerChoice,
        email: &str,
        name: &str,
        password: &str,
        invite: Option<&str>,
    ) -> Result<Arc<Account>> {
        let url = server.url()?;
        let api = ApiClient::new(&url)?;
        let device = self.device_name().await?;
        let auth = api
            .register_with_invite(
                email.trim(),
                name,
                password,
                invite,
                &device,
                &api::platform(),
            )
            .await?;
        self.adopt(&url, auth).await
    }

    /// Verifies an account's email with the six-digit code (and signs in
    /// again with the full session).
    pub async fn verify_account(
        &self,
        account: Id,
        code: &str,
        totp_code: Option<&str>,
    ) -> Result<Arc<Account>> {
        let acc = self.require_account(account)?;
        let info = acc.info();
        let api = ApiClient::new(&info.server_url)?;
        let device = self.device_name().await?;
        let auth = api
            .verify_code(&info.email, code, totp_code, &device, &api::platform())
            .await?;
        self.adopt(&info.server_url, auth).await
    }

    /// Emails a new verification code to an account.
    pub async fn resend_account_code(&self, account: Id) -> Result<()> {
        let info = self.require_account(account)?.info();
        ApiClient::new(&info.server_url)?
            .resend_code(&info.email)
            .await
    }

    /// Signs out of one account and deletes its local data. With unsynced
    /// changes and `discard_unsynced = false` nothing happens and the report
    /// says how many there are (`signed_out = false`): ask "Sync now /
    /// Discard". Other accounts are not touched. The app unregisters its
    /// push token on that server first.
    pub async fn sign_out(&self, account: Id, discard_unsynced: bool) -> Result<SignOutReport> {
        let acc = self.require_account(account)?;
        let unsynced = acc.store.dirty_summary().await?.total;
        if unsynced > 0 && !discard_unsynced {
            return Ok(SignOutReport {
                signed_out: false,
                unsynced,
                discarded: 0,
            });
        }
        crate::events::stop(&acc);
        if acc.is_signed_in() {
            let _ = acc.api.logout().await;
        }
        self.state.accounts.write().retain(|a| a.id != account);
        if *self.state.pinned.read() == Some(account) {
            *self.state.pinned.write() = None;
        }
        accounts::delete_registry(&self.store, account)?;
        drop(acc);
        accounts::remove_account_files(&self.dir, account)?;
        if self.view() == AccountView::One(account) {
            let next = self.account_list().first().map(|a| a.id);
            self.set_view(next.map_or(AccountView::All, AccountView::One))
                .await?;
        }
        Ok(SignOutReport {
            signed_out: true,
            unsynced,
            discarded: unsynced,
        })
    }

    /// Signs out of every account (their data is deleted; This device items
    /// stay).
    pub async fn sign_out_all(&self) -> Result<Vec<SignOutReport>> {
        let mut out = Vec::new();
        for a in self.accounts() {
            out.push(self.sign_out(a.id, true).await?);
        }
        Ok(out)
    }

    /// Syncs every signed-in account (errors per account).
    pub async fn sync_all(&self) -> Vec<(Id, Result<crate::sync::SyncReport>)> {
        let mut out = Vec::new();
        for a in self.account_list() {
            if a.is_signed_in() {
                let r = a.sync_once().await;
                out.push((a.id, r));
            }
        }
        out
    }

    // ----- Legacy single-server API (the current account) -----

    /// Client of the current account's server (if signed in).
    pub async fn server(&self) -> Result<Option<ApiClient>> {
        Ok(self
            .current()
            .filter(|a| a.is_signed_in())
            .map(|a| a.api.clone()))
    }

    /// Name this device shows on the server. Defaults to the computer's
    /// name.
    pub async fn device_name(&self) -> Result<String> {
        Ok(self
            .store
            .meta_get(DEVICE_NAME)
            .await?
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(api::device_name))
    }

    /// Changes the device name (used on the next sign-in). On mobile the app
    /// sets it, e.g. "Ane's iPhone".
    pub async fn set_device_name(&self, name: &str) -> Result<()> {
        self.store.meta_set(DEVICE_NAME, name.trim()).await?;
        Ok(())
    }

    /// Signs in to a server (as [`sign_in`](Self::sign_in) with a custom
    /// URL) and returns its client.
    pub async fn login(&self, url: &str, email: &str, password: &str) -> Result<ApiClient> {
        self.login_with_code(url, email, password, None).await
    }

    /// Signs in with the two-factor code. Without a code, if the account has
    /// two-factor authentication, the error satisfies `is_totp_required()`.
    pub async fn login_with_code(
        &self,
        url: &str,
        email: &str,
        password: &str,
        totp_code: Option<&str>,
    ) -> Result<ApiClient> {
        Ok(self
            .sign_in(
                ServerChoice::Custom(url.to_string()),
                email,
                password,
                totp_code,
            )
            .await?
            .api
            .clone())
    }

    /// Creates the account (the server's first user = administrator).
    pub async fn register(
        &self,
        url: &str,
        email: &str,
        name: &str,
        password: &str,
    ) -> Result<ApiClient> {
        self.register_with_invite(url, email, name, password, None)
            .await
    }

    /// Creates the account with an invitation code.
    pub async fn register_with_invite(
        &self,
        url: &str,
        email: &str,
        name: &str,
        password: &str,
        invite: Option<&str>,
    ) -> Result<ApiClient> {
        Ok(self
            .sign_up(
                ServerChoice::Custom(url.to_string()),
                email,
                name,
                password,
                invite,
            )
            .await?
            .api
            .clone())
    }

    /// Verifies the email with the code from the verification email and
    /// signs in to the server, remembering it like [`login`](Self::login).
    pub async fn verify_code(
        &self,
        url: &str,
        email: &str,
        code: &str,
        totp_code: Option<&str>,
    ) -> Result<ApiClient> {
        let url = servers::canonical(url)?;
        let api = ApiClient::new(&url)?;
        let device = self.device_name().await?;
        let auth = api
            .verify_code(email, code, totp_code, &device, &api::platform())
            .await?;
        Ok(self.adopt(&url, auth).await?.api.clone())
    }

    /// Asks the server for a new verification code (no sign-in needed).
    pub async fn resend_code(&self, url: &str, email: &str) -> Result<()> {
        ApiClient::new(&servers::canonical(url)?)?
            .resend_code(email)
            .await
    }

    /// Signs the current account out of its server, keeping its local data
    /// (it stays as "needs sign-in"; [`sign_out`](Self::sign_out) also
    /// deletes the data).
    pub async fn logout(&self) -> Result<()> {
        let Some(acc) = self.current() else {
            return Ok(());
        };
        crate::events::stop(&acc);
        if acc.is_signed_in() {
            let _ = acc.api.logout().await;
        }
        acc.api.replace_tokens(None);
        acc.update(|i| i.status = AccountStatus::NeedsSignIn)?;
        Ok(())
    }

    /// Email of the current account.
    pub async fn server_user(&self) -> Result<Option<String>> {
        Ok(self.current().map(|a| a.info().email))
    }

    /// URL of the current account's server.
    pub fn server_url(&self) -> Option<String> {
        self.current().map(|a| a.info().server_url)
    }

    /// Sync engine of the current account (if signed in).
    pub async fn sync_engine(&self) -> Result<Option<SyncEngine>> {
        Ok(self
            .current()
            .filter(|a| a.is_signed_in())
            .map(|a| a.sync_engine()))
    }

    /// Restores tokens for the current account (tests and tools).
    pub fn set_tokens(&self, tokens: TokenPair) -> Result<()> {
        let acc = self.current().ok_or(ClientError::NotLoggedIn)?;
        acc.set_tokens(tokens);
        acc.update(|i| i.status = AccountStatus::Active)?;
        Ok(())
    }

    // ----- Local SSH -----

    /// Host key verifier that asks the user (device store's known hosts).
    pub fn verifier(
        &self,
        prompter: Option<Arc<dyn AuthPrompter>>,
        policy: HostKeyPolicy,
    ) -> Arc<StoreVerifier> {
        Arc::new(StoreVerifier::for_owner(
            self.store.clone(),
            LOCAL_OWNER,
            policy,
            prompter,
        ))
    }

    /// Verifier with the known hosts of the store of `scope`.
    pub fn verifier_for(
        &self,
        scope: Scope,
        prompter: Option<Arc<dyn AuthPrompter>>,
        policy: HostKeyPolicy,
    ) -> Result<Arc<StoreVerifier>> {
        Ok(Arc::new(StoreVerifier::for_owner(
            self.store_of(scope)?,
            LOCAL_OWNER,
            policy,
            prompter,
        )))
    }

    /// Resolves a host by id, wherever it is (current account, This device,
    /// other accounts). See [`resolve_item`](Self::resolve_item).
    pub async fn resolve(&self, host_id: Id) -> Result<ResolvedHost> {
        let item = self.locate(host_id).await?;
        self.resolve_item(item).await
    }

    /// Connects to a host from this device (wherever it is).
    pub async fn connect(
        &self,
        host_id: Id,
        prompter: Arc<dyn AuthPrompter>,
        use_agent: bool,
    ) -> Result<Arc<Connection>> {
        let item = self.locate(host_id).await?;
        self.connect_item(item, prompter, use_agent).await
    }

    /// Connects to a host of a scope. Just-in-time credentials (Use-only
    /// vaults) are wiped from memory once the connection is up.
    pub async fn connect_item(
        &self,
        item: ItemRef,
        prompter: Arc<dyn AuthPrompter>,
        use_agent: bool,
    ) -> Result<Arc<Connection>> {
        let mut resolved = self.resolve_item(item).await?;
        let opts = ConnectOptions::new(self.verifier_for(
            item.scope,
            Some(prompter.clone()),
            HostKeyPolicy::Ask,
        )?)
        .with_prompter(prompter)
        .with_agent(use_agent);
        let conn = Connection::connect(&resolved, &opts).await;
        resolved.zeroize_secrets();
        Ok(conn?)
    }

    /// Opens a local terminal over a connection.
    pub async fn open_terminal(
        &self,
        host_id: Id,
        conn: Arc<Connection>,
        cols: u16,
        rows: u16,
        record: bool,
    ) -> Result<Arc<TerminalSession>> {
        let item = self.locate(host_id).await?;
        self.open_terminal_item(item, conn, cols, rows, record)
            .await
    }

    /// Opens a local terminal over a connection to the host `item`.
    pub async fn open_terminal_item(
        &self,
        item: ItemRef,
        conn: Arc<Connection>,
        cols: u16,
        rows: u16,
        record: bool,
    ) -> Result<Arc<TerminalSession>> {
        let resolved = self.resolve_public(item).await?;
        let recorder = if record || resolved.settings.record_sessions.unwrap_or(false) {
            let path = self.dir.join("recordings").join(format!(
                "{}-{}.cast",
                resolved.host.label.replace(['/', '\\'], "_"),
                termoak_core::time::now_ms()
            ));
            Recorder::create(&path, cols, rows, &resolved.host.label, false)
                .await
                .ok()
        } else {
            None
        };
        let pty = PtyOptions {
            term: resolved
                .settings
                .term
                .clone()
                .unwrap_or_else(|| "xterm-256color".into()),
            cols,
            rows,
            env: resolved.settings.env.clone(),
            startup_script: resolved.startup_script.clone(),
            agent_forwarding: resolved.settings.agent_forwarding.unwrap_or(false),
        };
        Ok(TerminalSession::open(conn, pty, 4 * 1024 * 1024, recorder).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use termoak_core::model::{Host, HostSettings, SecretUpdate};

    #[tokio::test]
    async fn workspace_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let key = MasterKey::generate();
        let ws = Workspace::open(dir.path(), key.clone()).unwrap();
        assert!(ws.server().await.unwrap().is_none());
        assert!(ws.accounts().is_empty());
        ws.store
            .save(
                LOCAL_OWNER,
                Host {
                    id: Id::nil(),
                    label: "a".into(),
                    address: "a.example.com".into(),
                    group_id: None,
                    tags: vec![],
                    settings: HostSettings::default(),
                    notes: String::new(),
                    color: None,
                    os: None,
                    os_version: None,
                    favorite: false,
                },
                SecretUpdate::Keep,
                None,
            )
            .await
            .unwrap();
        // Reopening keeps the layout and the item.
        drop(ws);
        let ws = Workspace::open(dir.path(), key).unwrap();
        assert_eq!(ws.store.list::<Host>(LOCAL_OWNER).await.unwrap().len(), 1);
        assert_eq!(layout::version(&ws.store).unwrap().as_deref(), Some("2"));
    }
}

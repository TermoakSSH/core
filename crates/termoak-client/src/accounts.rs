//! Signed-in accounts: the registry in the device store and one store per
//! account (`accounts/<id>.db`).
//!
//! An account is a (server, user) pair signed in on this device. Each one
//! has its own SQLite store (a mirror of the vaults it can access), its own
//! API client (tokens sealed with the device key, AAD
//! `termoak:account-tokens:<id>`), its own sync and its own events
//! WebSocket.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use parking_lot::{Mutex, RwLock};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use termoak_core::crypto::MasterKey;
use termoak_core::model::{TokenPair, VaultRole, VaultSettings};
use termoak_core::time::now_ms;
use termoak_core::{Id, Store};

use crate::api::ApiClient;
use crate::error::{ClientError, Result};
use crate::servers;
use crate::sync::{SyncEngine, SyncReport};

/// Meta key of an account store: its account id.
pub const ACCOUNT_ID_KEY: &str = "account.id";
/// Meta key of an account store: last successful sync (ms).
const LAST_SYNC_KEY: &str = "sync.last_at";
/// Marker the FFI layer leaves to detect a wrong vault key (copied into
/// every account store).
pub const VAULT_CHECK_KEY: &str = "ffi.vault_check";

/// Folder of the account stores inside the data directory.
pub fn accounts_dir(dir: &Path) -> PathBuf {
    dir.join("accounts")
}

/// Store file of an account.
pub fn account_db_path(dir: &Path, id: Id) -> PathBuf {
    accounts_dir(dir).join(format!("{id}.db"))
}

/// AAD of an account's tokens.
fn tokens_aad(id: Id) -> Vec<u8> {
    format!("termoak:account-tokens:{id}").into_bytes()
}

pub(crate) fn seal_tokens(key: &MasterKey, id: Id, tokens: &TokenPair) -> Result<Vec<u8>> {
    let json = zeroize::Zeroizing::new(
        serde_json::to_vec(tokens).map_err(|e| ClientError::Invalid(e.to_string()))?,
    );
    Ok(key.seal(&json, &tokens_aad(id))?)
}

fn open_tokens(key: &MasterKey, id: Id, blob: &[u8]) -> Option<TokenPair> {
    let plain = key.open(blob, &tokens_aad(id)).ok()?;
    serde_json::from_slice(&plain).ok()
}

/// State of an account on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    /// Signed in.
    Active,
    /// The session ended (signed out, or the refresh failed): its data
    /// stays readable offline; sign in again to sync.
    NeedsSignIn,
    /// Created but the email is not verified yet (enter the code).
    Unverified,
    #[serde(other)]
    Unknown,
}

impl AccountStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            AccountStatus::Active => "active",
            AccountStatus::NeedsSignIn => "needs_sign_in",
            AccountStatus::Unverified => "unverified",
            AccountStatus::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "active" => AccountStatus::Active,
            "needs_sign_in" => AccountStatus::NeedsSignIn,
            "unverified" => AccountStatus::Unverified,
            _ => AccountStatus::Unknown,
        }
    }
}

/// An account of the registry.
#[derive(Debug, Clone, Serialize)]
pub struct AccountInfo {
    /// Local id (names the store file).
    pub id: Id,
    /// Canonical server URL.
    pub server_url: String,
    /// The server's `/info.instance_id` (once known).
    pub instance_id: Option<String>,
    pub official: bool,
    /// The user's id on the server (once known): also the id of their
    /// personal vault.
    pub user_id: Option<Id>,
    pub email: String,
    pub name: String,
    pub status: AccountStatus,
    /// The server's `/info.features` (cached).
    pub features: Value,
    pub color: Option<String>,
    pub position: i64,
    pub added_at: i64,
    pub last_used_at: Option<i64>,
    /// Last successful sync (ms).
    pub last_sync_at: Option<i64>,
}

impl AccountInfo {
    /// The server has vaults and sync v2 (otherwise: the legacy sync, one
    /// implicit personal vault, and no vault UI for this account).
    pub fn vaults_supported(&self) -> bool {
        self.features["sync_v2"].as_bool().unwrap_or(false)
    }

    /// The server can give just-in-time credentials.
    pub fn credentials_supported(&self) -> bool {
        self.features["credentials"].as_bool().unwrap_or(false)
    }

    /// Host of the server, to show it.
    pub fn server_host(&self) -> String {
        servers::display_host(&self.server_url)
    }
}

/// Columns of the registry, in [`row_info`] order.
const COLUMNS: &str = "id, server_url, instance_id, official, user_id, email, name, status, \
     tokens, features, color, position, added_at, last_used_at";

fn row_info(r: &rusqlite::Row<'_>) -> rusqlite::Result<(AccountInfo, Option<Vec<u8>>)> {
    let id: String = r.get(0)?;
    let user_id: Option<String> = r.get(4)?;
    let features: String = r.get(9)?;
    Ok((
        AccountInfo {
            id: id.parse().unwrap_or_default(),
            server_url: r.get(1)?,
            instance_id: r.get(2)?,
            official: r.get::<_, i64>(3)? != 0,
            user_id: user_id.and_then(|u| u.parse().ok()),
            email: r.get(5)?,
            name: r.get(6)?,
            status: AccountStatus::parse(&r.get::<_, String>(7)?),
            features: serde_json::from_str(&features).unwrap_or(Value::Object(Default::default())),
            color: r.get(10)?,
            position: r.get(11)?,
            added_at: r.get(12)?,
            last_used_at: r.get(13)?,
            last_sync_at: None,
        },
        r.get(8)?,
    ))
}

/// Every account of the registry, with its sealed tokens.
pub(crate) fn load_registry(device: &Store) -> Result<Vec<(AccountInfo, Option<TokenPair>)>> {
    Ok(device.call_blocking(|c, key| {
        let mut stmt = c.prepare(&format!(
            "SELECT {COLUMNS} FROM accounts ORDER BY position, added_at, id"
        ))?;
        let rows = stmt
            .query_map([], row_info)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows
            .into_iter()
            .map(|(info, blob)| {
                let tokens = blob.and_then(|b| open_tokens(key, info.id, &b));
                (info, tokens)
            })
            .collect())
    })?)
}

/// Inserts (or replaces) an account of the registry.
pub(crate) fn save_registry(
    device: &Store,
    info: &AccountInfo,
    tokens: Option<&TokenPair>,
) -> Result<()> {
    let sealed = match tokens {
        Some(t) => Some(seal_tokens(device.master_key(), info.id, t)?),
        None => None,
    };
    let info = info.clone();
    device.call_blocking(move |c, _| {
        c.execute(
            &format!(
                "INSERT INTO accounts ({COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                 ON CONFLICT(id) DO UPDATE SET
                    server_url = excluded.server_url, instance_id = excluded.instance_id,
                    official = excluded.official, user_id = excluded.user_id, email = excluded.email,
                    name = excluded.name, status = excluded.status, tokens = excluded.tokens,
                    features = excluded.features, color = excluded.color, position = excluded.position,
                    last_used_at = excluded.last_used_at"
            ),
            params![
                info.id.to_string(),
                info.server_url,
                info.instance_id,
                info.official as i64,
                info.user_id.map(|u| u.to_string()),
                info.email,
                info.name,
                info.status.as_str(),
                sealed,
                info.features.to_string(),
                info.color,
                info.position,
                info.added_at,
                info.last_used_at
            ],
        )?;
        Ok(())
    })?;
    Ok(())
}

fn update_tokens(device: &Store, id: Id, tokens: Option<&TokenPair>) {
    let sealed = match tokens.map(|t| seal_tokens(device.master_key(), id, t)) {
        Some(Ok(b)) => Some(b),
        Some(Err(e)) => {
            tracing::warn!(error = %e, "could not seal the account tokens");
            return;
        }
        None => None,
    };
    let res = device.call_blocking(move |c, _| {
        c.execute(
            "UPDATE accounts SET tokens = ?2 WHERE id = ?1",
            params![id.to_string(), sealed],
        )?;
        Ok(())
    });
    if let Err(e) = res {
        tracing::warn!(error = %e, "could not save the account tokens");
    }
}

pub(crate) fn delete_registry(device: &Store, id: Id) -> Result<()> {
    device.call_blocking(move |c, _| {
        c.execute("DELETE FROM accounts WHERE id = ?1", [id.to_string()])?;
        Ok(())
    })?;
    Ok(())
}

/// Opens (or creates) an account store and labels it.
pub(crate) fn open_account_store(dir: &Path, device: &Store, id: Id) -> Result<Store> {
    let store = Store::open(&account_db_path(dir, id), device.master_key().clone())?;
    let check: Option<String> = device.call_blocking(|c, _| {
        Ok(c.query_row(
            "SELECT value FROM meta WHERE key = ?1",
            [VAULT_CHECK_KEY],
            |r| r.get(0),
        )
        .optional()?)
    })?;
    store.call_blocking(move |c, _| {
        c.execute(
            "INSERT INTO meta(key, value) VALUES(?1, ?2) ON CONFLICT(key) DO NOTHING",
            params![ACCOUNT_ID_KEY, id.to_string()],
        )?;
        if let Some(check) = check {
            c.execute(
                "INSERT INTO meta(key, value) VALUES(?1, ?2) ON CONFLICT(key) DO NOTHING",
                params![VAULT_CHECK_KEY, check],
            )?;
        }
        Ok(())
    })?;
    Ok(store)
}

/// Deletes an account store file (and its WAL files).
pub(crate) fn remove_account_files(dir: &Path, id: Id) -> Result<()> {
    let base = account_db_path(dir, id);
    for suffix in ["-wal", "-shm", ""] {
        let mut p = base.clone().into_os_string();
        p.push(suffix);
        match std::fs::remove_file(PathBuf::from(p)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// What a sign-out did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SignOutReport {
    /// The account was signed out and its local data deleted. `false` when
    /// there are unsynced changes and `discard_unsynced` was not given: ask
    /// "N changes are not uploaded yet: Sync now / Discard".
    pub signed_out: bool,
    /// Local changes not uploaded yet.
    pub unsynced: usize,
    /// Of them, discarded.
    pub discarded: usize,
}

/// A signed-in account: its store, API client and sync.
pub struct Account {
    pub id: Id,
    /// Mirror of the vaults this account can access.
    pub store: Store,
    pub api: ApiClient,
    pub(crate) device: Store,
    info: Arc<RwLock<AccountInfo>>,
    sync_lock: tokio::sync::Mutex<()>,
    sync_pending: AtomicBool,
    pub(crate) events: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account")
            .field("id", &self.id)
            .field("server", &self.info.read().server_url)
            .finish_non_exhaustive()
    }
}

impl Drop for Account {
    fn drop(&mut self) {
        if let Some(h) = self.events.lock().take() {
            h.abort();
        }
    }
}

impl Account {
    /// Builds the account object (store already open).
    pub(crate) fn new(
        mut info: AccountInfo,
        tokens: Option<TokenPair>,
        store: Store,
        device: Store,
    ) -> Result<Arc<Self>> {
        info.last_sync_at = store
            .call_blocking(|c, _| {
                Ok(c.query_row(
                    "SELECT value FROM meta WHERE key = ?1",
                    [LAST_SYNC_KEY],
                    |r| r.get::<_, String>(0),
                )
                .optional()?)
            })?
            .and_then(|v| v.parse().ok());
        let id = info.id;
        let shared = Arc::new(RwLock::new(info));
        let (dev_tokens, dev_expired) = (device.clone(), device.clone());
        let expired_info = shared.clone();
        let url = shared.read().server_url.clone();
        let api = ApiClient::new(&url)?
            .with_tokens(tokens)
            .on_tokens(move |t| update_tokens(&dev_tokens, id, Some(t)))
            .on_expired(move || {
                // The refresh token was refused: sign in again.
                let snapshot = {
                    let mut i = expired_info.write();
                    i.status = AccountStatus::NeedsSignIn;
                    i.clone()
                };
                if let Err(e) = save_registry(&dev_expired, &snapshot, None) {
                    tracing::warn!(error = %e, "could not save the account status");
                }
            });
        Ok(Arc::new(Self {
            id,
            store,
            api,
            device,
            info: shared,
            sync_lock: tokio::sync::Mutex::new(()),
            sync_pending: AtomicBool::new(false),
            events: Mutex::new(None),
        }))
    }

    pub fn info(&self) -> AccountInfo {
        self.info.read().clone()
    }

    pub fn status(&self) -> AccountStatus {
        self.info.read().status
    }

    /// Signed in with tokens.
    pub fn is_signed_in(&self) -> bool {
        self.api.is_logged_in()
    }

    /// The user's id on the server (and of their personal vault).
    pub fn user_id(&self) -> Option<Id> {
        self.info.read().user_id
    }

    /// Changes the cached data and saves it in the registry (with the
    /// current tokens).
    pub(crate) fn update(&self, f: impl FnOnce(&mut AccountInfo)) -> Result<AccountInfo> {
        let snapshot = {
            let mut i = self.info.write();
            f(&mut i);
            i.clone()
        };
        save_registry(&self.device, &snapshot, self.api.tokens().as_ref())?;
        Ok(snapshot)
    }

    /// Stores new tokens (after signing in again).
    pub(crate) fn set_tokens(&self, tokens: TokenPair) {
        update_tokens(&self.device, self.id, Some(&tokens));
        let api = self.api.clone();
        // `with_tokens` consumes; set them on the shared client instead.
        api.replace_tokens(Some(tokens));
    }

    /// Effective role in a vault of this store (`None`: rows without a
    /// vault, i.e. this account's own data on a server without vaults or
    /// before the first sync: full access).
    pub async fn role(&self, vault: Option<Id>) -> Result<VaultRole> {
        let Some(v) = vault else {
            return Ok(VaultRole::Manager);
        };
        if Some(v) == self.user_id() {
            return Ok(VaultRole::Manager);
        }
        Ok(self
            .store
            .local_roles()
            .await?
            .get(&v)
            .copied()
            .unwrap_or(VaultRole::UseOnly))
    }

    /// Whether a vault is Strict (Use-only members connect only through the
    /// server).
    pub async fn is_strict(&self, vault: Id) -> Result<bool> {
        Ok(self
            .store
            .local_vault_settings(vault)
            .await?
            .is_some_and(|s: VaultSettings| !s.use_only_local))
    }

    /// Refreshes the cached server data (`/info`) and the user (`/me`).
    pub async fn refresh_info(&self) -> Result<AccountInfo> {
        let info = self.api.info().await?;
        let me = if self.is_signed_in() {
            self.api.me().await.ok()
        } else {
            None
        };
        self.update(|i| {
            if let Some(f) = info.get("features") {
                i.features = f.clone();
            }
            if let Some(inst) = info["instance_id"].as_str() {
                i.instance_id = Some(inst.to_string());
            }
            if let Some(me) = &me {
                i.user_id = Some(me.id);
                i.email = me.email.clone();
                i.name = me.name.clone();
            }
        })
    }

    /// Sync engine of this account (v2 when the server has it).
    pub fn sync_engine(&self) -> SyncEngine {
        let info = self.info();
        if info.vaults_supported() {
            SyncEngine::v2(self.store.clone(), self.api.clone(), info.user_id)
        } else if info.features.as_object().is_some_and(|f| !f.is_empty()) {
            SyncEngine::legacy(self.store.clone(), self.api.clone())
        } else {
            SyncEngine::new(self.store.clone(), self.api.clone())
        }
    }

    /// One sync round (one at a time per account).
    pub async fn sync_once(&self) -> Result<SyncReport> {
        if !self.is_signed_in() {
            return Err(ClientError::NotLoggedIn);
        }
        let _guard = self.sync_lock.lock().await;
        self.sync_pending.store(false, Ordering::SeqCst);
        let needs_info = {
            let i = self.info.read();
            i.user_id.is_none() || i.features.as_object().is_none_or(|f| f.is_empty())
        };
        if needs_info && let Err(e) = self.refresh_info().await {
            tracing::debug!(error = %e, "could not refresh the account data");
        }
        let report = self.sync_engine().sync_once().await?;
        let now = now_ms();
        self.store.meta_set(LAST_SYNC_KEY, &now.to_string()).await?;
        self.info.write().last_sync_at = Some(now);
        Ok(report)
    }

    /// Syncs soon (debounced): after local saves and `vault` events.
    pub fn sync_soon(self: &Arc<Self>) {
        if !self.is_signed_in() || self.sync_pending.swap(true, Ordering::SeqCst) {
            return;
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            self.sync_pending.store(false, Ordering::SeqCst);
            return;
        };
        let me = Arc::downgrade(self);
        rt.spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if let Some(a) = me.upgrade()
                && let Err(e) = a.sync_once().await
            {
                tracing::warn!(account = %a.id, error = %e, "sync failed");
            }
        });
    }

    /// Marks the account as used now.
    pub(crate) fn touch(&self) {
        let _ = self.update(|i| i.last_used_at = Some(now_ms()));
    }
}

/// Sealed token blob of a legacy (0.3) store, opened with its frozen AAD.
pub(crate) fn open_legacy_tokens(key: &MasterKey, sealed_b64: &str) -> Option<TokenPair> {
    if sealed_b64.trim().is_empty() {
        return None;
    }
    let raw = STANDARD.decode(sealed_b64.trim()).ok()?;
    let plain = key.open(&raw, LEGACY_TOKENS_AAD).ok()?;
    serde_json::from_slice(&plain).ok()
}

/// AAD of the server tokens of a 0.3 store. Frozen (former project name).
pub(crate) const LEGACY_TOKENS_AAD: &[u8] = b"aceitunoak:server-tokens";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_bound_to_the_account() {
        let key = MasterKey::generate();
        let t = TokenPair {
            access_token: "a".into(),
            access_expires_at: 1,
            refresh_token: "r".into(),
            refresh_expires_at: 2,
            device_id: Id::nil(),
        };
        let (a, b) = (termoak_core::new_id(), termoak_core::new_id());
        let sealed = seal_tokens(&key, a, &t).unwrap();
        assert_eq!(open_tokens(&key, a, &sealed).unwrap().refresh_token, "r");
        assert!(open_tokens(&key, b, &sealed).is_none());
    }
}

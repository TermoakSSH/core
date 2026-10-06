//! [`TermoakCore`]: the device's encrypted local vault and its CRUD.
//!
//! Vault operations are synchronous (local SQLite, microseconds); the ones
//! that may take a while (generating or importing keys) are `async`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use termoak_client::{ItemRef, LOCAL_OWNER, SaveTarget, Scope, Scoped, Workspace};
use termoak_core::crypto::MasterKey;
use termoak_core::model::{
    self as cm, Entity, HostSecret, IdentitySecret, SecretUpdate, SshKeySecret,
};
use termoak_core::{Id, Store};

use crate::accounts::ItemFilter;
use crate::error::{Result, TermoakError};
use crate::models::*;
use crate::runtime::{block_on, run};

const VAULT_CHECK: &str = "ffi.vault_check";
// Frozen: changing it would make existing vaults look like they belong to another key.
const VAULT_CHECK_AAD: &[u8] = b"aceitunoak:ffi-vault-check";

/// The library's entry point: local vault, server and SSH engine.
///
/// Create it once when the app starts and share it. It is safe to use from
/// several threads.
#[derive(uniffi::Object)]
pub struct TermoakCore {
    pub(crate) ws: Workspace,
    /// Account this object works with (an [`AccountHandle`](crate::AccountHandle));
    /// `None`: the current account.
    pub(crate) pinned: Option<Id>,
}

/// Generates a new vault key (256 bits in base64). The app stores it in the
/// iOS Keychain or the Android Keystore and passes it to
/// [`TermoakCore::new`] on every start.
#[uniffi::export]
pub fn generate_vault_key() -> String {
    MasterKey::generate().to_base64().to_string()
}

/// Library version.
#[uniffi::export]
pub fn library_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Reads a private key (OpenSSH, PEM or unencrypted PuTTY) and returns its
/// public part, without saving it. Useful as a preview when importing.
#[uniffi::export]
pub async fn inspect_private_key(
    private_key: String,
    passphrase: Option<String>,
) -> Result<KeyDetails> {
    run(async move {
        let material = tokio::task::spawn_blocking(move || {
            termoak_ssh::keys::import_private(&private_key, passphrase.as_deref())
        })
        .await
        .map_err(|e| TermoakError::Internal(e.to_string()))??;
        Ok(KeyDetails::from(&material))
    })
    .await
}

/// The `{{name}}` variables of a script, without duplicates and in order.
#[uniffi::export]
pub fn snippet_variables(script: String) -> Vec<String> {
    snippet_of(script).variables()
}

/// Replaces the `{{name}}` variables of a script. Fails if any is missing.
#[uniffi::export]
pub fn render_snippet(script: String, values: HashMap<String, String>) -> Result<String> {
    Ok(snippet_of(script).render(&values.into_iter().collect())?)
}

fn snippet_of(script: String) -> cm::Snippet {
    cm::Snippet {
        id: Id::nil(),
        name: String::new(),
        script,
        description: String::new(),
        tags: Vec::new(),
    }
}

pub(crate) fn install_crypto_provider() {
    // rustls needs one crypto provider per process (ring, same as russh).
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Checks that the key opens the existing data; the first time it leaves an
/// encrypted marker to detect a wrong key later.
async fn check_vault_key(store: &Store) -> Result<()> {
    match store.meta_get(VAULT_CHECK).await? {
        Some(sealed) => {
            let raw = STANDARD
                .decode(sealed.trim())
                .map_err(|e| TermoakError::Vault(format!("damaged vault check marker: {e}")))?;
            store
                .master_key()
                .open(&raw, VAULT_CHECK_AAD)
                .map_err(|_| {
                    TermoakError::Vault("the vault key does not match this device's data".into())
                })?;
        }
        None => {
            let sealed = store.master_key().seal(b"aceitunoak", VAULT_CHECK_AAD)?;
            store
                .meta_set(VAULT_CHECK, &STANDARD.encode(sealed))
                .await?;
        }
    }
    Ok(())
}

#[uniffi::export]
impl TermoakCore {
    /// Opens (or creates) the local vault in `data_dir` with the key
    /// `vault_key_b64` (the one from [`generate_vault_key`], stored by the app
    /// in the Keychain or the Keystore). Fails with `Vault` if the key does not
    /// match the data.
    #[uniffi::constructor]
    pub fn new(data_dir: String, vault_key_b64: String) -> Result<Arc<Self>> {
        install_crypto_provider();
        let key = MasterKey::from_base64(&vault_key_b64)?;
        let dir = PathBuf::from(data_dir);
        std::fs::create_dir_all(&dir)?;
        // The key is checked before the data layout is migrated (one store
        // per account): a wrong key must not touch anything.
        {
            let device = Store::open(&termoak_client::workspace::database_path(&dir), key.clone())?;
            block_on(check_vault_key(&device))?;
        }
        let ws = Workspace::open(&dir, key)?;
        Ok(Arc::new(Self { ws, pinned: None }))
    }

    /// The vault's data directory.
    pub fn data_dir(&self) -> String {
        self.ws.dir.to_string_lossy().into_owned()
    }

    // ----- Hosts -----

    /// Hosts of `filter` (default: the current view, i.e. the current
    /// account, or every account, plus This device), in creation order.
    /// The same host seen through two accounts appears twice.
    #[uniffi::method(default(filter))]
    pub fn list_hosts(&self, filter: Option<ItemFilter>) -> Result<Vec<SshHost>> {
        self.list_into::<cm::Host, SshHost>(filter)
    }

    /// A host. `account_id`: where to look (default: the current account,
    /// This device, then the other accounts).
    #[uniffi::method(default(account_id))]
    pub fn get_host(&self, id: String, account_id: Option<String>) -> Result<SshHost> {
        Ok(self.get::<cm::Host>(&id, &account_id)?.into())
    }

    /// Creates (with an empty `id`) or updates a host. `password` decides what
    /// to do with its password.
    pub fn save_host(&self, host: SshHost, password: SecretChange) -> Result<SshHost> {
        let target = self.target_of(&host.id, &host.account_id, &host.vault_id)?;
        let (data, mode) = host.into_core()?;
        // The proxy password lives in the same secret: keep it.
        let secret = match password {
            SecretChange::Keep => SecretUpdate::Keep,
            change => {
                let mut s = self.secret_for::<cm::Host>(target, data.id)?;
                s.password = match change {
                    SecretChange::Set { value } => Some(value),
                    _ => None,
                };
                host_secret_update(s)
            }
        };
        Ok(self.save(target, data, secret, mode)?.into())
    }

    /// Changes a host's proxy password (`HostSettings.proxy`).
    #[uniffi::method(default(account_id))]
    pub fn set_host_proxy_password(
        &self,
        id: String,
        password: SecretChange,
        account_id: Option<String>,
    ) -> Result<()> {
        if matches!(password, SecretChange::Keep) {
            return Ok(());
        }
        let record = self.get::<cm::Host>(&id, &account_id)?;
        let item = record.item();
        let mut s = self.item_secret::<cm::Host>(item)?;
        s.proxy_password = match password {
            SecretChange::Set { value } => Some(value),
            _ => None,
        };
        self.save(
            target_of_item(item),
            record.record.data,
            host_secret_update(s),
            None,
        )?;
        Ok(())
    }

    /// Whether a proxy password is saved.
    #[uniffi::method(default(account_id))]
    pub fn host_has_proxy_password(&self, id: String, account_id: Option<String>) -> Result<bool> {
        Ok(self
            .secret::<cm::Host>(&id, &account_id)?
            .proxy_password
            .is_some())
    }

    #[uniffi::method(default(account_id))]
    pub fn delete_host(&self, id: String, account_id: Option<String>) -> Result<()> {
        self.delete::<cm::Host>(&id, &account_id)
    }

    /// The host's saved password (to show or copy it). Use-only hosts fail
    /// with `SecretHidden`.
    #[uniffi::method(default(account_id))]
    pub fn host_password(&self, id: String, account_id: Option<String>) -> Result<Option<String>> {
        Ok(self.secret::<cm::Host>(&id, &account_id)?.password)
    }

    /// The host's effective settings: those of its groups (outermost to
    /// innermost) with the host's own on top.
    #[uniffi::method(default(account_id))]
    pub fn effective_settings(
        &self,
        host_id: String,
        account_id: Option<String>,
    ) -> Result<HostSettings> {
        let rec = self.get::<cm::Host>(&host_id, &account_id)?;
        let store = self.ws.store_of(rec.scope)?;
        let host = rec.record.data;
        let settings = block_on(async move { store.effective_settings(LOCAL_OWNER, &host).await })?;
        Ok(settings.into())
    }

    // ----- Groups -----

    #[uniffi::method(default(filter))]
    pub fn list_groups(&self, filter: Option<ItemFilter>) -> Result<Vec<HostGroup>> {
        self.list_into::<cm::Group, HostGroup>(filter)
    }

    #[uniffi::method(default(account_id))]
    pub fn get_group(&self, id: String, account_id: Option<String>) -> Result<HostGroup> {
        Ok(self.get::<cm::Group>(&id, &account_id)?.into())
    }

    pub fn save_group(&self, group: HostGroup) -> Result<HostGroup> {
        let target = self.target_of(&group.id, &group.account_id, &group.vault_id)?;
        let (data, mode) = group.into_core()?;
        Ok(self.save(target, data, SecretUpdate::Keep, mode)?.into())
    }

    #[uniffi::method(default(account_id))]
    pub fn delete_group(&self, id: String, account_id: Option<String>) -> Result<()> {
        self.delete::<cm::Group>(&id, &account_id)
    }

    // ----- Identities -----

    #[uniffi::method(default(filter))]
    pub fn list_identities(&self, filter: Option<ItemFilter>) -> Result<Vec<SshIdentity>> {
        self.list_into::<cm::Identity, SshIdentity>(filter)
    }

    #[uniffi::method(default(account_id))]
    pub fn get_identity(&self, id: String, account_id: Option<String>) -> Result<SshIdentity> {
        Ok(self.get::<cm::Identity>(&id, &account_id)?.into())
    }

    pub fn save_identity(
        &self,
        identity: SshIdentity,
        password: SecretChange,
    ) -> Result<SshIdentity> {
        let target = self.target_of(&identity.id, &identity.account_id, &identity.vault_id)?;
        let (data, mode) = identity.into_core()?;
        let secret = password_update(password, |password| IdentitySecret { password });
        Ok(self.save(target, data, secret, mode)?.into())
    }

    #[uniffi::method(default(account_id))]
    pub fn delete_identity(&self, id: String, account_id: Option<String>) -> Result<()> {
        self.delete::<cm::Identity>(&id, &account_id)
    }

    #[uniffi::method(default(account_id))]
    pub fn identity_password(
        &self,
        id: String,
        account_id: Option<String>,
    ) -> Result<Option<String>> {
        Ok(self.secret::<cm::Identity>(&id, &account_id)?.password)
    }

    // ----- SSH keys -----

    #[uniffi::method(default(filter))]
    pub fn list_keys(&self, filter: Option<ItemFilter>) -> Result<Vec<SshKey>> {
        self.list_into::<cm::SshKey, SshKey>(filter)
    }

    #[uniffi::method(default(account_id))]
    pub fn get_key(&self, id: String, account_id: Option<String>) -> Result<SshKey> {
        Ok(self.get::<cm::SshKey>(&id, &account_id)?.into())
    }

    /// Generates a new key and saves it in the vault. With a `passphrase`, the
    /// private key is encrypted with it; `store_passphrase` decides whether the
    /// passphrase is saved too (otherwise it is asked for when connecting).
    /// `account_id`/`vault_id`: where to save it (see `SshHost.account_id`).
    #[allow(clippy::too_many_arguments)]
    #[uniffi::method(default(account_id = None, vault_id = None))]
    pub async fn generate_key(
        &self,
        label: String,
        key_type: KeyType,
        comment: String,
        passphrase: Option<String>,
        store_passphrase: bool,
        sync_mode: Option<SyncMode>,
        account_id: Option<String>,
        vault_id: Option<String>,
    ) -> Result<SshKey> {
        let target = self.target_of("", &account_id, &vault_id)?;
        let ws = self.ws.clone();
        run(async move {
            let pass = passphrase.clone();
            let material = tokio::task::spawn_blocking(move || {
                termoak_ssh::keys::generate(key_type.into(), &comment, pass.as_deref())
            })
            .await
            .map_err(|e| TermoakError::Internal(e.to_string()))??;
            save_key_material(
                &ws,
                target,
                label,
                material,
                passphrase,
                store_passphrase,
                sync_mode,
            )
            .await
        })
        .await
    }

    /// Imports a private key (OpenSSH, PEM PKCS#1/PKCS#8 or unencrypted PuTTY)
    /// and saves it in the vault.
    #[allow(clippy::too_many_arguments)]
    #[uniffi::method(default(account_id = None, vault_id = None))]
    pub async fn import_key(
        &self,
        label: String,
        private_key: String,
        passphrase: Option<String>,
        store_passphrase: bool,
        sync_mode: Option<SyncMode>,
        account_id: Option<String>,
        vault_id: Option<String>,
    ) -> Result<SshKey> {
        let target = self.target_of("", &account_id, &vault_id)?;
        let ws = self.ws.clone();
        run(async move {
            let pass = passphrase.clone();
            let material = tokio::task::spawn_blocking(move || {
                termoak_ssh::keys::import_private(&private_key, pass.as_deref())
            })
            .await
            .map_err(|e| TermoakError::Internal(e.to_string()))??;
            save_key_material(
                &ws,
                target,
                label,
                material,
                passphrase,
                store_passphrase,
                sync_mode,
            )
            .await
        })
        .await
    }

    /// Updates a key's editable data (label, comment, certificate and sync
    /// mode) and, if given, its saved passphrase. The private key does not
    /// change.
    pub fn save_key(&self, key: SshKey, passphrase: SecretChange) -> Result<SshKey> {
        let account = key.account_id.clone();
        let (edited, mode) = key.into_core()?;
        if edited.id.is_nil() {
            return Err(TermoakError::Invalid(
                "to add a key use generate_key or import_key".into(),
            ));
        }
        let rec = self.get::<cm::SshKey>(&edited.id.to_string(), &account)?;
        let item = rec.item();
        let mut data = rec.record.data;
        data.label = edited.label;
        data.comment = edited.comment;
        data.certificate = edited.certificate;
        let secret = if passphrase.is_keep() {
            SecretUpdate::Keep
        } else {
            let mut current = self.item_secret::<cm::SshKey>(item)?;
            current.passphrase = passphrase.apply(current.passphrase);
            SecretUpdate::Set(current)
        };
        Ok(self.save(target_of_item(item), data, secret, mode)?.into())
    }

    #[uniffi::method(default(account_id))]
    pub fn delete_key(&self, id: String, account_id: Option<String>) -> Result<()> {
        self.delete::<cm::SshKey>(&id, &account_id)
    }

    /// The saved private key (OpenSSH/PEM format), to export it. Use-only
    /// keys fail with `SecretHidden`.
    #[uniffi::method(default(account_id))]
    pub fn export_private_key(
        &self,
        id: String,
        account_id: Option<String>,
    ) -> Result<Option<String>> {
        Ok(self.secret::<cm::SshKey>(&id, &account_id)?.private_key)
    }

    // ----- Snippets -----

    #[uniffi::method(default(filter))]
    pub fn list_snippets(&self, filter: Option<ItemFilter>) -> Result<Vec<Snippet>> {
        self.list_into::<cm::Snippet, Snippet>(filter)
    }

    #[uniffi::method(default(account_id))]
    pub fn get_snippet(&self, id: String, account_id: Option<String>) -> Result<Snippet> {
        Ok(self.get::<cm::Snippet>(&id, &account_id)?.into())
    }

    pub fn save_snippet(&self, snippet: Snippet) -> Result<Snippet> {
        let target = self.target_of(&snippet.id, &snippet.account_id, &snippet.vault_id)?;
        let (data, mode) = snippet.into_core()?;
        Ok(self.save(target, data, SecretUpdate::Keep, mode)?.into())
    }

    #[uniffi::method(default(account_id))]
    pub fn delete_snippet(&self, id: String, account_id: Option<String>) -> Result<()> {
        self.delete::<cm::Snippet>(&id, &account_id)
    }

    // ----- Tunnels -----

    /// Saved tunnels; with `host_id`, only that host's.
    #[uniffi::method(default(filter))]
    pub fn list_forwards(
        &self,
        host_id: Option<String>,
        filter: Option<ItemFilter>,
    ) -> Result<Vec<PortForward>> {
        let host = parse_opt_id(&host_id)?;
        Ok(self
            .list_scoped::<cm::PortForward>(filter)?
            .into_iter()
            .filter(|r| host.is_none_or(|h| r.record.data.host_id == h))
            .map(Into::into)
            .collect())
    }

    #[uniffi::method(default(account_id))]
    pub fn get_forward(&self, id: String, account_id: Option<String>) -> Result<PortForward> {
        Ok(self.get::<cm::PortForward>(&id, &account_id)?.into())
    }

    pub fn save_forward(&self, forward: PortForward) -> Result<PortForward> {
        let target = self.target_of(&forward.id, &forward.account_id, &forward.vault_id)?;
        let (data, mode) = forward.into_core()?;
        Ok(self.save(target, data, SecretUpdate::Keep, mode)?.into())
    }

    #[uniffi::method(default(account_id))]
    pub fn delete_forward(&self, id: String, account_id: Option<String>) -> Result<()> {
        self.delete::<cm::PortForward>(&id, &account_id)
    }

    // ----- Known hosts -----

    /// Trusted server keys (added when accepting a new fingerprint while
    /// connecting).
    #[uniffi::method(default(filter))]
    pub fn list_known_hosts(&self, filter: Option<ItemFilter>) -> Result<Vec<KnownHost>> {
        self.list_into::<cm::KnownHost, KnownHost>(filter)
    }

    /// Forgets a server key (e.g. after reinstalling the server).
    #[uniffi::method(default(account_id))]
    pub fn delete_known_host(&self, id: String, account_id: Option<String>) -> Result<()> {
        self.delete::<cm::KnownHost>(&id, &account_id)
    }

    // ----- AI memories -----

    #[uniffi::method(default(filter))]
    pub fn list_memories(&self, filter: Option<ItemFilter>) -> Result<Vec<AiMemory>> {
        self.list_into::<cm::Memory, AiMemory>(filter)
    }

    pub fn save_memory(&self, memory: AiMemory) -> Result<AiMemory> {
        let target = self.target_of(&memory.id, &memory.account_id, &memory.vault_id)?;
        let data = memory.into_core()?;
        Ok(self.save(target, data, SecretUpdate::Keep, None)?.into())
    }

    #[uniffi::method(default(account_id))]
    pub fn delete_memory(&self, id: String, account_id: Option<String>) -> Result<()> {
        self.delete::<cm::Memory>(&id, &account_id)
    }
}

async fn save_key_material(
    ws: &Workspace,
    target: SaveTarget,
    label: String,
    material: termoak_ssh::keys::KeyMaterial,
    passphrase: Option<String>,
    store_passphrase: bool,
    sync_mode: Option<SyncMode>,
) -> Result<SshKey> {
    let data = cm::SshKey {
        id: Id::nil(),
        label: label.trim().to_string(),
        algorithm: material.algorithm.clone(),
        public_key: material.public_openssh.clone(),
        fingerprint: material.fingerprint.clone(),
        comment: material.comment.clone(),
        has_passphrase: material.encrypted,
        certificate: None,
    };
    let secret = SshKeySecret {
        private_key: Some(material.private_openssh.clone()),
        passphrase: passphrase.filter(|p| store_passphrase && material.encrypted && !p.is_empty()),
    };
    let rec = ws
        .save_item(
            target,
            data,
            SecretUpdate::Set(secret),
            sync_mode.map(Into::into),
        )
        .await?;
    Ok(rec.into())
}

/// Where an existing item is saved: its own store.
pub(crate) fn target_of_item(item: ItemRef) -> SaveTarget {
    match item.scope {
        Scope::Device => SaveTarget::Device,
        Scope::Account(account) => SaveTarget::Account {
            account,
            vault: None,
        },
    }
}

/// Generic helpers (not exported).
impl TermoakCore {
    /// Filter of a call (`None`: the current view, or the bound account).
    pub(crate) fn filter_of(
        &self,
        filter: Option<ItemFilter>,
    ) -> Result<termoak_client::ItemFilter> {
        match (filter, self.pinned) {
            (Some(f), _) => f.into_client(),
            (None, Some(id)) => Ok(termoak_client::ItemFilter {
                accounts: Some(vec![id]),
                vaults: None,
                include_device: false,
            }),
            (None, None) => Ok(self.ws.default_filter()),
        }
    }

    pub(crate) fn list_scoped<T: Entity>(
        &self,
        filter: Option<ItemFilter>,
    ) -> Result<Vec<Scoped<T>>> {
        let f = self.filter_of(filter)?;
        Ok(block_on(self.ws.list_items::<T>(&f))?)
    }

    fn list_into<T: Entity, R: From<Scoped<T>>>(
        &self,
        filter: Option<ItemFilter>,
    ) -> Result<Vec<R>> {
        Ok(self
            .list_scoped::<T>(filter)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// The item `id` (in `account`, or wherever it is).
    pub(crate) fn item_of(&self, id: Id, account: &Option<String>) -> Result<ItemRef> {
        match parse_opt_id(account)?.or(self.pinned) {
            Some(a) => {
                self.ws.require_account(a)?;
                Ok(ItemRef {
                    scope: Scope::Account(a),
                    id,
                })
            }
            None => Ok(block_on(self.ws.locate(id))?),
        }
    }

    pub(crate) fn get<T: Entity>(&self, id: &str, account: &Option<String>) -> Result<Scoped<T>> {
        let item = self.item_of(parse_id(id)?, account)?;
        Ok(block_on(self.ws.get_item::<T>(item))?)
    }

    pub(crate) fn item_secret<T: Entity>(&self, item: ItemRef) -> Result<T::Secret> {
        Ok(block_on(self.ws.item_secret::<T>(item))?)
    }

    fn secret<T: Entity>(&self, id: &str, account: &Option<String>) -> Result<T::Secret> {
        let item = self.item_of(parse_id(id)?, account)?;
        self.item_secret::<T>(item)
    }

    /// The current secret of an item about to be saved (empty if new).
    fn secret_for<T: Entity>(&self, target: SaveTarget, id: Id) -> Result<T::Secret> {
        if id.is_nil() {
            return Ok(T::Secret::default());
        }
        let item = match target {
            SaveTarget::Device => ItemRef {
                scope: Scope::Device,
                id,
            },
            SaveTarget::Account { account, .. } => ItemRef {
                scope: Scope::Account(account),
                id,
            },
            SaveTarget::Auto => match block_on(self.ws.locate(id)) {
                Ok(item) => item,
                Err(_) => return Ok(T::Secret::default()),
            },
        };
        match block_on(self.ws.item_secret::<T>(item)) {
            Ok(s) => Ok(s),
            Err(termoak_client::ClientError::Core(termoak_core::CoreError::NotFound(_))) => {
                Ok(T::Secret::default())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Where a record is saved: `account_id` and `vault_id` of the record
    /// (or of this handle's account), otherwise where it already is, or the
    /// current account / This device for a new one.
    pub(crate) fn target_of(
        &self,
        id: &str,
        account: &Option<String>,
        vault: &Option<String>,
    ) -> Result<SaveTarget> {
        let vault = parse_opt_id(vault)?;
        match parse_opt_id(account)?.or(self.pinned) {
            Some(account) => Ok(SaveTarget::Account { account, vault }),
            None => match (vault, self.ws.current()) {
                // A vault without an account: the current account's vault.
                (Some(v), Some(acc)) if parse_id_or_nil(id)?.is_nil() => Ok(SaveTarget::Account {
                    account: acc.id,
                    vault: Some(v),
                }),
                _ => Ok(SaveTarget::Auto),
            },
        }
    }

    fn save<T: Entity>(
        &self,
        target: SaveTarget,
        data: T,
        secret: SecretUpdate<T::Secret>,
        mode: Option<cm::SyncMode>,
    ) -> Result<Scoped<T>> {
        Ok(block_on(self.ws.save_item(target, data, secret, mode))?)
    }

    fn delete<T: Entity>(&self, id: &str, account: &Option<String>) -> Result<()> {
        let item = self.item_of(parse_id(id)?, account)?;
        Ok(block_on(self.ws.delete_item::<T>(item))?)
    }
}

/// A host's secret ready to save: if empty, it is cleared.
fn host_secret_update(s: HostSecret) -> SecretUpdate<HostSecret> {
    if s.password.is_none() && s.proxy_password.is_none() {
        SecretUpdate::Clear
    } else {
        SecretUpdate::Set(s)
    }
}

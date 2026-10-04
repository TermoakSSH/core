//! [`TermoakCore`]: the device's encrypted local vault and its CRUD.
//!
//! Vault operations are synchronous (local SQLite, microseconds); the ones
//! that may take a while (generating or importing keys) are `async`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use parking_lot::Mutex;
use termoak_client::{ApiClient, LOCAL_OWNER, Workspace};
use termoak_core::crypto::MasterKey;
use termoak_core::model::{
    self as cm, Entity, HostSecret, IdentitySecret, Record, SecretUpdate, SshKeySecret,
};
use termoak_core::{Id, Store};

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
    /// Server client (created on sign-in or on first use).
    pub(crate) api: Mutex<Option<ApiClient>>,
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
        let ws = Workspace::open(&dir, key)?;
        block_on(check_vault_key(&ws.store))?;
        Ok(Arc::new(Self {
            ws,
            api: Mutex::new(None),
        }))
    }

    /// The vault's data directory.
    pub fn data_dir(&self) -> String {
        self.ws.dir.to_string_lossy().into_owned()
    }

    // ----- Hosts -----

    /// Hosts, in creation order.
    pub fn list_hosts(&self) -> Result<Vec<SshHost>> {
        Ok(self
            .list::<cm::Host>()?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub fn get_host(&self, id: String) -> Result<SshHost> {
        Ok(self.get::<cm::Host>(&id)?.into())
    }

    /// Creates (with an empty `id`) or updates a host. `password` decides what
    /// to do with its password.
    pub fn save_host(&self, host: SshHost, password: SecretChange) -> Result<SshHost> {
        let (data, mode) = host.into_core()?;
        // The proxy password lives in the same secret: keep it.
        let secret = match password {
            SecretChange::Keep => SecretUpdate::Keep,
            change => {
                let mut s = self.secret_of::<cm::Host>(data.id)?;
                s.password = match change {
                    SecretChange::Set { value } => Some(value),
                    _ => None,
                };
                host_secret_update(s)
            }
        };
        Ok(self.save(data, secret, mode)?.into())
    }

    /// Changes a host's proxy password (`HostSettings.proxy`).
    pub fn set_host_proxy_password(&self, id: String, password: SecretChange) -> Result<()> {
        if matches!(password, SecretChange::Keep) {
            return Ok(());
        }
        let record = self.get::<cm::Host>(&id)?;
        let mut s = self.secret_of::<cm::Host>(record.data.id)?;
        s.proxy_password = match password {
            SecretChange::Set { value } => Some(value),
            _ => None,
        };
        self.save(record.data, host_secret_update(s), None)?;
        Ok(())
    }

    /// Whether a proxy password is saved.
    pub fn host_has_proxy_password(&self, id: String) -> Result<bool> {
        Ok(self.secret::<cm::Host>(&id)?.proxy_password.is_some())
    }

    pub fn delete_host(&self, id: String) -> Result<()> {
        self.delete::<cm::Host>(&id)
    }

    /// The host's saved password (to show or copy it).
    pub fn host_password(&self, id: String) -> Result<Option<String>> {
        Ok(self.secret::<cm::Host>(&id)?.password)
    }

    /// The host's effective settings: those of its groups (outermost to
    /// innermost) with the host's own on top.
    pub fn effective_settings(&self, host_id: String) -> Result<HostSettings> {
        let host = self.get::<cm::Host>(&host_id)?.data;
        let store = self.ws.store.clone();
        let settings = block_on(async move { store.effective_settings(LOCAL_OWNER, &host).await })?;
        Ok(settings.into())
    }

    // ----- Groups -----

    pub fn list_groups(&self) -> Result<Vec<HostGroup>> {
        Ok(self
            .list::<cm::Group>()?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub fn get_group(&self, id: String) -> Result<HostGroup> {
        Ok(self.get::<cm::Group>(&id)?.into())
    }

    pub fn save_group(&self, group: HostGroup) -> Result<HostGroup> {
        let (data, mode) = group.into_core()?;
        Ok(self.save(data, SecretUpdate::Keep, mode)?.into())
    }

    pub fn delete_group(&self, id: String) -> Result<()> {
        self.delete::<cm::Group>(&id)
    }

    // ----- Identities -----

    pub fn list_identities(&self) -> Result<Vec<SshIdentity>> {
        Ok(self
            .list::<cm::Identity>()?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub fn get_identity(&self, id: String) -> Result<SshIdentity> {
        Ok(self.get::<cm::Identity>(&id)?.into())
    }

    pub fn save_identity(
        &self,
        identity: SshIdentity,
        password: SecretChange,
    ) -> Result<SshIdentity> {
        let (data, mode) = identity.into_core()?;
        let secret = password_update(password, |password| IdentitySecret { password });
        Ok(self.save(data, secret, mode)?.into())
    }

    pub fn delete_identity(&self, id: String) -> Result<()> {
        self.delete::<cm::Identity>(&id)
    }

    pub fn identity_password(&self, id: String) -> Result<Option<String>> {
        Ok(self.secret::<cm::Identity>(&id)?.password)
    }

    // ----- SSH keys -----

    pub fn list_keys(&self) -> Result<Vec<SshKey>> {
        Ok(self
            .list::<cm::SshKey>()?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub fn get_key(&self, id: String) -> Result<SshKey> {
        Ok(self.get::<cm::SshKey>(&id)?.into())
    }

    /// Generates a new key and saves it in the vault. With a `passphrase`, the
    /// private key is encrypted with it; `store_passphrase` decides whether the
    /// passphrase is saved too (otherwise it is asked for when connecting).
    pub async fn generate_key(
        &self,
        label: String,
        key_type: KeyType,
        comment: String,
        passphrase: Option<String>,
        store_passphrase: bool,
        sync_mode: Option<SyncMode>,
    ) -> Result<SshKey> {
        let store = self.ws.store.clone();
        run(async move {
            let pass = passphrase.clone();
            let material = tokio::task::spawn_blocking(move || {
                termoak_ssh::keys::generate(key_type.into(), &comment, pass.as_deref())
            })
            .await
            .map_err(|e| TermoakError::Internal(e.to_string()))??;
            save_key_material(
                &store,
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
    pub async fn import_key(
        &self,
        label: String,
        private_key: String,
        passphrase: Option<String>,
        store_passphrase: bool,
        sync_mode: Option<SyncMode>,
    ) -> Result<SshKey> {
        let store = self.ws.store.clone();
        run(async move {
            let pass = passphrase.clone();
            let material = tokio::task::spawn_blocking(move || {
                termoak_ssh::keys::import_private(&private_key, pass.as_deref())
            })
            .await
            .map_err(|e| TermoakError::Internal(e.to_string()))??;
            save_key_material(
                &store,
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
        let (edited, mode) = key.into_core()?;
        if edited.id.is_nil() {
            return Err(TermoakError::Invalid(
                "to add a key use generate_key or import_key".into(),
            ));
        }
        let mut data = self.get_record::<cm::SshKey>(edited.id)?.data;
        data.label = edited.label;
        data.comment = edited.comment;
        data.certificate = edited.certificate;
        let secret = if passphrase.is_keep() {
            SecretUpdate::Keep
        } else {
            let mut current = self.secret_of::<cm::SshKey>(data.id)?;
            current.passphrase = passphrase.apply(current.passphrase);
            SecretUpdate::Set(current)
        };
        Ok(self.save(data, secret, mode)?.into())
    }

    pub fn delete_key(&self, id: String) -> Result<()> {
        self.delete::<cm::SshKey>(&id)
    }

    /// The saved private key (OpenSSH/PEM format), to export it.
    pub fn export_private_key(&self, id: String) -> Result<Option<String>> {
        Ok(self.secret::<cm::SshKey>(&id)?.private_key)
    }

    // ----- Snippets -----

    pub fn list_snippets(&self) -> Result<Vec<Snippet>> {
        Ok(self
            .list::<cm::Snippet>()?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub fn get_snippet(&self, id: String) -> Result<Snippet> {
        Ok(self.get::<cm::Snippet>(&id)?.into())
    }

    pub fn save_snippet(&self, snippet: Snippet) -> Result<Snippet> {
        let (data, mode) = snippet.into_core()?;
        Ok(self.save(data, SecretUpdate::Keep, mode)?.into())
    }

    pub fn delete_snippet(&self, id: String) -> Result<()> {
        self.delete::<cm::Snippet>(&id)
    }

    // ----- Tunnels -----

    /// Saved tunnels; with `host_id`, only that host's.
    pub fn list_forwards(&self, host_id: Option<String>) -> Result<Vec<PortForward>> {
        let host = parse_opt_id(&host_id)?;
        Ok(self
            .list::<cm::PortForward>()?
            .into_iter()
            .filter(|r| host.is_none_or(|h| r.data.host_id == h))
            .map(Into::into)
            .collect())
    }

    pub fn get_forward(&self, id: String) -> Result<PortForward> {
        Ok(self.get::<cm::PortForward>(&id)?.into())
    }

    pub fn save_forward(&self, forward: PortForward) -> Result<PortForward> {
        let (data, mode) = forward.into_core()?;
        Ok(self.save(data, SecretUpdate::Keep, mode)?.into())
    }

    pub fn delete_forward(&self, id: String) -> Result<()> {
        self.delete::<cm::PortForward>(&id)
    }

    // ----- Known hosts -----

    /// Trusted server keys (added when accepting a new fingerprint while
    /// connecting).
    pub fn list_known_hosts(&self) -> Result<Vec<KnownHost>> {
        Ok(self
            .list::<cm::KnownHost>()?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Forgets a server key (e.g. after reinstalling the server).
    pub fn delete_known_host(&self, id: String) -> Result<()> {
        self.delete::<cm::KnownHost>(&id)
    }

    // ----- AI memories -----

    pub fn list_memories(&self) -> Result<Vec<AiMemory>> {
        Ok(self
            .list::<cm::Memory>()?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub fn save_memory(&self, memory: AiMemory) -> Result<AiMemory> {
        let data = memory.into_core()?;
        Ok(self.save(data, SecretUpdate::Keep, None)?.into())
    }

    pub fn delete_memory(&self, id: String) -> Result<()> {
        self.delete::<cm::Memory>(&id)
    }
}

async fn save_key_material(
    store: &Store,
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
    let rec = store
        .save(
            LOCAL_OWNER,
            data,
            SecretUpdate::Set(secret),
            sync_mode.map(Into::into),
        )
        .await?;
    Ok(rec.into())
}

/// Generic helpers (not exported).
impl TermoakCore {
    pub(crate) fn store(&self) -> &Store {
        &self.ws.store
    }

    fn list<T: Entity>(&self) -> Result<Vec<Record<T>>> {
        Ok(block_on(self.ws.store.list::<T>(LOCAL_OWNER))?)
    }

    fn get<T: Entity>(&self, id: &str) -> Result<Record<T>> {
        self.get_record(parse_id(id)?)
    }

    pub(crate) fn get_record<T: Entity>(&self, id: Id) -> Result<Record<T>> {
        Ok(block_on(self.ws.store.get::<T>(LOCAL_OWNER, id))?)
    }

    fn secret<T: Entity>(&self, id: &str) -> Result<T::Secret> {
        self.secret_of::<T>(parse_id(id)?)
    }

    fn secret_of<T: Entity>(&self, id: Id) -> Result<T::Secret> {
        let store = self.ws.store.clone();
        block_on(async move { current_secret::<T>(&store, LOCAL_OWNER, id).await })
    }

    fn save<T: Entity>(
        &self,
        data: T,
        secret: SecretUpdate<T::Secret>,
        mode: Option<cm::SyncMode>,
    ) -> Result<Record<T>> {
        Ok(block_on(self.ws.store.save(
            LOCAL_OWNER,
            data,
            secret,
            mode,
        ))?)
    }

    fn delete<T: Entity>(&self, id: &str) -> Result<()> {
        let id = parse_id(id)?;
        Ok(block_on(self.ws.store.delete::<T>(LOCAL_OWNER, id))?)
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

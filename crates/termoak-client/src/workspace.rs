//! Local workspace: the device's encrypted database, the local SSH engine and
//! (optionally) the connection to a server.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use termoak_core::Store;
use termoak_core::crypto::MasterKey;
use termoak_core::model::TokenPair;
use termoak_core::{Id, resolve::ResolvedHost};
use termoak_ssh::prompt::AuthPrompter;
use termoak_ssh::recording::Recorder;
use termoak_ssh::{
    ConnectOptions, Connection, HostKeyPolicy, PtyOptions, StoreVerifier, TerminalSession,
};

use crate::LOCAL_OWNER;
use crate::api::{self, ApiClient};
use crate::error::{ClientError, Result};
use crate::sync::SyncEngine;
use crate::vault;

/// AAD of the stored server tokens. Frozen (former project name): see
/// `termoak_core::crypto::LEGACY_AAD_PREFIX`.
const SERVER_TOKENS_AAD: &[u8] = b"aceitunoak:server-tokens";

const SERVER_URL: &str = "server.url";
const SERVER_TOKENS: &str = "server.tokens";
const SERVER_USER: &str = "server.user";
const DEVICE_NAME: &str = "device.name";

/// The device's workspace.
#[derive(Clone)]
pub struct Workspace {
    pub store: Store,
    pub dir: PathBuf,
}

/// Database path. The first time, it renames the database left by
/// AceitunoakSSH (the project's former name); if that fails, the old database
/// keeps being used in place.
fn db_path(dir: &Path) -> PathBuf {
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

/// New address of a server that moved, if `url` points to its old one.
fn moved_server(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://aceitunoak.ohz.ovh")?;
    (rest.is_empty() || rest.starts_with('/')).then(|| format!("https://termoak.com{rest}"))
}

impl Workspace {
    /// Opens the user's default workspace.
    pub fn open_default() -> Result<Self> {
        let dir = vault::data_dir();
        std::fs::create_dir_all(&dir)?;
        let key = vault::load_or_create_key(&dir)?;
        Self::open(&dir, key)
    }

    /// Opens a workspace in `dir` with the given key.
    pub fn open(dir: &Path, key: MasterKey) -> Result<Self> {
        let store = Store::open(&db_path(dir), key)?;
        Ok(Self {
            store,
            dir: dir.to_path_buf(),
        })
    }

    pub fn owner(&self) -> Id {
        LOCAL_OWNER
    }

    // ----- Server -----

    fn seal_tokens(store: &Store, tokens: &TokenPair) -> Option<String> {
        let json = serde_json::to_vec(tokens).ok()?;
        let sealed = store.master_key().seal(&json, SERVER_TOKENS_AAD).ok()?;
        Some(STANDARD.encode(sealed))
    }

    fn persist_tokens(store: &Store, tokens: &TokenPair) {
        if let Some(sealed) = Self::seal_tokens(store, tokens) {
            let _ = store.call_blocking(move |c, _| {
                c.execute(
                    "INSERT INTO meta(key, value) VALUES(?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    [SERVER_TOKENS, sealed.as_str()],
                )?;
                Ok(())
            });
        }
    }

    fn api_for(&self, url: &str, tokens: Option<TokenPair>) -> Result<ApiClient> {
        let store = self.store.clone();
        Ok(ApiClient::new(url)?
            .with_tokens(tokens)
            .on_tokens(move |t| Self::persist_tokens(&store, t)))
    }

    /// Client for the configured server (if signed in).
    pub async fn server(&self) -> Result<Option<ApiClient>> {
        let Some(mut url) = self.store.meta_get(SERVER_URL).await? else {
            return Ok(None);
        };
        // The official server moved from aceitunoak.ohz.ovh to termoak.com; it is
        // the same server, so the saved session keeps working.
        if let Some(moved) = moved_server(&url) {
            self.store.meta_set(SERVER_URL, &moved).await?;
            url = moved;
        }
        let tokens = match self.store.meta_get(SERVER_TOKENS).await? {
            // `logout` leaves the value empty.
            Some(sealed) if !sealed.is_empty() => {
                let raw = STANDARD
                    .decode(sealed)
                    .map_err(|e| ClientError::Invalid(e.to_string()))?;
                let plain = self.store.master_key().open(&raw, SERVER_TOKENS_AAD)?;
                serde_json::from_slice::<TokenPair>(&plain).ok()
            }
            _ => None,
        };
        if tokens.is_none() {
            return Ok(None);
        }
        Ok(Some(self.api_for(&url, tokens)?))
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

    /// Signs in to a server and remembers it.
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
        let api = self.api_for(url, None)?;
        let device = self.device_name().await?;
        let auth = api
            .login_with_code(email, password, totp_code, &device, &api::platform())
            .await?;
        self.store.meta_set(SERVER_URL, api.base_url()).await?;
        self.store.meta_set(SERVER_USER, &auth.user.email).await?;
        Ok(api)
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
        let api = self.api_for(url, None)?;
        let device = self.device_name().await?;
        let auth = api
            .register_with_invite(email, name, password, invite, &device, &api::platform())
            .await?;
        self.store.meta_set(SERVER_URL, api.base_url()).await?;
        self.store.meta_set(SERVER_USER, &auth.user.email).await?;
        Ok(api)
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
        let api = self.api_for(url, None)?;
        let device = self.device_name().await?;
        let auth = api
            .verify_code(email, code, totp_code, &device, &api::platform())
            .await?;
        self.store.meta_set(SERVER_URL, api.base_url()).await?;
        self.store.meta_set(SERVER_USER, &auth.user.email).await?;
        Ok(api)
    }

    /// Asks the server for a new verification code (no sign-in needed).
    pub async fn resend_code(&self, url: &str, email: &str) -> Result<()> {
        ApiClient::new(url)?.resend_code(email).await
    }

    pub async fn logout(&self) -> Result<()> {
        if let Some(api) = self.server().await? {
            let _ = api.logout().await;
        }
        self.store.meta_set(SERVER_TOKENS, "").await?;
        Ok(())
    }

    /// Email used to sign in.
    pub async fn server_user(&self) -> Result<Option<String>> {
        Ok(self.store.meta_get(SERVER_USER).await?)
    }

    /// Sync engine (if there is a server).
    pub async fn sync_engine(&self) -> Result<Option<SyncEngine>> {
        Ok(self
            .server()
            .await?
            .map(|api| SyncEngine::new(self.store.clone(), api)))
    }

    // ----- Local SSH -----

    /// Host key verifier that asks the user.
    pub fn verifier(
        &self,
        prompter: Option<Arc<dyn AuthPrompter>>,
        policy: HostKeyPolicy,
    ) -> Arc<StoreVerifier> {
        Arc::new(StoreVerifier {
            store: self.store.clone(),
            owner: LOCAL_OWNER,
            policy,
            prompter,
        })
    }

    pub async fn resolve(&self, host_id: Id) -> Result<ResolvedHost> {
        Ok(self.store.resolve_host(LOCAL_OWNER, host_id).await?)
    }

    /// Connects to a host from this device.
    pub async fn connect(
        &self,
        host_id: Id,
        prompter: Arc<dyn AuthPrompter>,
        use_agent: bool,
    ) -> Result<Arc<Connection>> {
        let resolved = self.resolve(host_id).await?;
        let opts = ConnectOptions::new(self.verifier(Some(prompter.clone()), HostKeyPolicy::Ask))
            .with_prompter(prompter)
            .with_agent(use_agent);
        Ok(Connection::connect(&resolved, &opts).await?)
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
        let resolved = self.resolve(host_id).await?;
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

    #[test]
    fn old_official_server_moves_to_termoak() {
        assert_eq!(
            super::moved_server("https://aceitunoak.ohz.ovh").as_deref(),
            Some("https://termoak.com")
        );
        assert_eq!(
            super::moved_server("https://aceitunoak.ohz.ovh/").as_deref(),
            Some("https://termoak.com/")
        );
        assert_eq!(
            super::moved_server("https://aceitunoak.ohz.ovh.evil.com"),
            None
        );
        assert_eq!(super::moved_server("https://ssh.example.com"), None);
    }
    use super::*;
    use termoak_core::model::{Host, HostSettings, SecretUpdate};

    #[tokio::test]
    async fn workspace_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let ws = Workspace::open(dir.path(), MasterKey::generate()).unwrap();
        assert!(ws.server().await.unwrap().is_none());
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
        // Tokens sealed and recovered.
        let tokens = TokenPair {
            access_token: "a".into(),
            access_expires_at: i64::MAX,
            refresh_token: "r".into(),
            refresh_expires_at: i64::MAX,
            device_id: Id::nil(),
        };
        ws.store
            .meta_set(SERVER_URL, "http://127.0.0.1:1")
            .await
            .unwrap();
        Workspace::persist_tokens(&ws.store, &tokens);
        let api = ws.server().await.unwrap().unwrap();
        assert_eq!(api.tokens().unwrap().refresh_token, "r");
        // After signing out there is no server (and that is not an error).
        ws.logout().await.unwrap();
        assert!(ws.server().await.unwrap().is_none());
    }
}

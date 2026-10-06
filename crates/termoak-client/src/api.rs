//! HTTP client for the server API.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use termoak_core::Id;
use termoak_core::model::{AuditEntry, SyncRecord, TokenPair, User, Vault, VaultMember, VaultRole};
use termoak_core::time::now_ms;
use termoak_core::transfer::{TransferRequest, TransferResult};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use crate::error::{ClientError, Result};

/// Login/registration response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub user: User,
    pub tokens: TokenPair,
    /// The server requires a verified email and this account has not
    /// verified it yet: the tokens only reach the account itself (`/me`,
    /// `/auth/*`, `/devices`) until the code from the email is entered
    /// ([`ApiClient::verify_code`]) or its link is opened. `false` with older
    /// servers, which do not send it.
    #[serde(default)]
    pub verification_required: bool,
}

/// Sync response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    pub rev: i64,
    pub changes: Vec<SyncRecord>,
    #[serde(default)]
    pub accepted: Vec<Id>,
}

/// Languages a server has (`GET /api/v1/locales`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerLocales {
    /// Language used when the account has none the server knows.
    pub default: String,
    pub locales: Vec<ServerLocale>,
}

/// A language of the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerLocale {
    /// BCP 47 code (`en`, `es`, `pt-BR`...).
    pub code: String,
    /// Name of the language in that language (`English`, `Español`).
    pub name: String,
}

/// One of your own AI API keys (`GET /api/v1/me/ai/keys`). The key itself
/// never comes back from the server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiKeyInfo {
    /// `claude`, `gpt`, `openrouter` or `opencode-api`.
    pub provider: String,
    /// Display name of the provider.
    #[serde(default)]
    pub label: String,
    /// Model chosen for it (`None` = the provider's default).
    #[serde(default)]
    pub model: Option<String>,
    /// Last 4 characters of the key.
    #[serde(default)]
    pub hint: String,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub updated_at: i64,
}

/// Result of checking an AI key with its provider.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiKeyTest {
    pub ok: bool,
    /// What the provider said, when it failed.
    #[serde(default)]
    pub error: Option<String>,
    /// HTTP status of the provider (401/403 usually mean a wrong key).
    #[serde(default)]
    pub status: Option<u16>,
}

/// A provider that accepts your own API key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiKeyProvider {
    pub provider: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub default_model: Option<String>,
    /// Suggested models (others can be typed).
    #[serde(default)]
    pub models: Vec<String>,
}

/// Your AI situation (`GET /api/v1/me/ai/access`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiAccess {
    /// Providers with one of your own API keys (used first, no credit spent).
    #[serde(default)]
    pub own_keys: Vec<String>,
    /// Your plan can use the server's AI providers.
    #[serde(default)]
    pub server_ai: bool,
    /// Monthly credit (USD) for the server's providers (`None` = no cap, or
    /// no server AI).
    #[serde(default)]
    pub credit_usd: Option<f64>,
    /// Spent this month on the server's providers.
    #[serde(default)]
    pub spent_usd: f64,
    /// Credit left this month (`None` when there is no credit).
    #[serde(default)]
    pub remaining_usd: Option<f64>,
    /// Providers that accept your own API key.
    #[serde(default)]
    pub providers: Vec<AiKeyProvider>,
}

/// A provider key as a path segment (`claude`, `opencode-api`...).
fn provider_segment(provider: &str) -> Result<&str> {
    let p = provider.trim();
    if p.is_empty()
        || p.len() > 64
        || !p
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(ClientError::Invalid(format!(
            "invalid AI provider \"{}\"",
            p.chars().take(64).collect::<String>()
        )));
    }
    Ok(p)
}

type TokenCallback = Arc<dyn Fn(&TokenPair) + Send + Sync>;
type ExpiredCallback = Arc<dyn Fn() + Send + Sync>;

/// Credentials of one hop of a host (`POST /hosts/{id}/credentials`). Wiped
/// from memory on drop.
#[derive(Clone, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct CredentialHop {
    #[zeroize(skip)]
    pub host_id: Id,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub key: Option<CredentialKey>,
    #[serde(default)]
    pub proxy_password: Option<String>,
}

/// A private key of [`CredentialHop`].
#[derive(Clone, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct CredentialKey {
    pub private_key: String,
    #[serde(default)]
    pub passphrase: Option<String>,
    #[serde(default)]
    pub certificate: Option<String>,
}

/// Just-in-time credentials of a host and its jumps (the jumps first, the
/// host last), for a connection from this device to a host of a Use-only
/// vault. Kept in memory only, until the connection is authenticated.
#[derive(Clone, Deserialize)]
pub struct Credentials {
    pub vault_id: Id,
    /// Keep them at most until this time (ms).
    #[serde(default)]
    pub expires_at: i64,
    pub hops: Vec<CredentialHop>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("vault_id", &self.vault_id)
            .field("hops", &self.hops.len())
            .finish_non_exhaustive()
    }
}

/// API client. Cheap to clone.
#[derive(Clone)]
pub struct ApiClient {
    base: String,
    http: reqwest::Client,
    tokens: Arc<Mutex<Option<TokenPair>>>,
    on_tokens: Option<TokenCallback>,
    on_expired: Option<ExpiredCallback>,
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
}

/// The client's WebSocket.
pub type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

impl ApiClient {
    /// `base` is the server URL (e.g. `https://ssh.example.com`).
    pub fn new(base: &str) -> Result<Self> {
        let base = base.trim().trim_end_matches('/').to_string();
        url::Url::parse(&base).map_err(|e| ClientError::Invalid(format!("invalid URL: {e}")))?;
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .user_agent(concat!("Termoak/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            base,
            http,
            tokens: Arc::new(Mutex::new(None)),
            on_tokens: None,
            on_expired: None,
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// Restores saved tokens.
    pub fn with_tokens(self, tokens: Option<TokenPair>) -> Self {
        *self.tokens.lock() = tokens;
        self
    }

    /// Callback called when new tokens arrive (to save them).
    pub fn on_tokens(mut self, f: impl Fn(&TokenPair) + Send + Sync + 'static) -> Self {
        self.on_tokens = Some(Arc::new(f));
        self
    }

    /// Callback called when the session expires (the refresh token was
    /// refused): the account has to sign in again.
    pub fn on_expired(mut self, f: impl Fn() + Send + Sync + 'static) -> Self {
        self.on_expired = Some(Arc::new(f));
        self
    }

    /// Replaces the tokens of this client and of its clones (signing in
    /// again an account that already has a client).
    pub fn replace_tokens(&self, tokens: Option<TokenPair>) {
        *self.tokens.lock() = tokens;
    }

    pub fn tokens(&self) -> Option<TokenPair> {
        self.tokens.lock().clone()
    }

    pub fn is_logged_in(&self) -> bool {
        self.tokens.lock().is_some()
    }

    fn set_tokens(&self, t: TokenPair) {
        if let Some(cb) = &self.on_tokens {
            cb(&t);
        }
        *self.tokens.lock() = Some(t);
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn parse<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
        let status = resp.status();
        let text = resp.text().await?;
        if status.is_success() {
            let body = if text.trim().is_empty() {
                "null"
            } else {
                &text
            };
            return serde_json::from_str(body)
                .map_err(|e| ClientError::Invalid(format!("invalid response: {e}")));
        }
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        Err(ClientError::Api {
            status: status.as_u16(),
            code: v["error"]["code"].as_str().unwrap_or("error").to_string(),
            message: v["error"]["message"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| text.chars().take(300).collect()),
        })
    }

    /// Refreshes the access token if it expires in less than a minute.
    async fn ensure_fresh(&self) -> Result<String> {
        let current = self.tokens.lock().clone().ok_or(ClientError::NotLoggedIn)?;
        if current.access_expires_at - now_ms() > 60_000 {
            return Ok(current.access_token);
        }
        self.refresh().await
    }

    /// Forces a token refresh.
    pub async fn refresh(&self) -> Result<String> {
        let _guard = self.refresh_lock.lock().await;
        let current = self.tokens.lock().clone().ok_or(ClientError::NotLoggedIn)?;
        // Another thread may have refreshed it while we were waiting.
        if current.access_expires_at - now_ms() > 60_000 {
            return Ok(current.access_token);
        }
        let resp = self
            .http
            .post(self.url("/api/v1/auth/refresh"))
            .json(&json!({"refresh_token": current.refresh_token}))
            .send()
            .await?;
        if resp.status().as_u16() == 401 {
            *self.tokens.lock() = None;
            if let Some(cb) = &self.on_expired {
                cb();
            }
            return Err(ClientError::SessionExpired);
        }
        let tokens: TokenPair = Self::parse(resp).await?;
        let access = tokens.access_token.clone();
        self.set_tokens(tokens);
        Ok(access)
    }

    /// Generic authenticated request.
    pub async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<T> {
        let token = self.ensure_fresh().await?;
        let build = |token: &str| {
            let mut r = self
                .http
                .request(method.clone(), self.url(path))
                .bearer_auth(token);
            if let Some(b) = body {
                r = r.json(b);
            }
            r
        };
        let resp = build(&token).send().await?;
        if resp.status().as_u16() == 401 {
            // The token may have been revoked or expired: try one refresh.
            if let Some(t) = self.tokens.lock().as_mut() {
                t.access_expires_at = 0;
            }
            let token = self.refresh().await?;
            return Self::parse(build(&token).send().await?).await;
        }
        Self::parse(resp).await
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.request(Method::GET, path, None).await
    }

    pub async fn post<T: DeserializeOwned>(&self, path: &str, body: &Value) -> Result<T> {
        self.request(Method::POST, path, Some(body)).await
    }

    pub async fn put<T: DeserializeOwned>(&self, path: &str, body: &Value) -> Result<T> {
        self.request(Method::PUT, path, Some(body)).await
    }

    pub async fn patch<T: DeserializeOwned>(&self, path: &str, body: &Value) -> Result<T> {
        self.request(Method::PATCH, path, Some(body)).await
    }

    pub async fn delete(&self, path: &str) -> Result<Value> {
        self.request(Method::DELETE, path, None).await
    }

    /// Error from a non-2xx response.
    async fn error_of(resp: reqwest::Response) -> ClientError {
        match Self::parse::<Value>(resp).await {
            Err(e) => e,
            Ok(_) => ClientError::Invalid("unexpected response from the server".into()),
        }
    }

    /// Authenticated download to a file, streamed without loading it into
    /// memory. Writes to `<dest>.part` and renames it when done (if it is cut
    /// off, no half-written file is left under the final name). `progress`
    /// receives the bytes downloaded and the total, if known.
    pub async fn download_to(
        &self,
        path: &str,
        dest: &std::path::Path,
        mut progress: impl FnMut(u64, Option<u64>) + Send,
    ) -> Result<u64> {
        use futures::StreamExt;
        use tokio::io::AsyncWriteExt;

        let send = |token: String| self.http.get(self.url(path)).bearer_auth(token).send();
        let mut resp = send(self.ensure_fresh().await?).await?;
        if resp.status().as_u16() == 401 {
            if let Some(t) = self.tokens.lock().as_mut() {
                t.access_expires_at = 0;
            }
            resp = send(self.refresh().await?).await?;
        }
        if !resp.status().is_success() {
            return Err(Self::error_of(resp).await);
        }
        let total = resp.content_length();
        let tmp = {
            let mut s = dest.as_os_str().to_owned();
            s.push(".part");
            std::path::PathBuf::from(s)
        };
        let mut file = tokio::fs::File::create(&tmp).await?;
        let mut done = 0u64;
        let mut stream = resp.bytes_stream();
        let copied: Result<()> = async {
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                file.write_all(&chunk).await?;
                done += chunk.len() as u64;
                progress(done, total);
            }
            file.flush().await?;
            if let Some(t) = total
                && done != t
            {
                return Err(ClientError::Network(format!(
                    "incomplete download ({done} of {t} bytes)"
                )));
            }
            Ok(())
        }
        .await;
        drop(file);
        if let Err(e) = copied {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e);
        }
        tokio::fs::rename(&tmp, dest).await?;
        Ok(done)
    }

    /// Streams a file as the body of an authenticated `POST`.
    /// Returns the JSON response.
    pub async fn upload_from(
        &self,
        path: &str,
        src: &std::path::Path,
        mut progress: impl FnMut(u64, Option<u64>) + Send + 'static,
    ) -> Result<Value> {
        use futures::StreamExt;

        let file = tokio::fs::File::open(src).await?;
        let total = file.metadata().await?.len();
        let mut sent = 0u64;
        let stream =
            tokio_util::io::ReaderStream::with_capacity(file, 256 * 1024).map(move |chunk| {
                if let Ok(c) = &chunk {
                    sent += c.len() as u64;
                    progress(sent, Some(total));
                }
                chunk
            });
        // The body cannot be replayed: refresh the token first if needed.
        let token = self.ensure_fresh().await?;
        let resp = self
            .http
            .post(self.url(path))
            .bearer_auth(token)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .header(reqwest::header::CONTENT_LENGTH, total)
            .body(reqwest::Body::wrap_stream(stream))
            .send()
            .await?;
        Self::parse(resp).await
    }

    /// Unauthenticated `POST` (password recovery, email verification...).
    pub async fn post_public<T: DeserializeOwned>(&self, path: &str, body: &Value) -> Result<T> {
        Self::parse(self.http.post(self.url(path)).json(body).send().await?).await
    }

    /// The server's public information.
    pub async fn info(&self) -> Result<Value> {
        Self::parse(self.http.get(self.url("/api/v1/info")).send().await?).await
    }

    /// Public data of an invitation (without signing in): the email it is
    /// bound to, the team and the expiry.
    pub async fn invite_info(&self, token: &str) -> Result<Value> {
        let token = token.trim();
        if token.is_empty()
            || !token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(ClientError::Invalid(
                "the invitation code is not valid".into(),
            ));
        }
        let url = self.url(&format!("/api/v1/invites/{token}"));
        Self::parse(self.http.get(url).send().await?).await
    }

    pub async fn login(
        &self,
        email: &str,
        password: &str,
        device_name: &str,
        platform: &str,
    ) -> Result<AuthResponse> {
        self.login_with_code(email, password, None, device_name, platform)
            .await
    }

    /// Signs in with the two-factor code (or a recovery code). If the
    /// account needs it and none is given, the error satisfies
    /// [`ClientError::is_totp_required`].
    pub async fn login_with_code(
        &self,
        email: &str,
        password: &str,
        totp_code: Option<&str>,
        device_name: &str,
        platform: &str,
    ) -> Result<AuthResponse> {
        let resp = self
            .http
            .post(self.url("/api/v1/auth/login"))
            .json(&json!({"email": email, "password": password, "totp_code": totp_code, "device_name": device_name, "platform": platform}))
            .send()
            .await?;
        let auth: AuthResponse = Self::parse(resp).await?;
        self.set_tokens(auth.tokens.clone());
        Ok(auth)
    }

    pub async fn register(
        &self,
        email: &str,
        name: &str,
        password: &str,
        device_name: &str,
        platform: &str,
    ) -> Result<AuthResponse> {
        self.register_with_invite(email, name, password, None, device_name, platform)
            .await
    }

    /// Creates the account with an invitation code (works even when the
    /// server's registration is closed).
    pub async fn register_with_invite(
        &self,
        email: &str,
        name: &str,
        password: &str,
        invite: Option<&str>,
        device_name: &str,
        platform: &str,
    ) -> Result<AuthResponse> {
        let resp = self
            .http
            .post(self.url("/api/v1/auth/register"))
            .json(&json!({"email": email, "name": name, "password": password, "invite": invite, "device_name": device_name, "platform": platform}))
            .send()
            .await?;
        let auth: AuthResponse = Self::parse(resp).await?;
        self.set_tokens(auth.tokens.clone());
        Ok(auth)
    }

    /// Verifies the account's email with the six-digit code from the
    /// verification email and signs in (the tokens are kept like after
    /// [`login`](Self::login)). A wrong, expired or used-up code fails with
    /// [`ClientError::is_invalid_code`]. If the account already has
    /// two-factor authentication, the server asks for that code too
    /// ([`ClientError::is_totp_required`]): repeat with `totp_code`.
    pub async fn verify_code(
        &self,
        email: &str,
        code: &str,
        totp_code: Option<&str>,
        device_name: &str,
        platform: &str,
    ) -> Result<AuthResponse> {
        let resp = self
            .http
            .post(self.url("/api/v1/auth/verify-code"))
            .json(&json!({"email": email.trim(), "code": code.trim(), "totp_code": totp_code, "device_name": device_name, "platform": platform}))
            .send()
            .await?;
        let auth: AuthResponse = Self::parse(resp).await?;
        self.set_tokens(auth.tokens.clone());
        Ok(auth)
    }

    /// Asks for a new verification code by email. The server answers the
    /// same whether the account exists or not; it only fails when asked too
    /// often (`too_many_attempts`: once a minute and five times an hour).
    pub async fn resend_code(&self, email: &str) -> Result<()> {
        let _: Value = self
            .post_public("/api/v1/auth/resend-code", &json!({"email": email.trim()}))
            .await?;
        Ok(())
    }

    /// Whether the signed-in account still has to verify its email before
    /// using the server (see [`AuthResponse::verification_required`]).
    pub async fn verification_required(&self) -> Result<bool> {
        let me: Value = self.get("/api/v1/me").await?;
        if let Some(required) = me["verification_required"].as_bool() {
            return Ok(required);
        }
        // Older servers do not say: the same rule they apply.
        if me["user"]["email_verified"].as_bool().unwrap_or(true) {
            return Ok(false);
        }
        let info = self.info().await?;
        Ok(info["features"]["email_verification"]
            .as_bool()
            .unwrap_or(false))
    }

    pub async fn logout(&self) -> Result<()> {
        let _ = self.post::<Value>("/api/v1/auth/logout", &json!({})).await;
        *self.tokens.lock() = None;
        Ok(())
    }

    pub async fn sync(&self, since: i64, changes: Vec<SyncRecord>) -> Result<SyncResponse> {
        self.post("/api/v1/sync", &json!({"since": since, "changes": changes}))
            .await
    }

    /// Sync protocol v2 (`POST /api/v1/vaults/sync`): per-vault cursors.
    pub async fn sync_v2(
        &self,
        req: &crate::sync::SyncV2Request,
    ) -> Result<crate::sync::SyncV2Response> {
        self.post(
            "/api/v1/vaults/sync",
            &serde_json::to_value(req).map_err(|e| ClientError::Invalid(e.to_string()))?,
        )
        .await
    }

    // ----- Vaults -----

    /// Vaults you can access, with your role, owner name and counts.
    pub async fn vaults(&self) -> Result<Vec<Vault>> {
        self.get("/api/v1/vaults").await
    }

    pub async fn vault(&self, id: Id) -> Result<Vault> {
        self.get(&format!("/api/v1/vaults/{id}")).await
    }

    /// Creates a vault: `{name, description?, color?, icon?, team_id?,
    /// team_member_role?, settings?}`.
    pub async fn create_vault(&self, body: &Value) -> Result<Vault> {
        self.post("/api/v1/vaults", body).await
    }

    /// Changes a vault (managers): `{name?, description?, color?, icon?,
    /// team_member_role?, settings?}`.
    pub async fn update_vault(&self, id: Id, patch: &Value) -> Result<Vault> {
        self.patch(&format!("/api/v1/vaults/{id}"), patch).await
    }

    /// Deletes a vault and its items (managers). `confirm` is the vault's
    /// name.
    pub async fn delete_vault(&self, id: Id, confirm: &str) -> Result<()> {
        let name: String = url::form_urlencoded::byte_serialize(confirm.as_bytes()).collect();
        self.delete(&format!("/api/v1/vaults/{id}?confirm={name}"))
            .await?;
        Ok(())
    }

    /// Gives up your own grant on a vault.
    pub async fn leave_vault(&self, id: Id) -> Result<()> {
        let _: Value = self
            .post(&format!("/api/v1/vaults/{id}/leave"), &json!({}))
            .await?;
        Ok(())
    }

    pub async fn vault_members(&self, id: Id) -> Result<Vec<VaultMember>> {
        self.get(&format!("/api/v1/vaults/{id}/members")).await
    }

    /// Adds a member: `{email, role}` or `{team_id, role}`.
    pub async fn add_vault_member(&self, id: Id, body: &Value) -> Result<VaultMember> {
        self.post(&format!("/api/v1/vaults/{id}/members"), body)
            .await
    }

    pub async fn set_vault_member_role(
        &self,
        id: Id,
        member: Id,
        role: VaultRole,
    ) -> Result<VaultMember> {
        self.patch(
            &format!("/api/v1/vaults/{id}/members/{member}"),
            &json!({"role": role}),
        )
        .await
    }

    pub async fn remove_vault_member(&self, id: Id, member: Id) -> Result<()> {
        self.delete(&format!("/api/v1/vaults/{id}/members/{member}"))
            .await?;
        Ok(())
    }

    /// Audit of a vault (managers), newest first.
    pub async fn vault_audit(
        &self,
        id: Id,
        before: Option<i64>,
        limit: u32,
    ) -> Result<Vec<AuditEntry>> {
        let mut path = format!("/api/v1/vaults/{id}/audit?limit={}", limit.clamp(1, 1000));
        if let Some(b) = before {
            path.push_str(&format!("&before={b}"));
        }
        self.get(&path).await
    }

    /// Moves or copies items into the vault `target` (online).
    pub async fn transfer(&self, target: Id, req: &TransferRequest) -> Result<TransferResult> {
        self.post(
            &format!("/api/v1/vaults/{target}/transfer"),
            &serde_json::to_value(req).map_err(|e| ClientError::Invalid(e.to_string()))?,
        )
        .await
    }

    /// Just-in-time credentials of a host of a Use-only vault (`purpose`:
    /// `ssh`, `sftp` or `forward`). The response is never cached and is
    /// parsed from a buffer that is wiped afterwards.
    pub async fn credentials(&self, host_id: Id, purpose: &str) -> Result<Credentials> {
        let path = format!("/api/v1/hosts/{host_id}/credentials");
        let body = json!({"purpose": purpose});
        let send = |token: String| {
            self.http
                .post(self.url(&path))
                .bearer_auth(token)
                .json(&body)
                .send()
        };
        let mut resp = send(self.ensure_fresh().await?).await?;
        if resp.status().as_u16() == 401 {
            if let Some(t) = self.tokens.lock().as_mut() {
                t.access_expires_at = 0;
            }
            resp = send(self.refresh().await?).await?;
        }
        if !resp.status().is_success() {
            return Err(Self::error_of(resp).await);
        }
        let bytes = zeroize::Zeroizing::new(resp.bytes().await?.to_vec());
        serde_json::from_slice(&bytes)
            .map_err(|_| ClientError::Invalid("invalid credentials response".into()))
    }

    /// The signed-in user (`GET /api/v1/me`).
    pub async fn me(&self) -> Result<User> {
        #[derive(Deserialize)]
        struct Me {
            user: User,
        }
        Ok(self.get::<Me>("/api/v1/me").await?.user)
    }

    /// Saves the account's preferred language (`en`, `es`...; see
    /// [`locales`](Self::locales)); the server uses it for emails and
    /// notifications. Returns the updated user. The server rejects languages
    /// it does not have.
    pub async fn set_locale(&self, locale: &str) -> Result<User> {
        self.patch("/api/v1/me", &json!({"locale": locale.trim()}))
            .await
    }

    /// Languages the server has for emails and notifications (public,
    /// `GET /api/v1/locales`).
    pub async fn locales(&self) -> Result<ServerLocales> {
        Self::parse(self.http.get(self.url("/api/v1/locales")).send().await?).await
    }

    /// Your own AI API keys (without the keys).
    pub async fn ai_keys(&self) -> Result<Vec<AiKeyInfo>> {
        self.get("/api/v1/me/ai/keys").await
    }

    /// Saves your own API key for a provider (replacing the one you had).
    /// With `key` `None`, only the model of the saved key changes (not found
    /// if there is none). `model` empty or `None` = the provider's default.
    pub async fn set_ai_key(
        &self,
        provider: &str,
        key: Option<&str>,
        model: Option<&str>,
    ) -> Result<AiKeyInfo> {
        let provider = provider_segment(provider)?;
        let model = model.map(str::trim).filter(|m| !m.is_empty());
        let mut body = json!({"model": model});
        if let Some(key) = key {
            body["key"] = json!(key.trim());
        }
        self.put(&format!("/api/v1/me/ai/keys/{provider}"), &body)
            .await
    }

    /// Deletes your own API key for a provider. `false` if there was none.
    pub async fn delete_ai_key(&self, provider: &str) -> Result<bool> {
        let provider = provider_segment(provider)?;
        let v = self
            .delete(&format!("/api/v1/me/ai/keys/{provider}"))
            .await?;
        Ok(v["deleted"].as_bool().unwrap_or(true))
    }

    /// Checks a key with its provider (a call that spends nothing): `key`, or
    /// the saved one if `None`.
    pub async fn test_ai_key(&self, provider: &str, key: Option<&str>) -> Result<AiKeyTest> {
        let provider = provider_segment(provider)?;
        let key = key.map(str::trim).filter(|k| !k.is_empty());
        self.post(
            &format!("/api/v1/me/ai/keys/{provider}/test"),
            &json!({"key": key}),
        )
        .await
    }

    /// Your AI situation: own keys, server AI, credit and this month's spending.
    pub async fn ai_access(&self) -> Result<AiAccess> {
        self.get("/api/v1/me/ai/access").await
    }

    /// Opens an authenticated WebSocket on `path` (e.g. `/api/v1/sessions/{id}/ws`).
    pub async fn websocket(&self, path: &str) -> Result<WsStream> {
        let token = self.ensure_fresh().await.ok();
        let ws_base = if let Some(rest) = self.base.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = self.base.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            self.base.clone()
        };
        let mut req = format!("{ws_base}{path}").into_client_request()?;
        if let Some(t) = token {
            req.headers_mut().insert(
                "authorization",
                format!("Bearer {t}")
                    .parse()
                    .map_err(|_| ClientError::Invalid("invalid token".into()))?,
            );
        }
        // No Nagle: every keystroke goes out at once (otherwise it may wait up to 40 ms).
        let (ws, _) = tokio_tungstenite::connect_async_with_config(req, None, true).await?;
        Ok(ws)
    }
}

/// This device's platform (for the device registry).
pub fn platform() -> String {
    let os = std::env::consts::OS;
    match os {
        "linux" | "windows" | "macos" => format!("desktop-{os}"),
        other => other.to_string(),
    }
}

/// The computer's name (for the device registry).
pub fn device_name() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "computer".into())
}

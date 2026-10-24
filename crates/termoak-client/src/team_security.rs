//! Teams security on the client (0.7 phase 4b, docs-next/TEAMS-SECURITY.md
//! §4.8, §5.4, §6.2): team certificates for local connections, the host
//! access check before connecting, and the upload of mandatory recordings.
//!
//! Certificates and ephemeral keys live in memory only.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::{Value, json};
use termoak_core::access::{HostAccess, VaultPolicy};
use termoak_core::error::codes;
use termoak_core::resolve::{ResolvedHost, ResolvedKey};
use termoak_core::time::now_ms;
use termoak_core::{CoreError, Id};
use termoak_ssh::ca;
use zeroize::Zeroizing;

use crate::accounts::Account;
use crate::error::{ClientError, Result};

/// A cached certificate is reused while it has more than this left (ms).
const CERT_MARGIN_MS: i64 = 60_000;
/// The ephemeral key of an account is replaced after this long (ms).
const EPHEMERAL_MAX_AGE_MS: i64 = 30 * 60_000;
/// A host access answer is reused for this long (ms).
const ACCESS_TTL_MS: i64 = 30_000;

/// In-memory state of an account (certificates, ephemeral key, host access
/// answers).
#[derive(Default)]
pub struct SecurityCache {
    /// `(host, key fingerprint)` → `(certificate, valid_before ms)`.
    certs: Mutex<HashMap<(Id, String), (String, i64)>>,
    /// `(private key, public key line, created ms)`.
    ephemeral: Mutex<Option<(Zeroizing<String>, String, i64)>>,
    access: Mutex<HashMap<Id, (HostAccess, i64)>>,
}

impl SecurityCache {
    /// Forgets everything (sign-out, access changes).
    pub fn clear(&self) {
        self.certs.lock().clear();
        *self.ephemeral.lock() = None;
        self.access.lock().clear();
    }
}

/// `POST /api/v1/certificates` answer (the part the client needs).
#[derive(Debug, Clone, Deserialize)]
pub struct IssuedCert {
    pub certificate: String,
    pub serial: i64,
    #[serde(default)]
    pub key_id: String,
    #[serde(default)]
    pub principals: Vec<String>,
    pub valid_before: i64,
    #[serde(default)]
    pub valid_after: i64,
    #[serde(default)]
    pub request_id: Option<Id>,
    #[serde(default)]
    pub record_required: bool,
}

/// Which key to certify.
pub enum CertKey<'a> {
    /// A key of the account's vaults (by id; no proof needed).
    VaultKey(Id),
    /// Any key we hold: public key + a proof made with the private key.
    Private {
        private_key: &'a str,
        passphrase: Option<&'a str>,
    },
}

impl Account {
    /// The server has the teams security features (`/info`).
    pub fn teams_security_supported(&self) -> bool {
        self.info().features["teams_security"].is_object()
    }

    /// The effective team policy of a vault of this account (from the last
    /// sync; `None`: no policy, or an older server).
    pub async fn vault_policy(&self, vault: Option<Id>) -> Result<Option<VaultPolicy>> {
        match vault {
            Some(v) => Ok(self.store.local_vault_policy(v).await?),
            None => Ok(None),
        }
    }

    /// Whether this account may see the secrets of a vault (its role and
    /// the team's "forbid reveal" policy).
    pub async fn can_reveal(&self, vault: Option<Id>) -> Result<bool> {
        let role = self.role(vault).await?;
        if !role.can_read_secrets() {
            return Ok(false);
        }
        if role == termoak_core::model::VaultRole::Manager {
            return Ok(true);
        }
        Ok(self
            .vault_policy(vault)
            .await?
            .is_none_or(|p| p.reveal_allowed))
    }

    /// What the server says about one host (`GET /hosts/{id}/access`),
    /// cached for a few seconds unless `fresh`.
    pub async fn host_access(&self, host_id: Id, fresh: bool) -> Result<HostAccess> {
        if !fresh
            && let Some((a, at)) = self.security.access.lock().get(&host_id)
            && now_ms() - at < ACCESS_TTL_MS
        {
            return Ok(a.clone());
        }
        let a: HostAccess = self
            .api
            .get(&format!("/api/v1/hosts/{host_id}/access"))
            .await?;
        self.security
            .access
            .lock()
            .insert(host_id, (a.clone(), now_ms()));
        Ok(a)
    }

    /// Forgets the cached access answers and certificates (after an access
    /// request changes, or a vault's access).
    pub fn forget_access(&self) {
        self.security.access.lock().clear();
        self.security.certs.lock().clear();
    }

    /// Before a local connection to a host of `vault`: when the vault has
    /// access policies, the server must allow it now
    /// (`access_approval_required`, detail with the host and the policy) and
    /// be reachable (`access_needs_server`). Returns the answer, if asked.
    pub async fn check_host_access(
        &self,
        host_id: Id,
        vault: Option<Id>,
    ) -> Result<Option<HostAccess>> {
        let Some(policy) = self.vault_policy(vault).await? else {
            return Ok(None);
        };
        if !policy.access_policies && !policy.record_sessions {
            return Ok(None);
        }
        let needs_server = || -> ClientError {
            CoreError::vault(
                codes::ACCESS_NEEDS_SERVER,
                "this host has access rules: connect to its server first",
            )
            .into()
        };
        if !self.is_signed_in() {
            return Err(needs_server());
        }
        // Always asked fresh: a window may have opened or been revoked.
        let access = match self.host_access(host_id, true).await {
            Ok(a) => a,
            Err(ClientError::Network(_)) => return Err(needs_server()),
            Err(e) => return Err(e),
        };
        if !access.allowed {
            // Certificates obtained under a window that is gone are not
            // reused.
            self.security.certs.lock().retain(|(h, _), _| *h != host_id);
            return Err(approval_required(&access));
        }
        Ok(Some(access))
    }

    /// Whether a local terminal to this host must be recorded and uploaded
    /// (team or access policy).
    pub async fn must_record(&self, host_id: Id, vault: Option<Id>) -> bool {
        let Ok(Some(policy)) = self.vault_policy(vault).await else {
            return false;
        };
        if policy.record_sessions {
            return true;
        }
        if !policy.access_policies {
            return false;
        }
        self.host_access(host_id, false)
            .await
            .is_ok_and(|a| a.record_required)
    }

    /// Asks the server for a certificate for a key, for a connection to
    /// `host_id`.
    pub async fn request_certificate(
        &self,
        host_id: Id,
        key: CertKey<'_>,
        ttl_minutes: Option<u32>,
    ) -> Result<IssuedCert> {
        let mut body = json!({"host_id": host_id});
        if let Some(t) = ttl_minutes {
            body["ttl_minutes"] = json!(t);
        }
        match key {
            CertKey::VaultKey(id) => body["key_id"] = json!(id),
            CertKey::Private {
                private_key,
                passphrase,
            } => {
                let public = ca::public_key_of_private(private_key)?;
                let text = ca::public_key_text(&public)?;
                let info = self.info();
                let user = info.user_id.ok_or(ClientError::NotLoggedIn)?.to_string();
                let instance = info.instance_id.clone().unwrap_or_default();
                let ts = now_ms();
                let msg = ca::proof_message(&instance, &user, &text, ts);
                let proof = ca::sign_proof(private_key, passphrase, &msg)?;
                body["public_key"] = json!(text);
                body["proof"] = json!(proof);
                body["timestamp"] = json!(ts);
            }
        }
        self.api.post("/api/v1/certificates", &body).await
    }

    /// The ephemeral key of this account (made once, renewed every 30
    /// minutes; memory only).
    fn ephemeral_key(&self) -> Result<(Zeroizing<String>, String)> {
        let mut slot = self.security.ephemeral.lock();
        if let Some((k, p, at)) = slot.as_ref()
            && now_ms() - at < EPHEMERAL_MAX_AGE_MS
        {
            return Ok((k.clone(), p.clone()));
        }
        let (k, p) = ca::ephemeral_key("termoak-ephemeral")?;
        *slot = Some((k.clone(), p.clone(), now_ms()));
        Ok((k, p))
    }

    fn cached_cert(&self, host: Id, fingerprint: &str) -> Option<String> {
        let certs = self.security.certs.lock();
        let (c, until) = certs.get(&(host, fingerprint.to_string()))?;
        (*until - now_ms() > CERT_MARGIN_MS).then(|| c.clone())
    }

    fn remember_cert(&self, host: Id, fingerprint: String, cert: &IssuedCert) {
        self.security.certs.lock().insert(
            (host, fingerprint),
            (cert.certificate.clone(), cert.valid_before),
        );
    }

    /// For every hop (the jumps and the host) set to `team_certificate`:
    /// a certificate for its key (vault key, or a device key with a proof)
    /// or, without a usable key, for the account's ephemeral key, which
    /// becomes the hop's key. `vault_keys`: the ids of keys that live in this
    /// account's vaults. Does nothing on servers without the feature.
    pub async fn apply_team_certificates(
        &self,
        resolved: &mut ResolvedHost,
        vault_keys: &(dyn Fn(Id) -> bool + Sync),
    ) -> Result<()> {
        if !self.teams_security_supported() {
            return Ok(());
        }
        for hop in resolved.jumps.iter_mut() {
            self.certify_hop(hop, vault_keys).await?;
        }
        self.certify_hop(resolved, vault_keys).await
    }

    async fn certify_hop(
        &self,
        hop: &mut ResolvedHost,
        vault_keys: &(dyn Fn(Id) -> bool + Sync),
    ) -> Result<()> {
        if !hop
            .settings
            .auth
            .as_ref()
            .is_some_and(|a| a.is_team_certificate())
        {
            return Ok(());
        }
        let host_id = hop.host.id;
        // A just-in-time key that came with a team certificate.
        if let Some(k) = &hop.key
            && let Some(c) = &k.certificate
            && let Ok(d) = ca::parse_certificate(c)
            && d.key_id.starts_with("termoak:")
            && (d.valid_before as i64) * 1000 - now_ms() > CERT_MARGIN_MS
        {
            return Ok(());
        }
        // The hop's own key, if we can use it.
        if let Some(key) = hop.key.as_mut()
            && let Ok(public) = ca::public_key_of_private(&key.private_key)
        {
            let fp = ca::fingerprint(&public);
            if let Some(c) = self.cached_cert(host_id, &fp) {
                key.certificate = Some(c);
                return Ok(());
            }
            let encrypted = termoak_ssh::keys::is_encrypted(&key.private_key);
            let sk = termoak_ssh::sk::is_security_key(&key.private_key);
            let in_vault = !key.id.is_nil() && vault_keys(key.id);
            let issued = if in_vault {
                self.request_certificate(host_id, CertKey::VaultKey(key.id), None)
                    .await
            } else if !sk && (!encrypted || key.passphrase.is_some()) {
                self.request_certificate(
                    host_id,
                    CertKey::Private {
                        private_key: &key.private_key,
                        passphrase: key.passphrase.as_deref(),
                    },
                    None,
                )
                .await
            } else {
                Err(ClientError::Invalid("no usable key".into()))
            };
            match issued {
                Ok(c) => {
                    self.remember_cert(host_id, fp, &c);
                    key.certificate = Some(c.certificate);
                    return Ok(());
                }
                // Rules of the team: say so.
                Err(e @ ClientError::Api { .. }) if is_policy_error(&e) => return Err(e),
                // Anything else (a key the server does not take...): the
                // ephemeral key below.
                Err(e) => {
                    tracing::info!(error = %e, "team certificate for the host key failed: using an ephemeral key");
                }
            }
        }
        let (private, public) = self.ephemeral_key()?;
        let fp = ca::fingerprint(&ca::parse_public_key(&public)?);
        let cert = match self.cached_cert(host_id, &fp) {
            Some(c) => c,
            None => {
                let c = self
                    .request_certificate(
                        host_id,
                        CertKey::Private {
                            private_key: &private,
                            passphrase: None,
                        },
                        None,
                    )
                    .await?;
                self.remember_cert(host_id, fp, &c);
                c.certificate
            }
        };
        hop.key = Some(ResolvedKey {
            id: Id::nil(),
            label: "team certificate".into(),
            private_key: private.to_string(),
            passphrase: None,
            certificate: Some(cert),
            security_key: None,
        });
        Ok(())
    }

    /// Uploads a recording (asciicast) of a local session on a host of this
    /// account (`POST /api/v1/recordings`). Returns the new session id.
    pub async fn upload_recording(
        &self,
        host_id: Id,
        path: &std::path::Path,
        started_at: i64,
        title: &str,
    ) -> Result<Id> {
        let body = tokio::fs::read(path).await?;
        let v: Value = self
            .api
            .post_bytes(
                &format!(
                    "/api/v1/recordings?host_id={host_id}&started_at={started_at}&title={}",
                    urlencode(title)
                ),
                body,
                "application/x-asciicast",
            )
            .await?;
        v["id"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| {
                ClientError::Invalid("the server did not return the recording id".into())
            })
    }
}

/// Codes that mean "the team's rules say no" (shown as they are).
fn is_policy_error(e: &ClientError) -> bool {
    matches!(e, ClientError::Api { code, .. } if [
        codes::ACCESS_APPROVAL_REQUIRED,
        codes::TEAM_2FA_REQUIRED,
        codes::RECORDING_REQUIRED,
        codes::CA_NOT_CONFIGURED,
        codes::CONNECT_ONLY,
    ]
    .contains(&code.as_str()))
}

/// `access_approval_required` for a host the server does not allow now.
pub fn approval_required(access: &HostAccess) -> ClientError {
    CoreError::vault_detail(
        codes::ACCESS_APPROVAL_REQUIRED,
        "this host needs an approved access window: request access",
        json!({
            "host_id": access.host_id,
            "vault_id": access.vault_id,
            "policy_id": access.policy.as_ref().map(|p| p.id),
            "target_kind": access.policy.as_ref().map(|p| p.target_kind),
            "target_id": access.policy.as_ref().map(|p| p.target_id),
            "max_minutes": access.max_minutes,
            "pending": access.pending.as_ref().map(|p| p.id),
            "can_request": access.can_request,
        }),
    )
    .into()
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes().take(200) {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Watches a recorded terminal and uploads its recording when it closes.
pub fn upload_when_closed(
    account: Arc<Account>,
    host_id: Id,
    term: Arc<termoak_ssh::TerminalSession>,
    title: String,
) {
    let Some(path) = term.recording_path() else {
        return;
    };
    let started_at = now_ms();
    let mut status = term.watch_status();
    tokio::spawn(async move {
        while !status.borrow().is_closed() {
            if status.changed().await.is_err() {
                break;
            }
        }
        // Let the recorder flush its last lines.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if let Err(e) = account
            .upload_recording(host_id, &path, started_at, &title)
            .await
        {
            tracing::warn!(error = %e, "could not upload the recording of a local session");
        }
    });
}

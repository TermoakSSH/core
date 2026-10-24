//! FIDO2 security keys (docs/SSH-PRO.md §4): the app talks to the device
//! (USB, NFC, Lightning) through its platform library and implements
//! [`SecurityKeyHandler`]; the engine builds the SSH side.

use std::sync::Arc;

use async_trait::async_trait;
use termoak_core::model as cm;
use termoak_ssh::sk::{self, SkError, SkErrorCode};

use crate::error::{Result, TermoakError};
use crate::models::{SshKey, SyncMode};
use crate::runtime::run;
use crate::vault::{TermoakCore, save_key_material};

/// Security key algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SecurityKeyAlgorithm {
    /// `sk-ssh-ed25519@openssh.com` (COSE EdDSA, -8).
    Ed25519,
    /// `sk-ecdsa-sha2-nistp256@openssh.com` (COSE ES256, -7).
    EcdsaP256,
}

impl From<SecurityKeyAlgorithm> for sk::SkAlgorithm {
    fn from(a: SecurityKeyAlgorithm) -> Self {
        match a {
            SecurityKeyAlgorithm::Ed25519 => sk::SkAlgorithm::Ed25519,
            SecurityKeyAlgorithm::EcdsaP256 => sk::SkAlgorithm::EcdsaP256,
        }
    }
}

impl From<sk::SkAlgorithm> for SecurityKeyAlgorithm {
    fn from(a: sk::SkAlgorithm) -> Self {
        match a {
            sk::SkAlgorithm::Ed25519 => SecurityKeyAlgorithm::Ed25519,
            sk::SkAlgorithm::EcdsaP256 => SecurityKeyAlgorithm::EcdsaP256,
        }
    }
}

/// Details of a security key (`SshKey.security_key`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SecurityKeyInfo {
    /// FIDO relying party id (`ssh:` by default).
    pub application: String,
    /// User of a resident credential.
    #[uniffi(default)]
    pub user: Option<String>,
    /// Signing needs a touch (off: `no-touch-required`).
    #[uniffi(default = true)]
    pub touch_required: bool,
    /// Signing needs the PIN or biometrics (`verify-required`).
    #[uniffi(default)]
    pub verify_required: bool,
    /// Resident (discoverable) credential.
    #[uniffi(default)]
    pub resident: bool,
    /// Which device it lives on (a label).
    #[uniffi(default)]
    pub device: Option<String>,
}

impl From<cm::SecurityKeyInfo> for SecurityKeyInfo {
    fn from(i: cm::SecurityKeyInfo) -> Self {
        Self {
            application: i.application,
            user: i.user,
            touch_required: i.touch_required,
            verify_required: i.verify_required,
            resident: i.resident,
            device: i.device,
        }
    }
}

impl From<SecurityKeyInfo> for cm::SecurityKeyInfo {
    fn from(i: SecurityKeyInfo) -> Self {
        Self {
            application: i.application,
            user: i.user,
            touch_required: i.touch_required,
            verify_required: i.verify_required,
            resident: i.resident,
            device: i.device,
        }
    }
}

/// What the device must sign (CTAP2 get assertion with `rp_id =
/// application`, the allow list `[key_handle]` and `client_data_hash`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SecurityKeySignRequest {
    pub algorithm: SecurityKeyAlgorithm,
    pub application: String,
    pub key_handle: Vec<u8>,
    /// SHA-256 of `message` (what CTAP2 and YubiKit take).
    pub client_data_hash: Vec<u8>,
    /// The data to sign (for libraries that hash it themselves).
    pub message: Vec<u8>,
    /// CTAP2 option `up` (false: a `no-touch-required` key).
    pub require_presence: bool,
    /// CTAP2 option `uv` (PIN or biometrics).
    pub require_verification: bool,
    /// OpenSSH public key and fingerprint (to show or match).
    pub public_key: String,
    pub fingerprint: String,
    /// What to show: the host's label and address, the user, the key.
    pub host: String,
    pub address: String,
    pub username: String,
    pub key_label: String,
    pub key_id: Option<String>,
    pub device: Option<String>,
    /// `connect` (this device); forwarded by the server: `server_session`,
    /// `test` (host test), `server` (`/exec`, SFTP, AI).
    pub purpose: String,
    pub session_id: Option<String>,
}

impl From<sk::SkSignRequest> for SecurityKeySignRequest {
    fn from(r: sk::SkSignRequest) -> Self {
        Self {
            algorithm: r.algorithm.into(),
            application: r.application,
            key_handle: r.key_handle,
            client_data_hash: r.client_data_hash.to_vec(),
            message: r.message,
            require_presence: r.require_presence,
            require_verification: r.require_verification,
            public_key: r.public_key,
            fingerprint: r.fingerprint,
            host: r.context.host,
            address: r.context.address,
            username: r.context.username,
            key_label: r.context.key_label,
            key_id: r.context.key_id,
            device: r.context.device,
            purpose: r.context.purpose,
            session_id: r.context.session_id,
        }
    }
}

/// The device's assertion.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SecurityKeyAssertion {
    /// Authenticator data flags (0x01 user present, 0x04 verified).
    /// Ignored when `authenticator_data` is given.
    #[uniffi(default)]
    pub flags: u8,
    /// Signature counter. Ignored when `authenticator_data` is given.
    #[uniffi(default)]
    pub counter: u32,
    /// Ed25519: 64 bytes. ECDSA: DER (as CTAP2 returns it) or 64 bytes `r || s`.
    pub signature: Vec<u8>,
    /// The assertion's authenticator data, if the library gives it (flags
    /// and counter are read from it).
    #[uniffi(default)]
    pub authenticator_data: Option<Vec<u8>>,
}

/// What the device must create (CTAP2 make credential with `rp.id =
/// application`, `user`, `pubKeyCredParams = [algorithm]`, options `rk`
/// and `uv`, and `client_data_hash`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SecurityKeyCredentialRequest {
    pub algorithm: SecurityKeyAlgorithm,
    /// COSE algorithm (-8 EdDSA, -7 ES256).
    pub cose_algorithm: i64,
    pub application: String,
    pub user_id: Vec<u8>,
    pub user_name: String,
    pub client_data_hash: Vec<u8>,
    pub resident: bool,
    pub require_verification: bool,
    /// The flags the key will have (0x01 touch, 0x04 verify, 0x20 resident).
    pub flags: u8,
    pub device: Option<String>,
}

impl From<sk::SkMakeCredentialRequest> for SecurityKeyCredentialRequest {
    fn from(r: sk::SkMakeCredentialRequest) -> Self {
        Self {
            algorithm: r.algorithm.into(),
            cose_algorithm: r.algorithm.cose(),
            application: r.application,
            user_id: r.user_id,
            user_name: r.user_name,
            client_data_hash: r.client_data_hash.to_vec(),
            resident: r.resident,
            require_verification: r.require_verification,
            flags: r.flags,
            device: r.device,
        }
    }
}

impl TryFrom<SecurityKeyCredentialRequest> for sk::SkMakeCredentialRequest {
    type Error = TermoakError;
    fn try_from(r: SecurityKeyCredentialRequest) -> Result<Self> {
        Ok(Self {
            algorithm: r.algorithm.into(),
            application: r.application,
            user_id: r.user_id,
            user_name: r.user_name,
            client_data_hash: r
                .client_data_hash
                .try_into()
                .map_err(|_| TermoakError::Invalid("client_data_hash has 32 bytes".into()))?,
            resident: r.resident,
            require_verification: r.require_verification,
            flags: r.flags,
            device: r.device,
        })
    }
}

/// The device's new credential.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SecurityKeyCredential {
    /// The authenticator data (with the attested credential data).
    #[uniffi(default)]
    pub authenticator_data: Vec<u8>,
    /// Or the whole attestation object (CBOR), if that is what the library gives.
    #[uniffi(default)]
    pub attestation_object: Vec<u8>,
}

/// Which resident credentials to read (credential management, needs the PIN).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SecurityKeyResidentRequest {
    /// Relying parties starting with this (`ssh:`).
    pub application_prefix: String,
}

/// A resident credential on the device.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SecurityKeyResident {
    pub application: String,
    pub credential_id: Vec<u8>,
    /// COSE public key (CBOR map) from credential management.
    pub public_key_cose: Vec<u8>,
    #[uniffi(default)]
    pub user_id: Vec<u8>,
    #[uniffi(default)]
    pub user_name: Option<String>,
}

/// Options of a new security key.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SecurityKeyOptions {
    pub algorithm: SecurityKeyAlgorithm,
    /// Default `ssh:` (must start with `ssh:`).
    #[uniffi(default)]
    pub application: Option<String>,
    /// User of a resident credential (default `openssh`).
    #[uniffi(default)]
    pub user: Option<String>,
    #[uniffi(default)]
    pub resident: bool,
    #[uniffi(default)]
    pub verify_required: bool,
    #[uniffi(default)]
    pub no_touch_required: bool,
    /// Device label (`SecurityKeyInfo.device`).
    #[uniffi(default)]
    pub device: Option<String>,
}

impl From<SecurityKeyOptions> for sk::SkKeyOptions {
    fn from(o: SecurityKeyOptions) -> Self {
        Self {
            algorithm: o.algorithm.into(),
            application: o.application,
            user: o.user,
            resident: o.resident,
            verify_required: o.verify_required,
            no_touch_required: o.no_touch_required,
            device: o.device,
        }
    }
}

/// Errors the app's [`SecurityKeyHandler`] throws. The text is `reason`
/// (`message` would clash with the exceptions' own `message` in Kotlin).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum SecurityKeyError {
    /// No security key is connected or in range.
    #[error("{reason}")]
    NoDevice { reason: String },
    #[error("{reason}")]
    Timeout { reason: String },
    /// The user cancelled.
    #[error("{reason}")]
    Cancelled { reason: String },
    /// The device does not have this credential (CTAP2_ERR_NO_CREDENTIALS).
    #[error("{reason}")]
    NotFound { reason: String },
    /// The key needs its PIN and none was entered.
    #[error("{reason}")]
    PinRequired { reason: String },
    /// Wrong or blocked PIN.
    #[error("{reason}")]
    PinInvalid { reason: String },
    /// The device or platform cannot do this.
    #[error("{reason}")]
    Unsupported { reason: String },
    #[error("{reason}")]
    Failed { reason: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for SecurityKeyError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        SecurityKeyError::Failed { reason: e.reason }
    }
}

impl From<SecurityKeyError> for SkError {
    fn from(e: SecurityKeyError) -> Self {
        let (code, message) = match e {
            SecurityKeyError::NoDevice { reason } => (SkErrorCode::NoDevice, reason),
            SecurityKeyError::Timeout { reason } => (SkErrorCode::Timeout, reason),
            SecurityKeyError::Cancelled { reason } => (SkErrorCode::Cancelled, reason),
            SecurityKeyError::NotFound { reason } => (SkErrorCode::NotFound, reason),
            SecurityKeyError::PinRequired { reason } => (SkErrorCode::PinRequired, reason),
            SecurityKeyError::PinInvalid { reason } => (SkErrorCode::PinInvalid, reason),
            SecurityKeyError::Unsupported { reason } => (SkErrorCode::Unsupported, reason),
            SecurityKeyError::Failed { reason } => (SkErrorCode::Failed, reason),
        };
        if message.trim().is_empty() {
            SkError::of(code)
        } else {
            SkError::new(code, message)
        }
    }
}

/// Implemented by the app to use security keys (YubiKit on Android and iOS,
/// a CTAP2 library on the desktop).
///
/// **Threads**: called from a background thread and it **may block** while
/// the app shows "Touch your security key" (or "Hold it near the phone")
/// and waits for the device; never from the main thread. Throw
/// `Cancelled` when the user cancels.
#[uniffi::export(foreign)]
pub trait SecurityKeyHandler: Send + Sync {
    /// Signs (CTAP2 get assertion). Show the request's host, user, key and
    /// purpose: a request forwarded by the server (`purpose` other than
    /// `connect`) comes from a connection the server makes for you.
    fn sign(
        &self,
        request: SecurityKeySignRequest,
    ) -> std::result::Result<SecurityKeyAssertion, SecurityKeyError>;

    /// Creates a credential (CTAP2 make credential).
    fn make_credential(
        &self,
        request: SecurityKeyCredentialRequest,
    ) -> std::result::Result<SecurityKeyCredential, SecurityKeyError>;

    /// Reads the resident credentials (CTAP 2.1 credential management;
    /// asks for the PIN). Throw `Unsupported` if the platform cannot.
    fn list_resident(
        &self,
        request: SecurityKeyResidentRequest,
    ) -> std::result::Result<Vec<SecurityKeyResident>, SecurityKeyError>;
}

/// The app's handler as the engine's signer.
pub(crate) struct FfiSkSigner(pub(crate) Arc<dyn SecurityKeyHandler>);

#[async_trait]
impl sk::SecurityKeySigner for FfiSkSigner {
    async fn sign(
        &self,
        request: sk::SkSignRequest,
    ) -> std::result::Result<sk::SkAssertion, SkError> {
        let handler = self.0.clone();
        let req = SecurityKeySignRequest::from(request);
        let a = tokio::task::spawn_blocking(move || handler.sign(req))
            .await
            .map_err(|e| SkError::new(SkErrorCode::Failed, e.to_string()))?
            .map_err(SkError::from)?;
        match a.authenticator_data {
            Some(data) if !data.is_empty() => {
                sk::SkAssertion::from_authenticator_data(&data, a.signature)
            }
            _ => Ok(sk::SkAssertion {
                flags: a.flags,
                counter: a.counter,
                signature: a.signature,
            }),
        }
    }
}

fn sk_err(e: SkError) -> TermoakError {
    termoak_ssh::SshError::from(e).into()
}

/// The make credential request of `options` (to drive the device yourself;
/// `TermoakCore.create_security_key` does it all).
#[uniffi::export]
pub fn security_key_request(options: SecurityKeyOptions) -> Result<SecurityKeyCredentialRequest> {
    Ok(sk::make_credential_request(&options.into())
        .map_err(sk_err)?
        .into())
}

/// A new security key from the device's answer, without saving it: its
/// public part and the OpenSSH sk "private key" file (key handle, not a
/// secret key) to import with `import_key`.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct SecurityKeyMaterial {
    pub details: crate::models::KeyDetails,
    pub private_key: String,
}

#[uniffi::export]
pub fn security_key_from_credential(
    request: SecurityKeyCredentialRequest,
    credential: SecurityKeyCredential,
    comment: String,
) -> Result<SecurityKeyMaterial> {
    let req: sk::SkMakeCredentialRequest = request.try_into()?;
    let m = sk::key_from_credential(
        &req,
        &sk::SkCredential {
            authenticator_data: credential.authenticator_data,
            attestation_object: credential.attestation_object,
        },
        &comment,
    )
    .map_err(sk_err)?;
    Ok(SecurityKeyMaterial {
        details: (&m).into(),
        private_key: m.private_openssh,
    })
}

/// The `authorized_keys` line of a key, with `no-touch-required` /
/// `verify-required` when its flags need them.
#[uniffi::export]
pub fn security_key_authorized_keys_line(
    public_key: String,
    info: Option<SecurityKeyInfo>,
) -> String {
    sk::authorized_keys_line(&public_key, info.map(cm::SecurityKeyInfo::from).as_ref())
}

#[uniffi::export]
impl TermoakCore {
    /// Sets (or clears, with `nil`) the app's security key handler: local
    /// connections with sk keys use it, and while it is set the events
    /// socket (`subscribe_events`, opened after this call) answers the
    /// server's signature requests for server sessions.
    pub fn set_security_key_handler(&self, handler: Option<Arc<dyn SecurityKeyHandler>>) {
        self.ws.set_security_key_signer(
            handler.map(|h| Arc::new(FfiSkSigner(h)) as Arc<dyn sk::SecurityKeySigner>),
        );
    }

    /// Whether a security key handler is set.
    pub fn has_security_key_handler(&self) -> bool {
        self.ws.security_key_signer().is_some()
    }

    /// Creates a key on the security key (the handler's `make_credential`)
    /// and saves it (see `generate_key` for `account_id` and `vault_id`).
    #[uniffi::method(default(account_id = None, vault_id = None))]
    #[allow(clippy::too_many_arguments)]
    pub async fn create_security_key(
        &self,
        label: String,
        options: SecurityKeyOptions,
        comment: String,
        sync_mode: Option<SyncMode>,
        account_id: Option<String>,
        vault_id: Option<String>,
        handler: Arc<dyn SecurityKeyHandler>,
    ) -> Result<SshKey> {
        let target = self.target_of("", &account_id, &vault_id)?;
        let ws = self.ws.clone();
        run(async move {
            let req = sk::make_credential_request(&options.into()).map_err(sk_err)?;
            let ffi_req = SecurityKeyCredentialRequest::from(req.clone());
            let cred = tokio::task::spawn_blocking(move || handler.make_credential(ffi_req))
                .await
                .map_err(|e| TermoakError::Internal(e.to_string()))?
                .map_err(|e| sk_err(e.into()))?;
            let material = sk::key_from_credential(
                &req,
                &sk::SkCredential {
                    authenticator_data: cred.authenticator_data,
                    attestation_object: cred.attestation_object,
                },
                &comment,
            )
            .map_err(sk_err)?;
            save_key_material(&ws, target, label, material, None, false, sync_mode).await
        })
        .await
    }

    /// Loads the resident keys of the security key (the handler's
    /// `list_resident`) and saves those whose fingerprint is not among the
    /// keys yet. `verify_required`: mark them as needing the PIN (the
    /// device does not say). Labels: "<device or Security key> (<user>)".
    #[uniffi::method(default(account_id = None, vault_id = None))]
    #[allow(clippy::too_many_arguments)]
    pub async fn import_resident_security_keys(
        &self,
        application_prefix: Option<String>,
        verify_required: bool,
        device: Option<String>,
        sync_mode: Option<SyncMode>,
        account_id: Option<String>,
        vault_id: Option<String>,
        handler: Arc<dyn SecurityKeyHandler>,
    ) -> Result<Vec<SshKey>> {
        let target = self.target_of("", &account_id, &vault_id)?;
        let existing: Vec<String> = self
            .list_keys(None)?
            .into_iter()
            .map(|k| k.fingerprint)
            .collect();
        let ws = self.ws.clone();
        run(async move {
            let prefix = application_prefix
                .filter(|p| !p.is_empty())
                .unwrap_or_else(|| sk::DEFAULT_APPLICATION.into());
            let list = tokio::task::spawn_blocking(move || {
                handler.list_resident(SecurityKeyResidentRequest {
                    application_prefix: prefix,
                })
            })
            .await
            .map_err(|e| TermoakError::Internal(e.to_string()))?
            .map_err(|e| sk_err(e.into()))?;
            let mut saved = Vec::new();
            let mut seen = existing;
            for c in list {
                let m = sk::key_from_resident(
                    &sk::SkResidentCredential {
                        application: c.application,
                        credential_id: c.credential_id,
                        public_key_cose: c.public_key_cose,
                        user_id: c.user_id,
                        user_name: c.user_name,
                    },
                    verify_required,
                    device.clone(),
                    "",
                )
                .map_err(sk_err)?;
                if seen.contains(&m.fingerprint) {
                    continue;
                }
                seen.push(m.fingerprint.clone());
                let user = m.security_key.as_ref().and_then(|i| i.user.clone());
                let base = device.clone().unwrap_or_else(|| "Security key".into());
                let label = match user {
                    Some(u) => format!("{base} ({u})"),
                    None => base,
                };
                saved.push(save_key_material(&ws, target, label, m, None, false, sync_mode).await?);
            }
            Ok(saved)
        })
        .await
    }
}

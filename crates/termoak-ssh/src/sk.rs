//! FIDO2 security keys (`sk-ssh-ed25519@openssh.com`,
//! `sk-ecdsa-sha2-nistp256@openssh.com`): docs/SSH-PRO.md.
//!
//! The device (YubiKey...) is reached by the app through a
//! [`SecurityKeySigner`]; this module turns its answers into SSH: the
//! signature blob for russh ([`SkAuthSigner`]), new keys from a make
//! credential answer ([`key_from_credential`]) and resident credentials
//! ([`key_from_resident`]).

use std::sync::Arc;

use async_trait::async_trait;
use russh::keys::signature::Verifier;
use russh::keys::ssh_key::private::{self as skp, KeypairData};
use russh::keys::ssh_key::public::{self as skpub, EcdsaPublicKey, Ed25519PublicKey, KeyData};
use russh::keys::ssh_key::{self, Algorithm, HashAlg, LineEnding, PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use termoak_core::model::SecurityKeyInfo;

use crate::error::{Result, SshError};
use crate::keys::KeyMaterial;

#[cfg(feature = "soft-sk")]
pub mod soft;

/// Key flag: user presence (touch) required.
pub const FLAG_USER_PRESENCE: u8 = 0x01;
/// Key flag: user verification (PIN, biometrics) required.
pub const FLAG_USER_VERIFICATION: u8 = 0x04;
/// Key flag: resident (discoverable) credential.
pub const FLAG_RESIDENT: u8 = 0x20;
/// Authenticator data flag: attested credential data included.
const AUTH_DATA_AT: u8 = 0x40;
/// Authenticator data flag: extensions included.
const AUTH_DATA_ED: u8 = 0x80;

/// OpenSSH's default application (FIDO relying party id).
pub const DEFAULT_APPLICATION: &str = "ssh:";
/// OpenSSH's default user of resident credentials.
pub const DEFAULT_USER: &str = "openssh";

/// Security key algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkAlgorithm {
    /// `sk-ssh-ed25519@openssh.com` (COSE EdDSA, -8).
    Ed25519,
    /// `sk-ecdsa-sha2-nistp256@openssh.com` (COSE ES256, -7).
    EcdsaP256,
}

impl SkAlgorithm {
    pub fn ssh_name(self) -> &'static str {
        match self {
            SkAlgorithm::Ed25519 => "sk-ssh-ed25519@openssh.com",
            SkAlgorithm::EcdsaP256 => "sk-ecdsa-sha2-nistp256@openssh.com",
        }
    }

    /// COSE algorithm identifier (for `pubKeyCredParams`).
    pub fn cose(self) -> i64 {
        match self {
            SkAlgorithm::Ed25519 => -8,
            SkAlgorithm::EcdsaP256 => -7,
        }
    }

    fn of(alg: &Algorithm) -> Option<Self> {
        match alg {
            Algorithm::SkEd25519 => Some(SkAlgorithm::Ed25519),
            Algorithm::SkEcdsaSha2NistP256 => Some(SkAlgorithm::EcdsaP256),
            _ => None,
        }
    }

    fn ssh_algorithm(self) -> Algorithm {
        match self {
            SkAlgorithm::Ed25519 => Algorithm::SkEd25519,
            SkAlgorithm::EcdsaP256 => Algorithm::SkEcdsaSha2NistP256,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// What went wrong with a security key (docs/SSH-PRO.md §3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkErrorCode {
    /// Nothing here can ask for the key.
    Required,
    /// No device that can sign is available (online).
    NoDevice,
    Timeout,
    Cancelled,
    /// The device does not have this credential.
    NotFound,
    PinRequired,
    PinInvalid,
    /// The signature does not match the public key.
    WrongKey,
    Unsupported,
    /// Malformed credential, attestation or key file.
    Invalid,
    Failed,
}

impl SkErrorCode {
    /// The stable API code (`security_key_…`).
    pub fn api_code(self) -> &'static str {
        use termoak_core::error::codes::*;
        match self {
            SkErrorCode::Required => SECURITY_KEY_REQUIRED,
            SkErrorCode::NoDevice => SECURITY_KEY_NO_DEVICE,
            SkErrorCode::Timeout => SECURITY_KEY_TIMEOUT,
            SkErrorCode::Cancelled => SECURITY_KEY_CANCELLED,
            SkErrorCode::NotFound => SECURITY_KEY_NOT_FOUND,
            SkErrorCode::PinRequired => SECURITY_KEY_PIN_REQUIRED,
            SkErrorCode::PinInvalid => SECURITY_KEY_PIN_INVALID,
            SkErrorCode::WrongKey => SECURITY_KEY_WRONG_KEY,
            SkErrorCode::Unsupported => SECURITY_KEY_UNSUPPORTED,
            SkErrorCode::Invalid => SECURITY_KEY_INVALID,
            SkErrorCode::Failed => SECURITY_KEY_FAILED,
        }
    }

    /// The short code devices send in forwarding (`cancelled`, `timeout`...).
    pub fn wire(self) -> &'static str {
        match self {
            SkErrorCode::Required => "required",
            SkErrorCode::NoDevice => "no_device",
            SkErrorCode::Timeout => "timeout",
            SkErrorCode::Cancelled => "cancelled",
            SkErrorCode::NotFound => "not_found",
            SkErrorCode::PinRequired => "pin_required",
            SkErrorCode::PinInvalid => "pin_invalid",
            SkErrorCode::WrongKey => "wrong_key",
            SkErrorCode::Unsupported => "unsupported",
            SkErrorCode::Invalid => "invalid",
            SkErrorCode::Failed => "failed",
        }
    }

    /// From [`SkErrorCode::wire`] or [`SkErrorCode::api_code`]; anything
    /// else is `Failed`.
    pub fn parse(s: &str) -> Self {
        let s = s.strip_prefix("security_key_").unwrap_or(s);
        [
            SkErrorCode::Required,
            SkErrorCode::NoDevice,
            SkErrorCode::Timeout,
            SkErrorCode::Cancelled,
            SkErrorCode::NotFound,
            SkErrorCode::PinRequired,
            SkErrorCode::PinInvalid,
            SkErrorCode::WrongKey,
            SkErrorCode::Unsupported,
            SkErrorCode::Invalid,
            SkErrorCode::Failed,
        ]
        .into_iter()
        .find(|c| c.wire() == s)
        .unwrap_or(SkErrorCode::Failed)
    }

    /// How specific an error is when several devices failed (higher wins).
    pub fn rank(self) -> u8 {
        match self {
            SkErrorCode::Cancelled => 9,
            SkErrorCode::WrongKey => 8,
            SkErrorCode::PinInvalid => 7,
            SkErrorCode::PinRequired => 6,
            SkErrorCode::NotFound => 5,
            SkErrorCode::Unsupported => 4,
            SkErrorCode::Invalid => 3,
            SkErrorCode::Failed => 2,
            SkErrorCode::Timeout => 1,
            SkErrorCode::Required | SkErrorCode::NoDevice => 0,
        }
    }

    fn default_message(self) -> &'static str {
        match self {
            SkErrorCode::Required => "this key is a security key and none can be used here",
            SkErrorCode::NoDevice => "no device with a security key is available",
            SkErrorCode::Timeout => "the security key was not touched in time",
            SkErrorCode::Cancelled => "the security key request was cancelled",
            SkErrorCode::NotFound => "the security key does not have this key (another key?)",
            SkErrorCode::PinRequired => "the security key needs its PIN",
            SkErrorCode::PinInvalid => "wrong PIN for the security key",
            SkErrorCode::WrongKey => "the security key's signature does not match this key",
            SkErrorCode::Unsupported => "the security key cannot do this",
            SkErrorCode::Invalid => "invalid security key data",
            SkErrorCode::Failed => "the security key failed",
        }
    }
}

/// A security key error with its message (English).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{message}")]
pub struct SkError {
    pub code: SkErrorCode,
    pub message: String,
}

impl SkError {
    pub fn new(code: SkErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// With the code's default message.
    pub fn of(code: SkErrorCode) -> Self {
        Self::new(code, code.default_message())
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(SkErrorCode::Invalid, message)
    }
}

impl From<SkError> for SshError {
    fn from(e: SkError) -> Self {
        SshError::SecurityKey {
            code: e.code.api_code(),
            message: e.message,
        }
    }
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Why and where a signature is asked for (shown to the user).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkContext {
    /// The host's label.
    pub host: String,
    /// The address connected to.
    #[serde(default)]
    pub address: String,
    pub username: String,
    pub key_label: String,
    /// The vault id of the key (when known).
    #[serde(default)]
    pub key_id: Option<String>,
    /// The device label of the key (`SecurityKeyInfo::device`).
    #[serde(default)]
    pub device: Option<String>,
    /// `connect`, `server_session`, `test`, `exec`, `sftp`, `ai`...
    pub purpose: String,
    /// Server session id, when the request comes from one.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// What the device must sign (CTAP2 `authenticatorGetAssertion`).
#[derive(Clone, PartialEq, Eq)]
pub struct SkSignRequest {
    pub algorithm: SkAlgorithm,
    /// FIDO relying party id.
    pub application: String,
    /// Credential id (the allow list).
    pub key_handle: Vec<u8>,
    /// OpenSSH public key (to find or confirm the key).
    pub public_key: String,
    pub fingerprint: String,
    /// The data to sign (the client data): libraries that hash it themselves
    /// take this.
    pub message: Vec<u8>,
    /// SHA-256 of `message` (CTAP2's clientDataHash).
    pub client_data_hash: [u8; 32],
    /// CTAP2 option `up`.
    pub require_presence: bool,
    /// CTAP2 option `uv`.
    pub require_verification: bool,
    pub context: SkContext,
}

impl std::fmt::Debug for SkSignRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkSignRequest")
            .field("algorithm", &self.algorithm)
            .field("application", &self.application)
            .field("fingerprint", &self.fingerprint)
            .field("require_presence", &self.require_presence)
            .field("require_verification", &self.require_verification)
            .field("context", &self.context)
            .finish_non_exhaustive()
    }
}

/// The device's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkAssertion {
    /// Authenticator data flags (byte 32: 0x01 user present, 0x04 verified).
    pub flags: u8,
    /// Signature counter (bytes 33..37).
    pub counter: u32,
    /// Ed25519: 64 bytes. ECDSA: DER, or 64 bytes `r || s`.
    pub signature: Vec<u8>,
}

impl SkAssertion {
    /// From an assertion's whole authenticator data (flags and counter).
    pub fn from_authenticator_data(auth_data: &[u8], signature: Vec<u8>) -> Result<Self, SkError> {
        if auth_data.len() < 37 {
            return Err(SkError::invalid("the authenticator data is too short"));
        }
        Ok(Self {
            flags: auth_data[32],
            counter: u32::from_be_bytes([
                auth_data[33],
                auth_data[34],
                auth_data[35],
                auth_data[36],
            ]),
            signature,
        })
    }
}

/// Signs with a security key. Implemented by the apps (USB/NFC through
/// the platform's FIDO2 library), by the server (forwarding to the user's
/// devices) and by the test authenticator.
#[async_trait]
pub trait SecurityKeySigner: Send + Sync {
    async fn sign(&self, request: SkSignRequest) -> Result<SkAssertion, SkError>;
}

/// An sk key read from its OpenSSH "private key" file.
#[derive(Clone)]
pub struct SkKey {
    pub algorithm: SkAlgorithm,
    pub public: PublicKey,
    pub application: String,
    pub flags: u8,
    pub key_handle: Vec<u8>,
}

impl std::fmt::Debug for SkKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkKey")
            .field("algorithm", &self.algorithm)
            .field("application", &self.application)
            .field("flags", &self.flags)
            .finish_non_exhaustive()
    }
}

impl SkKey {
    pub fn fingerprint(&self) -> String {
        self.public.fingerprint(HashAlg::Sha256).to_string()
    }

    pub fn public_openssh(&self) -> String {
        crate::keys::public_openssh(&self.public)
    }

    /// Descriptive details (for `SshKey::security_key`).
    pub fn info(&self) -> SecurityKeyInfo {
        SecurityKeyInfo {
            application: self.application.clone(),
            user: None,
            touch_required: self.flags & FLAG_USER_PRESENCE != 0,
            verify_required: self.flags & FLAG_USER_VERIFICATION != 0,
            resident: self.flags & FLAG_RESIDENT != 0,
            device: None,
        }
    }

    /// The request to sign `message`.
    pub fn sign_request(&self, message: Vec<u8>, context: SkContext) -> SkSignRequest {
        let client_data_hash: [u8; 32] = Sha256::digest(&message).into();
        SkSignRequest {
            algorithm: self.algorithm,
            application: self.application.clone(),
            key_handle: self.key_handle.clone(),
            public_key: self.public_openssh(),
            fingerprint: self.fingerprint(),
            message,
            client_data_hash,
            require_presence: self.flags & FLAG_USER_PRESENCE != 0,
            require_verification: self.flags & FLAG_USER_VERIFICATION != 0,
            context,
        }
    }

    /// Checks a device's answer for `message` and returns the SSH signature
    /// blob (`string alg || string sig || byte flags || uint32 counter`).
    pub fn signature_blob(&self, message: &[u8], a: &SkAssertion) -> Result<Vec<u8>, SkError> {
        if self.flags & FLAG_USER_PRESENCE != 0 && a.flags & FLAG_USER_PRESENCE == 0 {
            return Err(SkError::new(
                SkErrorCode::Failed,
                "the security key did not confirm user presence (touch)",
            ));
        }
        if self.flags & FLAG_USER_VERIFICATION != 0 && a.flags & FLAG_USER_VERIFICATION == 0 {
            return Err(SkError::new(
                SkErrorCode::PinRequired,
                "the key requires user verification (PIN) and the security key did not verify the user",
            ));
        }
        let sig = match self.algorithm {
            SkAlgorithm::Ed25519 => {
                if a.signature.len() != 64 {
                    return Err(SkError::invalid("an Ed25519 signature has 64 bytes"));
                }
                a.signature.clone()
            }
            SkAlgorithm::EcdsaP256 => ecdsa_ssh_signature(&a.signature)?,
        };
        let mut data = sig;
        data.push(a.flags);
        data.extend_from_slice(&a.counter.to_be_bytes());
        let signature = ssh_key::Signature::new(self.algorithm.ssh_algorithm(), data)
            .map_err(|e| SkError::invalid(format!("invalid signature: {e}")))?;
        self.public
            .key_data()
            .verify(message, &signature)
            .map_err(|_| SkError::of(SkErrorCode::WrongKey))?;
        let mut blob = Vec::new();
        ssh_key::encoding::Encode::encode(&signature, &mut blob)
            .map_err(|e| SkError::invalid(e.to_string()))?;
        Ok(blob)
    }
}

/// Whether a private key text is an OpenSSH security key file.
pub fn is_security_key(private_key: &str) -> bool {
    PrivateKey::from_openssh(private_key.trim())
        .map(|k| SkAlgorithm::of(&k.algorithm()).is_some())
        .unwrap_or(false)
}

/// Reads an OpenSSH sk "private key" file (decrypting it with
/// `passphrase` if needed). `Ok(None)`: not a security key.
pub fn parse_private(pem: &str, passphrase: Option<&str>) -> Result<Option<SkKey>> {
    let Ok(mut key) = PrivateKey::from_openssh(pem.trim()) else {
        return Ok(None);
    };
    let Some(algorithm) = SkAlgorithm::of(&key.algorithm()) else {
        return Ok(None);
    };
    if key.is_encrypted() {
        let pass = passphrase.filter(|p| !p.is_empty()).ok_or_else(|| {
            SshError::Key("the key is encrypted and the passphrase is missing".into())
        })?;
        key = key
            .decrypt(pass)
            .map_err(|_| SshError::Key("wrong passphrase".into()))?;
    }
    let (application, flags, key_handle) = match key.key_data() {
        KeypairData::SkEd25519(sk) => (
            sk.public().application().to_string(),
            sk.flags(),
            sk.key_handle().to_vec(),
        ),
        KeypairData::SkEcdsaSha2NistP256(sk) => (
            sk.public().application().to_string(),
            sk.flags(),
            sk.key_handle().to_vec(),
        ),
        _ => return Ok(None),
    };
    Ok(Some(SkKey {
        algorithm,
        public: key.public_key().clone(),
        application,
        flags,
        key_handle,
    }))
}

/// The info of a public sk key (no flags: they are in the private file).
pub fn public_info(public: &PublicKey) -> Option<SecurityKeyInfo> {
    let application = match public.key_data() {
        KeyData::SkEd25519(k) => k.application(),
        KeyData::SkEcdsaSha2NistP256(k) => k.application(),
        _ => return None,
    };
    Some(SecurityKeyInfo {
        application: application.to_string(),
        touch_required: true,
        ..Default::default()
    })
}

/// The `authorized_keys` line of an sk key, with the options its flags
/// need (`no-touch-required`, `verify-required`).
pub fn authorized_keys_line(public_key: &str, info: Option<&SecurityKeyInfo>) -> String {
    let mut opts = Vec::new();
    if let Some(i) = info {
        if !i.touch_required {
            opts.push("no-touch-required");
        }
        if i.verify_required {
            opts.push("verify-required");
        }
    }
    let key = public_key.trim();
    if opts.is_empty() {
        key.to_string()
    } else {
        format!("{} {key}", opts.join(","))
    }
}

/// Signs `message` with the device through `signer` and returns the SSH
/// signature blob, checked against the public key.
pub async fn sign(
    key: &SkKey,
    signer: &dyn SecurityKeySigner,
    message: Vec<u8>,
    context: SkContext,
) -> Result<Vec<u8>, SkError> {
    let request = key.sign_request(message.clone(), context);
    let assertion = signer.sign(request).await?;
    key.signature_blob(&message, &assertion)
}

/// russh [`Signer`](russh::Signer) over a [`SecurityKeySigner`]: it
/// appends the sk signature to the buffer russh hands over (string session
/// id + userauth request), as an SSH agent does.
pub struct SkAuthSigner {
    pub key: SkKey,
    pub signer: Arc<dyn SecurityKeySigner>,
    pub context: SkContext,
    /// The device's error, if signing failed.
    pub error: Option<SkError>,
}

/// Error type of [`SkAuthSigner`].
#[derive(Debug, thiserror::Error)]
pub enum SkAuthError {
    #[error(transparent)]
    Send(#[from] russh::SendError),
    #[error(transparent)]
    Key(#[from] SkError),
}

impl russh::Signer for SkAuthSigner {
    type Error = SkAuthError;

    #[allow(clippy::manual_async_fn)]
    fn auth_sign(
        &mut self,
        _key: &russh::keys::agent::AgentIdentity,
        _hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        async move {
            match sign(
                &self.key,
                self.signer.as_ref(),
                to_sign.clone(),
                self.context.clone(),
            )
            .await
            {
                Ok(blob) => {
                    let mut out = to_sign;
                    ssh_key::encoding::Encode::encode(&blob.as_slice(), &mut out)
                        .map_err(|e| SkError::invalid(e.to_string()))?;
                    Ok(out)
                }
                Err(e) => {
                    // russh waits for a signed buffer: send one with an
                    // empty signature, so the server answers "failure" and
                    // the other methods can still be tried (an error here
                    // would leave the session waiting). The device's error
                    // is kept in `error`.
                    self.error = Some(e);
                    let mut blob = Vec::new();
                    let alg = self.key.algorithm.ssh_name();
                    ssh_key::encoding::Encode::encode(&alg, &mut blob)
                        .and_then(|_| ssh_key::encoding::Encode::encode(&[0u8; 0][..], &mut blob))
                        .map_err(|e| SkError::invalid(e.to_string()))?;
                    blob.push(0);
                    blob.extend_from_slice(&0u32.to_be_bytes());
                    let mut out = to_sign;
                    ssh_key::encoding::Encode::encode(&blob.as_slice(), &mut out)
                        .map_err(|e| SkError::invalid(e.to_string()))?;
                    Ok(out)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ECDSA signature formats
// ---------------------------------------------------------------------------

/// DER (`SEQUENCE {INTEGER r, INTEGER s}`) or 64-byte `r || s` → SSH
/// (`mpint r || mpint s`).
fn ecdsa_ssh_signature(sig: &[u8]) -> Result<Vec<u8>, SkError> {
    let (r, s) = if sig.first() == Some(&0x30) && sig.len() != 64 {
        der_ecdsa(sig).ok_or_else(|| SkError::invalid("invalid DER ECDSA signature"))?
    } else if sig.len() == 64 {
        (sig[..32].to_vec(), sig[32..].to_vec())
    } else if sig.first() == Some(&0x30) {
        // 64 bytes starting with 0x30: try DER first.
        der_ecdsa(sig).unwrap_or_else(|| (sig[..32].to_vec(), sig[32..].to_vec()))
    } else {
        return Err(SkError::invalid("invalid ECDSA signature"));
    };
    let mut out = Vec::new();
    put_mpint(&mut out, &r);
    put_mpint(&mut out, &s);
    Ok(out)
}

fn der_len(d: &[u8], i: &mut usize) -> Option<usize> {
    let b = *d.get(*i)?;
    *i += 1;
    if b < 0x80 {
        return Some(b as usize);
    }
    let n = (b & 0x7f) as usize;
    if n == 0 || n > 2 {
        return None;
    }
    let mut len = 0usize;
    for _ in 0..n {
        len = (len << 8) | *d.get(*i)? as usize;
        *i += 1;
    }
    Some(len)
}

fn der_ecdsa(d: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut i = 0;
    if *d.get(i)? != 0x30 {
        return None;
    }
    i += 1;
    let len = der_len(d, &mut i)?;
    if i + len != d.len() {
        return None;
    }
    let mut int = || -> Option<Vec<u8>> {
        if *d.get(i)? != 0x02 {
            return None;
        }
        i += 1;
        let l = der_len(d, &mut i)?;
        let v = d.get(i..i + l)?.to_vec();
        i += l;
        Some(v)
    };
    let r = int()?;
    let s = int()?;
    Some((r, s))
}

fn put_mpint(out: &mut Vec<u8>, v: &[u8]) {
    let mut v: &[u8] = v;
    while v.len() > 1 && v[0] == 0 {
        v = &v[1..];
    }
    let pad = !v.is_empty() && v[0] & 0x80 != 0;
    let len = v.len() + pad as usize;
    out.extend_from_slice(&(len as u32).to_be_bytes());
    if pad {
        out.push(0);
    }
    out.extend_from_slice(v);
}

/// SSH `mpint r || mpint s` → DER (what CTAP2 authenticators return).
pub fn ecdsa_der_from_ssh(sig: &[u8]) -> Option<Vec<u8>> {
    fn take(d: &[u8], i: &mut usize) -> Option<Vec<u8>> {
        let l = u32::from_be_bytes(d.get(*i..*i + 4)?.try_into().ok()?) as usize;
        *i += 4;
        let v = d.get(*i..*i + l)?.to_vec();
        *i += l;
        Some(v)
    }
    let mut i = 0;
    let r = take(sig, &mut i)?;
    let s = take(sig, &mut i)?;
    let int = |v: Vec<u8>| {
        let mut v: &[u8] = &v;
        while v.len() > 1 && v[0] == 0 && v[1] & 0x80 == 0 {
            v = &v[1..];
        }
        let mut out = vec![0x02, v.len() as u8];
        out.extend_from_slice(v);
        out
    };
    let mut body = int(r);
    body.extend(int(s));
    let mut out = vec![0x30, body.len() as u8];
    out.extend(body);
    Some(out)
}

// ---------------------------------------------------------------------------
// Make credential (generating a key on the device)
// ---------------------------------------------------------------------------

/// Options of a new security key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkKeyOptions {
    pub algorithm: SkAlgorithm,
    /// Default `ssh:`.
    #[serde(default)]
    pub application: Option<String>,
    /// User of a resident credential (default `openssh`, at most 32 bytes).
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub resident: bool,
    #[serde(default)]
    pub verify_required: bool,
    /// `no-touch-required` (the server needs that authorized_keys option).
    #[serde(default)]
    pub no_touch_required: bool,
    /// Device label to keep in `SecurityKeyInfo::device`.
    #[serde(default)]
    pub device: Option<String>,
}

/// What the device must create (CTAP2 `authenticatorMakeCredential`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkMakeCredentialRequest {
    pub algorithm: SkAlgorithm,
    /// `rp.id` (and `rp.name`).
    pub application: String,
    /// `user.id`: the user name zero-padded to 32 bytes (as OpenSSH).
    pub user_id: Vec<u8>,
    /// `user.name` (and `displayName`).
    pub user_name: String,
    /// A random challenge (the client data hash to pass).
    pub client_data_hash: [u8; 32],
    /// Option `rk`.
    pub resident: bool,
    /// Option `uv` (or the PIN).
    pub require_verification: bool,
    /// The key flags the new key will have.
    pub flags: u8,
    pub device: Option<String>,
}

/// The device's answer to make credential.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkCredential {
    /// The authenticator data (with the attested credential data).
    #[serde(default)]
    pub authenticator_data: Vec<u8>,
    /// Or the whole attestation object (CBOR map with `authData`).
    #[serde(default)]
    pub attestation_object: Vec<u8>,
}

fn validate_application(app: &str) -> Result<(), SkError> {
    if !app.starts_with("ssh:") || app.len() > 128 {
        return Err(SkError::invalid(
            "the application must start with \"ssh:\" (at most 128 characters)",
        ));
    }
    Ok(())
}

/// Prepares the make credential request of `options`.
pub fn make_credential_request(options: &SkKeyOptions) -> Result<SkMakeCredentialRequest, SkError> {
    let application = options
        .application
        .clone()
        .filter(|a| !a.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_APPLICATION.into());
    validate_application(&application)?;
    let user = options
        .user
        .clone()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| DEFAULT_USER.into());
    if user.len() > 32 {
        return Err(SkError::invalid("the user has at most 32 bytes"));
    }
    let mut user_id = user.as_bytes().to_vec();
    user_id.resize(32, 0);
    let mut challenge = [0u8; 32];
    rand::fill(&mut challenge);
    let mut flags = 0;
    if !options.no_touch_required {
        flags |= FLAG_USER_PRESENCE;
    }
    if options.verify_required {
        flags |= FLAG_USER_VERIFICATION;
    }
    if options.resident {
        flags |= FLAG_RESIDENT;
    }
    Ok(SkMakeCredentialRequest {
        algorithm: options.algorithm,
        application,
        user_id,
        user_name: user,
        client_data_hash: challenge,
        resident: options.resident,
        require_verification: options.verify_required,
        flags,
        device: options.device.clone(),
    })
}

/// Builds the key of a make credential answer: the OpenSSH public key and
/// sk private file (unencrypted), with its info.
pub fn key_from_credential(
    request: &SkMakeCredentialRequest,
    credential: &SkCredential,
    comment: &str,
) -> Result<KeyMaterial, SkError> {
    let auth_data = if !credential.authenticator_data.is_empty() {
        credential.authenticator_data.clone()
    } else if !credential.attestation_object.is_empty() {
        attestation_auth_data(&credential.attestation_object)?
    } else {
        return Err(SkError::invalid(
            "the device returned no authenticator data",
        ));
    };
    let parsed = parse_auth_data(&auth_data)?;
    let rp_hash: [u8; 32] = Sha256::digest(request.application.as_bytes()).into();
    if parsed.rp_id_hash != rp_hash {
        return Err(SkError::invalid(
            "the credential is for another application (rp id hash mismatch)",
        ));
    }
    let (credential_id, cose) = parsed
        .credential
        .ok_or_else(|| SkError::invalid("the authenticator data has no credential"))?;
    let mut material = build_key(
        request.algorithm,
        &request.application,
        request.flags,
        &credential_id,
        &cose,
        comment,
    )?;
    if let Some(info) = material.security_key.as_mut() {
        info.device = request.device.clone();
        if request.resident {
            info.user = Some(request.user_name.clone());
        }
    }
    Ok(material)
}

/// A resident credential read from the device (credential management).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkResidentCredential {
    /// Relying party id (`ssh:…`).
    pub application: String,
    pub credential_id: Vec<u8>,
    /// COSE public key (CBOR map).
    pub public_key_cose: Vec<u8>,
    #[serde(default)]
    pub user_id: Vec<u8>,
    #[serde(default)]
    pub user_name: Option<String>,
}

/// The key of a resident credential (flags: touch required + resident;
/// the device does not say whether it needs user verification).
pub fn key_from_resident(
    cred: &SkResidentCredential,
    verify_required: bool,
    device: Option<String>,
    comment: &str,
) -> Result<KeyMaterial, SkError> {
    validate_application(&cred.application)?;
    let cose = Cose::parse(&cred.public_key_cose)?;
    let algorithm = cose.algorithm();
    let mut flags = FLAG_USER_PRESENCE | FLAG_RESIDENT;
    if verify_required {
        flags |= FLAG_USER_VERIFICATION;
    }
    let mut m = build_key(
        algorithm,
        &cred.application,
        flags,
        &cred.credential_id,
        &cred.public_key_cose,
        comment,
    )?;
    if let Some(info) = m.security_key.as_mut() {
        info.device = device;
        info.user = cred
            .user_name
            .clone()
            .filter(|u| !u.is_empty())
            .or_else(|| {
                let trimmed: Vec<u8> = cred
                    .user_id
                    .iter()
                    .copied()
                    .take_while(|b| *b != 0)
                    .collect();
                String::from_utf8(trimmed).ok().filter(|u| !u.is_empty())
            });
    }
    Ok(m)
}

fn build_key(
    expected: SkAlgorithm,
    application: &str,
    flags: u8,
    credential_id: &[u8],
    cose: &[u8],
    comment: &str,
) -> Result<KeyMaterial, SkError> {
    if credential_id.is_empty() || credential_id.len() > 255 {
        return Err(SkError::invalid(
            "the credential id must have 1 to 255 bytes",
        ));
    }
    let cose = Cose::parse(cose)?;
    if cose.algorithm() != expected {
        return Err(SkError::new(
            SkErrorCode::Unsupported,
            "the device created a key of another algorithm",
        ));
    }
    let keypair = match cose {
        Cose::Ed25519(pk) => {
            let public = skpub::SkEd25519::new(Ed25519PublicKey(pk), application);
            KeypairData::SkEd25519(
                skp::SkEd25519::new(public, flags, credential_id.to_vec())
                    .map_err(|e| SkError::invalid(e.to_string()))?,
            )
        }
        Cose::P256 { x, y } => {
            let mut sec1 = vec![0x04];
            sec1.extend_from_slice(&x);
            sec1.extend_from_slice(&y);
            let point = match EcdsaPublicKey::from_sec1_bytes(&sec1)
                .map_err(|e| SkError::invalid(format!("invalid P-256 public key: {e}")))?
            {
                EcdsaPublicKey::NistP256(p) => p,
                _ => return Err(SkError::invalid("not a P-256 key")),
            };
            let public = skpub::SkEcdsaSha2NistP256::new(point, application);
            KeypairData::SkEcdsaSha2NistP256(
                skp::SkEcdsaSha2NistP256::new(public, flags, credential_id.to_vec())
                    .map_err(|e| SkError::invalid(e.to_string()))?,
            )
        }
    };
    let key = PrivateKey::new(keypair, comment).map_err(|e| SkError::invalid(e.to_string()))?;
    let public = key.public_key();
    let sk = SkKey {
        algorithm: expected,
        public: public.clone(),
        application: application.to_string(),
        flags,
        key_handle: credential_id.to_vec(),
    };
    Ok(KeyMaterial {
        private_openssh: key
            .to_openssh(LineEnding::LF)
            .map_err(|e| SkError::invalid(e.to_string()))?
            .to_string(),
        public_openssh: public
            .to_openssh()
            .map_err(|e| SkError::invalid(e.to_string()))?,
        fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
        algorithm: public.algorithm().as_str().to_string(),
        comment: comment.to_string(),
        encrypted: false,
        security_key: Some(sk.info()),
    })
}

/// Parsed authenticator data.
struct AuthData {
    rp_id_hash: [u8; 32],
    #[allow(dead_code)]
    flags: u8,
    /// (credential id, COSE public key bytes).
    credential: Option<(Vec<u8>, Vec<u8>)>,
}

fn parse_auth_data(d: &[u8]) -> Result<AuthData, SkError> {
    if d.len() < 37 {
        return Err(SkError::invalid("the authenticator data is too short"));
    }
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&d[..32]);
    let flags = d[32];
    let mut credential = None;
    if flags & AUTH_DATA_AT != 0 {
        let rest = &d[37..];
        if rest.len() < 18 {
            return Err(SkError::invalid("truncated attested credential data"));
        }
        let len = u16::from_be_bytes([rest[16], rest[17]]) as usize;
        let id = rest
            .get(18..18 + len)
            .ok_or_else(|| SkError::invalid("truncated credential id"))?
            .to_vec();
        let key_start = 18 + len;
        let (_, used) = cbor::decode(&rest[key_start..], 0)
            .ok_or_else(|| SkError::invalid("invalid COSE public key"))?;
        let cose = rest[key_start..key_start + used].to_vec();
        if flags & AUTH_DATA_ED == 0 && key_start + used != rest.len() {
            return Err(SkError::invalid("trailing bytes after the credential"));
        }
        credential = Some((id, cose));
    }
    Ok(AuthData {
        rp_id_hash,
        flags,
        credential,
    })
}

fn attestation_auth_data(obj: &[u8]) -> Result<Vec<u8>, SkError> {
    let (v, _) =
        cbor::decode(obj, 0).ok_or_else(|| SkError::invalid("invalid attestation object"))?;
    match v.get_text("authData") {
        Some(cbor::Value::Bytes(b)) => Ok(b.clone()),
        _ => Err(SkError::invalid("the attestation object has no authData")),
    }
}

enum Cose {
    Ed25519([u8; 32]),
    P256 { x: [u8; 32], y: [u8; 32] },
}

impl Cose {
    fn parse(bytes: &[u8]) -> Result<Self, SkError> {
        let (v, _) = cbor::decode(bytes, 0).ok_or_else(|| SkError::invalid("invalid COSE key"))?;
        let int = |k: i64| match v.get_int(k) {
            Some(cbor::Value::Int(i)) => Some(*i),
            _ => None,
        };
        let bytes32 = |k: i64| -> Result<[u8; 32], SkError> {
            match v.get_int(k) {
                Some(cbor::Value::Bytes(b)) if b.len() == 32 => {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(b);
                    Ok(a)
                }
                _ => Err(SkError::invalid("invalid COSE key coordinates")),
            }
        };
        match (int(1), int(3), int(-1)) {
            // kty OKP, alg EdDSA, crv Ed25519
            (Some(1), alg, Some(6)) if alg.is_none() || alg == Some(-8) => {
                Ok(Cose::Ed25519(bytes32(-2)?))
            }
            // kty EC2, alg ES256, crv P-256
            (Some(2), alg, Some(1)) if alg.is_none() || alg == Some(-7) => Ok(Cose::P256 {
                x: bytes32(-2)?,
                y: bytes32(-3)?,
            }),
            _ => Err(SkError::new(
                SkErrorCode::Unsupported,
                "the device's key is not Ed25519 or ECDSA P-256",
            )),
        }
    }

    fn algorithm(&self) -> SkAlgorithm {
        match self {
            Cose::Ed25519(_) => SkAlgorithm::Ed25519,
            Cose::P256 { .. } => SkAlgorithm::EcdsaP256,
        }
    }
}

/// COSE key of a public sk key (what a device returns in credential data).
pub fn cose_of(public: &PublicKey) -> Option<Vec<u8>> {
    use cbor::Value as V;
    let map = match public.key_data() {
        KeyData::SkEd25519(k) => V::Map(vec![
            (V::Int(1), V::Int(1)),
            (V::Int(3), V::Int(-8)),
            (V::Int(-1), V::Int(6)),
            (V::Int(-2), V::Bytes(k.public_key().0.to_vec())),
        ]),
        KeyData::SkEcdsaSha2NistP256(k) => {
            let p = k.ec_point().as_bytes();
            if p.len() != 65 {
                return None;
            }
            V::Map(vec![
                (V::Int(1), V::Int(2)),
                (V::Int(3), V::Int(-7)),
                (V::Int(-1), V::Int(1)),
                (V::Int(-2), V::Bytes(p[1..33].to_vec())),
                (V::Int(-3), V::Bytes(p[33..].to_vec())),
            ])
        }
        _ => return None,
    };
    let mut out = Vec::new();
    cbor::encode(&map, &mut out);
    Some(out)
}

/// A tiny CBOR reader/writer: what COSE keys and attestation objects use.
pub(crate) mod cbor {
    #[derive(Debug, Clone, PartialEq)]
    pub enum Value {
        Int(i64),
        Bytes(Vec<u8>),
        Text(String),
        Array(Vec<Value>),
        Map(Vec<(Value, Value)>),
        Simple(u8),
    }

    impl Value {
        pub fn get_int(&self, key: i64) -> Option<&Value> {
            match self {
                Value::Map(m) => m
                    .iter()
                    .find(|(k, _)| *k == Value::Int(key))
                    .map(|(_, v)| v),
                _ => None,
            }
        }

        pub fn get_text(&self, key: &str) -> Option<&Value> {
            match self {
                Value::Map(m) => m
                    .iter()
                    .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
                    .map(|(_, v)| v),
                _ => None,
            }
        }
    }

    const MAX_DEPTH: usize = 16;

    fn arg(d: &[u8], info: u8, i: &mut usize) -> Option<u64> {
        let n = match info {
            0..=23 => return Some(info as u64),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return None,
        };
        let b = d.get(*i..*i + n)?;
        *i += n;
        Some(b.iter().fold(0u64, |a, x| (a << 8) | *x as u64))
    }

    /// Decodes one value; returns it and the bytes used.
    pub fn decode(d: &[u8], depth: usize) -> Option<(Value, usize)> {
        if depth > MAX_DEPTH {
            return None;
        }
        let first = *d.first()?;
        let (major, info) = (first >> 5, first & 0x1f);
        let mut i = 1;
        let v = match major {
            0 => Value::Int(i64::try_from(arg(d, info, &mut i)?).ok()?),
            1 => Value::Int(-1 - i64::try_from(arg(d, info, &mut i)?).ok()?),
            2 | 3 => {
                let n = usize::try_from(arg(d, info, &mut i)?).ok()?;
                let b = d.get(i..i.checked_add(n)?)?.to_vec();
                i += n;
                if major == 2 {
                    Value::Bytes(b)
                } else {
                    Value::Text(String::from_utf8(b).ok()?)
                }
            }
            4 => {
                let n = usize::try_from(arg(d, info, &mut i)?).ok()?;
                if n > 1024 {
                    return None;
                }
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    let (v, used) = decode(&d[i..], depth + 1)?;
                    i += used;
                    items.push(v);
                }
                Value::Array(items)
            }
            5 => {
                let n = usize::try_from(arg(d, info, &mut i)?).ok()?;
                if n > 1024 {
                    return None;
                }
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    let (k, used) = decode(&d[i..], depth + 1)?;
                    i += used;
                    let (v, used) = decode(&d[i..], depth + 1)?;
                    i += used;
                    items.push((k, v));
                }
                Value::Map(items)
            }
            6 => {
                arg(d, info, &mut i)?;
                let (v, used) = decode(&d[i..], depth + 1)?;
                i += used;
                v
            }
            7 => match info {
                0..=23 => Value::Simple(info),
                24 => {
                    i += 1;
                    Value::Simple(*d.get(1)?)
                }
                25 => {
                    i += 2;
                    d.get(..3)?;
                    Value::Simple(0)
                }
                26 => {
                    i += 4;
                    d.get(..5)?;
                    Value::Simple(0)
                }
                27 => {
                    i += 8;
                    d.get(..9)?;
                    Value::Simple(0)
                }
                _ => return None,
            },
            _ => return None,
        };
        Some((v, i))
    }

    fn head(major: u8, n: u64, out: &mut Vec<u8>) {
        let m = major << 5;
        if n < 24 {
            out.push(m | n as u8);
        } else if n <= 0xff {
            out.extend_from_slice(&[m | 24, n as u8]);
        } else if n <= 0xffff {
            out.push(m | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        } else if n <= 0xffff_ffff {
            out.push(m | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        } else {
            out.push(m | 27);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }

    pub fn encode(v: &Value, out: &mut Vec<u8>) {
        match v {
            Value::Int(i) if *i >= 0 => head(0, *i as u64, out),
            Value::Int(i) => head(1, (-1 - *i) as u64, out),
            Value::Bytes(b) => {
                head(2, b.len() as u64, out);
                out.extend_from_slice(b);
            }
            Value::Text(t) => {
                head(3, t.len() as u64, out);
                out.extend_from_slice(t.as_bytes());
            }
            Value::Array(a) => {
                head(4, a.len() as u64, out);
                for x in a {
                    encode(x, out);
                }
            }
            Value::Map(m) => {
                head(5, m.len() as u64, out);
                for (k, x) in m {
                    encode(k, out);
                    encode(x, out);
                }
            }
            Value::Simple(s) => head(7, *s as u64, out),
        }
    }
}

/// JSON of server forwarding over the events WebSocket (docs/SSH-PRO.md
/// §5.1): the server writes requests and reads responses, the apps the
/// other way round.
pub mod wire {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    use super::{SkAlgorithm, SkAssertion, SkContext, SkError, SkErrorCode, SkSignRequest};

    /// The feature a device declares on the events socket
    /// (`?features=security_keys`).
    pub const FEATURE: &str = "security_keys";
    pub const REQUEST: &str = "security_key_request";
    pub const RESPONSE: &str = "security_key_response";
    pub const DONE: &str = "security_key_done";

    /// `security_key_request`.
    pub fn request(request_id: &str, req: &SkSignRequest, expires_at: i64) -> Value {
        let c = &req.context;
        json!({
            "type": REQUEST,
            "request_id": request_id,
            "expires_at": expires_at,
            "purpose": c.purpose,
            "session_id": c.session_id,
            "host": c.host,
            "address": c.address,
            "username": c.username,
            "key": {
                "id": c.key_id,
                "label": c.key_label,
                "fingerprint": req.fingerprint,
                "public_key": req.public_key,
                "algorithm": req.algorithm.ssh_name(),
                "application": req.application,
                "key_handle": B64.encode(&req.key_handle),
                "device": c.device,
            },
            "message": B64.encode(&req.message),
            "client_data_hash": B64.encode(req.client_data_hash),
            "require_presence": req.require_presence,
            "require_verification": req.require_verification,
        })
    }

    fn s(v: &Value) -> String {
        v.as_str().unwrap_or_default().to_string()
    }

    fn b64(v: &Value) -> Option<Vec<u8>> {
        B64.decode(v.as_str()?).ok()
    }

    /// Reads a `security_key_request` (the request id and what to sign).
    pub fn parse_request(v: &Value) -> Result<(String, SkSignRequest), SkError> {
        let bad = |m: &str| SkError::invalid(format!("invalid security key request: {m}"));
        if v["type"] != REQUEST {
            return Err(bad("type"));
        }
        let id = s(&v["request_id"]);
        if id.is_empty() {
            return Err(bad("request_id"));
        }
        let k = &v["key"];
        let algorithm = match k["algorithm"].as_str() {
            Some(a) if a == SkAlgorithm::Ed25519.ssh_name() => SkAlgorithm::Ed25519,
            Some(a) if a == SkAlgorithm::EcdsaP256.ssh_name() => SkAlgorithm::EcdsaP256,
            _ => return Err(bad("algorithm")),
        };
        let message = b64(&v["message"]).ok_or_else(|| bad("message"))?;
        let hash: [u8; 32] = Sha256::digest(&message).into();
        if let Some(given) = b64(&v["client_data_hash"])
            && given != hash
        {
            return Err(bad("client_data_hash does not match the message"));
        }
        let req = SkSignRequest {
            algorithm,
            application: s(&k["application"]),
            key_handle: b64(&k["key_handle"]).ok_or_else(|| bad("key_handle"))?,
            public_key: s(&k["public_key"]),
            fingerprint: s(&k["fingerprint"]),
            message,
            client_data_hash: hash,
            require_presence: v["require_presence"].as_bool().unwrap_or(true),
            require_verification: v["require_verification"].as_bool().unwrap_or(false),
            context: SkContext {
                host: s(&v["host"]),
                address: s(&v["address"]),
                username: s(&v["username"]),
                key_label: s(&k["label"]),
                key_id: k["id"].as_str().map(str::to_string),
                device: k["device"].as_str().map(str::to_string),
                purpose: s(&v["purpose"]),
                session_id: v["session_id"].as_str().map(str::to_string),
            },
        };
        if !req.application.starts_with("ssh:") {
            return Err(bad("application"));
        }
        Ok((id, req))
    }

    /// `security_key_response` with the device's answer.
    pub fn response(request_id: &str, result: &Result<SkAssertion, SkError>) -> Value {
        match result {
            Ok(a) => json!({
                "type": RESPONSE,
                "request_id": request_id,
                "flags": a.flags,
                "counter": a.counter,
                "signature": B64.encode(&a.signature),
            }),
            Err(e) => json!({
                "type": RESPONSE,
                "request_id": request_id,
                "error": {"code": e.code.wire(), "message": e.message},
            }),
        }
    }

    /// Reads a `security_key_response`.
    pub fn parse_response(v: &Value) -> Option<(String, Result<SkAssertion, SkError>)> {
        if v["type"] != RESPONSE {
            return None;
        }
        let id = v["request_id"].as_str()?.to_string();
        if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
            let code = SkErrorCode::parse(e["code"].as_str().unwrap_or("failed"));
            let message = e["message"]
                .as_str()
                .filter(|m| !m.is_empty())
                .map(|m| m.chars().take(300).collect::<String>())
                .unwrap_or_else(|| SkError::of(code).message);
            return Some((id, Err(SkError::new(code, message))));
        }
        let flags = u8::try_from(v["flags"].as_u64()?).ok()?;
        let counter = u32::try_from(v["counter"].as_u64()?).ok()?;
        let signature = b64(&v["signature"])?;
        if signature.is_empty() || signature.len() > 256 {
            return None;
        }
        Some((
            id,
            Ok(SkAssertion {
                flags,
                counter,
                signature,
            }),
        ))
    }

    /// `security_key_done`.
    pub fn done(request_id: &str, result: &str) -> Value {
        json!({"type": DONE, "request_id": request_id, "result": result})
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn roundtrip() {
            let req = SkSignRequest {
                algorithm: SkAlgorithm::EcdsaP256,
                application: "ssh:".into(),
                key_handle: vec![1, 2, 3],
                public_key: "sk-ecdsa… x".into(),
                fingerprint: "SHA256:x".into(),
                message: b"m".to_vec(),
                client_data_hash: Sha256::digest(b"m").into(),
                require_presence: true,
                require_verification: false,
                context: SkContext {
                    host: "web1".into(),
                    purpose: "server_session".into(),
                    session_id: Some("s".into()),
                    ..Default::default()
                },
            };
            let v = request("r1", &req, 5);
            let (id, back) = parse_request(&v).unwrap();
            assert_eq!(id, "r1");
            assert_eq!(back, req);
            let mut bad = v.clone();
            bad["client_data_hash"] = Value::String(B64.encode([0u8; 32]));
            assert!(parse_request(&bad).is_err());
            let ok = Ok(SkAssertion {
                flags: 1,
                counter: 9,
                signature: vec![7; 70],
            });
            assert_eq!(
                parse_response(&response("r1", &ok)).unwrap(),
                ("r1".into(), ok)
            );
            let err: Result<SkAssertion, SkError> = Err(SkError::of(SkErrorCode::Cancelled));
            let (_, back) = parse_response(&response("r1", &err)).unwrap();
            assert_eq!(back.unwrap_err().code, SkErrorCode::Cancelled);
            assert!(parse_response(&json!({"type": RESPONSE, "request_id": "x", "flags": 300, "counter": 1, "signature": "AA=="})).is_none());
        }
    }
}

/// Authenticator data of a new credential (what a device returns): used by
/// the test authenticator and tests.
pub fn make_auth_data(
    application: &str,
    flags: u8,
    counter: u32,
    credential: Option<(&[u8], &[u8])>,
) -> Vec<u8> {
    let mut d = Sha256::digest(application.as_bytes()).to_vec();
    let mut f = flags;
    if credential.is_some() {
        f |= AUTH_DATA_AT;
    }
    d.push(f);
    d.extend_from_slice(&counter.to_be_bytes());
    if let Some((id, cose)) = credential {
        d.extend_from_slice(&[0u8; 16]);
        d.extend_from_slice(&(id.len() as u16).to_be_bytes());
        d.extend_from_slice(id);
        d.extend_from_slice(cose);
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_roundtrip_and_mpints() {
        let mut r = [0u8; 32];
        r[0] = 0x80;
        r[31] = 1;
        let mut s = [0u8; 32];
        s[1] = 0x7f;
        let mut ssh = Vec::new();
        put_mpint(&mut ssh, &r);
        put_mpint(&mut ssh, &s);
        let der = ecdsa_der_from_ssh(&ssh).unwrap();
        assert_eq!(der[0], 0x30);
        assert_eq!(ecdsa_ssh_signature(&der).unwrap(), ssh);
        let mut raw = r.to_vec();
        raw.extend_from_slice(&s);
        assert_eq!(ecdsa_ssh_signature(&raw).unwrap(), ssh);
        assert!(ecdsa_ssh_signature(&[1, 2, 3]).is_err());
        assert!(der_ecdsa(&[0x30, 0x10, 0x02]).is_none());
    }

    #[test]
    fn cbor_roundtrip_and_limits() {
        use cbor::Value as V;
        let v = V::Map(vec![
            (V::Int(1), V::Int(2)),
            (V::Int(-3), V::Bytes(vec![7; 300])),
            (
                V::Text("authData".into()),
                V::Array(vec![V::Int(70000), V::Int(-70000)]),
            ),
        ]);
        let mut out = Vec::new();
        cbor::encode(&v, &mut out);
        let (back, used) = cbor::decode(&out, 0).unwrap();
        assert_eq!(back, v);
        assert_eq!(used, out.len());
        // Truncated input and absurd lengths fail cleanly.
        for n in 0..out.len() {
            assert!(cbor::decode(&out[..n], 0).is_none() || n == out.len());
        }
        assert!(cbor::decode(&[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0).is_none());
        let deep = vec![0x81u8; 64];
        assert!(cbor::decode(&deep, 0).is_none());
    }

    #[test]
    fn error_codes() {
        for c in [
            SkErrorCode::Cancelled,
            SkErrorCode::PinRequired,
            SkErrorCode::NoDevice,
        ] {
            assert_eq!(SkErrorCode::parse(c.wire()), c);
            assert_eq!(SkErrorCode::parse(c.api_code()), c);
        }
        assert_eq!(SkErrorCode::parse("weird"), SkErrorCode::Failed);
        let e: SshError = SkError::of(SkErrorCode::Timeout).into();
        assert!(matches!(
            e,
            SshError::SecurityKey {
                code: "security_key_timeout",
                ..
            }
        ));
    }

    #[test]
    fn requests_and_lines() {
        let req = make_credential_request(&SkKeyOptions {
            algorithm: SkAlgorithm::Ed25519,
            application: None,
            user: None,
            resident: true,
            verify_required: true,
            no_touch_required: false,
            device: Some("Yubi".into()),
        })
        .unwrap();
        assert_eq!(req.application, "ssh:");
        assert_eq!(&req.user_id[..7], b"openssh");
        assert_eq!(req.user_id.len(), 32);
        assert_eq!(
            req.flags,
            FLAG_USER_PRESENCE | FLAG_USER_VERIFICATION | FLAG_RESIDENT
        );
        assert!(
            make_credential_request(&SkKeyOptions {
                application: Some("web:".into()),
                ..serde_json::from_value(serde_json::json!({"algorithm": "ecdsa_p256"})).unwrap()
            })
            .is_err()
        );
        let info = SecurityKeyInfo {
            application: "ssh:".into(),
            touch_required: false,
            verify_required: true,
            ..Default::default()
        };
        assert_eq!(
            authorized_keys_line("sk-ssh-ed25519@openssh.com AAAA x", Some(&info)),
            "no-touch-required,verify-required sk-ssh-ed25519@openssh.com AAAA x"
        );
    }
}

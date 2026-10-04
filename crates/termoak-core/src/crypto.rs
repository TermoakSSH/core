//! Vault cryptography.
//!
//! - Secrets at rest: XChaCha20-Poly1305 with a 256-bit master key and
//!   associated data (AAD) that binds the ciphertext to its record.
//! - User passwords: Argon2id in PHC format.
//! - Password-based key derivation: Argon2id.
//! - Access tokens: 256 random bits; the database only stores their SHA-256.

use std::path::Path;

use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

/// Format version of sealed blobs: `[version][nonce 24][ciphertext + tag]`.
const SEAL_VERSION: u8 = 1;

/// Prefix of the AAD that binds stored secrets to their record. It keeps the
/// project's former name on purpose: data sealed before the rename to Termoak
/// would no longer open if it changed.
pub const LEGACY_AAD_PREFIX: &str = "aceitunoak";
const NONCE_LEN: usize = 24;

/// 256-bit master key. Wiped from memory when dropped.
#[derive(Clone)]
pub struct MasterKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(***)")
    }
}

impl MasterKey {
    /// Generates a new random key.
    pub fn generate() -> Self {
        Self(Zeroizing::new(random_bytes::<32>()))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_base64(s: &str) -> Result<Self> {
        let raw = Zeroizing::new(
            STANDARD
                .decode(s.trim())
                .map_err(|e| CoreError::Crypto(format!("master key is not base64: {e}")))?,
        );
        let bytes: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::Crypto("the master key must be 32 bytes".into()))?;
        Ok(Self::from_bytes(bytes))
    }

    pub fn to_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(STANDARD.encode(self.0.as_slice()))
    }

    /// Loads the key from `path`, or creates it (with 0600 permissions) if missing.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let content = Zeroizing::new(std::fs::read_to_string(path)?);
            return Self::from_base64(&content);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let key = Self::generate();
        write_private_file(path, key.to_base64().as_bytes())?;
        Ok(key)
    }

    /// Derives a key from a password (Argon2id, default parameters).
    pub fn derive_from_password(password: &[u8], salt: &[u8]) -> Result<Self> {
        let mut out = Zeroizing::new([0u8; 32]);
        Argon2::default()
            .hash_password_into(password, salt, out.as_mut())
            .map_err(|e| CoreError::Crypto(format!("argon2: {e}")))?;
        Ok(Self(out))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new_from_slice(self.0.as_slice())
            .expect("the master key is always 32 bytes")
    }

    /// Encrypts `plaintext`, binding it to `aad`.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let cipher = self.cipher();
        let nonce_bytes = random_bytes::<NONCE_LEN>();
        let nonce = XNonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CoreError::Crypto("encryption failed".into()))?;
        let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
        out.push(SEAL_VERSION);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypts a blob produced by [`MasterKey::seal`].
    pub fn open(&self, sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if sealed.len() < 1 + NONCE_LEN + 16 || sealed[0] != SEAL_VERSION {
            return Err(CoreError::Crypto("invalid encrypted blob".into()));
        }
        let nonce_bytes: [u8; NONCE_LEN] = sealed[1..1 + NONCE_LEN]
            .try_into()
            .map_err(|_| CoreError::Crypto("invalid nonce".into()))?;
        let nonce = XNonce::from(nonce_bytes);
        let cipher = self.cipher();
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &sealed[1 + NONCE_LEN..],
                    aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| {
                CoreError::Crypto("could not decrypt (wrong master key or tampered data)".into())
            })
    }
}

/// Writes a file readable only by its owner.
pub fn write_private_file(path: &Path, content: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(content)?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, content)?;
    }
    Ok(())
}

/// Random bytes from the operating system generator.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("the system random generator is unavailable");
    buf
}

/// Opaque 256-bit token in base64url.
pub fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<32>())
}

/// Token with a readable prefix (e.g. `aks_at_...`).
pub fn prefixed_token(prefix: &str) -> String {
    format!("{prefix}_{}", random_token())
}

/// Hex-encoded SHA-256.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// User password hash (Argon2id, PHC format).
pub fn hash_password(password: &str) -> Result<String> {
    let salt = random_bytes::<16>();
    Argon2::default()
        .hash_password_with_salt(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| CoreError::Crypto(format!("argon2: {e}")))
}

/// Verifies a password against its PHC hash. Returns `false` on any error.
pub fn verify_password(password: &str, hash: &str) -> bool {
    Argon2::default()
        .verify_password(password.as_bytes(), hash)
        .is_ok()
}

/// Compares two byte strings in constant time.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip_and_aad_binding() {
        let key = MasterKey::generate();
        let sealed = key.seal(b"secret", b"host:1").unwrap();
        assert_eq!(key.open(&sealed, b"host:1").unwrap().as_slice(), b"secret");
        assert!(key.open(&sealed, b"host:2").is_err());
        let other = MasterKey::generate();
        assert!(other.open(&sealed, b"host:1").is_err());
    }

    #[test]
    fn master_key_base64_roundtrip() {
        let key = MasterKey::generate();
        let b64 = key.to_base64();
        let again = MasterKey::from_base64(&b64).unwrap();
        assert_eq!(key.as_bytes(), again.as_bytes());
    }

    #[test]
    fn password_hash_verifies() {
        let hash = hash_password("olive").unwrap();
        assert!(verify_password("olive", &hash));
        assert!(!verify_password("pickle", &hash));
    }

    #[test]
    fn derive_is_deterministic() {
        let a = MasterKey::derive_from_password(b"pw", b"saltsalt12345678").unwrap();
        let b = MasterKey::derive_from_password(b"pw", b"saltsalt12345678").unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }
}

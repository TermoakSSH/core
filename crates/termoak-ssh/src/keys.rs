//! SSH key generation, import and fingerprints.

use russh::keys::ssh_key::private::{KeypairData, RsaKeypair};
use russh::keys::ssh_key::{
    self, Algorithm, EcdsaCurve, HashAlg, LineEnding, PrivateKey, PublicKey,
};
use serde::{Deserialize, Serialize};

use crate::error::{Result, SshError};

/// Key type to generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    Ed25519,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
}

impl KeyType {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().replace('-', "_").as_str() {
            "ed25519" => KeyType::Ed25519,
            "rsa" | "rsa4096" | "rsa_4096" => KeyType::Rsa4096,
            "rsa2048" | "rsa_2048" => KeyType::Rsa2048,
            "rsa3072" | "rsa_3072" => KeyType::Rsa3072,
            "ecdsa" | "ecdsa_p256" | "p256" => KeyType::EcdsaP256,
            "ecdsa_p384" | "p384" => KeyType::EcdsaP384,
            "ecdsa_p521" | "p521" => KeyType::EcdsaP521,
            _ => return None,
        })
    }
}

/// Freshly generated or imported key.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyMaterial {
    /// Private key in OpenSSH format (encrypted if a passphrase was given).
    pub private_openssh: String,
    /// Public key `type base64 comment`.
    pub public_openssh: String,
    /// Fingerprint `SHA256:...`.
    pub fingerprint: String,
    /// Algorithm (`ssh-ed25519`, `ssh-rsa`...).
    pub algorithm: String,
    pub comment: String,
    pub encrypted: bool,
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("algorithm", &self.algorithm)
            .field("fingerprint", &self.fingerprint)
            .field("encrypted", &self.encrypted)
            .finish_non_exhaustive()
    }
}

fn key_err(e: impl std::fmt::Display) -> SshError {
    SshError::Key(e.to_string())
}

/// Generates a new key, encrypted if `passphrase` is not empty.
pub fn generate(kind: KeyType, comment: &str, passphrase: Option<&str>) -> Result<KeyMaterial> {
    let mut rng = rand::rng();
    let mut key = match kind {
        KeyType::Ed25519 => PrivateKey::random(&mut rng, Algorithm::Ed25519).map_err(key_err)?,
        KeyType::EcdsaP256 => PrivateKey::random(
            &mut rng,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        )
        .map_err(key_err)?,
        KeyType::EcdsaP384 => PrivateKey::random(
            &mut rng,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            },
        )
        .map_err(key_err)?,
        KeyType::EcdsaP521 => PrivateKey::random(
            &mut rng,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            },
        )
        .map_err(key_err)?,
        KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
            let bits = match kind {
                KeyType::Rsa2048 => 2048,
                KeyType::Rsa3072 => 3072,
                _ => 4096,
            };
            let pair = RsaKeypair::random(&mut rng, bits).map_err(key_err)?;
            PrivateKey::new(KeypairData::from(pair), comment).map_err(key_err)?
        }
    };
    key.set_comment(comment);
    let encrypted = match passphrase.filter(|p| !p.is_empty()) {
        Some(pass) => {
            key = key.encrypt(&mut rng, pass).map_err(key_err)?;
            true
        }
        None => false,
    };
    material(&key, comment, encrypted)
}

fn material(key: &PrivateKey, comment: &str, encrypted: bool) -> Result<KeyMaterial> {
    let public = key.public_key();
    Ok(KeyMaterial {
        private_openssh: key.to_openssh(LineEnding::LF).map_err(key_err)?.to_string(),
        public_openssh: public.to_openssh().map_err(key_err)?,
        fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
        algorithm: public.algorithm().as_str().to_string(),
        comment: comment.to_string(),
        encrypted,
    })
}

/// Imports a private key (OpenSSH, PEM PKCS#1/PKCS#8 or unencrypted PuTTY PPK).
/// If it is encrypted, formats other than OpenSSH need the passphrase to read
/// the public part; the key is stored exactly as the user gave it.
pub fn import_private(pem: &str, passphrase: Option<&str>) -> Result<KeyMaterial> {
    let pem = pem.trim();
    if pem.is_empty() {
        return Err(SshError::Key("the key is empty".into()));
    }
    // OpenSSH format: the public part can be read even when encrypted.
    if let Ok(key) = PrivateKey::from_openssh(pem) {
        let encrypted = key.is_encrypted();
        if encrypted && let Some(pass) = passphrase.filter(|p| !p.is_empty()) {
            key.decrypt(pass)
                .map_err(|_| SshError::Key("wrong passphrase".into()))?;
        }
        let comment = key.comment().to_string();
        let public = key.public_key();
        return Ok(KeyMaterial {
            private_openssh: format!("{pem}\n"),
            public_openssh: public.to_openssh().map_err(key_err)?,
            fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
            algorithm: public.algorithm().as_str().to_string(),
            comment,
            encrypted,
        });
    }
    // Other formats: decode it (and re-export it in OpenSSH format).
    let key =
        russh::keys::decode_secret_key(pem, passphrase.filter(|p| !p.is_empty())).map_err(|e| {
            match e {
                russh::keys::Error::KeyIsEncrypted => {
                    SshError::Key("the key is encrypted: enter the passphrase".into())
                }
                other => SshError::Key(other.to_string()),
            }
        })?;
    let mut rng = rand::rng();
    let (key, encrypted) = match passphrase.filter(|p| !p.is_empty()) {
        Some(pass) => (key.encrypt(&mut rng, pass).map_err(key_err)?, true),
        None => (key, false),
    };
    let comment = key.comment().to_string();
    material(&key, &comment, encrypted)
}

/// Decodes a private key for authentication.
pub fn decode_private(pem: &str, passphrase: Option<&str>) -> Result<PrivateKey> {
    russh::keys::decode_secret_key(pem.trim(), passphrase.filter(|p| !p.is_empty())).map_err(|e| {
        match e {
            russh::keys::Error::KeyIsEncrypted => {
                SshError::Key("the key is encrypted and the passphrase is missing".into())
            }
            other => SshError::Key(other.to_string()),
        }
    })
}

/// Does the private key need a passphrase?
pub fn is_encrypted(pem: &str) -> bool {
    match PrivateKey::from_openssh(pem.trim()) {
        Ok(k) => k.is_encrypted(),
        Err(_) => matches!(
            russh::keys::decode_secret_key(pem.trim(), None),
            Err(russh::keys::Error::KeyIsEncrypted)
        ),
    }
}

/// Parses an OpenSSH public key (`type base64 [comment]`).
pub fn parse_public(openssh: &str) -> Result<PublicKey> {
    PublicKey::from_openssh(openssh.trim()).map_err(key_err)
}

/// SHA-256 fingerprint of a public key.
pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// Public key in OpenSSH format without comment.
pub fn public_openssh(key: &PublicKey) -> String {
    let mut k = key.clone();
    k.set_comment("");
    k.to_openssh().unwrap_or_default()
}

/// Readable algorithm of a public key.
pub fn algorithm_name(key: &PublicKey) -> String {
    key.algorithm().as_str().to_string()
}

/// Re-export for those who need the raw types.
pub use ssh_key::PublicKey as RawPublicKey;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_import_ed25519() {
        let k = generate(KeyType::Ed25519, "me@termoak", None).unwrap();
        assert!(k.public_openssh.starts_with("ssh-ed25519 "));
        assert!(k.fingerprint.starts_with("SHA256:"));
        let imported = import_private(&k.private_openssh, None).unwrap();
        assert_eq!(imported.fingerprint, k.fingerprint);
        assert!(!imported.encrypted);
        decode_private(&k.private_openssh, None).unwrap();
    }

    #[test]
    fn encrypted_keys_need_passphrase() {
        let k = generate(KeyType::EcdsaP256, "encrypted", Some("phrase")).unwrap();
        assert!(k.encrypted);
        assert!(is_encrypted(&k.private_openssh));
        assert!(decode_private(&k.private_openssh, None).is_err());
        decode_private(&k.private_openssh, Some("phrase")).unwrap();
        assert!(import_private(&k.private_openssh, Some("wrong")).is_err());
        let imp = import_private(&k.private_openssh, Some("phrase")).unwrap();
        assert_eq!(imp.fingerprint, k.fingerprint);
    }

    #[test]
    fn parse_public_roundtrip() {
        let k = generate(KeyType::Ed25519, "x", None).unwrap();
        let pk = parse_public(&k.public_openssh).unwrap();
        assert_eq!(fingerprint(&pk), k.fingerprint);
    }
}

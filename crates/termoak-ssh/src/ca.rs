//! SSH certificate authority (0.7 phase 4b, docs-next/TEAMS-SECURITY.md
//! §4): CA keys, user certificates, proofs of possession (SSHSIG), KRLs and
//! certificate details for display.
//!
//! The server signs; the apps make ephemeral keys and proofs and read
//! certificates. Nothing here touches the network or the store.

use std::time::{SystemTime, UNIX_EPOCH};

use russh::keys::ssh_key::certificate::{Builder, CertType};
use russh::keys::ssh_key::{
    Algorithm, Certificate, EcdsaCurve, HashAlg, LineEnding, PrivateKey, PublicKey, SshSig,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{Result, SshError};

/// SSHSIG namespace of the proofs of possession.
pub const PROOF_NAMESPACE: &str = "termoak-cert@termoak.com";

/// A proof is accepted this far from the server's clock (ms).
pub const PROOF_WINDOW_MS: i64 = 5 * 60_000;

fn err(e: impl std::fmt::Display) -> SshError {
    SshError::Key(e.to_string())
}

/// Algorithm of a CA key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaAlgorithm {
    Ed25519,
    EcdsaP256,
}

impl CaAlgorithm {
    /// `ed25519` / `ssh-ed25519` and `ecdsa-p256` / `ecdsa-sha2-nistp256`.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "ed25519" | "ssh-ed25519" => Some(CaAlgorithm::Ed25519),
            "ecdsa" | "ecdsa-p256" | "ecdsa-sha2-nistp256" | "p256" => Some(CaAlgorithm::EcdsaP256),
            _ => None,
        }
    }

    fn algorithm(self) -> Algorithm {
        match self {
            CaAlgorithm::Ed25519 => Algorithm::Ed25519,
            CaAlgorithm::EcdsaP256 => Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        }
    }
}

/// A new CA key pair.
pub struct CaKey {
    /// `ssh-ed25519` or `ecdsa-sha2-nistp256`.
    pub algorithm: String,
    /// OpenSSH public key line (with the comment).
    pub public_key: String,
    pub fingerprint: String,
    /// OpenSSH private key (unencrypted: the server seals it).
    pub private_key: Zeroizing<String>,
}

/// Generates a CA key pair.
pub fn generate_ca(alg: CaAlgorithm, comment: &str) -> Result<CaKey> {
    let mut rng = rand::rng();
    let mut key = PrivateKey::random(&mut rng, alg.algorithm()).map_err(err)?;
    key.set_comment(comment);
    let public = key.public_key();
    Ok(CaKey {
        algorithm: public.algorithm().as_str().to_string(),
        public_key: public.to_openssh().map_err(err)?,
        fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
        private_key: Zeroizing::new(key.to_openssh(LineEnding::LF).map_err(err)?.to_string()),
    })
}

/// An ephemeral Ed25519 key (memory only): `(private OpenSSH, public line)`.
pub fn ephemeral_key(comment: &str) -> Result<(Zeroizing<String>, String)> {
    let mut rng = rand::rng();
    let mut key = PrivateKey::random(&mut rng, Algorithm::Ed25519).map_err(err)?;
    key.set_comment(comment);
    let public = key.public_key().to_openssh().map_err(err)?;
    Ok((
        Zeroizing::new(key.to_openssh(LineEnding::LF).map_err(err)?.to_string()),
        public,
    ))
}

/// Parses an OpenSSH public key line (`type base64 [comment]`).
pub fn parse_public_key(line: &str) -> Result<PublicKey> {
    PublicKey::from_openssh(line.trim()).map_err(err)
}

/// `type base64` of a public key (no comment): what proofs sign.
pub fn public_key_text(key: &PublicKey) -> Result<String> {
    let mut k = key.clone();
    k.set_comment("");
    Ok(k.to_openssh().map_err(err)?.trim().to_string())
}

/// `SHA256:…` fingerprint of a public key.
pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// The public key of an OpenSSH private key (also security keys and
/// passphrase-protected keys: the public part is not encrypted).
pub fn public_key_of_private(pem: &str) -> Result<PublicKey> {
    let key = PrivateKey::from_openssh(pem.trim()).map_err(err)?;
    Ok(key.public_key().clone())
}

/// What goes in a user certificate.
#[derive(Debug, Clone)]
pub struct UserCertificate {
    pub serial: u64,
    pub key_id: String,
    pub principals: Vec<String>,
    /// Unix seconds.
    pub valid_after: u64,
    pub valid_before: u64,
    /// OpenSSH extension names (empty values).
    pub extensions: Vec<String>,
    pub source_address: Option<String>,
    pub force_command: Option<String>,
}

/// Signs a user certificate for `subject` with the CA private key (OpenSSH
/// format). Returns the certificate line.
pub fn sign_user_certificate(
    ca_private: &str,
    subject: &PublicKey,
    cert: &UserCertificate,
) -> Result<String> {
    let ca = PrivateKey::from_openssh(ca_private.trim()).map_err(err)?;
    if cert.principals.is_empty() {
        return Err(SshError::Key("a certificate needs principals".into()));
    }
    let nonce: [u8; 32] = rand::random();
    let mut b = Builder::new(
        nonce.to_vec(),
        subject.key_data().clone(),
        cert.valid_after,
        cert.valid_before,
    )
    .map_err(err)?;
    b.serial(cert.serial).map_err(err)?;
    b.cert_type(CertType::User).map_err(err)?;
    b.key_id(cert.key_id.clone()).map_err(err)?;
    for p in &cert.principals {
        b.valid_principal(p.clone()).map_err(err)?;
    }
    for e in &cert.extensions {
        b.extension(e.clone(), "").map_err(err)?;
    }
    if let Some(sa) = &cert.source_address {
        b.critical_option("source-address", sa.clone())
            .map_err(err)?;
    }
    if let Some(fc) = &cert.force_command {
        b.critical_option("force-command", fc.clone())
            .map_err(err)?;
    }
    b.comment(cert.key_id.clone()).map_err(err)?;
    let signed = b.sign(&ca).map_err(err)?;
    Ok(signed.to_openssh().map_err(err)?.trim().to_string())
}

/// What a certificate says (for the apps and checks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateDetails {
    pub key_id: String,
    pub serial: u64,
    /// `user` or `host`.
    pub cert_type: String,
    pub principals: Vec<String>,
    /// Unix seconds.
    pub valid_after: u64,
    pub valid_before: u64,
    pub extensions: Vec<String>,
    /// `name=value` (`source-address=10.0.0.0/8`).
    pub critical_options: Vec<String>,
    /// Fingerprint of the certified key.
    pub key_fingerprint: String,
    /// Fingerprint of the CA that signed it.
    pub ca_fingerprint: String,
    /// The CA signature is valid (not whether it is still in time).
    pub signature_valid: bool,
}

/// Parses an OpenSSH certificate line.
pub fn parse_certificate(line: &str) -> Result<CertificateDetails> {
    let cert = Certificate::from_openssh(line.trim()).map_err(err)?;
    let key = PublicKey::from(cert.public_key().clone());
    let ca = PublicKey::from(cert.signature_key().clone());
    Ok(CertificateDetails {
        key_id: cert.key_id().to_string(),
        serial: cert.serial(),
        cert_type: match cert.cert_type() {
            CertType::User => "user".into(),
            CertType::Host => "host".into(),
        },
        principals: cert.valid_principals().to_vec(),
        valid_after: cert.valid_after(),
        valid_before: cert.valid_before(),
        extensions: cert.extensions().keys().cloned().collect(),
        critical_options: cert
            .critical_options()
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect(),
        key_fingerprint: fingerprint(&key),
        ca_fingerprint: fingerprint(&ca),
        signature_valid: cert.verify_signature().is_ok(),
    })
}

/// Seconds since the epoch.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Proof of possession
// ---------------------------------------------------------------------------

/// The message a proof signs: it binds the key to this server, this user
/// and a moment.
pub fn proof_message(
    instance_id: &str,
    user_id: &str,
    public_key: &str,
    timestamp_ms: i64,
) -> String {
    format!("termoak-cert-request\n{instance_id}\n{user_id}\n{public_key}\n{timestamp_ms}")
}

/// Signs a proof with a private key (OpenSSH, optional passphrase): an
/// armored SSHSIG (SHA-512).
pub fn sign_proof(private_pem: &str, passphrase: Option<&str>, message: &str) -> Result<String> {
    let key = crate::keys::decode_private(private_pem, passphrase)?;
    let sig = key
        .sign(PROOF_NAMESPACE, HashAlg::Sha512, message.as_bytes())
        .map_err(err)?;
    Ok(sig.to_pem(LineEnding::LF).map_err(err)?)
}

/// Checks a proof made by `key` over `message`.
pub fn verify_proof(key: &PublicKey, armored: &str, message: &str) -> Result<()> {
    let sig = SshSig::from_pem(armored.trim()).map_err(err)?;
    key.verify(PROOF_NAMESPACE, message.as_bytes(), &sig)
        .map_err(|_| SshError::Key("the proof of possession does not verify".into()))
}

// ---------------------------------------------------------------------------
// KRL (OpenSSH key revocation list, PROTOCOL.krl)
// ---------------------------------------------------------------------------

const KRL_MAGIC: u64 = 0x5353_484b_524c_0a00;
const KRL_FORMAT_VERSION: u32 = 1;
const KRL_SECTION_CERTIFICATES: u8 = 1;
const KRL_SECTION_FINGERPRINT_SHA256: u8 = 5;
const KRL_SECTION_CERT_SERIAL_LIST: u8 = 0x20;

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    put_u32(out, s.len() as u32);
    out.extend_from_slice(s);
}

/// Revocations of one CA.
pub struct KrlCa {
    /// The CA public key line.
    pub ca_public_key: String,
    /// Revoked certificate serials.
    pub serials: Vec<u64>,
}

/// Builds a KRL (`RevokedKeys`): per CA its revoked serials, plus revoked
/// public keys by SHA-256. `version` grows with every change (the server
/// uses the time).
pub fn build_krl(
    cas: &[KrlCa],
    revoked_keys: &[String],
    version: u64,
    comment: &str,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    put_u64(&mut out, KRL_MAGIC);
    put_u32(&mut out, KRL_FORMAT_VERSION);
    put_u64(&mut out, version);
    put_u64(&mut out, unix_now());
    put_u64(&mut out, 0); // flags
    put_string(&mut out, b""); // reserved
    put_string(&mut out, comment.as_bytes());
    for ca in cas {
        let mut serials = ca.serials.clone();
        serials.sort_unstable();
        serials.dedup();
        if serials.is_empty() {
            continue;
        }
        let key = parse_public_key(&ca.ca_public_key)?;
        let mut section = Vec::new();
        put_string(&mut section, &key.to_bytes().map_err(err)?);
        put_string(&mut section, b""); // reserved
        let mut list = Vec::new();
        for s in serials {
            put_u64(&mut list, s);
        }
        section.push(KRL_SECTION_CERT_SERIAL_LIST);
        put_string(&mut section, &list);
        out.push(KRL_SECTION_CERTIFICATES);
        put_string(&mut out, &section);
    }
    let mut hashes: Vec<[u8; 32]> = Vec::new();
    for line in revoked_keys {
        let key = parse_public_key(line)?;
        let blob = key.to_bytes().map_err(err)?;
        hashes.push(Sha256::digest(&blob).into());
    }
    hashes.sort_unstable();
    hashes.dedup();
    if !hashes.is_empty() {
        let mut section = Vec::new();
        for h in &hashes {
            put_string(&mut section, h);
        }
        out.push(KRL_SECTION_FINGERPRINT_SHA256);
        put_string(&mut out, &section);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_parse_certificate() {
        let ca = generate_ca(CaAlgorithm::Ed25519, "termoak-ca test").unwrap();
        assert_eq!(ca.algorithm, "ssh-ed25519");
        assert!(ca.fingerprint.starts_with("SHA256:"));
        let (_, user_pub) = ephemeral_key("eph").unwrap();
        let subject = parse_public_key(&user_pub).unwrap();
        let now = unix_now();
        let line = sign_user_certificate(
            &ca.private_key,
            &subject,
            &UserCertificate {
                serial: 42,
                key_id: "termoak:ana@example.com:u:direct:42".into(),
                principals: vec!["deploy".into(), "ana".into()],
                valid_after: now - 300,
                valid_before: now + 3600,
                extensions: vec!["permit-pty".into()],
                source_address: Some("10.0.0.0/8".into()),
                force_command: None,
            },
        )
        .unwrap();
        assert!(line.starts_with("ssh-ed25519-cert-v01@openssh.com "));
        let d = parse_certificate(&line).unwrap();
        assert_eq!(d.serial, 42);
        assert_eq!(d.principals, vec!["deploy", "ana"]);
        assert_eq!(d.cert_type, "user");
        assert_eq!(d.extensions, vec!["permit-pty"]);
        assert_eq!(d.critical_options, vec!["source-address=10.0.0.0/8"]);
        assert_eq!(d.ca_fingerprint, ca.fingerprint);
        assert_eq!(d.key_fingerprint, fingerprint(&subject));
        assert!(d.signature_valid);
        // ECDSA CAs work too.
        let ec = generate_ca(CaAlgorithm::EcdsaP256, "ec").unwrap();
        assert_eq!(ec.algorithm, "ecdsa-sha2-nistp256");
        let line = sign_user_certificate(
            &ec.private_key,
            &subject,
            &UserCertificate {
                serial: 1,
                key_id: "k".into(),
                principals: vec!["root".into()],
                valid_after: now,
                valid_before: now + 60,
                extensions: vec![],
                source_address: None,
                force_command: Some("uptime".into()),
            },
        )
        .unwrap();
        assert_eq!(
            parse_certificate(&line).unwrap().ca_fingerprint,
            ec.fingerprint
        );
    }

    #[test]
    fn proofs_bind_key_user_and_time() {
        let (private, public) = ephemeral_key("x").unwrap();
        let key = parse_public_key(&public).unwrap();
        let text = public_key_text(&key).unwrap();
        assert!(!text.contains(" x"));
        let msg = proof_message("inst", "user-1", &text, 1000);
        let proof = sign_proof(&private, None, &msg).unwrap();
        assert!(proof.contains("BEGIN SSH SIGNATURE"));
        verify_proof(&key, &proof, &msg).unwrap();
        // Another user, time or key: refused.
        assert!(verify_proof(&key, &proof, &proof_message("inst", "user-2", &text, 1000)).is_err());
        assert!(verify_proof(&key, &proof, &proof_message("inst", "user-1", &text, 1001)).is_err());
        let (_, other) = ephemeral_key("y").unwrap();
        assert!(verify_proof(&parse_public_key(&other).unwrap(), &proof, &msg).is_err());
        assert_eq!(
            fingerprint(&public_key_of_private(&private).unwrap()),
            fingerprint(&key)
        );
    }

    #[test]
    fn krl_layout() {
        let ca = generate_ca(CaAlgorithm::Ed25519, "ca").unwrap();
        let (_, k) = ephemeral_key("k").unwrap();
        let krl = build_krl(
            &[KrlCa {
                ca_public_key: ca.public_key.clone(),
                serials: vec![7, 3, 7],
            }],
            &[k],
            5,
            "test",
        )
        .unwrap();
        assert_eq!(&krl[..8], b"SSHKRL\n\0");
        assert_eq!(u32::from_be_bytes(krl[8..12].try_into().unwrap()), 1);
        assert_eq!(u64::from_be_bytes(krl[12..20].try_into().unwrap()), 5);
        // Empty: just the header.
        let empty = build_krl(&[], &[], 1, "").unwrap();
        assert_eq!(empty.len(), 8 + 4 + 8 + 8 + 8 + 4 + 4);
    }
}

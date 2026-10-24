//! Test-only software FIDO2 authenticator (cargo feature `soft-sk`).
//!
//! It answers like a real security key (make credential, assertions with
//! `SHA-256(application) || flags || counter || clientDataHash` signed with
//! ECDSA P-256 or Ed25519, resident credentials), so the core, the server
//! and QA can test without hardware. **Never ship it**: its credential id
//! *contains* the private key (`TSK1 || alg || rp hash[8] || private ||
//! public`), which is what makes it stateless across processes.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use russh::keys::signature::Signer;
use russh::keys::ssh_key::private::{EcdsaKeypair, EcdsaPrivateKey, Ed25519Keypair, KeypairData};
use russh::keys::ssh_key::public::EcdsaPublicKey;
use russh::keys::ssh_key::{Algorithm, EcdsaCurve};
use sha2::{Digest, Sha256};

use super::{
    FLAG_USER_PRESENCE, FLAG_USER_VERIFICATION, SecurityKeySigner, SkAlgorithm, SkAssertion,
    SkCredential, SkError, SkErrorCode, SkMakeCredentialRequest, SkResidentCredential,
    SkSignRequest, cbor, ecdsa_der_from_ssh, make_auth_data,
};

const MAGIC: &[u8; 4] = b"TSK1";

/// How the authenticator behaves (to test errors).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Behavior {
    /// Sign normally.
    Sign,
    /// Fail every request with this code.
    Fail(SkErrorCode),
    /// Sign without setting the user-present flag.
    NoPresence,
    /// Sign with another key (a wrong signature).
    WrongKey,
}

/// The software authenticator.
pub struct SoftAuthenticator {
    counter: AtomicU32,
    behavior: Mutex<Behavior>,
    /// Delay before answering (to test timeouts).
    delay: Mutex<Duration>,
    /// Whether user verification succeeds (a "PIN" is set and entered).
    verify: Mutex<bool>,
    resident: Mutex<Vec<SkResidentCredential>>,
    /// Requests seen (for assertions in tests).
    pub seen: Mutex<Vec<SkSignRequest>>,
}

impl Default for SoftAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

fn rp8(application: &str) -> [u8; 8] {
    let h = Sha256::digest(application.as_bytes());
    let mut a = [0u8; 8];
    a.copy_from_slice(&h[..8]);
    a
}

/// A key pair rebuilt from a credential id.
struct SoftKey {
    keypair: KeypairData,
    algorithm: SkAlgorithm,
    rp8: [u8; 8],
}

fn decode_handle(handle: &[u8]) -> Option<SoftKey> {
    if handle.len() < 13 || &handle[..4] != MAGIC {
        return None;
    }
    let mut rp = [0u8; 8];
    rp.copy_from_slice(&handle[5..13]);
    let rest = &handle[13..];
    match handle[4] {
        1 if rest.len() == 64 => {
            let seed: [u8; 32] = rest[..32].try_into().ok()?;
            Some(SoftKey {
                keypair: KeypairData::Ed25519(Ed25519Keypair::from_seed(&seed)),
                algorithm: SkAlgorithm::Ed25519,
                rp8: rp,
            })
        }
        2 if rest.len() == 32 + 65 => {
            let private: [u8; 32] = rest[..32].try_into().ok()?;
            let EcdsaPublicKey::NistP256(public) =
                EcdsaPublicKey::from_sec1_bytes(&rest[32..]).ok()?
            else {
                return None;
            };
            Some(SoftKey {
                keypair: KeypairData::Ecdsa(EcdsaKeypair::NistP256 {
                    public,
                    private: EcdsaPrivateKey::from(private),
                }),
                algorithm: SkAlgorithm::EcdsaP256,
                rp8: rp,
            })
        }
        _ => None,
    }
}

impl SoftAuthenticator {
    pub fn new() -> Self {
        Self {
            counter: AtomicU32::new(1),
            behavior: Mutex::new(Behavior::Sign),
            delay: Mutex::new(Duration::ZERO),
            verify: Mutex::new(true),
            resident: Mutex::new(Vec::new()),
            seen: Mutex::new(Vec::new()),
        }
    }

    pub fn set_behavior(&self, b: Behavior) {
        *self.behavior.lock() = b;
    }

    pub fn set_delay(&self, d: Duration) {
        *self.delay.lock() = d;
    }

    /// Whether user verification (PIN) succeeds; off: requests that need it
    /// fail with `pin_required`.
    pub fn set_verify(&self, ok: bool) {
        *self.verify.lock() = ok;
    }

    /// Creates a credential (CTAP2 make credential).
    pub fn make_credential(&self, req: &SkMakeCredentialRequest) -> Result<SkCredential, SkError> {
        if let Behavior::Fail(code) = &*self.behavior.lock() {
            return Err(SkError::of(*code));
        }
        if req.require_verification && !*self.verify.lock() {
            return Err(SkError::of(SkErrorCode::PinRequired));
        }
        let mut rng = rand::rng();
        let mut handle = MAGIC.to_vec();
        let cose = match req.algorithm {
            SkAlgorithm::Ed25519 => {
                let kp = Ed25519Keypair::random(&mut rng);
                handle.push(1);
                handle.extend_from_slice(&rp8(&req.application));
                handle.extend_from_slice(&kp.private.to_bytes());
                handle.extend_from_slice(&kp.public.0);
                cose_map(vec![
                    (1, cbor::Value::Int(1)),
                    (3, cbor::Value::Int(-8)),
                    (-1, cbor::Value::Int(6)),
                    (-2, cbor::Value::Bytes(kp.public.0.to_vec())),
                ])
            }
            SkAlgorithm::EcdsaP256 => {
                let kp = EcdsaKeypair::random(&mut rng, EcdsaCurve::NistP256)
                    .map_err(|e| SkError::new(SkErrorCode::Failed, e.to_string()))?;
                let public = kp.public_key_bytes().to_vec();
                handle.push(2);
                handle.extend_from_slice(&rp8(&req.application));
                handle.extend_from_slice(kp.private_key_bytes());
                handle.extend_from_slice(&public);
                cose_map(vec![
                    (1, cbor::Value::Int(2)),
                    (3, cbor::Value::Int(-7)),
                    (-1, cbor::Value::Int(1)),
                    (-2, cbor::Value::Bytes(public[1..33].to_vec())),
                    (-3, cbor::Value::Bytes(public[33..].to_vec())),
                ])
            }
        };
        let mut flags = FLAG_USER_PRESENCE;
        if req.require_verification {
            flags |= FLAG_USER_VERIFICATION;
        }
        let counter = self.counter.fetch_add(1, Ordering::SeqCst);
        let auth = make_auth_data(&req.application, flags, counter, Some((&handle, &cose)));
        if req.resident {
            let mut list = self.resident.lock();
            list.retain(|c| !(c.application == req.application && c.user_id == req.user_id));
            list.push(SkResidentCredential {
                application: req.application.clone(),
                credential_id: handle,
                public_key_cose: cose,
                user_id: req.user_id.clone(),
                user_name: Some(req.user_name.clone()),
            });
        }
        // Like a real device: an attestation object ("none" format).
        let mut obj = Vec::new();
        cbor::encode(
            &cbor::Value::Map(vec![
                (
                    cbor::Value::Text("fmt".into()),
                    cbor::Value::Text("none".into()),
                ),
                (
                    cbor::Value::Text("attStmt".into()),
                    cbor::Value::Map(vec![]),
                ),
                (
                    cbor::Value::Text("authData".into()),
                    cbor::Value::Bytes(auth.clone()),
                ),
            ]),
            &mut obj,
        );
        Ok(SkCredential {
            authenticator_data: auth,
            attestation_object: obj,
        })
    }

    /// Resident credentials of applications starting with `prefix`.
    pub fn list_resident(&self, prefix: &str) -> Vec<SkResidentCredential> {
        self.resident
            .lock()
            .iter()
            .filter(|c| c.application.starts_with(prefix))
            .cloned()
            .collect()
    }

    /// Signs (CTAP2 get assertion), synchronously.
    pub fn sign_now(&self, req: &SkSignRequest) -> Result<SkAssertion, SkError> {
        self.seen.lock().push(req.clone());
        let behavior = self.behavior.lock().clone();
        if let Behavior::Fail(code) = behavior {
            return Err(SkError::of(code));
        }
        let key =
            decode_handle(&req.key_handle).ok_or_else(|| SkError::of(SkErrorCode::NotFound))?;
        if key.rp8 != rp8(&req.application) {
            return Err(SkError::of(SkErrorCode::NotFound));
        }
        if key.algorithm != req.algorithm {
            return Err(SkError::of(SkErrorCode::NotFound));
        }
        let mut flags = 0u8;
        if req.require_presence && behavior != Behavior::NoPresence {
            flags |= FLAG_USER_PRESENCE;
        }
        if req.require_verification {
            if !*self.verify.lock() {
                return Err(SkError::of(SkErrorCode::PinRequired));
            }
            flags |= FLAG_USER_VERIFICATION;
        }
        let counter = self.counter.fetch_add(1, Ordering::SeqCst);
        let mut data = make_auth_data(&req.application, flags, counter, None);
        data.extend_from_slice(&req.client_data_hash);
        let keypair = if behavior == Behavior::WrongKey {
            match key.algorithm {
                SkAlgorithm::Ed25519 => {
                    KeypairData::Ed25519(Ed25519Keypair::random(&mut rand::rng()))
                }
                SkAlgorithm::EcdsaP256 => KeypairData::Ecdsa(
                    EcdsaKeypair::random(&mut rand::rng(), EcdsaCurve::NistP256)
                        .map_err(|e| SkError::new(SkErrorCode::Failed, e.to_string()))?,
                ),
            }
        } else {
            key.keypair
        };
        let sig = keypair
            .try_sign(&data)
            .map_err(|e| SkError::new(SkErrorCode::Failed, e.to_string()))?;
        let signature = match sig.algorithm() {
            Algorithm::Ed25519 => sig.as_bytes().to_vec(),
            _ => ecdsa_der_from_ssh(sig.as_bytes())
                .ok_or_else(|| SkError::new(SkErrorCode::Failed, "bad ECDSA signature"))?,
        };
        Ok(SkAssertion {
            flags,
            counter,
            signature,
        })
    }
}

fn cose_map(items: Vec<(i64, cbor::Value)>) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::encode(
        &cbor::Value::Map(
            items
                .into_iter()
                .map(|(k, v)| (cbor::Value::Int(k), v))
                .collect(),
        ),
        &mut out,
    );
    out
}

#[async_trait]
impl SecurityKeySigner for SoftAuthenticator {
    async fn sign(&self, request: SkSignRequest) -> Result<SkAssertion, SkError> {
        let delay = *self.delay.lock();
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        self.sign_now(&request)
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;

    fn options(alg: SkAlgorithm) -> SkKeyOptions {
        SkKeyOptions {
            algorithm: alg,
            application: None,
            user: None,
            resident: false,
            verify_required: false,
            no_touch_required: false,
            device: Some("Soft".into()),
        }
    }

    #[tokio::test]
    async fn generate_sign_verify_both_algorithms() {
        let auth = SoftAuthenticator::new();
        for alg in [SkAlgorithm::Ed25519, SkAlgorithm::EcdsaP256] {
            let req = make_credential_request(&options(alg)).unwrap();
            let cred = auth.make_credential(&req).unwrap();
            // From the authenticator data and from the attestation object.
            let m = key_from_credential(&req, &cred, "me@test").unwrap();
            let m2 = key_from_credential(
                &req,
                &SkCredential {
                    authenticator_data: vec![],
                    attestation_object: cred.attestation_object.clone(),
                },
                "me@test",
            )
            .unwrap();
            assert_eq!(m.fingerprint, m2.fingerprint);
            assert_eq!(m.algorithm, alg.ssh_name());
            assert!(m.public_openssh.starts_with(alg.ssh_name()));
            let info = m.security_key.clone().unwrap();
            assert!(info.touch_required && !info.resident && !info.verify_required);
            assert_eq!(info.device.as_deref(), Some("Soft"));
            // The private file reads back (key handle, flags, application).
            assert!(is_security_key(&m.private_openssh));
            let sk = parse_private(&m.private_openssh, None).unwrap().unwrap();
            assert_eq!(sk.fingerprint(), m.fingerprint);
            assert_eq!(sk.application, "ssh:");
            assert_eq!(sk.flags, FLAG_USER_PRESENCE);
            // The import path recognizes it as well.
            let imported = crate::keys::import_private(&m.private_openssh, None).unwrap();
            assert_eq!(imported.security_key.unwrap().application, "ssh:");
            // COSE of the public key is what the device returned.
            assert!(cose_of(&sk.public).is_some());
            // Sign and verify.
            let msg = b"session id + userauth request".to_vec();
            let blob = sign(&sk, &auth, msg.clone(), SkContext::default())
                .await
                .unwrap();
            let sig = russh::keys::ssh_key::Signature::try_from(blob.as_slice()).unwrap();
            assert_eq!(sig.algorithm(), alg.ssh_algorithm());
            sk.public.key_data().verify(&msg, &sig).unwrap();
            // Another message does not verify.
            assert!(sk.public.key_data().verify(b"other", &sig).is_err());
            // Wrong key, no presence, failures.
            auth.set_behavior(Behavior::WrongKey);
            let e = sign(&sk, &auth, msg.clone(), SkContext::default())
                .await
                .unwrap_err();
            assert_eq!(e.code, SkErrorCode::WrongKey);
            auth.set_behavior(Behavior::NoPresence);
            let e = sign(&sk, &auth, msg.clone(), SkContext::default())
                .await
                .unwrap_err();
            assert_eq!(e.code, SkErrorCode::Failed);
            auth.set_behavior(Behavior::Fail(SkErrorCode::Cancelled));
            let e = sign(&sk, &auth, msg.clone(), SkContext::default())
                .await
                .unwrap_err();
            assert_eq!(e.code, SkErrorCode::Cancelled);
            auth.set_behavior(Behavior::Sign);
        }
    }

    #[tokio::test]
    async fn flags_resident_and_verification() {
        let auth = SoftAuthenticator::new();
        let mut o = options(SkAlgorithm::EcdsaP256);
        o.resident = true;
        o.verify_required = true;
        o.no_touch_required = true;
        o.user = Some("ops".into());
        let req = make_credential_request(&o).unwrap();
        let m = key_from_credential(&req, &auth.make_credential(&req).unwrap(), "c").unwrap();
        let info = m.security_key.clone().unwrap();
        assert!(info.resident && info.verify_required && !info.touch_required);
        assert_eq!(info.user.as_deref(), Some("ops"));
        let sk = parse_private(&m.private_openssh, None).unwrap().unwrap();
        let r = sk.sign_request(b"x".to_vec(), SkContext::default());
        assert!(!r.require_presence && r.require_verification);
        sign(&sk, &auth, b"x".to_vec(), SkContext::default())
            .await
            .unwrap();
        auth.set_verify(false);
        let e = sign(&sk, &auth, b"x".to_vec(), SkContext::default())
            .await
            .unwrap_err();
        assert_eq!(e.code, SkErrorCode::PinRequired);
        auth.set_verify(true);
        // Resident credentials from the device become the same key.
        let list = auth.list_resident("ssh:");
        assert_eq!(list.len(), 1);
        let r = key_from_resident(&list[0], true, Some("Soft".into()), "c").unwrap();
        assert_eq!(r.fingerprint, m.fingerprint);
        assert_eq!(r.security_key.unwrap().user.as_deref(), Some("ops"));
        // A credential for another application is refused.
        let mut other = req.clone();
        other.application = "ssh:other".into();
        let cred = auth.make_credential(&req).unwrap();
        assert_eq!(
            key_from_credential(&other, &cred, "c").unwrap_err().code,
            SkErrorCode::Invalid
        );
        // An encrypted sk file needs its passphrase.
        let mut key = russh::keys::ssh_key::PrivateKey::from_openssh(&m.private_openssh).unwrap();
        key = key.encrypt(&mut rand::rng(), "pw").unwrap();
        let pem = key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();
        assert!(parse_private(&pem, None).is_err());
        assert_eq!(
            parse_private(&pem, Some("pw")).unwrap().unwrap().key_handle,
            sk.key_handle
        );
        // Regular keys are not security keys.
        let reg = crate::keys::generate(crate::keys::KeyType::Ed25519, "x", None).unwrap();
        assert!(parse_private(&reg.private_openssh, None).unwrap().is_none());
        assert!(reg.security_key.is_none());
    }
}

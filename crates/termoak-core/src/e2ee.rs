//! End-to-end encrypted vaults (0.7 phase 5a, docs/E2EE-SSO-AUDIT.md §2).
//!
//! The server stores what this module produces and can open none of it:
//!
//! - **User key**: one X25519 key pair per user. The public key is on the
//!   server; the private key reaches a device only through the user:
//!   their E2EE passphrase (Argon2id), their recovery key (256 random bits
//!   shown as a 24-word BIP39 phrase, HKDF) or another unlocked device
//!   (pairing, HPKE to the new device's ephemeral key, confirmed with a
//!   six-digit code).
//! - **Vault key** (VK): 32 random bytes per vault and version, wrapped for
//!   every member who may read secrets with HPKE (RFC 9180, base mode,
//!   DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM).
//! - **Secrets**: the JSON secret of an entity sealed with AES-256-GCM under
//!   the VK, bound to the vault, the key version, the kind and the id.
//!
//! Only standard primitives (RustCrypto: x25519-dalek, hkdf, sha2, aes-gcm,
//! argon2). HPKE follows RFC 9180 §4–§5 and is checked against its test
//! vector A.1.1; the whole format is pinned by `tests/e2ee_vectors.json`,
//! which the web's implementation (WebCrypto) must pass too.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::Id;
use crate::crypto::random_bytes;
use crate::error::{CoreError, Result, codes};
use crate::model::EntityKind;

/// Algorithm of the user wraps of a vault key (`vault_key_wraps.alg`).
pub const WRAP_ALG: &str = "hpke-x25519-sha256-aes256gcm-v1";
/// Algorithm of the user keys (`user_keys.alg`).
pub const USER_KEY_ALG: &str = "x25519";
/// Format version byte of every blob of this module.
const BLOB_VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// HPKE `info` of the vault key wraps.
const INFO_VAULT_KEY: &[u8] = b"termoak e2ee v1 vault key";
/// HPKE `info` of the pairing hand-over (user key to a new device).
const INFO_PAIRING: &[u8] = b"termoak e2ee v1 pairing";
/// HKDF salt of the recovery key.
const RECOVERY_SALT: &[u8] = b"termoak:e2ee:recovery:v1";

/// Argon2id defaults for the E2EE passphrase (RFC 9106 §4, second
/// recommended option: 64 MiB, 3 passes, 1 lane).
pub const ARGON2_M_KIB: u32 = 65_536;
pub const ARGON2_T: u32 = 3;
pub const ARGON2_P: u32 = 1;
/// Lowest Argon2id cost accepted when opening (a server cannot downgrade
/// the parameters to make a stolen seal cheap to attack).
const ARGON2_MIN_M_KIB: u32 = 19_456;

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn unb64(field: &str, s: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(s.trim())
        .map_err(|_| CoreError::Invalid(format!("{field} is not base64")))
}

fn decrypt_failed() -> CoreError {
    CoreError::vault(
        codes::E2EE_DECRYPT_FAILED,
        "could not decrypt (wrong key or tampered data)",
    )
}

// ---------------------------------------------------------------------------
// HPKE (RFC 9180), base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256
// ---------------------------------------------------------------------------

mod hpke {
    use super::*;

    pub(super) const KEM_ID: u16 = 0x0020;
    pub(super) const KDF_ID: u16 = 0x0001;
    pub(super) const AEAD_AES128GCM: u16 = 0x0001;
    pub(super) const AEAD_AES256GCM: u16 = 0x0002;
    const VERSION_LABEL: &[u8] = b"HPKE-v1";

    fn kem_suite() -> Vec<u8> {
        let mut s = b"KEM".to_vec();
        s.extend_from_slice(&KEM_ID.to_be_bytes());
        s
    }

    fn hpke_suite(aead: u16) -> Vec<u8> {
        let mut s = b"HPKE".to_vec();
        s.extend_from_slice(&KEM_ID.to_be_bytes());
        s.extend_from_slice(&KDF_ID.to_be_bytes());
        s.extend_from_slice(&aead.to_be_bytes());
        s
    }

    /// `LabeledExtract(salt, label, ikm)`.
    fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut labeled = Zeroizing::new(Vec::with_capacity(
            7 + suite.len() + label.len() + ikm.len(),
        ));
        labeled.extend_from_slice(VERSION_LABEL);
        labeled.extend_from_slice(suite);
        labeled.extend_from_slice(label);
        labeled.extend_from_slice(ikm);
        let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &labeled);
        Zeroizing::new(prk.to_vec())
    }

    /// `LabeledExpand(prk, label, info, L)`.
    fn labeled_expand(
        suite: &[u8],
        prk: &[u8],
        label: &[u8],
        info: &[u8],
        len: usize,
    ) -> Zeroizing<Vec<u8>> {
        let mut labeled = Vec::with_capacity(9 + suite.len() + label.len() + info.len());
        labeled.extend_from_slice(&(len as u16).to_be_bytes());
        labeled.extend_from_slice(VERSION_LABEL);
        labeled.extend_from_slice(suite);
        labeled.extend_from_slice(label);
        labeled.extend_from_slice(info);
        let hk = Hkdf::<Sha256>::from_prk(prk).expect("the PRK is one SHA-256 output");
        let mut out = Zeroizing::new(vec![0u8; len]);
        hk.expand(&labeled, &mut out)
            .expect("HPKE lengths are far below the HKDF limit");
        out
    }

    /// `ExtractAndExpand(dh, kem_context)` of DHKEM.
    fn extract_and_expand(dh: &[u8], kem_context: &[u8]) -> Zeroizing<Vec<u8>> {
        let suite = kem_suite();
        let eae_prk = labeled_extract(&suite, b"", b"eae_prk", dh);
        labeled_expand(&suite, &eae_prk, b"shared_secret", kem_context, 32)
    }

    fn dh(sk: &StaticSecret, pk: &PublicKey) -> Result<Zeroizing<[u8; 32]>> {
        let shared = sk.diffie_hellman(pk);
        // RFC 9180 §7.1.4: an all-zero X25519 output must be rejected.
        if !shared.was_contributory() {
            return Err(CoreError::Crypto("invalid X25519 public key".into()));
        }
        Ok(Zeroizing::new(shared.to_bytes()))
    }

    /// `Encap(pkR)` with the ephemeral key `sk_e` → (shared_secret, enc).
    pub(super) fn encap(
        pk_r: &PublicKey,
        sk_e: &StaticSecret,
    ) -> Result<(Zeroizing<Vec<u8>>, [u8; 32])> {
        let pk_e = PublicKey::from(sk_e);
        let dh = dh(sk_e, pk_r)?;
        let mut kem_context = pk_e.as_bytes().to_vec();
        kem_context.extend_from_slice(pk_r.as_bytes());
        Ok((
            extract_and_expand(dh.as_slice(), &kem_context),
            *pk_e.as_bytes(),
        ))
    }

    /// `Decap(enc, skR)` → shared_secret.
    pub(super) fn decap(enc: &[u8; 32], sk_r: &StaticSecret) -> Result<Zeroizing<Vec<u8>>> {
        let pk_e = PublicKey::from(*enc);
        let pk_r = PublicKey::from(sk_r);
        let dh = dh(sk_r, &pk_e)?;
        let mut kem_context = enc.to_vec();
        kem_context.extend_from_slice(pk_r.as_bytes());
        Ok(extract_and_expand(dh.as_slice(), &kem_context))
    }

    /// `KeySchedule(mode_base, shared_secret, info, "", "")` → (key, base_nonce).
    pub(super) fn key_schedule(
        aead: u16,
        shared_secret: &[u8],
        info: &[u8],
    ) -> (Zeroizing<Vec<u8>>, [u8; NONCE_LEN]) {
        let suite = hpke_suite(aead);
        let psk_id_hash = labeled_extract(&suite, b"", b"psk_id_hash", b"");
        let info_hash = labeled_extract(&suite, b"", b"info_hash", info);
        let mut context = vec![0u8]; // mode_base
        context.extend_from_slice(&psk_id_hash);
        context.extend_from_slice(&info_hash);
        let secret = labeled_extract(&suite, shared_secret, b"secret", b"");
        let nk = if aead == AEAD_AES128GCM { 16 } else { 32 };
        let key = labeled_expand(&suite, &secret, b"key", &context, nk);
        let nonce = labeled_expand(&suite, &secret, b"base_nonce", &context, NONCE_LEN);
        let mut base_nonce = [0u8; NONCE_LEN];
        base_nonce.copy_from_slice(&nonce);
        (key, base_nonce)
    }

    fn aead_seal(
        aead: u16,
        key: &[u8],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        pt: &[u8],
    ) -> Result<Vec<u8>> {
        let payload = Payload { msg: pt, aad };
        let nonce = Nonce::from(*nonce);
        let out = if aead == AEAD_AES128GCM {
            Aes128Gcm::new_from_slice(key)
                .map_err(|_| CoreError::Crypto("bad key".into()))?
                .encrypt(&nonce, payload)
        } else {
            Aes256Gcm::new_from_slice(key)
                .map_err(|_| CoreError::Crypto("bad key".into()))?
                .encrypt(&nonce, payload)
        };
        out.map_err(|_| CoreError::Crypto("encryption failed".into()))
    }

    fn aead_open(
        aead: u16,
        key: &[u8],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let payload = Payload { msg: ct, aad };
        let nonce = Nonce::from(*nonce);
        let out = if aead == AEAD_AES128GCM {
            Aes128Gcm::new_from_slice(key)
                .map_err(|_| CoreError::Crypto("bad key".into()))?
                .decrypt(&nonce, payload)
        } else {
            Aes256Gcm::new_from_slice(key)
                .map_err(|_| CoreError::Crypto("bad key".into()))?
                .decrypt(&nonce, payload)
        };
        out.map(Zeroizing::new).map_err(|_| decrypt_failed())
    }

    /// Single-shot `SealBase` (sequence number 0) → (enc, ciphertext).
    pub(super) fn seal_base(
        aead: u16,
        pk_r: &PublicKey,
        info: &[u8],
        aad: &[u8],
        pt: &[u8],
        sk_e: &StaticSecret,
    ) -> Result<([u8; 32], Vec<u8>)> {
        let (shared, enc) = encap(pk_r, sk_e)?;
        let (key, nonce) = key_schedule(aead, &shared, info);
        Ok((enc, aead_seal(aead, &key, &nonce, aad, pt)?))
    }

    /// Single-shot `OpenBase` (sequence number 0).
    pub(super) fn open_base(
        aead: u16,
        enc: &[u8; 32],
        sk_r: &StaticSecret,
        info: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let shared = decap(enc, sk_r)?;
        let (key, nonce) = key_schedule(aead, &shared, info);
        aead_open(aead, &key, &nonce, aad, ct)
    }
}

/// HPKE seal to `recipient` as one blob: `[1][enc 32][ciphertext + tag]`.
fn hpke_blob(
    recipient: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
    sk_e: Option<&[u8; 32]>,
) -> Result<Vec<u8>> {
    let sk_e = match sk_e {
        Some(b) => StaticSecret::from(*b),
        None => StaticSecret::from(random_bytes::<32>()),
    };
    let (enc, ct) = hpke::seal_base(
        hpke::AEAD_AES256GCM,
        &PublicKey::from(*recipient),
        info,
        aad,
        pt,
        &sk_e,
    )?;
    let mut out = Vec::with_capacity(1 + 32 + ct.len());
    out.push(BLOB_VERSION);
    out.extend_from_slice(&enc);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn hpke_blob_open(
    blob: &[u8],
    secret: &StaticSecret,
    info: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < 1 + 32 + TAG_LEN || blob[0] != BLOB_VERSION {
        return Err(decrypt_failed());
    }
    let mut enc = [0u8; 32];
    enc.copy_from_slice(&blob[1..33]);
    hpke::open_base(hpke::AEAD_AES256GCM, &enc, secret, info, aad, &blob[33..])
}

/// AES-256-GCM as one blob: `[1][nonce 12][ciphertext + tag]`.
fn aes_blob(
    key: &[u8; 32],
    aad: &[u8],
    pt: &[u8],
    nonce: Option<&[u8; NONCE_LEN]>,
) -> Result<Vec<u8>> {
    let nonce = nonce.copied().unwrap_or_else(random_bytes::<NONCE_LEN>);
    let ct = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CoreError::Crypto("bad key".into()))?
        .encrypt(&Nonce::from(nonce), Payload { msg: pt, aad })
        .map_err(|_| CoreError::Crypto("encryption failed".into()))?;
    let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
    out.push(BLOB_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn aes_blob_open(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < 1 + NONCE_LEN + TAG_LEN || blob[0] != BLOB_VERSION {
        return Err(decrypt_failed());
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob[1..1 + NONCE_LEN]);
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| CoreError::Crypto("bad key".into()))?
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &blob[1 + NONCE_LEN..],
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| decrypt_failed())
}

// ---------------------------------------------------------------------------
// User keys
// ---------------------------------------------------------------------------

/// A user's X25519 key pair (the private half wiped on drop).
#[derive(Clone)]
pub struct UserKeyPair {
    /// `user_keys.id` (chosen by the client that creates the key).
    pub id: Id,
    secret: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl std::fmt::Debug for UserKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserKeyPair")
            .field("id", &self.id)
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

impl UserKeyPair {
    /// A new random key pair with a new id.
    pub fn generate() -> Self {
        Self::from_private(crate::new_id(), random_bytes::<32>())
    }

    /// From a stored private key.
    pub fn from_private(id: Id, private: [u8; 32]) -> Self {
        let secret = StaticSecret::from(private);
        let public = *PublicKey::from(&secret).as_bytes();
        Self {
            id,
            secret: Zeroizing::new(secret.to_bytes()),
            public,
        }
    }

    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }

    pub fn public_b64(&self) -> String {
        b64(&self.public)
    }

    /// The private key (to store it sealed with the device key).
    pub fn private_bytes(&self) -> Zeroizing<[u8; 32]> {
        self.secret.clone()
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public)
    }

    fn static_secret(&self) -> StaticSecret {
        StaticSecret::from(*self.secret)
    }
}

/// Fingerprint of a user public key: the first 16 bytes of its SHA-256 in
/// eight groups of four hex digits (`3f2a 9c01 …`). Members compare it to
/// check that the server handed out the right key.
pub fn fingerprint(public: &[u8]) -> String {
    let digest = Sha256::digest(public);
    digest[..16]
        .chunks(2)
        .map(hex::encode)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Parses a base64 X25519 public key.
pub fn parse_public_key(b64_key: &str) -> Result<[u8; 32]> {
    unb64("public_key", b64_key)?
        .try_into()
        .map_err(|_| CoreError::Invalid("public_key must be 32 bytes".into()))
}

// ---------------------------------------------------------------------------
// Recovery key
// ---------------------------------------------------------------------------

/// Words of a recovery phrase: 256 bits of entropy + an 8-bit BIP39
/// checksum = 264 bits = 24 words of 11 bits.
pub const RECOVERY_WORDS: usize = 24;

/// The BIP39 English word list, byte for byte `bip-0039/english.txt` of
/// github.com/bitcoin/bips (2048 words, sorted, unique in their first four
/// letters). Its SHA-256 is [`BIP39_ENGLISH_SHA256`] (checked by a test).
const BIP39_ENGLISH: &str = include_str!("bip39_english.txt");
/// The well-known SHA-256 of `bip-0039/english.txt`.
pub const BIP39_ENGLISH_SHA256: &str =
    "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

/// The 2048 words of the BIP39 English list, in order.
pub fn recovery_wordlist() -> &'static [&'static str] {
    static WORDS: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    WORDS.get_or_init(|| BIP39_ENGLISH.lines().filter(|w| !w.is_empty()).collect())
}

/// Why a typed recovery phrase was refused (`detail.reason` of
/// `e2ee_recovery_key_invalid`).
pub mod recovery_reason {
    /// Not 24 words (`detail.words` = how many were found).
    pub const WORD_COUNT: &str = "word_count";
    /// A word is not in the BIP39 English list (`detail.word` = its
    /// position, 1-based).
    pub const UNKNOWN_WORD: &str = "unknown_word";
    /// Every word is valid but the BIP39 checksum does not match (a word
    /// mistyped into another valid word, or two words swapped).
    pub const CHECKSUM: &str = "checksum";
    /// A recovery key of the first format (56 base32 characters, before
    /// v0.7.0-next.11): no longer accepted.
    pub const OLD_FORMAT: &str = "old_format";
}

/// Index of a typed word: the word itself, or (four letters or more) the
/// beginning of exactly one word (BIP39 words are unique in their first four
/// letters, so "aban" is "abandon").
fn recovery_word_index(token: &str) -> Option<usize> {
    let words = recovery_wordlist();
    if let Ok(i) = words.binary_search(&token) {
        return Some(i);
    }
    if token.len() < 4 {
        return None;
    }
    let start = words.partition_point(|w| *w < token);
    let mut found = words[start..].iter().take_while(|w| w.starts_with(token));
    match (found.next(), found.next()) {
        (Some(_), None) => Some(start),
        _ => None,
    }
}

/// The recovery key: 256 random bits shown once as a 24-word BIP39 English
/// phrase (the 256 bits are the BIP39 entropy, followed by the first 8 bits
/// of their SHA-256 as the checksum). The 256 bits themselves are the HKDF
/// input of the key that seals the private key (`kek`): the phrase is only
/// their encoding, BIP39's PBKDF2 seed (a wallet thing) is not used.
#[derive(Clone)]
pub struct RecoveryKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey(***)")
    }
}

impl RecoveryKey {
    pub fn generate() -> Self {
        Self(Zeroizing::new(random_bytes::<32>()))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The 24 words, in order.
    pub fn words(&self) -> Vec<&'static str> {
        let list = recovery_wordlist();
        let mut bits = Zeroizing::new([0u8; 33]);
        bits[..32].copy_from_slice(self.0.as_slice());
        bits[32] = Sha256::digest(self.0.as_slice())[0];
        let mut out = Vec::with_capacity(RECOVERY_WORDS);
        for w in 0..RECOVERY_WORDS {
            let mut index = 0usize;
            for b in w * 11..w * 11 + 11 {
                let bit = (bits[b / 8] >> (7 - b % 8)) & 1;
                index = (index << 1) | bit as usize;
            }
            out.push(list[index]);
        }
        out
    }

    /// The phrase: 24 lowercase words separated by single spaces (apps show
    /// them numbered, in columns).
    pub fn display(&self) -> Zeroizing<String> {
        Zeroizing::new(self.words().join(" "))
    }

    /// Parses what the person typed: case, spaces, line breaks, numbering
    /// and punctuation do not matter, and every word may be shortened to its
    /// first four letters (or more). Errors are `e2ee_recovery_key_invalid`
    /// with `detail.reason` ([`recovery_reason`]).
    pub fn parse(text: &str) -> Result<Self> {
        let invalid = |reason: &str, message: &str, extra: serde_json::Value| {
            let mut detail = serde_json::json!({ "reason": reason });
            if let (Some(d), Some(e)) = (detail.as_object_mut(), extra.as_object()) {
                d.extend(e.clone());
            }
            CoreError::vault_detail(codes::E2EE_RECOVERY_KEY_INVALID, message, detail)
        };
        // The first format: 56 base32 characters in groups of four.
        let compact: Zeroizing<String> = Zeroizing::new(
            text.chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .collect(),
        );
        if compact.len() == 56
            && compact
                .chars()
                .all(|c| matches!(c.to_ascii_uppercase(), 'A'..='Z' | '2'..='7'))
        {
            return Err(invalid(
                recovery_reason::OLD_FORMAT,
                "this is a recovery key of the old format: recovery keys are now 24 words",
                serde_json::Value::Null,
            ));
        }
        let lower: Zeroizing<String> = Zeroizing::new(text.to_lowercase());
        let tokens: Vec<&str> = lower
            .split(|c: char| !c.is_alphabetic())
            .filter(|t| !t.is_empty())
            .collect();
        if tokens.len() != RECOVERY_WORDS {
            return Err(invalid(
                recovery_reason::WORD_COUNT,
                &format!(
                    "a recovery phrase has {RECOVERY_WORDS} words ({} found)",
                    tokens.len()
                ),
                serde_json::json!({ "words": tokens.len() }),
            ));
        }
        let mut indices = Zeroizing::new([0usize; RECOVERY_WORDS]);
        for (i, t) in tokens.iter().enumerate() {
            indices[i] = recovery_word_index(t).ok_or_else(|| {
                invalid(
                    recovery_reason::UNKNOWN_WORD,
                    &format!("word {} is not a recovery phrase word", i + 1),
                    serde_json::json!({ "word": i + 1 }),
                )
            })?;
        }
        let mut bits = Zeroizing::new([0u8; 33]);
        for (w, index) in indices.iter().enumerate() {
            for k in 0..11 {
                if (index >> (10 - k)) & 1 == 1 {
                    let b = w * 11 + k;
                    bits[b / 8] |= 1 << (7 - b % 8);
                }
            }
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&bits[..32]);
        let key = Self::from_bytes(bytes);
        bytes.zeroize();
        if Sha256::digest(key.0.as_slice())[0] != bits[32] {
            return Err(invalid(
                recovery_reason::CHECKSUM,
                "the words do not form a valid recovery phrase (check for a mistyped or swapped word)",
                serde_json::Value::Null,
            ));
        }
        Ok(key)
    }

    fn kek(&self, user: Id, key_id: Id) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(RECOVERY_SALT), self.0.as_slice())
            .expand(format!("{user}:{key_id}").as_bytes(), out.as_mut())
            .expect("32 bytes");
        out
    }
}

// ---------------------------------------------------------------------------
// Sealed copies of the user's private key (stored on the server)
// ---------------------------------------------------------------------------

/// How a copy of the private key is sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum SealKind {
    /// The user's E2EE passphrase (Argon2id). Never the login password:
    /// the server sees that one.
    Passphrase,
    /// The recovery key.
    Recovery,
}

impl SealKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SealKind::Passphrase => "passphrase",
            SealKind::Recovery => "recovery",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "passphrase" => Some(SealKind::Passphrase),
            "recovery" => Some(SealKind::Recovery),
            _ => None,
        }
    }
}

/// Argon2id parameters stored with a passphrase seal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct KdfParams {
    /// `argon2id`.
    pub alg: String,
    /// Memory in KiB.
    pub m: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
    /// 16 random bytes, base64.
    pub salt: String,
}

impl KdfParams {
    pub fn new_random() -> Self {
        Self {
            alg: "argon2id".into(),
            m: ARGON2_M_KIB,
            t: ARGON2_T,
            p: ARGON2_P,
            salt: b64(&random_bytes::<16>()),
        }
    }

    fn derive(&self, passphrase: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        if self.alg != "argon2id" {
            return Err(CoreError::Invalid(format!("unknown KDF {}", self.alg)));
        }
        if self.m < ARGON2_MIN_M_KIB
            || self.t < 1
            || self.p < 1
            || self.m > 4 * 1024 * 1024
            || self.t > 16
            || self.p > 16
        {
            return Err(CoreError::Invalid(
                "unacceptable Argon2id parameters".into(),
            ));
        }
        let salt = unb64("salt", &self.salt)?;
        if salt.len() < 16 {
            return Err(CoreError::Invalid("the Argon2id salt is too short".into()));
        }
        let params = Params::new(self.m, self.t, self.p, Some(32))
            .map_err(|e| CoreError::Crypto(format!("argon2: {e}")))?;
        let mut out = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(passphrase, &salt, out.as_mut())
            .map_err(|e| CoreError::Crypto(format!("argon2: {e}")))?;
        Ok(out)
    }
}

/// A sealed copy of a user private key, as the server stores it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct KeySeal {
    pub kind: SealKind,
    /// Argon2id parameters (passphrase only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<KdfParams>,
    /// `[1][nonce 12][AES-256-GCM(private key) + tag]`, base64.
    pub sealed: String,
}

fn seal_aad(user: Id, key_id: Id, kind: SealKind) -> Vec<u8> {
    format!("termoak:e2ee:uk:{user}:{key_id}:{}", kind.as_str()).into_bytes()
}

/// Seals `key` with a passphrase (new random salt, default cost).
pub fn seal_with_passphrase(user: Id, key: &UserKeyPair, passphrase: &str) -> Result<KeySeal> {
    seal_with_passphrase_params(user, key, passphrase, KdfParams::new_random(), None)
}

fn seal_with_passphrase_params(
    user: Id,
    key: &UserKeyPair,
    passphrase: &str,
    params: KdfParams,
    nonce: Option<&[u8; NONCE_LEN]>,
) -> Result<KeySeal> {
    if passphrase.chars().count() < 8 {
        return Err(CoreError::vault(
            codes::E2EE_PASSPHRASE_TOO_SHORT,
            "the passphrase needs at least 8 characters",
        ));
    }
    let kek = params.derive(passphrase.as_bytes())?;
    let blob = aes_blob(
        &kek,
        &seal_aad(user, key.id, SealKind::Passphrase),
        key.secret.as_slice(),
        nonce,
    )?;
    Ok(KeySeal {
        kind: SealKind::Passphrase,
        params: Some(params),
        sealed: b64(&blob),
    })
}

/// Seals `key` with the recovery key.
pub fn seal_with_recovery(user: Id, key: &UserKeyPair, recovery: &RecoveryKey) -> Result<KeySeal> {
    seal_with_recovery_nonce(user, key, recovery, None)
}

fn seal_with_recovery_nonce(
    user: Id,
    key: &UserKeyPair,
    recovery: &RecoveryKey,
    nonce: Option<&[u8; NONCE_LEN]>,
) -> Result<KeySeal> {
    let kek = recovery.kek(user, key.id);
    let blob = aes_blob(
        &kek,
        &seal_aad(user, key.id, SealKind::Recovery),
        key.secret.as_slice(),
        nonce,
    )?;
    Ok(KeySeal {
        kind: SealKind::Recovery,
        params: None,
        sealed: b64(&blob),
    })
}

fn private_from(plain: &[u8]) -> Result<[u8; 32]> {
    plain
        .try_into()
        .map_err(|_| CoreError::Crypto("the sealed private key is not 32 bytes".into()))
}

/// Opens a passphrase seal of the user key `key_id`; checks the result
/// against the published public key when given.
pub fn open_with_passphrase(
    user: Id,
    key_id: Id,
    seal: &KeySeal,
    passphrase: &str,
    expected_public: Option<&[u8; 32]>,
) -> Result<UserKeyPair> {
    let params = seal
        .params
        .as_ref()
        .filter(|_| seal.kind == SealKind::Passphrase)
        .ok_or_else(|| CoreError::Invalid("not a passphrase seal".into()))?;
    let kek = params.derive(passphrase.as_bytes())?;
    let plain = aes_blob_open(
        &kek,
        &seal_aad(user, key_id, SealKind::Passphrase),
        &unb64("sealed", &seal.sealed)?,
    )
    .map_err(|_| {
        CoreError::vault(
            codes::E2EE_PASSPHRASE_INVALID,
            "the E2EE passphrase is not correct",
        )
    })?;
    checked(key_id, private_from(&plain)?, expected_public)
}

/// Opens a recovery seal of the user key `key_id`.
pub fn open_with_recovery(
    user: Id,
    key_id: Id,
    seal: &KeySeal,
    recovery: &RecoveryKey,
    expected_public: Option<&[u8; 32]>,
) -> Result<UserKeyPair> {
    if seal.kind != SealKind::Recovery {
        return Err(CoreError::Invalid("not a recovery seal".into()));
    }
    let kek = recovery.kek(user, key_id);
    let plain = aes_blob_open(
        &kek,
        &seal_aad(user, key_id, SealKind::Recovery),
        &unb64("sealed", &seal.sealed)?,
    )
    .map_err(|_| {
        CoreError::vault(
            codes::E2EE_RECOVERY_KEY_INVALID,
            "this recovery key does not open your E2EE key",
        )
    })?;
    checked(key_id, private_from(&plain)?, expected_public)
}

fn checked(
    key_id: Id,
    private: [u8; 32],
    expected_public: Option<&[u8; 32]>,
) -> Result<UserKeyPair> {
    let pair = UserKeyPair::from_private(key_id, private);
    if let Some(expected) = expected_public
        && expected != pair.public()
    {
        // The seal opened but holds another key than the published one: a
        // server swapping keys. Refuse.
        return Err(CoreError::vault(
            codes::E2EE_KEY_MISMATCH,
            "the private key does not match your published public key",
        ));
    }
    Ok(pair)
}

// ---------------------------------------------------------------------------
// Vault keys
// ---------------------------------------------------------------------------

/// A vault key (wiped on drop).
#[derive(Clone)]
pub struct VaultKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultKey(***)")
    }
}

impl VaultKey {
    pub fn generate() -> Self {
        Self(Zeroizing::new(random_bytes::<32>()))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn wrap_aad(vault: Id, version: u32, user: Id, key_id: Id) -> Vec<u8> {
    format!("termoak:e2ee:vk:{vault}:{version}:{user}:{key_id}").into_bytes()
}

/// Wraps a vault key for a member's public key (base64 blob).
pub fn wrap_vault_key(
    vk: &VaultKey,
    vault: Id,
    version: u32,
    user: Id,
    key_id: Id,
    recipient: &[u8; 32],
) -> Result<String> {
    wrap_vault_key_with(vk, vault, version, user, key_id, recipient, None)
}

fn wrap_vault_key_with(
    vk: &VaultKey,
    vault: Id,
    version: u32,
    user: Id,
    key_id: Id,
    recipient: &[u8; 32],
    sk_e: Option<&[u8; 32]>,
) -> Result<String> {
    Ok(b64(&hpke_blob(
        recipient,
        INFO_VAULT_KEY,
        &wrap_aad(vault, version, user, key_id),
        vk.as_bytes(),
        sk_e,
    )?))
}

/// Unwraps a vault key wrapped for `key`.
pub fn unwrap_vault_key(
    wrapped: &str,
    vault: Id,
    version: u32,
    user: Id,
    key: &UserKeyPair,
) -> Result<VaultKey> {
    let plain = hpke_blob_open(
        &unb64("wrapped", wrapped)?,
        &key.static_secret(),
        INFO_VAULT_KEY,
        &wrap_aad(vault, version, user, key.id),
    )?;
    let bytes: [u8; 32] = plain
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::Crypto("a vault key is 32 bytes".into()))?;
    Ok(VaultKey::from_bytes(bytes))
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

fn secret_aad(vault: Id, version: u32, kind: EntityKind, id: Id) -> Vec<u8> {
    format!(
        "termoak:e2ee:secret:{vault}:{version}:{}:{id}",
        kind.as_str()
    )
    .into_bytes()
}

/// Seals an entity's secret (its JSON) with the vault key (base64 blob).
pub fn encrypt_secret(
    vk: &VaultKey,
    vault: Id,
    version: u32,
    kind: EntityKind,
    id: Id,
    json: &[u8],
) -> Result<String> {
    Ok(b64(&aes_blob(
        vk.as_bytes(),
        &secret_aad(vault, version, kind, id),
        json,
        None,
    )?))
}

/// Opens a secret sealed by [`encrypt_secret`] (its JSON).
pub fn decrypt_secret(
    vk: &VaultKey,
    vault: Id,
    version: u32,
    kind: EntityKind,
    id: Id,
    blob: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    aes_blob_open(
        vk.as_bytes(),
        &secret_aad(vault, version, kind, id),
        &unb64("blob", blob)?,
    )
}

/// Checks the shape of a sealed secret from a client (the server cannot do
/// more): base64, version byte, nonce and tag present, bounded size.
pub fn check_sealed_blob(blob: &str) -> Result<Vec<u8>> {
    let raw = unb64("sealed.blob_b64", blob)?;
    if raw.len() < 1 + NONCE_LEN + TAG_LEN || raw[0] != BLOB_VERSION || raw.len() > 256 * 1024 {
        return Err(CoreError::Invalid(
            "sealed.blob_b64 is not a sealed secret".into(),
        ));
    }
    Ok(raw)
}

/// Checks the shape of a wrapped vault key from a client.
pub fn check_wrap_blob(wrapped: &str) -> Result<Vec<u8>> {
    let raw = unb64("wrapped", wrapped)?;
    if raw.len() != 1 + 32 + 32 + TAG_LEN || raw[0] != BLOB_VERSION {
        return Err(CoreError::Invalid(
            "wrapped is not a wrapped vault key".into(),
        ));
    }
    Ok(raw)
}

/// Checks the shape of a key seal from a client.
pub fn check_key_seal(seal: &KeySeal) -> Result<()> {
    let raw = unb64("sealed", &seal.sealed)?;
    if raw.len() != 1 + NONCE_LEN + 32 + TAG_LEN || raw[0] != BLOB_VERSION {
        return Err(CoreError::Invalid(
            "sealed is not a sealed private key".into(),
        ));
    }
    match (seal.kind, &seal.params) {
        (SealKind::Passphrase, Some(p)) => {
            if p.alg != "argon2id" || p.m < ARGON2_MIN_M_KIB || p.t < 1 || p.p < 1 {
                return Err(CoreError::Invalid(
                    "unacceptable Argon2id parameters".into(),
                ));
            }
            if unb64("params.salt", &p.salt)?.len() < 16 {
                return Err(CoreError::Invalid("the Argon2id salt is too short".into()));
            }
        }
        (SealKind::Passphrase, None) => {
            return Err(CoreError::Invalid("a passphrase seal needs params".into()));
        }
        (SealKind::Recovery, _) => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Pairing: handing the user key to a new device
// ---------------------------------------------------------------------------

/// The new device's ephemeral X25519 key for one pairing.
pub struct PairingKey {
    secret: StaticSecret,
    public: [u8; 32],
}

impl PairingKey {
    pub fn generate() -> Self {
        Self::from_private(random_bytes::<32>())
    }

    pub fn from_private(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = *PublicKey::from(&secret).as_bytes();
        Self { secret, public }
    }

    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }

    pub fn public_b64(&self) -> String {
        b64(&self.public)
    }

    pub fn private_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    /// Opens what the approving device sent (`pairing_seal`).
    pub fn open(&self, user: Id, pairing: Id, sealed: &str) -> Result<UserKeyPair> {
        let plain = hpke_blob_open(
            &unb64("sealed", sealed)?,
            &self.secret,
            INFO_PAIRING,
            &pairing_aad(user, pairing),
        )?;
        if plain.len() != 16 + 32 {
            return Err(CoreError::Crypto("unexpected pairing payload".into()));
        }
        let key_id =
            Id::from_slice(&plain[..16]).map_err(|_| CoreError::Crypto("bad key id".into()))?;
        Ok(UserKeyPair::from_private(
            key_id,
            private_from(&plain[16..])?,
        ))
    }
}

fn pairing_aad(user: Id, pairing: Id) -> Vec<u8> {
    format!("termoak:e2ee:pairing:{user}:{pairing}").into_bytes()
}

/// Seals the user key for a new device's pairing key (the approving
/// device does this after the user compared the codes).
pub fn pairing_seal(
    user: Id,
    pairing: Id,
    device_public: &[u8; 32],
    key: &UserKeyPair,
) -> Result<String> {
    pairing_seal_with(user, pairing, device_public, key, None)
}

fn pairing_seal_with(
    user: Id,
    pairing: Id,
    device_public: &[u8; 32],
    key: &UserKeyPair,
    sk_e: Option<&[u8; 32]>,
) -> Result<String> {
    let mut plain = Zeroizing::new(Vec::with_capacity(48));
    plain.extend_from_slice(key.id.as_bytes());
    plain.extend_from_slice(key.secret.as_slice());
    Ok(b64(&hpke_blob(
        device_public,
        INFO_PAIRING,
        &pairing_aad(user, pairing),
        &plain,
        sk_e,
    )?))
}

/// Six-digit code both devices show for a pairing: a server that swapped
/// the new device's key would make them differ.
pub fn pairing_code(pairing: Id, device_public: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(format!("termoak:e2ee:pairing-code:v1:{pairing}:").as_bytes());
    h.update(device_public);
    let d = h.finalize();
    let n = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 1_000_000;
    format!("{n:06}")
}

// ---------------------------------------------------------------------------
// Tests and the shared vectors
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s.replace([' ', '\n'], "")).unwrap()
    }

    fn arr<const N: usize>(s: &str) -> [u8; N] {
        h(s).try_into().unwrap()
    }

    /// RFC 9180 A.1.1 (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
    /// AES-128-GCM, base mode): the KEM, the key schedule and the first
    /// encryption. Production uses AES-256-GCM: only Nk changes.
    #[test]
    fn rfc9180_a1_1() {
        let sk_e = StaticSecret::from(arr::<32>(
            "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
        ));
        let sk_r = StaticSecret::from(arr::<32>(
            "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
        ));
        let pk_r = PublicKey::from(&sk_r);
        assert_eq!(
            pk_r.as_bytes().to_vec(),
            h("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d")
        );
        let (shared, enc) = hpke::encap(&pk_r, &sk_e).unwrap();
        assert_eq!(
            enc.to_vec(),
            h("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")
        );
        assert_eq!(
            shared.to_vec(),
            h("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc")
        );
        assert_eq!(hpke::decap(&enc, &sk_r).unwrap().to_vec(), shared.to_vec());
        let info = h("4f6465206f6e2061204772656369616e2055726e");
        let (key, nonce) = hpke::key_schedule(hpke::AEAD_AES128GCM, &shared, &info);
        assert_eq!(key.to_vec(), h("4531685d41d65f03dc48f6b8302c05b0"));
        assert_eq!(nonce.to_vec(), h("56d890e5accaaf011cff4b7d"));
        let pt = h("4265617574792069732074727574682c20747275746820626561757479");
        let aad = h("436f756e742d30");
        let (enc2, ct) =
            hpke::seal_base(hpke::AEAD_AES128GCM, &pk_r, &info, &aad, &pt, &sk_e).unwrap();
        assert_eq!(enc2, enc);
        assert_eq!(
            ct,
            h(
                "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"
            )
        );
        let opened = hpke::open_base(hpke::AEAD_AES128GCM, &enc, &sk_r, &info, &aad, &ct).unwrap();
        assert_eq!(opened.to_vec(), pt);
    }

    #[test]
    fn round_trips_and_tampering() {
        let user = crate::new_id();
        let vault = crate::new_id();
        let key = UserKeyPair::generate();
        let vk = VaultKey::generate();
        let wrapped = wrap_vault_key(&vk, vault, 3, user, key.id, key.public()).unwrap();
        check_wrap_blob(&wrapped).unwrap();
        assert_eq!(
            unwrap_vault_key(&wrapped, vault, 3, user, &key)
                .unwrap()
                .as_bytes(),
            vk.as_bytes()
        );
        // Bound to the version, the user and the key.
        assert!(unwrap_vault_key(&wrapped, vault, 4, user, &key).is_err());
        assert!(unwrap_vault_key(&wrapped, vault, 3, crate::new_id(), &key).is_err());
        assert!(unwrap_vault_key(&wrapped, vault, 3, user, &UserKeyPair::generate()).is_err());

        let id = crate::new_id();
        let blob =
            encrypt_secret(&vk, vault, 3, EntityKind::Host, id, br#"{"password":"x"}"#).unwrap();
        check_sealed_blob(&blob).unwrap();
        assert_eq!(
            &*decrypt_secret(&vk, vault, 3, EntityKind::Host, id, &blob).unwrap(),
            br#"{"password":"x"}"#
        );
        let err = decrypt_secret(&vk, vault, 3, EntityKind::Key, id, &blob).unwrap_err();
        assert_eq!(err.vault_code(), Some(codes::E2EE_DECRYPT_FAILED));

        let recovery = RecoveryKey::generate();
        let shown = recovery.display();
        assert_eq!(shown.split(' ').count(), RECOVERY_WORDS);
        let parsed = RecoveryKey::parse(&shown.to_uppercase().replace(' ', "\n")).unwrap();
        let seal = seal_with_recovery(user, &key, &recovery).unwrap();
        check_key_seal(&seal).unwrap();
        let opened = open_with_recovery(user, key.id, &seal, &parsed, Some(key.public())).unwrap();
        assert_eq!(opened.public(), key.public());
        // Another published key: refused even though the seal opens.
        let other = UserKeyPair::generate();
        assert_eq!(
            open_with_recovery(user, key.id, &seal, &recovery, Some(other.public()))
                .unwrap_err()
                .vault_code(),
            Some(codes::E2EE_KEY_MISMATCH)
        );

        let pk = PairingKey::generate();
        let pairing = crate::new_id();
        let sealed = pairing_seal(user, pairing, pk.public(), &key).unwrap();
        let got = pk.open(user, pairing, &sealed).unwrap();
        assert_eq!(got.id, key.id);
        assert_eq!(got.public(), key.public());
        assert!(pk.open(user, crate::new_id(), &sealed).is_err());
        assert_eq!(pairing_code(pairing, pk.public()).len(), 6);
    }

    #[test]
    fn passphrase_seal_with_cheap_params() {
        let user = crate::new_id();
        let key = UserKeyPair::generate();
        let params = KdfParams {
            m: ARGON2_MIN_M_KIB,
            t: 1,
            ..KdfParams::new_random()
        };
        let seal = seal_with_passphrase_params(user, &key, "correct horse", params, None).unwrap();
        check_key_seal(&seal).unwrap();
        let opened =
            open_with_passphrase(user, key.id, &seal, "correct horse", Some(key.public())).unwrap();
        assert_eq!(opened.public(), key.public());
        assert_eq!(
            open_with_passphrase(user, key.id, &seal, "wrong horse", None)
                .unwrap_err()
                .vault_code(),
            Some(codes::E2EE_PASSPHRASE_INVALID)
        );
        assert_eq!(
            seal_with_passphrase(user, &key, "short")
                .unwrap_err()
                .vault_code(),
            Some(codes::E2EE_PASSPHRASE_TOO_SHORT)
        );
        // A downgraded cost is refused before any work.
        let mut weak = seal.clone();
        weak.params.as_mut().unwrap().m = 8;
        assert!(open_with_passphrase(user, key.id, &weak, "correct horse", None).is_err());
    }

    fn reason(text: &str) -> String {
        match RecoveryKey::parse(text).unwrap_err() {
            CoreError::Vault { code, detail, .. } => {
                assert_eq!(code, codes::E2EE_RECOVERY_KEY_INVALID);
                detail.unwrap()["reason"].as_str().unwrap().to_string()
            }
            other => panic!("{other:?}"),
        }
    }

    /// The BIP39 English list is the standard one, and the phrases are
    /// standard BIP39 (Trezor's 256-bit vectors).
    #[test]
    fn recovery_phrase() {
        assert_eq!(hex::encode(Sha256::digest(BIP39_ENGLISH)), BIP39_ENGLISH_SHA256);
        let list = recovery_wordlist();
        assert_eq!(list.len(), 2048);
        assert!(list.windows(2).all(|w| w[0] < w[1]));
        for (entropy, phrase) in trezor_vectors() {
            let rk = RecoveryKey::from_bytes(arr(entropy));
            assert_eq!(&*rk.display(), phrase);
            assert_eq!(RecoveryKey::parse(phrase).unwrap().0.as_slice(), &h(entropy)[..]);
        }
        let rk = RecoveryKey::generate();
        let words = rk.words();
        // Numbered, upper case, commas, four-letter (or longer) prefixes.
        let typed: String = words
            .iter()
            .enumerate()
            .map(|(i, w)| {
                let w = if w.len() > 5 && i % 2 == 0 { &w[..4] } else { w };
                format!("{}. {},\n", i + 1, w.to_uppercase())
            })
            .collect();
        assert_eq!(RecoveryKey::parse(&typed).unwrap().0, rk.0);
        // Errors with their reason.
        assert_eq!(reason(&words[..23].join(" ")), recovery_reason::WORD_COUNT);
        let mut bad = words.clone();
        bad[6] = "abandom";
        match RecoveryKey::parse(&bad.join(" ")).unwrap_err() {
            CoreError::Vault { detail, .. } => assert_eq!(detail.unwrap()["word"], 7),
            other => panic!("{other:?}"),
        }
        assert_eq!(reason(&bad.join(" ")), recovery_reason::UNKNOWN_WORD);
        // Three letters are not a prefix ("aba" is no word).
        let mut short = words.clone();
        short[0] = "aba";
        assert_eq!(reason(&short.join(" ")), recovery_reason::UNKNOWN_WORD);
        // The last word carries the checksum: change only its checksum bits.
        let mut sum = words.clone();
        let last = list.iter().position(|w| *w == sum[23]).unwrap();
        sum[23] = list[last ^ 1];
        assert_eq!(reason(&sum.join(" ")), recovery_reason::CHECKSUM);
        // The first format (56 base32 characters) is refused as such.
        assert_eq!(
            reason("ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567-ABCD-EFGH-IJKL-MNOP-QRST-UVWX"),
            recovery_reason::OLD_FORMAT
        );
        assert!(recovery_word_index("zoo").is_some());
        assert_eq!(recovery_word_index("aban"), Some(0));
        assert_eq!(recovery_word_index("abandons"), None);
    }

    /// Trezor's python-mnemonic vectors with 256 bits of entropy.
    fn trezor_vectors() -> [(&'static str, &'static str); 8] {
        [
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            ),
            (
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
            ),
            (
                "8080808080808080808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
            ),
            (
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            ),
            (
                "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
                "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
            ),
            (
                "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
                "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
            ),
            (
                "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
                "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
            ),
            (
                "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
                "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
            ),
        ]
    }

    // ---- shared vectors (tests/e2ee_vectors.json) ----

    fn id(s: &str) -> Id {
        s.parse().unwrap()
    }

    /// What a typed phrase becomes: the raw key, or the refusal's reason
    /// (and word).
    fn recovery_parse_cases(recovery: &RecoveryKey) -> Value {
        let words = recovery.words();
        let list = recovery_wordlist();
        let numbered: String = words
            .iter()
            .enumerate()
            .map(|(i, w)| format!("{}) {}\n", i + 1, w.to_uppercase()))
            .collect();
        let prefixes = words
            .iter()
            .map(|w| if w.len() > 4 { &w[..4] } else { w })
            .collect::<Vec<_>>()
            .join("  ");
        let mut unknown = words.clone();
        unknown[4] = "qwerty";
        let mut sum = words.clone();
        let last = list.iter().position(|w| *w == sum[23]).unwrap();
        sum[23] = list[last ^ 1];
        let raw = hex::encode(recovery.0.as_slice());
        let case = |input: String| {
            let out = match RecoveryKey::parse(&input) {
                Ok(k) => json!({"input": input, "raw": hex::encode(k.0.as_slice())}),
                Err(CoreError::Vault { detail, .. }) => {
                    let mut d = detail.unwrap();
                    d["input"] = json!(input);
                    d
                }
                Err(e) => panic!("{e:?}"),
            };
            if out.get("raw").is_some() {
                assert_eq!(out["raw"], json!(raw));
            }
            out
        };
        json!([
            case(numbered),
            case(prefixes),
            case(words[..12].join(" ")),
            case(unknown.join(" ")),
            case(sum.join(" ")),
            case("ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567-ABCD-EFGH-IJKL-MNOP-QRST-UVWX".into()),
        ])
    }

    /// Builds the vectors from fixed inputs. `TERMOAK_WRITE_VECTORS=1 cargo
    /// test -p termoak-core e2ee::tests::vectors` rewrites the file.
    fn build_vectors() -> Value {
        let user = id("0192d3a0-0000-7000-8000-000000000001");
        let vault = id("0192d3a0-0000-7000-8000-0000000000a1");
        let key_id = id("0192d3a0-0000-7000-8000-0000000000b1");
        let entity = id("0192d3a0-0000-7000-8000-0000000000c1");
        let pairing = id("0192d3a0-0000-7000-8000-0000000000d1");
        let uk = UserKeyPair::from_private(
            key_id,
            arr("a8abababababababababababababababababababababababababababababab6b"),
        );
        let recovery = RecoveryKey::from_bytes(arr(
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        ));
        let params = KdfParams {
            alg: "argon2id".into(),
            m: ARGON2_M_KIB,
            t: ARGON2_T,
            p: ARGON2_P,
            salt: b64(&h("000102030405060708090a0b0c0d0e0f")),
        };
        let nonce1: [u8; 12] = arr("101112131415161718191a1b");
        let nonce2: [u8; 12] = arr("202122232425262728292a2b");
        let nonce3: [u8; 12] = arr("303132333435363738393a3b");
        let sk_e1: [u8; 32] =
            arr("c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf");
        let sk_e2: [u8; 32] =
            arr("e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let passphrase = "correct horse battery staple";
        let pass_seal =
            seal_with_passphrase_params(user, &uk, passphrase, params.clone(), Some(&nonce1))
                .unwrap();
        let rec_seal = seal_with_recovery_nonce(user, &uk, &recovery, Some(&nonce2)).unwrap();
        let vk = VaultKey::from_bytes(arr(
            "5ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2",
        ));
        let wrapped =
            wrap_vault_key_with(&vk, vault, 2, user, key_id, uk.public(), Some(&sk_e1)).unwrap();
        let secret_json = r#"{"password":"hunter2","proxy_password":null}"#;
        let sealed_secret = b64(&aes_blob(
            vk.as_bytes(),
            &secret_aad(vault, 2, EntityKind::Host, entity),
            secret_json.as_bytes(),
            Some(&nonce3),
        )
        .unwrap());
        let device = PairingKey::from_private(arr(
            "7171717171717171717171717171717171717171717171717171717171717171",
        ));
        let paired = pairing_seal_with(user, pairing, device.public(), &uk, Some(&sk_e2)).unwrap();
        json!({
            "about": "End-to-end encrypted vault test vectors (docs/E2EE-SSO-AUDIT.md §2.2). Every implementation (core, web) must reproduce each output from its inputs (the fixed nonces and ephemeral keys are for these vectors only) and open each blob. Binary values are hex unless the name ends in _b64 (standard base64 with padding). Blobs: version byte 1, then [nonce 12 | ciphertext+tag] (AES-256-GCM) or [enc 32 | ciphertext+tag] (HPKE base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, RFC 9180). AAD and HPKE info are the UTF-8 strings given.",
            "user_key": {
                "user_id": user, "key_id": key_id,
                "private": hex::encode(uk.private_bytes().as_slice()),
                "public_b64": uk.public_b64(),
                "fingerprint": uk.fingerprint(),
            },
            "recovery_key": {
                "raw": hex::encode(recovery.0.as_slice()),
                "display": recovery.display().to_string(),
                "format": "BIP39 English, 24 words: the 256-bit raw key is the entropy, the checksum is the first byte of its SHA-256; the raw key (not BIP39's PBKDF2 seed) is the HKDF input",
                "kek_hkdf": {"salt": String::from_utf8_lossy(RECOVERY_SALT), "info": format!("{user}:{key_id}"), "kek": hex::encode(recovery.kek(user, key_id).as_slice())},
            },
            "bip39": {
                "wordlist": "bitcoin/bips bip-0039/english.txt",
                "wordlist_sha256": BIP39_ENGLISH_SHA256,
                "vectors": trezor_vectors().iter().map(|(e, p)| json!({"entropy": e, "phrase": p})).collect::<Vec<_>>(),
                "parse": recovery_parse_cases(&recovery),
            },
            "passphrase_seal": {
                "passphrase": passphrase,
                "params": params,
                "kek": hex::encode(params.derive(passphrase.as_bytes()).unwrap().as_slice()),
                "aad": String::from_utf8_lossy(&seal_aad(user, key_id, SealKind::Passphrase)),
                "nonce": hex::encode(nonce1),
                "sealed_b64": pass_seal.sealed,
            },
            "recovery_seal": {
                "aad": String::from_utf8_lossy(&seal_aad(user, key_id, SealKind::Recovery)),
                "nonce": hex::encode(nonce2),
                "sealed_b64": rec_seal.sealed,
            },
            "vault_key_wrap": {
                "vault_id": vault, "version": 2,
                "vault_key": hex::encode(vk.as_bytes()),
                "info": String::from_utf8_lossy(INFO_VAULT_KEY),
                "aad": String::from_utf8_lossy(&wrap_aad(vault, 2, user, key_id)),
                "ephemeral_private": hex::encode(sk_e1),
                "wrapped_b64": wrapped,
            },
            "secret": {
                "vault_id": vault, "version": 2, "kind": "host", "entity_id": entity,
                "aad": String::from_utf8_lossy(&secret_aad(vault, 2, EntityKind::Host, entity)),
                "nonce": hex::encode(nonce3),
                "plaintext": secret_json,
                "blob_b64": sealed_secret,
            },
            "pairing": {
                "pairing_id": pairing,
                "device_private": hex::encode(device.private_bytes().as_slice()),
                "device_public_b64": device.public_b64(),
                "info": String::from_utf8_lossy(INFO_PAIRING),
                "aad": String::from_utf8_lossy(&pairing_aad(user, pairing)),
                "ephemeral_private": hex::encode(sk_e2),
                "plaintext": format!("{}{}", hex::encode(key_id.as_bytes()), hex::encode(uk.private_bytes().as_slice())),
                "sealed_b64": paired,
                "code": pairing_code(pairing, device.public()),
            },
        })
    }

    #[test]
    fn vectors() {
        let built = build_vectors();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/e2ee_vectors.json");
        if std::env::var("TERMOAK_WRITE_VECTORS").is_ok() {
            std::fs::write(path, serde_json::to_string_pretty(&built).unwrap() + "\n").unwrap();
        }
        let stored: Value =
            serde_json::from_str(include_str!("../tests/e2ee_vectors.json")).unwrap();
        assert_eq!(stored, built, "tests/e2ee_vectors.json is out of date");
        // And the other direction: every blob opens.
        let user = id(stored["user_key"]["user_id"].as_str().unwrap());
        let key_id = id(stored["user_key"]["key_id"].as_str().unwrap());
        let public = parse_public_key(stored["user_key"]["public_b64"].as_str().unwrap()).unwrap();
        let seal: KeySeal = serde_json::from_value(json!({
            "kind": "passphrase", "params": stored["passphrase_seal"]["params"],
            "sealed": stored["passphrase_seal"]["sealed_b64"],
        }))
        .unwrap();
        let uk = open_with_passphrase(
            user,
            key_id,
            &seal,
            "correct horse battery staple",
            Some(&public),
        )
        .unwrap();
        let recovery =
            RecoveryKey::parse(stored["recovery_key"]["display"].as_str().unwrap()).unwrap();
        let rseal = KeySeal {
            kind: SealKind::Recovery,
            params: None,
            sealed: stored["recovery_seal"]["sealed_b64"]
                .as_str()
                .unwrap()
                .into(),
        };
        open_with_recovery(user, key_id, &rseal, &recovery, Some(&public)).unwrap();
        let w = &stored["vault_key_wrap"];
        let vault = id(w["vault_id"].as_str().unwrap());
        let vk = unwrap_vault_key(w["wrapped_b64"].as_str().unwrap(), vault, 2, user, &uk).unwrap();
        let s = &stored["secret"];
        let plain = decrypt_secret(
            &vk,
            vault,
            2,
            EntityKind::Host,
            id(s["entity_id"].as_str().unwrap()),
            s["blob_b64"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            std::str::from_utf8(&plain).unwrap(),
            s["plaintext"].as_str().unwrap()
        );
        let p = &stored["pairing"];
        let device = PairingKey::from_private(arr(p["device_private"].as_str().unwrap()));
        let got = device
            .open(
                user,
                id(p["pairing_id"].as_str().unwrap()),
                p["sealed_b64"].as_str().unwrap(),
            )
            .unwrap();
        assert_eq!(got.public(), &public);
    }
}

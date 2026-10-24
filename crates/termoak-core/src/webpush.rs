//! Web Push message encryption (RFC 8291, `aes128gcm` of RFC 8188) and VAPID
//! (RFC 8292): what the server needs to notify UnifiedPush distributors
//! (ntfy, NextPush...) and browsers without Google or Apple in the middle,
//! and what a receiver needs to read them (tests, tools and apps that do
//! not decrypt with their own library).
//!
//! - The **server** keeps one VAPID key pair ([`VapidKey`]), signs a short
//!   JWT for the origin of each endpoint ([`VapidKey::authorization`]) and
//!   encrypts every payload for the device's public key and auth secret
//!   ([`encrypt`]). The push service only sees ciphertext.
//! - The **device** generates its own key pair and auth secret
//!   ([`ReceiverKeys`]), gives the server the public key (`p256dh`) and the
//!   auth secret (`auth`) with its endpoint, and decrypts what arrives
//!   ([`ReceiverKeys::decrypt`]).
//!
//! Keys travel base64url without padding, as in the W3C Push API
//! (`PushSubscription.toJSON()`).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToSec1Point as _;
use p256::{PublicKey, SecretKey};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

/// Record size written in the header (one record is ever sent).
const RECORD_SIZE: u32 = 4096;
/// Header: salt (16) + record size (4) + key id length (1) + key id (65).
const HEADER_LEN: usize = 16 + 4 + 1 + 65;
/// AES-GCM tag.
const TAG_LEN: usize = 16;
/// Largest plaintext that fits in one record (with its delimiter and tag).
pub const MAX_PLAINTEXT: usize = RECORD_SIZE as usize - TAG_LEN - 1;
/// Push services accept bodies of 4096 bytes: the plaintext that fits.
pub const MAX_PAYLOAD: usize = 4096 - HEADER_LEN - TAG_LEN - 1;

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes base64url, with or without padding (and standard base64, which
/// some libraries send).
fn unb64(s: &str) -> Result<Vec<u8>> {
    let t = s.trim().trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(t)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(t))
        .map_err(|_| CoreError::Invalid("invalid base64url".into()))
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("the system random generator is unavailable");
    b
}

fn random_secret() -> SecretKey {
    loop {
        let bytes = Zeroizing::new(random::<32>());
        if let Ok(k) = SecretKey::from_slice(bytes.as_slice()) {
            return k;
        }
    }
}

fn public_bytes(p: &PublicKey) -> Vec<u8> {
    p.as_affine().to_sec1_point(false).as_bytes().to_vec()
}

/// A device's public key (`p256dh`: an uncompressed P-256 point, 65 bytes).
fn parse_public(p256dh: &str) -> Result<PublicKey> {
    let raw = unb64(p256dh)?;
    if raw.len() != 65 || raw[0] != 0x04 {
        return Err(CoreError::Invalid(
            "p256dh must be an uncompressed P-256 public key (65 bytes)".into(),
        ));
    }
    PublicKey::from_sec1_bytes(&raw)
        .map_err(|_| CoreError::Invalid("p256dh is not a point of P-256".into()))
}

fn parse_auth(auth: &str) -> Result<[u8; 16]> {
    let raw = unb64(auth)?;
    raw.as_slice()
        .try_into()
        .map_err(|_| CoreError::Invalid("auth must be 16 bytes".into()))
}

/// Checks the keys a device registers (`p256dh` and `auth`).
pub fn validate_keys(p256dh: &str, auth: &str) -> Result<()> {
    parse_public(p256dh)?;
    parse_auth(auth)?;
    Ok(())
}

fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out)
        .expect("HKDF output length");
}

/// The content key and nonce (RFC 8291 §3.4 and RFC 8188 §2.2).
fn derive(
    shared: &[u8],
    auth: &[u8; 16],
    ua_public: &[u8],
    as_public: &[u8],
    salt: &[u8; 16],
) -> (Zeroizing<[u8; 16]>, [u8; 12]) {
    let mut key_info = Vec::with_capacity(14 + 65 + 65);
    key_info.extend_from_slice(b"WebPush: info\0");
    key_info.extend_from_slice(ua_public);
    key_info.extend_from_slice(as_public);
    let mut ikm = Zeroizing::new([0u8; 32]);
    hkdf(auth, shared, &key_info, ikm.as_mut_slice());
    let mut cek = Zeroizing::new([0u8; 16]);
    hkdf(
        salt,
        ikm.as_slice(),
        b"Content-Encoding: aes128gcm\0",
        cek.as_mut_slice(),
    );
    let mut nonce = [0u8; 12];
    hkdf(
        salt,
        ikm.as_slice(),
        b"Content-Encoding: nonce\0",
        &mut nonce,
    );
    (cek, nonce)
}

/// Encrypts `plaintext` for a device (its `p256dh` and `auth`): the body of
/// a Web Push request with `Content-Encoding: aes128gcm`. Pads the plaintext
/// to a multiple of 32 bytes so lengths say less.
pub fn encrypt(p256dh: &str, auth: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    encrypt_with(p256dh, auth, plaintext, &random_secret(), &random(), 32)
}

/// [`encrypt`] with a given ephemeral key and salt (test vectors). `pad_to`:
/// the padded plaintext length is a multiple of it (1 = no padding).
pub fn encrypt_with(
    p256dh: &str,
    auth: &str,
    plaintext: &[u8],
    ephemeral: &SecretKey,
    salt: &[u8; 16],
    pad_to: usize,
) -> Result<Vec<u8>> {
    if plaintext.len() > MAX_PAYLOAD {
        return Err(CoreError::Invalid(format!(
            "push payload too large ({} bytes, at most {MAX_PAYLOAD})",
            plaintext.len()
        )));
    }
    let ua = parse_public(p256dh)?;
    let auth = parse_auth(auth)?;
    let ua_public = public_bytes(&ua);
    let as_public = public_bytes(&ephemeral.public_key());
    let shared = ephemeral.diffie_hellman(&ua);
    let (cek, nonce) = derive(
        shared.raw_secret_bytes().as_slice(),
        &auth,
        &ua_public,
        &as_public,
        salt,
    );
    // Plaintext, the last-record delimiter (2) and zero padding.
    let mut padded = Zeroizing::new(Vec::with_capacity(plaintext.len() + 32));
    padded.extend_from_slice(plaintext);
    padded.push(0x02);
    let pad_to = pad_to.max(1);
    let target = padded.len().div_ceil(pad_to) * pad_to;
    let target = target.min(MAX_PAYLOAD + 1).max(padded.len());
    padded.resize(target, 0);
    let cipher = Aes128Gcm::new_from_slice(cek.as_slice())
        .map_err(|_| CoreError::Crypto("AES key".into()))?;
    let ct = cipher
        .encrypt(&Nonce::from(nonce), padded.as_slice())
        .map_err(|_| CoreError::Crypto("could not encrypt the push message".into()))?;
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    out.push(as_public.len() as u8);
    out.extend_from_slice(&as_public);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// The key pair and auth secret of a receiver (a device or a test
/// subscriber).
pub struct ReceiverKeys {
    secret: SecretKey,
    auth: [u8; 16],
}

impl ReceiverKeys {
    /// New random keys.
    pub fn generate() -> Self {
        Self {
            secret: random_secret(),
            auth: random(),
        }
    }

    /// Keys saved before: the private key (32 bytes) and the auth secret
    /// (16 bytes), base64url.
    pub fn from_parts(private_key: &str, auth: &str) -> Result<Self> {
        let raw = Zeroizing::new(unb64(private_key)?);
        let secret = SecretKey::from_slice(&raw)
            .map_err(|_| CoreError::Invalid("invalid P-256 private key".into()))?;
        Ok(Self {
            secret,
            auth: parse_auth(auth)?,
        })
    }

    /// The private key, base64url (keep it on the device).
    pub fn private_key(&self) -> Zeroizing<String> {
        Zeroizing::new(b64(self.secret.to_bytes().as_slice()))
    }

    /// The public key to register (`p256dh`), base64url.
    pub fn p256dh(&self) -> String {
        b64(&public_bytes(&self.secret.public_key()))
    }

    /// The auth secret to register (`auth`), base64url.
    pub fn auth(&self) -> String {
        b64(&self.auth)
    }

    /// Decrypts an `aes128gcm` Web Push body.
    pub fn decrypt(&self, body: &[u8]) -> Result<Vec<u8>> {
        let bad = |m: &str| CoreError::Invalid(format!("not a Web Push message: {m}"));
        if body.len() < 21 {
            return Err(bad("too short"));
        }
        let salt: [u8; 16] = body[..16].try_into().expect("16 bytes");
        let rs = u32::from_be_bytes(body[16..20].try_into().expect("4 bytes")) as usize;
        let idlen = body[20] as usize;
        if body.len() < 21 + idlen + TAG_LEN || rs < 18 {
            return Err(bad("truncated header"));
        }
        let as_public = &body[21..21 + idlen];
        let sender = PublicKey::from_sec1_bytes(as_public)
            .map_err(|_| bad("the key id is not a P-256 public key"))?;
        let ua_public = public_bytes(&self.secret.public_key());
        let shared = self.secret.diffie_hellman(&sender);
        let (cek, nonce) = derive(
            shared.raw_secret_bytes().as_slice(),
            &self.auth,
            &ua_public,
            as_public,
            &salt,
        );
        let cipher = Aes128Gcm::new_from_slice(cek.as_slice())
            .map_err(|_| CoreError::Crypto("AES key".into()))?;
        let records = &body[21 + idlen..];
        if records.len() > rs {
            return Err(bad("more than one record"));
        }
        let mut plain = cipher
            .decrypt(&Nonce::from(nonce), records)
            .map_err(|_| CoreError::Crypto("the push message does not decrypt".into()))?;
        // Strip the padding and the delimiter (2 = last record).
        while plain.last() == Some(&0) {
            plain.pop();
        }
        match plain.pop() {
            Some(0x02) => Ok(plain),
            _ => Err(bad("missing record delimiter")),
        }
    }
}

/// The server's VAPID key (RFC 8292): an ECDSA P-256 key that signs a JWT
/// for every push service it talks to.
pub struct VapidKey {
    secret: SecretKey,
}

impl VapidKey {
    /// A new random key.
    pub fn generate() -> Self {
        Self {
            secret: random_secret(),
        }
    }

    /// A key saved with [`VapidKey::to_base64url`] (the raw 32-byte private
    /// scalar, base64url: the format of most Web Push tools).
    pub fn from_base64url(s: &str) -> Result<Self> {
        let raw = Zeroizing::new(unb64(s)?);
        let secret = SecretKey::from_slice(&raw)
            .map_err(|_| CoreError::Invalid("invalid VAPID private key".into()))?;
        Ok(Self { secret })
    }

    /// The private key to save (secret).
    pub fn to_base64url(&self) -> Zeroizing<String> {
        Zeroizing::new(b64(self.secret.to_bytes().as_slice()))
    }

    /// The public key (base64url, uncompressed point): the
    /// `applicationServerKey` of browsers and the VAPID key UnifiedPush
    /// distributors may ask for.
    pub fn public_key(&self) -> String {
        b64(&public_bytes(&self.secret.public_key()))
    }

    /// The `Authorization` header for a request to `endpoint`: `vapid t=<JWT
    /// for the endpoint's origin, valid for 12 hours>, k=<public key>`.
    /// `subject` is a `mailto:` or `https:` contact for the push service.
    pub fn authorization(&self, endpoint: &str, subject: &str, now_secs: u64) -> Result<String> {
        let aud = origin(endpoint)
            .ok_or_else(|| CoreError::Invalid("the push endpoint is not a URL".into()))?;
        let header = b64(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = b64(serde_json::json!({
            "aud": aud,
            "exp": now_secs + 12 * 3600,
            "sub": subject,
        })
        .to_string()
        .as_bytes());
        let msg = format!("{header}.{claims}");
        let sig: Signature = SigningKey::from(&self.secret).sign(msg.as_bytes());
        Ok(format!(
            "vapid t={msg}.{}, k={}",
            b64(&sig.to_bytes()),
            self.public_key()
        ))
    }
}

/// `scheme://host[:port]` of a URL.
pub fn origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+')
    {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    Some(format!(
        "{}://{}",
        scheme.to_ascii_lowercase(),
        authority.to_ascii_lowercase()
    ))
}

/// A `Topic` header for a collapse key (at most 32 base64url characters,
/// RFC 8030 §5.4): the same key replaces a message still waiting at the
/// push service.
pub fn topic(collapse: &str) -> String {
    use sha2::Digest as _;
    let digest = Sha256::digest(collapse.as_bytes());
    b64(&digest)[..32].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8291, Appendix A.
    const PLAIN: &str = "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24";
    const AS_PRIVATE: &str = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
    const AS_PUBLIC: &str =
        "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
    const UA_PRIVATE: &str = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94";
    const UA_PUBLIC: &str =
        "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
    const AUTH: &str = "BTBZMqHH6r4Tts7J_aSIgg";
    const SALT: &str = "DGv6ra1nlYgDCS1FRnbzlw";
    const BODY: &str = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN";

    #[test]
    fn rfc8291_vector() {
        let eph = SecretKey::from_slice(&unb64(AS_PRIVATE).unwrap()).unwrap();
        assert_eq!(b64(&public_bytes(&eph.public_key())), AS_PUBLIC);
        let salt: [u8; 16] = unb64(SALT).unwrap().try_into().unwrap();
        let body = encrypt_with(UA_PUBLIC, AUTH, &unb64(PLAIN).unwrap(), &eph, &salt, 1).unwrap();
        assert_eq!(b64(&body), BODY);
        let ua = ReceiverKeys::from_parts(UA_PRIVATE, AUTH).unwrap();
        assert_eq!(ua.p256dh(), UA_PUBLIC);
        let plain = ua.decrypt(&unb64(BODY).unwrap()).unwrap();
        assert_eq!(
            String::from_utf8(plain).unwrap(),
            "When I grow up, I want to be a watermelon"
        );
    }

    #[test]
    fn round_trip_with_padding_and_limits() {
        let ua = ReceiverKeys::generate();
        let msg = br#"{"v":1,"type":"test"}"#;
        let body = encrypt(&ua.p256dh(), &ua.auth(), msg).unwrap();
        assert_eq!((body.len() - HEADER_LEN - TAG_LEN) % 32, 0);
        assert_eq!(ua.decrypt(&body).unwrap(), msg);
        // Another receiver cannot read it; a flipped bit fails.
        assert!(ReceiverKeys::generate().decrypt(&body).is_err());
        let mut bad = body.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(ua.decrypt(&bad).is_err());
        // The largest payload fits in 4096 bytes; one more byte is refused.
        let big = vec![b'x'; MAX_PAYLOAD];
        let body = encrypt(&ua.p256dh(), &ua.auth(), &big).unwrap();
        assert_eq!(body.len(), 4096);
        assert_eq!(ua.decrypt(&body).unwrap(), big);
        assert!(encrypt(&ua.p256dh(), &ua.auth(), &vec![0; MAX_PAYLOAD + 1]).is_err());
        // Saved keys work again.
        let again = ReceiverKeys::from_parts(&ua.private_key(), &ua.auth()).unwrap();
        assert_eq!(again.p256dh(), ua.p256dh());
    }

    #[test]
    fn key_validation() {
        let ua = ReceiverKeys::generate();
        validate_keys(&ua.p256dh(), &ua.auth()).unwrap();
        // Padded and standard base64 are accepted too.
        validate_keys(&format!("{}=", ua.p256dh()), &format!("{}==", ua.auth())).unwrap();
        assert!(validate_keys(&ua.auth(), &ua.auth()).is_err());
        assert!(validate_keys(&ua.p256dh(), &ua.p256dh()).is_err());
        assert!(validate_keys("BAAA", &ua.auth()).is_err());
        let mut not_on_curve = vec![4u8];
        not_on_curve.extend([1u8; 64]);
        assert!(validate_keys(&b64(&not_on_curve), &ua.auth()).is_err());
    }

    #[test]
    fn vapid_jwt_verifies() {
        use p256::ecdsa::VerifyingKey;
        use p256::ecdsa::signature::Verifier as _;
        let key = VapidKey::generate();
        let again = VapidKey::from_base64url(&key.to_base64url()).unwrap();
        assert_eq!(again.public_key(), key.public_key());
        let h = key
            .authorization(
                "https://ntfy.example.org:8443/upAbc?up=1",
                "mailto:admin@example.org",
                1_000,
            )
            .unwrap();
        let rest = h.strip_prefix("vapid t=").unwrap();
        let (jwt, k) = rest.split_once(", k=").unwrap();
        assert_eq!(k, key.public_key());
        let parts: Vec<&str> = jwt.split('.').collect();
        let claims: serde_json::Value = serde_json::from_slice(&unb64(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["aud"], "https://ntfy.example.org:8443");
        assert_eq!(claims["exp"], 1_000 + 12 * 3600);
        assert_eq!(claims["sub"], "mailto:admin@example.org");
        let vk = VerifyingKey::from_sec1_bytes(&unb64(k).unwrap()).unwrap();
        let sig = Signature::from_slice(&unb64(parts[2]).unwrap()).unwrap();
        vk.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
            .unwrap();
    }

    #[test]
    fn origins_and_topics() {
        assert_eq!(
            origin("https://Push.Example.com/wpush/v2/abc").as_deref(),
            Some("https://push.example.com")
        );
        assert_eq!(
            origin("http://127.0.0.1:2586/up1?up=1").as_deref(),
            Some("http://127.0.0.1:2586")
        );
        assert_eq!(origin("https://user@host/x"), None);
        assert_eq!(origin("nope"), None);
        let t = topic("approval-0192");
        assert_eq!(t.len(), 32);
        assert!(
            t.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        assert_eq!(t, topic("approval-0192"));
        assert_ne!(t, topic("approval-0193"));
    }
}

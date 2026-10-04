//! Time-based one-time passwords (TOTP, RFC 6238) for two-factor
//! authentication: HMAC-SHA1, 6 digits and 30-second steps, which is what
//! Google Authenticator, 1Password, Aegis, Bitwarden... understand.

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

use crate::crypto::random_bytes;

/// Length of each step.
pub const STEP_SECS: u64 = 30;
/// Tolerated steps on each side (clock skew).
const WINDOW: i64 = 1;

/// New secret (160 bits, as recommended by RFC 4226).
pub fn generate_secret() -> Vec<u8> {
    random_bytes::<20>().to_vec()
}

/// Secret in unpadded base32, as typed into the authenticator app.
pub fn secret_to_base32(secret: &[u8]) -> String {
    BASE32_NOPAD.encode(secret)
}

/// Parses a base32 secret (accepts lowercase, spaces and padding).
pub fn secret_from_base32(text: &str) -> Option<Vec<u8>> {
    let clean: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=' && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    BASE32_NOPAD.decode(clean.as_bytes()).ok()
}

/// `otpauth://` URL for the QR code.
pub fn otpauth_url(issuer: &str, account: &str, secret: &[u8]) -> String {
    let enc = |s: &str| url_encode(s);
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period={STEP_SECS}",
        enc(issuer),
        enc(account),
        secret_to_base32(secret),
        enc(issuer)
    )
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Code for a given step.
pub fn code_at(secret: &[u8], step: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts keys of any size");
    mac.update(&step.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);
    bin % 1_000_000
}

/// Step for a point in time (Unix seconds).
pub fn step_at(unix_secs: u64) -> u64 {
    unix_secs / STEP_SECS
}

/// Checks a code against the current step ± the window. Returns the matching
/// step, which must be greater than the last one used (prevents reusing an
/// already accepted code).
pub fn verify(secret: &[u8], code: &str, unix_secs: u64, last_step: u64) -> Option<u64> {
    let code = code.trim().replace([' ', '-'], "");
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let wanted: u32 = code.parse().ok()?;
    let now = step_at(unix_secs) as i64;
    let mut matched = None;
    for delta in -WINDOW..=WINDOW {
        let step = now + delta;
        if step < 0 {
            continue;
        }
        let step = step as u64;
        // No short-circuiting, so timing leaks nothing.
        if constant_eq(code_at(secret, step), wanted) && step > last_step {
            matched = Some(step);
        }
    }
    matched
}

fn constant_eq(a: u32, b: u32) -> bool {
    (a ^ b) == 0
}

/// Generates `n` recovery codes in the `xxxx-xxxx` format.
pub fn recovery_codes(n: usize) -> Vec<String> {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    (0..n)
        .map(|_| {
            let bytes = random_bytes::<8>();
            let chars: String = bytes
                .iter()
                .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
                .collect();
            format!("{}-{}", &chars[..4], &chars[4..])
        })
        .collect()
}

/// Canonical form of a recovery code (no spaces, lowercase).
pub fn normalize_recovery_code(code: &str) -> String {
    let c: String = code
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    if c.len() == 8 {
        format!("{}-{}", &c[..4], &c[4..])
    } else {
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 test vectors (SHA1, ASCII secret "12345678901234567890"),
    // truncated to 6 digits.
    #[test]
    fn rfc6238_vectors() {
        let secret = b"12345678901234567890";
        for (t, code) in [
            (59u64, 287_082u32),
            (1_111_111_109, 81_804),
            (1_111_111_111, 50_471),
            (1_234_567_890, 5_924),
            (2_000_000_000, 279_037),
            (20_000_000_000, 353_130),
        ] {
            assert_eq!(code_at(secret, step_at(t)), code, "t={t}");
        }
    }

    #[test]
    fn verify_window_and_replay() {
        let secret = generate_secret();
        let now = 1_700_000_000u64;
        let code = format!("{:06}", code_at(&secret, step_at(now)));
        let step = verify(&secret, &code, now, 0).expect("current code");
        assert_eq!(step, step_at(now));
        // The same code is not accepted twice.
        assert!(verify(&secret, &code, now, step).is_none());
        // One step of skew is accepted; three are not.
        let prev = format!("{:06}", code_at(&secret, step_at(now) - 1));
        assert!(verify(&secret, &prev, now, 0).is_some());
        let old = format!("{:06}", code_at(&secret, step_at(now) - 3));
        assert!(verify(&secret, &old, now, 0).is_none());
        assert!(verify(&secret, "12345", now, 0).is_none());
        assert!(verify(&secret, "abcdef", now, 0).is_none());
    }

    #[test]
    fn base32_and_url() {
        assert_eq!(
            secret_to_base32(b"12345678901234567890"),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
        assert_eq!(
            secret_from_base32("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").as_deref(),
            Some(&b"12345678901234567890"[..])
        );
        assert_eq!(secret_from_base32("1!"), None);
        let url = otpauth_url("Termoak", "ana@example.com", b"12345678901234567890");
        assert!(url.starts_with("otpauth://totp/Termoak:ana%40example.com?secret=GEZDGNBV"));
        assert!(url.contains("issuer=Termoak"));
    }

    #[test]
    fn recovery_code_format() {
        let codes = recovery_codes(10);
        assert_eq!(codes.len(), 10);
        for c in &codes {
            assert_eq!(c.len(), 9);
            assert_eq!(
                normalize_recovery_code(&c.to_uppercase().replace('-', " ")),
                *c
            );
        }
    }
}

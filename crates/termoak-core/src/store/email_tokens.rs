//! Single-use tokens sent by email: verifying the email, resetting the
//! password and confirming an email change, plus the six-digit codes that
//! verify the email by typing them in the app.

use hmac::{Hmac, KeyInit, Mac};
use rusqlite::{OptionalExtension, params};
use sha2::Sha256;

use super::{Store, parse_id};
use crate::Id;
use crate::crypto::{MasterKey, constant_time_eq, prefixed_token, random_bytes, sha256_hex};
use crate::error::Result;
use crate::time::now_ms;

/// Wrong guesses allowed per email code: the last one invalidates it.
pub const EMAIL_CODE_MAX_ATTEMPTS: i64 = 5;
/// Digits of an email code.
pub const EMAIL_CODE_DIGITS: usize = 6;
/// `purpose` of the email codes in `email_tokens`.
const CODE_PURPOSE: &str = "verify_code";

/// What a token is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailPurpose {
    /// Confirm the account email.
    Verify,
    /// Set a new password.
    ResetPassword,
    /// Confirm a new email (the token carries the new address).
    ChangeEmail,
}

impl EmailPurpose {
    fn as_str(self) -> &'static str {
        match self {
            EmailPurpose::Verify => "verify",
            EmailPurpose::ResetPassword => "reset",
            EmailPurpose::ChangeEmail => "change_email",
        }
    }
}

/// Token already checked and spent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailToken {
    pub user_id: Id,
    /// Address it was sent to.
    pub email: String,
}

impl Store {
    /// Creates a token for `email` that expires in `ttl_ms`. Invalidates the
    /// user's previous tokens of the same kind. Returns the token (only its
    /// hash is stored).
    pub async fn create_email_token(
        &self,
        user_id: Id,
        purpose: EmailPurpose,
        email: &str,
        ttl_ms: i64,
    ) -> Result<String> {
        let email = email.trim().to_lowercase();
        self.call(move |c, _| {
            let token = prefixed_token("aks_mail");
            let now = now_ms();
            c.execute(
                "UPDATE email_tokens SET used_at = ?3
                 WHERE user_id = ?1 AND purpose = ?2 AND used_at IS NULL",
                params![user_id.to_string(), purpose.as_str(), now],
            )?;
            c.execute(
                "INSERT INTO email_tokens (token_hash, user_id, purpose, email, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    sha256_hex(token.as_bytes()),
                    user_id.to_string(),
                    purpose.as_str(),
                    email,
                    now,
                    now + ttl_ms
                ],
            )?;
            Ok(token)
        })
        .await
    }

    /// When the last token of that kind was created (to avoid sending bursts
    /// of email).
    pub async fn last_email_token_at(
        &self,
        user_id: Id,
        purpose: EmailPurpose,
    ) -> Result<Option<i64>> {
        self.call(move |c, _| {
            Ok(c.query_row(
                "SELECT MAX(created_at) FROM email_tokens WHERE user_id = ?1 AND purpose = ?2",
                params![user_id.to_string(), purpose.as_str()],
                |r| r.get::<_, Option<i64>>(0),
            )?)
        })
        .await
    }

    /// Checks and spends a token. `None` if it does not exist, was used or expired.
    pub async fn consume_email_token(
        &self,
        token: &str,
        purpose: EmailPurpose,
    ) -> Result<Option<EmailToken>> {
        let hash = sha256_hex(token.trim().as_bytes());
        self.call(move |c, _| {
            let now = now_ms();
            let found = c
                .query_row(
                    "SELECT user_id, email FROM email_tokens
                     WHERE token_hash = ?1 AND purpose = ?2 AND used_at IS NULL
                       AND expires_at > ?3",
                    params![hash, purpose.as_str(), now],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                )
                .optional()?;
            let Some((user, email)) = found else {
                return Ok(None);
            };
            let n = c.execute(
                "UPDATE email_tokens SET used_at = ?2 WHERE token_hash = ?1 AND used_at IS NULL",
                params![hash, now],
            )?;
            if n == 0 {
                return Ok(None);
            }
            Ok(Some(EmailToken {
                user_id: parse_id(&user)?,
                email,
            }))
        })
        .await
    }
}

/// A random code of [`EMAIL_CODE_DIGITS`] digits (uniform, with leading zeros).
fn random_code() -> String {
    // 4_294_000_000 is the largest multiple of 1_000_000 below 2^32: values
    // above it are drawn again so that every code is equally likely.
    loop {
        let n = u32::from_le_bytes(random_bytes::<4>());
        if n < 4_294_000_000 {
            return format!("{:06}", n % 1_000_000);
        }
    }
}

/// Is `code` exactly [`EMAIL_CODE_DIGITS`] ASCII digits?
pub fn is_email_code(code: &str) -> bool {
    code.len() == EMAIL_CODE_DIGITS && code.bytes().all(|b| b.is_ascii_digit())
}

/// What is stored for a code: `c1$<salt>$<mac>`. The MAC is keyed with the
/// master key, so a copy of the database alone does not reveal the codes
/// (a plain hash of six digits would be trivial to reverse). The random salt
/// keeps the primary key unique even if a code repeats.
fn code_hash(key: &MasterKey, user_id: Id, salt: &str, code: &str) -> String {
    format!(
        "c1${salt}${}",
        hex::encode(code_mac(key, user_id, salt, code))
    )
}

fn code_mac(key: &MasterKey, user_id: Id, salt: &str, code: &str) -> Vec<u8> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts keys of any size");
    for part in [
        "termoak-email-code".as_bytes(),
        user_id.to_string().as_bytes(),
        salt.as_bytes(),
        code.as_bytes(),
    ] {
        mac.update(part);
        mac.update(&[0]);
    }
    mac.finalize().into_bytes().to_vec()
}

impl Store {
    /// Creates a six-digit code that verifies `email` for `ttl_ms`, and
    /// invalidates the user's previous codes. Returns the code (only a keyed
    /// hash is stored).
    pub async fn create_email_code(&self, user_id: Id, email: &str, ttl_ms: i64) -> Result<String> {
        let email = email.trim().to_lowercase();
        self.call(move |c, key| {
            let code = random_code();
            let salt = hex::encode(random_bytes::<12>());
            let now = now_ms();
            c.execute(
                "UPDATE email_tokens SET used_at = ?3
                 WHERE user_id = ?1 AND purpose = ?2 AND used_at IS NULL",
                params![user_id.to_string(), CODE_PURPOSE, now],
            )?;
            c.execute(
                "INSERT INTO email_tokens (token_hash, user_id, purpose, email, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    code_hash(key, user_id, &salt, &code),
                    user_id.to_string(),
                    CODE_PURPOSE,
                    email,
                    now,
                    now + ttl_ms
                ],
            )?;
            Ok(code)
        })
        .await
    }

    /// Checks a code against the user's current one. `None` when there is no
    /// valid code (none sent, used, expired or invalidated) or it does not
    /// match; a wrong guess counts, and the
    /// [`EMAIL_CODE_MAX_ATTEMPTS`]th invalidates the code. When it matches it
    /// is spent if `consume`, and kept otherwise (to check something else
    /// before spending it).
    pub async fn check_email_code(
        &self,
        user_id: Id,
        code: &str,
        consume: bool,
    ) -> Result<Option<EmailToken>> {
        let code = code.trim().to_string();
        self.call(move |c, key| {
            let now = now_ms();
            let found = c
                .query_row(
                    "SELECT token_hash, email, attempts FROM email_tokens
                     WHERE user_id = ?1 AND purpose = ?2 AND used_at IS NULL
                       AND expires_at > ?3 AND attempts < ?4
                     ORDER BY created_at DESC LIMIT 1",
                    params![user_id.to_string(), CODE_PURPOSE, now, EMAIL_CODE_MAX_ATTEMPTS],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional()?;
            let Some((stored, email, attempts)) = found else {
                return Ok(None);
            };
            let salt = stored.split('$').nth(1).unwrap_or_default();
            let matches = is_email_code(&code)
                && constant_time_eq(
                    code_hash(key, user_id, salt, &code).as_bytes(),
                    stored.as_bytes(),
                );
            if !matches {
                let attempts = attempts + 1;
                let used = (attempts >= EMAIL_CODE_MAX_ATTEMPTS).then_some(now);
                c.execute(
                    "UPDATE email_tokens SET attempts = ?2, used_at = ?3 WHERE token_hash = ?1",
                    params![stored, attempts, used],
                )?;
                return Ok(None);
            }
            if consume {
                let n = c.execute(
                    "UPDATE email_tokens SET used_at = ?2 WHERE token_hash = ?1 AND used_at IS NULL",
                    params![stored, now],
                )?;
                if n == 0 {
                    return Ok(None);
                }
            }
            Ok(Some(EmailToken { user_id, email }))
        })
        .await
    }

    /// Whether the user has a code that can still be used (not spent,
    /// expired or invalidated).
    pub async fn has_email_code(&self, user_id: Id) -> Result<bool> {
        self.call(move |c, _| {
            Ok(c.query_row(
                "SELECT EXISTS(SELECT 1 FROM email_tokens
                 WHERE user_id = ?1 AND purpose = ?2 AND used_at IS NULL
                   AND expires_at > ?3 AND attempts < ?4)",
                params![
                    user_id.to_string(),
                    CODE_PURPOSE,
                    now_ms(),
                    EMAIL_CODE_MAX_ATTEMPTS
                ],
                |r| r.get::<_, bool>(0),
            )?)
        })
        .await
    }

    /// Invalidates the user's codes (the email was verified another way).
    pub async fn invalidate_email_codes(&self, user_id: Id) -> Result<()> {
        self.call(move |c, _| {
            c.execute(
                "UPDATE email_tokens SET used_at = ?3
                 WHERE user_id = ?1 AND purpose = ?2 AND used_at IS NULL",
                params![user_id.to_string(), CODE_PURPOSE, now_ms()],
            )?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_store;
    use super::*;

    #[tokio::test]
    async fn tokens_are_single_use_and_expire() {
        let store = test_store();
        let user = store
            .create_account("ana@example.com", "Ana", "long-password", false, false)
            .await
            .unwrap();
        assert!(!user.email_verified);
        let t = store
            .create_email_token(user.id, EmailPurpose::Verify, &user.email, 60_000)
            .await
            .unwrap();
        // A different purpose is rejected.
        assert!(
            store
                .consume_email_token(&t, EmailPurpose::ResetPassword)
                .await
                .unwrap()
                .is_none()
        );
        let ok = store
            .consume_email_token(&t, EmailPurpose::Verify)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ok.user_id, user.id);
        assert!(
            store
                .consume_email_token(&t, EmailPurpose::Verify)
                .await
                .unwrap()
                .is_none()
        );
        // A new one invalidates the previous one; an expired one is rejected.
        let a = store
            .create_email_token(user.id, EmailPurpose::ResetPassword, &user.email, 60_000)
            .await
            .unwrap();
        let b = store
            .create_email_token(user.id, EmailPurpose::ResetPassword, &user.email, 60_000)
            .await
            .unwrap();
        assert!(
            store
                .consume_email_token(&a, EmailPurpose::ResetPassword)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .consume_email_token(&b, EmailPurpose::ResetPassword)
                .await
                .unwrap()
                .is_some()
        );
        let old = store
            .create_email_token(user.id, EmailPurpose::Verify, &user.email, -1)
            .await
            .unwrap();
        assert!(
            store
                .consume_email_token(&old, EmailPurpose::Verify)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .last_email_token_at(user.id, EmailPurpose::Verify)
                .await
                .unwrap()
                .is_some()
        );
    }

    /// Some other six-digit code.
    fn other_code(code: &str) -> String {
        let n: u32 = code.parse().unwrap();
        format!("{:06}", (n + 1) % 1_000_000)
    }

    #[tokio::test]
    async fn email_codes() {
        let store = test_store();
        let user = store
            .create_account("ana@example.com", "Ana", "long-password", false, false)
            .await
            .unwrap();
        assert!(!store.has_email_code(user.id).await.unwrap());
        let code = store
            .create_email_code(user.id, "Ana@Example.com", 60_000)
            .await
            .unwrap();
        assert!(is_email_code(&code), "{code}");
        assert!(store.has_email_code(user.id).await.unwrap());
        // Only a keyed hash is stored, never the code.
        let stored: String = store
            .call(|c, _| {
                Ok(c.query_row(
                    "SELECT token_hash FROM email_tokens WHERE purpose = 'verify_code'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert!(stored.starts_with("c1$") && !stored.contains(&code));
        // Codes are not link tokens and vice versa.
        assert!(
            store
                .consume_email_token(&code, EmailPurpose::Verify)
                .await
                .unwrap()
                .is_none()
        );
        // Checking without consuming keeps it; consuming spends it.
        let t = store
            .check_email_code(user.id, &code, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(t.email, "ana@example.com");
        assert!(
            store
                .check_email_code(user.id, &code, true)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .check_email_code(user.id, &code, true)
                .await
                .unwrap()
                .is_none()
        );
        assert!(!store.has_email_code(user.id).await.unwrap());

        // Another user's code does not work for this one.
        let bea = store
            .create_account("bea@example.com", "Bea", "long-password", false, false)
            .await
            .unwrap();
        let bea_code = store
            .create_email_code(bea.id, &bea.email, 60_000)
            .await
            .unwrap();
        assert!(
            store
                .check_email_code(user.id, &bea_code, true)
                .await
                .unwrap()
                .is_none()
        );

        // A new code replaces the previous one.
        let first = store
            .create_email_code(user.id, &user.email, 60_000)
            .await
            .unwrap();
        let second = store
            .create_email_code(user.id, &user.email, 60_000)
            .await
            .unwrap();
        if first != second {
            assert!(
                store
                    .check_email_code(user.id, &first, true)
                    .await
                    .unwrap()
                    .is_none()
            );
        }

        // Wrong guesses (the old code above was one): the fifth invalidates
        // the code, even the right one.
        let second = store
            .create_email_code(user.id, &user.email, 60_000)
            .await
            .unwrap();
        let wrong = other_code(&second);
        for _ in 0..EMAIL_CODE_MAX_ATTEMPTS - 1 {
            assert!(
                store
                    .check_email_code(user.id, &wrong, true)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(store.has_email_code(user.id).await.unwrap());
        }
        assert!(
            store
                .check_email_code(user.id, "12345", true)
                .await
                .unwrap()
                .is_none()
        );
        assert!(!store.has_email_code(user.id).await.unwrap());
        assert!(
            store
                .check_email_code(user.id, &second, true)
                .await
                .unwrap()
                .is_none()
        );

        // A right guess after a few wrong ones still works.
        let code = store
            .create_email_code(user.id, &user.email, 60_000)
            .await
            .unwrap();
        assert!(
            store
                .check_email_code(user.id, &other_code(&code), true)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .check_email_code(user.id, &code, true)
                .await
                .unwrap()
                .is_some()
        );

        // Expired.
        let old = store
            .create_email_code(user.id, &user.email, -1)
            .await
            .unwrap();
        assert!(!store.has_email_code(user.id).await.unwrap());
        assert!(
            store
                .check_email_code(user.id, &old, true)
                .await
                .unwrap()
                .is_none()
        );

        // Invalidated.
        let code = store
            .create_email_code(user.id, &user.email, 60_000)
            .await
            .unwrap();
        store.invalidate_email_codes(user.id).await.unwrap();
        assert!(
            store
                .check_email_code(user.id, &code, true)
                .await
                .unwrap()
                .is_none()
        );
        // Bea's code was not touched.
        assert!(
            store
                .check_email_code(bea.id, &bea_code, true)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn random_codes_have_six_digits() {
        for _ in 0..200 {
            assert!(is_email_code(&random_code()));
        }
        assert!(!is_email_code("12345a"));
        assert!(!is_email_code("1234567"));
        assert!(!is_email_code("１２３４５６"));
    }

    #[tokio::test]
    async fn delete_account_removes_data() {
        use crate::model::TeamRole;
        let store = test_store();
        let ana = store
            .create_user("ana@example.com", "Ana", "long-password", false)
            .await
            .unwrap();
        let bob = store
            .create_user("bob@example.com", "Bob", "long-password", false)
            .await
            .unwrap();
        let solo = store.create_team(ana.id, "Just Ana").await.unwrap();
        let shared = store.create_team(ana.id, "With Bob").await.unwrap();
        store
            .set_team_member(shared.id, bob.id, TeamRole::Owner)
            .await
            .unwrap();
        store.delete_user(ana.id).await.unwrap();
        assert!(store.user(ana.id).await.is_err());
        assert!(store.team_for(solo.id, bob.id).await.is_err());
        let left = store.team_members(shared.id).await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].user_id, bob.id);
        // Their email is free again.
        store
            .create_user("ana@example.com", "Ana", "long-password", false)
            .await
            .unwrap();
    }
}

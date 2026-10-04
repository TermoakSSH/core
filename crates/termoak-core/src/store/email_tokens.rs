//! Single-use tokens sent by email: verifying the email, resetting the
//! password and confirming an email change.

use rusqlite::{OptionalExtension, params};

use super::{Store, parse_id};
use crate::Id;
use crate::crypto::{prefixed_token, sha256_hex};
use crate::error::Result;
use crate::time::now_ms;

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

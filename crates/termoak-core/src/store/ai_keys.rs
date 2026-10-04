//! The users' own AI API keys (Claude, OpenAI, OpenRouter...).
//!
//! The key is sealed with the master key, bound to its user and provider
//! (AAD `termoak:ai-key:{user_id}:{provider}`), and never leaves the server:
//! the API only shows a hint with its last characters.

use rusqlite::params;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::Store;
use crate::Id;
use crate::crypto::MasterKey;
use crate::error::{CoreError, Result};
use crate::time::now_ms;

/// Public data of a stored key (never the key itself).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UserAiKey {
    /// Provider key (`claude`, `gpt`, `openrouter`, `opencode-api`).
    pub provider: String,
    /// Model chosen by the user (`None` = the provider's default).
    pub model: Option<String>,
    /// Last 4 characters of the key, so the user can tell which one it is.
    pub hint: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// A decrypted key, only for the AI engine.
#[derive(Clone)]
pub struct AiKeySecret {
    pub provider: String,
    pub key: Zeroizing<String>,
    pub model: Option<String>,
}

impl std::fmt::Debug for AiKeySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiKeySecret")
            .field("provider", &self.provider)
            .field("key", &"***")
            .field("model", &self.model)
            .finish()
    }
}

fn aad(user_id: Id, provider: &str) -> Vec<u8> {
    format!("termoak:ai-key:{user_id}:{provider}").into_bytes()
}

/// Last 4 characters of a key.
pub fn key_hint(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    chars[chars.len().saturating_sub(4)..].iter().collect()
}

type KeyRow = (String, Vec<u8>, Option<String>, i64, i64);

fn read_rows(c: &rusqlite::Connection, user_id: Id, provider: Option<&str>) -> Result<Vec<KeyRow>> {
    let mut stmt = c.prepare(
        "SELECT provider, secret, model, created_at, updated_at FROM user_ai_keys
         WHERE user_id = ?1 AND (?2 IS NULL OR provider = ?2) ORDER BY provider",
    )?;
    Ok(stmt
        .query_map(params![user_id.to_string(), provider], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

fn open_key(
    key: &MasterKey,
    user_id: Id,
    provider: &str,
    sealed: &[u8],
) -> Result<Zeroizing<String>> {
    let plain = key.open(sealed, &aad(user_id, provider))?;
    String::from_utf8(plain.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| CoreError::Crypto("the stored AI key is not text".into()))
}

impl Store {
    /// Saves (or replaces) a user's key for a provider.
    pub async fn set_user_ai_key(
        &self,
        user_id: Id,
        provider: &str,
        api_key: &str,
        model: Option<&str>,
    ) -> Result<UserAiKey> {
        let provider = provider.to_string();
        let api_key = Zeroizing::new(api_key.to_string());
        let model = model.map(str::to_string);
        self.call(move |c, key| {
            let sealed = key.seal(api_key.as_bytes(), &aad(user_id, &provider))?;
            let now = now_ms();
            c.execute(
                "INSERT INTO user_ai_keys (user_id, provider, secret, model, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                 ON CONFLICT(user_id, provider) DO UPDATE SET
                     secret = excluded.secret, model = excluded.model, updated_at = excluded.updated_at",
                params![user_id.to_string(), provider, sealed, model, now],
            )?;
            let created_at: i64 = c.query_row(
                "SELECT created_at FROM user_ai_keys WHERE user_id = ?1 AND provider = ?2",
                params![user_id.to_string(), provider],
                |r| r.get(0),
            )?;
            Ok(UserAiKey {
                hint: key_hint(&api_key),
                provider,
                model,
                created_at,
                updated_at: now,
            })
        })
        .await
    }

    /// Changes only the model of a saved key (`None` = the provider's
    /// default). Returns `None` if the user has no key for that provider.
    pub async fn set_user_ai_key_model(
        &self,
        user_id: Id,
        provider: &str,
        model: Option<&str>,
    ) -> Result<Option<UserAiKey>> {
        let provider = provider.to_string();
        let model = model.map(str::to_string);
        self.call(move |c, key| {
            let changed = c.execute(
                "UPDATE user_ai_keys SET model = ?3, updated_at = ?4
                 WHERE user_id = ?1 AND provider = ?2",
                params![user_id.to_string(), provider, model, now_ms()],
            )?;
            if changed == 0 {
                return Ok(None);
            }
            read_rows(c, user_id, Some(&provider))?
                .into_iter()
                .next()
                .map(|(provider, sealed, model, created_at, updated_at)| {
                    Ok(UserAiKey {
                        hint: key_hint(&open_key(key, user_id, &provider, &sealed)?),
                        provider,
                        model,
                        created_at,
                        updated_at,
                    })
                })
                .transpose()
        })
        .await
    }

    /// A user's keys (without the keys).
    pub async fn user_ai_keys(&self, user_id: Id) -> Result<Vec<UserAiKey>> {
        self.call(move |c, key| {
            read_rows(c, user_id, None)?
                .into_iter()
                .map(|(provider, sealed, model, created_at, updated_at)| {
                    let hint = key_hint(&open_key(key, user_id, &provider, &sealed)?);
                    Ok(UserAiKey {
                        provider,
                        model,
                        hint,
                        created_at,
                        updated_at,
                    })
                })
                .collect()
        })
        .await
    }

    /// A user's decrypted keys (for the AI engine). Keys that cannot be
    /// decrypted are skipped with a warning.
    pub async fn user_ai_key_secrets(&self, user_id: Id) -> Result<Vec<AiKeySecret>> {
        self.call(move |c, key| {
            Ok(read_rows(c, user_id, None)?
                .into_iter()
                .filter_map(|(provider, sealed, model, _, _)| {
                    match open_key(key, user_id, &provider, &sealed) {
                        Ok(k) => Some(AiKeySecret {
                            provider,
                            key: k,
                            model,
                        }),
                        Err(e) => {
                            tracing::warn!(user = %user_id, %provider, error = %e, "could not open an AI key");
                            None
                        }
                    }
                })
                .collect())
        })
        .await
    }

    /// One decrypted key of a user, if they have it.
    pub async fn user_ai_key_secret(
        &self,
        user_id: Id,
        provider: &str,
    ) -> Result<Option<AiKeySecret>> {
        let provider = provider.to_string();
        self.call(move |c, key| {
            let row = read_rows(c, user_id, Some(&provider))?.into_iter().next();
            row.map(|(provider, sealed, model, _, _)| {
                Ok(AiKeySecret {
                    key: open_key(key, user_id, &provider, &sealed)?,
                    provider,
                    model,
                })
            })
            .transpose()
        })
        .await
    }

    /// Deletes a user's key. `false` if there was none.
    pub async fn delete_user_ai_key(&self, user_id: Id, provider: &str) -> Result<bool> {
        let provider = provider.to_string();
        self.call(move |c, _| {
            Ok(c.execute(
                "DELETE FROM user_ai_keys WHERE user_id = ?1 AND provider = ?2",
                params![user_id.to_string(), provider],
            )? > 0)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_store;
    use super::*;

    #[tokio::test]
    async fn keys_are_sealed_and_removed_with_the_user() {
        let store = test_store();
        let user = store
            .create_user("keys@example.com", "Keys", "long-password", false)
            .await
            .unwrap();
        let other = store
            .create_user("other@example.com", "Other", "long-password", false)
            .await
            .unwrap();
        let saved = store
            .set_user_ai_key(user.id, "claude", "sk-ant-secret-1234", None)
            .await
            .unwrap();
        assert_eq!(saved.hint, "1234");
        store
            .set_user_ai_key(other.id, "claude", "sk-other-9999", None)
            .await
            .unwrap();

        // The blob is encrypted and bound to its user and provider.
        let blob: Vec<u8> = store
            .call(move |c, _| {
                Ok(c.query_row(
                    "SELECT secret FROM user_ai_keys WHERE user_id = ?1",
                    [user.id.to_string()],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&blob).contains("sk-ant-secret"));
        let key = store.master_key().clone();
        assert!(key.open(&blob, &aad(user.id, "claude")).is_ok());
        assert!(key.open(&blob, &aad(user.id, "gpt")).is_err());
        assert!(key.open(&blob, &aad(other.id, "claude")).is_err());

        // Replacing keeps created_at and updates the model.
        let replaced = store
            .set_user_ai_key(
                user.id,
                "claude",
                "sk-ant-new-5678",
                Some("claude-sonnet-5"),
            )
            .await
            .unwrap();
        assert_eq!(replaced.created_at, saved.created_at);
        let list = store.user_ai_keys(user.id).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].hint, "5678");
        assert_eq!(list[0].model.as_deref(), Some("claude-sonnet-5"));
        let secret = store
            .user_ai_key_secret(user.id, "claude")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(secret.key.as_str(), "sk-ant-new-5678");

        // Changing only the model keeps the key.
        let changed = store
            .set_user_ai_key_model(user.id, "claude", Some("claude-opus-5"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (changed.hint.as_str(), changed.model.as_deref()),
            ("5678", Some("claude-opus-5"))
        );
        assert_eq!(changed.created_at, saved.created_at);
        let secret = store
            .user_ai_key_secret(user.id, "claude")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(secret.key.as_str(), "sk-ant-new-5678");
        assert!(
            store
                .set_user_ai_key_model(user.id, "gpt", None)
                .await
                .unwrap()
                .is_none()
        );
        assert!(!format!("{secret:?}").contains("sk-ant"));
        assert!(
            store
                .user_ai_key_secret(user.id, "gpt")
                .await
                .unwrap()
                .is_none()
        );

        // Deleting the account deletes its keys.
        store.delete_user(user.id).await.unwrap();
        assert!(store.user_ai_key_secrets(user.id).await.unwrap().is_empty());
        assert_eq!(store.user_ai_keys(other.id).await.unwrap().len(), 1);
        assert!(store.delete_user_ai_key(other.id, "claude").await.unwrap());
        assert!(!store.delete_user_ai_key(other.id, "claude").await.unwrap());
    }

    #[tokio::test]
    async fn only_server_credit_is_counted() {
        use crate::store::AiUsageRow;
        let store = test_store();
        let owner = crate::new_id();
        // (own key, credit, time): the real cost does not count, only the credit.
        for (own_key, credit, at) in [(false, 100, 1_000), (true, 500, 1_000), (false, 40, 10)] {
            store
                .ai_record_usage(AiUsageRow {
                    owner_id: owner,
                    task_id: None,
                    provider: "claude::claude-opus-5".into(),
                    own_key,
                    input_tokens: 10,
                    output_tokens: 5,
                    cost_micros: 500,
                    credit_micros: credit,
                    created_at: at,
                })
                .await
                .unwrap();
        }
        assert_eq!(store.ai_credit_spent_since(owner, 0).await.unwrap(), 140);
        assert_eq!(store.ai_credit_spent_since(owner, 500).await.unwrap(), 100);
        // The real cost counts every call (own keys too): 3 × 500.
        assert_eq!(store.ai_usage_cost_since(owner, 0).await.unwrap(), 1500);
        assert_eq!(store.ai_usage_cost_since(owner, 500).await.unwrap(), 1000);
        assert_eq!(
            store
                .ai_credit_spent_since(crate::new_id(), 0)
                .await
                .unwrap(),
            0
        );
    }

    #[test]
    fn hints() {
        assert_eq!(key_hint("sk-abcdef"), "cdef");
        assert_eq!(key_hint("ab"), "ab");
    }
}

//! Server users and devices (access tokens).

use rusqlite::{OptionalExtension, params};

use super::{Store, parse_id};
use crate::crypto::{hash_password, prefixed_token, sha256_hex, verify_password};
use crate::error::{CoreError, Result};
use crate::model::{Device, TokenPair, User};
use crate::time::now_ms;
use crate::{Id, new_id};

/// Token lifetimes.
#[derive(Debug, Clone, Copy)]
pub struct TokenTtl {
    pub access_ms: i64,
    pub refresh_ms: i64,
}

impl Default for TokenTtl {
    fn default() -> Self {
        Self {
            access_ms: 60 * 60 * 1000,            // 1 hour
            refresh_ms: 90 * 24 * 60 * 60 * 1000, // 90 days
        }
    }
}

const USER_COLUMNS: &str =
    "id, email, name, is_admin, created_at, disabled, totp_enabled, plan, email_verified, locale";

fn map_user(r: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: parse_id(&r.get::<_, String>(0)?)?,
        email: r.get(1)?,
        name: r.get(2)?,
        is_admin: r.get::<_, i64>(3)? != 0,
        created_at: r.get(4)?,
        disabled: r.get::<_, i64>(5)? != 0,
        totp_enabled: r.get::<_, i64>(6)? != 0,
        plan: r.get(7)?,
        email_verified: r.get::<_, i64>(8)? != 0,
        locale: r.get(9)?,
    })
}

/// AAD of the TOTP secret (binds it to the user).
fn totp_aad(user_id: Id) -> Vec<u8> {
    format!("{}:totp:{user_id}", crate::crypto::LEGACY_AAD_PREFIX).into_bytes()
}

/// Result of checking the second factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondFactor {
    /// Valid TOTP code.
    Totp,
    /// Valid recovery code (now spent).
    RecoveryCode,
    Invalid,
}

const DEVICE_COLUMNS: &str = "id, user_id, name, platform, created_at, last_seen_at, \
                              access_expires_at, refresh_expires_at, push_platform";

/// Device that receives push notifications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushTarget {
    pub device_id: Id,
    /// `apns` or `fcm`.
    pub platform: String,
    pub token: String,
    /// Sandbox APNs (apps built in development mode).
    pub sandbox: bool,
}

fn map_device(r: &rusqlite::Row<'_>) -> rusqlite::Result<Device> {
    Ok(Device {
        id: parse_id(&r.get::<_, String>(0)?)?,
        user_id: parse_id(&r.get::<_, String>(1)?)?,
        name: r.get(2)?,
        platform: r.get(3)?,
        created_at: r.get(4)?,
        last_seen_at: r.get(5)?,
        access_expires_at: r.get(6)?,
        refresh_expires_at: r.get(7)?,
        push: r.get(8)?,
    })
}

fn get_user(c: &rusqlite::Connection, user_id: Id) -> Result<User> {
    c.query_row(
        &format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?1"),
        [user_id.to_string()],
        map_user,
    )
    .optional()?
    .ok_or_else(|| CoreError::NotFound(format!("user {user_id}")))
}

/// Dummy (valid) hash to equalize timing when the user does not exist.
fn dummy_hash() -> &'static str {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DUMMY.get_or_init(|| hash_password("termoak-dummy-password").unwrap_or_default())
}

fn normalize_email(email: &str) -> Result<String> {
    let email = email.trim().to_lowercase();
    if email.len() < 3 || !email.contains('@') || email.chars().any(char::is_whitespace) {
        return Err(CoreError::Invalid("invalid email".into()));
    }
    Ok(email)
}

/// Minimum password length.
pub const MIN_PASSWORD_LEN: usize = 10;

fn check_password_policy(password: &str) -> Result<()> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(CoreError::Invalid(format!(
            "the password must be at least {MIN_PASSWORD_LEN} characters long"
        )));
    }
    Ok(())
}

impl Store {
    pub async fn count_users(&self) -> Result<i64> {
        self.call(|c, _| Ok(c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?))
            .await
    }

    /// Creates a user with an already verified email. The password hash is
    /// computed outside the mutex.
    pub async fn create_user(
        &self,
        email: &str,
        name: &str,
        password: &str,
        is_admin: bool,
    ) -> Result<User> {
        self.create_account(email, name, password, is_admin, true)
            .await
    }

    /// Creates a user, stating whether their email is verified.
    pub async fn create_account(
        &self,
        email: &str,
        name: &str,
        password: &str,
        is_admin: bool,
        email_verified: bool,
    ) -> Result<User> {
        let email = normalize_email(email)?;
        check_password_policy(password)?;
        let name = if name.trim().is_empty() {
            email.split('@').next().unwrap_or("user").to_string()
        } else {
            name.trim().to_string()
        };
        let password = password.to_string();
        let hash = tokio::task::spawn_blocking(move || hash_password(&password))
            .await
            .map_err(|e| CoreError::Join(e.to_string()))??;
        self.call(move |c, _| {
            let user = User {
                id: new_id(),
                email,
                name,
                is_admin,
                created_at: now_ms(),
                disabled: false,
                totp_enabled: false,
                plan: crate::model::default_plan(),
                email_verified,
                locale: crate::model::default_locale(),
            };
            let res = c.execute(
                "INSERT INTO users (id, email, name, password_hash, is_admin, disabled, created_at,
                                    email_verified)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7)",
                params![
                    user.id.to_string(),
                    user.email,
                    user.name,
                    hash,
                    user.is_admin as i64,
                    user.created_at,
                    email_verified as i64
                ],
            );
            match res {
                Ok(_) => Ok(user),
                Err(rusqlite::Error::SqliteFailure(e, _))
                    if e.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    Err(CoreError::Conflict(
                        "a user with that email already exists".into(),
                    ))
                }
                Err(e) => Err(e.into()),
            }
        })
        .await
    }

    pub async fn user(&self, id: Id) -> Result<User> {
        self.call(move |c, _| {
            c.query_row(
                &format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?1"),
                [id.to_string()],
                map_user,
            )
            .optional()?
            .ok_or_else(|| CoreError::NotFound(format!("user {id}")))
        })
        .await
    }

    pub async fn user_by_email(&self, email: &str) -> Result<Option<User>> {
        let email = normalize_email(email)?;
        self.call(move |c, _| {
            Ok(c.query_row(
                &format!("SELECT {USER_COLUMNS} FROM users WHERE email = ?1"),
                [email],
                map_user,
            )
            .optional()?)
        })
        .await
    }

    pub async fn list_users(&self) -> Result<Vec<User>> {
        self.call(|c, _| {
            let mut stmt = c.prepare(&format!(
                "SELECT {USER_COLUMNS} FROM users ORDER BY created_at"
            ))?;
            Ok(stmt
                .query_map([], map_user)?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// Checks email + password. Takes the same time whether or not the user exists.
    pub async fn verify_login(&self, email: &str, password: &str) -> Result<Option<User>> {
        let email = match normalize_email(email) {
            Ok(e) => e,
            Err(_) => return Ok(None),
        };
        let row = self
            .call(move |c, _| {
                Ok(c.query_row(
                    &format!("SELECT {USER_COLUMNS}, password_hash FROM users WHERE email = ?1"),
                    [email],
                    |r| Ok((map_user(r)?, r.get::<_, String>(10)?)),
                )
                .optional()?)
            })
            .await?;
        let password = password.to_string();
        let (user, hash) = match row {
            Some((u, h)) => (Some(u), h),
            None => (None, dummy_hash().to_string()),
        };
        let ok = tokio::task::spawn_blocking(move || verify_password(&password, &hash))
            .await
            .map_err(|e| CoreError::Join(e.to_string()))?;
        Ok(match user {
            Some(u) if ok && !u.disabled => Some(u),
            _ => None,
        })
    }

    pub async fn set_password(&self, user_id: Id, password: &str) -> Result<()> {
        check_password_policy(password)?;
        let password = password.to_string();
        let hash = tokio::task::spawn_blocking(move || hash_password(&password))
            .await
            .map_err(|e| CoreError::Join(e.to_string()))??;
        self.call(move |c, _| {
            let n = c.execute(
                "UPDATE users SET password_hash = ?2 WHERE id = ?1",
                params![user_id.to_string(), hash],
            )?;
            if n == 0 {
                return Err(CoreError::NotFound(format!("user {user_id}")));
            }
            Ok(())
        })
        .await
    }

    pub async fn update_user(
        &self,
        user_id: Id,
        name: Option<String>,
        is_admin: Option<bool>,
        disabled: Option<bool>,
    ) -> Result<User> {
        self.call(move |c, _| {
            if let Some(name) = name {
                c.execute(
                    "UPDATE users SET name = ?2 WHERE id = ?1",
                    params![user_id.to_string(), name.trim()],
                )?;
            }
            if let Some(a) = is_admin {
                c.execute(
                    "UPDATE users SET is_admin = ?2 WHERE id = ?1",
                    params![user_id.to_string(), a as i64],
                )?;
            }
            if let Some(d) = disabled {
                c.execute(
                    "UPDATE users SET disabled = ?2 WHERE id = ?1",
                    params![user_id.to_string(), d as i64],
                )?;
                if d {
                    c.execute(
                        "DELETE FROM devices WHERE user_id = ?1",
                        [user_id.to_string()],
                    )?;
                }
            }
            c.query_row(
                &format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?1"),
                [user_id.to_string()],
                map_user,
            )
            .optional()?
            .ok_or_else(|| CoreError::NotFound(format!("user {user_id}")))
        })
        .await
    }

    /// Changes a user's plan.
    pub async fn set_user_plan(&self, user_id: Id, plan: &str) -> Result<User> {
        let plan = plan.trim().to_string();
        self.call(move |c, _| {
            c.execute(
                "UPDATE users SET plan = ?2 WHERE id = ?1",
                params![user_id.to_string(), plan],
            )?;
            get_user(c, user_id)
        })
        .await
    }

    /// Marks the email as verified (or not).
    pub async fn set_email_verified(&self, user_id: Id, verified: bool) -> Result<User> {
        self.call(move |c, _| {
            c.execute(
                "UPDATE users SET email_verified = ?2 WHERE id = ?1",
                params![user_id.to_string(), verified as i64],
            )?;
            get_user(c, user_id)
        })
        .await
    }

    /// Changes the preferred language (the caller validates it).
    pub async fn set_locale(&self, user_id: Id, locale: &str) -> Result<User> {
        let locale = locale.to_string();
        self.call(move |c, _| {
            c.execute(
                "UPDATE users SET locale = ?2 WHERE id = ?1",
                params![user_id.to_string(), locale],
            )?;
            get_user(c, user_id)
        })
        .await
    }

    /// Changes the email (already verified).
    pub async fn set_email(&self, user_id: Id, email: &str) -> Result<User> {
        let email = normalize_email(email)?;
        self.call(move |c, _| {
            let res = c.execute(
                "UPDATE users SET email = ?2, email_verified = 1 WHERE id = ?1",
                params![user_id.to_string(), email],
            );
            match res {
                Ok(_) => get_user(c, user_id),
                Err(rusqlite::Error::SqliteFailure(e, _))
                    if e.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    Err(CoreError::Conflict(
                        "a user with that email already exists".into(),
                    ))
                }
                Err(e) => Err(e.into()),
            }
        })
        .await
    }

    /// Deletes an account and all its data: vault records, sessions and
    /// history, AI tasks, its own audit log, pending invites it created and
    /// the teams where it was the only member. Teams with other members are
    /// kept (the caller must first check they are not left without an
    /// owner).
    pub async fn delete_user(&self, user_id: Id) -> Result<()> {
        self.call(move |c, _| {
            let id = user_id.to_string();
            let tx = c.transaction()?;
            // Teams where they were the only member.
            tx.execute(
                "DELETE FROM session_shares WHERE team_id IN (
                     SELECT team_id FROM team_members GROUP BY team_id
                     HAVING COUNT(*) = 1 AND MAX(user_id) = ?1)",
                [&id],
            )?;
            tx.execute(
                "DELETE FROM teams WHERE id IN (
                     SELECT team_id FROM team_members GROUP BY team_id
                     HAVING COUNT(*) = 1 AND MAX(user_id) = ?1)",
                [&id],
            )?;
            tx.execute("DELETE FROM entities WHERE owner_id = ?1", [&id])?;
            tx.execute(
                "DELETE FROM session_shares WHERE user_id = ?1 OR created_by = ?1",
                [&id],
            )?;
            tx.execute("DELETE FROM sessions WHERE owner_id = ?1", [&id])?;
            tx.execute("DELETE FROM ai_tasks WHERE owner_id = ?1", [&id])?;
            tx.execute("DELETE FROM ai_usage WHERE owner_id = ?1", [&id])?;
            tx.execute("DELETE FROM user_ai_keys WHERE user_id = ?1", [&id])?;
            tx.execute("DELETE FROM audit_log WHERE owner_id = ?1", [&id])?;
            tx.execute("DELETE FROM command_history WHERE owner_id = ?1", [&id])?;
            tx.execute(
                "DELETE FROM invites WHERE created_by = ?1 AND used_by IS NULL",
                [&id],
            )?;
            let n = tx.execute("DELETE FROM users WHERE id = ?1", [&id])?;
            if n == 0 {
                return Err(CoreError::NotFound(format!("user {user_id}")));
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    /// Stores a device's push notification token. The same token is removed
    /// from any other device (a reinstall or a new sign-in on the same
    /// phone).
    pub async fn set_push_token(
        &self,
        device_id: Id,
        platform: &str,
        token: &str,
        sandbox: bool,
    ) -> Result<()> {
        let (platform, token) = (platform.to_string(), token.trim().to_string());
        if !matches!(platform.as_str(), "apns" | "fcm") {
            return Err(CoreError::Invalid(
                "invalid notification platform (apns or fcm)".into(),
            ));
        }
        if token.is_empty() || token.len() > 4096 || token.chars().any(char::is_whitespace) {
            return Err(CoreError::Invalid("invalid notification token".into()));
        }
        self.call(move |c, _| {
            c.execute(
                "UPDATE devices SET push_platform = NULL, push_token = NULL, push_sandbox = 0
                 WHERE push_token = ?1 AND id != ?2",
                params![token, device_id.to_string()],
            )?;
            let n = c.execute(
                "UPDATE devices SET push_platform = ?2, push_token = ?3, push_sandbox = ?4 WHERE id = ?1",
                params![device_id.to_string(), platform, token, sandbox as i64],
            )?;
            if n == 0 {
                return Err(CoreError::NotFound(format!("device {device_id}")));
            }
            Ok(())
        })
        .await
    }

    /// Stops sending notifications to a device.
    pub async fn clear_push_token(&self, device_id: Id) -> Result<()> {
        self.call(move |c, _| {
            c.execute(
                "UPDATE devices SET push_platform = NULL, push_token = NULL, push_sandbox = 0 WHERE id = ?1",
                [device_id.to_string()],
            )?;
            Ok(())
        })
        .await
    }

    /// Removes a token the notification service reports as expired.
    pub async fn forget_push_token(&self, token: &str) -> Result<()> {
        let token = token.to_string();
        self.call(move |c, _| {
            c.execute(
                "UPDATE devices SET push_platform = NULL, push_token = NULL, push_sandbox = 0
                 WHERE push_token = ?1",
                [token],
            )?;
            Ok(())
        })
        .await
    }

    /// A user's devices with notifications enabled (and a valid session).
    pub async fn push_targets(&self, user_id: Id) -> Result<Vec<PushTarget>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(
                "SELECT id, push_platform, push_token, push_sandbox FROM devices
                 WHERE user_id = ?1 AND push_token IS NOT NULL AND refresh_expires_at > ?2",
            )?;
            let rows = stmt.query_map(params![user_id.to_string(), now_ms()], |r| {
                Ok(PushTarget {
                    device_id: parse_id(&r.get::<_, String>(0)?)?,
                    platform: r.get(1)?,
                    token: r.get(2)?,
                    sandbox: r.get::<_, i64>(3)? != 0,
                })
            })?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// Issues tokens for a new device.
    pub async fn issue_device(
        &self,
        user_id: Id,
        name: &str,
        platform: &str,
        ttl: TokenTtl,
    ) -> Result<TokenPair> {
        let (name, platform) = (name.trim().to_string(), platform.trim().to_string());
        self.call(move |c, _| {
            let now = now_ms();
            let id = new_id();
            let access = prefixed_token("aks_at");
            let refresh = prefixed_token("aks_rt");
            let pair = TokenPair {
                access_expires_at: now + ttl.access_ms,
                refresh_expires_at: now + ttl.refresh_ms,
                access_token: access,
                refresh_token: refresh,
                device_id: id,
            };
            c.execute(
                "INSERT INTO devices (id, user_id, name, platform, access_hash, access_expires_at,
                                      refresh_hash, refresh_expires_at, created_at, last_seen_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)",
                params![
                    id.to_string(),
                    user_id.to_string(),
                    if name.is_empty() { "device" } else { &name },
                    if platform.is_empty() {
                        "unknown"
                    } else {
                        &platform
                    },
                    sha256_hex(pair.access_token.as_bytes()),
                    pair.access_expires_at,
                    sha256_hex(pair.refresh_token.as_bytes()),
                    pair.refresh_expires_at,
                    now
                ],
            )?;
            Ok(pair)
        })
        .await
    }

    /// Validates an access token and returns its user and device.
    pub async fn authenticate(&self, access_token: &str) -> Result<Option<(User, Device)>> {
        let hash = sha256_hex(access_token.as_bytes());
        self.call(move |c, _| {
            let now = now_ms();
            let found = c
                .query_row(
                    &format!(
                        "SELECT {DEVICE_COLUMNS} FROM devices
                         WHERE access_hash = ?1 AND access_expires_at > ?2"
                    ),
                    params![hash, now],
                    map_device,
                )
                .optional()?;
            let Some(device) = found else { return Ok(None) };
            let user = c
                .query_row(
                    &format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?1"),
                    [device.user_id.to_string()],
                    map_user,
                )
                .optional()?;
            let Some(user) = user else { return Ok(None) };
            if user.disabled {
                return Ok(None);
            }
            // Updates "last seen" at most once a minute.
            if now - device.last_seen_at > 60_000 {
                c.execute(
                    "UPDATE devices SET last_seen_at = ?2 WHERE id = ?1",
                    params![device.id.to_string(), now],
                )?;
            }
            Ok(Some((user, device)))
        })
        .await
    }

    /// Rotates the tokens using the refresh token.
    pub async fn refresh_device(
        &self,
        refresh_token: &str,
        ttl: TokenTtl,
    ) -> Result<Option<TokenPair>> {
        let hash = sha256_hex(refresh_token.as_bytes());
        self.call(move |c, _| {
            let now = now_ms();
            let device: Option<(String, String)> = c
                .query_row(
                    "SELECT d.id, d.user_id FROM devices d JOIN users u ON u.id = d.user_id
                     WHERE d.refresh_hash = ?1 AND d.refresh_expires_at > ?2 AND u.disabled = 0",
                    params![hash, now],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((device_id, _user_id)) = device else {
                return Ok(None);
            };
            let access = prefixed_token("aks_at");
            let refresh = prefixed_token("aks_rt");
            let pair = TokenPair {
                access_expires_at: now + ttl.access_ms,
                refresh_expires_at: now + ttl.refresh_ms,
                access_token: access,
                refresh_token: refresh,
                device_id: parse_id(&device_id)?,
            };
            c.execute(
                "UPDATE devices SET access_hash = ?2, access_expires_at = ?3, refresh_hash = ?4,
                        refresh_expires_at = ?5, last_seen_at = ?6
                 WHERE id = ?1",
                params![
                    device_id,
                    sha256_hex(pair.access_token.as_bytes()),
                    pair.access_expires_at,
                    sha256_hex(pair.refresh_token.as_bytes()),
                    pair.refresh_expires_at,
                    now
                ],
            )?;
            Ok(Some(pair))
        })
        .await
    }

    pub async fn list_devices(&self, user_id: Id) -> Result<Vec<Device>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(&format!(
                "SELECT {DEVICE_COLUMNS} FROM devices WHERE user_id = ?1 ORDER BY last_seen_at DESC"
            ))?;
            Ok(stmt
                .query_map([user_id.to_string()], map_device)?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// Signs a user out of all their devices.
    pub async fn revoke_all_devices(&self, user_id: Id) -> Result<usize> {
        self.call(move |c, _| {
            Ok(c.execute(
                "DELETE FROM devices WHERE user_id = ?1",
                [user_id.to_string()],
            )?)
        })
        .await
    }

    /// Signs a device out.
    pub async fn revoke_device(&self, user_id: Id, device_id: Id) -> Result<()> {
        self.call(move |c, _| {
            let n = c.execute(
                "DELETE FROM devices WHERE id = ?1 AND user_id = ?2",
                params![device_id.to_string(), user_id.to_string()],
            )?;
            if n == 0 {
                return Err(CoreError::NotFound(format!("device {device_id}")));
            }
            Ok(())
        })
        .await
    }
}

impl Store {
    /// Checks the password of an already authenticated user (e.g. to disable
    /// two-factor authentication).
    pub async fn check_password(&self, user_id: Id, password: &str) -> Result<bool> {
        let hash: Option<String> = self
            .call(move |c, _| {
                Ok(c.query_row(
                    "SELECT password_hash FROM users WHERE id = ?1",
                    [user_id.to_string()],
                    |r| r.get(0),
                )
                .optional()?)
            })
            .await?;
        let Some(hash) = hash else {
            return Ok(false);
        };
        let password = password.to_string();
        tokio::task::spawn_blocking(move || verify_password(&password, &hash))
            .await
            .map_err(|e| CoreError::Join(e.to_string()))
    }

    /// Starts setting up two-factor authentication: stores a new (encrypted)
    /// secret without enabling it yet. Returns the plaintext secret to show
    /// it as a QR code.
    pub async fn totp_begin(&self, user_id: Id) -> Result<Vec<u8>> {
        self.call(move |c, key| {
            let enabled: Option<i64> = c
                .query_row(
                    "SELECT totp_enabled FROM users WHERE id = ?1",
                    [user_id.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            match enabled {
                None => return Err(CoreError::NotFound(format!("user {user_id}"))),
                Some(1) => {
                    return Err(CoreError::Conflict(
                        "two-factor authentication is already enabled".into(),
                    ));
                }
                Some(_) => {}
            }
            let secret = crate::totp::generate_secret();
            let sealed = key.seal(&secret, &totp_aad(user_id))?;
            c.execute(
                "UPDATE users SET totp_secret = ?2, totp_last_step = 0 WHERE id = ?1",
                params![user_id.to_string(), sealed],
            )?;
            Ok(secret)
        })
        .await
    }

    /// Enables two-factor authentication if the code is correct.
    /// Returns the recovery codes (shown only this once).
    pub async fn totp_enable(
        &self,
        user_id: Id,
        code: &str,
        unix_secs: u64,
    ) -> Result<Vec<String>> {
        let code = code.to_string();
        self.call(move |c, key| {
            let (sealed, enabled): (Option<Vec<u8>>, i64) = c
                .query_row(
                    "SELECT totp_secret, totp_enabled FROM users WHERE id = ?1",
                    [user_id.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?
                .ok_or_else(|| CoreError::NotFound(format!("user {user_id}")))?;
            if enabled == 1 {
                return Err(CoreError::Conflict(
                    "two-factor authentication is already enabled".into(),
                ));
            }
            let sealed = sealed.ok_or_else(|| {
                CoreError::Invalid("generate the QR code first (set up 2FA)".into())
            })?;
            let secret = key.open(&sealed, &totp_aad(user_id))?;
            let step = crate::totp::verify(&secret, &code, unix_secs, 0)
                .ok_or_else(|| CoreError::Invalid("incorrect code".into()))?;
            let codes = crate::totp::recovery_codes(10);
            let tx = c.transaction()?;
            tx.execute(
                "UPDATE users SET totp_enabled = 1, totp_last_step = ?2 WHERE id = ?1",
                params![user_id.to_string(), step as i64],
            )?;
            tx.execute(
                "DELETE FROM recovery_codes WHERE user_id = ?1",
                [user_id.to_string()],
            )?;
            for code in &codes {
                tx.execute(
                    "INSERT INTO recovery_codes (user_id, code_hash) VALUES (?1, ?2)",
                    params![user_id.to_string(), sha256_hex(code.as_bytes())],
                )?;
            }
            tx.commit()?;
            Ok(codes)
        })
        .await
    }

    /// Disables two-factor authentication (admins also use it to reset it).
    pub async fn totp_disable(&self, user_id: Id) -> Result<()> {
        self.call(move |c, _| {
            let n = c.execute(
                "UPDATE users SET totp_enabled = 0, totp_secret = NULL, totp_last_step = 0
                 WHERE id = ?1",
                [user_id.to_string()],
            )?;
            if n == 0 {
                return Err(CoreError::NotFound(format!("user {user_id}")));
            }
            c.execute(
                "DELETE FROM recovery_codes WHERE user_id = ?1",
                [user_id.to_string()],
            )?;
            Ok(())
        })
        .await
    }

    /// Checks the second factor: a TOTP code (not used before) or a recovery
    /// code (which gets spent).
    pub async fn totp_check(
        &self,
        user_id: Id,
        code: &str,
        unix_secs: u64,
    ) -> Result<SecondFactor> {
        let code = code.to_string();
        self.call(move |c, key| {
            let (sealed, enabled, last): (Option<Vec<u8>>, i64, i64) = c
                .query_row(
                    "SELECT totp_secret, totp_enabled, totp_last_step FROM users WHERE id = ?1",
                    [user_id.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?
                .ok_or_else(|| CoreError::NotFound(format!("user {user_id}")))?;
            let (Some(sealed), 1) = (sealed, enabled) else {
                return Ok(SecondFactor::Invalid);
            };
            let digits: String = code.chars().filter(|c| !c.is_whitespace()).collect();
            if digits.len() == 6 && digits.bytes().all(|b| b.is_ascii_digit()) {
                let secret = key.open(&sealed, &totp_aad(user_id))?;
                return Ok(
                    match crate::totp::verify(&secret, &digits, unix_secs, last.max(0) as u64) {
                        Some(step) => {
                            c.execute(
                                "UPDATE users SET totp_last_step = ?2 WHERE id = ?1",
                                params![user_id.to_string(), step as i64],
                            )?;
                            SecondFactor::Totp
                        }
                        None => SecondFactor::Invalid,
                    },
                );
            }
            let hash = sha256_hex(crate::totp::normalize_recovery_code(&code).as_bytes());
            let n = c.execute(
                "UPDATE recovery_codes SET used_at = ?3
                 WHERE user_id = ?1 AND code_hash = ?2 AND used_at IS NULL",
                params![user_id.to_string(), hash, now_ms()],
            )?;
            Ok(if n == 1 {
                SecondFactor::RecoveryCode
            } else {
                SecondFactor::Invalid
            })
        })
        .await
    }

    /// Unused recovery codes.
    pub async fn recovery_codes_left(&self, user_id: Id) -> Result<i64> {
        self.call(move |c, _| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM recovery_codes WHERE user_id = ?1 AND used_at IS NULL",
                [user_id.to_string()],
                |r| r.get(0),
            )?)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_store;

    #[tokio::test]
    async fn two_factor_flow() {
        use super::SecondFactor;
        let store = test_store();
        let user = store
            .create_user("two@example.com", "Two", "long-password", false)
            .await
            .unwrap();
        let now = 1_700_000_000u64;
        // Not set up: nothing can be checked or enabled without a secret.
        assert!(store.totp_enable(user.id, "123456", now).await.is_err());
        let secret = store.totp_begin(user.id).await.unwrap();
        let code = |t: u64| {
            format!(
                "{:06}",
                crate::totp::code_at(&secret, crate::totp::step_at(t))
            )
        };
        assert!(store.totp_enable(user.id, "000000", now).await.is_err());
        let recovery = store.totp_enable(user.id, &code(now), now).await.unwrap();
        assert_eq!(recovery.len(), 10);
        assert!(store.user(user.id).await.unwrap().totp_enabled);
        assert!(store.totp_begin(user.id).await.is_err());

        // The code used to enable it is not accepted again; the next one is.
        assert_eq!(
            store.totp_check(user.id, &code(now), now).await.unwrap(),
            SecondFactor::Invalid
        );
        let later = now + 30;
        assert_eq!(
            store
                .totp_check(user.id, &code(later), later)
                .await
                .unwrap(),
            SecondFactor::Totp
        );
        // A recovery code works only once.
        let rc = recovery[0].to_uppercase();
        assert_eq!(
            store.totp_check(user.id, &rc, later).await.unwrap(),
            SecondFactor::RecoveryCode
        );
        assert_eq!(
            store.totp_check(user.id, &rc, later).await.unwrap(),
            SecondFactor::Invalid
        );
        assert_eq!(store.recovery_codes_left(user.id).await.unwrap(), 9);

        assert!(
            store
                .check_password(user.id, "long-password")
                .await
                .unwrap()
        );
        assert!(!store.check_password(user.id, "another").await.unwrap());
        store.totp_disable(user.id).await.unwrap();
        assert!(!store.user(user.id).await.unwrap().totp_enabled);
        assert_eq!(
            store
                .totp_check(user.id, &code(later + 60), later + 60)
                .await
                .unwrap(),
            SecondFactor::Invalid
        );
    }
    use super::TokenTtl;

    #[tokio::test]
    async fn users_and_tokens() {
        let store = test_store();
        let user = store
            .create_user("Ana@Example.com", "Ana", "long-password", true)
            .await
            .unwrap();
        assert_eq!(user.email, "ana@example.com");
        assert!(
            store
                .create_user("ana@example.com", "", "long-password", false)
                .await
                .is_err()
        );
        assert!(
            store
                .create_user("b@x.es", "", "short", false)
                .await
                .is_err()
        );

        assert!(
            store
                .verify_login("ana@example.com", "wrong-password")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .verify_login("nobody@example.com", "long-password")
                .await
                .unwrap()
                .is_none()
        );
        let u = store
            .verify_login("ANA@example.com", "long-password")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(u.id, user.id);

        let pair = store
            .issue_device(user.id, "Laptop", "desktop-linux", TokenTtl::default())
            .await
            .unwrap();
        let (au, dev) = store
            .authenticate(&pair.access_token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(au.id, user.id);
        assert_eq!(dev.name, "Laptop");
        assert!(store.authenticate("aks_at_fake").await.unwrap().is_none());

        let rotated = store
            .refresh_device(&pair.refresh_token, TokenTtl::default())
            .await
            .unwrap()
            .unwrap();
        assert!(
            store
                .authenticate(&pair.access_token)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .authenticate(&rotated.access_token)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .refresh_device(&pair.refresh_token, TokenTtl::default())
                .await
                .unwrap()
                .is_none()
        );

        store
            .revoke_device(user.id, rotated.device_id)
            .await
            .unwrap();
        assert!(
            store
                .authenticate(&rotated.access_token)
                .await
                .unwrap()
                .is_none()
        );
    }
}

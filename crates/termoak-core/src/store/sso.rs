//! SSO / OIDC for teams on the server (0.7 phase 5a,
//! docs/E2EE-SSO-AUDIT.md §3): settings, verified domains, linked
//! identities and the short-lived sign-in flows.

use rusqlite::{Connection, OptionalExtension, params};

use super::{Store, parse_id, parse_opt_id};
use crate::error::{CoreError, Result};
use crate::model::User;
use crate::sso::{SsoConfig, TeamDomain, txt_record_name, txt_record_value};
use crate::time::now_ms;
use crate::{Id, new_id};

/// How long a sign-in flow lives (browser round trip and code exchange).
pub const FLOW_TTL_MS: i64 = 10 * 60 * 1000;
/// Wrong exchanges of one flow's code at most.
const MAX_EXCHANGE_ATTEMPTS: i64 = 5;
/// A domain claimed but not verified by another team for this long can be
/// claimed again.
const UNVERIFIED_CLAIM_MS: i64 = 7 * 24 * 3600 * 1000;

/// A sign-in flow (`sso_flows`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsoFlow {
    pub id: Id,
    pub state: String,
    pub team_id: Id,
    pub link_user: Option<Id>,
    pub nonce: String,
    pub verifier: String,
    pub redirect_uri: String,
    pub client_state: Option<String>,
    pub client_challenge: String,
    pub device_name: String,
    pub platform: String,
    pub status: String,
    pub user_id: Option<Id>,
    pub error: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
}

/// A new flow (the store fills id, status and times).
#[derive(Debug, Clone, Default)]
pub struct NewSsoFlow {
    pub team_id: Id,
    pub link_user: Option<Id>,
    pub state: String,
    pub nonce: String,
    pub verifier: String,
    pub redirect_uri: String,
    pub client_state: Option<String>,
    pub client_challenge: String,
    pub device_name: String,
    pub platform: String,
}

/// An identity linked to an account.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SsoIdentity {
    pub issuer: String,
    pub subject: String,
    pub user_id: uuid::Uuid,
    pub team_id: uuid::Uuid,
    pub email: String,
    pub created_at: i64,
    pub last_login_at: Option<i64>,
}

const FLOW_COLUMNS: &str = "id, state, team_id, link_user, nonce, verifier, redirect_uri, client_state, \
     client_challenge, device_name, platform, status, user_id, error, created_at, expires_at";

fn map_flow(r: &rusqlite::Row<'_>) -> rusqlite::Result<SsoFlow> {
    Ok(SsoFlow {
        id: parse_id(&r.get::<_, String>(0)?)?,
        state: r.get(1)?,
        team_id: parse_id(&r.get::<_, String>(2)?)?,
        link_user: parse_opt_id(r.get(3)?)?,
        nonce: r.get(4)?,
        verifier: r.get(5)?,
        redirect_uri: r.get(6)?,
        client_state: r.get(7)?,
        client_challenge: r.get(8)?,
        device_name: r.get(9)?,
        platform: r.get(10)?,
        status: r.get(11)?,
        user_id: parse_opt_id(r.get(12)?)?,
        error: r.get(13)?,
        created_at: r.get(14)?,
        expires_at: r.get(15)?,
    })
}

fn map_domain(r: &rusqlite::Row<'_>) -> rusqlite::Result<TeamDomain> {
    let domain: String = r.get(0)?;
    let token: String = r.get(2)?;
    Ok(TeamDomain {
        record_name: txt_record_name(&domain),
        record_value: txt_record_value(&token),
        domain,
        team_id: parse_id(&r.get::<_, String>(1)?)?,
        token,
        verified_at: r.get(3)?,
        verified_by: r.get(4)?,
        created_at: r.get(5)?,
        checked_at: r.get(6)?,
        last_error: r.get(7)?,
    })
}

const DOMAIN_COLUMNS: &str =
    "domain, team_id, token, verified_at, verified_by, created_at, checked_at, last_error";

fn load_config(conn: &Connection, team: Id) -> Result<Option<SsoConfig>> {
    let row: Option<(String, Option<Vec<u8>>)> = conn
        .query_row(
            "SELECT config, client_secret FROM team_sso WHERE team_id = ?1",
            [team.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(row.map(|(cfg, secret)| {
        let mut c: SsoConfig = serde_json::from_str(&cfg).unwrap_or_default();
        c.has_client_secret = secret.is_some();
        c
    }))
}

impl Store {
    /// A team's SSO settings.
    pub async fn team_sso(&self, team: Id) -> Result<Option<SsoConfig>> {
        self.call(move |c, _| load_config(c, team)).await
    }

    /// A team's client secret, sealed (the server opens it with the master key).
    pub async fn team_sso_secret(&self, team: Id) -> Result<Option<Vec<u8>>> {
        self.call(move |c, _| {
            Ok(c.query_row(
                "SELECT client_secret FROM team_sso WHERE team_id = ?1",
                [team.to_string()],
                |r| r.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?
            .flatten())
        })
        .await
    }

    /// Saves a team's SSO settings. `secret`: `None` keeps the stored one,
    /// `Some(None)` removes it, `Some(Some(sealed))` replaces it.
    pub async fn set_team_sso(
        &self,
        team: Id,
        config: SsoConfig,
        secret: Option<Option<Vec<u8>>>,
        by: Id,
    ) -> Result<SsoConfig> {
        let mut config = config;
        config.has_client_secret = false;
        self.call(move |c, _| {
            let tx = c.transaction()?;
            let now = now_ms();
            let stored: Option<Option<Vec<u8>>> = tx
                .query_row(
                    "SELECT client_secret FROM team_sso WHERE team_id = ?1",
                    [team.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            let secret = match secret {
                Some(s) => s,
                None => stored.flatten(),
            };
            tx.execute(
                "INSERT INTO team_sso (team_id, config, client_secret, updated_by, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(team_id) DO UPDATE SET config = excluded.config,
                    client_secret = excluded.client_secret, updated_by = excluded.updated_by,
                    updated_at = excluded.updated_at",
                params![
                    team.to_string(),
                    serde_json::to_string(&config)?,
                    secret,
                    by.to_string(),
                    now
                ],
            )?;
            let out = load_config(&tx, team)?.unwrap_or_default();
            tx.commit()?;
            Ok(out)
        })
        .await
        .inspect(|_| self.bump_access())
    }

    pub async fn delete_team_sso(&self, team: Id) -> Result<bool> {
        let n = self
            .call(move |c, _| {
                Ok(c.execute(
                    "DELETE FROM team_sso WHERE team_id = ?1",
                    [team.to_string()],
                )?)
            })
            .await?;
        self.bump_access();
        Ok(n > 0)
    }

    // ---- domains ----

    pub async fn team_domains(&self, team: Id) -> Result<Vec<TeamDomain>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(&format!(
                "SELECT {DOMAIN_COLUMNS} FROM team_domains WHERE team_id = ?1 ORDER BY domain"
            ))?;
            Ok(stmt
                .query_map([team.to_string()], map_domain)?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    pub async fn team_domain(&self, domain: String) -> Result<Option<TeamDomain>> {
        self.call(move |c, _| {
            Ok(c.query_row(
                &format!("SELECT {DOMAIN_COLUMNS} FROM team_domains WHERE domain = ?1"),
                [domain],
                map_domain,
            )
            .optional()?)
        })
        .await
    }

    /// Claims a domain for a team (a new token). A domain verified by
    /// another team, or claimed by it less than a week ago, is refused
    /// (`sso_domain_taken`).
    pub async fn add_team_domain(&self, team: Id, domain: String, by: Id) -> Result<TeamDomain> {
        self.call(move |c, _| {
            let tx = c.transaction()?;
            let now = now_ms();
            let existing: Option<TeamDomain> = tx
                .query_row(
                    &format!("SELECT {DOMAIN_COLUMNS} FROM team_domains WHERE domain = ?1"),
                    [&domain],
                    map_domain,
                )
                .optional()?;
            if let Some(d) = existing {
                if d.team_id == team {
                    tx.commit()?;
                    return Ok(d);
                }
                if d.verified_at.is_some() || now - d.created_at < UNVERIFIED_CLAIM_MS {
                    return Err(CoreError::vault(
                        crate::error::codes::SSO_DOMAIN_TAKEN,
                        "another team has claimed this domain",
                    ));
                }
                tx.execute("DELETE FROM team_domains WHERE domain = ?1", [&domain])?;
            }
            let token = crate::sso::random_token();
            tx.execute(
                "INSERT INTO team_domains (domain, team_id, token, created_by, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![domain, team.to_string(), token, by.to_string(), now],
            )?;
            let d = tx.query_row(
                &format!("SELECT {DOMAIN_COLUMNS} FROM team_domains WHERE domain = ?1"),
                [&domain],
                map_domain,
            )?;
            tx.commit()?;
            Ok(d)
        })
        .await
    }

    /// Records a verification attempt: `Ok(by)` verifies the domain.
    pub async fn record_domain_check(
        &self,
        domain: String,
        outcome: std::result::Result<String, String>,
    ) -> Result<TeamDomain> {
        self.call(move |c, _| {
            let now = now_ms();
            match &outcome {
                Ok(by) => c.execute(
                    "UPDATE team_domains SET verified_at = COALESCE(verified_at, ?2), verified_by = ?3,
                            checked_at = ?2, last_error = NULL WHERE domain = ?1",
                    params![domain, now, by],
                )?,
                Err(e) => c.execute(
                    "UPDATE team_domains SET checked_at = ?2, last_error = ?3 WHERE domain = ?1",
                    params![domain, now, e],
                )?,
            };
            c.query_row(
                &format!("SELECT {DOMAIN_COLUMNS} FROM team_domains WHERE domain = ?1"),
                [&domain],
                map_domain,
            )
            .optional()?
            .ok_or_else(|| CoreError::NotFound(format!("domain {domain}")))
        })
        .await
        .inspect(|_| self.bump_access())
    }

    pub async fn remove_team_domain(&self, team: Id, domain: String) -> Result<bool> {
        let n = self
            .call(move |c, _| {
                Ok(c.execute(
                    "DELETE FROM team_domains WHERE domain = ?1 AND team_id = ?2",
                    params![domain, team.to_string()],
                )?)
            })
            .await?;
        self.bump_access();
        Ok(n > 0)
    }

    /// The team whose verified domain covers an email, with its SSO
    /// settings (`None` when no team verified that domain).
    pub async fn sso_team_for_email(
        &self,
        email: &str,
    ) -> Result<Option<(Id, String, Option<SsoConfig>)>> {
        let Some(domain) = crate::sso::email_domain(email) else {
            return Ok(None);
        };
        self.call(move |c, _| {
            let row: Option<(String, String)> = c
                .query_row(
                    "SELECT d.team_id, t.name FROM team_domains d JOIN teams t ON t.id = d.team_id
                     WHERE d.domain = ?1 AND d.verified_at IS NOT NULL",
                    [&domain],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((team, name)) = row else {
                return Ok(None);
            };
            let team = parse_id(&team)?;
            Ok(Some((team, name, load_config(c, team)?)))
        })
        .await
    }

    // ---- identities ----

    pub async fn sso_identity(
        &self,
        issuer: String,
        subject: String,
    ) -> Result<Option<SsoIdentity>> {
        self.call(move |c, _| {
            Ok(c.query_row(
                "SELECT issuer, subject, user_id, team_id, email, created_at, last_login_at
                 FROM sso_identities WHERE issuer = ?1 AND subject = ?2",
                params![issuer, subject],
                map_identity,
            )
            .optional()?)
        })
        .await
    }

    pub async fn sso_identities_of(&self, user: Id) -> Result<Vec<SsoIdentity>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(
                "SELECT issuer, subject, user_id, team_id, email, created_at, last_login_at
                 FROM sso_identities WHERE user_id = ?1 ORDER BY created_at",
            )?;
            Ok(stmt
                .query_map([user.to_string()], map_identity)?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// Links (or re-links) an identity to an account and notes the sign-in.
    pub async fn link_sso_identity(
        &self,
        issuer: String,
        subject: String,
        user: Id,
        team: Id,
        email: String,
    ) -> Result<()> {
        self.call(move |c, _| {
            let now = now_ms();
            c.execute(
                "INSERT INTO sso_identities (issuer, subject, user_id, team_id, email, created_at, last_login_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
                 ON CONFLICT(issuer, subject) DO UPDATE SET user_id = excluded.user_id,
                    team_id = excluded.team_id, email = excluded.email, last_login_at = excluded.last_login_at",
                params![issuer, subject, user.to_string(), team.to_string(), email, now],
            )?;
            Ok(())
        })
        .await
        .inspect(|_| self.bump_access())
    }

    pub async fn unlink_sso_identities(&self, user: Id, team: Id) -> Result<usize> {
        let n = self
            .call(move |c, _| {
                Ok(c.execute(
                    "DELETE FROM sso_identities WHERE user_id = ?1 AND team_id = ?2",
                    params![user.to_string(), team.to_string()],
                )?)
            })
            .await?;
        self.bump_access();
        Ok(n)
    }

    /// Teams where signing in through SSO counts as two-step verification
    /// for this user (linked identity and `satisfies_2fa`).
    pub async fn sso_2fa_teams(&self, user: Id) -> Result<Vec<Id>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(
                "SELECT DISTINCT si.team_id FROM sso_identities si JOIN team_sso ts ON ts.team_id = si.team_id
                 WHERE si.user_id = ?1 AND json_extract(ts.config, '$.satisfies_2fa') = 1
                   AND json_extract(ts.config, '$.enabled') = 1",
            )?;
            Ok(stmt
                .query_map([user.to_string()], |r| parse_id(&r.get::<_, String>(0)?))?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// A new account created by SSO: verified email, no usable password.
    pub async fn create_sso_user(&self, email: &str, name: &str) -> Result<User> {
        let password = crate::sso::random_token();
        let mut user = self
            .create_account(email, name, &password, false, true)
            .await?;
        let id = user.id;
        self.call(move |c, _| {
            c.execute(
                "UPDATE users SET sso_only = 1 WHERE id = ?1",
                [id.to_string()],
            )?;
            Ok(())
        })
        .await?;
        user.sso_only = true;
        Ok(user)
    }

    /// The account has a password of its own again (it set one).
    pub async fn clear_sso_only(&self, user: Id) -> Result<()> {
        self.call(move |c, _| {
            c.execute(
                "UPDATE users SET sso_only = 0 WHERE id = ?1",
                [user.to_string()],
            )?;
            Ok(())
        })
        .await
    }

    // ---- flows ----

    pub async fn create_sso_flow(&self, f: NewSsoFlow) -> Result<SsoFlow> {
        self.call(move |c, _| {
            let now = now_ms();
            c.execute("DELETE FROM sso_flows WHERE expires_at < ?1", [now - FLOW_TTL_MS])?;
            let id = new_id();
            c.execute(
                "INSERT INTO sso_flows (id, state, team_id, link_user, nonce, verifier, redirect_uri,
                                        client_state, client_challenge, device_name, platform, status,
                                        created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'started', ?12, ?13)",
                params![
                    id.to_string(),
                    f.state,
                    f.team_id.to_string(),
                    f.link_user.map(|u| u.to_string()),
                    f.nonce,
                    f.verifier,
                    f.redirect_uri,
                    f.client_state,
                    f.client_challenge,
                    f.device_name,
                    f.platform,
                    now,
                    now + FLOW_TTL_MS
                ],
            )?;
            Ok(c.query_row(
                &format!("SELECT {FLOW_COLUMNS} FROM sso_flows WHERE id = ?1"),
                [id.to_string()],
                map_flow,
            )?)
        })
        .await
    }

    /// The started flow of a `state` (the identity provider's callback);
    /// it can come back only once.
    pub async fn take_sso_flow(&self, state: String) -> Result<Option<SsoFlow>> {
        self.call(move |c, _| {
            let tx = c.transaction()?;
            let flow: Option<SsoFlow> = tx
                .query_row(
                    &format!("SELECT {FLOW_COLUMNS} FROM sso_flows WHERE state = ?1"),
                    [&state],
                    map_flow,
                )
                .optional()?;
            let Some(flow) = flow else { return Ok(None) };
            if flow.status != "started" || flow.expires_at < now_ms() {
                return Ok(None);
            }
            tx.execute(
                "UPDATE sso_flows SET status = 'callback' WHERE id = ?1",
                [flow.id.to_string()],
            )?;
            tx.commit()?;
            Ok(Some(flow))
        })
        .await
    }

    /// Ends a flow after the callback: a user and the hash of the one-time
    /// code for the app, or an error.
    pub async fn finish_sso_flow(
        &self,
        id: Id,
        outcome: std::result::Result<(Id, String), String>,
    ) -> Result<()> {
        self.call(move |c, _| {
            match outcome {
                Ok((user, code_hash)) => c.execute(
                    "UPDATE sso_flows SET status = 'done', user_id = ?2, code_hash = ?3 WHERE id = ?1",
                    params![id.to_string(), user.to_string(), code_hash],
                )?,
                Err(e) => c.execute(
                    "UPDATE sso_flows SET status = 'failed', error = ?2 WHERE id = ?1",
                    params![id.to_string(), e],
                )?,
            };
            Ok(())
        })
        .await
    }

    /// The finished flow of a one-time code. `verify` checks the app's PKCE
    /// verifier against the flow; a wrong one counts, and five end the flow.
    /// A redeemed code never works again.
    pub async fn redeem_sso_code(
        &self,
        code_hash: String,
        verify: impl FnOnce(&SsoFlow) -> bool + Send + 'static,
    ) -> Result<Option<SsoFlow>> {
        self.call(move |c, _| {
            let tx = c.transaction()?;
            let flow: Option<SsoFlow> = tx
                .query_row(
                    &format!("SELECT {FLOW_COLUMNS} FROM sso_flows WHERE code_hash = ?1"),
                    [&code_hash],
                    map_flow,
                )
                .optional()?;
            let Some(flow) = flow else { return Ok(None) };
            if flow.status != "done" || flow.expires_at < now_ms() {
                return Ok(None);
            }
            if !verify(&flow) {
                tx.execute(
                    "UPDATE sso_flows SET attempts = attempts + 1,
                            status = CASE WHEN attempts + 1 >= ?2 THEN 'failed' ELSE status END
                     WHERE id = ?1",
                    params![flow.id.to_string(), MAX_EXCHANGE_ATTEMPTS],
                )?;
                tx.commit()?;
                return Ok(None);
            }
            tx.execute(
                "UPDATE sso_flows SET status = 'used' WHERE id = ?1",
                [flow.id.to_string()],
            )?;
            tx.commit()?;
            Ok(Some(flow))
        })
        .await
    }

    /// Puts a redeemed flow back to `done` (the app must still send the
    /// two-step code: the same one-time code works again until it expires).
    pub async fn reopen_sso_code(&self, id: Id) -> Result<()> {
        self.call(move |c, _| {
            c.execute(
                "UPDATE sso_flows SET status = 'done' WHERE id = ?1 AND status = 'used'",
                [id.to_string()],
            )?;
            Ok(())
        })
        .await
    }
}

fn map_identity(r: &rusqlite::Row<'_>) -> rusqlite::Result<SsoIdentity> {
    Ok(SsoIdentity {
        issuer: r.get(0)?,
        subject: r.get(1)?,
        user_id: parse_id(&r.get::<_, String>(2)?)?,
        team_id: parse_id(&r.get::<_, String>(3)?)?,
        email: r.get(4)?,
        created_at: r.get(5)?,
        last_login_at: r.get(6)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::test_store;

    #[tokio::test]
    async fn domains_flows_and_identities() {
        let store = test_store();
        let owner = store
            .create_user("own@corp.test", "Own", "password123", false)
            .await
            .unwrap()
            .id;
        let other = store
            .create_user("x@other.test", "X", "password123", false)
            .await
            .unwrap()
            .id;
        let team = store.create_team(owner, "Corp").await.unwrap().id;
        let team2 = store.create_team(other, "Other").await.unwrap().id;
        let d = store
            .add_team_domain(team, "corp.test".into(), owner)
            .await
            .unwrap();
        assert_eq!(d.record_name, "_termoak-challenge.corp.test");
        assert!(d.record_value.starts_with("termoak-verify="));
        assert_eq!(
            store
                .add_team_domain(team2, "corp.test".into(), other)
                .await
                .unwrap_err()
                .vault_code(),
            Some(crate::error::codes::SSO_DOMAIN_TAKEN)
        );
        assert!(
            store
                .sso_team_for_email("ana@corp.test")
                .await
                .unwrap()
                .is_none()
        );
        store
            .record_domain_check("corp.test".into(), Ok("dns".into()))
            .await
            .unwrap();
        let cfg = SsoConfig {
            enabled: true,
            issuer: "https://id.corp.test/realms/x".into(),
            client_id: "termoak".into(),
            satisfies_2fa: true,
            ..Default::default()
        };
        store
            .set_team_sso(team, cfg.clone(), Some(Some(vec![1, 2, 3])), owner)
            .await
            .unwrap();
        let (t, name, c) = store
            .sso_team_for_email("Ana@Corp.test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!((t, name.as_str()), (team, "Corp"));
        assert!(c.unwrap().has_client_secret);
        // Keeping the secret when it is not given.
        store.set_team_sso(team, cfg, None, owner).await.unwrap();
        assert_eq!(
            store.team_sso_secret(team).await.unwrap(),
            Some(vec![1, 2, 3])
        );

        let flow = store
            .create_sso_flow(NewSsoFlow {
                team_id: team,
                state: "s1".into(),
                nonce: "n".into(),
                verifier: "v".into(),
                redirect_uri: "termoak://sso".into(),
                client_challenge: crate::sso::pkce_challenge(
                    "app-verifier-app-verifier-app-verifier-123",
                ),
                device_name: "Phone".into(),
                platform: "android".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(store.take_sso_flow("s1".into()).await.unwrap().is_some());
        assert!(
            store.take_sso_flow("s1".into()).await.unwrap().is_none(),
            "a state comes back once"
        );
        let ana = store.create_sso_user("ana@corp.test", "").await.unwrap();
        assert!(ana.sso_only && ana.email_verified);
        store
            .finish_sso_flow(flow.id, Ok((ana.id, "h1".into())))
            .await
            .unwrap();
        let wrong = |_: &SsoFlow| false;
        assert!(
            store
                .redeem_sso_code("h1".into(), wrong)
                .await
                .unwrap()
                .is_none()
        );
        let ok = |f: &SsoFlow| {
            f.client_challenge
                == crate::sso::pkce_challenge("app-verifier-app-verifier-app-verifier-123")
        };
        let got = store
            .redeem_sso_code("h1".into(), ok)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.user_id, Some(ana.id));
        assert!(
            store
                .redeem_sso_code("h1".into(), ok)
                .await
                .unwrap()
                .is_none(),
            "used once"
        );

        store
            .link_sso_identity(
                "https://id".into(),
                "sub1".into(),
                ana.id,
                team,
                ana.email.clone(),
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .sso_identity("https://id".into(), "sub1".into())
                .await
                .unwrap()
                .unwrap()
                .user_id,
            ana.id
        );
        // The 2FA policy counts SSO as two-step verification.
        store
            .set_team_member(team, ana.id, crate::model::TeamRole::Member)
            .await
            .unwrap();
        let v = store
            .create_vault(
                owner,
                crate::store::NewVault {
                    name: "P".into(),
                    team_id: Some(team),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let policy = crate::access::TeamPolicy {
            require_2fa: true,
            require_2fa_since: Some(1),
            grace_days: 0,
            ..Default::default()
        };
        store.set_team_policy(team, policy).await.unwrap();
        let acc = store.vault_access(ana.id).await.unwrap();
        assert!(
            acc.role(v.id).is_some(),
            "SSO satisfies the team's 2FA policy"
        );
        store.unlink_sso_identities(ana.id, team).await.unwrap();
        let acc = store.vault_access(ana.id).await.unwrap();
        assert!(acc.role(v.id).is_none());
    }
}

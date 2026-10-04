//! Account invites: a single-use link that allows signing up even when
//! registration is closed (and, optionally, joining a team right away).

use rusqlite::{OptionalExtension, params};

use super::{Store, parse_id, parse_opt_id};
use crate::crypto::{prefixed_token, sha256_hex};
use crate::error::{CoreError, Result};
use crate::model::{Invite, TeamRole};
use crate::time::now_ms;
use crate::{Id, new_id};

const INVITE_COLUMNS: &str = "id, email, is_admin, team_id, created_by, created_at, expires_at, \
                              used_by, used_at, revoked, team_role";

/// Data for a new invite.
#[derive(Debug, Clone, Default)]
pub struct NewInvite {
    /// Only this email can use it.
    pub email: Option<String>,
    /// The account will be a server admin.
    pub is_admin: bool,
    /// Team joined on registration...
    pub team_id: Option<Id>,
    /// ...with this role (member if not set).
    pub team_role: Option<TeamRole>,
    pub expires_at: Option<i64>,
}

fn map_invite(r: &rusqlite::Row<'_>) -> rusqlite::Result<Invite> {
    Ok(Invite {
        id: parse_id(&r.get::<_, String>(0)?)?,
        email: r.get(1)?,
        is_admin: r.get::<_, i64>(2)? != 0,
        team_id: parse_opt_id(r.get(3)?)?,
        created_by: parse_id(&r.get::<_, String>(4)?)?,
        created_at: r.get(5)?,
        expires_at: r.get(6)?,
        used_by: parse_opt_id(r.get(7)?)?,
        used_at: r.get(8)?,
        revoked: r.get::<_, i64>(9)? != 0,
        team_role: r.get::<_, Option<String>>(10)?.map(|s| TeamRole::parse(&s)),
    })
}

impl Store {
    /// Creates an invite. Returns the token (shown only this once).
    pub async fn create_invite(&self, created_by: Id, new: NewInvite) -> Result<(Invite, String)> {
        let email = new
            .email
            .map(|e| e.trim().to_lowercase())
            .filter(|e| !e.is_empty());
        if let Some(e) = &email
            && (!e.contains('@') || e.chars().any(char::is_whitespace))
        {
            return Err(CoreError::Invalid("invalid email".into()));
        }
        let team_role = new.team_id.and(new.team_role);
        self.call(move |c, _| {
            let token = prefixed_token("aks_inv");
            let invite = Invite {
                id: new_id(),
                email,
                is_admin: new.is_admin,
                team_id: new.team_id,
                team_role,
                created_by,
                created_at: now_ms(),
                expires_at: new.expires_at,
                used_by: None,
                used_at: None,
                revoked: false,
            };
            c.execute(
                "INSERT INTO invites (id, token_hash, email, is_admin, team_id, team_role,
                                      created_by, created_at, expires_at, revoked)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)",
                params![
                    invite.id.to_string(),
                    sha256_hex(token.as_bytes()),
                    invite.email,
                    invite.is_admin as i64,
                    invite.team_id.map(|t| t.to_string()),
                    invite.team_role.map(TeamRole::as_str),
                    created_by.to_string(),
                    invite.created_at,
                    invite.expires_at
                ],
            )?;
            Ok((invite, token))
        })
        .await
    }

    /// An invite by its id.
    pub async fn invite(&self, id: Id) -> Result<Invite> {
        self.call(move |c, _| {
            c.query_row(
                &format!("SELECT {INVITE_COLUMNS} FROM invites WHERE id = ?1"),
                [id.to_string()],
                map_invite,
            )
            .optional()?
            .ok_or_else(|| CoreError::NotFound(format!("invite {id}")))
        })
        .await
    }

    /// Pending invites (unused, not revoked and not expired) of a team.
    pub async fn team_invites(&self, team_id: Id) -> Result<Vec<Invite>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(&format!(
                "SELECT {INVITE_COLUMNS} FROM invites
                 WHERE team_id = ?1 AND revoked = 0 AND used_by IS NULL
                   AND (expires_at IS NULL OR expires_at > ?2)
                 ORDER BY created_at DESC"
            ))?;
            Ok(stmt
                .query_map(params![team_id.to_string(), now_ms()], map_invite)?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    pub async fn list_invites(&self) -> Result<Vec<Invite>> {
        self.call(|c, _| {
            let mut stmt = c.prepare(&format!(
                "SELECT {INVITE_COLUMNS} FROM invites ORDER BY created_at DESC LIMIT 500"
            ))?;
            Ok(stmt
                .query_map([], map_invite)?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    pub async fn revoke_invite(&self, id: Id) -> Result<()> {
        self.call(move |c, _| {
            let n = c.execute(
                "UPDATE invites SET revoked = 1 WHERE id = ?1",
                [id.to_string()],
            )?;
            if n == 0 {
                return Err(CoreError::NotFound(format!("invite {id}")));
            }
            Ok(())
        })
        .await
    }

    /// Valid invite (unused, not revoked and not expired) for a token.
    pub async fn invite_by_token(&self, token: &str) -> Result<Option<Invite>> {
        let hash = sha256_hex(token.trim().as_bytes());
        self.call(move |c, _| {
            Ok(c.query_row(
                &format!(
                    "SELECT {INVITE_COLUMNS} FROM invites
                     WHERE token_hash = ?1 AND revoked = 0 AND used_by IS NULL
                       AND (expires_at IS NULL OR expires_at > ?2)"
                ),
                params![hash, now_ms()],
                map_invite,
            )
            .optional()?)
        })
        .await
    }

    /// Marks the invite as used. Fails if someone else used it first (race).
    pub async fn consume_invite(&self, id: Id, user_id: Id) -> Result<()> {
        self.call(move |c, _| {
            let n = c.execute(
                "UPDATE invites SET used_by = ?2, used_at = ?3
                 WHERE id = ?1 AND used_by IS NULL AND revoked = 0",
                params![id.to_string(), user_id.to_string(), now_ms()],
            )?;
            if n == 0 {
                return Err(CoreError::Conflict(
                    "the invite has already been used".into(),
                ));
            }
            Ok(())
        })
        .await
    }
}

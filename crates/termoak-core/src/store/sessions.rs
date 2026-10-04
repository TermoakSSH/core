//! Registry of persistent server sessions and their shares.

use rusqlite::{OptionalExtension, params};

use super::{Store, parse_id, parse_opt_id};
use crate::crypto::{prefixed_token, sha256_hex};
use crate::error::{CoreError, Result};
use crate::model::{SessionInfo, SessionShare, SessionStatus, SharePermission};
use crate::time::now_ms;
use crate::{Id, new_id};

const SESSION_COLUMNS: &str =
    "id, owner_id, host_id, title, status, kind, created_at, ended_at, error, recording";

fn map_session(r: &rusqlite::Row<'_>) -> rusqlite::Result<SessionInfo> {
    Ok(SessionInfo {
        id: parse_id(&r.get::<_, String>(0)?)?,
        owner_id: parse_id(&r.get::<_, String>(1)?)?,
        host_id: parse_opt_id(r.get(2)?)?,
        title: r.get(3)?,
        status: SessionStatus::parse(&r.get::<_, String>(4)?),
        kind: r.get(5)?,
        created_at: r.get(6)?,
        ended_at: r.get(7)?,
        error: r.get(8)?,
        recording: r.get::<_, i64>(9)? != 0,
    })
}

const SHARE_COLUMNS: &str = "id, session_id, created_by, user_id, token_hash, permission, \
     expires_at, revoked, created_at, team_id";

fn map_share(r: &rusqlite::Row<'_>) -> rusqlite::Result<SessionShare> {
    map_share_at(r, 0)
}

/// Reads a share starting at column `o` (for JOINs).
fn map_share_at(r: &rusqlite::Row<'_>, o: usize) -> rusqlite::Result<SessionShare> {
    Ok(SessionShare {
        id: parse_id(&r.get::<_, String>(o)?)?,
        session_id: parse_id(&r.get::<_, String>(o + 1)?)?,
        created_by: parse_id(&r.get::<_, String>(o + 2)?)?,
        user_id: parse_opt_id(r.get(o + 3)?)?,
        is_link: r.get::<_, Option<String>>(o + 4)?.is_some(),
        permission: SharePermission::parse(&r.get::<_, String>(o + 5)?),
        expires_at: r.get(o + 6)?,
        revoked: r.get::<_, i64>(o + 7)? != 0,
        created_at: r.get(o + 8)?,
        team_id: parse_opt_id(r.get(o + 9)?)?,
    })
}

/// Valid shares that give a user access: their own and those of the teams
/// they belong to.
const SHARE_FOR_USER: &str = "(sh.user_id = ?1 OR sh.team_id IN \
     (SELECT team_id FROM team_members WHERE user_id = ?1))";

/// Recipient of a share.
#[derive(Debug, Clone)]
pub enum ShareTarget {
    User(Id),
    /// All members of a team.
    Team(Id),
    Link,
}

impl Store {
    pub async fn insert_session(&self, info: SessionInfo) -> Result<()> {
        self.call(move |c, _| {
            c.execute(
                &format!("INSERT INTO sessions ({SESSION_COLUMNS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)"),
                params![
                    info.id.to_string(),
                    info.owner_id.to_string(),
                    info.host_id.map(|h| h.to_string()),
                    info.title,
                    info.status.as_str(),
                    info.kind,
                    info.created_at,
                    info.ended_at,
                    info.error,
                    info.recording as i64
                ],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn set_session_status(
        &self,
        id: Id,
        status: SessionStatus,
        error: Option<String>,
    ) -> Result<()> {
        self.call(move |c, _| {
            let ended =
                matches!(status, SessionStatus::Closed | SessionStatus::Failed).then(now_ms);
            c.execute(
                "UPDATE sessions SET status = ?2, error = COALESCE(?3, error),
                        ended_at = COALESCE(?4, ended_at)
                 WHERE id = ?1",
                params![id.to_string(), status.as_str(), error, ended],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn rename_session(&self, id: Id, title: &str) -> Result<()> {
        let title = title.trim().to_string();
        self.call(move |c, _| {
            c.execute(
                "UPDATE sessions SET title = ?2 WHERE id = ?1",
                params![id.to_string(), title],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn session(&self, id: Id) -> Result<SessionInfo> {
        self.call(move |c, _| {
            c.query_row(
                &format!("SELECT {SESSION_COLUMNS} FROM sessions WHERE id = ?1"),
                [id.to_string()],
                map_session,
            )
            .optional()?
            .ok_or_else(|| CoreError::NotFound(format!("session {id}")))
        })
        .await
    }

    /// A user's own sessions. `active_only` filters out closed ones.
    pub async fn list_sessions(
        &self,
        owner: Id,
        active_only: bool,
        limit: i64,
    ) -> Result<Vec<SessionInfo>> {
        self.call(move |c, _| {
            let sql = format!(
                "SELECT {SESSION_COLUMNS} FROM sessions WHERE owner_id = ?1 {}
                 ORDER BY created_at DESC LIMIT ?2",
                if active_only {
                    "AND status IN ('connecting','running')"
                } else {
                    ""
                }
            );
            let mut stmt = c.prepare(&sql)?;
            Ok(stmt
                .query_map(params![owner.to_string(), limit], map_session)?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// Active sessions shared with a user, directly or with one of their
    /// teams. If there are several shares for the same session, the one with
    /// the highest permission wins.
    pub async fn sessions_shared_with(&self, user: Id) -> Result<Vec<(SessionInfo, SessionShare)>> {
        self.call(move |c, _| {
            let now = now_ms();
            let mut stmt = c.prepare(&format!(
                "SELECT {}, {} FROM session_shares sh JOIN sessions s ON s.id = sh.session_id
                 WHERE {SHARE_FOR_USER} AND sh.revoked = 0
                   AND (sh.expires_at IS NULL OR sh.expires_at > ?2)
                   AND s.status IN ('connecting','running')
                   AND s.owner_id != ?1
                 ORDER BY s.created_at DESC",
                prefixed(SESSION_COLUMNS, "s"),
                prefixed(SHARE_COLUMNS, "sh"),
            ))?;
            let rows = stmt
                .query_map(params![user.to_string(), now], |r| {
                    Ok((map_session(r)?, map_share_at(r, 10)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut best: Vec<(SessionInfo, SessionShare)> = Vec::new();
            for (session, share) in rows {
                match best.iter_mut().find(|(s, _)| s.id == session.id) {
                    Some(entry) if share.permission > entry.1.permission => entry.1 = share,
                    Some(_) => {}
                    None => best.push((session, share)),
                }
            }
            Ok(best)
        })
        .await
    }

    /// On server start, sessions left "alive" are marked as closed, except
    /// those in `keep` (the ones the session holder preserved).
    pub async fn close_orphan_sessions(&self, keep: &[Id]) -> Result<usize> {
        let keep: Vec<String> = keep.iter().map(Id::to_string).collect();
        self.call(move |c, _| {
            let ids = c
                .prepare("SELECT id FROM sessions WHERE status IN ('connecting','running')")?
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let now = now_ms();
            let mut closed = 0;
            for id in ids.iter().filter(|id| !keep.contains(id)) {
                closed += c.execute(
                    "UPDATE sessions SET status = 'closed', ended_at = ?2,
                            error = COALESCE(error, 'the server restarted')
                     WHERE id = ?1",
                    params![id, now],
                )?;
            }
            Ok(closed)
        })
        .await
    }

    /// Creates a share. For links it returns the token (shown only once).
    pub async fn create_share(
        &self,
        session_id: Id,
        created_by: Id,
        target: ShareTarget,
        permission: SharePermission,
        expires_at: Option<i64>,
    ) -> Result<(SessionShare, Option<String>)> {
        self.call(move |c, _| {
            let (user_id, team_id, token) = match target {
                ShareTarget::User(u) => (Some(u), None, None),
                ShareTarget::Team(t) => (None, Some(t), None),
                ShareTarget::Link => (None, None, Some(prefixed_token("aks_sh"))),
            };
            let share = SessionShare {
                id: new_id(),
                session_id,
                created_by,
                user_id,
                team_id,
                is_link: token.is_some(),
                permission,
                expires_at,
                revoked: false,
                created_at: now_ms(),
            };
            c.execute(
                &format!("INSERT INTO session_shares ({SHARE_COLUMNS}) VALUES (?1,?2,?3,?4,?5,?6,?7,0,?8,?9)"),
                params![
                    share.id.to_string(),
                    session_id.to_string(),
                    created_by.to_string(),
                    user_id.map(|u| u.to_string()),
                    token.as_ref().map(|t| sha256_hex(t.as_bytes())),
                    permission.as_str(),
                    expires_at,
                    share.created_at,
                    team_id.map(|t| t.to_string())
                ],
            )?;
            Ok((share, token))
        })
        .await
    }

    pub async fn list_shares(&self, session_id: Id) -> Result<Vec<SessionShare>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(&format!(
                "SELECT {SHARE_COLUMNS} FROM session_shares WHERE session_id = ?1 ORDER BY created_at"
            ))?;
            Ok(stmt
                .query_map([session_id.to_string()], map_share)?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    pub async fn revoke_share(&self, session_id: Id, share_id: Id) -> Result<()> {
        self.call(move |c, _| {
            let n = c.execute(
                "UPDATE session_shares SET revoked = 1 WHERE id = ?1 AND session_id = ?2",
                params![share_id.to_string(), session_id.to_string()],
            )?;
            if n == 0 {
                return Err(CoreError::NotFound(format!("share {share_id}")));
            }
            Ok(())
        })
        .await
    }

    /// Valid share for a link token.
    pub async fn share_by_token(&self, token: &str) -> Result<Option<SessionShare>> {
        let hash = sha256_hex(token.as_bytes());
        self.call(move |c, _| {
            Ok(c.query_row(
                &format!(
                    "SELECT {SHARE_COLUMNS} FROM session_shares
                     WHERE token_hash = ?1 AND revoked = 0 AND (expires_at IS NULL OR expires_at > ?2)"
                ),
                params![hash, now_ms()],
                map_share,
            )
            .optional()?)
        })
        .await
    }

    /// Valid share that gives a user access to a session (theirs or one of
    /// their teams'); the one with the highest permission.
    pub async fn share_for_user(&self, session_id: Id, user: Id) -> Result<Option<SessionShare>> {
        self.call(move |c, _| {
            Ok(c.query_row(
                &format!(
                    "SELECT {} FROM session_shares sh
                     WHERE sh.session_id = ?3 AND {SHARE_FOR_USER} AND sh.revoked = 0
                       AND (sh.expires_at IS NULL OR sh.expires_at > ?2)
                     ORDER BY sh.permission DESC LIMIT 1",
                    prefixed(SHARE_COLUMNS, "sh")
                ),
                params![user.to_string(), now_ms(), session_id.to_string()],
                map_share,
            )
            .optional()?)
        })
        .await
    }

    /// Valid shares of a session aimed at a team (to notify its members or
    /// kick them out if they leave the team).
    pub async fn team_shares(&self, team_id: Id) -> Result<Vec<SessionShare>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(&format!(
                "SELECT {SHARE_COLUMNS} FROM session_shares
                 WHERE team_id = ?1 AND revoked = 0 AND (expires_at IS NULL OR expires_at > ?2)"
            ))?;
            Ok(stmt
                .query_map(params![team_id.to_string(), now_ms()], map_share)?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }
}

fn prefixed(columns: &str, alias: &str) -> String {
    columns
        .split(',')
        .map(|c| format!("{alias}.{}", c.trim()))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::super::test_store;
    use super::ShareTarget;
    use crate::model::*;
    use crate::new_id;

    #[tokio::test]
    async fn sessions_and_shares() {
        let store = test_store();
        let owner = new_id();
        let guest = new_id();
        let info = SessionInfo {
            id: new_id(),
            owner_id: owner,
            host_id: None,
            title: "web".into(),
            status: SessionStatus::Running,
            kind: "server".into(),
            created_at: 1,
            ended_at: None,
            error: None,
            recording: false,
        };
        store.insert_session(info.clone()).await.unwrap();
        assert_eq!(store.list_sessions(owner, true, 10).await.unwrap().len(), 1);

        let (share, token) = store
            .create_share(
                info.id,
                owner,
                ShareTarget::User(guest),
                SharePermission::Control,
                None,
            )
            .await
            .unwrap();
        assert!(token.is_none());
        assert_eq!(store.sessions_shared_with(guest).await.unwrap().len(), 1);
        assert!(
            store
                .share_for_user(info.id, guest)
                .await
                .unwrap()
                .is_some()
        );

        let (_, token) = store
            .create_share(
                info.id,
                owner,
                ShareTarget::Link,
                SharePermission::View,
                None,
            )
            .await
            .unwrap();
        let token = token.unwrap();
        let by_token = store.share_by_token(&token).await.unwrap().unwrap();
        assert_eq!(by_token.permission, SharePermission::View);

        store.revoke_share(info.id, share.id).await.unwrap();
        assert!(
            store
                .share_for_user(info.id, guest)
                .await
                .unwrap()
                .is_none()
        );

        // Sessions kept by the session holder stay open.
        assert_eq!(store.close_orphan_sessions(&[info.id]).await.unwrap(), 0);
        assert_eq!(store.list_sessions(owner, true, 10).await.unwrap().len(), 1);
        store.close_orphan_sessions(&[]).await.unwrap();
        assert!(
            store
                .list_sessions(owner, true, 10)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(store.sessions_shared_with(guest).await.unwrap().is_empty());
    }
}

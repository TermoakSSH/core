//! User teams. For now they are used to share sessions with all members at
//! once; later on, for shared vaults.

use rusqlite::{OptionalExtension, params};

use super::{Store, parse_id};
use crate::error::{CoreError, Result};
use crate::model::{Team, TeamMember, TeamRole};
use crate::time::now_ms;
use crate::{Id, new_id};

fn check_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return Err(CoreError::Invalid(
            "the team name must be between 1 and 80 characters".into(),
        ));
    }
    Ok(name.to_string())
}

const TEAM_SELECT: &str = "SELECT t.id, t.name, t.created_by, t.created_at, m.role,
        (SELECT COUNT(*) FROM team_members x WHERE x.team_id = t.id), t.plan
     FROM teams t";

fn map_team(r: &rusqlite::Row<'_>) -> rusqlite::Result<Team> {
    Ok(Team {
        id: parse_id(&r.get::<_, String>(0)?)?,
        name: r.get(1)?,
        created_by: parse_id(&r.get::<_, String>(2)?)?,
        created_at: r.get(3)?,
        role: r.get::<_, Option<String>>(4)?.map(|s| TeamRole::parse(&s)),
        member_count: r.get(5)?,
        plan: r.get(6)?,
    })
}

impl Store {
    /// Creates a team with its creator as owner.
    pub async fn create_team(&self, owner: Id, name: &str) -> Result<Team> {
        let name = check_name(name)?;
        self.call(move |c, _| {
            let team = Team {
                id: new_id(),
                name,
                created_by: owner,
                created_at: now_ms(),
                role: Some(TeamRole::Owner),
                member_count: 1,
                plan: crate::model::default_plan(),
            };
            let tx = c.transaction()?;
            tx.execute(
                "INSERT INTO teams (id, name, created_by, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![
                    team.id.to_string(),
                    team.name,
                    owner.to_string(),
                    team.created_at
                ],
            )?;
            tx.execute(
                "INSERT INTO team_members (team_id, user_id, role, added_at) VALUES (?1, ?2, 'owner', ?3)",
                params![team.id.to_string(), owner.to_string(), team.created_at],
            )?;
            tx.commit()?;
            Ok(team)
        })
        .await
    }

    /// Teams a user is a member of, with their role.
    pub async fn teams_of(&self, user: Id) -> Result<Vec<Team>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(&format!(
                "{TEAM_SELECT} JOIN team_members m ON m.team_id = t.id AND m.user_id = ?1
                 ORDER BY t.name COLLATE NOCASE"
            ))?;
            Ok(stmt
                .query_map([user.to_string()], map_team)?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// All teams (server administration), with `viewer`'s role in those they
    /// belong to.
    pub async fn all_teams(&self, viewer: Id) -> Result<Vec<Team>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(&format!(
                "{TEAM_SELECT} LEFT JOIN team_members m ON m.team_id = t.id AND m.user_id = ?1
                 ORDER BY t.name COLLATE NOCASE"
            ))?;
            Ok(stmt
                .query_map([viewer.to_string()], map_team)?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// A team as seen by a user (with their role, if a member).
    pub async fn team_for(&self, team_id: Id, user: Id) -> Result<Team> {
        self.call(move |c, _| {
            c.query_row(
                &format!(
                    "{TEAM_SELECT} LEFT JOIN team_members m ON m.team_id = t.id AND m.user_id = ?2
                     WHERE t.id = ?1"
                ),
                params![team_id.to_string(), user.to_string()],
                map_team,
            )
            .optional()?
            .ok_or_else(|| CoreError::NotFound(format!("team {team_id}")))
        })
        .await
    }

    /// A user's role in a team (`None` if not a member).
    pub async fn team_role(&self, team_id: Id, user: Id) -> Result<Option<TeamRole>> {
        self.call(move |c, _| {
            Ok(c.query_row(
                "SELECT role FROM team_members WHERE team_id = ?1 AND user_id = ?2",
                params![team_id.to_string(), user.to_string()],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .map(|s| TeamRole::parse(&s)))
        })
        .await
    }

    pub async fn rename_team(&self, team_id: Id, name: &str) -> Result<()> {
        let name = check_name(name)?;
        self.call(move |c, _| {
            let n = c.execute(
                "UPDATE teams SET name = ?2 WHERE id = ?1",
                params![team_id.to_string(), name],
            )?;
            if n == 0 {
                return Err(CoreError::NotFound(format!("team {team_id}")));
            }
            Ok(())
        })
        .await
    }

    /// Changes a team's plan.
    pub async fn set_team_plan(&self, team_id: Id, plan: &str) -> Result<()> {
        let plan = plan.trim().to_string();
        self.call(move |c, _| {
            let n = c.execute(
                "UPDATE teams SET plan = ?2 WHERE id = ?1",
                params![team_id.to_string(), plan],
            )?;
            if n == 0 {
                return Err(CoreError::NotFound(format!("team {team_id}")));
            }
            Ok(())
        })
        .await
    }

    /// Teams a user owns.
    pub async fn teams_owned(&self, user: Id) -> Result<i64> {
        self.call(move |c, _| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM team_members WHERE user_id = ?1 AND role = 'owner'",
                [user.to_string()],
                |r| r.get(0),
            )?)
        })
        .await
    }

    /// Teams with other members where the user is the only owner (they cannot
    /// delete their account until this is resolved).
    pub async fn teams_needing_owner(&self, user: Id) -> Result<Vec<Team>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(&format!(
                "{TEAM_SELECT} JOIN team_members m ON m.team_id = t.id AND m.user_id = ?1
                 WHERE m.role = 'owner'
                   AND (SELECT COUNT(*) FROM team_members o
                        WHERE o.team_id = t.id AND o.role = 'owner') = 1
                   AND (SELECT COUNT(*) FROM team_members x WHERE x.team_id = t.id) > 1
                 ORDER BY t.name COLLATE NOCASE"
            ))?;
            Ok(stmt
                .query_map([user.to_string()], map_team)?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// Deletes the team and revokes the sessions shared with it.
    pub async fn delete_team(&self, team_id: Id) -> Result<()> {
        self.call(move |c, _| {
            let tx = c.transaction()?;
            tx.execute(
                "UPDATE session_shares SET revoked = 1 WHERE team_id = ?1",
                [team_id.to_string()],
            )?;
            let n = tx.execute("DELETE FROM teams WHERE id = ?1", [team_id.to_string()])?;
            if n == 0 {
                return Err(CoreError::NotFound(format!("team {team_id}")));
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn team_members(&self, team_id: Id) -> Result<Vec<TeamMember>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(
                "SELECT u.id, u.email, u.name, m.role, m.added_at
                 FROM team_members m JOIN users u ON u.id = m.user_id
                 WHERE m.team_id = ?1
                 ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END,
                          u.name COLLATE NOCASE",
            )?;
            Ok(stmt
                .query_map([team_id.to_string()], |r| {
                    Ok(TeamMember {
                        user_id: parse_id(&r.get::<_, String>(0)?)?,
                        email: r.get(1)?,
                        name: r.get(2)?,
                        role: TeamRole::parse(&r.get::<_, String>(3)?),
                        added_at: r.get(4)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// Adds a member or changes their role.
    pub async fn set_team_member(&self, team_id: Id, user: Id, role: TeamRole) -> Result<()> {
        self.call(move |c, _| {
            let exists: Option<i64> = c
                .query_row(
                    "SELECT 1 FROM teams WHERE id = ?1",
                    [team_id.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            if exists.is_none() {
                return Err(CoreError::NotFound(format!("team {team_id}")));
            }
            c.execute(
                "INSERT INTO team_members (team_id, user_id, role, added_at) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (team_id, user_id) DO UPDATE SET role = excluded.role",
                params![team_id.to_string(), user.to_string(), role.as_str(), now_ms()],
            )?;
            Ok(())
        })
        .await
    }

    /// Removes a member. Never leaves the team without an owner.
    pub async fn remove_team_member(&self, team_id: Id, user: Id) -> Result<()> {
        self.call(move |c, _| {
            let role: Option<String> = c
                .query_row(
                    "SELECT role FROM team_members WHERE team_id = ?1 AND user_id = ?2",
                    params![team_id.to_string(), user.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(role) = role else {
                return Err(CoreError::NotFound("not a member of the team".into()));
            };
            if role == "owner" {
                let owners: i64 = c.query_row(
                    "SELECT COUNT(*) FROM team_members WHERE team_id = ?1 AND role = 'owner'",
                    [team_id.to_string()],
                    |r| r.get(0),
                )?;
                if owners <= 1 {
                    return Err(CoreError::Conflict(
                        "the team would be left without an owner: appoint another one first or delete it".into(),
                    ));
                }
            }
            c.execute(
                "DELETE FROM team_members WHERE team_id = ?1 AND user_id = ?2",
                params![team_id.to_string(), user.to_string()],
            )?;
            Ok(())
        })
        .await
    }

    /// How many owners a team has.
    pub async fn team_owner_count(&self, team_id: Id) -> Result<i64> {
        self.call(move |c, _| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM team_members WHERE team_id = ?1 AND role = 'owner'",
                [team_id.to_string()],
                |r| r.get(0),
            )?)
        })
        .await
    }

    /// Member ids of a team, to notify them.
    pub async fn team_member_ids(&self, team_id: Id) -> Result<Vec<Id>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare("SELECT user_id FROM team_members WHERE team_id = ?1")?;
            Ok(stmt
                .query_map([team_id.to_string()], |r| parse_id(&r.get::<_, String>(0)?))?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::super::sessions::ShareTarget;
    use super::super::test_store;
    use crate::model::*;
    use crate::new_id;

    #[tokio::test]
    async fn teams_and_team_shares() {
        let store = test_store();
        let ana = store
            .create_user("ana@example.com", "Ana", "long-password", true)
            .await
            .unwrap();
        let bea = store
            .create_user("bea@example.com", "Bea", "long-password", false)
            .await
            .unwrap();
        let carlos = store
            .create_user("carlos@example.com", "Carlos", "long-password", false)
            .await
            .unwrap();

        let team = store.create_team(ana.id, "Ops").await.unwrap();
        store
            .set_team_member(team.id, bea.id, TeamRole::Member)
            .await
            .unwrap();
        assert_eq!(store.team_members(team.id).await.unwrap().len(), 2);
        assert_eq!(
            store.teams_of(bea.id).await.unwrap()[0].role,
            Some(TeamRole::Member)
        );
        assert!(store.teams_of(carlos.id).await.unwrap().is_empty());
        assert_eq!(store.team_for(team.id, carlos.id).await.unwrap().role, None);

        // Ana's session shared with the team.
        let session = SessionInfo {
            id: new_id(),
            owner_id: ana.id,
            host_id: None,
            title: "web".into(),
            status: SessionStatus::Running,
            kind: "server".into(),
            created_at: 1,
            ended_at: None,
            error: None,
            recording: false,
        };
        store.insert_session(session.clone()).await.unwrap();
        let (share, _) = store
            .create_share(
                session.id,
                ana.id,
                ShareTarget::Team(team.id),
                SharePermission::View,
                None,
            )
            .await
            .unwrap();
        assert_eq!(share.team_id, Some(team.id));
        // Bea sees it; Carlos does not; Ana does not see it as "shared with me".
        assert_eq!(store.sessions_shared_with(bea.id).await.unwrap().len(), 1);
        assert!(
            store
                .share_for_user(session.id, bea.id)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .share_for_user(session.id, carlos.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.sessions_shared_with(ana.id).await.unwrap().is_empty());

        // If she is also invited directly with control, the higher permission
        // wins and the session is not listed twice.
        store
            .create_share(
                session.id,
                ana.id,
                ShareTarget::User(bea.id),
                SharePermission::Control,
                None,
            )
            .await
            .unwrap();
        let shared = store.sessions_shared_with(bea.id).await.unwrap();
        assert_eq!(shared.len(), 1);
        assert_eq!(shared[0].1.permission, SharePermission::Control);

        // The only owner cannot leave; when Bea leaves she loses the access she
        // had through the team.
        assert!(store.remove_team_member(team.id, ana.id).await.is_err());
        store
            .revoke_share(session.id, shared[0].1.id)
            .await
            .unwrap();
        store.remove_team_member(team.id, bea.id).await.unwrap();
        assert!(
            store
                .share_for_user(session.id, bea.id)
                .await
                .unwrap()
                .is_none()
        );

        // Deleting the team revokes its shares.
        store.delete_team(team.id).await.unwrap();
        assert!(store.team_shares(team.id).await.unwrap().is_empty());
    }
}

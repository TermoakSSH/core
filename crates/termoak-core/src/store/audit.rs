//! Audit log: who connected, what the AI ran, who typed in a shared session...
//!
//! 0.7 phase 5a (docs/E2EE-SSO-AUDIT.md §4): every entry may belong to a
//! team (`team_id`: team vaults and team actions), searchable with filters,
//! exportable, purged after a retention period, and delivered to SIEM
//! sinks (webhooks, syslog) that keep a cursor (the last id delivered).

use rusqlite::types::ToSql;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use super::{Store, parse_id, parse_opt_id};
use crate::Id;
use crate::error::{CoreError, Result};
use crate::model::AuditEntry;
use crate::time::now_ms;

const AUDIT_COLUMNS: &str =
    "id, owner_id, actor, action, target, detail, created_at, vault_id, team_id";

/// Whose entries a search covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditScope {
    /// The entries about one user's account (`owner_id`).
    Owner(Id),
    /// One vault's entries.
    Vault(Id),
    /// One team's entries (its vaults and the team's own actions).
    Team(Id),
    /// Everything (server administrators).
    All,
}

/// Filters of an audit search (all optional; combined with AND).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema, utoipa::IntoParams))]
pub struct AuditFilter {
    /// Actions, comma separated; `access.*` matches a prefix
    /// (`access.approve,cert.*`).
    #[serde(default)]
    pub action: Option<String>,
    /// `user:<id>`, a bare user id, or any actor string (`ai:<task>`).
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub vault_id: Option<uuid::Uuid>,
    #[serde(default)]
    pub target: Option<String>,
    /// From this time (ms since the epoch, inclusive).
    #[serde(default)]
    pub since: Option<i64>,
    /// Until this time (ms, exclusive).
    #[serde(default)]
    pub until: Option<i64>,
    /// Text anywhere in the action, actor, target or details.
    #[serde(default)]
    pub q: Option<String>,
    /// Entries older than this id (paging backwards).
    #[serde(default)]
    pub before: Option<i64>,
    /// Entries newer than this id (paging forwards, oldest first).
    #[serde(default)]
    pub after: Option<i64>,
    /// At most this many (default 100, max 1000; exports page through).
    #[serde(default)]
    pub limit: Option<i64>,
}

impl AuditFilter {
    /// Patterns of `action` as SQL LIKE patterns.
    fn action_patterns(&self) -> Vec<String> {
        self.action
            .as_deref()
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|a| !a.is_empty())
            .map(|a| match a.strip_suffix('*') {
                Some(prefix) => format!("{}%", escape_like(prefix)),
                None => escape_like(a),
            })
            .collect()
    }

    /// Whether an entry matches the action filter (sinks).
    pub fn matches_action(patterns: &[String], action: &str) -> bool {
        patterns.is_empty()
            || patterns.iter().any(|p| match p.strip_suffix('*') {
                Some(prefix) => action.starts_with(prefix),
                None => action == p,
            })
    }
}

fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Retention and sink bookkeeping of a team.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuditSettings {
    /// Days the team's entries are kept (`None`: the server's default).
    #[serde(default)]
    pub retention_days: Option<u32>,
}

/// Kind of an audit sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum AuditSinkKind {
    /// HTTPS POST of JSON batches signed with HMAC-SHA256.
    Webhook,
    /// RFC 5424 messages over TCP or TLS (RFC 6587 octet counting).
    Syslog,
}

impl AuditSinkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditSinkKind::Webhook => "webhook",
            AuditSinkKind::Syslog => "syslog",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "webhook" => Some(AuditSinkKind::Webhook),
            "syslog" => Some(AuditSinkKind::Syslog),
            _ => None,
        }
    }
}

/// Where a sink delivers (no secret in it).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuditSinkConfig {
    /// Webhook: the `https://` URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Syslog: host name or address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Syslog: port (default 6514 with TLS, 514 with TCP).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Syslog: `tls` (default) or `tcp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// Syslog over TLS: a PEM CA to trust instead of the public roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem: Option<String>,
    /// Syslog: facility number (default 13, log audit... RFC 5424 §6.2.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility: Option<u8>,
    /// Syslog: APP-NAME (default `termoak`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
}

/// An audit sink as the API shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuditSink {
    pub id: uuid::Uuid,
    /// `None`: the whole server (administrators).
    pub team_id: Option<uuid::Uuid>,
    pub kind: AuditSinkKind,
    pub name: String,
    pub config: AuditSinkConfig,
    /// Action patterns (`access.*`); empty: everything.
    pub actions: Vec<String>,
    pub enabled: bool,
    /// Last entry id delivered.
    pub cursor: i64,
    /// Failed attempts in a row.
    pub failures: i64,
    pub last_error: Option<String>,
    pub last_attempt_at: Option<i64>,
    pub last_success_at: Option<i64>,
    pub created_by: uuid::Uuid,
    pub created_at: i64,
    pub updated_at: i64,
}

/// A sink with its sealed signing secret (for the delivery worker).
#[derive(Debug, Clone)]
pub struct AuditSinkRow {
    pub sink: AuditSink,
    pub secret: Option<Vec<u8>>,
}

const SINK_COLUMNS: &str = "id, team_id, kind, name, config, actions, enabled, cursor, failures, \
     last_error, last_attempt_at, last_success_at, created_by, created_at, updated_at, secret";

fn map_sink(r: &rusqlite::Row<'_>) -> rusqlite::Result<AuditSinkRow> {
    let config: String = r.get(4)?;
    let actions: String = r.get(5)?;
    Ok(AuditSinkRow {
        sink: AuditSink {
            id: parse_id(&r.get::<_, String>(0)?)?,
            team_id: parse_opt_id(r.get(1)?)?,
            kind: AuditSinkKind::parse(&r.get::<_, String>(2)?).unwrap_or(AuditSinkKind::Webhook),
            name: r.get(3)?,
            config: serde_json::from_str(&config).unwrap_or_default(),
            actions: serde_json::from_str(&actions).unwrap_or_default(),
            enabled: r.get::<_, i64>(6)? != 0,
            cursor: r.get(7)?,
            failures: r.get(8)?,
            last_error: r.get(9)?,
            last_attempt_at: r.get(10)?,
            last_success_at: r.get(11)?,
            created_by: parse_id(&r.get::<_, String>(12)?)?,
            created_at: r.get(13)?,
            updated_at: r.get(14)?,
        },
        secret: r.get(15)?,
    })
}

impl Store {
    /// Writes an entry. When the target is a team, the entry belongs to it.
    pub async fn audit(
        &self,
        owner: Id,
        actor: &str,
        action: &str,
        target: Option<String>,
        detail: serde_json::Value,
    ) -> Result<()> {
        let (actor, action) = (actor.to_string(), action.to_string());
        self.call(move |c, _| {
            c.execute(
                "INSERT INTO audit_log (owner_id, actor, action, target, detail, created_at, team_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, (SELECT id FROM teams WHERE id = ?4))",
                params![
                    owner.to_string(),
                    actor,
                    action,
                    target,
                    detail.to_string(),
                    now_ms()
                ],
            )?;
            Ok(())
        })
        .await
    }

    /// Writes an entry of a team (SSO, audit settings and sinks...).
    pub async fn audit_team(
        &self,
        team: Id,
        owner: Id,
        actor: &str,
        action: &str,
        target: Option<String>,
        detail: serde_json::Value,
    ) -> Result<()> {
        let (actor, action) = (actor.to_string(), action.to_string());
        self.call(move |c, _| {
            c.execute(
                "INSERT INTO audit_log (owner_id, actor, action, target, detail, created_at, team_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    owner.to_string(),
                    actor,
                    action,
                    target,
                    detail.to_string(),
                    now_ms(),
                    team.to_string()
                ],
            )?;
            Ok(())
        })
        .await
    }

    /// Latest entries (most recent first). `before` pages backwards.
    pub async fn audit_list(
        &self,
        owner: Id,
        before: Option<i64>,
        limit: i64,
    ) -> Result<Vec<AuditEntry>> {
        self.audit_search(
            AuditScope::Owner(owner),
            AuditFilter {
                before,
                limit: Some(limit),
                ..Default::default()
            },
        )
        .await
    }

    /// Audit log of the whole server (for admins).
    pub async fn audit_list_all(&self, before: Option<i64>, limit: i64) -> Result<Vec<AuditEntry>> {
        self.audit_search(
            AuditScope::All,
            AuditFilter {
                before,
                limit: Some(limit),
                ..Default::default()
            },
        )
        .await
    }

    /// Entries of `scope` matching `filter`: newest first, or oldest first
    /// with `after`.
    pub async fn audit_search(
        &self,
        scope: AuditScope,
        filter: AuditFilter,
    ) -> Result<Vec<AuditEntry>> {
        self.call(move |c, _| {
            let mut sql = format!("SELECT {AUDIT_COLUMNS} FROM audit_log WHERE 1 = 1");
            let mut args: Vec<Box<dyn ToSql>> = Vec::new();
            fn push(
                sql: &mut String,
                args: &mut Vec<Box<dyn ToSql>>,
                clause: &str,
                v: Box<dyn ToSql>,
            ) {
                args.push(v);
                sql.push_str(&clause.replace('?', &format!("?{}", args.len())));
            }
            match scope {
                AuditScope::Owner(o) => push(
                    &mut sql,
                    &mut args,
                    " AND owner_id = ?",
                    Box::new(o.to_string()),
                ),
                AuditScope::Vault(v) => push(
                    &mut sql,
                    &mut args,
                    " AND vault_id = ?",
                    Box::new(v.to_string()),
                ),
                AuditScope::Team(t) => push(
                    &mut sql,
                    &mut args,
                    " AND team_id = ?",
                    Box::new(t.to_string()),
                ),
                AuditScope::All => {}
            }
            let patterns = filter.action_patterns();
            if !patterns.is_empty() {
                sql.push_str(" AND (");
                for (i, p) in patterns.iter().enumerate() {
                    if i > 0 {
                        sql.push_str(" OR ");
                    }
                    push(
                        &mut sql,
                        &mut args,
                        "action LIKE ? ESCAPE '\\'",
                        Box::new(p.clone()),
                    );
                }
                sql.push(')');
            }
            if let Some(a) = filter
                .actor
                .as_deref()
                .map(str::trim)
                .filter(|a| !a.is_empty())
            {
                let actor = if a.parse::<Id>().is_ok() {
                    format!("user:{a}")
                } else {
                    a.to_string()
                };
                push(&mut sql, &mut args, " AND actor = ?", Box::new(actor));
            }
            if let Some(v) = filter.vault_id {
                push(
                    &mut sql,
                    &mut args,
                    " AND vault_id = ?",
                    Box::new(v.to_string()),
                );
            }
            if let Some(t) = filter.target.as_deref().filter(|t| !t.is_empty()) {
                push(
                    &mut sql,
                    &mut args,
                    " AND target = ?",
                    Box::new(t.to_string()),
                );
            }
            if let Some(s) = filter.since {
                push(&mut sql, &mut args, " AND created_at >= ?", Box::new(s));
            }
            if let Some(u) = filter.until {
                push(&mut sql, &mut args, " AND created_at < ?", Box::new(u));
            }
            if let Some(q) = filter.q.as_deref().map(str::trim).filter(|q| !q.is_empty()) {
                args.push(Box::new(format!("%{}%", escape_like(q))));
                let n = args.len();
                sql.push_str(&format!(
                    " AND (action LIKE ?{n} ESCAPE '\\' OR actor LIKE ?{n} ESCAPE '\\' \
                     OR IFNULL(target, '') LIKE ?{n} ESCAPE '\\' OR detail LIKE ?{n} ESCAPE '\\')"
                ));
            }
            let limit = filter.limit.unwrap_or(100).clamp(1, 1000);
            let order = if let Some(a) = filter.after {
                push(&mut sql, &mut args, " AND id > ?", Box::new(a));
                "ASC"
            } else {
                push(
                    &mut sql,
                    &mut args,
                    " AND id < ?",
                    Box::new(filter.before.unwrap_or(i64::MAX)),
                );
                "DESC"
            };
            args.push(Box::new(limit));
            sql.push_str(&format!(" ORDER BY id {order} LIMIT ?{}", args.len()));
            let mut stmt = c.prepare(&sql)?;
            let refs: Vec<&dyn ToSql> = args.iter().map(|b| b.as_ref()).collect();
            let rows = stmt
                .query_map(refs.as_slice(), map_audit)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    /// Deletes entries older than their retention: a team's own setting,
    /// else `default_days` (0 keeps everything). Returns how many.
    pub async fn audit_purge(
        &self,
        default_days: u32,
        team_max_days: Option<u32>,
    ) -> Result<usize> {
        self.call(move |c, _| {
            const DAY: i64 = 24 * 3600 * 1000;
            let now = now_ms();
            let mut n = 0;
            // Teams with their own retention.
            let teams: Vec<(String, u32)> = {
                let mut stmt = c.prepare(
                    "SELECT id, audit_retention_days FROM teams WHERE audit_retention_days IS NOT NULL",
                )?;
                stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            for (team, days) in &teams {
                let days = team_max_days.map_or(*days, |m| (*days).min(m));
                if days > 0 {
                    n += c.execute(
                        "DELETE FROM audit_log WHERE team_id = ?1 AND created_at < ?2",
                        params![team, now - days as i64 * DAY],
                    )?;
                }
            }
            if default_days > 0 {
                n += c.execute(
                    "DELETE FROM audit_log WHERE created_at < ?1
                       AND (team_id IS NULL
                            OR team_id NOT IN (SELECT id FROM teams WHERE audit_retention_days IS NOT NULL))",
                    params![now - default_days as i64 * DAY],
                )?;
            }
            Ok(n)
        })
        .await
    }

    pub async fn audit_settings(&self, team: Id) -> Result<AuditSettings> {
        self.call(move |c, _| {
            let days: Option<u32> = c
                .query_row(
                    "SELECT audit_retention_days FROM teams WHERE id = ?1",
                    [team.to_string()],
                    |r| r.get(0),
                )
                .optional()?
                .ok_or_else(|| CoreError::NotFound(format!("team {team}")))?;
            Ok(AuditSettings {
                retention_days: days,
            })
        })
        .await
    }

    pub async fn set_audit_settings(&self, team: Id, settings: AuditSettings) -> Result<()> {
        self.call(move |c, _| {
            c.execute(
                "UPDATE teams SET audit_retention_days = ?2 WHERE id = ?1",
                params![team.to_string(), settings.retention_days],
            )?;
            Ok(())
        })
        .await
    }

    // ---- sinks ----

    /// Sinks of a team (`Some`) or of the server (`None`).
    pub async fn audit_sinks(&self, team: Option<Id>) -> Result<Vec<AuditSink>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(&format!(
                "SELECT {SINK_COLUMNS} FROM audit_sinks WHERE team_id IS ?1 ORDER BY created_at"
            ))?;
            Ok(stmt
                .query_map([team.map(|t| t.to_string())], map_sink)?
                .map(|r| r.map(|s| s.sink))
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// Every enabled sink with its secret (the delivery worker).
    pub async fn audit_sinks_enabled(&self) -> Result<Vec<AuditSinkRow>> {
        self.call(|c, _| {
            let mut stmt = c.prepare(&format!(
                "SELECT {SINK_COLUMNS} FROM audit_sinks WHERE enabled = 1"
            ))?;
            Ok(stmt
                .query_map([], map_sink)?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    pub async fn audit_sink(&self, id: Id) -> Result<AuditSinkRow> {
        self.call(move |c, _| {
            c.query_row(
                &format!("SELECT {SINK_COLUMNS} FROM audit_sinks WHERE id = ?1"),
                [id.to_string()],
                map_sink,
            )
            .optional()?
            .ok_or_else(|| CoreError::NotFound(format!("audit sink {id}")))
        })
        .await
    }

    /// Creates a sink starting after the newest entry (it delivers what
    /// happens from now on). `secret` is already sealed.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_audit_sink(
        &self,
        team: Option<Id>,
        kind: AuditSinkKind,
        name: String,
        config: AuditSinkConfig,
        actions: Vec<String>,
        secret: Option<Vec<u8>>,
        by: Id,
    ) -> Result<AuditSink> {
        let id = crate::new_id();
        self.call(move |c, _| {
            let now = now_ms();
            let cursor: i64 = c.query_row("SELECT IFNULL(MAX(id), 0) FROM audit_log", [], |r| r.get(0))?;
            c.execute(
                "INSERT INTO audit_sinks (id, team_id, kind, name, config, secret, actions, enabled, cursor,
                                          created_by, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, ?10, ?10)",
                params![
                    id.to_string(),
                    team.map(|t| t.to_string()),
                    kind.as_str(),
                    name,
                    serde_json::to_string(&config)?,
                    secret,
                    serde_json::to_string(&actions)?,
                    cursor,
                    by.to_string(),
                    now
                ],
            )?;
            Ok(())
        })
        .await?;
        Ok(self.audit_sink(id).await?.sink)
    }

    /// Changes a sink (`None`: unchanged). Re-enabling clears the failures.
    pub async fn update_audit_sink(
        &self,
        id: Id,
        name: Option<String>,
        config: Option<AuditSinkConfig>,
        actions: Option<Vec<String>>,
        enabled: Option<bool>,
    ) -> Result<AuditSink> {
        self.call(move |c, _| {
            let now = now_ms();
            if let Some(n) = name {
                c.execute("UPDATE audit_sinks SET name = ?2, updated_at = ?3 WHERE id = ?1", params![id.to_string(), n, now])?;
            }
            if let Some(cfg) = config {
                c.execute(
                    "UPDATE audit_sinks SET config = ?2, updated_at = ?3 WHERE id = ?1",
                    params![id.to_string(), serde_json::to_string(&cfg)?, now],
                )?;
            }
            if let Some(a) = actions {
                c.execute(
                    "UPDATE audit_sinks SET actions = ?2, updated_at = ?3 WHERE id = ?1",
                    params![id.to_string(), serde_json::to_string(&a)?, now],
                )?;
            }
            if let Some(e) = enabled {
                c.execute(
                    "UPDATE audit_sinks SET enabled = ?2, failures = CASE WHEN ?2 = 1 THEN 0 ELSE failures END,
                            updated_at = ?3 WHERE id = ?1",
                    params![id.to_string(), e as i64, now],
                )?;
            }
            Ok(())
        })
        .await?;
        Ok(self.audit_sink(id).await?.sink)
    }

    /// Stores a sink's sealed signing secret.
    pub async fn set_audit_sink_secret(&self, id: Id, sealed: Vec<u8>) -> Result<()> {
        self.call(move |c, _| {
            c.execute(
                "UPDATE audit_sinks SET secret = ?2 WHERE id = ?1",
                params![id.to_string(), sealed],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn delete_audit_sink(&self, id: Id) -> Result<bool> {
        self.call(move |c, _| {
            Ok(c.execute("DELETE FROM audit_sinks WHERE id = ?1", [id.to_string()])? > 0)
        })
        .await
    }

    /// Records a delivery attempt: success moves the cursor; a failure counts.
    pub async fn audit_sink_attempt(
        &self,
        id: Id,
        delivered_up_to: Option<i64>,
        error: Option<String>,
    ) -> Result<()> {
        self.call(move |c, _| {
            let now = now_ms();
            match (delivered_up_to, error) {
                (Some(cursor), None) => c.execute(
                    "UPDATE audit_sinks SET cursor = MAX(cursor, ?2), failures = 0, last_error = NULL,
                            last_attempt_at = ?3, last_success_at = ?3 WHERE id = ?1",
                    params![id.to_string(), cursor, now],
                )?,
                (_, err) => c.execute(
                    "UPDATE audit_sinks SET failures = failures + 1, last_error = ?2, last_attempt_at = ?3
                     WHERE id = ?1",
                    params![id.to_string(), err.unwrap_or_default(), now],
                )?,
            };
            Ok(())
        })
        .await
    }
}

pub(super) fn map_audit(r: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEntry> {
    let detail: String = r.get(5)?;
    Ok(AuditEntry {
        id: r.get(0)?,
        owner_id: parse_id(&r.get::<_, String>(1)?)?,
        actor: r.get(2)?,
        action: r.get(3)?,
        target: r.get(4)?,
        detail: serde_json::from_str(&detail).unwrap_or_default(),
        created_at: r.get(6)?,
        vault_id: parse_opt_id(r.get(7)?)?,
        team_id: parse_opt_id(r.get(8)?)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::test_store;
    use serde_json::json;

    #[tokio::test]
    async fn search_filters_scopes_purge_and_sinks() {
        let store = test_store();
        let u = store
            .create_user("a@x.test", "A", "password123", false)
            .await
            .unwrap()
            .id;
        let team = store.create_team(u, "Ops").await.unwrap().id;
        store
            .audit(
                u,
                &format!("user:{u}"),
                "auth.login",
                Some("d1".into()),
                json!({"ip": "1.2.3.4"}),
            )
            .await
            .unwrap();
        store
            .audit(
                u,
                &format!("user:{u}"),
                "team.policy",
                Some(team.to_string()),
                json!({}),
            )
            .await
            .unwrap();
        store
            .audit_team(
                team,
                u,
                &format!("user:{u}"),
                "sso.login",
                None,
                json!({"email": "a@x.test"}),
            )
            .await
            .unwrap();
        store
            .audit(
                u,
                "ai:t1",
                "access.approve",
                Some("r1".into()),
                json!({"minutes": 30}),
            )
            .await
            .unwrap();

        let all = store
            .audit_search(AuditScope::All, AuditFilter::default())
            .await
            .unwrap();
        assert_eq!(all.len(), 4);
        assert_eq!(all[0].action, "access.approve");
        let teams = store
            .audit_search(AuditScope::Team(team), AuditFilter::default())
            .await
            .unwrap();
        assert_eq!(
            teams.iter().map(|e| e.action.as_str()).collect::<Vec<_>>(),
            vec!["sso.login", "team.policy"]
        );
        let f = |action: &str| AuditFilter {
            action: Some(action.into()),
            ..Default::default()
        };
        assert_eq!(
            store
                .audit_search(AuditScope::All, f("sso.*,access.approve"))
                .await
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            store
                .audit_search(AuditScope::All, f("auth_login"))
                .await
                .unwrap()
                .len(),
            0,
            "_ is not a wildcard"
        );
        let q = AuditFilter {
            q: Some("1.2.3".into()),
            ..Default::default()
        };
        assert_eq!(
            store
                .audit_search(AuditScope::Owner(u), q)
                .await
                .unwrap()
                .len(),
            1
        );
        let a = AuditFilter {
            actor: Some(u.to_string()),
            ..Default::default()
        };
        assert_eq!(
            store.audit_search(AuditScope::All, a).await.unwrap().len(),
            3
        );
        let first = all.last().unwrap().id;
        let fwd = AuditFilter {
            after: Some(first),
            limit: Some(2),
            ..Default::default()
        };
        let page = store.audit_search(AuditScope::All, fwd).await.unwrap();
        assert_eq!(page.len(), 2);
        assert!(page[0].id < page[1].id);

        // A sink starts after the newest entry.
        let sink = store
            .create_audit_sink(
                Some(team),
                AuditSinkKind::Webhook,
                "SIEM".into(),
                AuditSinkConfig::default(),
                vec!["sso.*".into()],
                None,
                u,
            )
            .await
            .unwrap();
        assert_eq!(sink.cursor, all[0].id);
        store
            .audit_sink_attempt(sink.id, None, Some("refused".into()))
            .await
            .unwrap();
        assert_eq!(store.audit_sink(sink.id).await.unwrap().sink.failures, 1);
        store
            .audit_sink_attempt(sink.id, Some(all[0].id + 5), None)
            .await
            .unwrap();
        let s = store.audit_sink(sink.id).await.unwrap().sink;
        assert_eq!((s.failures, s.cursor), (0, all[0].id + 5));
        assert!(AuditFilter::matches_action(&s.actions, "sso.login"));
        assert!(!AuditFilter::matches_action(&s.actions, "auth.login"));

        // Retention: everything is recent, nothing goes; a 0-day team keeps.
        assert_eq!(store.audit_purge(30, None).await.unwrap(), 0);
        store
            .set_audit_settings(
                team,
                AuditSettings {
                    retention_days: Some(7),
                },
            )
            .await
            .unwrap();
        store
            .call(|c, _| {
                c.execute("UPDATE audit_log SET created_at = 1", [])?;
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(
            store.audit_purge(0, None).await.unwrap(),
            2,
            "only the team's entries have a retention"
        );
        assert_eq!(store.audit_purge(30, None).await.unwrap(), 2);
    }
}

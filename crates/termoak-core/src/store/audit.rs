//! Audit log: who connected, what the AI ran, who typed in a shared session...

use rusqlite::params;

use super::{Store, parse_id, parse_opt_id};
use crate::Id;
use crate::error::Result;
use crate::model::AuditEntry;
use crate::time::now_ms;

impl Store {
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
                "INSERT INTO audit_log (owner_id, actor, action, target, detail, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
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

    /// Latest entries (most recent first). `before` pages backwards.
    pub async fn audit_list(
        &self,
        owner: Id,
        before: Option<i64>,
        limit: i64,
    ) -> Result<Vec<AuditEntry>> {
        self.audit_query(Some(owner), before, limit).await
    }

    /// Audit log of the whole server (for admins).
    pub async fn audit_list_all(&self, before: Option<i64>, limit: i64) -> Result<Vec<AuditEntry>> {
        self.audit_query(None, before, limit).await
    }

    async fn audit_query(
        &self,
        owner: Option<Id>,
        before: Option<i64>,
        limit: i64,
    ) -> Result<Vec<AuditEntry>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(
                "SELECT id, owner_id, actor, action, target, detail, created_at, vault_id
                 FROM audit_log
                 WHERE (?1 IS NULL OR owner_id = ?1) AND id < ?2 ORDER BY id DESC LIMIT ?3",
            )?;
            let rows = stmt
                .query_map(
                    params![
                        owner.map(|o| o.to_string()),
                        before.unwrap_or(i64::MAX),
                        limit
                    ],
                    map_audit,
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
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
    })
}

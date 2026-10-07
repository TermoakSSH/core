//! AI task persistence: status, transcript, events and approvals.
//!
//! The core stores "raw" rows (JSON); the rich types live in `termoak-ai`.

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use super::{Store, parse_id};
use crate::Id;
use crate::error::{CoreError, Result};
use crate::time::now_ms;

/// `ai_tasks` row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiTaskRow {
    pub id: Id,
    pub owner_id: Id,
    pub title: String,
    pub prompt: String,
    pub status: String,
    pub mode: String,
    pub provider: String,
    pub used_provider: Option<String>,
    pub context: serde_json::Value,
    pub messages: serde_json::Value,
    pub usage: serde_json::Value,
    pub cost_micros: i64,
    pub result: Option<String>,
    pub error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub finished_at: Option<i64>,
}

/// `ai_events` row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiEventRow {
    pub task_id: Id,
    pub seq: i64,
    pub kind: String,
    pub data: serde_json::Value,
    pub created_at: i64,
}

/// `ai_approvals` row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiApprovalRow {
    pub id: Id,
    pub task_id: Id,
    pub tool: String,
    pub input: serde_json::Value,
    pub summary: String,
    pub status: String,
    pub decided_by: Option<String>,
    pub created_at: i64,
    pub decided_at: Option<i64>,
    /// What the approval shows (`termoak_ai::approval::ApprovalPreview`:
    /// the command with its risk, the diff of a file...). `None` for
    /// approvals saved before schema v11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<serde_json::Value>,
}

/// `ai_usage` row: one AI call (a turn of a task or a quick-assistant call).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiUsageRow {
    pub owner_id: Id,
    /// `None` for the quick assistant (no task).
    pub task_id: Option<Id>,
    /// `provider::model` that answered.
    pub provider: String,
    /// Run with the user's own API key (does not count against the plan's
    /// AI credit) or with the server's provider.
    pub own_key: bool,
    pub input_tokens: i64,
    pub output_tokens: i64,
    /// Real cost (what the server pays; 0 on a subscription).
    pub cost_micros: i64,
    /// What it took from the plan's AI credit (0 with the user's own key).
    pub credit_micros: i64,
    pub created_at: i64,
}

const TASK_COLUMNS: &str = "id, owner_id, title, prompt, status, mode, provider, used_provider, context, messages, usage, cost_micros, result, error, created_at, updated_at, finished_at";

fn map_task(r: &rusqlite::Row<'_>) -> rusqlite::Result<AiTaskRow> {
    let json = |i: usize| -> rusqlite::Result<serde_json::Value> {
        let s: String = r.get(i)?;
        serde_json::from_str(&s).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(i, rusqlite::types::Type::Text, Box::new(e))
        })
    };
    Ok(AiTaskRow {
        id: parse_id(&r.get::<_, String>(0)?)?,
        owner_id: parse_id(&r.get::<_, String>(1)?)?,
        title: r.get(2)?,
        prompt: r.get(3)?,
        status: r.get(4)?,
        mode: r.get(5)?,
        provider: r.get(6)?,
        used_provider: r.get(7)?,
        context: json(8)?,
        messages: json(9)?,
        usage: json(10)?,
        cost_micros: r.get(11)?,
        result: r.get(12)?,
        error: r.get(13)?,
        created_at: r.get(14)?,
        updated_at: r.get(15)?,
        finished_at: r.get(16)?,
    })
}

const APPROVAL_COLUMNS: &str =
    "id, task_id, tool, input, summary, status, decided_by, created_at, decided_at, preview";

fn map_approval(r: &rusqlite::Row<'_>) -> rusqlite::Result<AiApprovalRow> {
    let input: String = r.get(3)?;
    Ok(AiApprovalRow {
        id: parse_id(&r.get::<_, String>(0)?)?,
        task_id: parse_id(&r.get::<_, String>(1)?)?,
        tool: r.get(2)?,
        input: serde_json::from_str(&input).unwrap_or(serde_json::Value::Null),
        summary: r.get(4)?,
        status: r.get(5)?,
        decided_by: r.get(6)?,
        created_at: r.get(7)?,
        decided_at: r.get(8)?,
        preview: r
            .get::<_, Option<String>>(9)?
            .and_then(|p| serde_json::from_str(&p).ok()),
    })
}

impl Store {
    pub async fn ai_insert_task(&self, row: AiTaskRow) -> Result<()> {
        self.call(move |c, _| {
            c.execute(
                &format!(
                    "INSERT INTO ai_tasks ({TASK_COLUMNS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)"
                ),
                params![
                    row.id.to_string(),
                    row.owner_id.to_string(),
                    row.title,
                    row.prompt,
                    row.status,
                    row.mode,
                    row.provider,
                    row.used_provider,
                    row.context.to_string(),
                    row.messages.to_string(),
                    row.usage.to_string(),
                    row.cost_micros,
                    row.result,
                    row.error,
                    row.created_at,
                    row.updated_at,
                    row.finished_at
                ],
            )?;
            Ok(())
        })
        .await
    }

    /// Saves the full state of a task (except `owner_id`, `prompt` and `created_at`).
    pub async fn ai_update_task(&self, row: AiTaskRow) -> Result<()> {
        self.call(move |c, _| {
            c.execute(
                "UPDATE ai_tasks SET title = ?2, status = ?3, mode = ?4, provider = ?5, used_provider = ?6,
                        context = ?7, messages = ?8, usage = ?9, cost_micros = ?10, result = ?11,
                        error = ?12, updated_at = ?13, finished_at = ?14
                 WHERE id = ?1",
                params![
                    row.id.to_string(),
                    row.title,
                    row.status,
                    row.mode,
                    row.provider,
                    row.used_provider,
                    row.context.to_string(),
                    row.messages.to_string(),
                    row.usage.to_string(),
                    row.cost_micros,
                    row.result,
                    row.error,
                    now_ms(),
                    row.finished_at
                ],
            )?;
            Ok(())
        })
        .await
    }

    /// Changes only the status of a task.
    pub async fn ai_set_status(&self, id: Id, status: &str) -> Result<()> {
        let status = status.to_string();
        self.call(move |c, _| {
            c.execute(
                "UPDATE ai_tasks SET status = ?2, updated_at = ?3 WHERE id = ?1",
                params![id.to_string(), status, now_ms()],
            )?;
            Ok(())
        })
        .await
    }

    /// Changes the permission mode of one of the user's tasks. `false` if it does not exist.
    pub async fn ai_set_mode(&self, owner: Id, id: Id, mode: &str) -> Result<bool> {
        let mode = mode.to_string();
        self.call(move |c, _| {
            Ok(c.execute(
                "UPDATE ai_tasks SET mode = ?3, updated_at = ?4 WHERE id = ?1 AND owner_id = ?2",
                params![id.to_string(), owner.to_string(), mode, now_ms()],
            )? > 0)
        })
        .await
    }

    pub async fn ai_task(&self, owner: Id, id: Id) -> Result<AiTaskRow> {
        self.call(move |c, _| {
            c.query_row(
                &format!("SELECT {TASK_COLUMNS} FROM ai_tasks WHERE id = ?1 AND owner_id = ?2"),
                params![id.to_string(), owner.to_string()],
                map_task,
            )
            .optional()?
            .ok_or_else(|| CoreError::NotFound(format!("task {id}")))
        })
        .await
    }

    pub async fn ai_list_tasks(&self, owner: Id, limit: i64) -> Result<Vec<AiTaskRow>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(&format!(
                "SELECT {TASK_COLUMNS} FROM ai_tasks WHERE owner_id = ?1 ORDER BY created_at DESC LIMIT ?2"
            ))?;
            Ok(stmt
                .query_map(params![owner.to_string(), limit], map_task)?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    pub async fn ai_delete_task(&self, owner: Id, id: Id) -> Result<()> {
        self.call(move |c, _| {
            let n = c.execute(
                "DELETE FROM ai_tasks WHERE id = ?1 AND owner_id = ?2",
                params![id.to_string(), owner.to_string()],
            )?;
            if n == 0 {
                return Err(CoreError::NotFound(format!("task {id}")));
            }
            Ok(())
        })
        .await
    }

    /// Tasks left unfinished when the server restarted.
    pub async fn ai_fail_orphan_tasks(&self) -> Result<usize> {
        self.ai_fail_orphan_tasks_with("the server restarted during the task")
            .await
    }

    /// Tasks left unfinished by a restart, marked as failed with `error`
    /// (a client app says it was closed). Their pending approvals expire.
    pub async fn ai_fail_orphan_tasks_with(&self, error: &str) -> Result<usize> {
        let error = error.to_string();
        self.call(move |c, _| {
            let now = now_ms();
            c.execute(
                "UPDATE ai_approvals SET status = 'expired', decided_by = 'restart', decided_at = ?1
                 WHERE status = 'pending' AND task_id IN
                     (SELECT id FROM ai_tasks WHERE status IN ('queued','running','waiting_approval'))",
                params![now],
            )?;
            Ok(c.execute(
                "UPDATE ai_tasks SET status = 'failed', error = ?2,
                        finished_at = ?1, updated_at = ?1
                 WHERE status IN ('queued','running','waiting_approval')",
                params![now, error],
            )?)
        })
        .await
    }

    pub async fn ai_append_event(&self, ev: AiEventRow) -> Result<()> {
        self.call(move |c, _| {
            c.execute(
                "INSERT INTO ai_events (task_id, seq, kind, data, created_at) VALUES (?1,?2,?3,?4,?5)",
                params![
                    ev.task_id.to_string(),
                    ev.seq,
                    ev.kind,
                    ev.data.to_string(),
                    ev.created_at
                ],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn ai_events_since(&self, task_id: Id, after_seq: i64) -> Result<Vec<AiEventRow>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(
                "SELECT task_id, seq, kind, data, created_at FROM ai_events
                 WHERE task_id = ?1 AND seq > ?2 ORDER BY seq",
            )?;
            let rows = stmt
                .query_map(params![task_id.to_string(), after_seq], |r| {
                    let data: String = r.get(3)?;
                    Ok(AiEventRow {
                        task_id: parse_id(&r.get::<_, String>(0)?)?,
                        seq: r.get(1)?,
                        kind: r.get(2)?,
                        data: serde_json::from_str(&data).unwrap_or(serde_json::Value::Null),
                        created_at: r.get(4)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    pub async fn ai_insert_approval(&self, row: AiApprovalRow) -> Result<()> {
        self.call(move |c, _| {
            c.execute(
                &format!("INSERT INTO ai_approvals ({APPROVAL_COLUMNS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)"),
                params![
                    row.id.to_string(),
                    row.task_id.to_string(),
                    row.tool,
                    row.input.to_string(),
                    row.summary,
                    row.status,
                    row.decided_by,
                    row.created_at,
                    row.decided_at,
                    row.preview.as_ref().map(|p| p.to_string())
                ],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn ai_decide_approval(&self, id: Id, status: &str, decided_by: &str) -> Result<()> {
        let (status, decided_by) = (status.to_string(), decided_by.to_string());
        self.call(move |c, _| {
            c.execute(
                "UPDATE ai_approvals SET status = ?2, decided_by = ?3, decided_at = ?4
                 WHERE id = ?1 AND status = 'pending'",
                params![id.to_string(), status, decided_by, now_ms()],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn ai_approvals(&self, task_id: Id) -> Result<Vec<AiApprovalRow>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(&format!(
                "SELECT {APPROVAL_COLUMNS} FROM ai_approvals WHERE task_id = ?1 ORDER BY created_at"
            ))?;
            Ok(stmt
                .query_map([task_id.to_string()], map_approval)?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// A user's pending approvals (for mobile).
    pub async fn ai_pending_approvals(&self, owner: Id) -> Result<Vec<AiApprovalRow>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(
                "SELECT a.id, a.task_id, a.tool, a.input, a.summary, a.status, a.decided_by, a.created_at, a.decided_at, a.preview
                 FROM ai_approvals a JOIN ai_tasks t ON t.id = a.task_id
                 WHERE t.owner_id = ?1 AND a.status = 'pending' ORDER BY a.created_at",
            )?;
            Ok(stmt
                .query_map([owner.to_string()], map_approval)?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// Records the usage of an AI call.
    pub async fn ai_record_usage(&self, row: AiUsageRow) -> Result<()> {
        self.call(move |c, _| {
            c.execute(
                "INSERT INTO ai_usage (owner_id, task_id, provider, own_key, input_tokens,
                                       output_tokens, cost_micros, credit_micros, created_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    row.owner_id.to_string(),
                    row.task_id.map(|t| t.to_string()),
                    row.provider,
                    row.own_key,
                    row.input_tokens,
                    row.output_tokens,
                    row.cost_micros,
                    row.credit_micros,
                    row.created_at
                ],
            )?;
            Ok(())
        })
        .await
    }

    /// A user's AI credit spent on the server's providers (not their own API
    /// keys) since `since_ms`, in micro-USD. This is what the plan's credit limits.
    pub async fn ai_credit_spent_since(&self, owner: Id, since_ms: i64) -> Result<i64> {
        self.call(move |c, _| {
            Ok(c.query_row(
                "SELECT COALESCE(SUM(credit_micros), 0) FROM ai_usage
                 WHERE owner_id = ?1 AND own_key = 0 AND created_at >= ?2",
                params![owner.to_string(), since_ms],
                |r| r.get(0),
            )?)
        })
        .await
    }

    /// A user's real AI cost since `since_ms` from the usage ledger (every
    /// call, tasks and quick assistant, own keys included), in micro-USD.
    pub async fn ai_usage_cost_since(&self, owner: Id, since_ms: i64) -> Result<i64> {
        self.call(move |c, _| {
            Ok(c.query_row(
                "SELECT COALESCE(SUM(cost_micros), 0) FROM ai_usage
                 WHERE owner_id = ?1 AND created_at >= ?2",
                params![owner.to_string(), since_ms],
                |r| r.get(0),
            )?)
        })
        .await
    }

    /// A user's accumulated AI cost since `since_ms`.
    pub async fn ai_cost_since(&self, owner: Id, since_ms: i64) -> Result<i64> {
        self.call(move |c, _| {
            Ok(c.query_row(
                "SELECT COALESCE(SUM(cost_micros), 0) FROM ai_tasks WHERE owner_id = ?1 AND created_at >= ?2",
                params![owner.to_string(), since_ms],
                |r| r.get(0),
            )?)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::test_store;
    use super::*;

    fn task(owner: Id, status: &str) -> AiTaskRow {
        AiTaskRow {
            id: crate::new_id(),
            owner_id: owner,
            title: "t".into(),
            prompt: "p".into(),
            status: status.into(),
            mode: "ask".into(),
            provider: String::new(),
            used_provider: None,
            context: json!({}),
            messages: json!([]),
            usage: json!({}),
            cost_micros: 0,
            result: None,
            error: None,
            created_at: 1,
            updated_at: 1,
            finished_at: None,
        }
    }

    #[tokio::test]
    async fn orphans_fail_with_the_given_reason() {
        let store = test_store();
        let owner = crate::new_id();
        let running = task(owner, "waiting_approval");
        let done = task(owner, "completed");
        store.ai_insert_task(running.clone()).await.unwrap();
        store.ai_insert_task(done.clone()).await.unwrap();
        store
            .ai_insert_approval(AiApprovalRow {
                id: crate::new_id(),
                task_id: running.id,
                tool: "run_command".into(),
                input: json!({}),
                summary: "x".into(),
                status: "pending".into(),
                decided_by: None,
                created_at: 1,
                decided_at: None,
                preview: Some(json!({"kind": "command", "risk": "high"})),
            })
            .await
            .unwrap();
        // The preview is kept (schema v11).
        let pending = store.ai_pending_approvals(owner).await.unwrap();
        assert_eq!(pending[0].preview.as_ref().unwrap()["risk"], "high");
        assert_eq!(
            store.ai_approvals(running.id).await.unwrap()[0].preview,
            pending[0].preview
        );
        let n = store
            .ai_fail_orphan_tasks_with("the app was closed")
            .await
            .unwrap();
        assert_eq!(n, 1);
        let t = store.ai_task(owner, running.id).await.unwrap();
        assert_eq!(t.status, "failed");
        assert_eq!(t.error.as_deref(), Some("the app was closed"));
        assert!(t.finished_at.is_some());
        assert_eq!(
            store.ai_task(owner, done.id).await.unwrap().status,
            "completed"
        );
        assert!(store.ai_pending_approvals(owner).await.unwrap().is_empty());
    }
}

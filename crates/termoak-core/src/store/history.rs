//! Per-host command history, for terminal autocompletion.
//!
//! It only exists on each device: it is not synced, because what gets typed
//! may include sensitive data.

use rusqlite::params;

use super::Store;
use crate::Id;
use crate::error::Result;
use crate::time::now_ms;

/// Maximum commands kept per host (the oldest are purged).
const MAX_PER_HOST: i64 = 2000;
/// Maximum length of a stored command.
const MAX_LEN: usize = 2048;

/// History command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    pub command: String,
    pub uses: i64,
    pub last_used: i64,
}

/// Looks like it contains a secret: better not to store it.
fn looks_sensitive(cmd: &str) -> bool {
    let lower = cmd.to_lowercase();
    // Commands starting with a space: the HISTCONTROL=ignorespace convention.
    cmd.starts_with(' ')
        || [
            "password=",
            "passwd=",
            "token=",
            "secret=",
            "api_key=",
            "apikey=",
            "--password",
            "-p'",
            "authorization:",
            "bearer ",
        ]
        .iter()
        .any(|p| lower.contains(p))
}

/// History query with a host filter.
struct Search<'a> {
    owner: String,
    pattern: &'a str,
    now: i64,
    limit: usize,
}

impl Search<'_> {
    fn run(
        &self,
        c: &rusqlite::Connection,
        host_clause: &str,
        host_param: String,
        out: &mut Vec<HistoryEntry>,
    ) -> Result<()> {
        let mut stmt = c.prepare(&format!(
            "SELECT command, SUM(uses), MAX(last_used) FROM command_history
             WHERE owner_id = ?1 AND {host_clause}
               AND substr(command, 1, length(?3)) = ?3
             GROUP BY command
             ORDER BY (SUM(uses) * 1.0) / (1 + (?4 - MAX(last_used)) / 86400000.0) DESC
             LIMIT ?5"
        ))?;
        let rows = stmt.query_map(
            params![
                self.owner,
                host_param,
                self.pattern,
                self.now,
                self.limit as i64
            ],
            |r| {
                Ok(HistoryEntry {
                    command: r.get(0)?,
                    uses: r.get(1)?,
                    last_used: r.get(2)?,
                })
            },
        )?;
        for row in rows {
            let row = row?;
            if out.len() < self.limit && !out.iter().any(|e| e.command == row.command) {
                out.push(row);
            }
        }
        Ok(())
    }
}

impl Store {
    /// Stores (or updates) a command in a host's history.
    pub async fn history_record(&self, owner: Id, host: Id, command: &str) -> Result<bool> {
        let command = command.trim_end().to_string();
        if command.trim().is_empty() || command.len() > MAX_LEN || looks_sensitive(&command) {
            return Ok(false);
        }
        self.call(move |c, _| {
            let now = now_ms();
            c.execute(
                "INSERT INTO command_history (owner_id, host_id, command, uses, last_used)
                 VALUES (?1, ?2, ?3, 1, ?4)
                 ON CONFLICT (owner_id, host_id, command)
                 DO UPDATE SET uses = uses + 1, last_used = excluded.last_used",
                params![owner.to_string(), host.to_string(), command, now],
            )?;
            c.execute(
                "DELETE FROM command_history WHERE owner_id = ?1 AND host_id = ?2 AND command IN (
                     SELECT command FROM command_history WHERE owner_id = ?1 AND host_id = ?2
                     ORDER BY last_used DESC LIMIT -1 OFFSET ?3)",
                params![owner.to_string(), host.to_string(), MAX_PER_HOST],
            )?;
            Ok(true)
        })
        .await
    }

    /// Commands starting with `prefix`: the given host's first and, if there
    /// are not enough, those of other hosts. Sorted by use and recency.
    pub async fn history_search(
        &self,
        owner: Id,
        host: Option<Id>,
        prefix: &str,
        limit: usize,
    ) -> Result<Vec<HistoryEntry>> {
        let prefix = prefix.to_string();
        self.call(move |c, _| {
            // Exact prefix (case-sensitive, and `%` or `_` are literal).
            let pattern = prefix;
            let now = now_ms();
            let mut out: Vec<HistoryEntry> = Vec::new();
            let q = Search {
                owner: owner.to_string(),
                pattern: &pattern,
                now,
                limit,
            };
            if let Some(h) = host {
                q.run(c, "host_id = ?2", h.to_string(), &mut out)?;
                if out.len() < limit {
                    q.run(c, "host_id != ?2", h.to_string(), &mut out)?;
                }
            } else {
                q.run(c, "?2 = ?2", String::new(), &mut out)?;
            }
            Ok(out)
        })
        .await
    }

    /// Clears a host's history (or all of it if `host` is `None`).
    pub async fn history_clear(&self, owner: Id, host: Option<Id>) -> Result<()> {
        self.call(move |c, _| {
            match host {
                Some(h) => c.execute(
                    "DELETE FROM command_history WHERE owner_id = ?1 AND host_id = ?2",
                    params![owner.to_string(), h.to_string()],
                )?,
                None => c.execute(
                    "DELETE FROM command_history WHERE owner_id = ?1",
                    [owner.to_string()],
                )?,
            };
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_store;
    use crate::new_id;

    #[tokio::test]
    async fn history_ranking_and_privacy() {
        let store = test_store();
        let (me, web, db) = (new_id(), new_id(), new_id());
        for _ in 0..3 {
            store
                .history_record(me, web, "systemctl status nginx")
                .await
                .unwrap();
        }
        store
            .history_record(me, web, "systemctl restart nginx")
            .await
            .unwrap();
        store
            .history_record(me, db, "systemctl status postgresql")
            .await
            .unwrap();
        assert!(
            !store
                .history_record(me, web, " export TOKEN=abc")
                .await
                .unwrap()
        );
        assert!(
            !store
                .history_record(me, web, "mysql --password=x")
                .await
                .unwrap()
        );
        assert!(!store.history_record(me, web, "   ").await.unwrap());

        let found = store
            .history_search(me, Some(web), "systemctl", 10)
            .await
            .unwrap();
        let cmds: Vec<_> = found.iter().map(|e| e.command.as_str()).collect();
        // This host's first (most used first), then other hosts'.
        assert_eq!(
            cmds,
            [
                "systemctl status nginx",
                "systemctl restart nginx",
                "systemctl status postgresql"
            ]
        );
        // `_` and `%` are literal.
        assert!(
            store
                .history_search(me, Some(web), "sys_", 10)
                .await
                .unwrap()
                .is_empty()
        );
        // Case-sensitive (what gets inserted on accept must match).
        assert!(
            store
                .history_search(me, Some(web), "Systemctl", 10)
                .await
                .unwrap()
                .is_empty()
        );

        store.history_clear(me, Some(web)).await.unwrap();
        let left = store.history_search(me, None, "", 10).await.unwrap();
        assert_eq!(left.len(), 1);
    }
}

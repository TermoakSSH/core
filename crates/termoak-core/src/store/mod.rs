//! SQLite storage.
//!
//! A single connection behind a mutex, used from a blocking thread
//! (`spawn_blocking`). SQLite serializes writes anyway and each operation
//! takes microseconds, so this is simple and fast.

mod ai;
pub mod ai_keys;
mod audit;
pub mod email_tokens;
mod entities;
pub mod history;
pub mod invites;
pub mod sessions;
pub mod teams;
pub mod users;

use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension};

pub use ai::{AiApprovalRow, AiEventRow, AiTaskRow, AiUsageRow};

use crate::Id;
use crate::crypto::MasterKey;
use crate::error::{CoreError, Result};

/// Termoak data store. Cheap to clone.
#[derive(Clone)]
pub struct Store {
    inner: Arc<Inner>,
}

struct Inner {
    conn: Mutex<Connection>,
    key: MasterKey,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Store")
    }
}

impl Store {
    /// Opens (or creates) the database at `path`.
    pub fn open(path: &Path, key: MasterKey) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        Self::init(conn, key)
    }

    /// In-memory database (tests).
    pub fn open_in_memory(key: MasterKey) -> Result<Self> {
        Self::init(Connection::open_in_memory()?, key)
    }

    fn init(conn: Connection, key: MasterKey) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        migrate(&conn)?;
        Ok(Self {
            inner: Arc::new(Inner {
                conn: Mutex::new(conn),
                key,
            }),
        })
    }

    /// Master key used to encrypt secrets.
    pub fn master_key(&self) -> &MasterKey {
        &self.inner.key
    }

    /// Runs `f` with the connection on a blocking thread.
    pub async fn call<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Connection, &MasterKey) -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = inner.conn.lock();
            f(&mut conn, &inner.key)
        })
        .await
        .map_err(|e| CoreError::Join(e.to_string()))?
    }

    /// Synchronous variant (for contexts without a tokio runtime).
    pub fn call_blocking<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Connection, &MasterKey) -> Result<R>,
    {
        let mut conn = self.inner.conn.lock();
        f(&mut conn, &self.inner.key)
    }

    /// Reads a value from the `meta` table.
    pub async fn meta_get(&self, key: &str) -> Result<Option<String>> {
        let key = key.to_string();
        self.call(move |c, _| {
            Ok(
                c.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| {
                    r.get::<_, String>(0)
                })
                .optional()?,
            )
        })
        .await
    }

    /// Writes a value to the `meta` table.
    pub async fn meta_set(&self, key: &str, value: &str) -> Result<()> {
        let (key, value) = (key.to_string(), value.to_string());
        self.call(move |c, _| {
            c.execute(
                "INSERT INTO meta(key, value) VALUES(?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [key, value],
            )?;
            Ok(())
        })
        .await
    }
}

/// Converts database text into an `Id`.
pub(crate) fn parse_id(s: &str) -> rusqlite::Result<Id> {
    s.parse::<Id>().map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

pub(crate) fn parse_opt_id(s: Option<String>) -> rusqlite::Result<Option<Id>> {
    s.map(|s| parse_id(&s)).transpose()
}

/// Next sync revision.
pub(crate) fn next_rev(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row(
        "UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'rev' RETURNING CAST(value AS INTEGER)",
        [],
        |r| r.get(0),
    )?)
}

const MIGRATIONS: &[&str] = &[
    // v1: initial schema
    r#"
    CREATE TABLE meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    INSERT INTO meta(key, value) VALUES ('rev', '0');

    CREATE TABLE entities (
        id         TEXT PRIMARY KEY,
        owner_id   TEXT NOT NULL,
        kind       TEXT NOT NULL,
        data       TEXT NOT NULL,
        secret     BLOB,
        sync_mode  TEXT NOT NULL DEFAULT 'synced',
        rev        INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        deleted    INTEGER NOT NULL DEFAULT 0,
        dirty      INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX entities_owner_kind ON entities(owner_id, kind, deleted);
    CREATE INDEX entities_owner_rev ON entities(owner_id, rev);
    CREATE INDEX entities_dirty ON entities(dirty) WHERE dirty = 1;

    CREATE TABLE users (
        id            TEXT PRIMARY KEY,
        email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
        name          TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin      INTEGER NOT NULL DEFAULT 0,
        disabled      INTEGER NOT NULL DEFAULT 0,
        created_at    INTEGER NOT NULL
    );

    CREATE TABLE devices (
        id                 TEXT PRIMARY KEY,
        user_id            TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name               TEXT NOT NULL,
        platform           TEXT NOT NULL,
        access_hash        TEXT NOT NULL UNIQUE,
        access_expires_at  INTEGER NOT NULL,
        refresh_hash       TEXT NOT NULL UNIQUE,
        refresh_expires_at INTEGER NOT NULL,
        created_at         INTEGER NOT NULL,
        last_seen_at       INTEGER NOT NULL
    );
    CREATE INDEX devices_user ON devices(user_id);

    CREATE TABLE sessions (
        id         TEXT PRIMARY KEY,
        owner_id   TEXT NOT NULL,
        host_id    TEXT,
        title      TEXT NOT NULL,
        status     TEXT NOT NULL,
        kind       TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        ended_at   INTEGER,
        error      TEXT,
        recording  INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX sessions_owner ON sessions(owner_id, status);

    CREATE TABLE session_shares (
        id          TEXT PRIMARY KEY,
        session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        created_by  TEXT NOT NULL,
        user_id     TEXT,
        token_hash  TEXT UNIQUE,
        permission  TEXT NOT NULL,
        expires_at  INTEGER,
        revoked     INTEGER NOT NULL DEFAULT 0,
        created_at  INTEGER NOT NULL
    );
    CREATE INDEX session_shares_session ON session_shares(session_id);
    CREATE INDEX session_shares_user ON session_shares(user_id);

    CREATE TABLE ai_tasks (
        id            TEXT PRIMARY KEY,
        owner_id      TEXT NOT NULL,
        title         TEXT NOT NULL,
        prompt        TEXT NOT NULL,
        status        TEXT NOT NULL,
        mode          TEXT NOT NULL,
        provider      TEXT NOT NULL,
        used_provider TEXT,
        context       TEXT NOT NULL DEFAULT '{}',
        messages      TEXT NOT NULL DEFAULT '[]',
        usage         TEXT NOT NULL DEFAULT '{}',
        cost_micros   INTEGER NOT NULL DEFAULT 0,
        result        TEXT,
        error         TEXT,
        created_at    INTEGER NOT NULL,
        updated_at    INTEGER NOT NULL,
        finished_at   INTEGER
    );
    CREATE INDEX ai_tasks_owner ON ai_tasks(owner_id, created_at);

    CREATE TABLE ai_events (
        task_id    TEXT NOT NULL REFERENCES ai_tasks(id) ON DELETE CASCADE,
        seq        INTEGER NOT NULL,
        kind       TEXT NOT NULL,
        data       TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (task_id, seq)
    );

    CREATE TABLE ai_approvals (
        id          TEXT PRIMARY KEY,
        task_id     TEXT NOT NULL REFERENCES ai_tasks(id) ON DELETE CASCADE,
        tool        TEXT NOT NULL,
        input       TEXT NOT NULL,
        summary     TEXT NOT NULL,
        status      TEXT NOT NULL,
        decided_by  TEXT,
        created_at  INTEGER NOT NULL,
        decided_at  INTEGER
    );
    CREATE INDEX ai_approvals_task ON ai_approvals(task_id);

    CREATE TABLE audit_log (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id   TEXT NOT NULL,
        actor      TEXT NOT NULL,
        action     TEXT NOT NULL,
        target     TEXT,
        detail     TEXT NOT NULL DEFAULT '{}',
        created_at INTEGER NOT NULL
    );
    CREATE INDEX audit_owner ON audit_log(owner_id, created_at);
    "#,
    // v2: two-factor authentication, invites, teams and command history (the
    // latter is only used by clients and is not synced).
    r#"
    ALTER TABLE users ADD COLUMN totp_secret BLOB;
    ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0;

    CREATE TABLE recovery_codes (
        user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        code_hash TEXT NOT NULL,
        used_at   INTEGER,
        PRIMARY KEY (user_id, code_hash)
    );

    CREATE TABLE invites (
        id         TEXT PRIMARY KEY,
        token_hash TEXT NOT NULL UNIQUE,
        email      TEXT COLLATE NOCASE,
        is_admin   INTEGER NOT NULL DEFAULT 0,
        team_id    TEXT,
        created_by TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER,
        used_by    TEXT,
        used_at    INTEGER,
        revoked    INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE teams (
        id         TEXT PRIMARY KEY,
        name       TEXT NOT NULL,
        created_by TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );

    CREATE TABLE team_members (
        team_id  TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
        user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role     TEXT NOT NULL,
        added_at INTEGER NOT NULL,
        PRIMARY KEY (team_id, user_id)
    );
    CREATE INDEX team_members_user ON team_members(user_id);

    ALTER TABLE session_shares ADD COLUMN team_id TEXT;
    CREATE INDEX session_shares_team ON session_shares(team_id);

    CREATE TABLE command_history (
        owner_id  TEXT NOT NULL,
        host_id   TEXT NOT NULL,
        command   TEXT NOT NULL,
        uses      INTEGER NOT NULL DEFAULT 1,
        last_used INTEGER NOT NULL,
        PRIMARY KEY (owner_id, host_id, command)
    );
    CREATE INDEX command_history_recent ON command_history(owner_id, last_used);
    "#,
    // v3: web platform (plans, email verification, password reset, invites
    // with a team role) and push notifications.
    r#"
    ALTER TABLE users ADD COLUMN plan TEXT NOT NULL DEFAULT 'free';
    ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0;
    UPDATE users SET email_verified = 1;
    ALTER TABLE teams ADD COLUMN plan TEXT NOT NULL DEFAULT 'free';
    ALTER TABLE invites ADD COLUMN team_role TEXT;

    CREATE TABLE email_tokens (
        token_hash TEXT PRIMARY KEY,
        user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        purpose    TEXT NOT NULL,
        email      TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        used_at    INTEGER
    );
    CREATE INDEX email_tokens_user ON email_tokens(user_id, purpose);

    ALTER TABLE devices ADD COLUMN push_platform TEXT;
    ALTER TABLE devices ADD COLUMN push_token TEXT;
    ALTER TABLE devices ADD COLUMN push_sandbox INTEGER NOT NULL DEFAULT 0;
    "#,
    // v4: preferred language of each user (for emails). Accounts created
    // before this version used the Spanish-only apps, so they keep Spanish.
    r#"
    ALTER TABLE users ADD COLUMN locale TEXT NOT NULL DEFAULT 'en';
    UPDATE users SET locale = 'es';
    "#,
    // v5: the users' own AI API keys (sealed with the master key) and an AI
    // usage ledger that tells the user's own keys from the server's
    // providers (only the latter count against the plan's AI credit). The
    // ledger does not depend on the tasks: deleting a task does not give the
    // credit back.
    r#"
    CREATE TABLE user_ai_keys (
        user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        provider   TEXT NOT NULL,
        secret     BLOB NOT NULL,
        model      TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (user_id, provider)
    );

    CREATE TABLE ai_usage (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id      TEXT NOT NULL,
        task_id       TEXT,
        provider      TEXT NOT NULL,
        own_key       INTEGER NOT NULL DEFAULT 0,
        input_tokens  INTEGER NOT NULL DEFAULT 0,
        output_tokens INTEGER NOT NULL DEFAULT 0,
        -- Real cost (what the server pays; 0 on a subscription).
        cost_micros   INTEGER NOT NULL DEFAULT 0,
        -- What it took from the plan's AI credit (0 with the user's own key).
        credit_micros INTEGER NOT NULL DEFAULT 0,
        created_at    INTEGER NOT NULL
    );
    CREATE INDEX ai_usage_owner ON ai_usage(owner_id, created_at);

    -- Usage before this version ran on the server's providers.
    INSERT INTO ai_usage (owner_id, task_id, provider, own_key, cost_micros, credit_micros,
                          created_at)
        SELECT owner_id, id, COALESCE(used_provider, provider), 0, cost_micros, cost_micros,
               created_at
        FROM ai_tasks WHERE cost_micros > 0;
    "#,
];

fn migrate(conn: &Connection) -> Result<()> {
    let current: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    for (i, sql) in MIGRATIONS.iter().enumerate() {
        let version = i as i64 + 1;
        if version > current {
            conn.execute_batch(&format!(
                "BEGIN; {sql}; PRAGMA user_version = {version}; COMMIT;"
            ))?;
            tracing::info!(version, "database migration applied");
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn test_store() -> Store {
    Store::open_in_memory(MasterKey::generate()).unwrap()
}

#[cfg(test)]
mod migration_tests {
    use super::*;

    #[test]
    fn v5_moves_past_ai_cost_to_the_ledger_as_server_usage() {
        let conn = Connection::open_in_memory().unwrap();
        for (i, sql) in MIGRATIONS[..4].iter().enumerate() {
            conn.execute_batch(&format!(
                "BEGIN; {sql}; PRAGMA user_version = {}; COMMIT;",
                i + 1
            ))
            .unwrap();
        }
        conn.execute(
            "INSERT INTO ai_tasks (id, owner_id, title, prompt, status, mode, provider,
                                   used_provider, cost_micros, created_at, updated_at)
             VALUES ('t1', 'o1', 't', 'p', 'completed', 'ask', 'codex', 'claude::x', 1234, 5, 5)",
            [],
        )
        .unwrap();
        migrate(&conn).unwrap();
        let row: (i64, i64, i64, String, i64) = conn
            .query_row(
                "SELECT own_key, cost_micros, credit_micros, provider, created_at
                 FROM ai_usage WHERE owner_id = 'o1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(row, (0, 1234, 1234, "claude::x".to_string(), 5));
    }
}

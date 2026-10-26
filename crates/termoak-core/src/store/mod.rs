//! SQLite storage.
//!
//! A single connection behind a mutex, used from a blocking thread
//! (`spawn_blocking`). SQLite serializes writes anyway and each operation
//! takes microseconds, so this is simple and fast.

mod ai;
pub mod ai_keys;
pub mod audit;
pub mod e2ee;
pub mod email_tokens;
mod entities;
pub mod history;
pub mod invites;
mod local;
pub mod security;
pub mod sessions;
pub mod sso;
pub mod teams;
pub mod users;
pub mod vaults;

use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension};

pub use ai::{AiApprovalRow, AiEventRow, AiTaskRow, AiUsageRow};
pub use entities::{
    ApplyReport, SyncRejection, SyncWarning, VaultChange, VaultChanges, keep_omitted_fields,
    references,
};
pub use local::{DirtySummary, LocalItem, LocalVault, SealedRow, SyncV2Applied, SyncV2Apply};
pub use vaults::{
    NewVault, SecretUse, VaultAccess, VaultGrantee, VaultPatch, VaultTransfer, VaultTransferResult,
};

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
    keys: vaults::Keyring,
    access: vaults::AccessCache,
    /// Called after a commit that changed entities of these vaults.
    on_change: parking_lot::RwLock<Option<ChangeListener>>,
    /// Server hook run after every [`Store::resolve_in`] (0.7 phase 4b).
    resolve_hook: parking_lot::RwLock<Option<Arc<dyn ResolveHook>>>,
}

/// Server hook run by [`Store::resolve_in`] after a host and its jumps are
/// resolved (docs-next/TEAMS-SECURITY.md §4.8, §5.4): access policies
/// (approval windows), team certificates. An error refuses the resolution.
pub trait ResolveHook: Send + Sync {
    fn after_resolve<'a>(
        &'a self,
        access: &'a VaultAccess,
        vault: Id,
        purpose: SecretUse,
        resolved: &'a mut crate::resolve::ResolvedHost,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
}

/// Listener of entity changes per vault (the server sends `vault/changed`
/// events with it).
pub type ChangeListener = Arc<dyn Fn(&[Id]) + Send + Sync>;

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
                keys: vaults::Keyring::new(key),
                access: Default::default(),
                on_change: Default::default(),
                resolve_hook: Default::default(),
            }),
        })
    }

    /// Master key used to encrypt secrets.
    pub fn master_key(&self) -> &MasterKey {
        &self.inner.keys.master
    }

    /// Sets the function called after entities of some vaults change.
    pub fn set_change_listener(&self, listener: Option<ChangeListener>) {
        *self.inner.on_change.write() = listener;
    }

    /// Sets the hook run after every [`Store::resolve_in`].
    pub fn set_resolve_hook(&self, hook: Option<Arc<dyn ResolveHook>>) {
        *self.inner.resolve_hook.write() = hook;
    }

    pub(crate) fn resolve_hook(&self) -> Option<Arc<dyn ResolveHook>> {
        self.inner.resolve_hook.read().clone()
    }

    /// Tells the listener (if any) that these vaults changed.
    pub(crate) fn changed(&self, vaults: &[Id]) {
        if vaults.is_empty() {
            return;
        }
        let listener = self.inner.on_change.read().clone();
        if let Some(l) = listener {
            l(vaults);
        }
    }

    /// Runs `f` with the connection and the keyring on a blocking thread.
    pub(crate) async fn call_keys<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Connection, &vaults::Keyring) -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = inner.conn.lock();
            f(&mut conn, &inner.keys)
        })
        .await
        .map_err(|e| CoreError::Join(e.to_string()))?
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
            f(&mut conn, &inner.keys.master)
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
        f(&mut conn, &self.inner.keys.master)
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
    // v6: six-digit email verification codes live in `email_tokens` too
    // (purpose `verify_code`); `attempts` counts the wrong guesses of each
    // one, so it can be invalidated after a few.
    r#"
    ALTER TABLE email_tokens ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
    "#,
    // v7: live session sharing (one driver at a time). `require_approval`:
    // whoever joins waits until the owner lets them in; `auto_grant`:
    // requests for the keyboard are granted without asking. Shares created
    // before keep the old behaviour (no waiting room).
    r#"
    ALTER TABLE session_shares ADD COLUMN require_approval INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE session_shares ADD COLUMN auto_grant INTEGER NOT NULL DEFAULT 0;
    "#,
    // v8: timed keyboard. `control_minutes`: an automatic grant (`auto_grant`)
    // lasts at most this many minutes (NULL: no limit, as before).
    r#"
    ALTER TABLE session_shares ADD COLUMN control_minutes INTEGER;
    "#,
    // v9: vaults. Every user gets a personal vault (id = user id) and their
    // entities go there; access is decided by `entities.vault_id` from now
    // on (`owner_id` keeps "created by"). No foreign keys to `users` or
    // `teams`: client stores have neither, the store code does the
    // cascades. The vault keys are created lazily (no crypto here).
    r#"
    CREATE TABLE vaults (
        id               TEXT PRIMARY KEY,
        kind             TEXT NOT NULL,
        name             TEXT NOT NULL,
        description      TEXT NOT NULL DEFAULT '',
        color            TEXT,
        icon             TEXT,
        owner_user_id    TEXT,
        owner_team_id    TEXT,
        team_member_role TEXT,
        crypto_mode      TEXT NOT NULL DEFAULT 'server',
        key_version      INTEGER NOT NULL DEFAULT 0,
        settings         TEXT NOT NULL DEFAULT '{}',
        rev              INTEGER NOT NULL DEFAULT 0,
        created_by       TEXT NOT NULL,
        created_at       INTEGER NOT NULL,
        updated_at       INTEGER NOT NULL,
        CHECK ((owner_user_id IS NULL) <> (owner_team_id IS NULL))
    );
    CREATE INDEX vaults_owner_user ON vaults(owner_user_id);
    CREATE INDEX vaults_owner_team ON vaults(owner_team_id);

    CREATE TABLE vault_members (
        id        TEXT PRIMARY KEY,
        vault_id  TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
        user_id   TEXT,
        team_id   TEXT,
        role      TEXT NOT NULL,
        added_by  TEXT NOT NULL,
        added_at  INTEGER NOT NULL,
        CHECK ((user_id IS NULL) <> (team_id IS NULL)),
        UNIQUE (vault_id, user_id),
        UNIQUE (vault_id, team_id)
    );
    CREATE INDEX vault_members_user ON vault_members(user_id);
    CREATE INDEX vault_members_team ON vault_members(team_id);

    CREATE TABLE vault_keys (
        vault_id   TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
        version    INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        retired_at INTEGER,
        PRIMARY KEY (vault_id, version)
    );
    CREATE TABLE vault_key_wraps (
        vault_id         TEXT NOT NULL,
        version          INTEGER NOT NULL,
        recipient        TEXT NOT NULL,
        alg              TEXT NOT NULL,
        recipient_key_id TEXT,
        wrapped          BLOB NOT NULL,
        created_at       INTEGER NOT NULL,
        PRIMARY KEY (vault_id, version, recipient),
        FOREIGN KEY (vault_id, version) REFERENCES vault_keys(vault_id, version) ON DELETE CASCADE
    );
    -- Reserved for end-to-end encrypted vaults (stays empty for now).
    CREATE TABLE user_keys (
        id             TEXT PRIMARY KEY,
        user_id        TEXT NOT NULL,
        alg            TEXT NOT NULL,
        public_key     BLOB NOT NULL,
        sealed_private BLOB,
        created_at     INTEGER NOT NULL,
        revoked_at     INTEGER
    );

    ALTER TABLE entities ADD COLUMN vault_id TEXT;
    ALTER TABLE entities ADD COLUMN key_version INTEGER;
    ALTER TABLE entities ADD COLUMN updated_by TEXT;
    ALTER TABLE entities ADD COLUMN secret_hidden INTEGER NOT NULL DEFAULT 0;
    CREATE INDEX entities_vault_rev ON entities(vault_id, rev);
    CREATE INDEX entities_vault_kind ON entities(vault_id, kind, deleted);

    -- "This entity left this vault" (moved, or the vault lost it).
    CREATE TABLE entity_departures (
        vault_id  TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        kind      TEXT NOT NULL,
        rev       INTEGER NOT NULL,
        at        INTEGER NOT NULL,
        PRIMARY KEY (vault_id, entity_id)
    );
    CREATE INDEX entity_departures_rev ON entity_departures(vault_id, rev);

    ALTER TABLE sessions ADD COLUMN vault_id TEXT;
    ALTER TABLE audit_log ADD COLUMN vault_id TEXT;
    CREATE INDEX audit_vault ON audit_log(vault_id, created_at);

    -- Clients only: per-vault sync state of an account store.
    CREATE TABLE vault_sync (
        vault_id  TEXT PRIMARY KEY,
        role      TEXT NOT NULL,
        cursor    INTEGER NOT NULL DEFAULT 0,
        synced_at INTEGER
    );
    -- Clients only (device store): signed-in accounts.
    CREATE TABLE accounts (
        id           TEXT PRIMARY KEY,
        server_url   TEXT NOT NULL,
        instance_id  TEXT,
        official     INTEGER NOT NULL DEFAULT 0,
        user_id      TEXT,
        email        TEXT NOT NULL,
        name         TEXT NOT NULL DEFAULT '',
        status       TEXT NOT NULL,
        tokens       BLOB,
        features     TEXT NOT NULL DEFAULT '{}',
        color        TEXT,
        position     INTEGER NOT NULL DEFAULT 0,
        added_at     INTEGER NOT NULL,
        last_used_at INTEGER
    );

    -- Server data: one personal vault per user; existing entities go there.
    INSERT INTO vaults (id, kind, name, owner_user_id, created_by, created_at, updated_at)
        SELECT id, 'personal', 'Personal', id, id, created_at, created_at FROM users;
    UPDATE entities SET vault_id = owner_id
        WHERE vault_id IS NULL AND owner_id IN (SELECT id FROM users);
    "#,
    // v10: sessions and devices. The last IP a device was used from and a
    // short description of its client (`Firefox 131 on Linux`,
    // `Termoak 0.4.0`...). NULL on devices signed in before this version
    // until they are used again.
    r#"
    ALTER TABLE devices ADD COLUMN last_ip TEXT;
    ALTER TABLE devices ADD COLUMN user_agent TEXT;
    "#,
    // v11: AI approvals keep what they show (the command with its risk and
    // reasons, the diff of a file, a plan) as JSON. NULL for older ones.
    r#"
    ALTER TABLE ai_approvals ADD COLUMN preview TEXT;
    "#,
    // v12: push without Firebase (0.7). A device registers a Web Push
    // endpoint (UnifiedPush distributors, browsers): `push_platform =
    // 'webpush'`, the endpoint URL in `push_token` and its keys (`p256dh`,
    // `auth`, base64url). `push_prefs`: which notifications it wants (JSON,
    // NULL = all), kept when the registration goes away.
    r#"
    ALTER TABLE devices ADD COLUMN push_p256dh TEXT;
    ALTER TABLE devices ADD COLUMN push_auth TEXT;
    ALTER TABLE devices ADD COLUMN push_prefs TEXT;
    "#,
    // v13: teams security (0.7 phase 4b, docs-next/TEAMS-SECURITY.md §8).
    // SSH certificate authorities held by the server (the private key
    // sealed with the master key), the certificates they issued (serials
    // for audit and the KRL), revoked public keys, access policies per
    // host/group/vault, temporary access requests, team policies, member
    // principals and, on clients, the effective vault policy from the
    // server. Nothing existing is rewritten.
    r#"
    CREATE TABLE ssh_cas (
        id            TEXT PRIMARY KEY,
        owner_team_id TEXT,
        owner_user_id TEXT,
        kind          TEXT NOT NULL DEFAULT 'user',
        algorithm     TEXT NOT NULL,
        public_key    TEXT NOT NULL,
        fingerprint   TEXT NOT NULL,
        private_key   BLOB NOT NULL,
        status        TEXT NOT NULL,
        created_by    TEXT NOT NULL,
        created_at    INTEGER NOT NULL,
        retire_at     INTEGER,
        retired_at    INTEGER,
        CHECK ((owner_team_id IS NULL) <> (owner_user_id IS NULL))
    );
    CREATE INDEX ssh_cas_team ON ssh_cas(owner_team_id, status);
    CREATE INDEX ssh_cas_user ON ssh_cas(owner_user_id, status);

    CREATE TABLE ssh_certs (
        serial          INTEGER PRIMARY KEY AUTOINCREMENT,
        ca_id           TEXT NOT NULL,
        user_id         TEXT NOT NULL,
        vault_id        TEXT,
        host_id         TEXT,
        request_id      TEXT,
        device_id       TEXT,
        purpose         TEXT NOT NULL,
        key_fingerprint TEXT NOT NULL,
        key_id          TEXT NOT NULL,
        principals      TEXT NOT NULL,
        valid_after     INTEGER NOT NULL,
        valid_before    INTEGER NOT NULL,
        created_at      INTEGER NOT NULL,
        revoked_at      INTEGER,
        revoked_by      TEXT,
        revoke_reason   TEXT
    );
    CREATE INDEX ssh_certs_ca ON ssh_certs(ca_id, valid_before);
    CREATE INDEX ssh_certs_user ON ssh_certs(user_id, created_at);
    CREATE INDEX ssh_certs_request ON ssh_certs(request_id);

    CREATE TABLE ssh_revoked_keys (
        owner_id    TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        public_key  TEXT NOT NULL,
        revoked_by  TEXT NOT NULL,
        revoked_at  INTEGER NOT NULL,
        reason      TEXT,
        PRIMARY KEY (owner_id, fingerprint)
    );

    CREATE TABLE access_policies (
        id          TEXT PRIMARY KEY,
        vault_id    TEXT NOT NULL,
        target_kind TEXT NOT NULL,
        target_id   TEXT NOT NULL,
        policy      TEXT NOT NULL,
        updated_by  TEXT NOT NULL,
        updated_at  INTEGER NOT NULL,
        UNIQUE (vault_id, target_kind, target_id)
    );
    CREATE INDEX access_policies_vault ON access_policies(vault_id);

    CREATE TABLE access_requests (
        id              TEXT PRIMARY KEY,
        vault_id        TEXT NOT NULL,
        target_kind     TEXT NOT NULL,
        target_id       TEXT NOT NULL,
        target_label    TEXT NOT NULL,
        requester_id    TEXT NOT NULL,
        reason          TEXT NOT NULL,
        minutes         INTEGER NOT NULL,
        status          TEXT NOT NULL,
        created_at      INTEGER NOT NULL,
        expires_at      INTEGER NOT NULL,
        decided_by      TEXT,
        decided_at      INTEGER,
        decision_reason TEXT,
        starts_at       INTEGER,
        ends_at         INTEGER,
        closed_at       INTEGER,
        self_approved   INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX access_requests_vault ON access_requests(vault_id, status);
    CREATE INDEX access_requests_requester ON access_requests(requester_id, status);

    ALTER TABLE teams ADD COLUMN policy TEXT NOT NULL DEFAULT '{}';
    ALTER TABLE team_members ADD COLUMN principal TEXT;
    ALTER TABLE vaults ADD COLUMN policy TEXT;
    "#,
    // v14 (0.7 phase 5a, docs/E2EE-SSO-AUDIT.md): end-to-end encrypted
    // vaults, SSO/OIDC for teams, extended audit. Nothing existing changes
    // meaning: every vault stays server-managed until a manager converts
    // it, and no account needs SSO until a team enforces it.
    r#"
    -- E2EE: the secret of this row is a client's sealed blob (the server
    -- never opens it; a client keeps it like this while locked).
    ALTER TABLE entities ADD COLUMN e2ee INTEGER NOT NULL DEFAULT 0;
    CREATE INDEX user_keys_user ON user_keys(user_id, revoked_at);
    -- Copies of a user's private key sealed with their E2EE passphrase or
    -- recovery key (opaque to the server).
    CREATE TABLE user_key_seals (
        key_id     TEXT NOT NULL REFERENCES user_keys(id) ON DELETE CASCADE,
        kind       TEXT NOT NULL,              -- passphrase | recovery
        params     TEXT,                       -- Argon2id parameters (JSON)
        sealed     TEXT NOT NULL,              -- base64
        created_at INTEGER NOT NULL,
        PRIMARY KEY (key_id, kind)
    );
    -- A new device asking an unlocked one for the user key.
    CREATE TABLE e2ee_pairings (
        id          TEXT PRIMARY KEY,
        user_id     TEXT NOT NULL,
        device_id   TEXT NOT NULL,
        device_name TEXT NOT NULL,
        public_key  TEXT NOT NULL,
        status      TEXT NOT NULL,             -- pending | approved | denied
        sealed      TEXT,
        approved_by TEXT,                      -- device id
        created_at  INTEGER NOT NULL,
        expires_at  INTEGER NOT NULL
    );
    CREATE INDEX e2ee_pairings_user ON e2ee_pairings(user_id, status);

    -- SSO / OIDC per team.
    CREATE TABLE team_sso (
        team_id       TEXT PRIMARY KEY,
        config        TEXT NOT NULL,           -- SsoConfig (JSON, no secret)
        client_secret BLOB,                    -- sealed with the master key
        updated_by    TEXT NOT NULL,
        updated_at    INTEGER NOT NULL
    );
    CREATE TABLE team_domains (
        domain      TEXT PRIMARY KEY COLLATE NOCASE,
        team_id     TEXT NOT NULL,
        token       TEXT NOT NULL,             -- DNS TXT termoak-verify=<token>
        verified_at INTEGER,
        verified_by TEXT,                      -- dns | admin:<user id>
        created_by  TEXT NOT NULL,
        created_at  INTEGER NOT NULL,
        checked_at  INTEGER,
        last_error  TEXT
    );
    CREATE INDEX team_domains_team ON team_domains(team_id);
    CREATE TABLE sso_identities (
        issuer        TEXT NOT NULL,
        subject       TEXT NOT NULL,
        user_id       TEXT NOT NULL,
        team_id       TEXT NOT NULL,
        email         TEXT NOT NULL,
        created_at    INTEGER NOT NULL,
        last_login_at INTEGER,
        PRIMARY KEY (issuer, subject)
    );
    CREATE INDEX sso_identities_user ON sso_identities(user_id);
    CREATE TABLE sso_flows (
        id               TEXT PRIMARY KEY,
        state            TEXT NOT NULL UNIQUE,
        team_id          TEXT NOT NULL,
        link_user        TEXT,                 -- linking from a signed-in account
        nonce            TEXT NOT NULL,
        verifier         TEXT NOT NULL,        -- PKCE verifier towards the IdP
        redirect_uri     TEXT NOT NULL,        -- the app's callback
        client_state     TEXT,
        client_challenge TEXT NOT NULL,        -- PKCE of the app towards this server
        device_name      TEXT NOT NULL,
        platform         TEXT NOT NULL,
        status           TEXT NOT NULL,        -- started | done | failed | used
        code_hash        TEXT,
        user_id          TEXT,
        error            TEXT,
        attempts         INTEGER NOT NULL DEFAULT 0,
        created_at       INTEGER NOT NULL,
        expires_at       INTEGER NOT NULL
    );
    CREATE INDEX sso_flows_code ON sso_flows(code_hash);
    ALTER TABLE users ADD COLUMN sso_only INTEGER NOT NULL DEFAULT 0;

    -- Extended audit.
    ALTER TABLE audit_log ADD COLUMN team_id TEXT;
    CREATE INDEX audit_team ON audit_log(team_id, id);
    CREATE INDEX audit_action ON audit_log(action, id);
    CREATE INDEX audit_created ON audit_log(created_at);
    UPDATE audit_log SET team_id = (SELECT owner_team_id FROM vaults WHERE vaults.id = audit_log.vault_id)
        WHERE vault_id IS NOT NULL;
    UPDATE audit_log SET team_id = target
        WHERE team_id IS NULL AND target IN (SELECT id FROM teams);
    ALTER TABLE teams ADD COLUMN audit_retention_days INTEGER;
    CREATE TABLE audit_sinks (
        id              TEXT PRIMARY KEY,
        team_id         TEXT,                  -- NULL: the whole server (admins)
        kind            TEXT NOT NULL,         -- webhook | syslog
        name            TEXT NOT NULL,
        config          TEXT NOT NULL,         -- JSON (no secret)
        secret          BLOB,                  -- webhook signing secret, sealed
        actions         TEXT NOT NULL DEFAULT '[]',
        enabled         INTEGER NOT NULL DEFAULT 1,
        cursor          INTEGER NOT NULL,      -- last audit_log.id delivered
        failures        INTEGER NOT NULL DEFAULT 0,
        last_error      TEXT,
        last_attempt_at INTEGER,
        last_success_at INTEGER,
        created_by      TEXT NOT NULL,
        created_at      INTEGER NOT NULL,
        updated_at      INTEGER NOT NULL
    );
    CREATE INDEX audit_sinks_team ON audit_sinks(team_id);
    "#,
];

/// Schema version of the latest migration.
pub fn schema_version() -> usize {
    MIGRATIONS.len()
}

/// Creates (or upgrades) the database at `path` only up to schema
/// `version`, without opening a store: for upgrade tests and dry runs of a
/// migration on a copy.
pub fn create_at_version(path: &Path, version: usize) -> Result<()> {
    let conn = Connection::open(path)?;
    let current: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    for (i, sql) in MIGRATIONS.iter().enumerate().take(version) {
        let v = i as i64 + 1;
        if v > current {
            conn.execute_batch(&format!("BEGIN; {sql}; PRAGMA user_version = {v}; COMMIT;"))?;
        }
    }
    Ok(())
}

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
mod vault_tests;

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

    #[test]
    fn v13_keeps_teams_and_vaults_as_they_were() {
        let conn = Connection::open_in_memory().unwrap();
        for (i, sql) in MIGRATIONS[..12].iter().enumerate() {
            conn.execute_batch(&format!(
                "BEGIN; {sql}; PRAGMA user_version = {}; COMMIT;",
                i + 1
            ))
            .unwrap();
        }
        conn.execute_batch(
            "INSERT INTO teams (id, name, created_by, created_at) VALUES ('t1', 'Ops', 'u1', 1);
             INSERT INTO users (id, email, name, password_hash, created_at) VALUES ('u1', 'a@b', 'A', 'x', 1);
             INSERT INTO team_members (team_id, user_id, role, added_at) VALUES ('t1', 'u1', 'owner', 1);
             INSERT INTO vaults (id, kind, name, owner_team_id, team_member_role, created_by, created_at, updated_at)
                 VALUES ('v1', 'team', 'Prod', 't1', 'use_only', 'u1', 1, 1);",
        )
        .unwrap();
        migrate(&conn).unwrap();
        let (policy, principal, vpolicy, role): (String, Option<String>, Option<String>, String) = conn
            .query_row(
                "SELECT t.policy, tm.principal, v.policy, v.team_member_role
                 FROM teams t JOIN team_members tm ON tm.team_id = t.id JOIN vaults v ON v.owner_team_id = t.id",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            (policy.as_str(), principal, vpolicy, role.as_str()),
            ("{}", None, None, "use_only")
        );
        let p: crate::access::TeamPolicy = serde_json::from_str(&policy).unwrap();
        assert_eq!(p, crate::access::TeamPolicy::default());
        let v: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(v, MIGRATIONS.len() as i64);
    }

    #[test]
    fn v14_backfills_audit_teams_and_keeps_vaults_server_managed() {
        let conn = Connection::open_in_memory().unwrap();
        for (i, sql) in MIGRATIONS[..13].iter().enumerate() {
            conn.execute_batch(&format!(
                "BEGIN; {sql}; PRAGMA user_version = {}; COMMIT;",
                i + 1
            ))
            .unwrap();
        }
        conn.execute_batch(
            "INSERT INTO teams (id, name, created_by, created_at) VALUES ('t1', 'Ops', 'u1', 1);
             INSERT INTO users (id, email, name, password_hash, created_at) VALUES ('u1', 'a@b', 'A', 'x', 1);
             INSERT INTO vaults (id, kind, name, owner_team_id, created_by, created_at, updated_at)
                 VALUES ('v1', 'team', 'Prod', 't1', 'u1', 1, 1);
             INSERT INTO entities (id, owner_id, kind, data, secret, rev, updated_at, vault_id, key_version)
                 VALUES ('e1', 'u1', 'host', '{}', x'01', 1, 1, 'v1', 1);
             INSERT INTO audit_log (owner_id, actor, action, target, created_at, vault_id)
                 VALUES ('u1', 'user:u1', 'secret.reveal', 'e1', 1, 'v1');
             INSERT INTO audit_log (owner_id, actor, action, target, created_at)
                 VALUES ('u1', 'user:u1', 'team.policy', 't1', 2);
             INSERT INTO audit_log (owner_id, actor, action, target, created_at)
                 VALUES ('u1', 'user:u1', 'auth.login', 'd1', 3);",
        )
        .unwrap();
        migrate(&conn).unwrap();
        let teams: Vec<Option<String>> = conn
            .prepare("SELECT team_id FROM audit_log ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(teams, vec![Some("t1".into()), Some("t1".into()), None]);
        let (mode, e2ee): (String, i64) = conn
            .query_row(
                "SELECT v.crypto_mode, e.e2ee FROM vaults v JOIN entities e ON e.vault_id = v.id",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((mode.as_str(), e2ee), ("server", 0));
        let sso_only: i64 = conn
            .query_row("SELECT sso_only FROM users", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sso_only, 0);
    }
}

//! Migration of the local data from one store with one server (layout 1,
//! Termoak 0.3) to the device store plus one store per account (layout 2).
//!
//! Runs once when the workspace opens and `meta.layout.version` is missing.
//! It is idempotent and resumable:
//!
//! 1. `termoak.db` is copied to `termoak.db.pre-accounts` (`VACUUM INTO`,
//!    consistent; kept 30 days).
//! 2. Without a server ever configured nothing moves: every item becomes a
//!    "This device" item.
//! 3. With a server (signed in or not): an `accounts` row is created
//!    (canonical URL, the email, `active` with tokens or `needs_sign_in`),
//!    the tokens are resealed for the account, `accounts/<id>.db` is
//!    created and every `synced` row is copied there (with `dirty`,
//!    secrets, `rev` and `updated_at`), together with the sync revision.
//!    The copy is checked row by row before the rows leave the device
//!    store; `device_only` rows stay.
//! 4. `layout.version = 2` and `accounts.view = <id>` are set and the old
//!    `server.*` keys removed, in the same commit.
//!
//! The account id is saved before anything is created
//! (`layout.migrating`), so an interrupted migration resumes with the same
//! account and file.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use termoak_core::crypto::MasterKey;
use termoak_core::time::now_ms;
use termoak_core::{Id, Store};

use crate::accounts::{self, AccountInfo, AccountStatus};
use crate::error::{ClientError, Result};
use crate::servers;

/// Meta key: layout of the data directory (`2`).
pub const LAYOUT_VERSION_KEY: &str = "layout.version";
/// Meta key: the account being created by an interrupted migration.
const MIGRATING_KEY: &str = "layout.migrating";
/// Meta key: when the backup was made (ms).
const BACKUP_AT_KEY: &str = "layout.backup_at";
/// Meta key: the account (`<id>`) or `all` shown.
pub const VIEW_KEY: &str = "accounts.view";
/// Backup made before the migration.
pub const BACKUP_FILE: &str = "termoak.db.pre-accounts";
/// The backup is deleted after this long.
const BACKUP_KEEP_MS: i64 = 30 * 24 * 3600 * 1000;

const SERVER_URL: &str = "server.url";
const SERVER_TOKENS: &str = "server.tokens";
const SERVER_USER: &str = "server.user";
const SYNC_REV: &str = "sync.rev";

/// What the migration did (for logs and tests).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LayoutReport {
    /// It ran now (`false`: the data was already in layout 2).
    pub migrated: bool,
    /// Account created from the old server settings.
    pub account: Option<Id>,
    /// Rows moved to the account store.
    pub moved: usize,
    /// Rows left in the device store.
    pub kept: usize,
}

fn meta_get(c: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
    c.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
        .optional()
}

fn meta_set(c: &Connection, key: &str, value: &str) -> rusqlite::Result<()> {
    c.execute(
        "INSERT INTO meta(key, value) VALUES(?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

/// Columns of `entities` (the schema is shared by every store).
fn entity_columns(c: &Connection) -> rusqlite::Result<String> {
    let mut stmt = c.prepare("SELECT name FROM pragma_table_info('entities')")?;
    let cols = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(cols.join(", "))
}

/// Deletes the backup once it is old enough.
fn cleanup_backup(dir: &Path, c: &Connection) {
    let at = meta_get(c, BACKUP_AT_KEY)
        .ok()
        .flatten()
        .and_then(|v| v.parse::<i64>().ok());
    if let Some(at) = at
        && now_ms() - at > BACKUP_KEEP_MS
    {
        let path = dir.join(BACKUP_FILE);
        if path.exists() {
            match std::fs::remove_file(&path) {
                Ok(()) => tracing::info!("old pre-accounts backup deleted"),
                Err(e) => tracing::warn!(error = %e, "could not delete the pre-accounts backup"),
            }
        }
    }
}

/// Migrates `device` (the store at `dir/termoak.db`) to layout 2 if needed.
pub fn migrate(dir: &Path, device: &Store) -> Result<LayoutReport> {
    let done = device.call_blocking(|c, _| {
        let v = meta_get(c, LAYOUT_VERSION_KEY)?;
        if v.is_some() {
            cleanup_backup(dir, c);
        }
        Ok(v.is_some())
    })?;
    if done {
        return Ok(LayoutReport::default());
    }

    // 1. Backup.
    let backup = dir.join(BACKUP_FILE);
    if !backup.exists() {
        let tmp = dir.join(format!("{BACKUP_FILE}.tmp"));
        let _ = std::fs::remove_file(&tmp);
        device.call_blocking(|c, _| {
            c.execute("VACUUM INTO ?1", [tmp.to_string_lossy().as_ref()])?;
            meta_set(c, BACKUP_AT_KEY, &now_ms().to_string())?;
            Ok(())
        })?;
        std::fs::rename(&tmp, &backup)?;
    }

    // 2. Never signed in: nothing moves.
    let (url, migrating) =
        device.call_blocking(|c, _| Ok((meta_get(c, SERVER_URL)?, meta_get(c, MIGRATING_KEY)?)))?;
    let Some(url) = url.filter(|u| !u.trim().is_empty()) else {
        let kept = device.call_blocking(|c, _| {
            let kept: i64 = c.query_row("SELECT COUNT(*) FROM entities", [], |r| r.get(0))?;
            let tx = c.transaction()?;
            meta_set(&tx, LAYOUT_VERSION_KEY, "2")?;
            tx.execute(
                "DELETE FROM meta WHERE key IN (?1, ?2, ?3, ?4)",
                params![SERVER_TOKENS, SERVER_USER, SYNC_REV, MIGRATING_KEY],
            )?;
            tx.commit()?;
            Ok(kept as usize)
        })?;
        tracing::info!(
            kept,
            "data layout 2: no server configured, every item stays on this device"
        );
        return Ok(LayoutReport {
            migrated: true,
            account: None,
            moved: 0,
            kept,
        });
    };

    // 3. An account for the configured server.
    let id: Id = migrating
        .and_then(|m| m.parse().ok())
        .unwrap_or_else(termoak_core::new_id);
    device.call_blocking(move |c, _| {
        meta_set(c, MIGRATING_KEY, &id.to_string())?;
        Ok(())
    })?;
    let key: MasterKey = device.master_key().clone();
    let (sealed, email) = device
        .call_blocking(|c, _| Ok((meta_get(c, SERVER_TOKENS)?, meta_get(c, SERVER_USER)?)))?;
    let tokens = sealed
        .as_deref()
        .and_then(|s| accounts::open_legacy_tokens(&key, s));
    if sealed.as_deref().is_some_and(|s| !s.trim().is_empty()) && tokens.is_none() {
        tracing::warn!(
            "the saved server session could not be read; the account will ask to sign in again"
        );
    }
    let server_url =
        servers::canonical(&url).unwrap_or_else(|_| url.trim().trim_end_matches('/').to_string());
    let exists = device.call_blocking(move |c, _| {
        Ok(c.query_row(
            "SELECT 1 FROM accounts WHERE id = ?1",
            [id.to_string()],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        .is_some())
    })?;
    if !exists {
        let info = AccountInfo {
            id,
            official: servers::is_official(&server_url),
            server_url,
            instance_id: None,
            user_id: None,
            email: email.unwrap_or_default(),
            name: String::new(),
            status: if tokens.is_some() {
                AccountStatus::Active
            } else {
                AccountStatus::NeedsSignIn
            },
            features: serde_json::json!({}),
            color: None,
            position: 0,
            added_at: now_ms(),
            last_used_at: None,
            last_sync_at: None,
        };
        accounts::save_registry(device, &info, tokens.as_ref())?;
    }
    drop(accounts::open_account_store(dir, device, id)?);

    // Copy the synced rows, check them, then remove them from the device store.
    let path = accounts::account_db_path(dir, id);
    let (moved, kept) = device.call_blocking(move |c, _| {
        let cols = entity_columns(c)?;
        c.execute(
            "ATTACH DATABASE ?1 AS acct",
            [path.to_string_lossy().as_ref()],
        )?;
        let result = (|| -> termoak_core::error::Result<(usize, usize)> {
            let tx = c.transaction()?;
            tx.execute(
                &format!(
                    "INSERT OR REPLACE INTO acct.entities ({cols})
                     SELECT {cols} FROM main.entities WHERE sync_mode = 'synced'"
                ),
                [],
            )?;
            if let Some(rev) = meta_get(&tx, SYNC_REV)? {
                tx.execute(
                    "INSERT INTO acct.meta(key, value) VALUES(?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    params![SYNC_REV, rev],
                )?;
            }
            // The account store's revision counter goes past every copied row.
            tx.execute(
                "UPDATE acct.meta SET value = CAST(MAX(CAST(value AS INTEGER),
                        (SELECT CAST(value AS INTEGER) FROM main.meta WHERE key = 'rev')) AS TEXT)
                 WHERE key = 'rev'",
                [],
            )?;
            tx.commit()?;
            let source: i64 = c.query_row(
                "SELECT COUNT(*) FROM main.entities WHERE sync_mode = 'synced'",
                [],
                |r| r.get(0),
            )?;
            let copied: i64 = c.query_row(
                "SELECT COUNT(*) FROM main.entities m JOIN acct.entities a ON a.id = m.id
                 WHERE m.sync_mode = 'synced' AND a.updated_at = m.updated_at
                   AND a.dirty = m.dirty AND a.deleted = m.deleted AND a.kind = m.kind
                   AND a.data = m.data AND a.secret IS m.secret",
                [],
                |r| r.get(0),
            )?;
            if copied != source {
                return Err(termoak_core::CoreError::Invalid(format!(
                    "data layout migration: {copied} of {source} items copied; nothing was removed"
                )));
            }
            let kept: i64 = c.query_row(
                "SELECT COUNT(*) FROM main.entities WHERE sync_mode != 'synced'",
                [],
                |r| r.get(0),
            )?;
            let tx = c.transaction()?;
            tx.execute("DELETE FROM main.entities WHERE sync_mode = 'synced'", [])?;
            meta_set(&tx, LAYOUT_VERSION_KEY, "2")?;
            meta_set(&tx, crate::layout::VIEW_KEY, &id.to_string())?;
            tx.execute(
                "DELETE FROM main.meta WHERE key IN (?1, ?2, ?3, ?4, ?5)",
                params![
                    SERVER_URL,
                    SERVER_TOKENS,
                    SERVER_USER,
                    SYNC_REV,
                    MIGRATING_KEY
                ],
            )?;
            tx.commit()?;
            Ok((source as usize, kept as usize))
        })();
        let _ = c.execute("DETACH DATABASE acct", []);
        result
    })?;
    tracing::info!(moved, kept, account = %id, "data layout 2: synced items moved to the account store");
    Ok(LayoutReport {
        migrated: true,
        account: Some(id),
        moved,
        kept,
    })
}

/// Fails if the data directory is in layout 1 and could not be migrated.
pub fn version(device: &Store) -> Result<Option<String>> {
    device
        .call_blocking(|c, _| Ok(meta_get(c, LAYOUT_VERSION_KEY)?))
        .map_err(ClientError::from)
}

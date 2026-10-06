//! Generic store of syncable entities.
//!
//! Two families of functions:
//! - **Owner-based** (`list`, `get`, `secret`, `save`, `delete`,
//!   `changes_since`, `apply_remote`...): what clients use on their own
//!   stores (owner `LOCAL_OWNER`). Kept as they were.
//! - **Vault-scoped** (`*_in`, `vault_changes`, `apply_remote_v2`,
//!   `transfer`...): what the server uses. Access is decided only by
//!   `vault_id` and a [`VaultAccess`]; secrets only open through
//!   [`VaultAccess::authorize_secret`].

use std::collections::{BTreeSet, HashMap};

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::vaults::{Keyring, SecretUse, VaultAccess};
use super::{Store, next_rev, parse_id, parse_opt_id};
use crate::error::{CoreError, Result, codes};
use crate::model::{
    Entity, EntityKind, Record, RecordMeta, SecretUpdate, SyncMode, SyncRecord, VaultRole,
};
use crate::time::now_ms;
use crate::transfer::{self, Item, TransferMode, TransferRequest, TransferResult};
use crate::{Id, new_id};
use uuid::Uuid;

struct Row {
    id: Id,
    owner_id: Id,
    data: String,
    secret: Option<Vec<u8>>,
    sync_mode: SyncMode,
    rev: i64,
    updated_at: i64,
    deleted: bool,
    vault_id: Option<Id>,
    key_version: Option<u32>,
    updated_by: Option<Id>,
    secret_hidden: bool,
    kind: Option<EntityKind>,
}

const COLUMNS: &str = "id, owner_id, data, secret, sync_mode, rev, updated_at, deleted, vault_id, \
     key_version, updated_by, secret_hidden, kind";

fn map_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    Ok(Row {
        id: parse_id(&r.get::<_, String>(0)?)?,
        owner_id: parse_id(&r.get::<_, String>(1)?)?,
        data: r.get(2)?,
        secret: r.get(3)?,
        sync_mode: SyncMode::parse(&r.get::<_, String>(4)?),
        rev: r.get(5)?,
        updated_at: r.get(6)?,
        deleted: r.get::<_, i64>(7)? != 0,
        vault_id: parse_opt_id(r.get(8)?)?,
        key_version: r.get(9)?,
        updated_by: parse_opt_id(r.get(10)?)?,
        secret_hidden: r.get::<_, i64>(11)? != 0,
        kind: EntityKind::parse(&r.get::<_, String>(12)?),
    })
}

impl Row {
    /// Vault for access decisions: rows from before vaults belong to the
    /// personal vault of their owner.
    fn vault(&self) -> Id {
        self.vault_id.unwrap_or(self.owner_id)
    }

    fn meta(&self, role: Option<VaultRole>) -> RecordMeta {
        let has_secret = self.secret.is_some() || self.secret_hidden;
        RecordMeta {
            owner_id: self.owner_id,
            sync_mode: self.sync_mode,
            rev: self.rev,
            updated_at: self.updated_at,
            deleted: self.deleted,
            has_secret,
            vault_id: self.vault_id,
            updated_by: self.updated_by,
            secret_hidden: self.secret_hidden
                || (has_secret && role.is_some_and(|r| !r.can_read_secrets())),
        }
    }
}

fn to_record<T: Entity>(row: Row, role: Option<VaultRole>) -> Result<Record<T>> {
    let meta = row.meta(role);
    let mut data: T = serde_json::from_str(&row.data)?;
    data.set_id(row.id);
    Ok(Record { data, meta })
}

fn load_row(conn: &Connection, id: Id) -> Result<Option<Row>> {
    Ok(conn
        .query_row(
            &format!("SELECT {COLUMNS} FROM entities WHERE id = ?1"),
            [id.to_string()],
            map_row,
        )
        .optional()?)
}

/// Live row of kind `T` (owner-based check).
fn owned_row<T: Entity>(conn: &Connection, owner: Id, id: Id) -> Result<Row> {
    match load_row(conn, id)? {
        Some(row) if row.kind == Some(T::KIND) && row.owner_id == owner && !row.deleted => Ok(row),
        _ => Err(not_found::<T>(id)),
    }
}

fn not_found<T: Entity>(id: Id) -> CoreError {
    CoreError::NotFound(format!("{} {id}", T::KIND.as_str()))
}

/// Live row of kind `T` in a vault `access` can reach, with the role.
fn visible_row<T: Entity>(
    conn: &Connection,
    access: &VaultAccess,
    id: Id,
) -> Result<(Row, VaultRole)> {
    match load_row(conn, id)? {
        Some(row) if row.kind == Some(T::KIND) && !row.deleted => match access.role(row.vault()) {
            Some(role) => Ok((row, role)),
            None => Err(not_found::<T>(id)),
        },
        _ => Err(not_found::<T>(id)),
    }
}

fn open_secret<S: serde::de::DeserializeOwned + Default>(
    conn: &Connection,
    keys: &Keyring,
    row: &Row,
    kind: EntityKind,
) -> Result<S> {
    match row.secret.as_deref() {
        None => Ok(S::default()),
        Some(blob) => {
            let plain = keys.open(conn, row.vault_id, row.key_version, kind, row.id, blob)?;
            Ok(serde_json::from_slice(&plain)?)
        }
    }
}

/// Personal vault of `owner` on this store, if it exists (server). Rows
/// saved through the owner-based functions land there.
fn default_vault(conn: &Connection, owner: Id) -> Result<Option<Id>> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM vaults WHERE id = ?1 AND kind = 'personal'",
            [owner.to_string()],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        .map(|_| owner))
}

/// Ids an entity references (field, id): `group_id`, `parent_id`,
/// `settings.identity_id`, `settings.key_id`, `settings.jump_host_ids`,
/// `settings.startup_snippet_id`, an identity's `key_id`, and the
/// `host_id` of forwards and memories. They must stay inside the vault.
pub fn references(kind: EntityKind, data: &Value) -> Vec<(&'static str, Id)> {
    let id = |v: Option<&Value>| v.and_then(Value::as_str).and_then(|s| s.parse::<Id>().ok());
    let mut out = Vec::new();
    let settings = |s: Option<&Value>, out: &mut Vec<(&'static str, Id)>| {
        let Some(s) = s else { return };
        if let Some(i) = id(s.get("identity_id")) {
            out.push(("settings.identity_id", i));
        }
        if let Some(i) = id(s.get("key_id")) {
            out.push(("settings.key_id", i));
        }
        if let Some(list) = s.get("jump_host_ids").and_then(Value::as_array) {
            for j in list {
                if let Some(i) = id(Some(j)) {
                    out.push(("settings.jump_host_ids", i));
                }
            }
        }
        if let Some(i) = id(s.get("startup_snippet_id")) {
            out.push(("settings.startup_snippet_id", i));
        }
    };
    match kind {
        EntityKind::Host => {
            if let Some(i) = id(data.get("group_id")) {
                out.push(("group_id", i));
            }
            settings(data.get("settings"), &mut out);
        }
        EntityKind::Group => {
            if let Some(i) = id(data.get("parent_id")) {
                out.push(("parent_id", i));
            }
            settings(data.get("settings"), &mut out);
        }
        EntityKind::Identity => {
            if let Some(i) = id(data.get("key_id")) {
                out.push(("key_id", i));
            }
        }
        EntityKind::Forward | EntityKind::Memory => {
            if let Some(i) = id(data.get("host_id")) {
                out.push(("host_id", i));
            }
        }
        EntityKind::Key | EntityKind::Snippet | EntityKind::KnownHost => {}
    }
    out
}

/// Fields of `data` that reference a live item of another vault.
fn cross_refs(conn: &Connection, vault: Id, kind: EntityKind, data: &Value) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for (field, rid) in references(kind, data) {
        let other: Option<Option<String>> = conn
            .query_row(
                "SELECT vault_id FROM entities WHERE id = ?1 AND deleted = 0",
                [rid.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(v) = other
            && v.as_deref() != Some(vault.to_string().as_str())
            && !out.iter().any(|f| f == field)
        {
            out.push(field.to_string());
        }
    }
    Ok(out)
}

fn ids_json(ids: &[Id]) -> String {
    serde_json::to_string(&ids.iter().map(|i| i.to_string()).collect::<Vec<_>>())
        .unwrap_or_else(|_| "[]".into())
}

/// Writes a departure tombstone ("`id` left `vault`").
fn depart(conn: &Connection, vault: Id, id: Id, kind: EntityKind) -> Result<i64> {
    let rev = next_rev(conn)?;
    conn.execute(
        "INSERT INTO entity_departures (vault_id, entity_id, kind, rev, at) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT (vault_id, entity_id) DO UPDATE SET kind = excluded.kind, rev = excluded.rev,
                                                         at = excluded.at",
        params![vault.to_string(), id.to_string(), kind.as_str(), rev, now_ms()],
    )?;
    Ok(rev)
}

/// One change of a vault for sync.
#[derive(Debug, Clone)]
pub enum VaultChange {
    /// Created, updated or deleted (tombstone) in the vault.
    Record(SyncRecord),
    /// The entity left the vault (moved, or the vault lost it).
    Departed {
        id: Id,
        kind: EntityKind,
        rev: i64,
        at: i64,
    },
}

impl VaultChange {
    pub fn rev(&self) -> i64 {
        match self {
            VaultChange::Record(r) => r.rev,
            VaultChange::Departed { rev, .. } => *rev,
        }
    }
}

/// Changes of a vault after a cursor.
#[derive(Debug, Clone, Default)]
pub struct VaultChanges {
    /// Ordered by revision.
    pub items: Vec<VaultChange>,
    /// The limit cut the result.
    pub more: bool,
    /// Store revision when the changes were read: every change up to it is
    /// included (when not `more`), so it can be the next cursor.
    pub head: i64,
}

impl VaultChanges {
    /// Next cursor for this vault.
    pub fn cursor(&self, previous: i64) -> i64 {
        if self.more {
            self.items.last().map_or(previous, VaultChange::rev)
        } else {
            self.head.max(previous)
        }
    }
}

/// A pushed record the server did not take.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SyncRejection {
    pub id: Uuid,
    pub code: String,
    pub message: String,
}

/// A pushed record the server took with a remark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SyncWarning {
    pub id: Uuid,
    pub code: String,
    pub field: String,
}

/// Outcome of [`Store::apply_remote_v2`].
#[derive(Debug, Clone, Default)]
pub struct ApplyReport {
    /// Taken (including stale ones: the server keeps its newer version).
    pub accepted: Vec<Id>,
    pub rejected: Vec<SyncRejection>,
    pub warnings: Vec<SyncWarning>,
    /// Older than what the server has: the client must get the server's
    /// version (it is sent back with the changes).
    pub stale: Vec<Id>,
    /// Applied records (with their new revision, without secrets).
    pub applied: Vec<SyncRecord>,
}

fn reject(report: &mut ApplyReport, id: Id, code: &str, message: impl Into<String>) {
    report.rejected.push(SyncRejection {
        id,
        code: code.into(),
        message: message.into(),
    });
}

impl Store {
    // ------------------------------------------------------------------
    // Owner-based (clients)
    // ------------------------------------------------------------------

    /// Lists the live entities of a kind.
    pub async fn list<T: Entity>(&self, owner: Id) -> Result<Vec<Record<T>>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare_cached(&format!(
                "SELECT {COLUMNS} FROM entities
                 WHERE owner_id = ?1 AND kind = ?2 AND deleted = 0
                 ORDER BY id"
            ))?;
            let rows = stmt
                .query_map(params![owner.to_string(), T::KIND.as_str()], map_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows.into_iter().map(|r| to_record::<T>(r, None)).collect()
        })
        .await
    }

    /// Gets a live entity.
    pub async fn get<T: Entity>(&self, owner: Id, id: Id) -> Result<Record<T>> {
        self.call(move |c, _| to_record(owned_row::<T>(c, owner, id)?, None))
            .await
    }

    /// Decrypts an entity's secret (empty if it has none). Owner-based: for
    /// a client's own store.
    pub async fn secret<T: Entity>(&self, owner: Id, id: Id) -> Result<T::Secret> {
        self.call_keys(move |c, keys| {
            let row = owned_row::<T>(c, owner, id)?;
            open_secret(c, keys, &row, T::KIND)
        })
        .await
    }

    /// Creates or updates an entity. If `data.id()` is nil a new one is assigned.
    pub async fn save<T: Entity>(
        &self,
        owner: Id,
        mut data: T,
        secret: SecretUpdate<T::Secret>,
        sync_mode: Option<SyncMode>,
    ) -> Result<Record<T>> {
        if data.id().is_nil() {
            data.set_id(new_id());
        }
        data.validate()?;
        let (rec, vault) = self
            .call_keys(move |c, keys| {
                let tx = c.transaction()?;
                let id = data.id();
                let existing = load_row(&tx, id)?;
                if let Some(row) = &existing
                    && (row.owner_id != owner || row.kind != Some(T::KIND))
                {
                    return Err(CoreError::Conflict(format!("id {id} is already in use")));
                }
                let vault = match &existing {
                    Some(row) => row.vault_id,
                    None => default_vault(&tx, owner)?,
                };
                let mode = sync_mode
                    .or_else(|| existing.as_ref().map(|r| r.sync_mode))
                    .unwrap_or_default();
                let (secret_blob, key_version) = match secret {
                    SecretUpdate::Keep => existing
                        .as_ref()
                        .map(|r| (r.secret.clone(), r.key_version))
                        .unwrap_or((None, None)),
                    SecretUpdate::Clear => (None, None),
                    SecretUpdate::Set(s) => {
                        let json = zeroize::Zeroizing::new(serde_json::to_vec(&s)?);
                        let (b, v) = keys.seal(&tx, vault, T::KIND, id, &json)?;
                        (Some(b), v)
                    }
                };
                let rev = next_rev(&tx)?;
                let now = now_ms();
                let json = serde_json::to_string(&data)?;
                tx.execute(
                    "INSERT INTO entities (id, owner_id, kind, data, secret, sync_mode, rev, updated_at,
                                           deleted, dirty, vault_id, key_version)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 1, ?9, ?10)
                     ON CONFLICT(id) DO UPDATE SET
                        data = excluded.data, secret = excluded.secret, sync_mode = excluded.sync_mode,
                        rev = excluded.rev, updated_at = excluded.updated_at, deleted = 0, dirty = 1,
                        key_version = excluded.key_version, secret_hidden = 0",
                    params![
                        id.to_string(),
                        owner.to_string(),
                        T::KIND.as_str(),
                        json,
                        secret_blob,
                        mode.as_str(),
                        rev,
                        now,
                        vault.map(|v| v.to_string()),
                        key_version
                    ],
                )?;
                tx.commit()?;
                Ok((
                    Record {
                        data,
                        meta: RecordMeta {
                            owner_id: owner,
                            sync_mode: mode,
                            rev,
                            updated_at: now,
                            deleted: false,
                            has_secret: secret_blob.is_some(),
                            vault_id: vault,
                            updated_by: existing.and_then(|r| r.updated_by),
                            secret_hidden: false,
                        },
                    },
                    vault,
                ))
            })
            .await?;
        self.changed(&vault.into_iter().collect::<Vec<_>>());
        Ok(rec)
    }

    /// Deletes an entity (leaves a tombstone so the deletion syncs).
    pub async fn delete<T: Entity>(&self, owner: Id, id: Id) -> Result<()> {
        let vault = self
            .call(move |c, _| {
                let tx = c.transaction()?;
                let row = owned_row::<T>(&tx, owner, id)?;
                let rev = next_rev(&tx)?;
                tx.execute(
                    "UPDATE entities SET deleted = 1, secret = NULL, key_version = NULL, data = '{}',
                            rev = ?2, updated_at = ?3, dirty = 1, secret_hidden = 0
                     WHERE id = ?1",
                    params![id.to_string(), rev, now_ms()],
                )?;
                tx.commit()?;
                Ok(row.vault_id)
            })
            .await?;
        self.changed(&vault.into_iter().collect::<Vec<_>>());
        Ok(())
    }

    /// Highest revision of the owner.
    pub async fn max_rev(&self, owner: Id) -> Result<i64> {
        self.call(move |c, _| {
            Ok(c.query_row(
                "SELECT COALESCE(MAX(rev), 0) FROM entities WHERE owner_id = ?1",
                [owner.to_string()],
                |r| r.get(0),
            )?)
        })
        .await
    }

    /// Current store revision (global counter).
    pub async fn head_rev(&self) -> Result<i64> {
        self.call(|c, _| {
            Ok(c.query_row(
                "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'rev'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
    }

    /// Changes after `since` to send to another device. Never includes
    /// `device_only` records. With `with_secrets`, attaches the decrypted
    /// secrets (only to send them over TLS to the user themselves).
    /// Owner-based: for a client's own store.
    pub async fn changes_since(
        &self,
        owner: Id,
        since: i64,
        with_secrets: bool,
    ) -> Result<Vec<SyncRecord>> {
        self.call_keys(move |c, keys| {
            let mut stmt = c.prepare_cached(&format!(
                "SELECT {COLUMNS} FROM entities
                 WHERE owner_id = ?1 AND rev > ?2 AND sync_mode = 'synced'
                 ORDER BY rev"
            ))?;
            let rows = stmt
                .query_map(params![owner.to_string(), since], map_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                if row.kind.is_none() {
                    continue;
                }
                out.push(row_to_sync(c, keys, row, with_secrets, false)?);
            }
            Ok(out)
        })
        .await
    }

    /// Locally modified records waiting to be uploaded (client).
    pub async fn dirty_records(&self) -> Result<Vec<SyncRecord>> {
        self.call_keys(move |c, keys| {
            let mut stmt = c.prepare_cached(&format!(
                "SELECT {COLUMNS} FROM entities
                 WHERE dirty = 1 AND sync_mode = 'synced' ORDER BY rev"
            ))?;
            let rows = stmt
                .query_map([], map_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                if row.kind.is_none() {
                    continue;
                }
                out.push(row_to_sync(c, keys, row, true, false)?);
            }
            Ok(out)
        })
        .await
    }

    /// Marks as uploaded the records whose `updated_at` has not changed.
    pub async fn mark_clean(&self, pushed: Vec<(Id, i64)>) -> Result<()> {
        self.call(move |c, _| {
            let tx = c.transaction()?;
            for (id, updated_at) in pushed {
                tx.execute(
                    "UPDATE entities SET dirty = 0 WHERE id = ?1 AND updated_at = ?2",
                    params![id.to_string(), updated_at],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    /// Applies changes received from another device with a "last writer wins"
    /// rule. On the server `mark_dirty = false`; on the client, changes coming
    /// from the server are not marked dirty either. Owner-based: for a
    /// client's own store (the server uses [`Store::apply_remote_v2`]).
    ///
    /// Returns the applied records (with their new revision).
    pub async fn apply_remote(
        &self,
        owner: Id,
        records: Vec<SyncRecord>,
    ) -> Result<Vec<SyncRecord>> {
        self.call_keys(move |c, keys| {
            let tx = c.transaction()?;
            let mut applied = Vec::new();
            for mut rec in records {
                if rec.sync_mode == SyncMode::DeviceOnly {
                    continue;
                }
                let existing = load_row(&tx, rec.id)?;
                if let Some(row) = &existing {
                    if row.owner_id != owner || row.kind != Some(rec.kind) {
                        tracing::warn!(id = %rec.id, "sync record rejected: id belongs to another owner");
                        continue;
                    }
                    if row.updated_at > rec.updated_at {
                        continue;
                    }
                    if row.sync_mode == SyncMode::DeviceOnly {
                        continue;
                    }
                }
                if !rec.deleted {
                    validate_record(&rec)?;
                }
                let vault = match &existing {
                    Some(row) => row.vault_id,
                    None => match rec.vault_id {
                        Some(v) => Some(v),
                        None => default_vault(&tx, owner)?,
                    },
                };
                let (secret_blob, key_version) = if rec.deleted {
                    (None, None)
                } else {
                    match &rec.secret {
                        None => existing
                            .as_ref()
                            .map(|r| (r.secret.clone(), r.key_version))
                            .unwrap_or((None, None)),
                        Some(serde_json::Value::Null) => (None, None),
                        Some(v) => {
                            let json = zeroize::Zeroizing::new(serde_json::to_vec(v)?);
                            let (b, kv) = keys.seal(&tx, vault, rec.kind, rec.id, &json)?;
                            (Some(b), kv)
                        }
                    }
                };
                let rev = next_rev(&tx)?;
                let data = if rec.deleted {
                    "{}".to_string()
                } else {
                    serde_json::to_string(&rec.data)?
                };
                tx.execute(
                    "INSERT INTO entities (id, owner_id, kind, data, secret, sync_mode, rev, updated_at,
                                           deleted, dirty, vault_id, key_version)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'synced', ?6, ?7, ?8, 0, ?9, ?10)
                     ON CONFLICT(id) DO UPDATE SET
                        data = excluded.data, secret = excluded.secret, rev = excluded.rev,
                        updated_at = excluded.updated_at, deleted = excluded.deleted, dirty = 0,
                        key_version = excluded.key_version",
                    params![
                        rec.id.to_string(),
                        owner.to_string(),
                        rec.kind.as_str(),
                        data,
                        secret_blob,
                        rev,
                        rec.updated_at,
                        rec.deleted as i64,
                        vault.map(|v| v.to_string()),
                        key_version
                    ],
                )?;
                rec.rev = rev;
                rec.secret = None;
                applied.push(rec);
            }
            tx.commit()?;
            Ok(applied)
        })
        .await
    }

    // ------------------------------------------------------------------
    // Vault-scoped (server)
    // ------------------------------------------------------------------

    /// Live entities of a kind in every vault `access` reaches (or only in
    /// `vault`). Records carry `vault_id` and `secret_hidden`; never secrets.
    pub async fn list_in<T: Entity>(
        &self,
        access: &VaultAccess,
        vault: Option<Id>,
    ) -> Result<Vec<Record<T>>> {
        let vaults = match vault {
            Some(v) => {
                access.require(v, VaultRole::UseOnly)?;
                vec![v]
            }
            None => access.vault_ids(),
        };
        let roles: HashMap<Id, VaultRole> = vaults
            .iter()
            .filter_map(|v| access.role(*v).map(|r| (*v, r)))
            .collect();
        self.call(move |c, _| {
            let mut stmt = c.prepare_cached(&format!(
                "SELECT {COLUMNS} FROM entities
                 WHERE kind = ?1 AND deleted = 0
                   AND vault_id IN (SELECT value FROM json_each(?2))
                 ORDER BY id"
            ))?;
            let rows = stmt
                .query_map(params![T::KIND.as_str(), ids_json(&vaults)], map_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows.into_iter()
                .map(|r| {
                    let role = roles.get(&r.vault()).copied();
                    to_record::<T>(r, role)
                })
                .collect()
        })
        .await
    }

    /// A live entity in a vault `access` reaches (otherwise not found: its
    /// existence is not revealed).
    pub async fn get_in<T: Entity>(&self, access: &VaultAccess, id: Id) -> Result<Record<T>> {
        let access = access.clone();
        self.call(move |c, _| {
            let (row, role) = visible_row::<T>(c, &access, id)?;
            to_record(row, Some(role))
        })
        .await
    }

    /// The choke point of secrets: decrypts an entity's secret for `access`
    /// only if [`VaultAccess::authorize_secret`] allows `purpose`.
    pub async fn secret_in<T: Entity>(
        &self,
        access: &VaultAccess,
        id: Id,
        purpose: SecretUse,
    ) -> Result<T::Secret> {
        let access = access.clone();
        self.call_keys(move |c, keys| {
            let (row, _) = visible_row::<T>(c, &access, id)?;
            access.authorize_secret(row.vault(), purpose)?;
            open_secret(c, keys, &row, T::KIND)
        })
        .await
    }

    /// Creates or updates an entity in `vault` (Editor). An existing id in
    /// another vault gives `use_transfer` (or `id_in_use` if you cannot see
    /// it); references to items of another vault give
    /// `cross_vault_reference`.
    pub async fn save_in<T: Entity>(
        &self,
        access: &VaultAccess,
        vault: Id,
        mut data: T,
        secret: SecretUpdate<T::Secret>,
        sync_mode: Option<SyncMode>,
    ) -> Result<Record<T>> {
        let role = access.require(vault, VaultRole::Editor)?;
        if data.id().is_nil() {
            data.set_id(new_id());
        }
        data.validate()?;
        let access = access.clone();
        let actor = access.user;
        let rec = self
            .call_keys(move |c, keys| {
                let tx = c.transaction()?;
                let id = data.id();
                let existing = load_row(&tx, id)?;
                if let Some(row) = &existing {
                    if row.kind != Some(T::KIND) {
                        return Err(CoreError::vault(codes::ID_IN_USE, format!("id {id} is already in use")));
                    }
                    if row.vault() != vault {
                        return Err(if access.role(row.vault()).is_some() {
                            CoreError::vault(
                                codes::USE_TRANSFER,
                                "the item is in another vault: move it with transfer",
                            )
                        } else {
                            CoreError::vault(codes::ID_IN_USE, format!("id {id} is already in use"))
                        });
                    }
                }
                let json_value = serde_json::to_value(&data)?;
                let bad = cross_refs(&tx, vault, T::KIND, &json_value)?;
                if let Some(field) = bad.first() {
                    return Err(CoreError::vault_detail(
                        codes::CROSS_VAULT_REFERENCE,
                        format!("\"{field}\" points to an item of another vault"),
                        serde_json::json!({ "field": field }),
                    ));
                }
                let mode = sync_mode
                    .or_else(|| existing.as_ref().map(|r| r.sync_mode))
                    .unwrap_or_default();
                let (secret_blob, key_version) = match secret {
                    SecretUpdate::Keep => existing
                        .as_ref()
                        .map(|r| (r.secret.clone(), r.key_version))
                        .unwrap_or((None, None)),
                    SecretUpdate::Clear => (None, None),
                    SecretUpdate::Set(s) => {
                        let json = zeroize::Zeroizing::new(serde_json::to_vec(&s)?);
                        let (b, v) = keys.seal(&tx, Some(vault), T::KIND, id, &json)?;
                        (Some(b), v)
                    }
                };
                let owner = existing.as_ref().map_or(actor, |r| r.owner_id);
                let rev = next_rev(&tx)?;
                let now = now_ms();
                tx.execute(
                    "INSERT INTO entities (id, owner_id, kind, data, secret, sync_mode, rev, updated_at,
                                           deleted, dirty, vault_id, key_version, updated_by)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 1, ?9, ?10, ?11)
                     ON CONFLICT(id) DO UPDATE SET
                        data = excluded.data, secret = excluded.secret, sync_mode = excluded.sync_mode,
                        rev = excluded.rev, updated_at = excluded.updated_at, deleted = 0, dirty = 1,
                        vault_id = excluded.vault_id, key_version = excluded.key_version,
                        updated_by = excluded.updated_by, secret_hidden = 0",
                    params![
                        id.to_string(),
                        owner.to_string(),
                        T::KIND.as_str(),
                        json_value.to_string(),
                        secret_blob,
                        mode.as_str(),
                        rev,
                        now,
                        vault.to_string(),
                        key_version,
                        actor.to_string()
                    ],
                )?;
                tx.commit()?;
                Ok(Record {
                    data,
                    meta: RecordMeta {
                        owner_id: owner,
                        sync_mode: mode,
                        rev,
                        updated_at: now,
                        deleted: false,
                        has_secret: secret_blob.is_some(),
                        vault_id: Some(vault),
                        updated_by: Some(actor),
                        secret_hidden: secret_blob.is_some() && !role.can_read_secrets(),
                    },
                })
            })
            .await?;
        self.changed(&[vault]);
        Ok(rec)
    }

    /// Deletes an entity of a vault (Editor), leaving a tombstone.
    pub async fn delete_in<T: Entity>(&self, access: &VaultAccess, id: Id) -> Result<()> {
        let access = access.clone();
        let vault = self
            .call(move |c, _| {
                let tx = c.transaction()?;
                let (row, _) = visible_row::<T>(&tx, &access, id)?;
                access.require(row.vault(), VaultRole::Editor)?;
                let rev = next_rev(&tx)?;
                tx.execute(
                    "UPDATE entities SET deleted = 1, secret = NULL, key_version = NULL, data = '{}',
                            rev = ?2, updated_at = ?3, dirty = 1, updated_by = ?4, secret_hidden = 0
                     WHERE id = ?1",
                    params![id.to_string(), rev, now_ms(), access.user.to_string()],
                )?;
                tx.commit()?;
                Ok(row.vault())
            })
            .await?;
        self.changed(&[vault]);
        Ok(())
    }

    /// A live entity of exactly `vault` (`None`: rows without a vault).
    /// Internal: the same-vault lookups of host resolution.
    pub(crate) async fn get_in_vault<T: Entity>(
        &self,
        vault: Option<Id>,
        id: Id,
    ) -> Result<Option<T>> {
        self.call(move |c, _| match load_row(c, id)? {
            Some(row) if row.kind == Some(T::KIND) && !row.deleted && row.vault_id == vault => {
                Ok(Some(to_record::<T>(row, None)?.data))
            }
            _ => Ok(None),
        })
        .await
    }

    /// Secret of an entity of exactly `vault`. Internal: only after the
    /// access to the vault was authorized (host resolution).
    pub(crate) async fn secret_in_vault<T: Entity>(
        &self,
        vault: Option<Id>,
        id: Id,
    ) -> Result<T::Secret> {
        self.call_keys(move |c, keys| match load_row(c, id)? {
            Some(row) if row.kind == Some(T::KIND) && !row.deleted && row.vault_id == vault => {
                open_secret(c, keys, &row, T::KIND)
            }
            _ => Err(not_found::<T>(id)),
        })
        .await
    }

    /// Kind and vault of a live entity `access` can see (any kind).
    pub async fn locate_in(&self, access: &VaultAccess, id: Id) -> Result<(EntityKind, Id)> {
        let access = access.clone();
        self.call(move |c, _| match load_row(c, id)? {
            Some(row) if !row.deleted && access.role(row.vault()).is_some() => match row.kind {
                Some(kind) => Ok((kind, row.vault())),
                None => Err(CoreError::NotFound(format!("item {id}"))),
            },
            _ => Err(CoreError::NotFound(format!("item {id}"))),
        })
        .await
    }

    /// Vault of a live entity `access` can see.
    pub async fn vault_of<T: Entity>(&self, access: &VaultAccess, id: Id) -> Result<Id> {
        Ok(self
            .get_in::<T>(access, id)
            .await?
            .meta
            .vault_id
            .unwrap_or(access.user))
    }

    /// Changes of `vault` after `since` (entities, tombstones and
    /// departures), merged by revision, at most `limit`. Secrets are
    /// included only when `access` may reveal them; otherwise
    /// `has_secret: true` marks them.
    pub async fn vault_changes(
        &self,
        access: &VaultAccess,
        vault: Id,
        since: i64,
        limit: usize,
    ) -> Result<VaultChanges> {
        access.require(vault, VaultRole::UseOnly)?;
        let with_secrets = access.authorize_secret(vault, SecretUse::Reveal).is_ok();
        self.call_keys(move |c, keys| {
            let head: i64 = c.query_row(
                "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'rev'",
                [],
                |r| r.get(0),
            )?;
            let fetch = limit.saturating_add(1) as i64;
            let rows = {
                let mut stmt = c.prepare_cached(&format!(
                    "SELECT {COLUMNS} FROM entities
                     WHERE vault_id = ?1 AND rev > ?2 AND sync_mode = 'synced'
                     ORDER BY rev LIMIT ?3"
                ))?;
                stmt.query_map(params![vault.to_string(), since, fetch], map_row)?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            let departures = {
                let mut stmt = c.prepare_cached(
                    "SELECT entity_id, kind, rev, at FROM entity_departures
                     WHERE vault_id = ?1 AND rev > ?2 ORDER BY rev LIMIT ?3",
                )?;
                stmt.query_map(params![vault.to_string(), since, fetch], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
            };
            let mut items: Vec<VaultChange> = Vec::with_capacity(rows.len() + departures.len());
            for row in rows {
                if row.kind.is_none() {
                    continue;
                }
                items.push(VaultChange::Record(row_to_sync(
                    c,
                    keys,
                    row,
                    with_secrets,
                    true,
                )?));
            }
            for (id, kind, rev, at) in departures {
                if let Some(kind) = EntityKind::parse(&kind) {
                    items.push(VaultChange::Departed {
                        id: parse_id(&id)?,
                        kind,
                        rev,
                        at,
                    });
                }
            }
            items.sort_by_key(VaultChange::rev);
            let more = items.len() > limit;
            items.truncate(limit);
            Ok(VaultChanges { items, more, head })
        })
        .await
    }

    /// Applies records pushed by a user (sync v2 and the legacy sync), each
    /// in its vault (`vault_id`, or the personal vault). Last writer wins by
    /// `updated_at`.
    pub async fn apply_remote_v2(
        &self,
        access: &VaultAccess,
        records: Vec<SyncRecord>,
    ) -> Result<ApplyReport> {
        let access = access.clone();
        let (report, vaults) = self
            .call_keys(move |c, keys| {
                let tx = c.transaction()?;
                let actor = access.user;
                let mut report = ApplyReport::default();
                let mut vaults: BTreeSet<Id> = BTreeSet::new();
                for mut rec in records {
                    if rec.sync_mode == SyncMode::DeviceOnly {
                        continue;
                    }
                    let existing = load_row(&tx, rec.id)?;
                    let requested = rec.vault_id.unwrap_or(access.personal());
                    let mut target = requested;
                    if let Some(row) = &existing {
                        if row.kind != Some(rec.kind) {
                            reject(&mut report, rec.id, codes::ID_IN_USE, "the id is already in use");
                            continue;
                        }
                        if row.vault() != requested {
                            if access.role(row.vault()).is_some() {
                                // Moved meanwhile: the change goes where it is now.
                                target = row.vault();
                            } else {
                                reject(&mut report, rec.id, codes::ID_IN_USE, "the id is already in use");
                                continue;
                            }
                        }
                    }
                    match access.role(target) {
                        None => {
                            reject(&mut report, rec.id, codes::VAULT_NOT_FOUND, "vault not found");
                            continue;
                        }
                        Some(r) if !r.can_write() => {
                            reject(
                                &mut report,
                                rec.id,
                                codes::VAULT_READ_ONLY,
                                "you cannot change the items of this vault",
                            );
                            continue;
                        }
                        Some(_) => {}
                    }
                    if let Some(row) = &existing {
                        if row.updated_at > rec.updated_at {
                            report.accepted.push(rec.id);
                            report.stale.push(rec.id);
                            continue;
                        }
                        if let Some(base) = rec.base_rev
                            && base < row.rev
                        {
                            tracing::info!(id = %rec.id, base, rev = row.rev, "sync: the client overwrote a newer revision");
                        }
                    }
                    if !rec.deleted {
                        if let Err(e) = validate_record(&rec) {
                            reject(&mut report, rec.id, "invalid", e.to_string());
                            continue;
                        }
                        for field in cross_refs(&tx, target, rec.kind, &rec.data)? {
                            report.warnings.push(SyncWarning {
                                id: rec.id,
                                code: codes::CROSS_VAULT_REFERENCE.into(),
                                field,
                            });
                        }
                    }
                    let (secret_blob, key_version) = if rec.deleted {
                        (None, None)
                    } else {
                        match &rec.secret {
                            None => existing
                                .as_ref()
                                .map(|r| (r.secret.clone(), r.key_version))
                                .unwrap_or((None, None)),
                            Some(Value::Null) => (None, None),
                            Some(v) => {
                                let json = zeroize::Zeroizing::new(serde_json::to_vec(v)?);
                                let (b, kv) = keys.seal(&tx, Some(target), rec.kind, rec.id, &json)?;
                                (Some(b), kv)
                            }
                        }
                    };
                    let rev = next_rev(&tx)?;
                    let data = if rec.deleted {
                        "{}".to_string()
                    } else {
                        serde_json::to_string(&rec.data)?
                    };
                    tx.execute(
                        "INSERT INTO entities (id, owner_id, kind, data, secret, sync_mode, rev,
                                               updated_at, deleted, dirty, vault_id, key_version,
                                               updated_by)
                         VALUES (?1, ?2, ?3, ?4, ?5, 'synced', ?6, ?7, ?8, 0, ?9, ?10, ?11)
                         ON CONFLICT(id) DO UPDATE SET
                            data = excluded.data, secret = excluded.secret, rev = excluded.rev,
                            updated_at = excluded.updated_at, deleted = excluded.deleted, dirty = 0,
                            vault_id = excluded.vault_id, key_version = excluded.key_version,
                            updated_by = excluded.updated_by, sync_mode = 'synced'",
                        params![
                            rec.id.to_string(),
                            existing.as_ref().map_or(actor, |r| r.owner_id).to_string(),
                            rec.kind.as_str(),
                            data,
                            secret_blob,
                            rev,
                            rec.updated_at,
                            rec.deleted as i64,
                            target.to_string(),
                            key_version,
                            actor.to_string()
                        ],
                    )?;
                    vaults.insert(target);
                    report.accepted.push(rec.id);
                    rec.rev = rev;
                    rec.secret = None;
                    rec.vault_id = Some(target);
                    report.applied.push(rec);
                }
                tx.commit()?;
                Ok((report, vaults))
            })
            .await?;
        self.changed(&vaults.into_iter().collect::<Vec<_>>());
        Ok(report)
    }

    /// Current records of `ids` as `access` may receive them (for stale
    /// pushes: the client gets the server's version back).
    pub async fn sync_records_in(
        &self,
        access: &VaultAccess,
        ids: Vec<Id>,
    ) -> Result<Vec<SyncRecord>> {
        let access = access.clone();
        self.call_keys(move |c, keys| {
            let mut out = Vec::new();
            for id in ids {
                let Some(row) = load_row(c, id)? else {
                    continue;
                };
                if row.kind.is_none() || row.sync_mode != SyncMode::Synced {
                    continue;
                }
                let vault = row.vault();
                if access.role(vault).is_none() {
                    continue;
                }
                let with_secrets = access.authorize_secret(vault, SecretUse::Reveal).is_ok();
                out.push(row_to_sync(c, keys, row, with_secrets, true)?);
            }
            Ok(out)
        })
        .await
    }

    /// Moves entities to `target` keeping their ids (Editor on both
    /// vaults): writes a departure in the source, reseals the secret with
    /// the target key, and bumps the revision. `data` replaces the stored
    /// data when given (rewritten references).
    pub async fn move_entities(
        &self,
        access: &VaultAccess,
        target: Id,
        moves: Vec<(Id, Option<Value>)>,
    ) -> Result<i64> {
        access.require(target, VaultRole::Editor)?;
        let access = access.clone();
        let (rev, vaults) = self
            .call_keys(move |c, keys| {
                let tx = c.transaction()?;
                let mut vaults = BTreeSet::from([target]);
                for (id, data) in moves {
                    let row = load_row(&tx, id)?
                        .filter(|r| !r.deleted && r.kind.is_some())
                        .ok_or_else(|| CoreError::NotFound(format!("item {id}")))?;
                    access.require(row.vault(), VaultRole::Editor)?;
                    vaults.insert(row.vault());
                    move_row(&tx, keys, &row, target, data, access.user)?;
                }
                let rev = next_rev(&tx)?;
                tx.commit()?;
                Ok((rev, vaults))
            })
            .await?;
        self.changed(&vaults.into_iter().collect::<Vec<_>>());
        Ok(rev)
    }

    /// Moves or copies items to `target` (see [`crate::transfer`]). Move:
    /// Editor on the source and target vaults. Copy: Editor on the target
    /// and on the source, except snippets (Use-only members can read them);
    /// a copy out of a vault where the user is not Editor never carries
    /// secrets. One transaction; `dry_run` only plans.
    pub async fn transfer(
        &self,
        access: &VaultAccess,
        target: Id,
        req: TransferRequest,
    ) -> Result<TransferResult> {
        access.require(target, VaultRole::Editor)?;
        if req.items.is_empty() || req.items.len() > 1000 {
            return Err(CoreError::Invalid("give between 1 and 1000 items".into()));
        }
        let access = access.clone();
        let (result, vaults) = self
            .call_keys(move |c, keys| {
                let tx = c.transaction()?;
                // Source vaults of the selection, with permissions.
                let mut sources: BTreeSet<Id> = BTreeSet::new();
                let snippets_only = req.items.iter().all(|r| r.kind == EntityKind::Snippet);
                for r in &req.items {
                    let row = load_row(&tx, r.id)?
                        .filter(|row| !row.deleted && row.kind == Some(r.kind))
                        .filter(|row| access.role(row.vault()).is_some())
                        .ok_or_else(|| {
                            CoreError::NotFound(format!("{} {}", r.kind.as_str(), r.id))
                        })?;
                    let min = if req.mode == TransferMode::Copy && snippets_only {
                        VaultRole::UseOnly
                    } else {
                        VaultRole::Editor
                    };
                    access.require(row.vault(), min)?;
                    sources.insert(row.vault());
                }
                let load_items = |vault: Id| -> Result<Vec<Item>> {
                    let mut stmt = tx.prepare_cached(&format!(
                        "SELECT {COLUMNS} FROM entities WHERE vault_id = ?1 AND deleted = 0"
                    ))?;
                    let rows = stmt
                        .query_map([vault.to_string()], map_row)?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    let mut out = Vec::with_capacity(rows.len());
                    for row in rows {
                        if let Some(kind) = row.kind {
                            let mut data: Value = serde_json::from_str(&row.data)?;
                            if let Some(obj) = data.as_object_mut() {
                                obj.insert("id".into(), Value::String(row.id.to_string()));
                            }
                            out.push(Item {
                                kind,
                                id: row.id,
                                vault,
                                data,
                            });
                        }
                    }
                    Ok(out)
                };
                let mut universe = Vec::new();
                for v in &sources {
                    universe.extend(load_items(*v)?);
                }
                let target_items = load_items(target)?;
                let plan = transfer::plan(&req, target, &universe, &target_items, &mut new_id)?;
                let mut result = plan.result(req.dry_run);
                if req.dry_run {
                    result.rev = tx.query_row(
                        "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'rev'",
                        [],
                        |r| r.get(0),
                    )?;
                    return Ok((result, BTreeSet::new()));
                }
                let now = now_ms();
                for m in &plan.moves {
                    let row = load_row(&tx, m.id)?
                        .ok_or_else(|| CoreError::NotFound(format!("item {}", m.id)))?;
                    access.require(row.vault(), VaultRole::Editor)?;
                    move_row(&tx, keys, &row, target, Some(m.data.clone()), access.user)?;
                }
                for cp in &plan.copies {
                    let row = load_row(&tx, cp.from)?
                        .ok_or_else(|| CoreError::NotFound(format!("item {}", cp.from)))?;
                    let with_secret = access
                        .authorize_secret(cp.from_vault, SecretUse::Reveal)
                        .is_ok();
                    let (blob, kv) = match (&row.secret, with_secret) {
                        (Some(b), true) => {
                            let (b, kv) = keys.reseal(
                                &tx,
                                (row.vault_id, row.key_version),
                                Some(target),
                                cp.kind,
                                cp.from,
                                cp.to,
                                b,
                            )?;
                            (Some(b), kv)
                        }
                        _ => (None, None),
                    };
                    let mut data = cp.data.clone();
                    if let Some(obj) = data.as_object_mut() {
                        obj.remove("id");
                    }
                    let rev = next_rev(&tx)?;
                    tx.execute(
                        "INSERT INTO entities (id, owner_id, kind, data, secret, sync_mode, rev,
                                               updated_at, deleted, dirty, vault_id, key_version,
                                               updated_by)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 1, ?9, ?10, ?2)",
                        params![
                            cp.to.to_string(),
                            access.user.to_string(),
                            cp.kind.as_str(),
                            data.to_string(),
                            blob,
                            row.sync_mode.as_str(),
                            rev,
                            now,
                            target.to_string(),
                            kv
                        ],
                    )?;
                }
                for (_, id, data) in &plan.source_updates {
                    let mut data = data.clone();
                    if let Some(obj) = data.as_object_mut() {
                        obj.remove("id");
                    }
                    let rev = next_rev(&tx)?;
                    tx.execute(
                        "UPDATE entities SET data = ?2, rev = ?3, updated_at = ?4, updated_by = ?5,
                                dirty = 1
                         WHERE id = ?1",
                        params![
                            id.to_string(),
                            data.to_string(),
                            rev,
                            now,
                            access.user.to_string()
                        ],
                    )?;
                }
                result.rev = tx.query_row(
                    "SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'rev'",
                    [],
                    |r| r.get(0),
                )?;
                tx.commit()?;
                let mut vaults = sources;
                vaults.insert(target);
                Ok((result, vaults))
            })
            .await?;
        self.changed(&vaults.into_iter().collect::<Vec<_>>());
        Ok(result)
    }
}

/// Moves one row to `target` inside a transaction (see
/// [`Store::move_entities`]).
fn move_row(
    conn: &Connection,
    keys: &Keyring,
    row: &Row,
    target: Id,
    data: Option<Value>,
    actor: Id,
) -> Result<()> {
    let kind = row
        .kind
        .ok_or_else(|| CoreError::Invalid("unknown kind".into()))?;
    let from = row.vault();
    if from == target {
        return Ok(());
    }
    depart(conn, from, row.id, kind)?;
    let (secret, key_version) = match &row.secret {
        Some(blob) => {
            let (b, v) = keys.reseal(
                conn,
                (row.vault_id, row.key_version),
                Some(target),
                kind,
                row.id,
                row.id,
                blob,
            )?;
            (Some(b), v)
        }
        None => (None, None),
    };
    let data = match data {
        Some(mut d) => {
            if let Some(obj) = d.as_object_mut() {
                obj.remove("id");
            }
            d.to_string()
        }
        None => row.data.clone(),
    };
    let rev = next_rev(conn)?;
    conn.execute(
        "UPDATE entities SET vault_id = ?2, data = ?3, secret = ?4, key_version = ?5, rev = ?6,
                updated_at = ?7, updated_by = ?8, dirty = 1
         WHERE id = ?1",
        params![
            row.id.to_string(),
            target.to_string(),
            data,
            secret,
            key_version,
            rev,
            now_ms(),
            actor.to_string()
        ],
    )?;
    Ok(())
}

fn row_to_sync(
    conn: &Connection,
    keys: &Keyring,
    row: Row,
    with_secrets: bool,
    with_vault: bool,
) -> Result<SyncRecord> {
    let kind = row
        .kind
        .ok_or_else(|| CoreError::Invalid("unknown kind".into()))?;
    let secret = if with_secrets && !row.deleted {
        match row.secret.as_deref() {
            Some(blob) => {
                let plain = keys.open(conn, row.vault_id, row.key_version, kind, row.id, blob)?;
                Some(serde_json::from_slice(&plain)?)
            }
            None => None,
        }
    } else {
        None
    };
    let withheld = !with_secrets && !row.deleted && row.secret.is_some();
    Ok(SyncRecord {
        id: row.id,
        kind,
        data: serde_json::from_str(&row.data)?,
        secret,
        sync_mode: row.sync_mode,
        updated_at: row.updated_at,
        deleted: row.deleted,
        rev: row.rev,
        vault_id: if with_vault { Some(row.vault()) } else { None },
        has_secret: withheld.then_some(true),
        sealed: None,
        base_rev: None,
    })
}

/// Checks that the received data matches the declared kind.
fn validate_record(rec: &SyncRecord) -> Result<()> {
    use crate::model::*;
    fn check<T: Entity>(rec: &SyncRecord) -> Result<()> {
        let mut data: T = serde_json::from_value(rec.data.clone())
            .map_err(|e| CoreError::Invalid(format!("{}: {e}", T::KIND.as_str())))?;
        data.set_id(rec.id);
        data.validate()?;
        if let Some(secret) = &rec.secret
            && !secret.is_null()
        {
            serde_json::from_value::<T::Secret>(secret.clone())
                .map_err(|e| CoreError::Invalid(format!("{} secret: {e}", T::KIND.as_str())))?;
        }
        Ok(())
    }
    match rec.kind {
        EntityKind::Group => check::<Group>(rec),
        EntityKind::Host => check::<Host>(rec),
        EntityKind::Identity => check::<Identity>(rec),
        EntityKind::Key => check::<SshKey>(rec),
        EntityKind::Snippet => check::<Snippet>(rec),
        EntityKind::Forward => check::<PortForward>(rec),
        EntityKind::KnownHost => check::<KnownHost>(rec),
        EntityKind::Memory => check::<Memory>(rec),
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_store;
    use crate::model::*;
    use crate::new_id;

    fn host(label: &str) -> Host {
        Host {
            id: crate::Id::nil(),
            label: label.into(),
            address: "10.0.0.1".into(),
            group_id: None,
            tags: vec![],
            settings: HostSettings::default(),
            notes: String::new(),
            color: None,
            os: None,
            os_version: None,
            favorite: false,
        }
    }

    #[tokio::test]
    async fn crud_and_secrets() {
        let store = test_store();
        let owner = new_id();
        let rec = store
            .save(
                owner,
                host("web"),
                SecretUpdate::Set(HostSecret {
                    password: Some("pw".into()),
                    ..Default::default()
                }),
                None,
            )
            .await
            .unwrap();
        assert!(rec.meta.has_secret);
        let id = rec.data.id;
        assert_eq!(store.list::<Host>(owner).await.unwrap().len(), 1);
        assert!(store.list::<Host>(new_id()).await.unwrap().is_empty());
        let secret = store.secret::<Host>(owner, id).await.unwrap();
        assert_eq!(secret.password.as_deref(), Some("pw"));

        // Another owner can neither read nor overwrite it.
        assert!(store.get::<Host>(new_id(), id).await.is_err());
        let mut stolen = rec.data.clone();
        stolen.label = "x".into();
        assert!(
            store
                .save(new_id(), stolen, SecretUpdate::Keep, None)
                .await
                .is_err()
        );

        // Updating without touching the secret keeps it.
        let mut upd = rec.data.clone();
        upd.label = "web-1".into();
        store
            .save(owner, upd, SecretUpdate::Keep, None)
            .await
            .unwrap();
        let secret = store.secret::<Host>(owner, id).await.unwrap();
        assert_eq!(secret.password.as_deref(), Some("pw"));

        store.delete::<Host>(owner, id).await.unwrap();
        assert!(store.list::<Host>(owner).await.unwrap().is_empty());
        let changes = store.changes_since(owner, 0, true).await.unwrap();
        assert_eq!(changes.len(), 1);
        assert!(changes[0].deleted);
    }

    #[tokio::test]
    async fn sync_between_two_stores() {
        let server = test_store();
        let client = test_store();
        let owner = new_id();

        let rec = client
            .save(
                owner,
                host("db"),
                SecretUpdate::Set(HostSecret {
                    password: Some("s3cr3t".into()),
                    ..Default::default()
                }),
                None,
            )
            .await
            .unwrap();
        // A device-only record must not leave.
        client
            .save(
                owner,
                host("local"),
                SecretUpdate::Keep,
                Some(SyncMode::DeviceOnly),
            )
            .await
            .unwrap();

        let dirty = client.dirty_records().await.unwrap();
        assert_eq!(dirty.len(), 1);
        assert!(dirty[0].secret.is_some());
        let applied = server.apply_remote(owner, dirty.clone()).await.unwrap();
        assert_eq!(applied.len(), 1);
        client
            .mark_clean(dirty.iter().map(|r| (r.id, r.updated_at)).collect())
            .await
            .unwrap();
        assert!(client.dirty_records().await.unwrap().is_empty());

        let on_server = server.secret::<Host>(owner, rec.data.id).await.unwrap();
        assert_eq!(on_server.password.as_deref(), Some("s3cr3t"));

        // A second client downloads everything.
        let other = test_store();
        let changes = server.changes_since(owner, 0, true).await.unwrap();
        other.apply_remote(owner, changes).await.unwrap();
        let hosts = other.list::<Host>(owner).await.unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].data.label, "db");
        let s = other.secret::<Host>(owner, rec.data.id).await.unwrap();
        assert_eq!(s.password.as_deref(), Some("s3cr3t"));

        // An older change does not overwrite a newer one.
        let mut old = server.changes_since(owner, 0, false).await.unwrap();
        old[0].updated_at -= 10_000;
        old[0].data["label"] = serde_json::json!("old");
        assert!(server.apply_remote(owner, old).await.unwrap().is_empty());
    }
}

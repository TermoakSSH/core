//! Client stores (a device store or an account store, see
//! `termoak-client`): per-vault sync state, vault metadata, sync v2
//! responses and the raw item copies of client-side transfers.
//!
//! The server never calls these: access on a client is decided by the role
//! the server reported for each vault (`vault_sync.role`).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use zeroize::Zeroizing;

use super::entities::{COLUMNS, Row, load_row, map_row, open_secret, row_to_sync, validate_record};
use super::vaults::Keyring;
use super::{Store, SyncRejection, next_rev, parse_id};
use crate::Id;
use crate::error::{CoreError, Result, codes};
use crate::model::{EntityKind, SyncMode, SyncRecord, Vault, VaultRole, VaultSettings};
use crate::time::now_ms;
use crate::transfer::Item;

/// Meta key with the last vault listing of an account store (JSON).
const VAULTS_LIST: &str = "vaults.list";

/// Sync state of a vault in an account store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalVault {
    pub vault_id: Id,
    /// Role the server reported last.
    pub role: VaultRole,
    /// Highest revision received.
    pub cursor: i64,
    pub synced_at: Option<i64>,
}

/// A sync v2 response, as the client applies it (one transaction).
#[derive(Debug, Clone, Default)]
pub struct SyncV2Apply {
    /// What was pushed: `(id, updated_at)` (only the accepted ones whose
    /// `updated_at` did not change meanwhile become clean).
    pub pushed: Vec<(Id, i64)>,
    pub accepted: Vec<Id>,
    pub rejected: Vec<SyncRejection>,
    /// Authoritative list of the vaults the account can access.
    pub vaults: Vec<Vault>,
    /// New cursor per vault.
    pub cursors: Vec<(Id, i64)>,
    pub changes: Vec<SyncRecord>,
    /// Departures: `(entity, vault)`.
    pub removed: Vec<(Id, Id)>,
    /// Vaults to drop and download again.
    pub resync: Vec<Id>,
}

/// What applying a sync v2 response did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncV2Applied {
    pub pulled: usize,
    pub removed: usize,
    /// Local changes lost per vault: `vault → (name, count)` (rejected as
    /// read-only or not found, or the vault was lost).
    pub discarded: BTreeMap<Id, (String, usize)>,
    pub vaults_added: Vec<(Id, String)>,
    pub vaults_lost: Vec<(Id, String)>,
    /// Rejected changes that stay dirty (`invalid`, `id_in_use`...).
    pub kept: Vec<SyncRejection>,
}

/// An item with its plaintext secret, copied between client stores (This
/// device ↔ an account, across accounts). Wiped on drop.
#[derive(Clone)]
pub struct LocalItem {
    pub kind: EntityKind,
    pub id: Id,
    pub vault_id: Option<Id>,
    pub data: Value,
    /// Secret as JSON (`None`: no secret, or hidden).
    pub secret: Option<Zeroizing<Vec<u8>>>,
    pub secret_hidden: bool,
    pub sync_mode: SyncMode,
}

impl std::fmt::Debug for LocalItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalItem")
            .field("kind", &self.kind)
            .field("id", &self.id)
            .field("vault_id", &self.vault_id)
            .field("has_secret", &self.secret.is_some())
            .finish_non_exhaustive()
    }
}

/// Pending local changes of a store (sign-out report).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirtySummary {
    pub total: usize,
    /// Per vault (`None`: rows without a vault yet).
    pub per_vault: BTreeMap<Option<Id>, usize>,
}

fn vault_names(conn: &Connection) -> Result<HashMap<Id, String>> {
    let mut out = HashMap::new();
    let mut stmt = conn.prepare("SELECT id, name FROM vaults")?;
    for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
        let (id, name) = row?;
        if let Ok(id) = id.parse() {
            out.insert(id, name);
        }
    }
    Ok(out)
}

fn upsert_vault(conn: &Connection, v: &Vault) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO vaults (id, kind, name, description, color, icon, owner_user_id, owner_team_id,
                             team_member_role, crypto_mode, key_version, settings, rev, created_by,
                             created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
         ON CONFLICT(id) DO UPDATE SET
            kind = excluded.kind, name = excluded.name, description = excluded.description,
            color = excluded.color, icon = excluded.icon, owner_user_id = excluded.owner_user_id,
            owner_team_id = excluded.owner_team_id, team_member_role = excluded.team_member_role,
            crypto_mode = excluded.crypto_mode, key_version = excluded.key_version,
            settings = excluded.settings, rev = excluded.rev, updated_at = excluded.updated_at",
        params![
            v.id.to_string(),
            v.kind.as_str(),
            v.name,
            v.description,
            v.color,
            v.icon,
            v.owner_user_id.map(|i| i.to_string()),
            v.owner_team_id.map(|i| i.to_string()),
            v.team_member_role.map(|r| r.as_str()),
            v.crypto.as_str(),
            v.key_version,
            serde_json::to_string(&v.settings).unwrap_or_else(|_| "{}".into()),
            v.rev,
            v.created_by.to_string(),
            v.created_at,
            v.updated_at
        ],
    )
}

/// Adds a lost change to the per-vault count.
fn discard(
    out: &mut BTreeMap<Id, (String, usize)>,
    names: &HashMap<Id, String>,
    vault: Id,
    n: usize,
) {
    if n == 0 {
        return;
    }
    let e = out
        .entry(vault)
        .or_insert_with(|| (names.get(&vault).cloned().unwrap_or_default(), 0));
    e.1 += n;
}

/// Applies one record received from the server (sync v2) on a client store.
fn apply_change(
    tx: &Connection,
    keys: &Keyring,
    owner: Id,
    rec: &SyncRecord,
    roles: &HashMap<Id, VaultRole>,
) -> Result<bool> {
    if rec.sync_mode == SyncMode::DeviceOnly {
        return Ok(false);
    }
    let existing = load_row(tx, rec.id)?;
    if let Some(row) = &existing {
        if row.kind != Some(rec.kind) {
            tracing::warn!(id = %rec.id, "sync record skipped: the id has another kind here");
            return Ok(false);
        }
        if row.sync_mode == SyncMode::DeviceOnly || row.updated_at > rec.updated_at {
            return Ok(false);
        }
    }
    if !rec.deleted
        && let Err(e) = validate_record(rec)
    {
        tracing::warn!(id = %rec.id, error = %e, "sync record skipped: invalid");
        return Ok(false);
    }
    let vault = rec
        .vault_id
        .or_else(|| existing.as_ref().and_then(|r| r.vault_id));
    let can_read = vault
        .and_then(|v| roles.get(&v).copied())
        .is_none_or(VaultRole::can_read_secrets);
    let (secret, key_version, hidden) = if rec.deleted {
        (None, None, false)
    } else {
        match &rec.secret {
            Some(_) if !can_read => (None, None, true),
            Some(Value::Null) => (None, None, false),
            Some(v) => {
                let json = Zeroizing::new(serde_json::to_vec(v)?);
                let (b, kv) = keys.seal(tx, None, rec.kind, rec.id, &json)?;
                (Some(b), kv, false)
            }
            None if rec.has_secret == Some(true) => (None, None, true),
            None => match &existing {
                // Same rule as the legacy sync: no secret in the record keeps ours.
                Some(row) if can_read && row.vault_id == vault => {
                    (row.secret.clone(), row.key_version, row.secret_hidden)
                }
                Some(row) => (None, None, row.secret.is_some() || row.secret_hidden),
                None => (None, None, false),
            },
        }
    };
    let rev = next_rev(tx)?;
    let data = if rec.deleted {
        "{}".to_string()
    } else {
        serde_json::to_string(&rec.data)?
    };
    tx.execute(
        "INSERT INTO entities (id, owner_id, kind, data, secret, sync_mode, rev, updated_at,
                               deleted, dirty, vault_id, key_version, secret_hidden)
         VALUES (?1, ?2, ?3, ?4, ?5, 'synced', ?6, ?7, ?8, 0, ?9, ?10, ?11)
         ON CONFLICT(id) DO UPDATE SET
            data = excluded.data, secret = excluded.secret, rev = excluded.rev,
            updated_at = excluded.updated_at, deleted = excluded.deleted, dirty = 0,
            vault_id = excluded.vault_id, key_version = excluded.key_version,
            secret_hidden = excluded.secret_hidden, sync_mode = 'synced'",
        params![
            rec.id.to_string(),
            owner.to_string(),
            rec.kind.as_str(),
            data,
            secret,
            rev,
            rec.updated_at,
            rec.deleted as i64,
            vault.map(|v| v.to_string()),
            key_version,
            hidden as i64
        ],
    )?;
    Ok(true)
}

fn row_item(row: &Row) -> Result<Option<Item>> {
    let Some(kind) = row.kind else {
        return Ok(None);
    };
    let mut data: Value = serde_json::from_str(&row.data)?;
    if let Some(obj) = data.as_object_mut() {
        obj.insert("id".into(), Value::String(row.id.to_string()));
    }
    Ok(Some(Item {
        kind,
        id: row.id,
        vault: row.vault_id.unwrap_or_else(Id::nil),
        data,
    }))
}

impl Store {
    /// Sync state of every vault of this account store.
    pub async fn local_vaults(&self) -> Result<Vec<LocalVault>> {
        self.call(|c, _| {
            let mut stmt = c.prepare(
                "SELECT vault_id, role, cursor, synced_at FROM vault_sync ORDER BY vault_id",
            )?;
            let rows = stmt
                .query_map([], |r| {
                    Ok(LocalVault {
                        vault_id: parse_id(&r.get::<_, String>(0)?)?,
                        role: VaultRole::parse(&r.get::<_, String>(1)?),
                        cursor: r.get(2)?,
                        synced_at: r.get(3)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    /// Role per vault, as the server reported it.
    pub async fn local_roles(&self) -> Result<HashMap<Id, VaultRole>> {
        Ok(self
            .local_vaults()
            .await?
            .into_iter()
            .map(|v| (v.vault_id, v.role))
            .collect())
    }

    /// The vaults of the last sync (with role, owner name, member and item
    /// counts), in the server's order.
    pub async fn local_vault_list(&self) -> Result<Vec<Vault>> {
        Ok(match self.meta_get(VAULTS_LIST).await? {
            Some(json) => serde_json::from_str(&json).unwrap_or_default(),
            None => Vec::new(),
        })
    }

    /// Settings of a vault known locally (Strict switch...).
    pub async fn local_vault_settings(&self, vault: Id) -> Result<Option<VaultSettings>> {
        self.call(move |c, _| {
            let s: Option<String> = c
                .query_row(
                    "SELECT settings FROM vaults WHERE id = ?1",
                    [vault.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(s.map(|s| serde_json::from_str(&s).unwrap_or_default()))
        })
        .await
    }

    /// First sync with vaults after an upgrade (§5.4 of the design): rows
    /// without a vault belong to the personal vault, and the old global
    /// cursor (`legacy_cursor`) becomes the personal vault's cursor. Does
    /// nothing to the cursor when the vault already has sync state.
    pub async fn adopt_personal_vault(
        &self,
        personal: Id,
        legacy_cursor: Option<i64>,
    ) -> Result<()> {
        self.call(move |c, _| {
            let tx = c.transaction()?;
            tx.execute(
                "UPDATE entities SET vault_id = ?1 WHERE vault_id IS NULL",
                [personal.to_string()],
            )?;
            if let Some(cursor) = legacy_cursor {
                tx.execute(
                    "INSERT INTO vault_sync (vault_id, role, cursor) VALUES (?1, 'manager', ?2)
                     ON CONFLICT(vault_id) DO NOTHING",
                    params![personal.to_string(), cursor],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    /// Dirty records for sync v2, each with its `vault_id`.
    pub async fn dirty_records_v2(&self) -> Result<Vec<SyncRecord>> {
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
                let vault = row.vault_id;
                let mut rec = row_to_sync(c, keys, row, true, false)?;
                rec.vault_id = vault;
                out.push(rec);
            }
            Ok(out)
        })
        .await
    }

    /// Pending local changes (synced rows not uploaded yet).
    pub async fn dirty_summary(&self) -> Result<DirtySummary> {
        self.call(|c, _| {
            let mut stmt = c.prepare(
                "SELECT vault_id, COUNT(*) FROM entities
                 WHERE dirty = 1 AND sync_mode = 'synced' GROUP BY vault_id",
            )?;
            let mut out = DirtySummary::default();
            for row in stmt.query_map([], |r| {
                Ok((r.get::<_, Option<String>>(0)?, r.get::<_, i64>(1)?))
            })? {
                let (v, n) = row?;
                let v = v.and_then(|s| s.parse().ok());
                out.total += n as usize;
                *out.per_vault.entry(v).or_default() += n as usize;
            }
            Ok(out)
        })
        .await
    }

    /// Applies a sync v2 response on an account store (§5.3 of the design),
    /// in one transaction: clean the accepted changes, drop the rejected
    /// ones that cannot be applied, wipe lost vaults, reset resynced ones,
    /// save the vault metadata, wipe the secrets of Use-only vaults, apply
    /// the changes and departures, and save the cursors.
    pub async fn apply_sync_v2(&self, owner: Id, input: SyncV2Apply) -> Result<SyncV2Applied> {
        self.call_keys(move |c, keys| {
            let tx = c.transaction()?;
            let mut out = SyncV2Applied::default();
            let mut names = vault_names(&tx)?;
            for v in &input.vaults {
                names.entry(v.id).or_insert_with(|| v.name.clone());
            }
            let known_before: BTreeSet<Id> = {
                let mut stmt = tx.prepare("SELECT vault_id FROM vault_sync")?;
                stmt.query_map([], |r| r.get::<_, String>(0))?
                    .filter_map(|r| r.ok().and_then(|s| s.parse().ok()))
                    .collect()
            };

            // 1. Accepted changes are clean (unless edited meanwhile).
            let accepted: HashSet<Id> = input.accepted.iter().copied().collect();
            for (id, updated_at) in &input.pushed {
                if accepted.contains(id) {
                    tx.execute(
                        "UPDATE entities SET dirty = 0 WHERE id = ?1 AND updated_at = ?2",
                        params![id.to_string(), updated_at],
                    )?;
                }
            }

            // 2. Rejected changes.
            for r in &input.rejected {
                if r.code == codes::VAULT_READ_ONLY || r.code == codes::VAULT_NOT_FOUND {
                    if let Some(row) = load_row(&tx, r.id)? {
                        discard(
                            &mut out.discarded,
                            &names,
                            row.vault_id.unwrap_or_else(Id::nil),
                            1,
                        );
                        tx.execute("DELETE FROM entities WHERE id = ?1", [r.id.to_string()])?;
                    }
                } else {
                    out.kept.push(r.clone());
                }
            }

            // 3. Vaults no longer accessible: wipe them.
            let server: HashMap<Id, &Vault> = input.vaults.iter().map(|v| (v.id, v)).collect();
            let mut local: BTreeSet<Id> = known_before.clone();
            {
                let mut stmt = tx
                    .prepare("SELECT DISTINCT vault_id FROM entities WHERE vault_id IS NOT NULL")?;
                for v in stmt.query_map([], |r| r.get::<_, String>(0))? {
                    if let Ok(id) = v?.parse() {
                        local.insert(id);
                    }
                }
            }
            for v in local.iter().filter(|v| !server.contains_key(v)) {
                let dirty: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM entities WHERE vault_id = ?1 AND dirty = 1",
                    [v.to_string()],
                    |r| r.get(0),
                )?;
                discard(&mut out.discarded, &names, *v, dirty as usize);
                tx.execute("DELETE FROM entities WHERE vault_id = ?1", [v.to_string()])?;
                tx.execute(
                    "DELETE FROM vault_sync WHERE vault_id = ?1",
                    [v.to_string()],
                )?;
                tx.execute("DELETE FROM vaults WHERE id = ?1", [v.to_string()])?;
                if known_before.contains(v) {
                    out.vaults_lost
                        .push((*v, names.get(v).cloned().unwrap_or_default()));
                }
            }

            // 4. Resync: drop the local copy (the response starts from 0).
            for v in &input.resync {
                tx.execute(
                    "DELETE FROM entities WHERE vault_id = ?1 AND dirty = 0",
                    [v.to_string()],
                )?;
                tx.execute(
                    "UPDATE vault_sync SET cursor = 0 WHERE vault_id = ?1",
                    [v.to_string()],
                )?;
            }

            // 5. Vault metadata and roles.
            let mut roles: HashMap<Id, VaultRole> = HashMap::new();
            for v in &input.vaults {
                let role = v.role.unwrap_or(VaultRole::Unknown);
                roles.insert(v.id, role);
                if let Err(e) = upsert_vault(&tx, v) {
                    tracing::warn!(vault = %v.id, error = %e, "could not save the vault metadata");
                }
                tx.execute(
                    "INSERT INTO vault_sync (vault_id, role, cursor) VALUES (?1, ?2, 0)
                     ON CONFLICT(vault_id) DO UPDATE SET role = excluded.role",
                    params![v.id.to_string(), role.as_str()],
                )?;
                if !known_before.contains(&v.id) {
                    out.vaults_added.push((v.id, v.name.clone()));
                }
            }
            tx.execute(
                "INSERT INTO meta(key, value) VALUES(?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![VAULTS_LIST, serde_json::to_string(&input.vaults)?],
            )?;

            // 6. Use-only vaults keep no secrets on the device.
            for (v, role) in &roles {
                if !role.can_read_secrets() {
                    tx.execute(
                        "UPDATE entities SET secret = NULL, key_version = NULL, secret_hidden = 1
                         WHERE vault_id = ?1 AND secret IS NOT NULL",
                        [v.to_string()],
                    )?;
                }
            }

            // 7. Changes and departures.
            for rec in &input.changes {
                if apply_change(&tx, keys, owner, rec, &roles)? {
                    out.pulled += 1;
                }
            }
            for (id, vault) in &input.removed {
                out.removed += tx.execute(
                    "DELETE FROM entities WHERE id = ?1 AND vault_id = ?2",
                    params![id.to_string(), vault.to_string()],
                )?;
            }

            // 8. Cursors.
            let now = now_ms();
            for (v, cursor) in &input.cursors {
                tx.execute(
                    "UPDATE vault_sync SET cursor = ?2, synced_at = ?3 WHERE vault_id = ?1",
                    params![v.to_string(), cursor, now],
                )?;
            }
            tx.commit()?;
            Ok(out)
        })
        .await
    }

    /// Where an id lives in this store: kind and vault (live rows only).
    pub async fn locate_local(&self, id: Id) -> Result<Option<(EntityKind, Option<Id>)>> {
        self.call(move |c, _| {
            Ok(load_row(c, id)?
                .filter(|r| !r.deleted)
                .and_then(|r| r.kind.map(|k| (k, r.vault_id))))
        })
        .await
    }

    /// Live items of this store (optionally only those of `vault`), for
    /// planning a client-side transfer. Rows without a vault get the nil
    /// vault.
    pub async fn local_items(&self, vault: Option<Option<Id>>) -> Result<Vec<Item>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare_cached(&format!(
                "SELECT {COLUMNS} FROM entities WHERE deleted = 0 ORDER BY id"
            ))?;
            let rows = stmt
                .query_map([], map_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut out = Vec::new();
            for row in rows {
                if let Some(v) = vault
                    && row.vault_id != v
                {
                    continue;
                }
                if let Some(item) = row_item(&row)? {
                    out.push(item);
                }
            }
            Ok(out)
        })
        .await
    }

    /// Live items with their plaintext secrets (client-side transfers).
    pub async fn export_local(&self, ids: Vec<Id>) -> Result<Vec<LocalItem>> {
        self.call_keys(move |c, keys| {
            let mut out = Vec::with_capacity(ids.len());
            for id in ids {
                let Some(row) = load_row(c, id)?.filter(|r| !r.deleted) else {
                    return Err(CoreError::NotFound(format!("item {id}")));
                };
                let Some(kind) = row.kind else {
                    continue;
                };
                let secret = match row.secret.as_deref() {
                    Some(blob) => {
                        Some(keys.open(c, row.vault_id, row.key_version, kind, row.id, blob)?)
                    }
                    None => None,
                };
                let mut data: Value = serde_json::from_str(&row.data)?;
                if let Some(obj) = data.as_object_mut() {
                    obj.remove("id");
                }
                out.push(LocalItem {
                    kind,
                    id: row.id,
                    vault_id: row.vault_id,
                    data,
                    secret,
                    secret_hidden: row.secret_hidden,
                    sync_mode: row.sync_mode,
                });
            }
            Ok(out)
        })
        .await
    }

    /// Writes copied items into this store (new or replacing rows with the
    /// same id), in `vault`, sealing their secrets for their (possibly new)
    /// id. Marked dirty, so an account store uploads them.
    pub async fn import_local(
        &self,
        owner: Id,
        items: Vec<LocalItem>,
        vault: Option<Id>,
        sync_mode: Option<SyncMode>,
    ) -> Result<()> {
        self.call_keys(move |c, keys| {
            let tx = c.transaction()?;
            let now = now_ms();
            for item in items {
                if let Some(row) = load_row(&tx, item.id)?
                    && row.kind != Some(item.kind)
                {
                    return Err(CoreError::Conflict(format!(
                        "id {} is already in use",
                        item.id
                    )));
                }
                let (secret, key_version) = match &item.secret {
                    Some(plain) => {
                        let (b, kv) = keys.seal(&tx, None, item.kind, item.id, plain)?;
                        (Some(b), kv)
                    }
                    None => (None, None),
                };
                let mut data = item.data.clone();
                if let Some(obj) = data.as_object_mut() {
                    obj.remove("id");
                }
                let rev = next_rev(&tx)?;
                tx.execute(
                    "INSERT INTO entities (id, owner_id, kind, data, secret, sync_mode, rev,
                                           updated_at, deleted, dirty, vault_id, key_version,
                                           secret_hidden)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 1, ?9, ?10, 0)
                     ON CONFLICT(id) DO UPDATE SET
                        data = excluded.data, secret = excluded.secret,
                        sync_mode = excluded.sync_mode, rev = excluded.rev,
                        updated_at = excluded.updated_at, deleted = 0, dirty = 1,
                        vault_id = excluded.vault_id, key_version = excluded.key_version,
                        secret_hidden = 0",
                    params![
                        item.id.to_string(),
                        owner.to_string(),
                        item.kind.as_str(),
                        data.to_string(),
                        secret,
                        sync_mode.unwrap_or(item.sync_mode).as_str(),
                        rev,
                        now,
                        vault.map(|v| v.to_string()),
                        key_version
                    ],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    /// Replaces the public data of live items (references rewritten by a
    /// transfer), marking them dirty.
    pub async fn update_local_data(&self, updates: Vec<(Id, Value)>) -> Result<()> {
        self.call(move |c, _| {
            let tx = c.transaction()?;
            let now = now_ms();
            for (id, mut data) in updates {
                if let Some(obj) = data.as_object_mut() {
                    obj.remove("id");
                }
                let rev = next_rev(&tx)?;
                tx.execute(
                    "UPDATE entities SET data = ?2, rev = ?3, updated_at = ?4, dirty = 1
                     WHERE id = ?1 AND deleted = 0",
                    params![id.to_string(), data.to_string(), rev, now],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    /// Deletes rows for good (no tombstone): items that left a device store
    /// or an account store whose vault is gone.
    pub async fn purge_local(&self, ids: Vec<Id>) -> Result<usize> {
        self.call(move |c, _| {
            let tx = c.transaction()?;
            let mut n = 0;
            for id in ids {
                n += tx.execute("DELETE FROM entities WHERE id = ?1", [id.to_string()])?;
            }
            tx.commit()?;
            Ok(n)
        })
        .await
    }

    /// Deletes an item of any kind leaving a sync tombstone (the owner-based
    /// delete without knowing the type).
    pub async fn delete_local(&self, id: Id) -> Result<()> {
        self.call(move |c, _| {
            let tx = c.transaction()?;
            let rev = next_rev(&tx)?;
            let n = tx.execute(
                "UPDATE entities SET deleted = 1, secret = NULL, key_version = NULL, data = '{}',
                        rev = ?2, updated_at = ?3, dirty = 1, secret_hidden = 0
                 WHERE id = ?1 AND deleted = 0",
                params![id.to_string(), rev, now_ms()],
            )?;
            if n == 0 {
                return Err(CoreError::NotFound(format!("item {id}")));
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    /// Secret of an item of this store, with the kind checked (owner-free
    /// variant used by client transfers).
    pub async fn local_secret<S: serde::de::DeserializeOwned + Default + Send + 'static>(
        &self,
        kind: EntityKind,
        id: Id,
    ) -> Result<S> {
        self.call_keys(move |c, keys| match load_row(c, id)? {
            Some(row) if row.kind == Some(kind) && !row.deleted => open_secret(c, keys, &row, kind),
            _ => Err(CoreError::NotFound(format!("{} {id}", kind.as_str()))),
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_store;
    use super::*;
    use crate::model::{
        Host, HostSecret, HostSettings, SecretUpdate, SshKey, SshKeySecret, VaultCrypto, VaultKind,
    };

    const OWNER: Id = Id::nil();

    fn vault(id: Id, name: &str, role: VaultRole) -> Vault {
        Vault {
            id,
            kind: VaultKind::Shared,
            name: name.into(),
            description: String::new(),
            color: None,
            icon: None,
            owner_user_id: Some(id),
            owner_team_id: None,
            team_member_role: None,
            crypto: VaultCrypto::Server,
            key_version: 0,
            settings: VaultSettings::default(),
            rev: 1,
            created_by: id,
            created_at: 1,
            updated_at: 1,
            role: Some(role),
            owner_name: None,
            member_count: 0,
            item_counts: Default::default(),
        }
    }

    fn host(label: &str) -> Host {
        Host {
            id: Id::nil(),
            label: label.into(),
            address: format!("{label}.example.com"),
            group_id: None,
            tags: vec![],
            settings: HostSettings::default(),
            notes: String::new(),
            color: None,
            os: None,
            os_version: None,
            favorite: false,
            protocol: Default::default(),
            icon: None,
        }
    }

    fn record(
        id: Id,
        vault: Id,
        updated_at: i64,
        secret: Option<Value>,
        hidden: bool,
    ) -> SyncRecord {
        let mut h = host("srv");
        h.id = id;
        SyncRecord {
            id,
            kind: EntityKind::Host,
            data: serde_json::to_value(&h).unwrap(),
            secret,
            sync_mode: SyncMode::Synced,
            updated_at,
            deleted: false,
            rev: 5,
            vault_id: Some(vault),
            has_secret: hidden.then_some(true),
            sealed: None,
            base_rev: None,
        }
    }

    #[tokio::test]
    async fn sync_v2_apply_wipes_lost_vaults_and_hides_use_only_secrets() {
        let s = test_store();
        let personal = crate::new_id();
        let ops = crate::new_id();
        let gone = crate::new_id();
        // First round: three vaults; Ops is Use-only.
        let h1 = crate::new_id();
        let h2 = crate::new_id();
        let h3 = crate::new_id();
        let applied = s
            .apply_sync_v2(
                OWNER,
                SyncV2Apply {
                    vaults: vec![
                        vault(personal, "Personal", VaultRole::Manager),
                        vault(ops, "Ops", VaultRole::UseOnly),
                        vault(gone, "Gone", VaultRole::Editor),
                    ],
                    cursors: vec![(personal, 10), (ops, 11), (gone, 12)],
                    changes: vec![
                        record(
                            h1,
                            personal,
                            1,
                            Some(serde_json::json!({"password": "p"})),
                            false,
                        ),
                        record(h2, ops, 1, None, true),
                        record(
                            h3,
                            gone,
                            1,
                            Some(serde_json::json!({"password": "g"})),
                            false,
                        ),
                    ],
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(applied.pulled, 3);
        assert_eq!(applied.vaults_added.len(), 3);
        let roles = s.local_roles().await.unwrap();
        assert_eq!(roles[&ops], VaultRole::UseOnly);
        let r2 = s.get::<Host>(OWNER, h2).await.unwrap();
        assert!(r2.meta.secret_hidden && r2.meta.has_secret);
        let sec: HostSecret = s.secret::<Host>(OWNER, h1).await.unwrap();
        assert_eq!(sec.password.as_deref(), Some("p"));
        // A local edit in Gone that will be lost.
        let mut edited = s.get::<Host>(OWNER, h3).await.unwrap().data;
        edited.label = "edited".into();
        s.save(OWNER, edited, SecretUpdate::Keep, None)
            .await
            .unwrap();
        assert_eq!(s.dirty_summary().await.unwrap().total, 1);

        // Second round: Gone is gone, Personal is downgraded to... (Ops
        // becomes Editor and must resync; Personal stays).
        let applied = s
            .apply_sync_v2(
                OWNER,
                SyncV2Apply {
                    vaults: vec![
                        vault(personal, "Personal", VaultRole::Manager),
                        vault(ops, "Ops", VaultRole::Editor),
                    ],
                    resync: vec![ops],
                    cursors: vec![(personal, 20), (ops, 21)],
                    changes: vec![record(
                        h2,
                        ops,
                        2,
                        Some(serde_json::json!({"password": "now visible"})),
                        false,
                    )],
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(applied.vaults_lost, vec![(gone, "Gone".to_string())]);
        assert_eq!(applied.discarded.get(&gone), Some(&("Gone".to_string(), 1)));
        assert!(s.get::<Host>(OWNER, h3).await.is_err());
        let sec: HostSecret = s.secret::<Host>(OWNER, h2).await.unwrap();
        assert_eq!(sec.password.as_deref(), Some("now visible"));
        assert!(!s.get::<Host>(OWNER, h2).await.unwrap().meta.secret_hidden);
        let cursors: HashMap<Id, i64> = s
            .local_vaults()
            .await
            .unwrap()
            .into_iter()
            .map(|v| (v.vault_id, v.cursor))
            .collect();
        assert_eq!(cursors[&ops], 21);
        assert_eq!(s.local_vault_list().await.unwrap().len(), 2);

        // Third round: Personal goes down to Use-only (made up, but the
        // rule is per vault): its secrets are wiped locally.
        s.apply_sync_v2(
            OWNER,
            SyncV2Apply {
                vaults: vec![
                    vault(personal, "Personal", VaultRole::UseOnly),
                    vault(ops, "Ops", VaultRole::Editor),
                ],
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let r1 = s.get::<Host>(OWNER, h1).await.unwrap();
        assert!(r1.meta.secret_hidden);
        let sec: HostSecret = s.secret::<Host>(OWNER, h1).await.unwrap();
        assert!(sec.password.is_none());
    }

    #[tokio::test]
    async fn rejected_read_only_changes_are_dropped_and_counted() {
        let s = test_store();
        let ops = crate::new_id();
        s.apply_sync_v2(
            OWNER,
            SyncV2Apply {
                vaults: vec![vault(ops, "Ops", VaultRole::Editor)],
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let rec = s
            .save_local(OWNER, Some(ops), host("a"), SecretUpdate::Keep, None)
            .await
            .unwrap();
        let invalid = s
            .save_local(OWNER, Some(ops), host("b"), SecretUpdate::Keep, None)
            .await
            .unwrap();
        let dirty = s.dirty_records_v2().await.unwrap();
        assert_eq!(dirty.len(), 2);
        assert!(dirty.iter().all(|r| r.vault_id == Some(ops)));
        let pushed = dirty.iter().map(|r| (r.id, r.updated_at)).collect();
        let applied = s
            .apply_sync_v2(
                OWNER,
                SyncV2Apply {
                    pushed,
                    vaults: vec![vault(ops, "Ops", VaultRole::UseOnly)],
                    rejected: vec![
                        SyncRejection {
                            id: rec.data.id,
                            code: codes::VAULT_READ_ONLY.into(),
                            message: "no".into(),
                        },
                        SyncRejection {
                            id: invalid.data.id,
                            code: "invalid".into(),
                            message: "bad".into(),
                        },
                    ],
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(applied.discarded.get(&ops), Some(&("Ops".to_string(), 1)));
        assert_eq!(applied.kept.len(), 1);
        assert!(s.get::<Host>(OWNER, rec.data.id).await.is_err());
        assert_eq!(s.dirty_summary().await.unwrap().total, 1);
    }

    #[tokio::test]
    async fn adopt_personal_and_copy_between_stores() {
        let a = test_store();
        let personal = crate::new_id();
        let k = a
            .save(
                OWNER,
                SshKey {
                    id: Id::nil(),
                    label: "k".into(),
                    algorithm: "ssh-ed25519".into(),
                    public_key: "ssh-ed25519 AAAA".into(),
                    fingerprint: "SHA256:x".into(),
                    comment: String::new(),
                    has_passphrase: false,
                    certificate: None,
                },
                SecretUpdate::Set(SshKeySecret {
                    private_key: Some("PRIVATE".into()),
                    passphrase: None,
                }),
                None,
            )
            .await
            .unwrap();
        a.adopt_personal_vault(personal, Some(42)).await.unwrap();
        assert_eq!(
            a.locate_local(k.data.id).await.unwrap(),
            Some((EntityKind::Key, Some(personal)))
        );
        assert_eq!(a.local_vaults().await.unwrap()[0].cursor, 42);
        // Copy with a new id into another store (same device key): the
        // secret is sealed again for the new id.
        let b = Store::open_in_memory(a.master_key().clone()).unwrap();
        let mut items = a.export_local(vec![k.data.id]).await.unwrap();
        let new = crate::new_id();
        items[0].id = new;
        b.import_local(OWNER, items, None, Some(SyncMode::DeviceOnly))
            .await
            .unwrap();
        let sec: SshKeySecret = b.secret::<SshKey>(OWNER, new).await.unwrap();
        assert_eq!(sec.private_key.as_deref(), Some("PRIVATE"));
        assert_eq!(
            b.get::<SshKey>(OWNER, new).await.unwrap().meta.sync_mode,
            SyncMode::DeviceOnly
        );
        assert_eq!(a.purge_local(vec![k.data.id]).await.unwrap(), 1);
        assert!(a.locate_local(k.data.id).await.unwrap().is_none());
    }
}

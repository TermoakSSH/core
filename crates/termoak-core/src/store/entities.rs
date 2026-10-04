//! Generic store of syncable entities.

use rusqlite::{Connection, OptionalExtension, params};

use super::{Store, next_rev, parse_id};
use crate::crypto::MasterKey;
use crate::error::{CoreError, Result};
use crate::model::{Entity, EntityKind, Record, RecordMeta, SecretUpdate, SyncMode, SyncRecord};
use crate::time::now_ms;
use crate::{Id, new_id};

struct Row {
    id: Id,
    owner_id: Id,
    data: String,
    secret: Option<Vec<u8>>,
    sync_mode: SyncMode,
    rev: i64,
    updated_at: i64,
    deleted: bool,
}

const COLUMNS: &str = "id, owner_id, data, secret, sync_mode, rev, updated_at, deleted";

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
    })
}

fn to_record<T: Entity>(row: Row) -> Result<Record<T>> {
    let mut data: T = serde_json::from_str(&row.data)?;
    data.set_id(row.id);
    Ok(Record {
        data,
        meta: RecordMeta {
            owner_id: row.owner_id,
            sync_mode: row.sync_mode,
            rev: row.rev,
            updated_at: row.updated_at,
            deleted: row.deleted,
            has_secret: row.secret.is_some(),
        },
    })
}

fn secret_aad(kind: EntityKind, id: Id) -> Vec<u8> {
    format!(
        "{}:{}:{}",
        crate::crypto::LEGACY_AAD_PREFIX,
        kind.as_str(),
        id
    )
    .into_bytes()
}

fn load_row(conn: &Connection, id: Id) -> Result<Option<(Row, EntityKind)>> {
    Ok(conn
        .query_row(
            &format!("SELECT {COLUMNS}, kind FROM entities WHERE id = ?1"),
            [id.to_string()],
            |r| {
                let row = map_row(r)?;
                let kind: String = r.get(8)?;
                Ok((row, kind))
            },
        )
        .optional()?
        .and_then(|(row, kind)| EntityKind::parse(&kind).map(|k| (row, k))))
}

fn open_secret<S: serde::de::DeserializeOwned + Default>(
    key: &MasterKey,
    kind: EntityKind,
    id: Id,
    blob: Option<&[u8]>,
) -> Result<S> {
    match blob {
        None => Ok(S::default()),
        Some(blob) => {
            let plain = key.open(blob, &secret_aad(kind, id))?;
            Ok(serde_json::from_slice(&plain)?)
        }
    }
}

impl Store {
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
            rows.into_iter().map(to_record::<T>).collect()
        })
        .await
    }

    /// Gets a live entity.
    pub async fn get<T: Entity>(&self, owner: Id, id: Id) -> Result<Record<T>> {
        self.call(move |c, _| match load_row(c, id)? {
            Some((row, kind)) if kind == T::KIND && row.owner_id == owner && !row.deleted => {
                to_record(row)
            }
            _ => Err(CoreError::NotFound(format!("{} {id}", T::KIND.as_str()))),
        })
        .await
    }

    /// Decrypts an entity's secret (empty if it has none).
    pub async fn secret<T: Entity>(&self, owner: Id, id: Id) -> Result<T::Secret> {
        self.call(move |c, key| match load_row(c, id)? {
            Some((row, kind)) if kind == T::KIND && row.owner_id == owner && !row.deleted => {
                open_secret(key, kind, id, row.secret.as_deref())
            }
            _ => Err(CoreError::NotFound(format!("{} {id}", T::KIND.as_str()))),
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
        self.call(move |c, key| {
            let tx = c.transaction()?;
            let id = data.id();
            let existing = load_row(&tx, id)?;
            if let Some((row, kind)) = &existing
                && (row.owner_id != owner || *kind != T::KIND) {
                    return Err(CoreError::Conflict(format!("id {id} is already in use")));
                }
            let mode = sync_mode
                .or_else(|| existing.as_ref().map(|(r, _)| r.sync_mode))
                .unwrap_or_default();
            let secret_blob = match secret {
                SecretUpdate::Keep => existing.as_ref().and_then(|(r, _)| r.secret.clone()),
                SecretUpdate::Clear => None,
                SecretUpdate::Set(s) => {
                    let json = zeroize::Zeroizing::new(serde_json::to_vec(&s)?);
                    Some(key.seal(&json, &secret_aad(T::KIND, id))?)
                }
            };
            let rev = next_rev(&tx)?;
            let now = now_ms();
            let json = serde_json::to_string(&data)?;
            tx.execute(
                "INSERT INTO entities (id, owner_id, kind, data, secret, sync_mode, rev, updated_at, deleted, dirty)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 1)
                 ON CONFLICT(id) DO UPDATE SET
                    data = excluded.data, secret = excluded.secret, sync_mode = excluded.sync_mode,
                    rev = excluded.rev, updated_at = excluded.updated_at, deleted = 0, dirty = 1",
                params![
                    id.to_string(),
                    owner.to_string(),
                    T::KIND.as_str(),
                    json,
                    secret_blob,
                    mode.as_str(),
                    rev,
                    now
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
                },
            })
        })
        .await
    }

    /// Deletes an entity (leaves a tombstone so the deletion syncs).
    pub async fn delete<T: Entity>(&self, owner: Id, id: Id) -> Result<()> {
        self.call(move |c, _| {
            let tx = c.transaction()?;
            match load_row(&tx, id)? {
                Some((row, kind)) if kind == T::KIND && row.owner_id == owner && !row.deleted => {}
                _ => return Err(CoreError::NotFound(format!("{} {id}", T::KIND.as_str()))),
            }
            let rev = next_rev(&tx)?;
            tx.execute(
                "UPDATE entities SET deleted = 1, secret = NULL, data = '{}', rev = ?2,
                        updated_at = ?3, dirty = 1
                 WHERE id = ?1",
                params![id.to_string(), rev, now_ms()],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
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

    /// Changes after `since` to send to another device. Never includes
    /// `device_only` records. With `with_secrets`, attaches the decrypted
    /// secrets (only to send them over TLS to the user themselves).
    pub async fn changes_since(
        &self,
        owner: Id,
        since: i64,
        with_secrets: bool,
    ) -> Result<Vec<SyncRecord>> {
        self.call(move |c, key| {
            let mut stmt = c.prepare_cached(&format!(
                "SELECT {COLUMNS}, kind FROM entities
                 WHERE owner_id = ?1 AND rev > ?2 AND sync_mode = 'synced'
                 ORDER BY rev"
            ))?;
            let rows = stmt
                .query_map(params![owner.to_string(), since], |r| {
                    Ok((map_row(r)?, r.get::<_, String>(8)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut out = Vec::with_capacity(rows.len());
            for (row, kind) in rows {
                let Some(kind) = EntityKind::parse(&kind) else {
                    continue;
                };
                out.push(row_to_sync(key, row, kind, with_secrets)?);
            }
            Ok(out)
        })
        .await
    }

    /// Locally modified records waiting to be uploaded (client).
    pub async fn dirty_records(&self) -> Result<Vec<SyncRecord>> {
        self.call(move |c, key| {
            let mut stmt = c.prepare_cached(&format!(
                "SELECT {COLUMNS}, kind FROM entities
                 WHERE dirty = 1 AND sync_mode = 'synced' ORDER BY rev"
            ))?;
            let rows = stmt
                .query_map([], |r| Ok((map_row(r)?, r.get::<_, String>(8)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut out = Vec::with_capacity(rows.len());
            for (row, kind) in rows {
                let Some(kind) = EntityKind::parse(&kind) else {
                    continue;
                };
                out.push(row_to_sync(key, row, kind, true)?);
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
    /// from the server are not marked dirty either.
    ///
    /// Returns the applied records (with their new revision).
    pub async fn apply_remote(
        &self,
        owner: Id,
        records: Vec<SyncRecord>,
    ) -> Result<Vec<SyncRecord>> {
        self.call(move |c, key| {
            let tx = c.transaction()?;
            let mut applied = Vec::new();
            for mut rec in records {
                if rec.sync_mode == SyncMode::DeviceOnly {
                    continue;
                }
                let existing = load_row(&tx, rec.id)?;
                if let Some((row, kind)) = &existing {
                    if row.owner_id != owner || *kind != rec.kind {
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
                let secret_blob = if rec.deleted {
                    None
                } else {
                    match &rec.secret {
                        None => existing.as_ref().and_then(|(r, _)| r.secret.clone()),
                        Some(serde_json::Value::Null) => None,
                        Some(v) => {
                            let json = zeroize::Zeroizing::new(serde_json::to_vec(v)?);
                            Some(key.seal(&json, &secret_aad(rec.kind, rec.id))?)
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
                    "INSERT INTO entities (id, owner_id, kind, data, secret, sync_mode, rev, updated_at, deleted, dirty)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'synced', ?6, ?7, ?8, 0)
                     ON CONFLICT(id) DO UPDATE SET
                        data = excluded.data, secret = excluded.secret, rev = excluded.rev,
                        updated_at = excluded.updated_at, deleted = excluded.deleted, dirty = 0",
                    params![
                        rec.id.to_string(),
                        owner.to_string(),
                        rec.kind.as_str(),
                        data,
                        secret_blob,
                        rev,
                        rec.updated_at,
                        rec.deleted as i64
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
}

fn row_to_sync(
    key: &MasterKey,
    row: Row,
    kind: EntityKind,
    with_secrets: bool,
) -> Result<SyncRecord> {
    let secret = if with_secrets && !row.deleted {
        match row.secret.as_deref() {
            Some(blob) => {
                let plain = key.open(blob, &secret_aad(kind, row.id))?;
                Some(serde_json::from_slice(&plain)?)
            }
            None => None,
        }
    } else {
        None
    };
    Ok(SyncRecord {
        id: row.id,
        kind,
        data: serde_json::from_str(&row.data)?,
        secret,
        sync_mode: row.sync_mode,
        updated_at: row.updated_at,
        deleted: row.deleted,
        rev: row.rev,
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

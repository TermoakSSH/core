//! Sync between a local store and the server.
//!
//! Two protocols:
//! - **v2** (`POST /api/v1/vaults/sync`, servers with `features.sync_v2`):
//!   per-vault cursors, the authoritative list of the vaults the account can
//!   access (a vault that disappears is wiped locally), departures of moved
//!   items and explicit rejections. Use-only vaults never bring secrets.
//! - **legacy** (`POST /api/v1/sync`, older servers): one global revision
//!   and one implicit personal vault.
//!
//! In both, the client sends its pending changes (`dirty`) and the server
//! applies them (last writer wins) and returns everything newer.
//! `device_only` records never leave the device.

use serde::{Deserialize, Serialize};
use termoak_core::model::{EntityKind, SyncRecord, Vault, VaultRole};
use termoak_core::store::{SyncRejection, SyncV2Apply, SyncWarning};
use termoak_core::{Id, Store};

use crate::LOCAL_OWNER;
use crate::api::ApiClient;
use crate::error::Result;

const REV_KEY: &str = "sync.rev";

/// Most rounds of a single sync (paging with `more`).
const MAX_ROUNDS: usize = 1000;

/// What a store has of a vault (sync v2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultCursor {
    pub vault_id: Id,
    #[serde(default)]
    pub cursor: i64,
    /// The role this store last saw (the server answers `resync` when it
    /// changed in a way that matters).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<VaultRole>,
}

/// `POST /api/v1/vaults/sync` request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncV2Request {
    pub vaults: Vec<VaultCursor>,
    pub changes: Vec<SyncRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// An item left a vault (moved, or the vault lost it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemovedRecord {
    pub id: Id,
    pub vault_id: Id,
    #[serde(default)]
    pub kind: Option<EntityKind>,
    #[serde(default)]
    pub rev: i64,
}

/// `POST /api/v1/vaults/sync` response.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncV2Response {
    #[serde(default)]
    pub vaults: Vec<Vault>,
    #[serde(default)]
    pub cursors: Vec<VaultCursor>,
    #[serde(default)]
    pub changes: Vec<SyncRecord>,
    #[serde(default)]
    pub removed: Vec<RemovedRecord>,
    #[serde(default)]
    pub accepted: Vec<Id>,
    #[serde(default)]
    pub rejected: Vec<SyncRejection>,
    #[serde(default)]
    pub warnings: Vec<SyncWarning>,
    #[serde(default)]
    pub resync: Vec<Id>,
    #[serde(default)]
    pub more: bool,
}

/// A vault by id and name (in sync reports).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VaultRef {
    pub id: Id,
    pub name: String,
}

/// Local changes that were lost in a vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiscardedChanges {
    pub vault_id: Id,
    pub vault_name: String,
    pub count: usize,
}

/// Result of a sync. Show a notice when `discarded`, `vaults_added` or
/// `vaults_lost` is not empty ("You no longer have access to Ops; 2
/// unsynced changes were discarded").
#[derive(Debug, Clone, Default, Serialize)]
pub struct SyncReport {
    pub pushed: usize,
    pub pulled: usize,
    /// Legacy: the server revision. v2: the highest vault cursor.
    pub rev: i64,
    /// Items removed because they left their vault.
    pub removed: usize,
    pub discarded: Vec<DiscardedChanges>,
    pub vaults_added: Vec<VaultRef>,
    pub vaults_lost: Vec<VaultRef>,
    /// Rejected changes kept locally (still pending).
    pub rejected: Vec<SyncRejection>,
    pub warnings: Vec<SyncWarning>,
    /// `v2` or `legacy`.
    pub protocol: &'static str,
}

impl SyncReport {
    /// Total local changes lost.
    pub fn discarded_total(&self) -> usize {
        self.discarded.iter().map(|d| d.count).sum()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    /// Asks the server (`/info`) on every round.
    Auto,
    Legacy,
    V2,
}

/// Sync engine of one store and one server account.
#[derive(Clone)]
pub struct SyncEngine {
    store: Store,
    api: ApiClient,
    protocol: Protocol,
    /// The account's personal vault (its user id), if known.
    personal: Option<Id>,
}

impl SyncEngine {
    /// Engine that picks the protocol from the server's `/info`.
    pub fn new(store: Store, api: ApiClient) -> Self {
        Self {
            store,
            api,
            protocol: Protocol::Auto,
            personal: None,
        }
    }

    /// Legacy protocol (servers without vaults).
    pub fn legacy(store: Store, api: ApiClient) -> Self {
        Self {
            protocol: Protocol::Legacy,
            ..Self::new(store, api)
        }
    }

    /// Sync v2. `personal` is the user id (asked to `/me` when `None`).
    pub fn v2(store: Store, api: ApiClient, personal: Option<Id>) -> Self {
        Self {
            protocol: Protocol::V2,
            personal,
            ..Self::new(store, api)
        }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// One full round of upload and download.
    pub async fn sync_once(&self) -> Result<SyncReport> {
        // The device store ("This device" items) never syncs: an engine
        // made with it by older code would upload device items.
        if self
            .store
            .meta_get(crate::layout::LAYOUT_VERSION_KEY)
            .await?
            .is_some()
            && self
                .store
                .meta_get(crate::accounts::ACCOUNT_ID_KEY)
                .await?
                .is_none()
        {
            return Err(crate::error::ClientError::Invalid(
                "the device store does not sync: sync an account (Workspace::current)".into(),
            ));
        }
        let v2 = match self.protocol {
            Protocol::Legacy => false,
            Protocol::V2 => true,
            Protocol::Auto => {
                let info = self.api.info().await?;
                info["features"]["sync_v2"].as_bool().unwrap_or(false)
            }
        };
        if v2 {
            self.sync_v2().await
        } else {
            self.sync_legacy().await
        }
    }

    async fn sync_legacy(&self) -> Result<SyncReport> {
        let since: i64 = self
            .store
            .meta_get(REV_KEY)
            .await?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let dirty = self.store.dirty_records().await?;
        let pushed_ids: Vec<_> = dirty.iter().map(|r| (r.id, r.updated_at)).collect();
        let resp = self.api.sync(since, dirty).await?;
        // Whatever the server rejected as older will be replaced by the server's version.
        self.store.mark_clean(pushed_ids.clone()).await?;
        let pulled = resp.changes.len();
        self.store.apply_remote(LOCAL_OWNER, resp.changes).await?;
        self.store.meta_set(REV_KEY, &resp.rev.to_string()).await?;
        Ok(SyncReport {
            pushed: pushed_ids.len(),
            pulled,
            rev: resp.rev,
            protocol: "legacy",
            ..Default::default()
        })
    }

    async fn sync_v2(&self) -> Result<SyncReport> {
        let personal = match self.personal {
            Some(p) => p,
            None => self.api.me().await?.id,
        };
        // First v2 sync after an upgrade: rows without a vault are personal,
        // and the old global revision is the personal vault's cursor.
        let fresh = self.store.local_vaults().await?.is_empty();
        let legacy_cursor = if fresh {
            self.store
                .meta_get(REV_KEY)
                .await?
                .and_then(|v| v.parse::<i64>().ok())
        } else {
            None
        };
        self.store
            .adopt_personal_vault(personal, legacy_cursor)
            .await?;
        let mut report = SyncReport {
            protocol: "v2",
            ..Default::default()
        };
        let mut first = true;
        for _ in 0..MAX_ROUNDS {
            // Pending changes go up once; later rounds only page down.
            let changes = if first {
                self.store.dirty_records_v2().await?
            } else {
                Vec::new()
            };
            first = false;
            let pushed: Vec<(Id, i64)> = changes.iter().map(|r| (r.id, r.updated_at)).collect();
            let vaults = self
                .store
                .local_vaults()
                .await?
                .into_iter()
                .map(|v| VaultCursor {
                    vault_id: v.vault_id,
                    cursor: v.cursor,
                    role: Some(v.role),
                })
                .collect();
            let resp = self
                .api
                .sync_v2(&SyncV2Request {
                    vaults,
                    changes,
                    limit: None,
                })
                .await?;
            report.pushed += pushed.len();
            report.rev = report
                .rev
                .max(resp.cursors.iter().map(|c| c.cursor).max().unwrap_or(0));
            report.warnings.extend(resp.warnings.iter().cloned());
            let more = resp.more;
            let applied = self
                .store
                .apply_sync_v2(
                    LOCAL_OWNER,
                    SyncV2Apply {
                        pushed,
                        accepted: resp.accepted,
                        rejected: resp.rejected,
                        vaults: resp.vaults,
                        cursors: resp
                            .cursors
                            .iter()
                            .map(|c| (c.vault_id, c.cursor))
                            .collect(),
                        changes: resp.changes,
                        removed: resp.removed.iter().map(|r| (r.id, r.vault_id)).collect(),
                        resync: resp.resync,
                    },
                )
                .await?;
            report.pulled += applied.pulled;
            report.removed += applied.removed;
            report.rejected.extend(applied.kept);
            for (vault_id, (vault_name, count)) in applied.discarded {
                match report.discarded.iter_mut().find(|d| d.vault_id == vault_id) {
                    Some(d) => d.count += count,
                    None => report.discarded.push(DiscardedChanges {
                        vault_id,
                        vault_name,
                        count,
                    }),
                }
            }
            for (id, name) in applied.vaults_added {
                report.vaults_added.push(VaultRef { id, name });
            }
            for (id, name) in applied.vaults_lost {
                report.vaults_lost.push(VaultRef { id, name });
            }
            if !more {
                break;
            }
        }
        // The personal vault is never "new" to the user, and nothing is new
        // on the first sync of a store.
        if fresh {
            report.vaults_added.clear();
        } else {
            report.vaults_added.retain(|v| v.id != personal);
        }
        Ok(report)
    }

    /// Forgets the revision (legacy) and the vault cursors (v2) so
    /// everything is downloaded again.
    pub async fn reset(&self) -> Result<()> {
        self.store.meta_set(REV_KEY, "0").await?;
        self.store
            .call(|c, _| {
                c.execute("UPDATE vault_sync SET cursor = 0", [])?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Syncs periodically until the `JoinHandle` is dropped.
    pub fn spawn_periodic(self, every: std::time::Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            loop {
                tick.tick().await;
                if let Err(e) = self.sync_once().await {
                    tracing::warn!(error = %e, "sync failed");
                }
            }
        })
    }
}

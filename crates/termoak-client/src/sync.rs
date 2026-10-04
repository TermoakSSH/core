//! Sync between the local database and the server.
//!
//! Protocol: the client sends its pending changes (`dirty`) and the last
//! revision it received; the server applies them (last writer wins) and
//! returns everything newer. `device_only` records never leave the device.

use termoak_core::Store;

use crate::LOCAL_OWNER;
use crate::api::ApiClient;
use crate::error::Result;

const REV_KEY: &str = "sync.rev";

/// Result of a sync.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SyncReport {
    pub pushed: usize,
    pub pulled: usize,
    pub rev: i64,
}

/// Sync engine.
#[derive(Clone)]
pub struct SyncEngine {
    store: Store,
    api: ApiClient,
}

impl SyncEngine {
    pub fn new(store: Store, api: ApiClient) -> Self {
        Self { store, api }
    }

    /// One full round of upload and download.
    pub async fn sync_once(&self) -> Result<SyncReport> {
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
        })
    }

    /// Forgets the revision so everything is downloaded again.
    pub async fn reset(&self) -> Result<()> {
        self.store.meta_set(REV_KEY, "0").await?;
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

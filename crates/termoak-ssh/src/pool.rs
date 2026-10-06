//! Reusable connections per (user, host). Used by the AI and the server's SFTP
//! so they do not open a new connection for every command. Server only: the
//! hosts are resolved inside their vault with the user's access.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use termoak_core::model::Host;
use termoak_core::store::SecretUse;
use termoak_core::{Id, Store};

use crate::client::{ConnectOptions, Connection};
use crate::error::Result;
use crate::verify::{HostKeyPolicy, StoreVerifier};

struct Slot {
    conn: Option<Arc<Connection>>,
    last_used: Instant,
    /// Vault of the host when the connection was opened.
    vault: Option<Id>,
}

type SlotMap = HashMap<(Id, Id), Arc<tokio::sync::Mutex<Slot>>>;

/// Connection pool.
pub struct ConnectionPool {
    store: Store,
    policy: HostKeyPolicy,
    idle: Duration,
    slots: Mutex<SlotMap>,
}

impl ConnectionPool {
    /// Creates the pool and a task that closes idle connections.
    pub fn new(store: Store, policy: HostKeyPolicy, idle: Duration) -> Arc<Self> {
        let pool = Arc::new(Self {
            store,
            policy,
            idle,
            slots: Mutex::new(HashMap::new()),
        });
        let weak = Arc::downgrade(&pool);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                let Some(pool) = weak.upgrade() else { break };
                pool.reap().await;
            }
        });
        pool
    }

    /// Live connection of `user` to `host_id` (reused or opened). Checks the
    /// user's access to the host's vault on every call (cached roles): no
    /// access, or a host that moved to another vault, means no reuse.
    pub async fn get(&self, user: Id, host_id: Id) -> Result<Arc<Connection>> {
        let access = self.store.vault_access(user).await?;
        let vault = self.store.vault_of::<Host>(&access, host_id).await?;
        let slot = self
            .slots
            .lock()
            .entry((user, host_id))
            .or_insert_with(|| {
                Arc::new(tokio::sync::Mutex::new(Slot {
                    conn: None,
                    last_used: Instant::now(),
                    vault: None,
                }))
            })
            .clone();
        let mut slot = slot.lock().await;
        slot.last_used = Instant::now();
        if let Some(conn) = &slot.conn
            && !conn.is_closed()
            && slot.vault == Some(vault)
        {
            return Ok(conn.clone());
        }
        if let Some(old) = slot.conn.take() {
            old.disconnect().await;
        }
        let resolved = self
            .store
            .resolve_in(&access, host_id, SecretUse::Server)
            .await?;
        let opts = ConnectOptions::new(Arc::new(StoreVerifier::for_host(
            self.store.clone(),
            access,
            vault,
            self.policy,
            None,
        )));
        let conn = Connection::connect(&resolved, &opts).await?;
        slot.conn = Some(conn.clone());
        slot.vault = Some(vault);
        Ok(conn)
    }

    /// Forgets the connection (e.g. after an error).
    pub async fn invalidate(&self, owner: Id, host_id: Id) {
        let slot = self.slots.lock().get(&(owner, host_id)).cloned();
        if let Some(slot) = slot {
            let mut s = slot.lock().await;
            if let Some(conn) = s.conn.take() {
                conn.disconnect().await;
            }
        }
    }

    /// Closes the connections to hosts of `vault` (of one user, or of
    /// everyone): access was revoked or the vault is gone.
    pub async fn invalidate_vault(&self, vault: Id, user: Option<Id>) {
        let slots: Vec<_> = self
            .slots
            .lock()
            .iter()
            .filter(|((u, _), _)| user.is_none_or(|x| x == *u))
            .map(|(_, s)| s.clone())
            .collect();
        for slot in slots {
            let mut s = slot.lock().await;
            if s.vault == Some(vault)
                && let Some(conn) = s.conn.take()
            {
                conn.disconnect().await;
            }
        }
    }

    /// Open connections (tests).
    pub fn open_count(&self) -> usize {
        self.slots
            .lock()
            .values()
            .filter(|s| {
                s.try_lock()
                    .map(|s| s.conn.as_ref().is_some_and(|c| !c.is_closed()))
                    .unwrap_or(true)
            })
            .count()
    }

    async fn reap(&self) {
        let slots: Vec<_> = self.slots.lock().values().cloned().collect();
        for slot in slots {
            let Ok(mut s) = slot.try_lock() else { continue };
            if s.last_used.elapsed() > self.idle
                && let Some(conn) = s.conn.take()
            {
                conn.disconnect().await;
            }
        }
    }
}

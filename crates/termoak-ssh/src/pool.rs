//! Reusable connections per (user, host). Used by the AI and the server's SFTP
//! so they do not open a new connection for every command.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use termoak_core::{Id, Store};

use crate::client::{ConnectOptions, Connection};
use crate::error::Result;
use crate::verify::{HostKeyPolicy, StoreVerifier};

struct Slot {
    conn: Option<Arc<Connection>>,
    last_used: Instant,
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

    /// Live connection to `host_id` (reused or opened).
    pub async fn get(&self, owner: Id, host_id: Id) -> Result<Arc<Connection>> {
        let slot = self
            .slots
            .lock()
            .entry((owner, host_id))
            .or_insert_with(|| {
                Arc::new(tokio::sync::Mutex::new(Slot {
                    conn: None,
                    last_used: Instant::now(),
                }))
            })
            .clone();
        let mut slot = slot.lock().await;
        slot.last_used = Instant::now();
        if let Some(conn) = &slot.conn
            && !conn.is_closed()
        {
            return Ok(conn.clone());
        }
        let resolved = self.store.resolve_host(owner, host_id).await?;
        let opts = ConnectOptions::new(Arc::new(StoreVerifier {
            store: self.store.clone(),
            owner,
            policy: self.policy,
            prompter: None,
        }));
        let conn = Connection::connect(&resolved, &opts).await?;
        slot.conn = Some(conn.clone());
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

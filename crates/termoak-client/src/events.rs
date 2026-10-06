//! Per-account events WebSocket (`/api/v1/events/ws`) with reconnect and
//! backoff. Every event is forwarded with `"account_id"` added, and `vault`
//! events (`changed`, `access`) trigger a sync of that account.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use serde_json::Value;
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite::Message;

use crate::accounts::Account;

/// Longest wait between reconnections.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Adds `"account_id"` to an event (objects only).
pub fn tag_event(mut v: Value, account: termoak_core::Id) -> Value {
    if let Some(obj) = v.as_object_mut() {
        obj.insert("account_id".into(), Value::String(account.to_string()));
    }
    v
}

/// Whether an event asks for a sync (`{"type": "vault", ...}`).
pub fn wants_sync(v: &Value) -> bool {
    v["type"] == "vault"
}

/// Starts (or restarts) the events task of `account`, sending events to
/// `sink`.
pub(crate) fn start(account: &Arc<Account>, sink: broadcast::Sender<Value>) {
    let weak = Arc::downgrade(account);
    let handle = tokio::spawn(async move {
        let mut backoff = Duration::from_secs(1);
        loop {
            let Some(acc) = weak.upgrade() else { return };
            if !acc.is_signed_in() {
                return;
            }
            let api = acc.api.clone();
            let id = acc.id;
            drop(acc);
            match api.websocket("/api/v1/events/ws").await {
                Ok(ws) => {
                    backoff = Duration::from_secs(1);
                    let (_sink, mut stream) = ws.split();
                    while let Some(msg) = stream.next().await {
                        let text = match msg {
                            Ok(Message::Text(t)) => t.to_string(),
                            Ok(Message::Close(_)) | Err(_) => break,
                            Ok(_) => continue,
                        };
                        let Ok(v) = serde_json::from_str::<Value>(&text) else {
                            continue;
                        };
                        if wants_sync(&v)
                            && let Some(acc) = weak.upgrade()
                        {
                            acc.sync_soon();
                        }
                        let _ = sink.send(tag_event(v, id));
                    }
                }
                Err(e) => {
                    tracing::debug!(account = %id, error = %e, "events WebSocket failed");
                    if matches!(
                        e,
                        crate::ClientError::SessionExpired | crate::ClientError::NotLoggedIn
                    ) {
                        return;
                    }
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    });
    if let Some(old) = account.events.lock().replace(handle) {
        old.abort();
    }
}

/// Stops the events task of `account`.
pub(crate) fn stop(account: &Account) {
    if let Some(h) = account.events.lock().take() {
        h.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_get_the_account() {
        let id = termoak_core::new_id();
        let v = tag_event(serde_json::json!({"type": "vault", "event": "changed"}), id);
        assert_eq!(v["account_id"], id.to_string());
        assert!(wants_sync(&v));
        assert!(!wants_sync(&serde_json::json!({"type": "ai"})));
    }
}

//! Per-account events WebSocket (`/api/v1/events/ws`) with reconnect and
//! backoff. Every event is forwarded with `"account_id"` added, and `vault`
//! events (`changed`, `access`) trigger a sync of that account.
//!
//! With a security key signer set ([`SignerSlot`]), the socket declares
//! `features=security_keys` and answers the server's
//! `security_key_request`s (server sessions with FIDO2 keys,
//! docs/SSH-PRO.md §5).

use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use parking_lot::RwLock;
use serde_json::Value;
use termoak_ssh::sk::{SecurityKeySigner, wire};
use tokio::sync::{broadcast, mpsc};
use tokio_tungstenite::tungstenite::Message;

use crate::accounts::Account;

/// The security key signer the events sockets answer with (`None`: they
/// do not declare the feature).
pub type SignerSlot = Arc<RwLock<Option<Arc<dyn SecurityKeySigner>>>>;

/// Path of the events socket (with `features=security_keys` when this
/// device can sign).
pub fn events_path(can_sign: bool) -> String {
    // `roles_v2,policies` (0.7 phase 4b): roles and policies as this core
    // understands them (browsers cannot set headers on a WebSocket).
    if can_sign {
        format!(
            "/api/v1/events/ws?features=roles_v2,policies,{}",
            wire::FEATURE
        )
    } else {
        "/api/v1/events/ws?features=roles_v2,policies".to_string()
    }
}

/// Answers a `security_key_request` event with `signer` (the response to
/// send back), or `None` if `v` is not one. An invalid request is answered
/// with an `invalid` error.
pub async fn answer_security_key(signer: &dyn SecurityKeySigner, v: &Value) -> Option<Value> {
    if v["type"] != wire::REQUEST {
        return None;
    }
    let id = v["request_id"].as_str().unwrap_or_default().to_string();
    let result = match wire::parse_request(v) {
        Ok((_, req)) => signer.sign(req).await,
        Err(e) => Err(e),
    };
    Some(wire::response(&id, &result))
}

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
pub(crate) fn start(account: &Arc<Account>, sink: broadcast::Sender<Value>, signer: SignerSlot) {
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
            let can_sign = signer.read().is_some();
            match api.websocket(&events_path(can_sign)).await {
                Ok(ws) => {
                    backoff = Duration::from_secs(1);
                    let (mut out, mut stream) = ws.split();
                    let (tx, mut replies) = mpsc::unbounded_channel::<Value>();
                    loop {
                        let msg = tokio::select! {
                            m = stream.next() => match m {
                                Some(m) => m,
                                None => break,
                            },
                            Some(reply) = replies.recv() => {
                                if out.send(Message::Text(reply.to_string().into())).await.is_err() {
                                    break;
                                }
                                continue;
                            }
                        };
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
                        // The device signs while the socket keeps reading.
                        if v["type"] == wire::REQUEST
                            && let Some(s) = signer.read().clone()
                        {
                            let (tx, v) = (tx.clone(), v.clone());
                            tokio::spawn(async move {
                                if let Some(reply) = answer_security_key(s.as_ref(), &v).await {
                                    let _ = tx.send(reply);
                                }
                            });
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

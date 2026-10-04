//! Terminals that live on the server, seen from a client (WebSocket).
//!
//! If the connection to the server drops (it restarts, the network goes
//! away...), it reconnects by itself: the session stays alive there. Meanwhile
//! it emits [`RemoteEvent::Reconnecting`] and, once back,
//! [`RemoteEvent::Resync`] followed by the full history.

use std::time::Duration;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use termoak_core::Id;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::api::{ApiClient, WsStream};
use crate::error::{ClientError, Result};

/// What arrives from the server.
#[derive(Debug, Clone)]
pub enum RemoteEvent {
    /// First message: data about the session and the viewer.
    Hello(Value),
    /// Terminal output (the first chunk is the history).
    Output(Bytes),
    /// The client fell behind: the full history follows; clear the screen.
    Resync,
    /// State change (`connecting`, `running`, `closed`...).
    Status(Value),
    /// Who is connected.
    Presence(Value),
    /// Authentication prompt (2FA, fingerprint, password), sent only to the owner.
    Prompt(Value),
    Resize {
        cols: u16,
        rows: u16,
    },
    Error(String),
    /// Any other control message.
    Other(Value),
    /// The connection to the server was lost and is being retried.
    Reconnecting,
    /// Connection closed (and it will not be retried).
    Closed,
}

enum Outgoing {
    Binary(Bytes),
    Json(Value),
    Close,
}

/// An attached remote terminal.
#[derive(Clone)]
pub struct RemoteTerminal {
    tx: mpsc::Sender<Outgoing>,
}

impl RemoteTerminal {
    /// Attaches to one of your sessions or one shared with you.
    pub async fn attach(
        api: &ApiClient,
        session_id: Id,
    ) -> Result<(Self, mpsc::Receiver<RemoteEvent>)> {
        Self::attach_path(api, &format!("/api/v1/sessions/{session_id}/ws")).await
    }

    /// Attaches to a specific path (e.g. that of a link invitation).
    pub async fn attach_path(
        api: &ApiClient,
        path: &str,
    ) -> Result<(Self, mpsc::Receiver<RemoteEvent>)> {
        let ws = api.websocket(path).await?;
        let (events_tx, events_rx) = mpsc::channel::<RemoteEvent>(1024);
        let (tx, rx) = mpsc::channel::<Outgoing>(256);
        tokio::spawn(run(api.clone(), path.to_string(), ws, rx, events_tx));
        Ok((Self { tx }, events_rx))
    }

    /// Sends typed input.
    pub async fn input(&self, data: impl Into<Bytes>) {
        let _ = self.tx.send(Outgoing::Binary(data.into())).await;
    }

    pub async fn resize(&self, cols: u16, rows: u16) {
        let _ = self
            .tx
            .send(Outgoing::Json(
                json!({"type": "resize", "cols": cols, "rows": rows}),
            ))
            .await;
    }

    /// Answers an authentication prompt.
    pub async fn answer_prompt(
        &self,
        prompt_id: Id,
        accept: Option<bool>,
        answers: Option<Vec<String>>,
    ) {
        let _ = self
            .tx
            .send(Outgoing::Json(json!({"type": "prompt_answer", "prompt_id": prompt_id, "accept": accept, "answers": answers})))
            .await;
    }

    /// Closes the session on the server (owner only).
    pub async fn close_session(&self) {
        let _ = self
            .tx
            .send(Outgoing::Json(json!({"type": "close_session"})))
            .await;
    }

    /// Detaches (the session stays alive on the server).
    pub async fn detach(&self) {
        let _ = self.tx.send(Outgoing::Close).await;
    }
}

/// How a connection ended.
enum End {
    /// Closed for good (this side asked for it, the session ended...).
    Done,
    /// Dropped: reconnect.
    Lost,
}

/// Maximum time spent retrying before giving up.
const RECONNECT_FOR: Duration = Duration::from_secs(5 * 60);

async fn run(
    api: ApiClient,
    path: String,
    mut ws: WsStream,
    mut rx: mpsc::Receiver<Outgoing>,
    events: mpsc::Sender<RemoteEvent>,
) {
    // Last requested size: sent again on reconnect.
    let mut size: Option<Value> = None;
    loop {
        match connection(ws, &mut rx, &events, &mut size).await {
            End::Done => break,
            End::Lost => {
                if events.send(RemoteEvent::Reconnecting).await.is_err() {
                    return;
                }
                match reconnect(&api, &path, &mut rx, &mut size).await {
                    Some(fresh) => {
                        ws = fresh;
                        // What follows is the full history.
                        if events.send(RemoteEvent::Resync).await.is_err() {
                            return;
                        }
                    }
                    None => break,
                }
            }
        }
    }
    let _ = events.send(RemoteEvent::Closed).await;
}

async fn connection(
    ws: WsStream,
    rx: &mut mpsc::Receiver<Outgoing>,
    events: &mpsc::Sender<RemoteEvent>,
    size: &mut Option<Value>,
) -> End {
    let (mut sink, mut stream) = ws.split();
    if let Some(v) = size.as_ref()
        && sink
            .send(Message::Text(v.to_string().into()))
            .await
            .is_err()
    {
        return End::Lost;
    }
    // If the server closes right after an error (access revoked) or the end
    // of the session, do not retry.
    let mut last_was_final = false;
    loop {
        tokio::select! {
            out = rx.recv() => {
                let res = match out {
                    None | Some(Outgoing::Close) => {
                        let _ = sink.send(Message::Close(None)).await;
                        return End::Done;
                    }
                    Some(Outgoing::Binary(b)) => sink.send(Message::Binary(b)).await,
                    Some(Outgoing::Json(v)) => {
                        if v["type"] == "resize" {
                            *size = Some(v.clone());
                        }
                        sink.send(Message::Text(v.to_string().into())).await
                    }
                };
                if res.is_err() {
                    return End::Lost;
                }
            }
            msg = stream.next() => {
                let ev = match msg {
                    Some(Ok(Message::Binary(b))) => RemoteEvent::Output(b),
                    Some(Ok(Message::Text(t))) => parse_event(&t),
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => {
                        return if last_was_final { End::Done } else { End::Lost };
                    }
                    Some(Ok(_)) => continue,
                };
                last_was_final = match &ev {
                    RemoteEvent::Error(_) => true,
                    RemoteEvent::Status(v) => v["state"] == "closed",
                    _ => last_was_final,
                };
                if events.send(ev).await.is_err() {
                    return End::Done;
                }
            }
        }
    }
}

fn parse_event(text: &str) -> RemoteEvent {
    let v: Value = serde_json::from_str(text).unwrap_or(Value::Null);
    match v["type"].as_str().unwrap_or("") {
        "hello" => RemoteEvent::Hello(v),
        "resync" => RemoteEvent::Resync,
        "status" => RemoteEvent::Status(v["status"].clone()),
        "presence" => RemoteEvent::Presence(v["viewers"].clone()),
        "prompt" => RemoteEvent::Prompt(v),
        "resize" => RemoteEvent::Resize {
            cols: v["cols"].as_u64().unwrap_or(80) as u16,
            rows: v["rows"].as_u64().unwrap_or(24) as u16,
        },
        "error" => RemoteEvent::Error(v["message"].as_str().unwrap_or("error").to_string()),
        _ => RemoteEvent::Other(v),
    }
}

/// Retries until it reconnects, gives up (`None`) or this side closes.
/// Input typed in the meantime is discarded.
async fn reconnect(
    api: &ApiClient,
    path: &str,
    rx: &mut mpsc::Receiver<Outgoing>,
    size: &mut Option<Value>,
) -> Option<WsStream> {
    let deadline = tokio::time::Instant::now() + RECONNECT_FOR;
    let mut delay = Duration::from_millis(250);
    loop {
        let wait = tokio::time::sleep(delay);
        tokio::pin!(wait);
        loop {
            tokio::select! {
                _ = &mut wait => break,
                out = rx.recv() => match out {
                    None | Some(Outgoing::Close) => return None,
                    Some(Outgoing::Json(v)) if v["type"] == "resize" => *size = Some(v),
                    Some(_) => {}
                },
            }
        }
        match api.websocket(path).await {
            Ok(ws) => return Some(ws),
            // The session no longer exists or access is gone: nothing to fix.
            Err(ClientError::Api { status, .. }) if (400..500).contains(&status) => return None,
            Err(ClientError::SessionExpired | ClientError::NotLoggedIn) => return None,
            Err(_) => {}
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        delay = (delay * 2).min(Duration::from_secs(5));
    }
}

//! Sharing a local terminal through the server ("relay" session).
//!
//! The terminal keeps running on this device; the server only forwards the
//! output to the guests, and what they type (if they have control
//! permission) back here.

use std::sync::Arc;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use termoak_core::Id;
use termoak_ssh::TerminalSession;
use termoak_ssh::terminal::OutputHub;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::Message;

use crate::api::ApiClient;
use crate::error::{ClientError, Result};

/// A terminal on this computer that is not an SSH session (shell, serial
/// port): whoever draws it copies its output to `hub`, receives what the
/// guests type on `input` and signals `closed` when it ends.
#[derive(Clone)]
pub struct LocalTerm {
    pub hub: Arc<OutputHub>,
    pub input: mpsc::UnboundedSender<Bytes>,
    pub size: (u16, u16),
    pub closed: watch::Receiver<bool>,
}

/// What is shared.
enum Source {
    Ssh(Arc<TerminalSession>),
    Local(LocalTerm),
}

impl Source {
    fn size(&self) -> (u16, u16) {
        match self {
            Source::Ssh(t) => t.size(),
            Source::Local(l) => l.size,
        }
    }

    fn attach(&self) -> (Bytes, tokio::sync::broadcast::Receiver<Bytes>) {
        match self {
            Source::Ssh(t) => t.attach(),
            Source::Local(l) => l.hub.attach(),
        }
    }

    async fn write(&self, input: Bytes) {
        match self {
            Source::Ssh(t) => {
                let _ = t.write(input).await;
            }
            Source::Local(l) => {
                let _ = l.input.send(input);
            }
        }
    }

    /// Resolves when the terminal ends.
    async fn closed(&self) {
        match self {
            Source::Ssh(t) => {
                let mut status = t.watch_status();
                while !status.borrow().is_closed() {
                    if status.changed().await.is_err() {
                        return;
                    }
                }
            }
            Source::Local(l) => {
                let mut closed = l.closed.clone();
                while !*closed.borrow() {
                    if closed.changed().await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

/// A shared local terminal.
pub struct RelayShare {
    pub session_id: Id,
    api: ApiClient,
    control: mpsc::Sender<Value>,
    task: tokio::task::JoinHandle<()>,
}

impl RelayShare {
    /// Starts sharing `term` with the given title.
    pub async fn start(api: &ApiClient, term: Arc<TerminalSession>, title: &str) -> Result<Self> {
        Self::start_source(api, Source::Ssh(term), title).await
    }

    /// Shares a non-SSH terminal of this computer.
    pub async fn start_local(api: &ApiClient, term: LocalTerm, title: &str) -> Result<Self> {
        Self::start_source(api, Source::Local(term), title).await
    }

    async fn start_source(api: &ApiClient, source: Source, title: &str) -> Result<Self> {
        let (cols, rows) = source.size();
        let created: Value = api
            .post(
                "/api/v1/relay",
                &json!({"title": title, "cols": cols, "rows": rows}),
            )
            .await?;
        let session_id: Id = created["session"]["id"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| ClientError::Invalid("relay response without id".into()))?;
        let path = created["host_ws_path"]
            .as_str()
            .ok_or_else(|| ClientError::Invalid("relay response without path".into()))?
            .to_string();
        let ws = api.websocket(&path).await?;
        let (mut sink, mut stream) = ws.split();
        let (control, mut control_rx) = mpsc::channel::<Value>(32);

        let task = tokio::spawn(async move {
            let (snapshot, mut output) = source.attach();
            if sink.send(Message::Binary(snapshot)).await.is_err() {
                return;
            }
            let closed = source.closed();
            tokio::pin!(closed);
            loop {
                tokio::select! {
                    out = output.recv() => match out {
                        Ok(bytes) => if sink.send(Message::Binary(bytes)).await.is_err() { break },
                        Err(RecvError::Lagged(_)) => {}
                        Err(RecvError::Closed) => break,
                    },
                    msg = stream.next() => match msg {
                        Some(Ok(Message::Binary(input))) => source.write(input).await,
                        Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                        _ => {}
                    },
                    ctl = control_rx.recv() => match ctl {
                        Some(v) => { let _ = sink.send(Message::Text(v.to_string().into())).await; }
                        None => break,
                    },
                    _ = &mut closed => {
                        let _ = sink.send(Message::Text(json!({"type": "host_closed"}).to_string().into())).await;
                        break;
                    }
                }
            }
        });
        Ok(Self {
            session_id,
            api: api.clone(),
            control,
            task,
        })
    }

    /// Reports the new size of the local terminal.
    pub async fn resize(&self, cols: u16, rows: u16) {
        let _ = self
            .control
            .send(json!({"type": "resize", "cols": cols, "rows": rows}))
            .await;
    }

    /// Invites a server user (`control` = can type).
    pub async fn invite_user(&self, email: &str, control: bool) -> Result<Value> {
        self.api
            .post(
                &format!("/api/v1/sessions/{}/shares", self.session_id),
                &json!({"email": email, "permission": if control { "control" } else { "view" }}),
            )
            .await
    }

    /// Creates a link for guests without an account.
    pub async fn invite_link(
        &self,
        control: bool,
        expires_in_minutes: Option<i64>,
    ) -> Result<Value> {
        self.api
            .post(
                &format!("/api/v1/sessions/{}/shares", self.session_id),
                &json!({"link": true, "permission": if control { "control" } else { "view" }, "expires_in_minutes": expires_in_minutes}),
            )
            .await
    }

    /// Stops sharing.
    pub async fn stop(self) {
        let _ = self.control.send(json!({"type": "host_closed"})).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        self.task.abort();
    }
}

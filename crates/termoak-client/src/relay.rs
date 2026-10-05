//! Sharing a local terminal through the server ("relay" session).
//!
//! The terminal keeps running on this device; the server only forwards the
//! output to the guests, and what the driver (whoever has the keyboard)
//! types back here. This side is the owner: it hears who joins and who asks
//! for the keyboard ([`RelayShare::subscribe`]) and decides.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use termoak_core::Id;
use termoak_ssh::TerminalSession;
use termoak_ssh::terminal::OutputHub;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

use crate::api::{ApiClient, WsStream};
use crate::error::{ClientError, Result};
use crate::remote::{Participant, owner_msg};

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

/// What the host of a shared terminal hears from the server.
#[derive(Debug, Clone)]
pub enum RelayEvent {
    /// Who is in the session and who drives (`None`: you, the owner).
    Participants {
        participants: Vec<Participant>,
        driver: Option<Id>,
    },
    /// The keyboard changed hands. `until`: when a timed grant ends (ms).
    Control {
        driver: Option<Id>,
        driver_name: Option<String>,
        until: Option<i64>,
    },
    /// A timed grant ended: the keyboard is yours again (`participant`:
    /// who had it).
    ControlExpired { participant: Option<Id> },
    /// The driver (or you, from another device) would like this size. The
    /// terminal is here, so it decides: apply it to the local terminal or
    /// ignore it. Guests see the size this side reports with `resize`.
    ResizeRequest { cols: u16, rows: u16 },
    /// Someone waits to be let in (`allow_join` / `deny_join`).
    JoinRequest(Participant),
    /// Someone asks for the keyboard (`grant_control` / `deny_control`).
    ControlRequest(Participant),
    /// The connection to the server dropped; it is being retried (guests
    /// see the session as "host offline" meanwhile).
    Reconnecting,
    /// Back after `Reconnecting`.
    Reconnected,
    /// Sharing ended (`code` if the server said why, e.g. `session_ended`).
    Ended { code: Option<String> },
}

/// A shared local terminal. If the connection drops, it reconnects by
/// itself (the server keeps the session for a few minutes).
pub struct RelayShare {
    pub session_id: Id,
    api: ApiClient,
    control: mpsc::Sender<Value>,
    events: broadcast::Sender<RelayEvent>,
    task: tokio::task::JoinHandle<()>,
}

/// How a host connection ended.
enum End {
    /// For good (stopped, the terminal ended, the session is over).
    Done(Option<String>),
    /// Dropped: reconnect.
    Lost,
}

/// Maximum time spent reconnecting (the server waits
/// `[sessions] relay_grace_minutes`, 5 by default).
const RECONNECT_FOR: Duration = Duration::from_secs(10 * 60);

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
            .ok_or_else(|| ClientError::Invalid("relay response without path".into()))?;
        let path = crate::remote::ws_path(path, None);
        let ws = api.websocket(&path).await?;
        let (control, control_rx) = mpsc::channel::<Value>(32);
        let (events, _) = broadcast::channel(256);
        let task = tokio::spawn(host(
            api.clone(),
            path,
            ws,
            source,
            control_rx,
            events.clone(),
        ));
        Ok(Self {
            session_id,
            api: api.clone(),
            control,
            events,
            task,
        })
    }

    /// What the server says (participants, keyboard, requests...).
    pub fn subscribe(&self) -> broadcast::Receiver<RelayEvent> {
        self.events.subscribe()
    }

    /// Sends a control message as is (see `owner_msg`).
    pub async fn send_raw(&self, v: Value) {
        let _ = self.control.send(v).await;
    }

    async fn send(&self, v: Value) {
        self.send_raw(v).await;
    }

    /// Reports the new size of the local terminal.
    pub async fn resize(&self, cols: u16, rows: u16) {
        self.send(json!({"type": "resize", "cols": cols, "rows": rows}))
            .await;
    }

    /// Creates any share (`POST /sessions/{id}/shares` with `body`).
    pub async fn invite(&self, body: &Value) -> Result<Value> {
        self.api
            .post(
                &format!("/api/v1/sessions/{}/shares", self.session_id),
                body,
            )
            .await
    }

    /// Invites a server user (`control` = can ask for the keyboard).
    pub async fn invite_user(&self, email: &str, control: bool) -> Result<Value> {
        self.api
            .post(
                &format!("/api/v1/sessions/{}/shares", self.session_id),
                &json!({"email": email, "permission": if control { "control" } else { "view" }}),
            )
            .await
    }

    /// Creates a link for guests without an account (they wait until you
    /// let them in).
    pub async fn invite_link(
        &self,
        control: bool,
        expires_in_minutes: Option<i64>,
    ) -> Result<Value> {
        self.api
            .post(
                &format!("/api/v1/sessions/{}/shares", self.session_id),
                &json!({"link": true, "permission": if control { "control" } else { "view" }, "expires_in_minutes": expires_in_minutes, "require_approval": true}),
            )
            .await
    }

    /// Hands the keyboard to a participant, for `minutes` (1-240) or until
    /// it is given back or taken (`None`).
    pub async fn grant_control(&self, participant: Id, minutes: Option<u32>) {
        self.send(owner_msg::grant_control(participant, minutes))
            .await;
    }

    /// Says no to a request for the keyboard.
    pub async fn deny_control(&self, participant: Id) {
        self.send(owner_msg::deny_control(participant)).await;
    }

    /// Takes the keyboard back.
    pub async fn take_control(&self) {
        self.send(owner_msg::take_control()).await;
    }

    /// Lets someone in from the waiting room.
    pub async fn allow_join(&self, participant: Id) {
        self.send(owner_msg::allow_join(participant)).await;
    }

    /// Does not let someone in.
    pub async fn deny_join(&self, participant: Id) {
        self.send(owner_msg::deny_join(participant)).await;
    }

    /// Sends a participant away (`revoke_share`: and revokes their invitation).
    pub async fn kick(&self, participant: Id, revoke_share: bool) {
        self.send(owner_msg::kick(participant, revoke_share)).await;
    }

    /// Revokes every invitation (everyone leaves) but keeps the session.
    pub async fn stop_guests(&self) {
        self.send(owner_msg::stop_sharing()).await;
    }

    /// Stops sharing.
    pub async fn stop(self) {
        let _ = self.control.send(json!({"type": "host_closed"})).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        self.task.abort();
    }
}

/// The host's side: uploads the output, types what the driver types and
/// reconnects if the connection drops.
async fn host(
    api: ApiClient,
    path: String,
    mut ws: WsStream,
    source: Source,
    mut control: mpsc::Receiver<Value>,
    events: broadcast::Sender<RelayEvent>,
) {
    let mut size: Option<Value> = None;
    loop {
        match connection(ws, &source, &mut control, &events, &mut size).await {
            End::Done(code) => {
                let _ = events.send(RelayEvent::Ended { code });
                return;
            }
            End::Lost => {
                let _ = events.send(RelayEvent::Reconnecting);
                match reconnect(&api, &path, &mut control, &mut size).await {
                    Ok(fresh) => {
                        ws = fresh;
                        let _ = events.send(RelayEvent::Reconnected);
                    }
                    Err(code) => {
                        let _ = events.send(RelayEvent::Ended { code });
                        return;
                    }
                }
            }
        }
    }
}

async fn connection(
    ws: WsStream,
    source: &Source,
    control: &mut mpsc::Receiver<Value>,
    events: &broadcast::Sender<RelayEvent>,
    size: &mut Option<Value>,
) -> End {
    let (mut sink, mut stream) = ws.split();
    // The first frame is the whole screen (it replaces the history kept by
    // the server, so a reconnect does not duplicate it).
    let (snapshot, mut output) = source.attach();
    if sink.send(Message::Binary(snapshot)).await.is_err() {
        return End::Lost;
    }
    if let Some(v) = size.as_ref()
        && sink
            .send(Message::Text(v.to_string().into()))
            .await
            .is_err()
    {
        return End::Lost;
    }
    let closed = source.closed();
    tokio::pin!(closed);
    loop {
        tokio::select! {
            out = output.recv() => match out {
                Ok(bytes) => if sink.send(Message::Binary(bytes)).await.is_err() { return End::Lost },
                Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return End::Done(None),
            },
            msg = stream.next() => match msg {
                Some(Ok(Message::Binary(input))) => source.write(input).await,
                Some(Ok(Message::Text(t))) => {
                    if let Some(ev) = parse(&t) {
                        let _ = events.send(ev);
                    }
                }
                Some(Ok(Message::Close(frame))) => {
                    let code = frame.as_ref().and_then(|f| match f.code {
                        CloseCode::Library(c) if (4000..5000).contains(&c) => Some(f.reason.to_string()),
                        _ => None,
                    });
                    return match code {
                        Some(code) => End::Done(Some(code)),
                        None => End::Lost,
                    };
                }
                None | Some(Err(_)) => return End::Lost,
                _ => {}
            },
            ctl = control.recv() => match ctl {
                Some(v) => {
                    let host_closed = v["type"] == "host_closed";
                    if v["type"] == "resize" {
                        *size = Some(v.clone());
                    }
                    let _ = sink.send(Message::Text(v.to_string().into())).await;
                    if host_closed {
                        return End::Done(None);
                    }
                }
                None => return End::Done(None),
            },
            _ = &mut closed => {
                let _ = sink.send(Message::Text(json!({"type": "host_closed"}).to_string().into())).await;
                return End::Done(None);
            }
        }
    }
}

fn parse(text: &str) -> Option<RelayEvent> {
    let v: Value = serde_json::from_str(text).ok()?;
    let id = |v: &Value| v.as_str().and_then(|s| s.parse().ok());
    Some(match v["type"].as_str()? {
        "participants" => RelayEvent::Participants {
            participants: Participant::list_from_json(&v["participants"]),
            driver: id(&v["driver"]),
        },
        "control" => RelayEvent::Control {
            driver: id(&v["driver"]),
            driver_name: v["driver_name"].as_str().map(str::to_string),
            until: v["until"].as_i64(),
        },
        "control_expired" => RelayEvent::ControlExpired {
            participant: id(&v["participant"]),
        },
        "resize" => RelayEvent::ResizeRequest {
            cols: v["cols"].as_u64()? as u16,
            rows: v["rows"].as_u64()? as u16,
        },
        "join_request" => {
            RelayEvent::JoinRequest(serde_json::from_value(v["participant"].clone()).ok()?)
        }
        "control_request" => {
            RelayEvent::ControlRequest(serde_json::from_value(v["participant"].clone()).ok()?)
        }
        _ => return None,
    })
}

/// Retries until it reconnects. `Err` (with the code, if any) when it gives
/// up or this side stops.
async fn reconnect(
    api: &ApiClient,
    path: &str,
    control: &mut mpsc::Receiver<Value>,
    size: &mut Option<Value>,
) -> std::result::Result<WsStream, Option<String>> {
    let deadline = tokio::time::Instant::now() + RECONNECT_FOR;
    let mut delay = Duration::from_millis(250);
    loop {
        let wait = tokio::time::sleep(delay);
        tokio::pin!(wait);
        loop {
            tokio::select! {
                _ = &mut wait => break,
                ctl = control.recv() => match ctl {
                    None => return Err(None),
                    Some(v) if v["type"] == "host_closed" => return Err(None),
                    Some(v) if v["type"] == "resize" => *size = Some(v),
                    Some(_) => {}
                },
            }
        }
        match api.websocket(path).await {
            Ok(ws) => return Ok(ws),
            // The session is over (closed, or the host took too long).
            Err(ClientError::Api { status, .. }) if (400..500).contains(&status) => {
                return Err(Some("session_ended".into()));
            }
            Err(ClientError::SessionExpired | ClientError::NotLoggedIn) => return Err(None),
            Err(_) => {}
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(None);
        }
        delay = (delay * 2).min(Duration::from_secs(5));
    }
}

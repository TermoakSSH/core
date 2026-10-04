//! Terminals that live on the server, user events (WebSocket) and sharing a
//! local terminal through the server (relay).

use std::sync::Arc;

use futures::StreamExt;
use serde_json::{Value, json};
use termoak_client::ApiClient;
use termoak_client::relay::RelayShare;
use termoak_client::remote::{RemoteEvent, RemoteTerminal};
use termoak_core::Id;
use tokio::sync::{Notify, mpsc};
use tokio_tungstenite::tungstenite::Message;

use crate::error::{Result, TermoakError};
use crate::models::parse_id;
use crate::runtime::{block_on, run, runtime, spawn_callback_thread};
use crate::server::{
    JoinInfo, ServerPrompt, ServerSession, ServerSessionState, SessionViewer, str_of,
};
use crate::ssh::TerminalHandle;
use crate::vault::TermoakCore;

/// Maximum size of an output chunk delivered at once.
const MAX_OUTPUT_CHUNK: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Server terminal
// ---------------------------------------------------------------------------

/// What arrives from a server session.
#[derive(Debug, Clone, PartialEq, uniffi::Enum)]
pub enum ServerTerminalEvent {
    /// First message: session data and your permission.
    Hello { session: ServerSession },
    /// Terminal output (the first delivery is the full history).
    Output { data: Vec<u8> },
    /// The app fell behind: clear the screen (reset the emulator); the next
    /// `Output` is the full history.
    Resync,
    /// The session's state changed.
    Status { state: ServerSessionState },
    /// Who is connected.
    Presence { viewers: Vec<SessionViewer> },
    /// Authentication question (owner only): answer it with
    /// `ServerTerminalHandle::answer_prompt`.
    Prompt { prompt: ServerPrompt },
    /// Another screen (or device) already answered that question.
    PromptDone { prompt_id: String },
    /// Another viewer resized the terminal.
    Resize { cols: u32, rows: u32 },
    /// New session title.
    Title { title: String },
    /// Error sent by the server (e.g. access revoked).
    Error { message: String },
    /// Other control message (JSON), for future protocol versions.
    Other { json: String },
    /// Connection closed. Nothing else arrives.
    Closed,
}

/// Implemented by the app to receive the events of a server session.
///
/// **Threads**: each session has its own background thread that calls in
/// order, one at a time. It must return quickly (hop to the main thread).
#[uniffi::export(foreign)]
pub trait ServerTerminalListener: Send + Sync {
    fn on_event(&self, event: ServerTerminalEvent);
}

/// Attached server terminal. Dropping it (or `detach`) only detaches this
/// screen: the session stays alive on the server.
#[derive(uniffi::Object)]
pub struct ServerTerminalHandle {
    session_id: String,
    remote: RemoteTerminal,
}

impl Drop for ServerTerminalHandle {
    fn drop(&mut self) {
        let remote = self.remote.clone();
        runtime().spawn(async move { remote.detach().await });
    }
}

fn convert_event(ev: RemoteEvent) -> ServerTerminalEvent {
    match ev {
        RemoteEvent::Hello(v) => ServerTerminalEvent::Hello {
            session: ServerSession::from_json(&v["session"]),
        },
        RemoteEvent::Output(b) => ServerTerminalEvent::Output { data: b.to_vec() },
        RemoteEvent::Resync => ServerTerminalEvent::Resync,
        RemoteEvent::Status(v) => ServerTerminalEvent::Status {
            state: ServerSessionState::from_json(&v),
        },
        RemoteEvent::Presence(v) => ServerTerminalEvent::Presence {
            viewers: SessionViewer::list_from_json(&v),
        },
        RemoteEvent::Prompt(v) => ServerTerminalEvent::Prompt {
            prompt: ServerPrompt::from_json(&v),
        },
        RemoteEvent::Resize { cols, rows } => ServerTerminalEvent::Resize {
            cols: cols.into(),
            rows: rows.into(),
        },
        RemoteEvent::Error(message) => ServerTerminalEvent::Error { message },
        RemoteEvent::Other(v) => match v["type"].as_str().unwrap_or("") {
            "prompt_done" => ServerTerminalEvent::PromptDone {
                prompt_id: str_of(&v["prompt_id"]),
            },
            "title" => ServerTerminalEvent::Title {
                title: str_of(&v["title"]),
            },
            _ => ServerTerminalEvent::Other {
                json: v.to_string(),
            },
        },
        // The apps already show "connecting" with its message; on reconnect
        // `Resync`, the hello and the history arrive.
        RemoteEvent::Reconnecting => ServerTerminalEvent::Status {
            state: ServerSessionState::Connecting {
                message: "Lost the connection to the server: reconnecting…".into(),
            },
        },
        RemoteEvent::Closed => ServerTerminalEvent::Closed,
    }
}

/// Delivers the events of a server session to the app, merging consecutive
/// outputs into a single chunk.
fn pump_remote(
    rt: &tokio::runtime::Handle,
    mut rx: mpsc::Receiver<RemoteEvent>,
    listener: Arc<dyn ServerTerminalListener>,
) {
    let mut pending: Option<RemoteEvent> = None;
    loop {
        let ev = match pending.take() {
            Some(ev) => ev,
            None => match rt.block_on(rx.recv()) {
                Some(ev) => ev,
                None => {
                    listener.on_event(ServerTerminalEvent::Closed);
                    return;
                }
            },
        };
        match ev {
            RemoteEvent::Output(first) => {
                let mut buf = first.to_vec();
                while buf.len() < MAX_OUTPUT_CHUNK {
                    match rx.try_recv() {
                        Ok(RemoteEvent::Output(more)) => buf.extend_from_slice(&more),
                        Ok(other) => {
                            pending = Some(other);
                            break;
                        }
                        Err(_) => break,
                    }
                }
                listener.on_event(ServerTerminalEvent::Output { data: buf });
            }
            RemoteEvent::Closed => {
                listener.on_event(ServerTerminalEvent::Closed);
                return;
            }
            other => listener.on_event(convert_event(other)),
        }
    }
}

fn start_remote(
    session_id: String,
    remote: RemoteTerminal,
    events: mpsc::Receiver<RemoteEvent>,
    listener: Arc<dyn ServerTerminalListener>,
) -> Arc<ServerTerminalHandle> {
    spawn_callback_thread("termoak-server-term", move |rt| {
        pump_remote(rt, events, listener)
    });
    Arc::new(ServerTerminalHandle { session_id, remote })
}

#[uniffi::export]
impl ServerTerminalHandle {
    pub fn session_id(&self) -> String {
        self.session_id.clone()
    }

    /// Sends typed input (ignored if you only have read permission).
    pub fn write(&self, data: Vec<u8>) {
        block_on(self.remote.input(data));
    }

    pub fn write_text(&self, text: String) {
        block_on(self.remote.input(text.into_bytes()));
    }

    /// New size in columns and rows.
    pub fn resize(&self, cols: u32, rows: u32) {
        let c = u16::try_from(cols).unwrap_or(u16::MAX);
        let r = u16::try_from(rows).unwrap_or(u16::MAX);
        block_on(self.remote.resize(c, r));
    }

    /// Answers a `Prompt`: `accept` for fingerprints (`hostkey`), `answers`
    /// for the rest (one per field). `nil` in both cancels.
    pub fn answer_prompt(
        &self,
        prompt_id: String,
        accept: Option<bool>,
        answers: Option<Vec<String>>,
    ) -> Result<()> {
        let id = parse_id(&prompt_id)?;
        block_on(self.remote.answer_prompt(id, accept, answers));
        Ok(())
    }

    /// Detaches (the session stays alive on the server).
    pub fn detach(&self) {
        block_on(self.remote.detach());
    }

    /// Closes the session on the server (owner only).
    pub fn close_session(&self) {
        block_on(self.remote.close_session());
    }
}

#[uniffi::export]
impl TermoakCore {
    /// Attaches to a server session (yours or shared with you). `Hello`
    /// arrives first, then the history.
    pub async fn attach_server_session(
        &self,
        session_id: String,
        listener: Arc<dyn ServerTerminalListener>,
    ) -> Result<Arc<ServerTerminalHandle>> {
        let id = parse_id(&session_id)?;
        let api = self.api().await?;
        run(async move {
            let (remote, events) = RemoteTerminal::attach(&api, id).await?;
            Ok(start_remote(id.to_string(), remote, events, listener))
        })
        .await
    }
}

/// Joins a shared session with an invitation link, without an account.
/// `server_url` and `token` come from the link (`termoak://join?server=...&token=...`).
#[uniffi::export]
pub async fn join_shared_session(
    server_url: String,
    token: String,
    listener: Arc<dyn ServerTerminalListener>,
) -> Result<Arc<ServerTerminalHandle>> {
    crate::vault::install_crypto_provider();
    run(async move {
        let api = ApiClient::new(&server_url)?;
        let token = token.trim().to_string();
        if token.is_empty()
            || !token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_".contains(c))
        {
            return Err(TermoakError::Invalid(
                "the invitation link is not valid".into(),
            ));
        }
        let resp = reqwest::Client::new()
            .get(format!("{}/api/v1/join/{token}", api.base_url()))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(TermoakError::NotFound(
                "the link is not valid, has expired or the session has ended".into(),
            ));
        }
        let info: JoinInfo = resp.json().await?;
        let session_id = info
            .ws_path
            .split('/')
            .nth(4)
            .unwrap_or_default()
            .to_string();
        let (remote, events) = RemoteTerminal::attach_path(&api, &info.ws_path).await?;
        Ok(start_remote(session_id, remote, events, listener))
    })
    .await
}

// ---------------------------------------------------------------------------
// User events
// ---------------------------------------------------------------------------

/// Implemented by the app to receive its account's events: AI tasks
/// (progress, pending approvals), sessions opened, closed or shared with you,
/// pending questions...
///
/// **Threads**: its own background thread, in order; it must return quickly.
#[uniffi::export(foreign)]
pub trait ServerEventListener: Send + Sync {
    /// Event as JSON. Types (`type`): `hello` (user and pending approvals),
    /// `ai` (a task event: `task_id`, `seq`, `event`), `session` (`notice`:
    /// `session_opened`, `session_closed`, `session_shared`,
    /// `prompt_pending`) and `lagged` (events were lost: refresh).
    fn on_event(&self, event_json: String);

    /// The WebSocket closed (`reason` if it was due to an error). Nothing else
    /// arrives; subscribe again to keep receiving.
    fn on_closed(&self, reason: Option<String>);
}

/// Subscription to the user's events. Closed with `unsubscribe` or when
/// dropped.
#[derive(uniffi::Object)]
pub struct EventSubscription {
    stop: Arc<Notify>,
}

impl Drop for EventSubscription {
    fn drop(&mut self) {
        self.stop.notify_one();
    }
}

#[uniffi::export]
impl EventSubscription {
    /// Stops receiving events (`on_closed` arrives). It is not called `close`
    /// because Kotlin objects already have `close()` (to release them).
    pub fn unsubscribe(&self) {
        self.stop.notify_one();
    }
}

#[uniffi::export]
impl TermoakCore {
    /// Subscribes to your account's events (WebSocket `/api/v1/events/ws`).
    /// While the app is in the foreground it works as "push notifications".
    pub async fn subscribe_events(
        &self,
        listener: Arc<dyn ServerEventListener>,
    ) -> Result<Arc<EventSubscription>> {
        let api = self.api().await?;
        let ws = run(async move { Ok(api.websocket("/api/v1/events/ws").await?) }).await?;
        let stop = Arc::new(Notify::new());
        let thread_stop = stop.clone();
        spawn_callback_thread("termoak-events", move |rt| {
            let (_sink, mut stream) = ws.split();
            let reason = loop {
                let msg = rt.block_on(async {
                    tokio::select! {
                        m = stream.next() => Some(m),
                        _ = thread_stop.notified() => None,
                    }
                });
                match msg {
                    None => break None,
                    Some(Some(Ok(Message::Text(t)))) => listener.on_event(t.to_string()),
                    Some(Some(Ok(Message::Close(frame)))) => {
                        break frame
                            .map(|f| f.reason.to_string())
                            .filter(|r| !r.is_empty());
                    }
                    Some(Some(Ok(_))) => {}
                    Some(Some(Err(e))) => break Some(format!("WebSocket: {e}")),
                    Some(None) => break None,
                }
            };
            listener.on_closed(reason);
        });
        Ok(Arc::new(EventSubscription { stop }))
    }
}

// ---------------------------------------------------------------------------
// Sharing a local terminal (relay)
// ---------------------------------------------------------------------------

/// Invitation to a shared session.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct ShareInvite {
    pub share_id: String,
    /// `view` or `control`.
    pub permission: String,
    /// Link token (only for link invitations).
    pub token: Option<String>,
    /// Web link of the invitation.
    pub link: Option<String>,
    /// Link to open directly in the app (`termoak://join?...`).
    pub app_link: Option<String>,
}

impl ShareInvite {
    pub(crate) fn from_json(v: &Value) -> Self {
        ShareInvite {
            share_id: str_of(&v["share"]["id"]),
            permission: str_of(&v["share"]["permission"]),
            token: v["token"].as_str().map(str::to_string),
            link: v["link"].as_str().map(str::to_string),
            app_link: v["app_link"].as_str().map(str::to_string),
        }
    }
}

/// Local terminal shared through the server. The terminal stays on this
/// device; the server relays the output to the guests and what they type
/// (if they have control). Sharing stops with `stop` or when dropped.
#[derive(uniffi::Object)]
pub struct SharedTerminal {
    session_id: Id,
    api: ApiClient,
    share: Arc<tokio::sync::Mutex<Option<RelayShare>>>,
}

impl Drop for SharedTerminal {
    fn drop(&mut self) {
        let share = self.share.clone();
        runtime().spawn(async move {
            if let Some(s) = share.lock().await.take() {
                s.stop().await;
            }
        });
    }
}

impl SharedTerminal {
    async fn create_invite(&self, body: Value) -> Result<ShareInvite> {
        let api = self.api.clone();
        let path = format!("/api/v1/sessions/{}/shares", self.session_id);
        run(async move {
            let v: Value = api.post(&path, &body).await?;
            Ok(ShareInvite::from_json(&v))
        })
        .await
    }
}

fn permission(control: bool) -> &'static str {
    if control { "control" } else { "view" }
}

#[uniffi::export]
impl SharedTerminal {
    /// Id of the relay session on the server.
    pub fn session_id(&self) -> String {
        self.session_id.to_string()
    }

    /// Invites a server user by email (`control` = can type).
    pub async fn invite_user(&self, email: String, control: bool) -> Result<ShareInvite> {
        self.create_invite(json!({"email": email, "permission": permission(control)}))
            .await
    }

    /// Shares with all members of a team you belong to.
    pub async fn invite_team(&self, team_id: String, control: bool) -> Result<ShareInvite> {
        let target = crate::account::ShareTarget::Team { team_id };
        self.create_invite(crate::account::share_body(&target, control, None)?)
            .await
    }

    /// Creates a link for guests without an account (no expiry if not given).
    pub async fn invite_link(
        &self,
        control: bool,
        expires_in_minutes: Option<i64>,
    ) -> Result<ShareInvite> {
        self.create_invite(json!({"link": true, "permission": permission(control), "expires_in_minutes": expires_in_minutes}))
            .await
    }

    /// Revokes an invitation (kicks out whoever is using it).
    pub async fn revoke_invite(&self, share_id: String) -> Result<()> {
        let share = parse_id(&share_id)?;
        let api = self.api.clone();
        let path = format!("/api/v1/sessions/{}/shares/{share}", self.session_id);
        run(async move {
            api.delete(&path).await?;
            Ok(())
        })
        .await
    }

    /// Tells the guests the new size of the local terminal.
    pub async fn resize(&self, cols: u32, rows: u32) -> Result<()> {
        let share = self.share.clone();
        let (c, r) = (
            u16::try_from(cols).unwrap_or(u16::MAX),
            u16::try_from(rows).unwrap_or(u16::MAX),
        );
        run(async move {
            if let Some(s) = share.lock().await.as_ref() {
                s.resize(c, r).await;
            }
            Ok(())
        })
        .await
    }

    /// Stops sharing (the local terminal stays open).
    pub async fn stop(&self) -> Result<()> {
        let share = self.share.clone();
        run(async move {
            if let Some(s) = share.lock().await.take() {
                s.stop().await;
            }
            Ok(())
        })
        .await
    }
}

#[uniffi::export]
impl TermoakCore {
    /// Shares a local terminal through the server with the given title. Then
    /// invite with `invite_user` or `invite_link`.
    pub async fn share_terminal(
        &self,
        terminal: Arc<TerminalHandle>,
        title: String,
    ) -> Result<Arc<SharedTerminal>> {
        let api = self.api().await?;
        let term = terminal.session_arc();
        run(async move {
            let share = RelayShare::start(&api, term, &title).await?;
            Ok(Arc::new(SharedTerminal {
                session_id: share.session_id,
                api,
                share: Arc::new(tokio::sync::Mutex::new(Some(share))),
            }))
        })
        .await
    }
}

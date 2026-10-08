//! Terminals that live on the server, user events (WebSocket) and sharing a
//! local terminal through the server (relay).

use std::sync::Arc;

use futures::StreamExt;
use serde_json::{Value, json};
use termoak_client::ApiClient;
use termoak_client::relay::{LocalTerm, RelayEvent, RelayShare};
use termoak_client::remote::{RemoteEvent, RemoteTerminal, owner_msg};
use termoak_core::Id;
use termoak_ssh::Terminal;
use tokio::sync::{Notify, mpsc};
use tokio_tungstenite::tungstenite::Message;

use crate::account::{SessionShareInfo, ShareChanges};
use crate::error::{Result, TermoakError};
use crate::models::parse_id;
use crate::runtime::{block_on, run, runtime, spawn_callback_thread};
use crate::server::{
    JoinInfo, ServerPrompt, ServerSession, ServerSessionState, SessionAccess, SessionParticipant,
    SessionViewer, str_of,
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
    /// Who is connected (sockets; servers before 0.3 only).
    Presence { viewers: Vec<SessionViewer> },
    /// Who is in the session and who drives (`None`: the owner).
    Participants {
        participants: Vec<SessionParticipant>,
        driver: Option<String>,
    },
    /// The keyboard changed hands. `can_write`: your input and resizes reach
    /// the terminal now (otherwise the library does not send them).
    /// `until`: when a timed grant ends (ms since the epoch); the server
    /// takes the keyboard back by itself then.
    Control {
        driver: Option<String>,
        driver_name: Option<String>,
        can_write: bool,
        until: Option<i64>,
    },
    /// A timed grant ended and the keyboard went back to the owner. It
    /// reaches whoever had it and the owner (`participant_id`: who had it).
    ControlExpired { participant_id: Option<String> },
    /// You are in the waiting room until the owner lets you in (`Hello`
    /// arrives then).
    Waiting {
        participant_id: Option<String>,
        title: String,
        owner: String,
    },
    /// Owner: someone waits to be let in (`allow_join` / `deny_join`).
    JoinRequest { participant: SessionParticipant },
    /// Owner: someone asks for the keyboard (`grant_control` / `deny_control`).
    ControlRequest { participant: SessionParticipant },
    /// The owner said no to your request for the keyboard.
    ControlDenied,
    /// Authentication question (owner only): answer it with
    /// `ServerTerminalHandle::answer_prompt`.
    Prompt { prompt: ServerPrompt },
    /// Another screen (or device) already answered that question.
    PromptDone { prompt_id: String },
    /// Another viewer resized the terminal.
    Resize { cols: u32, rows: u32 },
    /// New session title.
    Title { title: String },
    /// Error that does not end the connection (an action that was not allowed).
    Error { message: String },
    /// The server sent you away for good. `code`: `revoked`, `kicked`,
    /// `expired`, `session_ended`, `join_denied` or `forbidden`. `Closed`
    /// follows; it does not reconnect.
    Ended { code: String, message: String },
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
        RemoteEvent::Ended { code, message } => ServerTerminalEvent::Ended { code, message },
        RemoteEvent::Participants {
            participants,
            driver,
        } => ServerTerminalEvent::Participants {
            participants: participants.iter().map(Into::into).collect(),
            driver: driver.map(|d| d.to_string()),
        },
        RemoteEvent::Control {
            driver,
            driver_name,
            can_write,
            until,
        } => ServerTerminalEvent::Control {
            driver: driver.map(|d| d.to_string()),
            driver_name,
            can_write,
            until,
        },
        RemoteEvent::ControlExpired { participant } => ServerTerminalEvent::ControlExpired {
            participant_id: participant.map(|p| p.to_string()),
        },
        RemoteEvent::Waiting(v) => ServerTerminalEvent::Waiting {
            participant_id: v["participant"].as_str().map(str::to_string),
            title: str_of(&v["session"]["title"]),
            owner: str_of(&v["session"]["owner"]),
        },
        RemoteEvent::JoinRequest(p) => ServerTerminalEvent::JoinRequest {
            participant: (&p).into(),
        },
        RemoteEvent::ControlRequest(p) => ServerTerminalEvent::ControlRequest {
            participant: (&p).into(),
        },
        RemoteEvent::ControlDenied => ServerTerminalEvent::ControlDenied,
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

    /// Sends typed input (dropped while you cannot write: see `can_write`).
    pub fn write(&self, data: Vec<u8>) {
        block_on(self.remote.input(data));
    }

    pub fn write_text(&self, text: String) {
        block_on(self.remote.input(text.into_bytes()));
    }

    /// New size in columns and rows. Remembered, and sent only while you
    /// can write (the owner or the driver set the size; the rest follow
    /// `Resize`).
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

    /// Your input and resizes reach the terminal now (you are the owner or
    /// have the keyboard). `false` until `Hello`.
    pub fn can_write(&self) -> bool {
        self.remote.can_write()
    }

    /// You have the keyboard (the owner has it when nobody else does).
    pub fn is_driver(&self) -> bool {
        self.remote.is_driver()
    }

    /// You are the session's owner.
    pub fn is_owner(&self) -> bool {
        self.remote.is_owner()
    }

    /// You are in the waiting room.
    pub fn is_waiting(&self) -> bool {
        self.remote.is_waiting()
    }

    /// Your participant id (once in).
    pub fn participant_id(&self) -> Option<String> {
        self.remote.participant_id().map(|p| p.to_string())
    }

    /// Asks the owner for the keyboard (invitations with control).
    pub fn request_control(&self) {
        block_on(self.remote.request_control());
    }

    /// Gives the keyboard back (or withdraws the request).
    pub fn release_control(&self) {
        block_on(self.remote.release_control());
    }

    /// Link guests: changes your display name (at most 40 characters).
    pub fn set_name(&self, name: String) {
        block_on(self.remote.set_name(&name));
    }

    /// Owner: hands the keyboard to a participant, for `minutes` (1-240)
    /// or until it is given back or taken (`None`, the default).
    #[uniffi::method(default(minutes = None))]
    pub fn grant_control(&self, participant_id: String, minutes: Option<u32>) -> Result<()> {
        let id = parse_id(&participant_id)?;
        check_minutes(minutes)?;
        block_on(self.remote.grant_control(id, minutes));
        Ok(())
    }

    /// When the current driver's timed grant ends (ms since the epoch);
    /// `None` if it is not timed or the owner has the keyboard.
    pub fn control_until(&self) -> Option<i64> {
        self.remote.control_until()
    }

    /// Owner: says no to a request for the keyboard.
    pub fn deny_control(&self, participant_id: String) -> Result<()> {
        let id = parse_id(&participant_id)?;
        block_on(self.remote.deny_control(id));
        Ok(())
    }

    /// Owner: takes the keyboard back.
    pub fn take_control(&self) {
        block_on(self.remote.take_control());
    }

    /// Owner: lets someone in from the waiting room.
    pub fn allow_join(&self, participant_id: String) -> Result<()> {
        let id = parse_id(&participant_id)?;
        block_on(self.remote.allow_join(id));
        Ok(())
    }

    /// Owner: does not let someone in.
    pub fn deny_join(&self, participant_id: String) -> Result<()> {
        let id = parse_id(&participant_id)?;
        block_on(self.remote.deny_join(id));
        Ok(())
    }

    /// Owner: sends a participant away. `revoke_share`: also revokes the
    /// invitation they used (for a team or a link, everyone who joined with
    /// it and has no other one leaves too).
    pub fn kick(&self, participant_id: String, revoke_share: bool) -> Result<()> {
        let id = parse_id(&participant_id)?;
        block_on(self.remote.kick(id, revoke_share));
        Ok(())
    }

    /// Owner: stops sharing (every invitation is revoked; everyone else leaves).
    pub fn stop_sharing(&self) {
        block_on(self.remote.stop_sharing());
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

/// Details of a link invitation (no account needed), to show before joining.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct LinkInvite {
    pub session_id: String,
    pub title: String,
    /// Name of who shares it.
    pub owner: String,
    /// The most you can get: `Control` (can ask for the keyboard) or `View`.
    pub access: SessionAccess,
    /// You will wait until the owner lets you in.
    pub require_approval: bool,
    /// People inside now.
    pub participants: u32,
    pub expires_at: Option<i64>,
}

fn check_token(token: &str) -> Result<String> {
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
    Ok(token)
}

async fn fetch_join_info(api: &ApiClient, token: &str) -> Result<JoinInfo> {
    let resp = reqwest::Client::new()
        .get(format!("{}/api/v1/join/{token}", api.base_url()))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(TermoakError::NotFound(
            "the link is not valid, has expired or the session has ended".into(),
        ));
    }
    Ok(resp.json().await?)
}

fn session_of(info: &JoinInfo) -> String {
    info.ws_path
        .split('/')
        .nth(4)
        .unwrap_or_default()
        .to_string()
}

/// What a link invitation offers (`server_url` and `token` come from the
/// link `termoak://join?server=...&token=...`).
#[uniffi::export]
pub async fn link_invite_info(server_url: String, token: String) -> Result<LinkInvite> {
    crate::vault::install_crypto_provider();
    run(async move {
        let api = ApiClient::new(&server_url)?;
        let token = check_token(&token)?;
        let info = fetch_join_info(&api, &token).await?;
        Ok(LinkInvite {
            session_id: session_of(&info),
            title: str_of(&info.session["title"]),
            owner: info.owner.clone(),
            access: SessionAccess::parse(&info.permission),
            require_approval: info.require_approval,
            participants: info.session["participants"].as_u64().unwrap_or(0) as u32,
            expires_at: info.expires_at,
        })
    })
    .await
}

/// Joins a shared session with an invitation link, without an account
/// (as "Guest N"). `server_url` and `token` come from the link
/// (`termoak://join?server=...&token=...`).
#[uniffi::export]
pub async fn join_shared_session(
    server_url: String,
    token: String,
    listener: Arc<dyn ServerTerminalListener>,
) -> Result<Arc<ServerTerminalHandle>> {
    join_shared_session_as(server_url, token, None, listener).await
}

/// Joins with a link, without an account, under a display name (at most 40
/// characters). If the invitation asks for approval, `Waiting` arrives
/// first and `Hello` once the owner lets you in.
#[uniffi::export]
pub async fn join_shared_session_as(
    server_url: String,
    token: String,
    name: Option<String>,
    listener: Arc<dyn ServerTerminalListener>,
) -> Result<Arc<ServerTerminalHandle>> {
    crate::vault::install_crypto_provider();
    run(async move {
        let api = ApiClient::new(&server_url)?;
        let token = check_token(&token)?;
        let info = fetch_join_info(&api, &token).await?;
        let (remote, events) =
            RemoteTerminal::attach_as(&api, &info.ws_path, name.as_deref()).await?;
        Ok(start_remote(session_of(&info), remote, events, listener))
    })
    .await
}

#[uniffi::export]
impl TermoakCore {
    /// Joins with a link of this server while signed in (you appear with
    /// your account's name; a direct invitation of yours is used if it
    /// gives more).
    pub async fn join_link(
        &self,
        token: String,
        listener: Arc<dyn ServerTerminalListener>,
    ) -> Result<Arc<ServerTerminalHandle>> {
        let api = self.api().await?;
        run(async move {
            let token = check_token(&token)?;
            let info = fetch_join_info(&api, &token).await?;
            let (remote, events) = RemoteTerminal::attach_path(&api, &info.ws_path).await?;
            Ok(start_remote(session_of(&info), remote, events, listener))
        })
        .await
    }
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
    /// Event as JSON, with `"account_id"` (the account it comes from).
    /// Types (`type`): `hello` (user and pending approvals),
    /// `ai` (a task event: `task_id`, `seq`, `event`), `session` (`notice`:
    /// `session_opened`, `session_closed`, `session_shared`,
    /// `prompt_pending`, `join_request`, `control_request`,
    /// `control_granted`, `control_revoked`), `vault` (`event`: `changed`
    /// or `access`, with `vault_id`; the account syncs by itself) and
    /// `lagged` (events were lost: refresh).
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
        let account = self.account_now()?;
        let api = self.api().await?;
        let ws = run(async move { Ok(api.websocket("/api/v1/events/ws").await?) }).await?;
        let weak = Arc::downgrade(&account);
        let account_id = account.id;
        drop(account);
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
                    Some(Some(Ok(Message::Text(t)))) => {
                        match serde_json::from_str::<Value>(&t) {
                            Ok(v) => {
                                // Vault changes: sync that account.
                                if termoak_client::events::wants_sync(&v)
                                    && let Some(acc) = weak.upgrade()
                                {
                                    acc.sync_soon();
                                }
                                let v = termoak_client::events::tag_event(v, account_id);
                                listener.on_event(v.to_string())
                            }
                            Err(_) => listener.on_event(t.to_string()),
                        }
                    }
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

/// What the device that shares a terminal hears from the server.
#[derive(Debug, Clone, PartialEq, uniffi::Enum)]
pub enum SharedTerminalEvent {
    /// Who is in the session and who drives (`None`: you).
    Participants {
        participants: Vec<SessionParticipant>,
        driver: Option<String>,
    },
    /// The keyboard changed hands. `until`: when a timed grant ends (ms).
    Control {
        driver: Option<String>,
        driver_name: Option<String>,
        until: Option<i64>,
    },
    /// A timed grant ended: the keyboard is yours again
    /// (`participant_id`: who had it).
    ControlExpired { participant_id: Option<String> },
    /// The driver would like this size. The terminal is here: apply it or
    /// ignore it (guests follow the size you report with `resize`).
    ResizeRequest { cols: u32, rows: u32 },
    /// Someone waits to be let in (`allow_join` / `deny_join`).
    JoinRequest { participant: SessionParticipant },
    /// Someone asks for the keyboard (`grant_control` / `deny_control`).
    ControlRequest { participant: SessionParticipant },
    /// The connection to the server dropped; it is being retried.
    Reconnecting,
    /// Back after `Reconnecting`.
    Reconnected,
    /// Sharing ended (`code` if the server said why). Nothing else arrives.
    Ended { code: Option<String> },
}

/// Implemented by the app to hear about a shared terminal.
///
/// **Threads**: its own background thread, in order; it must return quickly.
#[uniffi::export(foreign)]
pub trait SharedTerminalListener: Send + Sync {
    fn on_event(&self, event: SharedTerminalEvent);
}

fn convert_relay(ev: RelayEvent) -> SharedTerminalEvent {
    match ev {
        RelayEvent::Participants {
            participants,
            driver,
        } => SharedTerminalEvent::Participants {
            participants: participants.iter().map(Into::into).collect(),
            driver: driver.map(|d| d.to_string()),
        },
        RelayEvent::Control {
            driver,
            driver_name,
            until,
        } => SharedTerminalEvent::Control {
            driver: driver.map(|d| d.to_string()),
            driver_name,
            until,
        },
        RelayEvent::ControlExpired { participant } => SharedTerminalEvent::ControlExpired {
            participant_id: participant.map(|p| p.to_string()),
        },
        RelayEvent::ResizeRequest { cols, rows } => SharedTerminalEvent::ResizeRequest {
            cols: cols.into(),
            rows: rows.into(),
        },
        RelayEvent::JoinRequest(p) => SharedTerminalEvent::JoinRequest {
            participant: (&p).into(),
        },
        RelayEvent::ControlRequest(p) => SharedTerminalEvent::ControlRequest {
            participant: (&p).into(),
        },
        RelayEvent::Reconnecting => SharedTerminalEvent::Reconnecting,
        RelayEvent::Reconnected => SharedTerminalEvent::Reconnected,
        RelayEvent::Ended { code } => SharedTerminalEvent::Ended { code },
    }
}

/// Local terminal shared through the server. The terminal stays on this
/// device; the server relays the output to the guests and what the driver
/// types. Sharing stops with `stop` or when dropped.
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
    async fn owner(&self, msg: Value) -> Result<()> {
        let share = self.share.clone();
        run(async move {
            if let Some(s) = share.lock().await.as_ref() {
                s.send_raw(msg).await;
            }
            Ok(())
        })
        .await
    }

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

/// A timed grant lasts 1-240 minutes.
pub(crate) fn check_minutes(minutes: Option<u32>) -> Result<()> {
    match minutes {
        Some(m) if !(1..=owner_msg::MAX_CONTROL_MINUTES).contains(&m) => Err(
            TermoakError::Invalid("the keyboard can be handed over for 1 to 240 minutes".into()),
        ),
        _ => Ok(()),
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

    /// Invites a server user by email (`control` = can ask for the keyboard).
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

    /// Creates a link for guests without an account (no expiry if not
    /// given). They wait until you let them in (`JoinRequest`).
    pub async fn invite_link(
        &self,
        control: bool,
        expires_in_minutes: Option<i64>,
    ) -> Result<ShareInvite> {
        self.create_invite(json!({"link": true, "permission": permission(control), "expires_in_minutes": expires_in_minutes, "require_approval": true}))
            .await
    }

    /// Invites with every option (waiting room, automatic keyboard...).
    pub async fn invite(
        &self,
        target: crate::account::ShareTarget,
        options: crate::account::ShareOptions,
    ) -> Result<ShareInvite> {
        self.create_invite(crate::account::share_body_with(&target, &options)?)
            .await
    }

    /// Revokes an invitation (whoever used it and has no other one leaves).
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

    /// Receives what happens in the shared session (participants, requests,
    /// reconnections). Call it once.
    pub async fn set_listener(&self, listener: Arc<dyn SharedTerminalListener>) -> Result<()> {
        let share = self.share.clone();
        let rx = run(async move { Ok(share.lock().await.as_ref().map(|s| s.subscribe())) }).await?;
        let Some(mut rx) = rx else {
            return Err(TermoakError::Invalid(
                "the terminal is no longer shared".into(),
            ));
        };
        spawn_callback_thread("termoak-shared-term", move |rt| {
            loop {
                match rt.block_on(rx.recv()) {
                    Ok(ev) => {
                        let end = matches!(ev, RelayEvent::Ended { .. });
                        listener.on_event(convert_relay(ev));
                        if end {
                            return;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        listener.on_event(SharedTerminalEvent::Ended { code: None });
                        return;
                    }
                }
            }
        });
        Ok(())
    }

    /// Hands the keyboard to a participant, for `minutes` (1-240) or until
    /// it is given back or taken (`None`, the default).
    #[uniffi::method(default(minutes = None))]
    pub async fn grant_control(&self, participant_id: String, minutes: Option<u32>) -> Result<()> {
        let id = parse_id(&participant_id)?;
        check_minutes(minutes)?;
        self.owner(owner_msg::grant_control(id, minutes)).await
    }

    /// Says no to a request for the keyboard.
    pub async fn deny_control(&self, participant_id: String) -> Result<()> {
        let id = parse_id(&participant_id)?;
        self.owner(owner_msg::deny_control(id)).await
    }

    /// Takes the keyboard back.
    pub async fn take_control(&self) -> Result<()> {
        self.owner(owner_msg::take_control()).await
    }

    /// Lets someone in from the waiting room.
    pub async fn allow_join(&self, participant_id: String) -> Result<()> {
        let id = parse_id(&participant_id)?;
        self.owner(owner_msg::allow_join(id)).await
    }

    /// Does not let someone in.
    pub async fn deny_join(&self, participant_id: String) -> Result<()> {
        let id = parse_id(&participant_id)?;
        self.owner(owner_msg::deny_join(id)).await
    }

    /// Sends a participant away (`revoke_share`: and revokes their invitation).
    pub async fn kick(&self, participant_id: String, revoke_share: bool) -> Result<()> {
        let id = parse_id(&participant_id)?;
        self.owner(owner_msg::kick(id, revoke_share)).await
    }

    /// Revokes every invitation (everyone leaves) but keeps sharing the
    /// terminal, so you can invite again.
    pub async fn revoke_all_invites(&self) -> Result<()> {
        self.owner(owner_msg::stop_sharing()).await
    }

    /// The invitations of this shared terminal.
    pub async fn list_invites(&self) -> Result<Vec<SessionShareInfo>> {
        let api = self.api.clone();
        let id = self.session_id;
        run(async move { crate::account::list_shares(&api, id).await }).await
    }

    /// Changes an invitation live (permission, expiry, approval, automatic
    /// keyboard).
    pub async fn update_invite(
        &self,
        share_id: String,
        changes: ShareChanges,
    ) -> Result<SessionShareInfo> {
        let share = parse_id(&share_id)?;
        let api = self.api.clone();
        let id = self.session_id;
        run(async move { crate::account::update_share(&api, id, share, &changes).await }).await
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
    /// invite with `invite_user` or `invite_link`. SSH and Telnet terminals.
    pub async fn share_terminal(
        &self,
        terminal: Arc<TerminalHandle>,
        title: String,
    ) -> Result<Arc<SharedTerminal>> {
        let api = self.api().await?;
        let term = terminal.terminal();
        run(async move {
            let share = match term {
                Terminal::Ssh(t) => RelayShare::start(&api, t, &title).await?,
                // Telnet: its output hub, with the input and the end forwarded.
                Terminal::Telnet(t) => {
                    let (input, mut input_rx) = mpsc::unbounded_channel::<bytes::Bytes>();
                    let writer = t.clone();
                    tokio::spawn(async move {
                        while let Some(data) = input_rx.recv().await {
                            if writer.write(data).await.is_err() {
                                break;
                            }
                        }
                    });
                    let (closed_tx, closed) = tokio::sync::watch::channel(false);
                    let mut status = t.watch_status();
                    tokio::spawn(async move {
                        let _ = status.wait_for(|s| s.is_closed()).await;
                        let _ = closed_tx.send(true);
                    });
                    let local = LocalTerm {
                        hub: t.hub().clone(),
                        input,
                        size: t.size(),
                        closed,
                    };
                    RelayShare::start_local(&api, local, &title).await?
                }
            };
            Ok(Arc::new(SharedTerminal {
                session_id: share.session_id,
                api,
                share: Arc::new(tokio::sync::Mutex::new(Some(share))),
            }))
        })
        .await
    }
}

#[cfg(test)]
mod share_tests {
    use super::*;
    use crate::account::ShareKind;
    use crate::server::ParticipantKind;

    #[test]
    fn participants_control_and_ends_reach_the_apps() {
        let pid = termoak_core::new_id();
        let p = termoak_client::remote::Participant::list_from_json(&json!([{
            "id": pid, "name": "Zoe", "kind": "guest", "access": "control",
            "is_driver": true, "since": 5, "devices": 2, "you": true
        }]));
        match convert_event(RemoteEvent::Participants {
            participants: p,
            driver: Some(pid),
        }) {
            ServerTerminalEvent::Participants {
                participants,
                driver,
            } => {
                assert_eq!(driver, Some(pid.to_string()));
                assert_eq!(participants[0].kind, ParticipantKind::Guest);
                assert_eq!(participants[0].access, SessionAccess::Control);
                assert_eq!(participants[0].devices, 2);
                assert!(participants[0].you && participants[0].is_driver);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            convert_event(RemoteEvent::Ended {
                code: "kicked".into(),
                message: "bye".into()
            }),
            ServerTerminalEvent::Ended {
                code: "kicked".into(),
                message: "bye".into()
            }
        );
        assert_eq!(
            convert_event(RemoteEvent::Waiting(json!({
                "participant": pid, "session": {"title": "web", "owner": "Ana"}
            }))),
            ServerTerminalEvent::Waiting {
                participant_id: Some(pid.to_string()),
                title: "web".into(),
                owner: "Ana".into()
            }
        );
        // A timed grant and its end.
        let remote = termoak_client::remote::RemoteEvent::Control {
            driver: Some(pid),
            driver_name: Some("Zoe".into()),
            can_write: false,
            until: Some(1_900_000),
        };
        assert!(matches!(
            convert_event(remote),
            ServerTerminalEvent::Control {
                until: Some(1_900_000),
                ..
            }
        ));
        assert_eq!(
            convert_event(RemoteEvent::ControlExpired {
                participant: Some(pid)
            }),
            ServerTerminalEvent::ControlExpired {
                participant_id: Some(pid.to_string())
            }
        );
        assert_eq!(
            convert_relay(RelayEvent::ControlExpired { participant: None }),
            SharedTerminalEvent::ControlExpired {
                participant_id: None
            }
        );
        assert!(check_minutes(Some(240)).is_ok() && check_minutes(None).is_ok());
        assert!(check_minutes(Some(0)).is_err() && check_minutes(Some(241)).is_err());
    }

    #[test]
    fn share_info_from_the_server() {
        let s = SessionShareInfo::from_json(&json!({
            "id": "a", "session_id": "b", "is_link": true, "permission": "control",
            "expires_at": 10, "revoked": false, "active": true, "require_approval": true,
            "auto_grant": false, "created_at": 1, "participants": 3
        }));
        assert_eq!(s.kind, ShareKind::Link);
        assert!(s.control && s.require_approval && s.active);
        assert_eq!(s.participants, 3);
        assert_eq!(s.control_minutes, None);
        let timed = SessionShareInfo::from_json(&json!({"id": "d", "control_minutes": 15}));
        assert_eq!(timed.control_minutes, Some(15));
        let mut opts = crate::account::ShareOptions {
            control: true,
            expires_in_minutes: None,
            require_approval: None,
            auto_grant: true,
            control_minutes: Some(10),
        };
        let link = crate::account::ShareTarget::Link;
        let body = crate::account::share_body_with(&link, &opts).unwrap();
        assert_eq!(body["control_minutes"], 10);
        opts.control_minutes = Some(0);
        assert!(crate::account::share_body_with(&link, &opts).is_err());
        let t =
            SessionShareInfo::from_json(&json!({"id": "c", "team_id": "t", "permission": "view"}));
        assert_eq!(t.kind, ShareKind::Team);
        assert!(!t.control);
    }
}

//! Terminals that live on the server, seen from a client (WebSocket).
//!
//! If the connection to the server drops (it restarts, the network goes
//! away...), it reconnects by itself: the session stays alive there. Meanwhile
//! it emits [`RemoteEvent::Reconnecting`] and, once back,
//! [`RemoteEvent::Resync`] followed by the full history. It does not
//! reconnect when the server sends it away for good ([`RemoteEvent::Ended`]:
//! access revoked, kicked out, expired, not let in, session over).
//!
//! Shared sessions (protocol 2, see the server's `WEBSOCKET-PROTOCOL.md`):
//! one person drives at a time. The owner can always type; everyone else
//! joins read-only and asks for the keyboard with
//! [`RemoteTerminal::request_control`]. [`RemoteTerminal::can_write`] says
//! whether input and resizes reach the terminal now; while it is `false`
//! this side does not send them.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use termoak_core::Id;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

use crate::api::{ApiClient, WsStream};
use crate::error::{ClientError, Result};

/// Codes with which the server sends someone away for good (`error.code`
/// and the reason of the close frame).
pub const END_CODES: &[&str] = &[
    "revoked",
    "kicked",
    "expired",
    "session_ended",
    "join_denied",
    "forbidden",
];

/// A person in a shared session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Participant {
    /// Participant id (the same on every device of the person).
    pub id: Id,
    pub name: String,
    /// `owner`, `user` (account on the server) or `guest` (link, no account).
    #[serde(default)]
    pub kind: String,
    /// `owner`, `control` (can ask for the keyboard) or `view`.
    #[serde(default)]
    pub access: String,
    /// Has the keyboard (the owner when nobody else has it).
    #[serde(default)]
    pub is_driver: bool,
    /// Since when (ms).
    #[serde(default)]
    pub since: i64,
    /// Devices attached (0 while reconnecting).
    #[serde(default)]
    pub devices: u32,
    /// Asked for the keyboard and waits for the owner.
    #[serde(default)]
    pub requested_control: bool,
    /// In the waiting room (only in the owner's list).
    #[serde(default)]
    pub waiting: bool,
    /// It is you.
    #[serde(default)]
    pub you: bool,
    /// Only in the owner's list.
    #[serde(default)]
    pub user_id: Option<Id>,
    /// Only in the owner's list.
    #[serde(default)]
    pub share_id: Option<Id>,
}

impl Participant {
    pub fn list_from_json(v: &Value) -> Vec<Participant> {
        v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|p| serde_json::from_value(p.clone()).ok())
                    .collect()
            })
            .unwrap_or_default()
    }
}

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
    /// Who is connected (sockets; servers before protocol 2).
    Presence(Value),
    /// Who is in the session and who drives (`None`: the owner).
    Participants {
        participants: Vec<Participant>,
        driver: Option<Id>,
    },
    /// The keyboard changed hands. `can_write`: your input reaches the
    /// terminal now. `until`: when a timed grant ends (ms), if it is timed.
    Control {
        driver: Option<Id>,
        driver_name: Option<String>,
        can_write: bool,
        until: Option<i64>,
    },
    /// A timed grant ended: the keyboard went back to the owner. It reaches
    /// whoever had it and the owner (`participant`: who had it).
    ControlExpired {
        participant: Option<Id>,
    },
    /// You are in the waiting room until the owner lets you in (`Hello`
    /// arrives then).
    Waiting(Value),
    /// Owner: someone waits to be let in (`allow_join` / `deny_join`).
    JoinRequest(Participant),
    /// Owner: someone asks for the keyboard (`grant_control` / `deny_control`).
    ControlRequest(Participant),
    /// The owner said no to your request for the keyboard.
    ControlDenied,
    /// Authentication prompt (2FA, fingerprint, password), sent only to the owner.
    Prompt(Value),
    Resize {
        cols: u16,
        rows: u16,
    },
    /// Error that does not end the connection (an action that was not allowed...).
    Error(String),
    /// The server sent you away for good: `code` is one of [`END_CODES`].
    /// `Closed` follows; it is not retried.
    Ended {
        code: String,
        message: String,
    },
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

/// What this side knows about its place in the session.
#[derive(Debug, Default)]
struct Seat {
    participant: Option<Id>,
    owner: bool,
    /// `None` until the first `hello`.
    can_write: Option<bool>,
    driver: Option<Id>,
    /// End of the current timed grant (ms).
    until: Option<i64>,
    waiting: bool,
}

/// An attached remote terminal.
#[derive(Clone)]
pub struct RemoteTerminal {
    tx: mpsc::Sender<Outgoing>,
    seat: Arc<Mutex<Seat>>,
}

/// Adds the protocol version (and, for links, a guest key that survives
/// reconnects and the display name) to a WebSocket path.
pub fn ws_path(path: &str, guest_name: Option<&str>) -> String {
    fn add(path: &mut String, k: &str, v: &str) {
        let sep = if path.contains('?') { '&' } else { '?' };
        let v: String = url::form_urlencoded::byte_serialize(v.as_bytes()).collect();
        path.push_str(&format!("{sep}{k}={v}"));
    }
    let mut path = path.to_string();
    add(&mut path, "proto", "2");
    if path.contains("share_token=") {
        add(
            &mut path,
            "guest",
            &uuid::Uuid::new_v4().simple().to_string(),
        );
        if let Some(name) = guest_name.map(str::trim).filter(|n| !n.is_empty()) {
            add(&mut path, "name", name);
        }
    }
    path
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
        Self::attach_as(api, path, None).await
    }

    /// Joins with a link (`path` with `share_token`) under a display name
    /// (guests without an account; at most 40 characters).
    pub async fn attach_as(
        api: &ApiClient,
        path: &str,
        guest_name: Option<&str>,
    ) -> Result<(Self, mpsc::Receiver<RemoteEvent>)> {
        let path = ws_path(path, guest_name);
        let ws = api.websocket(&path).await?;
        let (events_tx, events_rx) = mpsc::channel::<RemoteEvent>(1024);
        let (tx, rx) = mpsc::channel::<Outgoing>(256);
        let seat = Arc::new(Mutex::new(Seat::default()));
        tokio::spawn(run(api.clone(), path, ws, rx, events_tx, seat.clone()));
        Ok((Self { tx, seat }, events_rx))
    }

    /// Your input and resizes reach the terminal now (you are the owner or
    /// have the keyboard). `false` until the server says hello.
    pub fn can_write(&self) -> bool {
        self.seat.lock().can_write.unwrap_or(false)
    }

    /// Participant with the keyboard (`None`: the owner).
    pub fn driver(&self) -> Option<Id> {
        self.seat.lock().driver
    }

    /// When the current driver's timed grant ends (ms since the epoch);
    /// `None` if it is not timed (or the owner has the keyboard).
    pub fn control_until(&self) -> Option<i64> {
        self.seat.lock().until
    }

    /// You have the keyboard (the owner has it when nobody else does).
    pub fn is_driver(&self) -> bool {
        let s = self.seat.lock();
        match s.driver {
            Some(d) => s.participant == Some(d),
            None => s.owner,
        }
    }

    /// Your participant id (once in).
    pub fn participant_id(&self) -> Option<Id> {
        self.seat.lock().participant
    }

    /// You are the owner of the session.
    pub fn is_owner(&self) -> bool {
        self.seat.lock().owner
    }

    /// You are in the waiting room.
    pub fn is_waiting(&self) -> bool {
        self.seat.lock().waiting
    }

    /// Sends typed input (dropped here if you cannot write).
    pub async fn input(&self, data: impl Into<Bytes>) {
        let _ = self.tx.send(Outgoing::Binary(data.into())).await;
    }

    /// New size. Remembered and sent only while you can write (the owner or
    /// the driver decide the size).
    pub async fn resize(&self, cols: u16, rows: u16) {
        self.send(json!({"type": "resize", "cols": cols, "rows": rows}))
            .await;
    }

    async fn send(&self, v: Value) {
        let _ = self.tx.send(Outgoing::Json(v)).await;
    }

    /// Answers an authentication prompt.
    pub async fn answer_prompt(
        &self,
        prompt_id: Id,
        accept: Option<bool>,
        answers: Option<Vec<String>>,
    ) {
        self.send(json!({"type": "prompt_answer", "prompt_id": prompt_id, "accept": accept, "answers": answers}))
            .await;
    }

    /// Closes the session on the server (owner only).
    pub async fn close_session(&self) {
        self.send(json!({"type": "close_session"})).await;
    }

    /// Asks the owner for the keyboard (`control` invitations).
    pub async fn request_control(&self) {
        self.send(json!({"type": "control_request"})).await;
    }

    /// Gives the keyboard back (or withdraws the request).
    pub async fn release_control(&self) {
        self.send(json!({"type": "control_release"})).await;
    }

    /// Link guests: changes the display name.
    pub async fn set_name(&self, name: &str) {
        self.send(json!({"type": "set_name", "name": name})).await;
    }

    /// Owner: hands the keyboard to a participant, for `minutes` (1-240)
    /// or until it is given back or taken (`None`). When the time is up the
    /// server takes it back by itself.
    pub async fn grant_control(&self, participant: Id, minutes: Option<u32>) {
        self.send(owner_msg::grant_control(participant, minutes))
            .await;
    }

    /// Owner: says no to a request for the keyboard.
    pub async fn deny_control(&self, participant: Id) {
        self.send(owner_msg::deny_control(participant)).await;
    }

    /// Owner: takes the keyboard back.
    pub async fn take_control(&self) {
        self.send(owner_msg::take_control()).await;
    }

    /// Owner: lets someone in from the waiting room.
    pub async fn allow_join(&self, participant: Id) {
        self.send(owner_msg::allow_join(participant)).await;
    }

    /// Owner: does not let someone in.
    pub async fn deny_join(&self, participant: Id) {
        self.send(owner_msg::deny_join(participant)).await;
    }

    /// Owner: sends a participant away (`revoke_share`: also revokes the
    /// invitation they used, so they cannot come back with it).
    pub async fn kick(&self, participant: Id, revoke_share: bool) {
        self.send(owner_msg::kick(participant, revoke_share)).await;
    }

    /// Owner: stops sharing (every invitation is revoked, everyone else leaves).
    pub async fn stop_sharing(&self) {
        self.send(owner_msg::stop_sharing()).await;
    }

    /// Detaches (the session stays alive on the server).
    pub async fn detach(&self) {
        let _ = self.tx.send(Outgoing::Close).await;
    }
}

/// Messages of the session's owner (also used by the relay host).
pub mod owner_msg {
    use serde_json::{Value, json};
    use termoak_core::Id;

    /// Longest timed grant, in minutes.
    pub const MAX_CONTROL_MINUTES: u32 = 240;

    /// `minutes`: timed grant (1-240; the server rejects anything else).
    pub fn grant_control(participant: Id, minutes: Option<u32>) -> Value {
        let mut v = json!({"type": "control_grant", "participant": participant});
        if let Some(m) = minutes {
            v["minutes"] = json!(m);
        }
        v
    }

    pub fn deny_control(participant: Id) -> Value {
        json!({"type": "control_deny", "participant": participant})
    }

    pub fn take_control() -> Value {
        json!({"type": "control_take"})
    }

    pub fn allow_join(participant: Id) -> Value {
        json!({"type": "join_allow", "participant": participant})
    }

    pub fn deny_join(participant: Id) -> Value {
        json!({"type": "join_deny", "participant": participant})
    }

    pub fn kick(participant: Id, revoke_share: bool) -> Value {
        json!({"type": "kick", "participant": participant, "revoke_share": revoke_share})
    }

    pub fn stop_sharing() -> Value {
        json!({"type": "stop_sharing"})
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
    seat: Arc<Mutex<Seat>>,
) {
    // Last requested size: sent again on reconnect.
    let mut size: Option<Value> = None;
    loop {
        match connection(ws, &mut rx, &events, &mut size, &seat).await {
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

/// Updates what this side knows from a message. Returns `true` if it just
/// became able to write (the pending size must be sent).
fn update_seat(seat: &Mutex<Seat>, ev: &RemoteEvent) -> bool {
    let mut s = seat.lock();
    let before = s.can_write.unwrap_or(false);
    match ev {
        RemoteEvent::Hello(v) => {
            let you = &v["you"];
            let access = you["access"]
                .as_str()
                .or_else(|| v["session"]["access"].as_str())
                .unwrap_or("");
            s.owner = you["kind"] == "owner" || access == "owner";
            s.participant = you["participant"].as_str().and_then(|p| p.parse().ok());
            s.driver = v["session"]["driver"].as_str().and_then(|p| p.parse().ok());
            s.until = v["session"]["driver_until"].as_i64();
            // Servers before protocol 2: `control` could always type.
            s.can_write = Some(
                you["can_write"]
                    .as_bool()
                    .unwrap_or(access == "owner" || access == "control"),
            );
            s.waiting = false;
        }
        RemoteEvent::Control {
            driver,
            can_write,
            until,
            ..
        } => {
            s.driver = *driver;
            s.until = *until;
            s.can_write = Some(*can_write);
        }
        RemoteEvent::Participants { driver, .. } => s.driver = *driver,
        RemoteEvent::Waiting(v) => {
            s.waiting = true;
            s.can_write = Some(false);
            s.participant = v["participant"].as_str().and_then(|p| p.parse().ok());
        }
        _ => {}
    }
    !before && s.can_write == Some(true)
}

async fn connection(
    ws: WsStream,
    rx: &mut mpsc::Receiver<Outgoing>,
    events: &mpsc::Sender<RemoteEvent>,
    size: &mut Option<Value>,
    seat: &Mutex<Seat>,
) -> End {
    let (mut sink, mut stream) = ws.split();
    // If it could write before, the size goes at once (otherwise after the
    // hello, if it can).
    let could_write = seat.lock().can_write == Some(true);
    if could_write
        && let Some(v) = size.as_ref()
        && sink
            .send(Message::Text(v.to_string().into()))
            .await
            .is_err()
    {
        return End::Lost;
    }
    // Sent away for good (or the session ended): do not retry.
    let mut ended = false;
    // `Ended` already delivered.
    let mut told = false;
    // An error without a code (older servers) right before the close is
    // final too (access revoked).
    let mut error_then_close = false;
    loop {
        tokio::select! {
            out = rx.recv() => {
                let can_write = seat.lock().can_write;
                let res = match out {
                    None | Some(Outgoing::Close) => {
                        let _ = sink.send(Message::Close(None)).await;
                        return End::Done;
                    }
                    // Read-only: the server would drop it anyway.
                    Some(Outgoing::Binary(_)) if can_write == Some(false) => Ok(()),
                    Some(Outgoing::Binary(b)) => sink.send(Message::Binary(b)).await,
                    Some(Outgoing::Json(v)) if v["type"] == "resize" => {
                        *size = Some(v.clone());
                        if can_write == Some(true) {
                            sink.send(Message::Text(v.to_string().into())).await
                        } else {
                            Ok(())
                        }
                    }
                    Some(Outgoing::Json(v)) => sink.send(Message::Text(v.to_string().into())).await,
                };
                if res.is_err() {
                    return End::Lost;
                }
            }
            msg = stream.next() => {
                let mut bare_error = false;
                let ev = match msg {
                    Some(Ok(Message::Binary(b))) => RemoteEvent::Output(b),
                    Some(Ok(Message::Text(t))) => {
                        let v: Value = serde_json::from_str(&t).unwrap_or(Value::Null);
                        bare_error = v["type"] == "error" && v["code"].is_null();
                        parse_event(v)
                    }
                    Some(Ok(Message::Close(frame))) => {
                        let reason = frame.as_ref().map(|f| f.reason.to_string()).unwrap_or_default();
                        let private = frame
                            .as_ref()
                            .is_some_and(|f| matches!(f.code, CloseCode::Library(c) if (4000..5000).contains(&c)));
                        if private && !told {
                            ended = true;
                            let code = if reason.is_empty() { "forbidden".to_string() } else { reason };
                            let _ = events.send(RemoteEvent::Ended { message: code.clone(), code }).await;
                        }
                        return if ended || error_then_close { End::Done } else { End::Lost };
                    }
                    None | Some(Err(_)) => {
                        return if ended || error_then_close { End::Done } else { End::Lost };
                    }
                    Some(Ok(_)) => continue,
                };
                error_then_close = bare_error;
                match &ev {
                    RemoteEvent::Ended { .. } => {
                        ended = true;
                        told = true;
                    }
                    RemoteEvent::Status(v) if v["state"] == "closed" => ended = true,
                    _ => {}
                }
                if update_seat(seat, &ev)
                    && let Some(v) = size.as_ref()
                    && sink.send(Message::Text(v.to_string().into())).await.is_err()
                {
                    return End::Lost;
                }
                if events.send(ev).await.is_err() {
                    return End::Done;
                }
            }
        }
    }
}

fn parse_id(v: &Value) -> Option<Id> {
    v.as_str().and_then(|s| s.parse().ok())
}

fn parse_event(v: Value) -> RemoteEvent {
    match v["type"].as_str().unwrap_or("") {
        "hello" => RemoteEvent::Hello(v),
        "resync" => RemoteEvent::Resync,
        "status" => RemoteEvent::Status(v["status"].clone()),
        "presence" => RemoteEvent::Presence(v["viewers"].clone()),
        "participants" => RemoteEvent::Participants {
            participants: Participant::list_from_json(&v["participants"]),
            driver: parse_id(&v["driver"]),
        },
        "control" => RemoteEvent::Control {
            driver: parse_id(&v["driver"]),
            driver_name: v["driver_name"].as_str().map(str::to_string),
            can_write: v["can_write"].as_bool().unwrap_or(false),
            until: v["until"].as_i64(),
        },
        "control_expired" => RemoteEvent::ControlExpired {
            participant: parse_id(&v["participant"]),
        },
        "waiting" => RemoteEvent::Waiting(v),
        "join_request" => match serde_json::from_value(v["participant"].clone()) {
            Ok(p) => RemoteEvent::JoinRequest(p),
            Err(_) => RemoteEvent::Other(v),
        },
        "control_request" => match serde_json::from_value(v["participant"].clone()) {
            Ok(p) => RemoteEvent::ControlRequest(p),
            Err(_) => RemoteEvent::Other(v),
        },
        "control_denied" => RemoteEvent::ControlDenied,
        "prompt" => RemoteEvent::Prompt(v),
        "resize" => RemoteEvent::Resize {
            cols: v["cols"].as_u64().unwrap_or(80) as u16,
            rows: v["rows"].as_u64().unwrap_or(24) as u16,
        },
        "error" => {
            let message = v["message"].as_str().unwrap_or("error").to_string();
            match v["code"].as_str() {
                Some(code) if END_CODES.contains(&code) => RemoteEvent::Ended {
                    code: code.to_string(),
                    message,
                },
                // Any other code: an error that does not end anything.
                _ => RemoteEvent::Error(message),
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_get_the_protocol_and_a_guest_key() {
        assert_eq!(
            ws_path("/api/v1/sessions/x/ws", None),
            "/api/v1/sessions/x/ws?proto=2"
        );
        let p = ws_path("/api/v1/sessions/x/ws?share_token=abc", Some(" Ana María "));
        assert!(p.starts_with("/api/v1/sessions/x/ws?share_token=abc&proto=2&guest="));
        assert!(p.ends_with("&name=Ana+Mar%C3%ADa"));
    }

    #[test]
    fn errors_with_and_without_codes() {
        let parse = |s: &str| parse_event(serde_json::from_str(s).unwrap());
        match parse(r#"{"type":"error","code":"kicked","message":"bye"}"#) {
            RemoteEvent::Ended { code, message } => {
                assert_eq!((code.as_str(), message.as_str()), ("kicked", "bye"))
            }
            other => panic!("{other:?}"),
        }
        let soft = parse(r#"{"type":"error","code":"bad_request","message":"no"}"#);
        assert!(matches!(soft, RemoteEvent::Error(ref m) if m == "no"));
    }

    #[test]
    fn seat_follows_hello_and_control() {
        let seat = Mutex::new(Seat::default());
        let pid = termoak_core::new_id();
        let hello = parse_event(
            json!({"type": "hello", "session": {"access": "control", "driver": null},
                    "you": {"participant": pid, "kind": "user", "access": "control", "can_write": false}}),
        );
        assert!(!update_seat(&seat, &hello));
        assert_eq!(seat.lock().can_write, Some(false));
        let grant = parse_event(
            json!({"type": "control", "driver": pid, "can_write": true, "until": 1_800_000}),
        );
        assert!(update_seat(&seat, &grant));
        assert_eq!(seat.lock().driver, Some(pid));
        assert_eq!(seat.lock().until, Some(1_800_000));
        // Time is up: the keyboard goes back to the owner.
        let back = parse_event(json!({"type": "control", "driver": null, "can_write": false}));
        update_seat(&seat, &back);
        let s = seat.lock();
        assert_eq!((s.driver, s.until), (None, None));
        drop(s);
        assert!(matches!(
            parse_event(json!({"type": "control_expired", "participant": pid})),
            RemoteEvent::ControlExpired { participant: Some(p) } if p == pid
        ));
        assert_eq!(
            owner_msg::grant_control(pid, Some(5)),
            json!({"type": "control_grant", "participant": pid, "minutes": 5})
        );
        assert_eq!(
            owner_msg::grant_control(pid, None),
            json!({"type": "control_grant", "participant": pid})
        );
        // An older server: `control` could always type.
        let seat = Mutex::new(Seat::default());
        let old =
            parse_event(json!({"type": "hello", "session": {}, "you": {"access": "control"}}));
        assert!(update_seat(&seat, &old));
    }
}

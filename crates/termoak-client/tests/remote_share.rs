//! Shared sessions seen from a client: the keyboard (read-only until it is
//! granted), participants, errors that end the connection and errors that
//! do not.

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use termoak_client::api::ApiClient;
use termoak_client::remote::{RemoteEvent, RemoteTerminal};
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

fn text(v: Value) -> Message {
    Message::Text(v.to_string().into())
}

async fn next_event(events: &mut tokio::sync::mpsc::Receiver<RemoteEvent>) -> RemoteEvent {
    tokio::time::timeout(Duration::from_secs(10), events.recv())
        .await
        .expect("no event")
        .expect("channel closed")
}

/// Next text message the server receives.
async fn next_text<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>) -> Value
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(t))) => return serde_json::from_str(&t).unwrap(),
                Some(Ok(_)) => {}
                other => panic!("socket ended: {other:?}"),
            }
        }
    })
    .await
    .expect("nothing arrived")
}

#[tokio::test]
#[allow(clippy::result_large_err)]
async fn read_only_until_the_keyboard_is_granted() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pid = "0190f5a8-0000-7000-8000-000000000001";
    let (path_tx, path_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (s, _) = listener.accept().await.unwrap();
        let mut path_tx = Some(path_tx);
        let mut ws = tokio_tungstenite::accept_hdr_async(
            s,
            |req: &tokio_tungstenite::tungstenite::handshake::server::Request, resp| {
                let _ = path_tx.take().unwrap().send(req.uri().to_string());
                Ok(resp)
            },
        )
        .await
        .unwrap();
        ws.send(text(json!({
            "type": "hello",
            "session": {"access": "control", "driver": null},
            "you": {"participant": pid, "kind": "user", "access": "control", "can_write": false},
        })))
        .await
        .unwrap();
        ws.send(text(json!({
            "type": "participants",
            "driver": null,
            "participants": [
                {"id": "0190f5a8-0000-7000-8000-000000000002", "name": "Ana", "kind": "owner", "access": "owner", "is_driver": true, "since": 1, "devices": 1},
                {"id": pid, "name": "Bea", "kind": "user", "access": "control", "is_driver": false, "since": 2, "devices": 2, "you": true},
            ],
        })))
        .await
        .unwrap();
        // The first thing that arrives is the request (the resize and the
        // input sent while read-only stayed on the client).
        let first = next_text(&mut ws).await;
        assert_eq!(first["type"], "control_request");
        ws.send(text(
            json!({"type": "control", "driver": pid, "driver_name": "Bea", "can_write": true}),
        ))
        .await
        .unwrap();
        // Once it can write, the pending size goes out.
        let size = next_text(&mut ws).await;
        assert_eq!(size, json!({"type": "resize", "cols": 100, "rows": 30}));
        // A non-final error, then the connection drops: it reconnects.
        ws.send(text(
            json!({"type": "error", "code": "bad_request", "message": "invalid message"}),
        ))
        .await
        .unwrap();
        drop(ws);
        let (s, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(s).await.unwrap();
        ws.send(text(json!({
            "type": "hello",
            "session": {"access": "control", "driver": pid},
            "you": {"participant": pid, "kind": "user", "access": "control", "can_write": true},
        })))
        .await
        .unwrap();
        // Kicked out: error with a code and close 4002; no reconnection.
        ws.send(text(
            json!({"type": "error", "code": "kicked", "message": "the owner removed you"}),
        ))
        .await
        .unwrap();
        ws.send(Message::Close(Some(CloseFrame {
            code: CloseCode::from(4002),
            reason: "kicked".into(),
        })))
        .await
        .unwrap();
        // Nobody else should knock.
        tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .is_err()
    });

    let api = ApiClient::new(&format!("http://{addr}")).unwrap();
    let (remote, mut events) = RemoteTerminal::attach_path(&api, "/ws?share_token=abc")
        .await
        .unwrap();
    let path = path_rx.await.unwrap();
    assert!(
        path.starts_with("/ws?share_token=abc&proto=2&guest="),
        "{path}"
    );
    assert!(matches!(
        next_event(&mut events).await,
        RemoteEvent::Hello(_)
    ));
    assert!(!remote.can_write());
    assert!(!remote.is_driver());
    match next_event(&mut events).await {
        RemoteEvent::Participants {
            participants,
            driver,
        } => {
            assert_eq!(driver, None);
            assert_eq!(participants.len(), 2);
            assert!(participants[1].you && participants[1].devices == 2);
        }
        other => panic!("{other:?}"),
    }
    remote.resize(100, 30).await;
    remote.input("ls\r").await;
    remote.request_control().await;
    match next_event(&mut events).await {
        RemoteEvent::Control {
            can_write,
            driver_name,
            ..
        } => {
            assert!(can_write);
            assert_eq!(driver_name.as_deref(), Some("Bea"));
        }
        other => panic!("{other:?}"),
    }
    assert!(remote.can_write() && remote.is_driver());
    assert!(
        matches!(next_event(&mut events).await, RemoteEvent::Error(m) if m == "invalid message")
    );
    assert!(matches!(
        next_event(&mut events).await,
        RemoteEvent::Reconnecting
    ));
    assert!(matches!(next_event(&mut events).await, RemoteEvent::Resync));
    assert!(matches!(
        next_event(&mut events).await,
        RemoteEvent::Hello(_)
    ));
    match next_event(&mut events).await {
        RemoteEvent::Ended { code, .. } => assert_eq!(code, "kicked"),
        other => panic!("{other:?}"),
    }
    assert!(matches!(next_event(&mut events).await, RemoteEvent::Closed));
    assert!(
        server.await.unwrap(),
        "the client reconnected after being kicked"
    );
}

#[tokio::test]
async fn waiting_room_and_owner_requests() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let guest = "0190f5a8-0000-7000-8000-000000000003";
    let server = tokio::spawn(async move {
        let (s, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(s).await.unwrap();
        ws.send(text(json!({
            "type": "hello",
            "session": {"access": "owner", "driver": null},
            "you": {"participant": "0190f5a8-0000-7000-8000-000000000002", "kind": "owner", "access": "owner", "can_write": true},
        })))
        .await
        .unwrap();
        ws.send(text(json!({"type": "join_request", "participant": {"id": guest, "name": "Guest 1", "kind": "guest", "access": "control", "waiting": true}})))
            .await
            .unwrap();
        assert_eq!(
            next_text(&mut ws).await,
            json!({"type": "join_allow", "participant": guest})
        );
        ws.send(text(json!({"type": "control_request", "participant": {"id": guest, "name": "Guest 1", "kind": "guest", "access": "control", "requested_control": true}})))
            .await
            .unwrap();
        assert_eq!(
            next_text(&mut ws).await,
            json!({"type": "control_grant", "participant": guest})
        );
        assert_eq!(
            next_text(&mut ws).await,
            json!({"type": "kick", "participant": guest, "revoke_share": true})
        );
        // The session ends: status, then close 4004.
        ws.send(text(
            json!({"type": "status", "status": {"state": "closed"}}),
        ))
        .await
        .unwrap();
        ws.send(Message::Close(Some(CloseFrame {
            code: CloseCode::from(4004),
            reason: "session_ended".into(),
        })))
        .await
        .unwrap();
    });
    let api = ApiClient::new(&format!("http://{addr}")).unwrap();
    let (remote, mut events) = RemoteTerminal::attach_path(&api, "/ws").await.unwrap();
    assert!(matches!(
        next_event(&mut events).await,
        RemoteEvent::Hello(_)
    ));
    assert!(remote.is_owner() && remote.can_write() && remote.is_driver());
    let id = match next_event(&mut events).await {
        RemoteEvent::JoinRequest(p) => {
            assert!(p.waiting);
            p.id
        }
        other => panic!("{other:?}"),
    };
    remote.allow_join(id).await;
    match next_event(&mut events).await {
        RemoteEvent::ControlRequest(p) => assert_eq!(p.id, id),
        other => panic!("{other:?}"),
    }
    remote.grant_control(id).await;
    remote.kick(id, true).await;
    assert!(matches!(
        next_event(&mut events).await,
        RemoteEvent::Status(_)
    ));
    match next_event(&mut events).await {
        RemoteEvent::Ended { code, .. } => assert_eq!(code, "session_ended"),
        other => panic!("{other:?}"),
    }
    assert!(matches!(next_event(&mut events).await, RemoteEvent::Closed));
    server.await.unwrap();
}

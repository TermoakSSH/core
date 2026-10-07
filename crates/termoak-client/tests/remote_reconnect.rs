//! Server terminals: if the connection drops, they reconnect by themselves;
//! their latency is measured with `ping` / `pong`.

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde_json::json;
use termoak_client::api::ApiClient;
use termoak_client::remote::{RemoteEvent, RemoteTerminal};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

fn text(v: serde_json::Value) -> Message {
    Message::Text(v.to_string().into())
}

fn hello() -> Message {
    text(
        json!({"type": "hello", "session": {"state": {"state": "running"}}, "you": {"access": "owner"}}),
    )
}

/// Summary of the events until closing.
async fn collect(mut events: tokio::sync::mpsc::Receiver<RemoteEvent>) -> Vec<String> {
    let mut seen = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(ev) = events.recv().await {
            seen.push(match ev {
                RemoteEvent::Hello(_) => "hello".to_string(),
                RemoteEvent::Output(b) => format!("output:{}", String::from_utf8_lossy(&b)),
                RemoteEvent::Reconnecting => "reconnecting".into(),
                RemoteEvent::Resync => "resync".into(),
                RemoteEvent::Status(v) => format!("status:{}", v["state"].as_str().unwrap_or("")),
                RemoteEvent::Closed => {
                    seen.push("closed".into());
                    return;
                }
                other => format!("{other:?}"),
            });
        }
    })
    .await
    .unwrap_or_else(|_| panic!("did not close: {seen:?}"));
    seen
}

#[tokio::test]
async fn reconnects_after_the_server_goes_away() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        // First connection: hello, some output, then it drops without notice
        // (like when the server restarts).
        let (s, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(s).await.unwrap();
        ws.send(hello()).await.unwrap();
        ws.send(Message::Binary("before".into())).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(ws);
        // Second: the client sends its size again, gets the history and the
        // session ends.
        let (s, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(s).await.unwrap();
        let size = loop {
            if let Some(Ok(Message::Text(t))) = ws.next().await {
                break t.to_string();
            }
        };
        ws.send(hello()).await.unwrap();
        ws.send(Message::Binary("before and after".into()))
            .await
            .unwrap();
        ws.send(text(
            json!({"type": "status", "status": {"state": "closed"}}),
        ))
        .await
        .unwrap();
        ws.close(None).await.unwrap();
        size
    });

    let api = ApiClient::new(&format!("http://{addr}")).unwrap();
    let (remote, events) = RemoteTerminal::attach_path(&api, "/ws").await.unwrap();
    remote.resize(90, 30).await;
    let seen = collect(events).await;
    assert_eq!(
        seen,
        [
            "hello",
            "output:before",
            "reconnecting",
            "resync",
            "hello",
            "output:before and after",
            "status:closed",
            "closed"
        ]
    );
    let size: serde_json::Value = serde_json::from_str(&server.await.unwrap()).unwrap();
    assert_eq!(size, json!({"type": "resize", "cols": 90, "rows": 30}));
}

#[tokio::test]
async fn gives_up_when_the_session_is_gone() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (s, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(s).await.unwrap();
        ws.send(hello()).await.unwrap();
        drop(ws);
        // Afterwards, the session no longer exists.
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            // Read the request first: closing a socket with unread data makes
            // Windows reset the connection instead of delivering the response.
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => request.extend_from_slice(&buf[..n]),
                }
            }
            let body = r#"{"error":{"code":"not_found","message":"not found"}}"#;
            let _ = s
                .write_all(
                    format!(
                        "HTTP/1.1 404 Not Found\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await;
            let _ = s.shutdown().await;
        }
    });
    let api = ApiClient::new(&format!("http://{addr}")).unwrap();
    let (_remote, events) = RemoteTerminal::attach_path(&api, "/ws").await.unwrap();
    assert_eq!(collect(events).await, ["hello", "reconnecting", "closed"]);
}

#[tokio::test]
async fn latency_with_ping_and_pong() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (s, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(s).await.unwrap();
        ws.send(hello()).await.unwrap();
        let mut pings = 0;
        while let Some(Ok(msg)) = ws.next().await {
            let Message::Text(t) = msg else { continue };
            let v: serde_json::Value = serde_json::from_str(&t).unwrap();
            if v["type"] != "ping" {
                continue;
            }
            pings += 1;
            match pings {
                // The first one is answered late.
                1 => tokio::time::sleep(Duration::from_millis(80)).await,
                // The second is never answered.
                2 => continue,
                _ => {}
            }
            ws.send(text(json!({"type": "pong", "ts": 1})))
                .await
                .unwrap();
            if pings == 3 {
                ws.send(Message::Binary("after".into())).await.unwrap();
                ws.send(text(
                    json!({"type": "status", "status": {"state": "closed"}}),
                ))
                .await
                .unwrap();
                ws.close(None).await.unwrap();
                break;
            }
        }
        pings
    });

    let api = ApiClient::new(&format!("http://{addr}")).unwrap();
    let (remote, events) = RemoteTerminal::attach_path(&api, "/ws").await.unwrap();
    let rtt = remote.latency(Duration::from_secs(5)).await.unwrap();
    assert!(
        rtt >= Duration::from_millis(80) && rtt < Duration::from_secs(5),
        "{rtt:?}"
    );
    // No answer: gives up after the timeout.
    assert_eq!(remote.latency(Duration::from_millis(200)).await, None);
    // The next pong answers the oldest ping (the one nobody waits for any
    // more), so this one gets no answer either and the session ends.
    assert_eq!(remote.latency(Duration::from_secs(5)).await, None);
    // Pongs are not events.
    assert_eq!(
        collect(events).await,
        ["hello", "output:after", "status:closed", "closed"]
    );
    assert_eq!(server.await.unwrap(), 3);
    // Closed: nothing answers.
    assert_eq!(remote.latency(Duration::from_secs(1)).await, None);
}

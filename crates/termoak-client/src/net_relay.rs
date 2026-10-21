//! Private networks from the apps (0.7): the "server relay" transport.
//!
//! The apps never join a WireGuard, Tailscale or ZeroTier network
//! themselves. To reach a host whose effective settings have a
//! `network_id`, the first connection (to the host, or to its first jump
//! host) is a WebSocket to the account's server,
//! `GET /api/v1/hosts/{id}/relay`: the server dials the first hop through
//! `termoak-netd` and pipes the bytes both ways (binary frames). SSH (or
//! Telnet) runs inside, end to end between the device and the host: the
//! server never sees the keys nor the session.
//!
//! [`RelayDialer`] is the [`NetworkDialer`] the workspace gives the SSH
//! engine for such hosts; [`ws_stream`] turns the WebSocket into a byte
//! stream for russh.

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use termoak_core::error::codes;
use termoak_ssh::net::{BoxedStream, DialRequest, NetworkDialer};
use termoak_ssh::{Result as SshResult, SshError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;

use crate::api::{ApiClient, WsStream};
use crate::error::ClientError;

/// Feature of `/api/v1/info` that tells the server can reach private
/// networks (it has `termoak-netd`).
pub const FEATURE: &str = "networks";

/// Bytes buffered between the WebSocket and the SSH engine.
const BUFFER: usize = 256 * 1024;

/// Path of the relay of a host (the server dials its first hop).
pub fn relay_path(target_host_id: termoak_core::Id) -> String {
    format!("/api/v1/hosts/{target_host_id}/relay")
}

/// Dials through the server relay of an account.
pub struct RelayDialer {
    api: ApiClient,
}

impl RelayDialer {
    pub fn new(api: ApiClient) -> Self {
        Self { api }
    }
}

#[async_trait::async_trait]
impl NetworkDialer for RelayDialer {
    async fn dial(&self, req: DialRequest<'_>) -> SshResult<BoxedStream> {
        let target = format!("{}:{}", req.address, req.port);
        let ws = tokio::time::timeout(
            req.timeout + Duration::from_secs(5),
            self.api.websocket(&relay_path(req.target_host_id)),
        )
        .await
        .map_err(|_| SshError::Timeout(format!("connecting to {target} through the server relay")))?
        .map_err(|e| relay_error(e, &target))?;
        Ok(Box::new(ws_stream(ws)))
    }
}

/// A relay failure as an SSH engine error: the server's network codes keep
/// their meaning (`network_unavailable`, `network_not_found`,
/// `network_dial_failed`), and so do the vault rules (`use_only_strict`,
/// `vault_not_found`) and a missing host.
pub fn relay_error(e: ClientError, target: &str) -> SshError {
    use termoak_core::CoreError;
    let ClientError::Api { message, .. } = &e else {
        return SshError::Connect {
            target: target.to_string(),
            reason: format!("server relay: {e}"),
        };
    };
    let message = message.clone();
    let network = |code| SshError::Network {
        code,
        message: message.clone(),
    };
    match e.api_code().unwrap_or("") {
        codes::NETWORK_UNAVAILABLE => network(codes::NETWORK_UNAVAILABLE),
        codes::NETWORK_NOT_FOUND => network(codes::NETWORK_NOT_FOUND),
        codes::NETWORK_DIAL_FAILED => network(codes::NETWORK_DIAL_FAILED),
        codes::USE_ONLY_STRICT => SshError::Core(CoreError::vault(codes::USE_ONLY_STRICT, message)),
        codes::VAULT_NOT_FOUND => SshError::Core(CoreError::vault(codes::VAULT_NOT_FOUND, message)),
        "not_found" => SshError::Core(CoreError::NotFound(message)),
        _ => SshError::Network {
            code: codes::NETWORK_DIAL_FAILED,
            message: format!("server relay to {target}: {e}"),
        },
    }
}

/// Turns a WebSocket of binary frames into a byte stream: what is written
/// goes out as binary frames, what arrives is read back. The stream ends
/// when the WebSocket closes (either side).
pub fn ws_stream(ws: WsStream) -> tokio::io::DuplexStream {
    let (app, mut pipe) = tokio::io::duplex(BUFFER);
    tokio::spawn(async move {
        let (mut sink, mut source) = ws.split();
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            tokio::select! {
                n = pipe.read(&mut buf) => match n {
                    Ok(0) | Err(_) => {
                        let _ = sink.send(Message::Close(None)).await;
                        break;
                    }
                    Ok(n) => {
                        if sink
                            .send(Message::Binary(buf[..n].to_vec().into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                },
                msg = source.next() => match msg {
                    Some(Ok(Message::Binary(b))) => {
                        if pipe.write_all(&b).await.is_err() {
                            let _ = sink.send(Message::Close(None)).await;
                            break;
                        }
                    }
                    // Pings are answered by the WebSocket itself.
                    Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Text(_))) => {}
                    Some(Ok(Message::Frame(_))) => {}
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                },
            }
        }
        let _ = pipe.shutdown().await;
    });
    app
}

#[cfg(test)]
#[allow(clippy::result_large_err)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// A relay server: accepts the WebSocket (checking the path and the
    /// token) and echoes the bytes back, or refuses with an API error.
    async fn relay(refuse: Option<(u16, &'static str)>) -> String {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = l.accept().await {
                tokio::spawn(async move {
                    let check =
                        |req: &tokio_tungstenite::tungstenite::handshake::server::Request, resp| {
                            assert!(req.uri().path().ends_with("/relay"), "{}", req.uri());
                            assert_eq!(
                                req.headers()["authorization"].to_str().unwrap(),
                                "Bearer tok"
                            );
                            match refuse {
                                Some((status, code)) => {
                                    let body = serde_json::json!({"error": {
                                        "code": code, "message": "refused", "network_id": "n1"
                                    }})
                                    .to_string();
                                    Err(tokio_tungstenite::tungstenite::http::Response::builder()
                                        .status(status)
                                        .body(Some(body))
                                        .unwrap())
                                }
                                None => Ok(resp),
                            }
                        };
                    let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(tcp, check).await else {
                        return;
                    };
                    while let Some(Ok(m)) = ws.next().await {
                        match m {
                            Message::Binary(b) => {
                                if ws.send(Message::Binary(b)).await.is_err() {
                                    break;
                                }
                            }
                            Message::Close(_) => break,
                            _ => {}
                        }
                    }
                });
            }
        });
        format!("http://{addr}")
    }

    fn api(base: &str) -> ApiClient {
        ApiClient::new(base)
            .unwrap()
            .with_tokens(Some(termoak_core::model::TokenPair {
                access_token: "tok".into(),
                access_expires_at: termoak_core::time::now_ms() + 3_600_000,
                refresh_token: "r".into(),
                refresh_expires_at: termoak_core::time::now_ms() + 3_600_000,
                device_id: termoak_core::new_id(),
            }))
    }

    fn req(target: termoak_core::Id) -> DialRequest<'static> {
        DialRequest {
            network_id: termoak_core::new_id(),
            network: None,
            target_host_id: target,
            hop_host_id: target,
            address: "10.0.0.5",
            port: 22,
            timeout: Duration::from_secs(5),
        }
    }

    #[tokio::test]
    async fn bytes_go_through_the_relay_both_ways() {
        let base = relay(None).await;
        let dialer = RelayDialer::new(api(&base));
        let mut s = dialer.dial(req(termoak_core::new_id())).await.unwrap();
        // More than one frame's worth, both ways.
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let to_send = data.clone();
        let (mut r, mut w) = tokio::io::split(s.as_mut());
        let writer = async {
            w.write_all(&to_send).await.unwrap();
        };
        let reader = async {
            let mut got = vec![0u8; data.len()];
            r.read_exact(&mut got).await.unwrap();
            got
        };
        let ((), got) = tokio::join!(writer, reader);
        assert_eq!(got, data);
    }

    #[tokio::test]
    async fn refusals_keep_the_network_codes() {
        let base = relay(Some((503, "network_unavailable"))).await;
        let err = RelayDialer::new(api(&base))
            .dial(req(termoak_core::new_id()))
            .await
            .err()
            .unwrap();
        assert!(
            matches!(&err, SshError::Network { code, message } if *code == codes::NETWORK_UNAVAILABLE && message == "refused"),
            "{err:?}"
        );
        let base = relay(Some((403, "use_only_strict"))).await;
        let err = RelayDialer::new(api(&base))
            .dial(req(termoak_core::new_id()))
            .await
            .err()
            .unwrap();
        assert!(
            matches!(&err, SshError::Core(c) if c.vault_code() == Some(codes::USE_ONLY_STRICT)),
            "{err:?}"
        );
        let base = relay(Some((502, "something_else"))).await;
        let err = RelayDialer::new(api(&base))
            .dial(req(termoak_core::new_id()))
            .await
            .err()
            .unwrap();
        assert!(
            matches!(&err, SshError::Network { code, .. } if *code == codes::NETWORK_DIAL_FAILED),
            "{err:?}"
        );
        assert!(err.to_string().contains("something_else"), "{err}");
    }
}

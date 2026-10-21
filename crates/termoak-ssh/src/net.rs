//! Private networks (0.7): the first connection to a host whose effective
//! settings have a `network_id` goes through a [`NetworkDialer`] instead of
//! a TCP connection (or a proxy).
//!
//! - On the server, the dialer asks `termoak-netd` (WireGuard, Tailscale,
//!   ZeroTier in user space) for a stream to `address:port` inside the
//!   network.
//! - In the apps, the dialer opens the server relay (a WebSocket the server
//!   pipes into `termoak-netd`): SSH stays end to end between the device
//!   and the host.
//!
//! A host with a network never falls back to a direct connection: without
//! a dialer the connection fails with `network_unavailable`.

use std::sync::Arc;
use std::time::Duration;

use termoak_core::Id;
use termoak_core::error::codes;
use termoak_core::resolve::{ResolvedHost, ResolvedNetwork};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{Result, SshError};

/// A byte stream (TCP, a netd connection, a WebSocket adapter...).
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// Boxed [`AsyncStream`].
pub type BoxedStream = Box<dyn AsyncStream>;

/// What to dial.
#[derive(Debug, Clone)]
pub struct DialRequest<'a> {
    /// The network of the first connection
    /// ([`ResolvedHost::first_hop_network_id`]).
    pub network_id: Id,
    /// The network with its configuration and secret, when resolved (the
    /// server has it; the apps may only have the id).
    pub network: Option<&'a ResolvedNetwork>,
    /// The host being connected to (the last of the chain).
    pub target_host_id: Id,
    /// The host dialed (the first jump, or the target).
    pub hop_host_id: Id,
    pub address: &'a str,
    pub port: u16,
    pub timeout: Duration,
}

/// Opens streams inside private networks.
#[async_trait::async_trait]
pub trait NetworkDialer: Send + Sync {
    async fn dial(&self, req: DialRequest<'_>) -> Result<BoxedStream>;
}

/// A shared [`NetworkDialer`] (for options that are `Clone` and `Debug`).
#[derive(Clone)]
pub struct Dialer(pub Arc<dyn NetworkDialer>);

impl Dialer {
    pub fn new(d: impl NetworkDialer + 'static) -> Self {
        Self(Arc::new(d))
    }
}

impl std::fmt::Debug for Dialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Dialer")
    }
}

/// `network_unavailable` error.
pub fn unavailable(message: impl Into<String>) -> SshError {
    SshError::Network {
        code: codes::NETWORK_UNAVAILABLE,
        message: message.into(),
    }
}

/// `network_dial_failed` error.
pub fn dial_failed(message: impl Into<String>) -> SshError {
    SshError::Network {
        code: codes::NETWORK_DIAL_FAILED,
        message: message.into(),
    }
}

/// Opens the first connection of a chain to `target`: through its network
/// (with `dialer`), its proxy, or a plain TCP connection.
pub(crate) async fn open_first_hop(
    target: &ResolvedHost,
    dialer: Option<&Dialer>,
    timeout: Duration,
) -> Result<BoxedStream> {
    let hop = target.first_hop();
    if let Some(network_id) = target.first_hop_network_id() {
        let Some(dialer) = dialer else {
            return Err(unavailable(format!(
                "{} is reached through a private network, which is not available here",
                hop.host.label
            )));
        };
        let req = DialRequest {
            network_id,
            network: target.first_hop_network(),
            target_host_id: target.host.id,
            hop_host_id: hop.host.id,
            address: &hop.host.address,
            port: hop.port,
            timeout,
        };
        let target_name = format!("{}:{}", hop.host.address, hop.port);
        return tokio::time::timeout(timeout + Duration::from_secs(5), dialer.0.dial(req))
            .await
            .map_err(|_| {
                SshError::Timeout(format!("connecting to {target_name} through the network"))
            })?;
    }
    let proxy = hop.proxy.as_ref().or(target.proxy.as_ref());
    Ok(match proxy {
        Some(p) => Box::new(crate::proxy::connect(p, &hop.host.address, hop.port, timeout).await?),
        None => Box::new(crate::client::tcp_connect(&hop.host.address, hop.port, timeout).await?),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use parking_lot::Mutex;
    use termoak_core::model::{Host, HostSettings, Network};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// Dials directly and records what it was asked (tests only).
    #[derive(Default)]
    pub(crate) struct Recorder {
        pub calls: Mutex<Vec<(Id, String, u16, bool)>>,
    }

    #[async_trait::async_trait]
    impl NetworkDialer for Recorder {
        async fn dial(&self, req: DialRequest<'_>) -> Result<BoxedStream> {
            self.calls.lock().push((
                req.network_id,
                req.address.to_string(),
                req.port,
                req.network.is_some(),
            ));
            let s = TcpStream::connect((req.address, req.port))
                .await
                .map_err(|e| dial_failed(e.to_string()))?;
            Ok(Box::new(s))
        }
    }

    pub(crate) fn host(label: &str, port: u16, network: Option<Id>) -> ResolvedHost {
        ResolvedHost {
            host: Host {
                id: termoak_core::new_id(),
                label: label.into(),
                address: "127.0.0.1".into(),
                group_id: None,
                tags: vec![],
                settings: HostSettings::default(),
                notes: String::new(),
                color: None,
                os: None,
                os_version: None,
                favorite: false,
                protocol: Default::default(),
                icon: None,
            },
            settings: HostSettings {
                network_id: network,
                ..Default::default()
            },
            port,
            username: "u".into(),
            password: None,
            key: None,
            jumps: vec![],
            startup_script: None,
            proxy: None,
            network: network.map(|id| ResolvedNetwork {
                network: Network {
                    id,
                    name: "n".into(),
                    ..Default::default()
                },
                secret: Default::default(),
            }),
        }
    }

    async fn echo() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut c, _)) = l.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = c.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn networks_go_through_the_dialer_and_never_direct() {
        let port = echo().await;
        let net = termoak_core::new_id();
        let rec = Arc::new(Recorder::default());
        let dialer = Dialer(rec.clone());
        let t = host("db", port, Some(net));
        // Without a dialer: network_unavailable, no direct connection.
        let err = open_first_hop(&t, None, Duration::from_secs(5))
            .await
            .err()
            .unwrap();
        assert!(
            matches!(err, SshError::Network { code, .. } if code == codes::NETWORK_UNAVAILABLE),
            "{err}"
        );
        let mut s = open_first_hop(&t, Some(&dialer), Duration::from_secs(5))
            .await
            .unwrap();
        s.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        assert_eq!(rec.calls.lock()[0], (net, "127.0.0.1".into(), port, true));

        // The first jump is dialed with the target's network.
        let mut chain = host("inner", 22, Some(net));
        chain.jumps = vec![host("bastion", port, None)];
        open_first_hop(&chain, Some(&dialer), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(rec.calls.lock()[1], (net, "127.0.0.1".into(), port, true));

        // No network: direct, the dialer is not used.
        let direct = host("web", port, None);
        open_first_hop(&direct, Some(&dialer), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(rec.calls.lock().len(), 2);
    }
}

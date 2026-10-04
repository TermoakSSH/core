//! Port forwarding: local (`-L`), remote (`-R`) and dynamic SOCKS5 (`-D`).

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use russh::Channel;
use russh::client::Msg;
use serde::{Deserialize, Serialize};
use termoak_core::model::{ForwardKind, PortForward};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::client::{Connection, RemoteTarget};
use crate::error::{Result, SshError};

/// Tunnel definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardSpec {
    pub kind: ForwardKind,
    pub bind_address: String,
    /// 0 = a free port chosen automatically.
    pub bind_port: u16,
    pub dest_host: Option<String>,
    pub dest_port: Option<u16>,
}

impl From<&PortForward> for ForwardSpec {
    fn from(f: &PortForward) -> Self {
        Self {
            kind: f.kind,
            bind_address: f.bind_address.clone(),
            bind_port: f.bind_port,
            dest_host: f.dest_host.clone(),
            dest_port: f.dest_port,
        }
    }
}

#[derive(Default)]
pub(crate) struct ForwardStatsInner {
    active: AtomicU64,
    total: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

/// Tunnel statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ForwardStats {
    pub active_connections: u64,
    pub total_connections: u64,
    /// Bytes received by the side that initiates the connection.
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// Running tunnel. It stops when dropped (or with `stop`).
pub struct ForwardHandle {
    pub spec: ForwardSpec,
    /// Port actually listened on (useful if 0 was requested).
    pub bound_port: u16,
    stats: Arc<ForwardStatsInner>,
    task: Option<JoinHandle<()>>,
    remote: Option<(Arc<Connection>, String, u32)>,
}

impl ForwardHandle {
    pub fn stats(&self) -> ForwardStats {
        ForwardStats {
            active_connections: self.stats.active.load(Ordering::Relaxed),
            total_connections: self.stats.total.load(Ordering::Relaxed),
            bytes_in: self.stats.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.stats.bytes_out.load(Ordering::Relaxed),
        }
    }

    pub async fn stop(mut self) {
        self.shutdown().await;
    }

    async fn shutdown(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        if let Some((conn, addr, port)) = self.remote.take() {
            conn.remote_forwards().remove(&addr, port);
            let _ = conn.handle().cancel_tcpip_forward(addr, port).await;
        }
    }
}

impl Drop for ForwardHandle {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        if let Some((conn, addr, port)) = self.remote.take() {
            conn.remote_forwards().remove(&addr, port);
            tokio::spawn(async move {
                let _ = conn.handle().cancel_tcpip_forward(addr, port).await;
            });
        }
    }
}

impl Connection {
    /// Starts a tunnel over this connection.
    pub async fn start_forward(self: &Arc<Self>, spec: ForwardSpec) -> Result<ForwardHandle> {
        let stats = Arc::new(ForwardStatsInner::default());
        match spec.kind {
            ForwardKind::Local | ForwardKind::Dynamic => {
                let listener = TcpListener::bind((spec.bind_address.as_str(), spec.bind_port))
                    .await
                    .map_err(|e| {
                        SshError::Forward(format!(
                            "could not listen on {}:{}: {e}",
                            spec.bind_address, spec.bind_port
                        ))
                    })?;
                let bound_port = listener.local_addr()?.port();
                let conn = self.clone();
                let task_stats = stats.clone();
                let task_spec = spec.clone();
                let task = tokio::spawn(async move {
                    loop {
                        let Ok((socket, _peer)) = listener.accept().await else {
                            break;
                        };
                        let _ = socket.set_nodelay(true);
                        let conn = conn.clone();
                        let stats = task_stats.clone();
                        let spec = task_spec.clone();
                        tokio::spawn(async move {
                            stats.total.fetch_add(1, Ordering::Relaxed);
                            stats.active.fetch_add(1, Ordering::Relaxed);
                            let res = match spec.kind {
                                ForwardKind::Dynamic => socks5(conn, socket, &stats).await,
                                _ => local(conn, socket, &spec, &stats).await,
                            };
                            if let Err(e) = res {
                                tracing::debug!(error = %e, "tunnel connection ended with an error");
                            }
                            stats.active.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                });
                Ok(ForwardHandle {
                    spec,
                    bound_port,
                    stats,
                    task: Some(task),
                    remote: None,
                })
            }
            ForwardKind::Remote => {
                let dest_host = spec
                    .dest_host
                    .clone()
                    .ok_or_else(|| SshError::Forward("missing destination host".into()))?;
                let dest_port = spec
                    .dest_port
                    .ok_or_else(|| SshError::Forward("missing destination port".into()))?;
                let port = self
                    .handle()
                    .tcpip_forward(spec.bind_address.clone(), spec.bind_port as u32)
                    .await
                    .map_err(|e| {
                        SshError::Forward(format!("the server rejected the remote tunnel: {e}"))
                    })?;
                let port = if spec.bind_port == 0 {
                    port
                } else {
                    spec.bind_port as u32
                };
                self.remote_forwards().insert(
                    &spec.bind_address,
                    port,
                    RemoteTarget {
                        host: dest_host,
                        port: dest_port,
                        stats: stats.clone(),
                    },
                );
                Ok(ForwardHandle {
                    bound_port: port as u16,
                    remote: Some((self.clone(), spec.bind_address.clone(), port)),
                    spec,
                    stats,
                    task: None,
                })
            }
        }
    }
}

async fn local(
    conn: Arc<Connection>,
    mut socket: TcpStream,
    spec: &ForwardSpec,
    stats: &ForwardStatsInner,
) -> Result<()> {
    let host = spec.dest_host.as_deref().unwrap_or("127.0.0.1");
    let port = spec.dest_port.unwrap_or(0);
    let mut channel = conn.direct_tcpip(host, port).await?;
    let (a, b) = tokio::io::copy_bidirectional(&mut socket, &mut channel).await?;
    stats.bytes_out.fetch_add(a, Ordering::Relaxed);
    stats.bytes_in.fetch_add(b, Ordering::Relaxed);
    Ok(())
}

/// Incoming connection through a remote tunnel: piped to the local destination.
pub(crate) async fn pipe_remote(channel: Channel<Msg>, target: RemoteTarget) {
    let stats = target.stats.clone();
    stats.total.fetch_add(1, Ordering::Relaxed);
    stats.active.fetch_add(1, Ordering::Relaxed);
    match TcpStream::connect((target.host.as_str(), target.port)).await {
        Ok(mut socket) => {
            let _ = socket.set_nodelay(true);
            let mut stream = channel.into_stream();
            if let Ok((a, b)) = tokio::io::copy_bidirectional(&mut stream, &mut socket).await {
                stats.bytes_in.fetch_add(a, Ordering::Relaxed);
                stats.bytes_out.fetch_add(b, Ordering::Relaxed);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, dest = %format!("{}:{}", target.host, target.port),
                "remote tunnel: could not connect to the local destination");
            let _ = channel.close().await;
        }
    }
    stats.active.fetch_sub(1, Ordering::Relaxed);
}

/// Destination requested by a SOCKS client.
#[derive(Debug, PartialEq)]
pub(crate) struct SocksTarget {
    pub host: String,
    pub port: u16,
}

/// SOCKS5 negotiation (no authentication, CONNECT only).
pub(crate) async fn socks5_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
) -> Result<SocksTarget> {
    let ver = s.read_u8().await?;
    if ver != 5 {
        return Err(SshError::Forward(format!(
            "unsupported SOCKS version: {ver}"
        )));
    }
    let n = s.read_u8().await? as usize;
    let mut methods = vec![0u8; n];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        s.write_all(&[5, 0xff]).await?;
        return Err(SshError::Forward(
            "the SOCKS client requires authentication".into(),
        ));
    }
    s.write_all(&[5, 0]).await?;

    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(SshError::Forward("invalid SOCKS request".into()));
    }
    let host = match head[3] {
        1 => {
            let mut ip = [0u8; 4];
            s.read_exact(&mut ip).await?;
            Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let len = s.read_u8().await? as usize;
            let mut name = vec![0u8; len];
            s.read_exact(&mut name).await?;
            String::from_utf8(name).map_err(|_| SshError::Forward("invalid domain".into()))?
        }
        4 => {
            let mut ip = [0u8; 16];
            s.read_exact(&mut ip).await?;
            Ipv6Addr::from(ip).to_string()
        }
        other => {
            s.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            return Err(SshError::Forward(format!(
                "unsupported SOCKS address type {other}"
            )));
        }
    };
    let port = s.read_u16().await?;
    if head[1] != 1 {
        // CONNECT only.
        s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Err(SshError::Forward(
            "only the CONNECT command is supported".into(),
        ));
    }
    Ok(SocksTarget { host, port })
}

async fn socks5(
    conn: Arc<Connection>,
    mut socket: TcpStream,
    stats: &ForwardStatsInner,
) -> Result<()> {
    let target = socks5_handshake(&mut socket).await?;
    let mut channel = match conn.direct_tcpip(&target.host, target.port).await {
        Ok(c) => c,
        Err(e) => {
            socket.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            return Err(e);
        }
    };
    socket.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    let (a, b) = tokio::io::copy_bidirectional(&mut socket, &mut channel).await?;
    stats.bytes_out.fetch_add(a, Ordering::Relaxed);
    stats.bytes_in.fetch_add(b, Ordering::Relaxed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn socks5_domain_request() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let srv = tokio::spawn(async move { socks5_handshake(&mut server).await });
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0]);
        let mut req = vec![5, 1, 0, 3, 11];
        req.extend_from_slice(b"example.com");
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).await.unwrap();
        let target = srv.await.unwrap().unwrap();
        assert_eq!(
            target,
            SocksTarget {
                host: "example.com".into(),
                port: 443
            }
        );
    }

    #[tokio::test]
    async fn socks5_rejects_auth_only_clients() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let srv = tokio::spawn(async move { socks5_handshake(&mut server).await });
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0xff]);
        assert!(srv.await.unwrap().is_err());
    }
}

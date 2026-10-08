//! Reachability of a host without connecting: a TCP connection to its port
//! (through its proxy, if it has one) that is closed as soon as it opens.
//! No SSH, no authentication, nothing in the host's logs beyond an accepted
//! and closed connection. Used for the status dots of the hosts lists.

use std::time::{Duration, Instant};

use termoak_core::resolve::ResolvedProxy;
use tokio::net::TcpStream;

/// Connects to `host:port` (through `proxy`) and closes at once. The time
/// the connection took, or `None` if it was refused, timed out or the name
/// does not resolve. Without a proxy the name is resolved first, so the
/// time is the connection's only; through a proxy it is the whole
/// handshake.
pub async fn tcp_probe(
    host: &str,
    port: u16,
    proxy: Option<&ResolvedProxy>,
    timeout: Duration,
) -> Option<Duration> {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    let attempt = async {
        match proxy {
            None => {
                let addrs: Vec<std::net::SocketAddr> =
                    tokio::net::lookup_host((host, port)).await.ok()?.collect();
                for addr in addrs {
                    let start = Instant::now();
                    if TcpStream::connect(addr).await.is_ok() {
                        return Some(start.elapsed());
                    }
                }
                None
            }
            Some(proxy) => {
                let start = Instant::now();
                crate::proxy::connect(proxy, host, port, timeout)
                    .await
                    .ok()
                    .map(|_| start.elapsed())
            }
        }
    };
    tokio::time::timeout(timeout, attempt).await.ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use termoak_core::{ProxyKind, ProxySettings};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const T: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn checks_a_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(tcp_probe("127.0.0.1", port, None, T).await.is_some());
        assert!(tcp_probe("[127.0.0.1]", port, None, T).await.is_some());
        drop(listener);
        // Closed now: refused.
        assert!(tcp_probe("127.0.0.1", port, None, T).await.is_none());
        assert!(tcp_probe("name.invalid", 22, None, T).await.is_none());
    }

    #[tokio::test]
    async fn checks_through_a_socks5_proxy() {
        let dest = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_port = dest.local_addr().unwrap().port();
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut c, _) = proxy.accept().await.unwrap();
            let mut g = [0u8; 3];
            c.read_exact(&mut g).await.unwrap();
            c.write_all(&[5, 0]).await.unwrap();
            let mut head = [0u8; 4];
            c.read_exact(&mut head).await.unwrap();
            assert_eq!(head[3], 1);
            let mut rest = [0u8; 6];
            c.read_exact(&mut rest).await.unwrap();
            let port = u16::from_be_bytes([rest[4], rest[5]]);
            let ok = TcpStream::connect(("127.0.0.1", port)).await.is_ok();
            let code = if ok { 0 } else { 5 };
            c.write_all(&[5, code, 0, 1, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
        });
        let p = ResolvedProxy {
            settings: ProxySettings {
                kind: ProxyKind::Socks5,
                host: "127.0.0.1".into(),
                port: proxy_port,
                username: None,
            },
            password: None,
        };
        assert!(
            tcp_probe("127.0.0.1", dest_port, Some(&p), T)
                .await
                .is_some()
        );
        drop(dest);
    }
}

//! TCP connection through a proxy: SOCKS5 (with or without a user), SOCKS4/4a
//! and HTTP `CONNECT`. Used for the first connection of the chain; the other
//! hops go inside SSH.

use std::net::IpAddr;
use std::time::Duration;

use base64::Engine;
use termoak_core::ProxyKind;
use termoak_core::resolve::ResolvedProxy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{Result, SshError};

/// Opens `host:port` through the proxy.
pub(crate) async fn connect(
    proxy: &ResolvedProxy,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<TcpStream> {
    let p = &proxy.settings;
    let via = format!("{}:{}", p.host, p.port);
    let target = format!("{host}:{port}");
    let fail = |reason: String| SshError::Connect {
        target: target.clone(),
        reason: format!("proxy {via}: {reason}"),
    };
    let run = async {
        let mut stream = TcpStream::connect((p.host.as_str(), p.port))
            .await
            .map_err(|e| fail(format!("could not connect ({e})")))?;
        let _ = stream.set_nodelay(true);
        let user = p.username.as_deref().filter(|u| !u.is_empty());
        let pass = proxy.password.as_deref().unwrap_or("");
        match p.kind {
            ProxyKind::Socks5 => socks5(&mut stream, host, port, user.map(|u| (u, pass))).await,
            ProxyKind::Socks4 => socks4(&mut stream, host, port, user.unwrap_or("")).await,
            ProxyKind::Http => http_connect(&mut stream, host, port, user.map(|u| (u, pass))).await,
        }
        .map_err(fail)?;
        Ok(stream)
    };
    tokio::time::timeout(timeout, run)
        .await
        .map_err(|_| SshError::Timeout(format!("connecting to {target} through proxy {via}")))?
}

type Step<T> = std::result::Result<T, String>;

fn io(e: std::io::Error) -> String {
    format!("the connection was cut ({e})")
}

async fn socks5(s: &mut TcpStream, host: &str, port: u16, auth: Option<(&str, &str)>) -> Step<()> {
    // Greeting: no authentication and, if there is a user, username/password.
    let greeting: &[u8] = if auth.is_some() {
        &[5, 2, 0x00, 0x02]
    } else {
        &[5, 1, 0x00]
    };
    s.write_all(greeting).await.map_err(io)?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await.map_err(io)?;
    if reply[0] != 5 {
        return Err("not a SOCKS5 proxy".into());
    }
    match reply[1] {
        0x00 => {}
        0x02 => {
            let (user, pass) = auth.ok_or("it requires a username and password")?;
            if user.len() > 255 || pass.len() > 255 {
                return Err("username or password too long".into());
            }
            let mut msg = vec![1, user.len() as u8];
            msg.extend_from_slice(user.as_bytes());
            msg.push(pass.len() as u8);
            msg.extend_from_slice(pass.as_bytes());
            s.write_all(&msg).await.map_err(io)?;
            let mut r = [0u8; 2];
            s.read_exact(&mut r).await.map_err(io)?;
            if r[1] != 0 {
                return Err("wrong proxy username or password".into());
            }
        }
        0xFF => return Err("it accepts none of the offered authentication methods".into()),
        m => return Err(format!("unsupported authentication method ({m})")),
    }
    // CONNECT
    let mut req = vec![5, 1, 0];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            req.push(1);
            req.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            req.push(4);
            req.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            if host.len() > 255 {
                return Err("host name too long".into());
            }
            req.push(3);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.map_err(io)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.map_err(io)?;
    if head[1] != 0 {
        return Err(match head[1] {
            1 => "general proxy failure",
            2 => "the proxy does not allow this connection",
            3 => "network unreachable",
            4 => "host unreachable",
            5 => "connection refused by the destination",
            6 => "TTL expired",
            7 => "command not supported",
            8 => "address type not supported",
            _ => "unknown error",
        }
        .into());
    }
    // Address it replies with (discarded).
    let skip = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await.map_err(io)?;
            len[0] as usize
        }
        _ => return Err("invalid SOCKS5 reply".into()),
    };
    let mut rest = vec![0u8; skip + 2];
    s.read_exact(&mut rest).await.map_err(io)?;
    Ok(())
}

async fn socks4(s: &mut TcpStream, host: &str, port: u16, user: &str) -> Step<()> {
    let mut req = vec![4, 1];
    req.extend_from_slice(&port.to_be_bytes());
    let ipv4 = host.parse::<std::net::Ipv4Addr>().ok();
    match ipv4 {
        Some(ip) => req.extend_from_slice(&ip.octets()),
        // SOCKS4a: 0.0.0.x and the name at the end.
        None => req.extend_from_slice(&[0, 0, 0, 1]),
    }
    req.extend_from_slice(user.as_bytes());
    req.push(0);
    if ipv4.is_none() {
        req.extend_from_slice(host.as_bytes());
        req.push(0);
    }
    s.write_all(&req).await.map_err(io)?;
    let mut reply = [0u8; 8];
    s.read_exact(&mut reply).await.map_err(io)?;
    match reply[1] {
        0x5A => Ok(()),
        0x5B => Err("the proxy refused the connection".into()),
        _ => Err(format!("invalid SOCKS4 reply ({})", reply[1])),
    }
}

async fn http_connect(
    s: &mut TcpStream,
    host: &str,
    port: u16,
    auth: Option<(&str, &str)>,
) -> Step<()> {
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some((user, pass)) = auth {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.map_err(io)?;
    // Response header, byte by byte so no tunnel data is consumed.
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 {
            return Err("HTTP response too long".into());
        }
        let mut b = [0u8; 1];
        s.read_exact(&mut b).await.map_err(io)?;
        head.push(b[0]);
    }
    let text = String::from_utf8_lossy(&head);
    let status_line = text.lines().next().unwrap_or("");
    let code = status_line.split_whitespace().nth(1).unwrap_or("");
    match code {
        "200" => Ok(()),
        "407" => {
            Err("the proxy requires authentication (407): check the username and password".into())
        }
        _ => Err(format!("the proxy replied \"{}\"", status_line.trim())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use termoak_core::ProxySettings;
    use tokio::net::TcpListener;

    /// Echo server reached through the proxy.
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

    /// Test proxy: `handshake` reads the request and returns the destination.
    async fn proxy<F, Fut>(handshake: F) -> u16
    where
        F: Fn(TcpStream) -> Fut + Send + Sync + 'static + Clone,
        Fut: std::future::Future<Output = Option<(TcpStream, u16)>> + Send,
    {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((c, _)) = l.accept().await {
                let h = handshake.clone();
                tokio::spawn(async move {
                    if let Some((mut client, dest)) = h(c).await {
                        let mut up = TcpStream::connect(("127.0.0.1", dest)).await.unwrap();
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
                    }
                });
            }
        });
        port
    }

    fn resolved(
        kind: ProxyKind,
        port: u16,
        user: Option<&str>,
        pass: Option<&str>,
    ) -> ResolvedProxy {
        ResolvedProxy {
            settings: ProxySettings {
                kind,
                host: "127.0.0.1".into(),
                port,
                username: user.map(Into::into),
            },
            password: pass.map(Into::into),
        }
    }

    async fn roundtrip(mut s: TcpStream) {
        s.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn http_connect_with_basic_auth() {
        let dest = echo().await;
        let p = proxy(|mut c: TcpStream| async move {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut b = [0u8; 1];
                c.read_exact(&mut b).await.ok()?;
                head.push(b[0]);
            }
            let text = String::from_utf8(head).unwrap();
            // "ana:secret" in base64.
            if !text.contains("Proxy-Authorization: Basic YW5hOnNlY3JldA==") {
                c.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                    .await
                    .ok()?;
                return None;
            }
            let port: u16 = text
                .split_whitespace()
                .nth(1)?
                .rsplit(':')
                .next()?
                .parse()
                .ok()?;
            c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .ok()?;
            Some((c, port))
        })
        .await;
        let ok = resolved(ProxyKind::Http, p, Some("ana"), Some("secret"));
        roundtrip(
            connect(&ok, "127.0.0.1", dest, Duration::from_secs(5))
                .await
                .unwrap(),
        )
        .await;

        let bad = resolved(ProxyKind::Http, p, Some("ana"), Some("wrong"));
        let err = connect(&bad, "127.0.0.1", dest, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("407"), "{err}");
    }

    #[tokio::test]
    async fn socks5_with_and_without_auth() {
        let dest = echo().await;
        let p = proxy(|mut c: TcpStream| async move {
            let mut h = [0u8; 2];
            c.read_exact(&mut h).await.ok()?;
            let mut methods = vec![0u8; h[1] as usize];
            c.read_exact(&mut methods).await.ok()?;
            if methods.contains(&2) {
                c.write_all(&[5, 2]).await.ok()?;
                let mut v = [0u8; 2];
                c.read_exact(&mut v).await.ok()?;
                let mut user = vec![0u8; v[1] as usize];
                c.read_exact(&mut user).await.ok()?;
                let mut l = [0u8; 1];
                c.read_exact(&mut l).await.ok()?;
                let mut pass = vec![0u8; l[0] as usize];
                c.read_exact(&mut pass).await.ok()?;
                let ok = user == b"ana" && pass == b"secret";
                c.write_all(&[1, if ok { 0 } else { 1 }]).await.ok()?;
                if !ok {
                    return None;
                }
            } else {
                c.write_all(&[5, 0]).await.ok()?;
            }
            let mut req = [0u8; 4];
            c.read_exact(&mut req).await.ok()?;
            // The client sends IPv4 (1) because the destination is 127.0.0.1.
            assert_eq!(req[3], 1);
            let mut addr = [0u8; 6];
            c.read_exact(&mut addr).await.ok()?;
            let port = u16::from_be_bytes([addr[4], addr[5]]);
            c.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await.ok()?;
            Some((c, port))
        })
        .await;
        roundtrip(
            connect(
                &resolved(ProxyKind::Socks5, p, None, None),
                "127.0.0.1",
                dest,
                Duration::from_secs(5),
            )
            .await
            .unwrap(),
        )
        .await;
        roundtrip(
            connect(
                &resolved(ProxyKind::Socks5, p, Some("ana"), Some("secret")),
                "127.0.0.1",
                dest,
                Duration::from_secs(5),
            )
            .await
            .unwrap(),
        )
        .await;
        let err = connect(
            &resolved(ProxyKind::Socks5, p, Some("ana"), Some("wrong")),
            "127.0.0.1",
            dest,
            Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("wrong proxy username or password"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn socks4a_with_hostname() {
        let dest = echo().await;
        let p = proxy(|mut c: TcpStream| async move {
            let mut head = [0u8; 8];
            c.read_exact(&mut head).await.ok()?;
            let port = u16::from_be_bytes([head[2], head[3]]);
            // user\0 host\0
            let mut zeros = 0;
            while zeros < 2 {
                let mut b = [0u8; 1];
                c.read_exact(&mut b).await.ok()?;
                if b[0] == 0 {
                    zeros += 1;
                }
            }
            assert_eq!(&head[4..8], &[0, 0, 0, 1], "SOCKS4a");
            c.write_all(&[0, 0x5A, 0, 0, 0, 0, 0, 0]).await.ok()?;
            Some((c, port))
        })
        .await;
        roundtrip(
            connect(
                &resolved(ProxyKind::Socks4, p, None, None),
                "localhost",
                dest,
                Duration::from_secs(5),
            )
            .await
            .unwrap(),
        )
        .await;
    }
}

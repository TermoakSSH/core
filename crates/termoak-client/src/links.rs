//! Links the apps open or have pasted, read the same way everywhere:
//!
//! - joining a shared session: `termoak://join?server=<url>&token=<token>`,
//!   the web page `https://<server>/join/<token>` and
//!   `https://<server>/api/v1/join/<token>` (servers without the web app);
//! - signing up with an invitation: `termoak://invite?server=<url>&token=<code>`
//!   and the web page `https://<server>/invite/<code>`;
//! - quick connect: `ssh://[user@]host[:port]` and
//!   `telnet://[user@]host[:port]` ([`parse_quick_target`] also reads what
//!   people type: `user@host:port`, `ssh user@host -p 2222`, `telnet host 23`).
//!
//! A server may live under a path (`https://example.com/termoak`): whatever
//! comes before `/join`, `/api/v1/join` or `/invite` is the server.
//! `aceitunoak://` (the scheme before the rename) works like `termoak://`.

use termoak_core::model::HostProtocol;

/// What a link asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Link {
    /// Join a shared session (with or without an account).
    Join { server: String, token: String },
    /// Sign up (or join a team) with an invitation code.
    Invite { server: String, code: String },
    /// Connect to an address without a saved host.
    Quick(QuickTarget),
}

/// An address to connect to without a saved host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickTarget {
    pub protocol: HostProtocol,
    pub user: Option<String>,
    /// Name or address (IPv6 without brackets).
    pub host: String,
    /// `None`: the protocol's default (22 or 23).
    pub port: Option<u16>,
}

impl QuickTarget {
    /// `user@host:port` as typed back (IPv6 addresses in brackets when there
    /// is a port), with `telnet://` in front for Telnet.
    pub fn display(&self) -> String {
        let host = match self.port {
            Some(_) if self.host.contains(':') => format!("[{}]", self.host),
            _ => self.host.clone(),
        };
        format!(
            "{}{}{host}{}",
            if self.protocol.is_telnet() {
                "telnet://"
            } else {
                ""
            },
            self.user
                .as_deref()
                .map(|u| format!("{u}@"))
                .unwrap_or_default(),
            self.port.map(|p| format!(":{p}")).unwrap_or_default()
        )
    }
}

/// A language segment of the web app's URLs: `es`, `pt-BR`... (two
/// lowercase letters, optionally a region).
fn is_language_segment(s: &str) -> bool {
    let (lang, region) = match s.split_once('-') {
        Some((l, r)) => (l, Some(r)),
        None => (s, None),
    };
    lang.len() == 2
        && lang.bytes().all(|b| b.is_ascii_lowercase())
        && region.is_none_or(|r| r.len() == 2 && r.bytes().all(|b| b.is_ascii_uppercase()))
}

/// A share or invitation token: base64url, at most 256 characters.
pub fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 256
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Reads a link (see the module docs). `None` if it is none of them, or is
/// incomplete (no server, a malformed token...).
pub fn parse_link(text: &str) -> Option<Link> {
    let text = text.trim();
    if strip_prefix_ci(text, "ssh://").is_some() || strip_prefix_ci(text, "telnet://").is_some() {
        return parse_quick_target(text).map(Link::Quick);
    }
    let url = url::Url::parse(text).ok()?;
    match url.scheme() {
        "termoak" | "aceitunoak" => {
            // `termoak://join?...`: the host is the action.
            let action = url.host_str()?.to_ascii_lowercase();
            let mut server = None;
            let mut token = None;
            for (k, v) in url.query_pairs() {
                match k.as_ref() {
                    "server" => server = Some(v.trim().to_string()),
                    "token" | "code" => token = Some(v.trim().to_string()),
                    _ => {}
                }
            }
            let server = server.filter(|s| !s.is_empty())?;
            let parsed = url::Url::parse(&server).ok()?;
            if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
                return None;
            }
            let server = server.trim_end_matches('/').to_string();
            let token = token.filter(|t| valid_token(t))?;
            match action.as_str() {
                "join" => Some(Link::Join { server, token }),
                "invite" => Some(Link::Invite {
                    server,
                    code: token,
                }),
                _ => None,
            }
        }
        "http" | "https" => {
            let segments: Vec<&str> = url.path_segments()?.filter(|s| !s.is_empty()).collect();
            let at = segments
                .iter()
                .rposition(|s| *s == "join" || *s == "invite")?;
            // Exactly one segment after `join` / `invite`.
            if at + 2 != segments.len() {
                return None;
            }
            let token = segments[at + 1].to_string();
            if !valid_token(&token) {
                return None;
            }
            let invite = segments[at] == "invite";
            // Whatever comes before `/join` (or `/api/v1/join`) is the server
            // (it may live under a path).
            let mut prefix = &segments[..at];
            if !invite && prefix.ends_with(&["api", "v1"]) {
                prefix = &prefix[..prefix.len() - 2];
            }
            // The web app's language prefix (`/es/join/...`) is not part of
            // the server's address.
            if let Some(last) = prefix.last()
                && is_language_segment(last)
            {
                prefix = &prefix[..prefix.len() - 1];
            }
            let mut server = format!("{}://{}", url.scheme(), url.host_str()?);
            if let Some(port) = url.port() {
                server.push_str(&format!(":{port}"));
            }
            for s in prefix {
                server.push('/');
                server.push_str(s);
            }
            Some(if invite {
                Link::Invite {
                    server,
                    code: token,
                }
            } else {
                Link::Join { server, token }
            })
        }
        _ => None,
    }
}

fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// `termoak://join?server=…&token=…`.
pub fn join_app_link(server: &str, token: &str) -> String {
    format!(
        "termoak://join?server={}&token={}",
        enc(server.trim().trim_end_matches('/')),
        enc(token.trim())
    )
}

/// `termoak://invite?server=…&token=…`.
pub fn invite_app_link(server: &str, code: &str) -> String {
    format!(
        "termoak://invite?server={}&token={}",
        enc(server.trim().trim_end_matches('/')),
        enc(code.trim())
    )
}

/// Reads an address typed to connect without a saved host:
/// `user@host:port`, `host:port`, `user@host`, `[v6]:port` or
/// `ssh user@host -p port`, and for Telnet `telnet://[user@]host[:port]`
/// or `telnet host [port]` (`ssh://` works too). Only text that looks like
/// an address (it has `@`, `:` or `.`, or a scheme) counts, so a plain
/// search word is not taken as a host.
pub fn parse_quick_target(text: &str) -> Option<QuickTarget> {
    let text = text.trim();
    if let Some(rest) = strip_prefix_ci(text, "telnet://") {
        let mut t = parse_address(rest.trim_end_matches('/'), true)?;
        t.protocol = HostProtocol::Telnet;
        return Some(t);
    }
    if let Some(rest) = strip_prefix_ci(text, "ssh://") {
        return parse_address(rest.trim_end_matches('/'), true);
    }
    if let Some(rest) = strip_prefix_ci(text, "telnet ") {
        // `telnet host [port]`, as on the command line.
        let mut words = rest.split_whitespace();
        let host = words.next()?;
        let port = match words.next() {
            Some(p) => Some(p.parse::<u16>().ok().filter(|p| *p > 0)?),
            None => None,
        };
        if words.next().is_some() {
            return None;
        }
        let mut t = parse_address(host, true)?;
        if port.is_some() {
            t.port = port;
        }
        t.protocol = HostProtocol::Telnet;
        return Some(t);
    }
    let text = text.strip_prefix("ssh ").map(str::trim).unwrap_or(text);
    let (text, flag_port) = match text.split_once(" -p ") {
        Some((t, p)) => (
            t.trim(),
            Some(p.trim().parse::<u16>().ok().filter(|p| *p > 0)?),
        ),
        None => (text, None),
    };
    if !text.contains(['@', ':', '.']) {
        return None;
    }
    let mut t = parse_address(text, false)?;
    if flag_port.is_some() {
        t.port = flag_port;
    }
    Some(t)
}

fn strip_prefix_ci<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    text.get(..prefix.len())
        .filter(|p| p.eq_ignore_ascii_case(prefix))
        .map(|_| &text[prefix.len()..])
}

/// `[user@]host[:port]` (SSH; `any`: a bare name counts too).
fn parse_address(text: &str, any: bool) -> Option<QuickTarget> {
    if text.is_empty() || text.chars().any(char::is_whitespace) {
        return None;
    }
    if !any && !text.contains(['@', ':', '.']) {
        return None;
    }
    let (user, rest) = match text.rsplit_once('@') {
        Some((u, r)) if !u.is_empty() => (Some(u.to_string()), r),
        Some(_) => return None,
        None => (None, text),
    };
    let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
        let (host, after) = v6.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p.parse::<u16>().ok().filter(|p| *p > 0)?),
            None if after.is_empty() => None,
            None => return None,
        };
        (host.to_string(), port)
    } else if rest.matches(':').count() == 1 {
        let (h, p) = rest.split_once(':')?;
        (
            h.to_string(),
            Some(p.parse::<u16>().ok().filter(|p| *p > 0)?),
        )
    } else {
        (rest.to_string(), None)
    };
    let valid = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '%'));
    valid.then_some(QuickTarget {
        protocol: HostProtocol::Ssh,
        user,
        host,
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn join(server: &str, token: &str) -> Option<Link> {
        Some(Link::Join {
            server: server.into(),
            token: token.into(),
        })
    }

    fn invite(server: &str, code: &str) -> Option<Link> {
        Some(Link::Invite {
            server: server.into(),
            code: code.into(),
        })
    }

    #[test]
    fn app_links() {
        assert_eq!(
            parse_link("termoak://join?server=https%3A%2F%2Fssh.example.com%2F&token=abc_DEF-1"),
            join("https://ssh.example.com", "abc_DEF-1")
        );
        assert_eq!(
            parse_link(" aceitunoak://join?server=https://a.b/termoak&token=t "),
            join("https://a.b/termoak", "t")
        );
        assert_eq!(
            parse_link("termoak://invite?server=https%3A%2F%2Fa.b%2Fsub%2Fpath&token=aks_inv_x"),
            invite("https://a.b/sub/path", "aks_inv_x")
        );
        // Incomplete or wrong.
        assert_eq!(parse_link("termoak://join?token=x"), None);
        assert_eq!(parse_link("termoak://join?server=&token=x"), None);
        assert_eq!(
            parse_link("termoak://join?server=ftp%3A%2F%2Fa&token=x"),
            None
        );
        assert_eq!(
            parse_link("termoak://join?server=https%3A%2F%2Fa&token=a%20b"),
            None
        );
        assert_eq!(
            parse_link("termoak://other?server=https%3A%2F%2Fa&token=x"),
            None
        );
        assert_eq!(parse_link("termoak://"), None);
        assert_eq!(parse_link("hello"), None);
        // Round trip.
        assert_eq!(
            parse_link(&join_app_link("https://a.b/x/", "tok")),
            join("https://a.b/x", "tok")
        );
        assert_eq!(
            parse_link(&invite_app_link("https://a.b", "code")),
            invite("https://a.b", "code")
        );
    }

    #[test]
    fn web_links_under_a_path() {
        assert_eq!(
            parse_link("https://ssh.example.com/join/tok"),
            join("https://ssh.example.com", "tok")
        );
        assert_eq!(
            parse_link("https://example.com:8443/termoak/join/tok/"),
            join("https://example.com:8443/termoak", "tok")
        );
        assert_eq!(
            parse_link("https://example.com/termoak/api/v1/join/tok"),
            join("https://example.com/termoak", "tok")
        );
        assert_eq!(
            parse_link("http://10.0.0.5:8080/apps/termoak/invite/aks_inv_abc"),
            invite("http://10.0.0.5:8080/apps/termoak", "aks_inv_abc")
        );
        assert_eq!(
            parse_link("https://termoak.com/es/join/tok"),
            Some(Link::Join {
                server: "https://termoak.com".into(),
                token: "tok".into()
            })
        );
        assert_eq!(
            parse_link("https://example.com/termoak/pt-BR/invite/aks_inv_abc"),
            Some(Link::Invite {
                server: "https://example.com/termoak".into(),
                code: "aks_inv_abc".into()
            })
        );
        assert_eq!(parse_link("https://example.com/join/"), None);
        assert_eq!(parse_link("https://example.com/join/a/b"), None);
        assert_eq!(parse_link("https://example.com/somewhere"), None);
    }

    #[test]
    fn quick_connect() {
        let q = |p, u: Option<&str>, h: &str, port| {
            Some(QuickTarget {
                protocol: p,
                user: u.map(str::to_string),
                host: h.into(),
                port,
            })
        };
        assert_eq!(
            parse_link("ssh://root@web.example.com:2222"),
            q(
                HostProtocol::Ssh,
                Some("root"),
                "web.example.com",
                Some(2222)
            )
            .map(Link::Quick)
        );
        assert_eq!(
            parse_link("TELNET://router"),
            q(HostProtocol::Telnet, None, "router", None).map(Link::Quick)
        );
        assert_eq!(
            parse_link("telnet://[2001:db8::1]:23"),
            q(HostProtocol::Telnet, None, "2001:db8::1", Some(23)).map(Link::Quick)
        );
        assert_eq!(
            parse_quick_target("ssh deploy@10.0.0.1 -p 2200"),
            q(HostProtocol::Ssh, Some("deploy"), "10.0.0.1", Some(2200))
        );
        assert_eq!(
            parse_quick_target("telnet 10.0.0.9 2323"),
            q(HostProtocol::Telnet, None, "10.0.0.9", Some(2323))
        );
        assert_eq!(
            parse_quick_target("ana@db"),
            q(HostProtocol::Ssh, Some("ana"), "db", None)
        );
        assert_eq!(parse_quick_target("web"), None);
        assert_eq!(parse_quick_target("host:0"), None);
        assert_eq!(parse_link("ssh://"), None);
        assert_eq!(
            q(HostProtocol::Telnet, Some("a"), "::1", Some(23))
                .unwrap()
                .display(),
            "telnet://a@[::1]:23"
        );
    }
}

//! Reading the links the apps open or have pasted (one parser for every
//! app: `termoak_client::links`).

use termoak_client::links::{self, Link, QuickTarget};

/// What a link asks for.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum LinkTarget {
    /// Join a shared session: `termoak://join?server=…&token=…`,
    /// `https://<server>/join/<token>` or `https://<server>/api/v1/join/<token>`
    /// (`join_shared_session`, or `core.join_link` with your account).
    Join { server: String, token: String },
    /// Sign up with an invitation: `termoak://invite?server=…&token=…` or
    /// `https://<server>/invite/<code>` (`invite_info`, then `sign_up`).
    Invite { server: String, code: String },
    /// Connect to an address without a saved host: `ssh://[user@]host[:port]`
    /// or `telnet://…` (`protocol` is `ssh` or `telnet`; `port` `None` = 22
    /// or 23).
    QuickConnect {
        protocol: String,
        user: Option<String>,
        host: String,
        port: Option<u32>,
    },
}

fn quick(t: QuickTarget) -> LinkTarget {
    LinkTarget::QuickConnect {
        protocol: t.protocol.as_str().to_string(),
        user: t.user,
        host: t.host,
        port: t.port.map(u32::from),
    }
}

/// Reads a link (from a deep link, a QR code or the clipboard). The server
/// may live under a path (`https://example.com/termoak/join/…` gives the
/// server `https://example.com/termoak`). `None` when it is none of them or
/// is incomplete.
#[uniffi::export]
pub fn parse_link(text: String) -> Option<LinkTarget> {
    Some(match links::parse_link(&text)? {
        Link::Join { server, token } => LinkTarget::Join { server, token },
        Link::Invite { server, code } => LinkTarget::Invite { server, code },
        Link::Quick(t) => quick(t),
    })
}

/// Reads an address typed to connect without a saved host (a "quick
/// connect" field): `user@host:port`, `host:port`, `[v6]:port`,
/// `ssh user@host -p 2222`, `telnet host 23`, `ssh://…`, `telnet://…`. Plain
/// words (no `@`, `:` or `.`) are not addresses, so it can run on a search
/// field. Gives `QuickConnect` or `None`.
#[uniffi::export]
pub fn parse_quick_connect(text: String) -> Option<LinkTarget> {
    links::parse_quick_target(&text).map(quick)
}

/// `termoak://join?server=…&token=…` (to share as a QR code or link).
#[uniffi::export]
pub fn join_app_link(server: String, token: String) -> String {
    links::join_app_link(&server, &token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_through_the_ffi() {
        assert_eq!(
            parse_link("https://example.com/termoak/join/abc".into()),
            Some(LinkTarget::Join {
                server: "https://example.com/termoak".into(),
                token: "abc".into()
            })
        );
        assert_eq!(
            parse_link("termoak://invite?server=https%3A%2F%2Fa.b&token=aks_inv_1".into()),
            Some(LinkTarget::Invite {
                server: "https://a.b".into(),
                code: "aks_inv_1".into()
            })
        );
        assert_eq!(
            parse_link("telnet://admin@switch:2323".into()),
            Some(LinkTarget::QuickConnect {
                protocol: "telnet".into(),
                user: Some("admin".into()),
                host: "switch".into(),
                port: Some(2323)
            })
        );
        assert_eq!(parse_link("not a link".into()), None);
        assert_eq!(
            parse_quick_connect("root@10.0.0.1".into()),
            Some(LinkTarget::QuickConnect {
                protocol: "ssh".into(),
                user: Some("root".into()),
                host: "10.0.0.1".into(),
                port: None
            })
        );
        assert_eq!(parse_quick_connect("search words".into()), None);
        assert_eq!(
            parse_link(join_app_link("https://a.b/x".into(), "t".into())),
            Some(LinkTarget::Join {
                server: "https://a.b/x".into(),
                token: "t".into()
            })
        );
    }
}

//! Server addresses: the official server, the canonical form of a URL and
//! the rule for servers that moved.
//!
//! Accounts are told apart by `(canonical URL or instance id, user)`, so
//! every URL that comes from the user or from old data goes through
//! [`canonical`] first.

use crate::error::{ClientError, Result};

/// The official Termoak server. A build can point it elsewhere with the
/// `TERMOAK_OFFICIAL_SERVER` environment variable at compile time (for
/// example `https://next.termoak.com` for test builds).
pub const OFFICIAL_SERVER: &str = match option_env!("TERMOAK_OFFICIAL_SERVER") {
    Some(url) => url,
    None => "https://termoak.com",
};

/// Which server to sign in to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerChoice {
    /// [`official_server`].
    Official,
    /// A server of your own (any URL; see [`canonical`]).
    Custom(String),
}

impl ServerChoice {
    /// Canonical URL of the chosen server.
    pub fn url(&self) -> Result<String> {
        match self {
            ServerChoice::Official => Ok(official_server()),
            ServerChoice::Custom(url) => canonical(url),
        }
    }
}

/// Canonical URL of the official server.
pub fn official_server() -> String {
    canonical(OFFICIAL_SERVER).unwrap_or_else(|_| OFFICIAL_SERVER.to_string())
}

/// Whether a (canonical) URL is the official server.
pub fn is_official(url: &str) -> bool {
    canonical(url).is_ok_and(|u| u == official_server())
}

/// Whether the connection to the server is not encrypted (`http://`):
/// allowed for your own servers, with a warning.
pub fn is_insecure(url: &str) -> bool {
    canonical(url).is_ok_and(|u| u.starts_with("http://"))
}

/// New address of a server that moved, if `url` points to its old one
/// (`https://aceitunoak.ohz.ovh[/…]` → `https://termoak.com[/…]`).
pub fn moved_server(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://aceitunoak.ohz.ovh")?;
    (rest.is_empty() || rest.starts_with('/')).then(|| format!("https://termoak.com{rest}"))
}

/// Canonical form of a server URL: trimmed, `https://` added when there is
/// no scheme, host in lowercase, no path, query or trailing `/`, and the
/// moved-server rule applied. Only `http` and `https` are accepted.
pub fn canonical(url: &str) -> Result<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(ClientError::Invalid("the server address is empty".into()));
    }
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let parsed = url::Url::parse(&with_scheme)
        .map_err(|e| ClientError::Invalid(format!("invalid server address: {e}")))?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(ClientError::Invalid(format!(
            "invalid server address: use https:// (got {scheme}://)"
        )));
    }
    let host = parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| ClientError::Invalid("invalid server address: no host".into()))?
        .to_ascii_lowercase();
    let mut out = format!("{scheme}://{host}");
    if let Some(port) = parsed.port() {
        out.push_str(&format!(":{port}"));
    }
    Ok(moved_server(&out).unwrap_or(out))
}

/// Host (and port) of a URL, to show it ("ssh.example.com").
pub fn display_host(url: &str) -> String {
    let c = canonical(url).unwrap_or_else(|_| url.to_string());
    c.split_once("://")
        .map(|(_, rest)| rest.to_string())
        .unwrap_or(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_official_server_moves_to_termoak() {
        assert_eq!(
            moved_server("https://aceitunoak.ohz.ovh").as_deref(),
            Some("https://termoak.com")
        );
        assert_eq!(
            moved_server("https://aceitunoak.ohz.ovh/").as_deref(),
            Some("https://termoak.com/")
        );
        assert_eq!(moved_server("https://aceitunoak.ohz.ovh.evil.com"), None);
        assert_eq!(moved_server("https://ssh.example.com"), None);
    }

    #[test]
    fn canonical_urls() {
        let c = |u: &str| canonical(u).unwrap();
        assert_eq!(c("  SSH.Example.com/  "), "https://ssh.example.com");
        assert_eq!(
            c("https://ssh.example.com/some/path?x=1#y"),
            "https://ssh.example.com"
        );
        assert_eq!(c("http://10.0.0.5:7733/"), "http://10.0.0.5:7733");
        assert_eq!(c("https://ssh.example.com:443"), "https://ssh.example.com");
        assert_eq!(c("HTTPS://aceitunoak.ohz.ovh/app"), "https://termoak.com");
        assert_eq!(
            c("https://aceitunoak.ohz.ovh.evil.com"),
            "https://aceitunoak.ohz.ovh.evil.com"
        );
        assert!(canonical("").is_err());
        assert!(canonical("ftp://x.example.com").is_err());
        assert!(is_insecure("http://localhost:7733"));
        assert!(!is_insecure("ssh.example.com"));
        assert_eq!(
            display_host("https://ssh.example.com:8443/x"),
            "ssh.example.com:8443"
        );
    }

    #[test]
    fn the_official_server() {
        assert!(is_official(OFFICIAL_SERVER));
        assert!(is_official(&format!("{OFFICIAL_SERVER}/")));
        assert_eq!(ServerChoice::Official.url().unwrap(), official_server());
        if option_env!("TERMOAK_OFFICIAL_SERVER").is_none() {
            // Typed as a custom URL, it is still the official server.
            assert!(is_official("termoak.com"));
            assert!(is_official("https://aceitunoak.ohz.ovh"));
        }
        assert!(!is_official("https://ssh.example.com"));
    }
}

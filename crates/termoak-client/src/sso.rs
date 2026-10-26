//! Single sign-on through a team's identity provider (0.7 phase 5a,
//! docs-next/E2EE-SSO-AUDIT.md §3.4).
//!
//! 1. [`start`]: the app asks the server for the identity provider's URL,
//!    sending its own PKCE challenge, a state and where the browser must
//!    come back to (its callback).
//! 2. The app opens that URL in the **system browser** (never a web view):
//!    desktop and CLI with a loopback callback ([`Loopback`],
//!    `http://127.0.0.1:<port>/callback`, RFC 8252 §7.3), Android with a
//!    Custom Tab and iOS with `ASWebAuthenticationSession`, both coming back
//!    to `termoak://sso` (RFC 8252 §7.1), the web app to `/app/sso`.
//! 3. [`code_from_callback`]: the callback carries a one-time code (or an
//!    error) and the state, checked here.
//! 4. [`exchange`]: the code plus the PKCE verifier give the tokens, as a
//!    password sign-in does (two-step code too, if the account has it).

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::json;
use termoak_core::sso::{SsoPending, pkce_challenge, pkce_verifier, random_token};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::api::{ApiClient, AuthResponse};
use crate::error::{ClientError, Result};

/// The custom-scheme callback of the mobile apps.
pub const MOBILE_REDIRECT: &str = "termoak://sso";

/// `GET /api/v1/auth/sso/discover?email=`: whether an email signs in
/// through a team's SSO.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SsoHint {
    #[serde(default)]
    pub sso: bool,
    /// Password sign-in is refused for this email (the team enforces SSO).
    #[serde(default)]
    pub enforced: bool,
    #[serde(default)]
    pub team_id: Option<termoak_core::Id>,
    #[serde(default)]
    pub team_name: Option<String>,
}

/// Whether `email` should sign in through SSO on this server.
pub async fn discover(api: &ApiClient, email: &str) -> Result<SsoHint> {
    let q: String = url::form_urlencoded::byte_serialize(email.trim().as_bytes()).collect();
    api.get_public(&format!("/api/v1/auth/sso/discover?email={q}"))
        .await
}

/// Starts a sign-in: the identity provider URL to open, and what to keep
/// until the callback. `email` picks the team by its verified domain;
/// `team_id` picks a team directly (linking an account, teams without a
/// verified domain).
pub async fn start(
    api: &ApiClient,
    email: Option<&str>,
    team_id: Option<termoak_core::Id>,
    redirect_uri: &str,
    device_name: &str,
    platform: &str,
    link: bool,
) -> Result<(String, SsoPending)> {
    let verifier = pkce_verifier();
    let state = random_token();
    let body = json!({
        "email": email.map(str::trim),
        "team_id": team_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": pkce_challenge(&verifier),
        "code_challenge_method": "S256",
        "device_name": device_name,
        "platform": platform,
    });
    let path = if link {
        "/api/v1/me/sso/link"
    } else {
        "/api/v1/auth/sso/start"
    };
    let v: serde_json::Value = if link {
        api.post(path, &body).await?
    } else {
        api.post_public(path, &body).await?
    };
    let url = v["authorize_url"]
        .as_str()
        .ok_or_else(|| ClientError::Invalid("the server sent no authorize_url".into()))?
        .to_string();
    Ok((
        url,
        SsoPending {
            server_url: api.base_url().to_string(),
            state,
            verifier,
            redirect_uri: redirect_uri.to_string(),
        },
    ))
}

/// The one-time code of a callback URL, after checking its state. An
/// `error` in the callback becomes the API error it names
/// (`sso_required`, `sso_failed`, `sso_email_unverified`...).
pub fn code_from_callback(callback_url: &str, pending: &SsoPending) -> Result<String> {
    let u = url::Url::parse(callback_url.trim())
        .map_err(|_| ClientError::Invalid("the callback is not a URL".into()))?;
    let mut code = None;
    let mut state = None;
    let mut error = None;
    let mut message = None;
    for (k, v) in u.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            "error" => error = Some(v.into_owned()),
            "error_description" => message = Some(v.into_owned()),
            _ => {}
        }
    }
    if state.as_deref() != Some(pending.state.as_str()) {
        return Err(ClientError::Api {
            status: 400,
            code: "sso_state_invalid".into(),
            message: "the sign-in came back for another request: start again".into(),
            details: serde_json::Value::Object(Default::default()),
        });
    }
    if let Some(e) = error {
        return Err(ClientError::Api {
            status: 401,
            code: e,
            message: message.unwrap_or_else(|| "single sign-on failed".into()),
            details: serde_json::Value::Object(Default::default()),
        });
    }
    code.filter(|c| !c.is_empty())
        .ok_or_else(|| ClientError::Invalid("the callback has no code".into()))
}

/// Exchanges the one-time code for tokens (the client's tokens are set).
/// With two-step verification and no `totp_code`, fails with
/// `is_totp_required()`; the same code works again with it.
pub async fn exchange(
    api: &ApiClient,
    code: &str,
    pending: &SsoPending,
    totp_code: Option<&str>,
) -> Result<AuthResponse> {
    let auth: AuthResponse = api
        .post_public(
            "/api/v1/auth/sso/exchange",
            &json!({"code": code, "code_verifier": pending.verifier, "totp_code": totp_code}),
        )
        .await?;
    api.replace_tokens(Some(auth.tokens.clone()));
    Ok(auth)
}

/// A loopback HTTP listener for the browser's way back (desktop, CLI).
pub struct Loopback {
    listener: TcpListener,
    redirect_uri: String,
}

const DONE_PAGE: &str = "<!doctype html><meta charset=utf-8><title>Termoak</title>\
<style>body{font-family:system-ui,sans-serif;margin:4em auto;max-width:28em;text-align:center}</style>\
<h1>Termoak</h1><p>You can close this window and go back to Termoak.</p>";

impl Loopback {
    /// Listens on a free port of 127.0.0.1.
    pub async fn bind() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        Ok(Self {
            listener,
            redirect_uri: format!("http://127.0.0.1:{port}/callback"),
        })
    }

    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Waits for the browser (at most `timeout`) and answers it with a page
    /// that says it can be closed. Returns the full callback URL.
    pub async fn wait(self, timeout: Duration) -> Result<String> {
        let fut = async {
            loop {
                let (mut sock, _) = self.listener.accept().await?;
                let mut buf = vec![0u8; 8192];
                let mut n = 0;
                // Read the request line and headers.
                while n < buf.len() {
                    let r = sock.read(&mut buf[n..]).await?;
                    if r == 0 {
                        break;
                    }
                    n += r;
                    if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf[..n]);
                let path = head
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                if !path.starts_with("/callback") {
                    let _ = sock
                        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .await;
                    continue;
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{DONE_PAGE}",
                    DONE_PAGE.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
                let base = self.redirect_uri.trim_end_matches("/callback");
                return Ok::<String, ClientError>(format!("{base}{path}"));
            }
        };
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| ClientError::Invalid("single sign-on timed out".into()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callbacks() {
        let p = SsoPending {
            server_url: "https://x".into(),
            state: "s1".into(),
            verifier: "v".into(),
            redirect_uri: MOBILE_REDIRECT.into(),
        };
        assert_eq!(
            code_from_callback("termoak://sso?code=c1&state=s1", &p).unwrap(),
            "c1"
        );
        let e = code_from_callback("termoak://sso?code=c1&state=other", &p).unwrap_err();
        assert!(matches!(e, ClientError::Api { ref code, .. } if code == "sso_state_invalid"));
        let e = code_from_callback("termoak://sso?error=sso_required&state=s1", &p).unwrap_err();
        assert!(matches!(e, ClientError::Api { ref code, .. } if code == "sso_required"));
    }

    #[tokio::test]
    async fn loopback_answers_the_browser() {
        let lb = Loopback::bind().await.unwrap();
        let uri = lb.redirect_uri().to_string();
        let wait = tokio::spawn(lb.wait(Duration::from_secs(10)));
        let resp = reqwest::get(format!("{uri}?code=abc&state=s"))
            .await
            .unwrap();
        assert!(resp.text().await.unwrap().contains("close this window"));
        let got = wait.await.unwrap().unwrap();
        assert_eq!(got, format!("{uri}?code=abc&state=s"));
    }
}

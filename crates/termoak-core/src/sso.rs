//! Single sign-on for teams (0.7 phase 5a, docs/E2EE-SSO-AUDIT.md §3):
//! the team's OpenID Connect settings, verified domains and the PKCE and
//! redirect rules shared by the server and the apps.
//!
//! The flow: the app asks the server to start (`POST /auth/sso/start` with
//! its own PKCE challenge and callback), opens the returned URL in the
//! system browser, the identity provider sends the browser back to the
//! server (`/auth/sso/callback`: authorization code + PKCE, ID token
//! checked), the server sends it on to the app's callback with a one-time
//! code, and the app exchanges that code and its PKCE verifier for tokens
//! (`POST /auth/sso/exchange`).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::random_bytes;
use crate::error::{CoreError, Result};

/// Identity provider presets: the defaults they fill in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum SsoPreset {
    /// Google Workspace: issuer `https://accounts.google.com`, `hd` must be
    /// the workspace domain.
    Google,
    /// Microsoft Entra ID: issuer `https://login.microsoftonline.com/<tenant>/v2.0`.
    Microsoft,
    /// Keycloak: issuer `https://<host>/realms/<realm>`.
    Keycloak,
    /// Authentik: issuer `https://<host>/application/o/<slug>/`.
    Authentik,
    /// Any OpenID Connect provider with discovery.
    #[default]
    Generic,
    #[serde(other)]
    Unknown,
}

fn yes() -> bool {
    true
}

fn default_scopes() -> Vec<String> {
    vec!["openid".into(), "email".into(), "profile".into()]
}

/// A team's SSO settings (no secret: the client secret is stored sealed
/// apart and never shown again).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SsoConfig {
    /// Sign-in through SSO works (off: settings kept, nothing offered).
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub preset: SsoPreset,
    /// OpenID issuer (discovery at `<issuer>/.well-known/openid-configuration`).
    /// Google fills it; Microsoft builds it from `tenant`.
    #[serde(default)]
    pub issuer: String,
    /// Microsoft Entra: the directory (tenant) id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    pub client_id: String,
    /// Scopes asked for (always includes `openid`).
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// The ID token claim with the email (default `email`; Entra may need
    /// `preferred_username`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_claim: Option<String>,
    /// Refuse ID tokens whose `email_verified` is not `true` (Entra does
    /// not send it: its preset turns this off and relies on the verified
    /// domain).
    #[serde(default = "yes")]
    pub require_email_verified: bool,
    /// Accounts of the team's verified domains must sign in through SSO
    /// (password sign-in and sign-up refused with `sso_required`).
    #[serde(default)]
    pub enforce: bool,
    /// The team owner may still sign in with a password while enforced
    /// (break glass when the identity provider fails).
    #[serde(default = "yes")]
    pub owner_password_allowed: bool,
    /// Create an account for a verified-domain email that has none.
    #[serde(default = "yes")]
    pub auto_create: bool,
    /// Add people who sign in through SSO to the team (as members).
    #[serde(default = "yes")]
    pub auto_join: bool,
    /// Signing in through SSO satisfies the team's "require 2FA" policy
    /// (the identity provider enforces MFA).
    #[serde(default)]
    pub satisfies_2fa: bool,
    /// Set by the server in answers: a client secret is stored.
    #[serde(default)]
    pub has_client_secret: bool,
}

impl Default for SsoConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            preset: SsoPreset::Generic,
            issuer: String::new(),
            tenant: None,
            client_id: String::new(),
            scopes: default_scopes(),
            email_claim: None,
            require_email_verified: true,
            enforce: false,
            owner_password_allowed: true,
            auto_create: true,
            auto_join: true,
            satisfies_2fa: false,
            has_client_secret: false,
        }
    }
}

impl SsoConfig {
    /// Fills the preset's values and checks the rest.
    pub fn normalized(mut self) -> Result<Self> {
        match self.preset {
            SsoPreset::Google => {
                self.issuer = "https://accounts.google.com".into();
            }
            SsoPreset::Microsoft => {
                let tenant = self
                    .tenant
                    .as_deref()
                    .map(str::trim)
                    .filter(|t| {
                        !t.is_empty()
                            && t.len() <= 64
                            && t.chars()
                                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
                    })
                    .ok_or_else(|| {
                        CoreError::Invalid("Microsoft Entra needs the tenant id".into())
                    })?
                    .to_string();
                self.issuer = format!("https://login.microsoftonline.com/{tenant}/v2.0");
                self.tenant = Some(tenant);
                if self.email_claim.is_none() {
                    self.email_claim = Some("email".into());
                }
            }
            SsoPreset::Unknown => {
                return Err(CoreError::Invalid("unknown SSO preset".into()));
            }
            _ => {}
        }
        self.issuer = self.issuer.trim().trim_end_matches('/').to_string();
        if self.preset == SsoPreset::Authentik {
            // Authentik's issuer ends with a slash: keep what the provider
            // says (the ID token's `iss` must match exactly).
            self.issuer.push('/');
        }
        let url = url::Url::parse(&self.issuer)
            .map_err(|_| CoreError::Invalid("the issuer must be a URL".into()))?;
        if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() {
            return Err(CoreError::Invalid("the issuer must be an https URL".into()));
        }
        self.client_id = self.client_id.trim().to_string();
        if self.client_id.is_empty() || self.client_id.len() > 512 {
            return Err(CoreError::Invalid("the client id is required".into()));
        }
        let mut scopes: Vec<String> = self
            .scopes
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic()))
            .collect();
        if !scopes.iter().any(|s| s == "openid") {
            scopes.insert(0, "openid".into());
        }
        if !scopes.iter().any(|s| s == "email") {
            scopes.push("email".into());
        }
        scopes.dedup();
        if scopes.len() > 20 {
            return Err(CoreError::Invalid("too many scopes".into()));
        }
        self.scopes = scopes;
        if let Some(c) = &self.email_claim
            && (c.is_empty() || c.len() > 64)
        {
            return Err(CoreError::Invalid("bad email claim".into()));
        }
        Ok(self)
    }

    pub fn email_claim(&self) -> &str {
        self.email_claim.as_deref().unwrap_or("email")
    }
}

/// A domain a team claims, with its DNS proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TeamDomain {
    pub domain: String,
    pub team_id: uuid::Uuid,
    /// Put `termoak-verify=<token>` in a TXT record at `_termoak-challenge.<domain>`.
    pub token: String,
    /// The TXT record name.
    pub record_name: String,
    /// The TXT record value.
    pub record_value: String,
    pub verified_at: Option<i64>,
    /// `dns`, or `admin:<user id>` (a server administrator vouched for it).
    pub verified_by: Option<String>,
    pub created_at: i64,
    pub checked_at: Option<i64>,
    pub last_error: Option<String>,
}

/// TXT record name of a domain's proof.
pub fn txt_record_name(domain: &str) -> String {
    format!("_termoak-challenge.{domain}")
}

/// TXT record value of a token.
pub fn txt_record_value(token: &str) -> String {
    format!("termoak-verify={token}")
}

/// Lowercase, no trailing dot, letters/digits/hyphens in labels, at least
/// two labels; IDNs in their ASCII (punycode) form.
pub fn normalize_domain(domain: &str) -> Result<String> {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let bad = || CoreError::Invalid(format!("\"{domain}\" is not a domain name"));
    if d.len() > 253 || !d.contains('.') {
        return Err(bad());
    }
    for label in d.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(bad());
        }
    }
    Ok(d)
}

/// The domain of an email address, normalized.
pub fn email_domain(email: &str) -> Option<String> {
    let (_, d) = email.trim().rsplit_once('@')?;
    normalize_domain(d).ok()
}

/// A random URL-safe token of 256 bits (state, nonce, codes).
pub fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<32>())
}

/// A PKCE code verifier (RFC 7636 §4.1: 43 characters).
pub fn pkce_verifier() -> String {
    random_token()
}

/// The S256 challenge of a verifier (RFC 7636 §4.2).
pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Whether a verifier has the shape RFC 7636 allows.
pub fn valid_verifier(v: &str) -> bool {
    (43..=128).contains(&v.len())
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c))
}

/// Callback URLs the server sends a finished sign-in to (docs/E2EE-SSO-AUDIT.md
/// §3.4): loopback HTTP on any port (desktop, CLI; RFC 8252 §7.3), the
/// apps' custom scheme `termoak://sso` (Android, iOS; RFC 8252 §7.1), or a
/// path of the server's own web app (`/app/sso`).
pub fn allowed_redirect(uri: &str, public_origin: Option<&str>) -> bool {
    let Ok(u) = url::Url::parse(uri) else {
        return false;
    };
    if u.fragment().is_some() || !u.username().is_empty() || u.password().is_some() {
        return false;
    }
    match u.scheme() {
        "http" => {
            matches!(
                u.host(),
                Some(url::Host::Ipv4(ip)) if ip.is_loopback()
            ) || matches!(u.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback())
                || u.host_str() == Some("localhost")
        }
        "termoak" => u.host_str() == Some("sso") || u.path().trim_start_matches('/') == "sso",
        "https" => public_origin.is_some_and(|origin| {
            url::Url::parse(origin).is_ok_and(|o| {
                o.scheme() == u.scheme()
                    && o.host_str() == u.host_str()
                    && o.port_or_known_default() == u.port_or_known_default()
            }) && u.path().starts_with("/app/sso")
        }),
        _ => false,
    }
}

/// A sign-in that is waiting for the browser (client side): what the app
/// keeps between opening the URL and the callback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsoPending {
    pub server_url: String,
    pub state: String,
    pub verifier: String,
    pub redirect_uri: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_and_validation() {
        let g = SsoConfig {
            preset: SsoPreset::Google,
            client_id: "x".into(),
            ..Default::default()
        }
        .normalized()
        .unwrap();
        assert_eq!(g.issuer, "https://accounts.google.com");
        assert_eq!(g.scopes, vec!["openid", "email", "profile"]);
        let m = SsoConfig {
            preset: SsoPreset::Microsoft,
            tenant: Some("contoso.onmicrosoft.com".into()),
            client_id: "x".into(),
            ..Default::default()
        }
        .normalized()
        .unwrap();
        assert_eq!(
            m.issuer,
            "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0"
        );
        assert!(
            SsoConfig {
                preset: SsoPreset::Microsoft,
                client_id: "x".into(),
                ..Default::default()
            }
            .normalized()
            .is_err()
        );
        let k = SsoConfig {
            issuer: "https://id.example.com/realms/ops/".into(),
            client_id: "termoak".into(),
            scopes: vec!["profile".into()],
            ..Default::default()
        }
        .normalized()
        .unwrap();
        assert_eq!(k.issuer, "https://id.example.com/realms/ops");
        assert_eq!(k.scopes, vec!["openid", "profile", "email"]);
        assert!(
            SsoConfig {
                issuer: "ftp://x".into(),
                client_id: "x".into(),
                ..Default::default()
            }
            .normalized()
            .is_err()
        );
    }

    #[test]
    fn domains_pkce_and_redirects() {
        assert_eq!(normalize_domain(" Example.COM. ").unwrap(), "example.com");
        assert!(normalize_domain("localhost").is_err());
        assert!(normalize_domain("-a.com").is_err());
        assert_eq!(
            email_domain("Ana@Corp.Example").as_deref(),
            Some("corp.example")
        );
        // RFC 7636 appendix B.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert!(valid_verifier(&pkce_verifier()));
        assert!(allowed_redirect("http://127.0.0.1:53124/callback", None));
        assert!(allowed_redirect("http://[::1]:1/cb", None));
        assert!(allowed_redirect("http://localhost:8080/", None));
        assert!(!allowed_redirect("http://evil.example/cb", None));
        assert!(allowed_redirect("termoak://sso", None));
        assert!(allowed_redirect("termoak://sso/done?x=1", None));
        assert!(!allowed_redirect("termoak://other", None));
        assert!(allowed_redirect(
            "https://next.termoak.com/app/sso",
            Some("https://next.termoak.com")
        ));
        assert!(!allowed_redirect(
            "https://next.termoak.com/app/sso",
            Some("https://termoak.com")
        ));
        assert!(!allowed_redirect(
            "https://next.termoak.com/elsewhere",
            Some("https://next.termoak.com")
        ));
        assert!(!allowed_redirect("http://127.0.0.1:1/cb#frag", None));
    }
}

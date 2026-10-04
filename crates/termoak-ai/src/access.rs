//! Who can use which AI.
//!
//! - A user's **own API key** for a provider (`claude`, `gpt`, `openrouter`,
//!   `opencode-api`) always wins: it replaces the server's key for that
//!   provider, with the user's model if they chose one, and its usage does
//!   not count against any credit.
//! - The **server's providers** (its API keys, the Codex subscription...) can
//!   only be used when the server allows it for that user (its plans decide,
//!   through an [`AccessPolicy`]), within a monthly credit.
//! - Otherwise the provider is skipped. If nothing is left, the request fails
//!   with [`AiError::KeyRequired`].

use std::collections::BTreeMap;

use async_trait::async_trait;
use termoak_core::Id;
use zeroize::Zeroizing;

use crate::config::split_spec;
use crate::error::AiError;
use crate::provider::Registry;

/// Providers that accept the user's own API key. CLI-based providers (Codex,
/// local OpenCode) and the local one only run with the server's setup.
pub const OWN_KEY_PROVIDERS: &[&str] = &["claude", "gpt", "openrouter", "opencode-api"];

/// Access of a user to the server's own providers.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ServerAccess {
    /// Can they use the server's providers?
    pub allowed: bool,
    /// Monthly credit for the server's providers in micro-USD (`None` =
    /// unlimited).
    pub credit_micros: Option<i64>,
}

impl ServerAccess {
    /// No restrictions (administrators, or a server without plans).
    pub const UNRESTRICTED: ServerAccess = ServerAccess {
        allowed: true,
        credit_micros: None,
    };
}

/// Decides each user's access to the server's providers. The server
/// implements it with its plans; without one, everybody can use them (with
/// `[ai] monthly_budget_usd` as the credit).
#[async_trait]
pub trait AccessPolicy: Send + Sync {
    async fn server_access(&self, owner: Id) -> Result<ServerAccess, AiError>;
}

/// Decides the whole provider chain of a request instead of the plans and
/// the server's providers: a client app that runs the AI on its own computer
/// (with the keys of its local vault or an agent installed there). With it,
/// no credit applies.
#[async_trait]
pub trait ChainSource: Send + Sync {
    async fn chain(&self, owner: Id, requested: Option<&str>) -> Result<Vec<ChainEntry>, AiError>;
}

/// A user's own key, decrypted for the duration of a request.
#[derive(Clone)]
pub struct OwnKey {
    pub key: Zeroizing<String>,
    /// Model chosen by the user (`None` = the provider's default).
    pub model: Option<String>,
}

/// One step of a provider chain.
#[derive(Clone, PartialEq, Eq)]
pub struct ChainEntry {
    /// `provider` or `provider::model`.
    pub spec: String,
    /// The user's own API key; `None` = the server's provider.
    pub own_key: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for ChainEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainEntry")
            .field("spec", &self.spec)
            .field("own_key", &self.own_key.as_ref().map(|_| "***"))
            .finish()
    }
}

impl ChainEntry {
    /// The server's provider.
    pub fn server(spec: impl Into<String>) -> Self {
        Self {
            spec: spec.into(),
            own_key: None,
        }
    }

    /// Runs with the user's own key.
    pub fn is_own(&self) -> bool {
        self.own_key.is_some()
    }

    fn own(provider: &str, model: Option<String>, key: &Zeroizing<String>) -> Self {
        Self {
            spec: match model {
                Some(m) => format!("{provider}::{m}"),
                None => provider.to_string(),
            },
            own_key: Some(key.clone()),
        }
    }
}

/// USD to micro-USD.
pub fn usd_to_micros(usd: f64) -> i64 {
    (usd * 1_000_000.0).round() as i64
}

/// Message of [`AiError::KeyRequired`].
pub fn key_required_message(registry: &Registry) -> String {
    let labels: Vec<String> = OWN_KEY_PROVIDERS
        .iter()
        .filter(|p| registry.own_key_supported(p))
        .map(|p| {
            registry
                .provider_config(p)
                .and_then(|c| c.label.clone())
                .unwrap_or_else(|| p.to_string())
        })
        .collect();
    format!(
        "your plan does not include this server's AI: add your own API key ({}) in Settings → AI",
        labels.join(", ")
    )
}

/// Provider chain of a user:
///
/// 1. The requested provider, if it can be used (with the user's key if they
///    have one for it).
/// 2. The providers the user has a key for: first in the order of the
///    server's default chain, then the rest.
/// 3. If allowed, the server's chain (default + fallbacks that are available).
///
/// The credit is not checked here (see `AiEngine`).
pub fn build_chain(
    registry: &Registry,
    requested: Option<&str>,
    own: &BTreeMap<String, OwnKey>,
    access: ServerAccess,
) -> Result<Vec<ChainEntry>, AiError> {
    let own: BTreeMap<&str, &OwnKey> = own
        .iter()
        .filter(|(p, _)| registry.own_key_supported(p))
        .map(|(p, k)| (p.as_str(), k))
        .collect();
    let mut out: Vec<ChainEntry> = Vec::new();
    fn push(out: &mut Vec<ChainEntry>, e: ChainEntry) {
        if !out.contains(&e) {
            out.push(e);
        }
    }

    let requested = requested.map(str::trim).filter(|s| !s.is_empty());
    if let Some(req) = requested {
        let (key, model) = split_spec(req);
        if let Some(k) = own.get(key.as_str()) {
            push(
                &mut out,
                ChainEntry::own(&key, model.or_else(|| k.model.clone()), &k.key),
            );
        } else if access.allowed {
            // Same check as before per-user access existed.
            if let Some(reason) = registry.unavailable_reason(&key) {
                return Err(AiError::NotConfigured(format!("{key}: {reason}")));
            }
            push(&mut out, ChainEntry::server(req));
        } else if registry.provider_config(&key).is_none() {
            return Err(AiError::NotConfigured(format!("{key}: does not exist")));
        }
        // Not allowed and without a key of their own: skipped (the user's
        // keys below may still answer).
    }

    let config = registry.config();
    let defaults =
        std::iter::once(config.default.as_str()).chain(config.fallback.iter().map(String::as_str));
    for spec in defaults {
        let (key, model) = split_spec(spec);
        if let Some(k) = own.get(key.as_str()) {
            push(
                &mut out,
                ChainEntry::own(&key, k.model.clone().or(model), &k.key),
            );
        }
    }
    for (key, k) in &own {
        let listed = out
            .iter()
            .any(|e| e.is_own() && split_spec(&e.spec).0 == *key);
        if !listed {
            push(&mut out, ChainEntry::own(key, k.model.clone(), &k.key));
        }
    }

    if access.allowed {
        for spec in registry.chain(None) {
            push(&mut out, ChainEntry::server(spec));
        }
    }

    if out.is_empty() {
        return Err(if access.allowed {
            AiError::NotConfigured(
                "no AI provider available: configure at least one (Codex, OpenCode Go, Claude, OpenAI...)".into(),
            )
        } else {
            AiError::KeyRequired(key_required_message(registry))
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AiConfig, Driver, ProviderConfig};

    fn registry() -> Registry {
        let mut cfg = AiConfig {
            default: "gpt".into(),
            fallback: vec!["opencode-api::kimi".into()],
            ..Default::default()
        };
        // The server has a key for OpenAI only.
        cfg.providers.insert(
            "gpt".into(),
            ProviderConfig {
                driver: Driver::OpenaiResponses,
                base_url: Some("http://127.0.0.1:9/v1".into()),
                api_key: Some("server-key".into()),
                model: Some("gpt-x".into()),
                ..Default::default()
            },
        );
        for (name, driver) in [
            ("claude", Driver::Anthropic),
            ("opencode-api", Driver::OpenaiChat),
            ("openrouter", Driver::OpenaiChat),
        ] {
            cfg.providers.insert(
                name.into(),
                ProviderConfig {
                    driver,
                    base_url: Some("http://127.0.0.1:9".into()),
                    model: Some(format!("{name}-default")),
                    ..Default::default()
                },
            );
        }
        cfg.providers.insert(
            "codex".into(),
            ProviderConfig {
                driver: Driver::CodexCli,
                command: Some("/nonexistent/codex".into()),
                ..Default::default()
            },
        );
        Registry::new(cfg)
    }

    fn keys(list: &[(&str, Option<&str>)]) -> BTreeMap<String, OwnKey> {
        list.iter()
            .map(|(p, m)| {
                (
                    p.to_string(),
                    OwnKey {
                        key: Zeroizing::new(format!("user-{p}")),
                        model: m.map(str::to_string),
                    },
                )
            })
            .collect()
    }

    fn specs(chain: &[ChainEntry]) -> Vec<(String, bool)> {
        chain.iter().map(|e| (e.spec.clone(), e.is_own())).collect()
    }

    const FREE: ServerAccess = ServerAccess {
        allowed: false,
        credit_micros: None,
    };

    #[test]
    fn without_server_ai_only_own_keys() {
        let r = registry();
        let err = build_chain(&r, None, &BTreeMap::new(), FREE).unwrap_err();
        assert!(matches!(err, AiError::KeyRequired(_)), "{err}");
        assert!(err.to_string().contains("Settings"));
        // A server-only provider is skipped, not used.
        let err = build_chain(&r, Some("gpt"), &BTreeMap::new(), FREE).unwrap_err();
        assert!(matches!(err, AiError::KeyRequired(_)));

        let chain = build_chain(&r, Some("gpt"), &keys(&[("claude", None)]), FREE).unwrap();
        assert_eq!(specs(&chain), vec![("claude".to_string(), true)]);
        assert_eq!(
            chain[0].own_key.as_deref().map(String::as_str),
            Some("user-claude")
        );
    }

    #[test]
    fn own_keys_come_first_and_override_the_server_key() {
        let r = registry();
        let own = keys(&[("gpt", Some("gpt-mine")), ("openrouter", None)]);
        let chain = build_chain(&r, None, &own, ServerAccess::UNRESTRICTED).unwrap();
        assert_eq!(
            specs(&chain),
            vec![
                ("gpt::gpt-mine".to_string(), true),
                ("openrouter".to_string(), true),
                ("gpt".to_string(), false),
            ]
        );
        // The explicit model of the request wins over the user's.
        let chain = build_chain(&r, Some("gpt::gpt-y"), &own, ServerAccess::UNRESTRICTED).unwrap();
        assert_eq!(chain[0].spec, "gpt::gpt-y");
        assert!(chain[0].is_own());
        // The fallback's model is kept when the user did not choose one.
        let chain = build_chain(&r, None, &keys(&[("opencode-api", None)]), FREE).unwrap();
        assert_eq!(
            specs(&chain),
            vec![("opencode-api::kimi".to_string(), true)]
        );
    }

    #[test]
    fn server_only_and_unknown_providers() {
        let r = registry();
        // Keys for providers that do not accept them are ignored.
        let err = build_chain(&r, None, &keys(&[("codex", None)]), FREE).unwrap_err();
        assert!(matches!(err, AiError::KeyRequired(_)));
        let err = build_chain(
            &r,
            Some("nope"),
            &BTreeMap::new(),
            ServerAccess::UNRESTRICTED,
        )
        .unwrap_err();
        assert!(matches!(err, AiError::NotConfigured(_)));
        // Allowed but not configured on the server (no key): same error as before.
        let err = build_chain(
            &r,
            Some("claude"),
            &BTreeMap::new(),
            ServerAccess::UNRESTRICTED,
        )
        .unwrap_err();
        assert!(matches!(err, AiError::NotConfigured(_)));
        let chain = build_chain(&r, None, &BTreeMap::new(), ServerAccess::UNRESTRICTED).unwrap();
        assert_eq!(specs(&chain), vec![("gpt".to_string(), false)]);
        let own = ChainEntry::own("gpt", None, &Zeroizing::new("user-secret".into()));
        assert!(!format!("{own:?}").contains("user-secret"));
    }
}

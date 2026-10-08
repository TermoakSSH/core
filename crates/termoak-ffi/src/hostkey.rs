//! A known host whose key changed: what changed, asking the app whether to
//! trust the new key (`HostKeyChangeHandler`), and replacing a known key.
//!
//! The error stays the flat `HostKey` (its message has the host and both
//! fingerprints); the structured data comes through the handler, passed to
//! `connect` / `connect_terminal` (`key_changed`). Without one nothing
//! changes: the connection fails with `HostKey` without asking.

use std::sync::Arc;

use termoak_client::{ItemRef, LOCAL_OWNER, SaveTarget, Scope, Workspace};
use termoak_core::model::{self as cm, SecretUpdate};

use crate::error::{Result, TermoakError};
use crate::models::{KnownHost, parse_opt_id};
use crate::runtime::block_on;
use crate::vault::TermoakCore;

/// The key of a known host is not the one saved.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HostKeyChange {
    /// Host (name or address, lowercase) as connected to; a jump host's
    /// when the change is on a jump.
    pub host: String,
    pub port: u32,
    /// Key algorithm (`ssh-ed25519`...).
    pub key_type: String,
    /// `SHA256:...` of the saved key.
    pub old_fingerprint: String,
    /// `SHA256:...` of the key the server presents now.
    pub new_fingerprint: String,
    /// Account whose known hosts have the old key (`None`: This device).
    pub account_id: Option<String>,
}

/// Implemented by the app to decide about a changed host key ("The key of
/// web-1 changed. Trust the new key?"), passed to `connect` /
/// `connect_terminal` as `key_changed`.
///
/// **Threads**: called from a background thread; it **may block** while
/// the dialog is shown (like `AuthHandler`).
#[uniffi::export(foreign)]
pub trait HostKeyChangeHandler: Send + Sync {
    /// `true`: forget the old key, trust the new one and go on connecting
    /// (the new key is saved in place of the old one). `false`: the
    /// connection fails with `HostKey`, as without a handler.
    fn on_host_key_changed(&self, change: HostKeyChange) -> bool;
}

/// `host:port` (as the SSH engine reports it) split in two.
pub(crate) fn split_host_port(s: &str) -> (String, u16) {
    match s.rsplit_once(':') {
        Some((h, p)) => match p.parse() {
            Ok(port) => (h.trim_matches(['[', ']']).to_string(), port),
            Err(_) => (s.to_string(), 22),
        },
        None => (s.to_string(), 22),
    }
}

/// The saved keys of `host:port` in the store of `scope`.
async fn known_of(
    ws: &Workspace,
    scope: Scope,
    host: &str,
    port: u16,
) -> Result<Vec<cm::Record<cm::KnownHost>>> {
    let store = ws.store_of(scope)?;
    Ok(store
        .list::<cm::KnownHost>(LOCAL_OWNER)
        .await?
        .into_iter()
        .filter(|r| r.data.host.eq_ignore_ascii_case(host) && r.data.port == port)
        .collect())
}

/// What changed, from the engine's `HostKeyChanged` (the key type is the
/// one of the saved key with the expected fingerprint).
pub(crate) async fn describe(
    ws: &Workspace,
    scope: Scope,
    host_port: &str,
    expected: &str,
    actual: &str,
) -> Result<HostKeyChange> {
    let (host, port) = split_host_port(host_port);
    let known = known_of(ws, scope, &host, port).await?;
    let key_type = known
        .iter()
        .find(|r| r.data.fingerprint == expected)
        .or(known.first())
        .map(|r| r.data.key_type.clone())
        .unwrap_or_default();
    Ok(HostKeyChange {
        host,
        port: port.into(),
        key_type,
        old_fingerprint: expected.to_string(),
        new_fingerprint: actual.to_string(),
        account_id: scope.account().map(|a| a.to_string()),
    })
}

/// Forgets the saved keys of `host:port` of type `key_type` (all of them
/// when it is empty) in the store of `scope`.
pub(crate) async fn forget(
    ws: &Workspace,
    scope: Scope,
    host: &str,
    port: u16,
    key_type: &str,
) -> Result<()> {
    for r in known_of(ws, scope, host, port).await? {
        if key_type.is_empty() || r.data.key_type == key_type {
            ws.delete_item::<cm::KnownHost>(ItemRef {
                scope,
                id: r.data.id,
            })
            .await?;
        }
    }
    Ok(())
}

/// Asks the app about a change (on a blocking thread).
pub(crate) async fn ask(handler: Arc<dyn HostKeyChangeHandler>, change: HostKeyChange) -> bool {
    tokio::task::spawn_blocking(move || handler.on_host_key_changed(change))
        .await
        .unwrap_or(false)
}

#[uniffi::export]
impl TermoakCore {
    /// Trusts `public_key` (OpenSSH format, `ssh-ed25519 AAAA…`) for
    /// `host:port`, replacing the saved keys of the same type (a "trust the
    /// new key" button, or a key checked another way). `account_id`: the
    /// account of the host being connected to (its known hosts are used),
    /// `None` for This device. Returns the saved entry.
    #[uniffi::method(default(account_id))]
    pub fn replace_known_host(
        &self,
        host: String,
        port: u32,
        public_key: String,
        account_id: Option<String>,
    ) -> Result<KnownHost> {
        let host = host.trim().to_ascii_lowercase();
        if host.is_empty() {
            return Err(TermoakError::Invalid("the host is empty".into()));
        }
        let port = u16::try_from(port)
            .ok()
            .filter(|p| *p > 0)
            .ok_or_else(|| TermoakError::Invalid(format!("invalid port: {port}")))?;
        let key = termoak_ssh::keys::parse_public(public_key.trim())?;
        let key_type = termoak_ssh::keys::algorithm_name(&key);
        let entry = cm::KnownHost {
            id: termoak_core::Id::nil(),
            host: host.clone(),
            port,
            key_type: key_type.clone(),
            public_key: termoak_ssh::keys::public_openssh(&key),
            fingerprint: termoak_ssh::keys::fingerprint(&key),
        };
        let (scope, target) = match parse_opt_id(&account_id)?.or(self.pinned) {
            Some(a) => {
                self.ws.require_account(a)?;
                (
                    Scope::Account(a),
                    SaveTarget::Account {
                        account: a,
                        vault: None,
                    },
                )
            }
            None => (Scope::Device, SaveTarget::Device),
        };
        let ws = self.ws.clone();
        block_on(async move {
            forget(&ws, scope, &host, port, &key_type).await?;
            let saved = ws
                .save_item(target, entry, SecretUpdate::Keep, None)
                .await?;
            Ok(saved.into())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_and_port() {
        assert_eq!(split_host_port("web:22"), ("web".into(), 22));
        assert_eq!(split_host_port("10.0.0.1:2222"), ("10.0.0.1".into(), 2222));
        assert_eq!(split_host_port("::1:22"), ("::1".into(), 22));
        assert_eq!(split_host_port("[::1]:22"), ("::1".into(), 22));
        assert_eq!(split_host_port("web"), ("web".into(), 22));
    }
}

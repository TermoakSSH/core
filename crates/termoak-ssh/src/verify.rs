//! Server host key verification (known hosts).

use std::sync::Arc;

use async_trait::async_trait;
use russh::keys::PublicKey;
use serde::{Deserialize, Serialize};
use termoak_core::model::{KnownHost, SecretUpdate};
use termoak_core::{Id, Store};

use crate::error::{Result, SshError};
use crate::keys::{algorithm_name, fingerprint, public_openssh};
use crate::prompt::AuthPrompter;

/// What to do with a host that is not in known hosts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKeyPolicy {
    /// Ask the user (rejected if there is nobody to ask).
    #[default]
    Ask,
    /// Trust on first use and save (TOFU).
    AcceptNew,
    /// Known hosts only.
    Strict,
}

#[async_trait]
pub trait HostKeyVerifier: Send + Sync {
    /// `Ok(())` if the key is trusted; otherwise, the reason.
    async fn verify(&self, host: &str, port: u16, key: &PublicKey) -> Result<()>;
}

/// Accepts any key. For tests only.
pub struct AcceptAll;

#[async_trait]
impl HostKeyVerifier for AcceptAll {
    async fn verify(&self, _host: &str, _port: u16, _key: &PublicKey) -> Result<()> {
        Ok(())
    }
}

/// Verifier backed by the store's `KnownHost` entities.
pub struct StoreVerifier {
    pub store: Store,
    pub owner: Id,
    pub policy: HostKeyPolicy,
    pub prompter: Option<Arc<dyn AuthPrompter>>,
}

#[async_trait]
impl HostKeyVerifier for StoreVerifier {
    async fn verify(&self, host: &str, port: u16, key: &PublicKey) -> Result<()> {
        let presented = public_openssh(key);
        let fp = fingerprint(key);
        let alg = algorithm_name(key);
        let host_norm = host.trim().to_ascii_lowercase();

        let known: Vec<KnownHost> = self
            .store
            .list::<KnownHost>(self.owner)
            .await?
            .into_iter()
            .map(|r| r.data)
            .filter(|k| k.host.eq_ignore_ascii_case(&host_norm) && k.port == port)
            .collect();

        if known.iter().any(|k| same_key(&k.public_key, &presented)) {
            return Ok(());
        }
        if let Some(old) = known.iter().find(|k| k.key_type == alg) {
            return Err(SshError::HostKeyChanged {
                host: format!("{host_norm}:{port}"),
                expected: old.fingerprint.clone(),
                actual: fp,
            });
        }

        let accept = match self.policy {
            HostKeyPolicy::AcceptNew => true,
            HostKeyPolicy::Strict => false,
            HostKeyPolicy::Ask => match &self.prompter {
                Some(p) => {
                    if p.confirm_host_key(&host_norm, port, &alg, &fp).await {
                        true
                    } else {
                        return Err(SshError::HostKeyRejected {
                            host: format!("{host_norm}:{port}"),
                        });
                    }
                }
                None => false,
            },
        };
        if !accept {
            return Err(SshError::HostKeyUnknown {
                host: format!("{host_norm}:{port}"),
                fingerprint: fp,
                key_type: alg,
            });
        }
        self.store
            .save(
                self.owner,
                KnownHost {
                    id: Id::nil(),
                    host: host_norm,
                    port,
                    key_type: alg,
                    public_key: presented,
                    fingerprint: fp,
                },
                SecretUpdate::Keep,
                None,
            )
            .await?;
        Ok(())
    }
}

/// Compares two OpenSSH public keys, ignoring the comment.
fn same_key(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    norm(a) == norm(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{KeyType, generate, parse_public};
    use termoak_core::crypto::MasterKey;

    #[tokio::test]
    async fn tofu_then_detects_change() {
        let store = Store::open_in_memory(MasterKey::generate()).unwrap();
        let owner = termoak_core::new_id();
        let v = StoreVerifier {
            store: store.clone(),
            owner,
            policy: HostKeyPolicy::AcceptNew,
            prompter: None,
        };
        let k1 =
            parse_public(&generate(KeyType::Ed25519, "", None).unwrap().public_openssh).unwrap();
        let k2 =
            parse_public(&generate(KeyType::Ed25519, "", None).unwrap().public_openssh).unwrap();
        v.verify("Example.com", 22, &k1).await.unwrap();
        v.verify("example.com", 22, &k1).await.unwrap();
        assert!(matches!(
            v.verify("example.com", 22, &k2).await,
            Err(SshError::HostKeyChanged { .. })
        ));
        // Another port is another host.
        v.verify("example.com", 2222, &k2).await.unwrap();

        let strict = StoreVerifier {
            store,
            owner,
            policy: HostKeyPolicy::Strict,
            prompter: None,
        };
        assert!(matches!(
            strict.verify("new.example.com", 22, &k1).await,
            Err(SshError::HostKeyUnknown { .. })
        ));
    }
}

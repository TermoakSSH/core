//! Server host key verification (known hosts).

use std::sync::Arc;

use async_trait::async_trait;
use russh::keys::PublicKey;
use serde::{Deserialize, Serialize};
use termoak_core::model::{KnownHost, SecretUpdate};
use termoak_core::store::VaultAccess;
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

/// Where known hosts are looked up and saved.
#[derive(Clone)]
pub enum KnownHostScope {
    /// Owner-based (a client's own store).
    Owner(Id),
    /// Vaults (server): looked up in `lookup` in order (the host's vault,
    /// then the personal vault); a new key is saved into `write_vault`.
    Vaults {
        access: Arc<VaultAccess>,
        lookup: Vec<Id>,
        write_vault: Id,
    },
}

/// Verifier backed by the store's `KnownHost` entities.
pub struct StoreVerifier {
    pub store: Store,
    pub scope: KnownHostScope,
    pub policy: HostKeyPolicy,
    pub prompter: Option<Arc<dyn AuthPrompter>>,
}

impl StoreVerifier {
    /// Known hosts of `owner` (clients).
    pub fn for_owner(
        store: Store,
        owner: Id,
        policy: HostKeyPolicy,
        prompter: Option<Arc<dyn AuthPrompter>>,
    ) -> Self {
        Self {
            store,
            scope: KnownHostScope::Owner(owner),
            policy,
            prompter,
        }
    }

    /// Known hosts for connecting to a host of `host_vault` (server): looks
    /// in the host's vault, then in the user's personal vault. A new key is
    /// saved into the host's vault when the user is Editor there, otherwise
    /// into their personal vault. A key that changed against a pin of the
    /// host's vault always fails (only Editors can replace it).
    pub fn for_host(
        store: Store,
        access: Arc<VaultAccess>,
        host_vault: Id,
        policy: HostKeyPolicy,
        prompter: Option<Arc<dyn AuthPrompter>>,
    ) -> Self {
        let personal = access.personal();
        let mut lookup = vec![host_vault];
        if personal != host_vault && access.role(personal).is_some() {
            lookup.push(personal);
        }
        let write_vault = if access.role(host_vault).is_some_and(|r| r.can_write()) {
            host_vault
        } else {
            personal
        };
        Self {
            store,
            scope: KnownHostScope::Vaults {
                access,
                lookup,
                write_vault,
            },
            policy,
            prompter,
        }
    }

    async fn known(&self, host: &str, port: u16) -> Result<Vec<Vec<KnownHost>>> {
        let keep = |list: Vec<termoak_core::model::Record<KnownHost>>| -> Vec<KnownHost> {
            list.into_iter()
                .map(|r| r.data)
                .filter(|k| k.host.eq_ignore_ascii_case(host) && k.port == port)
                .collect()
        };
        Ok(match &self.scope {
            KnownHostScope::Owner(owner) => {
                vec![keep(self.store.list::<KnownHost>(*owner).await?)]
            }
            KnownHostScope::Vaults { access, lookup, .. } => {
                let mut out = Vec::new();
                for v in lookup {
                    match self.store.list_in::<KnownHost>(access, Some(*v)).await {
                        Ok(list) => out.push(keep(list)),
                        Err(termoak_core::CoreError::Vault { .. }) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                out
            }
        })
    }
}

#[async_trait]
impl HostKeyVerifier for StoreVerifier {
    async fn verify(&self, host: &str, port: u16, key: &PublicKey) -> Result<()> {
        let presented = public_openssh(key);
        let fp = fingerprint(key);
        let alg = algorithm_name(key);
        let host_norm = host.trim().to_ascii_lowercase();

        // Vault by vault, in order: a match accepts, a different key of the
        // same type is a change.
        for known in self.known(&host_norm, port).await? {
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
        let entry = KnownHost {
            id: Id::nil(),
            host: host_norm,
            port,
            key_type: alg,
            public_key: presented,
            fingerprint: fp,
        };
        match &self.scope {
            KnownHostScope::Owner(owner) => {
                self.store
                    .save(*owner, entry, SecretUpdate::Keep, None)
                    .await?;
            }
            KnownHostScope::Vaults {
                access,
                write_vault,
                ..
            } => {
                self.store
                    .save_in(access, *write_vault, entry, SecretUpdate::Keep, None)
                    .await?;
            }
        }
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
        let v = StoreVerifier::for_owner(store.clone(), owner, HostKeyPolicy::AcceptNew, None);
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

        let strict = StoreVerifier::for_owner(store, owner, HostKeyPolicy::Strict, None);
        assert!(matches!(
            strict.verify("new.example.com", 22, &k1).await,
            Err(SshError::HostKeyUnknown { .. })
        ));
    }
}

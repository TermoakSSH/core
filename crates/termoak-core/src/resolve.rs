//! Host resolution: merges the settings inherited from its groups, fetches
//! the (decrypted) credentials and prepares the jump chain.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::Id;
use crate::error::{CoreError, Result};
use crate::model::{Entity, Group, Host, HostSettings, Identity, ProxySettings, Snippet, SshKey};
use crate::store::{SecretUse, Store, VaultAccess};

/// Private key ready to use.
#[derive(Clone, Serialize, Deserialize)]
pub struct ResolvedKey {
    pub id: Id,
    pub label: String,
    pub private_key: String,
    pub passphrase: Option<String>,
    pub certificate: Option<String>,
}

impl std::fmt::Debug for ResolvedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedKey")
            .field("id", &self.id)
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

/// Host with everything needed to connect.
#[derive(Clone, Serialize, Deserialize)]
pub struct ResolvedHost {
    pub host: Host,
    /// Effective settings (groups + host).
    pub settings: HostSettings,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub key: Option<ResolvedKey>,
    /// Preceding jumps, in order.
    pub jumps: Vec<ResolvedHost>,
    /// Resolved startup script.
    pub startup_script: Option<String>,
    /// Effective proxy (from the host or its groups), with its password.
    pub proxy: Option<ResolvedProxy>,
}

/// Proxy ready to use.
#[derive(Clone, Serialize, Deserialize)]
pub struct ResolvedProxy {
    pub settings: ProxySettings,
    pub password: Option<String>,
}

impl std::fmt::Debug for ResolvedProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedProxy")
            .field("settings", &self.settings)
            .field("has_password", &self.password.is_some())
            .finish()
    }
}

impl std::fmt::Debug for ResolvedHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedHost")
            .field("host", &self.host.label)
            .field("address", &self.host.address)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("has_password", &self.password.is_some())
            .field("key", &self.key)
            .field("jumps", &self.jumps)
            .field("proxy", &self.proxy)
            .finish()
    }
}

/// Maximum depth of nested groups and of jumps.
const MAX_DEPTH: usize = 16;

/// Where the references of a host are looked up.
#[derive(Clone, Copy)]
enum Scope<'a> {
    /// Owner-based (a client's own store).
    Owner(Id),
    /// Same-vault rule: only items of this vault (`None`: rows without a
    /// vault); then, optionally, a fallback store (a client's device store,
    /// owner-based).
    Vault {
        vault: Option<Id>,
        fallback: Option<(&'a Store, Id)>,
    },
}

impl Store {
    /// A live entity in the scope; `None` if missing there. The flag tells
    /// whether it came from the fallback store.
    async fn scoped_get<T: Entity>(&self, scope: Scope<'_>, id: Id) -> Result<Option<(T, bool)>> {
        let found = match scope {
            Scope::Owner(owner) => match self.get::<T>(owner, id).await {
                Ok(r) => Some(r.data),
                Err(CoreError::NotFound(_)) => None,
                Err(e) => return Err(e),
            },
            Scope::Vault { vault, .. } => self.get_in_vault::<T>(vault, id).await?,
        };
        if let Some(d) = found {
            return Ok(Some((d, false)));
        }
        if let Scope::Vault {
            fallback: Some((store, owner)),
            ..
        } = scope
        {
            return match store.get::<T>(owner, id).await {
                Ok(r) => Ok(Some((r.data, true))),
                Err(CoreError::NotFound(_)) => Ok(None),
                Err(e) => Err(e),
            };
        }
        Ok(None)
    }

    /// The secret of an entity found with [`Store::scoped_get`]. Only called
    /// after the access to the whole scope was authorized.
    async fn scoped_secret<T: Entity>(
        &self,
        scope: Scope<'_>,
        id: Id,
        from_fallback: bool,
    ) -> Result<T::Secret> {
        match scope {
            Scope::Owner(owner) => self.secret::<T>(owner, id).await,
            Scope::Vault {
                fallback: Some((store, owner)),
                ..
            } if from_fallback => store.secret::<T>(owner, id).await,
            Scope::Vault { vault, .. } => self.secret_in_vault::<T>(vault, id).await,
        }
    }

    /// Effective settings of a host (without credentials).
    pub async fn effective_settings(&self, owner: Id, host: &Host) -> Result<HostSettings> {
        self.effective_scoped(Scope::Owner(owner), host).await
    }

    /// Effective settings of a host of `vault` (groups of the same vault
    /// only). Needs any access to the vault.
    pub async fn effective_settings_in(
        &self,
        access: &VaultAccess,
        vault: Id,
        host: &Host,
    ) -> Result<HostSettings> {
        access.require(vault, crate::model::VaultRole::UseOnly)?;
        self.effective_scoped(
            Scope::Vault {
                vault: Some(vault),
                fallback: None,
            },
            host,
        )
        .await
    }

    async fn effective_scoped(&self, scope: Scope<'_>, host: &Host) -> Result<HostSettings> {
        let mut chain: Vec<Group> = Vec::new();
        let mut seen = HashSet::new();
        let mut next = host.group_id;
        while let Some(gid) = next {
            if !seen.insert(gid) || chain.len() >= MAX_DEPTH {
                break;
            }
            match self.scoped_get::<Group>(scope, gid).await? {
                Some((g, _)) => {
                    next = g.parent_id;
                    chain.push(g);
                }
                None => break,
            }
        }
        let mut settings = HostSettings::default();
        for group in chain.iter().rev() {
            settings = settings.overlay(&group.settings);
        }
        Ok(settings.overlay(&host.settings))
    }

    /// Resolves a host and its jump chain.
    pub async fn resolve_host(&self, owner: Id, host_id: Id) -> Result<ResolvedHost> {
        self.resolve_scoped(Scope::Owner(owner), host_id).await
    }

    /// Resolves a host of a vault `access` reaches, for `purpose` (checked
    /// once with [`VaultAccess::authorize_secret`] for the host's vault).
    /// Every reference (groups, identity, key, jumps, snippet) is looked up
    /// in the same vault only: one outside it resolves as missing, so nobody
    /// can make the server use a key from a vault they cannot see.
    pub async fn resolve_in(
        &self,
        access: &VaultAccess,
        host_id: Id,
        purpose: SecretUse,
    ) -> Result<ResolvedHost> {
        let vault = self.vault_of::<Host>(access, host_id).await?;
        access.authorize_secret(vault, purpose)?;
        self.resolve_scoped(
            Scope::Vault {
                vault: Some(vault),
                fallback: None,
            },
            host_id,
        )
        .await
    }

    /// Client side: resolves a host of this store's `vault` (same-vault
    /// rule), looking up missing references in `fallback` (the device
    /// store, owner-based). For a client's own data only: no access check.
    pub async fn resolve_local(
        &self,
        vault: Option<Id>,
        host_id: Id,
        fallback: Option<(&Store, Id)>,
    ) -> Result<ResolvedHost> {
        self.resolve_scoped(Scope::Vault { vault, fallback }, host_id)
            .await
    }

    async fn resolve_scoped(&self, scope: Scope<'_>, host_id: Id) -> Result<ResolvedHost> {
        let resolved = self.resolve_single(scope, host_id).await?;
        let mut jumps = Vec::new();
        if let Some(ids) = resolved.settings.jump_host_ids.clone() {
            if ids.len() > MAX_DEPTH {
                return Err(CoreError::Invalid("too many jumps".into()));
            }
            for jid in ids {
                if jid == host_id {
                    return Err(CoreError::Invalid(
                        "a host cannot jump through itself".into(),
                    ));
                }
                // A jump's own jumps are ignored: the chain is the one set by the final host.
                jumps.push(self.resolve_single(scope, jid).await?);
            }
        }
        Ok(ResolvedHost { jumps, ..resolved })
    }

    async fn resolve_single(&self, scope: Scope<'_>, host_id: Id) -> Result<ResolvedHost> {
        let (host, host_fb) = self
            .scoped_get::<Host>(scope, host_id)
            .await?
            .ok_or_else(|| CoreError::NotFound(format!("host {host_id}")))?;
        let settings = self.effective_scoped(scope, &host).await?;
        let host_secret = self.scoped_secret::<Host>(scope, host_id, host_fb).await?;

        let identity = match settings.identity_id {
            Some(iid) => match self.scoped_get::<Identity>(scope, iid).await? {
                Some((i, fb)) => Some((i, self.scoped_secret::<Identity>(scope, iid, fb).await?)),
                None => None,
            },
            None => None,
        };

        let username = settings
            .username
            .clone()
            .or_else(|| identity.as_ref().map(|(i, _)| i.username.clone()))
            .filter(|u| !u.trim().is_empty())
            .ok_or_else(|| {
                CoreError::Invalid(format!(
                    "host \"{}\" has no username (not set directly, by a group or by an identity)",
                    host.label
                ))
            })?;

        let password = host_secret
            .password
            .clone()
            .or_else(|| identity.as_ref().and_then(|(_, s)| s.password.clone()));

        let key_id = settings
            .key_id
            .or_else(|| identity.as_ref().and_then(|(i, _)| i.key_id));
        let key = match key_id {
            Some(kid) => {
                let (meta, fb) = self
                    .scoped_get::<SshKey>(scope, kid)
                    .await?
                    .ok_or_else(|| CoreError::NotFound(format!("key {kid}")))?;
                let secret = self.scoped_secret::<SshKey>(scope, kid, fb).await?;
                secret.private_key.map(|private_key| ResolvedKey {
                    id: kid,
                    label: meta.label,
                    private_key,
                    passphrase: secret.passphrase,
                    certificate: meta.certificate,
                })
            }
            None => None,
        };

        let startup_script = match settings.startup_snippet_id {
            Some(sid) => self
                .scoped_get::<Snippet>(scope, sid)
                .await?
                .map(|(s, _)| s.script),
            None => None,
        };

        let proxy = settings
            .proxy
            .clone()
            .filter(|p| !p.host.trim().is_empty() && p.port != 0)
            .map(|settings| ResolvedProxy {
                settings,
                password: host_secret.proxy_password.clone(),
            });

        Ok(ResolvedHost {
            port: settings.port.unwrap_or(22),
            proxy,
            host,
            settings,
            username,
            password,
            key,
            jumps: Vec::new(),
            startup_script,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::model::*;
    use crate::store::test_store;
    use crate::{Id, new_id};

    #[tokio::test]
    async fn resolves_inheritance_and_credentials() {
        let store = test_store();
        let owner = new_id();
        let key = store
            .save(
                owner,
                SshKey {
                    id: Id::nil(),
                    label: "prod".into(),
                    algorithm: "ssh-ed25519".into(),
                    public_key: "ssh-ed25519 AAAA".into(),
                    fingerprint: "SHA256:x".into(),
                    comment: String::new(),
                    has_passphrase: false,
                    certificate: None,
                },
                SecretUpdate::Set(SshKeySecret {
                    private_key: Some("PRIVATE".into()),
                    passphrase: None,
                }),
                None,
            )
            .await
            .unwrap();
        let ident = store
            .save(
                owner,
                Identity {
                    id: Id::nil(),
                    label: "deploy".into(),
                    username: "deploy".into(),
                    key_id: Some(key.data.id),
                },
                SecretUpdate::Keep,
                None,
            )
            .await
            .unwrap();
        let parent = store
            .save(
                owner,
                Group {
                    id: Id::nil(),
                    name: "prod".into(),
                    parent_id: None,
                    color: None,
                    settings: HostSettings {
                        port: Some(2222),
                        identity_id: Some(ident.data.id),
                        ..Default::default()
                    },
                },
                SecretUpdate::Keep,
                None,
            )
            .await
            .unwrap();
        let child = store
            .save(
                owner,
                Group {
                    id: Id::nil(),
                    name: "web".into(),
                    parent_id: Some(parent.data.id),
                    color: None,
                    settings: HostSettings::default(),
                },
                SecretUpdate::Keep,
                None,
            )
            .await
            .unwrap();
        let bastion = store
            .save(
                owner,
                Host {
                    id: Id::nil(),
                    label: "bastion".into(),
                    address: "bastion.example.com".into(),
                    group_id: Some(child.data.id),
                    tags: vec![],
                    settings: HostSettings::default(),
                    notes: String::new(),
                    color: None,
                    os: None,
                    os_version: None,
                    favorite: false,
                },
                SecretUpdate::Keep,
                None,
            )
            .await
            .unwrap();
        let web = store
            .save(
                owner,
                Host {
                    id: Id::nil(),
                    label: "web1".into(),
                    address: "10.0.0.5".into(),
                    group_id: Some(child.data.id),
                    tags: vec![],
                    settings: HostSettings {
                        port: Some(22),
                        jump_host_ids: Some(vec![bastion.data.id]),
                        ..Default::default()
                    },
                    notes: String::new(),
                    color: None,
                    os: None,
                    os_version: None,
                    favorite: false,
                },
                SecretUpdate::Set(HostSecret {
                    password: Some("pw".into()),
                    ..Default::default()
                }),
                None,
            )
            .await
            .unwrap();

        let r = store.resolve_host(owner, web.data.id).await.unwrap();
        assert_eq!(r.port, 22);
        assert_eq!(r.username, "deploy");
        assert_eq!(r.password.as_deref(), Some("pw"));
        assert_eq!(r.key.as_ref().unwrap().private_key, "PRIVATE");
        assert_eq!(r.jumps.len(), 1);
        assert_eq!(r.jumps[0].port, 2222);
        assert_eq!(r.jumps[0].host.label, "bastion");
    }
}

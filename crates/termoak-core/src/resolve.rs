//! Host resolution: merges the settings inherited from its groups, fetches
//! the (decrypted) credentials and prepares the jump chain.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::Id;
use crate::error::{CoreError, Result};
use crate::model::{Group, Host, HostSettings, Identity, ProxySettings, Snippet, SshKey};
use crate::store::Store;

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

impl Store {
    /// Effective settings of a host (without credentials).
    pub async fn effective_settings(&self, owner: Id, host: &Host) -> Result<HostSettings> {
        let mut chain: Vec<Group> = Vec::new();
        let mut seen = HashSet::new();
        let mut next = host.group_id;
        while let Some(gid) = next {
            if !seen.insert(gid) || chain.len() >= MAX_DEPTH {
                break;
            }
            match self.get::<Group>(owner, gid).await {
                Ok(g) => {
                    next = g.data.parent_id;
                    chain.push(g.data);
                }
                Err(CoreError::NotFound(_)) => break,
                Err(e) => return Err(e),
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
        let resolved = self.resolve_single(owner, host_id).await?;
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
                jumps.push(self.resolve_single(owner, jid).await?);
            }
        }
        Ok(ResolvedHost { jumps, ..resolved })
    }

    async fn resolve_single(&self, owner: Id, host_id: Id) -> Result<ResolvedHost> {
        let host = self.get::<Host>(owner, host_id).await?.data;
        let settings = self.effective_settings(owner, &host).await?;
        let host_secret = self.secret::<Host>(owner, host_id).await?;

        let identity = match settings.identity_id {
            Some(iid) => match self.get::<Identity>(owner, iid).await {
                Ok(i) => Some((i.data, self.secret::<Identity>(owner, iid).await?)),
                Err(CoreError::NotFound(_)) => None,
                Err(e) => return Err(e),
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
                let meta = self.get::<SshKey>(owner, kid).await?.data;
                let secret = self.secret::<SshKey>(owner, kid).await?;
                match secret.private_key {
                    Some(private_key) => Some(ResolvedKey {
                        id: kid,
                        label: meta.label,
                        private_key,
                        passphrase: secret.passphrase,
                        certificate: meta.certificate,
                    }),
                    None => None,
                }
            }
            None => None,
        };

        let startup_script = match settings.startup_snippet_id {
            Some(sid) => match self.get::<Snippet>(owner, sid).await {
                Ok(s) => Some(s.data.script),
                Err(CoreError::NotFound(_)) => None,
                Err(e) => return Err(e),
            },
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

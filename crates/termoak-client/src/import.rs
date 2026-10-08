//! Import of `~/.ssh/config`: hosts, keys (without duplicating those already
//! in the keychain), `ProxyJump` jumps and tunnels.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Serialize;
use termoak_core::model::{
    ForwardKind, Group, Host, HostSettings, PortForward, SecretUpdate, SshKey, SshKeySecret,
    SyncMode,
};
use termoak_core::{Id, new_id};
use termoak_ssh::sshconfig::{self, SshConfigHost};

use crate::error::Result;
use crate::workspace::Workspace;

/// Import options.
#[derive(Debug, Clone, Default)]
pub struct ImportOptions {
    /// Only work out what would be done, without saving anything.
    pub dry_run: bool,
    /// Put the hosts in this group (created if it doesn't exist).
    pub group: Option<String>,
    /// Save hosts and keys as "this device only".
    pub device_only: bool,
    /// Account whose store gets them (default: the current account; This
    /// device without one). Ignored with `device_only`.
    pub account: Option<Id>,
    /// Vault of that account (default: its personal vault).
    pub vault: Option<Id>,
}

/// Import result.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ImportReport {
    pub hosts_created: Vec<String>,
    pub hosts_skipped: Vec<SkippedHost>,
    /// Hosts created only to serve as jumps (`user@host:port`).
    pub jump_hosts_created: Vec<String>,
    pub keys_imported: Vec<String>,
    /// Keys that were already in the keychain (same fingerprint).
    pub keys_reused: Vec<String>,
    pub forwards_created: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SkippedHost {
    pub alias: String,
    pub reason: String,
}

/// `[user@]host[:port]`.
fn parse_jump(entry: &str) -> (Option<String>, String, Option<u16>) {
    let (user, rest) = match entry.rsplit_once('@') {
        Some((u, r)) => (Some(u.to_string()), r),
        None => (None, entry),
    };
    // `[ipv6]:port`, `host:port` or just `host`.
    if let Some(inner) = rest.strip_prefix('[')
        && let Some((addr, tail)) = inner.split_once(']')
    {
        let port = tail.strip_prefix(':').and_then(|p| p.parse().ok());
        return (user, addr.to_string(), port);
    }
    match rest.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (user, h.to_string(), p.parse().ok()),
        _ => (user, rest.to_string(), None),
    }
}

impl Workspace {
    /// Where imported items go: the chosen account (or the current one)
    /// and vault (or its personal vault) or, for device-only imports or
    /// without an account, This device.
    fn import_target(&self, opts: &ImportOptions) -> Result<(termoak_core::Store, Option<Id>)> {
        if opts.device_only {
            return Ok((self.store.clone(), None));
        }
        let acc = match opts.account {
            Some(id) => Some(self.require_account(id)?),
            None => self.current(),
        };
        Ok(match acc {
            Some(acc) => {
                let personal = acc
                    .info()
                    .vaults_supported()
                    .then(|| acc.user_id())
                    .flatten();
                let vault = match opts.vault {
                    Some(v) if acc.info().vaults_supported() => Some(v),
                    _ => personal,
                };
                (acc.store.clone(), vault)
            }
            None => (self.store.clone(), None),
        })
    }

    /// Imports an `ssh_config`. Hosts whose name already exists are skipped,
    /// so it can be repeated without duplicating anything.
    pub async fn import_ssh_config(
        &self,
        path: &Path,
        opts: &ImportOptions,
    ) -> Result<ImportReport> {
        let parsed = sshconfig::parse_file(path)?;
        self.import_hosts(parsed, opts).await
    }

    /// Imports hosts already parsed (useful for previews in the UI).
    pub async fn import_hosts(
        &self,
        parsed: Vec<SshConfigHost>,
        opts: &ImportOptions,
    ) -> Result<ImportReport> {
        let owner = self.owner();
        let sync = opts.device_only.then_some(SyncMode::DeviceOnly);
        let (store, vault) = self.import_target(opts)?;
        let mut report = ImportReport::default();

        // What is already there.
        let existing_hosts = store.list::<Host>(owner).await?;
        let mut by_label: HashMap<String, Id> = existing_hosts
            .iter()
            .map(|h| (h.data.label.to_lowercase(), h.data.id))
            .collect();
        // (address, port, user) → host, to reuse jumps.
        let mut by_target: HashMap<(String, u16, Option<String>), Id> = existing_hosts
            .iter()
            .map(|h| {
                (
                    (
                        h.data.address.to_lowercase(),
                        h.data.settings.port.unwrap_or(22),
                        h.data.settings.username.clone(),
                    ),
                    h.data.id,
                )
            })
            .collect();
        let existing_keys = store.list::<SshKey>(owner).await?;
        let mut key_by_fp: HashMap<String, Id> = existing_keys
            .iter()
            .map(|k| (k.data.fingerprint.clone(), k.data.id))
            .collect();
        let mut key_labels: Vec<String> = existing_keys
            .iter()
            .map(|k| k.data.label.to_lowercase())
            .collect();

        // Target group.
        let group_id = match opts
            .group
            .as_deref()
            .map(str::trim)
            .filter(|g| !g.is_empty())
        {
            None => None,
            Some(name) => {
                let groups = store.list::<Group>(owner).await?;
                match groups
                    .iter()
                    .find(|g| g.data.name.eq_ignore_ascii_case(name))
                {
                    Some(g) => Some(g.data.id),
                    None if opts.dry_run => Some(new_id()),
                    None => Some(
                        store
                            .save_local(
                                owner,
                                vault,
                                Group {
                                    id: new_id(),
                                    name: name.to_string(),
                                    parent_id: None,
                                    color: None,
                                    settings: HostSettings::default(),
                                },
                                SecretUpdate::Keep,
                                sync,
                            )
                            .await?
                            .data
                            .id,
                    ),
                }
            }
        };

        // Keys: path → id (or None if it couldn't be imported).
        let mut key_cache: HashMap<PathBuf, Option<Id>> = HashMap::new();

        // First pass: hosts without jumps.
        let mut created: Vec<(SshConfigHost, Host)> = Vec::new();
        for h in parsed {
            if by_label.contains_key(&h.alias.to_lowercase()) {
                report.hosts_skipped.push(SkippedHost {
                    alias: h.alias.clone(),
                    reason: "a host with that name already exists".into(),
                });
                continue;
            }
            // Only the keys that exist; OpenSSH tries several, here the first
            // one is used.
            let present: Vec<&PathBuf> = h.identity_files.iter().filter(|p| p.is_file()).collect();
            if present.is_empty() && !h.identity_files.is_empty() {
                report.warnings.push(format!(
                    "{}: the key {} does not exist on this computer; importing without a key",
                    h.alias,
                    h.identity_files[0].display()
                ));
            }
            if present.len() > 1 {
                report.warnings.push(format!(
                    "{}: it has {} keys; using {}",
                    h.alias,
                    present.len(),
                    present[0].display()
                ));
            }
            let mut key_id = None;
            if let Some(path) = present.first() {
                let path = (*path).clone();
                if !key_cache.contains_key(&path) {
                    let id = self
                        .import_key_file(
                            &path,
                            &h,
                            opts,
                            sync,
                            &mut key_by_fp,
                            &mut key_labels,
                            &mut report,
                        )
                        .await?;
                    key_cache.insert(path.clone(), id);
                }
                key_id = key_cache.get(&path).copied().flatten();
            }
            for u in &h.unsupported {
                report
                    .warnings
                    .push(format!("{}: cannot import \"{u}\"", h.alias));
            }
            let host = Host {
                id: new_id(),
                label: h.alias.clone(),
                address: h.hostname.clone().unwrap_or_else(|| h.alias.clone()),
                group_id,
                tags: Vec::new(),
                settings: HostSettings {
                    port: h.port,
                    username: h.user.clone(),
                    key_id,
                    keepalive_secs: h.server_alive_interval,
                    agent_forwarding: h.forward_agent,
                    env: h.env.clone(),
                    ..Default::default()
                },
                notes: "Imported from ~/.ssh/config".into(),
                color: None,
                os: None,
                os_version: None,
                favorite: false,
                protocol: Default::default(),
                icon: None,
            };
            let host = if opts.dry_run {
                host
            } else {
                store
                    .save_local(owner, vault, host, SecretUpdate::Keep, sync)
                    .await?
                    .data
            };
            by_label.insert(h.alias.to_lowercase(), host.id);
            by_target.insert(
                (
                    host.address.to_lowercase(),
                    host.settings.port.unwrap_or(22),
                    host.settings.username.clone(),
                ),
                host.id,
            );
            report.hosts_created.push(h.alias.clone());
            created.push((h, host));
        }

        // Second pass: jumps (they may point to hosts imported later) and
        // tunnels.
        for (h, mut host) in created {
            if !h.proxy_jump.is_empty() {
                let mut ids = Vec::new();
                for entry in &h.proxy_jump {
                    if let Some(id) = by_label.get(&entry.to_lowercase()) {
                        ids.push(*id);
                        continue;
                    }
                    let (user, addr, port) = parse_jump(entry);
                    if let Some(id) = by_label.get(&addr.to_lowercase())
                        && user.is_none()
                        && port.is_none()
                    {
                        ids.push(*id);
                        continue;
                    }
                    let target = (addr.to_lowercase(), port.unwrap_or(22), user.clone());
                    if let Some(id) = by_target.get(&target) {
                        ids.push(*id);
                        continue;
                    }
                    let jump = Host {
                        id: new_id(),
                        label: entry.clone(),
                        address: addr,
                        settings: HostSettings {
                            port,
                            username: user,
                            ..Default::default()
                        },
                        group_id,
                        tags: Vec::new(),
                        notes: format!("Jump for {} (imported from ~/.ssh/config)", h.alias),
                        color: None,
                        os: None,
                        os_version: None,
                        favorite: false,
                        protocol: Default::default(),
                        icon: None,
                    };
                    let jump = if opts.dry_run {
                        jump
                    } else {
                        store
                            .save_local(owner, vault, jump, SecretUpdate::Keep, sync)
                            .await?
                            .data
                    };
                    by_label.insert(entry.to_lowercase(), jump.id);
                    by_target.insert(target, jump.id);
                    report.jump_hosts_created.push(entry.clone());
                    ids.push(jump.id);
                }
                if ids.contains(&host.id) {
                    report
                        .warnings
                        .push(format!("{}: the jump points to itself; ignored", h.alias));
                    ids.retain(|i| *i != host.id);
                }
                host.settings.jump_host_ids = Some(ids);
                if !opts.dry_run {
                    store
                        .save_local(owner, vault, host.clone(), SecretUpdate::Keep, sync)
                        .await?;
                }
            }

            let mut forwards: Vec<PortForward> = Vec::new();
            for (kind, list, tag) in [
                (ForwardKind::Local, &h.local_forwards, "L"),
                (ForwardKind::Remote, &h.remote_forwards, "R"),
            ] {
                for f in list {
                    forwards.push(PortForward {
                        id: new_id(),
                        label: format!("{} {tag}{}", h.alias, f.bind_port),
                        host_id: host.id,
                        kind,
                        bind_address: f.bind_address.clone(),
                        bind_port: f.bind_port,
                        dest_host: Some(f.dest_host.clone()),
                        dest_port: Some(f.dest_port),
                        auto_start: true,
                    });
                }
            }
            for (addr, port) in &h.dynamic_forwards {
                forwards.push(PortForward {
                    id: new_id(),
                    label: format!("{} D{port}", h.alias),
                    host_id: host.id,
                    kind: ForwardKind::Dynamic,
                    bind_address: addr.clone(),
                    bind_port: *port,
                    dest_host: None,
                    dest_port: None,
                    auto_start: true,
                });
            }
            report.forwards_created += forwards.len();
            if !opts.dry_run {
                for f in forwards {
                    store
                        .save_local(owner, vault, f, SecretUpdate::Keep, sync)
                        .await?;
                }
            }
        }
        Ok(report)
    }

    #[allow(clippy::too_many_arguments)]
    async fn import_key_file(
        &self,
        path: &Path,
        host: &SshConfigHost,
        opts: &ImportOptions,
        sync: Option<SyncMode>,
        key_by_fp: &mut HashMap<String, Id>,
        key_labels: &mut Vec<String>,
        report: &mut ImportReport,
    ) -> Result<Option<Id>> {
        let (store, vault) = self.import_target(opts)?;
        let pem = match std::fs::read_to_string(path) {
            Ok(p) => p,
            Err(e) => {
                report
                    .warnings
                    .push(format!("could not read {}: {e}", path.display()));
                return Ok(None);
            }
        };
        let m = match termoak_ssh::keys::import_private(&pem, None) {
            Ok(m) => m,
            Err(e) => {
                report.warnings.push(format!(
                    "{}: could not import the key {} ({e}); import it by hand from the keychain",
                    host.alias,
                    path.display()
                ));
                return Ok(None);
            }
        };
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "key".into());
        if let Some(id) = key_by_fp.get(&m.fingerprint) {
            report.keys_reused.push(name);
            return Ok(Some(*id));
        }
        // Certificate: the one given, or the `-cert.pub` next to the key.
        let cert_path = host
            .certificate_files
            .iter()
            .find(|p| p.is_file())
            .cloned()
            .or_else(|| {
                let p = PathBuf::from(format!("{}-cert.pub", path.display()));
                p.is_file().then_some(p)
            });
        let certificate = cert_path
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty());
        let mut label = name.clone();
        let mut n = 2;
        while key_labels.contains(&label.to_lowercase()) {
            label = format!("{name} ({n})");
            n += 1;
        }
        key_labels.push(label.to_lowercase());
        let key = SshKey {
            id: new_id(),
            label: label.clone(),
            algorithm: m.algorithm.clone(),
            public_key: m.public_openssh.clone(),
            fingerprint: m.fingerprint.clone(),
            comment: m.comment.clone(),
            has_passphrase: m.encrypted,
            certificate,
        };
        let id = if opts.dry_run {
            key.id
        } else {
            store
                .save_local(
                    self.owner(),
                    vault,
                    key,
                    SecretUpdate::Set(SshKeySecret {
                        private_key: Some(m.private_openssh.clone()),
                        passphrase: None,
                    }),
                    sync,
                )
                .await?
                .data
                .id
        };
        key_by_fp.insert(m.fingerprint, id);
        report.keys_imported.push(label);
        Ok(Some(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use termoak_core::crypto::MasterKey;
    use termoak_ssh::keys::{KeyType, generate};

    #[tokio::test]
    async fn imports_hosts_keys_jumps_and_forwards() {
        let dir = tempfile::tempdir().unwrap();
        let ws = Workspace::open(dir.path(), MasterKey::generate()).unwrap();
        let ssh = dir.path().join("ssh");
        std::fs::create_dir(&ssh).unwrap();
        let key = generate(KeyType::Ed25519, "me@laptop", None).unwrap();
        std::fs::write(ssh.join("id_work"), &key.private_openssh).unwrap();
        let enc = generate(KeyType::Ed25519, "encrypted", Some("phrase")).unwrap();
        std::fs::write(ssh.join("id_enc"), &enc.private_openssh).unwrap();
        let config = format!(
            "Host web\n  HostName 10.0.0.5\n  User deploy\n  ProxyJump bastion\n  IdentityFile {k}\n  LocalForward 8080 localhost:80\n\
             Host bastion\n  HostName bastion.example.com\n  Port 2222\n  IdentityFile {k}\n\
             Host db\n  HostName 10.0.0.9\n  ProxyJump ops@gw.example.com:2200\n  IdentityFile {e}\n  DynamicForward 1080\n\
             Host nokey\n  HostName nokey.example.com\n  IdentityFile {ssh}/missing\n",
            k = ssh.join("id_work").display(),
            e = ssh.join("id_enc").display(),
            ssh = ssh.display(),
        );
        let path = ssh.join("config");
        std::fs::write(&path, config).unwrap();

        // Preview: saves nothing.
        let preview = ws
            .import_ssh_config(
                &path,
                &ImportOptions {
                    dry_run: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(preview.hosts_created.len(), 4);
        assert!(ws.store.list::<Host>(ws.owner()).await.unwrap().is_empty());

        let r = ws
            .import_ssh_config(
                &path,
                &ImportOptions {
                    group: Some("Imported".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(r.hosts_created, ["web", "bastion", "db", "nokey"]);
        assert_eq!(r.jump_hosts_created, ["ops@gw.example.com:2200"]);
        // The shared key is imported once; so is the encrypted one (without passphrase).
        assert_eq!(r.keys_imported, ["id_work", "id_enc"]);
        assert_eq!(r.forwards_created, 2);

        let hosts = ws.store.list::<Host>(ws.owner()).await.unwrap();
        let get = |l: &str| {
            hosts
                .iter()
                .find(|h| h.data.label == l)
                .unwrap()
                .data
                .clone()
        };
        let (web, bastion, db, gw) = (
            get("web"),
            get("bastion"),
            get("db"),
            get("ops@gw.example.com:2200"),
        );
        assert_eq!(web.settings.jump_host_ids, Some(vec![bastion.id]));
        assert_eq!(web.settings.key_id, bastion.settings.key_id);
        assert_eq!(bastion.settings.port, Some(2222));
        assert_eq!(db.settings.jump_host_ids, Some(vec![gw.id]));
        assert_eq!(gw.address, "gw.example.com");
        assert_eq!(gw.settings.port, Some(2200));
        assert_eq!(gw.settings.username.as_deref(), Some("ops"));
        assert!(get("nokey").settings.key_id.is_none());
        assert!(web.group_id.is_some());
        let keys = ws.store.list::<SshKey>(ws.owner()).await.unwrap();
        assert!(
            keys.iter()
                .any(|k| k.data.label == "id_enc" && k.data.has_passphrase)
        );
        let secret = ws
            .store
            .secret::<SshKey>(ws.owner(), web.settings.key_id.unwrap())
            .await
            .unwrap();
        assert!(secret.private_key.unwrap().contains("OPENSSH PRIVATE KEY"));

        // Repeating duplicates nothing.
        let again = ws
            .import_ssh_config(&path, &ImportOptions::default())
            .await
            .unwrap();
        assert!(again.hosts_created.is_empty());
        assert_eq!(again.hosts_skipped.len(), 4);
        assert_eq!(ws.store.list::<Host>(ws.owner()).await.unwrap().len(), 5);
    }

    #[test]
    fn jump_entries() {
        assert_eq!(
            parse_jump("ops@gw:2200"),
            (Some("ops".into()), "gw".into(), Some(2200))
        );
        assert_eq!(parse_jump("gw"), (None, "gw".into(), None));
        assert_eq!(parse_jump("[::1]:22"), (None, "::1".into(), Some(22)));
        assert_eq!(parse_jump("fe80::1"), (None, "fe80::1".into(), None));
    }
}

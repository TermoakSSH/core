//! Where the AI's hosts come from: a [`HostProvider`].
//!
//! The tools and the engine never read hosts, groups, snippets or memories
//! from a store themselves: they ask a provider for an [`Inventory`] (what
//! the user sees) and for connections.
//!
//! - The server uses [`VaultHosts`]: every vault the user can use in its
//!   store, with the server's connection pool.
//! - A client app implements its own (the desktop: This device and the
//!   accounts in view, each host resolved in its own store, with
//!   just-in-time credentials for Use-only vaults).
//!
//! Hosts are found by id, label or address ([`Inventory::resolve`]); a name
//! that matches several hosts is an error that lists them, never a guess.

use std::sync::Arc;

use async_trait::async_trait;
use serde::Serialize;
use termoak_core::model::{Group, Host, Memory, SecretUpdate, Snippet, VaultRole};
use termoak_core::{Id, Store};
use termoak_ssh::{Connection, ConnectionPool};

/// A host the user can see.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HostEntry {
    pub id: Id,
    pub label: String,
    pub address: String,
    pub port: u16,
    /// Effective username (host, group or identity).
    pub user: Option<String>,
    pub group_id: Option<Id>,
    pub tags: Vec<String>,
    pub os: Option<String>,
    pub notes: String,
    /// `ssh`, `telnet` or a later protocol.
    pub protocol: String,
    /// It is reached through jump hosts.
    pub via_jump: bool,
    /// Its vault (server; `None` on a client's own store).
    pub vault_id: Option<Id>,
    /// Where it is, for people and to tell same-named hosts apart ("This
    /// device", an account, a vault). `None`: not worth saying.
    pub location: Option<String>,
    /// The provider's own store of the host (the desktop: its account;
    /// `None`: the default one).
    pub source: Option<Id>,
    /// The user may use it but not see its secrets (Use-only vault).
    pub use_only: bool,
    /// Why the AI cannot run commands or open files on it (a Strict vault,
    /// an account that is signed out...). `None`: it can.
    pub unavailable: Option<String>,
}

impl HostEntry {
    /// A host with the defaults of a plain SSH host (port 22).
    pub fn new(id: Id, label: impl Into<String>, address: impl Into<String>) -> Self {
        Self {
            id,
            label: label.into(),
            address: address.into(),
            port: 22,
            user: None,
            group_id: None,
            tags: Vec::new(),
            os: None,
            notes: String::new(),
            protocol: "ssh".into(),
            via_jump: false,
            vault_id: None,
            location: None,
            source: None,
            use_only: false,
            unavailable: None,
        }
    }

    pub fn is_ssh(&self) -> bool {
        self.protocol.eq_ignore_ascii_case("ssh")
    }

    /// Why the SSH tools (commands, files) cannot use it: a host that is not
    /// SSH (Telnet), or one the provider marked unavailable.
    pub fn ssh_blocker(&self) -> Option<String> {
        if !self.is_ssh() {
            return Some(format!(
                "\"{}\" is a {} host: run_command, read_file, write_file and list_directory only work over SSH. \
                 If the user has it open in a terminal, use the terminal tools (list_sessions, read_terminal, send_to_terminal) instead; \
                 otherwise tell the user it has to be done by hand.",
                self.label,
                if self.protocol.eq_ignore_ascii_case("telnet") {
                    "Telnet".to_string()
                } else {
                    self.protocol.clone()
                }
            ));
        }
        self.unavailable
            .as_ref()
            .map(|why| format!("\"{}\" cannot be used here: {why}", self.label))
    }

    /// One line that tells it apart: `web-1 (10.0.0.1, This device, id …)`.
    pub fn describe(&self) -> String {
        let mut parts = vec![self.address.clone()];
        if let Some(l) = &self.location {
            parts.push(l.clone());
        }
        parts.push(format!("id {}", self.id));
        format!("{} ({})", self.label, parts.join(", "))
    }
}

/// A group the user can see.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GroupEntry {
    pub id: Id,
    pub name: String,
    pub parent_id: Option<Id>,
}

/// The hosts and groups the user sees.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Inventory {
    pub hosts: Vec<HostEntry>,
    pub groups: Vec<GroupEntry>,
}

impl Inventory {
    pub fn group_name(&self, id: Option<Id>) -> Option<String> {
        let id = id?;
        self.groups
            .iter()
            .find(|g| g.id == id)
            .map(|g| g.name.clone())
    }

    /// A group and all its subgroups.
    pub fn group_tree(&self, root: Id) -> Vec<Id> {
        let mut ids = vec![root];
        let mut i = 0;
        while i < ids.len() {
            let parent = ids[i];
            for g in &self.groups {
                if g.parent_id == Some(parent) && !ids.contains(&g.id) {
                    ids.push(g.id);
                }
            }
            i += 1;
        }
        ids
    }

    pub fn host(&self, id: Id) -> Option<&HostEntry> {
        self.hosts.iter().find(|h| h.id == id)
    }

    /// Finds a host by id, then by label, then by address (ignoring case),
    /// inside `scope` when the task is limited to some hosts. A reference
    /// that matches several hosts is an error that lists them: the model
    /// has to choose by id or ask the user.
    pub fn resolve(&self, reference: &str, scope: Option<&[Id]>) -> Result<&HostEntry, String> {
        let r = reference.trim();
        if r.is_empty() {
            return Err("no host given; use list_hosts".into());
        }
        let by_id: Vec<&HostEntry> = match r.parse::<Id>() {
            Ok(id) => self.hosts.iter().filter(|h| h.id == id).take(1).collect(),
            Err(_) => Vec::new(),
        };
        let by_label = || -> Vec<&HostEntry> {
            self.hosts
                .iter()
                .filter(|h| h.label.trim().eq_ignore_ascii_case(r))
                .collect()
        };
        let by_address = || -> Vec<&HostEntry> {
            self.hosts
                .iter()
                .filter(|h| h.address.trim().eq_ignore_ascii_case(r))
                .collect()
        };
        let mut found = by_id;
        if found.is_empty() {
            found = by_label();
        }
        if found.is_empty() {
            found = by_address();
        }
        if found.is_empty() {
            return Err(format!("there is no host \"{r}\"; use list_hosts"));
        }
        if let Some(scope) = scope {
            let inside: Vec<&HostEntry> = found
                .iter()
                .copied()
                .filter(|h| scope.contains(&h.id))
                .collect();
            if inside.is_empty() {
                return Err(format!(
                    "host \"{}\" is outside the scope of this task",
                    found[0].label
                ));
            }
            found = inside;
        }
        if found.len() > 1 {
            let list: Vec<String> = found.iter().map(|h| h.describe()).collect();
            return Err(format!(
                "\"{r}\" matches {} hosts: {}. Use the id of the one you mean, or ask the user which one.",
                found.len(),
                list.join("; ")
            ));
        }
        Ok(found[0])
    }
}

/// Where the AI gets the user's hosts, connections, snippets and memories.
#[async_trait]
pub trait HostProvider: Send + Sync {
    /// The hosts and groups `owner` sees.
    async fn inventory(&self, owner: Id) -> Result<Inventory, String>;

    /// An SSH connection to a host of the inventory (reused while alive).
    async fn connect(&self, owner: Id, host: &HostEntry) -> Result<Arc<Connection>, String>;

    /// Forgets the connection to a host (after an error).
    async fn invalidate(&self, owner: Id, host: &HostEntry);

    async fn snippets(&self, owner: Id) -> Result<Vec<Snippet>, String>;

    async fn memories(&self, owner: Id) -> Result<Vec<Memory>, String>;

    /// Saves a memory, about `host` if given (where the host is when the
    /// user can write there; otherwise in the user's own place, naming it).
    async fn remember(
        &self,
        owner: Id,
        host: Option<&HostEntry>,
        content: &str,
    ) -> Result<(), String>;

    /// Saves a snippet in the user's own place (runbooks).
    async fn save_snippet(&self, owner: Id, snippet: Snippet) -> Result<Snippet, String>;
}

/// The server's provider: every vault the user can use in one store, with a
/// connection pool (hosts resolved inside their vault).
pub struct VaultHosts {
    store: Store,
    pool: Arc<ConnectionPool>,
}

impl VaultHosts {
    pub fn new(store: Store, pool: Arc<ConnectionPool>) -> Self {
        Self { store, pool }
    }
}

#[async_trait]
impl HostProvider for VaultHosts {
    async fn inventory(&self, owner: Id) -> Result<Inventory, String> {
        let access = self
            .store
            .vault_access(owner)
            .await
            .map_err(|e| e.to_string())?;
        let hosts = self
            .store
            .list_in::<Host>(&access, None)
            .await
            .map_err(|e| e.to_string())?;
        let groups = self
            .store
            .list_in::<Group>(&access, None)
            .await
            .map_err(|e| e.to_string())?;
        let mut out = Inventory {
            hosts: Vec::with_capacity(hosts.len()),
            groups: groups
                .into_iter()
                .map(|g| GroupEntry {
                    id: g.data.id,
                    name: g.data.name,
                    parent_id: g.data.parent_id,
                })
                .collect(),
        };
        for rec in hosts {
            let vault = rec.meta.vault_id.unwrap_or(access.personal());
            let settings = self
                .store
                .effective_settings_in(&access, vault, &rec.data)
                .await
                .map_err(|e| e.to_string())?;
            let h = rec.data;
            out.hosts.push(HostEntry {
                port: settings.port.unwrap_or(22),
                user: settings.username,
                group_id: h.group_id,
                tags: h.tags,
                os: h.os,
                notes: h.notes,
                protocol: h.protocol.as_str().to_string(),
                via_jump: settings.jump_host_ids.is_some_and(|j| !j.is_empty()),
                vault_id: Some(vault),
                use_only: access.role(vault) == Some(VaultRole::UseOnly),
                ..HostEntry::new(h.id, h.label, h.address)
            });
        }
        Ok(out)
    }

    async fn connect(&self, owner: Id, host: &HostEntry) -> Result<Arc<Connection>, String> {
        self.pool
            .get(owner, host.id)
            .await
            .map_err(|e| e.to_string())
    }

    async fn invalidate(&self, owner: Id, host: &HostEntry) {
        self.pool.invalidate(owner, host.id).await;
    }

    async fn snippets(&self, owner: Id) -> Result<Vec<Snippet>, String> {
        let access = self
            .store
            .vault_access(owner)
            .await
            .map_err(|e| e.to_string())?;
        Ok(self
            .store
            .list_in::<Snippet>(&access, None)
            .await
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|r| r.data)
            .collect())
    }

    async fn memories(&self, owner: Id) -> Result<Vec<Memory>, String> {
        let access = self
            .store
            .vault_access(owner)
            .await
            .map_err(|e| e.to_string())?;
        Ok(self
            .store
            .list_in::<Memory>(&access, None)
            .await
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|r| r.data)
            .collect())
    }

    /// Into the host's vault when the user is Editor there, otherwise (or
    /// without a host) into their personal vault.
    async fn remember(
        &self,
        owner: Id,
        host: Option<&HostEntry>,
        content: &str,
    ) -> Result<(), String> {
        let access = self
            .store
            .vault_access(owner)
            .await
            .map_err(|e| e.to_string())?;
        let vault = host
            .and_then(|h| h.vault_id)
            .filter(|v| access.role(*v).is_some_and(|r| r.can_write()))
            .unwrap_or(access.personal());
        // References stay inside a vault: a memory about a host of a vault
        // the user cannot write names the host instead.
        let content = content.trim().to_string();
        let (host_id, content) = match host {
            Some(h) if h.vault_id == Some(vault) => (Some(h.id), content),
            Some(h) => (None, format!("{}: {content}", h.label)),
            None => (None, content),
        };
        self.store
            .save_in(
                &access,
                vault,
                Memory {
                    id: Id::nil(),
                    content,
                    host_id,
                },
                SecretUpdate::Keep,
                None,
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn save_snippet(&self, owner: Id, snippet: Snippet) -> Result<Snippet, String> {
        let access = self
            .store
            .vault_access(owner)
            .await
            .map_err(|e| e.to_string())?;
        match self
            .store
            .save_in(
                &access,
                access.personal(),
                snippet.clone(),
                SecretUpdate::Keep,
                None,
            )
            .await
        {
            Ok(r) => Ok(r.data),
            // A client's local store (no vaults yet).
            Err(_) => self
                .store
                .save(owner, snippet, SecretUpdate::Keep, None)
                .await
                .map(|r| r.data)
                .map_err(|e| e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(label: &str, address: &str, location: &str) -> HostEntry {
        HostEntry {
            location: Some(location.into()),
            ..HostEntry::new(termoak_core::new_id(), label, address)
        }
    }

    #[test]
    fn resolves_by_id_label_and_address() {
        let a = host("web-1", "10.0.0.1", "This device");
        let b = host("db", "db.example.com", "Acme");
        let inv = Inventory {
            hosts: vec![a.clone(), b.clone()],
            groups: Vec::new(),
        };
        assert_eq!(inv.resolve("web-1", None).unwrap().id, a.id);
        assert_eq!(inv.resolve(" WEB-1 ", None).unwrap().id, a.id);
        assert_eq!(inv.resolve(&b.id.to_string(), None).unwrap().id, b.id);
        assert_eq!(inv.resolve("DB.example.com", None).unwrap().id, b.id);
        let err = inv.resolve("nope", None).unwrap_err();
        assert!(err.contains("there is no host \"nope\""), "{err}");
        let err = inv.resolve("db", Some(&[a.id])).unwrap_err();
        assert!(err.contains("outside the scope"), "{err}");
        assert_eq!(inv.resolve("web-1", Some(&[a.id])).unwrap().id, a.id);
    }

    #[test]
    fn ambiguous_names_are_listed_not_guessed() {
        let a = host("web-1", "10.0.0.1", "This device");
        let b = host("web-1", "10.0.0.2", "Acme");
        let inv = Inventory {
            hosts: vec![a.clone(), b.clone()],
            groups: Vec::new(),
        };
        let err = inv.resolve("web-1", None).unwrap_err();
        assert!(err.contains("matches 2 hosts"), "{err}");
        assert!(err.contains("This device") && err.contains("Acme"), "{err}");
        assert!(err.contains(&a.id.to_string()) && err.contains(&b.id.to_string()));
        // The id chooses; so does a task limited to one of them.
        assert_eq!(inv.resolve(&b.id.to_string(), None).unwrap().id, b.id);
        assert_eq!(inv.resolve("web-1", Some(&[b.id])).unwrap().id, b.id);
    }

    #[test]
    fn telnet_and_unavailable_hosts_are_refused_by_ssh_tools() {
        let mut h = host("router", "192.168.1.1", "This device");
        assert_eq!(h.ssh_blocker(), None);
        h.protocol = "telnet".into();
        let why = h.ssh_blocker().unwrap();
        assert!(
            why.contains("Telnet") && why.contains("only work over SSH"),
            "{why}"
        );
        let mut s = host("vault-host", "10.1.1.1", "Acme");
        s.unavailable = Some("its vault is Strict".into());
        assert!(s.ssh_blocker().unwrap().contains("Strict"));
    }

    #[test]
    fn group_tree_includes_subgroups() {
        let (a, b, c, d) = (
            termoak_core::new_id(),
            termoak_core::new_id(),
            termoak_core::new_id(),
            termoak_core::new_id(),
        );
        let g = |id, parent| GroupEntry {
            id,
            name: "g".into(),
            parent_id: parent,
        };
        let inv = Inventory {
            hosts: Vec::new(),
            groups: vec![g(a, None), g(b, Some(a)), g(c, Some(b)), g(d, None)],
        };
        let tree = inv.group_tree(a);
        assert_eq!(tree.len(), 3);
        assert!(!tree.contains(&d));
    }
}

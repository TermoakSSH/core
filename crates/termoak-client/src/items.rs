//! Items across the local stores: "This device" (the device store) and
//! every signed-in account (its store).
//!
//! - Listings fan out over the stores of an [`ItemFilter`] and tag every
//!   record with its [`Scope`] and the user's [`ItemAccess`].
//! - Saves go to the store of the item ([`SaveTarget`]); writes need Editor
//!   in the item's vault and secrets of Use-only vaults are never on the
//!   device.
//! - Hosts resolve inside their own vault, then in the device store (a
//!   synced host may use a This-device key). Use-only hosts get
//!   just-in-time credentials from the server, kept in memory only.
//! - Transfers between stores (This device ↔ an account, across accounts)
//!   use the same planner as the server; inside one account they are an
//!   online operation of the server.

use std::collections::{BTreeSet, HashMap};

use serde::Serialize;
use termoak_core::error::codes;
use termoak_core::model::{Entity, EntityKind, Record, SecretUpdate, SyncMode, VaultRole};
use termoak_core::resolve::{ResolvedHost, ResolvedKey};
use termoak_core::store::LocalItem;
use termoak_core::transfer::{
    self, Dependencies, Item, TransferMode, TransferRequest, TransferResult,
};
use termoak_core::{CoreError, Id, Store};

use crate::LOCAL_OWNER;
use crate::accounts::Account;
use crate::api::Credentials;
use crate::error::{ClientError, Result};
use crate::workspace::{AccountView, Workspace};

/// Where an item lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Scope {
    /// The device store ("This device").
    Device,
    /// The store of an account.
    Account(Id),
}

impl Scope {
    pub fn account(self) -> Option<Id> {
        match self {
            Scope::Device => None,
            Scope::Account(id) => Some(id),
        }
    }

    /// `None` = This device.
    pub fn from_account(account: Option<Id>) -> Self {
        account.map_or(Scope::Device, Scope::Account)
    }
}

/// An item of a scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct ItemRef {
    pub scope: Scope,
    pub id: Id,
}

/// What the user can do with an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ItemAccess {
    /// A This-device item: everything.
    Device,
    Manager,
    Editor,
    /// Use it (connect, run), never see its secrets or change it.
    UseOnly,
}

impl ItemAccess {
    pub fn from_role(role: VaultRole) -> Self {
        match role {
            VaultRole::Manager => ItemAccess::Manager,
            VaultRole::Editor => ItemAccess::Editor,
            VaultRole::UseOnly | VaultRole::Unknown => ItemAccess::UseOnly,
        }
    }

    pub fn can_write(self) -> bool {
        !matches!(self, ItemAccess::UseOnly)
    }

    pub fn can_read_secrets(self) -> bool {
        self.can_write()
    }
}

/// Which stores a listing covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemFilter {
    /// `None`: every account.
    pub accounts: Option<Vec<Id>>,
    /// `None`: every vault. Rows without a vault count as the account's
    /// personal vault (its user id).
    pub vaults: Option<Vec<Id>>,
    /// Include This-device items.
    pub include_device: bool,
}

impl Default for ItemFilter {
    fn default() -> Self {
        Self::all()
    }
}

impl ItemFilter {
    /// Every account and This device.
    pub fn all() -> Self {
        Self {
            accounts: None,
            vaults: None,
            include_device: true,
        }
    }

    /// Only This device.
    pub fn device_only() -> Self {
        Self {
            accounts: Some(Vec::new()),
            vaults: None,
            include_device: true,
        }
    }

    /// One account (without This device).
    pub fn account(id: Id) -> Self {
        Self {
            accounts: Some(vec![id]),
            vaults: None,
            include_device: false,
        }
    }
}

/// A record with where it lives and what the user can do with it.
#[derive(Debug, Clone)]
pub struct Scoped<T> {
    pub scope: Scope,
    pub access: ItemAccess,
    pub record: Record<T>,
}

impl<T: Entity> Scoped<T> {
    pub fn item(&self) -> ItemRef {
        ItemRef {
            scope: self.scope,
            id: self.record.data.id(),
        }
    }

    pub fn account_id(&self) -> Option<Id> {
        self.scope.account()
    }
}

/// Where a save goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveTarget {
    /// An existing item stays where it is. A new one goes to the current
    /// account (its personal vault) unless it is `DeviceOnly` or there is
    /// no account: then to This device.
    Auto,
    Device,
    /// An account; `vault` for new items (default: the personal vault).
    Account {
        account: Id,
        vault: Option<Id>,
    },
}

/// A move or copy between stores.
#[derive(Debug, Clone)]
pub struct LocalTransfer {
    /// Items, all from the same scope.
    pub items: Vec<ItemRef>,
    pub to: Scope,
    /// Target vault (accounts; default: the personal vault).
    pub vault: Option<Id>,
    pub mode: TransferMode,
    pub dependencies: Dependencies,
    pub dry_run: bool,
    pub force: bool,
}

fn read_only() -> ClientError {
    CoreError::vault(
        codes::VAULT_READ_ONLY,
        "you can use the items of this vault but not change them",
    )
    .into()
}

fn secret_hidden() -> ClientError {
    CoreError::vault(
        codes::SECRET_HIDDEN,
        "Use-only members cannot see the secrets of this vault",
    )
    .into()
}

/// Role of a row of an account store, with the roles preloaded.
fn access_of(acc: &Account, roles: &HashMap<Id, VaultRole>, vault: Option<Id>) -> ItemAccess {
    match vault {
        None => ItemAccess::Manager,
        Some(v) if Some(v) == acc.user_id() => ItemAccess::Manager,
        Some(v) => ItemAccess::from_role(roles.get(&v).copied().unwrap_or(VaultRole::UseOnly)),
    }
}

/// Puts just-in-time credentials into a resolved host (the jumps first,
/// the host last).
fn apply_credentials(resolved: &mut ResolvedHost, creds: &Credentials) {
    fn apply(r: &mut ResolvedHost, hop: &crate::api::CredentialHop) {
        if !hop.username.is_empty() {
            r.username = hop.username.clone();
        }
        if hop.port != 0 {
            r.port = hop.port;
        }
        r.password = hop.password.clone();
        r.key = hop.key.as_ref().map(|k| ResolvedKey {
            id: r.key.as_ref().map(|k| k.id).unwrap_or_default(),
            label: r.key.as_ref().map(|k| k.label.clone()).unwrap_or_default(),
            private_key: k.private_key.clone(),
            passphrase: k.passphrase.clone(),
            certificate: k.certificate.clone(),
        });
        if let Some(p) = r.proxy.as_mut() {
            p.password = hop.proxy_password.clone();
        }
    }
    for hop in &creds.hops {
        if hop.host_id == resolved.host.id {
            apply(resolved, hop);
        } else if let Some(j) = resolved.jumps.iter_mut().find(|j| j.host.id == hop.host_id) {
            apply(j, hop);
        }
    }
}

impl Workspace {
    /// Store of a scope.
    pub fn store_of(&self, scope: Scope) -> Result<Store> {
        match scope {
            Scope::Device => Ok(self.store.clone()),
            Scope::Account(id) => Ok(self.require_account(id)?.store.clone()),
        }
    }

    /// The current view: its account(s) and This device.
    pub fn default_filter(&self) -> ItemFilter {
        let accounts = match (self.pinned(), self.view()) {
            (Some(p), _) => Some(vec![p]),
            (None, AccountView::One(_)) => self.current().map(|a| vec![a.id]),
            (None, AccountView::All) => None,
        };
        ItemFilter {
            accounts,
            vaults: None,
            include_device: true,
        }
    }

    /// Live items of a kind in the stores of `filter`: This device first,
    /// then the accounts in order.
    pub async fn list_items<T: Entity>(&self, filter: &ItemFilter) -> Result<Vec<Scoped<T>>> {
        let mut out = Vec::new();
        if filter.include_device {
            for record in self.store.list::<T>(LOCAL_OWNER).await? {
                out.push(Scoped {
                    scope: Scope::Device,
                    access: ItemAccess::Device,
                    record,
                });
            }
        }
        for acc in self.account_list() {
            if filter
                .accounts
                .as_ref()
                .is_some_and(|ids| !ids.contains(&acc.id))
            {
                continue;
            }
            let roles = acc.store.local_roles().await?;
            for record in acc.store.list::<T>(LOCAL_OWNER).await? {
                let vault = record.meta.vault_id;
                if let Some(vs) = &filter.vaults {
                    let v = vault.or(acc.user_id());
                    if !v.is_some_and(|v| vs.contains(&v)) {
                        continue;
                    }
                }
                out.push(Scoped {
                    scope: Scope::Account(acc.id),
                    access: access_of(&acc, &roles, vault),
                    record,
                });
            }
        }
        Ok(out)
    }

    /// An item of a scope.
    pub async fn get_item<T: Entity>(&self, item: ItemRef) -> Result<Scoped<T>> {
        match item.scope {
            Scope::Device => Ok(Scoped {
                scope: Scope::Device,
                access: ItemAccess::Device,
                record: self.store.get::<T>(LOCAL_OWNER, item.id).await?,
            }),
            Scope::Account(a) => {
                let acc = self.require_account(a)?;
                let record = acc.store.get::<T>(LOCAL_OWNER, item.id).await?;
                let access = ItemAccess::from_role(acc.role(record.meta.vault_id).await?);
                Ok(Scoped {
                    scope: item.scope,
                    access,
                    record,
                })
            }
        }
    }

    /// Where an id lives: the current account, This device, then the other
    /// accounts.
    pub async fn locate(&self, id: Id) -> Result<ItemRef> {
        let current = self.current();
        let mut order: Vec<Scope> = Vec::new();
        if let Some(c) = &current {
            order.push(Scope::Account(c.id));
        }
        order.push(Scope::Device);
        for a in self.account_list() {
            if current.as_ref().is_none_or(|c| c.id != a.id) {
                order.push(Scope::Account(a.id));
            }
        }
        for scope in order {
            if self.store_of(scope)?.locate_local(id).await?.is_some() {
                return Ok(ItemRef { scope, id });
            }
        }
        Err(CoreError::NotFound(format!("item {id}")).into())
    }

    /// An item by id, wherever it is (see [`locate`](Self::locate)).
    pub async fn find_item<T: Entity>(&self, id: Id) -> Result<Scoped<T>> {
        let item = self.locate(id).await?;
        self.get_item(item).await
    }

    /// Creates or updates an item (see [`SaveTarget`]). An account item
    /// saved as `DeviceOnly` moves to This device (accounts only keep
    /// synced items).
    pub async fn save_item<T: Entity>(
        &self,
        target: SaveTarget,
        data: T,
        secret: SecretUpdate<T::Secret>,
        sync_mode: Option<SyncMode>,
    ) -> Result<Scoped<T>> {
        let id = data.id();
        let (scope, vault) = match target {
            SaveTarget::Device => (Scope::Device, None),
            SaveTarget::Account { account, vault } => (Scope::Account(account), vault),
            SaveTarget::Auto => {
                let found = if id.is_nil() {
                    None
                } else {
                    self.locate(id).await.ok()
                };
                match (found, self.current()) {
                    (Some(item), _) => (item.scope, None),
                    (None, Some(acc)) if sync_mode != Some(SyncMode::DeviceOnly) => {
                        (Scope::Account(acc.id), None)
                    }
                    _ => (Scope::Device, None),
                }
            }
        };
        let Scope::Account(account) = scope else {
            let record = self
                .store
                .save(LOCAL_OWNER, data, secret, sync_mode)
                .await?;
            return Ok(Scoped {
                scope: Scope::Device,
                access: ItemAccess::Device,
                record,
            });
        };
        let acc = self.require_account(account)?;
        let existing = if id.is_nil() {
            None
        } else {
            acc.store.locate_local(id).await?
        };
        let target_vault = match existing {
            Some((kind, v)) => {
                if kind != T::KIND {
                    return Err(CoreError::Conflict(format!("id {id} is already in use")).into());
                }
                if vault.is_some() && vault != v {
                    return Err(CoreError::vault(
                        codes::USE_TRANSFER,
                        "moving an item to another vault goes through a transfer",
                    )
                    .into());
                }
                v
            }
            None => vault.or_else(|| {
                acc.info()
                    .vaults_supported()
                    .then(|| acc.user_id())
                    .flatten()
            }),
        };
        let role = acc.role(target_vault).await?;
        if !role.can_write() {
            return Err(read_only());
        }
        if sync_mode == Some(SyncMode::DeviceOnly) {
            // Accounts keep only synced items: it becomes a This-device item.
            let record = match existing {
                Some(_) => {
                    let saved = acc
                        .store
                        .save_local(LOCAL_OWNER, target_vault, data, secret, None)
                        .await?;
                    let mut items = acc.store.export_local(vec![id]).await?;
                    for i in &mut items {
                        i.vault_id = None;
                    }
                    self.store
                        .import_local(LOCAL_OWNER, items, None, Some(SyncMode::DeviceOnly))
                        .await?;
                    acc.store.delete_local(id).await?;
                    self.changed(scope);
                    let _ = saved;
                    self.store.get::<T>(LOCAL_OWNER, id).await?
                }
                None => {
                    self.store
                        .save(LOCAL_OWNER, data, secret, Some(SyncMode::DeviceOnly))
                        .await?
                }
            };
            return Ok(Scoped {
                scope: Scope::Device,
                access: ItemAccess::Device,
                record,
            });
        }
        let record = acc
            .store
            .save_local(
                LOCAL_OWNER,
                target_vault,
                data,
                secret,
                sync_mode.map(|_| SyncMode::Synced),
            )
            .await?;
        self.changed(scope);
        Ok(Scoped {
            scope,
            access: ItemAccess::from_role(role),
            record,
        })
    }

    /// Deletes an item (accounts: Editor; the deletion syncs).
    pub async fn delete_item<T: Entity>(&self, item: ItemRef) -> Result<()> {
        match item.scope {
            Scope::Device => Ok(self.store.delete::<T>(LOCAL_OWNER, item.id).await?),
            Scope::Account(a) => {
                let acc = self.require_account(a)?;
                let rec = acc.store.get::<T>(LOCAL_OWNER, item.id).await?;
                if !acc.role(rec.meta.vault_id).await?.can_write() {
                    return Err(read_only());
                }
                acc.store.delete::<T>(LOCAL_OWNER, item.id).await?;
                self.changed(item.scope);
                Ok(())
            }
        }
    }

    /// The secret of an item (empty if it has none). Use-only items fail
    /// with `secret_hidden`.
    pub async fn item_secret<T: Entity>(&self, item: ItemRef) -> Result<T::Secret> {
        let store = self.store_of(item.scope)?;
        if let Scope::Account(a) = item.scope {
            let acc = self.require_account(a)?;
            let rec = acc.store.get::<T>(LOCAL_OWNER, item.id).await?;
            if rec.meta.secret_hidden || !acc.role(rec.meta.vault_id).await?.can_read_secrets() {
                return Err(secret_hidden());
            }
        }
        Ok(store.secret::<T>(LOCAL_OWNER, item.id).await?)
    }

    /// Resolves a host for a connection from this device (settings, jumps,
    /// credentials). Hosts of an account resolve inside their vault, then
    /// in the device store. A Use-only host gets just-in-time credentials
    /// from the server (`use_only_strict` in Strict vaults,
    /// `use_only_needs_server` offline); wipe them with
    /// [`ResolvedHost::zeroize_secrets`] once connected.
    pub async fn resolve_item(&self, item: ItemRef) -> Result<ResolvedHost> {
        self.resolve_for(item, "ssh").await
    }

    /// [`resolve_item`](Self::resolve_item) for a purpose (`ssh`, `sftp` or
    /// `forward`, audited by the server).
    pub async fn resolve_for(&self, item: ItemRef, purpose: &str) -> Result<ResolvedHost> {
        let Scope::Account(a) = item.scope else {
            return Ok(self.store.resolve_host(LOCAL_OWNER, item.id).await?);
        };
        let acc = self.require_account(a)?;
        let (_, vault) = acc
            .store
            .locate_local(item.id)
            .await?
            .ok_or_else(|| CoreError::NotFound(format!("host {}", item.id)))?;
        let mut resolved = acc
            .store
            .resolve_local(vault, item.id, Some((&self.store, LOCAL_OWNER)))
            .await?;
        if acc.role(vault).await?.can_read_secrets() {
            return Ok(resolved);
        }
        let vault = vault.unwrap_or_default();
        if acc.is_strict(vault).await? {
            return Err(CoreError::vault(
                codes::USE_ONLY_STRICT,
                "this vault only allows connections through the server",
            )
            .into());
        }
        let needs_server = || -> ClientError {
            CoreError::vault(
                codes::USE_ONLY_NEEDS_SERVER,
                "this host can only be used while connected to its server",
            )
            .into()
        };
        if !acc.is_signed_in() {
            return Err(needs_server());
        }
        let creds = acc
            .api
            .credentials(item.id, purpose)
            .await
            .map_err(|e| match e {
                ClientError::Network(_)
                | ClientError::NotLoggedIn
                | ClientError::SessionExpired => needs_server(),
                other => other,
            })?;
        apply_credentials(&mut resolved, &creds);
        Ok(resolved)
    }

    /// Resolves a host without credentials from the server (terminal
    /// settings, startup script...). Use-only hosts come without secrets.
    pub async fn resolve_public(&self, item: ItemRef) -> Result<ResolvedHost> {
        match item.scope {
            Scope::Device => Ok(self.store.resolve_host(LOCAL_OWNER, item.id).await?),
            Scope::Account(a) => {
                let acc = self.require_account(a)?;
                let vault = acc
                    .store
                    .locate_local(item.id)
                    .await?
                    .ok_or_else(|| CoreError::NotFound(format!("host {}", item.id)))?
                    .1;
                Ok(acc
                    .store
                    .resolve_local(vault, item.id, Some((&self.store, LOCAL_OWNER)))
                    .await?)
            }
        }
    }

    /// Moves or copies items between stores (This device ↔ an account,
    /// across accounts) with the same planner as the server; inside one
    /// account it is the server's online transfer (then a sync). With
    /// `dry_run` nothing is written: the result is the plan ("this will
    /// also copy key `deploy`").
    pub async fn transfer(&self, req: LocalTransfer) -> Result<TransferResult> {
        let Some(first) = req.items.first() else {
            return Err(ClientError::Invalid("choose at least one item".into()));
        };
        let from = first.scope;
        if req.items.iter().any(|i| i.scope != from) {
            return Err(ClientError::Invalid(
                "move or copy items from one place at a time".into(),
            ));
        }
        let src = self.store_of(from)?;
        let mut refs = Vec::new();
        let mut src_vaults: BTreeSet<Option<Id>> = BTreeSet::new();
        for it in &req.items {
            let (kind, vault) = src
                .locate_local(it.id)
                .await?
                .ok_or_else(|| CoreError::NotFound(format!("item {}", it.id)))?;
            refs.push(transfer::ItemRef { kind, id: it.id });
            src_vaults.insert(vault);
        }
        let treq = TransferRequest {
            mode: req.mode,
            items: refs,
            dependencies: req.dependencies,
            dry_run: req.dry_run,
            force: req.force,
        };
        match (from, req.to) {
            (Scope::Device, Scope::Device) => Err(ClientError::Invalid(
                "the items are already on this device".into(),
            )),
            (Scope::Account(a), Scope::Account(b)) if a == b => {
                let acc = self.require_account(a)?;
                if !acc.info().vaults_supported() {
                    return Err(ClientError::Invalid(
                        "this server has no vaults: update it to move items between vaults".into(),
                    ));
                }
                let target = req
                    .vault
                    .or(acc.user_id())
                    .ok_or_else(|| ClientError::Invalid("choose the target vault".into()))?;
                let result = acc.api.transfer(target, &treq).await?;
                if !req.dry_run {
                    acc.sync_once().await?;
                }
                Ok(result)
            }
            _ => {
                self.transfer_between(from, req, treq, src, src_vaults)
                    .await
            }
        }
    }

    async fn transfer_between(
        &self,
        from: Scope,
        req: LocalTransfer,
        treq: TransferRequest,
        src: Store,
        src_vaults: BTreeSet<Option<Id>>,
    ) -> Result<TransferResult> {
        let dst = self.store_of(req.to)?;
        // Permissions: Editor on the source vaults (copying snippets only
        // needs Use-only) and on the target vault.
        let mut src_secret_ok = true;
        if let Scope::Account(a) = from {
            let acc = self.require_account(a)?;
            let snippets_only = treq.items.iter().all(|i| i.kind == EntityKind::Snippet);
            for v in &src_vaults {
                let role = acc.role(*v).await?;
                src_secret_ok &= role.can_read_secrets();
                if !role.can_write() && !(req.mode == TransferMode::Copy && snippets_only) {
                    return Err(read_only());
                }
            }
        }
        let dst_vault = match req.to {
            Scope::Device => None,
            Scope::Account(b) => {
                let acc = self.require_account(b)?;
                let v = req.vault.or_else(|| {
                    acc.info()
                        .vaults_supported()
                        .then(|| acc.user_id())
                        .flatten()
                });
                if !acc.role(v).await?.can_write() {
                    return Err(read_only());
                }
                v
            }
        };
        // Plan with a target id of its own (the source may be the same
        // server vault seen through another account).
        let plan_target = termoak_core::new_id();
        let universe = src.local_items(None).await?;
        let mut target_items: Vec<Item> = dst.local_items(Some(dst_vault)).await?;
        for t in &mut target_items {
            t.vault = plan_target;
        }
        let cross_account = matches!((from, req.to), (Scope::Account(_), Scope::Account(_)));
        let mut new_id = termoak_core::new_id;
        // Across accounts a move is a copy (new ids) plus deleting what a
        // move would have taken.
        let plan_req = TransferRequest {
            mode: if cross_account {
                TransferMode::Copy
            } else {
                treq.mode
            },
            ..treq.clone()
        };
        let plan = transfer::plan(
            &plan_req,
            plan_target,
            &universe,
            &target_items,
            &mut new_id,
        )?;
        let removed: Vec<Id> = if cross_account && treq.mode == TransferMode::Move {
            transfer::plan(&treq, plan_target, &universe, &target_items, &mut new_id)?
                .moves
                .iter()
                .map(|m| m.id)
                .collect()
        } else {
            plan.moves.iter().map(|m| m.id).collect()
        };
        let mut result = plan.result(req.dry_run);
        if req.dry_run {
            return Ok(result);
        }
        let mut wanted: Vec<Id> = plan.moves.iter().map(|m| m.id).collect();
        wanted.extend(plan.copies.iter().map(|c| c.from));
        wanted.sort();
        wanted.dedup();
        let exported: HashMap<Id, LocalItem> = src
            .export_local(wanted)
            .await?
            .into_iter()
            .map(|i| (i.id, i))
            .collect();
        let mut to_import = Vec::new();
        for m in &plan.moves {
            if let Some(it) = exported.get(&m.id) {
                let mut it = it.clone();
                it.data = m.data.clone();
                to_import.push(it);
            }
        }
        for c in &plan.copies {
            if let Some(it) = exported.get(&c.from) {
                let mut it = it.clone();
                it.id = c.to;
                it.data = c.data.clone();
                if !src_secret_ok {
                    it.secret = None;
                }
                to_import.push(it);
            }
        }
        let dst_mode = match req.to {
            Scope::Device => SyncMode::DeviceOnly,
            Scope::Account(_) => SyncMode::Synced,
        };
        dst.import_local(LOCAL_OWNER, to_import, dst_vault, Some(dst_mode))
            .await?;
        if !plan.source_updates.is_empty() {
            src.update_local_data(
                plan.source_updates
                    .iter()
                    .map(|(_, id, data)| (*id, data.clone()))
                    .collect(),
            )
            .await?;
        }
        match from {
            Scope::Device => {
                src.purge_local(removed.clone()).await?;
            }
            Scope::Account(_) => {
                for id in &removed {
                    src.delete_local(*id).await?;
                }
            }
        }
        if cross_account && treq.mode == TransferMode::Move {
            result.moved.clear();
        }
        self.changed(from);
        self.changed(req.to);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_ranks() {
        assert!(ItemAccess::Device.can_write());
        assert!(ItemAccess::Editor.can_read_secrets());
        assert!(!ItemAccess::UseOnly.can_write());
        assert_eq!(
            ItemAccess::from_role(VaultRole::Unknown),
            ItemAccess::UseOnly
        );
        assert_eq!(ItemFilter::device_only().accounts, Some(vec![]));
    }
}

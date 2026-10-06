//! Moving and copying items between vaults: a pure planner shared by the
//! server (`POST /vaults/{target}/transfer`) and the clients (This device ↔
//! vault, across accounts).
//!
//! Rules:
//! 1. **Selection.** A group brings its subgroups and their hosts; a host
//!    brings its forwards and memories. A copy brings the known hosts of
//!    the same host:port; a move moves them only if no other host left in
//!    the source uses them.
//! 2. **Dependencies** (`auto`): identity, key, jump hosts and startup
//!    snippet, from the host's effective settings. A copy always copies them
//!    with new ids (a key with the same fingerprint already in the target is
//!    reused). A move moves a dependency when everything that references it
//!    moves too; otherwise it copies it and rewrites the references.
//!    `none`: references are cleared (`detached`).
//! 3. **Groups.** An item that moves without its group (or parent group)
//!    loses it and gets the inherited settings written into its own, so it
//!    connects the same way.
//! 4. Explicitly moving a key or identity that remaining items still use
//!    fails with `still_referenced`, unless `force`, which detaches those
//!    references.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Id;
use crate::error::{CoreError, Result, codes};
use crate::model::{EntityKind, HostSettings};
use crate::store::references;

/// Move (keeps the ids) or copy (new ids).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum TransferMode {
    #[default]
    Move,
    Copy,
}

/// What to do with what the items reference.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum Dependencies {
    #[default]
    Auto,
    None,
}

/// An item by kind and id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ItemRef {
    pub kind: EntityKind,
    pub id: Id,
}

/// `POST /vaults/{target}/transfer`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TransferRequest {
    #[serde(default)]
    pub mode: TransferMode,
    pub items: Vec<ItemRef>,
    #[serde(default)]
    pub dependencies: Dependencies,
    /// Return the plan without writing.
    #[serde(default)]
    pub dry_run: bool,
    /// Detach references of remaining items to moved keys and identities.
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CopiedItem {
    pub kind: EntityKind,
    pub from: Id,
    pub to: Id,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DetachedRef {
    pub kind: EntityKind,
    pub id: Id,
    pub field: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TransferWarning {
    pub code: String,
    pub kind: EntityKind,
    pub id: Id,
}

/// Outcome (or plan, with `dry_run`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TransferResult {
    pub moved: Vec<ItemRef>,
    pub copied: Vec<CopiedItem>,
    /// Existing items of the target reused instead of a copy (same key).
    #[serde(default)]
    pub reused: Vec<CopiedItem>,
    pub detached: Vec<DetachedRef>,
    pub warnings: Vec<TransferWarning>,
    /// Store revision after the transfer.
    pub rev: i64,
    #[serde(default)]
    pub dry_run: bool,
}

/// A live item of a vault (input of the planner).
#[derive(Debug, Clone)]
pub struct Item {
    pub kind: EntityKind,
    pub id: Id,
    pub vault: Id,
    pub data: Value,
}

#[derive(Debug, Clone)]
pub struct PlannedMove {
    pub kind: EntityKind,
    pub id: Id,
    pub from: Id,
    /// Data after rewriting references and flattening groups.
    pub data: Value,
}

#[derive(Debug, Clone)]
pub struct PlannedCopy {
    pub kind: EntityKind,
    pub from: Id,
    pub from_vault: Id,
    pub to: Id,
    pub data: Value,
}

/// What the store has to write.
#[derive(Debug, Clone, Default)]
pub struct Plan {
    pub moves: Vec<PlannedMove>,
    pub copies: Vec<PlannedCopy>,
    pub reused: Vec<CopiedItem>,
    pub detached: Vec<DetachedRef>,
    pub warnings: Vec<TransferWarning>,
    /// Items left in the source whose references were detached (`force`).
    pub source_updates: Vec<(EntityKind, Id, Value)>,
}

impl Plan {
    /// The result to return (without the revision).
    pub fn result(&self, dry_run: bool) -> TransferResult {
        TransferResult {
            moved: self
                .moves
                .iter()
                .map(|m| ItemRef {
                    kind: m.kind,
                    id: m.id,
                })
                .collect(),
            copied: self
                .copies
                .iter()
                .map(|c| CopiedItem {
                    kind: c.kind,
                    from: c.from,
                    to: c.to,
                })
                .collect(),
            reused: self.reused.clone(),
            detached: self.detached.clone(),
            warnings: self.warnings.clone(),
            rev: 0,
            dry_run,
        }
    }
}

/// Dependency fields (not group membership).
fn is_dependency(field: &str) -> bool {
    !matches!(field, "group_id" | "parent_id")
}

/// Removes the reference `field` → `target` from `data`. Returns whether
/// something changed (a forward's host cannot be removed).
pub fn detach_ref(data: &mut Value, field: &str, target: Id) -> bool {
    let t = target.to_string();
    match field {
        "settings.jump_host_ids" => {
            let Some(list) = data
                .get_mut("settings")
                .and_then(|s| s.get_mut("jump_host_ids"))
            else {
                return false;
            };
            if let Some(arr) = list.as_array_mut() {
                let before = arr.len();
                arr.retain(|v| v.as_str() != Some(t.as_str()));
                let changed = arr.len() != before;
                if arr.is_empty() {
                    *list = Value::Null;
                }
                return changed;
            }
            false
        }
        "host_id" if data.get("label").is_some() => false, // forward: required
        _ => {
            let slot = match field.strip_prefix("settings.") {
                Some(f) => data.get_mut("settings").and_then(|s| s.get_mut(f)),
                None => data.get_mut(field),
            };
            match slot {
                Some(v) if v.as_str() == Some(t.as_str()) => {
                    *v = Value::Null;
                    true
                }
                _ => false,
            }
        }
    }
}

/// Replaces the reference `field` → `from` with `to`.
fn rewrite_ref(data: &mut Value, field: &str, from: Id, to: Id) {
    let (f, t) = (from.to_string(), Value::String(to.to_string()));
    let slot = match field.strip_prefix("settings.") {
        Some(name) => data.get_mut("settings").and_then(|s| s.get_mut(name)),
        None => data.get_mut(field),
    };
    match slot {
        Some(Value::Array(arr)) => {
            for v in arr.iter_mut() {
                if v.as_str() == Some(f.as_str()) {
                    *v = t.clone();
                }
            }
        }
        Some(v) if v.as_str() == Some(f.as_str()) => *v = t,
        _ => {}
    }
}

fn parse_id(v: &Value) -> Option<Id> {
    v.as_str().and_then(|s| s.parse().ok())
}

fn settings_of(data: &Value) -> HostSettings {
    data.get("settings")
        .cloned()
        .and_then(|s| serde_json::from_value(s).ok())
        .unwrap_or_default()
}

struct Universe<'a> {
    by_id: HashMap<Id, &'a Item>,
    items: &'a [Item],
}

impl<'a> Universe<'a> {
    fn get(&self, id: Id, vault: Id) -> Option<&'a Item> {
        self.by_id.get(&id).copied().filter(|i| i.vault == vault)
    }

    /// Settings inherited from the group chain of `start` (exclusive of the
    /// item's own settings).
    fn inherited(&self, vault: Id, start: Option<Id>) -> HostSettings {
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        let mut next = start;
        while let Some(gid) = next {
            if !seen.insert(gid) || chain.len() >= 16 {
                break;
            }
            match self.get(gid, vault) {
                Some(g) if g.kind == EntityKind::Group => {
                    next = g.data.get("parent_id").and_then(parse_id);
                    chain.push(settings_of(&g.data));
                }
                _ => break,
            }
        }
        let mut s = HostSettings::default();
        for g in chain.iter().rev() {
            s = s.overlay(g);
        }
        s
    }

    /// Items of `vault` whose own data references `target` through a
    /// dependency field.
    fn referencers(&self, vault: Id, target: Id) -> Vec<(&'a Item, &'static str)> {
        let mut out = Vec::new();
        for item in self.items.iter().filter(|i| i.vault == vault) {
            for (field, rid) in references(item.kind, &item.data) {
                if rid == target && is_dependency(field) {
                    out.push((item, field));
                }
            }
        }
        out
    }
}

/// Plans a transfer of `req.items` (all present in `universe`, the live
/// items of their vaults) to `target`. `target_items` are the live items of
/// the target (to reuse keys). `new_id` makes the ids of copies.
pub fn plan(
    req: &TransferRequest,
    target: Id,
    universe: &[Item],
    target_items: &[Item],
    new_id: &mut dyn FnMut() -> Id,
) -> Result<Plan> {
    let u = Universe {
        by_id: universe.iter().map(|i| (i.id, i)).collect(),
        items: universe,
    };
    let copy = req.mode == TransferMode::Copy;
    let mut out = Plan::default();

    // 1. Selection.
    let mut order: Vec<Id> = Vec::new();
    let mut set: HashSet<Id> = HashSet::new();
    let push = |id: Id, order: &mut Vec<Id>, set: &mut HashSet<Id>| {
        if set.insert(id) {
            order.push(id);
        }
    };
    for r in &req.items {
        let item = u
            .by_id
            .get(&r.id)
            .filter(|i| i.kind == r.kind)
            .ok_or_else(|| CoreError::NotFound(format!("{} {}", r.kind.as_str(), r.id)))?;
        if !copy && item.vault == target {
            out.warnings.push(TransferWarning {
                code: "already_in_vault".into(),
                kind: item.kind,
                id: item.id,
            });
            continue;
        }
        push(item.id, &mut order, &mut set);
    }
    // Groups bring their subgroups (to a fixpoint) and then their hosts.
    loop {
        let before = order.len();
        for item in universe {
            if item.kind == EntityKind::Group
                && let Some(p) = item.data.get("parent_id").and_then(parse_id)
                && set.contains(&p)
                && u.get(p, item.vault).is_some()
            {
                push(item.id, &mut order, &mut set);
            }
        }
        if order.len() == before {
            break;
        }
    }
    for item in universe {
        if item.kind == EntityKind::Host
            && let Some(g) = item.data.get("group_id").and_then(parse_id)
            && set.contains(&g)
            && u.get(g, item.vault).is_some()
        {
            push(item.id, &mut order, &mut set);
        }
    }
    // Hosts bring their forwards and memories.
    let hosts: Vec<Id> = order
        .iter()
        .copied()
        .filter(|id| u.by_id[id].kind == EntityKind::Host)
        .collect();
    for item in universe {
        if matches!(item.kind, EntityKind::Forward | EntityKind::Memory)
            && let Some(h) = item.data.get("host_id").and_then(parse_id)
            && hosts.contains(&h)
            && u.get(h, item.vault).is_some()
        {
            push(item.id, &mut order, &mut set);
        }
    }
    // Known hosts of the same host:port.
    let endpoint = |item: &Item| -> (String, u16) {
        let own = settings_of(&item.data);
        let group = item.data.get("group_id").and_then(parse_id);
        let port = own
            .port
            .or_else(|| u.inherited(item.vault, group).port)
            .unwrap_or(22);
        (
            item.data
                .get("address")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase(),
            port,
        )
    };
    let moved_endpoints: HashSet<(Id, String, u16)> = hosts
        .iter()
        .map(|h| {
            let item = u.by_id[h];
            let (a, p) = endpoint(item);
            (item.vault, a, p)
        })
        .collect();
    let remaining_endpoints: HashSet<(Id, String, u16)> = universe
        .iter()
        .filter(|i| i.kind == EntityKind::Host && !set.contains(&i.id))
        .map(|i| {
            let (a, p) = endpoint(i);
            (i.vault, a, p)
        })
        .collect();
    for item in universe {
        if item.kind != EntityKind::KnownHost || set.contains(&item.id) {
            continue;
        }
        let key = (
            item.vault,
            item.data
                .get("host")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase(),
            item.data.get("port").and_then(Value::as_u64).unwrap_or(22) as u16,
        );
        if moved_endpoints.contains(&key) && (copy || !remaining_endpoints.contains(&key)) {
            push(item.id, &mut order, &mut set);
        }
    }

    // 3. Flatten what leaves its group behind.
    let mut data: HashMap<Id, Value> = HashMap::new();
    for id in &order {
        let item = u.by_id[id];
        let mut d = item.data.clone();
        let field = match item.kind {
            EntityKind::Host => Some("group_id"),
            EntityKind::Group => Some("parent_id"),
            _ => None,
        };
        if let Some(field) = field
            && let Some(g) = d.get(field).and_then(parse_id)
            && !set.contains(&g)
        {
            let inherited = u.inherited(item.vault, Some(g));
            let own = settings_of(&d);
            if let Some(obj) = d.as_object_mut() {
                obj.insert(field.into(), Value::Null);
                obj.insert(
                    "settings".into(),
                    serde_json::to_value(inherited.overlay(&own))?,
                );
            }
        }
        data.insert(*id, d);
    }

    // 4. Explicit keys and identities still used by what stays.
    let explicit: HashSet<Id> = req.items.iter().map(|r| r.id).collect();
    if !copy {
        let mut still: Vec<Value> = Vec::new();
        for id in &order {
            let item = u.by_id[id];
            if !explicit.contains(id)
                || !matches!(item.kind, EntityKind::Key | EntityKind::Identity)
            {
                continue;
            }
            for (user, field) in u.referencers(item.vault, *id) {
                if set.contains(&user.id) {
                    continue;
                }
                if req.force {
                    let mut d = out
                        .source_updates
                        .iter()
                        .find(|(_, i, _)| *i == user.id)
                        .map(|(_, _, d)| d.clone())
                        .unwrap_or_else(|| user.data.clone());
                    if detach_ref(&mut d, field, *id) {
                        out.source_updates.retain(|(_, i, _)| *i != user.id);
                        out.source_updates.push((user.kind, user.id, d));
                        out.detached.push(DetachedRef {
                            kind: user.kind,
                            id: user.id,
                            field: field.into(),
                        });
                    }
                } else {
                    still.push(
                        serde_json::json!({"kind": user.kind, "id": user.id, "field": field}),
                    );
                }
            }
        }
        if !still.is_empty() {
            return Err(CoreError::vault_detail(
                codes::STILL_REFERENCED,
                "other items still use what you are moving",
                serde_json::json!({ "used_by": still }),
            ));
        }
    }

    // 2. Dependencies.
    // Ids of copies (old → new) and reused target keys.
    let mut ids: HashMap<Id, Id> = HashMap::new();
    let mut copies: HashSet<Id> = HashSet::new();
    let target_keys: HashMap<String, Id> = target_items
        .iter()
        .filter(|i| i.kind == EntityKind::Key && i.vault == target)
        .filter_map(|i| {
            i.data
                .get("fingerprint")
                .and_then(Value::as_str)
                .map(|f| (f.to_string(), i.id))
        })
        .collect();
    if copy {
        for id in &order {
            copies.insert(*id);
        }
    }
    let mut queue: Vec<Id> = order.clone();
    let mut qi = 0;
    while qi < queue.len() {
        let id = queue[qi];
        qi += 1;
        let item = u.by_id[&id];
        let current = data.get(&id).cloned().unwrap_or_else(|| item.data.clone());
        for (field, dep) in references(item.kind, &current) {
            if !is_dependency(field) || set.contains(&dep) || ids.contains_key(&dep) {
                continue;
            }
            let Some(dep_item) = u.get(dep, item.vault) else {
                continue; // missing or in another vault: resolves as missing anyway
            };
            if req.dependencies == Dependencies::None {
                continue; // detached below
            }
            // A key already in the target (same fingerprint) is reused.
            if dep_item.kind == EntityKind::Key
                && (copy || copies.contains(&id))
                && let Some(existing) = dep_item
                    .data
                    .get("fingerprint")
                    .and_then(Value::as_str)
                    .and_then(|f| target_keys.get(f))
            {
                ids.insert(dep, *existing);
                out.reused.push(CopiedItem {
                    kind: EntityKind::Key,
                    from: dep,
                    to: *existing,
                });
                continue;
            }
            let all_move = !copy
                && u.referencers(item.vault, dep)
                    .iter()
                    .all(|(r, _)| set.contains(&r.id) && !copies.contains(&r.id));
            if all_move {
                set.insert(dep);
                order.push(dep);
            } else {
                let fresh = new_id();
                ids.insert(dep, fresh);
                copies.insert(dep);
                set.insert(dep);
                order.push(dep);
            }
            let mut d = dep_item.data.clone();
            if dep_item.kind == EntityKind::Host
                && let Some(g) = d.get("group_id").and_then(parse_id)
                && !set.contains(&g)
            {
                let inherited = u.inherited(dep_item.vault, Some(g));
                let own = settings_of(&d);
                if let Some(obj) = d.as_object_mut() {
                    obj.insert("group_id".into(), Value::Null);
                    obj.insert(
                        "settings".into(),
                        serde_json::to_value(inherited.overlay(&own))?,
                    );
                }
            }
            data.insert(dep, d);
            queue.push(dep);
        }
    }
    if copy {
        for id in &order {
            ids.entry(*id).or_insert_with(&mut *new_id);
        }
    }

    // Rewrite references and detach what stays behind.
    for id in &order {
        let item = u.by_id[id];
        let mut d = data.remove(id).unwrap_or_else(|| item.data.clone());
        for (field, rid) in references(item.kind, &d) {
            if let Some(new) = ids.get(&rid) {
                rewrite_ref(&mut d, field, rid, *new);
            } else if !set.contains(&rid) && u.get(rid, item.vault).is_some() {
                if detach_ref(&mut d, field, rid) {
                    out.detached.push(DetachedRef {
                        kind: item.kind,
                        id: *id,
                        field: field.into(),
                    });
                } else {
                    out.warnings.push(TransferWarning {
                        code: "reference_left_behind".into(),
                        kind: item.kind,
                        id: *id,
                    });
                }
            }
        }
        if copies.contains(id) {
            let to = ids[id];
            if let Some(obj) = d.as_object_mut() {
                obj.insert("id".into(), Value::String(to.to_string()));
            }
            out.copies.push(PlannedCopy {
                kind: item.kind,
                from: *id,
                from_vault: item.vault,
                to,
                data: d,
            });
        } else {
            out.moves.push(PlannedMove {
                kind: item.kind,
                id: *id,
                from: item.vault,
                data: d,
            });
        }
    }
    // Moved items that remaining items still point to (jump hosts, snippets).
    if !copy {
        let moved: HashSet<Id> = out.moves.iter().map(|m| m.id).collect();
        for m in &out.moves {
            for (user, _) in u.referencers(m.from, m.id) {
                if !set.contains(&user.id) && !moved.contains(&user.id) {
                    out.warnings.push(TransferWarning {
                        code: "still_used_in_source".into(),
                        kind: user.kind,
                        id: user.id,
                    });
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::new_id;
    use serde_json::json;

    fn item(kind: EntityKind, vault: Id, data: Value) -> Item {
        let id = data["id"].as_str().unwrap().parse().unwrap();
        Item {
            kind,
            id,
            vault,
            data,
        }
    }

    struct Fixture {
        dst: Id,
        key: Id,
        ident: Id,
        group: Id,
        web: Id,
        db: Id,
        other: Id,
        items: Vec<Item>,
    }

    /// Source vault: key ← identity ← group "prod" ← hosts web, db; host
    /// "other" (no group) uses the same key directly.
    fn fixture() -> Fixture {
        let (src, dst) = (new_id(), new_id());
        let (key, ident, group, web, db, other) =
            (new_id(), new_id(), new_id(), new_id(), new_id(), new_id());
        let items = vec![
            item(
                EntityKind::Key,
                src,
                json!({"id": key, "label": "deploy", "algorithm": "ssh-ed25519",
                       "public_key": "ssh-ed25519 AAAA", "fingerprint": "SHA256:k"}),
            ),
            item(
                EntityKind::Identity,
                src,
                json!({"id": ident, "label": "deploy", "username": "deploy", "key_id": key}),
            ),
            item(
                EntityKind::Group,
                src,
                json!({"id": group, "name": "prod", "settings": {"port": 2222, "identity_id": ident}}),
            ),
            item(
                EntityKind::Host,
                src,
                json!({"id": web, "label": "web", "address": "web.example.com", "group_id": group}),
            ),
            item(
                EntityKind::Host,
                src,
                json!({"id": db, "label": "db", "address": "db.example.com", "group_id": group}),
            ),
            item(
                EntityKind::Host,
                src,
                json!({"id": other, "label": "other", "address": "o.example.com",
                       "settings": {"key_id": key}}),
            ),
        ];
        Fixture {
            dst,
            key,
            ident,
            group,
            web,
            db,
            other,
            items,
        }
    }

    fn req(mode: TransferMode, items: &[(EntityKind, Id)]) -> TransferRequest {
        TransferRequest {
            mode,
            items: items
                .iter()
                .map(|(kind, id)| ItemRef {
                    kind: *kind,
                    id: *id,
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn host_moving_without_group_is_flattened_and_shared_key_copied() {
        let f = fixture();
        let p = plan(
            &req(TransferMode::Move, &[(EntityKind::Host, f.web)]),
            f.dst,
            &f.items,
            &[],
            &mut new_id,
        )
        .unwrap();
        let web = p.moves.iter().find(|m| m.id == f.web).unwrap();
        assert!(web.data["group_id"].is_null());
        assert_eq!(web.data["settings"]["port"], 2222);
        // The identity is used by the group (stays) → copied with a new id;
        // its key is used by "other" too → copied.
        let ident = p.copies.iter().find(|c| c.from == f.ident).unwrap();
        assert_eq!(
            web.data["settings"]["identity_id"],
            json!(ident.to.to_string())
        );
        let key = p.copies.iter().find(|c| c.from == f.key).unwrap();
        assert_eq!(ident.data["key_id"], json!(key.to.to_string()));
        assert!(p.moves.iter().all(|m| m.id != f.db));
    }

    #[test]
    fn group_brings_hosts_and_moves_deps_only_used_inside() {
        let mut f = fixture();
        // Without "other" the key is only used by the identity.
        f.items.retain(|i| i.id != f.other);
        let p = plan(
            &req(TransferMode::Move, &[(EntityKind::Group, f.group)]),
            f.dst,
            &f.items,
            &[],
            &mut new_id,
        )
        .unwrap();
        let moved: HashSet<Id> = p.moves.iter().map(|m| m.id).collect();
        for id in [f.group, f.web, f.db, f.ident, f.key] {
            assert!(moved.contains(&id), "{id} should move");
        }
        assert!(p.copies.is_empty());
        // The hosts keep their group (it moves with them).
        let web = p.moves.iter().find(|m| m.id == f.web).unwrap();
        assert_eq!(web.data["group_id"], json!(f.group.to_string()));
    }

    #[test]
    fn explicit_key_still_referenced_and_force() {
        let f = fixture();
        let r = req(TransferMode::Move, &[(EntityKind::Key, f.key)]);
        let err = plan(&r, f.dst, &f.items, &[], &mut new_id).unwrap_err();
        assert_eq!(err.vault_code(), Some(codes::STILL_REFERENCED));
        let p = plan(
            &TransferRequest { force: true, ..r },
            f.dst,
            &f.items,
            &[],
            &mut new_id,
        )
        .unwrap();
        assert_eq!(p.moves.len(), 1);
        let updated: HashSet<Id> = p.source_updates.iter().map(|(_, id, _)| *id).collect();
        assert!(updated.contains(&f.ident) && updated.contains(&f.other));
        let (_, _, other) = p
            .source_updates
            .iter()
            .find(|(_, id, _)| *id == f.other)
            .unwrap();
        assert!(other["settings"]["key_id"].is_null());
    }

    #[test]
    fn copy_reuses_key_with_same_fingerprint_and_none_detaches() {
        let f = fixture();
        let existing = new_id();
        let target = vec![item(
            EntityKind::Key,
            f.dst,
            json!({"id": existing, "label": "deploy", "algorithm": "ssh-ed25519",
                   "public_key": "ssh-ed25519 AAAA", "fingerprint": "SHA256:k"}),
        )];
        let p = plan(
            &req(TransferMode::Copy, &[(EntityKind::Host, f.other)]),
            f.dst,
            &f.items,
            &target,
            &mut new_id,
        )
        .unwrap();
        assert_eq!(p.copies.len(), 1);
        assert_ne!(p.copies[0].to, f.other);
        assert_eq!(
            p.copies[0].data["settings"]["key_id"],
            json!(existing.to_string())
        );
        assert_eq!(p.reused.len(), 1);

        let p = plan(
            &TransferRequest {
                dependencies: Dependencies::None,
                ..req(TransferMode::Move, &[(EntityKind::Host, f.other)])
            },
            f.dst,
            &f.items,
            &[],
            &mut new_id,
        )
        .unwrap();
        assert!(p.moves[0].data["settings"]["key_id"].is_null());
        assert_eq!(p.detached[0].field, "settings.key_id");
    }
}

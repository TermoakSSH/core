//! Vaults: the unit of ownership, sharing and sync of entities.
//!
//! - Every user has a personal vault whose id is the user id. Users create
//!   `shared` vaults; teams own `team` vaults.
//! - The effective role of a user in a vault is the maximum (by rank, never
//!   by text) of: owner (manager), team owner/admin (manager), plain team
//!   member (`team_member_role`), direct grants and grants to their teams.
//! - Each vault has its own data key (VK), created lazily on the first
//!   secret written to it and wrapped with the server master key. Legacy
//!   secrets (sealed with the master key, `key_version IS NULL`) still open;
//!   [`Store::reseal_legacy`] moves them to the vault keys in batches.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, params};
use zeroize::Zeroizing;

use super::{Store, next_rev, parse_id, parse_opt_id};
use crate::crypto::{LEGACY_AAD_PREFIX, MasterKey};
use crate::error::{CoreError, Result, codes};
use crate::model::{
    AuditEntry, EntityKind, Vault, VaultCrypto, VaultKind, VaultMember, VaultPrincipal, VaultRole,
    VaultSettings,
};
use crate::time::now_ms;
use crate::{Id, new_id};

// ---------------------------------------------------------------------------
// Access
// ---------------------------------------------------------------------------

/// What a user can reach: their effective role in every vault they can use.
/// Cheap to share (`Arc`); cached per user by the store and invalidated by
/// every change to vaults, members, teams or team members.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VaultAccess {
    pub user: Id,
    /// Effective role per vault (only roles that give access).
    pub roles: BTreeMap<Id, VaultRole>,
    /// Vaults in Strict mode (`settings.use_only_local = false`).
    pub strict: BTreeSet<Id>,
    /// Team policies (0.7 phase 4b, docs-next/TEAMS-SECURITY.md §6), per
    /// vault where they restrict this user:
    /// Editors who may not reveal, export or receive secrets.
    pub no_reveal: BTreeSet<Id>,
    /// The server AI may not use the vault's hosts.
    pub no_ai: BTreeSet<Id>,
    /// Every AI action on the vault's hosts needs an approval.
    pub ai_confirm: BTreeSet<Id>,
    /// Hosts of the vault may not use private networks.
    pub no_networks: BTreeSet<Id>,
    /// Sessions on the vault's hosts are always recorded.
    pub record: BTreeSet<Id>,
    /// Team owning each team vault of `roles`.
    pub team_of: BTreeMap<Id, Id>,
    /// Team vaults hidden because the team requires 2FA and the grace
    /// period is over (they are not in `roles`).
    pub blocked_2fa: BTreeSet<Id>,
    /// This access changes by itself at this time (a 2FA grace period
    /// ends): cached copies expire then.
    pub valid_until: Option<i64>,
}

/// Why a secret is opened. Every path that decrypts a secret for a user goes
/// through [`VaultAccess::authorize_secret`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretUse {
    /// Shown or sent to the user (reveal, sync, export): Editor.
    Reveal,
    /// Used by the server itself (server sessions, SFTP, exec, AI): any
    /// role; the secret never leaves the server.
    Server,
    /// Just-in-time credentials for a connection from the user's device:
    /// Editor, or Use-only when the vault is not Strict.
    Credentials,
}

impl VaultAccess {
    /// Full (manager) access to `vaults`: tests, and a client's own data.
    pub fn owner_of(user: Id, vaults: impl IntoIterator<Item = Id>) -> Self {
        Self {
            user,
            roles: vaults
                .into_iter()
                .map(|v| (v, VaultRole::Manager))
                .collect(),
            ..Default::default()
        }
    }

    /// The personal vault (same id as the user).
    pub fn personal(&self) -> Id {
        self.user
    }

    /// Effective role in a vault (`None`: no access).
    pub fn role(&self, vault: Id) -> Option<VaultRole> {
        self.roles.get(&vault).copied().filter(|r| r.can_use())
    }

    pub fn vault_ids(&self) -> Vec<Id> {
        self.roles
            .iter()
            .filter(|(_, r)| r.can_use())
            .map(|(v, _)| *v)
            .collect()
    }

    pub fn is_strict(&self, vault: Id) -> bool {
        self.strict.contains(&vault)
    }

    /// May see, export and receive the secrets of `vault` (role and team
    /// policy).
    pub fn can_reveal(&self, vault: Id) -> bool {
        self.role(vault).is_some_and(VaultRole::can_read_secrets)
            && !self.no_reveal.contains(&vault)
    }

    /// The team policy lets the server AI use the vault's hosts.
    pub fn ai_allowed(&self, vault: Id) -> bool {
        !self.no_ai.contains(&vault)
    }

    /// Sessions on the vault's hosts must be recorded (team policy).
    pub fn must_record(&self, vault: Id) -> bool {
        self.record.contains(&vault)
    }

    /// The team policy lets the vault's hosts use private networks.
    pub fn networks_allowed(&self, vault: Id) -> bool {
        !self.no_networks.contains(&vault)
    }

    /// Requires at least `min` in `vault`: `vault_not_found` without access,
    /// `vault_read_only` (Use-only asked to write) or `vault_manager_only`.
    pub fn require(&self, vault: Id, min: VaultRole) -> Result<VaultRole> {
        let Some(role) = self.role(vault) else {
            return Err(CoreError::vault(
                codes::VAULT_NOT_FOUND,
                format!("vault {vault} not found"),
            ));
        };
        if role >= min {
            return Ok(role);
        }
        if min == VaultRole::Manager {
            Err(CoreError::vault(
                codes::VAULT_MANAGER_ONLY,
                "only the vault managers can do this",
            ))
        } else {
            Err(CoreError::vault(
                codes::VAULT_READ_ONLY,
                "you can use the items of this vault but not change them",
            ))
        }
    }

    /// The single check before a secret of `vault` is decrypted for this
    /// user.
    pub fn authorize_secret(&self, vault: Id, purpose: SecretUse) -> Result<()> {
        let Some(role) = self.role(vault) else {
            return Err(CoreError::NotFound("item not found".into()));
        };
        match purpose {
            SecretUse::Server => Ok(()),
            SecretUse::Reveal if role.can_read_secrets() && !self.no_reveal.contains(&vault) => {
                Ok(())
            }
            SecretUse::Reveal if role.can_read_secrets() => Err(CoreError::vault(
                codes::SECRET_REVEAL_FORBIDDEN,
                "the team does not allow revealing or exporting the secrets of this vault",
            )),
            SecretUse::Reveal => Err(CoreError::vault(
                codes::SECRET_HIDDEN,
                "Use-only members cannot see the secrets of this vault",
            )),
            SecretUse::Credentials if role.can_read_secrets() => Ok(()),
            SecretUse::Credentials if !role.can_get_credentials() => Err(CoreError::vault(
                codes::CONNECT_ONLY,
                "Connect only members connect through the server or with team certificates",
            )),
            SecretUse::Credentials if !self.is_strict(vault) => Ok(()),
            SecretUse::Credentials => Err(CoreError::vault(
                codes::USE_ONLY_STRICT,
                "this vault only allows connections through the server",
            )),
        }
    }
}

/// Cache of [`VaultAccess`] per user with a generation counter.
#[derive(Default)]
pub(crate) struct AccessCache {
    generation: AtomicU64,
    map: Mutex<HashMap<Id, Arc<VaultAccess>>>,
}

// ---------------------------------------------------------------------------
// Vault keys
// ---------------------------------------------------------------------------

/// Unwrapped vault keys kept in memory (wiped on drop).
const VK_CACHE_SIZE: usize = 512;
/// Algorithm of the `server` wraps.
const WRAP_ALG: &str = "master-xchacha20poly1305-v1";

#[derive(Default)]
struct VkCache {
    map: HashMap<(Id, u32), (MasterKey, u64)>,
    tick: u64,
}

/// Store master key plus the vault keys.
pub(crate) struct Keyring {
    pub(crate) master: MasterKey,
    /// Seal new secrets with vault keys (server). Clients keep the device
    /// key (legacy format).
    enabled: AtomicBool,
    cache: Mutex<VkCache>,
}

pub(crate) fn legacy_aad(kind: EntityKind, id: Id) -> Vec<u8> {
    format!("{LEGACY_AAD_PREFIX}:{}:{id}", kind.as_str()).into_bytes()
}

fn vault_aad(vault: Id, version: u32, kind: EntityKind, id: Id) -> Vec<u8> {
    format!("termoak:vault:{vault}:{version}:{}:{id}", kind.as_str()).into_bytes()
}

fn wrap_aad(vault: Id, version: u32) -> Vec<u8> {
    format!("termoak:vk:{vault}:{version}").into_bytes()
}

impl Keyring {
    pub(crate) fn new(master: MasterKey) -> Self {
        Self {
            master,
            enabled: AtomicBool::new(false),
            cache: Mutex::new(VkCache::default()),
        }
    }

    fn cached(&self, vault: Id, version: u32) -> Option<MasterKey> {
        let mut c = self.cache.lock();
        c.tick += 1;
        let tick = c.tick;
        c.map.get_mut(&(vault, version)).map(|(k, used)| {
            *used = tick;
            k.clone()
        })
    }

    fn remember(&self, vault: Id, version: u32, key: MasterKey) {
        let mut c = self.cache.lock();
        c.tick += 1;
        let tick = c.tick;
        if c.map.len() >= VK_CACHE_SIZE
            && let Some(oldest) = c.map.iter().min_by_key(|(_, (_, t))| *t).map(|(k, _)| *k)
        {
            c.map.remove(&oldest);
        }
        c.map.insert((vault, version), (key, tick));
    }

    pub(crate) fn forget_vault(&self, vault: Id) {
        self.cache.lock().map.retain(|(v, _), _| *v != vault);
    }

    /// A vault key version (unwrapped with the master key, then cached).
    fn vk(&self, conn: &Connection, vault: Id, version: u32) -> Result<MasterKey> {
        if let Some(k) = self.cached(vault, version) {
            return Ok(k);
        }
        let wrapped: Vec<u8> = conn
            .query_row(
                "SELECT wrapped FROM vault_key_wraps
                 WHERE vault_id = ?1 AND version = ?2 AND recipient = 'server'",
                params![vault.to_string(), version],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(|| CoreError::Crypto(format!("missing key {version} of vault {vault}")))?;
        let raw = self.master.open(&wrapped, &wrap_aad(vault, version))?;
        let bytes: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::Crypto("invalid vault key".into()))?;
        let key = MasterKey::from_bytes(bytes);
        self.remember(vault, version, key.clone());
        Ok(key)
    }

    /// Current key of a server-managed vault, created if it has none yet.
    /// `None` when vault keys are off (clients) or the vault does not exist
    /// here. Runs inside the caller's transaction; a key it creates is not
    /// cached until it is read back (a rollback leaves nothing behind).
    fn current_vk(&self, conn: &Connection, vault: Id) -> Result<Option<(u32, MasterKey)>> {
        if !self.enabled.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let row: Option<(u32, String)> = conn
            .query_row(
                "SELECT key_version, crypto_mode FROM vaults WHERE id = ?1",
                [vault.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((version, mode)) = row else {
            return Ok(None);
        };
        if VaultCrypto::parse(&mode) != VaultCrypto::Server {
            return Ok(None);
        }
        if version > 0 {
            return Ok(Some((version, self.vk(conn, vault, version)?)));
        }
        let key = MasterKey::generate();
        let version = 1u32;
        let now = now_ms();
        let wrapped = self
            .master
            .seal(key.as_bytes(), &wrap_aad(vault, version))?;
        conn.execute(
            "INSERT INTO vault_keys (vault_id, version, created_at) VALUES (?1, ?2, ?3)",
            params![vault.to_string(), version, now],
        )?;
        conn.execute(
            "INSERT INTO vault_key_wraps (vault_id, version, recipient, alg, wrapped, created_at)
             VALUES (?1, ?2, 'server', ?3, ?4, ?5)",
            params![vault.to_string(), version, WRAP_ALG, wrapped, now],
        )?;
        conn.execute(
            "UPDATE vaults SET key_version = ?2 WHERE id = ?1",
            params![vault.to_string(), version],
        )?;
        Ok(Some((version, key)))
    }

    /// Seals a secret for an entity of `vault`: with the vault key when
    /// enabled, otherwise with the master key (legacy format). Returns the
    /// blob and its key version (`None`: legacy).
    pub(crate) fn seal(
        &self,
        conn: &Connection,
        vault: Option<Id>,
        kind: EntityKind,
        id: Id,
        plain: &[u8],
    ) -> Result<(Vec<u8>, Option<u32>)> {
        if let Some(v) = vault
            && let Some((version, key)) = self.current_vk(conn, v)?
        {
            return Ok((
                key.seal(plain, &vault_aad(v, version, kind, id))?,
                Some(version),
            ));
        }
        Ok((self.master.seal(plain, &legacy_aad(kind, id))?, None))
    }

    /// Opens a stored secret blob.
    pub(crate) fn open(
        &self,
        conn: &Connection,
        vault: Option<Id>,
        key_version: Option<u32>,
        kind: EntityKind,
        id: Id,
        blob: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        match (vault, key_version) {
            (Some(v), Some(version)) => {
                let key = self.vk(conn, v, version)?;
                key.open(blob, &vault_aad(v, version, kind, id))
            }
            (None, Some(_)) => Err(CoreError::Crypto(format!(
                "secret of {id} sealed with a vault key but without a vault"
            ))),
            (_, None) => self.master.open(blob, &legacy_aad(kind, id)),
        }
    }

    /// Reseals a blob for another vault (moves, legacy migration).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reseal(
        &self,
        conn: &Connection,
        from: (Option<Id>, Option<u32>),
        to: Option<Id>,
        kind: EntityKind,
        old_id: Id,
        new_id: Id,
        blob: &[u8],
    ) -> Result<(Vec<u8>, Option<u32>)> {
        let plain = self.open(conn, from.0, from.1, kind, old_id, blob)?;
        self.seal(conn, to, kind, new_id, &plain)
    }
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// New vault.
#[derive(Debug, Clone, Default)]
pub struct NewVault {
    pub name: String,
    pub description: String,
    pub color: Option<String>,
    pub icon: Option<String>,
    /// Owned by this team (the creator must be a team owner or admin).
    pub team_id: Option<Id>,
    /// Team vaults: role of plain team members (default `editor`).
    pub team_member_role: Option<VaultRole>,
    pub settings: Option<VaultSettings>,
}

/// Changes to a vault (`None`: unchanged).
#[derive(Debug, Clone, Default)]
pub struct VaultPatch {
    pub name: Option<String>,
    pub description: Option<String>,
    /// `Some(None)` removes it.
    pub color: Option<Option<String>>,
    pub icon: Option<Option<String>>,
    /// Team vaults; `Some(None)`: plain team members get no access.
    pub team_member_role: Option<Option<VaultRole>>,
    pub settings: Option<VaultSettings>,
}

/// Who gets a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultGrantee {
    User(Id),
    Team(Id),
}

pub use crate::transfer::{
    TransferRequest as VaultTransfer, TransferResult as VaultTransferResult,
};

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

const VAULT_COLUMNS: &str = "v.id, v.kind, v.name, v.description, v.color, v.icon, v.owner_user_id, \
     v.owner_team_id, v.team_member_role, v.crypto_mode, v.key_version, v.settings, v.rev, \
     v.created_by, v.created_at, v.updated_at, \
     COALESCE((SELECT name FROM users WHERE id = v.owner_user_id), \
              (SELECT name FROM teams WHERE id = v.owner_team_id)), \
     (SELECT COUNT(*) FROM vault_members m WHERE m.vault_id = v.id)";

fn map_vault(r: &rusqlite::Row<'_>) -> rusqlite::Result<Vault> {
    let settings: String = r.get(11)?;
    Ok(Vault {
        id: parse_id(&r.get::<_, String>(0)?)?,
        kind: VaultKind::parse(&r.get::<_, String>(1)?),
        name: r.get(2)?,
        description: r.get(3)?,
        color: r.get(4)?,
        icon: r.get(5)?,
        owner_user_id: parse_opt_id(r.get(6)?)?,
        owner_team_id: parse_opt_id(r.get(7)?)?,
        team_member_role: r
            .get::<_, Option<String>>(8)?
            .map(|s| VaultRole::parse(&s))
            .filter(|r| r.can_use()),
        crypto: VaultCrypto::parse(&r.get::<_, String>(9)?),
        key_version: r.get(10)?,
        settings: serde_json::from_str(&settings).unwrap_or_default(),
        rev: r.get(12)?,
        created_by: parse_id(&r.get::<_, String>(13)?)?,
        created_at: r.get(14)?,
        updated_at: r.get(15)?,
        role: None,
        owner_name: r.get(16)?,
        member_count: r.get(17)?,
        item_counts: BTreeMap::new(),
        policy: None,
    })
}

fn load_vault(conn: &Connection, id: Id) -> Result<Option<Vault>> {
    Ok(conn
        .query_row(
            &format!("SELECT {VAULT_COLUMNS} FROM vaults v WHERE v.id = ?1"),
            [id.to_string()],
            map_vault,
        )
        .optional()?)
}

fn vault_not_found(id: Id) -> CoreError {
    CoreError::vault(codes::VAULT_NOT_FOUND, format!("vault {id} not found"))
}

fn check_text(field: &str, value: &str, max: usize, required: bool) -> Result<String> {
    let v = value.trim();
    if (required && v.is_empty()) || v.chars().count() > max {
        return Err(CoreError::Invalid(format!(
            "the vault {field} must be {} {max} characters",
            if required { "between 1 and" } else { "at most" }
        )));
    }
    Ok(v.to_string())
}

fn check_opt(field: &str, value: Option<String>, max: usize) -> Result<Option<String>> {
    match value {
        None => Ok(None),
        Some(v) if v.trim().is_empty() => Ok(None),
        Some(v) => Ok(Some(check_text(field, &v, max, false)?)),
    }
}

/// Grantable roles: `connect_only`, `use_only`, `editor` and (0.7 phase
/// 4b) `manager` ("Admin"). The role of plain team members of a team
/// vault cannot be `manager` (team admins already are).
fn check_grant_role(role: VaultRole) -> Result<()> {
    match role {
        VaultRole::Manager | VaultRole::Editor | VaultRole::UseOnly | VaultRole::ConnectOnly => {
            Ok(())
        }
        _ => Err(CoreError::vault(
            codes::INVALID_ROLE,
            "the role must be connect_only, use_only, editor or manager",
        )),
    }
}

fn check_team_member_role(role: VaultRole) -> Result<()> {
    match role {
        VaultRole::Editor | VaultRole::UseOnly | VaultRole::ConnectOnly => Ok(()),
        _ => Err(CoreError::vault(
            codes::INVALID_ROLE,
            "the role of team members must be connect_only, use_only or editor",
        )),
    }
}

/// Effective roles of `user` (all vaults, or only `vault`), maximum by rank.
fn compute_access(conn: &Connection, user: Id, only: Option<Id>) -> Result<VaultAccess> {
    let mut stmt = conn.prepare_cached(
        "SELECT v.id, 'manager', v.settings FROM vaults v
             WHERE v.owner_user_id = ?1 AND (?2 IS NULL OR v.id = ?2)
         UNION ALL
         SELECT v.id, CASE WHEN tm.role IN ('owner', 'admin') THEN 'manager'
                           ELSE v.team_member_role END, v.settings
             FROM vaults v JOIN team_members tm ON tm.team_id = v.owner_team_id
             WHERE tm.user_id = ?1 AND (?2 IS NULL OR v.id = ?2)
         UNION ALL
         SELECT v.id, vm.role, v.settings
             FROM vault_members vm JOIN vaults v ON v.id = vm.vault_id
             WHERE vm.user_id = ?1 AND (?2 IS NULL OR v.id = ?2)
         UNION ALL
         SELECT v.id, vm.role, v.settings
             FROM vault_members vm
             JOIN team_members tm ON tm.team_id = vm.team_id
             JOIN vaults v ON v.id = vm.vault_id
             WHERE tm.user_id = ?1 AND (?2 IS NULL OR v.id = ?2)",
    )?;
    let rows = stmt
        .query_map(
            params![user.to_string(), only.map(|v| v.to_string())],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut access = VaultAccess {
        user,
        ..Default::default()
    };
    for (vault, role, settings) in rows {
        let Some(role) = role.map(|r| VaultRole::parse(&r)).filter(|r| r.can_use()) else {
            continue;
        };
        let vault = parse_id(&vault)?;
        let best = access.roles.entry(vault).or_insert(role);
        if role > *best {
            *best = role;
        }
        let settings: VaultSettings = serde_json::from_str(&settings).unwrap_or_default();
        if !settings.use_only_local {
            access.strict.insert(vault);
        }
    }
    apply_team_policies(conn, &mut access, now_ms())?;
    Ok(access)
}

/// Applies the policies of the teams that own vaults of `access` (0.7
/// phase 4b): 2FA (hides team vaults after the grace period), reveal, AI,
/// networks and recording. Server data only (clients have no teams).
fn apply_team_policies(conn: &Connection, access: &mut VaultAccess, now: i64) -> Result<()> {
    if access.roles.is_empty() {
        return Ok(());
    }
    let user = access.user.to_string();
    let rows = {
        let mut stmt = conn.prepare_cached(
            "SELECT v.id, t.id, t.policy,
                    (SELECT added_at FROM team_members WHERE team_id = t.id AND user_id = ?1)
             FROM vaults v JOIN teams t ON t.id = v.owner_team_id
             WHERE v.owner_team_id IN (SELECT team_id FROM team_members WHERE user_id = ?1)
                OR v.id IN (SELECT vault_id FROM vault_members WHERE user_id = ?1
                            OR team_id IN (SELECT team_id FROM team_members WHERE user_id = ?1))",
        )?;
        stmt.query_map([&user], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<i64>>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?
    };
    if rows.is_empty() {
        return Ok(());
    }
    let totp: bool = conn
        .query_row(
            "SELECT totp_enabled FROM users WHERE id = ?1",
            [&user],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        .is_some_and(|v| v != 0);
    for (vault, team, policy, joined) in rows {
        let vault = parse_id(&vault)?;
        let Some(role) = access.roles.get(&vault).copied() else {
            continue;
        };
        access.team_of.insert(vault, parse_id(&team)?);
        let policy: crate::access::TeamPolicy = serde_json::from_str(&policy).unwrap_or_default();
        if !totp && let Some(deadline) = policy.twofa_deadline(joined.unwrap_or(0)) {
            if now >= deadline {
                access.roles.remove(&vault);
                access.strict.remove(&vault);
                access.blocked_2fa.insert(vault);
                continue;
            }
            access.valid_until = Some(access.valid_until.map_or(deadline, |v| v.min(deadline)));
        }
        if !policy.allow_reveal && role == VaultRole::Editor {
            access.no_reveal.insert(vault);
        }
        if !policy.ai.allowed {
            access.no_ai.insert(vault);
        }
        if policy.ai.approval.always() {
            access.ai_confirm.insert(vault);
        }
        if !policy.networks_allowed {
            access.no_networks.insert(vault);
        }
        if policy.record_sessions {
            access.record.insert(vault);
        }
    }
    Ok(())
}

/// Deletes a vault with its entities, departures, keys and grants (inside
/// the caller's transaction).
pub(crate) fn delete_vault_tx(conn: &Connection, vault: &str) -> Result<()> {
    conn.execute("DELETE FROM entities WHERE vault_id = ?1", [vault])?;
    conn.execute("DELETE FROM entity_departures WHERE vault_id = ?1", [vault])?;
    conn.execute("DELETE FROM vault_key_wraps WHERE vault_id = ?1", [vault])?;
    conn.execute("DELETE FROM vault_keys WHERE vault_id = ?1", [vault])?;
    conn.execute("DELETE FROM vault_members WHERE vault_id = ?1", [vault])?;
    conn.execute("DELETE FROM vaults WHERE id = ?1", [vault])?;
    Ok(())
}

/// Ids of the vaults a user owns directly (personal and shared).
pub(crate) fn user_vault_ids(conn: &Connection, user: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT id FROM vaults WHERE owner_user_id = ?1")?;
    Ok(stmt
        .query_map([user], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Ids of the vaults a team owns.
pub(crate) fn team_vault_ids(conn: &Connection, team: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT id FROM vaults WHERE owner_team_id = ?1")?;
    Ok(stmt
        .query_map([team], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Inserts the personal vault of a user (no-op if it exists).
pub(crate) fn insert_personal_vault(conn: &Connection, user: Id, at: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO vaults (id, kind, name, owner_user_id, created_by, created_at, updated_at)
         VALUES (?1, 'personal', 'Personal', ?1, ?1, ?2, ?2)
         ON CONFLICT(id) DO NOTHING",
        params![user.to_string(), at],
    )?;
    Ok(())
}

fn item_counts(conn: &Connection, vault: Id) -> Result<BTreeMap<String, i64>> {
    let mut stmt = conn.prepare_cached(
        "SELECT kind, COUNT(*) FROM entities WHERE vault_id = ?1 AND deleted = 0 GROUP BY kind",
    )?;
    Ok(stmt
        .query_map([vault.to_string()], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<BTreeMap<String, i64>>>()?)
}

fn map_member(r: &rusqlite::Row<'_>) -> rusqlite::Result<VaultMember> {
    let user_id: Option<String> = r.get(1)?;
    let principal = match user_id {
        Some(uid) => VaultPrincipal::User {
            id: parse_id(&uid)?,
            email: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
            name: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
        },
        None => VaultPrincipal::Team {
            id: parse_id(&r.get::<_, String>(2)?)?,
            name: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
        },
    };
    Ok(VaultMember {
        id: parse_id(&r.get::<_, String>(0)?)?,
        principal,
        role: VaultRole::parse(&r.get::<_, String>(6)?),
        added_by: parse_id(&r.get::<_, String>(7)?)?,
        added_at: r.get(8)?,
        implicit: false,
    })
}

const MEMBER_SELECT: &str = "SELECT m.id, m.user_id, m.team_id, u.email, u.name, t.name, m.role, \
     m.added_by, m.added_at
     FROM vault_members m
     LEFT JOIN users u ON u.id = m.user_id
     LEFT JOIN teams t ON t.id = m.team_id";

fn load_member(conn: &Connection, vault: Id, member: Id) -> Result<VaultMember> {
    conn.query_row(
        &format!("{MEMBER_SELECT} WHERE m.vault_id = ?1 AND m.id = ?2"),
        params![vault.to_string(), member.to_string()],
        map_member,
    )
    .optional()?
    .ok_or_else(|| CoreError::NotFound(format!("vault member {member}")))
}

fn bump_vault(conn: &Connection, vault: Id) -> Result<i64> {
    let rev = next_rev(conn)?;
    conn.execute(
        "UPDATE vaults SET rev = ?2, updated_at = ?3 WHERE id = ?1",
        params![vault.to_string(), rev, now_ms()],
    )?;
    Ok(rev)
}

// ---------------------------------------------------------------------------
// Store API
// ---------------------------------------------------------------------------

impl Store {
    /// Seals new secrets with per-vault keys (server). Off by default:
    /// clients keep their device key and the legacy format.
    pub fn enable_vault_keys(&self) {
        self.inner.keys.enabled.store(true, Ordering::Relaxed);
    }

    pub fn vault_keys_enabled(&self) -> bool {
        self.inner.keys.enabled.load(Ordering::Relaxed)
    }

    /// Forgets every cached [`VaultAccess`] (after a change to vaults,
    /// members, teams or team members).
    pub fn bump_access(&self) {
        let cache = &self.inner.access;
        cache.generation.fetch_add(1, Ordering::SeqCst);
        cache.map.lock().clear();
    }

    /// What `user` can reach (cached).
    pub async fn vault_access(&self, user: Id) -> Result<Arc<VaultAccess>> {
        let cache = &self.inner.access;
        let generation = cache.generation.load(Ordering::SeqCst);
        if let Some(a) = cache.map.lock().get(&user)
            && a.valid_until.is_none_or(|t| now_ms() < t)
        {
            return Ok(a.clone());
        }
        let access = Arc::new(self.call(move |c, _| compute_access(c, user, None)).await?);
        if cache.generation.load(Ordering::SeqCst) == generation {
            cache.map.lock().insert(user, access.clone());
        }
        Ok(access)
    }

    /// Vaults `user` can access, with their effective role (not cached).
    pub async fn accessible_vaults(&self, user: Id) -> Result<Vec<(Id, VaultRole)>> {
        self.call(move |c, _| Ok(compute_access(c, user, None)?.roles.into_iter().collect()))
            .await
    }

    /// Effective role of `user` in `vault` (not cached).
    pub async fn effective_role(&self, vault: Id, user: Id) -> Result<Option<VaultRole>> {
        self.call(move |c, _| Ok(compute_access(c, user, Some(vault))?.role(vault)))
            .await
    }

    /// Creates the personal vault of a user if it is missing.
    pub async fn ensure_personal_vault(&self, user: Id) -> Result<()> {
        let created = self
            .call(move |c, _| {
                let exists: Option<i64> = c
                    .query_row(
                        "SELECT 1 FROM vaults WHERE id = ?1",
                        [user.to_string()],
                        |r| r.get(0),
                    )
                    .optional()?;
                if exists.is_some() {
                    return Ok(false);
                }
                insert_personal_vault(c, user, now_ms())?;
                Ok(true)
            })
            .await?;
        if created {
            self.bump_access();
        }
        Ok(())
    }

    /// Creates a `shared` vault (owned by `creator`) or a `team` vault
    /// (`team_id`; the creator must be a team owner or admin).
    pub async fn create_vault(&self, creator: Id, req: NewVault) -> Result<Vault> {
        let name = check_text("name", &req.name, 80, true)?;
        let description = check_text("description", &req.description, 500, false)?;
        let color = check_opt("color", req.color, 32)?;
        let icon = check_opt("icon", req.icon, 64)?;
        let settings = serde_json::to_string(&req.settings.unwrap_or_default())?;
        let team_role = match (req.team_id, req.team_member_role) {
            (Some(_), None) => Some(VaultRole::Editor),
            (Some(_), Some(r)) => {
                check_team_member_role(r)?;
                Some(r)
            }
            (None, Some(_)) => {
                return Err(CoreError::Invalid(
                    "team_member_role is only for team vaults".into(),
                ));
            }
            (None, None) => None,
        };
        let id = self
            .call(move |c, _| {
                let tx = c.transaction()?;
                if let Some(team) = req.team_id {
                    let role: Option<String> = tx
                        .query_row(
                            "SELECT role FROM team_members WHERE team_id = ?1 AND user_id = ?2",
                            params![team.to_string(), creator.to_string()],
                            |r| r.get(0),
                        )
                        .optional()?;
                    match role.as_deref() {
                        Some("owner") | Some("admin") => {}
                        Some(_) => {
                            return Err(CoreError::Forbidden(
                                "only the team owners and admins can create team vaults".into(),
                            ));
                        }
                        None => return Err(CoreError::NotFound(format!("team {team}"))),
                    }
                }
                let id = new_id();
                let now = now_ms();
                let rev = next_rev(&tx)?;
                tx.execute(
                    "INSERT INTO vaults (id, kind, name, description, color, icon, owner_user_id,
                                         owner_team_id, team_member_role, settings, rev,
                                         created_by, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?13)",
                    params![
                        id.to_string(),
                        if req.team_id.is_some() {
                            "team"
                        } else {
                            "shared"
                        },
                        name,
                        description,
                        color,
                        icon,
                        req.team_id.is_none().then(|| creator.to_string()),
                        req.team_id.map(|t| t.to_string()),
                        team_role.map(|r| r.as_str()),
                        settings,
                        rev,
                        creator.to_string(),
                        now
                    ],
                )?;
                tx.commit()?;
                Ok(id)
            })
            .await?;
        self.bump_access();
        self.vault_for(id, creator).await
    }

    /// A vault, without the caller's role.
    pub async fn vault(&self, id: Id) -> Result<Vault> {
        self.call(move |c, _| load_vault(c, id)?.ok_or_else(|| vault_not_found(id)))
            .await
    }

    /// A vault as `user` sees it (with their role and item counts);
    /// `vault_not_found` without access.
    pub async fn vault_for(&self, id: Id, user: Id) -> Result<Vault> {
        let access = self.vault_access(user).await?;
        let role = access.role(id).ok_or_else(|| vault_not_found(id))?;
        self.call(move |c, _| {
            let mut v = load_vault(c, id)?.ok_or_else(|| vault_not_found(id))?;
            v.role = Some(role);
            v.item_counts = item_counts(c, id)?;
            Ok(v)
        })
        .await
    }

    /// Every vault `user` can access: personal first, then by name.
    pub async fn vaults_for(&self, user: Id) -> Result<Vec<Vault>> {
        let access = self.vault_access(user).await?;
        self.call(move |c, _| {
            let mut out = Vec::new();
            for (id, role) in &access.roles {
                if let Some(mut v) = load_vault(c, *id)? {
                    v.role = Some(*role);
                    v.item_counts = item_counts(c, *id)?;
                    out.push(v);
                }
            }
            out.sort_by(|a, b| {
                (a.kind != VaultKind::Personal, a.name.to_lowercase())
                    .cmp(&(b.kind != VaultKind::Personal, b.name.to_lowercase()))
            });
            Ok(out)
        })
        .await
    }

    /// Vaults owned by a team.
    pub async fn team_vaults(&self, team: Id) -> Result<Vec<Vault>> {
        self.call(move |c, _| {
            let mut out = Vec::new();
            for id in team_vault_ids(c, &team.to_string())? {
                if let Some(mut v) = load_vault(c, parse_id(&id)?)? {
                    v.item_counts = item_counts(c, v.id)?;
                    out.push(v);
                }
            }
            Ok(out)
        })
        .await
    }

    /// Shared vaults owned by `user` that have members (they are deleted
    /// with the account: the API asks first).
    pub async fn shared_vaults_with_members(&self, user: Id) -> Result<Vec<Vault>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(&format!(
                "SELECT {VAULT_COLUMNS} FROM vaults v
                 WHERE v.owner_user_id = ?1 AND v.kind = 'shared'
                   AND EXISTS (SELECT 1 FROM vault_members m WHERE m.vault_id = v.id)
                 ORDER BY v.name COLLATE NOCASE"
            ))?;
            Ok(stmt
                .query_map([user.to_string()], map_vault)?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// Changes a vault's metadata. Personal vaults: only name, color, icon.
    pub async fn update_vault(&self, id: Id, patch: VaultPatch) -> Result<Vault> {
        let name = patch
            .name
            .as_deref()
            .map(|n| check_text("name", n, 80, true))
            .transpose()?;
        let description = patch
            .description
            .as_deref()
            .map(|d| check_text("description", d, 500, false))
            .transpose()?;
        let color = patch.color.map(|c| check_opt("color", c, 32)).transpose()?;
        let icon = patch.icon.map(|i| check_opt("icon", i, 64)).transpose()?;
        if let Some(Some(r)) = patch.team_member_role {
            check_team_member_role(r)?;
        }
        let settings = patch
            .settings
            .map(|s| serde_json::to_string(&s))
            .transpose()?;
        self.call(move |c, _| {
            let tx = c.transaction()?;
            let v = load_vault(&tx, id)?.ok_or_else(|| vault_not_found(id))?;
            if v.kind == VaultKind::Personal
                && (description.is_some() || patch.team_member_role.is_some() || settings.is_some())
            {
                return Err(CoreError::vault(
                    codes::VAULT_PERSONAL,
                    "only the name, color and icon of the personal vault can change",
                ));
            }
            if patch.team_member_role.is_some() && v.kind != VaultKind::Team {
                return Err(CoreError::Invalid(
                    "team_member_role is only for team vaults".into(),
                ));
            }
            let sid = id.to_string();
            if let Some(n) = name {
                tx.execute("UPDATE vaults SET name = ?2 WHERE id = ?1", params![sid, n])?;
            }
            if let Some(d) = description {
                tx.execute(
                    "UPDATE vaults SET description = ?2 WHERE id = ?1",
                    params![sid, d],
                )?;
            }
            if let Some(col) = color {
                tx.execute(
                    "UPDATE vaults SET color = ?2 WHERE id = ?1",
                    params![sid, col],
                )?;
            }
            if let Some(i) = icon {
                tx.execute("UPDATE vaults SET icon = ?2 WHERE id = ?1", params![sid, i])?;
            }
            if let Some(r) = patch.team_member_role {
                tx.execute(
                    "UPDATE vaults SET team_member_role = ?2 WHERE id = ?1",
                    params![sid, r.map(|r| r.as_str())],
                )?;
            }
            if let Some(s) = settings {
                tx.execute(
                    "UPDATE vaults SET settings = ?2 WHERE id = ?1",
                    params![sid, s],
                )?;
            }
            bump_vault(&tx, id)?;
            tx.commit()?;
            Ok(())
        })
        .await?;
        self.bump_access();
        self.vault(id).await
    }

    /// Deletes a vault with its entities and keys (its secrets are
    /// crypto-shredded). The personal vault cannot be deleted.
    pub async fn delete_vault(&self, id: Id) -> Result<()> {
        self.call(move |c, _| {
            let tx = c.transaction()?;
            let v = load_vault(&tx, id)?.ok_or_else(|| vault_not_found(id))?;
            if v.kind == VaultKind::Personal {
                return Err(CoreError::vault(
                    codes::VAULT_PERSONAL,
                    "the personal vault cannot be deleted",
                ));
            }
            delete_vault_tx(&tx, &id.to_string())?;
            tx.commit()?;
            Ok(())
        })
        .await?;
        self.inner.keys.forget_vault(id);
        self.bump_access();
        Ok(())
    }

    /// Members of a vault: the implicit ones first (owner or team
    /// owners/admins as managers, and the owning team with its member role),
    /// then the grants.
    pub async fn vault_members(&self, id: Id) -> Result<Vec<VaultMember>> {
        self.call(move |c, _| {
            let v = load_vault(c, id)?.ok_or_else(|| vault_not_found(id))?;
            let mut out = Vec::new();
            if let Some(owner) = v.owner_user_id {
                let row: Option<(String, String)> = c
                    .query_row(
                        "SELECT email, name FROM users WHERE id = ?1",
                        [owner.to_string()],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                let (email, name) = row.unwrap_or_default();
                out.push(VaultMember {
                    id: owner,
                    principal: VaultPrincipal::User {
                        id: owner,
                        email,
                        name,
                    },
                    role: VaultRole::Manager,
                    added_by: v.created_by,
                    added_at: v.created_at,
                    implicit: true,
                });
            }
            if let Some(team) = v.owner_team_id {
                let mut stmt = c.prepare(
                    "SELECT u.id, u.email, u.name, m.added_at FROM team_members m
                     JOIN users u ON u.id = m.user_id
                     WHERE m.team_id = ?1 AND m.role IN ('owner', 'admin')
                     ORDER BY u.name COLLATE NOCASE",
                )?;
                let admins = stmt
                    .query_map([team.to_string()], |r| {
                        let uid = parse_id(&r.get::<_, String>(0)?)?;
                        Ok(VaultMember {
                            id: uid,
                            principal: VaultPrincipal::User {
                                id: uid,
                                email: r.get(1)?,
                                name: r.get(2)?,
                            },
                            role: VaultRole::Manager,
                            added_by: v.created_by,
                            added_at: r.get(3)?,
                            implicit: true,
                        })
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                out.extend(admins);
                if let Some(role) = v.team_member_role {
                    out.push(VaultMember {
                        id: team,
                        principal: VaultPrincipal::Team {
                            id: team,
                            name: v.owner_name.clone().unwrap_or_default(),
                        },
                        role,
                        added_by: v.created_by,
                        added_at: v.created_at,
                        implicit: true,
                    });
                }
            }
            let mut stmt = c.prepare(&format!(
                "{MEMBER_SELECT} WHERE m.vault_id = ?1 ORDER BY m.added_at"
            ))?;
            out.extend(
                stmt.query_map([id.to_string()], map_member)?
                    .collect::<rusqlite::Result<Vec<_>>>()?,
            );
            Ok(out)
        })
        .await
    }

    /// One grant of a vault.
    pub async fn vault_member(&self, vault: Id, member: Id) -> Result<VaultMember> {
        self.call(move |c, _| load_member(c, vault, member)).await
    }

    /// Grants `role` (`editor` or `use_only`) to a user or a team. Sharing
    /// with a team requires `by` to be a member of it.
    pub async fn add_vault_member(
        &self,
        vault: Id,
        by: Id,
        grantee: VaultGrantee,
        role: VaultRole,
    ) -> Result<VaultMember> {
        check_grant_role(role)?;
        let member = self
            .call(move |c, _| {
                let tx = c.transaction()?;
                let v = load_vault(&tx, vault)?.ok_or_else(|| vault_not_found(vault))?;
                if v.kind == VaultKind::Personal {
                    return Err(CoreError::vault(
                        codes::VAULT_PERSONAL,
                        "the personal vault cannot be shared",
                    ));
                }
                let exists = |sql: &str, id: Id| -> Result<bool> {
                    Ok(tx
                        .query_row(sql, [id.to_string()], |r| r.get::<_, i64>(0))
                        .optional()?
                        .is_some())
                };
                let (user_id, team_id) = match grantee {
                    VaultGrantee::User(u) => {
                        if !exists("SELECT 1 FROM users WHERE id = ?1", u)? {
                            return Err(CoreError::NotFound(format!("user {u}")));
                        }
                        if v.owner_user_id == Some(u) {
                            return Err(CoreError::vault(
                                codes::MEMBER_EXISTS,
                                "the owner already manages this vault",
                            ));
                        }
                        (Some(u.to_string()), None)
                    }
                    VaultGrantee::Team(t) => {
                        if !exists("SELECT 1 FROM teams WHERE id = ?1", t)? {
                            return Err(CoreError::NotFound(format!("team {t}")));
                        }
                        if v.owner_team_id == Some(t) {
                            return Err(CoreError::vault(
                                codes::MEMBER_EXISTS,
                                "the team already owns this vault",
                            ));
                        }
                        let member: Option<i64> = tx
                            .query_row(
                                "SELECT 1 FROM team_members WHERE team_id = ?1 AND user_id = ?2",
                                params![t.to_string(), by.to_string()],
                                |r| r.get(0),
                            )
                            .optional()?;
                        if member.is_none() {
                            return Err(CoreError::vault(
                                codes::NOT_TEAM_MEMBER,
                                "you can only share with teams you belong to",
                            ));
                        }
                        (None, Some(t.to_string()))
                    }
                };
                let id = new_id();
                let res = tx.execute(
                    "INSERT INTO vault_members (id, vault_id, user_id, team_id, role, added_by, added_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        id.to_string(),
                        vault.to_string(),
                        user_id,
                        team_id,
                        role.as_str(),
                        by.to_string(),
                        now_ms()
                    ],
                );
                match res {
                    Ok(_) => {}
                    Err(rusqlite::Error::SqliteFailure(e, _))
                        if e.code == rusqlite::ErrorCode::ConstraintViolation =>
                    {
                        return Err(CoreError::vault(
                            codes::MEMBER_EXISTS,
                            "that user or team already has access to this vault",
                        ));
                    }
                    Err(e) => return Err(e.into()),
                }
                bump_vault(&tx, vault)?;
                let m = load_member(&tx, vault, id)?;
                tx.commit()?;
                Ok(m)
            })
            .await?;
        self.bump_access();
        Ok(member)
    }

    /// Changes the role of a grant.
    pub async fn set_vault_member_role(
        &self,
        vault: Id,
        member: Id,
        role: VaultRole,
    ) -> Result<VaultMember> {
        check_grant_role(role)?;
        let m = self
            .call(move |c, _| {
                let tx = c.transaction()?;
                let n = tx.execute(
                    "UPDATE vault_members SET role = ?3 WHERE vault_id = ?1 AND id = ?2",
                    params![vault.to_string(), member.to_string(), role.as_str()],
                )?;
                if n == 0 {
                    return Err(CoreError::NotFound(format!("vault member {member}")));
                }
                bump_vault(&tx, vault)?;
                let m = load_member(&tx, vault, member)?;
                tx.commit()?;
                Ok(m)
            })
            .await?;
        self.bump_access();
        Ok(m)
    }

    /// Removes a grant; returns it.
    pub async fn remove_vault_member(&self, vault: Id, member: Id) -> Result<VaultMember> {
        let m = self
            .call(move |c, _| {
                let tx = c.transaction()?;
                let m = load_member(&tx, vault, member)?;
                tx.execute(
                    "DELETE FROM vault_members WHERE vault_id = ?1 AND id = ?2",
                    params![vault.to_string(), member.to_string()],
                )?;
                bump_vault(&tx, vault)?;
                tx.commit()?;
                Ok(m)
            })
            .await?;
        self.bump_access();
        Ok(m)
    }

    /// Removes the direct grant of `user` (leaving a vault).
    pub async fn leave_vault(&self, vault: Id, user: Id) -> Result<VaultMember> {
        let m = self
            .call(move |c, _| {
                let tx = c.transaction()?;
                let v = load_vault(&tx, vault)?.ok_or_else(|| vault_not_found(vault))?;
                if v.kind == VaultKind::Personal {
                    return Err(CoreError::vault(
                        codes::VAULT_PERSONAL,
                        "you cannot leave your personal vault",
                    ));
                }
                let id: Option<String> = tx
                    .query_row(
                        "SELECT id FROM vault_members WHERE vault_id = ?1 AND user_id = ?2",
                        params![vault.to_string(), user.to_string()],
                        |r| r.get(0),
                    )
                    .optional()?;
                let Some(id) = id else {
                    return Err(CoreError::NotFound(
                        "you have no direct access to this vault to give up".into(),
                    ));
                };
                let m = load_member(&tx, vault, parse_id(&id)?)?;
                tx.execute("DELETE FROM vault_members WHERE id = ?1", [id])?;
                bump_vault(&tx, vault)?;
                tx.commit()?;
                Ok(m)
            })
            .await?;
        self.bump_access();
        Ok(m)
    }

    /// Every user who may have access to a vault (owner, team members,
    /// direct members and members of the teams it is shared with).
    pub async fn vault_user_ids(&self, vault: Id) -> Result<Vec<Id>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare_cached(
                "SELECT owner_user_id FROM vaults WHERE id = ?1 AND owner_user_id IS NOT NULL
                 UNION SELECT tm.user_id FROM vaults v
                       JOIN team_members tm ON tm.team_id = v.owner_team_id WHERE v.id = ?1
                 UNION SELECT user_id FROM vault_members WHERE vault_id = ?1 AND user_id IS NOT NULL
                 UNION SELECT tm.user_id FROM vault_members vm
                       JOIN team_members tm ON tm.team_id = vm.team_id WHERE vm.vault_id = ?1",
            )?;
            Ok(stmt
                .query_map([vault.to_string()], |r| parse_id(&r.get::<_, String>(0)?))?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// Current key version of a vault (0: none yet).
    pub async fn vault_key_version(&self, vault: Id) -> Result<u32> {
        self.call(move |c, _| {
            c.query_row(
                "SELECT key_version FROM vaults WHERE id = ?1",
                [vault.to_string()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(|| vault_not_found(vault))
        })
        .await
    }

    /// Creates the vault key if the vault has none (vault keys must be
    /// enabled). Returns the current version.
    pub async fn ensure_vault_key(&self, vault: Id) -> Result<u32> {
        self.call_keys(move |c, keys| {
            let tx = c.transaction()?;
            let v = keys
                .current_vk(&tx, vault)?
                .map(|(v, _)| v)
                .ok_or_else(|| CoreError::Invalid("vault keys are not enabled here".into()))?;
            tx.commit()?;
            Ok(v)
        })
        .await
    }

    /// Reseals up to `batch` legacy secrets (master key) of vault entities
    /// with their vault key. Idempotent; returns how many it resealed (0:
    /// done). Does nothing while vault keys are off.
    pub async fn reseal_legacy(&self, batch: usize) -> Result<usize> {
        if !self.vault_keys_enabled() {
            return Ok(0);
        }
        self.call_keys(move |c, keys| {
            let tx = c.transaction()?;
            let rows: Vec<(String, String, String, Vec<u8>)> = {
                let mut stmt = tx.prepare(
                    "SELECT e.id, e.kind, e.vault_id, e.secret FROM entities e
                     JOIN vaults v ON v.id = e.vault_id AND v.crypto_mode = 'server'
                     WHERE e.key_version IS NULL AND e.secret IS NOT NULL
                     LIMIT ?1",
                )?;
                stmt.query_map([batch as i64], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
            };
            let mut done = 0;
            for (id, kind, vault, blob) in rows {
                let Some(kind) = EntityKind::parse(&kind) else {
                    continue;
                };
                let (eid, vid) = (parse_id(&id)?, parse_id(&vault)?);
                let (sealed, version) =
                    keys.reseal(&tx, (None, None), Some(vid), kind, eid, eid, &blob)?;
                done += tx.execute(
                    "UPDATE entities SET secret = ?2, key_version = ?3
                     WHERE id = ?1 AND key_version IS NULL",
                    params![id, sealed, version],
                )?;
            }
            tx.commit()?;
            Ok(done)
        })
        .await
    }

    /// Who a vault's items are billed to (plan limits such as
    /// `max_networks`): the owner of a personal or shared vault; for a team
    /// vault, the team's first owner (by date). `None`: unknown vault or a
    /// team without owners.
    pub async fn vault_billing_user(&self, vault: Id) -> Result<Option<Id>> {
        self.call(move |c, _| {
            let row: Option<(Option<String>, Option<String>)> = c
                .query_row(
                    "SELECT owner_user_id, owner_team_id FROM vaults WHERE id = ?1",
                    [vault.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let user = match row {
                Some((Some(user), _)) => Some(user),
                Some((None, Some(team))) => c
                    .query_row(
                        "SELECT user_id FROM team_members WHERE team_id = ?1 AND role = 'owner'
                         ORDER BY added_at, user_id LIMIT 1",
                        [team],
                        |r| r.get::<_, String>(0),
                    )
                    .optional()?,
                _ => None,
            };
            user.map(|u| parse_id(&u).map_err(Into::into)).transpose()
        })
        .await
    }

    /// Live private networks billed to `user` ([`Store::vault_billing_user`]):
    /// those of the vaults they own and of the team vaults of the teams
    /// whose first owner they are.
    pub async fn networks_billed_to(&self, user: Id) -> Result<i64> {
        self.call(move |c, _| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM entities e JOIN vaults v ON v.id = e.vault_id
                 WHERE e.kind = 'network' AND e.deleted = 0 AND (
                    v.owner_user_id = ?1
                    OR v.owner_team_id IN (
                        SELECT t.team_id FROM team_members t
                        WHERE t.role = 'owner' AND t.user_id = (
                            SELECT f.user_id FROM team_members f
                            WHERE f.team_id = t.team_id AND f.role = 'owner'
                            ORDER BY f.added_at, f.user_id LIMIT 1)
                          AND t.user_id = ?1))",
                [user.to_string()],
                |r| r.get(0),
            )?)
        })
        .await
    }

    /// Random id of this database (created once), for clients to tell
    /// servers apart.
    pub async fn instance_id(&self) -> Result<String> {
        self.call(|c, _| {
            let existing: Option<String> = c
                .query_row(
                    "SELECT value FROM meta WHERE key = 'instance_id'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(id) = existing {
                return Ok(id);
            }
            let id = uuid::Uuid::new_v4().to_string();
            c.execute(
                "INSERT INTO meta (key, value) VALUES ('instance_id', ?1)",
                [&id],
            )?;
            Ok(id)
        })
        .await
    }

    /// Audit entry about a vault (also listed in the vault's audit).
    pub async fn audit_vault(
        &self,
        owner: Id,
        actor: &str,
        action: &str,
        target: Option<String>,
        detail: serde_json::Value,
        vault: Id,
    ) -> Result<()> {
        let (actor, action) = (actor.to_string(), action.to_string());
        self.call(move |c, _| {
            c.execute(
                "INSERT INTO audit_log (owner_id, actor, action, target, detail, created_at, vault_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    owner.to_string(),
                    actor,
                    action,
                    target,
                    detail.to_string(),
                    now_ms(),
                    vault.to_string()
                ],
            )?;
            Ok(())
        })
        .await
    }

    /// Audit of a vault (most recent first).
    pub async fn vault_audit(
        &self,
        vault: Id,
        before: Option<i64>,
        limit: i64,
    ) -> Result<Vec<AuditEntry>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(
                "SELECT id, owner_id, actor, action, target, detail, created_at, vault_id
                 FROM audit_log WHERE vault_id = ?1 AND id < ?2 ORDER BY id DESC LIMIT ?3",
            )?;
            Ok(stmt
                .query_map(
                    params![vault.to_string(), before.unwrap_or(i64::MAX), limit],
                    super::audit::map_audit,
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// Records the vault of a server session.
    pub async fn set_session_vault(&self, session: Id, vault: Option<Id>) -> Result<()> {
        self.call(move |c, _| {
            c.execute(
                "UPDATE sessions SET vault_id = ?2 WHERE id = ?1",
                params![session.to_string(), vault.map(|v| v.to_string())],
            )?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use crate::store::test_store;

    async fn user(store: &Store, email: &str) -> Id {
        store
            .create_user(email, email, "long-password", false)
            .await
            .unwrap()
            .id
    }

    #[tokio::test]
    async fn personal_vault_and_roles() {
        let store = test_store();
        let ana = user(&store, "ana@example.com").await;
        let bea = user(&store, "bea@example.com").await;
        let carlos = user(&store, "carlos@example.com").await;
        let dani = user(&store, "dani@example.com").await;

        // Personal vault = user id, manager.
        let personal = store.vault(ana).await.unwrap();
        assert_eq!(personal.kind, VaultKind::Personal);
        assert_eq!(
            store.effective_role(ana, ana).await.unwrap(),
            Some(VaultRole::Manager)
        );
        assert_eq!(store.effective_role(ana, bea).await.unwrap(), None);
        assert!(matches!(
            store
                .add_vault_member(ana, ana, VaultGrantee::User(bea), VaultRole::Editor)
                .await,
            Err(CoreError::Vault {
                code: codes::VAULT_PERSONAL,
                ..
            })
        ));

        // Shared vault: direct grants.
        let ops = store
            .create_vault(
                ana,
                NewVault {
                    name: "Ops".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(ops.role, Some(VaultRole::Manager));
        let m = store
            .add_vault_member(ops.id, ana, VaultGrantee::User(bea), VaultRole::UseOnly)
            .await
            .unwrap();
        assert_eq!(
            store.vault_access(bea).await.unwrap().role(ops.id),
            Some(VaultRole::UseOnly)
        );
        assert!(matches!(
            store
                .add_vault_member(ops.id, ana, VaultGrantee::User(bea), VaultRole::Editor)
                .await,
            Err(CoreError::Vault {
                code: codes::MEMBER_EXISTS,
                ..
            })
        ));
        assert!(matches!(
            store
                .add_vault_member(ops.id, ana, VaultGrantee::User(carlos), VaultRole::Unknown)
                .await,
            Err(CoreError::Vault {
                code: codes::INVALID_ROLE,
                ..
            })
        ));

        // Team grant: the maximum wins (use_only direct + editor via team).
        let team = store.create_team(ana, "Infra").await.unwrap();
        store
            .set_team_member(team.id, bea, TeamRole::Member)
            .await
            .unwrap();
        store
            .add_vault_member(ops.id, ana, VaultGrantee::Team(team.id), VaultRole::Editor)
            .await
            .unwrap();
        assert_eq!(
            store.vault_access(bea).await.unwrap().role(ops.id),
            Some(VaultRole::Editor)
        );
        // Sharing with a team you are not in.
        let other = store.create_team(carlos, "Other").await.unwrap();
        assert!(matches!(
            store
                .add_vault_member(ops.id, ana, VaultGrantee::Team(other.id), VaultRole::Editor)
                .await,
            Err(CoreError::Vault {
                code: codes::NOT_TEAM_MEMBER,
                ..
            })
        ));

        // Team vault: owner/admin = manager, member = team_member_role.
        let tv = store
            .create_vault(
                ana,
                NewVault {
                    name: "Team stuff".into(),
                    team_id: Some(team.id),
                    team_member_role: Some(VaultRole::UseOnly),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(tv.kind, VaultKind::Team);
        assert_eq!(
            store.vault_access(bea).await.unwrap().role(tv.id),
            Some(VaultRole::UseOnly)
        );
        store
            .set_team_member(team.id, bea, TeamRole::Admin)
            .await
            .unwrap();
        assert_eq!(
            store.vault_access(bea).await.unwrap().role(tv.id),
            Some(VaultRole::Manager)
        );
        // A plain member cannot create team vaults.
        store
            .set_team_member(team.id, dani, TeamRole::Member)
            .await
            .unwrap();
        assert!(matches!(
            store
                .create_vault(
                    dani,
                    NewVault {
                        name: "x".into(),
                        team_id: Some(team.id),
                        ..Default::default()
                    }
                )
                .await,
            Err(CoreError::Forbidden(_))
        ));
        // No team member access at all.
        store
            .update_vault(
                tv.id,
                VaultPatch {
                    team_member_role: Some(None),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(store.vault_access(dani).await.unwrap().role(tv.id), None);
        // Dani still sees Ops through the team grant.
        assert_eq!(
            store.vault_access(dani).await.unwrap().role(ops.id),
            Some(VaultRole::Editor)
        );

        // Members list: owner (implicit) + grants.
        let members = store.vault_members(ops.id).await.unwrap();
        assert_eq!(members.len(), 3);
        assert!(members[0].implicit);

        // Removing the direct grant leaves the team one.
        store.remove_vault_member(ops.id, m.id).await.unwrap();
        assert_eq!(
            store.vault_access(bea).await.unwrap().role(ops.id),
            Some(VaultRole::Editor)
        );
        store.remove_team_member(team.id, bea).await.unwrap();
        assert_eq!(store.vault_access(bea).await.unwrap().role(ops.id), None);
        assert_eq!(store.vault_access(bea).await.unwrap().role(tv.id), None);

        // Listing: personal first.
        let list = store.vaults_for(ana).await.unwrap();
        assert_eq!(list[0].kind, VaultKind::Personal);
        assert_eq!(list.len(), 3);

        // Deleting the team deletes its vaults.
        store.delete_team(team.id).await.unwrap();
        assert!(store.vault(tv.id).await.is_err());
        assert_eq!(store.vault_access(dani).await.unwrap().role(ops.id), None);
    }

    #[tokio::test]
    async fn team_policies_shape_access() {
        use crate::access::{AiApproval, TeamPolicy};
        let store = test_store();
        let ana = user(&store, "ana@example.com").await;
        let bea = user(&store, "bea@example.com").await;
        let carla = user(&store, "carla@example.com").await;
        let team = store.create_team(ana, "Ops").await.unwrap();
        store
            .set_team_member(team.id, bea, TeamRole::Member)
            .await
            .unwrap();
        store
            .set_team_member(team.id, carla, TeamRole::Member)
            .await
            .unwrap();
        let tv = store
            .create_vault(
                ana,
                NewVault {
                    name: "Prod".into(),
                    team_id: Some(team.id),
                    team_member_role: Some(VaultRole::Editor),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        // Connect only by a direct grant (the maximum of both wins: the
        // team role, Editor, is higher).
        store
            .add_vault_member(
                tv.id,
                ana,
                VaultGrantee::User(carla),
                VaultRole::ConnectOnly,
            )
            .await
            .unwrap();
        // Explicit Admin grants are allowed now (on shared vaults).
        let shared = store
            .create_vault(
                ana,
                NewVault {
                    name: "S".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        store
            .add_vault_member(shared.id, ana, VaultGrantee::User(bea), VaultRole::Manager)
            .await
            .unwrap();
        assert_eq!(
            store.vault_access(bea).await.unwrap().role(shared.id),
            Some(VaultRole::Manager)
        );
        let a = store.vault_access(bea).await.unwrap();
        assert!(a.can_reveal(tv.id) && a.ai_allowed(tv.id) && a.networks_allowed(tv.id));
        assert_eq!(a.team_of.get(&tv.id), Some(&team.id));

        let mut p = TeamPolicy {
            allow_reveal: false,
            networks_allowed: false,
            record_sessions: true,
            ..Default::default()
        };
        p.ai.allowed = false;
        p.ai.approval = AiApproval::Always;
        store.set_team_policy(team.id, p.clone()).await.unwrap();
        let a = store.vault_access(bea).await.unwrap();
        assert!(!a.can_reveal(tv.id));
        assert!(matches!(
            a.authorize_secret(tv.id, SecretUse::Reveal),
            Err(CoreError::Vault {
                code: codes::SECRET_REVEAL_FORBIDDEN,
                ..
            })
        ));
        // Editors still use secrets just in time and on the server.
        assert!(a.authorize_secret(tv.id, SecretUse::Credentials).is_ok());
        assert!(!a.ai_allowed(tv.id) && a.ai_confirm.contains(&tv.id));
        assert!(!a.networks_allowed(tv.id) && a.must_record(tv.id));
        // Managers keep revealing.
        let owner = store.vault_access(ana).await.unwrap();
        assert!(owner.can_reveal(tv.id));
        // Not the shared vault (not owned by the team).
        assert!(a.can_reveal(shared.id) && a.networks_allowed(shared.id));

        // 2FA: grace period running → access with an expiry; over → hidden.
        p.require_2fa = true;
        p.grace_days = 7;
        p.require_2fa_since = Some(now_ms() - 86_400_000);
        store.set_team_policy(team.id, p.clone()).await.unwrap();
        let a = store.vault_access(bea).await.unwrap();
        assert!(a.role(tv.id).is_some());
        assert!(a.valid_until.is_some_and(|t| t > now_ms()));
        p.require_2fa_since = Some(now_ms() - 8 * 86_400_000);
        // Bea joined long ago (the grace period counts from the later of
        // the policy and the join).
        store
            .call(move |c, _| {
                c.execute(
                    "UPDATE team_members SET added_at = 0 WHERE user_id = ?1",
                    [bea.to_string()],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        store.set_team_policy(team.id, p.clone()).await.unwrap();
        let a = store.vault_access(bea).await.unwrap();
        assert_eq!(a.role(tv.id), None);
        assert!(a.blocked_2fa.contains(&tv.id));
        assert!(a.role(bea).is_some(), "the personal vault stays");
        assert!(
            a.role(shared.id).is_some(),
            "vaults not owned by the team stay"
        );
        // Enabling 2FA gives access back at once.
        store
            .call(move |c, _| {
                c.execute(
                    "UPDATE users SET totp_enabled = 1 WHERE id = ?1",
                    [bea.to_string()],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        store.bump_access();
        assert!(store.vault_access(bea).await.unwrap().role(tv.id).is_some());
        // A member who joined recently still has their own grace period.
        let dani = user(&store, "dani@example.com").await;
        store
            .set_team_member(team.id, dani, TeamRole::Member)
            .await
            .unwrap();
        assert!(
            store
                .vault_access(dani)
                .await
                .unwrap()
                .role(tv.id)
                .is_some()
        );
    }

    #[test]
    fn role_rank_order() {
        assert!(VaultRole::Manager > VaultRole::Editor);
        assert!(VaultRole::Editor > VaultRole::UseOnly);
        assert!(VaultRole::UseOnly > VaultRole::ConnectOnly);
        assert!(VaultRole::ConnectOnly > VaultRole::Unknown);
        assert!(VaultRole::ConnectOnly.can_use() && !VaultRole::ConnectOnly.can_get_credentials());
        assert_eq!(VaultRole::ConnectOnly.legacy(), VaultRole::UseOnly);
        assert_eq!(VaultRole::Editor.legacy(), VaultRole::Editor);
        assert_eq!(
            serde_json::to_string(&VaultRole::ConnectOnly).unwrap(),
            "\"connect_only\""
        );
        assert!(VaultRole::UseOnly > VaultRole::Unknown);
        assert!(!VaultRole::Unknown.can_use());
        // Text order would say otherwise ("use_only" > "manager" > "editor").
        assert!(VaultRole::UseOnly.as_str() > VaultRole::Manager.as_str());
        let r: VaultRole = serde_json::from_str("\"owner_of_everything\"").unwrap();
        assert_eq!(r, VaultRole::Unknown);
        let k: VaultKind = serde_json::from_str("\"galaxy\"").unwrap();
        assert_eq!(k, VaultKind::Unknown);
    }

    #[test]
    fn secret_authorization() {
        let user = new_id();
        let (ed, uo, strict) = (new_id(), new_id(), new_id());
        let mut a = VaultAccess {
            user,
            ..Default::default()
        };
        a.roles.insert(ed, VaultRole::Editor);
        a.roles.insert(uo, VaultRole::UseOnly);
        a.roles.insert(strict, VaultRole::UseOnly);
        a.strict.insert(strict);
        assert!(a.authorize_secret(ed, SecretUse::Reveal).is_ok());
        assert!(matches!(
            a.authorize_secret(uo, SecretUse::Reveal),
            Err(CoreError::Vault {
                code: codes::SECRET_HIDDEN,
                ..
            })
        ));
        assert!(a.authorize_secret(uo, SecretUse::Server).is_ok());
        assert!(a.authorize_secret(uo, SecretUse::Credentials).is_ok());
        assert!(matches!(
            a.authorize_secret(strict, SecretUse::Credentials),
            Err(CoreError::Vault {
                code: codes::USE_ONLY_STRICT,
                ..
            })
        ));
        assert!(a.authorize_secret(strict, SecretUse::Server).is_ok());
        assert!(matches!(
            a.authorize_secret(new_id(), SecretUse::Server),
            Err(CoreError::NotFound(_))
        ));
        // Connect only: server use only, never just-in-time credentials.
        let co = new_id();
        a.roles.insert(co, VaultRole::ConnectOnly);
        assert!(a.authorize_secret(co, SecretUse::Server).is_ok());
        assert!(matches!(
            a.authorize_secret(co, SecretUse::Credentials),
            Err(CoreError::Vault {
                code: codes::CONNECT_ONLY,
                ..
            })
        ));
        assert!(matches!(
            a.authorize_secret(co, SecretUse::Reveal),
            Err(CoreError::Vault {
                code: codes::SECRET_HIDDEN,
                ..
            })
        ));
    }
}

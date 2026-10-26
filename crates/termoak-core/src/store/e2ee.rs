//! End-to-end encrypted vaults on the server (0.7 phase 5a,
//! docs/E2EE-SSO-AUDIT.md §2): user keys and their sealed copies, pairings,
//! vault key wraps, and turning a vault's end-to-end encryption on, rotating
//! its key and turning it off. Every blob here comes from a client and is
//! only checked for shape: the server cannot open any of them.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use rusqlite::{Connection, OptionalExtension, params};

use super::entities::validate_record;
use super::vaults::{Keyring, bump_vault, compute_access, legacy_aad};
use super::{Store, next_rev, parse_id};
use crate::e2ee::{self, KeySeal, SealKind};
use crate::error::{CoreError, Result, codes};
use crate::model::{
    E2eeItem, E2eeMember, E2eePairing, E2eePlainItem, E2eeRecipient, E2eeSealedItem,
    E2eeVaultState, E2eeWrap, EntityKind, SyncMode, SyncRecord, UserKeyInfo, VaultCrypto,
    VaultE2ee, VaultRole,
};
use crate::store::VaultAccess;
use crate::time::now_ms;
use crate::{Id, new_id};

/// How long a pairing waits for another device.
pub const PAIRING_TTL_MS: i64 = 10 * 60 * 1000;
/// Pending pairings per user at most.
const MAX_PENDING_PAIRINGS: i64 = 3;

fn not_set_up() -> CoreError {
    CoreError::vault(
        codes::E2EE_NOT_SET_UP,
        "set up end-to-end encryption first (your E2EE key)",
    )
}

fn recipient(user: Id) -> String {
    format!("user:{user}")
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The active E2EE key of a user: (key id, public key).
fn active_key(conn: &Connection, user: Id) -> Result<Option<(Id, Vec<u8>, i64)>> {
    let row: Option<(String, Vec<u8>, i64)> = conn
        .query_row(
            "SELECT id, public_key, created_at FROM user_keys
             WHERE user_id = ?1 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1",
            [user.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    row.map(|(id, pk, at)| Ok((parse_id(&id)?, pk, at)))
        .transpose()
}

fn key_info(user: Id, id: Id, public: &[u8], created_at: i64) -> UserKeyInfo {
    UserKeyInfo {
        id,
        user_id: user,
        alg: e2ee::USER_KEY_ALG.into(),
        public_key: b64(public),
        fingerprint: e2ee::fingerprint(public),
        created_at,
    }
}

/// Users who may hold the key of `vault`: those whose role and team policy
/// let them read its secrets (Editors who may reveal, Admins).
fn holders(conn: &Connection, vault: Id) -> Result<BTreeSet<Id>> {
    let users: Vec<Id> = {
        let mut stmt = conn.prepare_cached(
            "SELECT owner_user_id FROM vaults WHERE id = ?1 AND owner_user_id IS NOT NULL
             UNION SELECT tm.user_id FROM vaults v
                   JOIN team_members tm ON tm.team_id = v.owner_team_id WHERE v.id = ?1
             UNION SELECT user_id FROM vault_members WHERE vault_id = ?1 AND user_id IS NOT NULL
             UNION SELECT tm.user_id FROM vault_members vm
                   JOIN team_members tm ON tm.team_id = vm.team_id WHERE vm.vault_id = ?1",
        )?;
        stmt.query_map([vault.to_string()], |r| parse_id(&r.get::<_, String>(0)?))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut out = BTreeSet::new();
    for u in users {
        if compute_access(conn, u, Some(vault))?.can_reveal(vault) {
            out.insert(u);
        }
    }
    Ok(out)
}

fn user_names(conn: &Connection, user: Id) -> Result<(String, String)> {
    Ok(conn
        .query_row(
            "SELECT email, name FROM users WHERE id = ?1",
            [user.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .unwrap_or_default())
}

fn vault_crypto(conn: &Connection, vault: Id) -> Result<(VaultCrypto, u32)> {
    conn.query_row(
        "SELECT crypto_mode, key_version FROM vaults WHERE id = ?1",
        [vault.to_string()],
        |r| Ok((VaultCrypto::parse(&r.get::<_, String>(0)?), r.get(1)?)),
    )
    .optional()?
    .ok_or_else(|| CoreError::vault(codes::VAULT_NOT_FOUND, format!("vault {vault} not found")))
}

/// Recipients (holders with an active key) and holders without a key.
fn recipients(
    conn: &Connection,
    holders: &BTreeSet<Id>,
) -> Result<(Vec<E2eeRecipient>, Vec<E2eeMember>)> {
    let mut with = Vec::new();
    let mut without = Vec::new();
    for u in holders {
        let (email, name) = user_names(conn, *u)?;
        match active_key(conn, *u)? {
            Some((key_id, pk, _)) => with.push(E2eeRecipient {
                user_id: *u,
                email,
                name,
                key_id,
                public_key: b64(&pk),
                fingerprint: e2ee::fingerprint(&pk),
            }),
            None => without.push(E2eeMember {
                user_id: *u,
                email,
                name,
            }),
        }
    }
    Ok((with, without))
}

/// Items with a secret that a conversion or rotation must cover.
fn secret_items(conn: &Connection, vault: Id) -> Result<Vec<E2eeItem>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, kind, key_version, e2ee FROM entities
         WHERE vault_id = ?1 AND deleted = 0 AND secret IS NOT NULL AND kind != 'network'
         ORDER BY id",
    )?;
    let rows = stmt
        .query_map([vault.to_string()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<u32>>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut out = Vec::with_capacity(rows.len());
    for (id, kind, kv, e) in rows {
        if let Some(kind) = EntityKind::parse(&kind) {
            out.push(E2eeItem {
                id: parse_id(&id)?,
                kind,
                key_version: kv,
                e2ee: e != 0,
            });
        }
    }
    Ok(out)
}

/// The wraps must be exactly one per recipient, for their active key.
fn check_wraps(recipients: &[E2eeRecipient], wraps: &[E2eeWrap], all: bool) -> Result<()> {
    let by_user: BTreeMap<Id, &E2eeRecipient> = recipients.iter().map(|r| (r.user_id, r)).collect();
    let mut seen = HashSet::new();
    for w in wraps {
        let Some(r) = by_user.get(&w.user_id) else {
            return Err(CoreError::vault_detail(
                codes::E2EE_WRAP_INVALID,
                "a wrap is for someone who may not hold this vault's key",
                serde_json::json!({"user_id": w.user_id}),
            ));
        };
        if r.key_id != w.key_id {
            return Err(CoreError::vault_detail(
                codes::E2EE_WRAP_INVALID,
                "a wrap is for an E2EE key that is not the member's current one",
                serde_json::json!({"user_id": w.user_id, "key_id": r.key_id}),
            ));
        }
        e2ee::check_wrap_blob(&w.wrapped)?;
        if !seen.insert(w.user_id) {
            return Err(CoreError::Invalid("two wraps for the same member".into()));
        }
    }
    if all {
        let missing: Vec<Id> = recipients
            .iter()
            .filter(|r| !seen.contains(&r.user_id))
            .map(|r| r.user_id)
            .collect();
        if !missing.is_empty() {
            return Err(CoreError::vault_detail(
                codes::E2EE_INCOMPLETE,
                "every member who may hold the key needs a wrap",
                serde_json::json!({"missing_wraps": missing}),
            ));
        }
    }
    Ok(())
}

/// The payload must cover exactly the items with secrets.
fn check_items(items: &[E2eeItem], ids: &[(Id, EntityKind)]) -> Result<()> {
    let want: BTreeMap<Id, EntityKind> = items.iter().map(|i| (i.id, i.kind)).collect();
    let mut got = HashSet::new();
    for (id, kind) in ids {
        match want.get(id) {
            Some(k) if k == kind => {
                if !got.insert(*id) {
                    return Err(CoreError::Invalid(format!("item {id} is given twice")));
                }
            }
            _ => {
                return Err(CoreError::vault_detail(
                    codes::E2EE_INCOMPLETE,
                    "the payload has an item without a secret in this vault",
                    serde_json::json!({"unexpected": id}),
                ));
            }
        }
    }
    let missing: Vec<Id> = want
        .keys()
        .filter(|id| !got.contains(id))
        .take(50)
        .copied()
        .collect();
    if !missing.is_empty() {
        return Err(CoreError::vault_detail(
            codes::E2EE_INCOMPLETE,
            "every item with a secret must be in the payload (sync and try again)",
            serde_json::json!({"missing_items": missing}),
        ));
    }
    Ok(())
}

fn insert_wraps(
    conn: &Connection,
    vault: Id,
    version: u32,
    wraps: &[E2eeWrap],
    now: i64,
) -> Result<()> {
    for w in wraps {
        conn.execute(
            "INSERT INTO vault_key_wraps (vault_id, version, recipient, alg, recipient_key_id, wrapped, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(vault_id, version, recipient) DO UPDATE SET
                recipient_key_id = excluded.recipient_key_id, wrapped = excluded.wrapped,
                alg = excluded.alg, created_at = excluded.created_at",
            params![
                vault.to_string(),
                version,
                recipient(w.user_id),
                e2ee::WRAP_ALG,
                w.key_id.to_string(),
                w.wrapped.as_bytes(),
                now
            ],
        )?;
    }
    Ok(())
}

/// Writes the sealed secrets of an item list (one new revision each; the
/// edit time is kept, so an offline edit made before still wins and comes
/// back sealed).
fn write_sealed(
    conn: &Connection,
    vault: Id,
    version: u32,
    items: &[E2eeSealedItem],
) -> Result<()> {
    for it in items {
        let blob = e2ee::check_sealed_blob(&it.blob_b64)?;
        let rev = next_rev(conn)?;
        conn.execute(
            "UPDATE entities SET secret = ?3, key_version = ?4, e2ee = 1, rev = ?5, dirty = 1
             WHERE id = ?1 AND vault_id = ?2",
            params![it.id.to_string(), vault.to_string(), blob, version, rev],
        )?;
    }
    Ok(())
}

impl Store {
    // -----------------------------------------------------------------------
    // User keys
    // -----------------------------------------------------------------------

    /// The user's active E2EE key.
    pub async fn user_key(&self, user: Id) -> Result<Option<UserKeyInfo>> {
        self.call(move |c, _| {
            Ok(active_key(c, user)?.map(|(id, pk, at)| key_info(user, id, &pk, at)))
        })
        .await
    }

    /// Sealed copies of the user's active private key.
    pub async fn user_key_seals(&self, user: Id) -> Result<Vec<KeySeal>> {
        self.call(move |c, _| {
            let Some((key_id, _, _)) = active_key(c, user)? else {
                return Ok(Vec::new());
            };
            let mut stmt = c.prepare(
                "SELECT kind, params, sealed FROM user_key_seals WHERE key_id = ?1 ORDER BY kind",
            )?;
            let rows = stmt
                .query_map([key_id.to_string()], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows
                .into_iter()
                .filter_map(|(kind, params, sealed)| {
                    Some(KeySeal {
                        kind: SealKind::parse(&kind)?,
                        params: params.and_then(|p| serde_json::from_str(&p).ok()),
                        sealed,
                    })
                })
                .collect())
        })
        .await
    }

    /// Publishes a user's first E2EE key with its sealed copies (a recovery
    /// seal is required).
    pub async fn e2ee_setup(
        &self,
        user: Id,
        key_id: Id,
        public_key: [u8; 32],
        seals: Vec<KeySeal>,
    ) -> Result<UserKeyInfo> {
        for s in &seals {
            e2ee::check_key_seal(s)?;
        }
        if !seals.iter().any(|s| s.kind == SealKind::Recovery) {
            return Err(CoreError::Invalid(
                "a recovery seal is required (the recovery key is the way back)".into(),
            ));
        }
        self.call(move |c, _| {
            let tx = c.transaction()?;
            if active_key(&tx, user)?.is_some() {
                return Err(CoreError::vault(
                    codes::E2EE_KEY_EXISTS,
                    "you already have an E2EE key (rotate it instead)",
                ));
            }
            let now = now_ms();
            tx.execute(
                "INSERT INTO user_keys (id, user_id, alg, public_key, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    key_id.to_string(),
                    user.to_string(),
                    e2ee::USER_KEY_ALG,
                    public_key.to_vec(),
                    now
                ],
            )?;
            for s in &seals {
                insert_seal(&tx, key_id, s, now)?;
            }
            tx.commit()?;
            Ok(key_info(user, key_id, &public_key, now))
        })
        .await
    }

    /// Adds or replaces a sealed copy of the active key (a new passphrase, a
    /// new recovery key).
    pub async fn e2ee_set_seal(&self, user: Id, key_id: Id, seal: KeySeal) -> Result<()> {
        e2ee::check_key_seal(&seal)?;
        self.call(move |c, _| {
            let active = active_key(c, user)?.ok_or_else(not_set_up)?;
            if active.0 != key_id {
                return Err(CoreError::vault(
                    codes::E2EE_WRAP_INVALID,
                    "that is not your current E2EE key",
                ));
            }
            insert_seal(c, key_id, &seal, now_ms())
        })
        .await
    }

    /// Removes the passphrase seal (the recovery seal cannot be removed).
    pub async fn e2ee_remove_passphrase(&self, user: Id) -> Result<bool> {
        self.call(move |c, _| {
            let active = active_key(c, user)?.ok_or_else(not_set_up)?;
            Ok(c.execute(
                "DELETE FROM user_key_seals WHERE key_id = ?1 AND kind = 'passphrase'",
                [active.0.to_string()],
            )? > 0)
        })
        .await
    }

    /// Forgets the user's E2EE key (everything lost: no device, no recovery
    /// key): the key, its seals, pairings and every wrap made for it. The
    /// vaults whose key only this user held can no longer be opened by
    /// anyone; returns them (to warn first, `dry_run`).
    pub async fn e2ee_reset(&self, user: Id, dry_run: bool) -> Result<Vec<Id>> {
        let vaults = self
            .call(move |c, _| {
                let tx = c.transaction()?;
                let keys: Vec<String> = {
                    let mut stmt = tx.prepare("SELECT id FROM user_keys WHERE user_id = ?1")?;
                    stmt.query_map([user.to_string()], |r| r.get(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()?
                };
                // Vaults where this user is the only holder of the current key.
                let orphaned: Vec<Id> = {
                    let mut stmt = tx.prepare(
                        "SELECT w.vault_id FROM vault_key_wraps w
                         JOIN vaults v ON v.id = w.vault_id AND v.key_version = w.version AND v.crypto_mode = 'e2ee'
                         WHERE w.recipient = ?1
                           AND NOT EXISTS (SELECT 1 FROM vault_key_wraps o
                                           WHERE o.vault_id = w.vault_id AND o.version = w.version
                                             AND o.recipient != ?1 AND o.recipient LIKE 'user:%')",
                    )?;
                    stmt.query_map([recipient(user)], |r| parse_id(&r.get::<_, String>(0)?))?
                        .collect::<rusqlite::Result<Vec<_>>>()?
                };
                if dry_run {
                    return Ok(orphaned);
                }
                for k in &keys {
                    tx.execute("DELETE FROM user_key_seals WHERE key_id = ?1", [k])?;
                }
                tx.execute("DELETE FROM user_keys WHERE user_id = ?1", [user.to_string()])?;
                tx.execute("DELETE FROM e2ee_pairings WHERE user_id = ?1", [user.to_string()])?;
                tx.execute("DELETE FROM vault_key_wraps WHERE recipient = ?1", [recipient(user)])?;
                tx.commit()?;
                Ok(orphaned)
            })
            .await?;
        if !dry_run {
            self.changed(&vaults);
        }
        Ok(vaults)
    }

    /// Replaces the user's key (a lost device): new key and seals, and a new
    /// wrap for every vault key the old one held at its current version.
    pub async fn e2ee_rotate_user_key(
        &self,
        user: Id,
        old_key_id: Id,
        new_key_id: Id,
        public_key: [u8; 32],
        seals: Vec<KeySeal>,
        wraps: Vec<(Id, u32, String)>,
    ) -> Result<(UserKeyInfo, Vec<Id>)> {
        for s in &seals {
            e2ee::check_key_seal(s)?;
        }
        if !seals.iter().any(|s| s.kind == SealKind::Recovery) {
            return Err(CoreError::Invalid("a recovery seal is required".into()));
        }
        for (_, _, w) in &wraps {
            e2ee::check_wrap_blob(w)?;
        }
        let (info, vaults) = self
            .call(move |c, _| {
                let tx = c.transaction()?;
                let active = active_key(&tx, user)?.ok_or_else(not_set_up)?;
                if active.0 != old_key_id {
                    return Err(CoreError::vault(codes::E2EE_STALE, "your E2EE key changed meanwhile"));
                }
                // Vault keys the old key holds at their current version.
                let held: Vec<(Id, u32)> = {
                    let mut stmt = tx.prepare(
                        "SELECT w.vault_id, w.version FROM vault_key_wraps w
                         JOIN vaults v ON v.id = w.vault_id AND v.key_version = w.version
                         WHERE w.recipient = ?1 AND w.recipient_key_id = ?2 AND v.crypto_mode = 'e2ee'",
                    )?;
                    stmt.query_map(params![recipient(user), old_key_id.to_string()], |r| {
                        Ok((parse_id(&r.get::<_, String>(0)?)?, r.get(1)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?
                };
                let given: BTreeMap<Id, (u32, &String)> =
                    wraps.iter().map(|(v, ver, w)| (*v, (*ver, w))).collect();
                let missing: Vec<Id> = held
                    .iter()
                    .filter(|(v, ver)| given.get(v).is_none_or(|(gv, _)| gv != ver))
                    .map(|(v, _)| *v)
                    .collect();
                if !missing.is_empty() {
                    return Err(CoreError::vault_detail(
                        codes::E2EE_INCOMPLETE,
                        "wrap every vault key you hold again for the new key",
                        serde_json::json!({"missing_vaults": missing}),
                    ));
                }
                let now = now_ms();
                tx.execute(
                    "UPDATE user_keys SET revoked_at = ?2 WHERE id = ?1",
                    params![old_key_id.to_string(), now],
                )?;
                tx.execute("DELETE FROM user_key_seals WHERE key_id = ?1", [old_key_id.to_string()])?;
                tx.execute(
                    "DELETE FROM vault_key_wraps WHERE recipient = ?1 AND recipient_key_id = ?2",
                    params![recipient(user), old_key_id.to_string()],
                )?;
                tx.execute(
                    "INSERT INTO user_keys (id, user_id, alg, public_key, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![new_key_id.to_string(), user.to_string(), e2ee::USER_KEY_ALG, public_key.to_vec(), now],
                )?;
                for s in &seals {
                    insert_seal(&tx, new_key_id, s, now)?;
                }
                let mut vaults = Vec::new();
                for (vault, version) in &held {
                    let (_, w) = given[vault];
                    insert_wraps(
                        &tx,
                        *vault,
                        *version,
                        &[E2eeWrap { user_id: user, key_id: new_key_id, wrapped: w.clone() }],
                        now,
                    )?;
                    vaults.push(*vault);
                }
                tx.commit()?;
                Ok((key_info(user, new_key_id, &public_key, now), vaults))
            })
            .await?;
        self.changed(&vaults);
        Ok((info, vaults))
    }

    // -----------------------------------------------------------------------
    // Pairings
    // -----------------------------------------------------------------------

    /// A new device asks for the user key with its ephemeral public key.
    pub async fn e2ee_pairing_create(
        &self,
        user: Id,
        device: Id,
        device_name: String,
        public_key: [u8; 32],
    ) -> Result<E2eePairing> {
        self.call(move |c, _| {
            if active_key(c, user)?.is_none() {
                return Err(not_set_up());
            }
            let now = now_ms();
            c.execute(
                "DELETE FROM e2ee_pairings WHERE user_id = ?1 AND expires_at < ?2",
                params![user.to_string(), now - PAIRING_TTL_MS],
            )?;
            let pending: i64 = c.query_row(
                "SELECT COUNT(*) FROM e2ee_pairings WHERE user_id = ?1 AND status = 'pending' AND expires_at > ?2",
                params![user.to_string(), now],
                |r| r.get(0),
            )?;
            if pending >= MAX_PENDING_PAIRINGS {
                return Err(CoreError::vault(
                    codes::E2EE_PAIRING_CLOSED,
                    "too many devices are waiting: approve or deny them first",
                ));
            }
            let p = E2eePairing {
                id: new_id(),
                device_id: device,
                device_name: device_name.chars().take(80).collect(),
                public_key: b64(&public_key),
                status: "pending".into(),
                sealed: None,
                created_at: now,
                expires_at: now + PAIRING_TTL_MS,
            };
            c.execute(
                "INSERT INTO e2ee_pairings (id, user_id, device_id, device_name, public_key, status, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?7)",
                params![p.id.to_string(), user.to_string(), device.to_string(), p.device_name, p.public_key, now, p.expires_at],
            )?;
            Ok(p)
        })
        .await
    }

    /// Pairings waiting for a decision (for the user's unlocked devices).
    pub async fn e2ee_pairings(&self, user: Id) -> Result<Vec<E2eePairing>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(
                "SELECT id, device_id, device_name, public_key, status, created_at, expires_at
                 FROM e2ee_pairings WHERE user_id = ?1 AND status = 'pending' AND expires_at > ?2
                 ORDER BY created_at",
            )?;
            Ok(stmt
                .query_map(params![user.to_string(), now_ms()], map_pairing)?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// One pairing. The device that asked gets the sealed key once (then
    /// it is forgotten).
    pub async fn e2ee_pairing(&self, user: Id, id: Id, device: Id) -> Result<E2eePairing> {
        self.call(move |c, _| {
            let tx = c.transaction()?;
            let (mut p, sealed): (E2eePairing, Option<String>) = tx
                .query_row(
                    "SELECT id, device_id, device_name, public_key, status, created_at, expires_at, sealed
                     FROM e2ee_pairings WHERE id = ?1 AND user_id = ?2",
                    params![id.to_string(), user.to_string()],
                    |r| Ok((map_pairing(r)?, r.get(7)?)),
                )
                .optional()?
                .ok_or_else(|| CoreError::NotFound(format!("pairing {id}")))?;
            if p.status == "pending" && p.expires_at <= now_ms() {
                p.status = "expired".into();
            }
            if p.status == "approved" && p.device_id == device {
                p.sealed = sealed;
                tx.execute(
                    "UPDATE e2ee_pairings SET status = 'completed', sealed = NULL WHERE id = ?1",
                    [id.to_string()],
                )?;
            }
            tx.commit()?;
            Ok(p)
        })
        .await
    }

    /// Approves (with the user key sealed for the pairing key) or denies
    /// (`sealed: None`) a pairing from another device of the same user.
    pub async fn e2ee_pairing_decide(
        &self,
        user: Id,
        id: Id,
        device: Id,
        sealed: Option<String>,
    ) -> Result<E2eePairing> {
        if let Some(s) = &sealed {
            let raw = {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD
                    .decode(s.trim())
                    .map_err(|_| CoreError::Invalid("sealed is not base64".into()))?
            };
            if raw.len() != 1 + 32 + 48 + 16 || raw[0] != 1 {
                return Err(CoreError::Invalid("sealed is not a sealed user key".into()));
            }
        }
        self.call(move |c, _| {
            let p: E2eePairing = c
                .query_row(
                    "SELECT id, device_id, device_name, public_key, status, created_at, expires_at
                     FROM e2ee_pairings WHERE id = ?1 AND user_id = ?2",
                    params![id.to_string(), user.to_string()],
                    map_pairing,
                )
                .optional()?
                .ok_or_else(|| CoreError::NotFound(format!("pairing {id}")))?;
            if p.status != "pending" || p.expires_at <= now_ms() {
                return Err(CoreError::vault(
                    codes::E2EE_PAIRING_CLOSED,
                    "this pairing is closed",
                ));
            }
            if p.device_id == device {
                return Err(CoreError::Forbidden(
                    "another of your devices must approve this one".into(),
                ));
            }
            let status = if sealed.is_some() {
                "approved"
            } else {
                "denied"
            };
            c.execute(
                "UPDATE e2ee_pairings SET status = ?2, sealed = ?3, approved_by = ?4 WHERE id = ?1",
                params![id.to_string(), status, sealed, device.to_string()],
            )?;
            Ok(E2eePairing {
                status: status.into(),
                ..p
            })
        })
        .await
    }

    // -----------------------------------------------------------------------
    // Vaults
    // -----------------------------------------------------------------------

    /// The E2EE state of a vault for one member (`None`: not E2EE).
    pub async fn vault_e2ee_info(&self, vault: Id, user: Id) -> Result<Option<VaultE2ee>> {
        self.call(move |c, _| {
            let (crypto, version) = vault_crypto(c, vault)?;
            if crypto != VaultCrypto::E2ee {
                return Ok(None);
            }
            let holders = holders(c, vault)?;
            let may_hold = holders.contains(&user);
            let wraps = current_wraps(c, vault, version)?;
            let rekey_needed = wraps.keys().any(|u| !holders.contains(u));
            let mut info = VaultE2ee {
                key_version: version,
                may_hold_key: may_hold,
                rekey_needed,
                ..Default::default()
            };
            let (with, without) = recipients(c, &holders)?;
            info.without_key = without.len() as i64;
            if may_hold && let Some((key_id, wrapped)) = wraps.get(&user) {
                // Only a wrap for the member's current key is useful.
                if with
                    .iter()
                    .any(|r| r.user_id == user && r.key_id == *key_id)
                {
                    info.wrap = Some(wrapped.clone());
                    info.key_id = Some(*key_id);
                    info.pending = with
                        .into_iter()
                        .filter(|r| wraps.get(&r.user_id).is_none_or(|(k, _)| *k != r.key_id))
                        .collect();
                }
            }
            Ok(Some(info))
        })
        .await
    }

    /// What a conversion or rotation must cover (`GET /vaults/{id}/e2ee`).
    pub async fn vault_e2ee_state(&self, vault: Id) -> Result<E2eeVaultState> {
        self.call(move |c, _| {
            let (crypto, version) = vault_crypto(c, vault)?;
            let holders = holders(c, vault)?;
            let (recipients, without_key) = recipients(c, &holders)?;
            let rekey_needed = crypto == VaultCrypto::E2ee
                && current_wraps(c, vault, version)?
                    .keys()
                    .any(|u| !holders.contains(u));
            Ok(E2eeVaultState {
                vault_id: vault,
                crypto,
                key_version: version,
                next_version: version + 1,
                recipients,
                without_key,
                items: secret_items(c, vault)?,
                rekey_needed,
            })
        })
        .await
    }

    /// Turns end-to-end encryption on (vault managers): the secrets sealed
    /// by the client with the new vault key `version`, and the key wrapped
    /// for every member who may hold it. The server's vault key is deleted
    /// (crypto-shredded); private networks keep a server-sealed secret.
    pub async fn e2ee_enable(
        &self,
        access: &VaultAccess,
        vault: Id,
        version: u32,
        wraps: Vec<E2eeWrap>,
        items: Vec<E2eeSealedItem>,
    ) -> Result<u32> {
        access.require(vault, VaultRole::Manager)?;
        let me = access.user;
        self.call_keys(move |c, keys| {
            let tx = c.transaction()?;
            let (crypto, current) = vault_crypto(&tx, vault)?;
            if crypto == VaultCrypto::E2ee {
                return Err(CoreError::vault(
                    codes::E2EE_ALREADY_ENABLED,
                    "the vault is already end-to-end encrypted",
                ));
            }
            if version != current + 1 {
                return Err(CoreError::vault_detail(
                    codes::E2EE_STALE,
                    "the vault key version changed: reload and try again",
                    serde_json::json!({"next_version": current + 1}),
                ));
            }
            if active_key(&tx, me)?.is_none() {
                return Err(not_set_up());
            }
            let holders = holders(&tx, vault)?;
            let (recips, _) = recipients(&tx, &holders)?;
            // The others can get theirs later (a key holder confirms them).
            check_wraps(&recips, &wraps, false)?;
            if !wraps.iter().any(|w| w.user_id == me) {
                return Err(CoreError::vault(
                    codes::E2EE_INCOMPLETE,
                    "include your own wrap",
                ));
            }
            let existing = secret_items(&tx, vault)?;
            check_items(
                &existing,
                &items.iter().map(|i| (i.id, i.kind)).collect::<Vec<_>>(),
            )?;
            // Private networks: from the vault key to the server's legacy
            // format (the vault key is about to be deleted).
            reseal_networks_legacy(&tx, keys, vault)?;
            let now = now_ms();
            tx.execute(
                "DELETE FROM vault_keys WHERE vault_id = ?1",
                [vault.to_string()],
            )?;
            tx.execute(
                "DELETE FROM vault_key_wraps WHERE vault_id = ?1",
                [vault.to_string()],
            )?;
            tx.execute(
                "INSERT INTO vault_keys (vault_id, version, created_at) VALUES (?1, ?2, ?3)",
                params![vault.to_string(), version, now],
            )?;
            insert_wraps(&tx, vault, version, &wraps, now)?;
            tx.execute(
                "UPDATE vaults SET crypto_mode = 'e2ee', key_version = ?2 WHERE id = ?1",
                params![vault.to_string(), version],
            )?;
            write_sealed(&tx, vault, version, &items)?;
            bump_vault(&tx, vault)?;
            tx.commit()?;
            keys.forget_vault(vault);
            Ok(version)
        })
        .await?;
        self.bump_access();
        self.changed(&[vault]);
        Ok(version)
    }

    /// Rotates the key of an E2EE vault (a key holder): every secret sealed
    /// again with `version` = current + 1 and the key wrapped for every
    /// member who may hold it; the old versions are deleted.
    pub async fn e2ee_rotate(
        &self,
        access: &VaultAccess,
        vault: Id,
        from_version: u32,
        wraps: Vec<E2eeWrap>,
        items: Vec<E2eeSealedItem>,
    ) -> Result<u32> {
        access.require(vault, VaultRole::Editor)?;
        if !access.can_reveal(vault) {
            return Err(CoreError::vault(
                codes::SECRET_REVEAL_FORBIDDEN,
                "you may not hold this vault's key",
            ));
        }
        let me = access.user;
        let version = self
            .call_keys(move |c, keys| {
                let tx = c.transaction()?;
                let (crypto, current) = vault_crypto(&tx, vault)?;
                if crypto != VaultCrypto::E2ee {
                    return Err(CoreError::vault(
                        codes::E2EE_NOT_ENABLED,
                        "this vault is not end-to-end encrypted",
                    ));
                }
                if from_version != current {
                    return Err(CoreError::vault_detail(
                        codes::E2EE_STALE,
                        "the vault key changed meanwhile: reload and try again",
                        serde_json::json!({"key_version": current}),
                    ));
                }
                let version = current + 1;
                let holders = holders(&tx, vault)?;
                let (recips, _) = recipients(&tx, &holders)?;
                check_wraps(&recips, &wraps, false)?;
                // Everyone who holds the key now and still may keeps it.
                let given: HashSet<Id> = wraps.iter().map(|w| w.user_id).collect();
                let missing: Vec<Id> = current_wraps(&tx, vault, current)?
                    .into_keys()
                    .filter(|u| {
                        holders.contains(u)
                            && recips.iter().any(|r| r.user_id == *u)
                            && !given.contains(u)
                    })
                    .collect();
                if !missing.is_empty() {
                    return Err(CoreError::vault_detail(
                        codes::E2EE_INCOMPLETE,
                        "every member who holds the key and still may needs a new wrap",
                        serde_json::json!({"missing_wraps": missing}),
                    ));
                }
                if !wraps.iter().any(|w| w.user_id == me) {
                    return Err(CoreError::vault(
                        codes::E2EE_INCOMPLETE,
                        "include your own wrap",
                    ));
                }
                let existing = secret_items(&tx, vault)?;
                check_items(
                    &existing,
                    &items.iter().map(|i| (i.id, i.kind)).collect::<Vec<_>>(),
                )?;
                let now = now_ms();
                tx.execute(
                    "DELETE FROM vault_keys WHERE vault_id = ?1",
                    [vault.to_string()],
                )?;
                tx.execute(
                    "DELETE FROM vault_key_wraps WHERE vault_id = ?1",
                    [vault.to_string()],
                )?;
                tx.execute(
                    "INSERT INTO vault_keys (vault_id, version, created_at) VALUES (?1, ?2, ?3)",
                    params![vault.to_string(), version, now],
                )?;
                insert_wraps(&tx, vault, version, &wraps, now)?;
                tx.execute(
                    "UPDATE vaults SET key_version = ?2 WHERE id = ?1",
                    params![vault.to_string(), version],
                )?;
                write_sealed(&tx, vault, version, &items)?;
                bump_vault(&tx, vault)?;
                tx.commit()?;
                keys.forget_vault(vault);
                Ok(version)
            })
            .await?;
        self.changed(&[vault]);
        Ok(version)
    }

    /// Turns end-to-end encryption off (vault managers): the client sends
    /// every secret in plaintext; the server seals them with a new server
    /// vault key and deletes the members' wraps.
    pub async fn e2ee_disable(
        &self,
        access: &VaultAccess,
        vault: Id,
        items: Vec<E2eePlainItem>,
    ) -> Result<u32> {
        access.require(vault, VaultRole::Manager)?;
        let version = self
            .call_keys(move |c, keys| {
                let tx = c.transaction()?;
                let (crypto, _) = vault_crypto(&tx, vault)?;
                if crypto != VaultCrypto::E2ee {
                    return Err(CoreError::vault(codes::E2EE_NOT_ENABLED, "this vault is not end-to-end encrypted"));
                }
                let existing = secret_items(&tx, vault)?;
                check_items(&existing, &items.iter().map(|i| (i.id, i.kind)).collect::<Vec<_>>())?;
                // Validate every secret against its item before writing.
                for it in &items {
                    let data: String = tx.query_row(
                        "SELECT data FROM entities WHERE id = ?1",
                        [it.id.to_string()],
                        |r| r.get(0),
                    )?;
                    let rec = SyncRecord {
                        id: it.id,
                        kind: it.kind,
                        data: serde_json::from_str(&data)?,
                        secret: Some(it.secret.clone()),
                        sync_mode: SyncMode::Synced,
                        updated_at: 0,
                        deleted: false,
                        rev: 0,
                        vault_id: Some(vault),
                        has_secret: None,
                        sealed: None,
                        base_rev: None,
                    };
                    validate_record(&rec)?;
                }
                tx.execute("DELETE FROM vault_keys WHERE vault_id = ?1", [vault.to_string()])?;
                tx.execute("DELETE FROM vault_key_wraps WHERE vault_id = ?1", [vault.to_string()])?;
                tx.execute(
                    "UPDATE vaults SET crypto_mode = 'server', key_version = 0 WHERE id = ?1",
                    [vault.to_string()],
                )?;
                keys.forget_vault(vault);
                let mut version = 0;
                for it in &items {
                    let json = zeroize::Zeroizing::new(serde_json::to_vec(&it.secret)?);
                    let (blob, kv) = keys.seal(&tx, Some(vault), it.kind, it.id, &json)?;
                    version = kv.unwrap_or(0);
                    let rev = next_rev(&tx)?;
                    tx.execute(
                        "UPDATE entities SET secret = ?2, key_version = ?3, e2ee = 0, rev = ?4, dirty = 1
                         WHERE id = ?1",
                        params![it.id.to_string(), blob, kv, rev],
                    )?;
                }
                bump_vault(&tx, vault)?;
                tx.commit()?;
                Ok(version)
            })
            .await?;
        self.bump_access();
        self.changed(&[vault]);
        Ok(version)
    }

    /// Adds wraps of the current key for members who may hold it (any key
    /// holder: new members, members who just set E2EE up).
    pub async fn e2ee_add_wraps(
        &self,
        access: &VaultAccess,
        vault: Id,
        version: u32,
        wraps: Vec<E2eeWrap>,
    ) -> Result<usize> {
        access.require(vault, VaultRole::Editor)?;
        if !access.can_reveal(vault) {
            return Err(CoreError::vault(
                codes::SECRET_REVEAL_FORBIDDEN,
                "you may not hold this vault's key",
            ));
        }
        let n = self
            .call(move |c, _| {
                let tx = c.transaction()?;
                let (crypto, current) = vault_crypto(&tx, vault)?;
                if crypto != VaultCrypto::E2ee {
                    return Err(CoreError::vault(
                        codes::E2EE_NOT_ENABLED,
                        "this vault is not end-to-end encrypted",
                    ));
                }
                if version != current {
                    return Err(CoreError::vault_detail(
                        codes::E2EE_STALE,
                        "the vault key changed meanwhile",
                        serde_json::json!({"key_version": current}),
                    ));
                }
                let holders = holders(&tx, vault)?;
                let (recips, _) = recipients(&tx, &holders)?;
                check_wraps(&recips, &wraps, false)?;
                insert_wraps(&tx, vault, version, &wraps, now_ms())?;
                bump_vault(&tx, vault)?;
                tx.commit()?;
                Ok(wraps.len())
            })
            .await?;
        self.changed(&[vault]);
        Ok(n)
    }
}

fn insert_seal(conn: &Connection, key_id: Id, s: &KeySeal, now: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO user_key_seals (key_id, kind, params, sealed, created_at) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(key_id, kind) DO UPDATE SET params = excluded.params, sealed = excluded.sealed,
            created_at = excluded.created_at",
        params![
            key_id.to_string(),
            s.kind.as_str(),
            s.params.as_ref().map(|p| serde_json::to_string(p).unwrap_or_default()),
            s.sealed,
            now
        ],
    )?;
    Ok(())
}

fn map_pairing(r: &rusqlite::Row<'_>) -> rusqlite::Result<E2eePairing> {
    Ok(E2eePairing {
        id: parse_id(&r.get::<_, String>(0)?)?,
        device_id: parse_id(&r.get::<_, String>(1)?)?,
        device_name: r.get(2)?,
        public_key: r.get(3)?,
        status: r.get(4)?,
        sealed: None,
        created_at: r.get(5)?,
        expires_at: r.get(6)?,
    })
}

/// Wraps of the current version: user → (key id, wrapped).
fn current_wraps(conn: &Connection, vault: Id, version: u32) -> Result<BTreeMap<Id, (Id, String)>> {
    let mut stmt = conn.prepare_cached(
        "SELECT recipient, recipient_key_id, wrapped FROM vault_key_wraps
         WHERE vault_id = ?1 AND version = ?2 AND recipient LIKE 'user:%'",
    )?;
    let rows = stmt
        .query_map(params![vault.to_string(), version], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut out = BTreeMap::new();
    for (rcpt, key, wrapped) in rows {
        let (Some(user), Some(key)) = (rcpt.strip_prefix("user:"), key) else {
            continue;
        };
        out.insert(
            parse_id(user)?,
            (
                parse_id(&key)?,
                String::from_utf8(wrapped).unwrap_or_default(),
            ),
        );
    }
    Ok(out)
}

/// Private network secrets of a vault to the master key's legacy format.
fn reseal_networks_legacy(conn: &Connection, keys: &Keyring, vault: Id) -> Result<()> {
    let rows: Vec<(String, Vec<u8>, u32)> = {
        let mut stmt = conn.prepare(
            "SELECT id, secret, key_version FROM entities
             WHERE vault_id = ?1 AND kind = 'network' AND secret IS NOT NULL AND key_version IS NOT NULL",
        )?;
        stmt.query_map([vault.to_string()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (id, blob, kv) in rows {
        let id = parse_id(&id)?;
        let plain = keys.open(conn, Some(vault), Some(kv), EntityKind::Network, id, &blob)?;
        let sealed = keys
            .master
            .seal(&plain, &legacy_aad(EntityKind::Network, id))?;
        conn.execute(
            "UPDATE entities SET secret = ?2, key_version = NULL WHERE id = ?1",
            params![id.to_string(), sealed],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use crate::store::{SecretUse, VaultChange, test_store};

    async fn user(store: &Store, email: &str) -> Id {
        store
            .create_user(email, email, "password123", false)
            .await
            .unwrap()
            .id
    }

    fn recovery_seal(user: Id, key: &e2ee::UserKeyPair) -> (e2ee::RecoveryKey, KeySeal) {
        let rk = e2ee::RecoveryKey::generate();
        let seal = e2ee::seal_with_recovery(user, key, &rk).unwrap();
        (rk, seal)
    }

    #[tokio::test]
    async fn enable_rotate_disable_and_wraps() {
        let store = test_store();
        store.enable_vault_keys();
        let ana = user(&store, "ana@x.test").await;
        let bob = user(&store, "bob@x.test").await;
        let carl = user(&store, "carl@x.test").await;
        let vault = store
            .create_vault(
                ana,
                crate::store::NewVault {
                    name: "Ops".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .id;
        store
            .add_vault_member(
                vault,
                ana,
                crate::store::VaultGrantee::User(bob),
                VaultRole::Editor,
            )
            .await
            .unwrap();
        store
            .add_vault_member(
                vault,
                ana,
                crate::store::VaultGrantee::User(carl),
                VaultRole::UseOnly,
            )
            .await
            .unwrap();
        let acc = store.vault_access(ana).await.unwrap();
        let host: Host = serde_json::from_value(serde_json::json!({
            "label": "web", "address": "10.0.0.1", "settings": {"username": "root"}
        }))
        .unwrap();
        let h = store
            .save_in(
                &acc,
                vault,
                host,
                SecretUpdate::Set(HostSecret {
                    password: Some("pw".into()),
                    ..Default::default()
                }),
                None,
            )
            .await
            .unwrap();
        let hid = h.data.id;

        // Ana and Bob set up keys; Carl (Use-only) may not hold the key.
        let ka = e2ee::UserKeyPair::generate();
        let (_, sa) = recovery_seal(ana, &ka);
        store
            .e2ee_setup(ana, ka.id, *ka.public(), vec![sa.clone()])
            .await
            .unwrap();
        assert_eq!(
            store
                .e2ee_setup(ana, ka.id, *ka.public(), vec![sa])
                .await
                .unwrap_err()
                .vault_code(),
            Some(codes::E2EE_KEY_EXISTS)
        );
        let kb = e2ee::UserKeyPair::generate();
        let (_, sb) = recovery_seal(bob, &kb);
        store
            .e2ee_setup(bob, kb.id, *kb.public(), vec![sb])
            .await
            .unwrap();

        let st = store.vault_e2ee_state(vault).await.unwrap();
        assert_eq!(st.recipients.len(), 2);
        assert_eq!(st.items.len(), 1);
        let version = st.next_version;
        let vk = e2ee::VaultKey::generate();
        let wrap = |u: Id, k: &e2ee::UserKeyPair, v: u32, vk: &e2ee::VaultKey| E2eeWrap {
            user_id: u,
            key_id: k.id,
            wrapped: e2ee::wrap_vault_key(vk, vault, v, u, k.id, k.public()).unwrap(),
        };
        let sealed = |v: u32, vk: &e2ee::VaultKey| E2eeSealedItem {
            id: hid,
            kind: EntityKind::Host,
            blob_b64: e2ee::encrypt_secret(
                vk,
                vault,
                v,
                EntityKind::Host,
                hid,
                br#"{"password":"pw"}"#,
            )
            .unwrap(),
        };
        // Without your own wrap: refused.
        assert_eq!(
            store
                .e2ee_enable(
                    &acc,
                    vault,
                    version,
                    vec![wrap(bob, &kb, version, &vk)],
                    vec![sealed(version, &vk)]
                )
                .await
                .unwrap_err()
                .vault_code(),
            Some(codes::E2EE_INCOMPLETE)
        );
        store
            .e2ee_enable(
                &acc,
                vault,
                version,
                vec![wrap(ana, &ka, version, &vk), wrap(bob, &kb, version, &vk)],
                vec![sealed(version, &vk)],
            )
            .await
            .unwrap();
        // The server cannot open it; resolution goes on without it.
        let acc = store.vault_access(ana).await.unwrap();
        assert!(acc.is_e2ee(vault));
        assert_eq!(
            store
                .secret_in::<Host>(&acc, hid, SecretUse::Reveal)
                .await
                .unwrap_err()
                .vault_code(),
            Some(codes::E2EE_LOCKED)
        );
        let err = store
            .resolve_in(&acc, hid, SecretUse::Server)
            .await
            .unwrap_err();
        assert_eq!(err.vault_code(), Some(codes::E2EE_UNLOCK_REQUIRED));
        let err = store
            .resolve_in(&acc, hid, SecretUse::Credentials)
            .await
            .unwrap_err();
        assert_eq!(err.vault_code(), Some(codes::E2EE_VAULT));
        // Per-session unlock: the device's password for this connection.
        let unlock = crate::resolve::E2eeUnlock {
            hops: vec![crate::resolve::UnlockHop {
                host_id: hid,
                password: Some("from-device".into()),
                key: None,
                proxy_password: None,
            }],
        };
        let r = store
            .resolve_in_with(&acc, hid, SecretUse::Server, Some(&unlock))
            .await
            .unwrap();
        assert!(r.e2ee_locked);
        assert_eq!(r.password.as_deref(), Some("from-device"));
        // Plaintext refused, sealed accepted.
        let err = store
            .save_in(
                &acc,
                vault,
                store.get_in::<Host>(&acc, hid).await.unwrap().data,
                SecretUpdate::Set(HostSecret {
                    password: Some("x".into()),
                    ..Default::default()
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.vault_code(), Some(codes::E2EE_PLAINTEXT_REJECTED));
        // Members' view.
        let ia = store.vault_e2ee_info(vault, ana).await.unwrap().unwrap();
        let vk2 =
            e2ee::unwrap_vault_key(ia.wrap.as_ref().unwrap(), vault, version, ana, &ka).unwrap();
        assert_eq!(vk2.as_bytes(), vk.as_bytes());
        let ic = store.vault_e2ee_info(vault, carl).await.unwrap().unwrap();
        assert!(!ic.may_hold_key && ic.wrap.is_none());
        // Sync v2 sends the sealed blob to Bob, nothing to Carl.
        let bacc = store.vault_access(bob).await.unwrap();
        let ch = store.vault_changes(&bacc, vault, 0, 100).await.unwrap();
        let rec = ch
            .items
            .iter()
            .find_map(|c| match c {
                VaultChange::Record(r) if r.id == hid => Some(r.clone()),
                _ => None,
            })
            .unwrap();
        let s = rec.sealed.unwrap();
        assert_eq!(s.key_version, version);
        let plain =
            e2ee::decrypt_secret(&vk, vault, version, EntityKind::Host, hid, &s.blob_b64).unwrap();
        assert_eq!(&*plain, br#"{"password":"pw"}"#);
        let cacc = store.vault_access(carl).await.unwrap();
        let ch = store.vault_changes(&cacc, vault, 0, 100).await.unwrap();
        let rec = ch
            .items
            .iter()
            .find_map(|c| match c {
                VaultChange::Record(r) if r.id == hid => Some(r.clone()),
                _ => None,
            })
            .unwrap();
        assert!(rec.sealed.is_none() && rec.has_secret == Some(true));
        // Old clients never see the vault.
        assert!(acc.without_e2ee().role(vault).is_none());

        // Bob loses Editor: the key must rotate.
        let members = store.vault_members(vault).await.unwrap();
        let bob_member = members
            .iter()
            .find(|m| matches!(&m.principal, VaultPrincipal::User { id, .. } if *id == bob))
            .unwrap()
            .id;
        store
            .set_vault_member_role(vault, bob_member, VaultRole::UseOnly)
            .await
            .unwrap();
        let ia = store.vault_e2ee_info(vault, ana).await.unwrap().unwrap();
        assert!(ia.rekey_needed);
        let ib = store.vault_e2ee_info(vault, bob).await.unwrap().unwrap();
        assert!(
            ib.wrap.is_none(),
            "a member who lost the right gets no wrap"
        );
        let acc = store.vault_access(ana).await.unwrap();
        let v2 = version + 1;
        let vk3 = e2ee::VaultKey::generate();
        assert_eq!(
            store
                .e2ee_rotate(
                    &acc,
                    vault,
                    version,
                    vec![wrap(ana, &ka, v2, &vk3), wrap(bob, &kb, v2, &vk3)],
                    vec![sealed(v2, &vk3)]
                )
                .await
                .unwrap_err()
                .vault_code(),
            Some(codes::E2EE_WRAP_INVALID)
        );
        store
            .e2ee_rotate(
                &acc,
                vault,
                version,
                vec![wrap(ana, &ka, v2, &vk3)],
                vec![sealed(v2, &vk3)],
            )
            .await
            .unwrap();
        let ia = store.vault_e2ee_info(vault, ana).await.unwrap().unwrap();
        assert!(!ia.rekey_needed && ia.key_version == v2);

        // Bob is Editor again, sets nothing new: Ana adds his wrap.
        store
            .set_vault_member_role(vault, bob_member, VaultRole::Editor)
            .await
            .unwrap();
        let ia = store.vault_e2ee_info(vault, ana).await.unwrap().unwrap();
        assert_eq!(ia.pending.len(), 1);
        let acc = store.vault_access(ana).await.unwrap();
        store
            .e2ee_add_wraps(&acc, vault, v2, vec![wrap(bob, &kb, v2, &vk3)])
            .await
            .unwrap();
        assert!(
            store
                .vault_e2ee_info(vault, bob)
                .await
                .unwrap()
                .unwrap()
                .wrap
                .is_some()
        );

        // Off again: the server seals the plaintext.
        store
            .e2ee_disable(
                &acc,
                vault,
                vec![E2eePlainItem {
                    id: hid,
                    kind: EntityKind::Host,
                    secret: serde_json::json!({"password": "pw"}),
                }],
            )
            .await
            .unwrap();
        let acc = store.vault_access(ana).await.unwrap();
        assert!(!acc.is_e2ee(vault));
        let sec = store
            .secret_in::<Host>(&acc, hid, SecretUse::Reveal)
            .await
            .unwrap();
        assert_eq!(sec.password.as_deref(), Some("pw"));
    }

    #[tokio::test]
    async fn pairing_hands_the_key_to_another_device() {
        let store = test_store();
        let ana = user(&store, "ana@x.test").await;
        let ka = e2ee::UserKeyPair::generate();
        let (_, sa) = recovery_seal(ana, &ka);
        store
            .e2ee_setup(ana, ka.id, *ka.public(), vec![sa])
            .await
            .unwrap();
        let (d1, d2) = (new_id(), new_id());
        let pk = e2ee::PairingKey::generate();
        let p = store
            .e2ee_pairing_create(ana, d2, "Phone".into(), *pk.public())
            .await
            .unwrap();
        assert_eq!(store.e2ee_pairings(ana).await.unwrap().len(), 1);
        // The asking device cannot approve itself.
        assert!(
            store
                .e2ee_pairing_decide(ana, p.id, d2, None)
                .await
                .is_err()
        );
        let sealed = e2ee::pairing_seal(ana, p.id, pk.public(), &ka).unwrap();
        store
            .e2ee_pairing_decide(ana, p.id, d1, Some(sealed))
            .await
            .unwrap();
        // Another device does not get it; the asking one gets it once.
        assert!(
            store
                .e2ee_pairing(ana, p.id, d1)
                .await
                .unwrap()
                .sealed
                .is_none()
        );
        let got = store.e2ee_pairing(ana, p.id, d2).await.unwrap();
        let key = pk.open(ana, p.id, got.sealed.as_ref().unwrap()).unwrap();
        assert_eq!(key.public(), ka.public());
        assert!(
            store
                .e2ee_pairing(ana, p.id, d2)
                .await
                .unwrap()
                .sealed
                .is_none()
        );
        assert_eq!(
            store
                .e2ee_pairing_decide(ana, p.id, d1, None)
                .await
                .unwrap_err()
                .vault_code(),
            Some(codes::E2EE_PAIRING_CLOSED)
        );
    }
}

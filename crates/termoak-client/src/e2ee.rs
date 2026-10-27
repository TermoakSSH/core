//! End-to-end encrypted vaults on a device (0.7 phase 5a,
//! docs-next/E2EE-SSO-AUDIT.md §2).
//!
//! - The user key lives in the account store, sealed with the device key
//!   (the keychain-protected key of every local store): an account is
//!   "unlocked" on this device when it is there. It gets there from the E2EE
//!   passphrase, the recovery key, or another device (pairing).
//! - Vault keys are never stored: each sync's vault list carries this
//!   member's wrap, opened with the user key when needed.
//! - Sync seals outgoing secrets of E2EE vaults and opens incoming ones;
//!   what cannot be opened (locked) is kept sealed and opened at unlock;
//!   local edits of secrets of a locked vault wait (dirty) until then.

use std::collections::{BTreeMap, HashMap};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use termoak_core::e2ee::{self, KeySeal, PairingKey, RecoveryKey, SealKind, UserKeyPair, VaultKey};
use termoak_core::error::codes;
use termoak_core::model::{
    E2eePairing, E2eePlainItem, E2eeSealedItem, E2eeVaultState, E2eeWrap, EntityKind, SealedSecret,
    SyncRecord, UserKeyInfo, Vault, VaultCrypto,
};
use termoak_core::{CoreError, Id, Store};
use zeroize::Zeroizing;

use crate::accounts::Account;
use crate::error::{ClientError, Result};

/// Account store meta key of the user key (sealed with the device key).
const META_USER_KEY: &str = "e2ee.user_key";
/// Account store meta key of the members' key fingerprints this device
/// wrapped vault keys for (trust on first use).
const META_PINS: &str = "e2ee.pins";

#[derive(Serialize, Deserialize)]
struct StoredKey {
    id: Id,
    user: Id,
    /// The private key sealed with the device key, base64.
    sealed: String,
}

fn device_aad(user: Id, key: Id) -> Vec<u8> {
    format!("termoak:e2ee:device:{user}:{key}").into_bytes()
}

/// The user key stored on this device for `user` (`None`: locked here).
pub async fn stored_user_key(store: &Store, user: Id) -> Result<Option<UserKeyPair>> {
    let Some(raw) = store.meta_get(META_USER_KEY).await? else {
        return Ok(None);
    };
    let Ok(sk) = serde_json::from_str::<StoredKey>(&raw) else {
        return Ok(None);
    };
    if sk.user != user {
        return Ok(None);
    }
    let blob = STANDARD
        .decode(sk.sealed.trim())
        .map_err(|_| ClientError::Invalid("stored E2EE key is not base64".into()))?;
    let plain = store.master_key().open(&blob, &device_aad(user, sk.id))?;
    let bytes: [u8; 32] = plain
        .as_slice()
        .try_into()
        .map_err(|_| ClientError::Invalid("stored E2EE key has a bad length".into()))?;
    Ok(Some(UserKeyPair::from_private(sk.id, bytes)))
}

/// Stores the user key on this device (unlock).
pub async fn store_user_key(store: &Store, user: Id, key: &UserKeyPair) -> Result<()> {
    let sealed = store
        .master_key()
        .seal(key.private_bytes().as_slice(), &device_aad(user, key.id))?;
    let v = serde_json::to_string(&StoredKey {
        id: key.id,
        user,
        sealed: STANDARD.encode(sealed),
    })
    .map_err(|e| ClientError::Invalid(e.to_string()))?;
    store.meta_set(META_USER_KEY, &v).await?;
    Ok(())
}

/// Forgets the user key on this device (lock).
pub async fn forget_user_key(store: &Store) -> Result<()> {
    store
        .call(|c, _| {
            c.execute("DELETE FROM meta WHERE key = ?1", [META_USER_KEY])?;
            Ok(())
        })
        .await?;
    Ok(())
}

/// The vault keys this device can open, from a vault list.
#[derive(Default)]
pub(crate) struct VaultKeys {
    /// E2EE vaults: current version and the key when we have it.
    pub vaults: HashMap<Id, (u32, Option<VaultKey>)>,
}

impl VaultKeys {
    pub fn from_vaults(vaults: &[Vault], user: Id, uk: Option<&UserKeyPair>) -> Self {
        let mut out = Self::default();
        for v in vaults {
            if v.crypto != VaultCrypto::E2ee {
                continue;
            }
            let Some(info) = &v.e2ee else {
                out.vaults.insert(v.id, (v.key_version, None));
                continue;
            };
            let vk = match (uk, &info.wrap, info.key_id) {
                (Some(uk), Some(w), Some(kid)) if kid == uk.id => {
                    e2ee::unwrap_vault_key(w, v.id, info.key_version, user, uk).ok()
                }
                _ => None,
            };
            out.vaults.insert(v.id, (info.key_version, vk));
        }
        out
    }

    /// Seals the plaintext secrets of outgoing records of E2EE vaults.
    /// Records whose vault is locked here are held back (they stay dirty
    /// and go once the vault is unlocked); returns how many.
    pub fn seal_outgoing(&self, records: &mut Vec<SyncRecord>, personal: Id) -> usize {
        let mut held = 0;
        records.retain_mut(|r| {
            let vault = r.vault_id.unwrap_or(personal);
            let Some((version, vk)) = self.vaults.get(&vault) else {
                return true;
            };
            if r.kind == EntityKind::Network || r.deleted {
                return true;
            }
            match &r.secret {
                None | Some(Value::Null) => true,
                Some(secret) => match vk {
                    Some(vk) => {
                        let json = Zeroizing::new(serde_json::to_vec(secret).unwrap_or_default());
                        match e2ee::encrypt_secret(vk, vault, *version, r.kind, r.id, &json) {
                            Ok(blob) => {
                                r.secret = None;
                                r.sealed = Some(SealedSecret {
                                    key_version: *version,
                                    blob_b64: blob,
                                });
                                true
                            }
                            Err(_) => {
                                held += 1;
                                false
                            }
                        }
                    }
                    None => {
                        held += 1;
                        false
                    }
                },
            }
        });
        held
    }

    /// Opens the sealed secrets of incoming records it can; the rest stay
    /// sealed (stored locked).
    pub fn open_incoming(&self, records: &mut [SyncRecord]) {
        for r in records {
            let (Some(sealed), Some(vault)) = (&r.sealed, r.vault_id) else {
                continue;
            };
            let Some((version, Some(vk))) = self.vaults.get(&vault) else {
                continue;
            };
            if sealed.key_version != *version {
                continue;
            }
            if let Ok(plain) =
                e2ee::decrypt_secret(vk, vault, *version, r.kind, r.id, &sealed.blob_b64)
                && let Ok(v) = serde_json::from_slice::<Value>(&plain)
            {
                r.secret = Some(v);
                r.sealed = None;
            }
        }
    }
}

/// Opens the secrets this store keeps sealed, with the keys it has now
/// (after an unlock, a new wrap...). Returns how many were opened.
pub async fn open_stored(store: &Store, user: Id) -> Result<usize> {
    let Some(uk) = stored_user_key(store, user).await? else {
        return Ok(0);
    };
    let vaults = store.local_vault_list().await?;
    let keys = VaultKeys::from_vaults(&vaults, user, Some(&uk));
    let mut opened = Vec::new();
    for row in store.e2ee_sealed_rows(None).await? {
        let Some((version, Some(vk))) = keys.vaults.get(&row.vault_id) else {
            continue;
        };
        if row.key_version != *version {
            continue;
        }
        if let Ok(plain) =
            e2ee::decrypt_secret(vk, row.vault_id, *version, row.kind, row.id, &row.blob_b64)
        {
            opened.push((row.id, plain));
        }
    }
    Ok(store.e2ee_store_opened(opened).await?)
}

/// `GET /api/v1/me/e2ee`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct E2eeStatus {
    #[serde(default)]
    pub key: Option<UserKeyInfo>,
    #[serde(default)]
    pub seals: Vec<KeySeal>,
    #[serde(default)]
    pub pairings: Vec<E2eePairing>,
}

/// What the new device shows while it waits for another one.
#[derive(Debug, Clone)]
pub struct PairingStart {
    pub id: Id,
    /// Six digits, also shown by the approving device.
    pub code: String,
    pub expires_at: i64,
}

/// A pairing as an unlocked device shows it.
#[derive(Debug, Clone)]
pub struct PairingRequest {
    pub pairing: E2eePairing,
    pub code: String,
}

/// A member who may hold a vault key but has no wrap yet, with what this
/// device knew of their key before.
#[derive(Debug, Clone)]
pub struct PendingMember {
    pub recipient: termoak_core::model::E2eeRecipient,
    /// This device wrapped for another key of theirs before: the key
    /// changed (could be a new device of theirs, or a swapped key).
    pub key_changed: bool,
}

fn not_unlocked() -> ClientError {
    CoreError::vault(
        codes::E2EE_LOCKED,
        "unlock end-to-end encryption on this device first",
    )
    .into()
}

impl Account {
    fn e2ee_user(&self) -> Result<Id> {
        self.user_id().ok_or(ClientError::NotLoggedIn)
    }

    /// The server supports E2EE vaults (`/info features.e2ee`).
    pub fn e2ee_supported(&self) -> bool {
        self.info().features["e2ee"].as_bool().unwrap_or(false)
    }

    /// The user key, if unlocked on this device.
    pub async fn e2ee_user_key(&self) -> Result<Option<UserKeyPair>> {
        stored_user_key(&self.store, self.e2ee_user()?).await
    }

    pub async fn e2ee_status(&self) -> Result<E2eeStatus> {
        self.api.get("/api/v1/me/e2ee").await
    }

    /// Creates the user key: a recovery key (returned once, to be written
    /// down) and, optionally, a passphrase to unlock other devices.
    pub async fn e2ee_setup(
        &self,
        passphrase: Option<&str>,
    ) -> Result<(UserKeyInfo, Zeroizing<String>)> {
        let user = self.e2ee_user()?;
        let key = UserKeyPair::generate();
        let recovery = RecoveryKey::generate();
        let mut seals = vec![e2ee::seal_with_recovery(user, &key, &recovery)?];
        if let Some(p) = passphrase.filter(|p| !p.is_empty()) {
            seals.push(e2ee::seal_with_passphrase(user, &key, p)?);
        }
        let info: UserKeyInfo = self
            .api
            .put(
                "/api/v1/me/e2ee",
                &json!({"key_id": key.id, "public_key": key.public_b64(), "seals": seals}),
            )
            .await?;
        store_user_key(&self.store, user, &key).await?;
        Ok((info, recovery.display()))
    }

    async fn unlock_with(
        &self,
        open: impl FnOnce(Id, &UserKeyInfo, &[KeySeal]) -> termoak_core::Result<UserKeyPair>,
    ) -> Result<usize> {
        let user = self.e2ee_user()?;
        let st = self.e2ee_status().await?;
        let info = st.key.ok_or_else(|| {
            CoreError::vault(codes::E2EE_NOT_SET_UP, "set up end-to-end encryption first")
        })?;
        let key = open(user, &info, &st.seals)?;
        store_user_key(&self.store, user, &key).await?;
        open_stored(&self.store, user).await
    }

    /// Unlocks this device with the E2EE passphrase. Returns how many
    /// stored secrets it opened (a sync opens the rest).
    pub async fn e2ee_unlock_passphrase(&self, passphrase: &str) -> Result<usize> {
        let pass = passphrase.to_string();
        self.unlock_with(move |user, info, seals| {
            let seal = seals
                .iter()
                .find(|s| s.kind == SealKind::Passphrase)
                .ok_or_else(|| {
                    CoreError::vault(
                        codes::E2EE_PASSPHRASE_INVALID,
                        "no passphrase is set: use the recovery key or another device",
                    )
                })?;
            let public = e2ee::parse_public_key(&info.public_key)?;
            e2ee::open_with_passphrase(user, info.id, seal, &pass, Some(&public))
        })
        .await
    }

    /// Unlocks this device with the recovery key.
    pub async fn e2ee_unlock_recovery(&self, recovery_key: &str) -> Result<usize> {
        let rk = RecoveryKey::parse(recovery_key)?;
        self.unlock_with(move |user, info, seals| {
            let seal = seals
                .iter()
                .find(|s| s.kind == SealKind::Recovery)
                .ok_or_else(|| {
                    CoreError::vault(codes::E2EE_RECOVERY_KEY_INVALID, "no recovery key is set")
                })?;
            let public = e2ee::parse_public_key(&info.public_key)?;
            e2ee::open_with_recovery(user, info.id, seal, &rk, Some(&public))
        })
        .await
    }

    /// Locks this device: forgets the user key and the opened secrets of
    /// E2EE vaults (downloaded sealed again at the next sync).
    pub async fn e2ee_lock(&self) -> Result<()> {
        forget_user_key(&self.store).await?;
        let vaults = self.store.local_vault_list().await?;
        for v in vaults.iter().filter(|v| v.crypto == VaultCrypto::E2ee) {
            self.store.forget_vault_secrets(v.id).await?;
        }
        Ok(())
    }

    /// Sets (or changes) the E2EE passphrase (unlocked devices).
    pub async fn e2ee_set_passphrase(&self, passphrase: &str) -> Result<()> {
        let user = self.e2ee_user()?;
        let key = self.e2ee_user_key().await?.ok_or_else(not_unlocked)?;
        let seal = e2ee::seal_with_passphrase(user, &key, passphrase)?;
        let _: Value = self
            .api
            .put(
                "/api/v1/me/e2ee/seals",
                &json!({"key_id": key.id, "seal": seal}),
            )
            .await?;
        Ok(())
    }

    /// A new recovery key (the old one stops working). Returned once.
    pub async fn e2ee_new_recovery_key(&self) -> Result<Zeroizing<String>> {
        let user = self.e2ee_user()?;
        let key = self.e2ee_user_key().await?.ok_or_else(not_unlocked)?;
        let rk = RecoveryKey::generate();
        let seal = e2ee::seal_with_recovery(user, &key, &rk)?;
        let _: Value = self
            .api
            .put(
                "/api/v1/me/e2ee/seals",
                &json!({"key_id": key.id, "seal": seal}),
            )
            .await?;
        Ok(rk.display())
    }

    /// Removes the E2EE passphrase (new devices then unlock with the
    /// recovery phrase or another device). Returns whether there was one.
    pub async fn e2ee_remove_passphrase(&self) -> Result<bool> {
        let v: Value = self.api.delete("/api/v1/me/e2ee/passphrase").await?;
        Ok(v["removed"].as_bool().unwrap_or(false))
    }

    /// Replaces the user key (a lost or stolen device): a new key with a new
    /// recovery phrase (returned once) and, optionally, a passphrase; every
    /// vault key the old key holds is wrapped again for the new one, on this
    /// device. Other devices of yours lock and must unlock again.
    pub async fn e2ee_rotate_user_key(
        &self,
        passphrase: Option<&str>,
    ) -> Result<(UserKeyInfo, Zeroizing<String>)> {
        let user = self.e2ee_user()?;
        let old = self.e2ee_user_key().await?.ok_or_else(not_unlocked)?;
        let key = UserKeyPair::generate();
        let recovery = RecoveryKey::generate();
        let mut seals = vec![e2ee::seal_with_recovery(user, &key, &recovery)?];
        if let Some(p) = passphrase.filter(|p| !p.is_empty()) {
            seals.push(e2ee::seal_with_passphrase(user, &key, p)?);
        }
        let vaults = self.api.vaults().await?;
        let mut wraps = Vec::new();
        for v in vaults.iter().filter(|v| v.crypto == VaultCrypto::E2ee) {
            let Some(info) = &v.e2ee else { continue };
            let (Some(w), Some(kid)) = (&info.wrap, info.key_id) else {
                continue;
            };
            if kid != old.id {
                continue;
            }
            let vk = e2ee::unwrap_vault_key(w, v.id, info.key_version, user, &old)?;
            wraps.push(json!({
                "vault_id": v.id,
                "version": info.key_version,
                "wrapped": e2ee::wrap_vault_key(&vk, v.id, info.key_version, user, key.id, key.public())?,
            }));
        }
        let info: UserKeyInfo = self
            .api
            .post(
                "/api/v1/me/e2ee/rotate",
                &json!({
                    "old_key_id": old.id,
                    "key_id": key.id,
                    "public_key": key.public_b64(),
                    "seals": seals,
                    "wraps": wraps,
                }),
            )
            .await?;
        store_user_key(&self.store, user, &key).await?;
        Ok((info, recovery.display()))
    }

    /// Everything lost (no device, no recovery phrase): with `confirm`
    /// forgets the account's E2EE key, seals, pairings and wraps (and the
    /// key on this device); without it only lists the vaults nobody else
    /// could open any more. Returns those vault ids.
    pub async fn e2ee_reset(&self, confirm: bool) -> Result<Vec<Id>> {
        let path = if confirm {
            "/api/v1/me/e2ee?confirm=reset"
        } else {
            "/api/v1/me/e2ee"
        };
        let v: Value = self.api.delete(path).await?;
        if confirm {
            self.e2ee_lock().await?;
        }
        Ok(v["orphaned_vaults"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().and_then(|s| s.parse().ok()))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Whether a move or copy between these vaults of this account touches
    /// an end-to-end encrypted vault (then it is done on this device).
    pub async fn e2ee_involved(&self, sources: &std::collections::BTreeSet<Option<Id>>, target: Id) -> Result<bool> {
        let personal = self.user_id();
        let vaults = self.store.local_vault_list().await?;
        let e2ee = |id: Option<Id>| {
            let id = id.or(personal);
            vaults
                .iter()
                .any(|v| Some(v.id) == id && v.crypto == VaultCrypto::E2ee)
        };
        Ok(e2ee(Some(target)) || sources.iter().any(|v| e2ee(*v)))
    }

    // ---- pairing ----

    /// New device: asks the user's other devices for the user key. Keep
    /// the returned private pairing key until [`Self::e2ee_pairing_finish`].
    pub async fn e2ee_pairing_start(&self) -> Result<(PairingStart, Zeroizing<[u8; 32]>)> {
        let pk = PairingKey::generate();
        let p: E2eePairing = self
            .api
            .post(
                "/api/v1/me/e2ee/pairings",
                &json!({"public_key": pk.public_b64(), "device_name": crate::api::device_name()}),
            )
            .await?;
        Ok((
            PairingStart {
                id: p.id,
                code: e2ee::pairing_code(p.id, pk.public()),
                expires_at: p.expires_at,
            },
            pk.private_bytes(),
        ))
    }

    /// New device: checks the pairing; when approved, stores the user key
    /// (`Some(opened secrets)`); `None` while it waits. Denied or expired
    /// pairings fail with `e2ee_pairing_closed`.
    pub async fn e2ee_pairing_finish(
        &self,
        id: Id,
        pairing_key: &[u8; 32],
    ) -> Result<Option<usize>> {
        let user = self.e2ee_user()?;
        let p: E2eePairing = self
            .api
            .get(&format!("/api/v1/me/e2ee/pairings/{id}"))
            .await?;
        match p.status.as_str() {
            "pending" => Ok(None),
            "approved" => {
                let sealed = p.sealed.ok_or_else(|| {
                    ClientError::Invalid("the pairing came without the key".into())
                })?;
                let key = PairingKey::from_private(*pairing_key).open(user, id, &sealed)?;
                // The key must be the user's published one.
                let st = self.e2ee_status().await?;
                let published = st
                    .key
                    .ok_or_else(|| ClientError::Invalid("no published E2EE key".into()))?;
                if published.id != key.id
                    || e2ee::parse_public_key(&published.public_key)? != *key.public()
                {
                    return Err(CoreError::vault(
                        codes::E2EE_KEY_MISMATCH,
                        "the received key is not your published key",
                    )
                    .into());
                }
                store_user_key(&self.store, user, &key).await?;
                Ok(Some(open_stored(&self.store, user).await?))
            }
            _ => Err(CoreError::vault(
                codes::E2EE_PAIRING_CLOSED,
                "the pairing was denied or expired",
            )
            .into()),
        }
    }

    /// Unlocked device: pairings waiting for a decision, with their codes.
    pub async fn e2ee_pairings(&self) -> Result<Vec<PairingRequest>> {
        let list: Vec<E2eePairing> = self.api.get("/api/v1/me/e2ee/pairings").await?;
        Ok(list
            .into_iter()
            .filter_map(|p| {
                let pk = e2ee::parse_public_key(&p.public_key).ok()?;
                Some(PairingRequest {
                    code: e2ee::pairing_code(p.id, &pk),
                    pairing: p,
                })
            })
            .collect())
    }

    /// Unlocked device: approves a pairing (after the user compared the
    /// codes) or denies it.
    pub async fn e2ee_pairing_decide(&self, id: Id, approve: bool) -> Result<()> {
        let user = self.e2ee_user()?;
        let body = if approve {
            let key = self.e2ee_user_key().await?.ok_or_else(not_unlocked)?;
            let list: Vec<E2eePairing> = self.api.get("/api/v1/me/e2ee/pairings").await?;
            let p = list.into_iter().find(|p| p.id == id).ok_or_else(|| {
                CoreError::vault(codes::E2EE_PAIRING_CLOSED, "this pairing is closed")
            })?;
            let pk = e2ee::parse_public_key(&p.public_key)?;
            json!({"approve": true, "sealed": e2ee::pairing_seal(user, id, &pk, &key)?})
        } else {
            json!({"approve": false})
        };
        let _: Value = self
            .api
            .post(&format!("/api/v1/me/e2ee/pairings/{id}/decide"), &body)
            .await?;
        Ok(())
    }

    // ---- vaults ----

    pub async fn e2ee_vault_state(&self, vault: Id) -> Result<E2eeVaultState> {
        self.api.get(&format!("/api/v1/vaults/{vault}/e2ee")).await
    }

    async fn pins(&self) -> Result<BTreeMap<Id, String>> {
        Ok(self
            .store
            .meta_get(META_PINS)
            .await?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default())
    }

    async fn pin(&self, users: &[(Id, String)]) -> Result<()> {
        let mut pins = self.pins().await?;
        for (u, fp) in users {
            pins.insert(*u, fp.clone());
        }
        self.store
            .meta_set(META_PINS, &serde_json::to_string(&pins).unwrap_or_default())
            .await?;
        Ok(())
    }

    fn wraps_for(
        vk: &VaultKey,
        vault: Id,
        version: u32,
        recipients: &[termoak_core::model::E2eeRecipient],
    ) -> Result<Vec<E2eeWrap>> {
        recipients
            .iter()
            .map(|r| {
                let pk = e2ee::parse_public_key(&r.public_key)?;
                Ok(E2eeWrap {
                    user_id: r.user_id,
                    key_id: r.key_id,
                    wrapped: e2ee::wrap_vault_key(vk, vault, version, r.user_id, r.key_id, &pk)?,
                })
            })
            .collect()
    }

    fn sealed_items(
        vk: &VaultKey,
        vault: Id,
        version: u32,
        plain: &[(Id, EntityKind, Zeroizing<Vec<u8>>)],
        wanted: &[termoak_core::model::E2eeItem],
    ) -> Result<Vec<E2eeSealedItem>> {
        let have: HashMap<Id, &(Id, EntityKind, Zeroizing<Vec<u8>>)> =
            plain.iter().map(|p| (p.0, p)).collect();
        wanted
            .iter()
            .map(|w| {
                let (_, kind, json) = have.get(&w.id).ok_or_else(|| {
                    ClientError::from(CoreError::vault(
                        codes::E2EE_INCOMPLETE,
                        "an item with a secret is not on this device yet: sync and try again",
                    ))
                })?;
                Ok(E2eeSealedItem {
                    id: w.id,
                    kind: *kind,
                    blob_b64: e2ee::encrypt_secret(vk, vault, version, *kind, w.id, json)?,
                })
            })
            .collect()
    }

    /// Turns end-to-end encryption on for a vault this account manages:
    /// syncs, seals every secret with a new vault key on this device and
    /// wraps it for `include` (members who may hold it, by user id; the
    /// others can be added later with [`Self::e2ee_add_members`]) and you.
    pub async fn e2ee_enable_vault(&self, vault: Id, include: Option<Vec<Id>>) -> Result<u32> {
        let user = self.e2ee_user()?;
        let key = self.e2ee_user_key().await?.ok_or_else(not_unlocked)?;
        self.sync_once().await?;
        let st = self.e2ee_vault_state(vault).await?;
        if st.crypto == VaultCrypto::E2ee {
            return Err(CoreError::vault(
                codes::E2EE_ALREADY_ENABLED,
                "the vault is already end-to-end encrypted",
            )
            .into());
        }
        let version = st.next_version;
        let vk = VaultKey::generate();
        let recipients: Vec<_> = st
            .recipients
            .iter()
            .filter(|r| {
                r.user_id == user || include.as_ref().is_none_or(|ids| ids.contains(&r.user_id))
            })
            .filter(|r| r.user_id != user || r.key_id == key.id)
            .cloned()
            .collect();
        if !recipients.iter().any(|r| r.user_id == user) {
            return Err(CoreError::vault(
                codes::E2EE_KEY_MISMATCH,
                "your published E2EE key is not the one on this device",
            )
            .into());
        }
        let wraps = Self::wraps_for(&vk, vault, version, &recipients)?;
        let plain = self.store.vault_secrets_plain(vault).await?;
        let items = Self::sealed_items(&vk, vault, version, &plain, &st.items)?;
        let _: Value = self
            .api
            .post(
                &format!("/api/v1/vaults/{vault}/e2ee/enable"),
                &json!({"version": version, "wraps": wraps, "items": items}),
            )
            .await?;
        self.pin(
            &recipients
                .iter()
                .map(|r| (r.user_id, r.fingerprint.clone()))
                .collect::<Vec<_>>(),
        )
        .await?;
        self.sync_once().await?;
        Ok(version)
    }

    /// The current vault key of an E2EE vault, opened on this device.
    async fn current_vault_key(&self, vault: Id) -> Result<(u32, VaultKey)> {
        let user = self.e2ee_user()?;
        let key = self.e2ee_user_key().await?.ok_or_else(not_unlocked)?;
        let v: Vault = self.api.get(&format!("/api/v1/vaults/{vault}")).await?;
        let keys = VaultKeys::from_vaults(std::slice::from_ref(&v), user, Some(&key));
        match keys.vaults.get(&vault) {
            Some((version, Some(vk))) => Ok((*version, vk.clone())),
            Some(_) => Err(CoreError::vault(
                codes::E2EE_LOCKED,
                "you do not hold this vault's key yet",
            )
            .into()),
            None => Err(CoreError::vault(
                codes::E2EE_NOT_ENABLED,
                "this vault is not end-to-end encrypted",
            )
            .into()),
        }
    }

    /// Rotates the key of an E2EE vault (after someone lost access): every
    /// secret sealed again with a new key, wrapped for the members who
    /// still hold it.
    pub async fn e2ee_rotate_vault(&self, vault: Id) -> Result<u32> {
        self.sync_once().await?;
        let user = self.e2ee_user()?;
        let (current, _) = self.current_vault_key(vault).await?;
        let st = self.e2ee_vault_state(vault).await?;
        let v: Vault = self.api.get(&format!("/api/v1/vaults/{vault}")).await?;
        let pending: Vec<Id> = v
            .e2ee
            .as_ref()
            .map(|e| e.pending.iter().map(|p| p.user_id).collect())
            .unwrap_or_default();
        // Holders keep the key; members still waiting stay waiting.
        let recipients: Vec<_> = st
            .recipients
            .iter()
            .filter(|r| r.user_id == user || !pending.contains(&r.user_id))
            .cloned()
            .collect();
        let version = current + 1;
        let vk = VaultKey::generate();
        let wraps = Self::wraps_for(&vk, vault, version, &recipients)?;
        let plain = self.store.vault_secrets_plain(vault).await?;
        let items = Self::sealed_items(&vk, vault, version, &plain, &st.items)?;
        let _: Value = self
            .api
            .post(
                &format!("/api/v1/vaults/{vault}/e2ee/rotate"),
                &json!({"from_version": current, "wraps": wraps, "items": items}),
            )
            .await?;
        self.sync_once().await?;
        Ok(version)
    }

    /// Turns end-to-end encryption off (the server can read the secrets
    /// again): this device sends them in plaintext over TLS.
    pub async fn e2ee_disable_vault(&self, vault: Id) -> Result<()> {
        self.sync_once().await?;
        let st = self.e2ee_vault_state(vault).await?;
        let plain = self.store.vault_secrets_plain(vault).await?;
        let have: HashMap<Id, &(Id, EntityKind, Zeroizing<Vec<u8>>)> =
            plain.iter().map(|p| (p.0, p)).collect();
        let mut items = Vec::new();
        for w in &st.items {
            let (_, kind, json) = have.get(&w.id).ok_or_else(|| {
                ClientError::from(CoreError::vault(
                    codes::E2EE_LOCKED,
                    "a secret of this vault is still locked on this device",
                ))
            })?;
            items.push(E2eePlainItem {
                id: w.id,
                kind: *kind,
                secret: serde_json::from_slice(json)
                    .map_err(|e| ClientError::Invalid(e.to_string()))?,
            });
        }
        let _: Value = self
            .api
            .post(
                &format!("/api/v1/vaults/{vault}/e2ee/disable"),
                &json!({"items": items}),
            )
            .await?;
        self.sync_once().await?;
        Ok(())
    }

    /// Members waiting for the key of a vault this device holds, with a
    /// warning when their key is not the one this device saw before.
    pub async fn e2ee_pending_members(&self, vault: Id) -> Result<Vec<PendingMember>> {
        let v: Vault = self.api.get(&format!("/api/v1/vaults/{vault}")).await?;
        let pins = self.pins().await?;
        Ok(v.e2ee
            .map(|e| e.pending)
            .unwrap_or_default()
            .into_iter()
            .map(|r| PendingMember {
                key_changed: pins.get(&r.user_id).is_some_and(|fp| *fp != r.fingerprint),
                recipient: r,
            })
            .collect())
    }

    /// Gives the vault key to waiting members (after checking their key
    /// fingerprints): `users`, or every waiting member.
    pub async fn e2ee_add_members(&self, vault: Id, users: Option<Vec<Id>>) -> Result<usize> {
        let (version, vk) = self.current_vault_key(vault).await?;
        let pending = self.e2ee_pending_members(vault).await?;
        let recipients: Vec<_> = pending
            .into_iter()
            .map(|p| p.recipient)
            .filter(|r| users.as_ref().is_none_or(|u| u.contains(&r.user_id)))
            .collect();
        if recipients.is_empty() {
            return Ok(0);
        }
        let wraps = Self::wraps_for(&vk, vault, version, &recipients)?;
        let _: Value = self
            .api
            .post(
                &format!("/api/v1/vaults/{vault}/e2ee/wraps"),
                &json!({"version": version, "wraps": wraps}),
            )
            .await?;
        self.pin(
            &recipients
                .iter()
                .map(|r| (r.user_id, r.fingerprint.clone()))
                .collect::<Vec<_>>(),
        )
        .await?;
        Ok(recipients.len())
    }

    /// The credentials of a host of an E2EE vault, resolved on this device,
    /// to send for one server session/host test/exec (`unlock`): the
    /// server uses them for that one connection and never stores them.
    pub async fn e2ee_unlock_for(&self, resolved: &termoak_core::resolve::ResolvedHost) -> Value {
        let hop = |h: &termoak_core::resolve::ResolvedHost| {
            json!({
                "host_id": h.host.id,
                "password": h.password,
                "key": h.key.as_ref().map(|k| json!({"private_key": k.private_key, "passphrase": k.passphrase})),
                "proxy_password": h.proxy.as_ref().and_then(|p| p.password.clone()),
            })
        };
        let mut hops: Vec<Value> = resolved.jumps.iter().map(hop).collect();
        hops.push(hop(resolved));
        json!({"hops": hops})
    }
}

/// The error of a host that needs a locked secret (no credential at all
/// for a hop that resolved without its E2EE secret).
pub(crate) fn check_unlocked(resolved: &termoak_core::resolve::ResolvedHost) -> Result<()> {
    let missing = std::iter::once(resolved)
        .chain(resolved.jumps.iter())
        .any(|h| h.e2ee_locked && h.password.is_none() && h.key.is_none());
    if missing {
        return Err(CoreError::vault(
            codes::E2EE_LOCKED,
            "this host's credentials are end-to-end encrypted: unlock E2EE on this device",
        )
        .into());
    }
    Ok(())
}

/// Number of secrets of E2EE vaults still sealed in a store.
pub async fn locked_count(store: &Store) -> Result<usize> {
    Ok(store.e2ee_sealed_rows(None).await?.len())
}

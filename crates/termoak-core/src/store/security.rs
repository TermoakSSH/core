//! Teams security storage (0.7 phase 4b, docs-next/TEAMS-SECURITY.md §8):
//! SSH certificate authorities (the private key sealed with the master
//! key), issued certificates, revoked keys, team policies and member
//! principals, access policies and temporary access requests.
//!
//! Server data. The rules (who may do what) live in the server; this layer
//! keeps the state transitions atomic (a request is decided once).

use rusqlite::{Connection, OptionalExtension, params};
use zeroize::Zeroizing;

use super::{Store, parse_id, parse_opt_id};
use crate::access::{
    AccessPolicy, AccessPolicyRecord, AccessRequest, AccessRequestStatus, AccessTargetKind, CaInfo,
    CaStatus, IssuedCertificate, TeamPolicy,
};
use crate::error::{CoreError, Result, codes};
use crate::time::now_ms;
use crate::{Id, new_id};

/// Who a CA belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaOwner {
    Team(Id),
    User(Id),
}

impl CaOwner {
    pub fn id(self) -> Id {
        match self {
            CaOwner::Team(i) | CaOwner::User(i) => i,
        }
    }

    fn column(self) -> &'static str {
        match self {
            CaOwner::Team(_) => "owner_team_id",
            CaOwner::User(_) => "owner_user_id",
        }
    }
}

/// A new CA key (made by the caller; the store seals the private key).
pub struct NewCa {
    pub algorithm: String,
    pub public_key: String,
    pub fingerprint: String,
    /// OpenSSH private key.
    pub private_key: Zeroizing<String>,
    pub created_by: Id,
}

/// Where a certificate is going (for its record).
#[derive(Debug, Clone, Default)]
pub struct NewCert {
    pub ca_id: Id,
    pub user_id: Id,
    pub vault_id: Option<Id>,
    pub host_id: Option<Id>,
    pub request_id: Option<Id>,
    pub device_id: Option<Id>,
    pub purpose: String,
    pub key_fingerprint: String,
    pub principals: Vec<String>,
    pub valid_after: i64,
    pub valid_before: i64,
}

/// Which certificates to revoke.
#[derive(Debug, Clone, Copy)]
pub enum CertSelector {
    Serial(i64),
    /// Every unexpired certificate of a user from this owner's CAs.
    User(Id),
    /// Every certificate issued under an access request.
    Request(Id),
}

/// Filter of a certificate listing.
#[derive(Debug, Clone, Default)]
pub struct CertFilter {
    pub owner: Option<CaOwner>,
    pub user: Option<Id>,
    pub active_only: bool,
    pub limit: usize,
}

/// Filter of an access request listing.
#[derive(Debug, Clone, Default)]
pub struct RequestFilter {
    pub requester: Option<Id>,
    /// Requests in any of these vaults.
    pub vaults: Option<Vec<Id>>,
    pub status: Option<AccessRequestStatus>,
    pub limit: usize,
}

/// A member of a team with what the 2FA policy needs.
#[derive(Debug, Clone)]
pub struct ComplianceRow {
    pub user_id: Id,
    pub email: String,
    pub name: String,
    pub role: crate::model::TeamRole,
    pub added_at: i64,
    pub totp_enabled: bool,
}

fn ca_aad(id: Id) -> Vec<u8> {
    format!("termoak:ssh-ca:{id}").into_bytes()
}

const CA_COLUMNS: &str = "id, owner_team_id, owner_user_id, algorithm, public_key, fingerprint, \
     status, created_by, created_at, retire_at, retired_at";

fn map_ca(r: &rusqlite::Row<'_>) -> rusqlite::Result<CaInfo> {
    Ok(CaInfo {
        id: parse_id(&r.get::<_, String>(0)?)?,
        owner_team_id: parse_opt_id(r.get(1)?)?,
        owner_user_id: parse_opt_id(r.get(2)?)?,
        algorithm: r.get(3)?,
        public_key: r.get(4)?,
        fingerprint: r.get(5)?,
        status: CaStatus::parse(&r.get::<_, String>(6)?),
        created_by: parse_id(&r.get::<_, String>(7)?)?,
        created_at: r.get(8)?,
        retire_at: r.get(9)?,
        retired_at: r.get(10)?,
    })
}

const CERT_COLUMNS: &str = "c.serial, c.ca_id, c.user_id, u.email, c.vault_id, c.host_id, \
     c.request_id, c.device_id, c.purpose, c.key_fingerprint, c.key_id, c.principals, \
     c.valid_after, c.valid_before, c.created_at, c.revoked_at, c.revoked_by, c.revoke_reason";

fn map_cert(r: &rusqlite::Row<'_>) -> rusqlite::Result<IssuedCertificate> {
    let principals: String = r.get(11)?;
    Ok(IssuedCertificate {
        serial: r.get(0)?,
        ca_id: parse_id(&r.get::<_, String>(1)?)?,
        user_id: parse_id(&r.get::<_, String>(2)?)?,
        user_email: r.get(3)?,
        vault_id: parse_opt_id(r.get(4)?)?,
        host_id: parse_opt_id(r.get(5)?)?,
        request_id: parse_opt_id(r.get(6)?)?,
        device_id: parse_opt_id(r.get(7)?)?,
        purpose: r.get(8)?,
        key_fingerprint: r.get(9)?,
        key_id: r.get(10)?,
        principals: serde_json::from_str(&principals).unwrap_or_default(),
        valid_after: r.get(12)?,
        valid_before: r.get(13)?,
        created_at: r.get(14)?,
        revoked_at: r.get(15)?,
        revoked_by: parse_opt_id(r.get(16)?)?,
        revoke_reason: r.get(17)?,
    })
}

const REQUEST_COLUMNS: &str = "r.id, r.vault_id, r.target_kind, r.target_id, r.target_label, \
     r.requester_id, COALESCE(u.name, ''), COALESCE(u.email, ''), r.reason, r.minutes, r.status, \
     r.created_at, r.expires_at, r.decided_by, d.name, r.decided_at, r.decision_reason, \
     r.starts_at, r.ends_at, r.self_approved";

const REQUEST_FROM: &str = "FROM access_requests r
     LEFT JOIN users u ON u.id = r.requester_id
     LEFT JOIN users d ON d.id = r.decided_by";

fn map_request(r: &rusqlite::Row<'_>) -> rusqlite::Result<AccessRequest> {
    let mut req = AccessRequest {
        id: parse_id(&r.get::<_, String>(0)?)?,
        vault_id: parse_id(&r.get::<_, String>(1)?)?,
        target_kind: AccessTargetKind::parse(&r.get::<_, String>(2)?),
        target_id: parse_id(&r.get::<_, String>(3)?)?,
        target_label: r.get(4)?,
        requester_id: parse_id(&r.get::<_, String>(5)?)?,
        requester_name: r.get(6)?,
        requester_email: r.get(7)?,
        reason: r.get(8)?,
        minutes: r.get(9)?,
        status: AccessRequestStatus::parse(&r.get::<_, String>(10)?),
        created_at: r.get(11)?,
        expires_at: r.get(12)?,
        decided_by: parse_opt_id(r.get(13)?)?,
        decided_by_name: r.get(14)?,
        decided_at: r.get(15)?,
        decision_reason: r.get(16)?,
        starts_at: r.get(17)?,
        ends_at: r.get(18)?,
        self_approved: r.get::<_, i64>(19)? != 0,
        active: false,
    };
    req.active = req.is_active(now_ms());
    Ok(req)
}

fn load_request(conn: &Connection, id: Id) -> Result<AccessRequest> {
    conn.query_row(
        &format!("SELECT {REQUEST_COLUMNS} {REQUEST_FROM} WHERE r.id = ?1"),
        [id.to_string()],
        map_request,
    )
    .optional()?
    .ok_or_else(|| CoreError::NotFound(format!("access request {id}")))
}

fn closed(status: AccessRequestStatus) -> CoreError {
    CoreError::vault_detail(
        codes::ACCESS_REQUEST_CLOSED,
        format!("the request is already {}", status.as_str()),
        serde_json::json!({"status": status}),
    )
}

fn map_policy(r: &rusqlite::Row<'_>) -> rusqlite::Result<AccessPolicyRecord> {
    let policy: String = r.get(4)?;
    Ok(AccessPolicyRecord {
        id: parse_id(&r.get::<_, String>(0)?)?,
        vault_id: parse_id(&r.get::<_, String>(1)?)?,
        target_kind: AccessTargetKind::parse(&r.get::<_, String>(2)?),
        target_id: parse_id(&r.get::<_, String>(3)?)?,
        // An unreadable policy (a later version's) fails closed.
        policy: serde_json::from_str(&policy).unwrap_or(AccessPolicy {
            mode: crate::access::AccessMode::Unknown,
            ..Default::default()
        }),
        updated_by: parse_id(&r.get::<_, String>(5)?)?,
        updated_at: r.get(6)?,
    })
}

impl Store {
    // ----- Team policy and principals -----

    /// A team's policy (defaults when it has none).
    pub async fn team_policy(&self, team: Id) -> Result<TeamPolicy> {
        self.call(move |c, _| {
            let p: Option<String> = c
                .query_row(
                    "SELECT policy FROM teams WHERE id = ?1",
                    [team.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            let p = p.ok_or_else(|| CoreError::NotFound("team not found".into()))?;
            Ok(serde_json::from_str(&p).unwrap_or_default())
        })
        .await
    }

    /// Replaces a team's policy (validated by the caller). Bumps the access
    /// cache and the revision of the team's vaults (members re-sync their
    /// effective policy). Returns the team's vault ids.
    pub async fn set_team_policy(&self, team: Id, policy: TeamPolicy) -> Result<Vec<Id>> {
        let json = serde_json::to_string(&policy)?;
        let vaults = self
            .call(move |c, _| {
                let tx = c.transaction()?;
                let n = tx.execute(
                    "UPDATE teams SET policy = ?2 WHERE id = ?1",
                    params![team.to_string(), json],
                )?;
                if n == 0 {
                    return Err(CoreError::NotFound("team not found".into()));
                }
                let ids = super::vaults::team_vault_ids(&tx, &team.to_string())?;
                for v in &ids {
                    let rev = super::next_rev(&tx)?;
                    tx.execute(
                        "UPDATE vaults SET rev = ?2, updated_at = ?3 WHERE id = ?1",
                        params![v, rev, now_ms()],
                    )?;
                }
                tx.commit()?;
                ids.iter()
                    .map(|v| parse_id(v).map_err(CoreError::from))
                    .collect::<Result<Vec<_>>>()
            })
            .await?;
        self.bump_access();
        Ok(vaults)
    }

    /// The certificate principal an admin set for a team member.
    pub async fn team_member_principal(&self, team: Id, user: Id) -> Result<Option<String>> {
        self.call(move |c, _| {
            Ok(c.query_row(
                "SELECT principal FROM team_members WHERE team_id = ?1 AND user_id = ?2",
                params![team.to_string(), user.to_string()],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten())
        })
        .await
    }

    /// Sets (or clears) a team member's certificate principal.
    pub async fn set_team_member_principal(
        &self,
        team: Id,
        user: Id,
        principal: Option<String>,
    ) -> Result<()> {
        self.call(move |c, _| {
            let n = c.execute(
                "UPDATE team_members SET principal = ?3 WHERE team_id = ?1 AND user_id = ?2",
                params![team.to_string(), user.to_string(), principal],
            )?;
            if n == 0 {
                return Err(CoreError::NotFound("team member not found".into()));
            }
            Ok(())
        })
        .await
    }

    /// Members of a team with their 2FA state.
    pub async fn team_compliance(&self, team: Id) -> Result<Vec<ComplianceRow>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(
                "SELECT u.id, u.email, u.name, tm.role, tm.added_at, u.totp_enabled
                 FROM team_members tm JOIN users u ON u.id = tm.user_id
                 WHERE tm.team_id = ?1 ORDER BY u.name, u.email",
            )?;
            let rows = stmt
                .query_map([team.to_string()], |r| {
                    Ok(ComplianceRow {
                        user_id: parse_id(&r.get::<_, String>(0)?)?,
                        email: r.get(1)?,
                        name: r.get(2)?,
                        role: crate::model::TeamRole::parse(&r.get::<_, String>(3)?),
                        added_at: r.get(4)?,
                        totp_enabled: r.get::<_, i64>(5)? != 0,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    /// Teams of `user` with their policy and the user's join time.
    pub async fn teams_with_policy(&self, user: Id) -> Result<Vec<(Id, String, TeamPolicy, i64)>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(
                "SELECT t.id, t.name, t.policy, tm.added_at
                 FROM team_members tm JOIN teams t ON t.id = tm.team_id
                 WHERE tm.user_id = ?1",
            )?;
            let rows = stmt
                .query_map([user.to_string()], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows.into_iter()
                .map(|(id, name, p, at)| {
                    Ok((
                        parse_id(&id)?,
                        name,
                        serde_json::from_str(&p).unwrap_or_default(),
                        at,
                    ))
                })
                .collect()
        })
        .await
    }

    // ----- Certificate authorities -----

    /// Creates the active CA of an owner (`ca_exists` if there is one).
    pub async fn create_ca(&self, owner: CaOwner, ca: NewCa) -> Result<CaInfo> {
        self.call(move |c, master| {
            let tx = c.transaction()?;
            let exists: Option<String> = tx
                .query_row(
                    &format!(
                        "SELECT id FROM ssh_cas WHERE {} = ?1 AND status = 'active'",
                        owner.column()
                    ),
                    [owner.id().to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            if exists.is_some() {
                return Err(CoreError::vault(
                    codes::CA_EXISTS,
                    "a certificate authority already exists",
                ));
            }
            let info = insert_ca(&tx, master, owner, &ca)?;
            tx.commit()?;
            Ok(info)
        })
        .await
    }

    /// Rotates: the new CA becomes active, the active one retires at
    /// `retire_at` (published until then).
    pub async fn rotate_ca(&self, owner: CaOwner, ca: NewCa, retire_at: i64) -> Result<CaInfo> {
        self.call(move |c, master| {
            let tx = c.transaction()?;
            let n = tx.execute(
                &format!(
                    "UPDATE ssh_cas SET status = 'retiring', retire_at = ?2
                     WHERE {} = ?1 AND status = 'active'",
                    owner.column()
                ),
                params![owner.id().to_string(), retire_at],
            )?;
            if n == 0 {
                return Err(CoreError::vault(
                    codes::CA_NOT_CONFIGURED,
                    "there is no certificate authority to rotate",
                ));
            }
            let info = insert_ca(&tx, master, owner, &ca)?;
            tx.commit()?;
            Ok(info)
        })
        .await
    }

    /// Retires every CA of an owner at once. Returns how many.
    pub async fn disable_ca(&self, owner: CaOwner) -> Result<usize> {
        self.call(move |c, _| {
            Ok(c.execute(
                &format!(
                    "UPDATE ssh_cas SET status = 'retired', retired_at = ?2
                     WHERE {} = ?1 AND status != 'retired'",
                    owner.column()
                ),
                params![owner.id().to_string(), now_ms()],
            )?)
        })
        .await
    }

    /// Published CAs of an owner (active first, then retiring).
    pub async fn cas_of(&self, owner: CaOwner) -> Result<Vec<CaInfo>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(&format!(
                "SELECT {CA_COLUMNS} FROM ssh_cas WHERE {} = ?1 AND status != 'retired'
                 ORDER BY CASE status WHEN 'active' THEN 0 ELSE 1 END, created_at DESC",
                owner.column()
            ))?;
            let rows = stmt
                .query_map([owner.id().to_string()], map_ca)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    /// Every CA of an owner (also retired), newest first.
    pub async fn ca_history(&self, owner: CaOwner) -> Result<Vec<CaInfo>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(&format!(
                "SELECT {CA_COLUMNS} FROM ssh_cas WHERE {} = ?1 ORDER BY created_at DESC",
                owner.column()
            ))?;
            let rows = stmt
                .query_map([owner.id().to_string()], map_ca)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    /// The active CA of an owner with its private key (OpenSSH).
    pub async fn active_ca(&self, owner: CaOwner) -> Result<Option<(CaInfo, Zeroizing<String>)>> {
        self.call(move |c, master| {
            let row: Option<(CaInfo, Vec<u8>)> = c
                .query_row(
                    &format!(
                        "SELECT {CA_COLUMNS}, private_key FROM ssh_cas
                         WHERE {} = ?1 AND status = 'active'",
                        owner.column()
                    ),
                    [owner.id().to_string()],
                    |r| Ok((map_ca(r)?, r.get(11)?)),
                )
                .optional()?;
            let Some((info, sealed)) = row else {
                return Ok(None);
            };
            let plain = master.open(&sealed, &ca_aad(info.id))?;
            let pem = String::from_utf8(plain.to_vec())
                .map_err(|_| CoreError::Crypto("invalid CA key".into()))?;
            Ok(Some((info, Zeroizing::new(pem))))
        })
        .await
    }

    /// Retires the CAs whose overlap ended. Returns how many.
    pub async fn retire_due_cas(&self, now: i64) -> Result<usize> {
        self.call(move |c, _| {
            Ok(c.execute(
                "UPDATE ssh_cas SET status = 'retired', retired_at = ?1
                 WHERE status = 'retiring' AND retire_at <= ?1",
                [now],
            )?)
        })
        .await
    }

    /// Fingerprints of every CA key of this server (no certificate for
    /// them).
    pub async fn ca_fingerprints(&self) -> Result<Vec<String>> {
        self.call(|c, _| {
            let mut stmt = c.prepare("SELECT fingerprint FROM ssh_cas")?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    // ----- Certificates -----

    /// Reserves a serial for a certificate about to be signed (its row
    /// without a key id). Finish with [`Store::finish_certificate`] or drop
    /// it with [`Store::drop_certificate`].
    pub async fn reserve_certificate(&self, cert: NewCert) -> Result<i64> {
        self.call(move |c, _| {
            c.execute(
                "INSERT INTO ssh_certs (ca_id, user_id, vault_id, host_id, request_id, device_id,
                                        purpose, key_fingerprint, key_id, principals, valid_after,
                                        valid_before, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, '', ?9, ?10, ?11, ?12)",
                params![
                    cert.ca_id.to_string(),
                    cert.user_id.to_string(),
                    cert.vault_id.map(|v| v.to_string()),
                    cert.host_id.map(|v| v.to_string()),
                    cert.request_id.map(|v| v.to_string()),
                    cert.device_id.map(|v| v.to_string()),
                    cert.purpose,
                    cert.key_fingerprint,
                    serde_json::to_string(&cert.principals)?,
                    cert.valid_after,
                    cert.valid_before,
                    now_ms()
                ],
            )?;
            Ok(c.last_insert_rowid())
        })
        .await
    }

    pub async fn finish_certificate(&self, serial: i64, key_id: &str) -> Result<()> {
        let key_id = key_id.to_string();
        self.call(move |c, _| {
            c.execute(
                "UPDATE ssh_certs SET key_id = ?2 WHERE serial = ?1",
                params![serial, key_id],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn drop_certificate(&self, serial: i64) -> Result<()> {
        self.call(move |c, _| {
            c.execute("DELETE FROM ssh_certs WHERE serial = ?1", [serial])?;
            Ok(())
        })
        .await
    }

    /// One issued certificate.
    pub async fn certificate(&self, serial: i64) -> Result<IssuedCertificate> {
        self.call(move |c, _| {
            c.query_row(
                &format!(
                    "SELECT {CERT_COLUMNS} FROM ssh_certs c LEFT JOIN users u ON u.id = c.user_id
                     WHERE c.serial = ?1"
                ),
                [serial],
                map_cert,
            )
            .optional()?
            .ok_or_else(|| CoreError::NotFound(format!("certificate {serial}")))
        })
        .await
    }

    /// Issued certificates, newest first.
    pub async fn certificates(&self, filter: CertFilter) -> Result<Vec<IssuedCertificate>> {
        self.call(move |c, _| {
            let mut sql = format!(
                "SELECT {CERT_COLUMNS} FROM ssh_certs c LEFT JOIN users u ON u.id = c.user_id
                 WHERE c.key_id != ''"
            );
            let mut args: Vec<rusqlite::types::Value> = Vec::new();
            if let Some(owner) = filter.owner {
                sql.push_str(&format!(
                    " AND c.ca_id IN (SELECT id FROM ssh_cas WHERE {} = ?)",
                    owner.column()
                ));
                args.push(owner.id().to_string().into());
            }
            if let Some(u) = filter.user {
                sql.push_str(" AND c.user_id = ?");
                args.push(u.to_string().into());
            }
            if filter.active_only {
                sql.push_str(" AND c.revoked_at IS NULL AND c.valid_before > ?");
                args.push(now_ms().into());
            }
            sql.push_str(" ORDER BY c.serial DESC LIMIT ?");
            args.push((filter.limit.clamp(1, 1000) as i64).into());
            let mut stmt = c.prepare(&sql)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(args), map_cert)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    /// Revokes certificates of an owner's CAs (only those not revoked or
    /// expired yet). Returns the revoked serials.
    pub async fn revoke_certificates(
        &self,
        owner: Option<CaOwner>,
        sel: CertSelector,
        by: Id,
        reason: Option<String>,
    ) -> Result<Vec<i64>> {
        self.call(move |c, _| {
            let now = now_ms();
            let mut sql = String::from(
                "UPDATE ssh_certs SET revoked_at = ?1, revoked_by = ?2, revoke_reason = ?3
                 WHERE revoked_at IS NULL AND valid_before > ?1",
            );
            let mut args: Vec<rusqlite::types::Value> =
                vec![now.into(), by.to_string().into(), reason.into()];
            match sel {
                CertSelector::Serial(s) => {
                    sql.push_str(" AND serial = ?4");
                    args.push(s.into());
                }
                CertSelector::User(u) => {
                    sql.push_str(" AND user_id = ?4");
                    args.push(u.to_string().into());
                }
                CertSelector::Request(r) => {
                    sql.push_str(" AND request_id = ?4");
                    args.push(r.to_string().into());
                }
            }
            if let Some(owner) = owner {
                sql.push_str(&format!(
                    " AND ca_id IN (SELECT id FROM ssh_cas WHERE {} = ?5)",
                    owner.column()
                ));
                args.push(owner.id().to_string().into());
            }
            sql.push_str(" RETURNING serial");
            let mut stmt = c.prepare(&sql)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(args), |r| r.get::<_, i64>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    /// Revoked serials of a CA that have not expired yet (for the KRL).
    pub async fn revoked_serials(&self, ca: Id) -> Result<Vec<u64>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(
                "SELECT serial FROM ssh_certs
                 WHERE ca_id = ?1 AND revoked_at IS NOT NULL AND valid_before > ?2
                 ORDER BY serial",
            )?;
            let rows = stmt
                .query_map(params![ca.to_string(), now_ms()], |r| r.get::<_, i64>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows.into_iter().map(|s| s as u64).collect())
        })
        .await
    }

    /// Revokes a public key for an owner (no new certificates; in the KRL).
    pub async fn revoke_key(
        &self,
        owner: CaOwner,
        fingerprint: &str,
        public_key: &str,
        by: Id,
        reason: Option<String>,
    ) -> Result<()> {
        let (fp, pk) = (fingerprint.to_string(), public_key.to_string());
        self.call(move |c, _| {
            c.execute(
                "INSERT INTO ssh_revoked_keys (owner_id, fingerprint, public_key, revoked_by,
                                               revoked_at, reason)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(owner_id, fingerprint) DO NOTHING",
                params![
                    owner.id().to_string(),
                    fp,
                    pk,
                    by.to_string(),
                    now_ms(),
                    reason
                ],
            )?;
            Ok(())
        })
        .await
    }

    /// Revoked public keys of an owner (OpenSSH lines).
    pub async fn revoked_keys(&self, owner: CaOwner) -> Result<Vec<String>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(
                "SELECT public_key FROM ssh_revoked_keys WHERE owner_id = ?1 ORDER BY revoked_at",
            )?;
            let rows = stmt
                .query_map([owner.id().to_string()], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    pub async fn is_key_revoked(&self, owner: CaOwner, fingerprint: &str) -> Result<bool> {
        let fp = fingerprint.to_string();
        self.call(move |c, _| {
            Ok(c.query_row(
                "SELECT 1 FROM ssh_revoked_keys WHERE owner_id = ?1 AND fingerprint = ?2",
                params![owner.id().to_string(), fp],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
        })
        .await
    }

    // ----- Access policies -----

    /// Access policies of a vault.
    pub async fn access_policies(&self, vault: Id) -> Result<Vec<AccessPolicyRecord>> {
        self.call(move |c, _| {
            let mut stmt = c.prepare(
                "SELECT id, vault_id, target_kind, target_id, policy, updated_by, updated_at
                 FROM access_policies WHERE vault_id = ?1 ORDER BY target_kind, updated_at",
            )?;
            let rows = stmt
                .query_map([vault.to_string()], map_policy)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    /// Vaults (of `vaults`) that have at least one access policy.
    pub async fn vaults_with_access_policies(&self, vaults: Vec<Id>) -> Result<Vec<Id>> {
        self.call(move |c, _| {
            let mut out = Vec::new();
            let mut stmt =
                c.prepare_cached("SELECT 1 FROM access_policies WHERE vault_id = ?1 LIMIT 1")?;
            for v in vaults {
                if stmt.exists([v.to_string()])? {
                    out.push(v);
                }
            }
            Ok(out)
        })
        .await
    }

    /// Creates or replaces the policy of a target (validated by the caller).
    pub async fn set_access_policy(
        &self,
        vault: Id,
        kind: AccessTargetKind,
        target: Id,
        policy: AccessPolicy,
        by: Id,
    ) -> Result<AccessPolicyRecord> {
        let json = serde_json::to_string(&policy)?;
        let rec = self
            .call(move |c, _| {
                let now = now_ms();
                c.execute(
                    "INSERT INTO access_policies (id, vault_id, target_kind, target_id, policy,
                                                  updated_by, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT(vault_id, target_kind, target_id) DO UPDATE SET
                        policy = excluded.policy, updated_by = excluded.updated_by,
                        updated_at = excluded.updated_at",
                    params![
                        new_id().to_string(),
                        vault.to_string(),
                        kind.as_str(),
                        target.to_string(),
                        json,
                        by.to_string(),
                        now
                    ],
                )?;
                Ok(c.query_row(
                    "SELECT id, vault_id, target_kind, target_id, policy, updated_by, updated_at
                     FROM access_policies
                     WHERE vault_id = ?1 AND target_kind = ?2 AND target_id = ?3",
                    params![vault.to_string(), kind.as_str(), target.to_string()],
                    map_policy,
                )?)
            })
            .await?;
        Ok(rec)
    }

    /// Deletes a policy of a vault. Returns it.
    pub async fn delete_access_policy(&self, vault: Id, id: Id) -> Result<AccessPolicyRecord> {
        self.call(move |c, _| {
            let rec = c
                .query_row(
                    "SELECT id, vault_id, target_kind, target_id, policy, updated_by, updated_at
                     FROM access_policies WHERE id = ?1 AND vault_id = ?2",
                    params![id.to_string(), vault.to_string()],
                    map_policy,
                )
                .optional()?
                .ok_or_else(|| CoreError::NotFound(format!("access policy {id}")))?;
            c.execute(
                "DELETE FROM access_policies WHERE id = ?1",
                [id.to_string()],
            )?;
            Ok(rec)
        })
        .await
    }

    // ----- Access requests -----

    /// Saves a new pending request (checks done by the caller). One pending
    /// request per requester and target: `access_request_exists` (detail
    /// `id`).
    pub async fn create_access_request(&self, req: AccessRequest) -> Result<AccessRequest> {
        self.call(move |c, _| {
            let tx = c.transaction()?;
            let existing: Option<String> = tx
                .query_row(
                    "SELECT id FROM access_requests
                     WHERE requester_id = ?1 AND target_kind = ?2 AND target_id = ?3
                       AND status = 'pending' AND expires_at > ?4",
                    params![
                        req.requester_id.to_string(),
                        req.target_kind.as_str(),
                        req.target_id.to_string(),
                        now_ms()
                    ],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(id) = existing {
                return Err(CoreError::vault_detail(
                    codes::ACCESS_REQUEST_EXISTS,
                    "you already asked for access to this",
                    serde_json::json!({"id": id}),
                ));
            }
            tx.execute(
                "INSERT INTO access_requests (id, vault_id, target_kind, target_id, target_label,
                                              requester_id, reason, minutes, status, created_at,
                                              expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', ?9, ?10)",
                params![
                    req.id.to_string(),
                    req.vault_id.to_string(),
                    req.target_kind.as_str(),
                    req.target_id.to_string(),
                    req.target_label,
                    req.requester_id.to_string(),
                    req.reason,
                    req.minutes,
                    req.created_at,
                    req.expires_at
                ],
            )?;
            let out = load_request(&tx, req.id)?;
            tx.commit()?;
            Ok(out)
        })
        .await
    }

    pub async fn access_request(&self, id: Id) -> Result<AccessRequest> {
        self.call(move |c, _| load_request(c, id)).await
    }

    /// Requests, newest first.
    pub async fn access_requests(&self, filter: RequestFilter) -> Result<Vec<AccessRequest>> {
        self.call(move |c, _| {
            let mut sql = format!("SELECT {REQUEST_COLUMNS} {REQUEST_FROM} WHERE 1 = 1");
            let mut args: Vec<rusqlite::types::Value> = Vec::new();
            if let Some(u) = filter.requester {
                sql.push_str(" AND r.requester_id = ?");
                args.push(u.to_string().into());
            }
            if let Some(vaults) = &filter.vaults {
                if vaults.is_empty() {
                    return Ok(Vec::new());
                }
                sql.push_str(&format!(
                    " AND r.vault_id IN ({})",
                    vec!["?"; vaults.len()].join(",")
                ));
                args.extend(vaults.iter().map(|v| v.to_string().into()));
            }
            if let Some(s) = filter.status {
                sql.push_str(" AND r.status = ?");
                args.push(s.as_str().to_string().into());
            }
            sql.push_str(" ORDER BY r.created_at DESC LIMIT ?");
            args.push((filter.limit.clamp(1, 500) as i64).into());
            let mut stmt = c.prepare(&sql)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(args), map_request)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    /// Approves a pending, unexpired request: window `[now, now + minutes)`.
    pub async fn approve_access_request(
        &self,
        id: Id,
        by: Id,
        minutes: u32,
        reason: Option<String>,
        self_approved: bool,
    ) -> Result<AccessRequest> {
        self.call(move |c, _| {
            let now = now_ms();
            let n = c.execute(
                "UPDATE access_requests SET status = 'approved', decided_by = ?2, decided_at = ?3,
                        decision_reason = ?4, minutes = ?5, starts_at = ?3,
                        ends_at = ?3 + ?5 * 60000, self_approved = ?6
                 WHERE id = ?1 AND status = 'pending' AND expires_at > ?3",
                params![
                    id.to_string(),
                    by.to_string(),
                    now,
                    reason,
                    minutes,
                    self_approved as i64
                ],
            )?;
            let req = load_request(c, id)?;
            if n == 0 {
                return Err(closed(effective_status(&req, now)));
            }
            Ok(req)
        })
        .await
    }

    /// Denies a pending request.
    pub async fn deny_access_request(
        &self,
        id: Id,
        by: Id,
        reason: Option<String>,
    ) -> Result<AccessRequest> {
        self.call(move |c, _| {
            let now = now_ms();
            let n = c.execute(
                "UPDATE access_requests SET status = 'denied', decided_by = ?2, decided_at = ?3,
                        decision_reason = ?4, closed_at = ?3
                 WHERE id = ?1 AND status = 'pending' AND expires_at > ?3",
                params![id.to_string(), by.to_string(), now, reason],
            )?;
            let req = load_request(c, id)?;
            if n == 0 {
                return Err(closed(effective_status(&req, now)));
            }
            Ok(req)
        })
        .await
    }

    /// The requester cancels a pending request, or ends an approved window
    /// early.
    pub async fn cancel_access_request(&self, id: Id) -> Result<AccessRequest> {
        self.call(move |c, _| {
            let now = now_ms();
            let n = c.execute(
                "UPDATE access_requests SET status = 'cancelled', closed_at = ?2,
                        ends_at = CASE WHEN status = 'approved' THEN ?2 ELSE ends_at END
                 WHERE id = ?1 AND ((status = 'pending' AND expires_at > ?2)
                                    OR (status = 'approved' AND ends_at > ?2))",
                params![id.to_string(), now],
            )?;
            let req = load_request(c, id)?;
            if n == 0 {
                return Err(closed(effective_status(&req, now)));
            }
            Ok(req)
        })
        .await
    }

    /// An approver ends an approved window early.
    pub async fn revoke_access_request(
        &self,
        id: Id,
        by: Id,
        reason: Option<String>,
    ) -> Result<AccessRequest> {
        self.call(move |c, _| {
            let now = now_ms();
            let n = c.execute(
                "UPDATE access_requests SET status = 'revoked', ends_at = ?2, closed_at = ?2,
                        decision_reason = COALESCE(?4, decision_reason), decided_by = ?3,
                        decided_at = ?2
                 WHERE id = ?1 AND status = 'approved' AND ends_at > ?2",
                params![id.to_string(), now, by.to_string(), reason],
            )?;
            let req = load_request(c, id)?;
            if n == 0 {
                return Err(closed(effective_status(&req, now)));
            }
            Ok(req)
        })
        .await
    }

    /// Marks the pending requests past their deadline as expired. Returns
    /// them.
    pub async fn expire_access_requests(&self, now: i64) -> Result<Vec<AccessRequest>> {
        self.call(move |c, _| {
            let ids: Vec<String> = {
                let mut stmt = c.prepare(
                    "UPDATE access_requests SET status = 'expired', closed_at = ?1
                     WHERE status = 'pending' AND expires_at <= ?1 RETURNING id",
                )?;
                stmt.query_map([now], |r| r.get(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            ids.iter()
                .map(|id| load_request(c, parse_id(id)?))
                .collect()
        })
        .await
    }

    /// Approved windows that ended and were not processed yet (marks them).
    pub async fn ended_access_requests(&self, now: i64) -> Result<Vec<AccessRequest>> {
        self.call(move |c, _| {
            let ids: Vec<String> = {
                let mut stmt = c.prepare(
                    "UPDATE access_requests SET closed_at = ?1
                     WHERE status = 'approved' AND ends_at <= ?1 AND closed_at IS NULL
                     RETURNING id",
                )?;
                stmt.query_map([now], |r| r.get(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            ids.iter()
                .map(|id| load_request(c, parse_id(id)?))
                .collect()
        })
        .await
    }

    /// Active windows of a user in a vault.
    pub async fn active_grants(&self, user: Id, vault: Id) -> Result<Vec<AccessRequest>> {
        self.call(move |c, _| {
            let now = now_ms();
            let mut stmt = c.prepare_cached(&format!(
                "SELECT {REQUEST_COLUMNS} {REQUEST_FROM}
                 WHERE r.requester_id = ?1 AND r.vault_id = ?2 AND r.status = 'approved'
                   AND r.starts_at <= ?3 AND r.ends_at > ?3
                 ORDER BY r.ends_at DESC"
            ))?;
            let rows = stmt
                .query_map(
                    params![user.to_string(), vault.to_string(), now],
                    map_request,
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    /// Pending requests of a user in a vault.
    pub async fn pending_requests(&self, user: Id, vault: Id) -> Result<Vec<AccessRequest>> {
        self.call(move |c, _| {
            let now = now_ms();
            let mut stmt = c.prepare_cached(&format!(
                "SELECT {REQUEST_COLUMNS} {REQUEST_FROM}
                 WHERE r.requester_id = ?1 AND r.vault_id = ?2 AND r.status = 'pending'
                   AND r.expires_at > ?3
                 ORDER BY r.created_at DESC"
            ))?;
            let rows = stmt
                .query_map(
                    params![user.to_string(), vault.to_string(), now],
                    map_request,
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }
}

/// What a request's state really is now (a pending one past its deadline
/// is expired even before the job marks it).
fn effective_status(req: &AccessRequest, now: i64) -> AccessRequestStatus {
    if req.status == AccessRequestStatus::Pending && req.expires_at <= now {
        AccessRequestStatus::Expired
    } else {
        req.status
    }
}

fn insert_ca(
    tx: &Connection,
    master: &crate::crypto::MasterKey,
    owner: CaOwner,
    ca: &NewCa,
) -> Result<CaInfo> {
    let id = new_id();
    let sealed = master.seal(ca.private_key.as_bytes(), &ca_aad(id))?;
    let (team, user) = match owner {
        CaOwner::Team(t) => (Some(t.to_string()), None),
        CaOwner::User(u) => (None, Some(u.to_string())),
    };
    tx.execute(
        "INSERT INTO ssh_cas (id, owner_team_id, owner_user_id, kind, algorithm, public_key,
                              fingerprint, private_key, status, created_by, created_at)
         VALUES (?1, ?2, ?3, 'user', ?4, ?5, ?6, ?7, 'active', ?8, ?9)",
        params![
            id.to_string(),
            team,
            user,
            ca.algorithm,
            ca.public_key,
            ca.fingerprint,
            sealed,
            ca.created_by.to_string(),
            now_ms()
        ],
    )?;
    Ok(tx.query_row(
        &format!("SELECT {CA_COLUMNS} FROM ssh_cas WHERE id = ?1"),
        [id.to_string()],
        map_ca,
    )?)
}

#[cfg(test)]
mod tests {
    use super::super::test_store;
    use super::*;
    use crate::access::{AccessMode, AccessRequestStatus as S};

    fn new_ca(by: Id, n: u8) -> NewCa {
        NewCa {
            algorithm: "ssh-ed25519".into(),
            public_key: format!("ssh-ed25519 AAAA{n}"),
            fingerprint: format!("SHA256:{n}"),
            private_key: Zeroizing::new(format!("PRIVATE {n}")),
            created_by: by,
        }
    }

    #[tokio::test]
    async fn ca_create_rotate_disable() {
        let s = test_store();
        let (team, by) = (new_id(), new_id());
        let owner = CaOwner::Team(team);
        assert!(s.active_ca(owner).await.unwrap().is_none());
        let a = s.create_ca(owner, new_ca(by, 1)).await.unwrap();
        assert_eq!(a.status, CaStatus::Active);
        let err = s.create_ca(owner, new_ca(by, 2)).await.unwrap_err();
        assert_eq!(err.vault_code(), Some(codes::CA_EXISTS));
        let (info, pem) = s.active_ca(owner).await.unwrap().unwrap();
        assert_eq!((info.id, pem.as_str()), (a.id, "PRIVATE 1"));
        // The private key is sealed at rest.
        let raw: Vec<u8> = s
            .call(move |c, _| {
                Ok(c.query_row(
                    "SELECT private_key FROM ssh_cas WHERE id = ?1",
                    [a.id.to_string()],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert!(!raw.windows(9).any(|w| w == b"PRIVATE 1"));

        let b = s
            .rotate_ca(owner, new_ca(by, 3), now_ms() + 1000)
            .await
            .unwrap();
        let cas = s.cas_of(owner).await.unwrap();
        assert_eq!(cas.len(), 2);
        assert_eq!((cas[0].id, cas[0].status), (b.id, CaStatus::Active));
        assert_eq!((cas[1].id, cas[1].status), (a.id, CaStatus::Retiring));
        assert_eq!(s.retire_due_cas(now_ms() + 2000).await.unwrap(), 1);
        assert_eq!(s.cas_of(owner).await.unwrap().len(), 1);
        assert_eq!(s.disable_ca(owner).await.unwrap(), 1);
        assert!(s.cas_of(owner).await.unwrap().is_empty());
        assert_eq!(s.ca_history(owner).await.unwrap().len(), 2);
        // Another owner is independent.
        assert!(s.active_ca(CaOwner::User(by)).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn certificates_serials_and_revocation() {
        let s = test_store();
        let (team, user, by) = (new_id(), new_id(), new_id());
        let owner = CaOwner::Team(team);
        let ca = s.create_ca(owner, new_ca(by, 1)).await.unwrap();
        let mk = |valid_before: i64| NewCert {
            ca_id: ca.id,
            user_id: user,
            purpose: "device".into(),
            key_fingerprint: "SHA256:k".into(),
            principals: vec!["deploy".into()],
            valid_after: 0,
            valid_before,
            ..Default::default()
        };
        let s1 = s.reserve_certificate(mk(now_ms() + 60_000)).await.unwrap();
        let s2 = s.reserve_certificate(mk(now_ms() + 60_000)).await.unwrap();
        let s3 = s.reserve_certificate(mk(now_ms() - 1)).await.unwrap();
        assert!(s1 < s2 && s2 < s3);
        for n in [s1, s2, s3] {
            s.finish_certificate(n, &format!("k{n}")).await.unwrap();
        }
        // A reserved, never finished one is not listed.
        let s4 = s.reserve_certificate(mk(now_ms() + 60_000)).await.unwrap();
        s.drop_certificate(s4).await.unwrap();
        let all = s
            .certificates(CertFilter {
                owner: Some(owner),
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].principals, vec!["deploy"]);
        let active = s
            .certificates(CertFilter {
                owner: Some(owner),
                active_only: true,
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(active.len(), 2);
        // Revoke by serial, then the rest of the user's unexpired ones.
        assert_eq!(
            s.revoke_certificates(Some(owner), CertSelector::Serial(s1), by, None)
                .await
                .unwrap(),
            vec![s1]
        );
        assert_eq!(
            s.revoke_certificates(
                Some(owner),
                CertSelector::User(user),
                by,
                Some("left".into())
            )
            .await
            .unwrap(),
            vec![s2]
        );
        // Expired ones are not "revoked" (they are not in the KRL anyway).
        assert_eq!(
            s.revoked_serials(ca.id).await.unwrap(),
            vec![s1 as u64, s2 as u64]
        );
        assert_eq!(
            s.certificate(s2).await.unwrap().revoke_reason.as_deref(),
            Some("left")
        );
        // Other owners' certificates are untouched.
        assert!(
            s.revoke_certificates(
                Some(CaOwner::Team(new_id())),
                CertSelector::User(user),
                by,
                None
            )
            .await
            .unwrap()
            .is_empty()
        );
        s.revoke_key(owner, "SHA256:x", "ssh-ed25519 AAAAx", by, None)
            .await
            .unwrap();
        s.revoke_key(owner, "SHA256:x", "ssh-ed25519 AAAAx", by, None)
            .await
            .unwrap();
        assert_eq!(s.revoked_keys(owner).await.unwrap().len(), 1);
        assert!(s.is_key_revoked(owner, "SHA256:x").await.unwrap());
        assert!(
            !s.is_key_revoked(CaOwner::User(by), "SHA256:x")
                .await
                .unwrap()
        );
    }

    fn request(vault: Id, requester: Id, target: Id) -> AccessRequest {
        let now = now_ms();
        AccessRequest {
            id: new_id(),
            vault_id: vault,
            target_kind: AccessTargetKind::Host,
            target_id: target,
            target_label: "db1".into(),
            requester_id: requester,
            requester_name: String::new(),
            requester_email: String::new(),
            reason: "deploy".into(),
            minutes: 30,
            status: S::Pending,
            created_at: now,
            expires_at: now + 60_000,
            decided_by: None,
            decided_by_name: None,
            decided_at: None,
            decision_reason: None,
            starts_at: None,
            ends_at: None,
            self_approved: false,
            active: false,
        }
    }

    #[tokio::test]
    async fn access_request_lifecycle() {
        let s = test_store();
        let (vault, ana, bea, host) = (new_id(), new_id(), new_id(), new_id());
        let r = s
            .create_access_request(request(vault, ana, host))
            .await
            .unwrap();
        assert_eq!(r.status, S::Pending);
        let dup = s
            .create_access_request(request(vault, ana, host))
            .await
            .unwrap_err();
        assert_eq!(dup.vault_code(), Some(codes::ACCESS_REQUEST_EXISTS));
        assert_eq!(s.pending_requests(ana, vault).await.unwrap().len(), 1);
        // Approved once: a second decision fails.
        let a = s
            .approve_access_request(r.id, bea, 10, Some("ok".into()), false)
            .await
            .unwrap();
        assert_eq!(a.status, S::Approved);
        assert!(a.active && a.minutes == 10);
        assert_eq!(a.ends_at.unwrap() - a.starts_at.unwrap(), 600_000);
        let again = s.deny_access_request(r.id, bea, None).await.unwrap_err();
        assert_eq!(again.vault_code(), Some(codes::ACCESS_REQUEST_CLOSED));
        assert_eq!(s.active_grants(ana, vault).await.unwrap().len(), 1);
        assert!(s.active_grants(bea, vault).await.unwrap().is_empty());
        // Revoked early: no longer active, the job reports nothing to end.
        let rv = s
            .revoke_access_request(r.id, bea, Some("done".into()))
            .await
            .unwrap();
        assert_eq!(rv.status, S::Revoked);
        assert!(!rv.active);
        assert!(s.active_grants(ana, vault).await.unwrap().is_empty());
        assert!(
            s.ended_access_requests(now_ms() + 1)
                .await
                .unwrap()
                .is_empty()
        );

        // Cancel a pending one; deny another; expire a third.
        let c = s
            .create_access_request(request(vault, ana, host))
            .await
            .unwrap();
        assert_eq!(
            s.cancel_access_request(c.id).await.unwrap().status,
            S::Cancelled
        );
        let d = s
            .create_access_request(request(vault, ana, host))
            .await
            .unwrap();
        assert_eq!(
            s.deny_access_request(d.id, bea, None).await.unwrap().status,
            S::Denied
        );
        let mut e = request(vault, ana, host);
        e.expires_at = now_ms() - 1;
        let e = s.create_access_request(e).await.unwrap();
        let late = s
            .approve_access_request(e.id, bea, 10, None, false)
            .await
            .unwrap_err();
        assert_eq!(late.vault_code(), Some(codes::ACCESS_REQUEST_CLOSED));
        let expired = s.expire_access_requests(now_ms()).await.unwrap();
        assert_eq!(expired.iter().map(|r| r.id).collect::<Vec<_>>(), vec![e.id]);
        assert_eq!(s.access_request(e.id).await.unwrap().status, S::Expired);

        // A window that ends is reported once.
        let f = s
            .create_access_request(request(vault, ana, host))
            .await
            .unwrap();
        s.approve_access_request(f.id, bea, 1, None, false)
            .await
            .unwrap();
        let ended = s.ended_access_requests(now_ms() + 61_000).await.unwrap();
        assert_eq!(ended.len(), 1);
        assert!(
            s.ended_access_requests(now_ms() + 61_000)
                .await
                .unwrap()
                .is_empty()
        );

        let mine = s
            .access_requests(RequestFilter {
                requester: Some(ana),
                limit: 50,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(mine.len(), 5);
        let none = s
            .access_requests(RequestFilter {
                vaults: Some(vec![]),
                limit: 50,
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(none.is_empty());
    }

    #[tokio::test]
    async fn access_policies_upsert() {
        let s = test_store();
        let (vault, host, by) = (new_id(), new_id(), new_id());
        let p = AccessPolicy {
            mode: AccessMode::Approval,
            ..Default::default()
        };
        let a = s
            .set_access_policy(vault, AccessTargetKind::Host, host, p.clone(), by)
            .await
            .unwrap();
        let mut p2 = p.clone();
        p2.max_minutes = 120;
        let b = s
            .set_access_policy(vault, AccessTargetKind::Host, host, p2, by)
            .await
            .unwrap();
        assert_eq!(a.id, b.id);
        assert_eq!(b.policy.max_minutes, 120);
        assert_eq!(s.access_policies(vault).await.unwrap().len(), 1);
        assert_eq!(
            s.vaults_with_access_policies(vec![vault, new_id()])
                .await
                .unwrap(),
            vec![vault]
        );
        s.delete_access_policy(vault, a.id).await.unwrap();
        assert!(s.access_policies(vault).await.unwrap().is_empty());
    }
}

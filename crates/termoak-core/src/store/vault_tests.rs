//! Vault-scoped entity operations: secrets, sync v2, moves, migration.

use rusqlite::Connection;
use serde_json::json;

use super::{MIGRATIONS, Store, migrate, test_store};
use crate::crypto::MasterKey;
use crate::error::{CoreError, codes};
use crate::model::*;
use crate::store::{NewVault, SecretUse, VaultAccess, VaultChange, VaultGrantee};
use crate::transfer::{ItemRef, TransferMode, TransferRequest};
use crate::{Id, new_id};

fn host(label: &str) -> Host {
    Host {
        id: Id::nil(),
        label: label.into(),
        address: format!("{label}.example.com"),
        group_id: None,
        tags: vec![],
        settings: HostSettings {
            username: Some("root".into()),
            ..Default::default()
        },
        notes: String::new(),
        color: None,
        os: None,
        os_version: None,
        favorite: false,
        protocol: Default::default(),
        icon: None,
    }
}

fn pw(p: &str) -> SecretUpdate<HostSecret> {
    SecretUpdate::Set(HostSecret {
        password: Some(p.into()),
        ..Default::default()
    })
}

async fn user(store: &Store, email: &str) -> Id {
    store
        .create_user(email, email, "long-password", false)
        .await
        .unwrap()
        .id
}

async fn shared(store: &Store, owner: Id, name: &str) -> Id {
    store
        .create_vault(
            owner,
            NewVault {
                name: name.into(),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .id
}

fn key_version(store: &Store, id: Id) -> Option<u32> {
    store
        .call_blocking(|c, _| {
            Ok(c.query_row(
                "SELECT key_version FROM entities WHERE id = ?1",
                [id.to_string()],
                |r| r.get(0),
            )?)
        })
        .unwrap()
}

#[tokio::test]
async fn use_only_never_gets_secrets_but_the_server_can_use_them() {
    let store = test_store();
    store.enable_vault_keys();
    let ana = user(&store, "ana@example.com").await;
    let bea = user(&store, "bea@example.com").await;
    let eve = user(&store, "eve@example.com").await;
    let ops = shared(&store, ana, "Ops").await;
    store
        .add_vault_member(ops, ana, VaultGrantee::User(bea), VaultRole::UseOnly)
        .await
        .unwrap();
    let a = store.vault_access(ana).await.unwrap();
    let b = store.vault_access(bea).await.unwrap();
    let e = store.vault_access(eve).await.unwrap();

    let rec = store
        .save_in(&a, ops, host("web"), pw("s3cret"), None)
        .await
        .unwrap();
    let id = rec.data.id;
    assert_eq!(rec.meta.vault_id, Some(ops));
    // Sealed with the vault key.
    assert_eq!(key_version(&store, id), Some(1));

    // Bea lists it (with secret_hidden) but cannot reveal it.
    let list = store.list_in::<Host>(&b, None).await.unwrap();
    assert_eq!(list.len(), 1);
    assert!(list[0].meta.secret_hidden);
    assert!(matches!(
        store.secret_in::<Host>(&b, id, SecretUse::Reveal).await,
        Err(CoreError::Vault {
            code: codes::SECRET_HIDDEN,
            ..
        })
    ));
    // The server may use it on her behalf, and the JIT credentials work.
    assert_eq!(
        store
            .secret_in::<Host>(&b, id, SecretUse::Server)
            .await
            .unwrap()
            .password
            .as_deref(),
        Some("s3cret")
    );
    let r = store
        .resolve_in(&b, id, SecretUse::Credentials)
        .await
        .unwrap();
    assert_eq!(r.password.as_deref(), Some("s3cret"));
    // Use-only cannot change it.
    assert!(matches!(
        store
            .save_in(&b, ops, rec.data.clone(), SecretUpdate::Keep, None)
            .await,
        Err(CoreError::Vault {
            code: codes::VAULT_READ_ONLY,
            ..
        })
    ));
    assert!(matches!(
        store.delete_in::<Host>(&b, id).await,
        Err(CoreError::Vault {
            code: codes::VAULT_READ_ONLY,
            ..
        })
    ));
    // Strict: no more JIT credentials, the server still can.
    store
        .update_vault(
            ops,
            crate::store::VaultPatch {
                settings: Some(VaultSettings {
                    use_only_local: false,
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let b = store.vault_access(bea).await.unwrap();
    assert!(matches!(
        store.resolve_in(&b, id, SecretUse::Credentials).await,
        Err(CoreError::Vault {
            code: codes::USE_ONLY_STRICT,
            ..
        })
    ));
    assert!(store.resolve_in(&b, id, SecretUse::Server).await.is_ok());

    // Sync: no secret, `has_secret` instead.
    let changes = store.vault_changes(&b, ops, 0, 100).await.unwrap();
    match &changes.items[0] {
        VaultChange::Record(r) => {
            assert!(r.secret.is_none());
            assert_eq!(r.has_secret, Some(true));
            assert_eq!(r.vault_id, Some(ops));
        }
        other => panic!("unexpected {other:?}"),
    }
    let changes = store.vault_changes(&a, ops, 0, 100).await.unwrap();
    match &changes.items[0] {
        VaultChange::Record(r) => assert!(r.secret.is_some()),
        other => panic!("unexpected {other:?}"),
    }

    // Eve sees nothing (not found, not forbidden).
    assert!(store.list_in::<Host>(&e, None).await.unwrap().is_empty());
    assert!(matches!(
        store.get_in::<Host>(&e, id).await,
        Err(CoreError::NotFound(_))
    ));
    assert!(matches!(
        store.secret_in::<Host>(&e, id, SecretUse::Server).await,
        Err(CoreError::NotFound(_))
    ));
    assert!(matches!(
        store.vault_changes(&e, ops, 0, 10).await,
        Err(CoreError::Vault {
            code: codes::VAULT_NOT_FOUND,
            ..
        })
    ));
    // Nor can she create with that id anywhere.
    let mut stolen = rec.data.clone();
    stolen.label = "x".into();
    assert!(matches!(
        store
            .save_in(&e, eve, stolen, SecretUpdate::Keep, None)
            .await,
        Err(CoreError::Vault {
            code: codes::ID_IN_USE,
            ..
        })
    ));
    // And Ana cannot just change the vault with an update.
    let mut moved = rec.data.clone();
    moved.label = "web2".into();
    assert!(matches!(
        store
            .save_in(&a, ana, moved, SecretUpdate::Keep, None)
            .await,
        Err(CoreError::Vault {
            code: codes::USE_TRANSFER,
            ..
        })
    ));
}

#[tokio::test]
async fn vault_keys_legacy_blobs_and_reseal() {
    let store = test_store();
    let ana = user(&store, "ana@example.com").await;
    let a = store.vault_access(ana).await.unwrap();
    // Before vault keys are enabled (an upgraded server): legacy blobs.
    let legacy = store
        .save_in(&a, ana, host("old"), pw("old-pw"), None)
        .await
        .unwrap();
    assert_eq!(key_version(&store, legacy.data.id), None);
    store.enable_vault_keys();
    let new = store
        .save_in(&a, ana, host("new"), pw("new-pw"), None)
        .await
        .unwrap();
    assert_eq!(key_version(&store, new.data.id), Some(1));
    assert_eq!(store.vault_key_version(ana).await.unwrap(), 1);
    // Both open.
    for (id, p) in [(legacy.data.id, "old-pw"), (new.data.id, "new-pw")] {
        let s = store
            .secret_in::<Host>(&a, id, SecretUse::Reveal)
            .await
            .unwrap();
        assert_eq!(s.password.as_deref(), Some(p));
    }
    // The blob is bound to the vault key: the master key alone does not open it.
    let blob: Vec<u8> = store
        .call_blocking(|c, _| {
            Ok(c.query_row(
                "SELECT secret FROM entities WHERE id = ?1",
                [new.data.id.to_string()],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert!(
        store
            .master_key()
            .open(
                &blob,
                &crate::store::vaults::legacy_aad(EntityKind::Host, new.data.id)
            )
            .is_err()
    );
    // Reseal: idempotent.
    assert_eq!(store.reseal_legacy(500).await.unwrap(), 1);
    assert_eq!(store.reseal_legacy(500).await.unwrap(), 0);
    assert_eq!(key_version(&store, legacy.data.id), Some(1));
    let s = store
        .secret_in::<Host>(&a, legacy.data.id, SecretUse::Reveal)
        .await
        .unwrap();
    assert_eq!(s.password.as_deref(), Some("old-pw"));

    // A second store handle with the same master key (server restart): the
    // wrapped key opens.
    let path = tempfile::tempdir().unwrap();
    let key = MasterKey::generate();
    let file = path.path().join("t.db");
    let s1 = Store::open(&file, key.clone()).unwrap();
    s1.enable_vault_keys();
    let u = user(&s1, "x@example.com").await;
    let acc = s1.vault_access(u).await.unwrap();
    let h = s1.save_in(&acc, u, host("h"), pw("p"), None).await.unwrap();
    drop(s1);
    let s2 = Store::open(&file, key).unwrap();
    let acc = s2.vault_access(u).await.unwrap();
    let s = s2
        .secret_in::<Host>(&acc, h.data.id, SecretUse::Reveal)
        .await
        .unwrap();
    assert_eq!(s.password.as_deref(), Some("p"));
}

#[tokio::test]
async fn move_writes_a_departure_and_reseals() {
    let store = test_store();
    store.enable_vault_keys();
    let ana = user(&store, "ana@example.com").await;
    let ops = shared(&store, ana, "Ops").await;
    let a = store.vault_access(ana).await.unwrap();
    let rec = store
        .save_in(&a, ana, host("web"), pw("pw"), None)
        .await
        .unwrap();
    let id = rec.data.id;
    let cursor = store
        .vault_changes(&a, ana, 0, 100)
        .await
        .unwrap()
        .cursor(0);

    store
        .move_entities(&a, ops, vec![(id, None)])
        .await
        .unwrap();
    let got = store.get_in::<Host>(&a, id).await.unwrap();
    assert_eq!(got.meta.vault_id, Some(ops));
    assert_eq!(key_version(&store, id), Some(1));
    let s = store
        .secret_in::<Host>(&a, id, SecretUse::Reveal)
        .await
        .unwrap();
    assert_eq!(s.password.as_deref(), Some("pw"));
    // The blob is now bound to the Ops key: resealed.
    let vault_of_key: String = store
        .call_blocking(|c, _| {
            Ok(c.query_row(
                "SELECT vault_id FROM vault_keys WHERE vault_id = ?1",
                [ops.to_string()],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(vault_of_key, ops.to_string());

    // The personal vault reports a departure, Ops the record.
    let personal = store.vault_changes(&a, ana, cursor, 100).await.unwrap();
    assert!(matches!(
        personal.items.as_slice(),
        [VaultChange::Departed { id: d, kind: EntityKind::Host, .. }] if *d == id
    ));
    let in_ops = store.vault_changes(&a, ops, 0, 100).await.unwrap();
    assert!(matches!(in_ops.items.as_slice(), [VaultChange::Record(r)] if r.id == id));
}

#[tokio::test]
async fn transfer_copy_with_and_without_secrets() {
    let store = test_store();
    store.enable_vault_keys();
    let ana = user(&store, "ana@example.com").await;
    let bea = user(&store, "bea@example.com").await;
    let ops = shared(&store, ana, "Ops").await;
    store
        .add_vault_member(ops, ana, VaultGrantee::User(bea), VaultRole::UseOnly)
        .await
        .unwrap();
    let a = store.vault_access(ana).await.unwrap();
    let b = store.vault_access(bea).await.unwrap();
    let web = store
        .save_in(&a, ops, host("web"), pw("pw"), None)
        .await
        .unwrap();
    let snip = store
        .save_in(
            &a,
            ops,
            Snippet {
                id: Id::nil(),
                name: "uptime".into(),
                script: "uptime".into(),
                description: String::new(),
                tags: vec![],
            },
            SecretUpdate::Keep,
            None,
        )
        .await
        .unwrap();
    // Use-only cannot copy hosts out, but can copy snippets.
    let req = |kind, id| TransferRequest {
        mode: TransferMode::Copy,
        items: vec![ItemRef { kind, id }],
        ..Default::default()
    };
    assert!(matches!(
        store
            .transfer(&b, bea, req(EntityKind::Host, web.data.id))
            .await,
        Err(CoreError::Vault {
            code: codes::VAULT_READ_ONLY,
            ..
        })
    ));
    let r = store
        .transfer(&b, bea, req(EntityKind::Snippet, snip.data.id))
        .await
        .unwrap();
    assert_eq!(r.copied.len(), 1);
    assert_eq!(
        store.list_in::<Snippet>(&b, Some(bea)).await.unwrap().len(),
        1
    );
    // Ana copies with the secret into her personal vault (new id).
    let r = store
        .transfer(&a, ana, req(EntityKind::Host, web.data.id))
        .await
        .unwrap();
    let copy = r.copied[0].to;
    assert_ne!(copy, web.data.id);
    let s = store
        .secret_in::<Host>(&a, copy, SecretUse::Reveal)
        .await
        .unwrap();
    assert_eq!(s.password.as_deref(), Some("pw"));
    // Dry run writes nothing.
    let before = store.list_in::<Host>(&a, Some(ana)).await.unwrap().len();
    let r = store
        .transfer(
            &a,
            ana,
            TransferRequest {
                dry_run: true,
                ..req(EntityKind::Host, web.data.id)
            },
        )
        .await
        .unwrap();
    assert!(r.dry_run);
    assert_eq!(
        store.list_in::<Host>(&a, Some(ana)).await.unwrap().len(),
        before
    );
}

#[tokio::test]
async fn cross_vault_reference_resolves_as_missing() {
    let store = test_store();
    store.enable_vault_keys();
    let ana = user(&store, "ana@example.com").await;
    let ops = shared(&store, ana, "Ops").await;
    let a = store.vault_access(ana).await.unwrap();
    // An identity in the personal vault...
    let ident = store
        .save_in(
            &a,
            ana,
            Identity {
                id: Id::nil(),
                label: "me".into(),
                username: "ana".into(),
                key_id: None,
            },
            SecretUpdate::Set(IdentitySecret {
                password: Some("personal-pw".into()),
            }),
            None,
        )
        .await
        .unwrap();
    // ...cannot be referenced from an Ops host through REST.
    let mut h = host("web");
    h.settings.username = None;
    h.settings.identity_id = Some(ident.data.id);
    let err = store
        .save_in(&a, ops, h.clone(), SecretUpdate::Keep, None)
        .await
        .unwrap_err();
    assert_eq!(err.vault_code(), Some(codes::CROSS_VAULT_REFERENCE));
    // Sync v2 accepts it with a warning, and resolution ignores it.
    let report = store
        .apply_remote_v2(
            &a,
            vec![SyncRecord {
                id: new_id(),
                kind: EntityKind::Host,
                data: serde_json::to_value(&h).unwrap(),
                secret: None,
                sync_mode: SyncMode::Synced,
                updated_at: 1,
                deleted: false,
                rev: 0,
                vault_id: Some(ops),
                has_secret: None,
                sealed: None,
                base_rev: None,
            }],
        )
        .await
        .unwrap();
    assert_eq!(report.accepted.len(), 1);
    assert_eq!(report.warnings[0].field, "settings.identity_id");
    let id = report.accepted[0];
    // No username: the identity of another vault is "missing".
    let err = store
        .resolve_in(&a, id, SecretUse::Server)
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::Invalid(m) if m.contains("no username")));
}

#[tokio::test]
async fn apply_remote_v2_rules_and_paging() {
    let store = test_store();
    let ana = user(&store, "ana@example.com").await;
    let bea = user(&store, "bea@example.com").await;
    let ops = shared(&store, ana, "Ops").await;
    store
        .add_vault_member(ops, ana, VaultGrantee::User(bea), VaultRole::UseOnly)
        .await
        .unwrap();
    let a = store.vault_access(ana).await.unwrap();
    let b = store.vault_access(bea).await.unwrap();
    let rec = |label: &str, vault: Option<Id>, at: i64| SyncRecord {
        id: new_id(),
        kind: EntityKind::Host,
        data: serde_json::to_value(host(label)).unwrap(),
        secret: Some(json!({"password": "x"})),
        sync_mode: SyncMode::Synced,
        updated_at: at,
        deleted: false,
        rev: 0,
        vault_id: vault,
        has_secret: None,
        sealed: None,
        base_rev: None,
    };
    // Old-format record (no vault_id) lands in the personal vault.
    let r1 = rec("a", None, 10);
    let rep = store.apply_remote_v2(&a, vec![r1.clone()]).await.unwrap();
    assert_eq!(rep.accepted, vec![r1.id]);
    assert_eq!(
        store.get_in::<Host>(&a, r1.id).await.unwrap().meta.vault_id,
        Some(ana)
    );
    // Use-only push → vault_read_only; unknown vault → vault_not_found.
    let rep = store
        .apply_remote_v2(
            &b,
            vec![rec("b", Some(ops), 10), rec("c", Some(new_id()), 10)],
        )
        .await
        .unwrap();
    let codes_: Vec<&str> = rep.rejected.iter().map(|r| r.code.as_str()).collect();
    assert_eq!(codes_, vec![codes::VAULT_READ_ONLY, codes::VAULT_NOT_FOUND]);
    // Someone else's id → id_in_use.
    let mut steal = r1.clone();
    steal.updated_at = 99;
    let rep = store.apply_remote_v2(&b, vec![steal]).await.unwrap();
    assert_eq!(rep.rejected[0].code, codes::ID_IN_USE);
    // Stale push: accepted but reported stale.
    let mut old = r1.clone();
    old.updated_at = 1;
    let rep = store.apply_remote_v2(&a, vec![old]).await.unwrap();
    assert_eq!(rep.stale, vec![r1.id]);
    // An edit pushed to the old vault after a move is applied where it is now.
    store
        .move_entities(&a, ops, vec![(r1.id, None)])
        .await
        .unwrap();
    let mut edit = r1.clone();
    edit.updated_at = now_plus();
    edit.data["label"] = json!("renamed");
    let rep = store.apply_remote_v2(&a, vec![edit]).await.unwrap();
    assert_eq!(rep.applied[0].vault_id, Some(ops));
    assert_eq!(
        store.get_in::<Host>(&a, r1.id).await.unwrap().data.label,
        "renamed"
    );

    // Paging.
    let many: Vec<SyncRecord> = (0..7).map(|i| rec(&format!("h{i}"), None, 10)).collect();
    store.apply_remote_v2(&a, many).await.unwrap();
    let mut cursor = 0;
    let mut seen = 0;
    let mut pages = 0;
    loop {
        let page = store.vault_changes(&a, ana, cursor, 3).await.unwrap();
        seen += page.items.len();
        pages += 1;
        cursor = page.cursor(cursor);
        if !page.more {
            break;
        }
    }
    // 7 hosts + "a"'s departure.
    assert_eq!(seen, 8);
    assert_eq!(pages, 3);
}

fn now_plus() -> i64 {
    crate::time::now_ms() + 60_000
}

#[tokio::test]
async fn deleting_a_user_deletes_their_vaults_but_not_team_items() {
    let store = test_store();
    let ana = user(&store, "ana@example.com").await;
    let bea = user(&store, "bea@example.com").await;
    let team = store.create_team(bea, "Infra").await.unwrap();
    store
        .set_team_member(team.id, ana, TeamRole::Member)
        .await
        .unwrap();
    let tv = store
        .create_vault(
            bea,
            NewVault {
                name: "Team".into(),
                team_id: Some(team.id),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .id;
    let ops = shared(&store, ana, "Ops").await;
    store
        .add_vault_member(ops, ana, VaultGrantee::User(bea), VaultRole::Editor)
        .await
        .unwrap();
    assert_eq!(
        store.shared_vaults_with_members(ana).await.unwrap().len(),
        1
    );
    let a = store.vault_access(ana).await.unwrap();
    store
        .save_in(&a, ana, host("mine"), SecretUpdate::Keep, None)
        .await
        .unwrap();
    store
        .save_in(&a, ops, host("ops"), SecretUpdate::Keep, None)
        .await
        .unwrap();
    let in_team = store
        .save_in(&a, tv, host("team"), SecretUpdate::Keep, None)
        .await
        .unwrap();
    store.delete_user(ana).await.unwrap();
    assert!(store.vault(ana).await.is_err());
    assert!(store.vault(ops).await.is_err());
    let b = store.vault_access(bea).await.unwrap();
    assert_eq!(b.role(ops), None);
    // What Ana created in the team vault stays.
    assert!(store.get_in::<Host>(&b, in_team.data.id).await.is_ok());
    let count: i64 = store
        .call_blocking(|c, _| Ok(c.query_row("SELECT COUNT(*) FROM entities", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn owner_based_functions_keep_working_for_clients() {
    // A client store: no users, no vaults, owner = nil.
    let store = test_store();
    let owner = Id::nil();
    let rec = store
        .save(owner, host("local"), pw("pw"), None)
        .await
        .unwrap();
    assert_eq!(rec.meta.vault_id, None);
    assert_eq!(
        store
            .secret::<Host>(owner, rec.data.id)
            .await
            .unwrap()
            .password
            .as_deref(),
        Some("pw")
    );
    let r = store.resolve_local(None, rec.data.id, None).await.unwrap();
    assert_eq!(r.password.as_deref(), Some("pw"));
    // A synced host using a device-only key of another store (fallback).
    let device = test_store();
    let key = device
        .save(
            owner,
            SshKey {
                id: Id::nil(),
                label: "k".into(),
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
            Some(SyncMode::DeviceOnly),
        )
        .await
        .unwrap();
    let mut h = host("synced");
    h.settings.key_id = Some(key.data.id);
    let synced = store
        .save(owner, h, SecretUpdate::Keep, None)
        .await
        .unwrap();
    assert!(
        store
            .resolve_local(None, synced.data.id, None)
            .await
            .is_err()
    );
    let r = store
        .resolve_local(None, synced.data.id, Some((&device, owner)))
        .await
        .unwrap();
    assert_eq!(r.key.unwrap().private_key, "PRIVATE");
}

/// v8 → v9 on a fixture with two users, their entities and a team.
#[tokio::test]
async fn migration_v9_attaches_entities_to_personal_vaults() {
    let conn = Connection::open_in_memory().unwrap();
    for (i, sql) in MIGRATIONS[..8].iter().enumerate() {
        conn.execute_batch(&format!(
            "BEGIN; {sql}; PRAGMA user_version = {}; COMMIT;",
            i + 1
        ))
        .unwrap();
    }
    let (ana, bea) = (new_id().to_string(), new_id().to_string());
    for (id, email) in [(&ana, "ana@x"), (&bea, "bea@x")] {
        conn.execute(
            "INSERT INTO users (id, email, name, password_hash, created_at) VALUES (?1, ?2, 'n', 'h', 5)",
            [id, email],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO teams (id, name, created_by, created_at) VALUES ('t1', 'Ops', ?1, 5)",
        [&ana],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO team_members (team_id, user_id, role, added_at) VALUES ('t1', ?1, 'owner', 5)",
        [&ana],
    )
    .unwrap();
    for (i, owner) in [&ana, &ana, &bea].iter().enumerate() {
        conn.execute(
            "INSERT INTO entities (id, owner_id, kind, data, rev, updated_at)
             VALUES (?1, ?2, 'host', '{\"label\":\"h\",\"address\":\"h\"}', ?3, 1)",
            rusqlite::params![new_id().to_string(), owner, i as i64 + 1],
        )
        .unwrap();
    }
    // An orphan row (owner without a user) keeps no vault.
    conn.execute(
        "INSERT INTO entities (id, owner_id, kind, data, rev, updated_at)
         VALUES (?1, ?2, 'host', '{}', 9, 1)",
        [new_id().to_string(), new_id().to_string()],
    )
    .unwrap();
    migrate(&conn).unwrap();
    let vaults: Vec<(String, String, String)> = conn
        .prepare("SELECT id, kind, owner_user_id FROM vaults ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        vaults.len(),
        2,
        "one personal vault per user, none for teams"
    );
    for (id, kind, owner) in &vaults {
        assert_eq!(kind, "personal");
        assert_eq!(id, owner);
    }
    let attached: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM entities WHERE vault_id = owner_id",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(attached, 3);
    let orphan: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM entities WHERE vault_id IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(orphan, 1);
    let v: i64 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(v as usize, MIGRATIONS.len());

    // The roles work on the migrated data.
    let store = Store::init(conn, MasterKey::generate()).unwrap();
    let ana: Id = ana.parse().unwrap();
    let access = store.vault_access(ana).await.unwrap();
    assert_eq!(access.role(ana), Some(VaultRole::Manager));
    assert_eq!(store.list_in::<Host>(&access, None).await.unwrap().len(), 2);
    assert_eq!(VaultAccess::default().role(ana), None);
}

fn wireguard(name: &str) -> Network {
    Network {
        id: Id::nil(),
        name: name.into(),
        kind: NetworkKind::Wireguard,
        description: String::new(),
        wireguard: Some(WireguardConfig {
            addresses: vec!["10.9.0.2/32".into()],
            peers: vec![WireguardPeer {
                public_key: "cGVlcg==".into(),
                endpoint: Some("vpn.example.com:51820".into()),
                allowed_ips: vec!["10.9.0.0/24".into()],
                persistent_keepalive: Some(25),
            }],
            ..Default::default()
        }),
        tailscale: None,
        zerotier: None,
    }
}

fn wg_secret() -> SecretUpdate<NetworkSecret> {
    SecretUpdate::Set(NetworkSecret {
        private_key: Some("cHJpdmF0ZQ==".into()),
        ..Default::default()
    })
}

#[tokio::test]
async fn networks_resolve_through_groups_in_the_same_vault_only() {
    let store = test_store();
    store.enable_vault_keys();
    let ana = user(&store, "ana@example.com").await;
    let ops = shared(&store, ana, "Ops").await;
    let a = store.vault_access(ana).await.unwrap();
    let net = store
        .save_in(&a, ops, wireguard("office"), wg_secret(), None)
        .await
        .unwrap();
    // Inherited from the group.
    let group = store
        .save_in(
            &a,
            ops,
            Group {
                id: Id::nil(),
                name: "lan".into(),
                parent_id: None,
                color: None,
                settings: HostSettings {
                    network_id: Some(net.data.id),
                    ..Default::default()
                },
            },
            SecretUpdate::Keep,
            None,
        )
        .await
        .unwrap();
    let mut h = host("nas");
    h.group_id = Some(group.data.id);
    let h = store
        .save_in(&a, ops, h, SecretUpdate::Keep, None)
        .await
        .unwrap();
    let r = store
        .resolve_in(&a, h.data.id, SecretUse::Server)
        .await
        .unwrap();
    assert_eq!(r.settings.network_id, Some(net.data.id));
    assert_eq!(r.first_hop_network_id(), Some(net.data.id));
    let n = r.first_hop_network().unwrap();
    assert_eq!(n.network.name, "office");
    assert_eq!(n.secret.private_key.as_deref(), Some("cHJpdmF0ZQ=="));
    // The secret never shows in Debug output.
    assert!(!format!("{r:?}").contains("cHJpdmF0ZQ=="));
    let mut wiped = r.clone();
    wiped.zeroize_secrets();
    assert!(wiped.network.unwrap().secret.private_key.is_none());

    // A network of another vault cannot be referenced...
    let other = store
        .save_in(&a, ana, wireguard("home"), SecretUpdate::Keep, None)
        .await
        .unwrap();
    let mut cross = host("cross");
    cross.settings.network_id = Some(other.data.id);
    let err = store
        .save_in(&a, ops, cross, SecretUpdate::Keep, None)
        .await
        .unwrap_err();
    assert_eq!(err.vault_code(), Some(codes::CROSS_VAULT_REFERENCE));

    // ...and a host whose network is gone never resolves as direct.
    store.delete_in::<Network>(&a, net.data.id).await.unwrap();
    let err = store
        .resolve_in(&a, h.data.id, SecretUse::Server)
        .await
        .unwrap_err();
    assert_eq!(err.vault_code(), Some(codes::NETWORK_NOT_FOUND));
}

#[tokio::test]
async fn first_hop_network_is_the_first_jumps_or_the_hosts() {
    let store = test_store();
    let ana = user(&store, "ana@example.com").await;
    let a = store.vault_access(ana).await.unwrap();
    let net = store
        .save_in(&a, ana, wireguard("office"), SecretUpdate::Keep, None)
        .await
        .unwrap();
    let bastion = store
        .save_in(&a, ana, host("bastion"), SecretUpdate::Keep, None)
        .await
        .unwrap();
    let mut inner = host("inner");
    inner.settings.network_id = Some(net.data.id);
    inner.settings.jump_host_ids = Some(vec![bastion.data.id]);
    let inner = store
        .save_in(&a, ana, inner, SecretUpdate::Keep, None)
        .await
        .unwrap();
    let r = store
        .resolve_in(&a, inner.data.id, SecretUse::Server)
        .await
        .unwrap();
    // The bastion has no network: the host's applies to the first hop.
    assert_eq!(r.first_hop().host.label, "bastion");
    assert_eq!(r.first_hop_network_id(), Some(net.data.id));
    assert!(r.first_hop_network().is_some());
    let direct = store
        .resolve_in(&a, bastion.data.id, SecretUse::Server)
        .await
        .unwrap();
    assert_eq!(direct.first_hop_network_id(), None);
}

#[tokio::test]
async fn old_cores_editing_a_host_keep_its_network() {
    let store = test_store();
    let ana = user(&store, "ana@example.com").await;
    let a = store.vault_access(ana).await.unwrap();
    let net = store
        .save_in(&a, ana, wireguard("office"), SecretUpdate::Keep, None)
        .await
        .unwrap();
    let mut h = host("db");
    h.settings.network_id = Some(net.data.id);
    let h = store
        .save_in(&a, ana, h, SecretUpdate::Keep, None)
        .await
        .unwrap();
    // New cores always write the key.
    let data = serde_json::to_value(&h.data).unwrap();
    assert_eq!(data["settings"]["network_id"], json!(net.data.id));
    let unset = serde_json::to_value(host("x")).unwrap();
    assert!(
        unset["settings"]
            .as_object()
            .unwrap()
            .contains_key("network_id")
    );

    let push = |data: serde_json::Value, at: i64| SyncRecord {
        id: h.data.id,
        kind: EntityKind::Host,
        data,
        secret: None,
        sync_mode: SyncMode::Synced,
        updated_at: at,
        deleted: false,
        rev: 0,
        vault_id: None,
        has_secret: None,
        sealed: None,
        base_rev: None,
    };
    // A core before 0.7 drops the unknown key when it edits the host.
    let mut old = data.clone();
    old["settings"]
        .as_object_mut()
        .unwrap()
        .remove("network_id");
    old["label"] = json!("db (renamed by an old app)");
    store
        .apply_remote_v2(&a, vec![push(old, now_plus())])
        .await
        .unwrap();
    let got = store.get_in::<Host>(&a, h.data.id).await.unwrap();
    assert_eq!(got.data.label, "db (renamed by an old app)");
    assert_eq!(got.data.settings.network_id, Some(net.data.id));
    // Without settings at all, too.
    let mut bare = data.clone();
    bare.as_object_mut().unwrap().remove("settings");
    store
        .apply_remote_v2(&a, vec![push(bare, now_plus() + 1)])
        .await
        .unwrap();
    let got = store.get_in::<Host>(&a, h.data.id).await.unwrap();
    assert_eq!(got.data.settings.network_id, Some(net.data.id));
    // A new core clears it with an explicit null.
    let mut cleared = data.clone();
    cleared["settings"]["network_id"] = json!(null);
    store
        .apply_remote_v2(&a, vec![push(cleared, now_plus() + 2)])
        .await
        .unwrap();
    let got = store.get_in::<Host>(&a, h.data.id).await.unwrap();
    assert_eq!(got.data.settings.network_id, None);
}

#[tokio::test]
async fn networks_are_billed_to_the_vault_owner_or_the_team_owner() {
    let store = test_store();
    let ana = user(&store, "ana@example.com").await;
    let bea = user(&store, "bea@example.com").await;
    let team = store.create_team(bea, "Infra").await.unwrap();
    store
        .set_team_member(team.id, ana, TeamRole::Admin)
        .await
        .unwrap();
    let tv = store
        .create_vault(
            ana,
            NewVault {
                name: "Team".into(),
                team_id: Some(team.id),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .id;
    let ops = shared(&store, ana, "Ops").await;
    let a = store.vault_access(ana).await.unwrap();
    for vault in [ana, ops, tv, tv] {
        store
            .save_in(&a, vault, wireguard("n"), SecretUpdate::Keep, None)
            .await
            .unwrap();
    }
    assert_eq!(store.vault_billing_user(ops).await.unwrap(), Some(ana));
    assert_eq!(store.vault_billing_user(tv).await.unwrap(), Some(bea));
    assert_eq!(store.networks_billed_to(ana).await.unwrap(), 2);
    assert_eq!(store.networks_billed_to(bea).await.unwrap(), 2);
    // Deleted networks do not count.
    let gone = store
        .save_in(&a, ana, wireguard("gone"), SecretUpdate::Keep, None)
        .await
        .unwrap();
    store.delete_in::<Network>(&a, gone.data.id).await.unwrap();
    assert_eq!(store.networks_billed_to(ana).await.unwrap(), 2);
}

#[test]
fn network_validation_and_unknown_kinds() {
    let mut zt = Network {
        name: "zt".into(),
        kind: NetworkKind::Zerotier,
        zerotier: Some(ZerotierConfig {
            network_id: "8056c2e21c000001".into(),
            central_url: None,
        }),
        ..Default::default()
    };
    zt.validate().unwrap();
    zt.zerotier.as_mut().unwrap().network_id = "nope".into();
    assert!(zt.validate().is_err());
    let ts: Network = serde_json::from_value(json!({
        "name": "tail", "kind": "Headscale",
        "tailscale": {"control_url": "ftp://x"}
    }))
    .unwrap();
    assert_eq!(ts.kind, NetworkKind::Tailscale);
    assert!(ts.validate().is_err());
    // A later version's kind is kept as it is.
    let later: Network = serde_json::from_value(json!({"name": "x", "kind": "Nebula"})).unwrap();
    assert_eq!(later.kind, NetworkKind::Other("nebula".into()));
    assert_eq!(
        serde_json::to_value(&later).unwrap()["kind"],
        json!("nebula")
    );
    later.validate().unwrap();
    assert!(EntityKind::Host.is_legacy() && !EntityKind::Network.is_legacy());
    assert_eq!(EntityKind::parse("network"), Some(EntityKind::Network));
}

#[test]
fn tailscale_settings_are_validated() {
    let net = |cfg: serde_json::Value| -> Network {
        serde_json::from_value(json!({"name": "tail", "kind": "tailscale", "tailscale": cfg})).unwrap()
    };
    net(json!({})).validate().unwrap();
    net(json!({"control_url": "https://hs.example.com:8443/", "hostname": "termoak-Office",
               "tags": ["tag:termoak", "tag:prod_1"], "ephemeral": false}))
    .validate()
    .unwrap();
    net(json!({"control_url": "", "hostname": " ", "tags": []})).validate().unwrap();
    for bad in [
        json!({"control_url": "ftp://x"}),
        json!({"control_url": "https://"}),
        json!({"control_url": "https://u:p@hs.example.com"}),
        json!({"control_url": "https://hs.example.com/?x=1"}),
        json!({"control_url": "https://hs example.com"}),
        json!({"hostname": "-office"}),
        json!({"hostname": "my office"}),
        json!({"hostname": "a".repeat(64)}),
        json!({"tags": ["termoak"]}),
        json!({"tags": ["tag:"]}),
        json!({"tags": ["tag:-x"]}),
        json!({"tags": ["tag:a b"]}),
        json!({"tags": (0..21).map(|i| format!("tag:t{i}")).collect::<Vec<_>>()}),
    ] {
        assert!(net(bad.clone()).validate().is_err(), "{bad}");
    }
    // `ephemeral` is always written (null when unset): its absence means an
    // older core.
    let v = serde_json::to_value(net(json!({}))).unwrap();
    assert!(v["tailscale"].as_object().unwrap().contains_key("ephemeral"));

    // The auth key: printable ASCII, never echoed in the error.
    let n = net(json!({}));
    let secret = |k: &str| NetworkSecret {
        auth_key: Some(k.into()),
        ..Default::default()
    };
    n.validate_secret(&secret("hskey-auth-abc_DEF-123")).unwrap();
    n.validate_secret(&secret("tskey-client-k123-SECRET?ephemeral=true&preauthorized=true")).unwrap();
    n.validate_secret(&NetworkSecret::default()).unwrap();
    for bad in ["tskey-auth SECRET", "tskey-auth-\u{e9}SECRET", &"k".repeat(1025)] {
        let err = n.validate_secret(&secret(bad)).unwrap_err().to_string();
        assert!(!err.contains("SECRET"), "{err}");
    }
    // Other kinds do not look at it.
    let wg = Network {
        name: "wg".into(),
        ..Default::default()
    };
    wg.validate_secret(&secret("not checked here")).unwrap();
}

#[tokio::test]
async fn tailscale_networks_are_checked_on_save_and_push_and_old_cores_keep_ephemeral() {
    let store = test_store();
    let ana = user(&store, "ana@example.com").await;
    let a = store.vault_access(ana).await.unwrap();
    let mut net: Network = serde_json::from_value(json!({
        "name": "tail", "kind": "tailscale",
        "tailscale": {"control_url": "https://hs.example.com", "ephemeral": false}
    }))
    .unwrap();
    let bad = NetworkSecret {
        auth_key: Some("has space".into()),
        ..Default::default()
    };
    assert!(matches!(
        store
            .save_in(&a, ana, net.clone(), SecretUpdate::Set(bad.clone()), None)
            .await,
        Err(CoreError::Invalid(_))
    ));
    let good = NetworkSecret {
        auth_key: Some("hskey-auth-ok".into()),
        ..Default::default()
    };
    let saved = store
        .save_in(&a, ana, net.clone(), SecretUpdate::Set(good), None)
        .await
        .unwrap();
    net.id = saved.data.id;
    let push = |data: serde_json::Value, secret: Option<serde_json::Value>, at: i64| SyncRecord {
        id: net.id,
        kind: EntityKind::Network,
        data,
        secret,
        sync_mode: SyncMode::Synced,
        updated_at: at,
        deleted: false,
        rev: 0,
        vault_id: None,
        has_secret: None,
        sealed: None,
        base_rev: None,
    };
    // A pushed bad key or bad tags are rejected as invalid.
    let data = serde_json::to_value(&net).unwrap();
    let rep = store
        .apply_remote_v2(&a, vec![push(data.clone(), Some(json!({"auth_key": "a b"})), now_plus())])
        .await
        .unwrap();
    assert_eq!(rep.rejected.len(), 1);
    assert_eq!(rep.rejected[0].code, "invalid");
    let mut tagged = data.clone();
    tagged["tailscale"]["tags"] = json!(["prod"]);
    let rep = store
        .apply_remote_v2(&a, vec![push(tagged, None, now_plus())])
        .await
        .unwrap();
    assert_eq!(rep.rejected[0].code, "invalid");
    // A core before 0.7.0-next.3 drops `ephemeral` when it renames the
    // network: the stored value is kept.
    let mut old = data.clone();
    old["tailscale"].as_object_mut().unwrap().remove("ephemeral");
    old["name"] = json!("tail (renamed)");
    let rep = store
        .apply_remote_v2(&a, vec![push(old, None, now_plus() + 1)])
        .await
        .unwrap();
    assert!(rep.rejected.is_empty(), "{:?}", rep.rejected);
    let got = store.get_in::<Network>(&a, net.id).await.unwrap();
    assert_eq!(got.data.name, "tail (renamed)");
    assert_eq!(got.data.tailscale.unwrap().ephemeral, Some(false));
    // null clears it.
    let mut cleared = data.clone();
    cleared["tailscale"]["ephemeral"] = json!(null);
    store
        .apply_remote_v2(&a, vec![push(cleared, None, now_plus() + 2)])
        .await
        .unwrap();
    let got = store.get_in::<Network>(&a, net.id).await.unwrap();
    assert_eq!(got.data.tailscale.unwrap().ephemeral, None);
}

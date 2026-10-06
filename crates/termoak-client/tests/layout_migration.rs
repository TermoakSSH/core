//! Layout 1 → 2 migration on data directories as Termoak 0.3 left them
//! (one `termoak.db` at schema v8 with one server in `meta`): signed in
//! with unsynced changes, signed out, never signed in, the old
//! `aceitunoak.ohz.ovh` address, a synced host using a This-device key, and
//! an interrupted migration.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rusqlite::{Connection, params};
use serde_json::json;
use termoak_client::{AccountStatus, LOCAL_OWNER, Scope, Workspace};
use termoak_core::crypto::MasterKey;
use termoak_core::model::{Host, HostSecret, KnownHost, Snippet, SshKey, SshKeySecret, TokenPair};
use termoak_core::{Id, new_id};

/// A 0.3 data directory.
struct Fixture {
    dir: tempfile::TempDir,
    key: MasterKey,
    conn: Connection,
}

fn tokens() -> TokenPair {
    TokenPair {
        access_token: "access-03".into(),
        access_expires_at: i64::MAX,
        refresh_token: "refresh-03".into(),
        refresh_expires_at: i64::MAX,
        device_id: Id::nil(),
    }
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("termoak.db");
        // The schema of Termoak 0.3 (migration v8).
        termoak_core::store::create_at_version(&path, 8).unwrap();
        let conn = Connection::open(&path).unwrap();
        Self {
            dir,
            key: MasterKey::generate(),
            conn,
        }
    }

    fn meta(&self, key: &str, value: &str) {
        self.conn
            .execute(
                "INSERT INTO meta(key, value) VALUES(?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .unwrap();
    }

    /// Signed in to `url` as `email` (empty tokens = signed out).
    fn server(&self, url: &str, email: &str, signed_in: bool) {
        self.meta("server.url", url);
        self.meta("server.user", email);
        let sealed = if signed_in {
            let json = serde_json::to_vec(&tokens()).unwrap();
            STANDARD.encode(self.key.seal(&json, b"aceitunoak:server-tokens").unwrap())
        } else {
            String::new()
        };
        self.meta("server.tokens", &sealed);
        self.meta("sync.rev", "77");
    }

    /// An entity row as 0.3 wrote it (owner nil, legacy secret AAD).
    fn entity(
        &self,
        kind: &str,
        id: Id,
        data: serde_json::Value,
        secret: Option<serde_json::Value>,
        sync_mode: &str,
        dirty: bool,
    ) {
        let blob = secret.map(|s| {
            self.key
                .seal(
                    &serde_json::to_vec(&s).unwrap(),
                    format!("aceitunoak:{kind}:{id}").as_bytes(),
                )
                .unwrap()
        });
        let rev: i64 = self
            .conn
            .query_row(
                "UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'rev'
                 RETURNING CAST(value AS INTEGER)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        self.conn
            .execute(
                "INSERT INTO entities (id, owner_id, kind, data, secret, sync_mode, rev, updated_at, deleted, dirty)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9)",
                params![
                    id.to_string(),
                    Id::nil().to_string(),
                    kind,
                    data.to_string(),
                    blob,
                    sync_mode,
                    rev,
                    1_000 + rev,
                    dirty as i64
                ],
            )
            .unwrap();
    }

    fn host(&self, id: Id, label: &str, key_id: Option<Id>, sync_mode: &str, dirty: bool) {
        self.entity(
            "host",
            id,
            json!({"label": label, "address": format!("{label}.example.com"),
                   "settings": {"username": "root", "key_id": key_id}}),
            Some(json!({"password": format!("pw-{label}")})),
            sync_mode,
            dirty,
        );
    }

    fn key(&self, id: Id, label: &str, sync_mode: &str) {
        self.entity(
            "key",
            id,
            json!({"label": label, "algorithm": "ssh-ed25519", "public_key": "ssh-ed25519 AAAA",
                   "fingerprint": format!("SHA256:{label}"), "comment": "", "has_passphrase": false}),
            Some(json!({"private_key": format!("PRIVATE-{label}")})),
            sync_mode,
            false,
        );
    }

    fn open(&self) -> Workspace {
        Workspace::open(self.dir.path(), self.key.clone()).unwrap()
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }
}

#[tokio::test]
async fn signed_in_with_unsynced_changes() {
    let fx = Fixture::new();
    fx.server("https://SSH.example.com/", "ana@example.com", true);
    let (h_dirty, h_clean, key, snip, kh) = (new_id(), new_id(), new_id(), new_id(), new_id());
    fx.host(h_dirty, "web", Some(key), "synced", true);
    fx.host(h_clean, "db", None, "synced", false);
    fx.key(key, "deploy", "synced");
    fx.entity(
        "snippet",
        snip,
        json!({"name": "local", "script": "uptime"}),
        None,
        "device_only",
        false,
    );
    fx.entity(
        "known_host",
        kh,
        json!({"host": "web.example.com", "port": 22, "key_type": "ssh-ed25519",
               "public_key": "AAAA", "fingerprint": "SHA256:k"}),
        None,
        "synced",
        false,
    );

    let ws = fx.open();
    assert!(fx.path().join("termoak.db.pre-accounts").exists());
    let accounts = ws.accounts();
    assert_eq!(accounts.len(), 1);
    let info = &accounts[0];
    assert_eq!(info.server_url, "https://ssh.example.com");
    assert_eq!(info.email, "ana@example.com");
    assert_eq!(info.status, AccountStatus::Active);
    assert!(!info.official);
    assert!(fx.path().join(format!("accounts/{}.db", info.id)).exists());

    // The tokens were resealed for the account.
    let acc = ws.current().unwrap();
    assert_eq!(acc.id, info.id);
    assert_eq!(acc.api.tokens().unwrap().refresh_token, "refresh-03");
    assert_eq!(acc.api.base_url(), "https://ssh.example.com");

    // Synced rows moved (dirty flag, secrets, sync revision kept).
    let hosts = acc.store.list::<Host>(LOCAL_OWNER).await.unwrap();
    assert_eq!(hosts.len(), 2);
    let dirty = acc.store.dirty_records().await.unwrap();
    assert_eq!(dirty.len(), 1);
    assert_eq!(dirty[0].id, h_dirty);
    let secret: HostSecret = acc
        .store
        .secret::<Host>(LOCAL_OWNER, h_dirty)
        .await
        .unwrap();
    assert_eq!(secret.password.as_deref(), Some("pw-web"));
    assert_eq!(
        acc.store.meta_get("sync.rev").await.unwrap().as_deref(),
        Some("77")
    );
    assert_eq!(
        acc.store
            .list::<KnownHost>(LOCAL_OWNER)
            .await
            .unwrap()
            .len(),
        1
    );
    // New local writes in the account store get revisions past the copied ones.
    let max_before = acc.store.max_rev(LOCAL_OWNER).await.unwrap();
    let mut h = acc
        .store
        .get::<Host>(LOCAL_OWNER, h_clean)
        .await
        .unwrap()
        .data;
    h.notes = "edited".into();
    let saved = acc
        .store
        .save(
            LOCAL_OWNER,
            h,
            termoak_core::model::SecretUpdate::Keep,
            None,
        )
        .await
        .unwrap();
    assert!(saved.meta.rev > max_before);

    // Device-only rows stayed; the old keys are gone.
    assert!(ws.store.list::<Host>(LOCAL_OWNER).await.unwrap().is_empty());
    assert_eq!(
        ws.store.list::<Snippet>(LOCAL_OWNER).await.unwrap().len(),
        1
    );
    assert!(ws.store.meta_get("server.url").await.unwrap().is_none());
    assert!(ws.store.meta_get("server.tokens").await.unwrap().is_none());
    assert_eq!(
        ws.store
            .meta_get("layout.version")
            .await
            .unwrap()
            .as_deref(),
        Some("2")
    );
    // The legacy API sees the account.
    assert_eq!(
        ws.server_user().await.unwrap().as_deref(),
        Some("ana@example.com")
    );
    assert!(ws.server().await.unwrap().is_some());

    // Opening again changes nothing.
    drop(acc);
    drop(ws);
    let ws = fx.open();
    assert_eq!(ws.accounts().len(), 1);
    let acc = ws.current().unwrap();
    assert_eq!(acc.store.list::<Host>(LOCAL_OWNER).await.unwrap().len(), 2);

    // The views across stores.
    let all = ws.list_items::<Host>(&ws.default_filter()).await.unwrap();
    assert_eq!(all.len(), 2);
    assert!(all.iter().all(|h| h.scope == Scope::Account(acc.id)));
    let snippets = ws
        .list_items::<Snippet>(&ws.default_filter())
        .await
        .unwrap();
    assert_eq!(snippets[0].scope, Scope::Device);
}

#[tokio::test]
async fn signed_out_account_needs_sign_in() {
    let fx = Fixture::new();
    fx.server("https://ssh.example.com", "ana@example.com", false);
    let h = new_id();
    fx.host(h, "web", None, "synced", true);
    let ws = fx.open();
    let info = &ws.accounts()[0];
    assert_eq!(info.status, AccountStatus::NeedsSignIn);
    // Its data stays readable offline.
    let acc = ws.current().unwrap();
    assert!(!acc.is_signed_in());
    assert_eq!(acc.store.list::<Host>(LOCAL_OWNER).await.unwrap().len(), 1);
    assert!(ws.server().await.unwrap().is_none());
    assert!(acc.sync_once().await.is_err());
}

#[tokio::test]
async fn never_signed_in_keeps_everything_on_the_device() {
    let fx = Fixture::new();
    let (h, k) = (new_id(), new_id());
    fx.host(h, "web", Some(k), "synced", true);
    fx.key(k, "deploy", "device_only");
    let ws = fx.open();
    assert!(ws.accounts().is_empty());
    assert!(ws.current().is_none());
    assert_eq!(ws.store.list::<Host>(LOCAL_OWNER).await.unwrap().len(), 1);
    assert_eq!(ws.store.list::<SshKey>(LOCAL_OWNER).await.unwrap().len(), 1);
    assert!(fx.path().join("termoak.db.pre-accounts").exists());
    assert!(
        !fx.path().join("accounts").exists()
            || std::fs::read_dir(fx.path().join("accounts"))
                .unwrap()
                .next()
                .is_none()
    );
    // The host still connects with its key.
    let r = ws.resolve(h).await.unwrap();
    assert_eq!(r.key.unwrap().private_key, "PRIVATE-deploy");
}

#[tokio::test]
async fn old_official_address_becomes_termoak_com() {
    let fx = Fixture::new();
    fx.server("https://aceitunoak.ohz.ovh/", "ana@example.com", true);
    let ws = fx.open();
    let info = &ws.accounts()[0];
    assert_eq!(info.server_url, "https://termoak.com");
    if option_env!("TERMOAK_OFFICIAL_SERVER").is_none() {
        assert!(info.official);
    }
}

#[tokio::test]
async fn synced_host_with_a_device_only_key() {
    let fx = Fixture::new();
    fx.server("https://ssh.example.com", "ana@example.com", true);
    let (h, k) = (new_id(), new_id());
    fx.host(h, "web", Some(k), "synced", false);
    fx.key(k, "laptop", "device_only");
    let ws = fx.open();
    let acc = ws.current().unwrap();
    // The host went to the account, the key stayed on the device...
    assert!(acc.store.get::<Host>(LOCAL_OWNER, h).await.is_ok());
    assert!(ws.store.get::<SshKey>(LOCAL_OWNER, k).await.is_ok());
    assert!(acc.store.get::<SshKey>(LOCAL_OWNER, k).await.is_err());
    // ...and the host still resolves with it (device store fallback).
    let r = ws.resolve(h).await.unwrap();
    assert_eq!(r.key.as_ref().unwrap().private_key, "PRIVATE-laptop");
    assert_eq!(r.password.as_deref(), Some("pw-web"));
    let item = ws.locate(h).await.unwrap();
    assert_eq!(item.scope, Scope::Account(acc.id));
    let sec: SshKeySecret = ws
        .item_secret::<SshKey>(termoak_client::ItemRef {
            scope: Scope::Device,
            id: k,
        })
        .await
        .unwrap();
    assert_eq!(sec.private_key.as_deref(), Some("PRIVATE-laptop"));
}

#[tokio::test]
async fn an_interrupted_migration_resumes_with_the_same_account() {
    let fx = Fixture::new();
    fx.server("https://ssh.example.com", "ana@example.com", true);
    let h = new_id();
    fx.host(h, "web", None, "synced", true);
    // Interrupted after creating the account and copying the rows (the v9
    // schema is applied first, as the real migration does).
    termoak_core::store::create_at_version(&fx.path().join("termoak.db"), 9).unwrap();
    let id = new_id();
    fx.meta("layout.migrating", &id.to_string());
    let acct_path = fx.path().join(format!("accounts/{id}.db"));
    std::fs::create_dir_all(acct_path.parent().unwrap()).unwrap();
    termoak_core::store::create_at_version(&acct_path, 9).unwrap();
    {
        let c = Connection::open(&acct_path).unwrap();
        c.execute(
            "ATTACH DATABASE ?1 AS old",
            [fx.path().join("termoak.db").to_string_lossy().as_ref()],
        )
        .unwrap();
        c.execute(
            "INSERT INTO main.entities SELECT * FROM old.entities WHERE sync_mode = 'synced'",
            [],
        )
        .unwrap();
    }
    let ws = fx.open();
    let accounts = ws.accounts();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].id, id);
    let acc = ws.current().unwrap();
    assert_eq!(acc.store.dirty_records().await.unwrap().len(), 1);
    assert!(ws.store.list::<Host>(LOCAL_OWNER).await.unwrap().is_empty());
    assert!(
        ws.store
            .meta_get("layout.migrating")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn sign_out_deletes_the_account_store() {
    let fx = Fixture::new();
    fx.server("http://127.0.0.1:9", "ana@example.com", true);
    let h = new_id();
    fx.host(h, "web", None, "synced", true);
    let ws = fx.open();
    let acc = ws.current().unwrap();
    let id = acc.id;
    drop(acc);
    let file = fx.path().join(format!("accounts/{id}.db"));
    assert!(file.exists());
    // One unsynced change: nothing happens without discarding it.
    let report = ws.sign_out(id, false).await.unwrap();
    assert!(!report.signed_out);
    assert_eq!(report.unsynced, 1);
    assert!(file.exists());
    let report = ws.sign_out(id, true).await.unwrap();
    assert!(report.signed_out);
    assert_eq!(report.discarded, 1);
    assert!(!file.exists());
    assert!(ws.accounts().is_empty());
    drop(ws);
    // Gone for good.
    let ws = fx.open();
    assert!(ws.accounts().is_empty());
}

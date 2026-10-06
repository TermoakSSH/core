//! An account on a server without vaults (0.3): sign-in registers the
//! account, the legacy sync (`/api/v1/sync`) is used with one implicit
//! personal vault, and signing in again reuses the account.

use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::{Value, json};
use termoak_client::{LOCAL_OWNER, SaveTarget, Scope, ServerChoice, Workspace};
use termoak_core::Id;
use termoak_core::crypto::MasterKey;
use termoak_core::model::{Host, HostSettings, SecretUpdate};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

type Seen = Arc<Mutex<Vec<(String, Value)>>>;

const USER: &str = "0190a3a4-7b1c-7cc0-9c1b-6d5f3e2a1b00";
const SERVER_HOST: &str = "0190a3a4-7b1c-7cc0-9c1b-6d5f3e2a1b77";

fn user() -> Value {
    json!({"id": USER, "email": "ana@example.com", "name": "Ana", "is_admin": false,
           "disabled": false, "created_at": 1})
}

fn answer(path: &str, body: &Value) -> (u16, Value) {
    match path {
        // A 0.3 server: no instance id, no vaults, no sync v2.
        "/api/v1/info" => (
            200,
            json!({"name": "Termoak", "version": "0.2.2", "api": "v1",
                   "features": {"sync": true, "teams": true}}),
        ),
        "/api/v1/auth/login" => (
            200,
            json!({"user": user(), "tokens": {"access_token": "a", "access_expires_at": i64::MAX,
                   "refresh_token": "r", "refresh_expires_at": i64::MAX,
                   "device_id": "0190a3a4-7b1c-7cc0-9c1b-6d5f3e2a1b01"}}),
        ),
        "/api/v1/me" => (200, json!({"user": user()})),
        "/api/v1/sync" => {
            let accepted: Vec<Value> = body["changes"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|c| c["id"].clone())
                .collect();
            (
                200,
                json!({"rev": 9, "accepted": accepted, "changes": [{
                    "id": SERVER_HOST, "kind": "host",
                    "data": {"label": "from-server", "address": "s.example.com", "settings": {"username": "ops"}},
                    "secret": {"password": "server-pw"},
                    "sync_mode": "synced", "updated_at": 5, "deleted": false, "rev": 9
                }]}),
            )
        }
        _ => (
            404,
            json!({"error": {"code": "not_found", "message": "no such route"}}),
        ),
    }
}

async fn fake_server() -> (String, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen: Seen = Arc::default();
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let log = log.clone();
            tokio::spawn(async move {
                let mut stream = BufReader::new(stream);
                loop {
                    let mut line = String::new();
                    if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                    let mut len = 0usize;
                    loop {
                        let mut h = String::new();
                        stream.read_line(&mut h).await.unwrap();
                        let h = h.trim_end();
                        if h.is_empty() {
                            break;
                        }
                        let (name, value) = h.split_once(':').unwrap_or((h, ""));
                        if name.eq_ignore_ascii_case("content-length") {
                            len = value.trim().parse().unwrap();
                        }
                    }
                    let mut raw = vec![0; len];
                    stream.read_exact(&mut raw).await.unwrap();
                    let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
                    let (status, reply) = answer(&path, &body);
                    log.lock().push((path, body));
                    let reply = reply.to_string();
                    let head = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                        reply.len()
                    );
                    let s = stream.get_mut();
                    s.write_all(head.as_bytes()).await.unwrap();
                    s.write_all(reply.as_bytes()).await.unwrap();
                }
            });
        }
    });
    (base, seen)
}

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
    }
}

#[tokio::test]
async fn an_old_server_uses_the_legacy_sync() {
    let (base, seen) = fake_server().await;
    let dir = tempfile::tempdir().unwrap();
    let ws = Workspace::open(dir.path(), MasterKey::generate()).unwrap();

    let acc = ws
        .sign_in(
            ServerChoice::Custom(base.clone()),
            "ana@example.com",
            "pw",
            None,
        )
        .await
        .unwrap();
    let info = acc.info();
    assert!(!info.vaults_supported());
    assert_eq!(info.user_id, Some(USER.parse().unwrap()));
    assert_eq!(ws.current().unwrap().id, acc.id);

    // A new synced item goes to the account, without a vault.
    let saved = ws
        .save_item(SaveTarget::Auto, host("local"), SecretUpdate::Keep, None)
        .await
        .unwrap();
    assert_eq!(saved.scope, Scope::Account(acc.id));
    assert_eq!(saved.record.meta.vault_id, None);

    let report = acc.sync_once().await.unwrap();
    assert_eq!(report.protocol, "legacy");
    assert_eq!(report.pushed, 1);
    assert_eq!(report.pulled, 1);
    let hosts = acc.store.list::<Host>(LOCAL_OWNER).await.unwrap();
    assert_eq!(hosts.len(), 2);
    assert!(hosts.iter().all(|h| h.meta.vault_id.is_none()));
    // Both resolve inside the implicit personal vault.
    let r = ws.resolve(SERVER_HOST.parse().unwrap()).await.unwrap();
    assert_eq!(r.password.as_deref(), Some("server-pw"));
    assert!(
        !seen
            .lock()
            .iter()
            .any(|(p, _)| p.starts_with("/api/v1/vaults"))
    );

    // Signing in again (same server and user) is the same account.
    let again = ws
        .sign_in(
            ServerChoice::Custom(format!("{base}/")),
            "ana@example.com",
            "pw",
            None,
        )
        .await
        .unwrap();
    assert_eq!(again.id, acc.id);
    assert_eq!(ws.accounts().len(), 1);

    // The legacy logout keeps the data and asks to sign in again.
    ws.logout().await.unwrap();
    assert!(ws.server().await.unwrap().is_none());
    assert_eq!(
        ws.accounts()[0].status,
        termoak_client::AccountStatus::NeedsSignIn
    );
    assert_eq!(acc.store.list::<Host>(LOCAL_OWNER).await.unwrap().len(), 2);
    // Reopened: still signed out (the tokens were removed from the registry).
    drop(again);
    drop(acc);
    let key = ws.store.master_key().clone();
    drop(ws);
    let ws = Workspace::open(dir.path(), key).unwrap();
    assert!(!ws.current().unwrap().is_signed_in());
}

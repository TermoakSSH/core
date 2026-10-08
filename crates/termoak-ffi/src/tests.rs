//! FFI layer tests: the exported API is called directly from Rust (`async`
//! functions are awaited with the crate's own runtime).

use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use parking_lot::{Condvar, Mutex};

use crate::runtime::block_on;
use crate::*;

fn new_core(dir: &std::path::Path, key: &str) -> Arc<TermoakCore> {
    TermoakCore::new(dir.to_string_lossy().into_owned(), key.to_string()).unwrap()
}

fn host(label: &str, address: &str) -> SshHost {
    SshHost {
        id: String::new(),
        label: label.into(),
        address: address.into(),
        group_id: None,
        tags: vec![],
        settings: HostSettings::default(),
        notes: String::new(),
        color: None,
        os: None,
        os_version: None,
        favorite: false,
        protocol: "ssh".into(),
        icon: None,
        sync_mode: None,
        has_password: false,
        updated_at: 0,
        account_id: None,
        vault_id: None,
        access: None,
        secret_hidden: false,
    }
}

fn set(v: &str) -> SecretChange {
    SecretChange::Set { value: v.into() }
}

#[test]
fn vault_key_roundtrip() {
    let key = generate_vault_key();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&key)
        .unwrap();
    assert_eq!(raw.len(), 32);
    assert_ne!(key, generate_vault_key());

    let dir = tempfile::tempdir().unwrap();
    let id = {
        let core = new_core(dir.path(), &key);
        assert_eq!(core.data_dir(), dir.path().to_string_lossy());
        core.save_host(host("web", "10.0.0.1"), set("s3cr3t"))
            .unwrap()
            .id
    };
    // Same key: the secrets can be read.
    let core = new_core(dir.path(), &key);
    assert_eq!(
        core.host_password(id.clone(), None).unwrap().as_deref(),
        Some("s3cr3t")
    );
    drop(core);

    // Another key: detected on open.
    let other = TermoakCore::new(
        dir.path().to_string_lossy().into_owned(),
        generate_vault_key(),
    );
    assert!(matches!(other, Err(TermoakError::Vault(_))));
    // Malformed key.
    let bad = TermoakCore::new(
        dir.path().to_string_lossy().into_owned(),
        "not-base64!".into(),
    );
    assert!(matches!(bad, Err(TermoakError::Vault(_))));
}

#[test]
fn hosts_groups_and_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path(), &generate_vault_key());

    let group = core
        .save_group(HostGroup {
            id: String::new(),
            name: "prod".into(),
            parent_id: None,
            color: Some("#00ff00".into()),
            settings: HostSettings {
                port: Some(2222),
                username: Some("deploy".into()),
                env: HashMap::from([("LANG".to_string(), "es_ES.UTF-8".to_string())]),
                ..Default::default()
            },
            sync_mode: None,
            updated_at: 0,
            account_id: None,
            vault_id: None,
            access: None,
            secret_hidden: false,
        })
        .unwrap();
    assert!(!group.id.is_empty());
    assert_eq!(group.sync_mode, Some(SyncMode::Synced));

    let mut h = host("web-1", " web1.example.com ");
    h.group_id = Some(group.id.clone());
    h.tags = vec!["nginx".into()];
    h.settings.term = Some("xterm".into());
    h.sync_mode = Some(SyncMode::DeviceOnly);
    let saved = core.save_host(h, set("pw")).unwrap();
    assert_eq!(saved.address, "web1.example.com");
    assert!(saved.has_password);
    assert_eq!(saved.sync_mode, Some(SyncMode::DeviceOnly));
    assert!(saved.updated_at > 0);

    // Effective settings: group + host.
    let eff = core.effective_settings(saved.id.clone(), None).unwrap();
    assert_eq!(eff.port, Some(2222));
    assert_eq!(eff.username.as_deref(), Some("deploy"));
    assert_eq!(eff.term.as_deref(), Some("xterm"));
    assert_eq!(eff.env.get("LANG").map(String::as_str), Some("es_ES.UTF-8"));

    // Updating without touching the secret (or the mode) keeps them.
    let mut upd = core.get_host(saved.id.clone(), None).unwrap();
    upd.label = "web-01".into();
    upd.sync_mode = None;
    let upd = core.save_host(upd, SecretChange::Keep).unwrap();
    assert_eq!(upd.label, "web-01");
    assert_eq!(upd.sync_mode, Some(SyncMode::DeviceOnly));
    assert_eq!(
        core.host_password(saved.id.clone(), None)
            .unwrap()
            .as_deref(),
        Some("pw")
    );
    // Clear the secret.
    let cleared = core.save_host(upd, SecretChange::Clear).unwrap();
    assert!(!cleared.has_password);
    assert_eq!(core.host_password(saved.id.clone(), None).unwrap(), None);

    assert_eq!(core.list_hosts(None).unwrap().len(), 1);
    assert_eq!(core.list_groups(None).unwrap().len(), 1);

    // Protocol and logo go through (SSH and automatic by default).
    assert_eq!(cleared.protocol, "ssh");
    assert_eq!(cleared.icon, None);
    let mut telnet = host("switch", "10.0.0.2");
    telnet.protocol = "Telnet".into();
    telnet.icon = Some("router".into());
    let telnet = core.save_host(telnet, SecretChange::Keep).unwrap();
    assert_eq!(telnet.protocol, "telnet");
    assert_eq!(telnet.icon.as_deref(), Some("router"));
    let again = core.get_host(telnet.id.clone(), None).unwrap();
    assert_eq!(
        (again.protocol.as_str(), again.icon),
        ("telnet", Some("router".into()))
    );
    core.delete_host(telnet.id, None).unwrap();

    // Errors with useful variants.
    assert!(matches!(
        core.save_host(host("", "x"), SecretChange::Keep),
        Err(TermoakError::Invalid(_))
    ));
    assert!(matches!(
        core.save_host(host("x", "with spaces"), SecretChange::Keep),
        Err(TermoakError::Invalid(_))
    ));
    let mut bad_port = host("x", "x");
    bad_port.settings.port = Some(70000);
    assert!(matches!(
        core.save_host(bad_port, SecretChange::Keep),
        Err(TermoakError::Invalid(_))
    ));
    assert!(matches!(
        core.get_host("not-an-id".into(), None),
        Err(TermoakError::Invalid(_))
    ));

    core.delete_host(saved.id.clone(), None).unwrap();
    assert!(matches!(
        core.get_host(saved.id.clone(), None),
        Err(TermoakError::NotFound(_))
    ));
    assert!(matches!(
        core.delete_host(saved.id, None),
        Err(TermoakError::NotFound(_))
    ));
    core.delete_group(group.id, None).unwrap();
    assert!(core.list_groups(None).unwrap().is_empty());
}

#[test]
fn command_history_and_line_tracking() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path(), &generate_vault_key());
    let web = core
        .save_host(host("web", "web.lan"), SecretChange::Keep)
        .unwrap();
    let db = core
        .save_host(host("db", "db.lan"), SecretChange::Keep)
        .unwrap();

    // What is typed in the terminal: only what shows up on screen is saved.
    let line = LineTracker::new();
    let run = |bytes: &[u8], screen: &str| {
        let pending = line.current();
        let echoed = pending
            .clone()
            .is_some_and(|p| command_echoed(p, screen.into(), true));
        if let Some(sent) = line.feed(bytes.to_vec())
            && echoed
            && pending.as_deref() == Some(sent.as_str())
        {
            core.record_command(web.id.clone(), sent).unwrap();
        }
    };
    run(b"htop", "");
    run(b"\r", "ana@web:~$ htop");
    run(b"secret", "");
    run(b"\r", "[sudo] password for ana: ");
    run(b"ls -la", "");
    run(b"\r", "ana@web:~$ ls -la");
    run(b"ls -la", "");
    run(b"\r", "ana@web:~$ ls -la");
    core.record_command(db.id.clone(), "psql".into()).unwrap();

    // Suggestions for what is being typed: only with the cursor at the end.
    let typing = LineTracker::new();
    typing.feed(b"ls -".to_vec());
    assert!(typing.at_end());
    let sug = core
        .complete_command(Some(web.id.clone()), None, typing.current().unwrap(), 5)
        .unwrap();
    assert_eq!(sug[0].text, "ls -la");
    assert_eq!(sug[0].insert, "la");
    typing.feed(b"\x1b[D".to_vec());
    assert!(!typing.at_end());

    let names = |items: Vec<CommandHistoryItem>| -> Vec<String> {
        items.into_iter().map(|i| i.command).collect()
    };
    // The host's first (most used first), then the others'.
    let all = core
        .command_history(Some(web.id.clone()), String::new(), 10)
        .unwrap();
    assert_eq!(all[0].uses, 2);
    assert_eq!(names(all), ["ls -la", "htop", "psql"]);
    // Filter by substring, case-insensitive.
    let found = core
        .command_history(Some(web.id.clone()), "TOP".into(), 10)
        .unwrap();
    assert_eq!(names(found), ["htop"]);
    assert_eq!(
        core.command_history(None, String::new(), 1).unwrap().len(),
        1
    );
}

#[test]
fn identities_snippets_forwards_and_memories() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path(), &generate_vault_key());

    let ident = core
        .save_identity(
            SshIdentity {
                id: String::new(),
                label: "deploy".into(),
                username: "deploy".into(),
                key_id: None,
                sync_mode: None,
                has_password: false,
                updated_at: 0,
                account_id: None,
                vault_id: None,
                access: None,
                secret_hidden: false,
            },
            set("secret"),
        )
        .unwrap();
    assert!(ident.has_password);
    assert_eq!(
        core.identity_password(ident.id.clone(), None)
            .unwrap()
            .as_deref(),
        Some("secret")
    );
    assert_eq!(core.list_identities(None).unwrap().len(), 1);

    // Snippets and variables.
    let snip = core
        .save_snippet(Snippet {
            id: String::new(),
            name: "logs".into(),
            script: "journalctl -u {{service}} -n {{lines}}".into(),
            description: "Latest logs".into(),
            tags: vec!["systemd".into()],
            sync_mode: None,
            updated_at: 0,
            account_id: None,
            vault_id: None,
            access: None,
            secret_hidden: false,
        })
        .unwrap();
    assert_eq!(
        core.get_snippet(snip.id.clone(), None).unwrap().name,
        "logs"
    );
    assert_eq!(
        snippet_variables(snip.script.clone()),
        vec!["service", "lines"]
    );
    let values = HashMap::from([
        ("service".to_string(), "nginx".to_string()),
        ("lines".to_string(), "50".to_string()),
    ]);
    assert_eq!(
        render_snippet(snip.script.clone(), values).unwrap(),
        "journalctl -u nginx -n 50"
    );
    assert!(matches!(
        render_snippet(snip.script.clone(), HashMap::new()),
        Err(TermoakError::Invalid(_))
    ));

    // Tunnels.
    let h = core
        .save_host(host("db", "10.0.0.2"), SecretChange::Keep)
        .unwrap();
    let other = core
        .save_host(host("other", "10.0.0.3"), SecretChange::Keep)
        .unwrap();
    let local = PortForward {
        id: String::new(),
        label: "postgres".into(),
        host_id: h.id.clone(),
        kind: ForwardKind::Local,
        bind_address: String::new(),
        bind_port: 15432,
        dest_host: Some("127.0.0.1".into()),
        dest_port: Some(5432),
        auto_start: true,
        sync_mode: None,
        updated_at: 0,
        account_id: None,
        vault_id: None,
        access: None,
        secret_hidden: false,
    };
    let saved = core.save_forward(local.clone()).unwrap();
    assert_eq!(saved.bind_address, "127.0.0.1");
    core.save_forward(PortForward {
        label: "socks".into(),
        host_id: other.id.clone(),
        kind: ForwardKind::Dynamic,
        dest_host: None,
        dest_port: None,
        ..local.clone()
    })
    .unwrap();
    assert_eq!(core.list_forwards(None, None).unwrap().len(), 2);
    assert_eq!(
        core.list_forwards(Some(h.id.clone()), None).unwrap().len(),
        1
    );
    // A local tunnel without a destination is invalid.
    assert!(matches!(
        core.save_forward(PortForward {
            dest_host: None,
            ..local.clone()
        }),
        Err(TermoakError::Invalid(_))
    ));
    core.delete_forward(saved.id, None).unwrap();
    assert_eq!(core.list_forwards(None, None).unwrap().len(), 1);

    // AI memories.
    let mem = core
        .save_memory(AiMemory {
            id: String::new(),
            content: "The database is on db (10.0.0.2)".into(),
            host_id: Some(h.id.clone()),
            updated_at: 0,
            account_id: None,
            vault_id: None,
            access: None,
            secret_hidden: false,
        })
        .unwrap();
    assert_eq!(core.list_memories(None).unwrap().len(), 1);
    core.delete_memory(mem.id, None).unwrap();
    assert!(core.list_memories(None).unwrap().is_empty());
    assert!(core.list_known_hosts(None).unwrap().is_empty());
}

#[test]
fn key_generation_and_import() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path(), &generate_vault_key());

    // Encrypted key without saving the passphrase.
    let k = block_on(core.generate_key(
        "laptop".into(),
        KeyType::Ed25519,
        "me@phone".into(),
        Some("passphrase".into()),
        false,
        Some(SyncMode::DeviceOnly),
        None,
        None,
    ))
    .unwrap();
    assert!(k.public_key.starts_with("ssh-ed25519 "));
    assert!(k.fingerprint.starts_with("SHA256:"));
    assert!(k.has_passphrase && k.has_private_key);
    assert_eq!(k.comment, "me@phone");
    assert_eq!(k.sync_mode, Some(SyncMode::DeviceOnly));
    let pem = core
        .export_private_key(k.id.clone(), None)
        .unwrap()
        .unwrap();
    assert!(pem.contains("OPENSSH PRIVATE KEY"));

    // Preview: the public part matches; a wrong passphrase fails.
    let details = block_on(inspect_private_key(pem.clone(), Some("passphrase".into()))).unwrap();
    assert_eq!(details.fingerprint, k.fingerprint);
    assert!(details.encrypted);
    assert!(matches!(
        block_on(inspect_private_key(pem.clone(), Some("wrong".into()))),
        Err(TermoakError::Invalid(_))
    ));

    // Edit: label and saved passphrase; the private key does not change.
    let mut edit = k.clone();
    edit.label = "iPhone".into();
    edit.public_key = "tampered".into();
    let edited = core.save_key(edit, set("passphrase")).unwrap();
    assert_eq!(edited.label, "iPhone");
    assert_eq!(edited.public_key, k.public_key);
    assert_eq!(
        core.export_private_key(k.id.clone(), None)
            .unwrap()
            .unwrap(),
        pem
    );
    assert!(matches!(
        core.save_key(
            SshKey {
                id: String::new(),
                ..k.clone()
            },
            SecretChange::Keep
        ),
        Err(TermoakError::Invalid(_))
    ));

    // Import an unencrypted key generated elsewhere.
    let material =
        termoak_ssh::keys::generate(termoak_ssh::keys::KeyType::EcdsaP256, "external", None)
            .unwrap();
    let imported = block_on(core.import_key(
        "external".into(),
        material.private_openssh.clone(),
        None,
        false,
        None,
        None,
        None,
    ))
    .unwrap();
    assert_eq!(imported.fingerprint, material.fingerprint);
    assert!(!imported.has_passphrase);
    assert_eq!(imported.sync_mode, Some(SyncMode::Synced));
    assert!(matches!(
        block_on(core.import_key(
            "broken".into(),
            "garbage".into(),
            None,
            false,
            None,
            None,
            None
        )),
        Err(TermoakError::Invalid(_))
    ));

    assert_eq!(core.list_keys(None).unwrap().len(), 2);
    core.delete_key(imported.id, None).unwrap();
    assert_eq!(core.list_keys(None).unwrap().len(), 1);
}

#[test]
fn server_calls_without_login() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path(), &generate_vault_key());
    assert!(!block_on(core.is_logged_in()).unwrap());
    assert_eq!(block_on(core.server_url()).unwrap(), None);
    assert!(matches!(
        block_on(core.list_server_sessions()),
        Err(TermoakError::NotLoggedIn(_))
    ));
    assert!(matches!(
        block_on(core.api_get("/api/v1/me".into())),
        Err(TermoakError::NotLoggedIn(_))
    ));
    assert!(matches!(
        block_on(core.api_get("me".into())),
        Err(TermoakError::Invalid(_))
    ));
    // Unreachable server: network error.
    assert!(matches!(
        block_on(server_info("http://127.0.0.1:1".into())),
        Err(TermoakError::Network(_))
    ));
}

// ---------------------------------------------------------------------------
// End to end against a temporary sshd
// ---------------------------------------------------------------------------

struct Sshd {
    child: Child,
    port: u16,
    _dir: tempfile::TempDir,
    private_key: String,
    user: String,
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_sshd() -> Option<Sshd> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let sshd = ["/usr/sbin/sshd", "/usr/local/sbin/sshd"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())?;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let hk = d.join("hk");
    let ok = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&hk)
        .status()
        .ok()?
        .success();
    if !ok {
        return None;
    }
    let key =
        termoak_ssh::keys::generate(termoak_ssh::keys::KeyType::Ed25519, "ffi", None).unwrap();
    std::fs::write(d.join("ak"), format!("{}\n", key.public_openssh)).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::create_dir_all("/run/sshd").ok();
    let cfg = d.join("cfg");
    std::fs::write(
        &cfg,
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin yes\nAllowTcpForwarding yes\nSubsystem sftp internal-sftp\nLogLevel ERROR\n",
            hk.display(),
            d.join("pid").display(),
            d.join("ak").display()
        ),
    )
    .unwrap();
    let child = Command::new(sshd)
        .args(["-D", "-e", "-f"])
        .arg(&cfg)
        .stdout(Stdio::null())
        .spawn()
        .ok()?;
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            let user = String::from_utf8(Command::new("id").arg("-un").output().ok()?.stdout)
                .ok()?
                .trim()
                .to_string();
            return Some(Sshd {
                child,
                port,
                _dir: dir,
                private_key: key.private_openssh,
                user,
            });
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

/// Test `AuthHandler`: accepts the fingerprint and counts the prompts.
#[derive(Default)]
struct AcceptingAuth {
    host_keys: Mutex<Vec<String>>,
}

impl AuthHandler for AcceptingAuth {
    fn on_host_key(&self, host: String, port: u32, key_type: String, fingerprint: String) -> bool {
        assert!(fingerprint.starts_with("SHA256:"));
        assert!(!key_type.is_empty());
        self.host_keys.lock().push(format!("{host}:{port}"));
        true
    }

    fn on_prompt(&self, _request: AuthRequest) -> Option<Vec<String>> {
        None
    }
}

/// Test `TerminalListener`: collects output and states.
#[derive(Default)]
struct Collector {
    output: Mutex<Vec<u8>>,
    statuses: Mutex<Vec<TerminalStatus>>,
    changed: Condvar,
}

impl TerminalListener for Collector {
    fn on_output(&self, data: Vec<u8>) {
        self.output.lock().extend_from_slice(&data);
        self.changed.notify_all();
    }

    fn on_status(&self, status: TerminalStatus) {
        self.statuses.lock().push(status);
        self.changed.notify_all();
    }
}

impl Collector {
    fn wait_output(&self, needle: &str) {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut out = self.output.lock();
        while !String::from_utf8_lossy(&out).contains(needle) {
            if self.changed.wait_until(&mut out, deadline).timed_out() {
                panic!(
                    "{needle:?} did not appear in the output: {:?}",
                    String::from_utf8_lossy(&out)
                );
            }
        }
    }

    fn wait_closed(&self) {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut statuses = self.statuses.lock();
        while !statuses
            .iter()
            .any(|s| matches!(s, TerminalStatus::Closed { .. }))
        {
            if self.changed.wait_until(&mut statuses, deadline).timed_out() {
                panic!("the terminal did not close: {statuses:?}");
            }
        }
    }
}

#[derive(Default)]
struct Progress(Mutex<Vec<(u64, Option<u64>)>>);

impl TransferListener for Progress {
    fn on_progress(&self, transferred: u64, total: Option<u64>) {
        self.0.lock().push((transferred, total));
    }
}

#[test]
fn ssh_end_to_end() {
    let Some(sshd) = start_sshd() else {
        eprintln!("sshd not available: test skipped");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(&dir.path().join("vault"), &generate_vault_key());
    let key = block_on(core.import_key(
        "test".into(),
        sshd.private_key.clone(),
        None,
        false,
        None,
        None,
        None,
    ))
    .unwrap();
    let mut h = host("local", "127.0.0.1");
    h.settings.port = Some(sshd.port.into());
    h.settings.username = Some(sshd.user.clone());
    h.settings.key_id = Some(key.id.clone());
    let h = core.save_host(h, SecretChange::Keep).unwrap();

    // Terminal: the fingerprint is confirmed the first time.
    let auth = Arc::new(AcceptingAuth::default());
    let listener = Arc::new(Collector::default());
    let term = block_on(core.connect_terminal(
        h.id.clone(),
        100,
        30,
        auth.clone(),
        listener.clone(),
        None,
        true,
    ))
    .unwrap();
    assert!(!term.is_telnet());
    assert_eq!(term.session().protocol(), "ssh");
    assert_eq!(auth.host_keys.lock().len(), 1);
    assert_eq!(core.list_known_hosts(None).unwrap().len(), 1);
    assert_eq!(term.status(), TerminalStatus::Running);
    term.resize(120, 40).unwrap();
    term.write_text("echo termoak-$((40+2))\n".into()).unwrap();
    listener.wait_output("termoak-42");
    assert!(String::from_utf8_lossy(&term.snapshot()).contains("termoak-42"));
    assert!(term.text_tail(4000).contains("termoak-42"));

    // SFTP and commands over the same connection.
    let session = term.session();
    assert_eq!(session.host_id(), h.id);
    let details = session.details();
    assert_eq!(details.port, u32::from(sshd.port));
    assert!(details.server_fingerprint.unwrap().starts_with("SHA256:"));
    let out = block_on(session.exec("echo hello; echo error >&2; exit 3".into(), 10)).unwrap();
    assert_eq!(out.stdout.trim(), "hello");
    assert_eq!(out.stderr.trim(), "error");
    assert_eq!(out.exit_code, Some(3));

    let remote_dir = dir.path().join("remote");
    let remote = remote_dir.to_string_lossy().into_owned();
    block_on(session.clone().sftp_mkdir(format!("{remote}/a/b"), true)).unwrap();
    block_on(
        session
            .clone()
            .sftp_write(format!("{remote}/a/hello.txt"), b"hello world".to_vec()),
    )
    .unwrap();
    let listing = block_on(session.clone().sftp_list(format!("{remote}/a"))).unwrap();
    assert_eq!(
        listing.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
        vec!["b", "hello.txt"]
    );
    assert_eq!(listing[0].kind, RemoteFileKind::Dir);
    assert_eq!(listing[1].size, 11);
    assert_eq!(
        block_on(
            session
                .clone()
                .sftp_read(format!("{remote}/a/hello.txt"), 1024)
        )
        .unwrap(),
        b"hello world"
    );

    let local_file = dir.path().join("downloaded.txt");
    let progress = Arc::new(Progress::default());
    let n = block_on(session.clone().sftp_download(
        format!("{remote}/a/hello.txt"),
        local_file.to_string_lossy().into_owned(),
        Some(progress.clone()),
        None,
    ))
    .unwrap();
    assert_eq!(n, 11);
    assert_eq!(std::fs::read(&local_file).unwrap(), b"hello world");
    assert_eq!(progress.0.lock().last(), Some(&(11, Some(11))));

    let n = block_on(session.clone().sftp_upload(
        local_file.to_string_lossy().into_owned(),
        format!("{remote}/uploaded.txt"),
        None,
        None,
    ))
    .unwrap();
    assert_eq!(n, 11);
    block_on(session.clone().sftp_rename(
        format!("{remote}/uploaded.txt"),
        format!("{remote}/renamed.txt"),
    ))
    .unwrap();
    block_on(
        session
            .clone()
            .sftp_chmod(format!("{remote}/renamed.txt"), 0o600),
    )
    .unwrap();
    let st = block_on(session.clone().sftp_stat(format!("{remote}/renamed.txt"))).unwrap();
    assert_eq!(st.mode, Some(0o600));
    assert_eq!(st.mode_string, "-rw-------");
    block_on(session.clone().sftp_remove(format!("{remote}/a"), true)).unwrap();
    block_on(
        session
            .clone()
            .sftp_remove(format!("{remote}/renamed.txt"), false),
    )
    .unwrap();
    assert!(
        block_on(session.clone().sftp_list(remote.clone()))
            .unwrap()
            .is_empty()
    );
    assert!(
        block_on(session.clone().sftp_home())
            .unwrap()
            .starts_with('/')
    );
    assert!(matches!(
        block_on(session.clone().sftp_stat(format!("{remote}/missing"))),
        Err(TermoakError::Sftp(_))
    ));

    // Detecting the system stores it in the host.
    let os = block_on(session.detect_os()).unwrap();
    assert!(os.is_some());
    assert_eq!(core.get_host(h.id.clone(), None).unwrap().os, os);

    // Ad hoc local tunnel to the sshd itself.
    let fwd = block_on(session.start_forward_spec(
        ForwardKind::Local,
        String::new(),
        0,
        Some("127.0.0.1".into()),
        Some(sshd.port.into()),
    ))
    .unwrap();
    assert!(fwd.is_running() && fwd.bound_port() > 0);
    let mut s = std::net::TcpStream::connect(("127.0.0.1", fwd.bound_port() as u16)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut banner = [0u8; 8];
    std::io::Read::read_exact(&mut s, &mut banner).unwrap();
    assert_eq!(&banner, b"SSH-2.0-");
    block_on(fwd.stop()).unwrap();
    assert!(!fwd.is_running());

    // Closing the terminal reports `Closed`.
    term.close_terminal();
    listener.wait_closed();
    assert!(matches!(term.status(), TerminalStatus::Closed { .. }));
    block_on(session.disconnect()).unwrap();

    // Second connection: the fingerprint is already known and not asked.
    let session = block_on(core.connect(h.id.clone(), auth.clone(), None)).unwrap();
    assert_eq!(auth.host_keys.lock().len(), 1);
    let listener2 = Arc::new(Collector::default());
    let term2 = block_on(
        session
            .clone()
            .open_terminal(80, 24, listener2.clone(), false),
    )
    .unwrap();
    term2.write_text("exit 7\n".into()).unwrap();
    listener2.wait_closed();
    assert!(listener2.statuses.lock().iter().any(|s| matches!(
        s,
        TerminalStatus::Closed {
            exit_code: Some(7),
            ..
        }
    )));
    drop(term2);
    block_on(session.disconnect()).unwrap();

    // Known host with a changed key: rejected without asking.
    for k in core.list_known_hosts(None).unwrap() {
        let mut fake = termoak_core::model::KnownHost {
            id: termoak_core::Id::nil(),
            host: k.host.clone(),
            port: k.port as u16,
            key_type: k.key_type.clone(),
            public_key: termoak_ssh::keys::generate(termoak_ssh::keys::KeyType::Ed25519, "", None)
                .unwrap()
                .public_openssh,
            fingerprint: "SHA256:fake".into(),
        };
        core.delete_known_host(k.id, None).unwrap();
        fake.id = termoak_core::new_id();
        block_on(core.ws.store.save(
            termoak_client::LOCAL_OWNER,
            fake,
            termoak_core::model::SecretUpdate::Keep,
            None,
        ))
        .unwrap();
    }
    let err = block_on(core.connect(h.id.clone(), auth.clone(), None))
        .err()
        .unwrap();
    assert!(matches!(err, TermoakError::HostKey(_)), "{err:?}");
    assert_eq!(auth.host_keys.lock().len(), 1);
}

// ----- Telnet -----

mod telnet_codes {
    pub const IAC: u8 = 255;
    pub const DO: u8 = 253;
    pub const WILL: u8 = 251;
    pub const SB: u8 = 250;
    pub const SE: u8 = 240;
    pub const NAWS: u8 = 31;
    pub const TIMING_MARK: u8 = 6;
}

/// Reads from the fake Telnet server's socket until `want` has arrived.
fn telnet_read_until(s: &mut std::net::TcpStream, got: &mut Vec<u8>, want: &[u8]) {
    use std::io::Read;
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut buf = [0u8; 1024];
    while !got.windows(want.len()).any(|w| w == want) {
        let n = s
            .read(&mut buf)
            .unwrap_or_else(|e| panic!("waiting for {want:?} ({e}); got {got:?}"));
        assert!(n > 0, "closed while waiting for {want:?}; got {got:?}");
        got.extend_from_slice(&buf[..n]);
    }
}

/// A Telnet host on a fake server of this test (with `admin` / `pw`).
fn telnet_host(core: &TermoakCore, port: u16) -> SshHost {
    let mut h = host("switch", "127.0.0.1");
    h.protocol = "telnet".into();
    h.icon = Some("router".into());
    h.settings.port = Some(port.into());
    h.settings.username = Some("admin".into());
    core.save_host(h, set("pw")).unwrap()
}

#[test]
fn telnet_terminal_through_the_ffi() {
    use std::io::Write;
    use telnet_codes::*;

    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path(), &generate_vault_key());
    let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    let h = telnet_host(&core, port);
    assert_eq!(h.protocol, "telnet");

    // The same entry point as SSH; the AuthHandler is not used.
    let auth = Arc::new(AcceptingAuth::default());
    let listener = Arc::new(Collector::default());
    let term = block_on(core.connect_terminal(
        h.id.clone(),
        100,
        30,
        auth.clone(),
        listener.clone(),
        None,
        true,
    ))
    .unwrap();
    let (mut srv, _) = server.accept().unwrap();
    assert!(term.is_telnet());
    assert_eq!(term.protocol(), "telnet");
    assert_eq!(term.status(), TerminalStatus::Running);
    assert!(auth.host_keys.lock().is_empty());

    // Automatic login: each prompt answered once.
    srv.write_all(b"\r\nUser Access Verification\r\n\r\nUsername: ")
        .unwrap();
    let mut got = Vec::new();
    telnet_read_until(&mut srv, &mut got, b"admin\r\n");
    srv.write_all(b"Password: ").unwrap();
    telnet_read_until(&mut srv, &mut got, b"pw\r\n");

    // The host accepts NAWS: the size arrives, and again after a resize.
    srv.write_all(&[IAC, DO, NAWS]).unwrap();
    let mut got = Vec::new();
    telnet_read_until(&mut srv, &mut got, &[IAC, SB, NAWS, 0, 100, 0, 30, IAC, SE]);
    srv.write_all(b"\r\nswitch# ").unwrap();
    listener.wait_output("switch# ");
    assert!(term.text_tail(1000).contains("switch#"));
    term.resize(132, 43).unwrap();
    telnet_read_until(&mut srv, &mut got, &[IAC, SB, NAWS, 0, 132, 0, 43, IAC, SE]);

    // Input: Enter goes as CR LF.
    term.write_text("show version\r".into()).unwrap();
    telnet_read_until(&mut srv, &mut got, b"show version\r\n");

    // Latency: a TIMING-MARK, answered.
    let pinger = {
        let term = term.clone();
        std::thread::spawn(move || block_on(term.latency_ms(5000)))
    };
    telnet_read_until(&mut srv, &mut got, &[IAC, DO, TIMING_MARK]);
    srv.write_all(&[IAC, WILL, TIMING_MARK]).unwrap();
    let ms = pinger.join().unwrap().unwrap();
    assert!((0.0..5000.0).contains(&ms), "{ms}");

    // The session: details work, SSH-only calls are refused clearly.
    let session = term.session();
    assert!(session.is_telnet());
    assert_eq!(session.host_id(), h.id);
    let details = session.details();
    assert_eq!(details.port, u32::from(port));
    assert_eq!(details.address, "127.0.0.1");
    assert!(details.server_fingerprint.is_none());
    let refused = |r: std::result::Result<(), TermoakError>| {
        let e = r.unwrap_err();
        assert!(matches!(e, TermoakError::NotSupportedForTelnet(_)), "{e:?}");
        assert!(e.to_string().contains("Telnet"), "{e}");
    };
    refused(block_on(session.clone().sftp_home()).map(drop));
    refused(block_on(session.clone().sftp_list("/".into())).map(drop));
    refused(block_on(session.exec("uname".into(), 5)).map(drop));
    refused(block_on(session.detect_os()).map(drop));
    refused(
        block_on(session.start_forward_spec(
            ForwardKind::Local,
            "127.0.0.1".into(),
            0,
            Some("127.0.0.1".into()),
            Some(80),
        ))
        .map(drop),
    );
    refused(block_on(session.start_auto_forwards()).map(drop));
    refused(
        block_on(
            session
                .clone()
                .open_terminal(80, 24, Arc::new(Collector::default()), false),
        )
        .map(drop),
    );
    // An SSH connection to a Telnet host (for files or tunnels).
    refused(block_on(core.connect(h.id.clone(), auth.clone(), None)).map(drop));
    assert!(!session.is_closed());

    // Closing: the host sees the end, the app gets Closed.
    term.close_terminal();
    let mut rest = Vec::new();
    {
        use std::io::Read;
        srv.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut buf = [0u8; 256];
        loop {
            match srv.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => rest.extend_from_slice(&buf[..n]),
                Err(e) => panic!("the client did not hang up: {e}"),
            }
        }
    }
    listener.wait_closed();
    assert!(session.is_closed());
    assert!(matches!(term.status(), TerminalStatus::Closed { .. }));
}

#[test]
fn telnet_without_auto_login_and_host_hanging_up() {
    use std::io::Write;

    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path(), &generate_vault_key());
    let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    let h = telnet_host(&core, port);
    let listener = Arc::new(Collector::default());
    let term = block_on(core.connect_terminal(
        h.id.clone(),
        80,
        24,
        Arc::new(AcceptingAuth::default()),
        listener.clone(),
        None,
        false,
    ))
    .unwrap();
    let (mut srv, _) = server.accept().unwrap();
    srv.write_all(b"login: ").unwrap();
    listener.wait_output("login: ");
    // Nothing typed for the user: what arrives is what they type.
    term.write_text("guest\r".into()).unwrap();
    let mut got = Vec::new();
    telnet_read_until(&mut srv, &mut got, b"guest\r\n");
    assert!(!got.windows(5).any(|w| w == b"admin"), "{got:?}");
    // A raw TCP service never spoke Telnet: no timing marks.
    let fresh = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let raw = telnet_host(&core, fresh.local_addr().unwrap().port());
    let raw_term = block_on(core.connect_terminal(
        raw.id,
        80,
        24,
        Arc::new(AcceptingAuth::default()),
        Arc::new(Collector::default()),
        None,
        false,
    ))
    .unwrap();
    let _raw_srv = fresh.accept().unwrap();
    assert!(block_on(raw_term.latency_ms(2000)).is_err());

    // The host hangs up.
    drop(srv);
    listener.wait_closed();
    let statuses = listener.statuses.lock().clone();
    assert!(
        statuses.iter().any(|s| matches!(
            s,
            TerminalStatus::Closed { reason: Some(r), .. } if r.contains("closed by the host")
        )),
        "{statuses:?}"
    );
}

#[test]
fn shared_session_owner_name_and_activity() {
    let shared = serde_json::json!({
        "id": "s", "owner_id": "o", "title": "t", "kind": "server",
        "state": {"state": "running"}, "created_at": 1, "cols": 132, "rows": 40,
        "recording": true, "access": "view", "viewers": [], "participants": [],
        "owner_name": " Ana ",
    });
    let s = crate::server::ServerSession::from_json(&shared);
    assert_eq!(s.owner_name.as_deref(), Some("Ana"));
    assert_eq!(s.access, SessionAccess::View);
    assert_eq!((s.cols, s.rows), (132, 40));
    let mut own = shared.clone();
    own.as_object_mut().unwrap().remove("owner_name");
    assert_eq!(
        crate::server::ServerSession::from_json(&own).owner_name,
        None
    );

    let v = serde_json::json!({
        "started_at": 1000,
        "authors": [
            {"time": 0.0, "participant": "p1", "name": "Ana", "kind": "owner"},
            {"time": 3.0, "participant": "p1", "name": "Ana", "kind": "owner"},
            {"time": 5.5, "participant": "p2", "name": "Zoe", "kind": "guest"},
            {"time": 9.0, "name": "AI", "kind": "ai"},
            {"name": "no time"},
            {"time": 12.0, "participant": "p1", "name": "Ana", "kind": "owner"},
        ],
    });
    let a = SessionActivity::from_json(&v);
    assert_eq!(a.started_at, Some(1000));
    let spans: Vec<_> = a
        .periods
        .iter()
        .map(|p| (p.name.as_str(), p.kind.as_str(), p.from_secs, p.to_secs))
        .collect();
    assert_eq!(
        spans,
        vec![
            ("Ana", "owner", 0.0, Some(5.5)),
            ("Zoe", "guest", 5.5, Some(9.0)),
            ("AI", "ai", 9.0, Some(12.0)),
            ("Ana", "owner", 12.0, None),
        ]
    );
    assert_eq!(a.periods[2].participant, None);
    let empty = SessionActivity::from_json(&serde_json::json!({}));
    assert!(empty.periods.is_empty() && empty.started_at.is_none());
}

/// A 0.3 data directory as the mobile apps left it: one store with the
/// vault check marker, a server with tokens, a synced host and a
/// device-only key.
fn v03_dir(key_b64: &str, wrong_marker: bool) -> (tempfile::TempDir, String, String) {
    use termoak_core::crypto::MasterKey;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("termoak.db");
    termoak_core::store::create_at_version(&path, 8).unwrap();
    let key = MasterKey::from_base64(key_b64).unwrap();
    let marker_key = if wrong_marker {
        MasterKey::generate()
    } else {
        key.clone()
    };
    let c = rusqlite_like::open(&path);
    let b64 = |b: Vec<u8>| base64::engine::general_purpose::STANDARD.encode(b);
    let meta = |k: &str, v: &str| rusqlite_like::meta(&c, k, v);
    meta(
        "ffi.vault_check",
        &b64(marker_key
            .seal(b"aceitunoak", b"aceitunoak:ffi-vault-check")
            .unwrap()),
    );
    meta("server.url", "https://ssh.example.com");
    meta("server.user", "ana@example.com");
    let tokens = serde_json::json!({"access_token": "a", "access_expires_at": i64::MAX,
        "refresh_token": "r", "refresh_expires_at": i64::MAX,
        "device_id": termoak_core::Id::nil()});
    meta(
        "server.tokens",
        &b64(key
            .seal(tokens.to_string().as_bytes(), b"aceitunoak:server-tokens")
            .unwrap()),
    );
    let host_id = termoak_core::new_id().to_string();
    let key_id = termoak_core::new_id().to_string();
    rusqlite_like::entity(
        &c,
        &host_id,
        "host",
        &serde_json::json!({"label": "web", "address": "web.example.com",
            "settings": {"username": "root", "key_id": key_id}})
        .to_string(),
        "synced",
    );
    rusqlite_like::entity(
        &c,
        &key_id,
        "key",
        &serde_json::json!({"label": "laptop", "algorithm": "ssh-ed25519",
            "public_key": "ssh-ed25519 AAAA", "fingerprint": "SHA256:x", "comment": "",
            "has_passphrase": false})
        .to_string(),
        "device_only",
    );
    (dir, host_id, key_id)
}

/// Minimal SQL helpers for the fixtures (a 0.3 database is written as is).
mod rusqlite_like {
    use std::path::Path;

    pub fn open(path: &Path) -> rusqlite::Connection {
        rusqlite::Connection::open(path).unwrap()
    }

    pub fn meta(c: &rusqlite::Connection, k: &str, v: &str) {
        c.execute(
            "INSERT INTO meta(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [k, v],
        )
        .unwrap();
    }

    pub fn entity(c: &rusqlite::Connection, id: &str, kind: &str, data: &str, mode: &str) {
        c.execute(
            "INSERT INTO entities (id, owner_id, kind, data, sync_mode, rev, updated_at, deleted, dirty)
             VALUES (?1, '00000000-0000-0000-0000-000000000000', ?2, ?3, ?4, 1, 1, 0, 0)",
            [id, kind, data, mode],
        )
        .unwrap();
    }
}

#[test]
fn accounts_views_and_filters_after_the_upgrade() {
    let key = generate_vault_key();

    // A wrong key: refused before anything is migrated.
    let (dir, _, _) = v03_dir(&key, true);
    let err = TermoakCore::new(dir.path().to_string_lossy().into_owned(), key.clone())
        .err()
        .unwrap();
    assert!(matches!(err, TermoakError::Vault(_)), "{err:?}");
    assert!(!dir.path().join("accounts").exists());
    assert!(!dir.path().join("termoak.db.pre-accounts").exists());

    let (dir, host_id, key_id) = v03_dir(&key, false);
    let core = new_core(dir.path(), &key);
    let accounts = core.accounts();
    assert_eq!(accounts.len(), 1);
    let acc = &accounts[0];
    assert_eq!(acc.server_url, "https://ssh.example.com");
    assert_eq!(acc.server_name, "ssh.example.com");
    assert_eq!(acc.email, "ana@example.com");
    assert_eq!(acc.status, AccountStatus::Active);
    assert!(acc.is_current && !acc.official && !acc.insecure);
    assert!(!acc.vaults_supported);
    assert_eq!(core.current_account().unwrap().id, acc.id);
    assert_eq!(core.account_view(), Some(acc.id.clone()));
    // The account store got the marker too.
    let handle = core.account(acc.id.clone()).unwrap();
    assert_eq!(handle.info().unwrap().id, acc.id);

    // Legacy calls see everything of the current view: the synced host (in
    // the account) and the device-only key (This device).
    let hosts = core.list_hosts(None).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].id, host_id);
    assert_eq!(hosts[0].account_id.as_deref(), Some(acc.id.as_str()));
    assert_eq!(hosts[0].access, Some(ItemAccess::Manager));
    let keys = core.list_keys(None).unwrap();
    assert_eq!(keys[0].id, key_id);
    assert_eq!(keys[0].account_id, None);
    assert_eq!(keys[0].access, Some(ItemAccess::Device));
    // Filters.
    let device_only = ItemFilter {
        account_ids: Some(vec![]),
        vault_ids: None,
        include_device: true,
    };
    assert!(
        core.list_hosts(Some(device_only.clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(core.list_keys(Some(device_only)).unwrap().len(), 1);
    let only_account = ItemFilter {
        account_ids: Some(vec![acc.id.clone()]),
        vault_ids: None,
        include_device: false,
    };
    assert!(core.list_keys(Some(only_account)).unwrap().is_empty());
    assert!(core.vaults(None).unwrap().is_empty());
    // The handle sees only its account.
    assert_eq!(handle.id(), acc.id);

    // New items: synced → the current account; device-only → This device.
    let synced = core
        .save_host(host("db", "db.example.com"), SecretChange::Keep)
        .unwrap();
    assert_eq!(synced.account_id.as_deref(), Some(acc.id.as_str()));
    let mut local = host("pi", "192.168.1.2");
    local.sync_mode = Some(SyncMode::DeviceOnly);
    let local = core.save_host(local, set("pw")).unwrap();
    assert_eq!(local.account_id, None);
    assert_eq!(
        core.host_password(local.id.clone(), None)
            .unwrap()
            .as_deref(),
        Some("pw")
    );
    // Editing keeps each where it is.
    let mut edited = core.get_host(synced.id.clone(), None).unwrap();
    edited.notes = "n".into();
    edited.account_id = None;
    let edited = core.save_host(edited, SecretChange::Keep).unwrap();
    assert_eq!(edited.account_id.as_deref(), Some(acc.id.as_str()));
    // The synced host still connects with the device-only key (resolution
    // falls back to This device).
    let resolved = block_on(core.ws.resolve(host_id.parse().unwrap())).unwrap();
    assert_eq!(resolved.username, "root");

    // Moving the device host into the account (no vaults on that server:
    // it goes to its implicit personal vault), then back.
    let r = block_on(core.transfer(
        vec![ItemRef {
            account_id: None,
            id: local.id.clone(),
        }],
        Some(acc.id.clone()),
        None,
        TransferMode::Move,
        false,
    ))
    .unwrap();
    assert_eq!(r.moved.len(), 1);
    let moved = core.get_host(local.id.clone(), None).unwrap();
    assert_eq!(moved.account_id.as_deref(), Some(acc.id.as_str()));
    assert_eq!(
        core.host_password(local.id.clone(), None)
            .unwrap()
            .as_deref(),
        Some("pw")
    );
    let r = block_on(core.transfer(
        vec![ItemRef {
            account_id: Some(acc.id.clone()),
            id: local.id.clone(),
        }],
        None,
        None,
        TransferMode::Copy,
        true,
    ))
    .unwrap();
    assert!(r.dry_run);
    assert_eq!(r.copied.len(), 1);

    // Views.
    core.set_account_view(None).unwrap();
    assert_eq!(core.account_view(), None);
    assert_eq!(core.current_account().unwrap().id, acc.id);
    core.set_account_view(Some(acc.id.clone())).unwrap();

    // Signing out with unsynced changes asks first.
    let report = block_on(core.sign_out_account(acc.id.clone(), false)).unwrap();
    assert!(!report.signed_out);
    assert!(report.unsynced >= 2);
    assert_eq!(
        core.unsynced_changes(acc.id.clone()).unwrap().total,
        report.unsynced
    );
    let report = block_on(core.sign_out_account(acc.id.clone(), true)).unwrap();
    assert!(report.signed_out);
    assert!(core.accounts().is_empty());
    assert!(core.current_account().is_none());
    // This-device items stay.
    assert_eq!(core.list_keys(None).unwrap().len(), 1);
    assert!(official_server_url().starts_with("https://"));
    assert_eq!(
        canonical_server_url(" SSH.example.com/x ".into()).unwrap(),
        "https://ssh.example.com"
    );
}

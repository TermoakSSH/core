//! Integration tests against a real OpenSSH server.
//!
//! They run with a temporary `sshd` on a free port. If `sshd` is not
//! installed, the tests are skipped (the Linux CI installs it).

use std::net::TcpListener as StdListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use termoak_core::crypto::MasterKey;
use termoak_core::model::{ForwardKind, Host, HostSettings};
use termoak_core::resolve::{ResolvedHost, ResolvedKey};
use termoak_core::{Id, Store, new_id};
use termoak_ssh::forward::ForwardSpec;
use termoak_ssh::keys::{KeyType, generate};
use termoak_ssh::{
    ConnectOptions, Connection, ExecOptions, HostKeyPolicy, PtyOptions, StoreVerifier,
    TerminalSession,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Sshd {
    child: Child,
    port: u16,
    dir: tempfile::TempDir,
    private_key: String,
    user: String,
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn find_sshd() -> Option<PathBuf> {
    // Linux only (on other systems the system sshd needs a different configuration).
    if !cfg!(target_os = "linux") {
        return None;
    }
    [
        "/usr/sbin/sshd",
        "/usr/local/sbin/sshd",
        "/opt/homebrew/sbin/sshd",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
}

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn current_user() -> String {
    std::env::var("USER")
        .ok()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| {
            String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
                .unwrap()
                .trim()
                .to_string()
        })
}

fn start_sshd() -> Option<Sshd> {
    let sshd = find_sshd()?;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let host_key = d.join("host_ed25519");
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&host_key)
        .status()
        .ok()?;
    assert!(status.success());

    let client = generate(KeyType::Ed25519, "test@termoak", None).unwrap();
    std::fs::write(
        d.join("authorized_keys"),
        format!("{}\n", client.public_openssh),
    )
    .unwrap();
    let port = free_port();
    std::fs::create_dir_all("/run/sshd").ok();
    let config = format!(
        "Port {port}
ListenAddress 127.0.0.1
HostKey {hk}
PidFile {pid}
AuthorizedKeysFile {ak}
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin yes
AllowTcpForwarding yes
Subsystem sftp internal-sftp
LogLevel ERROR
",
        hk = host_key.display(),
        pid = d.join("sshd.pid").display(),
        ak = d.join("authorized_keys").display(),
    );
    let cfg = d.join("sshd_config");
    std::fs::write(&cfg, config).unwrap();
    let child = Command::new(sshd)
        .args(["-D", "-e", "-f"])
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .ok()?;
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Some(Sshd {
                child,
                port,
                dir,
                private_key: client.private_openssh,
                user: current_user(),
            });
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

fn resolved(sshd: &Sshd, jumps: Vec<ResolvedHost>) -> ResolvedHost {
    ResolvedHost {
        host: Host {
            id: new_id(),
            label: "local".into(),
            address: "127.0.0.1".into(),
            group_id: None,
            tags: vec![],
            settings: HostSettings::default(),
            notes: String::new(),
            color: None,
            os: None,
            os_version: None,
            favorite: false,
        },
        settings: HostSettings::default(),
        port: sshd.port,
        username: sshd.user.clone(),
        password: None,
        key: Some(ResolvedKey {
            id: Id::nil(),
            label: "test".into(),
            private_key: sshd.private_key.clone(),
            passphrase: None,
            certificate: None,
        }),
        jumps,
        proxy: None,
        startup_script: None,
    }
}

fn options(store: &Store, owner: Id) -> ConnectOptions {
    ConnectOptions::new(Arc::new(StoreVerifier {
        store: store.clone(),
        owner,
        policy: HostKeyPolicy::AcceptNew,
        prompter: None,
    }))
}

async fn echo_server() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    let n = match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

async fn roundtrip(port: u16, msg: &[u8]) -> Vec<u8> {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    s.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; msg.len()];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut buf))
        .await
        .expect("no reply from the tunnel")
        .unwrap();
    buf
}

fn dir_str(p: &Path) -> String {
    p.display().to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_session_against_openssh() {
    let Some(sshd) = start_sshd() else {
        eprintln!("sshd not available: test skipped");
        return;
    };
    let store = Store::open_in_memory(MasterKey::generate()).unwrap();
    let owner = new_id();
    let opts = options(&store, owner);

    // Connection + TOFU.
    let conn = Connection::connect(&resolved(&sshd, vec![]), &opts)
        .await
        .unwrap();
    assert!(
        conn.info()
            .server_fingerprint
            .as_deref()
            .unwrap()
            .starts_with("SHA256:")
    );
    let known = store
        .list::<termoak_core::model::KnownHost>(owner)
        .await
        .unwrap();
    assert_eq!(known.len(), 1);

    // exec with stdout, stderr and exit code.
    let out = conn
        .exec(
            "echo hello; echo error >&2; exit 3",
            &ExecOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(out.stdout_text(), "hello\n");
    assert_eq!(out.stderr_text(), "error\n");
    assert_eq!(out.exit_code, Some(3));

    // Timeout.
    let out = conn
        .exec(
            "sleep 30",
            &ExecOptions {
                timeout: Duration::from_millis(500),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(out.timed_out);

    // System detection.
    assert!(termoak_ssh::detect::detect_os(&conn).await.is_some());

    // Interactive terminal.
    let term = TerminalSession::open(
        conn.clone(),
        PtyOptions {
            startup_script: Some("export TERMOAK_MARK=green".into()),
            ..Default::default()
        },
        256 * 1024,
        None,
    )
    .await
    .unwrap();
    let (_, mut rx) = term.attach();
    term.write(&b"echo \"mark-$TERMOAK_MARK\"\n"[..])
        .await
        .unwrap();
    let mut seen = String::new();
    let found = tokio::time::timeout(Duration::from_secs(10), async {
        while let Ok(chunk) = rx.recv().await {
            seen.push_str(&String::from_utf8_lossy(&chunk));
            if seen.contains("mark-green") {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    assert!(found, "terminal output: {seen:?}");
    term.resize(120, 40).await.unwrap();
    assert!(term.text_tail(10_000).contains("mark-green"));
    // A second viewer receives the scrollback.
    let (snapshot, _) = term.attach();
    assert!(String::from_utf8_lossy(&snapshot).contains("mark-green"));
    term.write(&b"exit\n"[..]).await.unwrap();
    let mut status = term.watch_status();
    tokio::time::timeout(Duration::from_secs(10), status.wait_for(|s| s.is_closed()))
        .await
        .unwrap()
        .unwrap();

    // SFTP.
    let sftp = conn.sftp().await.unwrap();
    let base = dir_str(&sshd.dir.path().join("sftp"));
    sftp.mkdir_all(&format!("{base}/a/b")).await.unwrap();
    sftp.write(&format!("{base}/a/b/f.txt"), b"some data", Some(0o640))
        .await
        .unwrap();
    assert_eq!(
        sftp.read(&format!("{base}/a/b/f.txt"), 1024).await.unwrap(),
        b"some data"
    );
    let st = sftp.stat(&format!("{base}/a/b/f.txt")).await.unwrap();
    assert_eq!(st.mode, Some(0o640));
    sftp.rename(&format!("{base}/a/b/f.txt"), &format!("{base}/a/g.txt"))
        .await
        .unwrap();
    let list = sftp.list(&format!("{base}/a")).await.unwrap();
    assert_eq!(list[0].name, "b");
    assert_eq!(list[1].name, "g.txt");
    let mut downloaded = Vec::new();
    let n = sftp
        .download(&format!("{base}/a/g.txt"), &mut downloaded, None)
        .await
        .unwrap();
    assert_eq!(n, 9);
    sftp.upload(&b"uploaded"[..], &format!("{base}/up.txt"), None)
        .await
        .unwrap();
    assert!(sftp.exists(&format!("{base}/up.txt")).await.unwrap());
    sftp.remove_dir(&base, true).await.unwrap();
    assert!(!sftp.exists(&base).await.unwrap());

    // Tunnels.
    let echo = echo_server().await;
    let local = conn
        .start_forward(ForwardSpec {
            kind: ForwardKind::Local,
            bind_address: "127.0.0.1".into(),
            bind_port: 0,
            dest_host: Some("127.0.0.1".into()),
            dest_port: Some(echo),
        })
        .await
        .unwrap();
    assert_eq!(roundtrip(local.bound_port, b"local").await, b"local");

    let dynamic = conn
        .start_forward(ForwardSpec {
            kind: ForwardKind::Dynamic,
            bind_address: "127.0.0.1".into(),
            bind_port: 0,
            dest_host: None,
            dest_port: None,
        })
        .await
        .unwrap();
    {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", dynamic.bound_port))
            .await
            .unwrap();
        s.write_all(&[5, 1, 0]).await.unwrap();
        let mut r = [0u8; 2];
        s.read_exact(&mut r).await.unwrap();
        let mut req = vec![5, 1, 0, 1, 127, 0, 0, 1];
        req.extend_from_slice(&echo.to_be_bytes());
        s.write_all(&req).await.unwrap();
        let mut r = [0u8; 10];
        s.read_exact(&mut r).await.unwrap();
        assert_eq!(r[1], 0, "SOCKS must reply with success");
        s.write_all(b"socks").await.unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"socks");
    }

    let remote = conn
        .start_forward(ForwardSpec {
            kind: ForwardKind::Remote,
            bind_address: "127.0.0.1".into(),
            bind_port: 0,
            dest_host: Some("127.0.0.1".into()),
            dest_port: Some(echo),
        })
        .await
        .unwrap();
    assert_ne!(remote.bound_port, 0);
    assert_eq!(roundtrip(remote.bound_port, b"remote").await, b"remote");
    assert!(remote.stats().total_connections >= 1);
    remote.stop().await;
    local.stop().await;
    dynamic.stop().await;

    // Jump (ProxyJump) through the same server.
    let via = resolved(&sshd, vec![resolved(&sshd, vec![])]);
    let jumped = Connection::connect(&via, &opts).await.unwrap();
    assert_eq!(jumped.info().via.len(), 1);
    let out = jumped
        .exec("echo jumped", &ExecOptions::default())
        .await
        .unwrap();
    assert_eq!(out.stdout_text(), "jumped\n");

    // Authentication with a key that is not authorized.
    let mut bad = resolved(&sshd, vec![]);
    bad.key.as_mut().unwrap().private_key = generate(KeyType::Ed25519, "other", None)
        .unwrap()
        .private_openssh;
    let err = Connection::connect(&bad, &opts).await.unwrap_err();
    assert!(matches!(err, termoak_ssh::SshError::Auth { .. }), "{err}");

    conn.disconnect().await;
}

/// Minimal HTTP `CONNECT` proxy that counts the connections it serves.
async fn http_proxy(used: Arc<std::sync::atomic::AtomicUsize>) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut c, _) = listener.accept().await.unwrap();
            let used = used.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    let mut b = [0u8; 1];
                    if c.read_exact(&mut b).await.is_err() {
                        return;
                    }
                    head.push(b[0]);
                }
                let text = String::from_utf8_lossy(&head).to_string();
                let dest: u16 = text
                    .split_whitespace()
                    .nth(1)
                    .and_then(|a| a.rsplit(':').next())
                    .and_then(|p| p.parse().ok())
                    .unwrap();
                used.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut up = tokio::net::TcpStream::connect(("127.0.0.1", dest))
                    .await
                    .unwrap();
                c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .unwrap();
                let _ = tokio::io::copy_bidirectional(&mut c, &mut up).await;
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_through_http_proxy() {
    let Some(sshd) = start_sshd() else {
        eprintln!("sshd not available: test skipped");
        return;
    };
    let store = Store::open_in_memory(MasterKey::generate()).unwrap();
    let owner = new_id();
    let opts = options(&store, owner);
    let used = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let proxy_port = http_proxy(used.clone()).await;

    let mut target = resolved(&sshd, vec![]);
    target.proxy = Some(termoak_core::resolve::ResolvedProxy {
        settings: termoak_core::model::ProxySettings {
            kind: termoak_core::model::ProxyKind::Http,
            host: "127.0.0.1".into(),
            port: proxy_port,
            username: None,
        },
        password: None,
    });
    let conn = Connection::connect(&target, &opts).await.unwrap();
    let out = conn
        .exec("echo via-proxy", &ExecOptions::default())
        .await
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "via-proxy");
    assert_eq!(
        used.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the connection went through the proxy"
    );
}

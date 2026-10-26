//! FIDO2 security keys against a real OpenSSH server (8.2+), with the
//! software authenticator (`--features soft-sk`). Skipped without `sshd`.

use std::net::TcpListener as StdListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use termoak_core::crypto::MasterKey;
use termoak_core::model::{Host, HostSettings};
use termoak_core::resolve::{ResolvedHost, ResolvedKey};
use termoak_core::{Id, Store, new_id};
use termoak_ssh::keys::KeyMaterial;
use termoak_ssh::sk::soft::{Behavior, SoftAuthenticator};
use termoak_ssh::sk::{
    SecurityKeySigner, SkAlgorithm, SkErrorCode, SkKeyOptions, key_from_credential,
    make_credential_request,
};
use termoak_ssh::{
    ConnectOptions, Connection, ExecOptions, HostKeyPolicy, SshError, StoreVerifier,
};

struct Sshd {
    child: Child,
    port: u16,
    _dir: tempfile::TempDir,
    user: String,
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn current_user() -> String {
    String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_string()
}

fn start_sshd(authorized: &[String]) -> Option<Sshd> {
    let sshd = PathBuf::from("/usr/sbin/sshd");
    if !cfg!(target_os = "linux") || !sshd.exists() {
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let host_key = d.join("host_ed25519");
    let ok = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&host_key)
        .status()
        .ok()?
        .success();
    assert!(ok);
    std::fs::write(d.join("authorized_keys"), authorized.join("\n") + "\n").unwrap();
    let port = StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::create_dir_all("/run/sshd").ok();
    let cfg = d.join("sshd_config");
    std::fs::write(
        &cfg,
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nPermitRootLogin yes\nMaxAuthTries 20\nLogLevel ERROR\n",
            host_key.display(),
            d.join("sshd.pid").display(),
            d.join("authorized_keys").display()
        ),
    )
    .unwrap();
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
                _dir: dir,
                user: current_user(),
            });
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

fn new_key(
    auth: &SoftAuthenticator,
    alg: SkAlgorithm,
    no_touch: bool,
    verify: bool,
) -> KeyMaterial {
    let req = make_credential_request(&SkKeyOptions {
        algorithm: alg,
        application: None,
        user: None,
        resident: false,
        verify_required: verify,
        no_touch_required: no_touch,
        device: Some("Soft".into()),
    })
    .unwrap();
    key_from_credential(&req, &auth.make_credential(&req).unwrap(), "sk@test").unwrap()
}

fn target(sshd: &Sshd, key: &KeyMaterial, certificate: Option<String>) -> ResolvedHost {
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
            protocol: Default::default(),
            icon: None,
        },
        settings: HostSettings::default(),
        port: sshd.port,
        username: sshd.user.clone(),
        password: None,
        key: Some(ResolvedKey {
            id: new_id(),
            label: "yubi".into(),
            private_key: key.private_openssh.clone(),
            passphrase: None,
            certificate,
            security_key: key.security_key.clone(),
        }),
        jumps: vec![],
        proxy: None,
        startup_script: None,
        network: None,
        group_name: None,
        e2ee_locked: false,
    }
}

fn options(signer: Option<Arc<dyn SecurityKeySigner>>) -> ConnectOptions {
    let store = Store::open_in_memory(MasterKey::generate()).unwrap();
    ConnectOptions::new(Arc::new(StoreVerifier::for_owner(
        store,
        Id::nil(),
        HostKeyPolicy::AcceptNew,
        None,
    )))
    .with_security_key(signer)
    .with_purpose("test", Some("session-1".into()))
}

async fn echo(
    sshd: &Sshd,
    key: &KeyMaterial,
    signer: Option<Arc<dyn SecurityKeySigner>>,
) -> Result<String, SshError> {
    let conn = Connection::connect(&target(sshd, key, None), &options(signer)).await?;
    let out = conn.exec("echo sk-ok", &ExecOptions::default()).await?;
    conn.disconnect().await;
    Ok(out.stdout_text())
}

fn code(e: &SshError) -> &'static str {
    match e {
        SshError::SecurityKey { code, .. } => code,
        _ => "other",
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn security_keys_against_openssh() {
    let auth = Arc::new(SoftAuthenticator::new());
    let ed = new_key(&auth, SkAlgorithm::Ed25519, false, false);
    let ec = new_key(&auth, SkAlgorithm::EcdsaP256, false, false);
    let no_touch = new_key(&auth, SkAlgorithm::Ed25519, true, false);
    let no_touch_unlisted = new_key(&auth, SkAlgorithm::EcdsaP256, true, false);
    let uv = new_key(&auth, SkAlgorithm::EcdsaP256, false, true);
    let unknown = new_key(&auth, SkAlgorithm::Ed25519, false, false);
    let lines = vec![
        ed.public_openssh.clone(),
        ec.public_openssh.clone(),
        format!("no-touch-required {}", no_touch.public_openssh),
        // Listed without the option: sshd wants the touch flag.
        no_touch_unlisted.public_openssh.clone(),
        format!("verify-required {}", uv.public_openssh),
    ];
    let Some(sshd) = start_sshd(&lines) else {
        eprintln!("sshd not available: skipped");
        return;
    };
    let signer: Arc<dyn SecurityKeySigner> = auth.clone();

    // Both algorithms sign and log in.
    for key in [&ed, &ec, &no_touch, &uv] {
        let out = echo(&sshd, key, Some(signer.clone())).await.unwrap();
        assert_eq!(out.trim(), "sk-ok", "{}", key.algorithm);
    }
    // The request said what it was for and needed the right flags.
    {
        let seen = auth.seen.lock();
        let last = seen.last().unwrap();
        assert_eq!(last.context.purpose, "test");
        assert_eq!(last.context.session_id.as_deref(), Some("session-1"));
        assert_eq!(last.context.key_label, "yubi");
        assert_eq!(last.context.device.as_deref(), Some("Soft"));
        assert!(last.require_presence && last.require_verification);
        assert_eq!(last.application, "ssh:");
        let nt = seen
            .iter()
            .find(|r| r.fingerprint == no_touch.fingerprint)
            .unwrap();
        assert!(!nt.require_presence);
    }

    // A no-touch key the server lists without `no-touch-required`: refused.
    let e = echo(&sshd, &no_touch_unlisted, Some(signer.clone()))
        .await
        .unwrap_err();
    assert!(matches!(e, SshError::Auth { .. }), "{e}");
    // A key the server does not know: an ordinary authentication failure.
    let e = echo(&sshd, &unknown, Some(signer.clone()))
        .await
        .unwrap_err();
    assert!(matches!(e, SshError::Auth { .. }), "{e}");

    // No signer here: security_key_required.
    let e = echo(&sshd, &ed, None).await.unwrap_err();
    assert_eq!(code(&e), "security_key_required", "{e}");

    // Device errors keep their code (and the connection survives them to
    // try the other methods).
    for (behavior, expected) in [
        (
            Behavior::Fail(SkErrorCode::Cancelled),
            "security_key_cancelled",
        ),
        (
            Behavior::Fail(SkErrorCode::NotFound),
            "security_key_not_found",
        ),
        (Behavior::Fail(SkErrorCode::Timeout), "security_key_timeout"),
        (Behavior::WrongKey, "security_key_wrong_key"),
        (Behavior::NoPresence, "security_key_failed"),
    ] {
        auth.set_behavior(behavior.clone());
        let e = echo(&sshd, &ec, Some(signer.clone())).await.unwrap_err();
        assert_eq!(code(&e), expected, "{behavior:?}: {e}");
    }
    auth.set_behavior(Behavior::Sign);
    auth.set_verify(false);
    let e = echo(&sshd, &uv, Some(signer.clone())).await.unwrap_err();
    assert_eq!(code(&e), "security_key_pin_required", "{e}");
    auth.set_verify(true);

    // Works again afterwards.
    assert_eq!(
        echo(&sshd, &ed, Some(signer.clone())).await.unwrap().trim(),
        "sk-ok"
    );
}

/// An sk key with an OpenSSH certificate (ssh-keygen as the CA).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn security_key_with_certificate() {
    let auth = Arc::new(SoftAuthenticator::new());
    let key = new_key(&auth, SkAlgorithm::Ed25519, false, false);
    let ca_dir = tempfile::tempdir().unwrap();
    let ca = ca_dir.path().join("ca");
    let pubfile = ca_dir.path().join("user-sk.pub");
    std::fs::write(&pubfile, format!("{}\n", key.public_openssh)).unwrap();
    let ok = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&ca)
        .status()
        .unwrap()
        .success();
    assert!(ok);
    let user = current_user();
    let ok = Command::new("ssh-keygen")
        .args(["-q", "-s"])
        .arg(&ca)
        .args(["-I", "termoak-test", "-n", &user, "-V", "+1h"])
        .arg(&pubfile)
        .status()
        .unwrap()
        .success();
    assert!(ok);
    let cert = std::fs::read_to_string(ca_dir.path().join("user-sk-cert.pub")).unwrap();
    let ca_pub = std::fs::read_to_string(ca.with_extension("pub")).unwrap();
    let Some(sshd) = start_sshd(&[format!("cert-authority {}", ca_pub.trim())]) else {
        eprintln!("sshd not available: skipped");
        return;
    };
    let signer: Arc<dyn SecurityKeySigner> = auth.clone();
    let conn = Connection::connect(&target(&sshd, &key, Some(cert)), &options(Some(signer)))
        .await
        .unwrap();
    let out = conn
        .exec("echo cert-ok", &ExecOptions::default())
        .await
        .unwrap();
    assert_eq!(out.stdout_text().trim(), "cert-ok");
    conn.disconnect().await;
}

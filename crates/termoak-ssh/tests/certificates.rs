//! Team SSH CA (0.7 phase 4b) against real OpenSSH: certificates made by
//! `termoak_ssh::ca` are read by `ssh-keygen -L`, accepted by `sshd` with
//! `TrustedUserCAKeys`, refused when expired, for another principal or
//! revoked in a KRL (`RevokedKeys`, also checked with `ssh-keygen -Q`), and
//! the client falls back to the plain key when the certificate is refused.
//! Skipped when `sshd` is not installed.

use std::net::TcpListener as StdListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use termoak_core::crypto::MasterKey;
use termoak_core::model::{Host, HostSettings};
use termoak_core::resolve::{ResolvedHost, ResolvedKey};
use termoak_core::{Id, Store, new_id};
use termoak_ssh::ca::{self, CaAlgorithm, KrlCa, UserCertificate};
use termoak_ssh::{ConnectOptions, Connection, HostKeyPolicy, StoreVerifier};

struct Sshd {
    child: Child,
    port: u16,
    dir: tempfile::TempDir,
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn find_sshd() -> Option<PathBuf> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    ["/usr/sbin/sshd", "/usr/local/sbin/sshd"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
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

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// sshd trusting `ca_pub`, with `authorized` keys and a KRL file.
fn start_sshd(ca_pub: &str, authorized: &str, krl: &[u8]) -> Option<Sshd> {
    let sshd = find_sshd()?;
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
    std::fs::write(d.join("ca.pub"), format!("{ca_pub}\n")).unwrap();
    std::fs::write(d.join("authorized_keys"), authorized).unwrap();
    std::fs::write(d.join("revoked.krl"), krl).unwrap();
    let port = free_port();
    std::fs::create_dir_all("/run/sshd").ok();
    let config = format!(
        "Port {port}
ListenAddress 127.0.0.1
HostKey {hk}
PidFile {pid}
AuthorizedKeysFile {ak}
TrustedUserCAKeys {ca}
RevokedKeys {krl}
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin yes
LogLevel ERROR
",
        hk = host_key.display(),
        pid = d.join("sshd.pid").display(),
        ak = d.join("authorized_keys").display(),
        ca = d.join("ca.pub").display(),
        krl = d.join("revoked.krl").display(),
    );
    let cfg = d.join("sshd_config");
    std::fs::write(&cfg, config).unwrap();
    let child = Command::new(sshd)
        .args(["-D", "-e", "-f"])
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Some(Sshd { child, port, dir });
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

fn hop(port: u16, private_key: &str, certificate: Option<String>) -> ResolvedHost {
    ResolvedHost {
        host: Host {
            id: new_id(),
            label: "ca-test".into(),
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
        port,
        username: current_user(),
        password: None,
        key: Some(ResolvedKey {
            id: Id::nil(),
            label: "eph".into(),
            private_key: private_key.into(),
            passphrase: None,
            certificate,
            security_key: None,
        }),
        jumps: vec![],
        proxy: None,
        startup_script: None,
        network: None,
        group_name: None,
    }
}

fn options() -> ConnectOptions {
    let store = Store::open_in_memory(MasterKey::generate()).unwrap();
    ConnectOptions::new(Arc::new(StoreVerifier::for_owner(
        store,
        Id::nil(),
        HostKeyPolicy::AcceptNew,
        None,
    )))
}

fn cert_for(
    ca_private: &str,
    public: &str,
    serial: u64,
    principal: &str,
    valid: (i64, i64),
) -> String {
    let now = ca::unix_now() as i64;
    ca::sign_user_certificate(
        ca_private,
        &ca::parse_public_key(public).unwrap(),
        &UserCertificate {
            serial,
            key_id: format!("termoak:test@example.com:{}:direct:{serial}", Id::nil()),
            principals: vec![principal.to_string()],
            valid_after: (now + valid.0) as u64,
            valid_before: (now + valid.1) as u64,
            extensions: vec!["permit-pty".into()],
            source_address: None,
            force_command: None,
        },
    )
    .unwrap()
}

fn keygen(args: &[&str], file: &Path) -> (bool, String) {
    let out = Command::new("ssh-keygen")
        .args(args)
        .arg(file)
        .output()
        .unwrap();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[tokio::test]
async fn certificates_against_openssh() {
    let user = current_user();
    let ca = ca::generate_ca(CaAlgorithm::Ed25519, "termoak-ca test").unwrap();
    let (private, public) = ca::ephemeral_key("eph").unwrap();
    let good = cert_for(&ca.private_key, &public, 11, &user, (-300, 3600));
    let revoked = cert_for(&ca.private_key, &public, 12, &user, (-300, 3600));
    let krl = ca::build_krl(
        &[KrlCa {
            ca_public_key: ca.public_key.clone(),
            serials: vec![12],
        }],
        &[],
        1,
        "test",
    )
    .unwrap();
    let Some(sshd) = start_sshd(&ca.public_key, "", &krl) else {
        eprintln!("sshd not available: skipped");
        return;
    };
    let d = sshd.dir.path();

    // ssh-keygen reads what we sign and the KRL we build.
    std::fs::write(d.join("good-cert.pub"), format!("{good}\n")).unwrap();
    std::fs::write(d.join("revoked-cert.pub"), format!("{revoked}\n")).unwrap();
    let (ok, text) = keygen(&["-L", "-f"], &d.join("good-cert.pub"));
    assert!(ok, "{text}");
    assert!(text.contains("Serial: 11"), "{text}");
    assert!(text.contains(&format!("        {user}")), "{text}");
    assert!(text.contains("permit-pty"), "{text}");
    assert!(text.contains("termoak:test@example.com"), "{text}");
    let (ok, text) = keygen(
        &["-Q", "-f", &d.join("revoked.krl").display().to_string()],
        &d.join("revoked-cert.pub"),
    );
    assert!(!ok && text.contains("REVOKED"), "{text}");
    let (ok, text) = keygen(
        &["-Q", "-f", &d.join("revoked.krl").display().to_string()],
        &d.join("good-cert.pub"),
    );
    assert!(ok && text.contains("ok"), "{text}");

    // Key + certificate: in (authorized_keys is empty).
    let conn = Connection::connect(&hop(sshd.port, &private, Some(good.clone())), &options()).await;
    assert!(conn.is_ok(), "{:?}", conn.err());
    // Without the certificate: out.
    let err = Connection::connect(&hop(sshd.port, &private, None), &options())
        .await
        .err()
        .expect("plain key must be refused");
    assert!(err.to_string().contains("authentication failed"), "{err}");
    // Revoked serial: out.
    assert!(
        Connection::connect(&hop(sshd.port, &private, Some(revoked)), &options())
            .await
            .is_err()
    );
    // Another principal, or expired: out.
    let other = cert_for(&ca.private_key, &public, 13, "someone-else", (-300, 3600));
    assert!(
        Connection::connect(&hop(sshd.port, &private, Some(other)), &options())
            .await
            .is_err()
    );
    let expired = cert_for(&ca.private_key, &public, 14, &user, (-7200, -3600));
    assert!(
        Connection::connect(&hop(sshd.port, &private, Some(expired)), &options())
            .await
            .is_err()
    );
    // A certificate of another CA: out.
    let rogue = ca::generate_ca(CaAlgorithm::Ed25519, "rogue").unwrap();
    let rogue_cert = cert_for(&rogue.private_key, &public, 15, &user, (-300, 3600));
    assert!(
        Connection::connect(&hop(sshd.port, &private, Some(rogue_cert)), &options())
            .await
            .is_err()
    );
    drop(sshd);

    // A host that does not trust the CA but has the key: the client falls
    // back to the plain key after the certificate is refused.
    let empty_krl = ca::build_krl(&[], &[], 1, "").unwrap();
    let other_ca = ca::generate_ca(CaAlgorithm::Ed25519, "other").unwrap();
    let Some(sshd) = start_sshd(&other_ca.public_key, &format!("{public}\n"), &empty_krl) else {
        return;
    };
    let conn = Connection::connect(&hop(sshd.port, &private, Some(good)), &options()).await;
    assert!(conn.is_ok(), "{:?}", conn.err());
    drop(sshd);

    // A key revoked by SHA-256 in the KRL is refused even with a valid
    // certificate.
    let krl = ca::build_krl(&[], &[public.clone()], 2, "").unwrap();
    let Some(sshd) = start_sshd(&ca.public_key, "", &krl) else {
        return;
    };
    let fresh = cert_for(&ca.private_key, &public, 16, &user, (-300, 3600));
    std::fs::write(sshd.dir.path().join("fresh-cert.pub"), format!("{fresh}\n")).unwrap();
    let (ok, text) = keygen(
        &[
            "-Q",
            "-f",
            &sshd.dir.path().join("revoked.krl").display().to_string(),
        ],
        &sshd.dir.path().join("fresh-cert.pub"),
    );
    assert!(!ok && text.contains("REVOKED"), "{text}");
    assert!(
        Connection::connect(&hop(sshd.port, &private, Some(fresh)), &options())
            .await
            .is_err()
    );
}

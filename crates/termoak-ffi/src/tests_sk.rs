//! FFI tests of security keys and snippets with variables (0.7 phase 3a).

use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use termoak_ssh::sk::soft::{Behavior, SoftAuthenticator};
use termoak_ssh::sk::{self, SkErrorCode};

use crate::runtime::block_on;
use crate::*;

fn new_core(dir: &std::path::Path) -> Arc<TermoakCore> {
    TermoakCore::new(dir.to_string_lossy().into_owned(), generate_vault_key()).unwrap()
}

/// An app's handler on top of the software authenticator.
struct SoftHandler {
    auth: Arc<SoftAuthenticator>,
    requests: parking_lot::Mutex<Vec<SecurityKeySignRequest>>,
    cancel: std::sync::atomic::AtomicBool,
}

impl SoftHandler {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            auth: Arc::new(SoftAuthenticator::new()),
            requests: Default::default(),
            cancel: Default::default(),
        })
    }
}

fn to_err(e: sk::SkError) -> SecurityKeyError {
    let message = e.message;
    match e.code {
        SkErrorCode::Cancelled => SecurityKeyError::Cancelled { message },
        SkErrorCode::NotFound => SecurityKeyError::NotFound { message },
        SkErrorCode::PinRequired => SecurityKeyError::PinRequired { message },
        _ => SecurityKeyError::Failed { message },
    }
}

impl SecurityKeyHandler for SoftHandler {
    fn sign(&self, r: SecurityKeySignRequest) -> Result<SecurityKeyAssertion, SecurityKeyError> {
        self.requests.lock().push(r.clone());
        if self.cancel.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(SecurityKeyError::Cancelled {
                message: String::new(),
            });
        }
        let req = sk::SkSignRequest {
            algorithm: r.algorithm.into(),
            application: r.application,
            key_handle: r.key_handle,
            public_key: r.public_key,
            fingerprint: r.fingerprint,
            client_data_hash: r.client_data_hash.try_into().unwrap(),
            message: r.message,
            require_presence: r.require_presence,
            require_verification: r.require_verification,
            context: Default::default(),
        };
        let a = self.auth.sign_now(&req).map_err(to_err)?;
        // Like YubiKit: the whole authenticator data.
        let mut data = vec![0u8; 32];
        data.push(a.flags);
        data.extend_from_slice(&a.counter.to_be_bytes());
        Ok(SecurityKeyAssertion {
            flags: 0,
            counter: 0,
            signature: a.signature,
            authenticator_data: Some(data),
        })
    }

    fn make_credential(
        &self,
        r: SecurityKeyCredentialRequest,
    ) -> Result<SecurityKeyCredential, SecurityKeyError> {
        let req: sk::SkMakeCredentialRequest = r.try_into().unwrap();
        let c = self.auth.make_credential(&req).map_err(to_err)?;
        Ok(SecurityKeyCredential {
            authenticator_data: vec![],
            attestation_object: c.attestation_object,
        })
    }

    fn list_resident(
        &self,
        r: SecurityKeyResidentRequest,
    ) -> Result<Vec<SecurityKeyResident>, SecurityKeyError> {
        Ok(self
            .auth
            .list_resident(&r.application_prefix)
            .into_iter()
            .map(|c| SecurityKeyResident {
                application: c.application,
                credential_id: c.credential_id,
                public_key_cose: c.public_key_cose,
                user_id: c.user_id,
                user_name: c.user_name,
            })
            .collect())
    }
}

struct Accept;

impl AuthHandler for Accept {
    fn on_host_key(&self, _: String, _: u32, _: String, _: String) -> bool {
        true
    }
    fn on_prompt(&self, _: AuthRequest) -> Option<Vec<String>> {
        None
    }
}

struct Sshd {
    child: Child,
    port: u16,
    _dir: tempfile::TempDir,
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_sshd(authorized: &str) -> Option<Sshd> {
    let sshd = "/usr/sbin/sshd";
    if !cfg!(target_os = "linux") || !std::path::Path::new(sshd).exists() {
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let hk = d.join("hk");
    Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&hk)
        .status()
        .ok()?;
    std::fs::write(d.join("ak"), authorized).unwrap();
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
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin yes\nLogLevel ERROR\n",
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
            return Some(Sshd {
                child,
                port,
                _dir: dir,
            });
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

fn options(alg: SecurityKeyAlgorithm) -> SecurityKeyOptions {
    SecurityKeyOptions {
        algorithm: alg,
        application: None,
        user: None,
        resident: false,
        verify_required: false,
        no_touch_required: false,
        device: Some("YubiKey 5C".into()),
    }
}

#[test]
fn security_keys_through_the_ffi() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    let handler = SoftHandler::new();

    // Generate on the "device" and save.
    let key = block_on(core.create_security_key(
        "Yubi".into(),
        options(SecurityKeyAlgorithm::EcdsaP256),
        "me@phone".into(),
        None,
        None,
        None,
        handler.clone(),
    ))
    .unwrap();
    assert_eq!(key.algorithm, "sk-ecdsa-sha2-nistp256@openssh.com");
    let info = key.security_key.clone().unwrap();
    assert_eq!(info.application, "ssh:");
    assert_eq!(info.device.as_deref(), Some("YubiKey 5C"));
    assert!(info.touch_required && !info.resident);
    assert!(
        core.list_keys(None)
            .unwrap()
            .iter()
            .any(|k| k.security_key.is_some())
    );
    // The "private key" file is the OpenSSH sk file.
    let file = core
        .export_private_key(key.id.clone(), None)
        .unwrap()
        .unwrap();
    assert!(file.contains("OPENSSH PRIVATE KEY"));
    let details = block_on(inspect_private_key(file.clone(), None)).unwrap();
    assert_eq!(details.fingerprint, key.fingerprint);
    assert!(details.security_key.is_some());
    // Editing the label keeps the details.
    let mut edited = key.clone();
    edited.label = "Yubi 2".into();
    let edited = core.save_key(edited, SecretChange::Keep).unwrap();
    assert_eq!(edited.security_key, key.security_key);
    assert_eq!(
        security_key_authorized_keys_line(key.public_key.clone(), key.security_key.clone()),
        key.public_key
    );

    // An sk key imported by an older app (no details) is still recognized.
    let bare =
        block_on(core.import_key("bare".into(), file.clone(), None, false, None, None, None))
            .unwrap();
    assert!(bare.security_key.is_some());

    // Resident keys: a new resident credential, then loaded from the device.
    let mut o = options(SecurityKeyAlgorithm::Ed25519);
    o.resident = true;
    o.user = Some("ops".into());
    let req = security_key_request(o).unwrap();
    assert_eq!(req.cose_algorithm, -8);
    let cred = handler.make_credential(req.clone()).unwrap();
    let m = security_key_from_credential(req, cred, "c".into()).unwrap();
    assert!(m.details.security_key.as_ref().unwrap().resident);
    let loaded = block_on(core.import_resident_security_keys(
        None,
        false,
        Some("Soft".into()),
        None,
        None,
        None,
        handler.clone(),
    ))
    .unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].label, "Soft (ops)");
    assert_eq!(loaded[0].fingerprint, m.details.fingerprint);
    // Loading again adds nothing.
    let again = block_on(core.import_resident_security_keys(
        None,
        false,
        None,
        None,
        None,
        None,
        handler.clone(),
    ))
    .unwrap();
    assert!(again.is_empty());

    // Connecting: without a handler → SecurityKey / security_key_required.
    let Some(sshd) = start_sshd(&format!("{}\n", key.public_key)) else {
        eprintln!("sshd not available: connection part skipped");
        return;
    };
    let user = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_string();
    let mut h = SshHost {
        id: String::new(),
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
        protocol: "ssh".into(),
        icon: None,
        sync_mode: None,
        has_password: false,
        updated_at: 0,
        account_id: None,
        vault_id: None,
        access: None,
        secret_hidden: false,
    };
    h.settings.port = Some(sshd.port.into());
    h.settings.username = Some(user);
    h.settings.key_id = Some(key.id.clone());
    let h = core.save_host(h, SecretChange::Keep).unwrap();
    assert!(!core.has_security_key_handler());
    let e = block_on(core.connect(h.id.clone(), Arc::new(Accept), None, None))
        .err()
        .unwrap();
    assert!(matches!(e, TermoakError::SecurityKey(_)), "{e}");
    assert_eq!(
        api_error_info(e.to_string()).unwrap().code,
        "security_key_required"
    );

    // With the handler: it signs and the command runs.
    core.set_security_key_handler(Some(handler.clone()));
    assert!(core.has_security_key_handler());
    let session = block_on(core.connect(h.id.clone(), Arc::new(Accept), None, None)).unwrap();
    let out = block_on(session.exec("echo ffi-sk".into(), 10)).unwrap();
    assert_eq!(out.stdout.trim(), "ffi-sk");
    {
        let reqs = handler.requests.lock();
        let r = reqs.last().unwrap();
        assert_eq!(r.purpose, "connect");
        assert_eq!(r.host, "local");
        assert_eq!(r.key_label, "Yubi 2");
        assert_eq!(r.device.as_deref(), Some("YubiKey 5C"));
        assert_eq!(r.client_data_hash.len(), 32);
    }
    // The user cancels.
    handler
        .cancel
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let e = block_on(core.connect(h.id.clone(), Arc::new(Accept), None, None))
        .err()
        .unwrap();
    assert_eq!(
        api_error_info(e.to_string()).unwrap().code,
        "security_key_cancelled"
    );
    handler
        .cancel
        .store(false, std::sync::atomic::Ordering::SeqCst);
    // Another device answers with another key.
    handler.auth.set_behavior(Behavior::WrongKey);
    let e = block_on(core.connect(h.id.clone(), Arc::new(Accept), None, None))
        .err()
        .unwrap();
    assert_eq!(
        api_error_info(e.to_string()).unwrap().code,
        "security_key_wrong_key"
    );
    handler.auth.set_behavior(Behavior::Sign);
    core.set_security_key_handler(None);
    assert!(!core.has_security_key_handler());
}

fn vals(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn snippets_with_variables_through_the_ffi() {
    let script = "ssh {{user}}@{{host}} 'git checkout {{prompt:Branch|main}} && deploy {{select:Env|prod|dev}} {{secret:Token}}'".to_string();
    let t = parse_snippet(script.clone());
    assert!(t.issues.is_empty());
    let kinds: Vec<_> = t.variables.iter().map(|v| v.kind).collect();
    assert_eq!(
        kinds,
        [
            SnippetVariableKind::Builtin,
            SnippetVariableKind::Builtin,
            SnippetVariableKind::Prompt,
            SnippetVariableKind::Select,
            SnippetVariableKind::Secret
        ]
    );
    assert!(t.variables[0].needs_host);
    assert_eq!(t.variables[3].options, ["prod", "dev"]);
    // Without a host the host built-ins are asked too.
    assert_eq!(snippet_prompts(script.clone(), None).len(), 5);
    let ctx = SnippetContext {
        host: Some("10.0.0.5".into()),
        user: Some("deploy".into()),
        ..Default::default()
    };
    let asked: Vec<_> = snippet_prompts(script.clone(), Some(ctx.clone()))
        .into_iter()
        .map(|v| v.key)
        .collect();
    assert_eq!(asked, ["Branch", "Env", "Token"]);
    let out =
        render_snippet_with(script.clone(), vals(&[("Token", "t")]), Some(ctx.clone())).unwrap();
    assert_eq!(
        out,
        "ssh deploy@10.0.0.5 'git checkout main && deploy prod t'"
    );
    assert!(render_snippet_with(script.clone(), vals(&[]), Some(ctx.clone())).is_err());
    let mut other = ctx.clone();
    other.host = Some("10.0.0.6".into());
    let both = render_snippet_for_hosts(
        script.clone(),
        vals(&[("Token", "t"), ("Env", "dev")]),
        vec![ctx, other],
    )
    .unwrap();
    assert!(
        both[0].contains("@10.0.0.5")
            && both[1].contains("@10.0.0.6")
            && both[1].contains("deploy dev")
    );
    // The old functions keep working (no host: everything is a variable).
    assert_eq!(
        snippet_variables("echo {{host}} {{x}}".into()),
        ["host", "x"]
    );
    assert_eq!(
        render_snippet(
            "echo {{host}} {{x}}".into(),
            vals(&[("host", "h"), ("x", "1")])
        )
        .unwrap(),
        "echo h 1"
    );

    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    // Saving a snippet with a malformed tag fails with invalid_snippet.
    let bad = Snippet {
        id: String::new(),
        name: "bad".into(),
        script: "deploy {{select:Env}}".into(),
        description: String::new(),
        tags: vec![],
        sync_mode: None,
        updated_at: 0,
        account_id: None,
        vault_id: None,
        access: None,
        secret_hidden: false,
    };
    let e = core.save_snippet(bad.clone()).unwrap_err();
    assert!(matches!(e, TermoakError::Invalid(_)), "{e}");
    let info = api_error_info(e.to_string()).unwrap();
    assert_eq!(info.code, "invalid_snippet");
    assert!(info.details_json.contains("issues"));
    let s = core
        .save_snippet(Snippet {
            script: script.clone(),
            ..bad
        })
        .unwrap();
    // Host built-ins of a saved host; remembered values per host.
    let mut h = SshHost {
        id: String::new(),
        label: "web1".into(),
        address: "10.1.1.1".into(),
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
    };
    h.settings.username = Some("root".into());
    h.settings.port = Some(2222);
    let h = core.save_host(h, SecretChange::Keep).unwrap();
    let ctx = core.snippet_context(h.id.clone(), None).unwrap();
    assert_eq!(ctx.host.as_deref(), Some("10.1.1.1"));
    assert_eq!(ctx.user.as_deref(), Some("root"));
    assert_eq!(ctx.port, Some(2222));
    assert_eq!(ctx.label.as_deref(), Some("web1"));
    core.remember_snippet_values(
        s.id.clone(),
        Some(h.id.clone()),
        s.script.clone(),
        vals(&[("Branch", "fix"), ("Env", "dev"), ("Token", "secret!")]),
    )
    .unwrap();
    let back = core
        .snippet_values(s.id.clone(), Some(h.id.clone()))
        .unwrap();
    assert_eq!(back, vals(&[("Branch", "fix"), ("Env", "dev")]));
    assert!(core.snippet_values(s.id.clone(), None).unwrap().is_empty());
}

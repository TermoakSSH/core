//! The typed server calls against a fake server: what they send and how
//! they read the answers (typed AI, per-account calls, server SFTP,
//! cancellable downloads).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::runtime::block_on;
use crate::*;

/// A request the fake server got.
#[derive(Debug, Clone)]
struct Req {
    method: String,
    /// Path with the query.
    path: String,
    body: Vec<u8>,
}

impl Req {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

/// What it answers.
enum Resp {
    Json(u16, Value),
    Bytes(Vec<u8>),
    /// Says `len` bytes, sends 1 KiB and stalls (a slow download).
    Stall(usize),
}

type Handler = Arc<dyn Fn(&Req) -> Resp + Send + Sync>;

struct Fake {
    url: String,
    seen: Arc<Mutex<Vec<Req>>>,
}

impl Fake {
    fn last(&self, method: &str, prefix: &str) -> Req {
        self.seen
            .lock()
            .iter()
            .rev()
            .find(|r| r.method == method && r.path.starts_with(prefix))
            .cloned()
            .unwrap_or_else(|| panic!("no {method} {prefix}: {:?}", self.seen.lock()))
    }
}

const USER_ID: &str = "0190a3a4-7b1c-7cc0-9c1b-6d5f3e2a1b00";

fn user(locale: &str) -> Value {
    json!({
        "id": USER_ID, "email": "ana@example.com", "name": "Ana",
        "is_admin": false, "disabled": false, "totp_enabled": false,
        "created_at": 1, "email_verified": true, "locale": locale,
    })
}

/// Sign-in answers, then `handler`.
fn fake_server(handler: impl Fn(&Req) -> Option<Resp> + Send + Sync + 'static) -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen: Arc<Mutex<Vec<Req>>> = Arc::default();
    let handler: Handler = Arc::new(move |r: &Req| {
        if let Some(resp) = handler(r) {
            return resp;
        }
        match (r.method.as_str(), r.path.as_str()) {
            ("POST", "/api/v1/auth/login") => Resp::Json(
                200,
                json!({"user": user("en"), "verification_required": false, "tokens": {
                    "access_token": "at", "access_expires_at": i64::MAX,
                    "refresh_token": "rt", "refresh_expires_at": i64::MAX,
                    "device_id": "0190a3a4-7b1c-7cc0-9c1b-6d5f3e2a1b01",
                }}),
            ),
            ("GET", "/api/v1/info") => Resp::Json(200, json!({"features": {}})),
            _ => Resp::Json(
                404,
                json!({"error": {"code": "not_found", "message": "not here"}}),
            ),
        }
    });
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let (handler, log) = (handler.clone(), log.clone());
            std::thread::spawn(move || serve(stream, handler, log));
        }
    });
    Fake { url, seen }
}

fn serve(stream: TcpStream, handler: Handler, log: Arc<Mutex<Vec<Req>>>) {
    let mut out = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let mut parts = line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").to_string();
        let mut len = 0usize;
        loop {
            let mut h = String::new();
            if reader.read_line(&mut h).unwrap_or(0) == 0 {
                return;
            }
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            if let Some((name, value)) = h.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                len = value.trim().parse().unwrap_or(0);
            }
        }
        let mut body = vec![0; len];
        if reader.read_exact(&mut body).is_err() {
            return;
        }
        let req = Req { method, path, body };
        let resp = handler(&req);
        log.lock().push(req);
        let (status, ctype, bytes, stall) = match resp {
            Resp::Json(s, v) => (s, "application/json", v.to_string().into_bytes(), None),
            Resp::Bytes(b) => (200, "application/octet-stream", b, None),
            Resp::Stall(n) => (200, "application/octet-stream", vec![b'x'; 1024], Some(n)),
        };
        let head = format!(
            "HTTP/1.1 {status} X\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\n\r\n",
            stall.unwrap_or(bytes.len())
        );
        if out.write_all(head.as_bytes()).is_err() || out.write_all(&bytes).is_err() {
            return;
        }
        let _ = out.flush();
        if stall.is_some() {
            std::thread::sleep(Duration::from_secs(30));
            return;
        }
    }
}

fn signed_in(fake: &Fake) -> (tempfile::TempDir, Arc<TermoakCore>) {
    let dir = tempfile::tempdir().unwrap();
    let core = TermoakCore::new(
        dir.path().to_string_lossy().into_owned(),
        generate_vault_key(),
    )
    .unwrap();
    block_on(core.login(
        fake.url.clone(),
        "ana@example.com".into(),
        "pw".into(),
        None,
    ))
    .unwrap();
    (dir, core)
}

const TASK: &str = "0190a3a4-7b1c-7cc0-9c1b-6d5f3e2a1b10";
const APPROVAL: &str = "0190a3a4-7b1c-7cc0-9c1b-6d5f3e2a1b11";
const HOST: &str = "0190a3a4-7b1c-7cc0-9c1b-6d5f3e2a1b12";
const GROUP: &str = "0190a3a4-7b1c-7cc0-9c1b-6d5f3e2a1b13";
const TEAM: &str = "0190a3a4-7b1c-7cc0-9c1b-6d5f3e2a1b14";
const SNIPPET: &str = "0190a3a4-7b1c-7cc0-9c1b-6d5f3e2a1b15";

fn task_json() -> Value {
    json!({
        "id": TASK, "title": "Disk", "prompt": "free space", "status": "waiting_approval",
        "mode": "ask", "provider": "claude", "host_ids": [HOST], "created_at": 1,
        "updated_at": 2, "cost_micros": 5, "fan_out": true, "plan_first": true,
        "group_id": GROUP, "tag": "web", "parent_id": null,
        "plan": {"text": "1. look\n2. clean", "approved": true, "edited": true},
        "steps": [{"call_id": "c1", "tool": "run_command", "host": "web-1",
                   "command": "df -h", "ok": true, "at": 9}],
        "hosts": [{"host_id": HOST, "label": "web-1", "task_id": TASK, "status": "running",
                   "summary": "ok", "duration_ms": 1200, "cost_micros": 3,
                   "pending_approvals": 1}],
        "pending_approvals": [{
            "id": APPROVAL, "task_id": TASK, "tool": "run_command",
            "input": {"command": "rm -rf /var/cache/app/*"}, "summary": "rm",
            "status": "pending", "created_at": 3,
            "preview": {"kind": "command", "host": "web-1", "command": "rm -rf /var/cache/app/*",
                        "risk": "high", "reasons": [{"code": "rm_rf", "text": "recursive forced delete"}],
                        "explanation": "Free disk space", "editable": true}
        }, {
            "id": APPROVAL, "task_id": TASK, "tool": "write_file", "input": {},
            "summary": "write", "status": "pending", "created_at": 4,
            "preview": {"kind": "file", "path": "/etc/app.conf", "diff": "--- a\n+++ b\n",
                        "diff_truncated": true, "added": 3, "removed": 1, "new_file": false,
                        "risk": "medium"}
        }, {
            "id": APPROVAL, "task_id": TASK, "tool": "run_command", "input": {},
            "summary": "old server", "status": "pending", "created_at": 5
        }],
    })
}

#[test]
fn typed_ai_calls() {
    let fake = fake_server(|r| {
        Some(match (r.method.as_str(), r.path.as_str()) {
            ("POST", "/api/v1/ai/tasks") => Resp::Json(200, task_json()),
            ("GET", p) if p == format!("/api/v1/ai/tasks/{TASK}") => Resp::Json(200, task_json()),
            ("DELETE", p) if p == format!("/api/v1/ai/tasks/{TASK}") => {
                Resp::Json(200, json!({"ok": true}))
            }
            ("POST", p) if p.contains("/approvals/") => Resp::Json(200, json!({"ok": true})),
            ("GET", p) if p.ends_with("/runbook") => Resp::Json(
                200,
                json!({"name": "Disk", "description": "d", "script": "df -h {{host}}",
                       "variables": ["host"], "steps": 2}),
            ),
            ("POST", p) if p.ends_with("/runbook") => Resp::Json(
                200,
                json!({"id": SNIPPET, "name": "Disk", "script": "df -h", "description": "",
                       "tags": ["ai", "runbook"], "owner_id": USER_ID, "rev": 1,
                       "updated_at": 7, "deleted": false, "has_secret": false,
                       "sync_mode": "synced"}),
            ),
            ("GET", "/api/v1/ai/providers") => Resp::Json(
                200,
                json!({"default": "claude", "fallback": ["gpt"], "default_mode": "confirm",
                       "providers": [{"key": "claude", "label": "Claude", "driver": "anthropic",
                         "available": false, "hidden": false, "default_model": "claude-opus-5",
                         "models": ["claude-opus-5"], "subscription": false,
                         "reason": "add your key", "reason_code": "own_key_required",
                         "accepts_own_key": true, "uses_own_key": false}]}),
            ),
            ("POST", "/api/v1/ai/suggest") => Resp::Json(
                200,
                json!({"command": "df -h", "explanation": "disk", "risk": "read",
                       "provider": "claude"}),
            ),
            ("POST", "/api/v1/ai/explain") => {
                Resp::Json(200, json!({"answer": "**full**", "provider": "gpt"}))
            }
            _ => return None,
        })
    });
    let (_dir, core) = signed_in(&fake);

    // New request fields, sent only when set.
    let task = block_on(core.create_ai_task(AiTaskRequest {
        prompt: "free space".into(),
        title: None,
        mode: None,
        provider: None,
        host_ids: vec![],
        session_id: None,
        effort: None,
        plan_first: true,
        group_id: Some(GROUP.into()),
        tag: Some(" web ".into()),
        fan_out: true,
    }))
    .unwrap();
    let body = fake.last("POST", "/api/v1/ai/tasks").json();
    assert_eq!(body["plan_first"], true);
    assert_eq!(body["fan_out"], true);
    assert_eq!(body["group_id"], GROUP);
    assert_eq!(body["tag"], "web");
    block_on(core.create_ai_task(AiTaskRequest {
        prompt: "p".into(),
        title: None,
        mode: None,
        provider: None,
        host_ids: vec![],
        session_id: None,
        effort: None,
        plan_first: false,
        group_id: None,
        tag: None,
        fan_out: false,
    }))
    .unwrap();
    let body = fake.last("POST", "/api/v1/ai/tasks").json();
    assert!(body.get("plan_first").is_none() && body.get("fan_out").is_none());
    assert!(body.get("group_id").is_none() && body.get("tag").is_none());

    // The task: plan, steps, hosts and previews.
    assert!(task.fan_out && task.plan_first);
    assert_eq!(task.group_id.as_deref(), Some(GROUP));
    assert_eq!(task.tag.as_deref(), Some("web"));
    assert_eq!(task.parent_id, None);
    let plan = task.plan.clone().unwrap();
    assert!(plan.approved && plan.edited);
    assert_eq!(task.steps.len(), 1);
    assert_eq!(task.steps[0].command.as_deref(), Some("df -h"));
    assert!(task.steps[0].ok);
    assert_eq!(task.hosts.len(), 1);
    assert_eq!(task.hosts[0].status, AiTaskStatus::Running);
    assert_eq!(task.hosts[0].pending_approvals, 1);
    assert_eq!(task.hosts[0].duration_ms, Some(1200));
    let p = task.pending_approvals[0].preview.clone().unwrap();
    assert_eq!(p.kind, "command");
    assert_eq!(p.risk, AiRiskLevel::High);
    assert_eq!(p.reasons[0].code, "rm_rf");
    assert!(p.editable);
    assert_eq!(p.explanation.as_deref(), Some("Free disk space"));
    let f = task.pending_approvals[1].preview.clone().unwrap();
    assert_eq!(f.kind, "file");
    assert!(f.truncated && !f.new_file);
    assert_eq!((f.added, f.removed), (Some(3), Some(1)));
    assert_eq!(f.risk, AiRiskLevel::Medium);
    assert_eq!(task.pending_approvals[2].preview, None);

    // Answering with an edit and a reason.
    block_on(core.decide_approval_with(
        TASK.into(),
        APPROVAL.into(),
        AiDecision {
            approve: true,
            always: false,
            edited: Some("  rm -rf /var/cache/app/tmp  ".into()),
            reason: Some("narrower".into()),
        },
    ))
    .unwrap();
    let d = fake.last("POST", "/api/v1/ai/tasks/").json();
    assert_eq!(
        d,
        json!({"approve": true, "always": false, "edited": "rm -rf /var/cache/app/tmp",
               "reason": "narrower"})
    );
    // A denial never carries an edit; empty texts are left out.
    let acc = core.account(core.current_account().unwrap().id).unwrap();
    block_on(acc.decide_approval_with(
        TASK.into(),
        APPROVAL.into(),
        AiDecision {
            approve: false,
            always: false,
            edited: Some("ls".into()),
            reason: Some("  ".into()),
        },
    ))
    .unwrap();
    let d = fake.last("POST", "/api/v1/ai/tasks/").json();
    assert_eq!(d, json!({"approve": false, "always": false}));

    // Runbooks.
    let rb = block_on(core.get_runbook(TASK.into())).unwrap();
    assert_eq!(rb.variables, vec!["host".to_string()]);
    assert_eq!(rb.steps, 2);
    let snippet = block_on(acc.save_runbook(TASK.into(), None, Some(" Disk ".into()))).unwrap();
    assert_eq!(snippet.id, SNIPPET);
    assert_eq!(snippet.tags, vec!["ai".to_string(), "runbook".to_string()]);
    assert_eq!(snippet.account_id, Some(acc.id()));
    assert_eq!(
        fake.last("POST", &format!("/api/v1/ai/tasks/{TASK}/runbook"))
            .json(),
        json!({"name": "Disk"})
    );
    assert!(matches!(
        block_on(core.save_runbook(TASK.into(), Some("nope".into()), None)),
        Err(TermoakError::Invalid(_))
    ));
    block_on(core.delete_ai_task(TASK.into())).unwrap();
    fake.last("DELETE", &format!("/api/v1/ai/tasks/{TASK}"));

    // Providers.
    let providers = block_on(acc.list_ai_providers()).unwrap();
    assert_eq!(providers.default_provider.as_deref(), Some("claude"));
    assert_eq!(providers.fallback, vec!["gpt".to_string()]);
    assert_eq!(providers.default_mode, Some(AiPermissionMode::Confirm));
    assert_eq!(
        providers.providers[0].reason_code.as_deref(),
        Some("own_key_required")
    );
    assert!(providers.providers[0].accepts_own_key && !providers.providers[0].available);

    // Quick assistant: the screen's secrets stay on the device.
    let s = block_on(core.ai_suggest(
        "free disk".into(),
        Some(AiAssistContext {
            os: Some("ubuntu".into()),
            screen: Some("$ export API_TOKEN=supersecretvalue123\n$ df\n".into()),
            cwd: None,
        }),
        None,
    ))
    .unwrap();
    assert_eq!((s.command.as_str(), s.risk.as_str()), ("df -h", "read"));
    let sent = fake.last("POST", "/api/v1/ai/suggest").json();
    let screen = sent["context"]["screen"].as_str().unwrap();
    assert!(!screen.contains("supersecretvalue123"), "{screen}");
    assert!(screen.contains("[redacted]"));
    assert_eq!(sent["context"]["os"], "ubuntu");
    assert!(matches!(
        block_on(core.ai_suggest("  ".into(), None, None)),
        Err(TermoakError::Invalid(_))
    ));
    let e = block_on(acc.ai_explain("error 42".into(), Some("why?".into()), None, None)).unwrap();
    assert_eq!(
        (e.answer.as_str(), e.provider.as_str()),
        ("**full**", "gpt")
    );
    let sent = fake.last("POST", "/api/v1/ai/explain").json();
    assert_eq!(sent["question"], "why?");
    assert_eq!(sent["context"], Value::Null);
}

#[test]
fn account_calls_per_account() {
    let fake = fake_server(|r| {
        let team = json!({"id": TEAM, "name": "Ops", "role": "owner", "member_count": 1,
                          "created_at": 1, "created_by": USER_ID, "plan": "free"});
        let member = json!({"user_id": USER_ID, "email": "ana@example.com", "name": "Ana",
                            "role": "owner", "added_at": 1});
        Some(match (r.method.as_str(), r.path.as_str()) {
            ("GET", "/api/v1/me") => Resp::Json(200, json!({"user": user("en")})),
            ("PATCH", "/api/v1/me") => Resp::Json(200, user("es")),
            ("GET", "/api/v1/me/2fa") => {
                Resp::Json(200, json!({"enabled": true, "recovery_codes_left": 7}))
            }
            ("POST", "/api/v1/push/register") => {
                Resp::Json(200, json!({"ok": true, "server_enabled": true}))
            }
            ("DELETE", "/api/v1/push/register") => Resp::Json(200, json!({"ok": true})),
            ("GET", "/api/v1/teams") => Resp::Json(200, json!([team])),
            ("GET", p) if p.ends_with("/invites") => Resp::Json(
                200,
                json!([{"id": GROUP, "email": "beto@example.com", "is_admin": false,
                        "team_id": TEAM, "team_role": "admin", "created_by": USER_ID,
                        "created_at": 1, "expires_at": 9, "used_by": null, "used_at": null,
                        "revoked": false}]),
            ),
            ("POST", p) if p.ends_with("/invites") => {
                if r.json()["email"] == "ana@example.com" {
                    Resp::Json(200, json!({"added": true, "members": [member]}))
                } else {
                    Resp::Json(
                        200,
                        json!({"added": false, "token": "aks_inv_x", "server": "https://s",
                               "url": "termoak://invite?server=https%3A%2F%2Fs&token=aks_inv_x",
                               "emailed": true,
                               "invite": {"id": GROUP, "email": "beto@example.com",
                                          "is_admin": false, "team_id": TEAM,
                                          "team_role": "member", "created_by": USER_ID,
                                          "created_at": 1, "expires_at": 9, "used_by": null,
                                          "used_at": null, "revoked": false}}),
                    )
                }
            }
            ("DELETE", p) if p.contains("/invites/") => Resp::Json(200, json!({"ok": true})),
            _ => return None,
        })
    });
    let (_dir, core) = signed_in(&fake);
    let acc = core.account(core.current_account().unwrap().id).unwrap();

    assert_eq!(
        block_on(acc.current_user()).unwrap().email,
        "ana@example.com"
    );
    assert_eq!(block_on(acc.set_locale("es".into())).unwrap().locale, "es");
    assert_eq!(fake.last("PATCH", "/api/v1/me").json()["locale"], "es");
    let tf = block_on(acc.two_factor_status()).unwrap();
    assert!(tf.enabled);
    assert_eq!(tf.recovery_codes_left, 7);
    assert!(block_on(acc.register_push_token(PushPlatform::Fcm, " tok ".into(), false)).unwrap());
    assert_eq!(
        fake.last("POST", "/api/v1/push/register").json(),
        json!({"platform": "fcm", "token": "tok", "sandbox": false})
    );
    block_on(acc.unregister_push_token()).unwrap();
    fake.last("DELETE", "/api/v1/push/register");
    let teams = block_on(acc.list_teams()).unwrap();
    assert_eq!(teams[0].role, Some(TeamRole::Owner));

    let invites = block_on(acc.list_team_invites(TEAM.into())).unwrap();
    assert_eq!(invites[0].team_role, Some(TeamRole::Admin));
    let added =
        block_on(acc.invite_to_team(TEAM.into(), "ana@example.com".into(), TeamRole::Member))
            .unwrap();
    assert!(added.added && added.invite.is_none());
    assert_eq!(added.members.len(), 1);
    let invited =
        block_on(core.invite_to_team(TEAM.into(), " beto@example.com ".into(), TeamRole::Admin))
            .unwrap();
    assert!(!invited.added && invited.emailed && invited.members.is_empty());
    let inv = invited.invite.unwrap();
    assert_eq!(inv.token, "aks_inv_x");
    assert!(inv.app_link.starts_with("termoak://invite"));
    assert_eq!(
        fake.last("POST", &format!("/api/v1/teams/{TEAM}/invites"))
            .json(),
        json!({"email": "beto@example.com", "role": "admin"})
    );
    block_on(acc.revoke_team_invite(TEAM.into(), GROUP.into())).unwrap();
    fake.last("DELETE", &format!("/api/v1/teams/{TEAM}/invites/{GROUP}"));

    // A signed-out account answers `NotLoggedIn` per account too.
    let dir = tempfile::tempdir().unwrap();
    let alone = TermoakCore::new(
        dir.path().to_string_lossy().into_owned(),
        generate_vault_key(),
    )
    .unwrap();
    assert!(matches!(
        block_on(alone.two_factor_status()),
        Err(TermoakError::NotLoggedIn(_))
    ));
}

#[test]
fn server_sftp_parity_and_cancel() {
    let fake = fake_server(|r| {
        let path = r.path.as_str();
        Some(match r.method.as_str() {
            "GET" if path.contains("/sftp/stat?") => Resp::Json(
                200,
                json!({"name": "app.conf", "path": "/etc/app.conf", "kind": "file",
                       "size": 12, "mode": 420, "mode_string": "-rw-r--r--",
                       "modified": 100}),
            ),
            "GET" if path.contains("big.bin") => Resp::Bytes(vec![1; 64]),
            "GET" if path.contains("slow.bin") => Resp::Stall(10 * 1024 * 1024),
            "GET" if path.contains("/sftp/download?") => Resp::Bytes(b"hello world\n".to_vec()),
            "POST" if path.contains("/sftp/upload?") => {
                Resp::Json(200, json!({"ok": true, "bytes": r.body.len()}))
            }
            "POST" if path.ends_with("/sftp/chmod") => Resp::Json(200, json!({"ok": true})),
            _ => return None,
        })
    });
    let (dir, core) = signed_in(&fake);
    let acc = core.account(core.current_account().unwrap().id).unwrap();

    let st = block_on(acc.server_sftp_stat(HOST.into(), "/etc/app.conf".into())).unwrap();
    assert_eq!((st.size, st.mode), (12, Some(0o644)));
    assert_eq!(st.kind, RemoteFileKind::File);
    assert!(
        fake.last("GET", &format!("/api/v1/hosts/{HOST}/sftp/stat"))
            .path
            .ends_with("path=%2Fetc%2Fapp.conf")
    );

    block_on(acc.server_sftp_chmod(HOST.into(), "/etc/app.conf".into(), 0o640)).unwrap();
    assert_eq!(
        fake.last("POST", &format!("/api/v1/hosts/{HOST}/sftp/chmod"))
            .json(),
        json!({"path": "/etc/app.conf", "mode": "640"})
    );
    assert!(matches!(
        block_on(acc.server_sftp_chmod(HOST.into(), "/x".into(), 0o17777)),
        Err(TermoakError::Invalid(_))
    ));

    let data = block_on(acc.server_sftp_read(HOST.into(), "/etc/app.conf".into(), 0)).unwrap();
    assert_eq!(data, b"hello world\n");
    assert!(matches!(
        block_on(acc.server_sftp_read(HOST.into(), "/big.bin".into(), 10)),
        Err(TermoakError::Invalid(_))
    ));
    let n = block_on(core.server_sftp_write(
        HOST.into(),
        "/etc/app.conf".into(),
        b"new content".to_vec(),
        None,
    ))
    .unwrap();
    assert_eq!(n, 11);
    let up = fake.last("POST", &format!("/api/v1/hosts/{HOST}/sftp/upload"));
    assert_eq!(up.body, b"new content");
    assert!(up.path.ends_with("path=%2Fetc%2Fapp.conf"));

    // Download with progress, then a slow one cancelled half way: no file,
    // no `.part`.
    let local = dir.path().join("got.txt");
    let n = block_on(acc.server_sftp_download(
        HOST.into(),
        "/etc/app.conf".into(),
        local.to_string_lossy().into_owned(),
        None,
        None,
    ))
    .unwrap();
    assert_eq!(n, 12);
    assert_eq!(std::fs::read(&local).unwrap(), b"hello world\n");

    struct CancelOnProgress(Arc<TransferHandle>);
    impl TransferListener for CancelOnProgress {
        fn on_progress(&self, _transferred: u64, _total: Option<u64>) {
            self.0.cancel();
        }
    }
    let cancel = TransferHandle::new();
    let slow = dir.path().join("slow.bin");
    let started = std::time::Instant::now();
    let err = block_on(core.server_sftp_download(
        HOST.into(),
        "/slow.bin".into(),
        slow.to_string_lossy().into_owned(),
        Some(Arc::new(CancelOnProgress(cancel.clone()))),
        None,
        Some(cancel.clone()),
    ))
    .err()
    .unwrap();
    assert!(matches!(err, TermoakError::Cancelled(_)), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(20));
    assert!(cancel.is_cancelled());
    assert!(!slow.exists());
    assert!(!dir.path().join("slow.bin.part").exists());
}

//! Engine tests with a fake provider (scripted turns) and a fake terminal.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::{Value, json};
use termoak_core::crypto::MasterKey;
use termoak_core::model::{Host, SecretUpdate, Snippet};
use termoak_core::{Id, Store, new_id};
use termoak_ssh::{ConnectionPool, HostKeyPolicy};

use super::*;
use crate::access::ChainSource;
use crate::message::StopReason;
use crate::policy::RiskLevel;
use crate::provider::{Backend, ChatProvider, EventSink, TurnRequest, TurnResponse};
use crate::tools::{SessionSummary, TerminalOutput};

enum Turn {
    Text(&'static str),
    Call(&'static str, Value),
}

/// Answers each request with the next scripted turn ("done" when they run
/// out) and keeps what it was sent.
#[derive(Default)]
struct FakeProvider {
    turns: Mutex<VecDeque<Turn>>,
    /// Number of tools offered and the conversation of each request.
    seen: Mutex<Vec<(usize, Vec<Message>)>>,
}

impl FakeProvider {
    fn new(turns: Vec<Turn>) -> Arc<Self> {
        Arc::new(Self {
            turns: Mutex::new(turns.into()),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn requests(&self) -> Vec<(usize, Vec<Message>)> {
        self.seen.lock().clone()
    }
}

#[async_trait]
impl ChatProvider for FakeProvider {
    fn key(&self) -> &str {
        "fake"
    }
    fn model(&self) -> &str {
        "m"
    }
    fn native_key(&self) -> String {
        "fake::m".into()
    }
    async fn turn(
        &self,
        req: &TurnRequest<'_>,
        _sink: &dyn EventSink,
    ) -> Result<TurnResponse, AiError> {
        let n = {
            let mut seen = self.seen.lock();
            seen.push((req.tools.len(), req.messages.to_vec()));
            seen.len()
        };
        let turn = self.turns.lock().pop_front().unwrap_or(Turn::Text("done"));
        let (content, stop) = match turn {
            Turn::Text(t) => (vec![Part::Text { text: t.into() }], StopReason::EndTurn),
            Turn::Call(name, input) => (
                vec![Part::ToolCall {
                    id: format!("call_{n}"),
                    name: name.into(),
                    input,
                }],
                StopReason::ToolUse,
            ),
        };
        Ok(TurnResponse {
            message: Message::Assistant {
                content,
                native: None,
                provider: None,
            },
            stop,
            usage: Usage {
                input_tokens: 10,
                output_tokens: 5,
                ..Default::default()
            },
            model: "m".into(),
            refusal_category: None,
        })
    }
}

struct FakeChain;

#[async_trait]
impl ChainSource for FakeChain {
    async fn chain(&self, _: Id, _: Option<&str>) -> Result<Vec<ChainEntry>, AiError> {
        Ok(vec![ChainEntry::server("fake")])
    }
}

/// A terminal that records what is typed and prints `output`.
struct FakeTerminal {
    id: Id,
    output: String,
    typed: Mutex<Vec<String>>,
}

#[async_trait]
impl SessionAccess for FakeTerminal {
    async fn list(&self, _: Id) -> Vec<SessionSummary> {
        vec![SessionSummary {
            id: self.id,
            title: "web1 terminal".into(),
            host_id: None,
            status: "open".into(),
            viewers: 1,
        }]
    }
    async fn read(&self, _: Id, _: Id, _: usize) -> Result<String, String> {
        Ok("$ ".into())
    }
    async fn send(&self, _: Id, _: Id, input: &str) -> Result<(), String> {
        self.typed.lock().push(input.to_string());
        Ok(())
    }
    async fn send_and_collect(
        &self,
        _: Id,
        _: Id,
        input: &str,
        _: Duration,
        _: Duration,
    ) -> Result<Option<TerminalOutput>, String> {
        self.typed.lock().push(input.to_string());
        Ok(Some(TerminalOutput {
            text: self.output.clone(),
            still_running: false,
        }))
    }
}

struct Setup {
    engine: Arc<AiEngine>,
    store: Store,
    owner: Id,
    term: Arc<FakeTerminal>,
    events: tokio::sync::broadcast::Receiver<UserEvent>,
}

async fn setup(provider: Arc<FakeProvider>, output: &str) -> Setup {
    let store = Store::open_in_memory(MasterKey::generate()).unwrap();
    let owner = store
        .create_user("ops@example.com", "Ops", "a long password 123", false)
        .await
        .unwrap()
        .id;
    let pool = ConnectionPool::new(
        store.clone(),
        HostKeyPolicy::Strict,
        Duration::from_secs(60),
    );
    let term = Arc::new(FakeTerminal {
        id: new_id(),
        output: output.to_string(),
        typed: Mutex::new(Vec::new()),
    });
    let config = AiConfig {
        approval_timeout_secs: 20,
        ..Default::default()
    };
    let engine = AiEngine::new(store.clone(), pool, Some(term.clone()), config)
        .await
        .unwrap();
    engine
        .registry
        .test_backends
        .lock()
        .insert("fake".into(), Backend::Chat(provider));
    engine.set_chain_source(Arc::new(FakeChain));
    let events = engine.subscribe();
    Setup {
        engine,
        store,
        owner,
        term,
        events,
    }
}

/// Waits for the first event of `task` that `f` accepts.
async fn wait_for<T>(
    events: &mut tokio::sync::broadcast::Receiver<UserEvent>,
    task: Id,
    mut f: impl FnMut(&TaskEvent) -> Option<T>,
) -> T {
    loop {
        let ev = tokio::time::timeout(Duration::from_secs(10), events.recv())
            .await
            .expect("timed out waiting for an event")
            .unwrap();
        if ev.task_id != task {
            continue;
        }
        if let Some(v) = f(&ev.event) {
            return v;
        }
    }
}

async fn approval(
    events: &mut tokio::sync::broadcast::Receiver<UserEvent>,
    task: Id,
) -> (Id, String, ApprovalPreview) {
    wait_for(events, task, |e| match e {
        TaskEvent::ApprovalRequested {
            approval_id,
            tool,
            preview,
            ..
        } => Some((*approval_id, tool.clone(), preview.clone().unwrap())),
        _ => None,
    })
    .await
}

async fn finished(
    events: &mut tokio::sync::broadcast::Receiver<UserEvent>,
    task: Id,
) -> (TaskStatus, Option<String>, Option<String>) {
    wait_for(events, task, |e| match e {
        TaskEvent::Finished {
            status,
            result,
            error,
        } => Some((*status, result.clone(), error.clone())),
        _ => None,
    })
    .await
}

fn task(prompt: &str) -> CreateTask {
    CreateTask {
        prompt: prompt.into(),
        mode: Some(PermissionMode::Ask),
        ..Default::default()
    }
}

/// Text of the tool results and user texts of the last user message of a request.
fn last_user_text(messages: &[Message]) -> String {
    match messages
        .iter()
        .rev()
        .find(|m| matches!(m, Message::User { .. }))
    {
        Some(Message::User { content }) => content
            .iter()
            .map(|p| match p {
                Part::Text { text } => text.clone(),
                Part::ToolResult { content, .. } => content.clone(),
                _ => String::new(),
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

#[tokio::test]
async fn approval_preview_edit_and_redaction_and_runbook() {
    let provider = FakeProvider::new(vec![]);
    let mut s = setup(provider.clone(), "removed\nDB_PASSWORD=hunter2\n").await;
    provider.turns.lock().extend([
        Turn::Call(
            "send_to_terminal",
            json!({"session_id": s.term.id, "input": "rm -rf /tmp/build"}),
        ),
        Turn::Text("Cleaned."),
    ]);
    let view = s
        .engine
        .create_task(s.owner, task("clean the build"))
        .await
        .unwrap();
    let (approval_id, tool, preview) = approval(&mut s.events, view.id).await;
    assert_eq!(tool, "send_to_terminal");
    assert_eq!(preview.kind, "terminal");
    assert_eq!(preview.command.as_deref(), Some("rm -rf /tmp/build"));
    assert_eq!(preview.host.as_deref(), Some("web1 terminal"));
    assert_eq!(preview.risk, RiskLevel::High);
    assert!(preview.reasons.iter().any(|r| r.code == "rm_rf"));
    assert!(preview.editable);
    // Also in the task's pending approvals (for apps that load it).
    let pending = s
        .engine
        .get(s.owner, view.id, false)
        .await
        .unwrap()
        .pending_approvals;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].preview.as_ref().unwrap()["risk"], "high");

    s.engine
        .decide_with(
            s.owner,
            view.id,
            approval_id,
            ApprovalDecision {
                approve: true,
                edited: Some("rm -rf /tmp/build-old".into()),
                ..Default::default()
            },
            "test",
        )
        .await
        .unwrap();
    let (status, result, _) = finished(&mut s.events, view.id).await;
    assert_eq!(status, TaskStatus::Completed);
    assert_eq!(result.as_deref(), Some("Cleaned."));
    // What ran is the edited command, and the model is told.
    assert_eq!(s.term.typed.lock().as_slice(), ["rm -rf /tmp/build-old\r"]);
    let requests = provider.requests();
    assert_eq!(requests.len(), 2);
    let told = last_user_text(&requests[1].1);
    assert!(told.contains("edited the command"), "{told}");
    assert!(told.contains("rm -rf /tmp/build-old"), "{told}");
    // Secrets in the output never reach the provider.
    assert!(!told.contains("hunter2"), "{told}");
    assert!(told.contains("DB_PASSWORD=[redacted]"), "{told}");

    let full = s.engine.get(s.owner, view.id, true).await.unwrap();
    assert_eq!(full.steps.len(), 1);
    assert!(full.steps[0].edited);
    assert_eq!(
        full.steps[0].command.as_deref(),
        Some("rm -rf /tmp/build-old")
    );
    // The decision is in the persisted events.
    let events = s.engine.events(s.owner, view.id, 0).await.unwrap();
    let decided = events
        .iter()
        .find(|e| e.kind == "approval_decided")
        .unwrap();
    assert_eq!(decided.data["edited"], "rm -rf /tmp/build-old");

    // Save as runbook.
    let rb = s.engine.runbook(s.owner, view.id).await.unwrap();
    assert_eq!(rb.steps, 1);
    assert!(
        rb.script.contains("\nrm -rf /tmp/build-old\n"),
        "{}",
        rb.script
    );
    let snippet = s
        .engine
        .save_runbook(s.owner, view.id, Some("Clean builds".into()))
        .await
        .unwrap();
    assert_eq!(snippet.name, "Clean builds");
    let access = s.store.vault_access(s.owner).await.unwrap();
    let saved = s.store.list_in::<Snippet>(&access, None).await.unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].data.script, rb.script);
}

#[tokio::test]
async fn denial_reason_goes_to_the_model() {
    let provider = FakeProvider::new(vec![]);
    let mut s = setup(provider.clone(), "ok").await;
    provider.turns.lock().extend([
        Turn::Call(
            "send_to_terminal",
            json!({"session_id": s.term.id, "input": "systemctl restart nginx"}),
        ),
        Turn::Text("Understood."),
    ]);
    let view = s
        .engine
        .create_task(s.owner, task("restart nginx"))
        .await
        .unwrap();
    let (approval_id, _, preview) = approval(&mut s.events, view.id).await;
    assert_eq!(preview.risk, RiskLevel::Medium);
    assert_eq!(preview.reasons[0].code, "service");
    s.engine
        .decide_with(
            s.owner,
            view.id,
            approval_id,
            ApprovalDecision::deny(Some("not during business hours".into())),
            "test",
        )
        .await
        .unwrap();
    let (status, ..) = finished(&mut s.events, view.id).await;
    assert_eq!(status, TaskStatus::Completed);
    assert!(s.term.typed.lock().is_empty());
    let told = last_user_text(&provider.requests()[1].1);
    assert!(told.contains("did NOT approve"), "{told}");
    assert!(told.contains("not during business hours"), "{told}");
    // Nothing ran: nothing for a runbook.
    let full = s.engine.get(s.owner, view.id, true).await.unwrap();
    assert!(full.steps.is_empty());
    assert!(s.engine.save_runbook(s.owner, view.id, None).await.is_err());
}

#[tokio::test]
async fn plan_first_is_approved_edited_before_acting() {
    let provider = FakeProvider::new(vec![]);
    let mut s = setup(provider.clone(), "Filesystem 10G").await;
    provider.turns.lock().extend([
        Turn::Text("1. Check the disk\n2. Delete old logs (approval)"),
        Turn::Call(
            "send_to_terminal",
            json!({"session_id": s.term.id, "input": "df -h"}),
        ),
        Turn::Text("Disk checked."),
    ]);
    let mut req = task("free some disk");
    req.plan_first = Some(true);
    let view = s.engine.create_task(s.owner, req).await.unwrap();
    assert!(view.plan_first);
    let (approval_id, tool, preview) = approval(&mut s.events, view.id).await;
    assert_eq!(tool, "plan");
    assert_eq!(preview.kind, "plan");
    assert!(
        preview
            .plan
            .as_deref()
            .unwrap()
            .starts_with("1. Check the disk")
    );
    // The plan was written without tools.
    assert_eq!(provider.requests()[0].0, 0);
    s.engine
        .decide_with(
            s.owner,
            view.id,
            approval_id,
            ApprovalDecision {
                approve: true,
                edited: Some("1. Only check the disk".into()),
                ..Default::default()
            },
            "test",
        )
        .await
        .unwrap();
    let (status, result, _) = finished(&mut s.events, view.id).await;
    assert_eq!(status, TaskStatus::Completed);
    assert_eq!(result.as_deref(), Some("Disk checked."));
    let requests = provider.requests();
    assert!(requests[1].0 > 0, "tools are offered after the plan");
    assert!(last_user_text(&requests[1].1).contains("1. Only check the disk"));
    let full = s.engine.get(s.owner, view.id, true).await.unwrap();
    assert_eq!(
        full.plan,
        Some(TaskPlan {
            text: "1. Only check the disk".into(),
            approved: true,
            edited: true,
        })
    );
    // df -h is read-only: it ran without an approval.
    assert_eq!(s.term.typed.lock().as_slice(), ["df -h\r"]);
}

#[tokio::test]
async fn rejected_plan_is_proposed_again_then_stops() {
    let provider = FakeProvider::new(vec![
        Turn::Text("1. Reboot the server"),
        Turn::Text("1. Restart only nginx"),
    ]);
    let mut s = setup(provider.clone(), "").await;
    let mut req = task("fix the web");
    req.plan_first = Some(true);
    let view = s.engine.create_task(s.owner, req).await.unwrap();
    let (first, ..) = approval(&mut s.events, view.id).await;
    s.engine
        .decide_with(
            s.owner,
            view.id,
            first,
            ApprovalDecision::deny(Some("no reboots".into())),
            "test",
        )
        .await
        .unwrap();
    let (second, _, preview) = approval(&mut s.events, view.id).await;
    assert_eq!(preview.plan.as_deref(), Some("1. Restart only nginx"));
    assert!(last_user_text(&provider.requests()[1].1).contains("no reboots"));
    s.engine
        .decide_with(
            s.owner,
            view.id,
            second,
            ApprovalDecision::deny(None),
            "test",
        )
        .await
        .unwrap();
    let (status, _, error) = finished(&mut s.events, view.id).await;
    assert_eq!(status, TaskStatus::Cancelled);
    assert_eq!(error.as_deref(), Some("the plan was not approved"));
    assert!(s.term.typed.lock().is_empty());
}

#[tokio::test]
async fn stop_and_continue_keeps_the_context() {
    let provider = FakeProvider::new(vec![]);
    let mut s = setup(provider.clone(), "").await;
    provider.turns.lock().extend([
        Turn::Call(
            "send_to_terminal",
            json!({"session_id": s.term.id, "input": "systemctl restart nginx"}),
        ),
        Turn::Text("Continuing as asked."),
    ]);
    let view = s
        .engine
        .create_task(s.owner, task("restart nginx"))
        .await
        .unwrap();
    approval(&mut s.events, view.id).await;
    s.engine.cancel(s.owner, view.id).await.unwrap();
    let (status, ..) = finished(&mut s.events, view.id).await;
    assert_eq!(status, TaskStatus::Cancelled);
    assert!(s.engine.cancel(s.owner, view.id).await.is_err());

    s.engine
        .send_message(s.owner, view.id, "go on, but only check its status")
        .await
        .unwrap();
    let (status, result, _) = finished(&mut s.events, view.id).await;
    assert_eq!(status, TaskStatus::Completed);
    assert_eq!(result.as_deref(), Some("Continuing as asked."));
    let requests = provider.requests();
    assert_eq!(requests.len(), 2);
    // The second request has the whole conversation: the request, the call,
    // its (not approved) result and the new message.
    let convo = &requests[1].1;
    assert!(matches!(&convo[0], Message::User { .. }));
    assert_eq!(convo[1].tool_calls().len(), 1);
    let last = last_user_text(convo);
    assert!(last.contains("go on, but only check its status"), "{last}");
    assert!(convo.iter().any(|m| {
        m.parts()
            .iter()
            .any(|p| matches!(p, Part::ToolResult { .. }))
    }));
}

#[test]
fn a_dangling_call_gets_a_result_before_the_next_message() {
    let mut messages = vec![
        Message::user_text("do it"),
        Message::Assistant {
            content: vec![Part::ToolCall {
                id: "c1".into(),
                name: "run_command".into(),
                input: json!({}),
            }],
            native: None,
            provider: None,
        },
    ];
    push_user_text(&mut messages, "continue");
    assert_eq!(messages.len(), 3);
    match &messages[2] {
        Message::User { content } => {
            assert!(
                matches!(&content[0], Part::ToolResult { id, is_error: true, .. } if id == "c1")
            );
            assert!(matches!(&content[1], Part::Text { text } if text == "continue"));
        }
        _ => panic!("expected a user message"),
    }
    // Without a dangling call it is a plain message.
    push_user_text(&mut messages, "again");
    assert_eq!(messages[3], Message::user_text("again"));
}

#[tokio::test]
async fn multi_host_task_fans_out_per_host() {
    let provider = FakeProvider::new(vec![]);
    let mut s = setup(provider.clone(), "").await;
    for (label, address, tag) in [
        ("web2", "10.0.0.2", "web"),
        ("web1", "10.0.0.1", "web"),
        ("db1", "10.0.0.9", "db"),
    ] {
        let host: Host =
            serde_json::from_value(json!({"label": label, "address": address, "tags": [tag]}))
                .unwrap();
        s.store
            .save(s.owner, host, SecretUpdate::Keep, None)
            .await
            .unwrap();
    }
    let mut req = task("check uptime");
    req.tag = Some("web".into());
    req.fan_out = Some(true);
    let view = s.engine.create_task(s.owner, req).await.unwrap();
    assert!(view.fan_out);
    assert_eq!(view.host_ids.as_ref().map(Vec::len), Some(2));
    let (status, result, _) = finished(&mut s.events, view.id).await;
    assert_eq!(status, TaskStatus::Completed);
    let result = result.unwrap();
    assert!(result.contains("**web1**: completed — done"), "{result}");

    let full = s.engine.get(s.owner, view.id, true).await.unwrap();
    let labels: Vec<&str> = full.hosts.iter().map(|h| h.label.as_str()).collect();
    assert_eq!(labels, ["web1", "web2"]);
    for h in &full.hosts {
        assert_eq!(h.status, TaskStatus::Completed);
        assert_eq!(h.summary.as_deref(), Some("done"));
        assert!(h.duration_ms.is_some());
        // Drill-down: each host has its own conversation, limited to it.
        let child = s.engine.get(s.owner, h.task_id, true).await.unwrap();
        assert_eq!(child.parent_id, Some(view.id));
        assert_eq!(child.host_ids, Some(vec![h.host_id]));
        let first = child.messages.unwrap()[0].text();
        assert!(
            first.contains(&format!("Hosts for this task: {} (", h.label)),
            "{first}"
        );
    }
    assert_eq!(provider.requests().len(), 2);
    // The list shows the multi-host task only.
    let list = s.engine.list(s.owner, 10).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, view.id);

    // A follow-up goes to every host.
    s.engine
        .send_message(s.owner, view.id, "and the load?")
        .await
        .unwrap();
    let (status, ..) = finished(&mut s.events, view.id).await;
    assert_eq!(status, TaskStatus::Completed);
    assert_eq!(provider.requests().len(), 4);

    // Deleting it deletes the hosts' conversations.
    s.engine.delete(s.owner, view.id).await.unwrap();
    assert!(
        s.engine
            .get(s.owner, full.hosts[0].task_id, false)
            .await
            .is_err()
    );

    // A group or tag without hosts is an error.
    let mut req = task("x");
    req.tag = Some("nothing".into());
    assert!(s.engine.create_task(s.owner, req).await.is_err());
}

#[tokio::test]
async fn write_file_previews_and_refuses_redacted_content() {
    let s = setup(FakeProvider::new(vec![]), "").await;
    let ctx = ToolContext {
        owner: s.owner,
        task_id: None,
        host_scope: None,
    };
    let input = json!({"host": "nowhere", "path": "/etc/app.env", "content": "KEY=1\n"});
    let p = s.engine.tools().preview(&ctx, "write_file", &input).await;
    assert_eq!(p.kind, "file");
    assert_eq!(p.path.as_deref(), Some("/etc/app.env"));
    assert_eq!(p.risk, RiskLevel::Medium);
    assert_eq!(p.reasons[0].text, "writes to /etc");
    assert!(p.diff.is_none());
    assert!(p.diff_error.as_deref().unwrap().contains("no host"));

    let input =
        json!({"host": "nowhere", "path": "/srv/.env", "content": "DB_PASSWORD=[redacted]\n"});
    let out = s.engine.tools().execute(&ctx, "write_file", &input).await;
    assert!(!out.ok);
    assert!(out.content.contains("[redacted]"), "{}", out.content);
}

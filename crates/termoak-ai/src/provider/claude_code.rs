//! Claude Code (`claude -p`), headless, with the user's own sign-in or
//! subscription.
//!
//! - Output: `--output-format stream-json --verbose --include-partial-messages`
//!   (one JSON event per line: `system`/`init`, `stream_event` deltas,
//!   complete `assistant` and `user` messages and a final `result`).
//! - Tools: none of its own (`--tools ""`). Termoak's tools come from one MCP
//!   server given with `--mcp-config` (a private file with the run's token)
//!   and `--strict-mcp-config` (no other MCP servers). `--permission-mode
//!   dontAsk` with `--allowedTools mcp__termoak` runs those tools and denies
//!   anything else; Termoak's own policy then decides what needs approval.
//! - The prompt goes through stdin and Termoak's instructions replace the
//!   default ones (`--system-prompt`). Nothing is saved
//!   (`--no-session-persistence`).

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

use super::cli::{self, MCP_NAME, Workdir};
use super::{EventSink, ExternalAgent, ExternalResult, ExternalRun, StreamEvent};
use crate::config::ProviderConfig;
use crate::error::AiError;
use crate::message::Usage;

pub struct ClaudeCode {
    key: String,
    model: Option<String>,
    command: String,
    path_env: Option<String>,
    timeout: Duration,
    effort: Option<String>,
}

impl ClaudeCode {
    pub fn new(key: &str, cfg: &ProviderConfig, model: Option<String>) -> Self {
        Self {
            key: key.to_string(),
            model,
            command: cfg.command.clone().unwrap_or_else(|| "claude".into()),
            path_env: cfg.path_env.clone(),
            timeout: Duration::from_secs(cfg.timeout_secs.unwrap_or(1800)),
            effort: cfg.effort.clone(),
        }
    }

    /// Arguments of `claude` (the prompt goes through stdin).
    pub fn arguments(
        &self,
        system: &str,
        mcp_config: Option<&Path>,
        effort: Option<&str>,
    ) -> Vec<String> {
        let mut args: Vec<String> = [
            "-p",
            "--output-format",
            "stream-json",
            "--verbose",
            "--include-partial-messages",
            "--no-session-persistence",
            "--disable-slash-commands",
            // No built-in tools (shell, files, web...).
            "--tools",
            "",
            // Whatever is not allowed below is denied without asking.
            "--permission-mode",
            "dontAsk",
            // Only the MCP servers given here.
            "--strict-mcp-config",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        if let Some(path) = mcp_config {
            args.extend([
                "--mcp-config".into(),
                path.display().to_string(),
                "--allowedTools".into(),
                format!("mcp__{MCP_NAME}"),
            ]);
        }
        if !system.is_empty() {
            args.extend(["--system-prompt".into(), system.to_string()]);
        }
        if let Some(model) = &self.model {
            args.extend(["--model".into(), model.clone()]);
        }
        if let Some(effort) = effort.map(str::to_string).or_else(|| self.effort.clone()) {
            args.extend(["--effort".into(), effort]);
        }
        args
    }
}

/// What a run of Claude Code produced, built from its events.
#[derive(Debug, Default)]
pub(crate) struct ClaudeStream {
    /// Text deltas arrived (`--include-partial-messages`): the complete
    /// messages do not emit their text again.
    partial: bool,
    /// Some text was already shown (to separate the following messages).
    shown_text: bool,
    last_text: String,
    pub(crate) reasoning: String,
    pub(crate) result: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) usage: Usage,
    pub(crate) model: Option<String>,
}

impl ClaudeStream {
    pub(crate) fn on_event(&mut self, v: &Value, sink: &dyn EventSink) {
        match v["type"].as_str().unwrap_or("") {
            "system" if v["subtype"] == "init" => {
                if let Some(m) = v["model"].as_str() {
                    self.model = Some(m.to_string());
                }
                for s in v["mcp_servers"].as_array().into_iter().flatten() {
                    let status = s["status"].as_str().unwrap_or("");
                    if s["name"] == MCP_NAME && status != "connected" {
                        sink.emit(StreamEvent::Notice(format!(
                            "Claude Code could not connect to Termoak's tools ({status})"
                        )));
                    }
                }
            }
            "stream_event" => {
                let e = &v["event"];
                match e["type"].as_str().unwrap_or("") {
                    "message_start" => {
                        if self.shown_text {
                            sink.emit(StreamEvent::Text("\n\n".into()));
                            self.shown_text = false;
                        }
                        self.last_text.clear();
                    }
                    "content_block_delta" => {
                        let d = &e["delta"];
                        match d["type"].as_str().unwrap_or("") {
                            "text_delta" => {
                                let t = d["text"].as_str().unwrap_or("");
                                self.partial = true;
                                if !t.is_empty() {
                                    self.shown_text = true;
                                    self.last_text.push_str(t);
                                    sink.emit(StreamEvent::Text(t.to_string()));
                                }
                            }
                            "thinking_delta" => {
                                let t = d["thinking"].as_str().unwrap_or("");
                                self.partial = true;
                                self.reasoning.push_str(t);
                                sink.emit(StreamEvent::Reasoning(t.to_string()));
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
            "assistant" => {
                for block in v["message"]["content"].as_array().into_iter().flatten() {
                    match block["type"].as_str().unwrap_or("") {
                        "text" if !self.partial => {
                            let t = block["text"].as_str().unwrap_or("");
                            if self.shown_text {
                                sink.emit(StreamEvent::Text("\n\n".into()));
                            }
                            self.shown_text = !t.is_empty();
                            self.last_text = t.to_string();
                            sink.emit(StreamEvent::Text(t.to_string()));
                        }
                        "thinking" if !self.partial => {
                            let t = block["thinking"].as_str().unwrap_or("");
                            self.reasoning.push_str(t);
                            sink.emit(StreamEvent::Reasoning(t.to_string()));
                        }
                        "tool_use" => sink.emit(StreamEvent::ToolStart {
                            id: block["id"].as_str().unwrap_or("").to_string(),
                            name: block["name"].as_str().unwrap_or("").to_string(),
                        }),
                        _ => {}
                    }
                }
            }
            "result" => {
                let text = v["result"].as_str().unwrap_or("").to_string();
                if v["is_error"].as_bool().unwrap_or(false)
                    || v["subtype"]
                        .as_str()
                        .is_some_and(|s| s.starts_with("error"))
                {
                    self.error = Some(if text.is_empty() {
                        v["subtype"].as_str().unwrap_or("error").to_string()
                    } else {
                        text
                    });
                } else {
                    self.result = Some(text);
                }
                let u = &v["usage"];
                let n = |k: &str| u[k].as_u64().unwrap_or(0);
                self.usage = Usage {
                    input_tokens: n("input_tokens"),
                    output_tokens: n("output_tokens"),
                    cache_read_tokens: n("cache_read_input_tokens"),
                    cache_write_tokens: n("cache_creation_input_tokens"),
                    reasoning_tokens: 0,
                    // `total_cost_usd` is an estimate at API prices, even on
                    // a subscription: not a real cost.
                    reported_cost_usd: None,
                };
                if let Some(m) = v["modelUsage"]
                    .as_object()
                    .and_then(|o| o.keys().next().cloned())
                {
                    self.model = Some(m);
                }
            }
            _ => {}
        }
    }

    /// The final answer: the `result`, or the last text seen.
    pub(crate) fn reply(&self) -> String {
        self.result
            .clone()
            .filter(|r| !r.trim().is_empty())
            .unwrap_or_else(|| self.last_text.clone())
    }
}

/// Error for a failed run, from what it said.
fn failure(key: &str, raw: &str) -> AiError {
    if cli::looks_logged_out(raw) {
        AiError::NotLoggedIn {
            provider: key.to_string(),
            message: "run \"claude\" (or \"claude auth login\") in a terminal to sign in".into(),
        }
    } else if cli::looks_outdated(raw) {
        AiError::Process {
            provider: key.to_string(),
            message: "the installed Claude Code is old or incompatible: update it (claude update)"
                .into(),
        }
    } else {
        AiError::Process {
            provider: key.to_string(),
            message: cli::last_line(raw),
        }
    }
}

#[async_trait]
impl ExternalAgent for ClaudeCode {
    fn key(&self) -> &str {
        &self.key
    }

    fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }

    fn uses_tools(&self) -> bool {
        true
    }

    async fn run(
        &self,
        req: ExternalRun<'_>,
        sink: &dyn EventSink,
    ) -> Result<ExternalResult, AiError> {
        let binary = cli::require_binary(&self.key, &self.command, self.path_env.as_deref())?;
        let workdir = Workdir::new(&self.key)?;
        let mcp_config = match &req.mcp {
            Some((url, token)) => Some(
                workdir
                    .write_private(
                        "mcp.json",
                        &cli::mcp_servers_json(url, token, "url").to_string(),
                    )
                    .map_err(|e| AiError::Process {
                        provider: self.key.clone(),
                        message: e.to_string(),
                    })?,
            ),
            None => None,
        };
        let args = self.arguments(req.system, mcp_config.as_deref(), req.effort);
        let prompt = cli::conversation_prompt(req.messages, req.mcp.is_some());

        let mut cmd = Command::new(&binary);
        cmd.args(&args)
            .current_dir(workdir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(path) = &self.path_env {
            cmd.env("PATH", path);
        }
        // A tool may wait for the user's approval (up to 30 minutes).
        cmd.env("MCP_TOOL_TIMEOUT", "3600000");
        cli::hide_window(&mut cmd);
        let mut child = cmd.spawn().map_err(|e| AiError::Process {
            provider: self.key.clone(),
            message: format!("could not launch Claude Code: {e}"),
        })?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(prompt.as_bytes()).await.ok();
            drop(stdin);
        }
        let stdout = child.stdout.take().expect("stdout");
        let stderr = cli::collect(child.stderr.take().expect("stderr"));

        let mut stream = ClaudeStream::default();
        let mut lines = BufReader::new(stdout).lines();
        let deadline = tokio::time::Instant::now() + self.timeout;
        loop {
            let line = tokio::select! {
                _ = req.cancel.cancelled() => {
                    let _ = child.kill().await;
                    return Err(AiError::Cancelled);
                }
                _ = tokio::time::sleep_until(deadline) => {
                    let _ = child.kill().await;
                    return Err(AiError::Timeout(self.key.clone()));
                }
                l = lines.next_line() => l,
            };
            let Ok(Some(line)) = line else { break };
            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                stream.on_event(&v, sink);
            }
        }
        let status = child.wait().await.map_err(|e| AiError::Process {
            provider: self.key.clone(),
            message: e.to_string(),
        })?;
        let stderr = stderr.await.unwrap_or_default();
        if let Some(e) = &stream.error {
            tracing::warn!(provider = %self.key, error = %e, stderr = %stderr, "Claude Code failed");
            return Err(failure(&self.key, &format!("{e}\n{stderr}")));
        }
        let reply = stream.reply();
        if !status.success() || (stream.result.is_none() && reply.trim().is_empty()) {
            tracing::warn!(provider = %self.key, stderr = %stderr, "Claude Code failed");
            return Err(failure(&self.key, &stderr));
        }
        Ok(ExternalResult {
            text: reply,
            reasoning: (!stream.reasoning.is_empty()).then(|| stream.reasoning.clone()),
            usage: stream.usage.clone(),
            model: stream
                .model
                .clone()
                .or_else(|| self.model.clone())
                .unwrap_or_else(|| "claude-code".into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use parking_lot::Mutex;

    use super::*;

    #[derive(Default)]
    struct Collect(Mutex<Vec<StreamEvent>>);

    impl EventSink for Collect {
        fn emit(&self, ev: StreamEvent) {
            self.0.lock().push(ev);
        }
    }

    impl Collect {
        fn text(&self) -> String {
            self.0
                .lock()
                .iter()
                .filter_map(|e| match e {
                    StreamEvent::Text(t) => Some(t.clone()),
                    _ => None,
                })
                .collect()
        }
    }

    fn run(fixture: &str) -> (ClaudeStream, Collect) {
        let sink = Collect::default();
        let mut s = ClaudeStream::default();
        for line in fixture.lines().filter(|l| !l.trim().is_empty()) {
            s.on_event(&serde_json::from_str(line).unwrap(), &sink);
        }
        (s, sink)
    }

    /// Recorded shape of `claude -p --output-format stream-json --verbose
    /// --include-partial-messages` with an MCP tool call in between.
    const PARTIAL: &str = r#"
{"type":"system","subtype":"init","session_id":"s1","model":"claude-sonnet-5","tools":["mcp__termoak__read_terminal"],"mcp_servers":[{"name":"termoak","status":"connected"}]}
{"type":"stream_event","event":{"type":"message_start","message":{"id":"m1"}}}
{"type":"stream_event","event":{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"Look at the screen."}}}
{"type":"stream_event","event":{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Let me "}}}
{"type":"stream_event","event":{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"check."}}}
{"type":"assistant","message":{"id":"m1","content":[{"type":"text","text":"Let me check."},{"type":"tool_use","id":"tu1","name":"mcp__termoak__read_terminal","input":{"session_id":"x"}}]}}
{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"tu1","content":"nginx: failed"}]}}
{"type":"stream_event","event":{"type":"message_start","message":{"id":"m2"}}}
{"type":"stream_event","event":{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Nginx failed."}}}
{"type":"assistant","message":{"id":"m2","content":[{"type":"text","text":"Nginx failed."}]}}
{"type":"result","subtype":"success","is_error":false,"result":"Nginx failed.","total_cost_usd":0.0123,"usage":{"input_tokens":120,"output_tokens":40,"cache_read_input_tokens":900,"cache_creation_input_tokens":30},"modelUsage":{"claude-sonnet-5":{}}}
"#;

    #[test]
    fn partial_stream_is_parsed_once() {
        let (s, sink) = run(PARTIAL);
        assert_eq!(sink.text(), "Let me check.\n\nNginx failed.");
        assert_eq!(s.reply(), "Nginx failed.");
        assert_eq!(s.reasoning, "Look at the screen.");
        assert_eq!(s.usage.input_tokens, 120);
        assert_eq!(s.usage.output_tokens, 40);
        assert_eq!(s.usage.cache_read_tokens, 900);
        assert_eq!(s.usage.cache_write_tokens, 30);
        assert_eq!(s.usage.reported_cost_usd, None);
        assert_eq!(s.model.as_deref(), Some("claude-sonnet-5"));
        assert!(
            sink.0
                .lock()
                .iter()
                .any(|e| matches!(e, StreamEvent::ToolStart { name, .. } if name == "mcp__termoak__read_terminal"))
        );
        assert!(s.error.is_none());
    }

    #[test]
    fn complete_messages_without_partials() {
        let (s, sink) = run(r#"
{"type":"assistant","message":{"content":[{"type":"text","text":"One."}]}}
{"type":"assistant","message":{"content":[{"type":"text","text":"Two."}]}}
{"type":"result","subtype":"success","is_error":false,"result":"Two.","usage":{}}
"#);
        assert_eq!(sink.text(), "One.\n\nTwo.");
        assert_eq!(s.reply(), "Two.");
    }

    #[test]
    fn errors_and_missing_tools() {
        let (s, sink) = run(r#"
{"type":"system","subtype":"init","mcp_servers":[{"name":"termoak","status":"failed"}]}
{"type":"result","subtype":"success","is_error":true,"result":"Invalid API key · Please run /login"}
"#);
        assert!(
            sink.0
                .lock()
                .iter()
                .any(|e| matches!(e, StreamEvent::Notice(m) if m.contains("failed")))
        );
        let e = failure("claude-code", s.error.as_deref().unwrap());
        assert_eq!(e.code(), "not_logged_in");
        let (s, _) = run(r#"{"type":"result","subtype":"error_max_turns","is_error":true}"#);
        assert_eq!(s.error.as_deref(), Some("error_max_turns"));
    }

    /// A fake `claude` that answers with the token it found in the MCP
    /// configuration and checks that the prompt came through stdin.
    #[cfg(unix)]
    #[tokio::test]
    async fn runs_a_fake_claude_with_the_mcp_config() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("termoak-fake-claude-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("claude");
        std::fs::write(
            &script,
            r#"#!/bin/sh
cfg=""
while [ $# -gt 0 ]; do
  if [ "$1" = "--mcp-config" ]; then cfg="$2"; fi
  shift
done
prompt=$(cat)
case "$prompt" in *"why is nginx down"*) ;; *) echo "no prompt" >&2; exit 3;; esac
case "$prompt" in *"logout"*) printf '{"type":"result","subtype":"success","is_error":true,"result":"Not logged in · Please run /login"}\n'; exit 1;; esac
tok=$(grep -o 'Bearer [A-Za-z0-9_]*' "$cfg")
printf '{"type":"assistant","message":{"content":[{"type":"text","text":"working"}]}}\n'
printf '{"type":"result","subtype":"success","is_error":false,"result":"%s","usage":{"input_tokens":5,"output_tokens":2}}\n' "$tok"
"#,
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cfg = ProviderConfig {
            command: Some(script.display().to_string()),
            ..Default::default()
        };
        let agent = ClaudeCode::new("claude-code", &cfg, None);
        let cancel = tokio_util::sync::CancellationToken::new();
        let sink = Collect::default();
        let msgs = vec![crate::message::Message::user_text("why is nginx down?")];
        let run = |msgs| ExternalRun {
            system: "SYS",
            messages: msgs,
            mcp: Some(("http://127.0.0.1:1/mcp".into(), "tok_123".into())),
            effort: None,
            cancel: &cancel,
        };
        let r = agent.run(run(&msgs), &sink).await.unwrap();
        assert_eq!(r.text, "Bearer tok_123");
        assert_eq!(r.usage.input_tokens, 5);
        assert!(sink.text().contains("working"));

        let msgs = vec![crate::message::Message::user_text(
            "why is nginx down? logout",
        )];
        let e = agent.run(run(&msgs), &sink).await.unwrap_err();
        assert_eq!(e.code(), "not_logged_in");

        let missing = ClaudeCode::new(
            "claude-code",
            &ProviderConfig {
                command: Some(dir.join("nope").display().to_string()),
                ..Default::default()
            },
            None,
        );
        let e = missing.run(run(&msgs), &sink).await.unwrap_err();
        assert_eq!(e.code(), "not_installed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn arguments_lock_it_to_termoak_tools() {
        let c = ClaudeCode::new(
            "claude-code",
            &ProviderConfig::default(),
            Some("sonnet".into()),
        );
        let args = c.arguments("SYS", Some(Path::new("/tmp/w/mcp.json")), Some("high"));
        let pos = |a: &str| args.iter().position(|x| x == a).unwrap();
        assert_eq!(args[0], "-p");
        assert_eq!(args[pos("--output-format") + 1], "stream-json");
        assert_eq!(args[pos("--tools") + 1], "");
        assert_eq!(args[pos("--permission-mode") + 1], "dontAsk");
        assert!(args.contains(&"--strict-mcp-config".to_string()));
        assert_eq!(args[pos("--mcp-config") + 1], "/tmp/w/mcp.json");
        assert_eq!(args[pos("--allowedTools") + 1], "mcp__termoak");
        assert_eq!(args[pos("--system-prompt") + 1], "SYS");
        assert_eq!(args[pos("--model") + 1], "sonnet");
        assert_eq!(args[pos("--effort") + 1], "high");
        assert!(!args.iter().any(|a| a.contains("dangerously")));
        // Without tools: no MCP at all.
        let args = c.arguments("", None, None);
        assert!(!args.contains(&"--mcp-config".to_string()));
        assert!(args.contains(&"--strict-mcp-config".to_string()));
    }
}

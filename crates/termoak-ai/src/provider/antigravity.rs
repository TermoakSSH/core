//! Google Antigravity (`agy -p`), headless, with the user's own sign-in.
//!
//! - `agy` prints nothing when its output is not a terminal (it checks
//!   `isatty()`), so it runs under a pseudo-terminal (feature `pty`) and the
//!   terminal decoration (`\r`, colors, spinners) is removed from each line
//!   before reading it as JSON. See github.com/rhishi99/agy-headless-bridge.
//! - Output: `--output-format stream-json`, one JSON event per line (`init`,
//!   `message` deltas, `tool_use`, `tool_result`, `error` and a final
//!   `result` with the answer and the token counts). The reader is tolerant:
//!   it also takes the field names other agents use.
//! - Tools: Termoak's, from the workspace MCP configuration
//!   (`.agents/mcp_config.json` in a private temporary directory, with the
//!   run's token). `agy` has no flag to restrict its built-in tools, so it
//!   runs in that empty directory with `--sandbox` (restricted terminal) and
//!   `--dangerously-skip-permissions` (nobody can answer its own prompts in
//!   headless mode; Termoak's tools keep Termoak's approvals).

use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;

use super::cli::{self, Workdir};
use super::{EventSink, ExternalAgent, ExternalResult, ExternalRun, StreamEvent};
use crate::config::ProviderConfig;
use crate::error::AiError;
use crate::message::Usage;

/// Longest prompt passed on the command line (the conversation keeps its end).
const MAX_PROMPT: usize = 24_000;

pub struct Antigravity {
    key: String,
    model: Option<String>,
    command: String,
    path_env: Option<String>,
    timeout: Duration,
    effort: Option<String>,
}

impl Antigravity {
    pub fn new(key: &str, cfg: &ProviderConfig, model: Option<String>) -> Self {
        Self {
            key: key.to_string(),
            model,
            command: cfg.command.clone().unwrap_or_else(|| "agy".into()),
            path_env: cfg.path_env.clone(),
            timeout: Duration::from_secs(cfg.timeout_secs.unwrap_or(1800)),
            effort: cfg.effort.clone(),
        }
    }

    /// Arguments of `agy` (the prompt is the value of `-p`).
    pub fn arguments(&self, prompt: &str, effort: Option<&str>) -> Vec<String> {
        let mut args: Vec<String> = vec![
            "-p".into(),
            prompt.to_string(),
            "--output-format".into(),
            "stream-json".into(),
            "--sandbox".into(),
            "--dangerously-skip-permissions".into(),
            "--disable-slash-commands".into(),
            "--print-timeout".into(),
            format!("{}m", self.timeout.as_secs().div_ceil(60).max(1)),
        ];
        if let Some(model) = &self.model {
            args.extend(["--model".into(), model.clone()]);
        }
        // `agy` knows low, medium and high.
        if let Some(effort) = effort.map(str::to_string).or_else(|| self.effort.clone()) {
            let effort = match effort.as_str() {
                "low" | "medium" => effort,
                _ => "high".into(),
            };
            args.extend(["--effort".into(), effort]);
        }
        args
    }
}

/// The prompt, keeping its end if it is too long for the command line.
fn bounded(prompt: String) -> String {
    let n = prompt.chars().count();
    if n <= MAX_PROMPT {
        return prompt;
    }
    let tail: String = prompt.chars().skip(n - MAX_PROMPT).collect();
    format!("[… earlier conversation omitted …]\n{tail}")
}

/// What a run of `agy` produced, built from its events.
#[derive(Debug, Default)]
pub(crate) struct AgyStream {
    text: String,
    shown_text: bool,
    pub(crate) reasoning: String,
    pub(crate) result: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) usage: Usage,
    pub(crate) model: Option<String>,
    /// Lines that were not JSON (to explain a failure).
    pub(crate) noise: String,
}

fn text_of(v: &Value) -> Option<&str> {
    ["content", "text", "delta", "response"]
        .iter()
        .find_map(|k| v[*k].as_str())
}

impl AgyStream {
    pub(crate) fn on_line(&mut self, line: &str, sink: &dyn EventSink) {
        match cli::json_line(line) {
            Some(v) => self.on_event(&v, sink),
            None => {
                let clean = termoak_ssh::ansi::strip(line);
                let clean = clean.trim();
                if !clean.is_empty() && self.noise.len() < 4000 {
                    self.noise.push_str(clean);
                    self.noise.push('\n');
                }
            }
        }
    }

    pub(crate) fn on_event(&mut self, v: &Value, sink: &dyn EventSink) {
        match v["type"].as_str().unwrap_or("") {
            "init" => {
                if let Some(m) = v["model"].as_str() {
                    self.model = Some(m.to_string());
                }
            }
            "message" | "text" | "assistant" => {
                if v["role"].as_str().is_some_and(|r| r != "assistant") {
                    return;
                }
                let Some(t) = text_of(v) else { return };
                let delta = v["delta"].as_bool().unwrap_or(v["type"] == "text");
                if !delta && self.shown_text {
                    // A complete message after others.
                    sink.emit(StreamEvent::Text("\n\n".into()));
                    self.text.push_str("\n\n");
                }
                if !t.is_empty() {
                    self.shown_text = true;
                    self.text.push_str(t);
                    sink.emit(StreamEvent::Text(t.to_string()));
                }
            }
            "thought" | "thinking" | "reasoning" => {
                if let Some(t) = text_of(v).or_else(|| v["thought"].as_str()) {
                    self.reasoning.push_str(t);
                    sink.emit(StreamEvent::Reasoning(t.to_string()));
                }
            }
            "tool_use" | "tool_call" => sink.emit(StreamEvent::ToolStart {
                id: v["tool_id"]
                    .as_str()
                    .or_else(|| v["id"].as_str())
                    .unwrap_or("")
                    .to_string(),
                name: v["tool_name"]
                    .as_str()
                    .or_else(|| v["name"].as_str())
                    .unwrap_or("")
                    .to_string(),
            }),
            "error" => {
                let msg = v["message"]
                    .as_str()
                    .or_else(|| v["error"]["message"].as_str())
                    .or_else(|| v["error"].as_str())
                    .unwrap_or("error")
                    .to_string();
                if v["severity"].as_str().is_some_and(|s| s != "error") {
                    sink.emit(StreamEvent::Notice(msg));
                } else {
                    self.error = Some(msg);
                }
            }
            "result" => {
                let failed = v["status"].as_str().is_some_and(|s| s != "success")
                    || v["is_error"].as_bool().unwrap_or(false)
                    || v["subtype"]
                        .as_str()
                        .is_some_and(|s| s.starts_with("error"));
                if failed {
                    self.error = Some(
                        v["error"]["message"]
                            .as_str()
                            .or_else(|| v["error"].as_str())
                            .or_else(|| v["result"].as_str())
                            .unwrap_or("error")
                            .to_string(),
                    );
                } else if let Some(t) = ["response", "result", "text", "content"]
                    .iter()
                    .find_map(|k| v[*k].as_str())
                {
                    self.result = Some(t.to_string());
                } else {
                    self.result = Some(String::new());
                }
                let stats = if v["stats"].is_object() {
                    &v["stats"]
                } else {
                    &v["usage"]
                };
                let n = |keys: &[&str]| keys.iter().find_map(|k| stats[*k].as_u64()).unwrap_or(0);
                self.usage = Usage {
                    input_tokens: n(&["input_tokens", "prompt_tokens"]),
                    output_tokens: n(&["output_tokens", "candidates_tokens"]),
                    cache_read_tokens: n(&["cache_read_tokens", "cached", "cached_tokens"]),
                    cache_write_tokens: 0,
                    reasoning_tokens: n(&["thinking_tokens", "thoughts_tokens"]),
                    reported_cost_usd: None,
                };
            }
            _ => {}
        }
    }

    /// The final answer: the `result`, or the text seen.
    pub(crate) fn reply(&self) -> String {
        self.result
            .clone()
            .filter(|r| !r.trim().is_empty())
            .unwrap_or_else(|| self.text.clone())
    }
}

/// Error for a failed run, from what it said.
fn failure(key: &str, raw: &str) -> AiError {
    let l = raw.to_lowercase();
    if cli::looks_logged_out(raw) || l.contains("sign in with google") {
        AiError::NotLoggedIn {
            provider: key.to_string(),
            message: "run \"agy\" in a terminal once to sign in".into(),
        }
    } else if l.contains("quota") || l.contains("resource_exhausted") || l.contains("429") {
        AiError::Process {
            provider: key.to_string(),
            message: "Antigravity has reached its usage quota".into(),
        }
    } else if cli::looks_outdated(raw) {
        AiError::Process {
            provider: key.to_string(),
            message: "the installed Antigravity CLI is old or incompatible: update it".into(),
        }
    } else {
        AiError::Process {
            provider: key.to_string(),
            message: cli::last_line(raw),
        }
    }
}

/// How the run ended.
enum Exit {
    Done,
    Cancelled,
    TimedOut,
}

#[async_trait]
impl ExternalAgent for Antigravity {
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
        if let Some((url, token)) = &req.mcp {
            workdir
                .write_private(
                    ".agents/mcp_config.json",
                    &cli::mcp_servers_json(url, token, "serverUrl").to_string(),
                )
                .map_err(|e| AiError::Process {
                    provider: self.key.clone(),
                    message: e.to_string(),
                })?;
        }
        let prompt = bounded(cli::agent_prompt(
            req.system,
            req.messages,
            req.mcp.is_some(),
        ));
        let args = self.arguments(&prompt, req.effort);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let handle =
            spawn(&binary, &args, workdir.path(), self.path_env.as_deref(), tx).map_err(|e| {
                AiError::Process {
                    provider: self.key.clone(),
                    message: format!("could not launch Antigravity: {e}"),
                }
            })?;

        let mut stream = AgyStream::default();
        let deadline = tokio::time::Instant::now() + self.timeout;
        let exit = loop {
            tokio::select! {
                _ = req.cancel.cancelled() => break Exit::Cancelled,
                _ = tokio::time::sleep_until(deadline) => break Exit::TimedOut,
                line = rx.recv() => match line {
                    Some(line) => stream.on_line(&line, sink),
                    None => break Exit::Done,
                },
            }
        };
        let success = match exit {
            Exit::Cancelled => {
                handle.kill();
                return Err(AiError::Cancelled);
            }
            Exit::TimedOut => {
                handle.kill();
                return Err(AiError::Timeout(self.key.clone()));
            }
            Exit::Done => handle.wait().await,
        };
        if let Some(e) = &stream.error {
            return Err(failure(&self.key, &format!("{e}\n{}", stream.noise)));
        }
        let reply = stream.reply();
        if reply.trim().is_empty() {
            tracing::warn!(provider = %self.key, output = %stream.noise, success, "Antigravity gave no answer");
            return Err(failure(
                &self.key,
                if stream.noise.trim().is_empty() {
                    "it gave no answer"
                } else {
                    &stream.noise
                },
            ));
        }
        Ok(ExternalResult {
            text: reply,
            reasoning: (!stream.reasoning.is_empty()).then(|| stream.reasoning.clone()),
            usage: stream.usage.clone(),
            model: stream
                .model
                .clone()
                .or_else(|| self.model.clone())
                .unwrap_or_else(|| "antigravity".into()),
        })
    }
}

/// A running `agy`: its lines arrive through the channel (closed at the end).
struct Running {
    kill: Box<dyn Fn() + Send + Sync>,
    done: tokio::sync::oneshot::Receiver<bool>,
}

impl Running {
    fn kill(self) {
        (self.kill)();
    }

    async fn wait(self) -> bool {
        self.done.await.unwrap_or(false)
    }
}

/// Splits the output in lines and sends them.
fn pump(mut reader: impl std::io::Read, tx: tokio::sync::mpsc::UnboundedSender<String>) {
    let mut pending: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                pending.extend_from_slice(&buf[..n]);
                while let Some(pos) = pending.iter().position(|b| *b == b'\n') {
                    let line: Vec<u8> = pending.drain(..=pos).collect();
                    if tx
                        .send(String::from_utf8_lossy(&line).into_owned())
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
    }
    if !pending.is_empty() {
        let _ = tx.send(String::from_utf8_lossy(&pending).into_owned());
    }
}

/// Starts `agy` under a pseudo-terminal.
#[cfg(feature = "pty")]
fn spawn(
    binary: &Path,
    args: &[String],
    cwd: &Path,
    path_env: Option<&str>,
    tx: tokio::sync::mpsc::UnboundedSender<String>,
) -> std::io::Result<Running> {
    use portable_pty::{CommandBuilder, PtySize, native_pty_system};
    fn io(e: impl std::fmt::Display) -> std::io::Error {
        std::io::Error::other(e.to_string())
    }
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 50,
            // Wide, so nothing is wrapped.
            cols: 4000,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(io)?;
    let mut cmd = CommandBuilder::new(binary);
    cmd.args(args);
    cmd.cwd(cwd);
    cmd.env("NO_COLOR", "1");
    cmd.env("TERM", "xterm");
    if let Some(p) = path_env {
        cmd.env("PATH", p);
    }
    let mut child = pair.slave.spawn_command(cmd).map_err(io)?;
    // Without the other end here, reading ends when `agy` exits.
    drop(pair.slave);
    let reader = pair.master.try_clone_reader().map_err(io)?;
    let killer = std::sync::Mutex::new(child.clone_killer());
    let (done_tx, done) = tokio::sync::oneshot::channel();
    let master = pair.master;
    std::thread::spawn(move || {
        pump(reader, tx);
        let ok = child.wait().map(|s| s.success()).unwrap_or(false);
        drop(master);
        let _ = done_tx.send(ok);
    });
    Ok(Running {
        kill: Box::new(move || {
            if let Ok(mut k) = killer.lock() {
                let _ = k.kill();
            }
        }),
        done,
    })
}

/// Without the `pty` feature: plain pipes (`agy` may print nothing).
#[cfg(not(feature = "pty"))]
fn spawn(
    binary: &Path,
    args: &[String],
    cwd: &Path,
    path_env: Option<&str>,
    tx: tokio::sync::mpsc::UnboundedSender<String>,
) -> std::io::Result<Running> {
    use std::process::{Command, Stdio};
    let mut cmd = Command::new(binary);
    cmd.args(args)
        .current_dir(cwd)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(p) = path_env {
        cmd.env("PATH", p);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let mut child = cmd.spawn()?;
    let stdout = child.stdout.take().expect("stdout");
    let stderr = child.stderr.take().expect("stderr");
    let tx2 = tx.clone();
    std::thread::spawn(move || pump(stderr, tx2));
    let child = std::sync::Arc::new(std::sync::Mutex::new(child));
    let (done_tx, done) = tokio::sync::oneshot::channel();
    let waiter = child.clone();
    std::thread::spawn(move || {
        pump(stdout, tx);
        let ok = loop {
            match waiter.lock().map(|mut c| c.try_wait()) {
                Ok(Ok(Some(s))) => break s.success(),
                Ok(Ok(None)) => std::thread::sleep(Duration::from_millis(50)),
                _ => break false,
            }
        };
        let _ = done_tx.send(ok);
    });
    Ok(Running {
        kill: Box::new(move || {
            if let Ok(mut c) = child.lock() {
                let _ = c.kill();
            }
        }),
        done,
    })
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

    fn run(fixture: &str) -> (AgyStream, String) {
        let sink = Collect::default();
        let mut s = AgyStream::default();
        for line in fixture.split_inclusive('\n') {
            s.on_line(line, &sink);
        }
        let text = sink
            .0
            .lock()
            .iter()
            .filter_map(|e| match e {
                StreamEvent::Text(t) => Some(t.clone()),
                _ => None,
            })
            .collect();
        (s, text)
    }

    /// What arrives through the pseudo-terminal: `\r\n` line ends, colors
    /// and a spinner before the JSON events.
    const PTY: &str = "\u{1b}[?25l⠋ Connecting…\r\n\
{\"type\":\"init\",\"session_id\":\"c1\",\"model\":\"gemini-3-pro\"}\r\n\
{\"type\":\"message\",\"role\":\"user\",\"content\":\"why?\"}\r\n\
{\"type\":\"tool_use\",\"tool_name\":\"termoak.read_terminal\",\"tool_id\":\"t1\",\"parameters\":{}}\r\n\
{\"type\":\"tool_result\",\"tool_id\":\"t1\",\"status\":\"success\",\"output\":\"502\"}\r\n\
\u{1b}[0m{\"type\":\"message\",\"role\":\"assistant\",\"content\":\"Nginx \",\"delta\":true}\r\n\
{\"type\":\"message\",\"role\":\"assistant\",\"content\":\"is down.\",\"delta\":true}\r\n\
{\"type\":\"result\",\"status\":\"success\",\"stats\":{\"input_tokens\":300,\"output_tokens\":20,\"thinking_tokens\":7,\"cache_read_tokens\":100}}\r\n";

    #[test]
    fn pty_stream_is_parsed() {
        let (s, text) = run(PTY);
        assert_eq!(text, "Nginx is down.");
        assert_eq!(s.reply(), "Nginx is down.");
        assert_eq!(s.model.as_deref(), Some("gemini-3-pro"));
        assert_eq!(s.usage.input_tokens, 300);
        assert_eq!(s.usage.output_tokens, 20);
        assert_eq!(s.usage.reasoning_tokens, 7);
        assert_eq!(s.usage.cache_read_tokens, 100);
        assert!(s.error.is_none());
        assert!(s.noise.contains("Connecting"));
    }

    #[test]
    fn final_response_wins_and_errors_are_reported() {
        let (s, _) = run("{\"type\":\"result\",\"status\":\"success\",\"response\":\"Done.\"}\n");
        assert_eq!(s.reply(), "Done.");
        let (s, _) = run(
            "{\"type\":\"error\",\"severity\":\"warning\",\"message\":\"slow\"}\n\
             {\"type\":\"result\",\"status\":\"error\",\"error\":{\"message\":\"Please sign in\"}}\n",
        );
        let e = failure("agy", s.error.as_deref().unwrap());
        assert_eq!(e.code(), "not_logged_in");
        assert_eq!(
            failure("agy", "RESOURCE_EXHAUSTED: quota").to_string(),
            "\"agy\" failed: Antigravity has reached its usage quota"
        );
    }

    /// A fake `agy` that, like the real one, prints nothing unless its
    /// output is a terminal, and says whether it found the MCP config.
    #[cfg(all(unix, feature = "pty"))]
    #[tokio::test]
    async fn runs_a_fake_agy_under_a_pty() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("termoak-fake-agy-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("agy");
        std::fs::write(
            &script,
            r#"#!/bin/sh
[ -t 1 ] || exit 0
mcp=no
grep -q 'Bearer tok_9' .agents/mcp_config.json 2>/dev/null && mcp=yes
printf '\033[32m⠋ starting\033[0m\n'
printf '{"type":"init","model":"fake-model"}\n'
printf '{"type":"message","role":"assistant","content":"tty ok, mcp %s","delta":true}\n' "$mcp"
printf '{"type":"result","status":"success","stats":{"input_tokens":3,"output_tokens":4}}\n'
"#,
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cfg = ProviderConfig {
            command: Some(script.display().to_string()),
            ..Default::default()
        };
        let agent = Antigravity::new("agy", &cfg, None);
        let cancel = tokio_util::sync::CancellationToken::new();
        let sink = Collect::default();
        let msgs = vec![crate::message::Message::user_text("hello")];
        let r = agent
            .run(
                ExternalRun {
                    system: "SYS",
                    messages: &msgs,
                    mcp: Some(("http://127.0.0.1:1/mcp".into(), "tok_9".into())),
                    effort: None,
                    cancel: &cancel,
                },
                &sink,
            )
            .await
            .unwrap();
        assert_eq!(r.text, "tty ok, mcp yes");
        assert_eq!(r.model, "fake-model");
        assert_eq!(r.usage.output_tokens, 4);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn arguments_and_long_prompts() {
        let a = Antigravity::new(
            "agy",
            &ProviderConfig::default(),
            Some("gemini-3-pro".into()),
        );
        let args = a.arguments("hi", Some("max"));
        let pos = |x: &str| args.iter().position(|a| a == x).unwrap();
        assert_eq!(args[pos("-p") + 1], "hi");
        assert_eq!(args[pos("--output-format") + 1], "stream-json");
        assert!(args.contains(&"--sandbox".to_string()));
        assert_eq!(args[pos("--print-timeout") + 1], "30m");
        assert_eq!(args[pos("--model") + 1], "gemini-3-pro");
        assert_eq!(args[pos("--effort") + 1], "high");
        let long = bounded("x".repeat(MAX_PROMPT + 10));
        assert!(long.starts_with("[… earlier conversation omitted …]"));
        assert!(long.chars().count() < MAX_PROMPT + 50);
    }
}

//! Agent tools: inventory, commands, files, terminals and memory.
//!
//! The same tools are offered to providers with native tool calls (Claude,
//! OpenAI, OpenCode Go...) and to Codex over MCP. All of them go through
//! [`ToolRuntime::effect`] to decide whether they need approval.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use termoak_core::model::{Group, Host, Memory, Record, SecretUpdate, Snippet};
use termoak_core::store::VaultAccess;
use termoak_core::{Id, Store};
use termoak_ssh::exec::ExecOptions;
use termoak_ssh::{ConnectionPool, FileKind};

use crate::policy::{Effect, is_read_only_command};
use crate::provider::ToolSpec;
use crate::provider::anthropic::INVALID_JSON_KEY;

/// Summary of an open terminal session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub id: Id,
    pub title: String,
    pub host_id: Option<Id>,
    pub status: String,
    pub viewers: usize,
}

/// Access to open terminals (implemented by the server or the desktop app).
#[async_trait]
pub trait SessionAccess: Send + Sync {
    async fn list(&self, owner: Id) -> Vec<SessionSummary>;
    async fn read(&self, owner: Id, session: Id, max_chars: usize) -> Result<String, String>;
    async fn send(&self, owner: Id, session: Id, input: &str) -> Result<(), String>;

    /// Writes and collects the output it produces: until the terminal stays
    /// silent for `quiet`, or at most `max`. `None` if unknown (the screen is
    /// read instead).
    async fn send_and_collect(
        &self,
        owner: Id,
        session: Id,
        input: &str,
        _quiet: Duration,
        _max: Duration,
    ) -> Result<Option<TerminalOutput>, String> {
        self.send(owner, session, input).await?;
        Ok(None)
    }
}

/// Terminal output after writing to it.
#[derive(Debug, Clone)]
pub struct TerminalOutput {
    /// What it printed (plain text).
    pub text: String,
    /// It was still printing when time ran out.
    pub still_running: bool,
}

/// Context of a call.
#[derive(Debug, Clone)]
pub struct ToolContext {
    pub owner: Id,
    pub task_id: Option<Id>,
    /// Whether the task is limited to certain hosts.
    pub host_scope: Option<Vec<Id>>,
}

/// Result of a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOutcome {
    pub ok: bool,
    pub content: String,
}

impl ToolOutcome {
    fn ok(content: impl Into<String>) -> Self {
        Self {
            ok: true,
            content: content.into(),
        }
    }

    fn err(content: impl Into<String>) -> Self {
        Self {
            ok: false,
            content: content.into(),
        }
    }
}

/// Tool limits.
#[derive(Debug, Clone)]
pub struct ToolLimits {
    pub command_timeout: Duration,
    pub max_output_chars: usize,
}

/// Tool runner.
pub struct ToolRuntime {
    store: Store,
    pool: Arc<ConnectionPool>,
    sessions: Option<Arc<dyn SessionAccess>>,
    limits: ToolLimits,
}

// Inputs of each tool (deserialization validates the model's input).

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListHostsIn {
    #[serde(default)]
    query: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunCommandIn {
    host: String,
    command: String,
    #[serde(default)]
    timeout_secs: Option<u64>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadFileIn {
    host: String,
    path: String,
    #[serde(default)]
    max_bytes: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteFileIn {
    host: String,
    path: String,
    content: String,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default = "yes")]
    backup: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListDirIn {
    host: String,
    path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadTerminalIn {
    session_id: String,
    #[serde(default)]
    max_chars: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SendTerminalIn {
    session_id: String,
    input: String,
    #[serde(default = "yes")]
    press_enter: bool,
    #[serde(default)]
    wait_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListSnippetsIn {
    #[serde(default)]
    query: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RememberIn {
    content: String,
    #[serde(default)]
    host: Option<String>,
}

fn parse<T: for<'de> Deserialize<'de>>(input: &Value) -> Result<T, String> {
    if let Some(raw) = input.get(INVALID_JSON_KEY) {
        return Err(json!({ "INVALID_JSON": raw }).to_string());
    }
    serde_json::from_value(input.clone()).map_err(|e| format!("invalid parameters: {e}"))
}

/// Truncates, keeping the beginning and the end.
pub fn truncate_middle(s: &str, max_chars: usize) -> String {
    let count = s.chars().count();
    if count <= max_chars {
        return s.to_string();
    }
    let head = max_chars / 4;
    let tail = max_chars - head;
    let head_str: String = s.chars().take(head).collect();
    let tail_str: String = s.chars().skip(count - tail).collect();
    format!(
        "{head_str}\n[… {} characters omitted …]\n{tail_str}",
        count - head - tail
    )
}

impl ToolRuntime {
    pub fn new(
        store: Store,
        pool: Arc<ConnectionPool>,
        sessions: Option<Arc<dyn SessionAccess>>,
        limits: ToolLimits,
    ) -> Self {
        Self {
            store,
            pool,
            sessions,
            limits,
        }
    }

    /// Definitions offered to the model.
    pub fn specs(&self) -> Vec<ToolSpec> {
        let host_prop = json!({"type": "string", "description": "Host: its id, exact label or address (use list_hosts to see them)."});
        let mut specs = vec![
            ToolSpec {
                name: "list_hosts".into(),
                description: "Lists the user's SSH hosts (id, label, address, user, group, tags, OS). Call it first when you do not know which host to act on.".into(),
                schema: json!({"type": "object", "properties": {"query": {"type": "string", "description": "Optional text filter (label, address, group or tag)."}}, "additionalProperties": false}),
            },
            ToolSpec {
                name: "run_command".into(),
                description: "Runs a non-interactive shell command on a host and returns the exit code, stdout and stderr. Use it to inspect or administer servers. Commands that change anything may require the user's approval. Do not use interactive commands (vim, top without -b, less) or commands that never finish (tail -f).".into(),
                schema: json!({"type": "object", "properties": {
                    "host": host_prop,
                    "command": {"type": "string", "description": "Command to run with sh."},
                    "timeout_secs": {"type": "integer", "description": "Timeout in seconds (default 120, maximum 1800)."},
                    "reason": {"type": "string", "description": "Why you are running it (shown to the user if they have to approve it). Write it in the user's language."}
                }, "required": ["host", "command"], "additionalProperties": false}),
            },
            ToolSpec {
                name: "read_file".into(),
                description: "Reads a text file from a host over SFTP.".into(),
                schema: json!({"type": "object", "properties": {
                    "host": host_prop,
                    "path": {"type": "string", "description": "Absolute path of the file."},
                    "max_bytes": {"type": "integer", "description": "Maximum size to read (default 256 KiB)."}
                }, "required": ["host", "path"], "additionalProperties": false}),
            },
            ToolSpec {
                name: "write_file".into(),
                description: "Writes (creates or replaces) a file on a host over SFTP. By default it keeps a backup of the original. Always requires approval except in autonomous mode.".into(),
                schema: json!({"type": "object", "properties": {
                    "host": host_prop,
                    "path": {"type": "string", "description": "Absolute path."},
                    "content": {"type": "string", "description": "Full file content."},
                    "mode": {"type": "string", "description": "Permissions in octal, e.g. \"644\"."},
                    "backup": {"type": "boolean", "description": "Copy the original to <path>.bak-<date> first (default true)."}
                }, "required": ["host", "path", "content"], "additionalProperties": false}),
            },
            ToolSpec {
                name: "list_directory".into(),
                description: "Lists the contents of a directory on a host (permissions, size, date, name).".into(),
                schema: json!({"type": "object", "properties": {
                    "host": host_prop,
                    "path": {"type": "string", "description": "Directory path."}
                }, "required": ["host", "path"], "additionalProperties": false}),
            },
            ToolSpec {
                name: "list_snippets".into(),
                description: "Lists the user's saved snippets (reusable scripts with {{name}} variables).".into(),
                schema: json!({"type": "object", "properties": {"query": {"type": "string"}}, "additionalProperties": false}),
            },
            ToolSpec {
                name: "remember".into(),
                description: "Saves a durable fact about the user's infrastructure for future tasks (e.g. \"web1 runs nginx with its config in /etc/nginx/sites-enabled\"). Do not save secrets.".into(),
                schema: json!({"type": "object", "properties": {
                    "content": {"type": "string", "description": "The fact, in one sentence (max. 1000 characters)."},
                    "host": {"type": "string", "description": "Host it refers to (optional)."}
                }, "required": ["content"], "additionalProperties": false}),
            },
        ];
        if self.sessions.is_some() {
            specs.extend([
                ToolSpec {
                    name: "list_sessions".into(),
                    description: "Lists the user's open terminals (persistent sessions).".into(),
                    schema: json!({"type": "object", "properties": {}, "additionalProperties": false}),
                },
                ToolSpec {
                    name: "read_terminal".into(),
                    description: "Reads the latest content shown by an open terminal (plain text). Useful when the user asks about an error on their screen.".into(),
                    schema: json!({"type": "object", "properties": {
                        "session_id": {"type": "string"},
                        "max_chars": {"type": "integer", "description": "Default 8000."}
                    }, "required": ["session_id"], "additionalProperties": false}),
                },
                ToolSpec {
                    name: "send_to_terminal".into(),
                    description: "Types into one of the user's open terminals as if typing on the keyboard (the user sees it live) and returns the output it produces. Read-only commands need no approval; everything else does, except in autonomous mode.".into(),
                    schema: json!({"type": "object", "properties": {
                        "session_id": {"type": "string"},
                        "input": {"type": "string", "description": "Text to type (a command, or whatever the running program asks for)."},
                        "press_enter": {"type": "boolean", "description": "Press Enter at the end (default true)."},
                        "wait_secs": {"type": "integer", "description": "Seconds without new output after which the command is considered finished (default 2; raise it for commands that stay silent for a while, such as downloads or builds). The wait is at most 120 s; if it is still running, read it later with read_terminal."}
                    }, "required": ["session_id", "input"], "additionalProperties": false}),
                },
            ]);
        }
        specs
    }

    /// Effect of a call (for the permission policy).
    pub fn effect(name: &str, input: &Value) -> Effect {
        match name {
            "run_command" => match input["command"].as_str() {
                Some(c) if is_read_only_command(c) => Effect::Read,
                _ => Effect::Write,
            },
            // A read-only command typed into the terminal changes nothing.
            "send_to_terminal" => match input["input"].as_str() {
                Some(c)
                    if input["press_enter"].as_bool().unwrap_or(true)
                        && !c.contains('\n')
                        && is_read_only_command(c) =>
                {
                    Effect::Read
                }
                _ => Effect::Write,
            },
            "write_file" => Effect::Write,
            _ => Effect::Read,
        }
    }

    /// Human-readable description of the call (for approvals and auditing).
    pub fn summarize(name: &str, input: &Value) -> String {
        let host = input["host"].as_str().unwrap_or("?");
        match name {
            "run_command" => {
                let mut s = format!("Run on {host}: {}", input["command"].as_str().unwrap_or(""));
                if let Some(r) = input["reason"].as_str().filter(|r| !r.is_empty()) {
                    s.push_str(&format!(" — {r}"));
                }
                s
            }
            "write_file" => format!(
                "Write {} on {host} ({} bytes)",
                input["path"].as_str().unwrap_or(""),
                input["content"].as_str().map(str::len).unwrap_or(0)
            ),
            "read_file" => format!("Read {} on {host}", input["path"].as_str().unwrap_or("")),
            "list_directory" => {
                format!("List {} on {host}", input["path"].as_str().unwrap_or(""))
            }
            "send_to_terminal" => format!(
                "Type into terminal {}: {}",
                input["session_id"].as_str().unwrap_or(""),
                input["input"].as_str().unwrap_or("")
            ),
            "read_terminal" => format!(
                "Read terminal {}",
                input["session_id"].as_str().unwrap_or("")
            ),
            "remember" => format!("Remember: {}", input["content"].as_str().unwrap_or("")),
            other => other.to_string(),
        }
    }

    /// What the caller can reach (every vault they can use).
    async fn access(&self, ctx: &ToolContext) -> Result<std::sync::Arc<VaultAccess>, String> {
        self.store
            .vault_access(ctx.owner)
            .await
            .map_err(|e| e.to_string())
    }

    /// Resolves a host by id, label or address (in any vault the user can
    /// use), honouring the task scope.
    async fn resolve_host(&self, ctx: &ToolContext, reference: &str) -> Result<Host, String> {
        Ok(self.resolve_host_record(ctx, reference).await?.data)
    }

    async fn resolve_host_record(
        &self,
        ctx: &ToolContext,
        reference: &str,
    ) -> Result<Record<Host>, String> {
        let access = self.access(ctx).await?;
        let hosts = self
            .store
            .list_in::<Host>(&access, None)
            .await
            .map_err(|e| e.to_string())?;
        let r = reference.trim();
        let found = r
            .parse::<Id>()
            .ok()
            .and_then(|id| hosts.iter().find(|h| h.data.id == id))
            .or_else(|| hosts.iter().find(|h| h.data.label.eq_ignore_ascii_case(r)))
            .or_else(|| {
                hosts
                    .iter()
                    .find(|h| h.data.address.eq_ignore_ascii_case(r))
            })
            .cloned()
            .ok_or_else(|| format!("there is no host \"{r}\"; use list_hosts"))?;
        if let Some(scope) = &ctx.host_scope
            && !scope.contains(&found.data.id)
        {
            return Err(format!(
                "host \"{}\" is outside the scope of this task",
                found.data.label
            ));
        }
        Ok(found)
    }

    /// Runs a tool.
    pub async fn execute(&self, ctx: &ToolContext, name: &str, input: &Value) -> ToolOutcome {
        let started = Instant::now();
        let result = match name {
            "list_hosts" => self.list_hosts(ctx, input).await,
            "run_command" => self.run_command(ctx, input).await,
            "read_file" => self.read_file(ctx, input).await,
            "write_file" => self.write_file(ctx, input).await,
            "list_directory" => self.list_directory(ctx, input).await,
            "list_snippets" => self.list_snippets(ctx, input).await,
            "remember" => self.remember(ctx, input).await,
            "list_sessions" => self.list_sessions(ctx).await,
            "read_terminal" => self.read_terminal(ctx, input).await,
            "send_to_terminal" => self.send_to_terminal(ctx, input).await,
            other => Err(format!("unknown tool: {other}")),
        };
        let outcome = match result {
            Ok(s) => ToolOutcome::ok(truncate_middle(&s, self.limits.max_output_chars)),
            Err(e) => ToolOutcome::err(truncate_middle(&e, self.limits.max_output_chars)),
        };
        tracing::debug!(
            tool = name,
            ok = outcome.ok,
            ms = started.elapsed().as_millis() as u64,
            "tool executed"
        );
        outcome
    }

    async fn list_hosts(&self, ctx: &ToolContext, input: &Value) -> Result<String, String> {
        let args: ListHostsIn = parse(input)?;
        let access = self.access(ctx).await?;
        let hosts = self
            .store
            .list_in::<Host>(&access, None)
            .await
            .map_err(|e| e.to_string())?;
        let groups = self
            .store
            .list_in::<Group>(&access, None)
            .await
            .map_err(|e| e.to_string())?;
        let group_name = |id: Option<Id>| {
            id.and_then(|g| groups.iter().find(|x| x.data.id == g))
                .map(|g| g.data.name.clone())
        };
        let q = args.query.unwrap_or_default().to_lowercase();
        let mut out = Vec::new();
        for rec in hosts {
            let vault = rec.meta.vault_id.unwrap_or(access.personal());
            let h = rec.data;
            if let Some(scope) = &ctx.host_scope
                && !scope.contains(&h.id)
            {
                continue;
            }
            let settings = self
                .store
                .effective_settings_in(&access, vault, &h)
                .await
                .map_err(|e| e.to_string())?;
            let group = group_name(h.group_id);
            let haystack = format!(
                "{} {} {} {}",
                h.label,
                h.address,
                group.clone().unwrap_or_default(),
                h.tags.join(" ")
            )
            .to_lowercase();
            if !q.is_empty() && !haystack.contains(&q) {
                continue;
            }
            out.push(json!({
                "id": h.id,
                "label": h.label,
                "address": h.address,
                "port": settings.port.unwrap_or(22),
                "user": settings.username,
                "group": group,
                "tags": h.tags,
                "os": h.os,
                "notes": truncate_middle(&h.notes, 300),
                "via_jump": settings.jump_host_ids.map(|j| !j.is_empty()).unwrap_or(false),
                "vault_id": vault,
            }));
        }
        if out.is_empty() {
            return Ok("No matching hosts.".into());
        }
        Ok(serde_json::to_string_pretty(&out).unwrap_or_default())
    }

    async fn run_command(&self, ctx: &ToolContext, input: &Value) -> Result<String, String> {
        let args: RunCommandIn = parse(input)?;
        let _ = args.reason;
        let host = self.resolve_host(ctx, &args.host).await?;
        let timeout = Duration::from_secs(
            args.timeout_secs
                .unwrap_or(self.limits.command_timeout.as_secs())
                .clamp(1, 1800),
        );
        let conn = self
            .pool
            .get(ctx.owner, host.id)
            .await
            .map_err(|e| format!("could not connect to {}: {e}", host.label))?;
        let opts = ExecOptions {
            timeout,
            max_output: 2 * 1024 * 1024,
            ..Default::default()
        };
        let out = match conn.exec(&args.command, &opts).await {
            Ok(o) => o,
            Err(e) => {
                self.pool.invalidate(ctx.owner, host.id).await;
                return Err(format!("error running on {}: {e}", host.label));
            }
        };
        let mut s = format!(
            "host: {} | exit code: {} | duration: {} ms{}{}\n",
            host.label,
            out.exit_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| out.exit_signal.clone().unwrap_or_else(|| "?".into())),
            out.duration_ms,
            if out.timed_out { " | TIMED OUT" } else { "" },
            if out.truncated {
                " | output truncated"
            } else {
                ""
            },
        );
        let stdout = out.stdout_text();
        let stderr = out.stderr_text();
        if !stdout.is_empty() {
            s.push_str("--- stdout ---\n");
            s.push_str(&stdout);
            if !stdout.ends_with('\n') {
                s.push('\n');
            }
        }
        if !stderr.is_empty() {
            s.push_str("--- stderr ---\n");
            s.push_str(&stderr);
        }
        if stdout.is_empty() && stderr.is_empty() {
            s.push_str("(no output)\n");
        }
        if out.success() { Ok(s) } else { Err(s) }
    }

    async fn read_file(&self, ctx: &ToolContext, input: &Value) -> Result<String, String> {
        let args: ReadFileIn = parse(input)?;
        let host = self.resolve_host(ctx, &args.host).await?;
        let conn = self
            .pool
            .get(ctx.owner, host.id)
            .await
            .map_err(|e| e.to_string())?;
        let sftp = conn.sftp().await.map_err(|e| e.to_string())?;
        let max = args
            .max_bytes
            .unwrap_or(256 * 1024)
            .clamp(1, 5 * 1024 * 1024);
        let data = sftp.read(&args.path, max).await.map_err(|e| e.to_string());
        sftp.close().await;
        let data = data?;
        if data.contains(&0) {
            return Ok(format!(
                "{} looks like a binary file ({} bytes); not shown.",
                args.path,
                data.len()
            ));
        }
        Ok(String::from_utf8_lossy(&data).into_owned())
    }

    async fn write_file(&self, ctx: &ToolContext, input: &Value) -> Result<String, String> {
        let args: WriteFileIn = parse(input)?;
        let mode = match &args.mode {
            Some(m) => Some(
                u32::from_str_radix(m.trim_start_matches("0o"), 8)
                    .map_err(|_| format!("invalid mode: {m}"))?,
            ),
            None => None,
        };
        let host = self.resolve_host(ctx, &args.host).await?;
        let conn = self
            .pool
            .get(ctx.owner, host.id)
            .await
            .map_err(|e| e.to_string())?;
        let sftp = conn.sftp().await.map_err(|e| e.to_string())?;
        let mut note = String::new();
        let result = async {
            if args.backup && sftp.exists(&args.path).await.map_err(|e| e.to_string())? {
                let original = sftp
                    .read(&args.path, 20 * 1024 * 1024)
                    .await
                    .map_err(|e| format!("could not read the original for the backup: {e}"))?;
                let backup = format!(
                    "{}.bak-{}",
                    args.path,
                    chrono::Utc::now().format("%Y%m%d%H%M%S")
                );
                let original_mode = sftp.stat(&args.path).await.ok().and_then(|s| s.mode);
                sftp.write(&backup, &original, original_mode)
                    .await
                    .map_err(|e| e.to_string())?;
                note = format!(" (backup at {backup})");
            }
            sftp.write(&args.path, args.content.as_bytes(), mode)
                .await
                .map_err(|e| e.to_string())
        }
        .await;
        sftp.close().await;
        result?;
        Ok(format!(
            "Wrote {} on {} ({} bytes){note}.",
            args.path,
            host.label,
            args.content.len()
        ))
    }

    async fn list_directory(&self, ctx: &ToolContext, input: &Value) -> Result<String, String> {
        let args: ListDirIn = parse(input)?;
        let host = self.resolve_host(ctx, &args.host).await?;
        let conn = self
            .pool
            .get(ctx.owner, host.id)
            .await
            .map_err(|e| e.to_string())?;
        let sftp = conn.sftp().await.map_err(|e| e.to_string())?;
        let entries = sftp.list(&args.path).await.map_err(|e| e.to_string());
        sftp.close().await;
        let entries = entries?;
        let mut s = format!("{} ({} entries)\n", args.path, entries.len());
        for e in entries.iter().take(500) {
            let date = e
                .modified
                .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
                .map(|d| d.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_default();
            s.push_str(&format!(
                "{:10} {:>12} {:16} {}{}\n",
                e.mode_string,
                e.size,
                date,
                e.name,
                if e.kind == FileKind::Dir { "/" } else { "" }
            ));
        }
        if entries.len() > 500 {
            s.push_str(&format!("… and {} more\n", entries.len() - 500));
        }
        Ok(s)
    }

    async fn list_snippets(&self, ctx: &ToolContext, input: &Value) -> Result<String, String> {
        let args: ListSnippetsIn = parse(input)?;
        let q = args.query.unwrap_or_default().to_lowercase();
        let access = self.access(ctx).await?;
        let snippets = self
            .store
            .list_in::<Snippet>(&access, None)
            .await
            .map_err(|e| e.to_string())?;
        let out: Vec<Value> = snippets
            .into_iter()
            .map(|s| s.data)
            .filter(|s| {
                q.is_empty()
                    || format!("{} {} {}", s.name, s.description, s.tags.join(" "))
                        .to_lowercase()
                        .contains(&q)
            })
            .map(|s| {
                json!({
                    "id": s.id,
                    "name": s.name,
                    "description": s.description,
                    "variables": s.variables(),
                    "script": truncate_middle(&s.script, 2000),
                })
            })
            .collect();
        if out.is_empty() {
            return Ok("No matching snippets.".into());
        }
        Ok(serde_json::to_string_pretty(&out).unwrap_or_default())
    }

    /// Saves a memory: into the host's vault when the user is Editor there,
    /// otherwise (or without a host) into their personal vault.
    async fn remember(&self, ctx: &ToolContext, input: &Value) -> Result<String, String> {
        let args: RememberIn = parse(input)?;
        let access = self.access(ctx).await?;
        let host = match args.host.as_deref() {
            Some(h) if !h.trim().is_empty() => Some(self.resolve_host_record(ctx, h).await?),
            _ => None,
        };
        let vault = host
            .as_ref()
            .and_then(|h| h.meta.vault_id)
            .filter(|v| access.role(*v).is_some_and(|r| r.can_write()))
            .unwrap_or(access.personal());
        let existing = self
            .store
            .list_in::<Memory>(&access, None)
            .await
            .map_err(|e| e.to_string())?;
        if existing.iter().any(|m| {
            m.data
                .content
                .trim()
                .eq_ignore_ascii_case(args.content.trim())
        }) {
            return Ok("Already noted.".into());
        }
        // References stay inside a vault: a memory about a host of a vault
        // the user cannot write names the host instead.
        let content = args.content.trim().to_string();
        let (host_id, content) = match &host {
            Some(h) if h.meta.vault_id == Some(vault) => (Some(h.data.id), content),
            Some(h) => (None, format!("{}: {content}", h.data.label)),
            None => (None, content),
        };
        self.store
            .save_in(
                &access,
                vault,
                Memory {
                    id: Id::nil(),
                    content,
                    host_id,
                },
                SecretUpdate::Keep,
                None,
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok("Noted.".into())
    }

    async fn list_sessions(&self, ctx: &ToolContext) -> Result<String, String> {
        let sessions = self.sessions.as_ref().ok_or("no terminal access")?;
        let list = sessions.list(ctx.owner).await;
        if list.is_empty() {
            return Ok("No open terminals.".into());
        }
        Ok(serde_json::to_string_pretty(&list).unwrap_or_default())
    }

    async fn read_terminal(&self, ctx: &ToolContext, input: &Value) -> Result<String, String> {
        let args: ReadTerminalIn = parse(input)?;
        let sessions = self.sessions.as_ref().ok_or("no terminal access")?;
        let id: Id = args
            .session_id
            .parse()
            .map_err(|_| "invalid session id".to_string())?;
        sessions
            .read(
                ctx.owner,
                id,
                args.max_chars.unwrap_or(8000).clamp(100, 50_000),
            )
            .await
    }

    async fn send_to_terminal(&self, ctx: &ToolContext, input: &Value) -> Result<String, String> {
        let args: SendTerminalIn = parse(input)?;
        let sessions = self.sessions.as_ref().ok_or("no terminal access")?;
        let id: Id = args
            .session_id
            .parse()
            .map_err(|_| "invalid session id".to_string())?;
        let mut text = args.input;
        if args.press_enter {
            text.push('\r');
        }
        let quiet = Duration::from_secs(args.wait_secs.unwrap_or(2).clamp(1, 60));
        let collected = sessions
            .send_and_collect(ctx.owner, id, &text, quiet, Duration::from_secs(120))
            .await?;
        match collected {
            Some(out) => {
                let mut s = if out.text.trim().is_empty() {
                    "Sent; the terminal printed nothing.".to_string()
                } else {
                    format!("Output:\n{}", out.text.trim_end())
                };
                if out.still_running {
                    s.push_str("\n\n(Still running: check again with read_terminal.)");
                }
                Ok(s)
            }
            None => {
                // Give the output time to appear.
                tokio::time::sleep(Duration::from_millis(800)).await;
                let screen = sessions.read(ctx.owner, id, 3000).await.unwrap_or_default();
                Ok(format!("Sent. End of the terminal:\n{screen}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typing_read_only_commands_needs_no_approval() {
        let read = |input: Value| ToolRuntime::effect("send_to_terminal", &input);
        assert_eq!(
            read(json!({"session_id": "x", "input": "df -h"})),
            Effect::Read
        );
        assert_eq!(
            read(json!({"session_id": "x", "input": "rm -rf /tmp/x"})),
            Effect::Write
        );
        // Without Enter we cannot know what it will do (it may be half of something else).
        assert_eq!(
            read(json!({"session_id": "x", "input": "ls", "press_enter": false})),
            Effect::Write
        );
        assert_eq!(
            read(json!({"session_id": "x", "input": "ls\nrm x"})),
            Effect::Write
        );
    }

    #[test]
    fn effects() {
        assert_eq!(
            ToolRuntime::effect("run_command", &json!({"command": "df -h"})),
            Effect::Read
        );
        assert_eq!(
            ToolRuntime::effect(
                "run_command",
                &json!({"command": "systemctl restart nginx"})
            ),
            Effect::Write
        );
        assert_eq!(ToolRuntime::effect("write_file", &json!({})), Effect::Write);
        assert_eq!(ToolRuntime::effect("list_hosts", &json!({})), Effect::Read);
    }

    #[test]
    fn invalid_json_is_reported() {
        let err = parse::<RunCommandIn>(&json!({ INVALID_JSON_KEY: "{\"host\": " })).unwrap_err();
        assert!(err.contains("INVALID_JSON"));
        let err = parse::<RunCommandIn>(&json!({"host": "a"})).unwrap_err();
        assert!(err.contains("command"));
        assert!(parse::<RunCommandIn>(&json!({"host": "a", "command": "ls", "extra": 1})).is_err());
    }

    #[test]
    fn truncation() {
        let s = "a".repeat(100) + &"b".repeat(100);
        let t = truncate_middle(&s, 40);
        assert!(t.starts_with("aaaaaaaaaa"));
        assert!(t.ends_with("bbbbbbbbbb"));
        assert!(t.contains("omitted"));
    }
}

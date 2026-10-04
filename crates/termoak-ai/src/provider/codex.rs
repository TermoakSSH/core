//! Codex with the ChatGPT subscription, through the `codex exec` CLI (as in VoxPanel).
//!
//! - The ChatGPT session lives in `CODEX_HOME/auth.json` (`codex login --device-auth`).
//! - Codex runs **locked down**: no shell of its own, no network for commands,
//!   no filesystem access beyond a temporary directory, and without the
//!   user's configuration. **It never runs anything on the server machine.**
//! - Its only tools are Termoak's, exposed over MCP with a task token: every
//!   call goes through Termoak's permissions and approvals and is audited.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

use super::{EventSink, ExternalAgent, ExternalResult, ExternalRun, StreamEvent};
use crate::config::ProviderConfig;
use crate::error::AiError;
use crate::message::{Usage, transcript_as_text};

pub struct CodexCli {
    key: String,
    model: Option<String>,
    command: String,
    home: PathBuf,
    timeout: Duration,
    effort: Option<String>,
    path_env: Option<String>,
}

/// Effective `CODEX_HOME` directory.
pub fn codex_home(cfg: &ProviderConfig) -> PathBuf {
    if let Some(h) = cfg.codex_home.as_deref().filter(|h| !h.is_empty()) {
        return PathBuf::from(h);
    }
    if let Ok(h) = std::env::var("CODEX_HOME")
        && !h.is_empty()
    {
        return PathBuf::from(h);
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".codex")
}

/// Models the CLI left in `models_cache.json`.
pub fn cached_models(cfg: &ProviderConfig) -> Vec<String> {
    let path = codex_home(cfg).join("models_cache.json");
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<Value>(&text) else {
        return Vec::new();
    };
    json["models"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|m| m["visibility"].as_str().is_none_or(|v| v == "list"))
        .filter_map(|m| m["slug"].as_str().map(str::to_string))
        .collect()
}

impl CodexCli {
    pub fn new(key: &str, cfg: &ProviderConfig, model: Option<String>) -> Self {
        Self {
            key: key.to_string(),
            model,
            command: cfg.command.clone().unwrap_or_else(|| "codex".into()),
            home: codex_home(cfg),
            timeout: Duration::from_secs(cfg.timeout_secs.unwrap_or(1800)),
            effort: cfg.effort.clone(),
            path_env: cfg.path_env.clone(),
        }
    }

    /// Arguments for `codex exec`.
    pub fn arguments(
        &self,
        workdir: &Path,
        binary: &Path,
        mcp_url: Option<&str>,
        effort: Option<&str>,
    ) -> Vec<String> {
        let mut args: Vec<String> = vec![
            "exec".into(),
            "--json".into(),
            "--ephemeral".into(),
            "--skip-git-repo-check".into(),
            "--output-last-message".into(),
            workdir.join("reply.txt").display().to_string(),
        ];
        if let Some(model) = &self.model {
            args.extend(["--model".into(), model.clone()]);
        }
        if let Some(effort) = effort.map(str::to_string).or_else(|| self.effort.clone()) {
            args.extend(["-c".into(), format!("model_reasoning_effort=\"{effort}\"")]);
        }
        args.extend(["-c".into(), "model_reasoning_summary=\"detailed\"".into()]);
        // Lockdown (same options VoxPanel uses in production).
        let wd = toml_str(&workdir.display().to_string());
        let bin = toml_str(&binary.display().to_string());
        args.extend([
            "--ignore-user-config".into(),
            "--ignore-rules".into(),
            "--strict-config".into(),
            "-c".into(),
            "default_permissions=\"termoak\"".into(),
            "-c".into(),
            format!(
                "permissions.termoak.filesystem={{\":root\" = \"deny\", \":minimal\" = \"read\", {wd} = \"read\", {bin} = \"read\"}}"
            ),
            "-c".into(),
            "permissions.termoak.network.enabled=false".into(),
            "-c".into(),
            "approval_policy=\"never\"".into(),
            "-c".into(),
            "shell_environment_policy.inherit=\"none\"".into(),
        ]);
        for feature in [
            "shell_tool",
            "unified_exec",
            "shell_snapshot",
            "multi_agent",
            "apps",
            "plugins",
            "hooks",
            "browser_use",
            "computer_use",
            "memories",
        ] {
            args.extend(["-c".into(), format!("features.{feature}=false")]);
        }
        args.extend(["-c".into(), "web_search=\"disabled\"".into()]);
        if let Some(url) = mcp_url {
            args.extend([
                "-c".into(),
                format!("mcp_servers.termoak.url={}", toml_str(url)),
                "-c".into(),
                "mcp_servers.termoak.bearer_token_env_var=\"TERMOAK_MCP_TOKEN\"".into(),
                "-c".into(),
                "mcp_servers.termoak.tool_timeout_sec=3600".into(),
                "-c".into(),
                "mcp_servers.termoak.default_tools_approval_mode=\"approve\"".into(),
            ]);
        }
        args.push("-".into());
        args
    }
}

fn toml_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| format!("\"{s}\""))
}

/// User-safe message built from Codex's error output.
fn friendly_error(home: &Path, raw: &str) -> String {
    let l = raw.to_lowercase();
    if l.contains("requires a newer version")
        || l.contains("unexpected argument")
        || l.contains("unknown") && l.contains("flag")
    {
        "the installed Codex version is old or incompatible: update it (npm i -g @openai/codex)"
            .into()
    } else if l.contains("token_revoked")
        || l.contains("refresh token")
        || l.contains("401")
        || l.contains("not logged in")
    {
        format!(
            "Codex's ChatGPT session has expired: run \"CODEX_HOME={} codex login --device-auth\"",
            home.display()
        )
    } else if l.contains("429") || l.contains("rate limit") || l.contains("usage limit") {
        "Codex has reached your ChatGPT plan's usage limit".into()
    } else if l.contains("model_not_found") || l.contains("model is not supported") {
        "Codex does not recognize that model".into()
    } else if l.contains("bwrap") || l.contains("namespace") {
        "Codex cannot create its sandbox (bubblewrap): check the service's RestrictNamespaces"
            .into()
    } else {
        raw.lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("unknown error")
            .chars()
            .take(300)
            .collect()
    }
}

#[async_trait]
impl ExternalAgent for CodexCli {
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
        let binary =
            super::cli::require_binary(&self.key, &self.command, self.path_env.as_deref())?;
        let workdir = std::env::temp_dir()
            .join("termoak-codex")
            .join(format!("request-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&workdir).map_err(|e| AiError::Process {
            provider: self.key.clone(),
            message: e.to_string(),
        })?;
        let result = self.run_in(&workdir, &binary, req, sink).await;
        let _ = std::fs::remove_dir_all(&workdir);
        result
    }
}

impl CodexCli {
    async fn run_in(
        &self,
        workdir: &Path,
        binary: &Path,
        req: ExternalRun<'_>,
        sink: &dyn EventSink,
    ) -> Result<ExternalResult, AiError> {
        let mut prompt = String::new();
        prompt.push_str(req.system);
        prompt.push_str("\n\n# Conversation\n");
        prompt.push_str(&transcript_as_text(req.messages));
        if req.mcp.is_some() {
            prompt.push_str(
                "\n\nUse ONLY the tools of the \"termoak\" MCP server to act on the hosts. \
                 You have no local shell. Reply to the user's last message, in the user's language.",
            );
        }

        let args = self.arguments(
            workdir,
            binary,
            req.mcp.as_ref().map(|(u, _)| u.as_str()),
            req.effort,
        );
        let mut cmd = Command::new(binary);
        cmd.args(&args)
            .current_dir(workdir)
            .env_clear()
            .env(
                "PATH",
                self.path_env
                    .as_deref()
                    .unwrap_or("/usr/local/bin:/usr/bin:/bin"),
            )
            .env("LANG", "C.UTF-8")
            .env("HOME", workdir)
            .env("TMPDIR", workdir)
            .env("CODEX_HOME", &self.home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        for var in [
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "NO_PROXY",
            "https_proxy",
            "http_proxy",
            "no_proxy",
            "SSL_CERT_FILE",
            "SYSTEMROOT",
            "OPENAI_API_KEY",
            // Windows: what Node and the system need to start.
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "PATHEXT",
            "COMSPEC",
            "TEMP",
            "TMP",
        ] {
            if let Ok(v) = std::env::var(var) {
                cmd.env(var, v);
            }
        }
        if let Some((_, token)) = &req.mcp {
            cmd.env("TERMOAK_MCP_TOKEN", token);
        }
        let mut child = cmd.spawn().map_err(|e| AiError::Process {
            provider: self.key.clone(),
            message: format!("could not launch Codex: {e}"),
        })?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(prompt.as_bytes()).await.ok();
            drop(stdin);
        }
        let stdout = child.stdout.take().expect("stdout");
        let stderr = child.stderr.take().expect("stderr");
        let stderr_task = tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            let mut buf = String::new();
            while let Ok(Some(l)) = lines.next_line().await {
                if buf.len() < 16_000 {
                    buf.push_str(&l);
                    buf.push('\n');
                }
            }
            buf
        });

        let mut last_message = String::new();
        let mut reasoning = String::new();
        let mut usage = Usage::default();
        let mut failure: Option<String> = None;
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
            let Ok(ev) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            let item = &ev["item"];
            match ev["type"].as_str().unwrap_or("") {
                "item.started" if item["type"] == "mcp_tool_call" => {
                    sink.emit(StreamEvent::ToolStart {
                        id: item["id"].as_str().unwrap_or("").to_string(),
                        name: item["tool"].as_str().unwrap_or("").to_string(),
                    });
                }
                "item.completed" => match item["type"].as_str().unwrap_or("") {
                    "agent_message" => {
                        let t = item["text"].as_str().unwrap_or("");
                        if !last_message.is_empty() {
                            sink.emit(StreamEvent::Text("\n\n".into()));
                        }
                        sink.emit(StreamEvent::Text(t.to_string()));
                        last_message = t.to_string();
                    }
                    "reasoning" => {
                        let t = item["text"].as_str().unwrap_or("");
                        if !t.is_empty() {
                            reasoning.push_str(t);
                            reasoning.push('\n');
                            sink.emit(StreamEvent::Reasoning(format!("{t}\n")));
                        }
                    }
                    "error" => {
                        sink.emit(StreamEvent::Notice(
                            item["message"]
                                .as_str()
                                .unwrap_or("Codex notice")
                                .to_string(),
                        ));
                    }
                    _ => {}
                },
                "turn.completed" => {
                    let u = &ev["usage"];
                    usage.input_tokens += u["input_tokens"]
                        .as_u64()
                        .unwrap_or(0)
                        .saturating_sub(u["cached_input_tokens"].as_u64().unwrap_or(0));
                    usage.cache_read_tokens += u["cached_input_tokens"].as_u64().unwrap_or(0);
                    usage.cache_write_tokens += u["cache_write_input_tokens"].as_u64().unwrap_or(0);
                    usage.output_tokens += u["output_tokens"].as_u64().unwrap_or(0);
                    usage.reasoning_tokens += u["reasoning_output_tokens"].as_u64().unwrap_or(0);
                }
                "turn.failed" => {
                    failure = Some(
                        ev["error"]["message"]
                            .as_str()
                            .unwrap_or("failure")
                            .to_string(),
                    );
                }
                "error" => {
                    failure = Some(ev["message"].as_str().unwrap_or("error").to_string());
                }
                _ => {}
            }
        }
        let status = child.wait().await.map_err(|e| AiError::Process {
            provider: self.key.clone(),
            message: e.to_string(),
        })?;
        let stderr = stderr_task.await.unwrap_or_default();
        let reply = std::fs::read_to_string(workdir.join("reply.txt"))
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(last_message);
        if !status.success() || (reply.trim().is_empty() && failure.is_some()) {
            let raw = failure.unwrap_or_else(|| stderr.clone());
            tracing::warn!(provider = %self.key, stderr = %stderr, "Codex failed");
            let message = friendly_error(&self.home, &raw);
            return Err(if message.contains("codex login") {
                AiError::NotLoggedIn {
                    provider: self.key.clone(),
                    message,
                }
            } else {
                AiError::Process {
                    provider: self.key.clone(),
                    message,
                }
            });
        }
        Ok(ExternalResult {
            text: reply,
            reasoning: (!reasoning.is_empty()).then_some(reasoning),
            usage,
            model: self.model.clone().unwrap_or_else(|| "codex".into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_are_locked_down_and_wire_mcp() {
        let c = CodexCli::new(
            "codex",
            &ProviderConfig::default(),
            Some("gpt-5.6-sol".into()),
        );
        let args = c.arguments(
            Path::new("/tmp/w"),
            Path::new("/usr/local/bin/codex"),
            Some("http://127.0.0.1:7722/api/v1/mcp"),
            Some("high"),
        );
        let joined = args.join(" ");
        assert!(joined.starts_with("exec --json --ephemeral"));
        assert!(joined.contains("--model gpt-5.6-sol"));
        assert!(joined.contains("approval_policy=\"never\""));
        assert!(joined.contains("features.shell_tool=false"));
        assert!(joined.contains("mcp_servers.termoak.url=\"http://127.0.0.1:7722/api/v1/mcp\""));
        assert!(joined.contains("bearer_token_env_var=\"TERMOAK_MCP_TOKEN\""));
        assert_eq!(args.last().unwrap(), "-");
    }

    #[test]
    fn friendly_errors() {
        let h = Path::new("/var/lib/x");
        assert!(friendly_error(h, "error: refresh token was revoked").contains("codex login"));
        assert!(friendly_error(h, "HTTP 429 Too Many Requests").contains("usage limit"));
    }
}

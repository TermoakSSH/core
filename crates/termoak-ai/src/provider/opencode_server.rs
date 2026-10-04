//! Local `opencode serve` server (sessions API), which keeps its own
//! credential (e.g. the OpenCode Go subscription).
//!
//! Two ways:
//! - **An existing server** (`base_url`): a conversational fallback, a new
//!   session per request that is deleted at the end (as in VoxPanel). It
//!   does not get Termoak's tools; for tasks with tools use `opencode-api`.
//! - **A server per run** (`command`, e.g. the desktop app with OpenCode
//!   installed): `opencode serve --hostname 127.0.0.1 --port <free port>`
//!   with a random password, its own tools turned off and Termoak's MCP
//!   server (with the run's token) in its configuration
//!   (`OPENCODE_CONFIG_CONTENT`). It is stopped at the end.

use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};

use super::cli::{self, MCP_NAME};
use super::{EventSink, ExternalAgent, ExternalResult, ExternalRun, StreamEvent};
use crate::config::ProviderConfig;
use crate::error::AiError;
use crate::message::{Usage, transcript_as_text};

pub struct OpenCodeServer {
    key: String,
    model: Option<String>,
    base_url: String,
    auth: Option<(String, String)>,
    timeout: Duration,
    http: reqwest::Client,
    /// Start a server per run with this binary.
    command: Option<String>,
    path_env: Option<String>,
}

/// Configuration of a server started for a run: no tools of its own (shell,
/// files, web) and Termoak's MCP server, if any.
pub fn spawned_config(mcp: Option<(&str, &str)>) -> Value {
    let mut cfg = json!({
        "$schema": "https://opencode.ai/config.json",
        "share": "disabled",
        "autoupdate": false,
        "permission": {"edit": "deny", "bash": "deny", "webfetch": "deny"},
        "tools": {"bash": false, "edit": false, "write": false, "patch": false, "webfetch": false, "read": false, "list": false, "glob": false, "grep": false, "todowrite": false, "todoread": false},
    });
    if let Some((url, token)) = mcp {
        cfg["mcp"] = json!({MCP_NAME: {
            "type": "remote",
            "url": url,
            "enabled": true,
            "headers": {"Authorization": format!("Bearer {token}")},
        }});
    }
    cfg
}

/// A server started for one run (stopped when dropped).
struct Spawned {
    _child: tokio::process::Child,
    _dir: cli::Workdir,
    base_url: String,
    auth: (String, String),
}

impl OpenCodeServer {
    pub fn new(
        key: &str,
        cfg: &ProviderConfig,
        model: Option<String>,
        http: reqwest::Client,
    ) -> Self {
        Self {
            key: key.to_string(),
            model,
            base_url: cfg
                .base_url
                .clone()
                .unwrap_or_else(|| "http://127.0.0.1:4096".into())
                .trim_end_matches('/')
                .to_string(),
            auth: cfg
                .password
                .clone()
                .map(|p| (cfg.username.clone().unwrap_or_else(|| "opencode".into()), p)),
            timeout: Duration::from_secs(cfg.timeout_secs.unwrap_or(600)),
            http,
            command: cfg.command.clone(),
            path_env: cfg.path_env.clone(),
        }
    }

    /// Starts `opencode serve` for one run and waits until it answers.
    async fn spawn(&self, command: &str, mcp: Option<(&str, &str)>) -> Result<Spawned, AiError> {
        let binary = cli::require_binary(&self.key, command, self.path_env.as_deref())?;
        let dir = cli::Workdir::new(&self.key)?;
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .map(|a| a.port())
            .map_err(|e| AiError::Process {
                provider: self.key.clone(),
                message: e.to_string(),
            })?;
        let password = uuid::Uuid::new_v4().simple().to_string();
        let mut cmd = tokio::process::Command::new(&binary);
        cmd.args([
            "serve",
            "--hostname",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ])
        .current_dir(dir.path())
        .env("OPENCODE_SERVER_PASSWORD", &password)
        .env("OPENCODE_CONFIG_CONTENT", spawned_config(mcp).to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
        if let Some(p) = &self.path_env {
            cmd.env("PATH", p);
        }
        cli::hide_window(&mut cmd);
        let mut child = cmd.spawn().map_err(|e| AiError::Process {
            provider: self.key.clone(),
            message: format!("could not launch OpenCode: {e}"),
        })?;
        let stderr = cli::collect(child.stderr.take().expect("stderr"));
        let spawned = Spawned {
            _child: child,
            _dir: dir,
            base_url: format!("http://127.0.0.1:{port}"),
            auth: ("opencode".into(), password),
        };
        // Ready when it answers (up to 30 s).
        for _ in 0..120 {
            let ok = self
                .http
                .get(format!("{}/config", spawned.base_url))
                .basic_auth(&spawned.auth.0, Some(&spawned.auth.1))
                .timeout(Duration::from_secs(2))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success());
            if ok {
                return Ok(spawned);
            }
            if stderr.is_finished() {
                let raw = stderr.await.unwrap_or_default();
                return Err(if cli::looks_logged_out(&raw) {
                    AiError::NotLoggedIn {
                        provider: self.key.clone(),
                        message: "run \"opencode auth login\" in a terminal".into(),
                    }
                } else {
                    AiError::Process {
                        provider: self.key.clone(),
                        message: cli::last_line(&raw),
                    }
                });
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        Err(AiError::Timeout(self.key.clone()))
    }

    fn req(
        &self,
        base: &str,
        auth: Option<&(String, String)>,
        method: reqwest::Method,
        path: &str,
    ) -> reqwest::RequestBuilder {
        let r = self.http.request(method, format!("{base}{path}"));
        match auth {
            Some((u, p)) => r.basic_auth(u, Some(p)),
            None => r,
        }
    }

    fn err(&self, e: reqwest::Error) -> AiError {
        super::net_error(&self.key, e)
    }
}

#[async_trait]
impl ExternalAgent for OpenCodeServer {
    fn key(&self) -> &str {
        &self.key
    }

    fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }

    fn uses_tools(&self) -> bool {
        self.command.is_some()
    }

    async fn run(
        &self,
        req: ExternalRun<'_>,
        sink: &dyn EventSink,
    ) -> Result<ExternalResult, AiError> {
        let spawned = match &self.command {
            Some(command) => Some(
                self.spawn(
                    command,
                    req.mcp.as_ref().map(|(u, t)| (u.as_str(), t.as_str())),
                )
                .await?,
            ),
            None => None,
        };
        let (base, auth) = match &spawned {
            Some(s) => (s.base_url.as_str(), Some(&s.auth)),
            None => (self.base_url.as_str(), self.auth.as_ref()),
        };
        let session: Value = self
            .req(base, auth, reqwest::Method::POST, "/session")
            .json(&json!({}))
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .map_err(|e| self.err(e))?
            .json()
            .await
            .map_err(|e| self.err(e))?;
        let id = session["id"]
            .as_str()
            .ok_or_else(|| AiError::Protocol {
                provider: self.key.clone(),
                message: "did not return a session id".into(),
            })?
            .to_string();

        let text = if spawned.is_some() {
            cli::conversation_prompt(req.messages, req.mcp.is_some())
        } else {
            transcript_as_text(req.messages)
        };
        let mut body = json!({
            "parts": [{"type": "text", "text": text}],
            "system": req.system,
        });
        if let Some((provider_id, model_id)) = self.model.as_deref().and_then(|m| m.split_once('/'))
        {
            body["model"] = json!({"providerID": provider_id, "modelID": model_id});
        }
        let send = self
            .req(
                base,
                auth,
                reqwest::Method::POST,
                &format!("/session/{id}/message"),
            )
            .json(&body)
            .timeout(self.timeout)
            .send();
        let result = tokio::select! {
            _ = req.cancel.cancelled() => Err(AiError::Cancelled),
            r = send => match r {
                Ok(resp) if resp.status().is_success() => resp.json::<Value>().await.map_err(|e| self.err(e)),
                Ok(resp) => Err(super::http_error(&self.key, resp).await),
                Err(e) => Err(self.err(e)),
            },
        };
        // The session is always deleted.
        let _ = self
            .req(
                base,
                auth,
                reqwest::Method::DELETE,
                &format!("/session/{id}"),
            )
            .timeout(Duration::from_secs(10))
            .send()
            .await;
        let reply = result?;

        let mut text = String::new();
        let mut reasoning = String::new();
        for part in reply["parts"].as_array().into_iter().flatten() {
            match part["type"].as_str().unwrap_or("") {
                "text" => text.push_str(part["text"].as_str().unwrap_or("")),
                "reasoning" | "thinking" => reasoning.push_str(part["text"].as_str().unwrap_or("")),
                _ => {}
            }
        }
        if !reasoning.is_empty() {
            sink.emit(StreamEvent::Reasoning(reasoning.clone()));
        }
        sink.emit(StreamEvent::Text(text.clone()));
        let info = &reply["info"];
        let t = &info["tokens"];
        Ok(ExternalResult {
            text,
            reasoning: (!reasoning.is_empty()).then_some(reasoning),
            usage: Usage {
                input_tokens: t["input"].as_u64().unwrap_or(0),
                output_tokens: t["output"].as_u64().unwrap_or(0),
                reasoning_tokens: t["reasoning"].as_u64().unwrap_or(0),
                cache_read_tokens: t["cache"]["read"].as_u64().unwrap_or(0),
                cache_write_tokens: t["cache"]["write"].as_u64().unwrap_or(0),
                reported_cost_usd: info["cost"].as_f64(),
            },
            model: info["modelID"]
                .as_str()
                .map(str::to_string)
                .or_else(|| self.model.clone())
                .unwrap_or_else(|| "opencode".into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawned_servers_only_get_termoak_tools() {
        let cfg = spawned_config(Some(("http://127.0.0.1:9/mcp", "tok")));
        assert_eq!(cfg["tools"]["bash"], false);
        assert_eq!(cfg["permission"]["bash"], "deny");
        assert_eq!(cfg["mcp"]["termoak"]["type"], "remote");
        assert_eq!(
            cfg["mcp"]["termoak"]["headers"]["Authorization"],
            "Bearer tok"
        );
        assert!(spawned_config(None).get("mcp").is_none());
    }
}

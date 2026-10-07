//! AI engine configuration.
//!
//! As in VoxPanel, each provider has a key (`claude`, `gpt`, `codex`,
//! `codex-api`, `opencode-api`, `openrouter`, `opencode`, `local`...) and is selected as
//! `key` or `key::model`. There is a default provider and a fallback chain.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use termoak_ssh::HostKeyPolicy;

use crate::policy::PermissionMode;
use crate::pricing::Price;

/// Implementation a provider uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Driver {
    /// Anthropic Messages API (Claude).
    Anthropic,
    /// OpenAI Responses API.
    OpenaiResponses,
    /// OpenAI-compatible Chat Completions API (OpenCode Go, Ollama, vLLM, NVIDIA...).
    OpenaiChat,
    /// `codex exec` CLI with the ChatGPT session stored in `CODEX_HOME`.
    CodexCli,
    /// Local `opencode serve` server (sessions API). With `command` set, a
    /// server is started for each run (with Termoak's tools over MCP).
    OpencodeServer,
    /// Claude Code (`claude -p`, headless with `stream-json` output), with its
    /// own sign-in or subscription. Its only tools are Termoak's, over MCP.
    ClaudeCode,
    /// Google Antigravity (`agy -p`, headless with `stream-json` output), run
    /// under a pseudo-terminal (it prints nothing without one). Termoak's
    /// tools over MCP.
    Antigravity,
}

/// Provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProviderConfig {
    pub driver: Driver,
    /// Display name (defaults to the key).
    pub label: Option<String>,
    pub enabled: bool,
    pub base_url: Option<String>,
    /// Literal key (prefer `api_key_env`).
    pub api_key: Option<String>,
    /// Environment variables to read the key from, in order.
    pub api_key_env: Vec<String>,
    /// Default model.
    pub model: Option<String>,
    /// Extra models to offer in the picker.
    pub models: Vec<String>,
    /// Query `GET /models` to discover models.
    pub list_models: bool,
    pub max_tokens: Option<u32>,
    /// Reasoning effort (`low`, `medium`, `high`, `xhigh`, `max`).
    pub effort: Option<String>,
    /// Anthropic: `adaptive` (default) or `none` to not send `thinking`.
    pub thinking: Option<String>,
    /// Anthropic: server-side fallback on refusals (`default` or `none`).
    pub fallbacks: Option<String>,
    /// Anthropic: `eager_input_streaming` on tools (only against the real API).
    pub eager_input_streaming: Option<bool>,
    /// Extra HTTP headers.
    pub headers: BTreeMap<String, String>,
    /// Path under `base_url` queried (`GET`) to check a user's own API key
    /// (`/models` by default; Anthropic always uses `/v1/models`).
    pub key_check_path: Option<String>,
    /// External agents: binary (`codex`, `claude`, `agy`, `opencode`), by
    /// name or absolute path.
    pub command: Option<String>,
    /// External agents: `PATH` of their process (scripts installed with npm
    /// need `node`). Codex defaults to `/usr/local/bin:/usr/bin:/bin`; the
    /// others inherit it.
    pub path_env: Option<String>,
    /// Codex: `CODEX_HOME` directory with the ChatGPT session.
    pub codex_home: Option<String>,
    /// Codex/OpenCode: maximum time per run.
    pub timeout_secs: Option<u64>,
    /// Local OpenCode: HTTP Basic user and password.
    pub username: Option<String>,
    pub password: Option<String>,
    /// Price per million tokens (defaults to the built-in table). On a
    /// subscription it is only the reference for the plans' AI credit.
    pub price: Option<Price>,
    /// Price per million tokens charged to the plans' AI credit, instead of
    /// the real cost (`{ input, output, cached_input }`). When not set: the
    /// real cost, else the model's price, else a reference price (Codex:
    /// GPT-5.3-codex; others: a conservative default).
    pub credit_price: Option<Price>,
    /// The subscription is not billed per token (Codex with ChatGPT, OpenCode Go...).
    pub subscription: bool,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            driver: Driver::OpenaiChat,
            label: None,
            enabled: true,
            base_url: None,
            api_key: None,
            api_key_env: Vec::new(),
            model: None,
            models: Vec::new(),
            list_models: false,
            max_tokens: None,
            effort: None,
            thinking: None,
            fallbacks: None,
            eager_input_streaming: None,
            headers: BTreeMap::new(),
            key_check_path: None,
            command: None,
            path_env: None,
            codex_home: None,
            timeout_secs: None,
            username: None,
            password: None,
            price: None,
            credit_price: None,
            subscription: false,
        }
    }
}

impl ProviderConfig {
    /// Effective API key (literal or from the environment).
    pub fn resolve_key(&self) -> Option<String> {
        self.api_key
            .clone()
            .filter(|k| !k.trim().is_empty())
            .or_else(|| {
                self.api_key_env
                    .iter()
                    .find_map(|v| std::env::var(v).ok().filter(|k| !k.trim().is_empty()))
            })
    }
}

/// Engine configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AiConfig {
    /// Default provider (`key` or `key::model`).
    pub default: String,
    /// Fallback chain.
    pub fallback: Vec<String>,
    /// Providers (merged with the built-in ones).
    pub providers: BTreeMap<String, ProviderConfig>,
    /// Providers hidden from the picker (still usable as fallback).
    pub hidden: Vec<String>,
    /// Default permission mode for tasks.
    pub default_mode: PermissionMode,
    /// Maximum agent steps per message.
    pub max_steps: u32,
    /// Maximum time to wait for an approval.
    pub approval_timeout_secs: u64,
    /// Maximum time per command.
    pub command_timeout_secs: u64,
    /// Maximum tool output characters the model sees.
    pub max_tool_output_chars: usize,
    /// Host key policy for AI connections.
    pub host_key_policy: HostKeyPolicy,
    /// Monthly credit per user (USD) for the server's providers. Plans set
    /// their own (`ai_credit_usd`); this is the fallback for plans that allow
    /// the server's AI without an explicit credit. `None` = no cap.
    pub monthly_budget_usd: Option<f64>,
    /// Concurrent tasks per user.
    pub max_concurrent_tasks: usize,
    /// Tool mode for external agents using MCP with a user token.
    pub mcp_user_mode: PermissionMode,
    /// Hosts of a multi-host task (one conversation per host) that run at
    /// the same time.
    pub fan_out_concurrency: usize,
    /// Most hosts in a multi-host task.
    pub max_fan_out_hosts: usize,
    /// Hide secrets (passwords, tokens, keys...) in tool results and
    /// terminal context before they go to the AI provider.
    pub redact_secrets: bool,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            default: "codex".into(),
            fallback: vec![
                "opencode-api::deepseek-v4-flash".into(),
                "opencode-api::kimi-k2.6".into(),
            ],
            providers: BTreeMap::new(),
            hidden: vec!["opencode".into()],
            default_mode: PermissionMode::Ask,
            max_steps: 40,
            approval_timeout_secs: 30 * 60,
            command_timeout_secs: 120,
            max_tool_output_chars: 16_000,
            host_key_policy: HostKeyPolicy::AcceptNew,
            monthly_budget_usd: None,
            max_concurrent_tasks: 4,
            mcp_user_mode: PermissionMode::ReadOnly,
            fan_out_concurrency: 4,
            max_fan_out_hosts: 50,
            redact_secrets: true,
        }
    }
}

impl AiConfig {
    /// Built-in providers + those from the config file (which win).
    pub fn effective_providers(&self) -> BTreeMap<String, ProviderConfig> {
        let mut out = builtin_providers();
        for (key, cfg) in &self.providers {
            out.insert(key.clone(), cfg.clone());
        }
        out
    }
}

fn env_list(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| s.to_string()).collect()
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn env_opt(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// Built-in providers, configurable through environment variables as in VoxPanel.
pub fn builtin_providers() -> BTreeMap<String, ProviderConfig> {
    let mut m = BTreeMap::new();
    m.insert(
        "claude".into(),
        ProviderConfig {
            driver: Driver::Anthropic,
            label: Some("Claude".into()),
            base_url: Some(env_or("ANTHROPIC_BASE_URL", "https://api.anthropic.com")),
            api_key_env: env_list(&["ANTHROPIC_API_KEY"]),
            model: Some(env_or("ANTHROPIC_MODEL", "claude-opus-5")),
            models: vec![
                "claude-opus-5".into(),
                "claude-opus-5-5".into(),
                "claude-sonnet-5".into(),
                "claude-haiku-4-5".into(),
                "claude-fable-5-1".into(),
            ],
            max_tokens: Some(64_000),
            effort: Some(env_or("ANTHROPIC_EFFORT", "high")),
            thinking: Some("adaptive".into()),
            fallbacks: Some("default".into()),
            ..Default::default()
        },
    );
    m.insert(
        "gpt".into(),
        ProviderConfig {
            driver: Driver::OpenaiResponses,
            label: Some("OpenAI".into()),
            base_url: Some(env_or("OPENAI_BASE_URL", "https://api.openai.com/v1")),
            api_key_env: env_list(&["OPENAI_API_KEY"]),
            model: Some(env_or("OPENAI_MODEL", "gpt-5.6-sol")),
            list_models: true,
            max_tokens: Some(32_000),
            effort: Some(env_or("OPENAI_EFFORT", "medium")),
            ..Default::default()
        },
    );
    m.insert(
        "codex".into(),
        ProviderConfig {
            driver: Driver::CodexCli,
            label: Some("Codex (ChatGPT subscription)".into()),
            command: Some(env_or("CODEX_COMMAND", "codex")),
            codex_home: env_opt("CODEX_HOME"),
            model: env_opt("CODEX_CLI_MODEL"),
            models: env_opt("CODEX_EXTRA_MODELS")
                .map(|s| {
                    s.split(',')
                        .map(|m| m.split('|').next().unwrap_or("").trim().to_string())
                        .filter(|m| !m.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            effort: env_opt("CODEX_EFFORT"),
            timeout_secs: Some(1800),
            subscription: true,
            ..Default::default()
        },
    );
    m.insert(
        "codex-api".into(),
        ProviderConfig {
            driver: Driver::OpenaiResponses,
            label: Some("Codex (API)".into()),
            base_url: Some(env_or("CODEX_BASE_URL", "https://api.openai.com/v1")),
            api_key_env: env_list(&["CODEX_API_KEY", "OPENAI_API_KEY"]),
            model: Some(env_or("CODEX_MODEL", "gpt-5-codex")),
            max_tokens: Some(32_000),
            effort: Some("medium".into()),
            ..Default::default()
        },
    );
    m.insert(
        "opencode-api".into(),
        ProviderConfig {
            driver: Driver::OpenaiChat,
            label: Some("OpenCode Go".into()),
            base_url: Some(env_or(
                "OPENCODE_GO_BASE_URL",
                "https://opencode.ai/zen/go/v1",
            )),
            api_key_env: env_list(&["OPENCODE_GO_KEY", "OPENCODE_API_KEY"]),
            model: Some(env_or("OPENCODE_GO_MODEL", "deepseek-v4-flash")),
            models: vec!["deepseek-v4-flash".into(), "kimi-k2.6".into()],
            list_models: true,
            max_tokens: Some(16_000),
            subscription: true,
            ..Default::default()
        },
    );
    m.insert(
        "openrouter".into(),
        ProviderConfig {
            driver: Driver::OpenaiChat,
            label: Some("OpenRouter".into()),
            base_url: Some(env_or(
                "OPENROUTER_BASE_URL",
                "https://openrouter.ai/api/v1",
            )),
            api_key_env: env_list(&["OPENROUTER_API_KEY"]),
            model: Some(env_or("OPENROUTER_MODEL", "openrouter/auto")),
            max_tokens: Some(16_000),
            headers: BTreeMap::from([
                (
                    "HTTP-Referer".to_string(),
                    "https://termoak.com".to_string(),
                ),
                ("X-Title".to_string(), "Termoak".to_string()),
            ]),
            // `/models` is public at OpenRouter; `/key` needs a valid key.
            key_check_path: Some("/key".into()),
            ..Default::default()
        },
    );
    m.insert(
        "opencode".into(),
        ProviderConfig {
            driver: Driver::OpencodeServer,
            label: Some("OpenCode (local server)".into()),
            base_url: Some(env_or("OPENCODE_BASE_URL", "http://127.0.0.1:4096")),
            model: env_opt("OPENCODE_MODEL"),
            username: Some(env_or("OPENCODE_SERVER_USERNAME", "opencode")),
            password: env_opt("OPENCODE_SERVER_PASSWORD"),
            timeout_secs: Some(600),
            subscription: true,
            ..Default::default()
        },
    );
    m.insert(
        "local".into(),
        ProviderConfig {
            driver: Driver::OpenaiChat,
            label: Some("Local (Ollama/LM Studio/vLLM)".into()),
            enabled: env_opt("LOCAL_AI_BASE_URL").is_some() || env_opt("LOCAL_AI_MODEL").is_some(),
            base_url: Some(env_or("LOCAL_AI_BASE_URL", "http://localhost:11434/v1")),
            api_key: Some(env_or("LOCAL_AI_API_KEY", "local")),
            model: env_opt("LOCAL_AI_MODEL"),
            list_models: true,
            max_tokens: Some(8_000),
            subscription: true,
            ..Default::default()
        },
    );
    m
}

/// Splits `provider::model`.
pub fn split_spec(spec: &str) -> (String, Option<String>) {
    match spec.split_once("::") {
        Some((p, m)) if !m.trim().is_empty() => (p.trim().to_string(), Some(m.trim().to_string())),
        Some((p, _)) => (p.trim().to_string(), None),
        None => (spec.trim().to_string(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_parsing() {
        assert_eq!(split_spec("codex"), ("codex".into(), None));
        assert_eq!(
            split_spec("opencode-api::kimi-k2.6"),
            ("opencode-api".into(), Some("kimi-k2.6".into()))
        );
        assert_eq!(
            split_spec("opencode::opencode-go/qwen3.7-plus"),
            ("opencode".into(), Some("opencode-go/qwen3.7-plus".into()))
        );
    }

    #[test]
    fn config_overrides_builtin() {
        let mut cfg = AiConfig::default();
        cfg.providers.insert(
            "claude".into(),
            ProviderConfig {
                driver: Driver::Anthropic,
                model: Some("claude-sonnet-5".into()),
                ..Default::default()
            },
        );
        let eff = cfg.effective_providers();
        assert_eq!(eff["claude"].model.as_deref(), Some("claude-sonnet-5"));
        assert!(eff.contains_key("opencode-api"));
        assert_eq!(eff["openrouter"].driver, Driver::OpenaiChat);
        assert!(eff["openrouter"].model.is_some());
    }
}

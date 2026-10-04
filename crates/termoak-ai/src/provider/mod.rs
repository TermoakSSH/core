//! AI providers and registry with a fallback chain.

pub mod anthropic;
pub mod antigravity;
pub mod claude_code;
pub(crate) mod cli;
pub mod codex;
pub mod openai_chat;
pub mod openai_responses;
pub mod opencode_server;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::config::{AiConfig, Driver, ProviderConfig, split_spec};
use crate::error::AiError;
use crate::message::{Message, StopReason, Usage};

/// Tool offered to the model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub schema: serde_json::Value,
}

/// Request for a turn.
pub struct TurnRequest<'a> {
    pub system: &'a str,
    pub messages: &'a [Message],
    pub tools: &'a [ToolSpec],
    /// Stable conversation identifier (`x-opencode-session` header, etc.).
    pub session_id: &'a str,
    pub max_tokens: Option<u32>,
    /// Ask for a JSON-only answer (quick assistant).
    pub json_schema: Option<&'a serde_json::Value>,
    /// Effort for this turn (the provider's otherwise).
    pub effort: Option<&'a str>,
    pub cancel: &'a CancellationToken,
}

/// Response of a turn.
#[derive(Debug, Clone)]
pub struct TurnResponse {
    /// Always `Message::Assistant`.
    pub message: Message,
    pub stop: StopReason,
    pub usage: Usage,
    /// Model that actually answered.
    pub model: String,
    pub refusal_category: Option<String>,
}

/// Live events of a turn.
#[derive(Debug, Clone)]
pub enum StreamEvent {
    Text(String),
    Reasoning(String),
    Notice(String),
    ToolStart { id: String, name: String },
}

pub trait EventSink: Send + Sync {
    fn emit(&self, ev: StreamEvent);
}

/// Discards events.
pub struct NullSink;

impl EventSink for NullSink {
    fn emit(&self, _ev: StreamEvent) {}
}

/// Conversational provider with tools (Termoak runs the loop).
#[async_trait]
pub trait ChatProvider: Send + Sync {
    fn key(&self) -> &str;
    fn model(&self) -> &str;
    /// Identifies reusable native blocks (`driver::model`).
    fn native_key(&self) -> String;
    async fn turn(
        &self,
        req: &TurnRequest<'_>,
        sink: &dyn EventSink,
    ) -> Result<TurnResponse, AiError>;
}

/// Complete run delegated to an external agent (Codex CLI, local OpenCode).
pub struct ExternalRun<'a> {
    pub system: &'a str,
    pub messages: &'a [Message],
    /// Termoak MCP endpoint and task token (for tools).
    pub mcp: Option<(String, String)>,
    pub effort: Option<&'a str>,
    pub cancel: &'a CancellationToken,
}

/// Result of an external agent.
#[derive(Debug, Clone, Default)]
pub struct ExternalResult {
    pub text: String,
    pub reasoning: Option<String>,
    pub usage: Usage,
    pub model: String,
}

#[async_trait]
pub trait ExternalAgent: Send + Sync {
    fn key(&self) -> &str;
    fn model(&self) -> Option<&str>;
    /// Can it use Termoak's tools (via MCP)?
    fn uses_tools(&self) -> bool;
    async fn run(
        &self,
        req: ExternalRun<'_>,
        sink: &dyn EventSink,
    ) -> Result<ExternalResult, AiError>;
}

/// Resolved implementation of a `provider::model`.
#[derive(Clone)]
pub enum Backend {
    Chat(Arc<dyn ChatProvider>),
    External(Arc<dyn ExternalAgent>),
}

impl Backend {
    pub fn spec(&self) -> String {
        match self {
            Backend::Chat(p) => format!("{}::{}", p.key(), p.model()),
            Backend::External(a) => match a.model() {
                Some(m) => format!("{}::{m}", a.key()),
                None => a.key().to_string(),
            },
        }
    }
}

/// Public provider information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    pub key: String,
    pub label: String,
    pub driver: Driver,
    pub available: bool,
    pub hidden: bool,
    pub default_model: Option<String>,
    pub models: Vec<String>,
    pub subscription: bool,
    /// Reason, if unavailable (detailed for administrators, generic for
    /// everybody else).
    pub reason: Option<String>,
    /// Stable code of the reason, if unavailable: `not_configured` (the
    /// server's provider cannot run), `own_key_required` (your plan does not
    /// include the server's AI: add your own key) or `plan` (not included in
    /// your plan).
    #[serde(default)]
    pub reason_code: Option<String>,
    /// Accepts the user's own API key (`PUT /api/v1/me/ai/keys/{provider}`).
    #[serde(default)]
    pub accepts_own_key: bool,
    /// Runs with the user's own API key.
    #[serde(default)]
    pub uses_own_key: bool,
}

/// [`ProviderInfo::reason_code`]: the server's provider cannot run.
pub const REASON_NOT_CONFIGURED: &str = "not_configured";
/// [`ProviderInfo::reason_code`]: the plan has no server AI; an own key works.
pub const REASON_OWN_KEY_REQUIRED: &str = "own_key_required";
/// [`ProviderInfo::reason_code`]: not included in the plan.
pub const REASON_PLAN: &str = "plan";

/// Provider registry.
pub struct Registry {
    config: AiConfig,
    providers: BTreeMap<String, ProviderConfig>,
    http: reqwest::Client,
    model_cache: Mutex<BTreeMap<String, (Instant, Vec<String>)>>,
}

impl Registry {
    pub fn new(config: AiConfig) -> Self {
        let providers = config.effective_providers();
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(Duration::from_secs(600))
            .user_agent(concat!("Termoak/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("HTTP client");
        Self {
            config,
            providers,
            http,
            model_cache: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn config(&self) -> &AiConfig {
        &self.config
    }

    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }

    pub fn provider_config(&self, key: &str) -> Option<&ProviderConfig> {
        self.providers.get(key)
    }

    /// Why a provider is unavailable (`None` = available).
    pub fn unavailable_reason(&self, key: &str) -> Option<String> {
        let Some(cfg) = self.providers.get(key) else {
            return Some("does not exist".into());
        };
        if !cfg.enabled {
            return Some("disabled".into());
        }
        match cfg.driver {
            Driver::Anthropic | Driver::OpenaiResponses | Driver::OpenaiChat => {
                if cfg.resolve_key().is_none() {
                    return Some(format!(
                        "missing API key ({})",
                        if cfg.api_key_env.is_empty() {
                            "api_key".to_string()
                        } else {
                            cfg.api_key_env.join(" or ")
                        }
                    ));
                }
                if cfg.model.is_none() && cfg.models.is_empty() && !cfg.list_models {
                    return Some("no model configured".into());
                }
                None
            }
            Driver::CodexCli => {
                let cmd = cfg.command.clone().unwrap_or_else(|| "codex".into());
                let Some(bin) = cli::find_binary(&cmd, cfg.path_env.as_deref()) else {
                    return Some(format!("executable \"{cmd}\" not found"));
                };
                // Codex calls the tools through this helper; without it, it can
                // only answer (it runs nothing on your hosts). Installed with
                // npm, `codex` is a script that finds its own copy.
                let host = bin.with_file_name("codex-code-mode-host");
                if !host.exists() && !is_script(&bin) {
                    return Some(format!(
                        "missing \"{}\": copy it next to \"{}\" from the Codex installation (without it, tools cannot be used)",
                        host.display(),
                        bin.display()
                    ));
                }
                let home = codex::codex_home(cfg);
                if !home.join("auth.json").exists() && std::env::var("OPENAI_API_KEY").is_err() {
                    return Some(format!(
                        "not signed in: run \"CODEX_HOME={} codex login --device-auth\"",
                        home.display()
                    ));
                }
                None
            }
            Driver::ClaudeCode | Driver::Antigravity => {
                let default = if cfg.driver == Driver::ClaudeCode {
                    "claude"
                } else {
                    "agy"
                };
                let cmd = cfg.command.clone().unwrap_or_else(|| default.into());
                if cli::find_binary(&cmd, cfg.path_env.as_deref()).is_none() {
                    return Some(format!("executable \"{cmd}\" not found"));
                }
                None
            }
            Driver::OpencodeServer if cfg.command.is_some() => {
                let cmd = cfg.command.clone().unwrap_or_default();
                if cli::find_binary(&cmd, cfg.path_env.as_deref()).is_none() {
                    return Some(format!("executable \"{cmd}\" not found"));
                }
                None
            }
            Driver::OpencodeServer => {
                let explicit = std::env::var("OPENCODE_BASE_URL").is_ok_and(|v| !v.is_empty())
                    || self.config.providers.contains_key(key);
                if !explicit && find_in_path("opencode").is_none() {
                    return Some(
                        "\"opencode\" not found (install it or set OPENCODE_BASE_URL)".into(),
                    );
                }
                None
            }
        }
    }

    /// Does the provider accept a user's own API key? Only the HTTP ones in
    /// [`OWN_KEY_PROVIDERS`](crate::access::OWN_KEY_PROVIDERS) that are
    /// enabled and have a model.
    pub fn own_key_supported(&self, key: &str) -> bool {
        crate::access::OWN_KEY_PROVIDERS.contains(&key)
            && self.providers.get(key).is_some_and(|cfg| {
                cfg.enabled
                    && matches!(
                        cfg.driver,
                        Driver::Anthropic | Driver::OpenaiResponses | Driver::OpenaiChat
                    )
                    && (cfg.model.is_some() || !cfg.models.is_empty())
            })
    }

    /// Builds the backend for `provider[::model]` with the server's credentials.
    pub fn resolve(&self, spec: &str) -> Result<Backend, AiError> {
        let (key, model) = split_spec(spec);
        let cfg = self
            .providers
            .get(&key)
            .ok_or_else(|| AiError::NotConfigured(key.clone()))?;
        if let Some(reason) = self.unavailable_reason(&key) {
            return Err(AiError::NotConfigured(format!("{key}: {reason}")));
        }
        self.build(&key, cfg, model)
    }

    /// Builds the backend of a chain step: with the user's own key (which
    /// replaces the server's) or with the server's credentials.
    pub fn resolve_entry(&self, entry: &crate::access::ChainEntry) -> Result<Backend, AiError> {
        let Some(own_key) = &entry.own_key else {
            return self.resolve(&entry.spec);
        };
        let (key, model) = split_spec(&entry.spec);
        if !self.own_key_supported(&key) {
            return Err(AiError::NotConfigured(format!(
                "{key}: does not accept your own API key"
            )));
        }
        let mut cfg = self.providers[&key].clone();
        cfg.api_key = Some(own_key.to_string());
        cfg.api_key_env.clear();
        self.build(&key, &cfg, model)
    }

    fn build(
        &self,
        key: &str,
        cfg: &ProviderConfig,
        model: Option<String>,
    ) -> Result<Backend, AiError> {
        let key = key.to_string();
        let model = model.or_else(|| cfg.model.clone());
        Ok(match cfg.driver {
            Driver::Anthropic => Backend::Chat(Arc::new(anthropic::Anthropic::new(
                &key,
                cfg,
                need_model(&key, model)?,
                self.http.clone(),
            ))),
            Driver::OpenaiResponses => {
                Backend::Chat(Arc::new(openai_responses::OpenAiResponses::new(
                    &key,
                    cfg,
                    need_model(&key, model)?,
                    self.http.clone(),
                )))
            }
            Driver::OpenaiChat => Backend::Chat(Arc::new(openai_chat::OpenAiChat::new(
                &key,
                cfg,
                need_model(&key, model)?,
                self.http.clone(),
            ))),
            Driver::CodexCli => Backend::External(Arc::new(codex::CodexCli::new(&key, cfg, model))),
            Driver::OpencodeServer => Backend::External(Arc::new(
                opencode_server::OpenCodeServer::new(&key, cfg, model, self.http.clone()),
            )),
            Driver::ClaudeCode => {
                Backend::External(Arc::new(claude_code::ClaudeCode::new(&key, cfg, model)))
            }
            Driver::Antigravity => {
                Backend::External(Arc::new(antigravity::Antigravity::new(&key, cfg, model)))
            }
        })
    }

    /// Provider chain: the requested one (or the default) + fallbacks, without
    /// repeats and only the available ones.
    pub fn chain(&self, requested: Option<&str>) -> Vec<String> {
        let first = requested
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| self.config.default.clone());
        let mut out: Vec<String> = Vec::new();
        for spec in std::iter::once(first).chain(self.config.fallback.iter().cloned()) {
            let (key, _) = split_spec(&spec);
            if self.unavailable_reason(&key).is_none() && !out.contains(&spec) {
                out.push(spec);
            }
        }
        out
    }

    /// Providers for the app's picker.
    pub async fn list(&self) -> Vec<ProviderInfo> {
        let mut out = Vec::new();
        for (key, cfg) in &self.providers {
            let reason = self.unavailable_reason(key);
            let models = if reason.is_none() {
                self.models(key).await
            } else {
                static_models(cfg)
            };
            out.push(ProviderInfo {
                key: key.clone(),
                label: cfg.label.clone().unwrap_or_else(|| key.clone()),
                driver: cfg.driver,
                available: reason.is_none(),
                hidden: self.config.hidden.contains(key),
                default_model: cfg.model.clone(),
                models,
                subscription: cfg.subscription,
                reason_code: reason.as_ref().map(|_| REASON_NOT_CONFIGURED.to_string()),
                reason,
                accepts_own_key: self.own_key_supported(key),
                uses_own_key: false,
            });
        }
        out
    }

    /// Known models of a provider (with discovery cached for 1 h).
    pub async fn models(&self, key: &str) -> Vec<String> {
        let Some(cfg) = self.providers.get(key) else {
            return Vec::new();
        };
        let mut models = static_models(cfg);
        if cfg.driver == Driver::CodexCli {
            for m in codex::cached_models(cfg) {
                if !models.contains(&m) {
                    models.push(m);
                }
            }
            return models;
        }
        if !cfg.list_models {
            return models;
        }
        if let Some((at, cached)) = self.model_cache.lock().get(key).cloned()
            && at.elapsed() < Duration::from_secs(3600)
        {
            return merge(models, cached);
        }
        let discovered = match cfg.driver {
            Driver::OpenaiChat | Driver::OpenaiResponses => discover_openai_models(&self.http, cfg)
                .await
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        self.model_cache
            .lock()
            .insert(key.to_string(), (Instant::now(), discovered.clone()));
        models = merge(models, discovered);
        models
    }
}

impl Registry {
    /// Checks a user's own API key with a cheap call that spends nothing
    /// (listing models, or the provider's `key_check_path`).
    pub async fn check_key(&self, provider: &str, api_key: &str) -> Result<(), AiError> {
        if !self.own_key_supported(provider) {
            return Err(AiError::NotConfigured(format!(
                "{provider}: does not accept your own API key"
            )));
        }
        let cfg = &self.providers[provider];
        let base = cfg
            .base_url
            .clone()
            .unwrap_or_default()
            .trim_end_matches('/')
            .to_string();
        let mut req = match cfg.driver {
            Driver::Anthropic => self
                .http
                .get(format!(
                    "{base}{}",
                    cfg.key_check_path
                        .as_deref()
                        .unwrap_or("/v1/models?limit=1")
                ))
                .header("x-api-key", api_key)
                .header("anthropic-version", anthropic::API_VERSION),
            _ => self
                .http
                .get(format!(
                    "{base}{}",
                    cfg.key_check_path.as_deref().unwrap_or("/models")
                ))
                .bearer_auth(api_key),
        };
        for (k, v) in &cfg.headers {
            req = req.header(k, v);
        }
        let resp = req
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .map_err(|e| net_error(provider, e))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(http_error(provider, resp).await)
        }
    }
}

fn need_model(key: &str, model: Option<String>) -> Result<String, AiError> {
    model.ok_or_else(|| AiError::NotConfigured(format!("{key}: no model configured")))
}

fn static_models(cfg: &ProviderConfig) -> Vec<String> {
    let mut v: Vec<String> = cfg.model.iter().cloned().collect();
    for m in &cfg.models {
        if !v.contains(m) {
            v.push(m.clone());
        }
    }
    v
}

fn merge(mut a: Vec<String>, b: Vec<String>) -> Vec<String> {
    for m in b {
        if !a.contains(&m) {
            a.push(m);
        }
    }
    a
}

/// `GET {base}/models` on OpenAI-compatible APIs, filtering out non-chat models.
async fn discover_openai_models(
    http: &reqwest::Client,
    cfg: &ProviderConfig,
) -> Result<Vec<String>, AiError> {
    let base = cfg.base_url.clone().unwrap_or_default();
    let key = cfg.resolve_key().unwrap_or_default();
    let resp = http
        .get(format!("{}/models", base.trim_end_matches('/')))
        .bearer_auth(key)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| AiError::Network {
            provider: "models".into(),
            message: e.to_string(),
        })?;
    let json: serde_json::Value = resp.json().await.map_err(|e| AiError::Protocol {
        provider: "models".into(),
        message: e.to_string(),
    })?;
    let mut out: Vec<String> = json["data"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|m| m["id"].as_str().map(str::to_string))
                .filter(|id| {
                    let l = id.to_lowercase();
                    ![
                        "embed",
                        "rerank",
                        "whisper",
                        "tts",
                        "dall-e",
                        "moderation",
                        "image",
                        "audio",
                        "transcribe",
                    ]
                    .iter()
                    .any(|bad| l.contains(bad))
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    Ok(out)
}

/// Is the file a script (`#!`, or a Windows `.cmd` shim) rather than a
/// native binary?
fn is_script(path: &std::path::Path) -> bool {
    use std::io::Read;
    if path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| ["cmd", "bat", "ps1"].contains(&e.to_ascii_lowercase().as_str()))
    {
        return true;
    }
    let mut head = [0u8; 2];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok_and(|_| &head == b"#!")
}

/// Looks for an executable in PATH (or checks an absolute path).
pub fn find_in_path(cmd: &str) -> Option<PathBuf> {
    let p = PathBuf::from(cmd);
    if p.components().count() > 1 {
        return p.exists().then_some(p);
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(cmd);
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let exe = dir.join(format!("{cmd}.exe"));
            if exe.is_file() {
                return Some(exe);
            }
        }
    }
    None
}

/// Reads the body of an HTTP error and summarizes it.
pub(crate) async fn http_error(provider: &str, resp: reqwest::Response) -> AiError {
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    let message = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| {
            v["error"]["message"]
                .as_str()
                .or_else(|| v["message"].as_str())
                .or_else(|| v["error"].as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| body.chars().take(500).collect());
    AiError::Http {
        provider: provider.to_string(),
        status,
        message,
    }
}

pub(crate) fn net_error(provider: &str, e: reqwest::Error) -> AiError {
    if e.is_timeout() {
        AiError::Timeout(provider.to_string())
    } else {
        AiError::Network {
            provider: provider.to_string(),
            message: e.to_string(),
        }
    }
}

/// Sends a request, retrying on transient errors (429/5xx/network).
pub(crate) async fn send_with_retry(
    provider: &str,
    build: impl Fn() -> reqwest::RequestBuilder,
    cancel: &CancellationToken,
    sink: &dyn EventSink,
) -> Result<reqwest::Response, AiError> {
    let mut attempt = 0u32;
    loop {
        let result = tokio::select! {
            _ = cancel.cancelled() => return Err(AiError::Cancelled),
            r = build().send() => r,
        };
        let err = match result {
            Ok(resp) if resp.status().is_success() => return Ok(resp),
            Ok(resp) => {
                let retry_after = resp
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok());
                let err = http_error(provider, resp).await;
                (err, retry_after)
            }
            Err(e) => (net_error(provider, e), None),
        };
        let (err, retry_after) = err;
        if !err.is_transient() || attempt >= 2 {
            return Err(err);
        }
        attempt += 1;
        let wait = retry_after.unwrap_or(2u64.pow(attempt)).min(30);
        sink.emit(StreamEvent::Notice(format!(
            "\"{provider}\" is busy ({err}); retry {attempt}/2 in {wait} s…"
        )));
        tokio::select! {
            _ = cancel.cancelled() => return Err(AiError::Cancelled),
            _ = tokio::time::sleep(Duration::from_secs(wait)) => {}
        }
    }
}

/// Validates that `input` has the schema's required fields and basic types.
/// (Tools validate again when deserializing into their types.)
pub fn parse_tool_input(raw: &str) -> Result<serde_json::Value, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(serde_json::json!({}));
    }
    serde_json::from_str::<serde_json::Value>(trimmed)
        .map_err(|_| trimmed.chars().take(2000).collect::<String>())
        .and_then(|v| {
            if v.is_object() {
                Ok(v)
            } else {
                Err(trimmed.chars().take(2000).collect())
            }
        })
}

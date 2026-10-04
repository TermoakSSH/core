//! Termoak AI engine.
//!
//! - **Multi-provider** (like VoxPanel): Claude (Messages API), OpenAI
//!   (Responses API), Codex with your ChatGPT subscription (`codex exec` CLI),
//!   OpenCode Go (OpenAI-compatible) and any compatible server (Ollama,
//!   LM Studio, vLLM...). `provider::model` format and a fallback chain.
//! - **Agent** with native SSH tools: run commands on your hosts, read/write
//!   files over SFTP, read from and write to open terminals...
//! - **Background tasks** that survive closing the app, with approvals,
//!   auditing and usage and cost tracking.
//! - **Per-user access**: each user's own API keys first; the server's
//!   providers only when the server allows it (see [`access`]).
//! - **MCP server** so Codex (or other agents) can use the same tools, always
//!   going through Termoak's permissions.

pub mod access;
pub mod agent;
pub mod assist;
pub mod config;
pub mod engine;
pub mod error;
pub mod mcp;
pub mod mcp_http;
pub mod message;
pub mod policy;
pub mod pricing;
pub mod provider;
pub mod sse;
pub mod tools;

pub use access::{AccessPolicy, ChainEntry, ChainSource, OWN_KEY_PROVIDERS, ServerAccess};
pub use config::{AiConfig, Driver, ProviderConfig};
pub use engine::{AccessInfo, AiEngine, CreateTask, TaskEvent, TaskStatus, TaskView, UserEvent};
pub use error::AiError;
pub use policy::PermissionMode;
pub use tools::{SessionAccess, SessionSummary, TerminalOutput};

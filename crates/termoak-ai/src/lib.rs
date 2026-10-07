//! Termoak AI engine.
//!
//! - **Multi-provider** (like VoxPanel): Claude (Messages API), OpenAI
//!   (Responses API), Codex with your ChatGPT subscription (`codex exec` CLI),
//!   OpenCode Go (OpenAI-compatible) and any compatible server (Ollama,
//!   LM Studio, vLLM...). `provider::model` format and a fallback chain.
//! - **Agent** with native SSH tools: run commands on your hosts, read/write
//!   files over SFTP, read from and write to open terminals...
//! - **Background tasks** that survive closing the app, with approvals
//!   (with a preview: the command and its risk, the diff of a file; editable),
//!   an optional plan to approve first, one conversation per host for
//!   multi-host tasks, runbooks from what ran, auditing and usage and cost
//!   tracking.
//! - **Secret redaction**: tool results go through [`redact()`] before the
//!   provider sees them.
//! - **Hosts from a provider** ([`HostProvider`]): the server's vaults, or
//!   whatever a client app shows (its device and account stores).
//! - **Per-user access**: each user's own API keys first; the server's
//!   providers only when the server allows it (see [`access`]).
//! - **MCP server** so Codex (or other agents) can use the same tools, always
//!   going through Termoak's permissions.

pub mod access;
pub mod agent;
pub mod approval;
pub mod assist;
pub mod config;
pub mod diff;
pub mod engine;
pub mod error;
pub mod hosts;
pub mod mcp;
pub mod mcp_http;
pub mod message;
pub mod policy;
pub mod pricing;
pub mod provider;
pub mod redact;
pub mod runbook;
pub mod sse;
pub mod tools;

pub use access::{AccessPolicy, ChainEntry, ChainSource, OWN_KEY_PROVIDERS, ServerAccess};
pub use approval::{ApprovalDecision, ApprovalPreview};
pub use config::{AiConfig, Driver, ProviderConfig};
pub use engine::{
    AccessInfo, AiEngine, CreateTask, HostRun, TaskEvent, TaskPlan, TaskStatus, TaskView, UserEvent,
};
pub use error::AiError;
pub use hosts::{GroupEntry, HostEntry, HostProvider, Inventory, VaultHosts};
pub use policy::{CommandRisk, PermissionMode, RiskLevel, RiskReason};
pub use redact::redact;
pub use runbook::{ExecutedStep, Runbook};
pub use tools::{SessionAccess, SessionSummary, TerminalOutput};

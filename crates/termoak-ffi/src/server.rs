//! Termoak server: account, sync, generic API and typed helpers for the most
//! common things (persistent sessions and background AI).
//!
//! Everything is `async` (network). The generic API (`api_get`, `api_post`...)
//! can call any endpoint in `GET /api/openapi.json` with JSON as text, without
//! waiting for a typed helper to exist.

use reqwest::Method;
use serde::Deserialize;
use serde_json::{Value, json};
use termoak_client::ApiClient;
use termoak_core::Id;

use crate::auth::PromptField;
use crate::error::{Result, TermoakError};
use crate::models::parse_id;
use crate::runtime::{block_on, run};
use crate::vault::TermoakCore;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Result of a sync. Show a notice when `discarded`, `vaults_added` or
/// `vaults_lost` is not empty ("You no longer have access to Ops; 2
/// unsynced changes were discarded").
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct SyncReport {
    /// Local changes uploaded.
    pub pushed: u64,
    /// Changes received from the server.
    pub pulled: u64,
    /// Server revision after syncing (vaults: the highest vault cursor).
    pub rev: i64,
    /// Account synced.
    #[uniffi(default)]
    pub account_id: Option<String>,
    /// Items removed because they left their vault.
    #[uniffi(default)]
    pub removed: u64,
    /// Local changes lost (the vault was lost, or became Use-only).
    #[uniffi(default)]
    pub discarded: Vec<crate::accounts::DiscardedChanges>,
    /// Vaults shared with you since the last sync.
    #[uniffi(default)]
    pub vaults_added: Vec<crate::accounts::VaultRef>,
    /// Vaults you no longer have access to (their items were removed).
    #[uniffi(default)]
    pub vaults_lost: Vec<crate::accounts::VaultRef>,
    /// `v2` (vaults) or `legacy`.
    #[uniffi(default)]
    pub protocol: String,
}

impl SyncReport {
    pub(crate) fn from_client(r: termoak_client::SyncReport, account: Id) -> Self {
        let vref = |v: &termoak_client::sync::VaultRef| crate::accounts::VaultRef {
            id: v.id.to_string(),
            name: v.name.clone(),
        };
        SyncReport {
            pushed: r.pushed as u64,
            pulled: r.pulled as u64,
            rev: r.rev,
            account_id: Some(account.to_string()),
            removed: r.removed as u64,
            discarded: r
                .discarded
                .iter()
                .map(|d| crate::accounts::DiscardedChanges {
                    vault_id: d.vault_id.to_string(),
                    vault_name: d.vault_name.clone(),
                    count: d.count as u64,
                })
                .collect(),
            vaults_added: r.vaults_added.iter().map(vref).collect(),
            vaults_lost: r.vaults_lost.iter().map(vref).collect(),
            protocol: r.protocol.to_string(),
        }
    }
}

/// HTTP method for [`TermoakCore::api_request`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

/// Permission of someone viewing a server session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SessionAccess {
    /// Owner: types, answers questions and can close or share it.
    Owner,
    /// Guest with control: can type.
    Control,
    /// Read-only guest.
    View,
}

impl SessionAccess {
    pub(crate) fn parse(s: &str) -> Self {
        match s {
            "owner" => SessionAccess::Owner,
            "control" => SessionAccess::Control,
            _ => SessionAccess::View,
        }
    }
}

/// State of a server session.
#[derive(Debug, Clone, PartialEq, uniffi::Enum)]
pub enum ServerSessionState {
    /// Connecting to the host (the message says how far it got).
    Connecting {
        message: String,
    },
    Running,
    /// Relay session whose host is disconnected (waiting for it to come back).
    HostOffline,
    Closed {
        exit_code: Option<u32>,
        reason: Option<String>,
    },
}

impl ServerSessionState {
    pub(crate) fn from_json(v: &Value) -> Self {
        match v["state"].as_str().unwrap_or("") {
            "connecting" => ServerSessionState::Connecting {
                message: v["message"].as_str().unwrap_or("").to_string(),
            },
            "running" => ServerSessionState::Running,
            "host_offline" => ServerSessionState::HostOffline,
            _ => ServerSessionState::Closed {
                exit_code: v["exit_code"].as_u64().map(|c| c as u32),
                reason: v["reason"].as_str().map(str::to_string),
            },
        }
    }
}

/// Person connected to a server session.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct SessionViewer {
    pub id: String,
    pub name: String,
    pub user_id: Option<String>,
    pub access: SessionAccess,
    /// `viewer` or `host` (the host of a relay session).
    pub role: String,
    /// Since when (ms).
    pub since: i64,
}

impl SessionViewer {
    pub(crate) fn list_from_json(v: &Value) -> Vec<Self> {
        v.as_array()
            .map(|a| {
                a.iter()
                    .map(|v| SessionViewer {
                        id: str_of(&v["id"]),
                        name: str_of(&v["name"]),
                        user_id: v["user_id"].as_str().map(str::to_string),
                        access: SessionAccess::parse(v["access"].as_str().unwrap_or("")),
                        role: str_of(&v["role"]),
                        since: v["since"].as_i64().unwrap_or(0),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Kind of participant in a shared session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ParticipantKind {
    /// The session's owner.
    Owner,
    /// A user of the server (invited directly, through a team or by link).
    User,
    /// Someone without an account who joined with a link.
    Guest,
}

/// A person in a shared session (all their devices count as one).
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct SessionParticipant {
    /// Participant id (for `grant_control`, `kick`...).
    pub id: String,
    pub name: String,
    pub kind: ParticipantKind,
    /// `Owner`, `Control` (can ask for the keyboard) or `View`.
    pub access: SessionAccess,
    /// Has the keyboard (the owner, when nobody else has it).
    pub is_driver: bool,
    /// Since when (ms).
    pub since: i64,
    /// Devices attached (0 while reconnecting).
    pub devices: u32,
    /// Asked for the keyboard and waits for the owner.
    pub requested_control: bool,
    /// In the waiting room (only in the owner's list).
    pub waiting: bool,
    /// It is you.
    pub you: bool,
    /// Only in the owner's list.
    pub user_id: Option<String>,
    /// Share they joined with (only in the owner's list).
    pub share_id: Option<String>,
}

impl From<&termoak_client::remote::Participant> for SessionParticipant {
    fn from(p: &termoak_client::remote::Participant) -> Self {
        SessionParticipant {
            id: p.id.to_string(),
            name: p.name.clone(),
            kind: match p.kind.as_str() {
                "owner" => ParticipantKind::Owner,
                "user" => ParticipantKind::User,
                _ => ParticipantKind::Guest,
            },
            access: SessionAccess::parse(&p.access),
            is_driver: p.is_driver,
            since: p.since,
            devices: p.devices,
            requested_control: p.requested_control,
            waiting: p.waiting,
            you: p.you,
            user_id: p.user_id.map(|u| u.to_string()),
            share_id: p.share_id.map(|s| s.to_string()),
        }
    }
}

impl SessionParticipant {
    pub(crate) fn list_from_json(v: &Value) -> Vec<Self> {
        termoak_client::remote::Participant::list_from_json(v)
            .iter()
            .map(Into::into)
            .collect()
    }
}

/// Live terminal session on the server (yours or shared with you).
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct ServerSession {
    pub id: String,
    pub owner_id: String,
    pub host_id: Option<String>,
    pub title: String,
    /// `server` (runs on the server) or `relay` (shared local terminal).
    pub kind: String,
    pub state: ServerSessionState,
    pub created_at: i64,
    pub cols: u32,
    pub rows: u32,
    pub recording: bool,
    /// Your permission on the session.
    pub access: SessionAccess,
    pub viewers: Vec<SessionViewer>,
    /// People in the session (servers 0.3+).
    pub participants: Vec<SessionParticipant>,
    /// Participant with the keyboard (`None`: the owner).
    pub driver: Option<String>,
    /// When the driver's timed grant ends (ms since the epoch), if timed.
    #[uniffi(default)]
    pub driver_until: Option<i64>,
    /// Name of the owner, in sessions shared with you (`None` in your own
    /// sessions and on servers before 0.3).
    #[uniffi(default)]
    pub owner_name: Option<String>,
}

impl ServerSession {
    pub(crate) fn from_json(v: &Value) -> Self {
        ServerSession {
            id: str_of(&v["id"]),
            owner_id: str_of(&v["owner_id"]),
            host_id: v["host_id"].as_str().map(str::to_string),
            title: str_of(&v["title"]),
            kind: str_of(&v["kind"]),
            state: ServerSessionState::from_json(&v["state"]),
            created_at: v["created_at"].as_i64().unwrap_or(0),
            cols: v["cols"].as_u64().unwrap_or(80) as u32,
            rows: v["rows"].as_u64().unwrap_or(24) as u32,
            recording: v["recording"].as_bool().unwrap_or(false),
            access: SessionAccess::parse(v["access"].as_str().unwrap_or("")),
            viewers: SessionViewer::list_from_json(&v["viewers"]),
            participants: SessionParticipant::list_from_json(&v["participants"]),
            driver: v["driver"].as_str().map(str::to_string),
            driver_until: v["driver_until"].as_i64(),
            owner_name: v["owner_name"]
                .as_str()
                .map(str::trim)
                .filter(|n| !n.is_empty())
                .map(str::to_string),
        }
    }
}

/// A stretch of a recording in which one person had the keyboard (from the
/// author marks of `GET /api/v1/sessions/{id}/recording/authors`). Only who
/// typed and when, not what.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct AuthorPeriod {
    /// Participant id (`None` for the AI).
    pub participant: Option<String>,
    pub name: String,
    /// `owner`, `user`, `guest` or `ai`.
    pub kind: String,
    /// Seconds since the start of the recording.
    pub from_secs: f64,
    /// Until the next person (`None`: the last one, until the end).
    pub to_secs: Option<f64>,
}

/// Who typed in a recorded session, in order.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct SessionActivity {
    /// When the recording started (ms since the epoch), if known.
    pub started_at: Option<i64>,
    /// Consecutive marks of the same person are merged into one period.
    pub periods: Vec<AuthorPeriod>,
}

impl SessionActivity {
    pub(crate) fn from_json(v: &Value) -> Self {
        let mut periods: Vec<AuthorPeriod> = Vec::new();
        let mut last: Option<(Option<String>, String)> = None;
        for a in v["authors"].as_array().into_iter().flatten() {
            let Some(time) = a["time"].as_f64() else {
                continue;
            };
            let participant = a["participant"].as_str().map(str::to_string);
            let name = a["name"].as_str().unwrap_or("").trim().to_string();
            let who = (participant.clone(), name.clone());
            if last.as_ref() == Some(&who) {
                continue;
            }
            if let Some(prev) = periods.last_mut() {
                prev.to_secs = Some(time);
            }
            periods.push(AuthorPeriod {
                participant,
                name,
                kind: a["kind"].as_str().unwrap_or("user").to_string(),
                from_secs: time,
                to_secs: None,
            });
            last = Some(who);
        }
        SessionActivity {
            started_at: v["started_at"].as_i64(),
            periods,
        }
    }
}

/// Closed session (history).
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct ServerSessionSummary {
    pub id: String,
    pub host_id: Option<String>,
    pub title: String,
    pub kind: String,
    /// `connecting`, `running`, `closed` or `failed`.
    pub status: String,
    pub created_at: i64,
    pub ended_at: Option<i64>,
    pub error: Option<String>,
    /// A recording can be downloaded (`GET /api/v1/sessions/{id}/recording`).
    pub recording: bool,
}

/// Server sessions.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct ServerSessionList {
    /// Your open sessions.
    pub active: Vec<ServerSession>,
    /// Other people's sessions shared with you.
    pub shared: Vec<ServerSession>,
    /// Recent history (closed).
    pub recent: Vec<ServerSessionSummary>,
}

/// Permission mode of an AI task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AiPermissionMode {
    /// Read-only commands only.
    ReadOnly,
    /// Asks for approval for anything that changes something.
    Ask,
    /// Asks for approval for everything run on a host, even if it only reads.
    Confirm,
    /// Autonomous.
    Auto,
}

impl AiPermissionMode {
    fn as_str(self) -> &'static str {
        match self {
            AiPermissionMode::ReadOnly => "read_only",
            AiPermissionMode::Ask => "ask",
            AiPermissionMode::Confirm => "confirm",
            AiPermissionMode::Auto => "auto",
        }
    }

    pub(crate) fn parse(s: &str) -> Self {
        match s {
            "read_only" => AiPermissionMode::ReadOnly,
            "confirm" => AiPermissionMode::Confirm,
            "auto" => AiPermissionMode::Auto,
            _ => AiPermissionMode::Ask,
        }
    }
}

/// State of an AI task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AiTaskStatus {
    Queued,
    Running,
    /// Waiting for you to approve an action.
    WaitingApproval,
    Completed,
    Failed,
    Cancelled,
    /// A state this library version does not know.
    Unknown,
}

impl AiTaskStatus {
    pub(crate) fn parse(s: &str) -> Self {
        match s {
            "queued" => AiTaskStatus::Queued,
            "running" => AiTaskStatus::Running,
            "waiting_approval" => AiTaskStatus::WaitingApproval,
            "completed" => AiTaskStatus::Completed,
            "failed" => AiTaskStatus::Failed,
            "cancelled" => AiTaskStatus::Cancelled,
            _ => AiTaskStatus::Unknown,
        }
    }
}

/// Request to create a background AI task.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct AiTaskRequest {
    /// What you want it to do, in natural language.
    pub prompt: String,
    #[uniffi(default)]
    pub title: Option<String>,
    /// If not given, the server's default mode.
    #[uniffi(default)]
    pub mode: Option<AiPermissionMode>,
    /// `provider` or `provider::model` (otherwise the default one).
    #[uniffi(default)]
    pub provider: Option<String>,
    /// Restrict the task to these hosts (empty = no restriction).
    #[uniffi(default)]
    pub host_ids: Vec<String>,
    /// Server terminal it was started from (context).
    #[uniffi(default)]
    pub session_id: Option<String>,
    /// Reasoning effort (`low`, `medium`, `high`), if the provider supports it.
    #[uniffi(default)]
    pub effort: Option<String>,
    /// The model first writes a numbered plan (without tools) that you
    /// approve, edit or deny: an approval with `tool == "plan"` and
    /// `preview.kind == "plan"`; the task's `plan` has it.
    #[uniffi(default)]
    pub plan_first: bool,
    /// Run it on the hosts of this group (and its subgroups).
    #[uniffi(default)]
    pub group_id: Option<String>,
    /// Run it on the hosts with this tag.
    #[uniffi(default)]
    pub tag: Option<String>,
    /// With several hosts: one conversation per host (the task becomes the
    /// parent; see `AiTask::hosts`) instead of one that goes through them.
    #[uniffi(default)]
    pub fan_out: bool,
}

/// AI action pending approval (or already decided).
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct AiApproval {
    pub id: String,
    pub task_id: String,
    /// Tool (`run_command`, `write_file`...).
    pub tool: String,
    /// Tool arguments (JSON).
    pub input_json: String,
    /// Readable summary of what will be done.
    pub summary: String,
    /// `pending`, `approved`, `denied`...
    pub status: String,
    pub decided_by: Option<String>,
    pub created_at: i64,
    pub decided_at: Option<i64>,
    /// What it is about (the command and its risk, the diff of a file, the
    /// plan), to show instead of `input_json`. `None` on servers before 0.6
    /// and for approvals saved by them.
    #[uniffi(default)]
    pub preview: Option<crate::ai::AiApprovalPreview>,
}

impl AiApproval {
    pub(crate) fn from_json(v: &Value) -> Self {
        AiApproval {
            id: str_of(&v["id"]),
            task_id: str_of(&v["task_id"]),
            tool: str_of(&v["tool"]),
            input_json: v["input"].to_string(),
            summary: str_of(&v["summary"]),
            status: str_of(&v["status"]),
            decided_by: v["decided_by"].as_str().map(str::to_string),
            created_at: v["created_at"].as_i64().unwrap_or(0),
            decided_at: v["decided_at"].as_i64(),
            preview: crate::ai::AiApprovalPreview::from_json(&v["preview"]),
        }
    }

    pub(crate) fn list_from_json(v: &Value) -> Vec<Self> {
        v.as_array()
            .map(|a| a.iter().map(AiApproval::from_json).collect())
            .unwrap_or_default()
    }
}

/// Background AI task.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct AiTask {
    pub id: String,
    pub title: String,
    pub prompt: String,
    pub status: AiTaskStatus,
    pub mode: AiPermissionMode,
    pub provider: String,
    /// Provider that actually answered (may be the fallback one).
    pub used_provider: Option<String>,
    pub host_ids: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub finished_at: Option<i64>,
    /// Final answer.
    pub result: Option<String>,
    pub error: Option<String>,
    /// Estimated cost in millionths of a dollar.
    pub cost_micros: i64,
    pub pending_approvals: Vec<AiApproval>,
    /// The full task as returned by the server (conversation, usage...).
    pub raw_json: String,
    /// The plan of a `plan_first` task (once the model wrote it).
    #[uniffi(default)]
    pub plan: Option<crate::ai::AiTaskPlan>,
    /// Commands and file writes it ran, in order (in `get_ai_task`).
    #[uniffi(default)]
    pub steps: Vec<crate::ai::AiTaskStep>,
    /// Multi-host (`fan_out`) task: one row per host with its own task
    /// (in `get_ai_task`).
    #[uniffi(default)]
    pub hosts: Vec<crate::ai::AiHostRun>,
    /// The multi-host task this host's conversation belongs to.
    #[uniffi(default)]
    pub parent_id: Option<String>,
    /// One conversation per host (see `hosts`).
    #[uniffi(default)]
    pub fan_out: bool,
    #[uniffi(default)]
    pub plan_first: bool,
    #[uniffi(default)]
    pub group_id: Option<String>,
    #[uniffi(default)]
    pub tag: Option<String>,
}

impl AiTask {
    pub(crate) fn from_json(v: &Value) -> Self {
        AiTask {
            id: str_of(&v["id"]),
            title: str_of(&v["title"]),
            prompt: str_of(&v["prompt"]),
            status: AiTaskStatus::parse(v["status"].as_str().unwrap_or("")),
            mode: AiPermissionMode::parse(v["mode"].as_str().unwrap_or("")),
            provider: str_of(&v["provider"]),
            used_provider: v["used_provider"].as_str().map(str::to_string),
            host_ids: v["host_ids"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|i| i.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
            created_at: v["created_at"].as_i64().unwrap_or(0),
            updated_at: v["updated_at"].as_i64().unwrap_or(0),
            finished_at: v["finished_at"].as_i64(),
            result: v["result"].as_str().map(str::to_string),
            error: v["error"].as_str().map(str::to_string),
            cost_micros: v["cost_micros"].as_i64().unwrap_or(0),
            pending_approvals: AiApproval::list_from_json(&v["pending_approvals"]),
            raw_json: v.to_string(),
            plan: crate::ai::AiTaskPlan::from_json(&v["plan"]),
            steps: crate::ai::AiTaskStep::list_from_json(&v["steps"]),
            hosts: crate::ai::AiHostRun::list_from_json(&v["hosts"]),
            parent_id: v["parent_id"].as_str().map(str::to_string),
            fan_out: v["fan_out"].as_bool().unwrap_or(false),
            plan_first: v["plan_first"].as_bool().unwrap_or(false),
            group_id: v["group_id"].as_str().map(str::to_string),
            tag: v["tag"].as_str().map(str::to_string),
        }
    }
}

/// One of your own AI API keys. The key itself never comes back from the
/// server: `hint` has its last 4 characters.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct AiKeyInfo {
    /// `claude`, `gpt`, `openrouter` or `opencode-api`.
    pub provider: String,
    /// Display name of the provider.
    pub label: String,
    /// Model chosen for it (`None` = the provider's default).
    pub model: Option<String>,
    /// Last 4 characters of the key.
    pub hint: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl From<termoak_client::api::AiKeyInfo> for AiKeyInfo {
    fn from(k: termoak_client::api::AiKeyInfo) -> Self {
        AiKeyInfo {
            provider: k.provider,
            label: k.label,
            model: k.model,
            hint: k.hint,
            created_at: k.created_at,
            updated_at: k.updated_at,
        }
    }
}

/// Result of checking an AI key with its provider.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct AiKeyTestResult {
    pub ok: bool,
    /// What the provider said, when it failed.
    pub error: Option<String>,
    /// HTTP status of the provider (401/403 usually mean a wrong key).
    pub status: Option<u16>,
}

/// A provider that accepts your own API key.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct AiKeyProvider {
    pub provider: String,
    pub label: String,
    pub default_model: Option<String>,
    /// Suggested models (others can be typed).
    pub models: Vec<String>,
}

/// Your AI situation, to explain it in the AI settings.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct AiAccessInfo {
    /// Providers with one of your own API keys (used first, no credit spent).
    pub own_keys: Vec<String>,
    /// Your plan can use the server's AI providers.
    pub server_ai: bool,
    /// Monthly credit (USD) for the server's providers (`None` = no cap, or
    /// no server AI).
    pub credit_usd: Option<f64>,
    /// Spent this month on the server's providers (USD).
    pub spent_usd: f64,
    /// Credit left this month (`None` when there is no credit).
    pub remaining_usd: Option<f64>,
    /// Providers that accept your own API key.
    pub providers: Vec<AiKeyProvider>,
}

impl From<termoak_client::api::AiAccess> for AiAccessInfo {
    fn from(a: termoak_client::api::AiAccess) -> Self {
        AiAccessInfo {
            own_keys: a.own_keys,
            server_ai: a.server_ai,
            credit_usd: a.credit_usd,
            spent_usd: a.spent_usd,
            remaining_usd: a.remaining_usd,
            providers: a
                .providers
                .into_iter()
                .map(|p| AiKeyProvider {
                    provider: p.provider,
                    label: p.label,
                    default_model: p.default_model,
                    models: p.models,
                })
                .collect(),
        }
    }
}

/// Authentication question of a server session (owner only).
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct ServerPrompt {
    pub prompt_id: String,
    /// `hostkey`, `keyboard_interactive`, `password` or `passphrase`.
    pub kind: String,
    pub host: String,
    pub message: String,
    pub fields: Vec<PromptField>,
    /// Only for `hostkey`.
    pub fingerprint: Option<String>,
    pub key_type: Option<String>,
}

impl ServerPrompt {
    pub(crate) fn from_json(v: &Value) -> Self {
        ServerPrompt {
            prompt_id: str_of(&v["prompt_id"]),
            kind: str_of(&v["kind"]),
            host: str_of(&v["host"]),
            message: str_of(&v["message"]),
            fields: v["prompts"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|p| PromptField {
                            text: str_of(&p["text"]),
                            echo: p["echo"].as_bool().unwrap_or(false),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            fingerprint: v["fingerprint"].as_str().map(str::to_string),
            key_type: v["key_type"].as_str().map(str::to_string),
        }
    }
}

pub(crate) fn str_of(v: &Value) -> String {
    v.as_str().unwrap_or_default().to_string()
}

fn parse_json_body(body: Option<String>) -> Result<Option<Value>> {
    match body.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(b) => Ok(Some(serde_json::from_str(b)?)),
    }
}

fn check_path(path: &str) -> Result<()> {
    if path.starts_with("/api/") {
        Ok(())
    } else {
        Err(TermoakError::Invalid(format!(
            "the path must start with /api/ (got \"{path}\")"
        )))
    }
}

// ---------------------------------------------------------------------------
// Account, sync and API
// ---------------------------------------------------------------------------

/// Public information about a server (version, whether it needs initial
/// setup...), without signing in. Useful to validate the URL.
#[uniffi::export]
pub async fn server_info(url: String) -> Result<String> {
    crate::vault::install_crypto_provider();
    run(async move {
        let api = ApiClient::new(&url)?;
        Ok(api.info().await?.to_string())
    })
    .await
}

impl TermoakCore {
    /// The account this object works with: the bound one
    /// ([`AccountHandle`](crate::AccountHandle)) or the current one.
    pub(crate) fn account_now(&self) -> Result<std::sync::Arc<termoak_client::Account>> {
        match self.pinned {
            Some(id) => Ok(self.ws.require_account(id)?),
            None => self.ws.current().ok_or_else(|| {
                TermoakError::NotLoggedIn("you are not signed in to any server".into())
            }),
        }
    }

    /// Signed-in server client.
    pub(crate) async fn api(&self) -> Result<ApiClient> {
        let acc = self.account_now()?;
        if acc.is_signed_in() {
            return Ok(acc.api.clone());
        }
        Err(if acc.session_expired() {
            TermoakError::SessionExpired("the session has expired: sign in again".into())
        } else {
            TermoakError::NotLoggedIn("you are not signed in to any server".into())
        })
    }

    /// Runs `f` with the server client, on the library's runtime.
    pub(crate) async fn with_api<T, F, Fut>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(ApiClient) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<T>> + Send,
    {
        let api = self.api().await?;
        run(async move { f(api).await }).await
    }

    /// Client of the account of a host: `account_id`, the bound account,
    /// the account whose store has the host, or the current one.
    pub(crate) async fn api_for_host(
        &self,
        host_id: Id,
        account_id: &Option<String>,
    ) -> Result<ApiClient> {
        let account = match crate::models::parse_opt_id(account_id)?.or(self.pinned) {
            Some(a) => Some(a),
            None => {
                let ws = self.ws.clone();
                run(async move { Ok(ws.locate(host_id).await.ok()) })
                    .await?
                    .and_then(|item| item.scope.account())
            }
        };
        match account {
            Some(a) => {
                let acc = self.ws.require_account(a)?;
                if acc.is_signed_in() {
                    Ok(acc.api.clone())
                } else if acc.session_expired() {
                    Err(TermoakError::SessionExpired(
                        "the session has expired: sign in again".into(),
                    ))
                } else {
                    Err(TermoakError::NotLoggedIn(
                        "this account is signed out: sign in again".into(),
                    ))
                }
            }
            None => self.api().await,
        }
    }

    /// Runs `f` with the client of a host's account.
    pub(crate) async fn with_host_api<T, F, Fut>(
        &self,
        host_id: Id,
        account_id: &Option<String>,
        f: F,
    ) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(ApiClient) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<T>> + Send,
    {
        let api = self.api_for_host(host_id, account_id).await?;
        run(async move { f(api).await }).await
    }
}

#[uniffi::export]
impl TermoakCore {
    /// Name this device shows up with on the server (device list, audit log,
    /// "approved from…"). Call it before `login` or `register`, e.g. with
    /// `UIDevice.current.name` or `Build.MODEL`.
    pub fn set_device_name(&self, name: String) -> Result<()> {
        Ok(block_on(self.ws.set_device_name(&name))?)
    }

    /// Current device name.
    pub fn device_name(&self) -> Result<String> {
        Ok(block_on(self.ws.device_name())?)
    }

    /// Signs in to a server and remembers it (the tokens are stored encrypted
    /// in the vault and refreshed automatically).
    ///
    /// If the account has two-factor authentication and no `totp_code` is
    /// given, it fails with `TotpRequired`: ask for the code (from the
    /// authenticator app, or a recovery code) and repeat the call with it.
    ///
    /// On a server that requires a verified email, an account that has not
    /// verified it still signs in, but can only manage itself: check
    /// `verification_required` afterwards (the server emails a new code if
    /// the previous one expired).
    #[uniffi::method(default(totp_code))]
    pub async fn login(
        &self,
        url: String,
        email: String,
        password: String,
        totp_code: Option<String>,
    ) -> Result<()> {
        let ws = self.ws.clone();
        let code = totp_code
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty());
        crate::vault::install_crypto_provider();
        run(async move {
            ws.login_with_code(&url, &email, &password, code.as_deref())
                .await?;
            Ok(())
        })
        .await
    }

    /// Creates an account (the server's first user is the admin) and signs in.
    /// When registration is closed, an invitation code is required (see
    /// [`invite_info`](crate::invite_info)).
    ///
    /// On a server that requires a verified email (`features.email_verification`
    /// in `server_info`), the new account must enter the six-digit code from
    /// the email before using the server: check `verification_required`
    /// afterwards and show the code screen (`verify_code`, `resend_code`).
    /// Accounts created from an invitation sent to the same email are
    /// verified already.
    #[uniffi::method(default(invite))]
    pub async fn register(
        &self,
        url: String,
        email: String,
        name: String,
        password: String,
        invite: Option<String>,
    ) -> Result<()> {
        let ws = self.ws.clone();
        let invite = invite
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty());
        crate::vault::install_crypto_provider();
        run(async move {
            ws.register_with_invite(&url, &email, &name, &password, invite.as_deref())
                .await?;
            Ok(())
        })
        .await
    }

    /// Whether the signed-in account still has to verify its email before
    /// using the server. Ask after `login` or `register`: when `true`, show
    /// the screen to enter the six-digit code from the email (`verify_code`)
    /// with a "resend" button (`resend_code`). Until then, everything except
    /// the account itself fails with `EmailNotVerified`.
    pub async fn verification_required(&self) -> Result<bool> {
        self.with_api(|api| async move { Ok(api.verification_required().await?) })
            .await
    }

    /// Verifies the account's email with the six-digit code from the
    /// verification email and signs in to the server (like `login`: the
    /// tokens are stored encrypted in the vault). Works whether or not
    /// `register` or `login` were called before on this device.
    ///
    /// A wrong or expired code fails with `Invalid` (the code is used up
    /// after 5 wrong tries: ask for another one with `resend_code`); too many
    /// tries in a few minutes fail with `Server` (HTTP 429). If the account
    /// already has two-factor authentication it fails with `TotpRequired`:
    /// repeat with `totp_code`.
    #[uniffi::method(default(totp_code))]
    pub async fn verify_code(
        &self,
        url: String,
        email: String,
        code: String,
        totp_code: Option<String>,
    ) -> Result<()> {
        let ws = self.ws.clone();
        let totp = totp_code
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty());
        // Codes are often pasted with spaces or dashes ("123 456").
        let code: String = code.chars().filter(char::is_ascii_digit).collect();
        run(async move {
            ws.verify_code(&url, &email, &code, totp.as_deref()).await?;
            Ok(())
        })
        .await
    }

    /// Emails a new six-digit verification code to `email` on the server at
    /// `url` (no sign-in needed). It succeeds whether or not that account
    /// exists; asking more than once a minute (or five times an hour) fails
    /// with `Server` (HTTP 429).
    pub async fn resend_code(&self, url: String, email: String) -> Result<()> {
        let ws = self.ws.clone();
        run(async move { Ok(ws.resend_code(&url, &email).await?) }).await
    }

    /// Signs the current account out of its server. Its local data is kept
    /// (the account asks to sign in again); `sign_out_account` also deletes
    /// it.
    pub async fn logout(&self) -> Result<()> {
        let ws = self.ws.clone();
        run(async move { Ok(ws.logout().await?) }).await
    }

    /// Whether the current account is signed in (with saved tokens).
    pub async fn is_logged_in(&self) -> Result<bool> {
        match self.api().await {
            Ok(_) => Ok(true),
            Err(TermoakError::NotLoggedIn(_) | TermoakError::SessionExpired(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// URL of the current account's server (if signed in).
    pub async fn server_url(&self) -> Result<Option<String>> {
        match self.api().await {
            Ok(api) => Ok(Some(api.base_url().to_string())),
            Err(TermoakError::NotLoggedIn(_) | TermoakError::SessionExpired(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Email of the current account.
    pub async fn server_user(&self) -> Result<Option<String>> {
        Ok(self.account_now().ok().map(|a| a.info().email))
    }

    /// One sync round of the current account: uploads local changes and
    /// downloads the server's (last writer wins). `DeviceOnly` records never
    /// leave the device.
    pub async fn sync_now(&self) -> Result<SyncReport> {
        let acc = self.account_now()?;
        self.api().await?;
        run(async move {
            let r = acc.sync_once().await?;
            Ok(SyncReport::from_client(r, acc.id))
        })
        .await
    }

    /// Forgets the sync position of the current account: the next round
    /// downloads everything.
    pub async fn reset_sync(&self) -> Result<()> {
        let acc = self.account_now()?;
        self.api().await?;
        run(async move { Ok(acc.sync_engine().reset().await?) }).await
    }

    // ----- Generic API -----

    /// Authenticated request to any JSON endpoint of the server. `path` starts
    /// with `/api/` (it may include a query), `body_json` is the JSON body (or
    /// `nil`). Returns the response as JSON (`null` if it was empty).
    pub async fn api_request(
        &self,
        method: HttpMethod,
        path: String,
        body_json: Option<String>,
    ) -> Result<String> {
        check_path(&path)?;
        let body = parse_json_body(body_json)?;
        let method = match method {
            HttpMethod::Get => Method::GET,
            HttpMethod::Post => Method::POST,
            HttpMethod::Put => Method::PUT,
            HttpMethod::Patch => Method::PATCH,
            HttpMethod::Delete => Method::DELETE,
        };
        self.with_api(move |api| async move {
            let v: Value = api.request(method, &path, body.as_ref()).await?;
            Ok(v.to_string())
        })
        .await
    }

    pub async fn api_get(&self, path: String) -> Result<String> {
        self.api_request(HttpMethod::Get, path, None).await
    }

    pub async fn api_post(&self, path: String, body_json: Option<String>) -> Result<String> {
        self.api_request(HttpMethod::Post, path, body_json).await
    }

    pub async fn api_put(&self, path: String, body_json: Option<String>) -> Result<String> {
        self.api_request(HttpMethod::Put, path, body_json).await
    }

    pub async fn api_patch(&self, path: String, body_json: Option<String>) -> Result<String> {
        self.api_request(HttpMethod::Patch, path, body_json).await
    }

    pub async fn api_delete(&self, path: String) -> Result<String> {
        self.api_request(HttpMethod::Delete, path, None).await
    }

    // ----- Server sessions -----

    /// Your open sessions, sessions shared with you, and history.
    pub async fn list_server_sessions(&self) -> Result<ServerSessionList> {
        self.with_api(|api| async move {
            let v: Value = api.get("/api/v1/sessions").await?;
            let live = |key: &str| -> Vec<ServerSession> {
                v[key]
                    .as_array()
                    .map(|a| a.iter().map(ServerSession::from_json).collect())
                    .unwrap_or_default()
            };
            Ok(ServerSessionList {
                active: live("active"),
                shared: live("shared"),
                recent: v["recent"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|s| ServerSessionSummary {
                                id: str_of(&s["id"]),
                                host_id: s["host_id"].as_str().map(str::to_string),
                                title: str_of(&s["title"]),
                                kind: str_of(&s["kind"]),
                                status: str_of(&s["status"]),
                                created_at: s["created_at"].as_i64().unwrap_or(0),
                                ended_at: s["ended_at"].as_i64(),
                                error: s["error"].as_str().map(str::to_string),
                                recording: s["recording"].as_bool().unwrap_or(false),
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        })
        .await
    }

    /// Opens a persistent terminal on the server to a synced host. It stays
    /// alive even if the phone disconnects; to see it, use
    /// `attach_server_session`. The session opens on the host's account
    /// (`account_id`, or the account that has the host).
    #[uniffi::method(default(account_id))]
    pub async fn open_server_session(
        &self,
        host_id: String,
        cols: u32,
        rows: u32,
        title: Option<String>,
        record: Option<bool>,
        account_id: Option<String>,
    ) -> Result<ServerSession> {
        let hid = parse_id(&host_id)?;
        self.with_host_api(hid, &account_id, move |api| async move {
            let v: Value = api
                .post(
                    "/api/v1/sessions",
                    &json!({"host_id": host_id, "cols": cols.min(1000), "rows": rows.min(500), "title": title, "record": record}),
                )
                .await?;
            Ok(ServerSession::from_json(&v))
        })
        .await
    }

    /// State of a live session.
    pub async fn get_server_session(&self, session_id: String) -> Result<ServerSession> {
        let id = parse_id(&session_id)?;
        self.with_api(move |api| async move {
            let v: Value = api.get(&format!("/api/v1/sessions/{id}")).await?;
            Ok(ServerSession::from_json(&v))
        })
        .await
    }

    /// Who typed in a recorded session and when (owner only), from the
    /// author marks of its recording. `None` if the session was not recorded.
    pub async fn session_activity(&self, session_id: String) -> Result<Option<SessionActivity>> {
        let id = parse_id(&session_id)?;
        self.with_api(move |api| async move {
            match api
                .get::<Value>(&format!("/api/v1/sessions/{id}/recording/authors"))
                .await
            {
                Ok(v) => Ok(Some(SessionActivity::from_json(&v))),
                Err(e) if e.api_code() == Some("recording_not_found") => Ok(None),
                Err(e) => Err(e.into()),
            }
        })
        .await
    }

    /// Closes a server session (owner only).
    pub async fn close_server_session(&self, session_id: String) -> Result<()> {
        let id = parse_id(&session_id)?;
        self.with_api(move |api| async move {
            api.delete(&format!("/api/v1/sessions/{id}")).await?;
            Ok(())
        })
        .await
    }

    // ----- Background AI -----

    /// Creates an AI task that runs on the server even if you close the app.
    /// Actions that change something wait for your approval (`Ask` mode): they
    /// show up in `pending_approvals` and on the events WebSocket.
    pub async fn create_ai_task(&self, request: AiTaskRequest) -> Result<AiTask> {
        for h in &request.host_ids {
            parse_id(h)?;
        }
        if let Some(s) = &request.session_id {
            parse_id(s)?;
        }
        if let Some(g) = &request.group_id {
            parse_id(g)?;
        }
        let mut body = json!({
            "prompt": request.prompt,
            "title": request.title,
            "mode": request.mode.map(AiPermissionMode::as_str),
            "provider": request.provider,
            "host_ids": if request.host_ids.is_empty() { Value::Null } else { json!(request.host_ids) },
            "session_id": request.session_id,
            "effort": request.effort,
        });
        // Only when asked: servers before 0.6 refuse nothing, but keep the
        // body as it was for plain tasks.
        if request.plan_first {
            body["plan_first"] = json!(true);
        }
        if request.fan_out {
            body["fan_out"] = json!(true);
        }
        if let Some(g) = request.group_id {
            body["group_id"] = json!(g);
        }
        if let Some(t) = request
            .tag
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
        {
            body["tag"] = json!(t);
        }
        self.with_api(move |api| async move {
            let v: Value = api.post("/api/v1/ai/tasks", &body).await?;
            Ok(AiTask::from_json(&v))
        })
        .await
    }

    /// AI tasks, newest first.
    pub async fn list_ai_tasks(&self, limit: u32) -> Result<Vec<AiTask>> {
        self.with_api(move |api| async move {
            let v: Value = api
                .get(&format!("/api/v1/ai/tasks?limit={}", limit.clamp(1, 500)))
                .await?;
            Ok(v.as_array()
                .map(|a| a.iter().map(AiTask::from_json).collect())
                .unwrap_or_default())
        })
        .await
    }

    /// A task with its full conversation (in `raw_json`).
    pub async fn get_ai_task(&self, task_id: String) -> Result<AiTask> {
        let id = parse_id(&task_id)?;
        self.with_api(move |api| async move {
            let v: Value = api.get(&format!("/api/v1/ai/tasks/{id}")).await?;
            Ok(AiTask::from_json(&v))
        })
        .await
    }

    /// Continues a task's conversation.
    pub async fn send_ai_message(&self, task_id: String, text: String) -> Result<AiTask> {
        let id = parse_id(&task_id)?;
        self.with_api(move |api| async move {
            let v: Value = api
                .post(
                    &format!("/api/v1/ai/tasks/{id}/messages"),
                    &json!({"text": text}),
                )
                .await?;
            Ok(AiTask::from_json(&v))
        })
        .await
    }

    pub async fn cancel_ai_task(&self, task_id: String) -> Result<()> {
        let id = parse_id(&task_id)?;
        self.with_api(move |api| async move {
            api.post::<Value>(&format!("/api/v1/ai/tasks/{id}/cancel"), &json!({}))
                .await?;
            Ok(())
        })
        .await
    }

    /// Changes the permission mode of a running task.
    pub async fn set_ai_task_mode(&self, task_id: String, mode: AiPermissionMode) -> Result<()> {
        let id = parse_id(&task_id)?;
        self.with_api(move |api| async move {
            api.post::<Value>(
                &format!("/api/v1/ai/tasks/{id}/mode"),
                &json!({"mode": mode.as_str()}),
            )
            .await?;
            Ok(())
        })
        .await
    }

    // ----- Your own AI API keys -----

    /// Your own AI API keys (without the keys).
    pub async fn list_ai_keys(&self) -> Result<Vec<AiKeyInfo>> {
        self.with_api(|api| async move {
            Ok(api.ai_keys().await?.into_iter().map(Into::into).collect())
        })
        .await
    }

    /// Saves your own API key for `claude`, `gpt`, `openrouter` or
    /// `opencode-api` (replacing the one you had). It is used instead of the
    /// server's key for that provider and never spends your plan's AI credit.
    /// With `key` `None`, only the model of the saved key changes
    /// (`NotFound` if there is none). `model` empty or `None` = the
    /// provider's default.
    pub async fn set_ai_key(
        &self,
        provider: String,
        key: Option<String>,
        model: Option<String>,
    ) -> Result<AiKeyInfo> {
        self.with_api(move |api| async move {
            Ok(api
                .set_ai_key(&provider, key.as_deref(), model.as_deref())
                .await?
                .into())
        })
        .await
    }

    /// Deletes your own API key for a provider. `false` if there was none.
    pub async fn delete_ai_key(&self, provider: String) -> Result<bool> {
        self.with_api(move |api| async move { Ok(api.delete_ai_key(&provider).await?) })
            .await
    }

    /// Checks a key with its provider, with a call that spends nothing:
    /// `key`, or the saved one if `None`. At most 10 per minute.
    pub async fn test_ai_key(
        &self,
        provider: String,
        key: Option<String>,
    ) -> Result<AiKeyTestResult> {
        self.with_api(move |api| async move {
            let t = api.test_ai_key(&provider, key.as_deref()).await?;
            Ok(AiKeyTestResult {
                ok: t.ok,
                error: t.error,
                status: t.status,
            })
        })
        .await
    }

    /// Your AI situation: own keys, whether your plan includes the server's
    /// AI, its credit and this month's spending.
    pub async fn ai_access(&self) -> Result<AiAccessInfo> {
        self.with_api(|api| async move { Ok(api.ai_access().await?.into()) })
            .await
    }

    /// AI actions pending approval (from all tasks).
    pub async fn list_pending_approvals(&self) -> Result<Vec<AiApproval>> {
        self.with_api(|api| async move {
            let v: Value = api.get("/api/v1/ai/approvals").await?;
            Ok(AiApproval::list_from_json(&v))
        })
        .await
    }

    /// Approves or denies an action. `always` also approves the task's next
    /// actions (switches to autonomous mode).
    pub async fn decide_approval(
        &self,
        task_id: String,
        approval_id: String,
        approve: bool,
        always: bool,
    ) -> Result<()> {
        let task = parse_id(&task_id)?;
        let approval = parse_id(&approval_id)?;
        self.with_api(move |api| async move {
            api.post::<Value>(
                &format!("/api/v1/ai/tasks/{task}/approvals/{approval}"),
                &json!({"approve": approve, "always": always}),
            )
            .await?;
            Ok(())
        })
        .await
    }
}

/// Response of `GET /api/v1/join/{token}`.
#[derive(Debug, Deserialize)]
pub(crate) struct JoinInfo {
    pub ws_path: String,
    #[serde(default)]
    pub session: Value,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub permission: String,
    #[serde(default)]
    pub require_approval: bool,
    #[serde(default)]
    pub expires_at: Option<i64>,
}

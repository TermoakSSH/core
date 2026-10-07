//! Background AI task engine.
//!
//! A task is a conversation with the agent that runs on the server even if
//! you close the app: it publishes live events, saves the transcript, asks
//! for approvals (which you can give from another device), records usage and
//! cost, and is audited.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use termoak_core::crypto::{prefixed_token, sha256_hex};
use termoak_core::store::{AiApprovalRow, AiEventRow, AiTaskRow, AiUsageRow};
use termoak_core::time::now_ms;
use termoak_core::{Id, Store, new_id};
use termoak_ssh::ConnectionPool;
use tokio::sync::{Semaphore, broadcast, oneshot};
use tokio_util::sync::CancellationToken;

use crate::access::{AccessPolicy, ChainEntry, OwnKey, ServerAccess, build_chain, usd_to_micros};
use crate::agent::{AgentHooks, AgentOutcome, AgentRun, PLAN_PROMPT, SYSTEM_PROMPT, run_agent};
use crate::approval::{ApprovalDecision, ApprovalPreview};
use crate::config::{AiConfig, Driver, split_spec};
use crate::error::AiError;
use crate::message::{Message, Part, Usage};
use crate::policy::{PermissionMode, Verdict, decide};
use crate::pricing::{
    CODEX_CREDIT_PRICE, DEFAULT_CREDIT_PRICE, UsageCost, builtin_price, cost_micros, credit_micros,
};
use crate::provider::{ProviderInfo, REASON_OWN_KEY_REQUIRED, REASON_PLAN, Registry};
use crate::redact::redact_context_blocks;
use crate::runbook::{ExecutedStep, HostNames, MAX_STEP_CONTENT, Runbook};
use crate::tools::{
    SessionAccess, ToolContext, ToolLimits, ToolOutcome, ToolRuntime, truncate_middle,
};

/// Task status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Queued,
    Running,
    WaitingApproval,
    Completed,
    Failed,
    Cancelled,
}

impl TaskStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            TaskStatus::Queued => "queued",
            TaskStatus::Running => "running",
            TaskStatus::WaitingApproval => "waiting_approval",
            TaskStatus::Completed => "completed",
            TaskStatus::Failed => "failed",
            TaskStatus::Cancelled => "cancelled",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "queued" => TaskStatus::Queued,
            "running" => TaskStatus::Running,
            "waiting_approval" => TaskStatus::WaitingApproval,
            "completed" => TaskStatus::Completed,
            "cancelled" => TaskStatus::Cancelled,
            _ => TaskStatus::Failed,
        }
    }

    pub fn is_active(self) -> bool {
        matches!(
            self,
            TaskStatus::Queued | TaskStatus::Running | TaskStatus::WaitingApproval
        )
    }
}

/// Task events (live text events are not persisted).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TaskEvent {
    Status {
        status: TaskStatus,
    },
    /// Text chunk of the response in progress.
    Text {
        delta: String,
    },
    /// Chunk of the reasoning (summary) in progress.
    Reasoning {
        delta: String,
    },
    /// Notice (retries, switching to a fallback provider...).
    Notice {
        message: String,
    },
    /// Discard the text in progress (the provider failed midway).
    Reset,
    ToolCall {
        call_id: String,
        tool: String,
        summary: String,
        input: Value,
        needs_approval: bool,
    },
    ToolResult {
        call_id: String,
        ok: bool,
        output: String,
        duration_ms: u64,
    },
    ApprovalRequested {
        approval_id: Id,
        call_id: String,
        /// The tool, or `plan` for the plan of a "plan before acting" task.
        tool: String,
        summary: String,
        input: Value,
        /// What to show: the command with its risk and reasons, the diff of
        /// a file, the plan... (see [`ApprovalPreview`]).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        preview: Option<ApprovalPreview>,
    },
    ApprovalDecided {
        approval_id: Id,
        approved: bool,
        by: String,
        /// The command or plan the user approved instead of the model's.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        edited: Option<String>,
        /// Why it was denied (sent to the model).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Complete message (at the end of each turn).
    Message {
        role: String,
        text: String,
        provider: Option<String>,
    },
    Usage {
        provider: String,
        input_tokens: u64,
        output_tokens: u64,
        cost_micros: i64,
        /// Taken from the plan's AI credit (0 with the user's own key).
        #[serde(default)]
        credit_micros: i64,
        /// Run with the user's own API key (it does not use the plan's credit).
        #[serde(default)]
        own_key: bool,
    },
    Finished {
        status: TaskStatus,
        result: Option<String>,
        error: Option<String>,
    },
}

impl TaskEvent {
    fn kind(&self) -> &'static str {
        match self {
            TaskEvent::Status { .. } => "status",
            TaskEvent::Text { .. } => "text",
            TaskEvent::Reasoning { .. } => "reasoning",
            TaskEvent::Notice { .. } => "notice",
            TaskEvent::Reset => "reset",
            TaskEvent::ToolCall { .. } => "tool_call",
            TaskEvent::ToolResult { .. } => "tool_result",
            TaskEvent::ApprovalRequested { .. } => "approval_requested",
            TaskEvent::ApprovalDecided { .. } => "approval_decided",
            TaskEvent::Message { .. } => "message",
            TaskEvent::Usage { .. } => "usage",
            TaskEvent::Finished { .. } => "finished",
        }
    }

    fn persisted(&self) -> bool {
        !matches!(
            self,
            TaskEvent::Text { .. } | TaskEvent::Reasoning { .. } | TaskEvent::Reset
        )
    }
}

/// Event addressed to a user (for the events WebSocket and push notifications).
#[derive(Debug, Clone, Serialize)]
pub struct UserEvent {
    #[serde(skip)]
    pub owner: Id,
    pub task_id: Id,
    /// Persisted sequence (0 for live events that are not saved).
    pub seq: i64,
    pub event: TaskEvent,
}

/// New task request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CreateTask {
    pub prompt: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub mode: Option<PermissionMode>,
    /// `provider` or `provider::model` (the default one otherwise).
    #[serde(default)]
    pub provider: Option<String>,
    /// Limit the task to these hosts.
    #[serde(default)]
    pub host_ids: Option<Vec<Id>>,
    /// Terminal it was launched from (context).
    #[serde(default)]
    pub session_id: Option<Id>,
    #[serde(default)]
    pub effort: Option<String>,
    /// Run it on the hosts of this group (and its subgroups).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<Id>,
    /// Run it on the hosts with this tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// With several hosts: one conversation per host (the same request,
    /// [`AiConfig::fan_out_concurrency`] at a time) instead of one
    /// conversation that goes through them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fan_out: Option<bool>,
    /// The model first writes a short numbered plan (without tools) that the
    /// user approves or edits (an approval with `tool: "plan"`) before it
    /// starts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_first: Option<bool>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// One host of a multi-host task (its row in the per-host table).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostRun {
    pub host_id: Id,
    pub label: String,
    /// The host's own task (its conversation).
    pub task_id: Id,
    pub status: TaskStatus,
    /// Its result, shortened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<i64>,
    pub cost_micros: i64,
    #[serde(default)]
    pub pending_approvals: usize,
}

/// The plan of a "plan before acting" task.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskPlan {
    pub text: String,
    pub approved: bool,
    /// The user edited it before approving it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub edited: bool,
}

/// Public view of a task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskView {
    pub id: Id,
    pub title: String,
    pub prompt: String,
    pub status: TaskStatus,
    pub mode: PermissionMode,
    pub provider: String,
    pub used_provider: Option<String>,
    pub host_ids: Option<Vec<Id>>,
    pub created_at: i64,
    pub updated_at: i64,
    pub finished_at: Option<i64>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub cost_micros: i64,
    pub usage: Usage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub messages: Option<Vec<Message>>,
    pub pending_approvals: Vec<AiApprovalRow>,
    /// The multi-host task this host's conversation belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<Id>,
    /// A multi-host task: one conversation per host (see `hosts`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub fan_out: bool,
    /// Per-host table of a multi-host task (with `GET` of one task).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<HostRun>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// "Plan before acting".
    #[serde(default, skip_serializing_if = "is_false")]
    pub plan_first: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<TaskPlan>,
    /// Commands and file writes it ran, in order (with the messages).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<ExecutedStep>,
}

/// A host's conversation in a multi-host task.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct ChildRef {
    task_id: Id,
    host_id: Id,
    label: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TaskContext {
    #[serde(default)]
    host_ids: Option<Vec<Id>>,
    #[serde(default)]
    session_id: Option<Id>,
    #[serde(default)]
    effort: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    group_id: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    plan_first: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    plan: Option<TaskPlan>,
    #[serde(default, skip_serializing_if = "is_false")]
    fan_out: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    children: Vec<ChildRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent_id: Option<Id>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    steps: Vec<ExecutedStep>,
    /// When the last run started (for the duration in the per-host table).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    started_at: Option<i64>,
}

/// Most steps kept per task.
const MAX_STEPS_KEPT: usize = 500;
/// Plans the model may propose again after a rejection with a reason.
const MAX_PLAN_ROUNDS: usize = 3;

struct LiveTask {
    id: Id,
    owner: Id,
    /// The multi-host task it belongs to.
    parent: Option<Id>,
    cancel: CancellationToken,
    mode: Mutex<PermissionMode>,
    approvals: Mutex<HashMap<Id, oneshot::Sender<ApprovalDecision>>>,
    ctx: ToolContext,
    /// The task's context (plan, executed steps...), saved with each checkpoint.
    task_ctx: Mutex<TaskContext>,
}

struct McpGrant {
    owner: Id,
    task_id: Id,
}

/// AI engine.
pub struct AiEngine {
    store: Store,
    registry: Registry,
    tools: ToolRuntime,
    live: Mutex<HashMap<Id, Arc<LiveTask>>>,
    seqs: Mutex<HashMap<Id, Arc<AtomicI64>>>,
    bus: broadcast::Sender<UserEvent>,
    mcp_tokens: Mutex<HashMap<String, McpGrant>>,
    mcp_url: Mutex<Option<String>>,
    policy: Mutex<Option<Arc<dyn AccessPolicy>>>,
    chain_source: Mutex<Option<Arc<dyn crate::access::ChainSource>>>,
}

/// A user's AI situation: their own keys and the server's AI.
#[derive(Debug, Clone, PartialEq)]
pub struct AccessInfo {
    /// Providers with a key of the user's that can be used.
    pub own_keys: Vec<String>,
    /// Can they use the server's providers?
    pub server_ai: bool,
    /// Monthly credit for the server's providers (`None` = unlimited).
    pub credit_micros: Option<i64>,
    /// Credit spent this month on the server's providers.
    pub spent_micros: i64,
}

/// Start of the current month (UTC), in milliseconds: the credit period.
pub fn month_start_ms() -> i64 {
    chrono::Utc::now()
        .date_naive()
        .with_day0(0)
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|d| d.and_utc().timestamp_millis())
        .unwrap_or(0)
}

impl AiEngine {
    /// The engine over the vaults of `store` (the server).
    pub async fn new(
        store: Store,
        pool: Arc<ConnectionPool>,
        sessions: Option<Arc<dyn SessionAccess>>,
        config: AiConfig,
    ) -> Result<Arc<Self>, AiError> {
        let hosts = Arc::new(crate::hosts::VaultHosts::new(store.clone(), pool));
        Self::with_hosts(store, hosts, sessions, config).await
    }

    /// The engine with the hosts of a [`HostProvider`](crate::hosts::HostProvider)
    /// (a client app: its device and account stores); tasks, usage and
    /// audit stay in `store`.
    pub async fn with_hosts(
        store: Store,
        hosts: Arc<dyn crate::hosts::HostProvider>,
        sessions: Option<Arc<dyn SessionAccess>>,
        config: AiConfig,
    ) -> Result<Arc<Self>, AiError> {
        let orphans = store.ai_fail_orphan_tasks().await?;
        if orphans > 0 {
            tracing::warn!(orphans, "AI tasks interrupted by a restart");
        }
        let limits = ToolLimits {
            command_timeout: Duration::from_secs(config.command_timeout_secs),
            max_output_chars: config.max_tool_output_chars,
        };
        let (bus, _) = broadcast::channel(4096);
        let mut tools = ToolRuntime::with_hosts(hosts, sessions, limits);
        tools.set_redact(config.redact_secrets);
        Ok(Arc::new(Self {
            tools,
            registry: Registry::new(config),
            store,
            live: Mutex::new(HashMap::new()),
            seqs: Mutex::new(HashMap::new()),
            bus,
            mcp_tokens: Mutex::new(HashMap::new()),
            mcp_url: Mutex::new(None),
            policy: Mutex::new(None),
            chain_source: Mutex::new(None),
        }))
    }

    /// Decides who can use the server's providers (the server's plans).
    /// Without it, everybody can, with `[ai] monthly_budget_usd` as the credit.
    pub fn set_access_policy(&self, policy: Arc<dyn AccessPolicy>) {
        *self.policy.lock() = Some(policy);
    }

    /// Lets a client app decide every chain itself (the AI on its own
    /// computer): plans, own keys in the store and credit no longer apply.
    pub fn set_chain_source(&self, source: Arc<dyn crate::access::ChainSource>) {
        *self.chain_source.lock() = Some(source);
    }

    /// Access of a user to the server's providers.
    pub async fn server_access(&self, owner: Id) -> Result<ServerAccess, AiError> {
        let policy = self.policy.lock().clone();
        match policy {
            Some(p) => p.server_access(owner).await,
            None => Ok(ServerAccess {
                allowed: true,
                credit_micros: self.config().monthly_budget_usd.map(usd_to_micros),
            }),
        }
    }

    /// The user's own keys that can be used, decrypted.
    async fn own_keys(&self, owner: Id) -> Result<BTreeMap<String, OwnKey>, AiError> {
        Ok(self
            .store
            .user_ai_key_secrets(owner)
            .await?
            .into_iter()
            .filter(|k| self.registry.own_key_supported(&k.provider))
            .map(|k| {
                (
                    k.provider,
                    OwnKey {
                        key: k.key,
                        model: k.model,
                    },
                )
            })
            .collect())
    }

    /// Credit spent this month on the server's providers (micro-USD).
    pub async fn server_spend_this_month(&self, owner: Id) -> Result<i64, AiError> {
        Ok(self
            .store
            .ai_credit_spent_since(owner, month_start_ms())
            .await?)
    }

    /// Is there credit left this month for the server's providers?
    async fn credit_left(&self, owner: Id, credit_micros: Option<i64>) -> bool {
        match credit_micros {
            None => true,
            Some(credit) => match self.server_spend_this_month(owner).await {
                Ok(spent) => spent < credit,
                Err(e) => {
                    tracing::warn!(error = %e, "could not read the AI spending");
                    false
                }
            },
        }
    }

    /// The user's provider chain: their own keys, then the server's
    /// providers if their plan allows it and there is credit left.
    pub async fn plan_chain(
        &self,
        owner: Id,
        requested: Option<&str>,
    ) -> Result<Vec<ChainEntry>, AiError> {
        let source = self.chain_source.lock().clone();
        if let Some(source) = source {
            return source.chain(owner, requested).await;
        }
        let access = self.server_access(owner).await?;
        let own = self.own_keys(owner).await?;
        let mut chain = build_chain(&self.registry, requested, &own, access)?;
        if chain.iter().any(|e| !e.is_own()) && !self.credit_left(owner, access.credit_micros).await
        {
            chain.retain(ChainEntry::is_own);
            if chain.is_empty() {
                let credit = access.credit_micros.unwrap_or(0) as f64 / 1_000_000.0;
                return Err(AiError::BudgetExceeded(format!(
                    "you have used this month's AI credit (${credit:.2}); add your own API key in Settings → AI to keep using the AI"
                )));
            }
        }
        Ok(chain)
    }

    /// A user's AI situation (`GET /api/v1/me/ai/access`).
    pub async fn access_info(&self, owner: Id) -> Result<AccessInfo, AiError> {
        let access = self.server_access(owner).await?;
        Ok(AccessInfo {
            own_keys: self.own_keys(owner).await?.into_keys().collect(),
            server_ai: access.allowed,
            credit_micros: access.credit_micros.filter(|_| access.allowed),
            spent_micros: self.server_spend_this_month(owner).await?,
        })
    }

    /// Providers for a user's picker: available if they have their own key
    /// for it, or if the server's provider works and their plan allows it.
    pub async fn providers_for(&self, owner: Id) -> Result<Vec<ProviderInfo>, AiError> {
        let access = self.server_access(owner).await?;
        let own = self.own_keys(owner).await?;
        let mut list = self.registry.list().await;
        for p in &mut list {
            if let Some(k) = own.get(&p.key) {
                p.uses_own_key = true;
                p.available = true;
                p.reason = None;
                p.reason_code = None;
                if k.model.is_some() {
                    p.default_model = k.model.clone();
                }
            } else if !access.allowed {
                p.available = false;
                let (code, reason) = if p.accepts_own_key {
                    (
                        REASON_OWN_KEY_REQUIRED,
                        "add your own API key in Settings → AI",
                    )
                } else {
                    (REASON_PLAN, "not included in your plan")
                };
                p.reason_code = Some(code.into());
                p.reason = Some(reason.into());
            }
        }
        Ok(list)
    }

    /// Records the usage of an AI call in the ledger.
    async fn record_usage(
        &self,
        owner: Id,
        task_id: Option<Id>,
        spec: &str,
        own_key: bool,
        usage: &Usage,
        cost: UsageCost,
    ) {
        let row = AiUsageRow {
            owner_id: owner,
            task_id,
            provider: spec.to_string(),
            own_key,
            input_tokens: (usage.input_tokens + usage.cache_read_tokens + usage.cache_write_tokens)
                as i64,
            output_tokens: usage.output_tokens as i64,
            cost_micros: cost.cost_micros,
            credit_micros: cost.credit_micros,
            created_at: now_ms(),
        };
        if let Err(e) = self.store.ai_record_usage(row).await {
            tracing::warn!(error = %e, "could not record the AI usage");
        }
    }

    /// Records the usage of a call without a task (quick assistant).
    pub(crate) async fn record_assist_usage(
        &self,
        owner: Id,
        spec: &str,
        own_key: bool,
        usage: &Usage,
    ) {
        let cost = self.cost(spec, own_key, usage);
        self.record_usage(owner, None, spec, own_key, usage, cost)
            .await;
    }

    /// Checks a user's own API key with a call that spends nothing.
    pub async fn check_own_key(&self, provider: &str, api_key: &str) -> Result<(), AiError> {
        self.registry.check_key(provider, api_key).await
    }

    pub fn config(&self) -> &AiConfig {
        self.registry.config()
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn store_ref(&self) -> &Store {
        &self.store
    }

    pub fn tools(&self) -> &ToolRuntime {
        &self.tools
    }

    /// URL of the MCP endpoint passed to Codex (e.g. `http://127.0.0.1:7722/api/v1/mcp`).
    pub fn set_mcp_url(&self, url: String) {
        *self.mcp_url.lock() = Some(url);
    }

    /// All events (the server filters by user).
    pub fn subscribe(&self) -> broadcast::Receiver<UserEvent> {
        self.bus.subscribe()
    }

    pub async fn providers(&self) -> Vec<ProviderInfo> {
        self.registry.list().await
    }

    fn seq_counter(&self, task: Id, start: i64) -> Arc<AtomicI64> {
        self.seqs
            .lock()
            .entry(task)
            .or_insert_with(|| Arc::new(AtomicI64::new(start)))
            .clone()
    }

    /// Publishes an event (and persists it if applicable).
    fn publish(&self, owner: Id, task_id: Id, event: TaskEvent) {
        let seq = if event.persisted() {
            let counter = self.seq_counter(task_id, 0);
            let seq = counter.fetch_add(1, Ordering::SeqCst) + 1;
            let store = self.store.clone();
            let row = AiEventRow {
                task_id,
                seq,
                kind: event.kind().to_string(),
                data: serde_json::to_value(&event).unwrap_or(Value::Null),
                created_at: now_ms(),
            };
            tokio::spawn(async move {
                if let Err(e) = store.ai_append_event(row).await {
                    tracing::warn!(error = %e, "could not save the AI event");
                }
            });
            seq
        } else {
            0
        };
        let _ = self.bus.send(UserEvent {
            owner,
            task_id,
            seq,
            event,
        });
    }

    /// Real cost and credit cost of some usage with a provider. With the
    /// user's own key nothing is taken from the credit.
    fn cost(&self, spec: &str, own_key: bool, usage: &Usage) -> UsageCost {
        let (key, model) = split_spec(spec);
        let cfg = self.registry.provider_config(&key);
        let subscription = cfg.map(|c| c.subscription).unwrap_or(false);
        let price = cfg
            .and_then(|c| c.price)
            .or_else(|| model.as_deref().and_then(builtin_price));
        let cost = cost_micros(usage, price, subscription);
        if own_key {
            return UsageCost {
                cost_micros: cost,
                credit_micros: 0,
            };
        }
        let fallback = match cfg.map(|c| c.driver) {
            Some(Driver::CodexCli) => CODEX_CREDIT_PRICE,
            _ => DEFAULT_CREDIT_PRICE,
        };
        UsageCost {
            cost_micros: cost,
            credit_micros: credit_micros(
                usage,
                cost,
                cfg.and_then(|c| c.credit_price),
                price,
                fallback,
            ),
        }
    }

    /// Creates a task and launches it in the background. With a group, a tag
    /// or several hosts and `fan_out`, it creates one conversation per host
    /// under a multi-host task (see [`CreateTask::fan_out`]).
    pub async fn create_task(
        self: &Arc<Self>,
        owner: Id,
        req: CreateTask,
    ) -> Result<TaskView, AiError> {
        let mut prompt = req.prompt.trim().to_string();
        if prompt.is_empty() {
            return Err(AiError::Invalid("the request is empty".into()));
        }
        if prompt.chars().count() > 100_000 {
            return Err(AiError::Invalid("the request is too long".into()));
        }
        if self.config().redact_secrets {
            prompt = redact_context_blocks(&prompt);
        }
        self.check_limits(owner).await?;
        // Fails early if the user can use no provider (or has no credit left).
        self.plan_chain(owner, req.provider.as_deref()).await?;
        let mode = req.mode.unwrap_or(self.config().default_mode);
        let title = req
            .title
            .clone()
            .filter(|t| !t.trim().is_empty())
            .unwrap_or_else(|| title_from(&prompt));
        let targets = self.target_hosts(owner, &req).await?;
        let mut ctx = TaskContext {
            host_ids: req.host_ids.clone(),
            session_id: req.session_id,
            effort: req.effort.clone(),
            group_id: req.group_id,
            tag: req.tag.clone().filter(|t| !t.trim().is_empty()),
            plan_first: req.plan_first.unwrap_or(false),
            ..Default::default()
        };
        if let Some(targets) = &targets {
            ctx.host_ids = Some(targets.iter().map(|(id, _)| *id).collect());
        }
        let fan_out = req.fan_out.unwrap_or(false) && targets.as_ref().is_some_and(|t| t.len() > 1);
        if fan_out {
            let targets = targets.unwrap_or_default();
            if targets.len() > self.config().max_fan_out_hosts {
                return Err(AiError::Invalid(format!(
                    "too many hosts for one task ({}; maximum {})",
                    targets.len(),
                    self.config().max_fan_out_hosts
                )));
            }
            return self
                .create_fan_out(owner, &req, prompt, title, mode, ctx, targets)
                .await;
        }
        let id = new_id();
        let now = now_ms();
        let first = Message::user_text(self.context_block(owner, &ctx, mode).await + &prompt);
        let row = new_row(id, owner, title, prompt, mode, &req, &ctx, vec![first], now);
        self.store.ai_insert_task(row.clone()).await?;
        self.store
            .audit(
                owner,
                &format!("user:{owner}"),
                "ai.task.create",
                Some(id.to_string()),
                json!({"mode": mode.as_str(), "provider": req.provider, "plan_first": ctx.plan_first}),
            )
            .await?;
        self.spawn(row);
        self.get(owner, id, false).await
    }

    /// The hosts a request names (its `host_ids`, the hosts of its group and
    /// subgroups, the hosts with its tag), with their labels. `None`: no
    /// limit. Only the plain `host_ids` of a single conversation are kept as
    /// they are (as before).
    async fn target_hosts(
        &self,
        owner: Id,
        req: &CreateTask,
    ) -> Result<Option<Vec<(Id, String)>>, AiError> {
        let tag = req.tag.as_deref().map(str::trim).filter(|t| !t.is_empty());
        if req.group_id.is_none() && tag.is_none() && !req.fan_out.unwrap_or(false) {
            return Ok(None);
        }
        if req.group_id.is_none() && tag.is_none() && req.host_ids.is_none() {
            return Ok(None);
        }
        let inventory = self
            .tools
            .hosts()
            .inventory(owner)
            .await
            .map_err(AiError::Invalid)?;
        // The group and its subgroups.
        let group_ids: Vec<Id> = req
            .group_id
            .map(|g| inventory.group_tree(g))
            .unwrap_or_default();
        let mut out: Vec<(Id, String)> = Vec::new();
        for id in req.host_ids.iter().flatten() {
            if let Some(h) = inventory.host(*id)
                && !out.iter().any(|(x, _)| x == id)
            {
                out.push((*id, h.label.clone()));
            }
        }
        let mut by_label: Vec<&crate::hosts::HostEntry> = inventory
            .hosts
            .iter()
            .filter(|h| {
                h.group_id.is_some_and(|g| group_ids.contains(&g))
                    || tag.is_some_and(|t| h.tags.iter().any(|x| x.trim().eq_ignore_ascii_case(t)))
            })
            .collect();
        by_label.sort_by_key(|h| h.label.to_lowercase());
        for h in by_label {
            if !out.iter().any(|(x, _)| *x == h.id) {
                out.push((h.id, h.label.clone()));
            }
        }
        if out.is_empty() {
            return Err(AiError::Invalid(if req.group_id.is_some() {
                "there are no hosts in that group".into()
            } else if tag.is_some() {
                "there are no hosts with that tag".into()
            } else {
                "none of those hosts exist".into()
            }));
        }
        Ok(Some(out))
    }

    /// A multi-host task: the parent (it runs no model) and one conversation
    /// per host with the same request.
    #[allow(clippy::too_many_arguments)]
    async fn create_fan_out(
        self: &Arc<Self>,
        owner: Id,
        req: &CreateTask,
        prompt: String,
        title: String,
        mode: PermissionMode,
        mut ctx: TaskContext,
        targets: Vec<(Id, String)>,
    ) -> Result<TaskView, AiError> {
        let parent_id = new_id();
        let now = now_ms();
        ctx.fan_out = true;
        ctx.session_id = None;
        for (host_id, label) in &targets {
            ctx.children.push(ChildRef {
                task_id: new_id(),
                host_id: *host_id,
                label: label.clone(),
            });
        }
        let parent = new_row(
            parent_id,
            owner,
            title.clone(),
            prompt.clone(),
            mode,
            req,
            &ctx,
            vec![Message::user_text(prompt.clone())],
            now,
        );
        self.store.ai_insert_task(parent.clone()).await?;
        for child in &ctx.children {
            let cctx = TaskContext {
                host_ids: Some(vec![child.host_id]),
                effort: ctx.effort.clone(),
                plan_first: ctx.plan_first,
                parent_id: Some(parent_id),
                ..Default::default()
            };
            let first = Message::user_text(self.context_block(owner, &cctx, mode).await + &prompt);
            let row = new_row(
                child.task_id,
                owner,
                format!("{} · {title}", child.label),
                prompt.clone(),
                mode,
                req,
                &cctx,
                vec![first],
                now,
            );
            self.store.ai_insert_task(row).await?;
        }
        self.store
            .audit(
                owner,
                &format!("user:{owner}"),
                "ai.task.create",
                Some(parent_id.to_string()),
                json!({"mode": mode.as_str(), "provider": req.provider, "fan_out": targets.len(), "plan_first": ctx.plan_first}),
            )
            .await?;
        self.spawn(parent);
        self.get(owner, parent_id, false).await
    }

    /// Continues a finished conversation with a new message (also a stopped
    /// one: it keeps its context). On a multi-host task the message goes to
    /// every host's conversation.
    pub async fn send_message(
        self: &Arc<Self>,
        owner: Id,
        task_id: Id,
        text: &str,
    ) -> Result<TaskView, AiError> {
        let text = text.trim();
        if text.is_empty() {
            return Err(AiError::Invalid("the message is empty".into()));
        }
        let text = if self.config().redact_secrets {
            redact_context_blocks(text)
        } else {
            text.to_string()
        };
        if self.live.lock().contains_key(&task_id) {
            return Err(AiError::Invalid(
                "the task is still running; wait for it to finish or cancel it".into(),
            ));
        }
        self.check_limits(owner).await?;
        let mut row = self.store.ai_task(owner, task_id).await?;
        self.plan_chain(owner, Some(row.provider.as_str()).filter(|p| !p.is_empty()))
            .await?;
        let ctx: TaskContext = serde_json::from_value(row.context.clone()).unwrap_or_default();
        if ctx.fan_out {
            if ctx
                .children
                .iter()
                .any(|c| self.live.lock().contains_key(&c.task_id))
            {
                return Err(AiError::Invalid(
                    "a host of this task is still running; wait for it to finish or cancel it"
                        .into(),
                ));
            }
            for child in &ctx.children {
                let Ok(mut crow) = self.store.ai_task(owner, child.task_id).await else {
                    continue;
                };
                self.queue_message(&mut crow, &text).await?;
            }
        }
        self.queue_message(&mut row, &text).await?;
        self.spawn(row);
        self.get(owner, task_id, false).await
    }

    /// Adds the user's message to a task and marks it queued.
    async fn queue_message(&self, row: &mut AiTaskRow, text: &str) -> Result<(), AiError> {
        let mut messages: Vec<Message> =
            serde_json::from_value(row.messages.clone()).unwrap_or_default();
        push_user_text(&mut messages, text);
        row.messages = serde_json::to_value(&messages).unwrap_or_default();
        row.status = TaskStatus::Queued.as_str().into();
        row.error = None;
        row.finished_at = None;
        self.store.ai_update_task(row.clone()).await?;
        self.publish(
            row.owner_id,
            row.id,
            TaskEvent::Status {
                status: TaskStatus::Queued,
            },
        );
        self.publish(
            row.owner_id,
            row.id,
            TaskEvent::Message {
                role: "user".into(),
                text: text.to_string(),
                provider: None,
            },
        );
        Ok(())
    }

    async fn check_limits(&self, owner: Id) -> Result<(), AiError> {
        // The hosts of a multi-host task count as one task.
        let running = self
            .live
            .lock()
            .values()
            .filter(|t| t.owner == owner && t.parent.is_none())
            .count();
        if running >= self.config().max_concurrent_tasks {
            return Err(AiError::Invalid(format!(
                "you already have {running} tasks running (maximum {})",
                self.config().max_concurrent_tasks
            )));
        }
        Ok(())
    }

    /// Context block that precedes the first request.
    async fn context_block(&self, owner: Id, ctx: &TaskContext, mode: PermissionMode) -> String {
        // Hosts and memories the user sees.
        let provider = self.tools.hosts();
        let hosts = match &ctx.host_ids {
            Some(ids) => {
                let inventory = provider.inventory(owner).await.unwrap_or_default();
                Some(
                    inventory
                        .hosts
                        .iter()
                        .filter(|h| ids.contains(&h.id))
                        .map(|h| format!("{} ({})", h.label, h.id))
                        .collect::<Vec<_>>(),
                )
            }
            None => None,
        };
        let memories: Vec<String> = provider
            .memories(owner)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|m| m.content)
            .collect();
        crate::agent::context_block(
            mode,
            hosts.as_deref(),
            ctx.session_id.map(|s| s.to_string()).as_deref(),
            &memories,
        )
    }

    /// Registers a task as running (it can be cancelled and answer approvals).
    fn make_live(
        &self,
        row: &AiTaskRow,
        ctx: &TaskContext,
        cancel: CancellationToken,
    ) -> Arc<LiveTask> {
        let mode = PermissionMode::parse(&row.mode).unwrap_or_default();
        let live = Arc::new(LiveTask {
            id: row.id,
            owner: row.owner_id,
            parent: ctx.parent_id,
            cancel,
            mode: Mutex::new(mode),
            approvals: Mutex::new(HashMap::new()),
            ctx: ToolContext {
                owner: row.owner_id,
                task_id: Some(row.id),
                host_scope: ctx.host_ids.clone(),
            },
            task_ctx: Mutex::new(ctx.clone()),
        });
        self.live.lock().insert(row.id, live.clone());
        live
    }

    /// Initializes the event sequence of a task from what is already saved.
    async fn init_seq(&self, task: Id) {
        let last = self
            .store
            .ai_events_since(task, 0)
            .await
            .ok()
            .and_then(|v| v.last().map(|e| e.seq))
            .unwrap_or(0);
        self.seqs
            .lock()
            .insert(task, Arc::new(AtomicI64::new(last)));
    }

    fn spawn(self: &Arc<Self>, row: AiTaskRow) {
        let ctx: TaskContext = serde_json::from_value(row.context.clone()).unwrap_or_default();
        let live = self.make_live(&row, &ctx, CancellationToken::new());
        let engine = self.clone();
        tokio::spawn(async move {
            engine.init_seq(row.id).await;
            if ctx.fan_out {
                engine.run_fan_out(live, row, ctx).await;
            } else {
                engine.run(live, row, ctx).await;
            }
        });
    }

    /// Runs the queued conversations of a multi-host task, a few at a time,
    /// and then sums them up.
    async fn run_fan_out(
        self: Arc<Self>,
        live: Arc<LiveTask>,
        mut row: AiTaskRow,
        ctx: TaskContext,
    ) {
        let owner = row.owner_id;
        row.status = TaskStatus::Running.as_str().into();
        row.finished_at = None;
        let _ = self.store.ai_update_task(row.clone()).await;
        self.publish(
            owner,
            row.id,
            TaskEvent::Status {
                status: TaskStatus::Running,
            },
        );
        let slots = Arc::new(Semaphore::new(self.config().fan_out_concurrency.max(1)));
        let mut runs = Vec::new();
        for child in &ctx.children {
            let Ok(crow) = self.store.ai_task(owner, child.task_id).await else {
                continue;
            };
            if TaskStatus::parse(&crow.status) != TaskStatus::Queued
                || self.live.lock().contains_key(&crow.id)
            {
                continue;
            }
            let cctx: TaskContext =
                serde_json::from_value(crow.context.clone()).unwrap_or_default();
            let clive = self.make_live(&crow, &cctx, live.cancel.child_token());
            let engine = self.clone();
            let slots = slots.clone();
            let label = child.label.clone();
            let parent_id = row.id;
            runs.push(tokio::spawn(async move {
                let slot = tokio::select! {
                    s = slots.acquire_owned() => s.ok(),
                    _ = clive.cancel.cancelled() => None,
                };
                engine.init_seq(crow.id).await;
                let id = crow.id;
                match slot {
                    Some(_slot) => engine.clone().run(clive, crow, cctx).await,
                    None => engine.finish_unstarted(clive, crow).await,
                }
                let status = engine
                    .store
                    .ai_task(owner, id)
                    .await
                    .map(|r| TaskStatus::parse(&r.status))
                    .unwrap_or(TaskStatus::Failed);
                engine.publish(
                    owner,
                    parent_id,
                    TaskEvent::Notice {
                        message: format!("{label}: {}", status.as_str()),
                    },
                );
            }));
        }
        for r in runs {
            let _ = r.await;
        }
        self.finish_fan_out(owner, row.id, live.cancel.is_cancelled(), true)
            .await;
    }

    /// A host's conversation cancelled before it started.
    async fn finish_unstarted(&self, live: Arc<LiveTask>, mut row: AiTaskRow) {
        row.status = TaskStatus::Cancelled.as_str().into();
        row.error = Some("cancelled by the user".into());
        row.finished_at = Some(now_ms());
        let _ = self.store.ai_update_task(row.clone()).await;
        self.live.lock().remove(&live.id);
        self.publish(
            row.owner_id,
            row.id,
            TaskEvent::Finished {
                status: TaskStatus::Cancelled,
                result: None,
                error: row.error.clone(),
            },
        );
    }

    /// The per-host table of a multi-host task.
    async fn host_runs(&self, owner: Id, ctx: &TaskContext) -> Vec<HostRun> {
        let mut out = Vec::new();
        for child in &ctx.children {
            let Ok(row) = self.store.ai_task(owner, child.task_id).await else {
                continue;
            };
            let cctx: TaskContext = serde_json::from_value(row.context.clone()).unwrap_or_default();
            let pending = self
                .store
                .ai_approvals(row.id)
                .await
                .map(|a| a.iter().filter(|a| a.status == "pending").count())
                .unwrap_or(0);
            let status = TaskStatus::parse(&row.status);
            out.push(HostRun {
                host_id: child.host_id,
                label: child.label.clone(),
                task_id: row.id,
                status,
                summary: row.result.as_deref().map(|r| summary_of(r, 300)),
                error: row.error.clone(),
                duration_ms: cctx
                    .started_at
                    .map(|s| row.finished_at.unwrap_or_else(now_ms) - s)
                    .filter(|d| *d >= 0),
                cost_micros: row.cost_micros,
                pending_approvals: pending,
            });
        }
        out
    }

    /// Sums up a multi-host task from its hosts: status, result (one line
    /// per host), cost and usage. `finish`: it was running (it publishes
    /// `finished` and stops being live).
    async fn finish_fan_out(&self, owner: Id, parent_id: Id, cancelled: bool, finish: bool) {
        let Ok(mut row) = self.store.ai_task(owner, parent_id).await else {
            self.live.lock().remove(&parent_id);
            return;
        };
        let ctx: TaskContext = serde_json::from_value(row.context.clone()).unwrap_or_default();
        let runs = self.host_runs(owner, &ctx).await;
        let mut usage = Usage::default();
        for child in &ctx.children {
            if let Ok(c) = self.store.ai_task(owner, child.task_id).await {
                usage.add(&serde_json::from_value::<Usage>(c.usage).unwrap_or_default());
            }
        }
        let count = |s: TaskStatus| runs.iter().filter(|r| r.status == s).count();
        let status = if runs.iter().any(|r| r.status.is_active()) && !finish {
            TaskStatus::parse(&row.status)
        } else if cancelled || (count(TaskStatus::Cancelled) > 0 && count(TaskStatus::Failed) == 0)
        {
            TaskStatus::Cancelled
        } else if count(TaskStatus::Failed) > 0 {
            TaskStatus::Failed
        } else {
            TaskStatus::Completed
        };
        let result: String = runs
            .iter()
            .map(|r| {
                let detail = r
                    .summary
                    .clone()
                    .or_else(|| r.error.clone())
                    .map(|d| format!(" — {}", summary_of(&d, 200)))
                    .unwrap_or_default();
                format!("- **{}**: {}{detail}\n", r.label, r.status.as_str())
            })
            .collect();
        let failed: Vec<&str> = runs
            .iter()
            .filter(|r| r.status == TaskStatus::Failed)
            .map(|r| r.label.as_str())
            .collect();
        row.status = status.as_str().into();
        row.result = Some(result.trim_end().to_string());
        row.error = match status {
            TaskStatus::Failed => Some(format!("failed on {}", failed.join(", "))),
            TaskStatus::Cancelled => Some("cancelled by the user".into()),
            _ => None,
        };
        row.cost_micros = runs.iter().map(|r| r.cost_micros).sum();
        row.usage = serde_json::to_value(&usage).unwrap_or_default();
        if !status.is_active() {
            row.finished_at = Some(now_ms());
        }
        if let Err(e) = self.store.ai_update_task(row.clone()).await {
            tracing::error!(error = %e, "could not save the AI task");
        }
        if finish {
            let _ = self
                .store
                .audit(owner, &format!("ai:{parent_id}"), "ai.task.finish", Some(parent_id.to_string()), json!({"status": status.as_str(), "hosts": runs.len(), "cost_micros": row.cost_micros}))
                .await;
            self.live.lock().remove(&parent_id);
            self.publish(
                owner,
                parent_id,
                TaskEvent::Finished {
                    status,
                    result: row.result.clone(),
                    error: row.error.clone(),
                },
            );
        }
    }

    async fn run(self: Arc<Self>, live: Arc<LiveTask>, mut row: AiTaskRow, ctx: TaskContext) {
        let owner = row.owner_id;
        live.task_ctx.lock().started_at = Some(now_ms());
        row.context = serde_json::to_value(&*live.task_ctx.lock()).unwrap_or_default();
        row.status = TaskStatus::Running.as_str().into();
        let _ = self.store.ai_update_task(row.clone()).await;
        self.publish(
            owner,
            row.id,
            TaskEvent::Status {
                status: TaskStatus::Running,
            },
        );

        let mut messages: Vec<Message> =
            serde_json::from_value(row.messages.clone()).unwrap_or_default();
        let requested = (!row.provider.is_empty()).then(|| row.provider.clone());
        let chain = self.plan_chain(owner, requested.as_deref()).await;
        let credit_micros = match self.server_access(owner).await {
            Ok(a) => a.credit_micros,
            Err(_) => Some(0),
        };

        // MCP token for external agents (Codex) for the duration of the run.
        let mcp_url = self.mcp_url.lock().clone();
        let mcp_token = mcp_url.as_ref().map(|_| prefixed_token("aks_mcp"));
        if let Some(t) = &mcp_token {
            self.mcp_tokens.lock().insert(
                sha256_hex(t.as_bytes()),
                McpGrant {
                    owner,
                    task_id: row.id,
                },
            );
        }
        let hooks = EngineHooks {
            engine: self.clone(),
            live: live.clone(),
            row: Mutex::new(row.clone()),
            credit_micros,
        };
        let result = match chain {
            Ok(chain) => {
                self.run_phases(
                    &hooks,
                    chain,
                    &mut messages,
                    &row,
                    &ctx,
                    mcp_url.zip(mcp_token.clone()),
                )
                .await
            }
            Err(e) => Err(e),
        };

        if let Some(t) = &mcp_token {
            self.mcp_tokens.lock().remove(&sha256_hex(t.as_bytes()));
        }
        // Any approvals left hanging are cancelled.
        live.approvals.lock().clear();

        let mut row = hooks.row.lock().clone();
        row.messages = serde_json::to_value(&messages).unwrap_or_default();
        row.context = serde_json::to_value(&*live.task_ctx.lock()).unwrap_or_default();
        row.finished_at = Some(now_ms());
        let add_usage = |row: &mut AiTaskRow, outcome: &AgentOutcome| {
            row.used_provider = outcome.used_provider.clone().or(row.used_provider.clone());
            let mut usage: Usage = serde_json::from_value(row.usage.clone()).unwrap_or_default();
            usage.add(&outcome.usage);
            row.usage = serde_json::to_value(&usage).unwrap_or_default();
            row.cost_micros += outcome.cost_micros;
        };
        let (status, result_text, error) = match result {
            Ok(RunEnd::Done(outcome)) => {
                add_usage(&mut row, &outcome);
                (TaskStatus::Completed, Some(outcome.final_text), None)
            }
            Ok(RunEnd::PlanRejected(outcome)) => {
                add_usage(&mut row, &outcome);
                (
                    TaskStatus::Cancelled,
                    None,
                    Some("the plan was not approved".to_string()),
                )
            }
            Err(AiError::Cancelled) => (
                TaskStatus::Cancelled,
                None,
                Some("cancelled by the user".to_string()),
            ),
            Err(e) => (TaskStatus::Failed, None, Some(e.to_string())),
        };
        row.status = status.as_str().into();
        row.result = result_text.clone();
        row.error = error.clone();
        // The mode may have changed while it was working ("always approve",
        // or from the app).
        row.mode = live.mode.lock().as_str().into();
        if let Err(e) = self.store.ai_update_task(row.clone()).await {
            tracing::error!(error = %e, "could not save the AI task");
        }
        let _ = self
            .store
            .audit(owner, &format!("ai:{}", row.id), "ai.task.finish", Some(row.id.to_string()), json!({"status": status.as_str(), "provider": row.used_provider, "cost_micros": row.cost_micros}))
            .await;
        self.live.lock().remove(&row.id);
        self.publish(
            owner,
            row.id,
            TaskEvent::Finished {
                status,
                result: result_text,
                error,
            },
        );
        // A host's conversation continued on its own: update its multi-host task.
        if let Some(parent) = live.parent
            && !self.live.lock().contains_key(&parent)
        {
            self.finish_fan_out(owner, parent, false, false).await;
        }
    }

    /// The plan (if the task asks for one and it is not approved yet), then
    /// the work.
    async fn run_phases(
        &self,
        hooks: &EngineHooks,
        chain: Vec<ChainEntry>,
        messages: &mut Vec<Message>,
        row: &AiTaskRow,
        ctx: &TaskContext,
        mcp: Option<(String, String)>,
    ) -> Result<RunEnd, AiError> {
        let mut planned = AgentOutcome::default();
        let needs_plan = {
            let c = hooks.live.task_ctx.lock();
            c.plan_first && !c.plan.as_ref().is_some_and(|p| p.approved)
        };
        if needs_plan {
            let (approved, outcome) = self.plan_phase(hooks, &chain, messages, row, ctx).await?;
            planned = outcome;
            if !approved {
                return Ok(RunEnd::PlanRejected(planned));
            }
        }
        let run = AgentRun {
            registry: &self.registry,
            chain,
            tools: self.tools.specs(),
            system: SYSTEM_PROMPT.to_string(),
            session_id: format!("ses_{}", row.id.simple()),
            max_steps: self.config().max_steps,
            effort: ctx.effort.clone(),
            mcp,
            cancel: hooks.live.cancel.clone(),
        };
        let mut outcome = run_agent(run, messages, hooks).await?;
        outcome.usage.add(&planned.usage);
        outcome.cost_micros += planned.cost_micros;
        if outcome.used_provider.is_none() {
            outcome.used_provider = planned.used_provider;
        }
        Ok(outcome).map(RunEnd::Done)
    }

    /// "Plan before acting": the model writes a numbered plan without tools
    /// and the user approves it (maybe edited) or rejects it (with a reason,
    /// the model proposes another one). Returns whether it was approved.
    async fn plan_phase(
        &self,
        hooks: &EngineHooks,
        chain: &[ChainEntry],
        messages: &mut Vec<Message>,
        row: &AiTaskRow,
        ctx: &TaskContext,
    ) -> Result<(bool, AgentOutcome), AiError> {
        let mut total = AgentOutcome::default();
        let no_tools = NoTools(hooks);
        for round in 0..MAX_PLAN_ROUNDS {
            let run = AgentRun {
                registry: &self.registry,
                chain: chain.to_vec(),
                tools: Vec::new(),
                system: format!("{SYSTEM_PROMPT}\n\n{PLAN_PROMPT}"),
                session_id: format!("ses_{}", row.id.simple()),
                max_steps: 1,
                effort: ctx.effort.clone(),
                mcp: None,
                cancel: hooks.live.cancel.clone(),
            };
            let out = run_agent(run, messages, &no_tools).await?;
            total.usage.add(&out.usage);
            total.cost_micros += out.cost_micros;
            total.used_provider = out.used_provider.clone();
            let plan = out.final_text.trim().to_string();
            if plan.is_empty() {
                // Nothing to approve: go ahead as a normal task.
                return Ok((true, total));
            }
            let preview = ApprovalPreview {
                kind: "plan".into(),
                plan: Some(plan.clone()),
                editable: true,
                risk: crate::policy::RiskLevel::Low,
                ..Default::default()
            };
            let summary = format!("Plan: {}", summary_of(&plan, 200));
            let call_id = format!("plan_{}", round + 1);
            let decision = hooks
                .request_approval(&call_id, "plan", &json!({"plan": plan}), &summary, preview)
                .await;
            if hooks.live.cancel.is_cancelled() {
                return Err(AiError::Cancelled);
            }
            if decision.approve {
                let edited = decision.edited_text().filter(|e| e.trim() != plan);
                let text = edited.unwrap_or(&plan).to_string();
                hooks.live.task_ctx.lock().plan = Some(TaskPlan {
                    text: text.clone(),
                    approved: true,
                    edited: edited.is_some(),
                });
                let mut note = match edited {
                    Some(e) => format!(
                        "The user edited and approved the plan. Follow this plan instead of yours:\n\n{e}\n\nCarry it out now."
                    ),
                    None => "The user approved the plan. Carry it out now.".to_string(),
                };
                if let Some(r) = decision.reason_text() {
                    note.push_str(&format!("\nTheir note: {r}"));
                }
                push_user_text(messages, &note);
                hooks.checkpoint(messages).await;
                return Ok((true, total));
            }
            hooks.live.task_ctx.lock().plan = Some(TaskPlan {
                text: plan,
                approved: false,
                edited: false,
            });
            match decision.reason_text() {
                Some(r) if round + 1 < MAX_PLAN_ROUNDS => {
                    push_user_text(
                        messages,
                        &format!(
                            "The user did not approve the plan. Their reason: {r}\nPropose a new plan."
                        ),
                    );
                    hooks.checkpoint(messages).await;
                }
                reason => {
                    let mut note = "The user did not approve the plan; do not act.".to_string();
                    if let Some(r) = reason {
                        note.push_str(&format!(" Their reason: {r}"));
                    }
                    push_user_text(messages, &note);
                    hooks.checkpoint(messages).await;
                    return Ok((false, total));
                }
            }
        }
        Ok((false, total))
    }

    /// Decides a pending approval. `always` switches the task to autonomous mode.
    pub async fn decide(
        &self,
        owner: Id,
        task_id: Id,
        approval_id: Id,
        approve: bool,
        always: bool,
        by: &str,
    ) -> Result<(), AiError> {
        self.decide_with(
            owner,
            task_id,
            approval_id,
            ApprovalDecision {
                approve,
                always,
                edited: None,
                reason: None,
            },
            by,
        )
        .await
    }

    /// Decides a pending approval with the full answer: the edited command
    /// or plan (what runs, and what the model is told ran) and the reason
    /// of a denial (sent to the model).
    pub async fn decide_with(
        &self,
        owner: Id,
        task_id: Id,
        approval_id: Id,
        decision: ApprovalDecision,
        by: &str,
    ) -> Result<(), AiError> {
        if decision.edited.as_ref().is_some_and(|e| e.len() > 100_000) {
            return Err(AiError::Invalid("the edited text is too long".into()));
        }
        let live = self
            .live
            .lock()
            .get(&task_id)
            .cloned()
            .filter(|l| l.owner == owner)
            .ok_or_else(|| AiError::NotFound(format!("active task {task_id}")))?;
        let tx = live
            .approvals
            .lock()
            .remove(&approval_id)
            .ok_or_else(|| AiError::NotFound(format!("pending approval {approval_id}")))?;
        let approve = decision.approve;
        let _ = tx.send(decision);
        self.store
            .ai_decide_approval(approval_id, if approve { "approved" } else { "denied" }, by)
            .await?;
        Ok(())
    }

    /// Stops a running task (also a multi-host one, with all its hosts). It
    /// keeps its conversation and can be continued with a message.
    pub async fn cancel(&self, owner: Id, task_id: Id) -> Result<(), AiError> {
        let live = self
            .live
            .lock()
            .get(&task_id)
            .cloned()
            .filter(|l| l.owner == owner)
            .ok_or_else(|| AiError::NotFound(format!("active task {task_id}")))?;
        live.cancel.cancel();
        Ok(())
    }

    /// Changes the permission mode of a task (running or not: it also applies
    /// to the following messages). On a multi-host task, also its hosts.
    pub async fn set_mode(
        &self,
        owner: Id,
        task_id: Id,
        mode: PermissionMode,
    ) -> Result<(), AiError> {
        let mut ids = vec![task_id];
        if let Ok(row) = self.store.ai_task(owner, task_id).await {
            let ctx: TaskContext = serde_json::from_value(row.context).unwrap_or_default();
            ids.extend(ctx.children.iter().map(|c| c.task_id));
        }
        for id in ids {
            let live = self
                .live
                .lock()
                .get(&id)
                .cloned()
                .filter(|l| l.owner == owner);
            if let Some(live) = live {
                *live.mode.lock() = mode;
            }
            if !self.store.ai_set_mode(owner, id, mode.as_str()).await? && id == task_id {
                return Err(AiError::NotFound(format!("task {task_id}")));
            }
        }
        Ok(())
    }

    fn view(&self, row: AiTaskRow, with_messages: bool, pending: Vec<AiApprovalRow>) -> TaskView {
        let ctx: TaskContext = serde_json::from_value(row.context.clone()).unwrap_or_default();
        let messages = with_messages.then(|| {
            serde_json::from_value::<Vec<Message>>(row.messages.clone()).unwrap_or_default()
        });
        let status = TaskStatus::parse(&row.status);
        TaskView {
            id: row.id,
            title: row.title,
            prompt: row.prompt,
            status,
            mode: PermissionMode::parse(&row.mode).unwrap_or_default(),
            provider: row.provider,
            used_provider: row.used_provider,
            host_ids: ctx.host_ids,
            created_at: row.created_at,
            updated_at: row.updated_at,
            finished_at: row.finished_at,
            result: row.result,
            error: row.error,
            cost_micros: row.cost_micros,
            usage: serde_json::from_value(row.usage).unwrap_or_default(),
            messages,
            pending_approvals: pending,
            parent_id: ctx.parent_id,
            fan_out: ctx.fan_out,
            hosts: Vec::new(),
            group_id: ctx.group_id,
            tag: ctx.tag,
            plan_first: ctx.plan_first,
            plan: ctx.plan,
            steps: if with_messages { ctx.steps } else { Vec::new() },
        }
    }

    pub async fn get(&self, owner: Id, id: Id, with_messages: bool) -> Result<TaskView, AiError> {
        let row = self.store.ai_task(owner, id).await?;
        let ctx: TaskContext = serde_json::from_value(row.context.clone()).unwrap_or_default();
        let pending = self
            .store
            .ai_approvals(id)
            .await?
            .into_iter()
            .filter(|a| a.status == "pending")
            .collect();
        let mut view = self.view(row, with_messages, pending);
        if ctx.fan_out {
            view.hosts = self.host_runs(owner, &ctx).await;
        }
        Ok(view)
    }

    /// The latest tasks (the hosts of a multi-host task are inside it, not
    /// in the list).
    pub async fn list(&self, owner: Id, limit: i64) -> Result<Vec<TaskView>, AiError> {
        let limit = limit.clamp(1, 500);
        let rows = self.store.ai_list_tasks(owner, limit * 4).await?;
        let pending = self.store.ai_pending_approvals(owner).await?;
        Ok(rows
            .into_iter()
            .filter(|r| r.context.get("parent_id").is_none_or(Value::is_null))
            .take(limit as usize)
            .map(|r| {
                let p = pending
                    .iter()
                    .filter(|a| a.task_id == r.id)
                    .cloned()
                    .collect();
                self.view(r, false, p)
            })
            .collect())
    }

    pub async fn events(&self, owner: Id, id: Id, after: i64) -> Result<Vec<AiEventRow>, AiError> {
        self.store.ai_task(owner, id).await?;
        Ok(self.store.ai_events_since(id, after).await?)
    }

    /// Deletes a task (a multi-host one with its hosts' conversations).
    pub async fn delete(&self, owner: Id, id: Id) -> Result<(), AiError> {
        let row = self.store.ai_task(owner, id).await?;
        let ctx: TaskContext = serde_json::from_value(row.context).unwrap_or_default();
        let ids: Vec<Id> = std::iter::once(id)
            .chain(ctx.children.iter().map(|c| c.task_id))
            .collect();
        if ids.iter().any(|i| self.live.lock().contains_key(i)) {
            return Err(AiError::Invalid(
                "cancel the task before deleting it".into(),
            ));
        }
        for child in ctx.children.iter().map(|c| c.task_id) {
            let _ = self.store.ai_delete_task(owner, child).await;
            self.seqs.lock().remove(&child);
        }
        self.store.ai_delete_task(owner, id).await?;
        self.seqs.lock().remove(&id);
        Ok(())
    }

    pub async fn pending_approvals(&self, owner: Id) -> Result<Vec<AiApprovalRow>, AiError> {
        Ok(self.store.ai_pending_approvals(owner).await?)
    }

    /// The runbook of a finished task: its executed commands as a snippet
    /// (see [`crate::runbook`]). For a multi-host task, those of the first
    /// host that ran any.
    pub async fn runbook(&self, owner: Id, id: Id) -> Result<Runbook, AiError> {
        let row = self.store.ai_task(owner, id).await?;
        let ctx: TaskContext = serde_json::from_value(row.context.clone()).unwrap_or_default();
        let title = row.title.clone();
        let mut source = (row, ctx);
        if source.1.fan_out {
            let children = source.1.children.clone();
            let mut found = None;
            for child in &children {
                let Ok(c) = self.store.ai_task(owner, child.task_id).await else {
                    continue;
                };
                let cctx: TaskContext =
                    serde_json::from_value(c.context.clone()).unwrap_or_default();
                let messages: Vec<Message> =
                    serde_json::from_value(c.messages.clone()).unwrap_or_default();
                let has_steps = cctx.steps.iter().any(|s| s.ok)
                    || crate::runbook::steps_from_messages(&messages)
                        .iter()
                        .any(|s| s.ok);
                if has_steps {
                    found = Some((c, cctx));
                    break;
                }
            }
            match found {
                Some(f) => source = f,
                None => return Err(AiError::Invalid("the task ran no commands".into())),
            }
        }
        let (row, ctx) = source;
        let messages: Vec<Message> = serde_json::from_value(row.messages).unwrap_or_default();
        let steps = if ctx.steps.is_empty() {
            crate::runbook::steps_from_messages(&messages)
        } else {
            ctx.steps.clone()
        };
        let hosts = self.runbook_host(owner, &ctx, &steps).await;
        Ok(crate::runbook::build(&title, &messages, &steps, &hosts))
    }

    /// The one host a task ran its commands on (its label and address
    /// become `{{host}}`); none when it used several.
    async fn runbook_host(
        &self,
        owner: Id,
        ctx: &TaskContext,
        steps: &[ExecutedStep],
    ) -> Vec<HostNames> {
        let Ok(inventory) = self.tools.hosts().inventory(owner).await else {
            return Vec::new();
        };
        let known: Vec<(Id, HostNames)> = inventory
            .hosts
            .iter()
            .map(|h| {
                (
                    h.id,
                    HostNames {
                        label: h.label.clone(),
                        address: h.address.clone(),
                    },
                )
            })
            .collect();
        crate::runbook::single_host(steps, ctx.host_ids.as_deref(), &known)
            .into_iter()
            .collect()
    }

    /// Saves the runbook of a task as a snippet in the user's personal
    /// vault (`name`: the task's title otherwise).
    pub async fn save_runbook(
        &self,
        owner: Id,
        id: Id,
        name: Option<String>,
    ) -> Result<termoak_core::model::Snippet, AiError> {
        let rb = self.runbook(owner, id).await?;
        if rb.steps == 0 {
            return Err(AiError::Invalid("the task ran no commands".into()));
        }
        let snippet = termoak_core::model::Snippet {
            id: Id::nil(),
            name: name
                .map(|n| n.trim().to_string())
                .filter(|n| !n.is_empty())
                .unwrap_or(rb.name),
            script: rb.script,
            description: rb.description,
            tags: vec!["ai".into(), "runbook".into()],
        };
        let saved = self
            .tools
            .hosts()
            .save_snippet(owner, snippet)
            .await
            .map_err(AiError::Invalid)?;
        let _ = self
            .store
            .audit(
                owner,
                &format!("user:{owner}"),
                "ai.task.runbook",
                Some(id.to_string()),
                json!({"snippet": saved.id}),
            )
            .await;
        Ok(saved)
    }

    /// Resolves a task MCP token.
    pub(crate) fn mcp_grant(&self, token: &str) -> Option<(Id, Id)> {
        self.mcp_tokens
            .lock()
            .get(&sha256_hex(token.as_bytes()))
            .map(|g| (g.owner, g.task_id))
    }

    /// Runs a tool in the context of a task (used by MCP).
    pub(crate) async fn call_tool_for_task(
        self: &Arc<Self>,
        task_id: Id,
        call_id: &str,
        name: &str,
        input: &Value,
    ) -> Option<ToolOutcome> {
        let live = self.live.lock().get(&task_id).cloned()?;
        let row = self.store.ai_task(live.owner, task_id).await.ok()?;
        let hooks = EngineHooks {
            engine: self.clone(),
            live,
            row: Mutex::new(row),
            credit_micros: None,
        };
        Some(hooks.call_tool(call_id, name, input).await)
    }
}

/// How a run ended without an error.
enum RunEnd {
    Done(AgentOutcome),
    /// "Plan before acting" and the user did not approve the plan.
    PlanRejected(AgentOutcome),
}

/// A new `ai_tasks` row.
#[allow(clippy::too_many_arguments)]
fn new_row(
    id: Id,
    owner: Id,
    title: String,
    prompt: String,
    mode: PermissionMode,
    req: &CreateTask,
    ctx: &TaskContext,
    messages: Vec<Message>,
    now: i64,
) -> AiTaskRow {
    AiTaskRow {
        id,
        owner_id: owner,
        title,
        prompt,
        status: TaskStatus::Queued.as_str().into(),
        mode: mode.as_str().into(),
        provider: req.provider.clone().unwrap_or_default(),
        used_provider: None,
        context: serde_json::to_value(ctx).unwrap_or_default(),
        messages: serde_json::to_value(messages).unwrap_or_default(),
        usage: json!({}),
        cost_micros: 0,
        result: None,
        error: None,
        created_at: now,
        updated_at: now,
        finished_at: None,
    }
}

/// First line of a text, at most `max` characters.
fn summary_of(text: &str, max: usize) -> String {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    let mut out: String = line.chars().take(max).collect();
    if line.chars().count() > max || text.trim().lines().count() > 1 {
        out.push('…');
    }
    out
}

/// Adds the user's next message. Tool calls left without a result (the task
/// was stopped, or the app closed, while they ran) get one saying they did
/// not run, in the same message: providers reject a call without its result.
pub(crate) fn push_user_text(messages: &mut Vec<Message>, text: &str) {
    let dangling: Vec<String> = match messages.last() {
        Some(m @ Message::Assistant { .. }) => {
            m.tool_calls().into_iter().map(|(id, _, _)| id).collect()
        }
        _ => Vec::new(),
    };
    if dangling.is_empty() {
        messages.push(Message::user_text(text));
        return;
    }
    let mut content: Vec<Part> = dangling
        .into_iter()
        .map(|id| Part::ToolResult {
            id,
            content: "Not run: the task was stopped before this call ran.".into(),
            is_error: true,
        })
        .collect();
    content.push(Part::Text {
        text: text.to_string(),
    });
    messages.push(Message::User { content });
}

struct EngineHooks {
    engine: Arc<AiEngine>,
    live: Arc<LiveTask>,
    row: Mutex<AiTaskRow>,
    /// The user's monthly credit for the server's providers.
    credit_micros: Option<i64>,
}

#[async_trait]
impl AgentHooks for EngineHooks {
    fn emit(&self, ev: TaskEvent) {
        self.engine.publish(self.live.owner, self.live.id, ev);
    }

    async fn call_tool(&self, call_id: &str, name: &str, input: &Value) -> ToolOutcome {
        let effect = ToolRuntime::effect(name, input);
        let summary = ToolRuntime::summarize(name, input);
        let mode = *self.live.mode.lock();
        let verdict = decide(mode, name, effect);
        self.emit(TaskEvent::ToolCall {
            call_id: call_id.to_string(),
            tool: name.to_string(),
            summary: summary.clone(),
            input: input.clone(),
            needs_approval: verdict == Verdict::NeedsApproval,
        });
        let started = std::time::Instant::now();
        let outcome = match verdict {
            Verdict::Deny(reason) => ToolOutcome {
                ok: false,
                content: format!("Denied: {reason}."),
            },
            Verdict::NeedsApproval => {
                let preview = self.engine.tools.preview(&self.live.ctx, name, input).await;
                let decision = self
                    .request_approval(call_id, name, input, &summary, preview)
                    .await;
                if decision.approve {
                    self.run_approved(call_id, name, input, &summary, &decision)
                        .await
                } else {
                    let content = match decision.reason_text() {
                        Some(r) => format!(
                            "The user did NOT approve this action. Their reason: {r}\nDo not retry it in another form; take their reason into account, explain alternatives or ask."
                        ),
                        None => "The user did NOT approve this action. Do not retry it in another form; explain alternatives or ask.".into(),
                    };
                    ToolOutcome { ok: false, content }
                }
            }
            Verdict::Allow => self.execute(call_id, name, input, &summary, false).await,
        };
        self.emit(TaskEvent::ToolResult {
            call_id: call_id.to_string(),
            ok: outcome.ok,
            output: truncate_middle(&outcome.content, 4000),
            duration_ms: started.elapsed().as_millis() as u64,
        });
        outcome
    }

    async fn checkpoint(&self, messages: &[Message]) {
        let mut row = self.row.lock().clone();
        row.messages = serde_json::to_value(messages).unwrap_or_default();
        row.mode = self.live.mode.lock().as_str().into();
        row.context = serde_json::to_value(&*self.live.task_ctx.lock()).unwrap_or_default();
        *self.row.lock() = row.clone();
        if let Err(e) = self.engine.store.ai_update_task(row).await {
            tracing::warn!(error = %e, "could not save the task progress");
        }
    }

    fn cost(&self, spec: &str, own_key: bool, usage: &Usage) -> UsageCost {
        self.engine.cost(spec, own_key, usage)
    }

    async fn record_usage(&self, spec: &str, own_key: bool, usage: &Usage, cost: UsageCost) {
        self.engine
            .record_usage(
                self.live.owner,
                Some(self.live.id),
                spec,
                own_key,
                usage,
                cost,
            )
            .await;
    }

    async fn server_credit_left(&self) -> bool {
        self.engine
            .credit_left(self.live.owner, self.credit_micros)
            .await
    }
}

/// The hooks of the planning turn: no tool runs.
struct NoTools<'a>(&'a EngineHooks);

#[async_trait]
impl AgentHooks for NoTools<'_> {
    fn emit(&self, ev: TaskEvent) {
        self.0.emit(ev);
    }

    async fn call_tool(&self, _call_id: &str, _name: &str, _input: &Value) -> ToolOutcome {
        ToolOutcome {
            ok: false,
            content: "Not run: this is the planning step; write the plan without using tools."
                .into(),
        }
    }

    async fn checkpoint(&self, messages: &[Message]) {
        self.0.checkpoint(messages).await;
    }

    fn cost(&self, spec: &str, own_key: bool, usage: &Usage) -> UsageCost {
        self.0.cost(spec, own_key, usage)
    }

    async fn record_usage(&self, spec: &str, own_key: bool, usage: &Usage, cost: UsageCost) {
        self.0.record_usage(spec, own_key, usage, cost).await;
    }

    async fn server_credit_left(&self) -> bool {
        self.0.server_credit_left().await
    }
}

impl EngineHooks {
    /// Runs an approved call: with the user's edit of the command, if any
    /// (what runs, and the model is told), or as the model asked.
    async fn run_approved(
        &self,
        call_id: &str,
        name: &str,
        input: &Value,
        summary: &str,
        decision: &ApprovalDecision,
    ) -> ToolOutcome {
        let field = match name {
            "run_command" => Some("command"),
            "send_to_terminal" => Some("input"),
            _ => None,
        };
        let edit = field.and_then(|f| {
            decision
                .edited_text()
                .filter(|e| Some(*e) != input[f].as_str().map(str::trim))
                .map(|e| (f, e.to_string()))
        });
        let mut outcome = match &edit {
            Some((f, cmd)) => {
                let mut edited = input.clone();
                edited[*f] = Value::String(cmd.clone());
                let summary = ToolRuntime::summarize(name, &edited);
                let mut o = self.execute(call_id, name, &edited, &summary, true).await;
                o.content = format!(
                    "The user edited the command before approving it; this is what ran instead of yours:\n{cmd}\n\n{}",
                    o.content
                );
                o
            }
            None => self.execute(call_id, name, input, summary, false).await,
        };
        if let Some(r) = decision.reason_text() {
            outcome.content = format!(
                "The user approved it with this note: {r}\n\n{}",
                outcome.content
            );
        }
        outcome
    }

    /// Runs a tool (stopping it if the task is cancelled), audits changes
    /// and records the commands and writes for the runbook.
    async fn execute(
        &self,
        call_id: &str,
        name: &str,
        input: &Value,
        summary: &str,
        edited: bool,
    ) -> ToolOutcome {
        let outcome = tokio::select! {
            biased;
            _ = self.live.cancel.cancelled() => {
                return ToolOutcome {
                    ok: false,
                    content: "Stopped by the user before it finished.".into(),
                };
            }
            o = self.engine.tools.execute(&self.live.ctx, name, input) => o,
        };
        if ToolRuntime::effect(name, input) == crate::policy::Effect::Write || name == "run_command"
        {
            let _ = self
                .engine
                .store
                .audit(
                    self.live.owner,
                    &format!("ai:{}", self.live.id),
                    &format!("ai.tool.{name}"),
                    input["host"].as_str().map(str::to_string),
                    json!({"summary": summary, "ok": outcome.ok, "edited": edited}),
                )
                .await;
        }
        if matches!(name, "run_command" | "send_to_terminal" | "write_file") {
            let text = |k: &str| input[k].as_str().map(str::to_string);
            let step = ExecutedStep {
                call_id: call_id.to_string(),
                tool: name.to_string(),
                host: text("host").or_else(|| text("session_id")),
                command: text("command").or_else(|| text("input")),
                path: text("path"),
                content: input["content"]
                    .as_str()
                    .filter(|c| c.len() <= MAX_STEP_CONTENT)
                    .map(str::to_string),
                ok: outcome.ok,
                edited,
                explanation: text("reason").filter(|r| !r.trim().is_empty()),
                at: now_ms(),
            };
            let mut ctx = self.live.task_ctx.lock();
            if ctx.steps.len() < MAX_STEPS_KEPT {
                ctx.steps.push(step);
            }
        }
        outcome
    }

    /// Asks the user and waits for the answer (denied when it times out or
    /// the task is cancelled).
    async fn request_approval(
        &self,
        call_id: &str,
        name: &str,
        input: &Value,
        summary: &str,
        preview: ApprovalPreview,
    ) -> ApprovalDecision {
        let approval_id = new_id();
        let (tx, rx) = oneshot::channel();
        self.live.approvals.lock().insert(approval_id, tx);
        let _ = self
            .engine
            .store
            .ai_insert_approval(AiApprovalRow {
                id: approval_id,
                task_id: self.live.id,
                tool: name.to_string(),
                input: input.clone(),
                summary: summary.to_string(),
                status: "pending".into(),
                decided_by: None,
                created_at: now_ms(),
                decided_at: None,
                preview: serde_json::to_value(&preview).ok(),
            })
            .await;
        self.emit(TaskEvent::ApprovalRequested {
            approval_id,
            call_id: call_id.to_string(),
            tool: name.to_string(),
            summary: summary.to_string(),
            input: input.clone(),
            preview: Some(preview),
        });
        self.row.lock().status = TaskStatus::WaitingApproval.as_str().into();
        let _ = self
            .engine
            .store
            .ai_set_status(self.live.id, TaskStatus::WaitingApproval.as_str())
            .await;
        self.emit(TaskEvent::Status {
            status: TaskStatus::WaitingApproval,
        });
        let timeout = Duration::from_secs(self.engine.config().approval_timeout_secs);
        let decision = tokio::select! {
            _ = self.live.cancel.cancelled() => None,
            r = tokio::time::timeout(timeout, rx) => r.ok().and_then(|r| r.ok()),
        };
        let (decision, by) = match decision {
            Some(d) => {
                if d.approve && d.always {
                    *self.live.mode.lock() = PermissionMode::Auto;
                }
                (d, "user".to_string())
            }
            None => {
                self.live.approvals.lock().remove(&approval_id);
                let _ = self
                    .engine
                    .store
                    .ai_decide_approval(approval_id, "expired", "timeout")
                    .await;
                (ApprovalDecision::deny(None), "timeout".to_string())
            }
        };
        self.emit(TaskEvent::ApprovalDecided {
            approval_id,
            approved: decision.approve,
            by,
            edited: decision
                .edited_text()
                .filter(|_| decision.approve)
                .map(str::to_string),
            reason: decision.reason_text(),
        });
        if !self.live.cancel.is_cancelled() {
            self.row.lock().status = TaskStatus::Running.as_str().into();
            let _ = self
                .engine
                .store
                .ai_set_status(self.live.id, TaskStatus::Running.as_str())
                .await;
            self.emit(TaskEvent::Status {
                status: TaskStatus::Running,
            });
        }
        decision
    }
}

/// Short title from the request (without the `<context>` blocks clients may
/// prepend, such as the terminal screen).
fn title_from(prompt: &str) -> String {
    let mut rest = prompt.trim_start();
    while rest.starts_with("<context>")
        && let Some(end) = rest.find("</context>")
    {
        rest = rest[end + "</context>".len()..].trim_start();
    }
    let prompt = if rest.is_empty() { prompt } else { rest };
    let line = prompt
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or(prompt)
        .trim();
    let mut t: String = line.chars().take(80).collect();
    if line.chars().count() > 80 {
        t.push('…');
    }
    t
}

use chrono::Datelike;

/// Converts user message parts to text (for simple views).
pub fn user_text(parts: &[Part]) -> String {
    parts
        .iter()
        .filter_map(|p| match p {
            Part::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("")
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod title_tests {
    use super::title_from;

    #[test]
    fn title_skips_context_blocks() {
        assert_eq!(
            title_from("<context>\nscreen\n</context>\n\nWhat is wrong with nginx?"),
            "What is wrong with nginx?"
        );
        assert_eq!(title_from("Check the disk"), "Check the disk");
    }
}

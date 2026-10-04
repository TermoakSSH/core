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
use termoak_core::model::Memory;
use termoak_core::store::{AiApprovalRow, AiEventRow, AiTaskRow, AiUsageRow};
use termoak_core::time::now_ms;
use termoak_core::{Id, Store, new_id};
use termoak_ssh::ConnectionPool;
use tokio::sync::{broadcast, oneshot};
use tokio_util::sync::CancellationToken;

use crate::access::{AccessPolicy, ChainEntry, OwnKey, ServerAccess, build_chain, usd_to_micros};
use crate::agent::{AgentHooks, AgentRun, SYSTEM_PROMPT, run_agent};
use crate::config::{AiConfig, Driver, split_spec};
use crate::error::AiError;
use crate::message::{Message, Part, Usage};
use crate::policy::{PermissionMode, Verdict, decide};
use crate::pricing::{
    CODEX_CREDIT_PRICE, DEFAULT_CREDIT_PRICE, UsageCost, builtin_price, cost_micros, credit_micros,
};
use crate::provider::{ProviderInfo, REASON_OWN_KEY_REQUIRED, REASON_PLAN, Registry};
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
        tool: String,
        summary: String,
        input: Value,
    },
    ApprovalDecided {
        approval_id: Id,
        approved: bool,
        by: String,
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
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TaskContext {
    #[serde(default)]
    host_ids: Option<Vec<Id>>,
    #[serde(default)]
    session_id: Option<Id>,
    #[serde(default)]
    effort: Option<String>,
}

struct LiveTask {
    id: Id,
    owner: Id,
    cancel: CancellationToken,
    mode: Mutex<PermissionMode>,
    approvals: Mutex<HashMap<Id, oneshot::Sender<(bool, bool)>>>,
    ctx: ToolContext,
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
    pub async fn new(
        store: Store,
        pool: Arc<ConnectionPool>,
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
        Ok(Arc::new(Self {
            tools: ToolRuntime::new(store.clone(), pool, sessions, limits),
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
    fn publish(self: &Arc<Self>, owner: Id, task_id: Id, event: TaskEvent) {
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

    /// Creates a task and launches it in the background.
    pub async fn create_task(
        self: &Arc<Self>,
        owner: Id,
        req: CreateTask,
    ) -> Result<TaskView, AiError> {
        let prompt = req.prompt.trim().to_string();
        if prompt.is_empty() {
            return Err(AiError::Invalid("the request is empty".into()));
        }
        if prompt.chars().count() > 100_000 {
            return Err(AiError::Invalid("the request is too long".into()));
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
        let id = new_id();
        let now = now_ms();
        let ctx = TaskContext {
            host_ids: req.host_ids.clone(),
            session_id: req.session_id,
            effort: req.effort.clone(),
        };
        let first = Message::user_text(self.context_block(owner, &ctx, mode).await + &prompt);
        let row = AiTaskRow {
            id,
            owner_id: owner,
            title,
            prompt: prompt.clone(),
            status: TaskStatus::Queued.as_str().into(),
            mode: mode.as_str().into(),
            provider: req.provider.clone().unwrap_or_default(),
            used_provider: None,
            context: serde_json::to_value(&ctx).unwrap_or_default(),
            messages: serde_json::to_value(vec![first]).unwrap_or_default(),
            usage: json!({}),
            cost_micros: 0,
            result: None,
            error: None,
            created_at: now,
            updated_at: now,
            finished_at: None,
        };
        self.store.ai_insert_task(row.clone()).await?;
        self.store
            .audit(
                owner,
                &format!("user:{owner}"),
                "ai.task.create",
                Some(id.to_string()),
                json!({"mode": mode.as_str(), "provider": req.provider}),
            )
            .await?;
        self.spawn(row);
        self.get(owner, id, false).await
    }

    /// Continues a finished conversation with a new message.
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
        if self.live.lock().contains_key(&task_id) {
            return Err(AiError::Invalid(
                "the task is still running; wait for it to finish or cancel it".into(),
            ));
        }
        self.check_limits(owner).await?;
        let mut row = self.store.ai_task(owner, task_id).await?;
        self.plan_chain(owner, Some(row.provider.as_str()).filter(|p| !p.is_empty()))
            .await?;
        let mut messages: Vec<Message> =
            serde_json::from_value(row.messages.clone()).unwrap_or_default();
        messages.push(Message::user_text(text));
        row.messages = serde_json::to_value(&messages).unwrap_or_default();
        row.status = TaskStatus::Queued.as_str().into();
        row.error = None;
        row.finished_at = None;
        self.store.ai_update_task(row.clone()).await?;
        self.publish(
            owner,
            task_id,
            TaskEvent::Message {
                role: "user".into(),
                text: text.to_string(),
                provider: None,
            },
        );
        self.spawn(row);
        self.get(owner, task_id, false).await
    }

    async fn check_limits(&self, owner: Id) -> Result<(), AiError> {
        let running = self
            .live
            .lock()
            .values()
            .filter(|t| t.owner == owner)
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
        let hosts = match &ctx.host_ids {
            Some(ids) => {
                let hosts = self
                    .store
                    .list::<termoak_core::model::Host>(owner)
                    .await
                    .unwrap_or_default();
                Some(
                    hosts
                        .iter()
                        .filter(|h| ids.contains(&h.data.id))
                        .map(|h| format!("{} ({})", h.data.label, h.data.id))
                        .collect::<Vec<_>>(),
                )
            }
            None => None,
        };
        let memories: Vec<String> = self
            .store
            .list::<Memory>(owner)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|m| m.data.content)
            .collect();
        crate::agent::context_block(
            mode,
            hosts.as_deref(),
            ctx.session_id.map(|s| s.to_string()).as_deref(),
            &memories,
        )
    }

    fn spawn(self: &Arc<Self>, row: AiTaskRow) {
        let ctx: TaskContext = serde_json::from_value(row.context.clone()).unwrap_or_default();
        let mode = PermissionMode::parse(&row.mode).unwrap_or_default();
        let live = Arc::new(LiveTask {
            id: row.id,
            owner: row.owner_id,
            cancel: CancellationToken::new(),
            mode: Mutex::new(mode),
            approvals: Mutex::new(HashMap::new()),
            ctx: ToolContext {
                owner: row.owner_id,
                task_id: Some(row.id),
                host_scope: ctx.host_ids.clone(),
            },
        });
        self.live.lock().insert(row.id, live.clone());
        let engine = self.clone();
        tokio::spawn(async move {
            // Initialize the event sequence from what is already saved.
            let last = engine
                .store
                .ai_events_since(row.id, 0)
                .await
                .ok()
                .and_then(|v| v.last().map(|e| e.seq))
                .unwrap_or(0);
            engine
                .seqs
                .lock()
                .insert(row.id, Arc::new(AtomicI64::new(last)));
            engine.run(live, row, ctx).await;
        });
    }

    async fn run(self: Arc<Self>, live: Arc<LiveTask>, mut row: AiTaskRow, ctx: TaskContext) {
        let owner = row.owner_id;
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
                let run = AgentRun {
                    registry: &self.registry,
                    chain,
                    tools: self.tools.specs(),
                    system: SYSTEM_PROMPT.to_string(),
                    session_id: format!("ses_{}", row.id.simple()),
                    max_steps: self.config().max_steps,
                    effort: ctx.effort.clone(),
                    mcp: mcp_url.zip(mcp_token.clone()),
                    cancel: live.cancel.clone(),
                };
                run_agent(run, &mut messages, &hooks).await
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
        row.finished_at = Some(now_ms());
        let (status, result_text, error) = match result {
            Ok(outcome) => {
                row.used_provider = outcome.used_provider.clone();
                let mut usage: Usage =
                    serde_json::from_value(row.usage.clone()).unwrap_or_default();
                usage.add(&outcome.usage);
                row.usage = serde_json::to_value(&usage).unwrap_or_default();
                row.cost_micros += outcome.cost_micros;
                (TaskStatus::Completed, Some(outcome.final_text), None)
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
        let _ = tx.send((approve, always));
        self.store
            .ai_decide_approval(approval_id, if approve { "approved" } else { "denied" }, by)
            .await?;
        Ok(())
    }

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
    /// to the following messages).
    pub async fn set_mode(
        &self,
        owner: Id,
        task_id: Id,
        mode: PermissionMode,
    ) -> Result<(), AiError> {
        let live = self
            .live
            .lock()
            .get(&task_id)
            .cloned()
            .filter(|l| l.owner == owner);
        if let Some(live) = live {
            *live.mode.lock() = mode;
        }
        if !self
            .store
            .ai_set_mode(owner, task_id, mode.as_str())
            .await?
        {
            return Err(AiError::NotFound(format!("task {task_id}")));
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
        }
    }

    pub async fn get(&self, owner: Id, id: Id, with_messages: bool) -> Result<TaskView, AiError> {
        let row = self.store.ai_task(owner, id).await?;
        let pending = self
            .store
            .ai_approvals(id)
            .await?
            .into_iter()
            .filter(|a| a.status == "pending")
            .collect();
        Ok(self.view(row, with_messages, pending))
    }

    pub async fn list(&self, owner: Id, limit: i64) -> Result<Vec<TaskView>, AiError> {
        let rows = self.store.ai_list_tasks(owner, limit.clamp(1, 500)).await?;
        let pending = self.store.ai_pending_approvals(owner).await?;
        Ok(rows
            .into_iter()
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

    pub async fn delete(&self, owner: Id, id: Id) -> Result<(), AiError> {
        if self.live.lock().contains_key(&id) {
            return Err(AiError::Invalid(
                "cancel the task before deleting it".into(),
            ));
        }
        self.store.ai_delete_task(owner, id).await?;
        self.seqs.lock().remove(&id);
        Ok(())
    }

    pub async fn pending_approvals(&self, owner: Id) -> Result<Vec<AiApprovalRow>, AiError> {
        Ok(self.store.ai_pending_approvals(owner).await?)
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
                if self.request_approval(call_id, name, input, &summary).await {
                    self.execute(name, input, &summary).await
                } else {
                    ToolOutcome {
                        ok: false,
                        content: "The user did NOT approve this action. Do not retry it in another form; explain alternatives or ask.".into(),
                    }
                }
            }
            Verdict::Allow => self.execute(name, input, &summary).await,
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

impl EngineHooks {
    async fn execute(&self, name: &str, input: &Value, summary: &str) -> ToolOutcome {
        let outcome = self.engine.tools.execute(&self.live.ctx, name, input).await;
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
                    json!({"summary": summary, "ok": outcome.ok}),
                )
                .await;
        }
        outcome
    }

    async fn request_approval(
        &self,
        call_id: &str,
        name: &str,
        input: &Value,
        summary: &str,
    ) -> bool {
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
            })
            .await;
        self.emit(TaskEvent::ApprovalRequested {
            approval_id,
            call_id: call_id.to_string(),
            tool: name.to_string(),
            summary: summary.to_string(),
            input: input.clone(),
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
        let (approved, by) = match decision {
            Some((approved, always)) => {
                if approved && always {
                    *self.live.mode.lock() = PermissionMode::Auto;
                }
                (approved, "user".to_string())
            }
            None => {
                self.live.approvals.lock().remove(&approval_id);
                let _ = self
                    .engine
                    .store
                    .ai_decide_approval(approval_id, "expired", "timeout")
                    .await;
                (false, "timeout".to_string())
            }
        };
        self.emit(TaskEvent::ApprovalDecided {
            approval_id,
            approved,
            by,
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
        approved
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

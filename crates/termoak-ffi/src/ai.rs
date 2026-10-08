//! Typed background AI on top of the server's AI API (servers 0.6+): what an
//! approval is about (`AiApprovalPreview`), answering it with an edit or a
//! reason (`decide_approval_with`), plans, steps and multi-host tasks,
//! runbooks, providers and the quick assistant (`ai_suggest`,
//! `ai_explain`).
//!
//! The records are read leniently from the server's JSON: a field an older
//! server does not send is empty, never an error.

use serde_json::{Value, json};
use termoak_core::model as cm;

use crate::accounts::AccountHandle;
use crate::error::{Result, TermoakError};
use crate::models::{Snippet, parse_id, parse_opt_id};
use crate::server::{AiTaskStatus, str_of};
use crate::vault::TermoakCore;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// How risky an action looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AiRiskLevel {
    /// Only reads.
    Low,
    /// Changes something.
    Medium,
    /// Destructive or hard to undo (deleting data, disks, reboots...).
    High,
}

impl AiRiskLevel {
    fn parse(s: &str) -> Self {
        match s {
            "low" => Self::Low,
            "high" => Self::High,
            _ => Self::Medium,
        }
    }
}

/// One of the reasons for a risk level.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AiRiskReason {
    /// Stable code to translate: `pipe`, `chain`, `redirect`,
    /// `substitution`, `sudo`, `rm_rf`, `delete`, `disk`, `reboot`,
    /// `service`, `packages`, `firewall`, `permissions`, `kill`, `users`,
    /// `remote_script`, `containers`, `cron`, `git_history`, `system_path`,
    /// `redacted`, `changes`...
    pub code: String,
    /// English text.
    pub text: String,
}

/// What an approval is about, to show it instead of the raw arguments.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct AiApprovalPreview {
    /// `command` (run_command), `terminal` (send_to_terminal), `file`
    /// (write_file), `plan` (a `plan_first` task's plan) or `other`.
    pub kind: String,
    /// Exact command (or text typed into a terminal).
    pub command: Option<String>,
    /// Host as the model named it, or the terminal's title.
    pub host: Option<String>,
    pub risk: AiRiskLevel,
    pub reasons: Vec<AiRiskReason>,
    /// Why the model wants to do it.
    pub explanation: Option<String>,
    /// File written (`file`).
    pub path: Option<String>,
    /// Unified diff of the file (`--- a/…`, `+++ b/…`, hunks).
    pub diff: Option<String>,
    /// Lines added and removed by the write.
    pub added: Option<u32>,
    pub removed: Option<u32>,
    /// The file does not exist yet.
    pub new_file: bool,
    /// The diff was cut (at 64 KB).
    pub truncated: bool,
    /// Why there is no diff (unreadable, binary or too large file).
    pub diff_error: Option<String>,
    /// The plan to approve (`plan`).
    pub plan: Option<String>,
    /// It can be edited before approving (`AiDecision::edited`).
    pub editable: bool,
}

fn opt_str(v: &Value) -> Option<String> {
    v.as_str().map(str::to_string)
}

fn opt_u32(v: &Value) -> Option<u32> {
    v.as_u64().map(|n| u32::try_from(n).unwrap_or(u32::MAX))
}

impl AiApprovalPreview {
    /// `None` without a preview (servers before 0.6).
    pub(crate) fn from_json(v: &Value) -> Option<Self> {
        if !v.is_object() {
            return None;
        }
        Some(AiApprovalPreview {
            kind: v["kind"].as_str().unwrap_or("other").to_string(),
            command: opt_str(&v["command"]),
            host: opt_str(&v["host"]),
            risk: AiRiskLevel::parse(v["risk"].as_str().unwrap_or("")),
            reasons: v["reasons"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|r| AiRiskReason {
                            code: str_of(&r["code"]),
                            text: str_of(&r["text"]),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            explanation: opt_str(&v["explanation"]),
            path: opt_str(&v["path"]),
            diff: opt_str(&v["diff"]),
            added: opt_u32(&v["added"]),
            removed: opt_u32(&v["removed"]),
            new_file: v["new_file"].as_bool().unwrap_or(false),
            truncated: v["diff_truncated"].as_bool().unwrap_or(false),
            diff_error: opt_str(&v["diff_error"]),
            plan: opt_str(&v["plan"]),
            editable: v["editable"].as_bool().unwrap_or(false),
        })
    }
}

/// The answer to an approval.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AiDecision {
    pub approve: bool,
    /// Also approve the task's next actions (switches it to autonomous).
    #[uniffi(default)]
    pub always: bool,
    /// With `approve`, for previews with `editable`: the command or plan to
    /// use instead of the model's. It is what runs, and the model is told.
    #[uniffi(default)]
    pub edited: Option<String>,
    /// Why it was denied (sent to the model, which does not retry the same
    /// action another way), or a note with an approval.
    #[uniffi(default)]
    pub reason: Option<String>,
}

impl AiDecision {
    pub(crate) fn body(&self) -> Value {
        let mut body = json!({"approve": self.approve, "always": self.always});
        if self.approve
            && let Some(e) = self
                .edited
                .as_deref()
                .map(str::trim)
                .filter(|e| !e.is_empty())
        {
            body["edited"] = json!(e);
        }
        if let Some(r) = self
            .reason
            .as_deref()
            .map(str::trim)
            .filter(|r| !r.is_empty())
        {
            body["reason"] = json!(r);
        }
        body
    }
}

/// The plan of a `plan_first` task.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AiTaskPlan {
    pub text: String,
    pub approved: bool,
    /// You edited it before approving it.
    pub edited: bool,
}

impl AiTaskPlan {
    pub(crate) fn from_json(v: &Value) -> Option<Self> {
        v.is_object().then(|| AiTaskPlan {
            text: str_of(&v["text"]),
            approved: v["approved"].as_bool().unwrap_or(false),
            edited: v["edited"].as_bool().unwrap_or(false),
        })
    }
}

/// A command or file write the task ran.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AiTaskStep {
    pub call_id: String,
    /// `run_command`, `send_to_terminal` or `write_file`.
    pub tool: String,
    pub host: Option<String>,
    /// What ran (your edit, if you edited it).
    pub command: Option<String>,
    /// File written.
    pub path: Option<String>,
    pub ok: bool,
    /// You edited it before approving.
    pub edited: bool,
    /// The model's reason for it.
    pub explanation: Option<String>,
    /// When (ms since the epoch).
    pub at: i64,
}

impl AiTaskStep {
    pub(crate) fn list_from_json(v: &Value) -> Vec<Self> {
        v.as_array()
            .map(|a| {
                a.iter()
                    .map(|s| AiTaskStep {
                        call_id: str_of(&s["call_id"]),
                        tool: str_of(&s["tool"]),
                        host: opt_str(&s["host"]),
                        command: opt_str(&s["command"]),
                        path: opt_str(&s["path"]),
                        ok: s["ok"].as_bool().unwrap_or(false),
                        edited: s["edited"].as_bool().unwrap_or(false),
                        explanation: opt_str(&s["explanation"]),
                        at: s["at"].as_i64().unwrap_or(0),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// One host of a multi-host (`fan_out`) task.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct AiHostRun {
    pub host_id: String,
    pub label: String,
    /// The host's own task (its conversation, approvals and steps).
    pub task_id: String,
    pub status: AiTaskStatus,
    /// Its result, shortened.
    pub summary: Option<String>,
    pub error: Option<String>,
    pub duration_ms: Option<i64>,
    pub cost_micros: i64,
    pub pending_approvals: u32,
}

impl AiHostRun {
    pub(crate) fn list_from_json(v: &Value) -> Vec<Self> {
        v.as_array()
            .map(|a| {
                a.iter()
                    .map(|h| AiHostRun {
                        host_id: str_of(&h["host_id"]),
                        label: str_of(&h["label"]),
                        task_id: str_of(&h["task_id"]),
                        status: AiTaskStatus::parse(h["status"].as_str().unwrap_or("")),
                        summary: opt_str(&h["summary"]),
                        error: opt_str(&h["error"]),
                        duration_ms: h["duration_ms"].as_i64(),
                        cost_micros: h["cost_micros"].as_i64().unwrap_or(0),
                        pending_approvals: opt_u32(&h["pending_approvals"]).unwrap_or(0),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// What a task ran, as a snippet to review before saving it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AiRunbook {
    /// Suggested name (the task's title).
    pub name: String,
    pub description: String,
    /// The script (`{{host}}` where the host's name or address was).
    pub script: String,
    /// Its `{{variables}}`.
    pub variables: Vec<String>,
    /// Commands and file writes in it (0: nothing to save).
    pub steps: u32,
}

/// An AI provider of the server.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AiProvider {
    /// What `AiTaskRequest::provider` takes (`claude`, `gpt`, `codex`...).
    pub key: String,
    pub label: String,
    /// `anthropic`, `openai`, `codex`, `opencode`, `local`...
    pub driver: String,
    /// Usable by you now (your plan and your own keys considered).
    pub available: bool,
    /// Hidden from pickers by the server's configuration.
    pub hidden: bool,
    pub default_model: Option<String>,
    pub models: Vec<String>,
    /// Runs on a subscription (Codex with ChatGPT...).
    pub subscription: bool,
    /// Why it is not available (English).
    pub reason: Option<String>,
    /// Stable code of `reason` to translate: `not_configured`,
    /// `own_key_required` (add your own key) or `plan`.
    pub reason_code: Option<String>,
    /// Accepts your own API key (`set_ai_key`).
    pub accepts_own_key: bool,
    /// Runs with your own API key.
    pub uses_own_key: bool,
}

/// The server's AI providers and defaults.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AiProviders {
    /// Default provider (`provider` or `provider::model`).
    pub default_provider: Option<String>,
    /// Fallback chain.
    pub fallback: Vec<String>,
    /// Default permission mode of new tasks.
    pub default_mode: Option<crate::server::AiPermissionMode>,
    pub providers: Vec<AiProvider>,
}

impl AiProviders {
    pub(crate) fn from_json(v: &Value) -> Self {
        let strings = |v: &Value| -> Vec<String> {
            match v {
                Value::Array(a) => a
                    .iter()
                    .filter_map(|s| s.as_str().map(str::to_string))
                    .collect(),
                Value::String(s) if !s.is_empty() => vec![s.clone()],
                _ => Vec::new(),
            }
        };
        AiProviders {
            default_provider: opt_str(&v["default"]).filter(|d| !d.is_empty()),
            fallback: strings(&v["fallback"]),
            default_mode: v["default_mode"]
                .as_str()
                .map(crate::server::AiPermissionMode::parse),
            providers: v["providers"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|p| AiProvider {
                            key: str_of(&p["key"]),
                            label: str_of(&p["label"]),
                            driver: str_of(&p["driver"]),
                            available: p["available"].as_bool().unwrap_or(false),
                            hidden: p["hidden"].as_bool().unwrap_or(false),
                            default_model: opt_str(&p["default_model"]),
                            models: strings(&p["models"]),
                            subscription: p["subscription"].as_bool().unwrap_or(false),
                            reason: opt_str(&p["reason"]),
                            reason_code: opt_str(&p["reason_code"]),
                            accepts_own_key: p["accepts_own_key"].as_bool().unwrap_or(false),
                            uses_own_key: p["uses_own_key"].as_bool().unwrap_or(false),
                        })
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

/// Terminal context for the quick assistant.
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct AiAssistContext {
    /// Host OS (`ubuntu`, `alpine`...).
    #[uniffi(default)]
    pub os: Option<String>,
    /// Last visible terminal output. Its secrets are hidden on the device
    /// (`redact_secrets`) before it is sent.
    #[uniffi(default)]
    pub screen: Option<String>,
    #[uniffi(default)]
    pub cwd: Option<String>,
}

impl AiAssistContext {
    fn to_json(&self) -> Value {
        json!({
            "os": self.os,
            "screen": self.screen.as_deref().map(termoak_core::redact::redact_terminal),
            "cwd": self.cwd,
        })
    }
}

/// A command suggested by the quick assistant.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AiCommandSuggestion {
    pub command: String,
    /// One short sentence.
    pub explanation: String,
    /// `read` (read-only), `write` (changes something) or `dangerous`.
    pub risk: String,
    /// Provider that answered.
    pub provider: String,
}

/// The quick assistant's explanation of an output or an error.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AiExplanation {
    /// Markdown.
    pub answer: String,
    /// Provider that answered.
    pub provider: String,
}

// ---------------------------------------------------------------------------
// Calls (the current account; `AccountHandle` has the same per account)
// ---------------------------------------------------------------------------

#[uniffi::export]
impl TermoakCore {
    /// Answers an approval with every option: `edited` (approve this
    /// command or plan instead of the model's) and `reason` (why it was
    /// denied, for the model). Servers before 0.6 ignore both.
    pub async fn decide_approval_with(
        &self,
        task_id: String,
        approval_id: String,
        decision: AiDecision,
    ) -> Result<()> {
        let task = parse_id(&task_id)?;
        let approval = parse_id(&approval_id)?;
        let body = decision.body();
        self.with_api(move |api| async move {
            api.post::<Value>(
                &format!("/api/v1/ai/tasks/{task}/approvals/{approval}"),
                &body,
            )
            .await?;
            Ok(())
        })
        .await
    }

    /// Deletes a task (cancel it first if it is running).
    pub async fn delete_ai_task(&self, task_id: String) -> Result<()> {
        let id = parse_id(&task_id)?;
        self.with_api(move |api| async move {
            api.delete(&format!("/api/v1/ai/tasks/{id}")).await?;
            Ok(())
        })
        .await
    }

    /// What the task ran, as a snippet to review (`steps == 0`: nothing).
    pub async fn get_runbook(&self, task_id: String) -> Result<AiRunbook> {
        let id = parse_id(&task_id)?;
        self.with_api(move |api| async move {
            let v: Value = api.get(&format!("/api/v1/ai/tasks/{id}/runbook")).await?;
            Ok(AiRunbook {
                name: str_of(&v["name"]),
                description: str_of(&v["description"]),
                script: str_of(&v["script"]),
                variables: v["variables"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|s| s.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
                steps: opt_u32(&v["steps"]).unwrap_or(0),
            })
        })
        .await
    }

    /// Saves the task's runbook as a snippet (tags `ai` and `runbook`) in
    /// `vault_id` (default: your personal vault; you must be an Editor
    /// there), named `name` (default: the task's title), and syncs so it
    /// shows up in the snippets. `Invalid` (`runbook_empty`) if the task
    /// ran no commands.
    #[uniffi::method(default(vault_id = None, name = None))]
    pub async fn save_runbook(
        &self,
        task_id: String,
        vault_id: Option<String>,
        name: Option<String>,
    ) -> Result<Snippet> {
        let id = parse_id(&task_id)?;
        let vault = parse_opt_id(&vault_id)?;
        let mut body = json!({});
        if let Some(v) = vault {
            body["vault_id"] = json!(v);
        }
        if let Some(n) = name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty()) {
            body["name"] = json!(n);
        }
        let account = self.account_now()?;
        self.with_api(move |api| async move {
            let v: Value = api
                .post(&format!("/api/v1/ai/tasks/{id}/runbook"), &body)
                .await?;
            let rec: cm::Record<cm::Snippet> = serde_json::from_value(v)
                .map_err(|e| TermoakError::Server(format!("unexpected server response: {e}")))?;
            let mut snippet = Snippet::from(rec);
            snippet.account_id = Some(account.id.to_string());
            // Best effort: the next sync brings it otherwise.
            if let Err(e) = account.sync_once().await {
                tracing::warn!(error = %e, "sync after saving a runbook failed");
            }
            Ok(snippet)
        })
        .await
    }

    /// The server's AI providers, whether you can use each one and why not.
    pub async fn list_ai_providers(&self) -> Result<AiProviders> {
        self.with_api(|api| async move {
            let v: Value = api.get("/api/v1/ai/providers").await?;
            Ok(AiProviders::from_json(&v))
        })
        .await
    }

    /// Quick assistant: one shell command for a request in natural language.
    #[uniffi::method(default(context = None, provider = None))]
    pub async fn ai_suggest(
        &self,
        request: String,
        context: Option<AiAssistContext>,
        provider: Option<String>,
    ) -> Result<AiCommandSuggestion> {
        if request.trim().is_empty() {
            return Err(TermoakError::Invalid("the request is empty".into()));
        }
        let body = json!({
            "request": request,
            "context": context.map(|c| c.to_json()),
            "provider": provider,
        });
        self.with_api(move |api| async move {
            let v: Value = api.post("/api/v1/ai/suggest", &body).await?;
            Ok(AiCommandSuggestion {
                command: str_of(&v["command"]),
                explanation: str_of(&v["explanation"]),
                risk: str_of(&v["risk"]),
                provider: str_of(&v["provider"]),
            })
        })
        .await
    }

    /// Quick assistant: explains an output or an error (`question`: what
    /// to ask about it). `text` is sent as given: pass it through
    /// `redact_secrets` first if it may hold secrets.
    #[uniffi::method(default(question = None, context = None, provider = None))]
    pub async fn ai_explain(
        &self,
        text: String,
        question: Option<String>,
        context: Option<AiAssistContext>,
        provider: Option<String>,
    ) -> Result<AiExplanation> {
        let body = json!({
            "text": text,
            "question": question,
            "context": context.map(|c| c.to_json()),
            "provider": provider,
        });
        self.with_api(move |api| async move {
            let v: Value = api.post("/api/v1/ai/explain", &body).await?;
            Ok(AiExplanation {
                answer: str_of(&v["answer"]),
                provider: str_of(&v["provider"]),
            })
        })
        .await
    }
}

#[uniffi::export]
impl AccountHandle {
    /// See [`TermoakCore::decide_approval_with`].
    pub async fn decide_approval_with(
        &self,
        task_id: String,
        approval_id: String,
        decision: AiDecision,
    ) -> Result<()> {
        self.core()
            .decide_approval_with(task_id, approval_id, decision)
            .await
    }

    pub async fn delete_ai_task(&self, task_id: String) -> Result<()> {
        self.core().delete_ai_task(task_id).await
    }

    pub async fn get_runbook(&self, task_id: String) -> Result<AiRunbook> {
        self.core().get_runbook(task_id).await
    }

    /// See [`TermoakCore::save_runbook`].
    #[uniffi::method(default(vault_id = None, name = None))]
    pub async fn save_runbook(
        &self,
        task_id: String,
        vault_id: Option<String>,
        name: Option<String>,
    ) -> Result<Snippet> {
        self.core().save_runbook(task_id, vault_id, name).await
    }

    pub async fn list_ai_providers(&self) -> Result<AiProviders> {
        self.core().list_ai_providers().await
    }

    #[uniffi::method(default(context = None, provider = None))]
    pub async fn ai_suggest(
        &self,
        request: String,
        context: Option<AiAssistContext>,
        provider: Option<String>,
    ) -> Result<AiCommandSuggestion> {
        self.core().ai_suggest(request, context, provider).await
    }

    #[uniffi::method(default(question = None, context = None, provider = None))]
    pub async fn ai_explain(
        &self,
        text: String,
        question: Option<String>,
        context: Option<AiAssistContext>,
        provider: Option<String>,
    ) -> Result<AiExplanation> {
        self.core()
            .ai_explain(text, question, context, provider)
            .await
    }
}

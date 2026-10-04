//! MCP server (Model Context Protocol, JSON-RPC 2.0 over HTTP).
//!
//! Exposes Termoak's tools to:
//! - **Codex** during a task: it uses a task token, and every call goes
//!   through that task's permissions and approvals and shows up in its history.
//! - **External agents** (Claude Code, Codex, OpenCode...) with a user token:
//!   they use the mode configured in `mcp_user_mode` (read-only by default;
//!   mutating actions are denied because there is nowhere to ask for
//!   approval).
//!
//! The JSON-RPC part ([`handle`]) does not depend on the engine: the desktop
//! app serves its own tools with it, over [`crate::mcp_http`].

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};
use termoak_core::{Id, new_id};

use crate::engine::AiEngine;
use crate::policy::{PermissionMode, Verdict, decide};
use crate::provider::ToolSpec;
use crate::tools::{ToolContext, ToolOutcome, ToolRuntime};

/// Tools served over MCP and how to run them.
#[async_trait]
pub trait McpTools: Send + Sync {
    fn specs(&self) -> Vec<ToolSpec>;
    /// Runs a tool (already known to exist). `Err` = JSON-RPC error
    /// (code, message).
    async fn call(&self, name: &str, args: &Value) -> Result<ToolOutcome, (i64, String)>;
}

/// Handles a JSON-RPC request (or batch). `None` = no response (notifications).
pub async fn handle(tools: &dyn McpTools, request: Value) -> Option<Value> {
    match request {
        Value::Array(batch) => {
            let mut out = Vec::new();
            for r in batch {
                if let Some(resp) = handle_one(tools, &r).await {
                    out.push(resp);
                }
            }
            (!out.is_empty()).then_some(Value::Array(out))
        }
        other => handle_one(tools, &other).await,
    }
}

async fn handle_one(tools: &dyn McpTools, req: &Value) -> Option<Value> {
    let id = req.get("id").cloned();
    let method = req["method"].as_str().unwrap_or("");
    if id.is_none() || method.starts_with("notifications/") {
        return None;
    }
    let result: Result<Value, (i64, String)> = match method {
        "initialize" => Ok(json!({
            "protocolVersion": req["params"]["protocolVersion"].as_str().unwrap_or(PROTOCOL_VERSION),
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {"name": "termoak", "title": "Termoak", "version": env!("CARGO_PKG_VERSION")},
            "instructions": "Termoak tools to operate the user's SSH servers. Use list_hosts to see the hosts. Actions that change anything may require the user's approval.",
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({
            "tools": tools.specs().into_iter().map(|t| json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": t.schema,
            })).collect::<Vec<_>>()
        })),
        "tools/call" => call(tools, &req["params"]).await,
        _ => Err((-32601, format!("unsupported method: {method}"))),
    };
    Some(match result {
        Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
        Err((code, message)) => {
            json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
        }
    })
}

async fn call(tools: &dyn McpTools, params: &Value) -> Result<Value, (i64, String)> {
    let name = params["name"]
        .as_str()
        .ok_or((-32602, "missing tool name".to_string()))?;
    if !tools.specs().iter().any(|t| t.name == name) {
        return Err((-32602, format!("unknown tool: {name}")));
    }
    let args = match &params["arguments"] {
        Value::Null => json!({}),
        v => v.clone(),
    };
    let outcome = tools.call(name, &args).await?;
    Ok(json!({
        "content": [{"type": "text", "text": outcome.content}],
        "isError": !outcome.ok,
    }))
}

/// The engine's tools for one caller.
struct EngineMcp<'a> {
    engine: &'a Arc<AiEngine>,
    caller: &'a McpCaller,
}

#[async_trait]
impl McpTools for EngineMcp<'_> {
    fn specs(&self) -> Vec<ToolSpec> {
        self.engine.tools().specs()
    }

    async fn call(&self, name: &str, args: &Value) -> Result<ToolOutcome, (i64, String)> {
        self.engine.mcp_call(self.caller, name, args).await
    }
}

/// Who is calling the MCP endpoint.
#[derive(Debug, Clone)]
pub enum McpCaller {
    /// Temporary task token (Codex).
    TaskToken(String),
    /// User authenticated with their access token.
    User { owner: Id, mode: PermissionMode },
}

const PROTOCOL_VERSION: &str = "2025-06-18";

impl AiEngine {
    /// Is this a valid task MCP token?
    pub fn is_task_mcp_token(&self, token: &str) -> bool {
        self.mcp_grant(token).is_some()
    }

    /// Handles a JSON-RPC request (or batch). `None` = no response (notifications).
    pub async fn mcp_handle(self: &Arc<Self>, caller: &McpCaller, request: Value) -> Option<Value> {
        handle(
            &EngineMcp {
                engine: self,
                caller,
            },
            request,
        )
        .await
    }

    async fn mcp_call(
        self: &Arc<Self>,
        caller: &McpCaller,
        name: &str,
        args: &Value,
    ) -> Result<ToolOutcome, (i64, String)> {
        let args = args.clone();
        let outcome = match caller {
            McpCaller::TaskToken(token) => {
                let (_, task_id) = self
                    .mcp_grant(token)
                    .ok_or((-32001, "invalid or expired MCP token".to_string()))?;
                self.call_tool_for_task(task_id, &format!("mcp_{}", new_id().simple()), name, &args)
                    .await
                    .ok_or((-32001, "the task is no longer active".to_string()))?
            }
            McpCaller::User { owner, mode } => {
                let effect = ToolRuntime::effect(name, &args);
                match decide(*mode, name, effect) {
                    Verdict::Allow => {
                        let ctx = ToolContext {
                            owner: *owner,
                            task_id: None,
                            host_scope: None,
                        };
                        let out = self.tools().execute(&ctx, name, &args).await;
                        let _ = self
                            .store_ref()
                            .audit(
                                *owner,
                                "mcp:external",
                                &format!("mcp.tool.{name}"),
                                args["host"].as_str().map(str::to_string),
                                json!({"summary": ToolRuntime::summarize(name, &args), "ok": out.ok}),
                            )
                            .await;
                        out
                    }
                    Verdict::NeedsApproval | Verdict::Deny(_) => ToolOutcome {
                        ok: false,
                        content: "This action changes the system and external MCP access is read-only. Create a task in Termoak so it can be approved.".into(),
                    },
                }
            }
        };
        Ok(outcome)
    }
}

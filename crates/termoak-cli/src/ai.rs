//! AI from the terminal: background tasks with interactive approvals.

use std::io::Write;

use anyhow::{Context, Result};
use clap::Subcommand;
use futures::StreamExt;
use serde_json::{Value, json};
use termoak_client::Workspace;
use tokio_tungstenite::tungstenite::Message;

use crate::data::{find_hosts, need_server};

#[derive(Subcommand)]
pub enum AiCmd {
    /// Asks the AI for something (runs on the server, in the background).
    Ask {
        prompt: String,
        /// read_only | ask | auto
        #[arg(long, default_value = "ask")]
        mode: String,
        /// Provider (`codex`, `opencode-api::kimi-k2.6`, `claude`...).
        #[arg(long)]
        provider: Option<String>,
        /// Limit to these hosts (comma-separated).
        #[arg(long)]
        hosts: Option<String>,
        /// Don't wait: start it and exit.
        #[arg(long)]
        detach: bool,
    },
    /// Continues a conversation.
    Reply { task: String, text: String },
    /// Lists the tasks.
    Tasks,
    /// Shows a task.
    Show { task: String },
    /// Follows a task live.
    Follow { task: String },
    /// Cancels a task.
    Cancel { task: String },
    /// Pending approvals.
    Pending,
    /// Approves or denies an action.
    Approve {
        task: String,
        approval: String,
        #[arg(long)]
        deny: bool,
        #[arg(long)]
        always: bool,
    },
    /// From natural language to a command.
    Suggest { request: String },
    /// Explains an error or some output (reads standard input if no text is given).
    Explain { text: Option<String> },
    /// Available providers and models.
    Providers,
}

pub async fn run(ws: &Workspace, cmd: AiCmd, json: bool) -> Result<()> {
    let api = need_server(ws).await?;
    match cmd {
        AiCmd::Ask {
            prompt,
            mode,
            provider,
            hosts,
            detach,
        } => {
            let host_ids = match hosts {
                Some(h) => Some(
                    find_hosts(ws, &h)
                        .await?
                        .into_iter()
                        .map(|h| h.id)
                        .collect::<Vec<_>>(),
                ),
                None => None,
            };
            let task: Value = api
                .post("/api/v1/ai/tasks", &json!({"prompt": prompt, "mode": mode, "provider": provider, "host_ids": host_ids}))
                .await?;
            let id = task["id"]
                .as_str()
                .context("response without id")?
                .to_string();
            if detach {
                println!("Task {id} started. Follow it with `termoak ai follow {id}`.");
                return Ok(());
            }
            follow(&api, &id).await?;
        }
        AiCmd::Reply { task, text } => {
            let _: Value = api
                .post(
                    &format!("/api/v1/ai/tasks/{task}/messages"),
                    &json!({"text": text}),
                )
                .await?;
            follow(&api, &task).await?;
        }
        AiCmd::Tasks => {
            let list: Value = api.get("/api/v1/ai/tasks").await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                for t in list.as_array().into_iter().flatten() {
                    println!(
                        "{}  {:17} {:50} {}",
                        t["id"].as_str().unwrap_or(""),
                        t["status"].as_str().unwrap_or(""),
                        t["title"]
                            .as_str()
                            .unwrap_or("")
                            .chars()
                            .take(50)
                            .collect::<String>(),
                        t["used_provider"].as_str().unwrap_or("")
                    );
                }
            }
        }
        AiCmd::Show { task } => {
            let t: Value = api.get(&format!("/api/v1/ai/tasks/{task}")).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&t)?);
            } else {
                println!(
                    "{} — {}",
                    t["title"].as_str().unwrap_or(""),
                    t["status"].as_str().unwrap_or("")
                );
                if let Some(r) = t["result"].as_str() {
                    println!("\n{r}");
                }
                if let Some(e) = t["error"].as_str() {
                    println!("\nError: {e}");
                }
            }
        }
        AiCmd::Follow { task } => follow(&api, &task).await?,
        AiCmd::Cancel { task } => {
            let _: Value = api
                .post(&format!("/api/v1/ai/tasks/{task}/cancel"), &json!({}))
                .await?;
            println!("Cancelled.");
        }
        AiCmd::Pending => {
            let list: Value = api.get("/api/v1/ai/approvals").await?;
            for a in list.as_array().into_iter().flatten() {
                println!(
                    "{}  task {}  {}",
                    a["id"].as_str().unwrap_or(""),
                    a["task_id"].as_str().unwrap_or(""),
                    a["summary"].as_str().unwrap_or("")
                );
            }
        }
        AiCmd::Approve {
            task,
            approval,
            deny,
            always,
        } => {
            let _: Value = api
                .post(
                    &format!("/api/v1/ai/tasks/{task}/approvals/{approval}"),
                    &json!({"approve": !deny, "always": always}),
                )
                .await?;
            println!("{}", if deny { "Denied." } else { "Approved." });
        }
        AiCmd::Suggest { request } => {
            let s: Value = api
                .post("/api/v1/ai/suggest", &json!({"request": request}))
                .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&s)?);
            } else {
                println!("{}", s["command"].as_str().unwrap_or(""));
                eprintln!(
                    "# {} [{}]",
                    s["explanation"].as_str().unwrap_or(""),
                    s["risk"].as_str().unwrap_or("")
                );
            }
        }
        AiCmd::Explain { text } => {
            let text = match text {
                Some(t) => t,
                None => {
                    let mut s = String::new();
                    std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
                    s
                }
            };
            let r: Value = api
                .post("/api/v1/ai/explain", &json!({"text": text}))
                .await?;
            println!("{}", r["answer"].as_str().unwrap_or(""));
        }
        AiCmd::Providers => {
            let p: Value = api.get("/api/v1/ai/providers").await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&p)?);
            } else {
                println!(
                    "Default: {}  · fallback: {}",
                    p["default"].as_str().unwrap_or(""),
                    p["fallback"]
                        .as_array()
                        .map(|a| a
                            .iter()
                            .filter_map(|x| x.as_str())
                            .collect::<Vec<_>>()
                            .join(", "))
                        .unwrap_or_default()
                );
                for x in p["providers"].as_array().into_iter().flatten() {
                    println!(
                        "{} {:14} {:32} {}",
                        if x["available"].as_bool().unwrap_or(false) {
                            "✓"
                        } else {
                            "✗"
                        },
                        x["key"].as_str().unwrap_or(""),
                        x["label"].as_str().unwrap_or(""),
                        x["reason"]
                            .as_str()
                            .unwrap_or_else(|| x["default_model"].as_str().unwrap_or(""))
                    );
                }
            }
        }
    }
    Ok(())
}

/// Follows a task live and handles approvals in the terminal.
async fn follow(api: &termoak_client::ApiClient, task: &str) -> Result<()> {
    let mut ws = api.websocket("/api/v1/events/ws").await?;
    // Current state, in case it already finished or is waiting for approval.
    let current: Value = api.get(&format!("/api/v1/ai/tasks/{task}")).await?;
    for a in current["pending_approvals"]
        .as_array()
        .into_iter()
        .flatten()
    {
        ask_approval(
            api,
            task,
            a["id"].as_str().unwrap_or(""),
            a["summary"].as_str().unwrap_or(""),
        )
        .await?;
    }
    if matches!(
        current["status"].as_str(),
        Some("completed" | "failed" | "cancelled")
    ) && current["pending_approvals"]
        .as_array()
        .is_none_or(|a| a.is_empty())
    {
        print_final(&current);
        return Ok(());
    }
    let mut stdout = std::io::stdout();
    let mut in_reasoning = false;
    while let Some(msg) = ws.next().await {
        let Ok(Message::Text(t)) = msg else { continue };
        let v: Value = serde_json::from_str(&t).unwrap_or(Value::Null);
        if v["type"] != "ai" || v["task_id"].as_str() != Some(task) {
            continue;
        }
        let ev = &v["event"];
        match ev["type"].as_str().unwrap_or("") {
            "reasoning" => {
                if !in_reasoning {
                    eprint!("\x1b[2m");
                    in_reasoning = true;
                }
                eprint!("{}", ev["delta"].as_str().unwrap_or(""));
            }
            "text" => {
                if in_reasoning {
                    eprintln!("\x1b[0m");
                    in_reasoning = false;
                }
                print!("{}", ev["delta"].as_str().unwrap_or(""));
                stdout.flush()?;
            }
            "reset" => println!("\n[discarded: the provider failed midway]"),
            "notice" => eprintln!("\n\x1b[33m{}\x1b[0m", ev["message"].as_str().unwrap_or("")),
            "tool_call" => eprintln!(
                "\n\x1b[36m→ {}\x1b[0m",
                ev["summary"].as_str().unwrap_or("")
            ),
            "tool_result" => {
                let ok = ev["ok"].as_bool().unwrap_or(false);
                let out = ev["output"].as_str().unwrap_or("");
                let preview: String = out.lines().take(8).collect::<Vec<_>>().join("\n");
                eprintln!(
                    "{}{}\x1b[0m",
                    if ok { "\x1b[2m" } else { "\x1b[31m" },
                    preview
                );
            }
            "approval_requested" => {
                if in_reasoning {
                    eprintln!("\x1b[0m");
                    in_reasoning = false;
                }
                ask_approval(
                    api,
                    task,
                    ev["approval_id"].as_str().unwrap_or(""),
                    ev["summary"].as_str().unwrap_or(""),
                )
                .await?;
            }
            "usage" => {}
            "finished" => {
                println!();
                let t: Value = api.get(&format!("/api/v1/ai/tasks/{task}")).await?;
                eprintln!(
                    "\x1b[2m[{} · {} · {:.4} $]\x1b[0m",
                    t["status"].as_str().unwrap_or(""),
                    t["used_provider"].as_str().unwrap_or(""),
                    t["cost_micros"].as_i64().unwrap_or(0) as f64 / 1_000_000.0
                );
                if let Some(e) = t["error"].as_str() {
                    eprintln!("Error: {e}");
                }
                break;
            }
            _ => {}
        }
    }
    Ok(())
}

async fn ask_approval(
    api: &termoak_client::ApiClient,
    task: &str,
    approval: &str,
    summary: &str,
) -> Result<()> {
    let answer = crate::prompt::ask_line(&format!(
        "\n\x1b[1;33mApprove?\x1b[0m {summary}\n[y]es / [n]o / [a]ll for this task: "
    ))?;
    let (approve, always) = match answer.trim().to_lowercase().as_str() {
        "y" | "yes" => (true, false),
        "a" | "all" => (true, true),
        _ => (false, false),
    };
    let _: Value = api
        .post(
            &format!("/api/v1/ai/tasks/{task}/approvals/{approval}"),
            &json!({"approve": approve, "always": always}),
        )
        .await?;
    Ok(())
}

fn print_final(t: &Value) {
    if let Some(r) = t["result"].as_str() {
        println!("{r}");
    }
    if let Some(e) = t["error"].as_str() {
        eprintln!("Error: {e}");
    }
}

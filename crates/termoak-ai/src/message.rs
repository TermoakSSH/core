//! Conversation in a format shared by all providers.
//!
//! Each provider translates these messages to its API. Assistant messages
//! also keep the "native" blocks of the response (Claude's signed thinking
//! blocks, OpenAI's encrypted reasoning items...) to send them back untouched
//! to the SAME model on the next turn. If another provider handles the next
//! turn (fallback), the common version is used and native blocks are ignored.

use serde::{Deserialize, Serialize};

/// Part of a message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Part {
    Text {
        text: String,
    },
    /// Reasoning summary (display only; not resent through the common path).
    Reasoning {
        text: String,
    },
    ToolCall {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    ToolResult {
        id: String,
        content: String,
        #[serde(default)]
        is_error: bool,
    },
}

/// Native response blocks from a specific model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Native {
    /// `driver::model` that produced them.
    pub key: String,
    pub blocks: serde_json::Value,
}

/// Conversation message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum Message {
    User {
        content: Vec<Part>,
    },
    Assistant {
        content: Vec<Part>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        native: Option<Native>,
        /// Provider that answered (`key::model`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider: Option<String>,
    },
}

impl Message {
    pub fn user_text(text: impl Into<String>) -> Self {
        Message::User {
            content: vec![Part::Text { text: text.into() }],
        }
    }

    pub fn parts(&self) -> &[Part] {
        match self {
            Message::User { content } | Message::Assistant { content, .. } => content,
        }
    }

    /// Concatenated visible text.
    pub fn text(&self) -> String {
        self.parts()
            .iter()
            .filter_map(|p| match p {
                Part::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("")
    }

    /// Tool calls of an assistant message.
    pub fn tool_calls(&self) -> Vec<(String, String, serde_json::Value)> {
        match self {
            Message::Assistant { content, .. } => content
                .iter()
                .filter_map(|p| match p {
                    Part::ToolCall { id, name, input } => {
                        Some((id.clone(), name.clone(), input.clone()))
                    }
                    _ => None,
                })
                .collect(),
            Message::User { .. } => Vec::new(),
        }
    }

    /// Native blocks, if they belong to `key`.
    pub fn native_for(&self, key: &str) -> Option<&serde_json::Value> {
        match self {
            Message::Assistant {
                native: Some(n), ..
            } if n.key == key => Some(&n.blocks),
            _ => None,
        }
    }
}

/// Converts the conversation to plain text (for providers without
/// conversation memory, such as Codex CLI or local OpenCode).
pub fn transcript_as_text(messages: &[Message]) -> String {
    let mut out = String::new();
    for m in messages {
        match m {
            Message::User { content } => {
                for p in content {
                    match p {
                        Part::Text { text } => {
                            out.push_str("\n### User\n");
                            out.push_str(text);
                            out.push('\n');
                        }
                        Part::ToolResult {
                            content, is_error, ..
                        } => {
                            out.push_str(if *is_error {
                                "\n[tool result: ERROR]\n"
                            } else {
                                "\n[tool result]\n"
                            });
                            out.push_str(content);
                            out.push('\n');
                        }
                        _ => {}
                    }
                }
            }
            Message::Assistant { content, .. } => {
                for p in content {
                    match p {
                        Part::Text { text } if !text.trim().is_empty() => {
                            out.push_str("\n### Assistant\n");
                            out.push_str(text);
                            out.push('\n');
                        }
                        Part::ToolCall { name, input, .. } => {
                            out.push_str(&format!(
                                "\n[the assistant called {name} with {input}]\n"
                            ));
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    out
}

/// Why a turn stopped.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    EndTurn,
    ToolUse,
    MaxTokens,
    Refusal,
    PauseTurn,
    Other(String),
}

/// Token usage of a turn.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub reasoning_tokens: u64,
    /// Cost reported by the provider itself (USD), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_cost_usd: Option<f64>,
}

impl Usage {
    pub fn add(&mut self, o: &Usage) {
        self.input_tokens += o.input_tokens;
        self.output_tokens += o.output_tokens;
        self.cache_read_tokens += o.cache_read_tokens;
        self.cache_write_tokens += o.cache_write_tokens;
        self.reasoning_tokens += o.reasoning_tokens;
        self.reported_cost_usd = match (self.reported_cost_usd, o.reported_cost_usd) {
            (Some(a), Some(b)) => Some(a + b),
            (a, b) => a.or(b),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_json() {
        let m = Message::Assistant {
            content: vec![
                Part::Text {
                    text: "hello".into(),
                },
                Part::ToolCall {
                    id: "t1".into(),
                    name: "run_command".into(),
                    input: serde_json::json!({"command": "ls"}),
                },
            ],
            native: Some(Native {
                key: "anthropic::claude-opus-5".into(),
                blocks: serde_json::json!([]),
            }),
            provider: Some("claude::claude-opus-5".into()),
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: Message = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.tool_calls().len(), 1);
        assert!(back.native_for("anthropic::claude-opus-5").is_some());
        assert!(back.native_for("openai::x").is_none());
    }
}

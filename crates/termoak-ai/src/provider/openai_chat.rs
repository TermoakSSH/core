//! OpenAI Chat Completions-compatible APIs: OpenCode Go
//! (`https://opencode.ai/zen/go/v1`), Ollama, LM Studio, vLLM, NVIDIA...
//!
//! As in VoxPanel:
//! - streaming with `stream_options.include_usage`;
//! - reasoning in `delta.reasoning_content` (or `delta.reasoning`);
//! - a stable per-conversation `x-opencode-session` header when the host is
//!   `opencode.ai` (OpenCode requires it since September 2026);
//! - cost reported by the provider (`usage.cost`), if present.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde_json::{Value, json};

use super::anthropic::INVALID_JSON_KEY;
use super::{
    ChatProvider, EventSink, StreamEvent, TurnRequest, TurnResponse, parse_tool_input,
    send_with_retry,
};
use crate::config::ProviderConfig;
use crate::error::AiError;
use crate::message::{Message, Part, StopReason, Usage};
use crate::sse::for_each_event;

pub struct OpenAiChat {
    key: String,
    model: String,
    base_url: String,
    api_key: String,
    max_tokens: u32,
    effort: Option<String>,
    headers: Vec<(String, String)>,
    opencode: bool,
    http: reqwest::Client,
}

/// Is it an OpenCode endpoint (`opencode.ai` or a subdomain)?
pub fn is_opencode(base: &str) -> bool {
    url::Url::parse(base)
        .ok()
        .and_then(|u| {
            u.host_str()
                .map(|h| h == "opencode.ai" || h.ends_with(".opencode.ai"))
        })
        .unwrap_or(false)
}

/// `x-opencode-session` value: `ses_` + sanitized id (max. 64 characters).
pub fn opencode_session_header(session_id: &str) -> String {
    let clean: String = session_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .collect();
    let value = if clean.starts_with("ses_") {
        clean
    } else {
        format!("ses_{clean}")
    };
    value.chars().take(64).collect()
}

impl OpenAiChat {
    pub fn new(key: &str, cfg: &ProviderConfig, model: String, http: reqwest::Client) -> Self {
        let base_url = cfg
            .base_url
            .clone()
            .unwrap_or_default()
            .trim_end_matches('/')
            .to_string();
        Self {
            key: key.to_string(),
            opencode: is_opencode(&base_url),
            base_url,
            api_key: cfg.resolve_key().unwrap_or_default(),
            max_tokens: cfg.max_tokens.unwrap_or(8_000),
            effort: cfg.effort.clone(),
            headers: cfg.headers.clone().into_iter().collect(),
            model,
            http,
        }
    }

    fn build_body(&self, req: &TurnRequest<'_>) -> Value {
        let mut messages: Vec<Value> = vec![json!({"role": "system", "content": req.system})];
        for m in req.messages {
            match m {
                Message::User { content } => {
                    for p in content {
                        match p {
                            Part::ToolResult { id, content, .. } => messages.push(json!({
                                "role": "tool",
                                "tool_call_id": id,
                                "content": content,
                            })),
                            Part::Text { text } if !text.is_empty() => {
                                messages.push(json!({"role": "user", "content": text}))
                            }
                            _ => {}
                        }
                    }
                }
                Message::Assistant { content, .. } => {
                    let text: String = content
                        .iter()
                        .filter_map(|p| match p {
                            Part::Text { text } => Some(text.as_str()),
                            _ => None,
                        })
                        .collect();
                    let calls: Vec<Value> = content
                        .iter()
                        .filter_map(|p| match p {
                            Part::ToolCall { id, name, input } => Some(json!({
                                "id": id,
                                "type": "function",
                                "function": {
                                    "name": name,
                                    "arguments": if input.get(INVALID_JSON_KEY).is_some() { "{}".to_string() } else { input.to_string() },
                                },
                            })),
                            _ => None,
                        })
                        .collect();
                    let mut msg = json!({"role": "assistant", "content": text});
                    if !calls.is_empty() {
                        msg["tool_calls"] = Value::Array(calls);
                    }
                    messages.push(msg);
                }
            }
        }
        let mut body = json!({
            "model": self.model,
            "messages": messages,
            "stream": true,
            "stream_options": {"include_usage": true},
            "max_tokens": req.max_tokens.unwrap_or(self.max_tokens),
        });
        if !req.tools.is_empty() {
            body["tools"] = Value::Array(
                req.tools
                    .iter()
                    .map(|t| {
                        json!({
                            "type": "function",
                            "function": {
                                "name": t.name,
                                "description": t.description,
                                "parameters": t.schema,
                            }
                        })
                    })
                    .collect(),
            );
        }
        if let Some(effort) = req
            .effort
            .map(str::to_string)
            .or_else(|| self.effort.clone())
        {
            body["reasoning_effort"] = json!(effort);
        }
        if req.json_schema.is_some() {
            body["response_format"] = json!({"type": "json_object"});
        }
        body
    }
}

#[derive(Default)]
struct PendingCall {
    id: String,
    name: String,
    arguments: String,
}

#[async_trait]
impl ChatProvider for OpenAiChat {
    fn key(&self) -> &str {
        &self.key
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn native_key(&self) -> String {
        format!("openai-chat::{}::{}", self.key, self.model)
    }

    async fn turn(
        &self,
        req: &TurnRequest<'_>,
        sink: &dyn EventSink,
    ) -> Result<TurnResponse, AiError> {
        let body = self.build_body(req);
        let url = format!("{}/chat/completions", self.base_url);
        let session = opencode_session_header(req.session_id);
        let resp = send_with_retry(
            &self.key,
            || {
                let mut r = self
                    .http
                    .post(&url)
                    .bearer_auth(&self.api_key)
                    .header("accept", "text/event-stream")
                    .header("cache-control", "no-cache")
                    .json(&body);
                if self.opencode {
                    r = r.header("x-opencode-session", &session);
                }
                for (k, v) in &self.headers {
                    r = r.header(k, v);
                }
                r
            },
            req.cancel,
            sink,
        )
        .await?;

        let mut text = String::new();
        let mut reasoning = String::new();
        let mut calls: BTreeMap<u64, PendingCall> = BTreeMap::new();
        let mut finish: Option<String> = None;
        let mut usage = Usage::default();
        let mut model: Option<String> = None;
        let mut error: Option<String> = None;
        let read = for_each_event(resp, |ev| {
            if ev.data.trim() == "[DONE]" {
                return false;
            }
            let Ok(data) = serde_json::from_str::<Value>(&ev.data) else {
                return true;
            };
            if let Some(msg) = data["error"]["message"].as_str() {
                error = Some(msg.to_string());
                return false;
            }
            if model.is_none() {
                model = data["model"].as_str().map(str::to_string);
            }
            if let Some(choice) = data["choices"].get(0) {
                let delta = &choice["delta"];
                if let Some(t) = delta["content"].as_str().filter(|t| !t.is_empty()) {
                    text.push_str(t);
                    sink.emit(StreamEvent::Text(t.to_string()));
                }
                if let Some(r) = delta["reasoning_content"]
                    .as_str()
                    .or_else(|| delta["reasoning"].as_str())
                    .filter(|r| !r.is_empty())
                {
                    reasoning.push_str(r);
                    sink.emit(StreamEvent::Reasoning(r.to_string()));
                }
                for tc in delta["tool_calls"].as_array().into_iter().flatten() {
                    let idx = tc["index"].as_u64().unwrap_or(calls.len() as u64);
                    let entry = calls.entry(idx).or_default();
                    if let Some(id) = tc["id"].as_str().filter(|s| !s.is_empty()) {
                        entry.id = id.to_string();
                    }
                    if let Some(name) = tc["function"]["name"].as_str().filter(|s| !s.is_empty()) {
                        entry.name.push_str(name);
                        sink.emit(StreamEvent::ToolStart {
                            id: entry.id.clone(),
                            name: entry.name.clone(),
                        });
                    }
                    if let Some(args) = tc["function"]["arguments"].as_str() {
                        entry.arguments.push_str(args);
                    }
                }
                if let Some(f) = choice["finish_reason"].as_str() {
                    finish = Some(f.to_string());
                }
            }
            let u = &data["usage"];
            if u.is_object() {
                let cached = u["prompt_tokens_details"]["cached_tokens"]
                    .as_u64()
                    .unwrap_or(0);
                usage.input_tokens = u["prompt_tokens"]
                    .as_u64()
                    .unwrap_or(0)
                    .saturating_sub(cached);
                usage.cache_read_tokens = cached;
                usage.output_tokens = u["completion_tokens"].as_u64().unwrap_or(0);
                usage.reasoning_tokens = u["completion_tokens_details"]["reasoning_tokens"]
                    .as_u64()
                    .unwrap_or(0);
                usage.reported_cost_usd = u["cost"].as_f64();
            }
            true
        });
        tokio::select! {
            _ = req.cancel.cancelled() => return Err(AiError::Cancelled),
            r = read => r.map_err(|e| super::net_error(&self.key, e))?,
        }
        if let Some(message) = error {
            return Err(AiError::Http {
                provider: self.key.clone(),
                status: 500,
                message,
            });
        }

        let mut parts = Vec::new();
        if !reasoning.is_empty() {
            parts.push(Part::Reasoning { text: reasoning });
        }
        if !text.is_empty() {
            parts.push(Part::Text { text });
        }
        for (i, call) in calls.into_values().enumerate() {
            let input = match parse_tool_input(&call.arguments) {
                Ok(v) => v,
                Err(bad) => json!({ INVALID_JSON_KEY: bad }),
            };
            parts.push(Part::ToolCall {
                id: if call.id.is_empty() {
                    format!("call_{i}")
                } else {
                    call.id
                },
                name: call.name,
                input,
            });
        }
        let has_calls = parts.iter().any(|p| matches!(p, Part::ToolCall { .. }));
        let stop = match finish.as_deref() {
            Some("length") => StopReason::MaxTokens,
            Some("content_filter") => StopReason::Refusal,
            _ if has_calls => StopReason::ToolUse,
            _ => StopReason::EndTurn,
        };
        let model = model.unwrap_or_else(|| self.model.clone());
        Ok(TurnResponse {
            message: Message::Assistant {
                content: parts,
                native: None,
                provider: Some(format!("{}::{}", self.key, model)),
            },
            stop,
            usage,
            model,
            refusal_category: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opencode_detection_and_header() {
        assert!(is_opencode("https://opencode.ai/zen/go/v1"));
        assert!(is_opencode("https://api.opencode.ai/v1"));
        assert!(!is_opencode("https://notopencode.ai/v1"));
        assert!(!is_opencode("http://localhost:11434/v1"));
        let h = opencode_session_header("0190-abc/def ghi");
        assert_eq!(h, "ses_0190-abcdefghi");
        assert!(opencode_session_header(&"x".repeat(200)).len() <= 64);
    }
}

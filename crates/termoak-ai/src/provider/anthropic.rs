//! Claude through Anthropic's Messages API (plain HTTP + SSE; there is no
//! official Rust SDK).
//!
//! - Adaptive thinking (`thinking: {type: "adaptive"}`) with a visible summary.
//! - Configurable effort (`output_config.effort`).
//! - Automatic prompt caching (top-level `cache_control`).
//! - Server-side fallback on safety refusals (`fallbacks: "default"`,
//!   beta `server-side-fallback-2026-07-01`).
//! - `eager_input_streaming` on tools + strict input validation (invalid
//!   JSON → `tool_result` with an error, never executed).
//! - Response blocks (including signed thinking) are stored as-is and sent
//!   back untouched to the same model on the next turn.

use std::collections::HashMap;

use async_trait::async_trait;
use serde_json::{Value, json};

use super::{
    ChatProvider, EventSink, StreamEvent, TurnRequest, TurnResponse, parse_tool_input,
    send_with_retry,
};
use crate::config::ProviderConfig;
use crate::error::AiError;
use crate::message::{Message, Native, Part, StopReason, Usage};
use crate::sse::for_each_event;

pub(crate) const API_VERSION: &str = "2023-06-01";
const FALLBACK_BETA: &str = "server-side-fallback-2026-07-01";
/// Marker for tool input that was not valid JSON.
pub const INVALID_JSON_KEY: &str = "__invalid_json__";

pub struct Anthropic {
    key: String,
    model: String,
    base_url: String,
    api_key: String,
    max_tokens: u32,
    effort: Option<String>,
    thinking: bool,
    fallbacks: bool,
    eager: bool,
    headers: Vec<(String, String)>,
    http: reqwest::Client,
}

fn official(base: &str) -> bool {
    url::Url::parse(base)
        .ok()
        .and_then(|u| u.host_str().map(|h| h == "api.anthropic.com"))
        .unwrap_or(false)
}

/// Models before the 4.6 family support neither adaptive thinking nor `effort`.
fn legacy_model(model: &str) -> bool {
    [
        "haiku-4-5",
        "sonnet-4-5",
        "opus-4-5",
        "opus-4-1",
        "opus-4-0",
        "sonnet-4-0",
        "claude-3",
    ]
    .iter()
    .any(|m| model.contains(m))
}

/// Models with documented server-side fallback.
fn supports_server_fallback(model: &str) -> bool {
    model.starts_with("claude-opus-5")
        || model.starts_with("claude-fable-5")
        || model.starts_with("claude-mythos-5")
}

impl Anthropic {
    pub fn new(key: &str, cfg: &ProviderConfig, model: String, http: reqwest::Client) -> Self {
        let base_url = cfg
            .base_url
            .clone()
            .unwrap_or_else(|| "https://api.anthropic.com".into())
            .trim_end_matches('/')
            .to_string();
        let is_official = official(&base_url);
        let legacy = legacy_model(&model);
        Self {
            key: key.to_string(),
            max_tokens: cfg.max_tokens.unwrap_or(64_000),
            effort: if legacy { None } else { cfg.effort.clone() },
            thinking: !legacy && cfg.thinking.as_deref().unwrap_or("adaptive") == "adaptive",
            fallbacks: is_official
                && supports_server_fallback(&model)
                && cfg.fallbacks.as_deref().unwrap_or("default") == "default",
            eager: cfg.eager_input_streaming.unwrap_or(is_official),
            api_key: cfg.resolve_key().unwrap_or_default(),
            headers: cfg.headers.clone().into_iter().collect(),
            base_url,
            model,
            http,
        }
    }

    fn build_body(&self, req: &TurnRequest<'_>) -> Value {
        let native_key = self.native_key();
        let messages: Vec<Value> = req
            .messages
            .iter()
            .map(|m| convert_message(m, &native_key))
            .collect();
        let mut body = json!({
            "model": self.model,
            "max_tokens": req.max_tokens.unwrap_or(self.max_tokens),
            "stream": true,
            "system": req.system,
            "messages": messages,
            "cache_control": {"type": "ephemeral"},
        });
        if !req.tools.is_empty() {
            body["tools"] = Value::Array(
                req.tools
                    .iter()
                    .map(|t| {
                        let mut tool = json!({
                            "name": t.name,
                            "description": t.description,
                            "input_schema": t.schema,
                        });
                        if self.eager {
                            tool["eager_input_streaming"] = json!(true);
                        }
                        tool
                    })
                    .collect(),
            );
        }
        if self.thinking {
            body["thinking"] = json!({"type": "adaptive", "display": "summarized"});
        }
        let mut output_config = serde_json::Map::new();
        if let Some(effort) = req
            .effort
            .map(str::to_string)
            .or_else(|| self.effort.clone())
        {
            output_config.insert("effort".into(), json!(effort));
        }
        if let Some(schema) = req.json_schema {
            output_config.insert(
                "format".into(),
                json!({"type": "json_schema", "schema": schema}),
            );
        }
        if !output_config.is_empty() {
            body["output_config"] = Value::Object(output_config);
        }
        if self.fallbacks {
            body["fallbacks"] = json!("default");
        }
        body
    }
}

/// Common message → Messages API format.
fn convert_message(m: &Message, native_key: &str) -> Value {
    match m {
        Message::User { content } => {
            // `tool_result` blocks must come before the text.
            let mut blocks: Vec<Value> = content
                .iter()
                .filter_map(|p| match p {
                    Part::ToolResult {
                        id,
                        content,
                        is_error,
                    } => Some(json!({
                        "type": "tool_result",
                        "tool_use_id": id,
                        "content": if content.is_empty() { "(no output)" } else { content },
                        "is_error": is_error,
                    })),
                    _ => None,
                })
                .collect();
            blocks.extend(content.iter().filter_map(|p| match p {
                Part::Text { text } if !text.is_empty() => {
                    Some(json!({"type": "text", "text": text}))
                }
                _ => None,
            }));
            json!({"role": "user", "content": blocks})
        }
        Message::Assistant { content, .. } => {
            if let Some(blocks) = m.native_for(native_key) {
                return json!({"role": "assistant", "content": blocks});
            }
            let mut blocks: Vec<Value> = content
                .iter()
                .filter_map(|p| match p {
                    Part::Text { text } if !text.trim().is_empty() => {
                        Some(json!({"type": "text", "text": text}))
                    }
                    Part::ToolCall { id, name, input } => Some(json!({
                        "type": "tool_use",
                        "id": id,
                        "name": name,
                        "input": sanitize_input(input),
                    })),
                    _ => None,
                })
                .collect();
            if blocks.is_empty() {
                blocks.push(json!({"type": "text", "text": "…"}));
            }
            json!({"role": "assistant", "content": blocks})
        }
    }
}

fn sanitize_input(input: &Value) -> Value {
    if input.get(INVALID_JSON_KEY).is_some() || !input.is_object() {
        json!({})
    } else {
        input.clone()
    }
}

#[async_trait]
impl ChatProvider for Anthropic {
    fn key(&self) -> &str {
        &self.key
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn native_key(&self) -> String {
        format!("anthropic::{}", self.model)
    }

    async fn turn(
        &self,
        req: &TurnRequest<'_>,
        sink: &dyn EventSink,
    ) -> Result<TurnResponse, AiError> {
        let body = self.build_body(req);
        let url = format!("{}/v1/messages", self.base_url);
        let resp = send_with_retry(
            &self.key,
            || {
                let mut r = self
                    .http
                    .post(&url)
                    .header("x-api-key", &self.api_key)
                    .header("anthropic-version", API_VERSION)
                    .header("content-type", "application/json")
                    .header("accept", "text/event-stream")
                    .json(&body);
                if self.fallbacks {
                    r = r.header("anthropic-beta", FALLBACK_BETA);
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

        let mut acc = Accumulator::default();
        let mut stream_error: Option<AiError> = None;
        let provider = self.key.clone();
        let read = async {
            for_each_event(resp, |ev| {
                let Ok(data) = serde_json::from_str::<Value>(&ev.data) else {
                    return true;
                };
                match acc.handle(&data, sink) {
                    Ok(done) => !done,
                    Err(message) => {
                        stream_error = Some(AiError::Http {
                            provider: provider.clone(),
                            status: 529,
                            message,
                        });
                        false
                    }
                }
            })
            .await
        };
        tokio::select! {
            _ = req.cancel.cancelled() => return Err(AiError::Cancelled),
            r = read => r.map_err(|e| super::net_error(&self.key, e))?,
        }
        if let Some(e) = stream_error {
            return Err(e);
        }
        acc.finish(self)
    }
}

/// Accumulates SSE events into the complete response.
#[derive(Default)]
struct Accumulator {
    blocks: Vec<Value>,
    partial_json: HashMap<usize, String>,
    invalid: HashMap<usize, String>,
    model: Option<String>,
    stop_reason: Option<String>,
    refusal_category: Option<String>,
    usage: Usage,
    finished: bool,
}

impl Accumulator {
    /// Returns `Ok(true)` when the message ends.
    fn handle(&mut self, data: &Value, sink: &dyn EventSink) -> Result<bool, String> {
        match data["type"].as_str().unwrap_or("") {
            "message_start" => {
                let msg = &data["message"];
                self.model = msg["model"].as_str().map(str::to_string);
                let u = &msg["usage"];
                self.usage.input_tokens = u["input_tokens"].as_u64().unwrap_or(0);
                self.usage.cache_read_tokens = u["cache_read_input_tokens"].as_u64().unwrap_or(0);
                self.usage.cache_write_tokens =
                    u["cache_creation_input_tokens"].as_u64().unwrap_or(0);
            }
            "content_block_start" => {
                let idx = data["index"].as_u64().unwrap_or(0) as usize;
                let mut block = data["content_block"].clone();
                if block["type"] == "tool_use" {
                    block["input"] = json!({});
                    self.partial_json.insert(idx, String::new());
                    sink.emit(StreamEvent::ToolStart {
                        id: block["id"].as_str().unwrap_or("").to_string(),
                        name: block["name"].as_str().unwrap_or("").to_string(),
                    });
                }
                while self.blocks.len() <= idx {
                    self.blocks.push(Value::Null);
                }
                self.blocks[idx] = block;
            }
            "content_block_delta" => {
                let idx = data["index"].as_u64().unwrap_or(0) as usize;
                let delta = &data["delta"];
                let Some(block) = self.blocks.get_mut(idx) else {
                    return Ok(false);
                };
                match delta["type"].as_str().unwrap_or("") {
                    "text_delta" => {
                        let t = delta["text"].as_str().unwrap_or("");
                        append(block, "text", t);
                        sink.emit(StreamEvent::Text(t.to_string()));
                    }
                    "thinking_delta" => {
                        let t = delta["thinking"].as_str().unwrap_or("");
                        append(block, "thinking", t);
                        if !t.is_empty() {
                            sink.emit(StreamEvent::Reasoning(t.to_string()));
                        }
                    }
                    "signature_delta" => {
                        append(
                            block,
                            "signature",
                            delta["signature"].as_str().unwrap_or(""),
                        );
                    }
                    "input_json_delta" => {
                        if let Some(buf) = self.partial_json.get_mut(&idx) {
                            buf.push_str(delta["partial_json"].as_str().unwrap_or(""));
                        }
                    }
                    "citations_delta" => {
                        if !block["citations"].is_array() {
                            block["citations"] = json!([]);
                        }
                        if let Some(arr) = block["citations"].as_array_mut() {
                            arr.push(delta["citation"].clone());
                        }
                    }
                    _ => {}
                }
            }
            "content_block_stop" => {
                let idx = data["index"].as_u64().unwrap_or(0) as usize;
                if let Some(raw) = self.partial_json.remove(&idx) {
                    match parse_tool_input(&raw) {
                        Ok(v) => {
                            if let Some(b) = self.blocks.get_mut(idx) {
                                b["input"] = v;
                            }
                        }
                        Err(bad) => {
                            self.invalid.insert(idx, bad);
                        }
                    }
                }
            }
            "message_delta" => {
                if let Some(r) = data["delta"]["stop_reason"].as_str() {
                    self.stop_reason = Some(r.to_string());
                }
                if let Some(c) = data["delta"]["stop_details"]["category"].as_str() {
                    self.refusal_category = Some(c.to_string());
                }
                if let Some(o) = data["usage"]["output_tokens"].as_u64() {
                    self.usage.output_tokens = o;
                }
            }
            "message_stop" => {
                self.finished = true;
                return Ok(true);
            }
            "error" => {
                return Err(data["error"]["message"]
                    .as_str()
                    .unwrap_or("stream error")
                    .to_string());
            }
            _ => {}
        }
        Ok(false)
    }

    fn finish(self, p: &Anthropic) -> Result<TurnResponse, AiError> {
        if !self.finished && self.stop_reason.is_none() {
            return Err(AiError::Protocol {
                provider: p.key.clone(),
                message: "the stream ended prematurely".into(),
            });
        }
        let blocks: Vec<Value> = self.blocks.into_iter().filter(|b| !b.is_null()).collect();
        let mut parts = Vec::new();
        for (i, b) in blocks.iter().enumerate() {
            match b["type"].as_str().unwrap_or("") {
                "text" => parts.push(Part::Text {
                    text: b["text"].as_str().unwrap_or("").to_string(),
                }),
                "thinking" => {
                    let t = b["thinking"].as_str().unwrap_or("");
                    if !t.is_empty() {
                        parts.push(Part::Reasoning {
                            text: t.to_string(),
                        });
                    }
                }
                "tool_use" => {
                    let input = match self.invalid.get(&i) {
                        Some(raw) => json!({ INVALID_JSON_KEY: raw }),
                        None => b["input"].clone(),
                    };
                    parts.push(Part::ToolCall {
                        id: b["id"].as_str().unwrap_or("").to_string(),
                        name: b["name"].as_str().unwrap_or("").to_string(),
                        input,
                    });
                }
                _ => {}
            }
        }
        let stop = match self.stop_reason.as_deref() {
            Some("end_turn") | Some("stop_sequence") | None => StopReason::EndTurn,
            Some("tool_use") => StopReason::ToolUse,
            Some("max_tokens") => StopReason::MaxTokens,
            Some("refusal") => StopReason::Refusal,
            Some("pause_turn") => StopReason::PauseTurn,
            Some(other) => StopReason::Other(other.to_string()),
        };
        let model = self.model.unwrap_or_else(|| p.model.clone());
        Ok(TurnResponse {
            message: Message::Assistant {
                content: parts,
                native: Some(Native {
                    key: p.native_key(),
                    blocks: Value::Array(blocks),
                }),
                provider: Some(format!("{}::{}", p.key, model)),
            },
            stop,
            usage: self.usage,
            model,
            refusal_category: self.refusal_category,
        })
    }
}

fn append(block: &mut Value, field: &str, s: &str) {
    let current = block[field].as_str().unwrap_or("").to_string();
    block[field] = Value::String(current + s);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::NullSink;

    #[test]
    fn accumulates_stream() {
        let events = [
            json!({"type":"message_start","message":{"model":"claude-opus-5","usage":{"input_tokens":10,"cache_read_input_tokens":5}}}),
            json!({"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}),
            json!({"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"thinking"}}),
            json!({"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig"}}),
            json!({"type":"content_block_stop","index":0}),
            json!({"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}),
            json!({"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Let me check."}}),
            json!({"type":"content_block_stop","index":1}),
            json!({"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_1","name":"run_command","input":{}}}),
            json!({"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"command\": \"df"}}),
            json!({"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":" -h\"}"}}),
            json!({"type":"content_block_stop","index":2}),
            json!({"type":"content_block_start","index":3,"content_block":{"type":"tool_use","id":"toolu_2","name":"run_command","input":{}}}),
            json!({"type":"content_block_delta","index":3,"delta":{"type":"input_json_delta","partial_json":"{\"command\": \"broken"}}),
            json!({"type":"content_block_stop","index":3}),
            json!({"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":42}}),
            json!({"type":"message_stop"}),
        ];
        let mut acc = Accumulator::default();
        for e in &events {
            acc.handle(e, &NullSink).unwrap();
        }
        let p = Anthropic::new(
            "claude",
            &ProviderConfig {
                api_key: Some("k".into()),
                ..Default::default()
            },
            "claude-opus-5".into(),
            reqwest::Client::new(),
        );
        let r = acc.finish(&p).unwrap();
        assert_eq!(r.stop, StopReason::ToolUse);
        assert_eq!(r.usage.output_tokens, 42);
        let calls = r.message.tool_calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].2, json!({"command": "df -h"}));
        assert!(calls[1].2.get(INVALID_JSON_KEY).is_some());
        // Native blocks keep the thinking signature.
        let native = r.message.native_for("anthropic::claude-opus-5").unwrap();
        assert_eq!(native[0]["signature"], "sig");
        assert_eq!(r.message.text(), "Let me check.");
    }

    #[test]
    fn body_has_expected_fields() {
        let p = Anthropic::new(
            "claude",
            &ProviderConfig {
                api_key: Some("k".into()),
                effort: Some("high".into()),
                ..Default::default()
            },
            "claude-opus-5".into(),
            reqwest::Client::new(),
        );
        let cancel = tokio_util::sync::CancellationToken::new();
        let msgs = vec![Message::user_text("hello")];
        let tools = vec![super::super::ToolSpec {
            name: "t".into(),
            description: "d".into(),
            schema: json!({"type":"object","properties":{}}),
        }];
        let req = TurnRequest {
            system: "sys",
            messages: &msgs,
            tools: &tools,
            session_id: "s",
            max_tokens: None,
            json_schema: None,
            effort: None,
            cancel: &cancel,
        };
        let body = p.build_body(&req);
        assert_eq!(body["thinking"]["type"], "adaptive");
        assert_eq!(body["output_config"]["effort"], "high");
        assert_eq!(body["fallbacks"], "default");
        assert_eq!(body["tools"][0]["eager_input_streaming"], true);
        assert_eq!(body["cache_control"]["type"], "ephemeral");

        let haiku = Anthropic::new(
            "claude",
            &ProviderConfig {
                api_key: Some("k".into()),
                effort: Some("high".into()),
                ..Default::default()
            },
            "claude-haiku-4-5".into(),
            reqwest::Client::new(),
        );
        let body = haiku.build_body(&req);
        assert!(body.get("thinking").is_none());
        assert!(body.get("output_config").is_none());
        assert!(body.get("fallbacks").is_none());
    }
}

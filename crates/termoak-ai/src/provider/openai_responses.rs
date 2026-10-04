//! OpenAI through the Responses API (`POST /responses`) with streaming and functions.
//!
//! It uses `store: false` and `include: ["reasoning.encrypted_content"]` so
//! the conversation is not stored at OpenAI and the encrypted reasoning can be
//! sent back to the same model on the next turn.

use async_trait::async_trait;
use serde_json::{Value, json};

use super::anthropic::INVALID_JSON_KEY;
use super::{
    ChatProvider, EventSink, StreamEvent, TurnRequest, TurnResponse, parse_tool_input,
    send_with_retry,
};
use crate::config::ProviderConfig;
use crate::error::AiError;
use crate::message::{Message, Native, Part, StopReason, Usage};
use crate::sse::for_each_event;

pub struct OpenAiResponses {
    key: String,
    model: String,
    base_url: String,
    api_key: String,
    max_tokens: u32,
    effort: Option<String>,
    headers: Vec<(String, String)>,
    http: reqwest::Client,
}

impl OpenAiResponses {
    pub fn new(key: &str, cfg: &ProviderConfig, model: String, http: reqwest::Client) -> Self {
        Self {
            key: key.to_string(),
            base_url: cfg
                .base_url
                .clone()
                .unwrap_or_else(|| "https://api.openai.com/v1".into())
                .trim_end_matches('/')
                .to_string(),
            api_key: cfg.resolve_key().unwrap_or_default(),
            max_tokens: cfg.max_tokens.unwrap_or(32_000),
            effort: cfg.effort.clone(),
            headers: cfg.headers.clone().into_iter().collect(),
            model,
            http,
        }
    }

    fn build_body(&self, req: &TurnRequest<'_>) -> Value {
        let native_key = self.native_key();
        let mut input: Vec<Value> = Vec::new();
        for m in req.messages {
            match m {
                Message::User { content } => {
                    for p in content {
                        match p {
                            Part::ToolResult { id, content, .. } => input.push(json!({
                                "type": "function_call_output",
                                "call_id": id,
                                "output": content,
                            })),
                            Part::Text { text } if !text.is_empty() => input.push(json!({
                                "role": "user",
                                "content": [{"type": "input_text", "text": text}],
                            })),
                            _ => {}
                        }
                    }
                }
                Message::Assistant { content, .. } => {
                    if let Some(Value::Array(items)) = m.native_for(&native_key) {
                        input.extend(items.iter().cloned());
                        continue;
                    }
                    for p in content {
                        match p {
                            Part::Text { text } if !text.trim().is_empty() => input.push(json!({
                                "role": "assistant",
                                "content": [{"type": "output_text", "text": text}],
                            })),
                            Part::ToolCall { id, name, input: args } => input.push(json!({
                                "type": "function_call",
                                "call_id": id,
                                "name": name,
                                "arguments": if args.get(INVALID_JSON_KEY).is_some() { "{}".to_string() } else { args.to_string() },
                            })),
                            _ => {}
                        }
                    }
                }
            }
        }
        let mut body = json!({
            "model": self.model,
            "instructions": req.system,
            "input": input,
            "stream": true,
            "store": false,
            "include": ["reasoning.encrypted_content"],
            "max_output_tokens": req.max_tokens.unwrap_or(self.max_tokens),
        });
        if !req.tools.is_empty() {
            body["tools"] = Value::Array(
                req.tools
                    .iter()
                    .map(|t| {
                        json!({
                            "type": "function",
                            "name": t.name,
                            "description": t.description,
                            "parameters": t.schema,
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
            body["reasoning"] = json!({"effort": effort, "summary": "auto"});
        }
        if let Some(schema) = req.json_schema {
            body["text"] = json!({"format": {"type": "json_schema", "name": "response", "schema": schema, "strict": false}});
        }
        body
    }
}

#[async_trait]
impl ChatProvider for OpenAiResponses {
    fn key(&self) -> &str {
        &self.key
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn native_key(&self) -> String {
        format!("openai-responses::{}", self.model)
    }

    async fn turn(
        &self,
        req: &TurnRequest<'_>,
        sink: &dyn EventSink,
    ) -> Result<TurnResponse, AiError> {
        let body = self.build_body(req);
        let url = format!("{}/responses", self.base_url);
        let resp = send_with_retry(
            &self.key,
            || {
                let mut r = self
                    .http
                    .post(&url)
                    .bearer_auth(&self.api_key)
                    .header("accept", "text/event-stream")
                    .json(&body);
                for (k, v) in &self.headers {
                    r = r.header(k, v);
                }
                r
            },
            req.cancel,
            sink,
        )
        .await?;

        let mut completed: Option<Value> = None;
        let mut failure: Option<String> = None;
        let read = for_each_event(resp, |ev| {
            let Ok(data) = serde_json::from_str::<Value>(&ev.data) else {
                return true;
            };
            match data["type"].as_str().unwrap_or("") {
                "response.output_text.delta" => {
                    sink.emit(StreamEvent::Text(
                        data["delta"].as_str().unwrap_or("").to_string(),
                    ));
                }
                "response.reasoning_summary_text.delta" => {
                    sink.emit(StreamEvent::Reasoning(
                        data["delta"].as_str().unwrap_or("").to_string(),
                    ));
                }
                "response.output_item.added" => {
                    if data["item"]["type"] == "function_call" {
                        sink.emit(StreamEvent::ToolStart {
                            id: data["item"]["call_id"].as_str().unwrap_or("").to_string(),
                            name: data["item"]["name"].as_str().unwrap_or("").to_string(),
                        });
                    }
                }
                "response.completed" | "response.incomplete" => {
                    completed = Some(data["response"].clone());
                    return false;
                }
                "response.failed" => {
                    failure = Some(
                        data["response"]["error"]["message"]
                            .as_str()
                            .unwrap_or("the response failed")
                            .to_string(),
                    );
                    return false;
                }
                "error" => {
                    failure = Some(data["message"].as_str().unwrap_or("error").to_string());
                    return false;
                }
                _ => {}
            }
            true
        });
        tokio::select! {
            _ = req.cancel.cancelled() => return Err(AiError::Cancelled),
            r = read => r.map_err(|e| super::net_error(&self.key, e))?,
        }
        if let Some(message) = failure {
            return Err(AiError::Http {
                provider: self.key.clone(),
                status: 500,
                message,
            });
        }
        let response = completed.ok_or_else(|| AiError::Protocol {
            provider: self.key.clone(),
            message: "the stream ended without a complete response".into(),
        })?;
        Ok(parse_response(self, &response))
    }
}

fn parse_response(p: &OpenAiResponses, response: &Value) -> TurnResponse {
    let output = response["output"].as_array().cloned().unwrap_or_default();
    let mut parts = Vec::new();
    let mut refusal = false;
    for item in &output {
        match item["type"].as_str().unwrap_or("") {
            "message" => {
                for c in item["content"].as_array().into_iter().flatten() {
                    match c["type"].as_str().unwrap_or("") {
                        "output_text" => parts.push(Part::Text {
                            text: c["text"].as_str().unwrap_or("").to_string(),
                        }),
                        "refusal" => {
                            refusal = true;
                            parts.push(Part::Text {
                                text: c["refusal"].as_str().unwrap_or("").to_string(),
                            });
                        }
                        _ => {}
                    }
                }
            }
            "reasoning" => {
                let summary: Vec<&str> = item["summary"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|s| s["text"].as_str())
                    .collect();
                if !summary.is_empty() {
                    parts.push(Part::Reasoning {
                        text: summary.join("\n"),
                    });
                }
            }
            "function_call" => {
                let raw = item["arguments"].as_str().unwrap_or("");
                let input = match parse_tool_input(raw) {
                    Ok(v) => v,
                    Err(bad) => json!({ INVALID_JSON_KEY: bad }),
                };
                parts.push(Part::ToolCall {
                    id: item["call_id"].as_str().unwrap_or("").to_string(),
                    name: item["name"].as_str().unwrap_or("").to_string(),
                    input,
                });
            }
            _ => {}
        }
    }
    let has_calls = parts.iter().any(|p| matches!(p, Part::ToolCall { .. }));
    let incomplete = response["status"] == "incomplete";
    let stop = if refusal {
        StopReason::Refusal
    } else if incomplete
        && response["incomplete_details"]["reason"].as_str() == Some("max_output_tokens")
    {
        StopReason::MaxTokens
    } else if has_calls {
        StopReason::ToolUse
    } else {
        StopReason::EndTurn
    };
    let u = &response["usage"];
    let usage = Usage {
        input_tokens: u["input_tokens"].as_u64().unwrap_or(0).saturating_sub(
            u["input_tokens_details"]["cached_tokens"]
                .as_u64()
                .unwrap_or(0),
        ),
        output_tokens: u["output_tokens"].as_u64().unwrap_or(0),
        cache_read_tokens: u["input_tokens_details"]["cached_tokens"]
            .as_u64()
            .unwrap_or(0),
        cache_write_tokens: 0,
        reasoning_tokens: u["output_tokens_details"]["reasoning_tokens"]
            .as_u64()
            .unwrap_or(0),
        reported_cost_usd: None,
    };
    let model = response["model"].as_str().unwrap_or(&p.model).to_string();
    TurnResponse {
        message: Message::Assistant {
            content: parts,
            native: Some(Native {
                key: p.native_key(),
                blocks: Value::Array(
                    output
                        .into_iter()
                        .map(|mut item| {
                            // `status` is not accepted as input on some items.
                            if let Some(obj) = item.as_object_mut() {
                                obj.remove("status");
                            }
                            item
                        })
                        .collect(),
                ),
            }),
            provider: Some(format!("{}::{}", p.key, model)),
        },
        stop,
        usage,
        model,
        refusal_category: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_completed_response() {
        let p = OpenAiResponses::new(
            "gpt",
            &ProviderConfig {
                api_key: Some("k".into()),
                ..Default::default()
            },
            "gpt-x".into(),
            reqwest::Client::new(),
        );
        let resp = json!({
            "model": "gpt-x",
            "status": "completed",
            "output": [
                {"type": "reasoning", "id": "rs_1", "summary": [{"type": "summary_text", "text": "thinking"}], "encrypted_content": "xyz"},
                {"type": "message", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": "Hello"}]},
                {"type": "function_call", "call_id": "call_1", "name": "run_command", "arguments": "{\"command\":\"uptime\"}"}
            ],
            "usage": {"input_tokens": 100, "input_tokens_details": {"cached_tokens": 40}, "output_tokens": 20, "output_tokens_details": {"reasoning_tokens": 5}}
        });
        let r = parse_response(&p, &resp);
        assert_eq!(r.stop, StopReason::ToolUse);
        assert_eq!(r.usage.input_tokens, 60);
        assert_eq!(r.usage.cache_read_tokens, 40);
        assert_eq!(r.message.text(), "Hello");
        assert_eq!(r.message.tool_calls()[0].2["command"], "uptime");
        let native = r.message.native_for("openai-responses::gpt-x").unwrap();
        assert_eq!(native.as_array().unwrap().len(), 3);
        assert!(native[1].get("status").is_none());
    }
}

//! Server-Sent Events reader over an HTTP response body.

use bytes::{Buf, BytesMut};
use futures::StreamExt;

/// An SSE event.
#[derive(Debug, Clone, PartialEq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
}

/// Incremental decoder (transport-independent, easy to test).
#[derive(Default)]
pub struct SseDecoder {
    buf: BytesMut,
}

impl SseDecoder {
    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Extracts the next complete event, if any.
    pub fn next_event(&mut self) -> Option<SseEvent> {
        loop {
            let (end, sep) = find_boundary(&self.buf)?;
            let raw = self.buf.split_to(end);
            self.buf.advance(sep);
            let text = String::from_utf8_lossy(&raw);
            let mut event = None;
            let mut data: Vec<&str> = Vec::new();
            for line in text.lines() {
                if line.starts_with(':') {
                    continue;
                }
                let (field, value) = match line.split_once(':') {
                    Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
                    None => (line, ""),
                };
                match field {
                    "event" => event = Some(value.to_string()),
                    "data" => data.push(value),
                    _ => {}
                }
            }
            if event.is_none() && data.is_empty() {
                continue;
            }
            return Some(SseEvent {
                event,
                data: data.join("\n"),
            });
        }
    }
}

fn find_boundary(buf: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while i + 1 < buf.len() {
        if buf[i] == b'\n' && buf[i + 1] == b'\n' {
            return Some((i, 2));
        }
        if i + 3 < buf.len() && &buf[i..i + 4] == b"\r\n\r\n" {
            return Some((i, 4));
        }
        i += 1;
    }
    None
}

/// Walks the SSE events of a response, calling `on_event` for each one.
/// Reading stops if `on_event` returns `false`.
pub async fn for_each_event<F>(
    response: reqwest::Response,
    mut on_event: F,
) -> Result<(), reqwest::Error>
where
    F: FnMut(SseEvent) -> bool,
{
    let mut stream = response.bytes_stream();
    let mut decoder = SseDecoder::default();
    while let Some(chunk) = stream.next().await {
        decoder.push(&chunk?);
        while let Some(ev) = decoder.next_event() {
            if !on_event(ev) {
                return Ok(());
            }
        }
    }
    // Last event without a trailing blank line.
    decoder.push(b"\n\n");
    while let Some(ev) = decoder.next_event() {
        if !on_event(ev) {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_split_events() {
        let mut d = SseDecoder::default();
        d.push(b"event: message_start\ndata: {\"a\":");
        assert!(d.next_event().is_none());
        d.push(b"1}\n\n: comment\n\ndata: [DONE]\r\n\r\n");
        assert_eq!(
            d.next_event().unwrap(),
            SseEvent {
                event: Some("message_start".into()),
                data: "{\"a\":1}".into()
            }
        );
        assert_eq!(d.next_event().unwrap().data, "[DONE]");
        assert!(d.next_event().is_none());
    }

    #[test]
    fn multiline_data() {
        let mut d = SseDecoder::default();
        d.push(b"data: a\ndata: b\n\n");
        assert_eq!(d.next_event().unwrap().data, "a\nb");
    }
}

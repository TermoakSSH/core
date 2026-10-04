//! A small MCP endpoint (Streamable HTTP, JSON responses) for the external
//! agents a client app runs on the same computer (Codex, Claude Code,
//! Antigravity, OpenCode).
//!
//! Security:
//! - It listens **only on 127.0.0.1**, on a random port.
//! - Every request needs `Authorization: Bearer <token>`: a random token for
//!   this endpoint only (compared in constant time), or, serving an
//!   [`AiEngine`]'s tasks, the token of a task that is running.
//! - The `Host` header must name this address and an `Origin`, if present,
//!   must be this same address (a web page cannot reach it through DNS
//!   rebinding or a cross-site request).
//! - Bodies are limited to 4 MiB and headers to 16 KiB.
//!
//! Only `POST` with JSON-RPC is served (no server-to-client stream: `GET`
//! answers 405, as the specification allows).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::engine::AiEngine;
use crate::mcp::{McpCaller, McpTools, handle};

/// What the endpoint serves and who may call it.
#[async_trait]
pub trait McpEndpoint: Send + Sync {
    /// Is this bearer token accepted?
    fn authorized(&self, token: &str) -> bool;
    /// Handles a JSON-RPC request of an authorized caller.
    async fn handle(&self, token: &str, request: Value) -> Option<Value>;
}

/// Some tools behind one fixed token.
struct FixedToken {
    tools: Arc<dyn McpTools>,
    token: String,
}

#[async_trait]
impl McpEndpoint for FixedToken {
    fn authorized(&self, token: &str) -> bool {
        termoak_core::crypto::constant_time_eq(token.as_bytes(), self.token.as_bytes())
    }

    async fn handle(&self, _token: &str, request: Value) -> Option<Value> {
        handle(self.tools.as_ref(), request).await
    }
}

/// An engine's tools for its running tasks: each external agent uses the
/// token of its own task (valid only while it runs), so every call goes
/// through that task's permissions and approvals.
struct EngineTasks(Arc<AiEngine>);

#[async_trait]
impl McpEndpoint for EngineTasks {
    fn authorized(&self, token: &str) -> bool {
        self.0.is_task_mcp_token(token)
    }

    async fn handle(&self, token: &str, request: Value) -> Option<Value> {
        self.0
            .mcp_handle(&McpCaller::TaskToken(token.to_string()), request)
            .await
    }
}

const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 4 * 1024 * 1024;
/// A connection without a new request for this long is closed.
const IDLE: Duration = Duration::from_secs(300);

/// A running endpoint (it stops when dropped).
pub struct LocalMcpServer {
    url: String,
    token: String,
    task: tokio::task::JoinHandle<()>,
}

impl LocalMcpServer {
    /// Starts it on 127.0.0.1 with a random port and token.
    pub async fn start(tools: Arc<dyn McpTools>) -> std::io::Result<Self> {
        let token = termoak_core::crypto::prefixed_token("tmk_mcp");
        let endpoint = Arc::new(FixedToken {
            tools,
            token: token.clone(),
        });
        Self::start_endpoint(endpoint, token).await
    }

    /// Starts it on 127.0.0.1 with a random port for an engine's tasks (set
    /// its URL with [`AiEngine::set_mcp_url`]); each task brings its token.
    pub async fn start_for_tasks(engine: Arc<AiEngine>) -> std::io::Result<Self> {
        Self::start_endpoint(Arc::new(EngineTasks(engine)), String::new()).await
    }

    async fn start_endpoint(
        endpoint: Arc<dyn McpEndpoint>,
        token: String,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let shared = Arc::new(Shared { endpoint, port });
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = listener.accept().await else {
                    continue;
                };
                let shared = shared.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve(stream, peer, &shared).await {
                        tracing::debug!(error = %e, "local MCP connection closed");
                    }
                });
            }
        });
        Ok(Self {
            url: format!("http://127.0.0.1:{port}/mcp"),
            token,
            task,
        })
    }

    /// `http://127.0.0.1:<port>/mcp`.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Bearer token of this endpoint (empty when serving an engine's tasks).
    pub fn token(&self) -> &str {
        &self.token
    }
}

impl Drop for LocalMcpServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Shared {
    endpoint: Arc<dyn McpEndpoint>,
    port: u16,
}

/// A parsed request head.
struct Head {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

impl Head {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

async fn serve(stream: TcpStream, peer: SocketAddr, shared: &Shared) -> std::io::Result<()> {
    if !peer.ip().is_loopback() {
        return Ok(());
    }
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    loop {
        let head = match tokio::time::timeout(IDLE, read_head(&mut reader)).await {
            Ok(Ok(Some(h))) => h,
            Ok(Ok(None)) | Err(_) => return Ok(()),
            Ok(Err(e)) => {
                respond(&mut write, 400, "text/plain", b"bad request", true).await?;
                return Err(e);
            }
        };
        let close = head
            .header("connection")
            .is_some_and(|c| c.eq_ignore_ascii_case("close"));
        let body = match read_body(&mut reader, &head).await {
            Ok(b) => b,
            Err(e) => {
                respond(&mut write, 413, "text/plain", b"body too large", true).await?;
                return Err(e);
            }
        };
        let (status, kind, out) = answer(shared, &head, &body).await;
        respond(&mut write, status, kind, &out, close).await?;
        if close {
            return Ok(());
        }
    }
}

/// Status, content type and body of the answer to a request.
async fn answer(shared: &Shared, head: &Head, body: &[u8]) -> (u16, &'static str, Vec<u8>) {
    let text = |s: &str| s.as_bytes().to_vec();
    if !allowed_host(head.header("host"), shared.port) {
        return (403, "text/plain", text("forbidden host"));
    }
    if let Some(origin) = head.header("origin")
        && !allowed_origin(origin, shared.port)
    {
        return (403, "text/plain", text("forbidden origin"));
    }
    if head.path.split('?').next() != Some("/mcp") {
        return (404, "text/plain", text("not found"));
    }
    let Some(token) = bearer(head.header("authorization")) else {
        return (401, "text/plain", text("missing or invalid token"));
    };
    if !shared.endpoint.authorized(token) {
        return (401, "text/plain", text("missing or invalid token"));
    }
    if head.method != "POST" {
        return (405, "text/plain", text("only POST"));
    }
    let Ok(request) = serde_json::from_slice::<Value>(body) else {
        let err = serde_json::json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse error"}});
        return (400, "application/json", err.to_string().into_bytes());
    };
    match shared.endpoint.handle(token, request).await {
        Some(resp) => (200, "application/json", resp.to_string().into_bytes()),
        // Only notifications.
        None => (202, "text/plain", Vec::new()),
    }
}

/// `Host` names this endpoint (DNS rebinding protection).
fn allowed_host(host: Option<&str>, port: u16) -> bool {
    let Some(host) = host else { return false };
    let host = host.trim().to_ascii_lowercase();
    [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
    ]
    .contains(&host)
}

/// An `Origin` (sent by browsers) is this same endpoint.
fn allowed_origin(origin: &str, port: u16) -> bool {
    let origin = origin.trim().to_ascii_lowercase();
    [
        format!("http://127.0.0.1:{port}"),
        format!("http://localhost:{port}"),
    ]
    .contains(&origin)
}

/// The token of an `Authorization: Bearer <token>` header.
fn bearer(header: Option<&str>) -> Option<&str> {
    header
        .and_then(|h| {
            h.strip_prefix("Bearer ")
                .or_else(|| h.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

async fn read_head<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> std::io::Result<Option<Head>> {
    let mut size = 0usize;
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return if lines.is_empty() {
                Ok(None)
            } else {
                Err(std::io::Error::other("connection closed mid-request"))
            };
        }
        size += n;
        if size > MAX_HEAD {
            return Err(std::io::Error::other("headers too large"));
        }
        let line = line.trim_end_matches(['\r', '\n']).to_string();
        if line.is_empty() {
            if lines.is_empty() {
                // Stray empty line between requests.
                continue;
            }
            break;
        }
        lines.push(line);
    }
    let mut first = lines[0].split_whitespace();
    let method = first.next().unwrap_or("").to_string();
    let path = first.next().unwrap_or("").to_string();
    let headers = lines[1..]
        .iter()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Ok(Some(Head {
        method,
        path,
        headers,
    }))
}

async fn read_body<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    head: &Head,
) -> std::io::Result<Vec<u8>> {
    let too_large = || std::io::Error::other("body too large");
    if head
        .header("transfer-encoding")
        .is_some_and(|t| t.to_ascii_lowercase().contains("chunked"))
    {
        let mut body = Vec::new();
        loop {
            let mut size_line = String::new();
            reader.read_line(&mut size_line).await?;
            let size = usize::from_str_radix(size_line.trim().split(';').next().unwrap_or("0"), 16)
                .map_err(|_| std::io::Error::other("bad chunk"))?;
            if size == 0 {
                // Trailers until the empty line.
                loop {
                    let mut l = String::new();
                    if reader.read_line(&mut l).await? == 0 || l.trim().is_empty() {
                        break;
                    }
                }
                return Ok(body);
            }
            if body.len() + size > MAX_BODY {
                return Err(too_large());
            }
            let start = body.len();
            body.resize(start + size, 0);
            reader.read_exact(&mut body[start..]).await?;
            let mut crlf = [0u8; 2];
            reader.read_exact(&mut crlf).await?;
        }
    }
    let len: usize = head
        .header("content-length")
        .and_then(|l| l.parse().ok())
        .unwrap_or(0);
    if len > MAX_BODY {
        return Err(too_large());
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await?;
    Ok(body)
}

async fn respond<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    status: u16,
    kind: &str,
    body: &[u8],
    close: bool,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        _ => "Error",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n",
        body.len()
    );
    if status == 401 {
        head.push_str("WWW-Authenticate: Bearer\r\n");
    }
    if status == 405 {
        head.push_str("Allow: POST\r\n");
    }
    if close {
        head.push_str("Connection: close\r\n");
    }
    head.push_str("\r\n");
    w.write_all(head.as_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use serde_json::json;

    use super::*;
    use crate::provider::ToolSpec;
    use crate::tools::ToolOutcome;

    struct Echo;

    #[async_trait]
    impl McpTools for Echo {
        fn specs(&self) -> Vec<ToolSpec> {
            vec![ToolSpec {
                name: "echo".into(),
                description: "Echoes".into(),
                schema: json!({"type": "object"}),
            }]
        }

        async fn call(&self, _: &str, args: &Value) -> Result<ToolOutcome, (i64, String)> {
            Ok(ToolOutcome {
                ok: true,
                content: args["text"].as_str().unwrap_or("").to_string(),
            })
        }
    }

    /// Sends a raw request and returns the status and body.
    async fn raw(server: &LocalMcpServer, request: String) -> (u16, String) {
        let addr = server
            .url()
            .trim_start_matches("http://")
            .trim_end_matches("/mcp");
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(request.as_bytes()).await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        let status = out[9..12].parse().unwrap();
        let body = out.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        (status, body)
    }

    fn post(
        server: &LocalMcpServer,
        host: &str,
        auth: Option<&str>,
        extra: &str,
        body: &str,
    ) -> String {
        let _ = server;
        format!(
            "POST /mcp HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n{}{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            auth.map(|t| format!("Authorization: Bearer {t}\r\n"))
                .unwrap_or_default(),
            body.len()
        )
    }

    #[tokio::test]
    async fn only_localhost_with_the_token() {
        let server = LocalMcpServer::start(Arc::new(Echo)).await.unwrap();
        assert!(server.url().starts_with("http://127.0.0.1:"));
        assert!(server.token().len() > 20);
        let host = server
            .url()
            .trim_start_matches("http://")
            .trim_end_matches("/mcp")
            .to_string();
        let list = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;

        // No token, or a wrong one.
        let (status, _) = raw(&server, post(&server, &host, None, "", list)).await;
        assert_eq!(status, 401);
        let (status, _) = raw(&server, post(&server, &host, Some("nope"), "", list)).await;
        assert_eq!(status, 401);

        // Right token.
        let token = server.token().to_string();
        let (status, body) = raw(&server, post(&server, &host, Some(&token), "", list)).await;
        assert_eq!(status, 200);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["result"]["tools"][0]["name"], "echo");

        // Another host name (DNS rebinding) or a web page's origin.
        let (status, _) = raw(
            &server,
            post(&server, "evil.example:80", Some(&token), "", list),
        )
        .await;
        assert_eq!(status, 403);
        let (status, _) = raw(
            &server,
            post(
                &server,
                &host,
                Some(&token),
                "Origin: https://evil.example\r\n",
                list,
            ),
        )
        .await;
        assert_eq!(status, 403);

        // Only POST to /mcp.
        let (status, _) = raw(
            &server,
            format!("GET /mcp HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert_eq!(status, 405);
        let (status, _) = raw(
            &server,
            format!("POST /other HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert_eq!(status, 404);

        // Notifications get no body.
        let (status, body) = raw(
            &server,
            post(
                &server,
                &host,
                Some(&token),
                "",
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            ),
        )
        .await;
        assert_eq!((status, body.as_str()), (202, ""));
    }

    #[tokio::test]
    async fn tool_calls_over_http_with_keep_alive_and_chunks() {
        let server = LocalMcpServer::start(Arc::new(Echo)).await.unwrap();
        let client = reqwest::Client::new();
        for text in ["one", "two"] {
            let v: Value = client
                .post(server.url())
                .bearer_auth(server.token())
                .json(&json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "echo", "arguments": {"text": text}}}))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(v["result"]["content"][0]["text"], text);
            assert_eq!(v["result"]["isError"], false);
        }
        // Unknown tool.
        let v: Value = client
            .post(server.url())
            .bearer_auth(server.token())
            .json(&json!({"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "rm"}}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(v["error"]["code"], -32602);
        // Chunked body.
        let host = server
            .url()
            .trim_start_matches("http://")
            .trim_end_matches("/mcp")
            .to_string();
        let body = r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#;
        let (status, out) = raw(
            &server,
            format!(
                "POST /mcp HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
                server.token(),
                body.len()
            ),
        )
        .await;
        assert_eq!(status, 200);
        assert!(out.contains("\"id\":2"));
    }

    #[tokio::test]
    async fn engine_tasks_need_a_running_tasks_token_and_chain_source_wins() {
        use termoak_core::crypto::MasterKey;

        struct Fixed;
        #[async_trait]
        impl crate::access::ChainSource for Fixed {
            async fn chain(
                &self,
                _: termoak_core::Id,
                _: Option<&str>,
            ) -> Result<Vec<crate::access::ChainEntry>, crate::error::AiError> {
                Ok(vec![crate::access::ChainEntry::server("local-agent")])
            }
        }

        let store = termoak_core::Store::open_in_memory(MasterKey::generate()).unwrap();
        let pool = termoak_ssh::ConnectionPool::new(
            store.clone(),
            termoak_ssh::HostKeyPolicy::Strict,
            Duration::from_secs(60),
        );
        let engine = AiEngine::new(store, pool, None, crate::config::AiConfig::default())
            .await
            .unwrap();
        engine.set_chain_source(Arc::new(Fixed));
        let chain = engine
            .plan_chain(termoak_core::new_id(), Some("claude"))
            .await
            .unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].spec, "local-agent");

        let server = LocalMcpServer::start_for_tasks(engine.clone())
            .await
            .unwrap();
        assert!(server.url().starts_with("http://127.0.0.1:"));
        let client = reqwest::Client::new();
        let ping = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
        for token in [None, Some("aks_mcp_not_a_task")] {
            let mut req = client.post(server.url()).json(&ping);
            if let Some(t) = token {
                req = req.bearer_auth(t);
            }
            assert_eq!(req.send().await.unwrap().status(), 401);
        }
    }

    #[test]
    fn host_and_origin_rules() {
        assert!(allowed_host(Some("127.0.0.1:4000"), 4000));
        assert!(allowed_host(Some("LOCALHOST:4000"), 4000));
        assert!(!allowed_host(Some("127.0.0.1:4001"), 4000));
        assert!(!allowed_host(None, 4000));
        assert!(allowed_origin("http://127.0.0.1:4000", 4000));
        assert!(!allowed_origin("null", 4000));
        assert_eq!(bearer(Some("Bearer abc")), Some("abc"));
        assert_eq!(bearer(Some("Basic abc")), None);
        assert_eq!(bearer(Some("Bearer ")), None);
        let fixed = FixedToken {
            tools: Arc::new(Echo),
            token: "abc".into(),
        };
        assert!(fixed.authorized("abc"));
        assert!(!fixed.authorized("abcd"));
        assert!(!fixed.authorized(""));
    }
}

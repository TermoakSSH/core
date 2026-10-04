//! Email verification with a code: registration says it is pending,
//! `verify_code` signs in and keeps the tokens, `resend_code` asks for
//! another code, and the errors are recognized.

use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::{Value, json};
use termoak_client::api::ApiClient;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

type Seen = Arc<Mutex<Vec<(String, Value)>>>;

fn user(verified: bool) -> Value {
    json!({
        "id": "0190a3a4-7b1c-7cc0-9c1b-6d5f3e2a1b00",
        "email": "ana@example.com",
        "name": "Ana",
        "is_admin": false,
        "disabled": false,
        "totp_enabled": false,
        "created_at": 1,
        "email_verified": verified,
    })
}

fn tokens(access: &str) -> Value {
    json!({
        "access_token": access,
        "access_expires_at": i64::MAX,
        "refresh_token": format!("{access}-refresh"),
        "refresh_expires_at": i64::MAX,
        "device_id": "0190a3a4-7b1c-7cc0-9c1b-6d5f3e2a1b01",
    })
}

/// What the fake server answers to each request.
fn answer(path: &str, auth: Option<&str>, body: &Value) -> (u16, Value) {
    match path {
        "/api/v1/auth/register" => (
            200,
            json!({"user": user(false), "tokens": tokens("restricted"), "verification_required": true}),
        ),
        // An older server: no `verification_required`.
        "/api/v1/auth/login" => (200, json!({"user": user(true), "tokens": tokens("old")})),
        "/api/v1/auth/verify-code" if body["code"] == "123456" => (
            200,
            json!({"user": user(true), "tokens": tokens("verified"), "verification_required": false}),
        ),
        "/api/v1/auth/verify-code" => (
            400,
            json!({"error": {"code": "invalid_code", "message": "the code is wrong or has expired"}}),
        ),
        "/api/v1/auth/resend-code" if body["email"] == "busy@example.com" => (
            429,
            json!({"error": {"code": "too_many_attempts", "message": "wait", "retry_after": 42}}),
        ),
        "/api/v1/auth/resend-code" => (200, json!({"ok": true, "resend_after": 60})),
        "/api/v1/me" if auth == Some("Bearer verified") => (
            200,
            json!({"user": user(true), "verification_required": false}),
        ),
        "/api/v1/me" => (
            200,
            json!({"user": user(false), "verification_required": true}),
        ),
        "/api/v1/teams" => (
            403,
            json!({"error": {"code": "email_not_verified", "message": "confirm your email",
                             "email": "ana@example.com", "verification": ["code", "link"]}}),
        ),
        _ => (
            404,
            json!({"error": {"code": "not_found", "message": "no"}}),
        ),
    }
}

/// A tiny HTTP/1.1 server that records the requests.
async fn fake_server() -> (String, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen: Seen = Arc::default();
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let log = log.clone();
            tokio::spawn(async move {
                let mut stream = BufReader::new(stream);
                loop {
                    let mut line = String::new();
                    if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                    let (mut len, mut auth) = (0usize, None);
                    loop {
                        let mut h = String::new();
                        stream.read_line(&mut h).await.unwrap();
                        let h = h.trim_end();
                        if h.is_empty() {
                            break;
                        }
                        let (name, value) = h.split_once(':').unwrap_or((h, ""));
                        if name.eq_ignore_ascii_case("content-length") {
                            len = value.trim().parse().unwrap();
                        } else if name.eq_ignore_ascii_case("authorization") {
                            auth = Some(value.trim().to_string());
                        }
                    }
                    let mut raw = vec![0; len];
                    stream.read_exact(&mut raw).await.unwrap();
                    let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
                    let (status, reply) = answer(&path, auth.as_deref(), &body);
                    log.lock().push((path, body));
                    let reply = reply.to_string();
                    let head = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                        reply.len()
                    );
                    let s = stream.get_mut();
                    s.write_all(head.as_bytes()).await.unwrap();
                    s.write_all(reply.as_bytes()).await.unwrap();
                }
            });
        }
    });
    (base, seen)
}

#[tokio::test]
async fn verification_with_a_code() {
    let (base, seen) = fake_server().await;

    // Registration says that the email is pending.
    let api = ApiClient::new(&base).unwrap();
    let auth = api
        .register("ana@example.com", "Ana", "long-password", "laptop", "cli")
        .await
        .unwrap();
    assert!(auth.verification_required);
    assert!(api.verification_required().await.unwrap());
    // Anything else fails with email_not_verified.
    let err = api.get::<Value>("/api/v1/teams").await.unwrap_err();
    assert!(err.is_email_not_verified(), "{err}");

    // A wrong code.
    let fresh = ApiClient::new(&base).unwrap();
    let err = fresh
        .verify_code("ana@example.com", "000000", None, "phone", "ios")
        .await
        .unwrap_err();
    assert!(err.is_invalid_code(), "{err}");
    assert!(!fresh.is_logged_in());

    // The right one signs in and keeps the tokens.
    let auth = fresh
        .verify_code(" ana@example.com ", " 123456 ", None, "phone", "ios")
        .await
        .unwrap();
    assert!(!auth.verification_required);
    assert!(auth.user.email_verified);
    assert_eq!(fresh.tokens().unwrap().access_token, "verified");
    assert!(!fresh.verification_required().await.unwrap());

    // Asking for another code.
    fresh.resend_code("ana@example.com").await.unwrap();
    let err = fresh.resend_code("busy@example.com").await.unwrap_err();
    assert_eq!(err.api_code(), Some("too_many_attempts"));

    // An older server does not send the flag: not pending.
    let old = ApiClient::new(&base).unwrap();
    let auth = old
        .login("ana@example.com", "long-password", "laptop", "cli")
        .await
        .unwrap();
    assert!(!auth.verification_required);

    let seen = seen.lock();
    let verify: Vec<&Value> = seen
        .iter()
        .filter(|(p, _)| p == "/api/v1/auth/verify-code")
        .map(|(_, b)| b)
        .collect();
    assert_eq!(verify.len(), 2);
    assert_eq!(verify[1]["email"], "ana@example.com");
    assert_eq!(verify[1]["code"], "123456");
    assert_eq!(verify[1]["device_name"], "phone");
    assert_eq!(verify[1]["platform"], "ios");
    assert!(
        seen.iter()
            .any(|(p, b)| p == "/api/v1/auth/resend-code" && b["email"] == "ana@example.com")
    );
}

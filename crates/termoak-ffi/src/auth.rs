//! Interactive questions while connecting over SSH (server fingerprint, 2FA,
//! passwords, passphrases), answered by the app.

use std::sync::Arc;

use async_trait::async_trait;
use termoak_ssh::prompt::{AuthPrompter, Prompt};

/// Kind of authentication question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AuthPromptKind {
    /// Questions from the server (2FA codes, OTP...).
    KeyboardInteractive,
    /// The user's password (none is saved).
    Password,
    /// Passphrase of an encrypted key with no saved passphrase.
    Passphrase,
}

/// A field to fill in.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PromptField {
    pub text: String,
    /// Whether the answer may be shown (`false` = password or code).
    pub echo: bool,
}

/// Authentication question to show in a dialog.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AuthRequest {
    pub kind: AuthPromptKind,
    /// Host being connected to.
    pub host: String,
    /// Title (request name, user or key).
    pub title: String,
    /// Instructions from the server (may be empty).
    pub instructions: String,
    /// Fields to fill in; the answer must have one entry per field, in order.
    pub fields: Vec<PromptField>,
}

/// Implemented by the app to answer the questions of an SSH connection.
///
/// **Threads**: called from a background thread and it **may block** while
/// the app shows a dialog and waits for the user (hopping to the main thread
/// and waiting for the answer, e.g. with a semaphore). It is never called
/// from the main thread. The fingerprint must be confirmed within about 30
/// seconds or the SSH handshake times out.
#[uniffi::export(foreign)]
pub trait AuthHandler: Send + Sync {
    /// Unknown server: trust this fingerprint? If accepted, it is saved in the
    /// known hosts. If the key of a known server changes, nothing is asked:
    /// the connection fails with `HostKey`.
    fn on_host_key(&self, host: String, port: u32, key_type: String, fingerprint: String) -> bool;

    /// Authentication question. Returning `nil`/`null` cancels.
    fn on_prompt(&self, request: AuthRequest) -> Option<Vec<String>>;
}

/// Adapts the app's `AuthHandler` to the SSH engine's `AuthPrompter`.
pub(crate) struct FfiPrompter {
    pub(crate) handler: Arc<dyn AuthHandler>,
    /// Fingerprints already confirmed through `HostKeyChangeHandler`
    /// (changed keys the user trusted): accepted without asking again.
    pub(crate) trusted: Vec<String>,
}

impl FfiPrompter {
    async fn ask(&self, request: AuthRequest) -> Option<Vec<String>> {
        let handler = self.handler.clone();
        tokio::task::spawn_blocking(move || handler.on_prompt(request))
            .await
            .ok()
            .flatten()
    }

    async fn ask_one(&self, request: AuthRequest) -> Option<String> {
        self.ask(request)
            .await
            .and_then(|a| a.into_iter().next())
            .filter(|a| !a.is_empty())
    }
}

#[async_trait]
impl AuthPrompter for FfiPrompter {
    async fn confirm_host_key(
        &self,
        host: &str,
        port: u16,
        key_type: &str,
        fingerprint: &str,
    ) -> bool {
        if self.trusted.iter().any(|t| t == fingerprint) {
            return true;
        }
        let handler = self.handler.clone();
        let (host, key_type, fingerprint) = (
            host.to_string(),
            key_type.to_string(),
            fingerprint.to_string(),
        );
        tokio::task::spawn_blocking(move || {
            handler.on_host_key(host, port.into(), key_type, fingerprint)
        })
        .await
        .unwrap_or(false)
    }

    async fn keyboard_interactive(
        &self,
        host: &str,
        name: &str,
        instructions: &str,
        prompts: &[Prompt],
    ) -> Option<Vec<String>> {
        self.ask(AuthRequest {
            kind: AuthPromptKind::KeyboardInteractive,
            host: host.to_string(),
            title: name.to_string(),
            instructions: instructions.to_string(),
            fields: prompts
                .iter()
                .map(|p| PromptField {
                    text: p.text.clone(),
                    echo: p.echo,
                })
                .collect(),
        })
        .await
    }

    async fn passphrase(&self, host: &str, key_label: &str) -> Option<String> {
        self.ask_one(AuthRequest {
            kind: AuthPromptKind::Passphrase,
            host: host.to_string(),
            title: key_label.to_string(),
            instructions: String::new(),
            fields: vec![PromptField {
                text: format!("Passphrase for key \"{key_label}\""),
                echo: false,
            }],
        })
        .await
    }

    async fn password(&self, host: &str, user: &str) -> Option<String> {
        self.ask_one(AuthRequest {
            kind: AuthPromptKind::Password,
            host: host.to_string(),
            title: user.to_string(),
            instructions: String::new(),
            fields: vec![PromptField {
                text: format!("Password for {user}@{host}"),
                echo: false,
            }],
        })
        .await
    }
}

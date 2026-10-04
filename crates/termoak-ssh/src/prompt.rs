//! Interactive questions while connecting (2FA, passphrases, fingerprints).
//!
//! Each client implements them its own way: the desktop app shows a dialog,
//! the server forwards them over WebSocket to the connected device, and the
//! background AI does not answer (the connection fails with a clear error).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Keyboard-interactive authentication question.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prompt {
    pub text: String,
    /// Whether the answer may be shown (false = password/code).
    pub echo: bool,
}

#[async_trait]
pub trait AuthPrompter: Send + Sync {
    /// Unknown host: trust this fingerprint?
    async fn confirm_host_key(
        &self,
        _host: &str,
        _port: u16,
        _key_type: &str,
        _fingerprint: &str,
    ) -> bool {
        false
    }

    /// Questions from the server (2FA codes, OTP...). `None` cancels.
    async fn keyboard_interactive(
        &self,
        _host: &str,
        _name: &str,
        _instructions: &str,
        _prompts: &[Prompt],
    ) -> Option<Vec<String>> {
        None
    }

    /// Passphrase for an encrypted key with no saved passphrase.
    async fn passphrase(&self, _host: &str, _key_label: &str) -> Option<String> {
        None
    }

    /// Password when none is saved.
    async fn password(&self, _host: &str, _user: &str) -> Option<String> {
        None
    }

    /// Server welcome banner.
    async fn banner(&self, _host: &str, _banner: &str) {}
}

/// Answers nothing (background tasks).
pub struct NoPrompter;

#[async_trait]
impl AuthPrompter for NoPrompter {}

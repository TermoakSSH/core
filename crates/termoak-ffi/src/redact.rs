//! Secret redaction on the device: the heuristic the server applies to what
//! reaches an AI provider, plus bare `Bearer` tokens, exactly as the desktop
//! does for terminal text (`termoak_core::redact::redact_terminal`), so the
//! apps hide passwords, tokens and keys in the terminal screen before it
//! leaves the phone (the copilot's context, a question about an error...).

/// Hides the secrets in `text` with `[redacted]`: private key blocks,
/// `Authorization`/`Cookie` header values, the password of
/// `scheme://user:password@host` URLs, values of secret-looking keys
/// (`password=…`, `"api_key": "…"`, `export GITHUB_TOKEN=…`, `--password …`),
/// well-known token formats (AWS, Google, GitHub, GitLab, Slack, Stripe,
/// OpenAI/Anthropic, npm, Hugging Face, JWTs) and the token after a bare
/// `Bearer` (a token a command printed). Key names are kept, so the
/// text still makes sense. Fast enough to call on every screen sent to the
/// AI.
#[uniffi::export]
pub fn redact_secrets(text: String) -> String {
    termoak_core::redact::redact_terminal(&text)
}

/// Whether [`redact_secrets`] would hide anything in `text` (e.g. to warn
/// before sending it).
#[uniffi::export]
pub fn contains_secrets(text: String) -> bool {
    termoak_core::redact::terminal_contains_secrets(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_and_detects() {
        let screen = "$ export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n$ ls\n";
        let out = redact_secrets(screen.into());
        assert!(!out.contains("ghp_abcdefghijklmnopqrstuvwxyz0123456789"));
        assert!(out.contains("[redacted]"));
        assert!(out.contains("GITHUB_TOKEN"));
        assert!(contains_secrets(screen.into()));
        assert!(!contains_secrets("total 0\n$ uptime\n".into()));
        assert_eq!(redact_secrets("plain text".into()), "plain text");
        assert_eq!(
            redact_secrets("got Bearer abcdefgh12345 back".into()),
            "got Bearer [redacted] back"
        );
    }
}

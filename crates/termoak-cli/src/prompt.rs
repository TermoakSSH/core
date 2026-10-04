//! Interactive prompts in the terminal (fingerprints, passwords, 2FA).

use std::io::Write;

use async_trait::async_trait;
use termoak_ssh::prompt::{AuthPrompter, Prompt};

/// Reads a line from standard input.
pub fn ask_line(question: &str) -> std::io::Result<String> {
    eprint!("{question}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Password from `TERMOAK_PASSWORD` (scripts) or asked for without echo.
pub fn password_from_env_or(question: &str) -> std::io::Result<String> {
    match std::env::var("TERMOAK_PASSWORD") {
        Ok(p) if !p.is_empty() => Ok(p),
        _ => rpassword::prompt_password(question),
    }
}

fn ask_blocking(question: String, secret: bool) -> Option<String> {
    if secret {
        rpassword::prompt_password(question).ok()
    } else {
        ask_line(&question).ok()
    }
}

/// Asks the user through the terminal.
pub struct CliPrompter;

#[async_trait]
impl AuthPrompter for CliPrompter {
    async fn confirm_host_key(
        &self,
        host: &str,
        port: u16,
        key_type: &str,
        fingerprint: &str,
    ) -> bool {
        let q = format!(
            "The host {host}:{port} is new.\n{key_type} fingerprint: {fingerprint}\nTrust it and save it? [y/N] "
        );
        tokio::task::spawn_blocking(move || ask_blocking(q, false))
            .await
            .ok()
            .flatten()
            .is_some_and(|a| matches!(a.trim().to_lowercase().as_str(), "y" | "yes"))
    }

    async fn keyboard_interactive(
        &self,
        host: &str,
        name: &str,
        instructions: &str,
        prompts: &[Prompt],
    ) -> Option<Vec<String>> {
        if !name.is_empty() || !instructions.is_empty() {
            eprintln!("{host}: {name} {instructions}");
        }
        let prompts = prompts.to_vec();
        tokio::task::spawn_blocking(move || {
            prompts
                .into_iter()
                .map(|p| ask_blocking(p.text, !p.echo))
                .collect::<Option<Vec<String>>>()
        })
        .await
        .ok()
        .flatten()
    }

    async fn passphrase(&self, _host: &str, key_label: &str) -> Option<String> {
        let q = format!("Passphrase for key \"{key_label}\": ");
        tokio::task::spawn_blocking(move || ask_blocking(q, true))
            .await
            .ok()
            .flatten()
    }

    async fn password(&self, host: &str, user: &str) -> Option<String> {
        let q = format!("Password for {user}@{host}: ");
        tokio::task::spawn_blocking(move || ask_blocking(q, true))
            .await
            .ok()
            .flatten()
    }

    async fn banner(&self, _host: &str, banner: &str) {
        eprintln!("{}", banner.trim_end());
    }
}

/// No interaction (parallel runs): unknown hosts fail.
pub struct NoInteractive;

#[async_trait]
impl AuthPrompter for NoInteractive {}

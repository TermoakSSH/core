//! Pieces shared by the external agents that run as command-line programs
//! (Claude Code, Antigravity, a local OpenCode server): the prompt, a private
//! temporary directory, the binary, the process environment and the MCP
//! configuration that gives them Termoak's tools.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use super::find_in_path;
use crate::error::AiError;
use crate::message::{Message, transcript_as_text};

/// Instruction added when the agent gets Termoak's tools.
pub(crate) const TOOLS_ONLY: &str = "Use ONLY the tools of the \"termoak\" MCP server to act on the user's hosts and terminals. \
You have no local shell and must not touch files on this computer. Reply to the user's last message, in the user's language.";

/// Name of the MCP server in the agents' configuration (their tools are
/// called `mcp__termoak__<tool>` or similar).
pub(crate) const MCP_NAME: &str = "termoak";

/// The prompt of a one-shot run: instructions, the conversation and, with
/// tools, how to use them.
pub(crate) fn agent_prompt(system: &str, messages: &[Message], tools: bool) -> String {
    let mut prompt = String::new();
    if !system.is_empty() {
        prompt.push_str(system);
        prompt.push_str("\n\n");
    }
    prompt.push_str("# Conversation\n");
    prompt.push_str(&transcript_as_text(messages));
    if tools {
        prompt.push_str("\n\n");
        prompt.push_str(TOOLS_ONLY);
    }
    prompt
}

/// The conversation part only (for agents that take the instructions apart).
pub(crate) fn conversation_prompt(messages: &[Message], tools: bool) -> String {
    agent_prompt("", messages, tools)
}

/// Temporary directory of a run, only for this user, removed at the end.
pub(crate) struct Workdir(PathBuf);

impl Workdir {
    pub(crate) fn new(provider: &str) -> Result<Self, AiError> {
        let dir = std::env::temp_dir()
            .join(format!("termoak-{provider}"))
            .join(format!("run-{}", uuid::Uuid::new_v4()));
        create_private_dir(&dir).map_err(|e| AiError::Process {
            provider: provider.to_string(),
            message: format!("could not create a temporary directory: {e}"),
        })?;
        Ok(Self(dir))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    /// Writes a file readable only by this user (it may hold a token).
    pub(crate) fn write_private(&self, name: &str, content: &str) -> std::io::Result<PathBuf> {
        let path = self.0.join(name);
        if let Some(parent) = path.parent() {
            create_private_dir(parent)?;
        }
        write_private_file(&path, content.as_bytes())?;
        Ok(path)
    }
}

impl Drop for Workdir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_private_file(path: &Path, content: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(content)
}

/// The agent's executable: by absolute path, or looked up in `path_env`
/// (when given) and then in this process' `PATH`.
pub(crate) fn find_binary(command: &str, path_env: Option<&str>) -> Option<PathBuf> {
    let p = PathBuf::from(command);
    if p.components().count() > 1 {
        return p.exists().then_some(p);
    }
    if let Some(dirs) = path_env {
        for dir in std::env::split_paths(dirs) {
            for name in exe_names(command) {
                let candidate = dir.join(&name);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    find_in_path(command)
}

fn exe_names(command: &str) -> Vec<String> {
    if cfg!(windows) {
        ["exe", "cmd", "bat"]
            .iter()
            .map(|e| format!("{command}.{e}"))
            .chain(std::iter::once(command.to_string()))
            .collect()
    } else {
        vec![command.to_string()]
    }
}

/// The binary or [`AiError::NotInstalled`].
pub(crate) fn require_binary(
    provider: &str,
    command: &str,
    path_env: Option<&str>,
) -> Result<PathBuf, AiError> {
    find_binary(command, path_env).ok_or_else(|| AiError::NotInstalled {
        provider: provider.to_string(),
        message: format!("\"{command}\" was not found"),
    })
}

/// MCP server entry (Streamable HTTP with a bearer token) in the
/// `{"mcpServers": {...}}` format most agents read. `url_key` is `url`
/// (Claude Code) or `serverUrl` (Antigravity).
pub(crate) fn mcp_servers_json(url: &str, token: &str, url_key: &str) -> Value {
    let mut server = json!({
        "headers": {"Authorization": format!("Bearer {token}")},
    });
    server[url_key] = json!(url);
    if url_key == "url" {
        server["type"] = json!("http");
    }
    json!({"mcpServers": {MCP_NAME: server}})
}

/// The last non-empty line of an error output, shortened.
pub(crate) fn last_line(raw: &str) -> String {
    raw.lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("unknown error")
        .chars()
        .take(300)
        .collect()
}

/// Does an error output say the agent is not signed in?
pub(crate) fn looks_logged_out(raw: &str) -> bool {
    let l = raw.to_lowercase();
    [
        "not logged in",
        "not signed in",
        "please run /login",
        "please log in",
        "please sign in",
        "invalid api key",
        "authentication_error",
        "oauth token has expired",
        "login required",
        "unauthenticated",
    ]
    .iter()
    .any(|p| l.contains(p))
}

/// Does an error output say the CLI is too old for these flags?
pub(crate) fn looks_outdated(raw: &str) -> bool {
    let l = raw.to_lowercase();
    l.contains("unknown option")
        || l.contains("unexpected argument")
        || l.contains("unrecognized option")
        || (l.contains("unknown") && l.contains("flag"))
}

/// Collects (up to 16 KB of) an error output in the background.
pub(crate) fn collect<R>(reader: R) -> tokio::task::JoinHandle<String>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        use tokio::io::AsyncBufReadExt;
        let mut lines = tokio::io::BufReader::new(reader).lines();
        let mut buf = String::new();
        while let Ok(Some(l)) = lines.next_line().await {
            if buf.len() < 16_000 {
                buf.push_str(&l);
                buf.push('\n');
            }
        }
        buf
    })
}

/// Text of a line of output that should hold one JSON event: without the
/// terminal decoration a pseudo-terminal may add (`\r`, colors...).
pub(crate) fn json_line(raw: &str) -> Option<Value> {
    let clean = termoak_ssh::ansi::strip(raw);
    let clean = clean.trim_matches(|c: char| c.is_whitespace() || c == '\r');
    let start = clean.find('{')?;
    serde_json::from_str(&clean[start..]).ok()
}

/// No console window for the agents on Windows.
pub(crate) fn hide_window(cmd: &mut tokio::process::Command) {
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    let _ = cmd;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompts_carry_the_conversation_and_the_tool_rule() {
        let msgs = vec![Message::user_text("why is nginx down?")];
        let p = agent_prompt("SYSTEM", &msgs, true);
        assert!(p.starts_with("SYSTEM\n\n# Conversation\n"));
        assert!(p.contains("why is nginx down?"));
        assert!(p.ends_with(TOOLS_ONLY));
        assert!(!conversation_prompt(&msgs, false).contains("SYSTEM"));
    }

    #[test]
    fn mcp_config_has_the_token_in_a_header() {
        let v = mcp_servers_json("http://127.0.0.1:5/mcp", "tok", "url");
        assert_eq!(v["mcpServers"]["termoak"]["type"], "http");
        assert_eq!(
            v["mcpServers"]["termoak"]["headers"]["Authorization"],
            "Bearer tok"
        );
        let v = mcp_servers_json("http://127.0.0.1:5/mcp", "tok", "serverUrl");
        assert_eq!(
            v["mcpServers"]["termoak"]["serverUrl"],
            "http://127.0.0.1:5/mcp"
        );
        assert!(v["mcpServers"]["termoak"].get("type").is_none());
    }

    #[test]
    fn json_lines_survive_terminal_decoration() {
        let v = json_line("\u{1b}[0m{\"type\":\"init\"}\r").unwrap();
        assert_eq!(v["type"], "init");
        assert!(json_line("⠋ thinking…").is_none());
        assert!(json_line("").is_none());
    }

    #[test]
    fn error_classification() {
        assert!(looks_logged_out("Invalid API key · Please run /login"));
        assert!(looks_logged_out("Error: Not logged in"));
        assert!(!looks_logged_out("rate limit"));
        assert!(looks_outdated("error: unknown option '--tools'"));
        assert_eq!(last_line("a\nlast one\n\n"), "last one");
    }

    #[cfg(unix)]
    #[test]
    fn private_files_are_private_and_removed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = Workdir::new("test").unwrap();
        let path = dir.write_private(".agents/mcp.json", "{}").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let root = dir.path().to_path_buf();
        drop(dir);
        assert!(!root.exists());
    }
}

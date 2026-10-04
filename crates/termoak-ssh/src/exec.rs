//! Non-interactive command execution with time and output limits.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use russh::{ChannelMsg, Sig};
use serde::{Deserialize, Serialize};

use crate::client::Connection;
use crate::error::Result;

/// Options for `exec`.
#[derive(Debug, Clone)]
pub struct ExecOptions {
    /// Maximum time (5 minutes by default).
    pub timeout: Duration,
    /// Maximum bytes kept per stream (stdout/stderr).
    pub max_output: usize,
    pub env: BTreeMap<String, String>,
    /// Data for standard input.
    pub stdin: Option<Vec<u8>>,
    /// Request a PTY (some commands need one, e.g. `sudo` with a password).
    pub pty: bool,
}

impl Default for ExecOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(300),
            max_output: 1024 * 1024,
            env: BTreeMap::new(),
            stdin: None,
            pty: false,
        }
    }
}

/// Result of `exec`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecOutput {
    pub exit_code: Option<u32>,
    pub exit_signal: Option<String>,
    #[serde(with = "lossy_bytes")]
    pub stdout: Vec<u8>,
    #[serde(with = "lossy_bytes")]
    pub stderr: Vec<u8>,
    /// Output was discarded for exceeding `max_output`.
    pub truncated: bool,
    pub timed_out: bool,
    pub duration_ms: u64,
}

impl ExecOutput {
    pub fn success(&self) -> bool {
        self.exit_code == Some(0) && !self.timed_out
    }

    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

mod lossy_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&String::from_utf8_lossy(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        Ok(String::deserialize(d)?.into_bytes())
    }
}

fn push_limited(buf: &mut Vec<u8>, data: &[u8], max: usize, truncated: &mut bool) {
    let room = max.saturating_sub(buf.len());
    if data.len() > room {
        *truncated = true;
    }
    buf.extend_from_slice(&data[..data.len().min(room)]);
}

impl Connection {
    /// Runs `command` and waits for it to finish (or for the timeout).
    pub async fn exec(&self, command: &str, opts: &ExecOptions) -> Result<ExecOutput> {
        let started = Instant::now();
        let mut channel = self.open_session_channel().await?;
        for (k, v) in &opts.env {
            let _ = channel.set_env(false, k.as_str(), v.as_str()).await;
        }
        if opts.pty {
            channel
                .request_pty(false, "xterm-256color", 200, 50, 0, 0, &[])
                .await?;
        }
        channel.exec(true, command).await?;
        if let Some(stdin) = &opts.stdin {
            channel.data(&stdin[..]).await?;
        }
        channel.eof().await?;

        let mut out = ExecOutput::default();
        let deadline = tokio::time::Instant::now() + opts.timeout;
        loop {
            match tokio::time::timeout_at(deadline, channel.wait()).await {
                Err(_) => {
                    out.timed_out = true;
                    let _ = channel.signal(Sig::KILL).await;
                    let _ = channel.close().await;
                    break;
                }
                Ok(None) => break,
                Ok(Some(msg)) => match msg {
                    ChannelMsg::Data { data } => {
                        push_limited(&mut out.stdout, &data, opts.max_output, &mut out.truncated)
                    }
                    ChannelMsg::ExtendedData { data, .. } => {
                        push_limited(&mut out.stderr, &data, opts.max_output, &mut out.truncated)
                    }
                    ChannelMsg::ExitStatus { exit_status } => out.exit_code = Some(exit_status),
                    ChannelMsg::ExitSignal { signal_name, .. } => {
                        out.exit_signal = Some(format!("{signal_name:?}"))
                    }
                    ChannelMsg::Close => break,
                    _ => {}
                },
            }
        }
        out.duration_ms = started.elapsed().as_millis() as u64;
        Ok(out)
    }
}

/// Quotes an argument for `sh`.
pub fn shell_quote(arg: &str) -> String {
    if !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:@%+,".contains(c))
    {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(shell_quote("abc/def"), "abc/def");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn output_limit() {
        let mut buf = Vec::new();
        let mut t = false;
        push_limited(&mut buf, b"hello", 6, &mut t);
        push_limited(&mut buf, b"world", 6, &mut t);
        assert_eq!(buf, b"hellow");
        assert!(t);
    }
}

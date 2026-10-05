//! Interactive terminal session (PTY) with scrollback and multiple viewers.
//!
//! A `TerminalSession` is independent of who is watching it: the server keeps
//! it alive even if the phone disconnects, and any number of clients can
//! `attach` to receive the scrollback first and then the live output, with no
//! gaps or duplicates.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use parking_lot::Mutex;
use russh::ChannelMsg;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, watch};

use crate::client::Connection;
use crate::error::{Result, SshError};
use crate::recording::{InputAuthor, Recorder};

/// PTY options.
#[derive(Debug, Clone)]
pub struct PtyOptions {
    pub term: String,
    pub cols: u16,
    pub rows: u16,
    pub env: BTreeMap<String, String>,
    /// Commands to type right after the shell opens.
    pub startup_script: Option<String>,
    pub agent_forwarding: bool,
}

impl Default for PtyOptions {
    fn default() -> Self {
        Self {
            term: "xterm-256color".into(),
            cols: 80,
            rows: 24,
            env: BTreeMap::new(),
            startup_script: None,
            agent_forwarding: false,
        }
    }
}

/// Session status.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TermStatus {
    Starting,
    Running,
    Closed {
        exit_code: Option<u32>,
        reason: Option<String>,
    },
}

impl TermStatus {
    pub fn is_closed(&self) -> bool {
        matches!(self, TermStatus::Closed { .. })
    }
}

/// Bounded scrollback + live broadcast.
pub struct OutputHub {
    scrollback: Mutex<Scrollback>,
    tx: broadcast::Sender<Bytes>,
}

struct Scrollback {
    chunks: VecDeque<Bytes>,
    size: usize,
    limit: usize,
}

impl OutputHub {
    pub fn new(limit: usize) -> Self {
        // Generous margin: a reader that falls further behind gets the whole
        // scrollback again (expensive), so it should not happen with normal bursts.
        let (tx, _) = broadcast::channel(4096);
        Self {
            scrollback: Mutex::new(Scrollback {
                chunks: VecDeque::new(),
                size: 0,
                limit: limit.max(4096),
            }),
            tx,
        }
    }

    /// Appends output to the scrollback and broadcasts it.
    pub fn push(&self, data: Bytes) {
        if data.is_empty() {
            return;
        }
        let mut sb = self.scrollback.lock();
        sb.size += data.len();
        sb.chunks.push_back(data.clone());
        while sb.size > sb.limit {
            match sb.chunks.pop_front() {
                Some(old) => sb.size -= old.len(),
                None => break,
            }
        }
        // Broadcast while holding the lock so `attach` is atomic.
        let _ = self.tx.send(data);
    }

    /// Replaces the whole scrollback (with that of another process that has
    /// it complete). Subscribers receive an empty chunk, which is never real
    /// output: they must `attach` again to read the new one.
    pub fn reset(&self, data: Bytes) {
        let mut sb = self.scrollback.lock();
        sb.chunks.clear();
        sb.size = 0;
        if !data.is_empty() {
            sb.size = data.len();
            sb.chunks.push_back(data);
        }
        while sb.size > sb.limit {
            match sb.chunks.pop_front() {
                Some(old) => sb.size -= old.len(),
                None => break,
            }
        }
        let _ = self.tx.send(Bytes::new());
    }

    /// Current scrollback + subscription to whatever comes next.
    pub fn attach(&self) -> (Bytes, broadcast::Receiver<Bytes>) {
        let sb = self.scrollback.lock();
        let rx = self.tx.subscribe();
        (concat(&sb.chunks, sb.size), rx)
    }

    pub fn snapshot(&self) -> Bytes {
        let sb = self.scrollback.lock();
        concat(&sb.chunks, sb.size)
    }

    /// End of the scrollback as plain text (no ANSI).
    pub fn text_tail(&self, max_chars: usize) -> String {
        let snap = self.snapshot();
        let text = crate::ansi::strip(&String::from_utf8_lossy(&snap));
        crate::ansi::tail(&text, max_chars).to_string()
    }

    pub fn viewers(&self) -> usize {
        self.tx.receiver_count()
    }
}

fn concat(chunks: &VecDeque<Bytes>, size: usize) -> Bytes {
    let mut buf = BytesMut::with_capacity(size);
    for c in chunks {
        buf.extend_from_slice(c);
    }
    buf.freeze()
}

enum Input {
    Data(Bytes),
    Resize(u16, u16),
    Author(InputAuthor),
    Close,
}

/// Interactive terminal over an SSH connection.
pub struct TerminalSession {
    input: mpsc::Sender<Input>,
    hub: Arc<OutputHub>,
    status: watch::Receiver<TermStatus>,
    size: Mutex<(u16, u16)>,
    recorder: Option<Arc<Recorder>>,
    connection: Arc<Connection>,
}

impl TerminalSession {
    /// Opens a PTY with a shell on `conn`.
    pub async fn open(
        conn: Arc<Connection>,
        opts: PtyOptions,
        scrollback_bytes: usize,
        recorder: Option<Recorder>,
    ) -> Result<Arc<Self>> {
        let channel = conn.open_session_channel().await?;
        for (k, v) in &opts.env {
            let _ = channel.set_env(false, k.as_str(), v.as_str()).await;
        }
        if opts.agent_forwarding {
            let _ = channel.agent_forward(false).await;
        }
        channel
            .request_pty(
                true,
                &opts.term,
                opts.cols as u32,
                opts.rows as u32,
                0,
                0,
                &[],
            )
            .await?;
        channel.request_shell(true).await?;
        if let Some(script) = opts
            .startup_script
            .as_deref()
            .filter(|s| !s.trim().is_empty())
        {
            let mut s = script.to_string();
            if !s.ends_with('\n') {
                s.push('\n');
            }
            channel.data(s.as_bytes()).await?;
        }

        let hub = Arc::new(OutputHub::new(scrollback_bytes));
        let (status_tx, status_rx) = watch::channel(TermStatus::Running);
        let (input_tx, mut input_rx) = mpsc::channel::<Input>(256);
        let recorder = recorder.map(Arc::new);
        let (mut read, write) = channel.split();
        // If this side asks to close, russh does not notify the reader: we do it here.
        let closing = Arc::new(tokio::sync::Notify::new());

        // Writer: user input, resizes and close.
        let rec_w = recorder.clone();
        let closing_w = closing.clone();
        tokio::spawn(async move {
            while let Some(input) = input_rx.recv().await {
                let res = match input {
                    Input::Data(data) => {
                        if let Some(r) = &rec_w {
                            r.input(&data);
                        }
                        write.data(&data[..]).await
                    }
                    Input::Resize(c, r) => {
                        if let Some(rec) = &rec_w {
                            rec.resize(c, r);
                        }
                        write.window_change(c as u32, r as u32, 0, 0).await
                    }
                    Input::Author(author) => {
                        if let Some(rec) = &rec_w {
                            rec.author(&author);
                        }
                        Ok(())
                    }
                    Input::Close => {
                        let _ = write.eof().await;
                        let _ = write.close().await;
                        closing_w.notify_one();
                        break;
                    }
                };
                if res.is_err() {
                    break;
                }
            }
        });

        // Reader: server output.
        let hub_r = hub.clone();
        let rec_r = recorder.clone();
        tokio::spawn(async move {
            let mut exit_code = None;
            let mut reason = None;
            let mut deadline: Option<tokio::time::Instant> = None;
            loop {
                let msg = tokio::select! {
                    m = read.wait() => m,
                    _ = closing.notified(), if deadline.is_none() => {
                        // Grace period to collect the last output.
                        deadline = Some(tokio::time::Instant::now() + std::time::Duration::from_millis(500));
                        reason = Some("closed by the user".into());
                        continue;
                    }
                    _ = async {
                        match deadline {
                            Some(d) => tokio::time::sleep_until(d).await,
                            None => std::future::pending().await,
                        }
                    } => break,
                };
                let Some(msg) = msg else { break };
                match msg {
                    ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                        if let Some(r) = &rec_r {
                            r.output(&data);
                        }
                        hub_r.push(data);
                    }
                    ChannelMsg::ExitStatus { exit_status } => exit_code = Some(exit_status),
                    ChannelMsg::ExitSignal {
                        signal_name,
                        error_message,
                        ..
                    } => {
                        reason = Some(if error_message.is_empty() {
                            format!("terminated by signal {signal_name:?}")
                        } else {
                            error_message
                        })
                    }
                    ChannelMsg::Failure => {
                        reason = Some("the server rejected the terminal request".into());
                    }
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
            let _ = status_tx.send(TermStatus::Closed { exit_code, reason });
        });

        if let Some(r) = &recorder {
            r.resize(opts.cols, opts.rows);
        }
        Ok(Arc::new(Self {
            input: input_tx,
            hub,
            status: status_rx,
            size: Mutex::new((opts.cols, opts.rows)),
            recorder,
            connection: conn,
        }))
    }

    /// Scrollback + live output.
    pub fn attach(&self) -> (Bytes, broadcast::Receiver<Bytes>) {
        self.hub.attach()
    }

    pub fn hub(&self) -> &Arc<OutputHub> {
        &self.hub
    }

    pub async fn write(&self, data: impl Into<Bytes>) -> Result<()> {
        self.input
            .send(Input::Data(data.into()))
            .await
            .map_err(|_| SshError::Closed)
    }

    /// Marks who types the input written after this (an `a` event in the
    /// recording, in order with the input). Nothing if not recording.
    pub async fn set_input_author(&self, author: InputAuthor) -> Result<()> {
        if self.recorder.is_none() {
            return Ok(());
        }
        self.input
            .send(Input::Author(author))
            .await
            .map_err(|_| SshError::Closed)
    }

    pub async fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        let (cols, rows) = (cols.clamp(10, 1000), rows.clamp(2, 500));
        {
            let mut size = self.size.lock();
            if *size == (cols, rows) {
                return Ok(());
            }
            *size = (cols, rows);
        }
        self.input
            .send(Input::Resize(cols, rows))
            .await
            .map_err(|_| SshError::Closed)
    }

    pub async fn close(&self) {
        let _ = self.input.send(Input::Close).await;
    }

    pub fn status(&self) -> TermStatus {
        self.status.borrow().clone()
    }

    pub fn watch_status(&self) -> watch::Receiver<TermStatus> {
        self.status.clone()
    }

    pub fn size(&self) -> (u16, u16) {
        *self.size.lock()
    }

    pub fn recording_path(&self) -> Option<std::path::PathBuf> {
        self.recorder.as_ref().map(|r| r.path().to_path_buf())
    }

    pub fn connection(&self) -> &Arc<Connection> {
        &self.connection
    }

    /// Last `max_chars` characters of the screen as plain text.
    pub fn text_tail(&self, max_chars: usize) -> String {
        self.hub.text_tail(max_chars)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn attach_is_gapless() {
        let hub = OutputHub::new(8192);
        hub.push(Bytes::from_static(b"one "));
        let (snap, mut rx) = hub.attach();
        hub.push(Bytes::from_static(b"two"));
        assert_eq!(&snap[..], b"one ");
        assert_eq!(&rx.recv().await.unwrap()[..], b"two");
    }

    #[tokio::test]
    async fn reset_replaces_history_and_warns_readers() {
        let hub = OutputHub::new(8192);
        hub.push(Bytes::from_static(b"old"));
        let (_, mut rx) = hub.attach();
        hub.reset(Bytes::from_static(b"new"));
        assert!(rx.recv().await.unwrap().is_empty());
        assert_eq!(&hub.snapshot()[..], b"new");
    }

    #[test]
    fn scrollback_is_bounded() {
        let hub = OutputHub::new(4096);
        for _ in 0..100 {
            hub.push(Bytes::from(vec![b'x'; 1000]));
        }
        assert!(hub.snapshot().len() <= 4096);
    }
}

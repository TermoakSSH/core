//! Telnet terminal (RFC 854), for the hosts whose protocol is Telnet:
//! network gear, old systems, serial servers.
//!
//! [`TelnetSession`] has the same shape as the SSH [`TerminalSession`]
//! (scrollback and live output, input, resize, status, recording), and
//! [`crate::Terminal`] holds either, so an app can treat both alike.
//!
//! Telnet is unencrypted: everything, passwords too, travels in clear text.
//! It has no keys, agent, jump hosts, SFTP or tunnels; the proxy of the host
//! (SOCKS5, SOCKS4, HTTP `CONNECT`) is used as for SSH.
//!
//! [`TerminalSession`]: crate::TerminalSession

mod login;
mod protocol;

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use termoak_core::resolve::ResolvedHost;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use crate::error::{Result, SshError};
use crate::recording::{InputAuthor, Recorder};
use crate::terminal::{OutputHub, TermStatus};
use login::AutoLogin;
use protocol::Telnet;

/// Options of a Telnet terminal.
#[derive(Debug, Clone)]
pub struct TelnetOptions {
    /// Terminal type sent to the host (`TERMINAL-TYPE`).
    pub term: String,
    pub cols: u16,
    pub rows: u16,
    pub connect_timeout: Duration,
    /// Answer the host's first `login:` and `Password:` prompts with the
    /// host's username and password (see the `login` module: only during
    /// the first 30 seconds, each once).
    pub auto_login: bool,
}

impl Default for TelnetOptions {
    fn default() -> Self {
        Self {
            term: "xterm-256color".into(),
            cols: 80,
            rows: 24,
            connect_timeout: Duration::from_secs(15),
            auto_login: true,
        }
    }
}

/// What a Telnet terminal is connected to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelnetInfo {
    pub label: String,
    pub address: String,
    pub port: u16,
    /// Proxy it goes through (`host:port`), if any.
    pub proxy: Option<String>,
}

enum Input {
    Data(Bytes),
    Resize(u16, u16),
    Author(InputAuthor),
    Ping(oneshot::Sender<Duration>),
    Close,
}

/// Unanswered timing marks after which no more are sent.
const MAX_PENDING_MARKS: usize = 4;

/// Interactive terminal over Telnet.
pub struct TelnetSession {
    input: mpsc::Sender<Input>,
    hub: Arc<OutputHub>,
    status: watch::Receiver<TermStatus>,
    size: Mutex<(u16, u16)>,
    recorder: Option<Arc<Recorder>>,
    info: TelnetInfo,
}

impl std::fmt::Debug for TelnetSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelnetSession")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

/// Checks that a resolved host can be reached over Telnet.
fn check_target(target: &ResolvedHost) -> Result<()> {
    if !target.host.protocol.is_telnet() {
        return Err(SshError::Unsupported(format!(
            "{} is not a Telnet host",
            target.host.label
        )));
    }
    if !target.jumps.is_empty() {
        return Err(SshError::Unsupported(
            "Telnet connections cannot go through jump hosts (remove them from the host or its group)"
                .into(),
        ));
    }
    Ok(())
}

impl TelnetSession {
    /// Connects to a Telnet host (through its proxy, if it has one) and
    /// starts the terminal.
    pub async fn open(
        target: &ResolvedHost,
        opts: TelnetOptions,
        scrollback_bytes: usize,
        recorder: Option<Recorder>,
    ) -> Result<Arc<Self>> {
        check_target(target)?;
        let address = target.host.address.as_str();
        let stream = match &target.proxy {
            Some(p) => crate::proxy::connect(p, address, target.port, opts.connect_timeout).await?,
            None => crate::client::tcp_connect(address, target.port, opts.connect_timeout).await?,
        };
        let info = TelnetInfo {
            label: target.host.label.clone(),
            address: address.to_string(),
            port: target.port,
            proxy: target
                .proxy
                .as_ref()
                .map(|p| format!("{}:{}", p.settings.host, p.settings.port)),
        };
        let login = if opts.auto_login {
            AutoLogin::new(&target.username, target.password.as_deref())
        } else {
            None
        };
        Ok(Self::start(
            stream,
            info,
            login,
            opts,
            scrollback_bytes,
            recorder,
        ))
    }

    /// Runs the terminal over an open stream.
    fn start<S>(
        stream: S,
        info: TelnetInfo,
        login: Option<AutoLogin>,
        opts: TelnetOptions,
        scrollback_bytes: usize,
        recorder: Option<Recorder>,
    ) -> Arc<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let hub = Arc::new(OutputHub::new(scrollback_bytes));
        let (status_tx, status_rx) = watch::channel(TermStatus::Running);
        let (input_tx, input_rx) = mpsc::channel::<Input>(256);
        let recorder = recorder.map(Arc::new);
        if let Some(r) = &recorder {
            r.resize(opts.cols, opts.rows);
        }
        let telnet = Telnet::new(&opts.term, opts.cols, opts.rows);
        tokio::spawn(run(
            stream,
            telnet,
            login,
            input_rx,
            hub.clone(),
            status_tx,
            recorder.clone(),
        ));
        Arc::new(Self {
            input: input_tx,
            hub,
            status: status_rx,
            size: Mutex::new((opts.cols, opts.rows)),
            recorder,
            info,
        })
    }

    pub fn info(&self) -> &TelnetInfo {
        &self.info
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

    /// Marks who types the input written after this (recordings only).
    pub async fn set_input_author(&self, author: InputAuthor) -> Result<()> {
        if self.recorder.is_none() {
            return Ok(());
        }
        self.input
            .send(Input::Author(author))
            .await
            .map_err(|_| SshError::Closed)
    }

    /// New window size (sent with `NAWS` if the host accepted it).
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

    /// Round trip to the host: the time it takes to answer a Telnet
    /// `TIMING-MARK`, sent behind whatever is being typed. Hosts that never
    /// spoke Telnet (raw TCP services) or that do not answer give an error.
    pub async fn latency(&self, timeout: Duration) -> Result<Duration> {
        let (tx, rx) = oneshot::channel();
        self.input
            .send(Input::Ping(tx))
            .await
            .map_err(|_| SshError::Closed)?;
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(d)) => Ok(d),
            Ok(Err(_)) => Err(SshError::Unsupported(format!(
                "{} does not answer Telnet timing marks",
                self.info.label
            ))),
            Err(_) => Err(SshError::Timeout(format!(
                "waiting for {}",
                self.info.label
            ))),
        }
    }

    pub async fn close(&self) {
        let _ = self.input.send(Input::Close).await;
    }

    pub fn is_closed(&self) -> bool {
        self.status.borrow().is_closed()
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

    /// Last `max_chars` characters of the screen as plain text.
    pub fn text_tail(&self, max_chars: usize) -> String {
        self.hub.text_tail(max_chars)
    }
}

/// The connection: host output to the hub, input and negotiation to the host.
async fn run<S>(
    stream: S,
    mut telnet: Telnet,
    mut login: Option<AutoLogin>,
    mut input_rx: mpsc::Receiver<Input>,
    hub: Arc<OutputHub>,
    status_tx: watch::Sender<TermStatus>,
    recorder: Option<Arc<Recorder>>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut pending: VecDeque<(Instant, oneshot::Sender<Duration>)> = VecDeque::new();
    let mut buf = vec![0u8; 16 * 1024];

    let first = telnet.start();
    if let Err(e) = wr.write_all(&first).await {
        let _ = status_tx.send(TermStatus::Closed {
            exit_code: None,
            reason: Some(format!("the connection was cut ({e})")),
        });
        return;
    }
    let reason = loop {
        tokio::select! {
            n = rd.read(&mut buf) => {
                let n = match n {
                    Ok(0) => {
                        break Some("connection closed by the host".into());
                    }
                    Ok(n) => n,
                    Err(e) => {
                        break Some(format!("the connection was cut ({e})"));
                    }
                };
                let got = telnet.receive(&buf[..n]);
                for _ in 0..got.timing_marks {
                    if let Some((at, tx)) = pending.pop_front() {
                        let _ = tx.send(at.elapsed());
                    }
                }
                let mut reply = got.reply;
                if !got.data.is_empty() {
                    if let Some(r) = &recorder {
                        r.output(&got.data);
                    }
                    if let Some(l) = login.as_mut() {
                        if let Some(answer) = l.feed(&got.data) {
                            telnet.encode_input(&answer, &mut reply);
                        }
                        if !l.active() {
                            login = None;
                        }
                    }
                    hub.push(Bytes::from(got.data));
                }
                if !reply.is_empty() && wr.write_all(&reply).await.is_err() {
                    break Some("the connection was cut".into());
                }
            }
            input = input_rx.recv() => {
                let mut out = Vec::new();
                match input {
                    Some(Input::Data(data)) => {
                        if let Some(r) = &recorder {
                            r.input(&data);
                        }
                        telnet.encode_input(&data, &mut out);
                    }
                    Some(Input::Resize(c, r)) => {
                        if let Some(rec) = &recorder {
                            rec.resize(c, r);
                        }
                        if let Some(naws) = telnet.resize(c, r) {
                            out = naws;
                        }
                    }
                    Some(Input::Author(author)) => {
                        if let Some(rec) = &recorder {
                            rec.author(&author);
                        }
                    }
                    Some(Input::Ping(tx)) => {
                        // Only to real Telnet servers, and not piling up
                        // marks a host never answers. Marks that timed out
                        // stay in the queue: answers come in order.
                        if telnet.spoke_telnet() && pending.len() < MAX_PENDING_MARKS {
                            out.extend_from_slice(&Telnet::timing_mark());
                            pending.push_back((Instant::now(), tx));
                        }
                    }
                    Some(Input::Close) | None => {
                        let _ = wr.shutdown().await;
                        break Some("closed by the user".into());
                    }
                }
                if !out.is_empty() && wr.write_all(&out).await.is_err() {
                    break Some("the connection was cut".into());
                }
            }
        }
    };
    let _ = status_tx.send(TermStatus::Closed {
        exit_code: None,
        reason,
    });
}

#[cfg(test)]
mod tests {
    use super::protocol::{cmd::*, opt};
    use super::*;
    use termoak_core::model::{Host, HostProtocol, HostSettings};
    use tokio::net::{TcpListener, TcpStream};

    fn target(port: u16, user: &str, password: Option<&str>) -> ResolvedHost {
        ResolvedHost {
            host: Host {
                id: termoak_core::new_id(),
                label: "switch".into(),
                address: "127.0.0.1".into(),
                group_id: None,
                tags: vec![],
                settings: HostSettings::default(),
                notes: String::new(),
                color: None,
                os: None,
                os_version: None,
                favorite: false,
                protocol: HostProtocol::Telnet,
                icon: None,
            },
            settings: HostSettings::default(),
            port,
            username: user.into(),
            password: password.map(str::to_string),
            key: None,
            jumps: vec![],
            startup_script: None,
            proxy: None,
        }
    }

    /// Reads from the fake server until `want` has arrived (in order, maybe
    /// among other bytes); returns everything read.
    async fn read_until(s: &mut TcpStream, got: &mut Vec<u8>, want: &[u8]) {
        let mut buf = [0u8; 1024];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !got.windows(want.len()).any(|w| w == want) {
            let n = tokio::time::timeout_at(deadline, s.read(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for {want:?}; got {got:?}"))
                .unwrap();
            assert!(n > 0, "closed while waiting for {want:?}; got {got:?}");
            got.extend_from_slice(&buf[..n]);
        }
    }

    async fn output_until(rx: &mut broadcast::Receiver<Bytes>, seen: &mut Vec<u8>, want: &[u8]) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !seen.windows(want.len()).any(|w| w == want) {
            let b = tokio::time::timeout_at(deadline, rx.recv())
                .await
                .expect("timed out waiting for output")
                .unwrap();
            seen.extend_from_slice(&b);
        }
    }

    #[tokio::test]
    async fn negotiates_resizes_escapes_and_closes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let opts = TelnetOptions {
            term: "xterm-256color".into(),
            cols: 100,
            rows: 30,
            ..Default::default()
        };
        let t = target(port, "", None);
        let (session, accepted) = tokio::join!(
            TelnetSession::open(&t, opts, 1 << 16, None),
            listener.accept()
        );
        let session = session.unwrap();
        let (mut srv, _) = accepted.unwrap();
        let (_, mut out) = session.attach();

        // What the client offers first.
        let mut got = Vec::new();
        read_until(&mut srv, &mut got, &[IAC, DO, opt::SGA]).await;
        assert!(got.windows(3).any(|w| w == [IAC, WILL, opt::NAWS]));
        assert!(got.windows(3).any(|w| w == [IAC, WILL, opt::TERMINAL_TYPE]));

        // The server: accepts NAWS and TTYPE, asks for the type, echoes,
        // asks for something unknown (LINEMODE), and sends text with an
        // escaped 255 and a CR NUL.
        srv.write_all(&[
            IAC,
            DO,
            opt::NAWS,
            IAC,
            DO,
            opt::TERMINAL_TYPE,
            IAC,
            SB,
            opt::TERMINAL_TYPE,
            1,
            IAC,
            SE,
            IAC,
            WILL,
            opt::ECHO,
            IAC,
            DO,
            34,
        ])
        .await
        .unwrap();
        let mut got = Vec::new();
        read_until(
            &mut srv,
            &mut got,
            &[IAC, SB, opt::NAWS, 0, 100, 0, 30, IAC, SE],
        )
        .await;
        let mut ttype = vec![IAC, SB, opt::TERMINAL_TYPE, 0];
        ttype.extend_from_slice(b"xterm-256color");
        ttype.extend_from_slice(&[IAC, SE]);
        read_until(&mut srv, &mut got, &ttype).await;
        read_until(&mut srv, &mut got, &[IAC, WONT, 34]).await;
        // Our WILL ECHO answer would be a loop: never sent.
        assert!(!got.windows(3).any(|w| w == [IAC, DO, opt::ECHO]));

        srv.write_all(&[b'h', b'i', IAC, IAC, b'\r', 0, b'$', b' ', IAC, GA])
            .await
            .unwrap();
        let mut seen = Vec::new();
        output_until(&mut out, &mut seen, b"$ ").await;
        assert_eq!(seen, [b'h', b'i', 255, b'\r', b'$', b' ']);

        // Resize: a new NAWS. Input: IAC doubled, Enter as CR LF.
        session.resize(132, 43).await.unwrap();
        session.write(vec![b'a', 255, b'\r']).await.unwrap();
        let mut got = Vec::new();
        read_until(
            &mut srv,
            &mut got,
            &[IAC, SB, opt::NAWS, 0, 132, 0, 43, IAC, SE],
        )
        .await;
        read_until(&mut srv, &mut got, &[b'a', IAC, IAC, b'\r', b'\n']).await;

        // Latency: a timing mark, answered.
        let ping = {
            let s = session.clone();
            tokio::spawn(async move { s.latency(Duration::from_secs(5)).await })
        };
        let mut got = Vec::new();
        read_until(&mut srv, &mut got, &[IAC, DO, opt::TIMING_MARK]).await;
        srv.write_all(&[IAC, WILL, opt::TIMING_MARK]).await.unwrap();
        assert!(ping.await.unwrap().is_ok());

        // The server hangs up.
        drop(srv);
        let mut status = session.watch_status();
        tokio::time::timeout(Duration::from_secs(5), status.wait_for(|s| s.is_closed()))
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            session.status(),
            TermStatus::Closed { reason: Some(r), .. } if r.contains("closed by the host")
        ));
        assert!(session.write(b"x".to_vec()).await.is_err());
    }

    #[tokio::test]
    async fn logs_in_automatically_once() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let t = target(port, "admin", Some("s3cret"));
        let (session, accepted) = tokio::join!(
            TelnetSession::open(&t, TelnetOptions::default(), 1 << 16, None),
            listener.accept()
        );
        let session = session.unwrap();
        let (mut srv, _) = accepted.unwrap();
        srv.write_all(b"\r\nUser Access Verification\r\n\r\nUsername: ")
            .await
            .unwrap();
        let mut got = Vec::new();
        read_until(&mut srv, &mut got, b"admin\r\n").await;
        srv.write_all(b"Password: ").await.unwrap();
        read_until(&mut srv, &mut got, b"s3cret\r\n").await;
        // A second prompt is not answered: the user types.
        srv.write_all(b"\r\n% Login invalid\r\n\r\nUsername: ")
            .await
            .unwrap();
        session.write(b"me\r".to_vec()).await.unwrap();
        let mut more = Vec::new();
        read_until(&mut srv, &mut more, b"me\r\n").await;
        assert!(!more.windows(5).any(|w| w == b"admin"));
        session.close().await;
    }

    #[tokio::test]
    async fn refuses_jump_hosts_and_ssh_hosts() {
        let mut t = target(23, "", None);
        t.jumps.push(target(23, "", None));
        let e = TelnetSession::open(&t, TelnetOptions::default(), 4096, None)
            .await
            .unwrap_err();
        assert!(matches!(e, SshError::Unsupported(_)), "{e}");
        let mut t = target(23, "", None);
        t.host.protocol = HostProtocol::Ssh;
        assert!(matches!(
            TelnetSession::open(&t, TelnetOptions::default(), 4096, None).await,
            Err(SshError::Unsupported(_))
        ));
    }

    #[tokio::test]
    async fn latency_needs_a_telnet_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let t = target(port, "", None);
        let (session, accepted) = tokio::join!(
            TelnetSession::open(&t, TelnetOptions::default(), 4096, None),
            listener.accept()
        );
        let session = session.unwrap();
        let _srv = accepted.unwrap();
        // A raw TCP service that never sent a Telnet command.
        assert!(matches!(
            session.latency(Duration::from_secs(2)).await,
            Err(SshError::Unsupported(_))
        ));
    }
}

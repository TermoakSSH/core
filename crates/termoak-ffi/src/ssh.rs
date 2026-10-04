//! Local SSH engine: connections from the phone itself with terminals, SFTP,
//! tunnels and commands. No server needed.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use parking_lot::Mutex;
use termoak_client::{LOCAL_OWNER, Workspace};
use termoak_core::Id;
use termoak_core::model::{self as cm, SecretUpdate};
use termoak_ssh::forward::{ForwardHandle, ForwardSpec};
use termoak_ssh::{
    Connection, ExecOptions, FileEntry, FileKind, Sftp, TermStatus, TerminalSession,
};
use tokio::sync::broadcast::error::{RecvError, TryRecvError};

use crate::auth::{AuthHandler, FfiPrompter};
use crate::error::{Result, TermoakError};
use crate::models::{ForwardKind, parse_id};
use crate::runtime::{InRuntime, block_on, run, runtime, spawn_callback_thread};
use crate::vault::TermoakCore;

/// Maximum size of an output chunk delivered to `on_output`.
const MAX_OUTPUT_CHUNK: usize = 64 * 1024;
/// RIS sequence: resets the emulator (sent before replaying the history).
const FULL_RESET: &[u8] = b"\x1bc";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Details of an established SSH connection.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct ConnectionDetails {
    pub label: String,
    pub address: String,
    pub port: u32,
    pub username: String,
    pub server_key_type: Option<String>,
    pub server_fingerprint: Option<String>,
    /// The server's welcome banner, if it sent one.
    pub banner: Option<String>,
    /// Jumps traversed (labels), in order.
    pub via: Vec<String>,
}

/// State of a local terminal.
#[derive(Debug, Clone, PartialEq, uniffi::Enum)]
pub enum TerminalStatus {
    Running,
    Closed {
        exit_code: Option<u32>,
        reason: Option<String>,
    },
}

impl From<TermStatus> for TerminalStatus {
    fn from(s: TermStatus) -> Self {
        match s {
            TermStatus::Starting | TermStatus::Running => TerminalStatus::Running,
            TermStatus::Closed { exit_code, reason } => {
                TerminalStatus::Closed { exit_code, reason }
            }
        }
    }
}

/// Implemented by the app to receive what happens in a local terminal.
///
/// **Threads**: each terminal has its own background thread that calls these
/// methods in order, one at a time. They must return quickly: copy the data
/// and hop to the main thread (e.g. `DispatchQueue.main.async` or
/// `withContext(Dispatchers.Main)`).
#[uniffi::export(foreign)]
pub trait TerminalListener: Send + Sync {
    /// Terminal output (raw bytes, with ANSI sequences) for the emulator.
    /// The first delivery is the history. If the app falls too far behind,
    /// `ESC c` (reset) arrives followed by the full history.
    fn on_output(&self, data: Vec<u8>);

    /// State change. Nothing else arrives after `Closed`.
    fn on_status(&self, status: TerminalStatus);
}

/// Progress of an SFTP transfer.
///
/// **Threads**: called from a background thread after each chunk (256 KiB);
/// it must return quickly.
#[uniffi::export(foreign)]
pub trait TransferListener: Send + Sync {
    fn on_progress(&self, transferred: u64, total: Option<u64>);
}

/// Result of a non-interactive command.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct ExecResult {
    pub exit_code: Option<u32>,
    pub exit_signal: Option<String>,
    pub stdout: String,
    pub stderr: String,
    /// Output was discarded for exceeding the maximum (1 MiB per stream).
    pub truncated: bool,
    pub timed_out: bool,
    pub duration_ms: u64,
}

/// Type of a remote directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RemoteFileKind {
    Dir,
    File,
    Symlink,
    Other,
}

/// Remote directory entry.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct RemoteFile {
    pub name: String,
    pub path: String,
    pub kind: RemoteFileKind,
    pub size: u64,
    /// Unix permissions (e.g. 0o644), if the server provides them.
    pub mode: Option<u32>,
    /// Permissions as text (`drwxr-xr-x`).
    pub mode_string: String,
    /// Last modification (seconds since 1970).
    pub modified: Option<i64>,
    pub owner: Option<String>,
    pub group: Option<String>,
}

impl From<FileEntry> for RemoteFile {
    fn from(e: FileEntry) -> Self {
        Self {
            name: e.name,
            path: e.path,
            kind: match e.kind {
                FileKind::Dir => RemoteFileKind::Dir,
                FileKind::File => RemoteFileKind::File,
                FileKind::Symlink => RemoteFileKind::Symlink,
                FileKind::Other => RemoteFileKind::Other,
            },
            size: e.size,
            mode: e.mode,
            mode_string: e.mode_string,
            modified: e.modified,
            owner: e.owner.or_else(|| e.uid.map(|u| u.to_string())),
            group: e.group.or_else(|| e.gid.map(|g| g.to_string())),
        }
    }
}

/// Tunnel statistics.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct ForwardStats {
    pub active_connections: u64,
    pub total_connections: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

/// Local SSH connection to a host. Terminals, SFTP, tunnels and commands are
/// opened over it. It is closed with [`SshSession::disconnect`] or when all
/// its references are dropped (including terminals and tunnels).
#[derive(uniffi::Object)]
pub struct SshSession {
    host_id: Id,
    ws: Workspace,
    conn: InRuntime<Arc<Connection>>,
    sftp: tokio::sync::Mutex<Option<Arc<Sftp>>>,
}

impl Drop for SshSession {
    fn drop(&mut self) {
        if let Some(sftp) = self.sftp.get_mut().take() {
            let _guard = runtime().enter();
            drop(sftp);
        }
    }
}

impl SshSession {
    fn conn(&self) -> Arc<Connection> {
        Arc::clone(&self.conn)
    }

    async fn sftp(&self) -> Result<Arc<Sftp>> {
        let mut guard = self.sftp.lock().await;
        if let Some(s) = guard.as_ref() {
            return Ok(s.clone());
        }
        let s = Arc::new(self.conn.sftp().await?);
        *guard = Some(s.clone());
        Ok(s)
    }

    /// Runs `f` with the SFTP session (opened on first use) on the runtime.
    async fn with_sftp<T, F, Fut>(self: &Arc<Self>, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Sftp>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<T>> + Send,
    {
        let this = self.clone();
        run(async move {
            let sftp = this.sftp().await?;
            f(sftp).await
        })
        .await
    }
}

#[uniffi::export]
impl SshSession {
    /// Host it is connected to.
    pub fn host_id(&self) -> String {
        self.host_id.to_string()
    }

    pub fn details(&self) -> ConnectionDetails {
        let i = self.conn.info();
        ConnectionDetails {
            label: i.label.clone(),
            address: i.address.clone(),
            port: i.port.into(),
            username: i.username.clone(),
            server_key_type: i.server_key_type.clone(),
            server_fingerprint: i.server_fingerprint.clone(),
            banner: i.banner.clone(),
            via: i.via.clone(),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }

    /// Opens a terminal (PTY with a shell) with the host's effective settings
    /// (TERM, variables, startup snippet...). `record` forces recording
    /// (asciicast in `<data_dir>/recordings`).
    #[uniffi::method(default(record = false))]
    pub async fn open_terminal(
        self: Arc<Self>,
        cols: u32,
        rows: u32,
        listener: Arc<dyn TerminalListener>,
        record: bool,
    ) -> Result<Arc<TerminalHandle>> {
        run(async move {
            let term = self
                .ws
                .open_terminal(self.host_id, self.conn(), dim(cols), dim(rows), record)
                .await?;
            Ok(TerminalHandle::start(term, self, listener))
        })
        .await
    }

    /// Runs a non-interactive command and waits for it to finish.
    pub async fn exec(&self, command: String, timeout_secs: u32) -> Result<ExecResult> {
        let conn = self.conn();
        run(async move {
            let opts = ExecOptions {
                timeout: Duration::from_secs(u64::from(timeout_secs.max(1))),
                ..Default::default()
            };
            let out = conn.exec(&command, &opts).await?;
            Ok(ExecResult {
                exit_code: out.exit_code,
                exit_signal: out.exit_signal.clone(),
                stdout: out.stdout_text(),
                stderr: out.stderr_text(),
                truncated: out.truncated,
                timed_out: out.timed_out,
                duration_ms: out.duration_ms,
            })
        })
        .await
    }

    /// Detects the remote system (`ubuntu`, `debian`, `alpine`, `freebsd`,
    /// `macos`, `windows`...) and stores it in the host to show its icon.
    /// See [`detect_os_info`](Self::detect_os_info) for the version and the
    /// full name.
    pub async fn detect_os(&self) -> Result<Option<String>> {
        Ok(self.detect_os_info().await?.map(|i| i.id))
    }

    /// Detects the remote system with its version and display name
    /// (`Ubuntu 24.04.1 LTS`), like Termius does, and stores it in the host
    /// (`os` and `os_version`).
    pub async fn detect_os_info(&self) -> Result<Option<crate::assist::RemoteOs>> {
        let conn = self.conn();
        let store = self.ws.store.clone();
        let host_id = self.host_id;
        run(async move {
            let Some(info) = termoak_ssh::detect::detect_os_info(&conn).await else {
                return Ok(None);
            };
            let mut host = store.get::<cm::Host>(LOCAL_OWNER, host_id).await?.data;
            let display = info.display();
            if host.os.as_deref() != Some(info.id.as_str())
                || host.os_version.as_deref() != Some(display.as_str())
            {
                host.os = Some(info.id.clone());
                host.os_version = Some(display);
                store
                    .save(LOCAL_OWNER, host, SecretUpdate::Keep, None)
                    .await?;
            }
            Ok(Some(info.into()))
        })
        .await
    }

    // ----- SFTP -----

    /// The user's home directory.
    pub async fn sftp_home(self: Arc<Self>) -> Result<String> {
        self.with_sftp(|s| async move { Ok(s.home().await?) }).await
    }

    /// Lists a directory: folders first, then by name.
    pub async fn sftp_list(self: Arc<Self>, path: String) -> Result<Vec<RemoteFile>> {
        self.with_sftp(
            |s| async move { Ok(s.list(&path).await?.into_iter().map(Into::into).collect()) },
        )
        .await
    }

    pub async fn sftp_stat(self: Arc<Self>, path: String) -> Result<RemoteFile> {
        self.with_sftp(|s| async move { Ok(s.stat(&path).await?.into()) })
            .await
    }

    /// Reads a whole file into memory (for editors and viewers).
    pub async fn sftp_read(self: Arc<Self>, path: String, max_bytes: u64) -> Result<Vec<u8>> {
        self.with_sftp(move |s| async move { Ok(s.read(&path, max_bytes).await?) })
            .await
    }

    /// Writes (creates or overwrites) a file.
    pub async fn sftp_write(self: Arc<Self>, path: String, data: Vec<u8>) -> Result<()> {
        self.with_sftp(move |s| async move { Ok(s.write(&path, &data, None).await?) })
            .await
    }

    /// Downloads `remote_path` to `local_path` (a file on the device).
    /// Returns the bytes copied.
    pub async fn sftp_download(
        self: Arc<Self>,
        remote_path: String,
        local_path: String,
        listener: Option<Arc<dyn TransferListener>>,
    ) -> Result<u64> {
        self.with_sftp(move |s| async move {
            let total = s.stat(&remote_path).await.ok().map(|e| e.size);
            let file = tokio::fs::File::create(&local_path).await?;
            let progress = listener.map(|l| move |n: u64| l.on_progress(n, total));
            let res = s
                .download(
                    &remote_path,
                    file,
                    progress.as_ref().map(|p| p as &(dyn Fn(u64) + Send + Sync)),
                )
                .await;
            if res.is_err() {
                let _ = tokio::fs::remove_file(&local_path).await;
            }
            Ok(res?)
        })
        .await
    }

    /// Uploads `local_path` (a file on the device) to `remote_path`.
    /// Returns the bytes copied.
    pub async fn sftp_upload(
        self: Arc<Self>,
        local_path: String,
        remote_path: String,
        listener: Option<Arc<dyn TransferListener>>,
    ) -> Result<u64> {
        self.with_sftp(move |s| async move {
            let file = tokio::fs::File::open(&local_path).await?;
            let total = file.metadata().await.ok().map(|m| m.len());
            let progress = listener.map(|l| move |n: u64| l.on_progress(n, total));
            Ok(s.upload(
                file,
                &remote_path,
                progress.as_ref().map(|p| p as &(dyn Fn(u64) + Send + Sync)),
            )
            .await?)
        })
        .await
    }

    /// Creates a directory (with `recursive`, also any missing parents).
    pub async fn sftp_mkdir(self: Arc<Self>, path: String, recursive: bool) -> Result<()> {
        self.with_sftp(move |s| async move {
            if recursive {
                Ok(s.mkdir_all(&path).await?)
            } else {
                Ok(s.mkdir(&path).await?)
            }
        })
        .await
    }

    /// Renames or moves.
    pub async fn sftp_rename(self: Arc<Self>, from: String, to: String) -> Result<()> {
        self.with_sftp(move |s| async move { Ok(s.rename(&from, &to).await?) })
            .await
    }

    /// Deletes a file or a directory (with `recursive`, with its contents).
    pub async fn sftp_remove(self: Arc<Self>, path: String, recursive: bool) -> Result<()> {
        self.with_sftp(move |s| async move {
            match s.stat(&path).await?.kind {
                FileKind::Dir => Ok(s.remove_dir(&path, recursive).await?),
                _ => Ok(s.remove_file(&path).await?),
            }
        })
        .await
    }

    /// Changes the permissions (e.g. `0o644`).
    pub async fn sftp_chmod(self: Arc<Self>, path: String, mode: u32) -> Result<()> {
        self.with_sftp(move |s| async move { Ok(s.chmod(&path, mode).await?) })
            .await
    }

    // ----- Tunnels -----

    /// Starts a tunnel saved in the vault.
    pub async fn start_forward(&self, forward_id: String) -> Result<Arc<ActiveForward>> {
        let id = parse_id(&forward_id)?;
        let store = self.ws.store.clone();
        let conn = self.conn();
        run(async move {
            let fwd = store.get::<cm::PortForward>(LOCAL_OWNER, id).await?.data;
            start(conn, ForwardSpec::from(&fwd), fwd.label).await
        })
        .await
    }

    /// Starts an ad hoc tunnel (without saving it). `bind_port` 0 = free port.
    pub async fn start_forward_spec(
        &self,
        kind: ForwardKind,
        bind_address: String,
        bind_port: u32,
        dest_host: Option<String>,
        dest_port: Option<u32>,
    ) -> Result<Arc<ActiveForward>> {
        let conn = self.conn();
        let bind_port = u16::try_from(bind_port)
            .map_err(|_| TermoakError::Invalid("invalid bind port".into()))?;
        let dest_port = dest_port
            .map(u16::try_from)
            .transpose()
            .map_err(|_| TermoakError::Invalid("invalid destination port".into()))?;
        let bind_address = match bind_address.trim() {
            "" => "127.0.0.1".to_string(),
            a => a.to_string(),
        };
        run(async move {
            let spec = ForwardSpec {
                kind: kind.into(),
                bind_address,
                bind_port,
                dest_host,
                dest_port,
            };
            start(conn, spec, String::new()).await
        })
        .await
    }

    /// Starts the host's tunnels marked `auto_start`. Those that fail are
    /// skipped (and the error is logged).
    pub async fn start_auto_forwards(&self) -> Result<Vec<Arc<ActiveForward>>> {
        let store = self.ws.store.clone();
        let conn = self.conn();
        let host_id = self.host_id;
        run(async move {
            let mut out = Vec::new();
            for rec in store.list::<cm::PortForward>(LOCAL_OWNER).await? {
                let f = rec.data;
                if f.host_id != host_id || !f.auto_start {
                    continue;
                }
                match start(conn.clone(), ForwardSpec::from(&f), f.label.clone()).await {
                    Ok(h) => out.push(h),
                    Err(e) => {
                        tracing::warn!(forward = %f.label, error = %e, "auto-start tunnel failed")
                    }
                }
            }
            Ok(out)
        })
        .await
    }

    /// Closes the connection (and with it its terminals, SFTP and tunnels).
    pub async fn disconnect(&self) -> Result<()> {
        let conn = self.conn();
        run(async move {
            conn.disconnect().await;
            Ok(())
        })
        .await
    }
}

fn dim(v: u32) -> u16 {
    u16::try_from(v).unwrap_or(u16::MAX)
}

async fn start(
    conn: Arc<Connection>,
    spec: ForwardSpec,
    label: String,
) -> Result<Arc<ActiveForward>> {
    let kind = spec.kind.into();
    let handle = conn.start_forward(spec).await?;
    Ok(Arc::new(ActiveForward {
        label,
        kind,
        bound_port: handle.bound_port,
        handle: Mutex::new(Some(handle)),
    }))
}

// ---------------------------------------------------------------------------
// Terminal
// ---------------------------------------------------------------------------

/// Open local terminal. It is closed with [`TerminalHandle::close_terminal`]
/// or when dropped. The `TerminalListener` is retained until the terminal closes.
#[derive(uniffi::Object)]
pub struct TerminalHandle {
    term: InRuntime<Arc<TerminalSession>>,
    session: Arc<SshSession>,
}

impl Drop for TerminalHandle {
    fn drop(&mut self) {
        let term = Arc::clone(&self.term);
        runtime().spawn(async move { term.close().await });
    }
}

impl TerminalHandle {
    fn start(
        term: Arc<TerminalSession>,
        session: Arc<SshSession>,
        listener: Arc<dyn TerminalListener>,
    ) -> Arc<Self> {
        let pump_term = term.clone();
        spawn_callback_thread("termoak-terminal", move |rt| {
            pump_output(rt, pump_term, listener)
        });
        Arc::new(Self {
            term: InRuntime::new(term),
            session,
        })
    }

    pub(crate) fn session_arc(&self) -> Arc<TerminalSession> {
        Arc::clone(&self.term)
    }
}

/// Delivers a terminal's output and state changes to the app.
fn pump_output(
    rt: &tokio::runtime::Handle,
    term: Arc<TerminalSession>,
    listener: Arc<dyn TerminalListener>,
) {
    enum Ev {
        Out(std::result::Result<Bytes, RecvError>),
        Status,
    }
    let (snapshot, mut rx) = term.attach();
    let mut status = term.watch_status();
    let mut output_open = true;
    listener.on_status(TerminalStatus::Running);
    if !snapshot.is_empty() {
        listener.on_output(snapshot.to_vec());
    }
    loop {
        let ev = rt.block_on(async {
            tokio::select! {
                r = rx.recv(), if output_open => Ev::Out(r),
                _ = status.changed() => Ev::Status,
            }
        });
        if matches!(ev, Ev::Out(Err(RecvError::Closed))) {
            output_open = false;
        }
        match ev {
            Ev::Out(Ok(first)) => {
                let mut buf = first.to_vec();
                while buf.len() < MAX_OUTPUT_CHUNK {
                    match rx.try_recv() {
                        Ok(more) => buf.extend_from_slice(&more),
                        Err(_) => break,
                    }
                }
                listener.on_output(buf);
            }
            Ev::Out(Err(RecvError::Lagged(_))) => {
                // The app is lagging behind: emulator reset + full history.
                let (snapshot, new_rx) = term.attach();
                rx = new_rx;
                let mut buf = FULL_RESET.to_vec();
                buf.extend_from_slice(&snapshot);
                listener.on_output(buf);
            }
            Ev::Out(Err(RecvError::Closed)) | Ev::Status => {
                let current = term.status();
                // If the state sender went away without closing, nothing else will arrive.
                let gone = status.has_changed().is_err();
                if current.is_closed() || gone {
                    // Whatever is still pending, and the final state.
                    let mut buf = Vec::new();
                    loop {
                        match rx.try_recv() {
                            Ok(more) => buf.extend_from_slice(&more),
                            Err(TryRecvError::Lagged(_)) => continue,
                            Err(_) => break,
                        }
                    }
                    if !buf.is_empty() {
                        listener.on_output(buf);
                    }
                    let final_status = match current {
                        TermStatus::Closed { .. } => current.into(),
                        _ => TerminalStatus::Closed {
                            exit_code: None,
                            reason: Some("the terminal ended".into()),
                        },
                    };
                    listener.on_status(final_status);
                    break;
                }
            }
        }
    }
}

#[uniffi::export]
impl TerminalHandle {
    /// Sends typed input (raw bytes: UTF-8, key sequences...).
    pub fn write(&self, data: Vec<u8>) -> Result<()> {
        Ok(block_on(self.term.write(data))?)
    }

    /// Sends text (e.g. an already rendered snippet).
    pub fn write_text(&self, text: String) -> Result<()> {
        Ok(block_on(self.term.write(text.into_bytes()))?)
    }

    /// New size in columns and rows.
    pub fn resize(&self, cols: u32, rows: u32) -> Result<()> {
        Ok(block_on(self.term.resize(dim(cols), dim(rows)))?)
    }

    /// Closes the terminal (the connection stays open if anything else uses
    /// it). It is not called `close` because Kotlin objects already have
    /// `close()` (releasing them, which also closes the terminal).
    pub fn close_terminal(&self) {
        block_on(self.term.close());
    }

    pub fn status(&self) -> TerminalStatus {
        self.term.status().into()
    }

    /// Current history (up to 4 MiB) to redraw the screen.
    pub fn snapshot(&self) -> Vec<u8> {
        self.term.hub().snapshot().to_vec()
    }

    /// Last `max_chars` characters of the screen as plain text (no ANSI),
    /// e.g. to give the AI context.
    pub fn text_tail(&self, max_chars: u32) -> String {
        self.term.text_tail(max_chars as usize)
    }

    /// Path of the recording, if recording.
    pub fn recording_path(&self) -> Option<String> {
        self.term
            .recording_path()
            .map(|p| p.to_string_lossy().into_owned())
    }

    /// The terminal's connection (to open SFTP or tunnels over it).
    pub fn session(&self) -> Arc<SshSession> {
        self.session.clone()
    }
}

// ---------------------------------------------------------------------------
// Tunnels
// ---------------------------------------------------------------------------

/// Running tunnel. It is stopped with [`ActiveForward::stop`] or when dropped.
#[derive(uniffi::Object)]
pub struct ActiveForward {
    label: String,
    kind: ForwardKind,
    bound_port: u16,
    handle: Mutex<Option<ForwardHandle>>,
}

impl Drop for ActiveForward {
    fn drop(&mut self) {
        if let Some(h) = self.handle.get_mut().take() {
            let _guard = runtime().enter();
            drop(h);
        }
    }
}

#[uniffi::export]
impl ActiveForward {
    pub fn label(&self) -> String {
        self.label.clone()
    }

    pub fn kind(&self) -> ForwardKind {
        self.kind
    }

    /// Port actually listened on (useful if 0 was requested).
    pub fn bound_port(&self) -> u32 {
        self.bound_port.into()
    }

    pub fn is_running(&self) -> bool {
        self.handle.lock().is_some()
    }

    pub fn stats(&self) -> ForwardStats {
        let s = self
            .handle
            .lock()
            .as_ref()
            .map(|h| h.stats())
            .unwrap_or_default();
        ForwardStats {
            active_connections: s.active_connections,
            total_connections: s.total_connections,
            bytes_in: s.bytes_in,
            bytes_out: s.bytes_out,
        }
    }

    pub async fn stop(&self) -> Result<()> {
        let handle = self.handle.lock().take();
        run(async move {
            if let Some(h) = handle {
                h.stop().await;
            }
            Ok(())
        })
        .await
    }
}

// ---------------------------------------------------------------------------
// Connecting from the core
// ---------------------------------------------------------------------------

#[uniffi::export]
impl TermoakCore {
    /// Connects to a host over SSH from this device (through its jumps).
    /// `auth` answers the prompts (fingerprint, 2FA, password...).
    pub async fn connect(
        &self,
        host_id: String,
        auth: Arc<dyn AuthHandler>,
    ) -> Result<Arc<SshSession>> {
        let ws = self.ws.clone();
        run(async move { connect(ws, &host_id, auth).await }).await
    }

    /// Shortcut: connects and opens a terminal. The connection remains
    /// reachable with `TerminalHandle::session()` (e.g. to open SFTP without
    /// reconnecting).
    pub async fn connect_terminal(
        &self,
        host_id: String,
        cols: u32,
        rows: u32,
        auth: Arc<dyn AuthHandler>,
        listener: Arc<dyn TerminalListener>,
    ) -> Result<Arc<TerminalHandle>> {
        let ws = self.ws.clone();
        run(async move {
            let session = connect(ws, &host_id, auth).await?;
            let term = session
                .ws
                .open_terminal(session.host_id, session.conn(), dim(cols), dim(rows), false)
                .await?;
            Ok(TerminalHandle::start(term, session, listener))
        })
        .await
    }
}

async fn connect(
    ws: Workspace,
    host_id: &str,
    auth: Arc<dyn AuthHandler>,
) -> Result<Arc<SshSession>> {
    let host_id = parse_id(host_id)?;
    let prompter = Arc::new(FfiPrompter { handler: auth });
    let conn = ws.connect(host_id, prompter, false).await?;
    Ok(Arc::new(SshSession {
        host_id,
        ws,
        conn: InRuntime::new(conn),
        sftp: tokio::sync::Mutex::new(None),
    }))
}

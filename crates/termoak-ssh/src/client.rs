//! SSH connection: TCP or through jump hosts, host verification and authentication.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use russh::client::{self, Handle, KeyboardInteractiveAuthResponse, Msg, Session};
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{Channel, ChannelStream, Disconnect};
use serde::{Deserialize, Serialize};
use termoak_core::resolve::ResolvedHost;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::error::{Result, SshError};
use crate::forward::{self, ForwardStatsInner};
use crate::keys::{self, algorithm_name, fingerprint};
use crate::prompt::{AuthPrompter, NoPrompter, Prompt};
use crate::verify::HostKeyVerifier;

/// Connection options.
#[derive(Clone)]
pub struct ConnectOptions {
    pub verifier: Arc<dyn HostKeyVerifier>,
    pub prompter: Arc<dyn AuthPrompter>,
    pub connect_timeout: Duration,
    /// Try the keys of the local SSH agent (`SSH_AUTH_SOCK`, Pageant...).
    pub use_agent: bool,
}

impl ConnectOptions {
    pub fn new(verifier: Arc<dyn HostKeyVerifier>) -> Self {
        Self {
            verifier,
            prompter: Arc::new(NoPrompter),
            connect_timeout: Duration::from_secs(15),
            use_agent: false,
        }
    }

    pub fn with_prompter(mut self, prompter: Arc<dyn AuthPrompter>) -> Self {
        self.prompter = prompter;
        self
    }

    pub fn with_agent(mut self, use_agent: bool) -> Self {
        self.use_agent = use_agent;
        self
    }
}

/// Details of an established connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub label: String,
    pub address: String,
    pub port: u16,
    pub username: String,
    pub server_key_type: Option<String>,
    pub server_fingerprint: Option<String>,
    pub banner: Option<String>,
    /// Jump hosts traversed (labels), in order.
    pub via: Vec<String>,
}

#[derive(Default)]
struct HandlerState {
    rejection: Mutex<Option<SshError>>,
    server_key: Mutex<Option<(String, String)>>,
    banner: Mutex<Option<String>>,
}

/// Destination of a remote tunnel (`-R`).
#[derive(Clone)]
pub(crate) struct RemoteTarget {
    pub host: String,
    pub port: u16,
    pub stats: Arc<ForwardStatsInner>,
}

/// Active remote tunnels of a connection: (address, port) → local destination.
#[derive(Default)]
pub(crate) struct RemoteForwards {
    map: Mutex<HashMap<(String, u32), RemoteTarget>>,
}

impl RemoteForwards {
    pub(crate) fn insert(&self, address: &str, port: u32, target: RemoteTarget) {
        self.map.lock().insert((address.to_string(), port), target);
    }

    pub(crate) fn remove(&self, address: &str, port: u32) {
        self.map.lock().remove(&(address.to_string(), port));
    }

    fn lookup(&self, address: &str, port: u32) -> Option<RemoteTarget> {
        let map = self.map.lock();
        map.get(&(address.to_string(), port))
            .or_else(|| {
                // Some servers report a different address (e.g. "localhost").
                map.iter().find(|((_, p), _)| *p == port).map(|(_, t)| t)
            })
            .cloned()
    }
}

pub(crate) struct ClientHandler {
    host: String,
    port: u16,
    verifier: Arc<dyn HostKeyVerifier>,
    prompter: Arc<dyn AuthPrompter>,
    state: Arc<HandlerState>,
    forwards: Arc<RemoteForwards>,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = server_public_key.public_key();
        *self.state.server_key.lock() = Some((algorithm_name(&key), fingerprint(&key)));
        match self.verifier.verify(&self.host, self.port, &key).await {
            Ok(()) => Ok(true),
            Err(e) => {
                tracing::warn!(host = %self.host, port = self.port, error = %e, "host key rejected");
                *self.state.rejection.lock() = Some(e);
                Ok(false)
            }
        }
    }

    async fn auth_banner(
        &mut self,
        banner: &str,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        *self.state.banner.lock() = Some(banner.to_string());
        self.prompter.banner(&self.host, banner).await;
        Ok(())
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        match self.forwards.lookup(connected_address, connected_port) {
            Some(target) => {
                tracing::debug!(
                    from = %format!("{originator_address}:{originator_port}"),
                    to = %format!("{}:{}", target.host, target.port),
                    "incoming connection on remote tunnel"
                );
                reply.accept().await;
                tokio::spawn(forward::pipe_remote(channel, target));
            }
            None => {
                reply
                    .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
            }
        }
        Ok(())
    }
}

/// Authenticated SSH connection. Shared with `Arc`.
pub struct Connection {
    handle: Handle<ClientHandler>,
    info: ConnectionInfo,
    forwards: Arc<RemoteForwards>,
    /// Jump connections that must stay alive.
    _jumps: Vec<Arc<Connection>>,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("info", &self.info)
            .finish()
    }
}

impl Connection {
    /// Connects to the resolved host, going through its jump hosts if any.
    pub async fn connect(target: &ResolvedHost, opts: &ConnectOptions) -> Result<Arc<Connection>> {
        let hops: Vec<&ResolvedHost> = target.jumps.iter().chain(std::iter::once(target)).collect();
        // Proxy for the first connection: the first jump host's or, if it has
        // none, the final host's.
        let proxy = hops[0].proxy.as_ref().or(target.proxy.as_ref());
        let mut jumps: Vec<Arc<Connection>> = Vec::new();
        let last = hops.len() - 1;
        for (i, hop) in hops.into_iter().enumerate() {
            let mut conn = match jumps.last() {
                None => {
                    let tcp = match proxy {
                        Some(p) => {
                            crate::proxy::connect(
                                p,
                                &hop.host.address,
                                hop.port,
                                opts.connect_timeout,
                            )
                            .await?
                        }
                        None => {
                            tcp_connect(&hop.host.address, hop.port, opts.connect_timeout).await?
                        }
                    };
                    connect_stream(hop, opts, tcp).await?
                }
                Some(prev) => {
                    let stream = prev
                        .direct_tcpip(&hop.host.address, hop.port)
                        .await
                        .map_err(|e| SshError::Connect {
                            target: format!("{}:{}", hop.host.address, hop.port),
                            reason: format!("via {}: {e}", prev.info.label),
                        })?;
                    connect_stream(hop, opts, stream).await?
                }
            };
            conn.info.via = jumps.iter().map(|j| j.info.label.clone()).collect();
            if i == last {
                conn._jumps = jumps;
                return Ok(Arc::new(conn));
            }
            jumps.push(Arc::new(conn));
        }
        unreachable!("there is always at least one hop")
    }

    pub fn info(&self) -> &ConnectionInfo {
        &self.info
    }

    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    /// Opens a session channel (for exec, shell or subsystems).
    pub async fn open_session_channel(&self) -> Result<Channel<Msg>> {
        if self.is_closed() {
            return Err(SshError::Closed);
        }
        Ok(self.handle.channel_open_session().await?)
    }

    /// Opens a `direct-tcpip` channel to `host:port` from the server.
    pub async fn direct_tcpip(&self, host: &str, port: u16) -> Result<ChannelStream<Msg>> {
        if self.is_closed() {
            return Err(SshError::Closed);
        }
        let channel = self
            .handle
            .channel_open_direct_tcpip(host, port as u32, "127.0.0.1", 0)
            .await?;
        Ok(channel.into_stream())
    }

    /// Sends a keep-alive (useful to check whether the connection is still alive).
    pub async fn ping(&self) -> Result<()> {
        Ok(self.handle.send_keepalive(true).await?)
    }

    /// Round trip to the server (through the jump hosts, if any): the time it
    /// takes to answer a `keepalive@openssh.com` global request on this same
    /// connection. No channel is opened and the terminals are not disturbed.
    /// Most servers answer it with a failure, which counts as an answer too.
    /// The request waits behind whatever this connection is already sending,
    /// as typing does.
    pub async fn latency(&self, timeout: Duration) -> Result<Duration> {
        if self.is_closed() {
            return Err(SshError::Closed);
        }
        let started = std::time::Instant::now();
        tokio::time::timeout(timeout, self.handle.send_ping())
            .await
            .map_err(|_| SshError::Timeout(format!("waiting for {}", self.info.label)))??;
        let elapsed = started.elapsed();
        // The wait also ends when the connection drops (no answer is coming).
        if self.is_closed() {
            return Err(SshError::Closed);
        }
        Ok(elapsed)
    }

    pub async fn disconnect(&self) {
        let _ = self
            .handle
            .disconnect(Disconnect::ByApplication, "closed by the user", "en")
            .await;
    }

    pub(crate) fn handle(&self) -> &Handle<ClientHandler> {
        &self.handle
    }

    pub(crate) fn remote_forwards(&self) -> &Arc<RemoteForwards> {
        &self.forwards
    }
}

async fn tcp_connect(address: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let target = format!("{address}:{port}");
    let stream = tokio::time::timeout(timeout, TcpStream::connect((address, port)))
        .await
        .map_err(|_| SshError::Timeout(format!("connecting to {target}")))?
        .map_err(|e| SshError::Connect {
            target: target.clone(),
            reason: e.to_string(),
        })?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

async fn connect_stream<S>(
    hop: &ResolvedHost,
    opts: &ConnectOptions,
    stream: S,
) -> Result<Connection>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let keepalive = hop.settings.keepalive_secs.unwrap_or(30);
    let config = Arc::new(client::Config {
        client_id: russh::SshId::Standard(
            format!("SSH-2.0-Termoak_{}", env!("CARGO_PKG_VERSION")).into(),
        ),
        keepalive_interval: (keepalive > 0).then(|| Duration::from_secs(keepalive as u64)),
        keepalive_max: 3,
        nodelay: true,
        ..Default::default()
    });
    let state = Arc::new(HandlerState::default());
    let forwards = Arc::new(RemoteForwards::default());
    let handler = ClientHandler {
        host: hop.host.address.clone(),
        port: hop.port,
        verifier: opts.verifier.clone(),
        prompter: opts.prompter.clone(),
        state: state.clone(),
        forwards: forwards.clone(),
    };
    let target = format!("{}:{}", hop.host.address, hop.port);
    let handshake = tokio::time::timeout(
        opts.connect_timeout + Duration::from_secs(15),
        client::connect_stream(config, stream, handler),
    )
    .await
    .map_err(|_| SshError::Timeout(format!("negotiating SSH with {target}")))?;
    let mut handle = match handshake {
        Ok(h) => h,
        Err(e) => {
            if let Some(rejection) = state.rejection.lock().take() {
                return Err(rejection);
            }
            return Err(SshError::Connect {
                target,
                reason: e.to_string(),
            });
        }
    };

    authenticate(&mut handle, hop, opts).await?;

    let server_key = state.server_key.lock().clone();
    let banner = state.banner.lock().clone();
    Ok(Connection {
        handle,
        info: ConnectionInfo {
            label: hop.host.label.clone(),
            address: hop.host.address.clone(),
            port: hop.port,
            username: hop.username.clone(),
            server_key_type: server_key.as_ref().map(|(t, _)| t.clone()),
            server_fingerprint: server_key.map(|(_, f)| f),
            banner,
            via: Vec::new(),
        },
        forwards,
        _jumps: Vec::new(),
    })
}

/// Tries, in order: key, agent, password, keyboard-interactive and, if no
/// password is saved, asks the user.
async fn authenticate(
    handle: &mut Handle<ClientHandler>,
    hop: &ResolvedHost,
    opts: &ConnectOptions,
) -> Result<()> {
    let user = hop.username.clone();
    let host = hop.host.address.clone();
    let mut reasons: Vec<String> = Vec::new();

    if let Some(key) = &hop.key {
        let mut passphrase = key.passphrase.clone();
        if passphrase.is_none() && keys::is_encrypted(&key.private_key) {
            passphrase = opts.prompter.passphrase(&host, &key.label).await;
        }
        match keys::decode_private(&key.private_key, passphrase.as_deref()) {
            Ok(private) => {
                let private = Arc::new(private);
                let cert = key
                    .certificate
                    .as_deref()
                    .map(str::trim)
                    .filter(|c| !c.is_empty())
                    .map(russh::keys::Certificate::from_openssh);
                let result = match cert {
                    Some(Ok(cert)) => {
                        handle
                            .authenticate_openssh_cert(user.clone(), private, cert)
                            .await?
                    }
                    Some(Err(e)) => {
                        reasons.push(format!("invalid certificate: {e}"));
                        let hash = handle.best_supported_rsa_hash().await?.flatten();
                        handle
                            .authenticate_publickey(
                                user.clone(),
                                PrivateKeyWithHashAlg::new(private, hash),
                            )
                            .await?
                    }
                    None => {
                        let hash = handle.best_supported_rsa_hash().await?.flatten();
                        handle
                            .authenticate_publickey(
                                user.clone(),
                                PrivateKeyWithHashAlg::new(private, hash),
                            )
                            .await?
                    }
                };
                if result.success() {
                    return Ok(());
                }
                reasons.push(format!("key \"{}\" rejected", key.label));
            }
            Err(e) => reasons.push(format!("key \"{}\": {e}", key.label)),
        }
    }

    if opts.use_agent {
        match agent_auth(handle, &user).await {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(e) => reasons.push(format!("SSH agent: {e}")),
        }
    }

    if let Some(password) = &hop.password {
        if handle
            .authenticate_password(user.clone(), password.clone())
            .await?
            .success()
        {
            return Ok(());
        }
        reasons.push("password rejected".into());
    }

    if keyboard_interactive(handle, &user, &host, hop.password.as_deref(), opts).await? {
        return Ok(());
    }

    if hop.password.is_none()
        && let Some(password) = opts.prompter.password(&host, &user).await
    {
        if handle
            .authenticate_password(user.clone(), password)
            .await?
            .success()
        {
            return Ok(());
        }
        reasons.push("entered password rejected".into());
    }

    if reasons.is_empty() {
        reasons.push("no credentials configured (key or password)".into());
    }
    Err(SshError::Auth {
        user,
        host,
        reason: reasons.join("; "),
    })
}

async fn keyboard_interactive(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    host: &str,
    password: Option<&str>,
    opts: &ConnectOptions,
) -> Result<bool> {
    let mut response = handle
        .authenticate_keyboard_interactive_start(user.to_string(), None)
        .await?;
    let mut password_used = false;
    for _ in 0..16 {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                let answers = if prompts.is_empty() {
                    Vec::new()
                } else if prompts.len() == 1
                    && !prompts[0].echo
                    && prompts[0].prompt.to_lowercase().contains("password")
                    && password.is_some()
                    && !password_used
                {
                    password_used = true;
                    vec![password.unwrap_or_default().to_string()]
                } else {
                    let converted: Vec<Prompt> = prompts
                        .iter()
                        .map(|p| Prompt {
                            text: p.prompt.clone(),
                            echo: p.echo,
                        })
                        .collect();
                    match opts
                        .prompter
                        .keyboard_interactive(host, &name, &instructions, &converted)
                        .await
                    {
                        Some(a) if a.len() == prompts.len() => a,
                        _ => return Ok(false),
                    }
                };
                response = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await?;
            }
        }
    }
    Ok(false)
}

#[cfg(unix)]
async fn agent_auth(handle: &mut Handle<ClientHandler>, user: &str) -> Result<bool> {
    let mut agent = match russh::keys::agent::client::AgentClient::connect_env().await {
        Ok(a) => a,
        Err(_) => return Ok(false),
    };
    try_agent_identities(handle, user, &mut agent).await
}

#[cfg(windows)]
async fn agent_auth(handle: &mut Handle<ClientHandler>, user: &str) -> Result<bool> {
    if let Ok(mut agent) =
        russh::keys::agent::client::AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent")
            .await
        && try_agent_identities(handle, user, &mut agent).await?
    {
        return Ok(true);
    }
    match russh::keys::agent::client::AgentClient::connect_pageant().await {
        Ok(mut agent) => try_agent_identities(handle, user, &mut agent).await,
        Err(_) => Ok(false),
    }
}

#[cfg(not(any(unix, windows)))]
async fn agent_auth(_handle: &mut Handle<ClientHandler>, _user: &str) -> Result<bool> {
    Ok(false)
}

#[cfg(any(unix, windows))]
async fn try_agent_identities<S>(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    agent: &mut russh::keys::agent::client::AgentClient<S>,
) -> Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let identities = agent.request_identities().await.unwrap_or_default();
    for identity in identities {
        let key = identity.public_key().into_owned();
        let hash = handle.best_supported_rsa_hash().await?.flatten();
        if let Ok(result) = handle
            .authenticate_publickey_with(user.to_string(), key, hash, agent)
            .await
            && result.success()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

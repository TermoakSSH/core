//! Termoak SSH engine (and the Telnet terminal, [`telnet`]).
//!
//! Shared by the server (persistent sessions and the AI), the desktop app, the
//! CLI and the mobile apps. Built on `russh`, pure-Rust SSH with no OpenSSH
//! dependency.

pub mod ansi;
pub mod client;
pub mod detect;
pub mod error;
pub mod exec;
pub mod forward;
pub mod keys;
pub mod pool;
pub mod prompt;
mod proxy;
pub mod recording;
pub mod sftp;
pub mod sshconfig;
pub mod telnet;
pub mod terminal;
pub mod verify;

pub use client::{ConnectOptions, Connection, ConnectionInfo};
pub use error::{Result, SshError};
pub use exec::{ExecOptions, ExecOutput};
pub use forward::{ForwardHandle, ForwardSpec, ForwardStats};
pub use pool::ConnectionPool;
pub use prompt::{AuthPrompter, NoPrompter};
pub use sftp::{FileEntry, FileKind, Sftp};
pub use telnet::{TelnetInfo, TelnetOptions, TelnetSession};
pub use terminal::{PtyOptions, TermStatus, Terminal, TerminalSession};
pub use verify::{AcceptAll, HostKeyPolicy, HostKeyVerifier, KnownHostScope, StoreVerifier};

/// Re-export of the public key type.
pub use russh::keys::PublicKey;

//! Termoak FFI layer for the mobile apps (iOS with SwiftUI and Android with
//! Jetpack Compose), generated with
//! [UniFFI](https://mozilla.github.io/uniffi-rs/) through macros.
//!
//! The apps embed the same engine as the desktop app and the CLI:
//! - [`TermoakCore`]: encrypted local vault (hosts, groups, identities, keys,
//!   snippets, tunnels, known hosts), server account (login, sync, generic
//!   API, persistent sessions, AI) and local SSH connections.
//! - [`SshSession`]: local SSH connection with terminals, SFTP, tunnels and
//!   commands.
//! - [`ServerTerminalHandle`]: terminal that lives on the server (it stays
//!   alive even if the phone disconnects).
//! - [`TerminalScreen`]: terminal emulator (the desktop one) that turns the
//!   output into a screen ready to draw.
//! - Account: two-factor authentication, teams, invitations and user
//!   administration; `ssh_config` import and command autocompletion.
//! - Several accounts (servers) on one device ([`AccountHandle`],
//!   `sign_in`, `accounts`, `set_account_view`), vaults (`vaults`,
//!   `AccountHandle::create_vault`...) and moving items between This device,
//!   vaults and accounts (`transfer`).
//!
//! Threads: the library has its own tokio runtime. Synchronous functions can
//! be called from any thread (they are fast); `async` ones show up as
//! `async throws` in Swift and `suspend` in Kotlin. Callbacks
//! (`TerminalListener`, `AuthHandler`...) arrive on background threads: the
//! app must hop to the main thread to touch the UI. See `docs/MOBILE.md`.

uniffi::setup_scaffolding!();

mod account;
mod accounts;
mod assist;
mod auth;
mod error;
mod files;
mod logging;
mod models;
mod remote;
mod runtime;
mod screen;
mod server;
mod ssh;
mod vault;

pub use account::*;
pub use accounts::*;
pub use assist::*;
pub use auth::{AuthHandler, AuthPromptKind, AuthRequest, PromptField};
pub use error::{Result, TermoakError};
pub use logging::{LogLevel, LogListener, init_logging};
pub use models::*;
pub use remote::{
    EventSubscription, LinkInvite, ServerEventListener, ServerTerminalEvent, ServerTerminalHandle,
    ServerTerminalListener, ShareInvite, SharedTerminal, SharedTerminalEvent,
    SharedTerminalListener, join_shared_session, join_shared_session_as, link_invite_info,
};
pub use screen::{
    KeyModifiers, ScreenCursor, ScreenCursorShape, ScreenEvent, ScreenLine, ScreenRun,
    ScreenSnapshot, TerminalKey, TerminalScreen,
};
pub use server::*;
pub use ssh::{
    ActiveForward, ConnectionDetails, ExecResult, ForwardStats, RemoteFile, RemoteFileKind,
    SshSession, TerminalHandle, TerminalListener, TerminalStatus, TransferListener,
};
pub use vault::{
    TermoakCore, generate_vault_key, inspect_private_key, library_version, render_snippet,
    snippet_variables,
};

#[cfg(test)]
mod tests;

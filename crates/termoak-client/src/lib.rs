//! Termoak client.
//!
//! What the desktop app, the CLI and the mobile apps share:
//! - [`api::ApiClient`]: the server API, with automatic token refresh.
//! - [`sync::SyncEngine`]: syncs hosts, keys, snippets... between the local
//!   database and the server.
//! - [`remote`]: terminals that live on the server (WebSocket).
//! - [`relay`]: sharing a local terminal through the server.
//! - [`vault`]: the local vault key (system keyring or file).
//! - [`workspace::Workspace`]: the device store, one store per signed-in
//!   account ([`accounts`]), the local SSH engine; [`items`] work across
//!   those stores.
//! - [`servers`]: the official server and canonical server URLs.
//! - [`layout`]: the one-time migration of 0.3 data to one store per account.
//! - Shared app logic without UI (moved from the desktop so every app
//!   behaves the same): [`find`] in a terminal, [`command_watch`] and
//!   [`ai_assist`] (AI in the terminal).

pub mod accounts;
pub mod ai_assist;
pub mod api;
pub mod command_watch;
pub mod complete;
pub mod error;
pub mod events;
pub mod find;
pub mod import;
pub mod items;
pub mod layout;
pub mod line;
pub mod qr;
pub mod relay;
pub mod remote;
pub mod servers;
pub mod sync;
pub mod vault;
pub mod workspace;

pub use accounts::{Account, AccountInfo, AccountStatus, SignOutReport};
pub use api::ApiClient;
pub use error::{ClientError, Result};
pub use items::{ItemAccess, ItemFilter, ItemRef, LocalTransfer, SaveTarget, Scope, Scoped};
pub use servers::{OFFICIAL_SERVER, ServerChoice};
pub use sync::{SyncEngine, SyncReport};
pub use workspace::{AccountView, Workspace};

/// Owner of the records in every local store (device and account stores).
pub const LOCAL_OWNER: termoak_core::Id = uuid::Uuid::nil();

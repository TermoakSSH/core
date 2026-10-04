//! Termoak client.
//!
//! What the desktop app, the CLI and the mobile apps share:
//! - [`api::ApiClient`]: the server API, with automatic token refresh.
//! - [`sync::SyncEngine`]: syncs hosts, keys, snippets... between the local
//!   database and the server.
//! - [`remote`]: terminals that live on the server (WebSocket).
//! - [`relay`]: sharing a local terminal through the server.
//! - [`vault`]: the local vault key (system keyring or file).
//! - [`workspace::Workspace`]: local database + local SSH engine.

pub mod api;
pub mod complete;
pub mod error;
pub mod import;
pub mod line;
pub mod qr;
pub mod relay;
pub mod remote;
pub mod sync;
pub mod vault;
pub mod workspace;

pub use api::ApiClient;
pub use error::{ClientError, Result};
pub use sync::SyncEngine;
pub use workspace::Workspace;

/// Owner of the records in the local database (a single user per device).
pub const LOCAL_OWNER: termoak_core::Id = uuid::Uuid::nil();

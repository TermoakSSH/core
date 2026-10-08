//! Termoak core: data models, SQLite storage, encrypted vault and host
//! settings resolution. Shared by the server, the CLI, the desktop app and
//! the mobile apps (through FFI).

pub mod crypto;
pub mod error;
pub mod model;
pub mod qr;
pub mod redact;
pub mod resolve;
pub mod store;
pub mod time;
pub mod totp;
pub mod transfer;

pub use error::{CoreError, Result};
pub use model::*;
pub use store::Store;

/// Identifier of any record (UUID v7, sortable by date).
pub type Id = uuid::Uuid;

/// Generates a new identifier.
pub fn new_id() -> Id {
    uuid::Uuid::now_v7()
}

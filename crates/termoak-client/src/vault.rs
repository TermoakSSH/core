//! Local vault key and data paths.
//!
//! The key that encrypts local secrets is stored in the system keyring
//! (macOS Keychain, Windows Credential Manager, Secret Service on Linux).
//! If no keyring is available (e.g. a server without a graphical session),
//! it is stored in a file with 0600 permissions and a warning is logged.
//! On iOS and Android the app manages the key (Keychain/Keystore) and passes
//! it over FFI.

use std::path::{Path, PathBuf};

use termoak_core::crypto::MasterKey;

use crate::error::{ClientError, Result};

#[cfg(feature = "os-keyring")]
const SERVICE: &str = "Termoak";
#[cfg(feature = "os-keyring")]
const ACCOUNT: &str = "vault-key";
/// Keyring service used before the rename to Termoak.
#[cfg(feature = "os-keyring")]
const LEGACY_SERVICE: &str = "AceitunoakSSH";

/// App data directory (`TERMOAK_HOME` or the platform default).
pub fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("TERMOAK_HOME")
        && !dir.is_empty()
    {
        return PathBuf::from(dir);
    }
    let Some(dirs) = directories::ProjectDirs::from("com", "termoak", "Termoak") else {
        return PathBuf::from(".termoak");
    };
    let dir = dirs.data_dir().to_path_buf();
    migrate_legacy_dir(&dir).unwrap_or(dir)
}

/// Moves the data left by AceitunoakSSH (the project's former name) to `dir`
/// the first time. If the move fails (e.g. the old app is still running), it
/// returns the old directory so the data is not lost from view.
fn migrate_legacy_dir(dir: &Path) -> Option<PathBuf> {
    if dir.exists() {
        return None;
    }
    let old = directories::ProjectDirs::from("es", "ohz", "AceitunoakSSH")?
        .data_dir()
        .to_path_buf();
    if !old.is_dir() {
        return None;
    }
    if let Some(parent) = dir.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::rename(&old, dir) {
        Ok(()) => {
            tracing::info!(from = %old.display(), to = %dir.display(), "data moved to the new folder");
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, dir = %old.display(), "could not move the old data folder; using it in place");
            Some(old)
        }
    }
}

/// Loads (or creates) the local vault key.
pub fn load_or_create_key(dir: &Path) -> Result<MasterKey> {
    if let Ok(v) = std::env::var("TERMOAK_VAULT_KEY")
        && !v.trim().is_empty()
    {
        return Ok(MasterKey::from_base64(&v)?);
    }
    #[cfg(feature = "os-keyring")]
    {
        match keyring_key() {
            Ok(k) => return Ok(k),
            Err(e) => {
                tracing::warn!(error = %e, "system keyring unavailable; using a protected file")
            }
        }
    }
    let path = dir.join("vault.key");
    MasterKey::load_or_create(&path).map_err(ClientError::from)
}

#[cfg(feature = "os-keyring")]
fn keyring_key() -> Result<MasterKey> {
    let entry = keyring::Entry::new(SERVICE, ACCOUNT)
        .map_err(|e| ClientError::Invalid(format!("keyring: {e}")))?;
    match entry.get_password() {
        Ok(v) => Ok(MasterKey::from_base64(&v)?),
        Err(keyring::Error::NoEntry) => {
            let key = match legacy_keyring_key() {
                Some(key) => key,
                None => MasterKey::generate(),
            };
            entry
                .set_password(&key.to_base64())
                .map_err(|e| ClientError::Invalid(format!("keyring: {e}")))?;
            // Check that it was really saved (some environments ignore it).
            let back = entry
                .get_password()
                .map_err(|e| ClientError::Invalid(format!("keyring: {e}")))?;
            if back != *key.to_base64() {
                return Err(ClientError::Invalid(
                    "the keyring does not keep the key".into(),
                ));
            }
            Ok(key)
        }
        Err(e) => Err(ClientError::Invalid(format!("keyring: {e}"))),
    }
}

/// Key saved by AceitunoakSSH, if any. It is copied to the new service and the
/// old entry is left untouched.
#[cfg(feature = "os-keyring")]
fn legacy_keyring_key() -> Option<MasterKey> {
    let entry = keyring::Entry::new(LEGACY_SERVICE, ACCOUNT).ok()?;
    let value = entry.get_password().ok()?;
    MasterKey::from_base64(&value).ok()
}

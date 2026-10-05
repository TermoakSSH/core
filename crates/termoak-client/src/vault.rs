//! Local vault key and data paths.
//!
//! The key that encrypts local secrets is stored in the system keyring
//! (macOS Keychain, Windows Credential Manager, Secret Service on Linux).
//! If no keyring is available (e.g. a server without a graphical session),
//! it is stored in a `vault.key` file with 0600 permissions and a warning is
//! logged. On iOS and Android the app manages the key (Keychain/Keystore)
//! and passes it over FFI.
//!
//! Rules about when the keyring is touched and what happens when it fails
//! ([`load_key`]):
//!
//! - When the item exists, the keyring is read exactly once per process
//!   ([`load_or_create_key`] keeps the key it got).
//! - The item of AceitunoakSSH (the former name) is only read when the new
//!   item is missing and there is already a database to open with it, so a
//!   fresh install never asks for it.
//! - If the item is missing but a `vault.key` file exists (the keyring was
//!   not available before), that file is the key of the database: it is
//!   used, and copied to the keyring for the next launches.
//! - If the keyring refuses (access denied, locked, no Secret Service...)
//!   and there is already a database without a `vault.key` file, opening
//!   fails with [`ClientError::KeychainUnavailable`] instead of inventing a
//!   new key: a new key would make every saved password and key unreadable.
//!   Apps show it with a "Try again" button.

use std::path::{Path, PathBuf};

use termoak_core::crypto::{MasterKey, write_private_file};

use crate::error::{ClientError, Result};

/// Keyring item of the vault key.
pub const SERVICE: &str = "Termoak";
pub const ACCOUNT: &str = "vault-key";
/// Keyring service used before the rename to Termoak.
pub const LEGACY_SERVICE: &str = "AceitunoakSSH";
/// Key file used when there is no keyring.
pub const KEY_FILE: &str = "vault.key";
/// Databases that can already exist in the data directory (the second one
/// is renamed to the first when opened).
const DATABASES: [&str; 2] = ["termoak.db", "aceitunoak.db"];

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

/// Loads (or creates) the local vault key: `TERMOAK_VAULT_KEY`, then the
/// system keyring (see [`load_key`]) or, without the `os-keyring` feature,
/// the `vault.key` file. The key is kept for the rest of the process, so the
/// keyring is read once; a failure is not kept, so calling it again (a "Try
/// again" button) reads the keyring again.
pub fn load_or_create_key(dir: &Path) -> Result<MasterKey> {
    if let Ok(v) = std::env::var("TERMOAK_VAULT_KEY")
        && !v.trim().is_empty()
    {
        return Ok(MasterKey::from_base64(&v)?);
    }
    #[cfg(feature = "os-keyring")]
    {
        static LOADED: std::sync::Mutex<Option<(PathBuf, MasterKey)>> = std::sync::Mutex::new(None);
        let mut loaded = LOADED.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((d, key)) = loaded.as_ref()
            && d == dir
        {
            return Ok(key.clone());
        }
        let key = load_key(dir, &SystemKeychain)?;
        *loaded = Some((dir.to_path_buf(), key.clone()));
        Ok(key)
    }
    #[cfg(not(feature = "os-keyring"))]
    {
        MasterKey::load_or_create(&dir.join(KEY_FILE)).map_err(ClientError::from)
    }
}

/// Result of reading the keyring item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// The item exists (base64 key).
    Found(String),
    /// There is no item.
    Missing,
    /// The keyring did not answer: access denied, locked, no service...
    Failed(String),
}

/// What is on disk in the data directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disk {
    /// There is a `vault.key` file.
    pub key_file: bool,
    /// There is a database (with secrets sealed with some key).
    pub database: bool,
}

impl Disk {
    pub fn of(dir: &Path) -> Self {
        Disk {
            key_file: dir.join(KEY_FILE).exists(),
            database: DATABASES.iter().any(|db| dir.join(db).exists()),
        }
    }
}

/// What to do after reading the keyring item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    /// Use the key from the keyring.
    UseKeychain,
    /// Use `vault.key` and copy it to the keyring.
    UseFileAndStore,
    /// Look for the AceitunoakSSH item; otherwise generate a key. Then store it.
    TryLegacyThenGenerate,
    /// New key, stored in the keyring.
    GenerateAndStore,
    /// The keyring failed: use `vault.key`.
    UseFile,
    /// The keyring failed and there is no data yet: new key in `vault.key`.
    CreateFile,
    /// The keyring failed and the database needs the key that is in it.
    Refuse,
}

/// Decides how to get the key (pure: no keyring nor disk access).
pub fn plan(lookup: &Lookup, disk: Disk) -> Plan {
    match lookup {
        Lookup::Found(_) => Plan::UseKeychain,
        Lookup::Missing if disk.key_file => Plan::UseFileAndStore,
        Lookup::Missing if disk.database => Plan::TryLegacyThenGenerate,
        Lookup::Missing => Plan::GenerateAndStore,
        Lookup::Failed(_) if disk.key_file => Plan::UseFile,
        Lookup::Failed(_) if !disk.database => Plan::CreateFile,
        Lookup::Failed(_) => Plan::Refuse,
    }
}

/// Access to the keyring (the system one, or a fake in the tests).
pub trait Secrets {
    fn read(&self, service: &str) -> Lookup;
    fn write(&self, service: &str, value: &str) -> std::result::Result<(), String>;
}

/// The system keyring, through the `keyring` crate. Some backends block:
/// do not use it from a UI thread nor inside a tokio task.
#[cfg(feature = "os-keyring")]
pub struct SystemKeychain;

#[cfg(feature = "os-keyring")]
impl Secrets for SystemKeychain {
    fn read(&self, service: &str) -> Lookup {
        let entry = match keyring::Entry::new(service, ACCOUNT) {
            Ok(e) => e,
            Err(e) => return Lookup::Failed(e.to_string()),
        };
        match entry.get_password() {
            Ok(v) => Lookup::Found(v),
            Err(keyring::Error::NoEntry) => Lookup::Missing,
            Err(e) => Lookup::Failed(e.to_string()),
        }
    }

    fn write(&self, service: &str, value: &str) -> std::result::Result<(), String> {
        keyring::Entry::new(service, ACCOUNT)
            .and_then(|e| e.set_password(value))
            .map_err(|e| e.to_string())
    }
}

/// Gets (or creates) the vault key for the data directory `dir` with the
/// keyring `secrets`. The keyring item is read once (twice only when a new
/// key is stored, to check that it was kept).
///
/// Fails with [`ClientError::KeychainUnavailable`] when the keyring refuses
/// and the existing database needs the key that is in it, or when the item
/// is damaged (it is never replaced).
pub fn load_key(dir: &Path, secrets: &dyn Secrets) -> Result<MasterKey> {
    let key_file = dir.join(KEY_FILE);
    let lookup = secrets.read(SERVICE);
    let file_key = || MasterKey::load_or_create(&key_file).map_err(ClientError::from);
    match (plan(&lookup, Disk::of(dir)), lookup) {
        (Plan::UseKeychain, Lookup::Found(value)) => {
            // A damaged item is not replaced: the database needs the key.
            MasterKey::from_base64(&value).map_err(|e| {
                ClientError::KeychainUnavailable(format!("the saved vault key is damaged: {e}"))
            })
        }
        (Plan::UseFileAndStore, _) => {
            let key = file_key()?;
            // The file stays: it is the key the database was sealed with.
            if let Err(e) = store(secrets, &key) {
                tracing::warn!(error = %e, "could not copy vault.key to the keyring");
            }
            Ok(key)
        }
        (Plan::TryLegacyThenGenerate, _) => {
            let legacy = match secrets.read(LEGACY_SERVICE) {
                Lookup::Found(v) => MasterKey::from_base64(&v).ok(),
                _ => None,
            };
            if legacy.is_none() {
                tracing::warn!("there is a database but no vault key anywhere; creating a new key");
            }
            persist(
                secrets,
                legacy.unwrap_or_else(MasterKey::generate),
                &key_file,
            )
        }
        (Plan::GenerateAndStore, _) => persist(secrets, MasterKey::generate(), &key_file),
        (Plan::UseFile, _) => {
            tracing::warn!("system keyring unavailable; using vault.key");
            file_key()
        }
        (Plan::CreateFile, lookup) => {
            if let Lookup::Failed(e) = lookup {
                tracing::warn!(error = %e, "system keyring unavailable; using a protected file");
            }
            file_key()
        }
        (Plan::Refuse, Lookup::Failed(error)) => Err(ClientError::KeychainUnavailable(error)),
        (plan, lookup) => unreachable!("{plan:?} does not come from {lookup:?}"),
    }
}

/// Saves the key in the keyring and checks that it was really kept (some
/// environments ignore it).
fn store(secrets: &dyn Secrets, key: &MasterKey) -> std::result::Result<(), String> {
    let value = key.to_base64();
    secrets.write(SERVICE, &value)?;
    match secrets.read(SERVICE) {
        Lookup::Found(back) if back == *value => Ok(()),
        Lookup::Found(_) | Lookup::Missing => Err("the keyring does not keep the key".into()),
        Lookup::Failed(e) => Err(e),
    }
}

/// Keeps a new key: in the keyring or, if it does not keep it, in
/// `vault.key` (so the next launch finds the same key).
fn persist(secrets: &dyn Secrets, key: MasterKey, key_file: &Path) -> Result<MasterKey> {
    if let Err(e) = store(secrets, &key) {
        tracing::warn!(error = %e, "system keyring unavailable; using a protected file");
        if let Some(parent) = key_file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_private_file(key_file, key.to_base64().as_bytes())?;
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use super::*;

    fn disk(key_file: bool, database: bool) -> Disk {
        Disk { key_file, database }
    }

    #[test]
    fn plans() {
        let found = Lookup::Found("k".into());
        let failed = Lookup::Failed("denied".into());
        for d in [
            disk(false, false),
            disk(true, true),
            disk(true, false),
            disk(false, true),
        ] {
            assert_eq!(plan(&found, d), Plan::UseKeychain);
        }
        let missing = Lookup::Missing;
        assert_eq!(plan(&missing, disk(true, true)), Plan::UseFileAndStore);
        assert_eq!(plan(&missing, disk(true, false)), Plan::UseFileAndStore);
        assert_eq!(
            plan(&missing, disk(false, true)),
            Plan::TryLegacyThenGenerate
        );
        assert_eq!(plan(&missing, disk(false, false)), Plan::GenerateAndStore);
        assert_eq!(plan(&failed, disk(true, true)), Plan::UseFile);
        assert_eq!(plan(&failed, disk(true, false)), Plan::UseFile);
        assert_eq!(plan(&failed, disk(false, false)), Plan::CreateFile);
        assert_eq!(plan(&failed, disk(false, true)), Plan::Refuse);
    }

    /// Keyring in memory that counts the reads of each service.
    #[derive(Default)]
    struct Fake {
        items: RefCell<HashMap<String, String>>,
        reads: RefCell<HashMap<String, usize>>,
        fail: Option<String>,
        /// Accepts writes but forgets them.
        forgetful: bool,
    }

    impl Fake {
        fn with(items: &[(&str, &str)]) -> Self {
            let fake = Self::default();
            for (s, v) in items {
                fake.items.borrow_mut().insert(s.to_string(), v.to_string());
            }
            fake
        }

        fn failing(error: &str) -> Self {
            Self {
                fail: Some(error.into()),
                ..Self::default()
            }
        }

        fn reads(&self, service: &str) -> usize {
            self.reads.borrow().get(service).copied().unwrap_or(0)
        }

        fn item(&self, service: &str) -> Option<String> {
            self.items.borrow().get(service).cloned()
        }
    }

    impl Secrets for Fake {
        fn read(&self, service: &str) -> Lookup {
            *self.reads.borrow_mut().entry(service.into()).or_default() += 1;
            if let Some(e) = &self.fail {
                return Lookup::Failed(e.clone());
            }
            match self.items.borrow().get(service) {
                Some(v) => Lookup::Found(v.clone()),
                None => Lookup::Missing,
            }
        }

        fn write(&self, service: &str, value: &str) -> std::result::Result<(), String> {
            if let Some(e) = &self.fail {
                return Err(e.clone());
            }
            if !self.forgetful {
                self.items.borrow_mut().insert(service.into(), value.into());
            }
            Ok(())
        }
    }

    fn touch(dir: &tempfile::TempDir, name: &str, content: &str) {
        std::fs::write(dir.path().join(name), content).unwrap();
    }

    fn b64(key: &MasterKey) -> String {
        key.to_base64().to_string()
    }

    #[test]
    fn existing_item_is_read_once() {
        let dir = tempfile::tempdir().unwrap();
        touch(&dir, "termoak.db", "");
        let key = MasterKey::generate();
        let fake = Fake::with(&[(SERVICE, &b64(&key)), (LEGACY_SERVICE, "x")]);
        let got = load_key(dir.path(), &fake).unwrap();
        assert_eq!(b64(&got), b64(&key));
        assert_eq!(fake.reads(SERVICE), 1);
        assert_eq!(fake.reads(LEGACY_SERVICE), 0);
        assert!(!dir.path().join(KEY_FILE).exists());
    }

    #[test]
    fn damaged_item_is_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        touch(&dir, "termoak.db", "");
        let fake = Fake::with(&[(SERVICE, "not a key")]);
        let err = load_key(dir.path(), &fake).unwrap_err();
        assert!(matches!(err, ClientError::KeychainUnavailable(_)), "{err}");
        assert_eq!(fake.item(SERVICE).as_deref(), Some("not a key"));
        assert!(!dir.path().join(KEY_FILE).exists());
    }

    #[test]
    fn fresh_install_never_reads_the_legacy_item() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = MasterKey::generate();
        let fake = Fake::with(&[(LEGACY_SERVICE, &b64(&legacy))]);
        let got = load_key(dir.path(), &fake).unwrap();
        assert_ne!(b64(&got), b64(&legacy));
        assert_eq!(fake.reads(LEGACY_SERVICE), 0);
        assert_eq!(fake.item(SERVICE), Some(b64(&got)));
        assert!(!dir.path().join(KEY_FILE).exists());
    }

    #[test]
    fn migrated_data_takes_the_legacy_key() {
        let dir = tempfile::tempdir().unwrap();
        touch(&dir, "aceitunoak.db", "");
        let legacy = MasterKey::generate();
        let fake = Fake::with(&[(LEGACY_SERVICE, &b64(&legacy))]);
        let got = load_key(dir.path(), &fake).unwrap();
        assert_eq!(b64(&got), b64(&legacy));
        assert_eq!(fake.item(SERVICE), Some(b64(&legacy)));
        // The next launch only reads the new item.
        let again = load_key(dir.path(), &fake).unwrap();
        assert_eq!(b64(&again), b64(&legacy));
        assert_eq!(fake.reads(LEGACY_SERVICE), 1);
    }

    #[test]
    fn missing_item_uses_the_key_file_and_copies_it() {
        let dir = tempfile::tempdir().unwrap();
        touch(&dir, "termoak.db", "");
        let key = MasterKey::generate();
        touch(&dir, KEY_FILE, &b64(&key));
        let fake = Fake::default();
        let got = load_key(dir.path(), &fake).unwrap();
        assert_eq!(b64(&got), b64(&key));
        assert_eq!(fake.item(SERVICE), Some(b64(&key)));
        // The file stays (the database was sealed with it).
        assert!(dir.path().join(KEY_FILE).exists());
        assert_eq!(fake.reads(LEGACY_SERVICE), 0);
    }

    #[test]
    fn keychain_that_forgets_falls_back_to_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Fake {
            forgetful: true,
            ..Fake::default()
        };
        let got = load_key(dir.path(), &fake).unwrap();
        let saved = std::fs::read_to_string(dir.path().join(KEY_FILE)).unwrap();
        assert_eq!(saved, b64(&got));
        // Next launch: same key, from the file.
        assert_eq!(b64(&load_key(dir.path(), &fake).unwrap()), b64(&got));
    }

    #[test]
    fn failing_keychain_uses_the_key_file() {
        let dir = tempfile::tempdir().unwrap();
        touch(&dir, "termoak.db", "");
        let key = MasterKey::generate();
        touch(&dir, KEY_FILE, &b64(&key));
        let fake = Fake::failing("locked");
        assert_eq!(b64(&load_key(dir.path(), &fake).unwrap()), b64(&key));
    }

    #[test]
    fn failing_keychain_on_a_fresh_install_creates_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Fake::failing("no secret service");
        let got = load_key(dir.path(), &fake).unwrap();
        let saved = std::fs::read_to_string(dir.path().join(KEY_FILE)).unwrap();
        assert_eq!(saved.trim(), b64(&got));
    }

    #[test]
    fn denied_keychain_never_invents_a_key_for_existing_data() {
        let dir = tempfile::tempdir().unwrap();
        touch(&dir, "termoak.db", "");
        let fake = Fake::failing("user canceled");
        let err = load_key(dir.path(), &fake).unwrap_err();
        match &err {
            ClientError::KeychainUnavailable(e) => assert_eq!(e, "user canceled"),
            other => panic!("{other:?}"),
        }
        assert!(err.is_keychain_unavailable());
        assert!(!dir.path().join(KEY_FILE).exists());
        assert_eq!(fake.reads(LEGACY_SERVICE), 0);
        assert!(fake.item(SERVICE).is_none());
        // "Try again" once the keyring answers: the same data opens.
        let key = MasterKey::generate();
        let fixed = Fake::with(&[(SERVICE, &b64(&key))]);
        assert_eq!(b64(&load_key(dir.path(), &fixed).unwrap()), b64(&key));
    }
}

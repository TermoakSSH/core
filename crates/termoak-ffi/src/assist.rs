//! Terminal and vault helpers: `ssh_config` import, command autocompletion,
//! QR codes and the hosts' operating system.

use std::path::PathBuf;

use termoak_client::complete::{self as cc, SuggestionSource as CcSource};
use termoak_client::import::ImportOptions as CcImportOptions;

use crate::error::Result;
use crate::models::parse_opt_id;
use crate::runtime::block_on;
use crate::vault::TermoakCore;

// ---------------------------------------------------------------------------
// ssh_config import
// ---------------------------------------------------------------------------

/// Options for importing an `ssh_config`.
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct SshConfigImportOptions {
    /// Only compute what would be done (preview), without saving anything.
    #[uniffi(default)]
    pub dry_run: bool,
    /// Put the hosts in this group (created if it does not exist).
    #[uniffi(default)]
    pub group: Option<String>,
    /// Save hosts and keys as "this device only".
    #[uniffi(default)]
    pub device_only: bool,
    /// Account to import into (default: the current account; This device
    /// without one). Ignored with `device_only`.
    #[uniffi(default)]
    pub account_id: Option<String>,
    /// Vault of that account (default: its personal vault).
    #[uniffi(default)]
    pub vault_id: Option<String>,
}

impl SshConfigImportOptions {
    fn into_client(self) -> Result<CcImportOptions> {
        Ok(CcImportOptions {
            dry_run: self.dry_run,
            group: self
                .group
                .map(|g| g.trim().to_string())
                .filter(|g| !g.is_empty()),
            device_only: self.device_only,
            account: parse_opt_id(&self.account_id)?,
            vault: parse_opt_id(&self.vault_id)?,
        })
    }
}

/// A host that was not imported.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SkippedImport {
    pub alias: String,
    pub reason: String,
}

/// Result (or preview) of the import.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SshConfigImportReport {
    pub hosts_created: Vec<String>,
    pub hosts_skipped: Vec<SkippedImport>,
    /// Hosts created only to serve as jump hosts (`user@host:port`).
    pub jump_hosts_created: Vec<String>,
    pub keys_imported: Vec<String>,
    /// Keys that were already in the keychain (same fingerprint).
    pub keys_reused: Vec<String>,
    pub forwards_created: u32,
    pub warnings: Vec<String>,
}

impl From<termoak_client::import::ImportReport> for SshConfigImportReport {
    fn from(r: termoak_client::import::ImportReport) -> Self {
        SshConfigImportReport {
            hosts_created: r.hosts_created,
            hosts_skipped: r
                .hosts_skipped
                .into_iter()
                .map(|s| SkippedImport {
                    alias: s.alias,
                    reason: s.reason,
                })
                .collect(),
            jump_hosts_created: r.jump_hosts_created,
            keys_imported: r.keys_imported,
            keys_reused: r.keys_reused,
            forwards_created: u32::try_from(r.forwards_created).unwrap_or(u32::MAX),
            warnings: r.warnings,
        }
    }
}

// ---------------------------------------------------------------------------
// Autocompletion
// ---------------------------------------------------------------------------

/// Where a suggestion comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SuggestionSource {
    /// This device's history.
    History,
    /// Single-line snippet without variables.
    Snippet,
    /// Dictionary of system commands.
    Command,
}

/// Suggestion to complete the line being typed.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CommandSuggestion {
    /// Full suggested line.
    pub text: String,
    /// What is left to type: this is sent to the terminal on accept.
    pub insert: String,
    /// Short explanation for the list.
    pub description: String,
    pub source: SuggestionSource,
}

impl From<cc::Suggestion> for CommandSuggestion {
    fn from(s: cc::Suggestion) -> Self {
        CommandSuggestion {
            text: s.text,
            insert: s.insert,
            description: s.description,
            source: match s.source {
                CcSource::History => SuggestionSource::History,
                CcSource::Snippet => SuggestionSource::Snippet,
                CcSource::Command => SuggestionSource::Command,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// QR and operating system
// ---------------------------------------------------------------------------

/// QR code as a matrix of modules (`true` = dark), row by row.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct QrCode {
    /// Modules per side (no margin: leave 4 light modules around it).
    pub size: u32,
    /// `size * size` modules; the one at row `y`, column `x` is `y * size + x`.
    pub modules: Vec<bool>,
}

/// Generates the QR code of a text (e.g. the two-factor `otpauth_url` or an
/// invitation link). `None` if the text is too long.
#[uniffi::export]
pub fn qr_code(text: String) -> Option<QrCode> {
    let rows = termoak_client::qr::matrix(&text)?;
    Some(QrCode {
        size: u32::try_from(rows.len()).ok()?,
        modules: rows.into_iter().flatten().collect(),
    })
}

/// Operating system detected on a remote host.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RemoteOs {
    /// Short identifier for the icon: `ubuntu`, `debian`, `alpine`,
    /// `centos`, `rhel`, `fedora`, `arch`, `freebsd`, `macos`, `windows`...
    pub id: String,
    /// Version (`24.04`, `12`, `14.5`...).
    pub version: Option<String>,
    /// Display name (`Ubuntu 24.04.1 LTS`).
    pub display_name: String,
    /// Families it derives from (`debian`, `rhel`...).
    pub like: Vec<String>,
    /// Usual package manager (`apt`, `dnf`, `apk`, `brew`...).
    pub package_manager: Option<String>,
}

impl From<termoak_ssh::detect::OsInfo> for RemoteOs {
    fn from(i: termoak_ssh::detect::OsInfo) -> Self {
        let package_manager = termoak_ssh::detect::package_manager(&i.id)
            .or_else(|| {
                i.like
                    .iter()
                    .find_map(|l| termoak_ssh::detect::package_manager(l))
            })
            .map(str::to_string);
        RemoteOs {
            display_name: i.display(),
            id: i.id,
            version: i.version,
            like: i.like,
            package_manager,
        }
    }
}

#[uniffi::export]
impl TermoakCore {
    // ----- Import -----

    /// Imports the contents of an `ssh_config` (the user picks it with the
    /// file picker). Hosts whose name already exists are skipped, so it can
    /// be repeated. Keys (`IdentityFile`) are only imported if the path
    /// exists on this device; otherwise a warning is reported.
    pub fn import_ssh_config(
        &self,
        text: String,
        options: SshConfigImportOptions,
    ) -> Result<SshConfigImportReport> {
        let base = termoak_ssh::sshconfig::ssh_dir();
        let parsed = termoak_ssh::sshconfig::parse_str(&text, &base);
        Ok(block_on(self.ws.import_hosts(parsed, &options.into_client()?))?.into())
    }

    /// Imports an `ssh_config` from a path on the device (following its
    /// `Include`s).
    pub fn import_ssh_config_file(
        &self,
        path: String,
        options: SshConfigImportOptions,
    ) -> Result<SshConfigImportReport> {
        let text = std::fs::read_to_string(&path)?;
        let base = PathBuf::from(&path)
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(termoak_ssh::sshconfig::ssh_dir);
        let parsed = termoak_ssh::sshconfig::parse_str(&text, &base);
        Ok(block_on(self.ws.import_hosts(parsed, &options.into_client()?))?.into())
    }

    // ----- Autocompletion -----

    /// Suggestions to complete `line` (what was typed after the prompt) in a
    /// terminal of `host_id`. `os` is the host's operating system
    /// (`SshHost.os`), to suggest the right package manager. Fast: it can be
    /// called on every keystroke.
    pub fn complete_command(
        &self,
        host_id: Option<String>,
        os: Option<String>,
        line: String,
        limit: u32,
    ) -> Result<Vec<CommandSuggestion>> {
        let host = parse_opt_id(&host_id)?;
        let limit = usize::try_from(limit).unwrap_or(10);
        Ok(
            block_on(self.ws.complete(host, os.as_deref(), &line, limit))?
                .into_iter()
                .map(Into::into)
                .collect(),
        )
    }

    /// Saves an executed command (on Enter) in the host's history. It only
    /// lives on this device, and commands that look like they contain secrets
    /// or start with a space are not saved. Returns whether it was saved.
    pub fn record_command(&self, host_id: String, command: String) -> Result<bool> {
        let host = crate::models::parse_id(&host_id)?;
        Ok(block_on(self.ws.record_command(host, &command))?)
    }

    /// Clears the command history of a host (or all of it if `None`).
    pub fn clear_command_history(&self, host_id: Option<String>) -> Result<()> {
        let host = parse_opt_id(&host_id)?;
        Ok(block_on(self.ws.clear_history(host))?)
    }

    /// Command history to show in a list: the host's first and, if there are
    /// not enough, the other hosts', by usage and recency. `query` filters by
    /// content (case-insensitive; empty = all).
    pub fn command_history(
        &self,
        host_id: Option<String>,
        query: String,
        limit: u32,
    ) -> Result<Vec<CommandHistoryItem>> {
        let host = parse_opt_id(&host_id)?;
        let limit = usize::try_from(limit).unwrap_or(100);
        Ok(block_on(self.ws.command_history(host, &query, limit))?
            .into_iter()
            .map(|h| CommandHistoryItem {
                command: h.command,
                uses: u32::try_from(h.uses).unwrap_or(u32::MAX),
                last_used: h.last_used,
            })
            .collect())
    }
}

/// A command from the history.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CommandHistoryItem {
    pub command: String,
    /// Number of times it was run.
    pub uses: u32,
    /// Last time (ms since 1970).
    pub last_used: i64,
}

// ---------------------------------------------------------------------------
// Typed line (for the history)
// ---------------------------------------------------------------------------

/// Tracks what is typed in a terminal to know which command is sent with
/// Enter. Usage, on every chunk of bytes sent to the terminal:
///
/// 1. `pending = current()` and whether the screen shows it before the
///    cursor ([`command_echoed`]);
/// 2. `sent = feed(bytes)`;
/// 3. if `sent == pending` and it was on screen, save it with
///    `TermoakCore::record_command`.
///
/// Inside full-screen programs (vim, less...) call `forget()`. Anything the
/// shell can change on its own (arrows, Tab, Alt...) makes the line unknown
/// until the next Enter.
#[derive(uniffi::Object, Default)]
pub struct LineTracker {
    inner: parking_lot::Mutex<termoak_client::line::LineTracker>,
}

#[uniffi::export]
impl LineTracker {
    #[uniffi::constructor]
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::default())
    }

    /// Applies what is sent to the terminal. Returns the line sent with Enter,
    /// if it was known and not empty.
    pub fn feed(&self, data: Vec<u8>) -> Option<String> {
        self.inner.lock().feed(&data)
    }

    /// The line being typed, if known.
    pub fn current(&self) -> Option<String> {
        self.inner.lock().current()
    }

    /// Is the line known and the cursor at its end? Only then does it make
    /// sense to suggest how to continue it (`complete_command`).
    pub fn at_end(&self) -> bool {
        self.inner.lock().at_end()
    }

    /// The line becomes unknown until the next Enter.
    pub fn forget(&self) {
        self.inner.lock().forget();
    }

    /// New, empty line (e.g. after reconnecting).
    pub fn reset(&self) {
        self.inner.lock().reset();
    }
}

/// Does the screen show the typed line? `before` is the text before the
/// cursor (with wrapped rows joined) and `after_blank` whether there is
/// nothing to its right. Without echo (passwords) it does not match and
/// nothing is saved.
#[uniffi::export]
pub fn command_echoed(line: String, before: String, after_blank: bool) -> bool {
    termoak_client::line::screen_matches(&line, &before, after_blank)
}

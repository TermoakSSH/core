//! Import of hosts from other apps' files and Termoak's own export, and the
//! export (`termoak_client::importers`, the desktop's importers):
//!
//! 1. The user picks a file: [`detect_import_format`] says what it looks
//!    like (an `ssh_config` goes to `import_ssh_config`, which keeps jumps
//!    and tunnels).
//! 2. [`TermoakCore::preview_import`] reads it: an [`ImportPreview`] with
//!    the hosts, the duplicates in the target vault, warnings, the column
//!    mapping of a CSV (change it with [`ImportPreview::with_mapping`]) and,
//!    for a Termoak export with secrets, [`ImportPreview::unlock`].
//! 3. [`TermoakCore::apply_import`] saves it into a vault (or This
//!    device), with a duplicate policy and the hosts the user unchecked.
//!
//! [`TermoakCore::export_hosts`] writes a Termoak JSON (optionally with
//! secrets sealed by a passphrase) or a CSV of a vault or a group.
//!
//! Formats: Termoak JSON, CSV (any columns, mapped), Termius (CSV or JSON),
//! PuTTY `.reg` exports, MobaXterm (`MobaXterm.ini`, `.mxtsessions`),
//! SecureCRT (XML export or one session `.ini`), ZOC (CSV, `.zocdir`, XML).
//! Telnet sessions become Telnet hosts; other protocols are left out with a
//! warning. Private key files the source points to are imported when the
//! path can be read on the device (rarely on a phone: their path goes to
//! the host's notes).

use std::collections::HashSet;
use std::sync::Arc;

use termoak_client::importers::apply::{self, ExportRequest, Place};
use termoak_client::importers::csv::{self, Field, Mapping};
use termoak_client::importers::load::{self, Loaded};
use termoak_client::importers::termoak::Secrets;
use termoak_client::importers::{
    self as ci, DupPolicy, Duplicate, ImportError, ImportSet, ImportWarning, Source,
};
use termoak_client::{Scope, Workspace};
use termoak_core::Id;

use crate::error::{Result, TermoakError};
use crate::models::{parse_id, parse_opt_id};
use crate::runtime::run;
use crate::vault::TermoakCore;

fn import_error(e: ImportError) -> TermoakError {
    TermoakError::Invalid(e.to_string())
}

/// What a file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ImportFormat {
    /// Guess from the name and the content.
    Auto,
    TermoakJson,
    Csv,
    /// An `ssh_config`: use `import_ssh_config` (it keeps jumps and
    /// tunnels).
    SshConfig,
    Termius,
    /// A `.reg` export of PuTTY's sessions (the registry itself is only
    /// read by the Windows desktop app).
    Putty,
    MobaXterm,
    SecureCrt,
    Zoc,
}

impl ImportFormat {
    fn source(self) -> Option<Source> {
        Some(match self {
            ImportFormat::Auto => return None,
            ImportFormat::TermoakJson => Source::Termoak,
            ImportFormat::Csv => Source::Csv,
            ImportFormat::SshConfig => Source::SshConfig,
            ImportFormat::Termius => Source::Termius,
            ImportFormat::Putty => Source::Putty,
            ImportFormat::MobaXterm => Source::MobaXterm,
            ImportFormat::SecureCrt => Source::SecureCrt,
            ImportFormat::Zoc => Source::Zoc,
        })
    }
}

impl From<Source> for ImportFormat {
    fn from(s: Source) -> Self {
        match s {
            Source::Termoak => ImportFormat::TermoakJson,
            Source::Csv => ImportFormat::Csv,
            Source::SshConfig => ImportFormat::SshConfig,
            Source::Termius => ImportFormat::Termius,
            Source::Putty => ImportFormat::Putty,
            Source::MobaXterm => ImportFormat::MobaXterm,
            Source::SecureCrt => ImportFormat::SecureCrt,
            Source::Zoc => ImportFormat::Zoc,
        }
    }
}

/// The format a file looks like, from its name and its content.
#[uniffi::export]
pub fn detect_import_format(data: Vec<u8>, file_name: String) -> ImportFormat {
    let text = ci::text::decode(&data);
    ci::detect(std::path::Path::new(&file_name), &text).into()
}

/// A field a CSV column can feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CsvField {
    Label,
    Address,
    Port,
    User,
    Group,
    Tags,
    Notes,
    Password,
    Protocol,
}

impl From<CsvField> for Field {
    fn from(f: CsvField) -> Self {
        match f {
            CsvField::Label => Field::Label,
            CsvField::Address => Field::Address,
            CsvField::Port => Field::Port,
            CsvField::User => Field::User,
            CsvField::Group => Field::Group,
            CsvField::Tags => Field::Tags,
            CsvField::Notes => Field::Notes,
            CsvField::Password => Field::Password,
            CsvField::Protocol => Field::Protocol,
        }
    }
}

impl From<Field> for CsvField {
    fn from(f: Field) -> Self {
        match f {
            Field::Label => CsvField::Label,
            Field::Address => CsvField::Address,
            Field::Port => CsvField::Port,
            Field::User => CsvField::User,
            Field::Group => CsvField::Group,
            Field::Tags => CsvField::Tags,
            Field::Notes => CsvField::Notes,
            Field::Password => CsvField::Password,
            Field::Protocol => CsvField::Protocol,
        }
    }
}

/// A column mapped to a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct CsvColumn {
    pub field: CsvField,
    /// Column index (from 0).
    pub column: u32,
}

/// Which column feeds each field of a CSV.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CsvMapping {
    /// The first row has the column names.
    pub has_header: bool,
    pub columns: Vec<CsvColumn>,
}

impl From<&Mapping> for CsvMapping {
    fn from(m: &Mapping) -> Self {
        CsvMapping {
            has_header: m.has_header,
            columns: m
                .columns
                .iter()
                .map(|(f, c)| CsvColumn {
                    field: (*f).into(),
                    column: *c as u32,
                })
                .collect(),
        }
    }
}

impl From<CsvMapping> for Mapping {
    fn from(m: CsvMapping) -> Self {
        let mut out = Mapping {
            has_header: m.has_header,
            columns: Vec::new(),
        };
        for c in m.columns {
            out.set(c.field.into(), Some(c.column as usize));
        }
        out
    }
}

/// A warning of the import (a host left out or changed).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ImportWarningInfo {
    /// Stable code to translate by: `not_ssh`, `no_address`,
    /// `no_address_line`, `bad_port`, `proxy_unsupported`, `key_file`,
    /// `key_without_private`.
    pub code: String,
    /// The English text.
    pub message: String,
    /// Values for a translated text (`name`, `protocol`, `line`, `port`,
    /// `path`, `error`).
    pub params: std::collections::HashMap<String, String>,
}

impl From<&ImportWarning> for ImportWarningInfo {
    fn from(w: &ImportWarning) -> Self {
        ImportWarningInfo {
            code: w.code().to_string(),
            message: w.to_string(),
            params: w
                .params()
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        }
    }
}

/// Why a host of the file is a duplicate (same address, port and user).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ImportDuplicate {
    /// Of a host already in the target vault.
    Existing { host_id: String, label: String },
    /// Of an earlier host of the same file.
    InFile { index: u32 },
}

/// A host of the file, as the preview shows it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ImportHostPreview {
    /// Index in the file (for `ImportOptions.excluded`).
    pub index: u32,
    pub label: String,
    pub address: String,
    pub port: Option<u16>,
    pub username: Option<String>,
    /// `ssh` or `telnet`.
    pub protocol: String,
    /// `user@host:port` (`telnet://` in front for Telnet).
    pub target: String,
    /// Folder path (`Prod / Web`).
    pub group: Option<String>,
    pub tags: Vec<String>,
    pub notes: String,
    pub has_password: bool,
    /// Private key file the source points to.
    pub key_file: Option<String>,
    pub duplicate: Option<ImportDuplicate>,
}

/// A file read for the import, before anything is saved. Immutable:
/// [`Self::with_mapping`] and [`Self::unlock`] return a new preview.
#[derive(uniffi::Object)]
pub struct ImportPreview {
    loaded: Loaded,
    secrets: Option<Secrets>,
    set: ImportSet,
    /// Hosts already in the target, for duplicates.
    existing: Vec<ci::ExistingHost>,
    dups: Vec<Option<Duplicate>>,
    /// Workspace and target, to compute the duplicates again.
    ws: Workspace,
    place: Option<Place>,
}

impl ImportPreview {
    fn rebuild(
        ws: Workspace,
        loaded: Loaded,
        secrets: Option<Secrets>,
        place: Option<Place>,
        existing: Vec<ci::ExistingHost>,
    ) -> Arc<Self> {
        let set = loaded.set(secrets.as_ref());
        let dups = ci::find_duplicates(&set, &existing);
        Arc::new(Self {
            loaded,
            secrets,
            set,
            existing,
            dups,
            ws,
            place,
        })
    }
}

#[uniffi::export]
impl ImportPreview {
    /// The format read.
    pub fn format(&self) -> ImportFormat {
        self.loaded.source.into()
    }

    /// The file's name.
    pub fn origin(&self) -> String {
        self.loaded.origin.clone()
    }

    pub fn hosts(&self) -> Vec<ImportHostPreview> {
        self.set
            .hosts
            .iter()
            .enumerate()
            .map(|(i, h)| ImportHostPreview {
                index: i as u32,
                label: h.label.clone(),
                address: h.address.clone(),
                port: h.port,
                username: h.username.clone(),
                protocol: h.protocol.as_str().to_string(),
                target: h.target(),
                group: h.group.as_deref().map(|g| self.set.group_label(g)),
                tags: h.tags.clone(),
                notes: h.notes.clone(),
                has_password: h.password.is_some(),
                key_file: h.key_file.clone(),
                duplicate: self.dups.get(i).cloned().flatten().map(|d| match d {
                    Duplicate::Existing(ix) => {
                        let e = &self.existing[ix];
                        ImportDuplicate::Existing {
                            host_id: e.id.to_string(),
                            label: e.label.clone(),
                        }
                    }
                    Duplicate::InFile(ix) => ImportDuplicate::InFile { index: ix as u32 },
                }),
            })
            .collect()
    }

    pub fn warnings(&self) -> Vec<ImportWarningInfo> {
        self.set.warnings.iter().map(Into::into).collect()
    }

    /// Groups (folders) the file brings.
    pub fn group_count(&self) -> u32 {
        self.set.groups.len() as u32
    }

    /// Keys, identities and snippets (Termoak JSON).
    pub fn key_count(&self) -> u32 {
        self.set.keys.len() as u32
    }

    pub fn identity_count(&self) -> u32 {
        self.set.identities.len() as u32
    }

    pub fn snippet_count(&self) -> u32 {
        self.set.snippets.len() as u32
    }

    /// A Termoak export with sealed passwords and keys that are not open
    /// yet: ask for the passphrase ([`Self::unlock`]), or import the rest
    /// without them.
    pub fn needs_passphrase(&self) -> bool {
        self.loaded.has_sealed_secrets() && self.secrets.is_none()
    }

    /// Opens the sealed secrets (takes a moment). `None`: wrong passphrase.
    pub fn unlock(&self, passphrase: String) -> Result<Option<Arc<ImportPreview>>> {
        let secrets = match self.loaded.open_secrets(&passphrase) {
            Ok(s) => s,
            Err(ImportError::WrongPassphrase) => return Ok(None),
            Err(e) => return Err(import_error(e)),
        };
        Ok(Some(Self::rebuild(
            self.ws.clone(),
            self.loaded.clone(),
            secrets,
            self.place,
            self.existing.clone(),
        )))
    }

    /// The column mapping of a CSV (`None` for other formats). Without an
    /// address column nothing is imported: let the user map it.
    pub fn csv_mapping(&self) -> Option<CsvMapping> {
        self.loaded.mapping().map(Into::into)
    }

    /// Names of the CSV columns (the headers, or `Column 3`).
    pub fn csv_columns(&self) -> Vec<String> {
        match &self.loaded.content {
            load::Content::Table { table, mapping } => csv::column_names(table, mapping.has_header),
            _ => Vec::new(),
        }
    }

    /// The first rows of a CSV (at most `max`), to show next to the
    /// mapping.
    #[uniffi::method(default(max = 5))]
    pub fn csv_sample(&self, max: u32) -> Vec<Vec<String>> {
        match &self.loaded.content {
            load::Content::Table { table, .. } => {
                table.rows.iter().take(max as usize).cloned().collect()
            }
            _ => Vec::new(),
        }
    }

    /// The same file with another CSV column mapping.
    pub fn with_mapping(&self, mapping: CsvMapping) -> Arc<ImportPreview> {
        let mut loaded = self.loaded.clone();
        loaded.set_mapping(mapping.into());
        Self::rebuild(
            self.ws.clone(),
            loaded,
            self.secrets.clone(),
            self.place,
            self.existing.clone(),
        )
    }
}

/// Where an import goes or what an export reads.
fn place_of(
    ws: &Workspace,
    account_id: &Option<String>,
    vault_id: &Option<String>,
    device_only: bool,
) -> Result<Place> {
    if device_only {
        return Ok(Place {
            scope: Scope::Device,
            vault: None,
        });
    }
    let vault = parse_opt_id(vault_id)?;
    let account = match parse_opt_id(account_id)? {
        Some(a) => Some(ws.require_account(a)?),
        None => ws.current(),
    };
    Ok(match account {
        Some(acc) => {
            let info = acc.info();
            let vault = if info.vaults_supported() {
                vault.or(acc.user_id())
            } else {
                None
            };
            Place {
                scope: Scope::Account(acc.id),
                vault,
            }
        }
        None => Place {
            scope: Scope::Device,
            vault: None,
        },
    })
}

/// What to do with hosts that are already in the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DuplicatePolicy {
    /// Leave them out.
    Skip,
    /// Update the existing host (address, port, user, proxy, tags, notes,
    /// passwords).
    Update,
    /// Import them anyway, as `web (2)`.
    Copy,
}

impl From<DuplicatePolicy> for DupPolicy {
    fn from(p: DuplicatePolicy) -> Self {
        match p {
            DuplicatePolicy::Skip => DupPolicy::Skip,
            DuplicatePolicy::Update => DupPolicy::Update,
            DuplicatePolicy::Copy => DupPolicy::Copy,
        }
    }
}

/// Where and how an import is saved.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ImportOptions {
    /// Account (default: the current one; This device without one).
    #[uniffi(default)]
    pub account_id: Option<String>,
    /// Vault of that account (default: its personal vault).
    #[uniffi(default)]
    pub vault_id: Option<String>,
    /// This device, whatever the account.
    #[uniffi(default)]
    pub device_only: bool,
    /// An existing group of the target to put everything under.
    #[uniffi(default)]
    pub group_id: Option<String>,
    /// Or a top-level group by name (found or created), e.g. "PuTTY".
    #[uniffi(default)]
    pub group_name: Option<String>,
    pub duplicate_policy: DuplicatePolicy,
    /// Hosts the user unchecked (`ImportHostPreview.index`).
    #[uniffi(default)]
    pub excluded: Vec<u32>,
}

/// What an import did.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ImportSummary {
    pub created: u32,
    pub updated: u32,
    pub skipped: u32,
    pub groups: u32,
    pub keys: u32,
    /// Keys that were already there (same fingerprint).
    pub keys_reused: u32,
    pub identities: u32,
    pub snippets: u32,
    pub warnings: Vec<ImportWarningInfo>,
}

/// What an export writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ExportFormat {
    /// Termoak JSON: hosts, groups, identities, keys (public parts) and
    /// snippets; passwords and private keys only with `include_secrets`,
    /// sealed with a passphrase.
    TermoakJson,
    /// CSV of the hosts (for spreadsheets and other apps); never secrets.
    Csv,
}

/// Which items an export takes.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ExportScope {
    /// Account (default: the current one; This device without one).
    #[uniffi(default)]
    pub account_id: Option<String>,
    /// Vault of that account (default: its personal vault).
    #[uniffi(default)]
    pub vault_id: Option<String>,
    /// This device.
    #[uniffi(default)]
    pub device_only: bool,
    /// Only this group and its subgroups (with what their hosts use).
    #[uniffi(default)]
    pub group_id: Option<String>,
}

/// An export file, ready to save (with the share sheet or the file
/// picker).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ExportResult {
    pub data: Vec<u8>,
    /// Suggested name (`termoak-hosts-2026-10-08.json`).
    pub file_name: String,
    pub mime_type: String,
    pub hosts: u32,
    /// Secrets that could not be read (Use-only vaults) and are not in it.
    pub hidden_secrets: u32,
    /// It has passwords or keys (sealed): store it carefully.
    pub has_secrets: bool,
}

#[uniffi::export]
impl TermoakCore {
    /// Reads a file for the import preview, against the vault it would go
    /// to (`account_id` / `vault_id`, default the current account's
    /// personal vault; `device_only`: This device) to find duplicates.
    /// `file_name` helps guess the format. Fails with `Invalid` when the
    /// file cannot be read as that format (an `ssh_config` too: use
    /// `import_ssh_config`).
    #[uniffi::method(default(format = None, account_id = None, vault_id = None, device_only = false))]
    pub async fn preview_import(
        &self,
        data: Vec<u8>,
        file_name: String,
        format: Option<ImportFormat>,
        account_id: Option<String>,
        vault_id: Option<String>,
        device_only: bool,
    ) -> Result<Arc<ImportPreview>> {
        let place = place_of(&self.ws, &account_id, &vault_id, device_only)?;
        let ws = self.ws.clone();
        run(async move {
            let loaded = tokio::task::spawn_blocking(move || {
                load::load(&data, &file_name, format.and_then(ImportFormat::source))
            })
            .await
            .map_err(|e| TermoakError::Internal(e.to_string()))?
            .map_err(import_error)?;
            let existing = apply::load_place(&ws, place).await?.existing_hosts();
            Ok(ImportPreview::rebuild(
                ws,
                loaded,
                None,
                Some(place),
                existing,
            ))
        })
        .await
    }

    /// [`Self::preview_import`] of a file on the device.
    #[uniffi::method(default(format = None, account_id = None, vault_id = None, device_only = false))]
    pub async fn preview_import_file(
        &self,
        path: String,
        format: Option<ImportFormat>,
        account_id: Option<String>,
        vault_id: Option<String>,
        device_only: bool,
    ) -> Result<Arc<ImportPreview>> {
        let data = std::fs::read(&path)?;
        let name = std::path::Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or(path);
        self.preview_import(data, name, format, account_id, vault_id, device_only)
            .await
    }

    /// Saves a previewed import. The target may differ from the preview's:
    /// duplicates are found again against it.
    pub async fn apply_import(
        &self,
        preview: Arc<ImportPreview>,
        options: ImportOptions,
    ) -> Result<ImportSummary> {
        let place = place_of(
            &self.ws,
            &options.account_id,
            &options.vault_id,
            options.device_only,
        )?;
        let base_group_id = parse_opt_id(&options.group_id)?;
        let ws = self.ws.clone();
        run(async move {
            let existing = apply::load_place(&ws, place).await?;
            let existing_hosts = existing.existing_hosts();
            let set = preview.set.clone();
            let dups = ci::find_duplicates(&set, &existing_hosts);
            let excluded: HashSet<u32> = options.excluded.iter().copied().collect();
            let included: Vec<bool> = (0..set.hosts.len())
                .map(|i| !excluded.contains(&(i as u32)))
                .collect();
            let actions = ci::plan(
                &dups,
                &included,
                &existing_hosts,
                options.duplicate_policy.into(),
            );
            let summary = apply::run(
                &ws,
                apply::Request {
                    set,
                    actions,
                    place,
                    base_group: options
                        .group_name
                        .map(|g| g.trim().to_string())
                        .filter(|g| !g.is_empty()),
                    base_group_id,
                    existing,
                    home: termoak_ssh::sshconfig::ssh_dir().parent().map(Into::into),
                },
            )
            .await?;
            Ok(ImportSummary {
                created: summary.created as u32,
                updated: summary.updated as u32,
                skipped: summary.skipped as u32,
                groups: summary.groups as u32,
                keys: summary.keys as u32,
                keys_reused: summary.keys_reused as u32,
                identities: summary.identities as u32,
                snippets: summary.snippets as u32,
                warnings: summary.warnings.iter().map(Into::into).collect(),
            })
        })
        .await
    }

    /// Writes an export of a vault (or This device, or one group). Secrets
    /// only go into a Termoak JSON, with `include_secrets` and a passphrase
    /// of at least 8 characters (sealing takes a moment). `app` names the
    /// app in the file ("Termoak for iOS 0.6.1").
    #[uniffi::method(default(include_secrets = false, passphrase = None, app = None))]
    pub async fn export_hosts(
        &self,
        format: ExportFormat,
        scope: ExportScope,
        include_secrets: bool,
        passphrase: Option<String>,
        app: Option<String>,
    ) -> Result<ExportResult> {
        let place = place_of(
            &self.ws,
            &scope.account_id,
            &scope.vault_id,
            scope.device_only,
        )?;
        let group: Option<Id> = match &scope.group_id {
            Some(g) => Some(parse_id(g)?),
            None => None,
        };
        let app = app
            .filter(|a| !a.trim().is_empty())
            .unwrap_or_else(|| format!("Termoak {}", env!("CARGO_PKG_VERSION")));
        let ws = self.ws.clone();
        run(async move {
            let (fmt, mime) = match format {
                ExportFormat::TermoakJson => (apply::ExportFormat::Termoak, "application/json"),
                ExportFormat::Csv => (apply::ExportFormat::Csv, "text/csv"),
            };
            let out = apply::export(
                &ws,
                ExportRequest {
                    place,
                    group,
                    include_secrets,
                },
                fmt,
                passphrase.as_deref(),
                &app,
            )
            .await?;
            Ok(ExportResult {
                data: out.bytes,
                file_name: format!(
                    "termoak-hosts-{}.{}",
                    chrono::Utc::now().format("%Y-%m-%d"),
                    fmt.extension()
                ),
                mime_type: mime.to_string(),
                hosts: out.hosts as u32,
                hidden_secrets: out.hidden_secrets as u32,
                has_secrets: out.has_secrets,
            })
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::block_on;

    fn new_core() -> (tempfile::TempDir, Arc<TermoakCore>) {
        let dir = tempfile::tempdir().unwrap();
        let core = TermoakCore::new(
            dir.path().to_string_lossy().into_owned(),
            crate::generate_vault_key(),
        )
        .unwrap();
        (dir, core)
    }

    const CSV: &str = "Name;Address;User;Folder;Kind\n\
        web-1;10.0.0.11:2222;deploy;Prod;ssh\n\
        sw-1;10.0.0.2;;Net;telnet\n\
        desk;10.0.0.3;;;rdp\n";

    #[test]
    fn preview_apply_and_export() {
        let (_dir, core) = new_core();
        assert_eq!(
            detect_import_format(CSV.as_bytes().to_vec(), "hosts.csv".into()),
            ImportFormat::Csv
        );
        assert_eq!(
            detect_import_format(b"Host a\n HostName b\n".to_vec(), "config".into()),
            ImportFormat::SshConfig
        );
        let p = block_on(core.preview_import(
            CSV.as_bytes().to_vec(),
            "hosts.csv".into(),
            None,
            None,
            None,
            false,
        ))
        .unwrap();
        assert_eq!(p.format(), ImportFormat::Csv);
        assert!(!p.needs_passphrase());
        let m = p.csv_mapping().unwrap();
        assert!(m.has_header);
        assert_eq!(p.csv_columns()[1], "Address");
        assert_eq!(p.csv_sample(2).len(), 2);
        let hosts = p.hosts();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].target, "deploy@10.0.0.11:2222");
        assert_eq!(hosts[0].group.as_deref(), Some("Prod"));
        assert_eq!(hosts[1].protocol, "telnet");
        let w = p.warnings();
        assert_eq!(w[0].code, "not_ssh");
        assert_eq!(w[0].params["protocol"], "rdp");

        let options = ImportOptions {
            account_id: None,
            vault_id: None,
            device_only: false,
            group_id: None,
            group_name: Some("Imported".into()),
            duplicate_policy: DuplicatePolicy::Skip,
            excluded: vec![1],
        };
        let s = block_on(core.apply_import(p.clone(), options.clone())).unwrap();
        assert_eq!((s.created, s.skipped), (1, 1));
        // The same file again: the host is a duplicate now.
        let p = block_on(core.preview_import(
            CSV.as_bytes().to_vec(),
            "hosts.csv".into(),
            Some(ImportFormat::Csv),
            None,
            None,
            false,
        ))
        .unwrap();
        assert!(matches!(
            p.hosts()[0].duplicate,
            Some(ImportDuplicate::Existing { .. })
        ));
        assert_eq!(p.hosts()[1].duplicate, None);
        // A remapped CSV: the folder column is ignored now.
        let mut m = p.csv_mapping().unwrap();
        m.columns.retain(|c| c.field != CsvField::Group);
        assert_eq!(p.with_mapping(m).hosts()[0].group, None);

        let out = block_on(core.export_hosts(
            ExportFormat::Csv,
            ExportScope {
                account_id: None,
                vault_id: None,
                device_only: true,
                group_id: None,
            },
            false,
            None,
            None,
        ))
        .unwrap();
        assert_eq!(out.hosts, 1);
        assert!(out.file_name.starts_with("termoak-hosts-") && out.file_name.ends_with(".csv"));
        let text = String::from_utf8(out.data).unwrap();
        assert!(text.contains("web-1,10.0.0.11,2222,deploy,Imported/Prod"));

        // Termoak JSON with secrets needs a passphrase.
        let scope = ExportScope {
            account_id: None,
            vault_id: None,
            device_only: true,
            group_id: None,
        };
        assert!(
            block_on(core.export_hosts(ExportFormat::TermoakJson, scope.clone(), true, None, None))
                .is_err()
        );
        let out = block_on(core.export_hosts(
            ExportFormat::TermoakJson,
            scope,
            true,
            Some("a long passphrase".into()),
            Some("Termoak test".into()),
        ))
        .unwrap();
        assert!(out.has_secrets);
        let (_dir2, other) = new_core();
        let p =
            block_on(other.preview_import(out.data, "export.json".into(), None, None, None, false))
                .unwrap();
        assert_eq!(p.format(), ImportFormat::TermoakJson);
        assert!(p.needs_passphrase());
        assert!(p.unlock("nope".into()).unwrap().is_none());
        let p = p.unlock("a long passphrase".into()).unwrap().unwrap();
        assert!(!p.needs_passphrase());
        assert_eq!(p.group_count(), 2);
        let s = block_on(other.apply_import(
            p,
            ImportOptions {
                group_name: None,
                excluded: vec![],
                ..options
            },
        ))
        .unwrap();
        assert_eq!(s.created, 1);
        assert_eq!(other.list_hosts(None).unwrap()[0].label, "web-1");
    }

    #[test]
    fn ssh_config_goes_to_its_importer() {
        let (_dir, core) = new_core();
        let err = block_on(core.preview_import(
            b"Host a\n  HostName b\n".to_vec(),
            "config".into(),
            None,
            None,
            None,
            false,
        ))
        .err()
        .unwrap();
        assert!(matches!(err, TermoakError::Invalid(_)));
    }
}

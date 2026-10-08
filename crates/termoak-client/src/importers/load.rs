//! Reading a file for the import preview: its source (given, or guessed
//! from the name and the content) and what it holds, before any vault is
//! touched. Moved from the desktop's import dialog.

use std::path::Path;

use super::csv::{self, CsvTable, Mapping};
use super::termoak::{self, ExportFile};
use super::{
    ImportError, ImportSet, Source, detect, mobaxterm, putty, securecrt, termius, text, zoc,
};

/// What a file holds.
#[derive(Debug, Clone)]
pub enum Content {
    Set(ImportSet),
    /// A table whose columns can be mapped (CSV, and the CSV exports of
    /// Termius and ZOC).
    Table {
        table: CsvTable,
        mapping: Mapping,
    },
    /// A Termoak export (its secrets may still be sealed).
    Termoak(Box<ExportFile>),
}

/// A file read for the preview.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub source: Source,
    /// File name (or folder, or "registry").
    pub origin: String,
    pub content: Content,
}

impl Loaded {
    /// The hosts of the file: a table with its current mapping, a Termoak
    /// export with its secrets when `secrets` were opened (see
    /// [`Self::open_secrets`]).
    pub fn set(&self, secrets: Option<&termoak::Secrets>) -> ImportSet {
        match &self.content {
            Content::Set(set) => set.clone(),
            Content::Table { table, mapping } => csv::to_set(table, mapping),
            Content::Termoak(file) => termoak::to_set(file, secrets),
        }
    }

    /// A Termoak export with sealed secrets (a passphrase is needed to
    /// import them; without it the rest is imported).
    pub fn has_sealed_secrets(&self) -> bool {
        matches!(&self.content, Content::Termoak(f) if f.secrets.is_some())
    }

    /// Opens the sealed secrets of a Termoak export (Argon2id: it takes a
    /// moment). `None` when there are none.
    pub fn open_secrets(&self, passphrase: &str) -> Result<Option<termoak::Secrets>, ImportError> {
        match &self.content {
            Content::Termoak(f) => match &f.secrets {
                Some(sealed) => termoak::open(sealed, passphrase).map(Some),
                None => Ok(None),
            },
            _ => Ok(None),
        }
    }

    /// The column mapping, for a table.
    pub fn mapping(&self) -> Option<&Mapping> {
        match &self.content {
            Content::Table { mapping, .. } => Some(mapping),
            _ => None,
        }
    }

    /// Uses another column mapping (a table only).
    pub fn set_mapping(&mut self, new: Mapping) {
        if let Content::Table { mapping, .. } = &mut self.content {
            *mapping = new;
        }
    }
}

fn table_or_set(
    text: &str,
    fallback: impl FnOnce() -> Result<ImportSet, ImportError>,
) -> Result<Content, ImportError> {
    let table = csv::read(text);
    let mapping = csv::guess_mapping(&table);
    if mapping.is_usable() {
        return Ok(Content::Table { table, mapping });
    }
    fallback().map(Content::Set)
}

/// Reads the bytes of a file named `name` (only its name and extension
/// matter) as `source`, or as the source it looks like. An `ssh_config`
/// answers [`ImportError::SshConfig`]: it has its own importer.
pub fn load(bytes: &[u8], name: &str, source: Option<Source>) -> Result<Loaded, ImportError> {
    let path = Path::new(name);
    let text = text::decode(bytes);
    let source = source.unwrap_or_else(|| detect(path, &text));
    let content = match source {
        Source::Termoak => Content::Termoak(Box::new(termoak::parse(&text)?)),
        Source::Csv => {
            let table = csv::read(&text);
            if table.rows.is_empty() {
                return Err(ImportError::NoHostsFound);
            }
            let mapping = csv::guess_mapping(&table);
            Content::Table { table, mapping }
        }
        Source::Termius => {
            let t = text.trim_start_matches('\u{feff}').trim_start();
            if t.starts_with('{') || t.starts_with('[') {
                Content::Set(termius::parse(&text)?)
            } else {
                table_or_set(&text, || termius::parse(&text))?
            }
        }
        Source::Putty => {
            let sessions = putty::parse_reg(&text);
            if sessions.is_empty() {
                return Err(ImportError::NoPuttySessions);
            }
            Content::Set(putty::to_set(&sessions))
        }
        Source::MobaXterm => Content::Set(mobaxterm::parse(&text)),
        Source::SecureCrt => {
            if text.trim_start().starts_with('<') {
                Content::Set(securecrt::parse_xml(&text)?)
            } else {
                let stem = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                Content::Set(securecrt::from_ini_files(&[(stem, text.clone())]))
            }
        }
        Source::Zoc => {
            let t = text.trim_start_matches('\u{feff}').trim_start();
            let first = t.lines().next().unwrap_or("");
            if !t.starts_with('<') && !first.contains('=') {
                table_or_set(&text, || zoc::parse(&text))?
            } else {
                Content::Set(zoc::parse(&text)?)
            }
        }
        Source::SshConfig => return Err(ImportError::SshConfig),
    };
    Ok(Loaded {
        source,
        origin: path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| name.to_string()),
        content,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_by_content_and_name() {
        let l = load(b"label,host\nweb,10.0.0.1\n", "hosts.csv", None).unwrap();
        assert_eq!(l.source, Source::Csv);
        assert!(l.mapping().unwrap().is_usable());
        assert_eq!(l.set(None).hosts.len(), 1);

        let reg = "Windows Registry Editor Version 5.00\r\n\r\n\
            [HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\web]\r\n\
            \"HostName\"=\"10.0.0.2\"\r\n\"Protocol\"=\"ssh\"\r\n";
        let l = load(reg.as_bytes(), "putty.reg", None).unwrap();
        assert_eq!(l.source, Source::Putty);
        assert_eq!(l.origin, "putty.reg");
        assert_eq!(l.set(None).hosts[0].address, "10.0.0.2");

        assert_eq!(
            load(b"Host web\n  HostName 1.2.3.4\n", "config", None).unwrap_err(),
            ImportError::SshConfig
        );
        assert_eq!(
            load(b"Windows Registry Editor Version 5.00\r\n", "x.reg", None).unwrap_err(),
            ImportError::NoPuttySessions
        );
        assert_eq!(
            load(b"{\"format\":\"other\"}", "x.json", Some(Source::Termoak)).unwrap_err(),
            ImportError::NotTermoak
        );
        // A forced source wins over the guess.
        let l = load(
            b"Name;Connect to\nr1;10.0.0.3:2222\n",
            "dir.txt",
            Some(Source::Zoc),
        )
        .unwrap();
        assert_eq!(l.source, Source::Zoc);
        let set = l.set(None);
        assert_eq!(set.hosts[0].port, Some(2222));
    }

    #[test]
    fn remapping_a_table() {
        let mut l = load(b"a,b\nweb,10.0.0.1\n", "x.csv", None).unwrap();
        assert!(l.set(None).hosts.is_empty());
        let mut m = l.mapping().unwrap().clone();
        m.set(csv::Field::Address, Some(1));
        m.set(csv::Field::Label, Some(0));
        l.set_mapping(m);
        let set = l.set(None);
        assert_eq!(set.hosts.len(), 2, "no header row: both rows are hosts");
    }
}

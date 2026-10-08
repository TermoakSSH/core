//! What the importers say: warnings about hosts left out or changed, the
//! notes they add to hosts, and why a file could not be read. Each one has
//! a stable [`code`](ImportWarning::code) (the apps translate by it, with
//! [`params`](ImportWarning::params)) and an English text (`Display`).

use std::fmt;

/// A host left out, or imported with a change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportWarning {
    /// A session of another protocol (RDP, VNC, serial...): not imported.
    NotSsh { name: String, protocol: String },
    /// A host without an address: not imported.
    NoAddress { name: String },
    /// A CSV row without an address: not imported.
    NoAddressRow { line: usize },
    /// A CSV port that is not a number: the default port is used.
    BadPort { line: usize, port: String },
    /// A PuTTY Telnet or local-command proxy: imported without proxy.
    ProxyUnsupported { name: String },
    /// A private key file the source points to could not be imported (its
    /// path goes to the host's notes).
    KeyFile {
        name: String,
        path: String,
        error: String,
    },
    /// A key of a Termoak export without its private part: not imported.
    KeyWithoutPrivate { name: String },
}

impl ImportWarning {
    /// Stable code (`not_ssh`, `no_address`, `no_address_line`, `bad_port`,
    /// `proxy_unsupported`, `key_file`, `key_without_private`; the
    /// desktop's `import_export.warn.*` keys).
    pub fn code(&self) -> &'static str {
        match self {
            ImportWarning::NotSsh { .. } => "not_ssh",
            ImportWarning::NoAddress { .. } => "no_address",
            ImportWarning::NoAddressRow { .. } => "no_address_line",
            ImportWarning::BadPort { .. } => "bad_port",
            ImportWarning::ProxyUnsupported { .. } => "proxy_unsupported",
            ImportWarning::KeyFile { .. } => "key_file",
            ImportWarning::KeyWithoutPrivate { .. } => "key_without_private",
        }
    }

    /// Values of the message, by name (`name`, `protocol`, `line`, `port`,
    /// `path`, `error`).
    pub fn params(&self) -> Vec<(&'static str, String)> {
        match self {
            ImportWarning::NotSsh { name, protocol } => {
                vec![("name", name.clone()), ("protocol", protocol.clone())]
            }
            ImportWarning::NoAddress { name }
            | ImportWarning::ProxyUnsupported { name }
            | ImportWarning::KeyWithoutPrivate { name } => vec![("name", name.clone())],
            ImportWarning::NoAddressRow { line } => vec![("line", line.to_string())],
            ImportWarning::BadPort { line, port } => {
                vec![("line", line.to_string()), ("port", port.clone())]
            }
            ImportWarning::KeyFile { name, path, error } => vec![
                ("name", name.clone()),
                ("path", path.clone()),
                ("error", error.clone()),
            ],
        }
    }
}

impl fmt::Display for ImportWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportWarning::NotSsh { name, protocol } => write!(
                f,
                "“{name}” is a {protocol} session, not SSH or Telnet: not imported"
            ),
            ImportWarning::NoAddress { name } => write!(f, "“{name}” has no address: not imported"),
            ImportWarning::NoAddressRow { line } => {
                write!(f, "Row {line} has no address: not imported")
            }
            ImportWarning::BadPort { line, port } => {
                write!(f, "Row {line}: “{port}” is not a port; 22 is used")
            }
            ImportWarning::ProxyUnsupported { name } => write!(
                f,
                "“{name}” uses a Telnet or local-command proxy, which Termoak does not support: imported without proxy"
            ),
            ImportWarning::KeyFile { name, path, error } => write!(
                f,
                "“{name}”: the key {path} could not be imported ({error}); its path is in the notes"
            ),
            ImportWarning::KeyWithoutPrivate { name } => write!(
                f,
                "The key “{name}” was exported without its private part: not imported"
            ),
        }
    }
}

/// A note an importer adds to a host (written in its notes, in English).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportNote {
    /// MobaXterm's SSH gateway (to add as a jump host).
    Gateway { gateway: String },
    /// A SecureCRT firewall/proxy by name.
    Firewall { name: String },
    /// The private key the original app used.
    KeyFile { path: String },
}

impl fmt::Display for ImportNote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportNote::Gateway { gateway } => write!(
                f,
                "SSH gateway in MobaXterm: {gateway} (add it as a jump host)"
            ),
            ImportNote::Firewall { name } => write!(
                f,
                "SecureCRT firewall/proxy “{name}” (set the proxy in the host)"
            ),
            ImportNote::KeyFile { path } => write!(f, "Private key in the original app: {path}"),
        }
    }
}

/// Why a file could not be imported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    /// It is not a Termoak export.
    NotTermoak,
    /// A Termoak export of a newer format version.
    NewerVersion(u32),
    /// Not valid (JSON, XML...): the parser's message.
    Invalid(String),
    WrongPassphrase,
    /// A table without a column with the hosts' addresses.
    NoAddressColumn,
    NoHostsFound,
    /// A SecureCRT XML without its `Sessions` key.
    NoSessions,
    /// A `.reg` file without PuTTY sessions.
    NoPuttySessions,
    /// The file could not be read.
    Read(String),
    /// An `ssh_config`: it has its own importer (`Workspace::import_hosts`,
    /// FFI `import_ssh_config`), which keeps jumps and tunnels.
    SshConfig,
}

impl ImportError {
    /// Stable code (the desktop's `import_export.error.*` keys).
    pub fn code(&self) -> &'static str {
        match self {
            ImportError::NotTermoak => "not_termoak",
            ImportError::NewerVersion(_) => "newer_version",
            ImportError::Invalid(_) => "invalid",
            ImportError::WrongPassphrase => "wrong_passphrase",
            ImportError::NoAddressColumn => "no_address_column",
            ImportError::NoHostsFound => "no_hosts_found",
            ImportError::NoSessions => "no_sessions",
            ImportError::NoPuttySessions => "no_putty_sessions",
            ImportError::Read(_) => "read",
            ImportError::SshConfig => "ssh_config",
        }
    }
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportError::NotTermoak => write!(f, "It is not a Termoak export"),
            ImportError::NewerVersion(v) => write!(
                f,
                "The file is from a newer Termoak (format {v}): update the app"
            ),
            ImportError::Invalid(e) => write!(f, "The file is not valid: {e}"),
            ImportError::WrongPassphrase => write!(f, "Wrong passphrase"),
            ImportError::NoAddressColumn => {
                write!(f, "No column with the address of the hosts was found")
            }
            ImportError::NoHostsFound => write!(f, "No hosts were found in the file"),
            ImportError::NoSessions => write!(f, "The file has no “Sessions” key"),
            ImportError::NoPuttySessions => write!(
                f,
                "The file has no PuTTY sessions (HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions)"
            ),
            ImportError::Read(e) => write!(f, "Could not read the file: {e}"),
            ImportError::SshConfig => write!(
                f,
                "It is an ssh_config file: import it with the ssh_config importer"
            ),
        }
    }
}

impl std::error::Error for ImportError {}

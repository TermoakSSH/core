//! Remote operating system detection (to show the host icon, like Termius
//! does, for autocompletion and to give context to the AI).

use std::time::Duration;

use crate::client::Connection;
use crate::exec::ExecOptions;

/// Detected system.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsInfo {
    /// Short identifier: `ubuntu`, `debian`, `alpine`, `centos`, `rhel`,
    /// `fedora`, `arch`, `linux`, `freebsd`, `openbsd`, `macos`, `windows`...
    pub id: String,
    /// Version (`24.04`, `12`, `3.20`, `14.5`...).
    pub version: Option<String>,
    /// Display name (`Ubuntu 24.04.1 LTS`).
    pub pretty_name: Option<String>,
    /// Families it derives from (`ID_LIKE`: `debian`, `rhel fedora`...).
    pub like: Vec<String>,
}

/// Returns only the identifier (see [`detect_os_info`]).
pub async fn detect_os(conn: &Connection) -> Option<String> {
    detect_os_info(conn).await.map(|i| i.id)
}

/// Detects the system with `uname` and `/etc/os-release` (or `sw_vers` on
/// macOS and `ver` on Windows).
pub async fn detect_os_info(conn: &Connection) -> Option<OsInfo> {
    let opts = ExecOptions {
        timeout: Duration::from_secs(10),
        max_output: 8192,
        ..Default::default()
    };
    let out = conn
        .exec(
            "uname -s 2>/dev/null; cat /etc/os-release 2>/dev/null; \
             sw_vers -productVersion 2>/dev/null | sed 's/^/MACOS_VERSION=/'; \
             uname -r 2>/dev/null | sed 's/^/KERNEL_RELEASE=/'",
            &opts,
        )
        .await
        .ok()?;
    if let Some(info) = parse(&out.stdout_text()) {
        return Some(info);
    }
    // Windows with OpenSSH: `uname` does not exist.
    let out = conn.exec("ver", &opts).await.ok()?;
    parse_windows(&out.stdout_text())
}

fn unquote(v: &str) -> String {
    v.trim().trim_matches('"').trim_matches('\'').to_string()
}

fn parse(output: &str) -> Option<OsInfo> {
    let mut kernel = None;
    let mut info = OsInfo::default();
    let mut kernel_release = None;
    let mut macos_version = None;
    for line in output.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("ID=") {
            info.id = unquote(v).to_lowercase();
        } else if let Some(v) = line.strip_prefix("VERSION_ID=") {
            info.version = Some(unquote(v)).filter(|v| !v.is_empty());
        } else if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
            info.pretty_name = Some(unquote(v)).filter(|v| !v.is_empty());
        } else if let Some(v) = line.strip_prefix("ID_LIKE=") {
            info.like = unquote(v)
                .split_whitespace()
                .map(|s| s.to_lowercase())
                .collect();
        } else if let Some(v) = line.strip_prefix("MACOS_VERSION=") {
            macos_version = Some(v.trim().to_string()).filter(|v| !v.is_empty());
        } else if let Some(v) = line.strip_prefix("KERNEL_RELEASE=") {
            kernel_release = Some(v.trim().to_string()).filter(|v| !v.is_empty());
        } else if kernel.is_none() && !line.contains('=') && !line.is_empty() {
            kernel = Some(line.to_lowercase());
        }
    }
    if !info.id.is_empty() {
        return Some(info);
    }
    let id = match kernel.as_deref() {
        Some("darwin") => "macos".to_string(),
        Some(k) if k.starts_with("mingw") || k.starts_with("msys") || k.starts_with("cygwin") => {
            "windows".to_string()
        }
        Some(k) => k.to_string(),
        None => return None,
    };
    let version = if id == "macos" {
        macos_version
    } else {
        kernel_release
    };
    let pretty_name = match id.as_str() {
        "macos" => Some(
            format!("macOS {}", version.clone().unwrap_or_default())
                .trim()
                .to_string(),
        ),
        "freebsd" => Some(
            format!("FreeBSD {}", version.clone().unwrap_or_default())
                .trim()
                .to_string(),
        ),
        _ => None,
    };
    Some(OsInfo {
        id,
        version,
        pretty_name,
        like: Vec::new(),
    })
}

fn parse_windows(output: &str) -> Option<OsInfo> {
    let lower = output.to_lowercase();
    if !lower.contains("windows") {
        return None;
    }
    // "Microsoft Windows [Version 10.0.22631.4037]" (the word is localized).
    let version = output
        .split(['[', ']'])
        .nth(1)
        .and_then(|s| s.split_whitespace().last())
        .map(str::to_string);
    Some(OsInfo {
        id: "windows".into(),
        pretty_name: Some("Windows".into()),
        version,
        like: Vec::new(),
    })
}

impl OsInfo {
    /// Display name: `PRETTY_NAME` or identifier + version.
    pub fn display(&self) -> String {
        if let Some(p) = &self.pretty_name {
            return p.clone();
        }
        match &self.version {
            Some(v) => format!("{} {v}", self.id),
            None => self.id.clone(),
        }
    }
}

/// Usual package manager of a system (by its id or family).
pub fn package_manager(os: &str) -> Option<&'static str> {
    let os = os.to_lowercase();
    Some(match os.as_str() {
        "ubuntu" | "debian" | "linuxmint" | "pop" | "raspbian" | "kali" | "elementary"
        | "zorin" | "neon" | "devuan" | "pureos" => "apt",
        "fedora" | "rhel" | "centos" | "rocky" | "almalinux" | "ol" | "amzn" | "nobara" => "dnf",
        "arch" | "manjaro" | "endeavouros" | "garuda" | "artix" => "pacman",
        "alpine" | "postmarketos" => "apk",
        "opensuse" | "opensuse-leap" | "opensuse-tumbleweed" | "sles" | "sled" => "zypper",
        "gentoo" => "emerge",
        "void" => "xbps",
        "nixos" => "nix",
        "macos" => "brew",
        "freebsd" => "pkg",
        "openbsd" => "pkg_add",
        "windows" => "winget",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_os_release() {
        let out = "Linux\nNAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n\
                   PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nKERNEL_RELEASE=6.8.0-45-generic\n";
        let i = parse(out).unwrap();
        assert_eq!(i.id, "ubuntu");
        assert_eq!(i.version.as_deref(), Some("24.04"));
        assert_eq!(i.display(), "Ubuntu 24.04.1 LTS");
        assert_eq!(i.like, ["debian"]);
        let mac = parse("Darwin\nMACOS_VERSION=14.5\nKERNEL_RELEASE=23.5.0\n").unwrap();
        assert_eq!(mac.id, "macos");
        assert_eq!(mac.display(), "macOS 14.5");
        let bsd = parse("FreeBSD\nKERNEL_RELEASE=14.1-RELEASE\n").unwrap();
        assert_eq!(bsd.display(), "FreeBSD 14.1-RELEASE");
        assert_eq!(parse(""), None);
        let alpine = parse("Linux\nID=alpine\nVERSION_ID=3.20.3\n").unwrap();
        assert_eq!(alpine.display(), "alpine 3.20.3");
    }

    #[test]
    fn windows_and_package_managers() {
        let w = parse_windows("\r\nMicrosoft Windows [Version 10.0.22631.4037]\r\n").unwrap();
        assert_eq!(w.version.as_deref(), Some("10.0.22631.4037"));
        assert_eq!(package_manager("Ubuntu"), Some("apt"));
        assert_eq!(package_manager("rocky"), Some("dnf"));
        assert_eq!(package_manager("alpine"), Some("apk"));
        assert_eq!(package_manager("macos"), Some("brew"));
        assert_eq!(package_manager("unknown"), None);
    }
}

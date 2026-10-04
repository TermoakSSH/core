//! Reading `~/.ssh/config` (OpenSSH format) to import hosts.
//!
//! Follows the OpenSSH rules that matter for importing:
//! - For each option the **first** value found wins, so `Host *` blocks at the
//!   end only fill in what is missing (and those at the start take precedence).
//! - `Host` patterns support `*`, `?` and negation with `!`.
//! - `Include` is expanded in place (with wildcards and paths relative to
//!   `~/.ssh`), also inside a `Host` block.
//! - `IdentityFile`, `LocalForward`, `RemoteForward`, `DynamicForward` and
//!   `SetEnv` accumulate.
//! - `Match` blocks cannot be evaluated without connecting: they are ignored.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Concrete host (an alias without wildcards) with its effective configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshConfigHost {
    pub alias: String,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    /// Already expanded paths (`~`, `%d`, `%h`, `%r`, `%u`).
    pub identity_files: Vec<PathBuf>,
    pub certificate_files: Vec<PathBuf>,
    /// Jump hosts in order: alias of another host or `[user@]host[:port]`.
    pub proxy_jump: Vec<String>,
    pub forward_agent: Option<bool>,
    pub server_alive_interval: Option<u32>,
    pub local_forwards: Vec<Forward>,
    pub remote_forwards: Vec<Forward>,
    pub dynamic_forwards: Vec<(String, u16)>,
    pub env: BTreeMap<String, String>,
    /// Options that cannot be carried over (to warn about).
    pub unsupported: Vec<String>,
}

/// Forward `[address:]port destination:port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forward {
    pub bind_address: String,
    pub bind_port: u16,
    pub dest_host: String,
    pub dest_port: u16,
}

/// `Host` block (or `Match`, which never matches).
#[derive(Debug, Default)]
struct Block {
    patterns: Vec<String>,
    is_match: bool,
    directives: Vec<(String, String)>,
}

/// Reads a config file and returns its concrete hosts.
pub fn parse_file(path: &Path) -> std::io::Result<Vec<SshConfigHost>> {
    let text = std::fs::read_to_string(path)?;
    let base = path.parent().map(Path::to_path_buf).unwrap_or_else(ssh_dir);
    Ok(parse_str(&text, &base))
}

/// Parses the text of an `ssh_config`. `base` is the directory for relative
/// `Include`s (usually `~/.ssh`).
pub fn parse_str(text: &str, base: &Path) -> Vec<SshConfigHost> {
    let mut lines = Vec::new();
    expand_includes(text, base, 0, &mut lines);
    let mut blocks = vec![Block {
        patterns: vec!["*".into()],
        ..Default::default()
    }];
    for (key, value) in lines {
        match key.as_str() {
            "host" => blocks.push(Block {
                patterns: split_args(&value),
                ..Default::default()
            }),
            "match" => blocks.push(Block {
                is_match: true,
                ..Default::default()
            }),
            _ => blocks
                .last_mut()
                .expect("there is always a block")
                .directives
                .push((key, value)),
        }
    }
    // Concrete aliases, in order of appearance and without duplicates.
    let mut aliases: Vec<String> = Vec::new();
    for b in blocks.iter().filter(|b| !b.is_match) {
        for p in &b.patterns {
            if !p.contains(['*', '?', '!']) && !aliases.iter().any(|a| a == p) {
                aliases.push(p.clone());
            }
        }
    }
    aliases
        .into_iter()
        .map(|alias| resolve(&alias, &blocks))
        .collect()
}

/// `~/.ssh`.
pub fn ssh_dir() -> PathBuf {
    home_dir().join(".ssh")
}

/// Default path: `~/.ssh/config`.
pub fn default_path() -> PathBuf {
    ssh_dir().join("config")
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn local_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_default()
}

/// Splits a line into (lowercase option, value).
fn split_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let end = line
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(line.len());
    let key = line[..end].to_ascii_lowercase();
    let rest = line[end..]
        .trim_start()
        .strip_prefix('=')
        .unwrap_or(line[end..].trim_start())
        .trim();
    Some((key, rest.to_string()))
}

/// Splits arguments, honouring double quotes.
fn split_args(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut any = false;
    for c in value.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => {
                cur.push(c);
                any = true;
            }
        }
    }
    if any {
        out.push(cur);
    }
    out
}

fn expand_includes(text: &str, base: &Path, depth: usize, out: &mut Vec<(String, String)>) {
    for line in text.lines() {
        let Some((key, value)) = split_line(line) else {
            continue;
        };
        if key != "include" {
            out.push((key, value));
            continue;
        }
        if depth >= 16 {
            continue;
        }
        for pattern in split_args(&value) {
            let pattern = expand_tilde(&pattern);
            let full = if Path::new(&pattern).is_absolute() {
                PathBuf::from(&pattern)
            } else {
                base.join(&pattern)
            };
            for file in glob(&full) {
                if let Ok(t) = std::fs::read_to_string(&file) {
                    expand_includes(&t, base, depth + 1, out);
                }
            }
        }
    }
}

/// Wildcards in the last path component (the usual case:
/// `~/.ssh/config.d/*`). Result in alphabetical order, like OpenSSH.
fn glob(path: &Path) -> Vec<PathBuf> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    if !name.contains(['*', '?']) {
        return vec![path.to_path_buf()];
    }
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter(|e| wildcard(&name, &e.file_name().to_string_lossy()))
        .map(|e| e.path())
        .collect();
    files.sort();
    files
}

/// Matching with `*` and `?` (case-insensitive, like OpenSSH for host
/// names).
fn wildcard(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Does the block apply to this alias? Some positive pattern must match and
/// no negated pattern may match.
fn block_matches(patterns: &[String], alias: &str) -> bool {
    let mut positive = false;
    for p in patterns {
        if let Some(neg) = p.strip_prefix('!') {
            if wildcard(neg, alias) {
                return false;
            }
        } else if wildcard(p, alias) {
            positive = true;
        }
    }
    positive
}

fn expand_tilde(s: &str) -> String {
    if s == "~" {
        return home_dir().to_string_lossy().to_string();
    }
    match s.strip_prefix("~/") {
        Some(rest) => home_dir().join(rest).to_string_lossy().to_string(),
        None => s.to_string(),
    }
}

/// Replaces the `IdentityFile` tokens.
fn expand_tokens(s: &str, host: &SshConfigHost) -> PathBuf {
    let s = expand_tilde(s);
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('%') => out.push('%'),
            Some('d') => out.push_str(&home_dir().to_string_lossy()),
            Some('h') => out.push_str(host.hostname.as_deref().unwrap_or(&host.alias)),
            Some('n') => out.push_str(&host.alias),
            Some('r') => out.push_str(host.user.as_deref().unwrap_or("")),
            Some('u') => out.push_str(&local_user()),
            Some('p') => out.push_str(&host.port.unwrap_or(22).to_string()),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    PathBuf::from(out)
}

fn parse_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "yes" | "true" => Some(true),
        "no" | "false" => Some(false),
        _ => None,
    }
}

/// `[address:]port` → (address, port).
fn parse_bind(s: &str) -> Option<(String, u16)> {
    let s = s.trim();
    if let Ok(port) = s.parse() {
        return Some(("127.0.0.1".into(), port));
    }
    // `[::1]:8080` or `0.0.0.0:8080`.
    let (addr, port) = s.rsplit_once(':')?;
    let addr = addr.trim_start_matches('[').trim_end_matches(']');
    let addr = match addr {
        "" | "*" => "0.0.0.0",
        "localhost" => "127.0.0.1",
        a => a,
    };
    Some((addr.to_string(), port.parse().ok()?))
}

/// `host:port` (accepts `[ipv6]:port`).
fn parse_dest(s: &str) -> Option<(String, u16)> {
    let (host, port) = s.trim().rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Some((host.to_string(), port.parse().ok()?))
}

fn parse_forward(value: &str) -> Option<Forward> {
    let args = split_args(value);
    let (bind_address, bind_port) = parse_bind(args.first()?)?;
    let (dest_host, dest_port) = parse_dest(args.get(1)?)?;
    Some(Forward {
        bind_address,
        bind_port,
        dest_host,
        dest_port,
    })
}

/// `ProxyCommand ssh -W %h:%p jump` (or `ssh jump -W %h:%p`) is equivalent to
/// `ProxyJump jump`; anything else cannot be carried over.
fn proxy_command_jump(value: &str) -> Option<String> {
    let args = split_args(value);
    if args.first().map(String::as_str) != Some("ssh") {
        return None;
    }
    let mut jump = None;
    let mut has_w = false;
    let mut user = None;
    let mut port = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-W" => {
                has_w = args.get(i + 1).is_some_and(|a| a == "%h:%p");
                i += 2;
            }
            "-l" => {
                user = args.get(i + 1).cloned();
                i += 2;
            }
            "-p" => {
                port = args.get(i + 1).cloned();
                i += 2;
            }
            "-q" | "-T" | "-A" | "-x" | "-C" => i += 1,
            a if a.starts_with('-') => return None,
            a => {
                if jump.is_some() {
                    return None;
                }
                jump = Some(a.to_string());
                i += 1;
            }
        }
    }
    let mut jump = jump.filter(|_| has_w)?;
    if let Some(u) = user {
        jump = format!("{u}@{jump}");
    }
    if let Some(p) = port {
        jump = format!("{jump}:{p}");
    }
    Some(jump)
}

fn resolve(alias: &str, blocks: &[Block]) -> SshConfigHost {
    let mut h = SshConfigHost {
        alias: alias.to_string(),
        ..Default::default()
    };
    let mut raw_identities: Vec<String> = Vec::new();
    let mut raw_certs: Vec<String> = Vec::new();
    let mut proxy_set = false;
    for b in blocks
        .iter()
        .filter(|b| !b.is_match && block_matches(&b.patterns, alias))
    {
        for (key, value) in &b.directives {
            let value = value.trim();
            match key.as_str() {
                "hostname" if h.hostname.is_none() => h.hostname = Some(value.to_string()),
                "user" if h.user.is_none() => h.user = Some(value.to_string()),
                "port" if h.port.is_none() => h.port = value.parse().ok(),
                "identityfile" => raw_identities.push(value.trim_matches('"').to_string()),
                "certificatefile" => raw_certs.push(value.trim_matches('"').to_string()),
                "proxyjump" if !proxy_set => {
                    proxy_set = true;
                    if !value.eq_ignore_ascii_case("none") {
                        h.proxy_jump = value
                            .split(',')
                            .map(|j| j.trim().trim_start_matches("ssh://").to_string())
                            .filter(|j| !j.is_empty())
                            .collect();
                    }
                }
                "proxycommand" if !proxy_set => {
                    proxy_set = true;
                    if value.eq_ignore_ascii_case("none") {
                        continue;
                    }
                    match proxy_command_jump(value) {
                        Some(j) => h.proxy_jump = vec![j],
                        None => h.unsupported.push(format!("ProxyCommand {value}")),
                    }
                }
                "forwardagent" if h.forward_agent.is_none() => h.forward_agent = parse_bool(value),
                "serveraliveinterval" if h.server_alive_interval.is_none() => {
                    h.server_alive_interval = value.parse().ok();
                }
                "localforward" => {
                    if let Some(f) = parse_forward(value) {
                        h.local_forwards.push(f);
                    }
                }
                "remoteforward" => {
                    if let Some(f) = parse_forward(value) {
                        h.remote_forwards.push(f);
                    }
                }
                "dynamicforward" => {
                    if let Some(b) = parse_bind(value) {
                        h.dynamic_forwards.push(b);
                    }
                }
                "setenv" => {
                    for kv in split_args(value) {
                        if let Some((k, v)) = kv.split_once('=')
                            && !h.env.contains_key(k)
                        {
                            h.env.insert(k.to_string(), v.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
    }
    // `HostName` accepts `%h` (the alias) and `%%`.
    if let Some(hn) = h.hostname.take() {
        h.hostname = Some(hn.replace("%h", alias).replace("%%", "%"));
    }
    let ids: Vec<PathBuf> = raw_identities
        .iter()
        .map(|p| expand_tokens(p, &h))
        .collect();
    let certs: Vec<PathBuf> = raw_certs.iter().map(|p| expand_tokens(p, &h)).collect();
    for p in ids {
        if !h.identity_files.contains(&p) {
            h.identity_files.push(p);
        }
    }
    h.certificate_files = certs;
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
# Global options before any Host
ServerAliveInterval 30

Host bastion
    HostName bastion.example.com
    User ops
    Port 2222
    IdentityFile ~/.ssh/id_bastion

Host web1 web2
    HostName %h.internal
    User deploy
    ProxyJump bastion
    LocalForward 8080 localhost:80
    LocalForward 0.0.0.0:9090 [::1]:9090
    DynamicForward 1080
    SetEnv LANG=es_ES.UTF-8 EDITOR=vim

Host db
    HostName 10.0.0.9
    ProxyCommand ssh -q -W %h:%p ops@bastion.example.com
    RemoteForward 5432 localhost:5432
    ForwardAgent yes

Host legacy
    ProxyCommand nc -X 5 -x proxy:1080 %h %p

Host *.example.com !secret.example.com
    User wildcard

Host "with space"
    HostName 192.0.2.1

Match exec "true"
    User never

Host *
    User root
    IdentityFile ~/.ssh/id_ed25519
    ForwardAgent no
"#;

    fn find<'a>(hosts: &'a [SshConfigHost], alias: &str) -> &'a SshConfigHost {
        hosts.iter().find(|h| h.alias == alias).unwrap()
    }

    #[test]
    fn parses_hosts_with_openssh_precedence() {
        let hosts = parse_str(CONFIG, Path::new("/nonexistent"));
        let aliases: Vec<_> = hosts.iter().map(|h| h.alias.as_str()).collect();
        assert_eq!(
            aliases,
            ["bastion", "web1", "web2", "db", "legacy", "with space"]
        );

        let b = find(&hosts, "bastion");
        assert_eq!(b.hostname.as_deref(), Some("bastion.example.com"));
        assert_eq!(b.user.as_deref(), Some("ops")); // the first one beats `Host *`
        assert_eq!(b.port, Some(2222));
        assert_eq!(b.server_alive_interval, Some(30)); // global option
        assert_eq!(b.forward_agent, Some(false)); // from `Host *`
        let ids: Vec<String> = b
            .identity_files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(ids, ["id_bastion", "id_ed25519"]); // they accumulate

        let w = find(&hosts, "web2");
        assert_eq!(w.hostname.as_deref(), Some("web2.internal")); // `%h` is the alias
        assert_eq!(w.proxy_jump, ["bastion"]);
        assert_eq!(w.local_forwards.len(), 2);
        assert_eq!(w.local_forwards[0].bind_address, "127.0.0.1");
        assert_eq!(w.local_forwards[0].dest_host, "localhost");
        assert_eq!(w.local_forwards[1].bind_address, "0.0.0.0");
        assert_eq!(w.local_forwards[1].dest_host, "::1");
        assert_eq!(w.dynamic_forwards, [("127.0.0.1".to_string(), 1080)]);
        assert_eq!(w.env.get("EDITOR").map(String::as_str), Some("vim"));

        let db = find(&hosts, "db");
        assert_eq!(db.proxy_jump, ["ops@bastion.example.com"]);
        assert_eq!(db.remote_forwards[0].bind_port, 5432);
        assert_eq!(db.forward_agent, Some(true));
        assert_eq!(db.user.as_deref(), Some("root"));

        let legacy = find(&hosts, "legacy");
        assert!(legacy.proxy_jump.is_empty());
        assert_eq!(legacy.unsupported.len(), 1);

        // `Match` never applies; the quoted alias is kept.
        assert_eq!(find(&hosts, "with space").user.as_deref(), Some("root"));
    }

    #[test]
    fn wildcards_and_negation() {
        assert!(wildcard("*.example.com", "a.example.com"));
        assert!(wildcard("web?", "WEB1"));
        assert!(!wildcard("web?", "web10"));
        let pats = vec![
            "*.example.com".to_string(),
            "!secret.example.com".to_string(),
        ];
        assert!(block_matches(&pats, "a.example.com"));
        assert!(!block_matches(&pats, "secret.example.com"));
    }

    #[test]
    fn includes_and_equals_syntax() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("config.d")).unwrap();
        std::fs::write(
            dir.path().join("config.d/10-work"),
            "Host work\n  HostName=work.example.com\n  Port=2200\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("config.d/20-home"),
            "Host home\n  HostName 192.168.1.2\n",
        )
        .unwrap();
        let hosts = parse_str("Include config.d/*\nHost *\n  User me\n", dir.path());
        let aliases: Vec<_> = hosts.iter().map(|h| h.alias.as_str()).collect();
        assert_eq!(aliases, ["work", "home"]);
        assert_eq!(hosts[0].port, Some(2200));
        assert_eq!(hosts[1].user.as_deref(), Some("me"));
    }
}

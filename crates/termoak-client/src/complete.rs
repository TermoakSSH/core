//! Command autocompletion for the terminal (like Termius's).
//!
//! While a line is being typed, it suggests how to finish it from:
//! 1. the history of that host (and of the others, if that is not enough),
//!    which lives only on this device;
//! 2. single-line snippets without variables;
//! 3. a dictionary of common commands that depends on the host's system
//!    (`apt` on Ubuntu, `dnf` on Fedora, `apk` on Alpine, `brew` on macOS…).
//!
//! The UI shows the first suggestion as ghost text and the rest in a list;
//! accepting one types what is missing (`insert`) into the terminal.

use serde::Serialize;
use termoak_core::Id;
use termoak_core::model::Snippet;
use termoak_core::store::history::HistoryEntry;
use termoak_ssh::detect::package_manager;

use crate::error::Result;
use crate::workspace::Workspace;

/// Where a suggestion comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuggestionSource {
    History,
    Snippet,
    Command,
}

/// A suggestion to complete the line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Suggestion {
    /// Full suggested line.
    pub text: String,
    /// What is left to type (sent when accepted).
    pub insert: String,
    /// Short explanation (for the list).
    pub description: String,
    pub source: SuggestionSource,
}

/// Which family of commands makes sense on a system.
fn family(os: Option<&str>) -> Family {
    match os.map(str::to_lowercase).as_deref() {
        Some("windows") => Family::Windows,
        Some("macos") => Family::Mac,
        Some("freebsd" | "openbsd" | "netbsd") => Family::Bsd,
        _ => Family::Linux,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Linux,
    Mac,
    Bsd,
    Windows,
}

/// Dictionary entry: (requirement, command, description). The requirement is
/// a package manager (`apt`, `dnf`…), a family (`linux`, `unix`, `mac`,
/// `win`) or empty (any Unix).
type Entry = (&'static str, &'static str, &'static str);

const DICTIONARY: &[Entry] = &[
    // System and processes
    ("unix", "uptime", "uptime and load"),
    ("unix", "df -h", "disk space"),
    ("unix", "du -sh *", "size of each item in the directory"),
    ("linux", "free -h", "free memory"),
    ("unix", "top", "live processes"),
    ("unix", "htop", "live processes (improved)"),
    ("unix", "ps aux", "all processes"),
    (
        "unix",
        "ps aux --sort=-%mem | head",
        "processes using the most memory",
    ),
    (
        "unix",
        "ps aux --sort=-%cpu | head",
        "processes using the most CPU",
    ),
    ("unix", "kill -9 ", "kill a process"),
    ("unix", "uname -a", "kernel and architecture"),
    ("linux", "cat /etc/os-release", "distribution and version"),
    ("linux", "lsblk", "disks and partitions"),
    ("linux", "lscpu", "CPU information"),
    ("unix", "whoami", "current user"),
    ("unix", "last -n 20", "recent logins"),
    ("unix", "who", "logged-in users"),
    ("unix", "history | tail -50", "recent commands"),
    ("unix", "sudo -i", "root shell"),
    ("unix", "reboot", "reboot"),
    ("linux", "shutdown -h now", "shut down now"),
    // Files
    ("unix", "ls -la", "list with details and hidden files"),
    ("unix", "ls -lah", "list with readable sizes"),
    ("unix", "cd ..", "go up one directory"),
    ("unix", "tail -f ", "follow a file"),
    ("unix", "tail -n 100 ", "last 100 lines"),
    ("unix", "less ", "view a file"),
    ("unix", "grep -rn ", "search text recursively"),
    ("unix", "find . -name ", "find files by name"),
    ("unix", "chmod +x ", "make executable"),
    ("unix", "chown -R ", "change owner"),
    ("unix", "tar -czf ", "compress to .tar.gz"),
    ("unix", "tar -xzf ", "extract .tar.gz"),
    ("unix", "rsync -avz --progress ", "copy/sync"),
    ("unix", "scp ", "copy over SSH"),
    ("unix", "ln -s ", "symbolic link"),
    ("unix", "mkdir -p ", "create directories"),
    ("unix", "cp -r ", "copy recursively"),
    ("unix", "nano ", "edit with nano"),
    ("unix", "vim ", "edit with vim"),
    // Network
    ("unix", "ping -c 4 ", "check connectivity"),
    ("unix", "curl -I ", "HTTP headers"),
    ("unix", "curl -sS ", "HTTP request"),
    ("unix", "wget ", "download"),
    ("linux", "ip a", "interfaces and addresses"),
    ("linux", "ip route", "routing table"),
    ("linux", "ss -tulpn", "listening ports"),
    ("unix", "netstat -tulpn", "listening ports (classic)"),
    ("unix", "dig ", "DNS lookup"),
    ("unix", "nslookup ", "DNS lookup"),
    ("unix", "traceroute ", "route to a host"),
    ("linux", "ufw status", "firewall status (ufw)"),
    ("linux", "iptables -L -n -v", "firewall rules"),
    // Services and logs (systemd)
    ("linux", "systemctl status ", "service status"),
    ("linux", "systemctl restart ", "restart a service"),
    ("linux", "systemctl start ", "start a service"),
    ("linux", "systemctl stop ", "stop a service"),
    ("linux", "systemctl enable --now ", "enable and start"),
    ("linux", "systemctl list-units --failed", "failed services"),
    ("linux", "systemctl daemon-reload", "reload units"),
    ("linux", "journalctl -u ", "service log"),
    ("linux", "journalctl -xe", "latest system errors"),
    ("linux", "journalctl -f", "follow the system log"),
    (
        "linux",
        "journalctl --disk-usage",
        "disk space used by logs",
    ),
    ("linux", "dmesg -T | tail", "kernel messages"),
    // Package managers
    ("apt", "sudo apt update", "update the package list"),
    ("apt", "sudo apt upgrade", "upgrade packages"),
    ("apt", "sudo apt install ", "install packages"),
    ("apt", "sudo apt remove ", "remove packages"),
    ("apt", "sudo apt autoremove", "remove unused dependencies"),
    ("apt", "apt search ", "search packages"),
    ("apt", "apt list --upgradable", "upgradable packages"),
    ("dnf", "sudo dnf check-update", "check for updates"),
    ("dnf", "sudo dnf upgrade", "upgrade packages"),
    ("dnf", "sudo dnf install ", "install packages"),
    ("dnf", "sudo dnf remove ", "remove packages"),
    ("dnf", "dnf search ", "search packages"),
    ("pacman", "sudo pacman -Syu", "upgrade the system"),
    ("pacman", "sudo pacman -S ", "install packages"),
    ("pacman", "sudo pacman -Rns ", "remove packages"),
    ("pacman", "pacman -Ss ", "search packages"),
    ("apk", "apk update", "update the package list"),
    ("apk", "apk upgrade", "upgrade packages"),
    ("apk", "apk add ", "install packages"),
    ("apk", "apk del ", "remove packages"),
    ("apk", "apk search ", "search packages"),
    ("zypper", "sudo zypper refresh", "refresh repositories"),
    ("zypper", "sudo zypper update", "upgrade packages"),
    ("zypper", "sudo zypper install ", "install packages"),
    ("brew", "brew update", "update Homebrew"),
    ("brew", "brew upgrade", "upgrade packages"),
    ("brew", "brew install ", "install packages"),
    ("brew", "brew services list", "Homebrew services"),
    ("pkg", "pkg update", "update the catalog"),
    ("pkg", "pkg upgrade", "upgrade packages"),
    ("pkg", "pkg install ", "install packages"),
    ("mac", "sw_vers", "macOS version"),
    ("mac", "vm_stat", "memory"),
    ("mac", "launchctl list", "services"),
    // Docker and Kubernetes
    ("unix", "docker ps", "running containers"),
    ("unix", "docker ps -a", "all containers"),
    ("unix", "docker logs -f ", "follow a container's log"),
    ("unix", "docker exec -it ", "open a shell in a container"),
    ("unix", "docker images", "images"),
    (
        "unix",
        "docker stats --no-stream",
        "container resource usage",
    ),
    ("unix", "docker system df", "disk space used by Docker"),
    ("unix", "docker system prune", "clean up unused data"),
    ("unix", "docker compose up -d", "start the services"),
    ("unix", "docker compose down", "stop the services"),
    ("unix", "docker compose logs -f", "follow the logs"),
    ("unix", "docker compose pull", "pull new images"),
    ("unix", "docker compose ps", "service status"),
    ("unix", "kubectl get pods -A", "pods in all namespaces"),
    ("unix", "kubectl get nodes", "nodes"),
    ("unix", "kubectl logs -f ", "follow a pod's log"),
    ("unix", "kubectl describe pod ", "pod details"),
    ("unix", "kubectl exec -it ", "open a shell in a pod"),
    // Git
    ("unix", "git status", "repository status"),
    ("unix", "git pull", "pull changes"),
    ("unix", "git log --oneline -20", "recent commits"),
    ("unix", "git diff", "unstaged changes"),
    ("unix", "git checkout ", "switch branch"),
    ("unix", "git branch -a", "branches"),
    // Web servers and databases
    ("unix", "nginx -t", "check the nginx configuration"),
    ("linux", "systemctl reload nginx", "reload nginx"),
    ("unix", "tail -f /var/log/nginx/error.log", "nginx errors"),
    ("unix", "tail -f /var/log/syslog", "system log"),
    (
        "unix",
        "certbot renew --dry-run",
        "test certificate renewal",
    ),
    ("unix", "mysql -u root -p", "MySQL console"),
    ("unix", "psql -U postgres", "PostgreSQL console"),
    ("unix", "redis-cli ping", "check Redis"),
    ("unix", "crontab -l", "scheduled jobs"),
    ("unix", "crontab -e", "edit scheduled jobs"),
    // Windows (PowerShell)
    ("win", "Get-Process", "processes"),
    ("win", "Get-Service", "services"),
    ("win", "Restart-Service ", "restart a service"),
    (
        "win",
        "Get-EventLog -LogName System -Newest 20",
        "latest system events",
    ),
    ("win", "Get-ComputerInfo", "computer information"),
    ("win", "Get-NetIPAddress", "IP addresses"),
    ("win", "Test-NetConnection ", "check connectivity"),
    ("win", "Get-ChildItem", "list"),
    ("win", "winget upgrade --all", "upgrade programs"),
    ("win", "winget install ", "install programs"),
];

/// Does the entry apply to this system?
fn applies(req: &str, os: Option<&str>) -> bool {
    let fam = family(os);
    match req {
        "win" => fam == Family::Windows,
        "mac" => fam == Family::Mac,
        "linux" => fam == Family::Linux,
        "unix" | "" => fam != Family::Windows,
        pm => match os.and_then(package_manager) {
            Some(own) => own == pm,
            // Unknown system: offer the most common ones.
            None => fam == Family::Linux && matches!(pm, "apt" | "dnf"),
        },
    }
}

/// Dictionary suggestions for a line.
pub fn dictionary(line: &str, os: Option<&str>, limit: usize) -> Vec<Suggestion> {
    if line.trim().is_empty() {
        return Vec::new();
    }
    let windows = family(os) == Family::Windows;
    let matches = |cmd: &str| {
        cmd.len() > line.len()
            && if windows {
                // PowerShell is case-insensitive.
                cmd.to_lowercase().starts_with(&line.to_lowercase())
            } else {
                cmd.starts_with(line)
            }
    };
    DICTIONARY
        .iter()
        .filter(|(req, _, _)| applies(req, os))
        .filter_map(|(_, cmd, desc)| {
            // Whoever does not type `sudo` (e.g. is already root) also gets
            // the suggestion, without it.
            [Some(*cmd), cmd.strip_prefix("sudo ")]
                .into_iter()
                .flatten()
                .find(|c| matches(c))
                .map(|c| Suggestion {
                    text: c.to_string(),
                    insert: c.get(line.len()..).unwrap_or_default().to_string(),
                    description: desc.to_string(),
                    source: SuggestionSource::Command,
                })
        })
        .take(limit)
        .collect()
}

impl Workspace {
    /// Suggestions to complete `line` in a terminal on `host` (with its
    /// detected system, if known).
    pub async fn complete(
        &self,
        host: Option<Id>,
        os: Option<&str>,
        line: &str,
        limit: usize,
    ) -> Result<Vec<Suggestion>> {
        let limit = limit.clamp(1, 50);
        // Nothing typed (or only spaces): no suggestions.
        if line.trim().is_empty() {
            return Ok(Vec::new());
        }
        let mut out: Vec<Suggestion> = Vec::new();
        let push = |out: &mut Vec<Suggestion>, s: Suggestion| {
            if out.len() < limit && s.text != line && !out.iter().any(|o| o.text == s.text) {
                out.push(s);
            }
        };
        for h in self
            .store
            .history_search(self.owner(), host, line, limit)
            .await?
        {
            let Some(insert) = h.command.strip_prefix(line).map(str::to_string) else {
                continue;
            };
            push(
                &mut out,
                Suggestion {
                    insert,
                    description: format!(
                        "history · {} {}",
                        h.uses,
                        if h.uses == 1 { "use" } else { "uses" }
                    ),
                    text: h.command,
                    source: SuggestionSource::History,
                },
            );
        }
        if out.len() < limit {
            for s in self.store.list::<Snippet>(self.owner()).await? {
                let script = s.data.script.trim_end();
                if script.contains('\n') || !s.data.variables().is_empty() {
                    continue;
                }
                if let Some(rest) = script.strip_prefix(line) {
                    push(
                        &mut out,
                        Suggestion {
                            text: script.to_string(),
                            insert: rest.to_string(),
                            description: format!("snippet · {}", s.data.name),
                            source: SuggestionSource::Snippet,
                        },
                    );
                }
            }
        }
        if out.len() < limit {
            for s in dictionary(line, os, limit) {
                push(&mut out, s);
            }
        }
        Ok(out)
    }

    /// Saves a command that was run to the host's history (only on this
    /// device). Commands that look like they contain secrets are not saved.
    pub async fn record_command(&self, host: Id, command: &str) -> Result<bool> {
        Ok(self
            .store
            .history_record(self.owner(), host, command)
            .await?)
    }

    /// History to show in a list: the host's commands first and, if there are
    /// not enough, those of the other hosts, by use and recency. `query`
    /// filters by content (case-insensitive).
    pub async fn command_history(
        &self,
        host: Option<Id>,
        query: &str,
        limit: usize,
    ) -> Result<Vec<HistoryEntry>> {
        let limit = limit.clamp(1, 500);
        let query = query.trim().to_lowercase();
        // To filter, look at all of them (a few thousand per device at most).
        let fetch = if query.is_empty() { limit } else { 5000 };
        let all = self
            .store
            .history_search(self.owner(), host, "", fetch)
            .await?;
        Ok(all
            .into_iter()
            .filter(|h| query.is_empty() || h.command.to_lowercase().contains(&query))
            .take(limit)
            .collect())
    }

    /// Clears a host's history (or all of it).
    pub async fn clear_history(&self, host: Option<Id>) -> Result<()> {
        Ok(self.store.history_clear(self.owner(), host).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use termoak_core::crypto::MasterKey;
    use termoak_core::model::SecretUpdate;
    use termoak_core::new_id;

    #[test]
    fn dictionary_depends_on_os() {
        let ubuntu = dictionary("sudo a", Some("ubuntu"), 10);
        assert!(ubuntu.iter().any(|s| s.text == "sudo apt update"));
        assert_eq!(ubuntu[0].insert, ubuntu[0].text["sudo a".len()..]);
        assert!(dictionary("sudo a", Some("fedora"), 10).is_empty());
        assert!(
            dictionary("sudo d", Some("rocky"), 10)
                .iter()
                .any(|s| s.text.starts_with("sudo dnf"))
        );
        assert!(
            dictionary("apk", Some("alpine"), 10)
                .iter()
                .any(|s| s.text == "apk update")
        );
        assert!(dictionary("apk", Some("ubuntu"), 10).is_empty());
        assert!(dictionary("brew", Some("macos"), 10).len() >= 3);
        assert!(dictionary("systemctl", Some("macos"), 10).is_empty());
        // On Windows, PowerShell is case-insensitive and there are no Unix commands.
        let win = dictionary("get-s", Some("windows"), 10);
        assert_eq!(win[0].text, "Get-Service");
        assert!(dictionary("ls", Some("windows"), 10).is_empty());
        // Unknown system: Linux commands and the most common package managers.
        assert!(
            dictionary("sudo a", None, 10)
                .iter()
                .any(|s| s.text == "sudo apt update")
        );
        assert!(dictionary("", Some("ubuntu"), 10).is_empty());
    }

    #[tokio::test]
    async fn history_snippets_and_dictionary_merge() {
        let dir = tempfile::tempdir().unwrap();
        let ws = Workspace::open(dir.path(), MasterKey::generate()).unwrap();
        let host = new_id();
        ws.record_command(host, "docker compose logs -f web")
            .await
            .unwrap();
        ws.record_command(host, "docker compose logs -f web")
            .await
            .unwrap();
        ws.store
            .save(
                ws.owner(),
                Snippet {
                    id: new_id(),
                    name: "Restart stack".into(),
                    script: "docker compose restart".into(),
                    description: String::new(),
                    tags: vec![],
                },
                SecretUpdate::Keep,
                None,
            )
            .await
            .unwrap();
        ws.store
            .save(
                ws.owner(),
                Snippet {
                    id: new_id(),
                    name: "With variable".into(),
                    script: "docker compose logs {{service}}".into(),
                    description: String::new(),
                    tags: vec![],
                },
                SecretUpdate::Keep,
                None,
            )
            .await
            .unwrap();
        let s = ws
            .complete(Some(host), Some("debian"), "docker comp", 10)
            .await
            .unwrap();
        assert_eq!(s[0].text, "docker compose logs -f web");
        assert_eq!(s[0].source, SuggestionSource::History);
        assert_eq!(s[0].insert, "ose logs -f web");
        assert_eq!(s[1].source, SuggestionSource::Snippet);
        assert!(s[2..].iter().all(|x| x.source == SuggestionSource::Command));
        // Snippets with variables are not offered; no duplicates.
        assert!(!s.iter().any(|x| x.text.contains("{{")));
        let mut texts: Vec<_> = s.iter().map(|x| x.text.clone()).collect();
        texts.dedup();
        assert_eq!(texts.len(), s.len());
        // What has been fully typed already is not suggested.
        let exact = ws
            .complete(Some(host), None, "docker compose logs -f web", 5)
            .await
            .unwrap();
        assert!(exact.iter().all(|x| x.text != "docker compose logs -f web"));
        // What looks like a secret is not saved.
        assert!(!ws.record_command(host, "export API_KEY=abc").await.unwrap());
        ws.clear_history(Some(host)).await.unwrap();
        let after = ws
            .complete(Some(host), None, "docker compose l", 5)
            .await
            .unwrap();
        assert!(after.iter().all(|x| x.source != SuggestionSource::History));
    }
}

//! Status of the hosts in the hosts list, without connecting: a light TCP
//! connection to the host's SSH port (through its proxy, if it has one) that
//! is closed as soon as it opens. No SSH, no authentication, nothing in the
//! host's logs beyond an accepted and closed connection; only `debug` logs
//! here.
//!
//! - Green: it answered (with the time the connection took, "23 ms").
//! - Red: refused, timed out or the name does not resolve.
//! - Gray: unknown. Not checked yet, or not checked at all: hosts behind
//!   jump hosts (the path is inside SSH), hosts of Strict vaults (they are
//!   only reached through the server), proxies that need a password the
//!   user cannot read (Use-only), and hosts with the check turned off.
//!
//! The apps check the hosts on screen in the background, at most
//! [`CONCURRENCY`] at a time, every [`EVERY`] while the hosts list is in
//! view, and at once with "Check now" ([`Book`] schedules them). It is an
//! opt-in setting of each app; the host menu can turn it off for one host
//! on the device.
//!
//! [`Workspace::probe_hosts`] does everything for a list of host items
//! (settings inherited from groups, Strict vaults, Use-only proxies, the
//! proxy password); the pure parts ([`target_of`], [`Book`]) are what the
//! desktop's hosts list uses with its own model. The TCP check itself is
//! `termoak_ssh::probe`. Moved from the desktop.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use futures::StreamExt;
use termoak_core::Id;
use termoak_core::model::{Group, Host, HostSecret, HostSettings, ProxyKind, ProxySettings};
use termoak_core::resolve::ResolvedProxy;
use termoak_core::time::now_ms;
use zeroize::Zeroize;

use crate::error::Result as ClientResult;
use crate::items::{ItemRef, Scope};
use crate::workspace::Workspace;
use crate::LOCAL_OWNER;

/// Time between checks of a host while the list is on screen.
pub const EVERY: Duration = Duration::from_secs(60);
/// Most checks running at the same time.
pub const CONCURRENCY: usize = 8;
/// Longest wait for a host (then it is unreachable).
pub const TIMEOUT: Duration = Duration::from_secs(5);
/// Most levels of nested groups followed for inherited settings (as the core).
const MAX_DEPTH: usize = 16;

/// Where a check connects to. A host whose target changed (edited address,
/// port or proxy) is checked again.
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    pub address: String,
    pub port: u16,
    pub proxy: Option<ProxySettings>,
}

/// Why a host is not checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// Turned off for this host.
    Off,
    /// Reached through jump hosts.
    Jump,
    /// Strict vault: only through the server.
    Strict,
    /// Its proxy needs a password this user cannot read (Use-only).
    UseOnly,
}

/// A host to check.
#[derive(Debug, Clone, PartialEq)]
pub struct Probe {
    pub host_id: Id,
    pub target: Target,
    /// Where its proxy password is (only when the proxy needs one).
    pub secret: Option<ItemRef>,
}

/// Result of a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// It answered after this long.
    Up(Duration),
    Down,
}

/// What is known of a host.
#[derive(Debug, Clone, PartialEq)]
struct Entry {
    target: Target,
    reach: Reach,
    at: Instant,
}

/// What the card shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shown {
    Up {
        rtt: Duration,
        ago: Duration,
    },
    Down {
        ago: Duration,
    },
    /// Not checked yet (or its target changed and the new one is pending).
    Pending,
    Skipped(Skip),
}

/// Effective settings of a host: those of its groups, from the outermost,
/// with its own on top (like the core's resolver).
pub fn effective_settings(host: &Host, groups: &[&Group]) -> HostSettings {
    let mut chain: Vec<&Group> = Vec::new();
    let mut seen = HashSet::new();
    let mut next = host.group_id;
    while let Some(gid) = next {
        if !seen.insert(gid) || chain.len() >= MAX_DEPTH {
            break;
        }
        match groups.iter().find(|g| g.id == gid) {
            Some(g) => {
                next = g.parent_id;
                chain.push(g);
            }
            None => break,
        }
    }
    let mut settings = HostSettings::default();
    for g in chain.iter().rev() {
        settings = settings.overlay(&g.settings);
    }
    settings.overlay(&host.settings)
}

/// What to check for a host, or why not.
pub fn target_of(
    host: &Host,
    settings: &HostSettings,
    strict: bool,
    can_read_secrets: bool,
    off: bool,
) -> Result<(Target, bool), Skip> {
    if off {
        return Err(Skip::Off);
    }
    if strict {
        return Err(Skip::Strict);
    }
    if settings
        .jump_host_ids
        .as_ref()
        .is_some_and(|j| !j.is_empty())
    {
        return Err(Skip::Jump);
    }
    let proxy = settings
        .proxy
        .clone()
        .filter(|p| !p.host.trim().is_empty() && p.port != 0);
    // SOCKS4 sends only a user id; SOCKS5 and HTTP send a password too.
    let needs_password = proxy.as_ref().is_some_and(|p| {
        p.kind != ProxyKind::Socks4 && p.username.as_deref().is_some_and(|u| !u.is_empty())
    });
    if needs_password && !can_read_secrets {
        return Err(Skip::UseOnly);
    }
    let address = host
        .address
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    Ok((
        Target {
            address,
            port: settings.port.unwrap_or(host.protocol.default_port()),
            proxy,
        },
        needs_password,
    ))
}

/// What is known of every host, and which checks are running.
#[derive(Debug, Default)]
pub struct Book {
    entries: HashMap<Id, Entry>,
    running: HashSet<Id>,
}

impl Book {
    /// Hosts to check now: not running, and never checked, checked
    /// `every` ago or more, or with a different target. Never checked
    /// first.
    pub fn due(&self, targets: &[(Id, &Target)], now: Instant, every: Duration) -> Vec<Id> {
        let mut fresh = Vec::new();
        let mut stale: Vec<(Instant, Id)> = Vec::new();
        for (id, target) in targets {
            if self.running.contains(id) {
                continue;
            }
            match self.entries.get(id) {
                Some(e) if e.target != **target => fresh.push(*id),
                Some(e) if now.saturating_duration_since(e.at) >= every => stale.push((e.at, *id)),
                Some(_) => {}
                None => fresh.push(*id),
            }
        }
        stale.sort_by_key(|(at, _)| *at);
        fresh.extend(stale.into_iter().map(|(_, id)| id));
        fresh
    }

    /// When the next host of `targets` is due (`None`: one is running and
    /// the others are fresh, or there are none).
    pub fn next_due(
        &self,
        targets: &[(Id, &Target)],
        now: Instant,
        every: Duration,
    ) -> Option<Duration> {
        targets
            .iter()
            .filter(|(id, _)| !self.running.contains(id))
            .map(|(id, target)| match self.entries.get(id) {
                Some(e) if e.target == **target => (e.at + every).saturating_duration_since(now),
                _ => Duration::ZERO,
            })
            .min()
    }

    pub fn start(&mut self, ids: &[Id]) {
        self.running.extend(ids.iter().copied());
    }

    pub fn is_running(&self, id: Id) -> bool {
        self.running.contains(&id)
    }

    pub fn finish(&mut self, id: Id, target: Target, reach: Reach, now: Instant) {
        self.running.remove(&id);
        self.entries.insert(
            id,
            Entry {
                target,
                reach,
                at: now,
            },
        );
    }

    /// What a card shows for a host whose check is `target`.
    pub fn shown(&self, id: Id, target: Result<&Target, Skip>, now: Instant) -> Shown {
        let target = match target {
            Ok(t) => t,
            Err(skip) => return Shown::Skipped(skip),
        };
        match self.entries.get(&id) {
            Some(e) if e.target == *target => {
                let ago = now.saturating_duration_since(e.at);
                match e.reach {
                    Reach::Up(rtt) => Shown::Up { rtt, ago },
                    Reach::Down => Shown::Down { ago },
                }
            }
            _ => Shown::Pending,
        }
    }
}

/// Connects to the target (through its proxy) and closes at once.
pub async fn check(target: &Target, proxy_password: Option<&str>) -> Reach {
    let proxy = target.proxy.clone().map(|settings| ResolvedProxy {
        settings,
        password: proxy_password.map(str::to_string),
    });
    let reach = match termoak_ssh::probe::tcp_probe(
        &target.address,
        target.port,
        proxy.as_ref(),
        TIMEOUT,
    )
    .await
    {
        Some(rtt) => Reach::Up(rtt),
        None => Reach::Down,
    };
    if let Some(mut p) = proxy
        && let Some(pw) = p.password.as_mut()
    {
        pw.zeroize();
    }
    reach
}

/// Checks probes, at most `concurrency` at a time, reading the proxy
/// password of the ones that need it. Results in the order they finish.
pub async fn run(ws: &Workspace, probes: Vec<Probe>, concurrency: usize) -> Vec<(Probe, Reach)> {
    futures::stream::iter(probes)
        .map(|p| async move {
            let mut password = match p.secret {
                Some(item) => ws
                    .item_secret::<Host>(item)
                    .await
                    .ok()
                    .and_then(|s: HostSecret| s.proxy_password),
                None => None,
            };
            let reach = check(&p.target, password.as_deref()).await;
            password.zeroize();
            tracing::debug!(host = %p.host_id, ?reach, "host status");
            (p, reach)
        })
        .buffer_unordered(concurrency.max(1))
        .collect()
        .await
}

/// What a check found for a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStatus {
    /// It answered after `rtt`.
    Up(Duration),
    /// Refused, timed out or the name does not resolve.
    Down,
    /// Not checked, and why.
    Skipped(Skip),
}

/// The check of one host item.
#[derive(Debug, Clone, PartialEq)]
pub struct HostProbe {
    pub item: ItemRef,
    pub status: ProbeStatus,
    /// When it was checked (ms since the epoch).
    pub checked_at: i64,
    /// Where it was checked (`None` when skipped).
    pub target: Option<Target>,
}

impl Workspace {
    /// What to check for a host item, or why not (`off`: the user turned
    /// the check off for it). Settings come from its groups; hosts of
    /// Strict vaults are skipped, and so are proxies whose password a
    /// Use-only user cannot read.
    pub async fn probe_of(&self, item: ItemRef, off: bool) -> ClientResult<Result<Probe, Skip>> {
        let rec = self.get_item::<Host>(item).await?;
        let store = self.store_of(item.scope)?;
        let host = rec.record.data;
        let settings = store.effective_settings(LOCAL_OWNER, &host).await?;
        let strict = match (item.scope, rec.record.meta.vault_id) {
            (Scope::Account(a), Some(vault)) => self.require_account(a)?.is_strict(vault).await?,
            _ => false,
        };
        Ok(
            target_of(&host, &settings, strict, rec.access.can_read_secrets(), off).map(
                |(target, needs_password)| Probe {
                    host_id: host.id,
                    target,
                    secret: needs_password.then_some(item),
                },
            ),
        )
    }

    /// Checks host items (at most `concurrency` at a time; 0: [`CONCURRENCY`])
    /// and answers in the same order. Items that are not hosts or cannot be
    /// read come back `Down`; `off` lists the hosts whose check the user
    /// turned off.
    pub async fn probe_hosts(
        &self,
        items: &[ItemRef],
        off: &[Id],
        concurrency: usize,
    ) -> Vec<HostProbe> {
        let concurrency = if concurrency == 0 { CONCURRENCY } else { concurrency };
        let mut out: Vec<HostProbe> = Vec::with_capacity(items.len());
        let mut probes: Vec<(usize, Probe)> = Vec::new();
        for (i, item) in items.iter().enumerate() {
            let status = match self.probe_of(*item, off.contains(&item.id)).await {
                Ok(Ok(p)) => {
                    out.push(HostProbe {
                        item: *item,
                        status: ProbeStatus::Down,
                        checked_at: 0,
                        target: Some(p.target.clone()),
                    });
                    probes.push((i, p));
                    continue;
                }
                Ok(Err(skip)) => ProbeStatus::Skipped(skip),
                Err(e) => {
                    tracing::debug!(host = %item.id, error = %e, "host status: not readable");
                    ProbeStatus::Down
                }
            };
            out.push(HostProbe {
                item: *item,
                status,
                checked_at: now_ms(),
                target: None,
            });
        }
        let index: HashMap<Id, Vec<usize>> = probes.iter().fold(HashMap::new(), |mut m, (i, p)| {
            m.entry(p.host_id).or_default().push(*i);
            m
        });
        let results = run(self, probes.into_iter().map(|(_, p)| p).collect(), concurrency).await;
        let mut taken: HashSet<usize> = HashSet::new();
        for (p, reach) in results {
            let Some(i) = index
                .get(&p.host_id)
                .and_then(|l| l.iter().find(|i| !taken.contains(*i)))
                .copied()
            else {
                continue;
            };
            taken.insert(i);
            out[i].status = match reach {
                Reach::Up(rtt) => ProbeStatus::Up(rtt),
                Reach::Down => ProbeStatus::Down,
            };
            out[i].checked_at = now_ms();
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use termoak_core::new_id;

    fn host(group: Option<Id>, settings: HostSettings) -> Host {
        Host {
            id: new_id(),
            label: "web".into(),
            address: "web.example".into(),
            group_id: group,
            tags: Vec::new(),
            settings,
            notes: String::new(),
            color: None,
            os: None,
            os_version: None,
            favorite: false,
            protocol: Default::default(),
            icon: None,
        }
    }

    fn group(id: Id, parent: Option<Id>, settings: HostSettings) -> Group {
        Group {
            id,
            name: "g".into(),
            parent_id: parent,
            color: None,
            settings,
        }
    }

    fn target(port: u16) -> Target {
        Target {
            address: "h".into(),
            port,
            proxy: None,
        }
    }

    #[test]
    fn settings_come_from_the_groups() {
        let (outer, inner) = (new_id(), new_id());
        let groups = [
            group(
                outer,
                None,
                HostSettings {
                    port: Some(2200),
                    proxy: Some(ProxySettings {
                        kind: ProxyKind::Http,
                        host: "proxy".into(),
                        port: 3128,
                        username: None,
                    }),
                    ..Default::default()
                },
            ),
            group(
                inner,
                Some(outer),
                HostSettings {
                    port: Some(2222),
                    ..Default::default()
                },
            ),
        ];
        let refs: Vec<&Group> = groups.iter().collect();
        let h = host(Some(inner), HostSettings::default());
        let s = effective_settings(&h, &refs);
        assert_eq!(s.port, Some(2222));
        assert_eq!(s.proxy.as_ref().map(|p| p.port), Some(3128));
        // The host's own settings win.
        let h = host(
            Some(inner),
            HostSettings {
                port: Some(22),
                ..Default::default()
            },
        );
        assert_eq!(effective_settings(&h, &refs).port, Some(22));
        // A loop of groups ends.
        let a = new_id();
        let looped = [group(a, Some(a), HostSettings::default())];
        let refs: Vec<&Group> = looped.iter().collect();
        effective_settings(&host(Some(a), HostSettings::default()), &refs);
    }

    #[test]
    fn what_is_not_checked() {
        let plain = host(None, HostSettings::default());
        let s = HostSettings::default();
        let (t, needs) = target_of(&plain, &s, false, true, false).unwrap();
        assert_eq!(t.port, 22);
        assert_eq!(t.address, "web.example");
        assert!(!needs);
        assert_eq!(target_of(&plain, &s, false, true, true), Err(Skip::Off));
        assert_eq!(target_of(&plain, &s, true, true, false), Err(Skip::Strict));
        let jumps = HostSettings {
            jump_host_ids: Some(vec![new_id()]),
            ..Default::default()
        };
        assert_eq!(
            target_of(&plain, &jumps, false, true, false),
            Err(Skip::Jump)
        );
        // An empty chain is no chain.
        let empty = HostSettings {
            jump_host_ids: Some(Vec::new()),
            ..Default::default()
        };
        assert!(target_of(&plain, &empty, false, true, false).is_ok());
        // A proxy with a user needs its password: Use-only cannot read it.
        let mut proxied = HostSettings {
            proxy: Some(ProxySettings {
                kind: ProxyKind::Socks5,
                host: "p".into(),
                port: 1080,
                username: Some("me".into()),
            }),
            ..Default::default()
        };
        assert_eq!(
            target_of(&plain, &proxied, false, false, false),
            Err(Skip::UseOnly)
        );
        let (t, needs) = target_of(&plain, &proxied, false, true, false).unwrap();
        assert!(needs && t.proxy.is_some());
        // SOCKS4 only sends the user.
        proxied.proxy.as_mut().unwrap().kind = ProxyKind::Socks4;
        assert_eq!(
            target_of(&plain, &proxied, false, false, false).map(|(_, n)| n),
            Ok(false)
        );
        // A proxy without a host is ignored (as when connecting).
        proxied.proxy.as_mut().unwrap().host = " ".into();
        let (t, _) = target_of(&plain, &proxied, false, false, false).unwrap();
        assert!(t.proxy.is_none());
        // IPv6 in brackets.
        let mut v6 = host(None, HostSettings::default());
        v6.address = "[::1]".into();
        assert_eq!(
            target_of(&v6, &s, false, true, false).unwrap().0.address,
            "::1"
        );
    }

    #[test]
    fn scheduler_checks_what_is_due() {
        let (a, b, c) = (new_id(), new_id(), new_id());
        let (ta, tb, tc) = (target(22), target(22), target(22));
        let mut book = Book::default();
        let t0 = Instant::now();
        let targets = [(a, &ta), (b, &tb), (c, &tc)];
        // Nothing known: all of them.
        assert_eq!(book.due(&targets, t0, EVERY), vec![a, b, c]);
        assert_eq!(book.next_due(&targets, t0, EVERY), Some(Duration::ZERO));
        book.start(&[a, b, c]);
        // Running: not again.
        assert!(book.due(&targets, t0, EVERY).is_empty());
        assert_eq!(book.next_due(&targets, t0, EVERY), None);
        book.finish(a, ta.clone(), Reach::Up(Duration::from_millis(23)), t0);
        book.finish(b, tb.clone(), Reach::Down, t0 + Duration::from_secs(10));
        book.finish(c, tc.clone(), Reach::Up(Duration::from_millis(5)), t0);
        let t1 = t0 + Duration::from_secs(30);
        assert!(book.due(&targets, t1, EVERY).is_empty());
        assert_eq!(
            book.next_due(&targets, t1, EVERY),
            Some(Duration::from_secs(30))
        );
        // A minute later: the oldest checks first.
        let t2 = t0 + Duration::from_secs(75);
        assert_eq!(book.due(&targets, t2, EVERY), vec![a, c, b]);
        // An edited host is checked at once and shown as pending.
        let moved = target(2222);
        let edited = [(a, &moved)];
        assert_eq!(book.due(&edited, t1, EVERY), vec![a]);
        assert_eq!(book.shown(a, Ok(&moved), t1), Shown::Pending);
        // What the cards show.
        assert_eq!(
            book.shown(a, Ok(&ta), t1),
            Shown::Up {
                rtt: Duration::from_millis(23),
                ago: Duration::from_secs(30)
            }
        );
        assert_eq!(
            book.shown(b, Ok(&tb), t1),
            Shown::Down {
                ago: Duration::from_secs(20)
            }
        );
        assert_eq!(
            book.shown(a, Err(Skip::Jump), t1),
            Shown::Skipped(Skip::Jump)
        );
        assert_eq!(book.shown(new_id(), Ok(&ta), t1), Shown::Pending);
    }

    #[tokio::test]
    async fn probes_device_hosts() {
        use crate::items::SaveTarget;
        use termoak_core::crypto::MasterKey;
        use termoak_core::model::SecretUpdate;

        let dir = tempfile::tempdir().unwrap();
        let ws = Workspace::open(dir.path(), MasterKey::generate()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let save = |mut h: Host| {
            let ws = &ws;
            async move {
                h.id = Id::nil();
                ws.save_item(SaveTarget::Device, h, SecretUpdate::Keep, None)
                    .await
                    .unwrap()
                    .item()
            }
        };
        let mut up = host(None, HostSettings {
            port: Some(port),
            ..Default::default()
        });
        up.address = "127.0.0.1".into();
        let up = save(up).await;
        let jump = save(host(None, HostSettings {
            jump_host_ids: Some(vec![up.id]),
            ..Default::default()
        }))
        .await;
        let mut down = host(None, HostSettings {
            port: Some(1),
            ..Default::default()
        });
        down.address = "127.0.0.1".into();
        let down = save(down).await;
        let off = save(host(None, HostSettings::default())).await;
        let missing = ItemRef {
            scope: Scope::Device,
            id: new_id(),
        };
        let res = ws
            .probe_hosts(&[up, jump, down, off, missing], &[off.id], 2)
            .await;
        assert_eq!(res.len(), 5);
        assert!(matches!(res[0].status, ProbeStatus::Up(_)), "{:?}", res[0]);
        assert_eq!(res[0].target.as_ref().unwrap().port, port);
        assert!(res[0].checked_at > 0);
        assert_eq!(res[1].status, ProbeStatus::Skipped(Skip::Jump));
        assert_eq!(res[2].status, ProbeStatus::Down);
        assert_eq!(res[3].status, ProbeStatus::Skipped(Skip::Off));
        assert_eq!(res[4].status, ProbeStatus::Down);
        assert_eq!(res[4].item, missing);
    }
}

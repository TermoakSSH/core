//! Host reachability for the status dots of the hosts lists
//! (`termoak_client::host_status`, the desktop's): a TCP connection to the
//! host's port, through its proxy, closed as soon as it opens. No SSH and
//! no authentication.
//!
//! Battery: check only while the list is on screen, the visible hosts, at
//! most once a minute each (the desktop's rhythm), and leave it off by
//! default (a setting, plus "turn off for this host").

use termoak_client::Scope;
use termoak_client::host_status::{self as hs, ProbeStatus, Skip};

use crate::accounts::ItemRef;
use crate::error::Result;
use crate::models::{parse_id, parse_opt_id};
use crate::runtime::run;
use crate::vault::TermoakCore;

/// Whether a host answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum HostReach {
    /// It accepted the connection (green, with `ms`).
    Up,
    /// Refused, timed out, the name does not resolve, or the host could not
    /// be read (red).
    Down,
    /// Not checked: see `skipped` (gray).
    Skipped,
}

/// Why a host is not checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ProbeSkip {
    /// The user turned the check off for this host.
    Off,
    /// It is reached through jump hosts (the path is inside SSH).
    JumpHosts,
    /// It is in a Strict vault (only reached through the server).
    Strict,
    /// Its proxy needs a password this (Use-only) user cannot read.
    UseOnly,
}

impl From<Skip> for ProbeSkip {
    fn from(s: Skip) -> Self {
        match s {
            Skip::Off => ProbeSkip::Off,
            Skip::Jump => ProbeSkip::JumpHosts,
            Skip::Strict => ProbeSkip::Strict,
            Skip::UseOnly => ProbeSkip::UseOnly,
        }
    }
}

/// The check of one host.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HostProbe {
    pub host_id: String,
    /// `None`: This device.
    pub account_id: Option<String>,
    pub status: HostReach,
    /// Time the connection took (only `Up`).
    pub ms: Option<u32>,
    /// When it was checked (ms since the epoch; 0 if it was not).
    pub checked_at: i64,
    pub skipped: Option<ProbeSkip>,
    /// Address and port checked (a host whose target changed, edited
    /// address, port or proxy, should be checked again).
    pub address: Option<String>,
    pub port: Option<u16>,
}

#[uniffi::export]
impl TermoakCore {
    /// Checks whether hosts answer, at most `concurrency` at a time (0: 8),
    /// each within 5 seconds, and answers in the order given. Hosts behind
    /// jump hosts, of Strict vaults or with a proxy whose password cannot be
    /// read are skipped; `off` are ids of hosts the user turned the check
    /// off for.
    #[uniffi::method(default(off = [], concurrency = 0))]
    pub async fn probe_hosts(
        &self,
        hosts: Vec<ItemRef>,
        off: Vec<String>,
        concurrency: u32,
    ) -> Result<Vec<HostProbe>> {
        let mut refs = Vec::with_capacity(hosts.len());
        for h in &hosts {
            refs.push(termoak_client::ItemRef {
                scope: Scope::from_account(parse_opt_id(&h.account_id)?),
                id: parse_id(&h.id)?,
            });
        }
        let off = off
            .iter()
            .filter_map(|id| parse_id(id).ok())
            .collect::<Vec<_>>();
        let ws = self.ws.clone();
        run(async move {
            let res = ws.probe_hosts(&refs, &off, concurrency as usize).await;
            Ok(res.into_iter().map(probe_of).collect())
        })
        .await
    }
}

fn probe_of(p: hs::HostProbe) -> HostProbe {
    let (status, ms, skipped) = match p.status {
        ProbeStatus::Up(rtt) => (
            HostReach::Up,
            Some(u32::try_from(rtt.as_millis()).unwrap_or(u32::MAX)),
            None,
        ),
        ProbeStatus::Down => (HostReach::Down, None, None),
        ProbeStatus::Skipped(s) => (HostReach::Skipped, None, Some(s.into())),
    };
    HostProbe {
        host_id: p.item.id.to_string(),
        account_id: p.item.scope.account().map(|a| a.to_string()),
        status,
        ms,
        checked_at: p.checked_at,
        skipped,
        address: p.target.as_ref().map(|t| t.address.clone()),
        port: p.target.as_ref().map(|t| t.port),
    }
}

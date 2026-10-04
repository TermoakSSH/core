//! Record lookup by id/label, and the hosts commands.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use termoak_client::{ApiClient, Workspace};
use termoak_core::Id;
use termoak_core::model::*;

fn matches(id: Id, label: &str, reference: &str) -> bool {
    id.to_string() == reference || label.eq_ignore_ascii_case(reference)
}

pub async fn find_host(ws: &Workspace, reference: &str) -> Result<Host> {
    let hosts = ws.store.list::<Host>(ws.owner()).await?;
    hosts
        .iter()
        .map(|h| &h.data)
        .find(|h| matches(h.id, &h.label, reference))
        .or_else(|| {
            hosts
                .iter()
                .map(|h| &h.data)
                .find(|h| h.address.eq_ignore_ascii_case(reference))
        })
        .cloned()
        .with_context(|| format!("no host \"{reference}\" (see `termoak hosts list`)"))
}

/// Several comma-separated hosts; `@tag` selects by tag.
pub async fn find_hosts(ws: &Workspace, list: &str) -> Result<Vec<Host>> {
    let all = ws.store.list::<Host>(ws.owner()).await?;
    let mut out: Vec<Host> = Vec::new();
    for r in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some(tag) = r.strip_prefix('@') {
            let tagged: Vec<Host> = all
                .iter()
                .map(|h| h.data.clone())
                .filter(|h| h.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)))
                .collect();
            if tagged.is_empty() {
                bail!("no host has the tag \"{tag}\"");
            }
            out.extend(tagged);
        } else {
            out.push(find_host(ws, r).await?);
        }
    }
    out.dedup_by_key(|h| h.id);
    if out.is_empty() {
        bail!("specify at least one host");
    }
    Ok(out)
}

pub async fn find_key(ws: &Workspace, reference: &str) -> Result<SshKey> {
    ws.store
        .list::<SshKey>(ws.owner())
        .await?
        .into_iter()
        .map(|k| k.data)
        .find(|k| matches(k.id, &k.label, reference) || k.fingerprint == reference)
        .with_context(|| format!("no key \"{reference}\""))
}

pub async fn find_group(ws: &Workspace, reference: &str) -> Result<Group> {
    ws.store
        .list::<Group>(ws.owner())
        .await?
        .into_iter()
        .map(|g| g.data)
        .find(|g| matches(g.id, &g.name, reference))
        .with_context(|| format!("no group \"{reference}\""))
}

pub async fn find_snippet(ws: &Workspace, reference: &str) -> Result<Snippet> {
    ws.store
        .list::<Snippet>(ws.owner())
        .await?
        .into_iter()
        .map(|s| s.data)
        .find(|s| matches(s.id, &s.name, reference))
        .with_context(|| format!("no snippet \"{reference}\""))
}

pub async fn need_server(ws: &Workspace) -> Result<ApiClient> {
    ws.server()
        .await?
        .context("not signed in to any server: use `termoak login <url>`")
}

pub enum HostsAction {
    List(Option<String>),
    Add {
        label: String,
        address: String,
        port: Option<u16>,
        user: Option<String>,
        key: Option<String>,
        password: bool,
        group: Option<String>,
        jump: Vec<String>,
        tags: Vec<String>,
        device_only: bool,
    },
    Show(String),
    Rm(String),
    Test(String),
}

pub async fn hosts(ws: &Workspace, action: HostsAction, json: bool) -> Result<()> {
    let owner = ws.owner();
    match action {
        HostsAction::List(query) => {
            let q = query.unwrap_or_default().to_lowercase();
            let groups = ws.store.list::<Group>(owner).await?;
            let mut list: Vec<Record<Host>> = ws
                .store
                .list::<Host>(owner)
                .await?
                .into_iter()
                .filter(|h| {
                    q.is_empty()
                        || format!(
                            "{} {} {}",
                            h.data.label,
                            h.data.address,
                            h.data.tags.join(" ")
                        )
                        .to_lowercase()
                        .contains(&q)
                })
                .collect();
            list.sort_by(|a, b| {
                (!a.data.favorite, a.data.label.to_lowercase())
                    .cmp(&(!b.data.favorite, b.data.label.to_lowercase()))
            });
            if json {
                println!("{}", serde_json::to_string_pretty(&list)?);
                return Ok(());
            }
            if list.is_empty() {
                println!(
                    "No hosts. Add one with `termoak hosts add <label> <address> --user <user>`."
                );
            }
            for h in &list {
                let s = ws.store.effective_settings(owner, &h.data).await?;
                let group = h
                    .data
                    .group_id
                    .and_then(|g| groups.iter().find(|x| x.data.id == g))
                    .map(|g| g.data.name.clone())
                    .unwrap_or_default();
                println!(
                    "{} {:22} {}@{}:{}  {}{}{}",
                    if h.data.favorite { "★" } else { " " },
                    h.data.label,
                    s.username.unwrap_or_else(|| "?".into()),
                    h.data.address,
                    s.port.unwrap_or(22),
                    if group.is_empty() {
                        String::new()
                    } else {
                        format!("[{group}] ")
                    },
                    h.data
                        .tags
                        .iter()
                        .map(|t| format!("#{t} "))
                        .collect::<String>(),
                    h.data
                        .os
                        .as_deref()
                        .map(|o| format!("({o})"))
                        .unwrap_or_default(),
                );
            }
        }
        HostsAction::Add {
            label,
            address,
            port,
            user,
            key,
            password,
            group,
            jump,
            tags,
            device_only,
        } => {
            let key_id = match key {
                Some(k) => Some(find_key(ws, &k).await?.id),
                None => None,
            };
            let group_id = match group {
                Some(g) => Some(find_group(ws, &g).await?.id),
                None => None,
            };
            let mut jumps = Vec::new();
            for j in jump {
                jumps.push(find_host(ws, &j).await?.id);
            }
            let secret = if password {
                SecretUpdate::Set(HostSecret {
                    password: Some(rpassword::prompt_password("Password: ")?),
                    ..Default::default()
                })
            } else {
                SecretUpdate::Keep
            };
            let rec = ws
                .store
                .save(
                    owner,
                    Host {
                        id: Id::nil(),
                        label,
                        address,
                        group_id,
                        tags,
                        settings: HostSettings {
                            port,
                            username: user,
                            key_id,
                            jump_host_ids: (!jumps.is_empty()).then_some(jumps),
                            ..Default::default()
                        },
                        notes: String::new(),
                        color: None,
                        os: None,
                        os_version: None,
                        favorite: false,
                    },
                    secret,
                    device_only.then_some(SyncMode::DeviceOnly),
                )
                .await?;
            println!("Host created: {}", rec.data.id);
        }
        HostsAction::Show(r) => {
            let h = find_host(ws, &r).await?;
            let s = ws.store.effective_settings(owner, &h).await?;
            let v = serde_json::json!({"host": h, "effective": s});
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        HostsAction::Rm(r) => {
            let h = find_host(ws, &r).await?;
            ws.store.delete::<Host>(owner, h.id).await?;
            println!("Host \"{}\" deleted.", h.label);
        }
        HostsAction::Test(r) => {
            let h = find_host(ws, &r).await?;
            let started = std::time::Instant::now();
            let conn = ws
                .connect(h.id, Arc::new(crate::prompt::CliPrompter), false)
                .await?;
            let latency = started.elapsed().as_millis();
            let info_os = termoak_ssh::detect::detect_os_info(&conn).await;
            let os = info_os.as_ref().map(|i| i.display());
            if let Some(i) = &info_os {
                let mut host = h.clone();
                host.os = Some(i.id.clone());
                host.os_version = Some(i.display());
                ws.store.save(owner, host, SecretUpdate::Keep, None).await?;
            }
            let info = conn.info().clone();
            conn.disconnect().await;
            if json {
                println!(
                    "{}",
                    serde_json::json!({"ok": true, "latency_ms": latency, "os": os, "fingerprint": info.server_fingerprint})
                );
            } else {
                println!("Connected to {} in {latency} ms", h.label);
                println!(
                    "Fingerprint: {}",
                    info.server_fingerprint.unwrap_or_default()
                );
                if let Some(os) = os {
                    println!("System: {os}");
                }
            }
        }
    }
    Ok(())
}

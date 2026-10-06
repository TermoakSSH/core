//! `termoak`: the Termoak CLI.
//!
//! Works on the same (encrypted) local database as the desktop app, with its
//! own SSH engine, and uses the server (if signed in) for persistent
//! sessions, sharing, sync and AI.

mod account;
mod ai;
mod data;
mod prompt;
mod remote;
mod term;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use termoak_client::Workspace;
use termoak_core::Id;
use termoak_core::model::*;
use termoak_ssh::exec::ExecOptions;
use termoak_ssh::forward::ForwardSpec;

use crate::data::{Items, find_host, find_key, find_snippet};

#[derive(Parser)]
#[command(
    name = "termoak",
    version,
    about = "Termoak — SSH client with AI",
    propagate_version = true
)]
struct Cli {
    /// JSON output (for scripts).
    #[arg(long, global = true)]
    json: bool,
    /// Account to use (email, email@server, server or id; see `termoak
    /// account list`). Defaults to the one chosen with `termoak account use`.
    #[arg(long, global = true, env = "TERMOAK_ACCOUNT")]
    account: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Opens a terminal on a host (locally or on the server).
    Connect {
        host: String,
        /// Opens the session on the server (it stays alive after you close the terminal).
        #[arg(long)]
        server: bool,
        /// Also use the local SSH agent.
        #[arg(long)]
        agent: bool,
        /// Records the session (asciicast).
        #[arg(long)]
        record: bool,
    },
    /// Runs a command on one or more hosts, in parallel.
    Exec {
        /// Hosts (id, label or address), comma-separated.
        hosts: String,
        /// Command (after `--`).
        #[arg(last = true, required = true)]
        command: Vec<String>,
        #[arg(long, default_value_t = 120)]
        timeout: u64,
    },
    /// Hosts.
    #[command(subcommand)]
    Hosts(HostsCmd),
    /// Host groups.
    #[command(subcommand)]
    Groups(GroupsCmd),
    /// SSH key keychain.
    #[command(subcommand)]
    Keys(KeysCmd),
    /// Identities (user + password/key).
    #[command(subcommand)]
    Identities(IdentitiesCmd),
    /// Snippets.
    #[command(subcommand)]
    Snippets(SnippetsCmd),
    /// Known hosts.
    #[command(subcommand, name = "known-hosts")]
    KnownHosts(KnownHostsCmd),
    /// SFTP.
    #[command(subcommand)]
    Sftp(SftpCmd),
    /// Tunnel: -L port:host:port, -R port:host:port or -D port.
    Forward {
        host: String,
        #[arg(short = 'L', long = "local")]
        local: Vec<String>,
        #[arg(short = 'R', long = "remote")]
        remote: Vec<String>,
        #[arg(short = 'D', long = "dynamic")]
        dynamic: Vec<String>,
    },
    /// Shares a local terminal through the server.
    Share {
        host: String,
        /// Invite a server user.
        #[arg(long)]
        invite: Vec<String>,
        /// Let guests type: they get the keyboard when they ask for it (one at
        /// a time; you can always type).
        #[arg(long)]
        control: bool,
    },
    /// Signs in to a Termoak server (the official one without a URL). Adds
    /// the account, or signs it in again.
    Login {
        url: Option<String>,
        #[arg(long)]
        email: Option<String>,
    },
    /// Creates an account on a server (the first user is the administrator).
    Register {
        url: String,
        #[arg(long)]
        email: Option<String>,
        #[arg(long, default_value = "")]
        name: String,
        /// Invitation code (if the server's registration is closed).
        #[arg(long)]
        invite: Option<String>,
    },
    /// Signs the current account out of its server (its data is kept; see
    /// `termoak account remove`).
    Logout,
    /// Syncs the current account with its server.
    Sync {
        /// Every signed-in account.
        #[arg(long)]
        all: bool,
    },
    /// Sessions that live on the server.
    #[command(subcommand)]
    Sessions(SessionsCmd),
    /// AI engine.
    #[command(subcommand)]
    Ai(ai::AiCmd),
    /// Your account's two-factor authentication.
    #[command(name = "2fa", subcommand)]
    TwoFa(account::TwoFaCmd),
    /// Server administration (users, invitations, audit log).
    #[command(subcommand)]
    Admin(account::AdminCmd),
    /// Teams (to share sessions with the whole team).
    #[command(subcommand)]
    Teams(account::TeamsCmd),
    /// Accounts on this device (list, add, use, remove) and your account on
    /// the server: plan, email, forgotten password and account deletion.
    #[command(subcommand)]
    Account(account::AccountCmd),
    /// Status of the local setup.
    Status,
}

#[derive(Subcommand)]
enum HostsCmd {
    List {
        #[arg(long)]
        query: Option<String>,
    },
    Add(HostArgs),
    Show {
        host: String,
    },
    Rm {
        host: String,
    },
    /// Tests the connection and saves the host's fingerprint.
    Test {
        host: String,
    },
    /// Imports the hosts from `~/.ssh/config` (keys, jumps and tunnels included).
    Import {
        /// File (defaults to `~/.ssh/config`).
        path: Option<std::path::PathBuf>,
        /// Put them in this group (created if it doesn't exist).
        #[arg(long)]
        group: Option<String>,
        /// Don't sync (their keys never leave this computer).
        #[arg(long)]
        device_only: bool,
        /// Only show what would be imported.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Args)]
struct HostArgs {
    label: String,
    address: String,
    #[arg(long)]
    port: Option<u16>,
    #[arg(long)]
    user: Option<String>,
    /// Key (id or label).
    #[arg(long)]
    key: Option<String>,
    /// Ask for a password and store it encrypted.
    #[arg(long)]
    password: bool,
    #[arg(long)]
    group: Option<String>,
    /// Jumps (ProxyJump), in order.
    #[arg(long)]
    jump: Vec<String>,
    #[arg(long)]
    tag: Vec<String>,
    /// Don't sync (its secrets never leave this computer).
    #[arg(long)]
    device_only: bool,
}

#[derive(Subcommand)]
enum GroupsCmd {
    List,
    Add {
        name: String,
        #[arg(long)]
        parent: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        key: Option<String>,
    },
    Rm {
        group: String,
    },
}

#[derive(Subcommand)]
enum KeysCmd {
    List,
    Generate {
        label: String,
        /// ed25519, rsa4096, rsa3072, rsa2048, ecdsa_p256, ecdsa_p384, ecdsa_p521.
        #[arg(long, default_value = "ed25519")]
        r#type: String,
        #[arg(long)]
        comment: Option<String>,
        /// Protect with a passphrase (asked for interactively).
        #[arg(long)]
        passphrase: bool,
        #[arg(long)]
        device_only: bool,
    },
    Import {
        label: String,
        file: std::path::PathBuf,
        #[arg(long)]
        device_only: bool,
    },
    /// Prints the public key (for authorized_keys).
    Public {
        key: String,
    },
    Rm {
        key: String,
    },
}

#[derive(Subcommand)]
enum IdentitiesCmd {
    List,
    Add {
        label: String,
        username: String,
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        password: bool,
    },
    Rm {
        identity: String,
    },
}

#[derive(Subcommand)]
enum SnippetsCmd {
    List,
    Add {
        name: String,
        /// Script (or read it from a file with --file).
        #[arg(long)]
        script: Option<String>,
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        #[arg(long, default_value = "")]
        description: String,
    },
    /// Runs a snippet on several hosts.
    Run {
        snippet: String,
        /// Comma-separated hosts.
        hosts: String,
        /// Variables name=value.
        #[arg(long = "var")]
        vars: Vec<String>,
    },
    Rm {
        snippet: String,
    },
}

#[derive(Subcommand)]
enum KnownHostsCmd {
    List,
    Rm { host: String },
}

#[derive(Subcommand)]
enum SftpCmd {
    Ls {
        host: String,
        path: Option<String>,
    },
    Get {
        host: String,
        remote: String,
        local: Option<std::path::PathBuf>,
    },
    Put {
        host: String,
        local: std::path::PathBuf,
        remote: String,
    },
    Mkdir {
        host: String,
        path: String,
    },
    Rm {
        host: String,
        path: String,
        #[arg(short, long)]
        recursive: bool,
    },
}

#[derive(Subcommand)]
enum SessionsCmd {
    List,
    /// Opens a session on the server and attaches to it.
    Open {
        host: String,
    },
    /// Attaches to an existing session (yours or shared with you).
    Attach {
        id: String,
    },
    Close {
        id: String,
    },
    /// Shares a server session.
    Share {
        id: String,
        #[arg(long)]
        email: Option<String>,
        /// With a whole team (name or id).
        #[arg(long)]
        team: Option<String>,
        #[arg(long)]
        link: bool,
        /// Guests can ask for the keyboard (one types at a time).
        #[arg(long)]
        control: bool,
        /// Grant the keyboard without asking (with --control).
        #[arg(long)]
        auto_grant: bool,
        /// Whoever joins waits until you let them in from an app or the web
        /// (default for --link).
        #[arg(long)]
        approve: Option<bool>,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("TERMOAK_LOG")
                .unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn out<T: serde::Serialize>(json: bool, value: &T, text: impl FnOnce()) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(value).unwrap_or_default()
        );
    } else {
        text();
    }
}

async fn run(cli: Cli) -> Result<()> {
    let ws = Workspace::open_default().context("could not open the local database")?;
    if let Some(q) = cli.account.as_deref() {
        let acc = ws.find_account(q)?;
        ws.pin(Some(acc.id))?;
    }
    let json = cli.json;
    match cli.command {
        Command::Status => {
            let hosts = ws.all::<Host>().await?.len();
            let keys = ws.all::<SshKey>().await?.len();
            let current = ws.current().map(|a| a.id);
            let accounts: Vec<serde_json::Value> = ws
                .accounts()
                .into_iter()
                .map(|a| {
                    serde_json::json!({"id": a.id, "server": a.server_url, "email": a.email,
                        "status": a.status, "current": Some(a.id) == current,
                        "vaults": a.vaults_supported(), "last_sync_at": a.last_sync_at})
                })
                .collect();
            let user = ws.server_user().await?;
            let server = ws.server_url();
            let logged = ws.server().await?.is_some();
            let v = serde_json::json!({"data_dir": ws.dir, "hosts": hosts, "keys": keys, "server": server, "user": user, "logged_in": logged, "accounts": accounts});
            out(json, &v, || {
                println!("Data:      {}", ws.dir.display());
                println!("Hosts:     {hosts}");
                println!("Keys:      {keys}");
                match (&server, logged) {
                    (Some(s), true) => {
                        println!("Server:    {s} ({})", user.clone().unwrap_or_default())
                    }
                    (Some(s), false) => println!("Server:    {s} (signed out)"),
                    _ => println!("Server:    none (use `termoak login`)"),
                }
                if accounts.len() > 1 {
                    println!("Accounts:  {} (see `termoak account list`)", accounts.len());
                }
            });
        }
        Command::Connect {
            host,
            server,
            agent,
            record,
        } => {
            let h = find_host(&ws, &host).await?;
            if server {
                let api = data::need_server(&ws).await?;
                let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
                let s: serde_json::Value = api
                    .post(
                        "/api/v1/sessions",
                        &serde_json::json!({"host_id": h.id, "cols": cols, "rows": rows}),
                    )
                    .await?;
                let id: Id = s["id"].as_str().unwrap_or_default().parse()?;
                eprintln!("Session {id} opened on the server. Ctrl+] to detach (it stays alive).");
                remote::attach(&api, id).await?;
            } else {
                let prompter = Arc::new(prompt::CliPrompter);
                eprintln!("Connecting to {}…", h.label);
                let conn = ws.connect(h.id, prompter, agent).await?;
                let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
                let t = ws.open_terminal(h.id, conn, cols, rows, record).await?;
                term::run_local(t).await?;
            }
        }
        Command::Exec {
            hosts,
            command,
            timeout,
        } => {
            let command = command.join(" ");
            let targets = data::find_hosts(&ws, &hosts).await?;
            let futures = targets.into_iter().map(|h| {
                let ws = ws.clone();
                let command = command.clone();
                async move {
                    let res = async {
                        let conn = ws
                            .connect(h.id, Arc::new(prompt::NoInteractive), false)
                            .await?;
                        let o = conn
                            .exec(
                                &command,
                                &ExecOptions {
                                    timeout: Duration::from_secs(timeout),
                                    ..Default::default()
                                },
                            )
                            .await?;
                        conn.disconnect().await;
                        anyhow::Ok(o)
                    }
                    .await;
                    (h, res)
                }
            });
            let results = futures::future::join_all(futures).await;
            let mut failed = false;
            for (h, r) in &results {
                match r {
                    Ok(o) => {
                        if json {
                            println!(
                                "{}",
                                serde_json::json!({"host": h.label, "exit_code": o.exit_code, "stdout": o.stdout_text(), "stderr": o.stderr_text()})
                            );
                        } else {
                            println!(
                                "── {} (exit code {})",
                                h.label,
                                o.exit_code.map(|c| c.to_string()).unwrap_or("?".into())
                            );
                            print!("{}", o.stdout_text());
                            eprint!("{}", o.stderr_text());
                        }
                        failed |= !o.success();
                    }
                    Err(e) => {
                        failed = true;
                        eprintln!("── {}: {e:#}", h.label);
                    }
                }
            }
            if failed {
                std::process::exit(2);
            }
        }
        Command::Hosts(HostsCmd::Import {
            path,
            group,
            device_only,
            dry_run,
        }) => {
            let path = path.unwrap_or_else(termoak_ssh::sshconfig::default_path);
            let r = ws
                .import_ssh_config(
                    &path,
                    &termoak_client::import::ImportOptions {
                        dry_run,
                        group,
                        device_only,
                    },
                )
                .await
                .with_context(|| format!("could not import {}", path.display()))?;
            out(json, &r, || {
                let verb = if dry_run { "Would import" } else { "Imported" };
                println!("{verb} {} host(s):", r.hosts_created.len());
                for h in &r.hosts_created {
                    println!("  + {h}");
                }
                for h in &r.jump_hosts_created {
                    println!("  + {h} (jump)");
                }
                for s in &r.hosts_skipped {
                    println!("  = {} ({})", s.alias, s.reason);
                }
                if !r.keys_imported.is_empty() {
                    println!("New keys in the keychain: {}", r.keys_imported.join(", "));
                }
                if !r.keys_reused.is_empty() {
                    println!("Keys you already had: {}", r.keys_reused.join(", "));
                }
                if r.forwards_created > 0 {
                    println!("Tunnels: {}", r.forwards_created);
                }
                for w in &r.warnings {
                    println!("warning: {w}");
                }
            });
        }
        Command::Hosts(cmd) => data::hosts(&ws, cmd_hosts(cmd), json).await?,
        Command::Groups(cmd) => match cmd {
            GroupsCmd::List => {
                let groups = ws.all::<Group>().await?;
                out(json, &groups, || {
                    for g in &groups {
                        println!("{}  {}", g.data.id, g.data.name);
                    }
                });
            }
            GroupsCmd::Add {
                name,
                parent,
                user,
                port,
                key,
            } => {
                let parent_id = match parent {
                    Some(p) => Some(data::find_group(&ws, &p).await?.id),
                    None => None,
                };
                let key_id = match key {
                    Some(k) => Some(find_key(&ws, &k).await?.id),
                    None => None,
                };
                let rec = ws
                    .put(
                        Group {
                            id: Id::nil(),
                            name,
                            parent_id,
                            color: None,
                            settings: HostSettings {
                                username: user,
                                port,
                                key_id,
                                ..Default::default()
                            },
                        },
                        SecretUpdate::Keep,
                        None,
                    )
                    .await?;
                println!("Group created: {}", rec.data.id);
            }
            GroupsCmd::Rm { group } => {
                let g = data::find_group(&ws, &group).await?;
                ws.remove::<Group>(g.id).await?;
                println!("Group deleted.");
            }
        },
        Command::Keys(cmd) => keys(&ws, cmd, json).await?,
        Command::Identities(cmd) => match cmd {
            IdentitiesCmd::List => {
                let list = ws.all::<Identity>().await?;
                out(json, &list, || {
                    for i in &list {
                        println!("{}  {:20} {}", i.data.id, i.data.label, i.data.username);
                    }
                });
            }
            IdentitiesCmd::Add {
                label,
                username,
                key,
                password,
            } => {
                let key_id = match key {
                    Some(k) => Some(find_key(&ws, &k).await?.id),
                    None => None,
                };
                let secret = if password {
                    SecretUpdate::Set(IdentitySecret {
                        password: Some(rpassword::prompt_password("Password: ")?),
                    })
                } else {
                    SecretUpdate::Keep
                };
                let rec = ws
                    .put(
                        Identity {
                            id: Id::nil(),
                            label,
                            username,
                            key_id,
                        },
                        secret,
                        None,
                    )
                    .await?;
                println!("Identity created: {}", rec.data.id);
            }
            IdentitiesCmd::Rm { identity } => {
                let list = ws.all::<Identity>().await?;
                let i = list
                    .iter()
                    .find(|i| {
                        i.data.id.to_string() == identity
                            || i.data.label.eq_ignore_ascii_case(&identity)
                    })
                    .context("no such identity")?;
                ws.remove::<Identity>(i.data.id).await?;
                println!("Identity deleted.");
            }
        },
        Command::Snippets(cmd) => snippets(&ws, cmd, json).await?,
        Command::KnownHosts(cmd) => match cmd {
            KnownHostsCmd::List => {
                let list = ws.all::<KnownHost>().await?;
                out(json, &list, || {
                    for k in &list {
                        println!(
                            "{}:{}  {}  {}",
                            k.data.host, k.data.port, k.data.key_type, k.data.fingerprint
                        );
                    }
                });
            }
            KnownHostsCmd::Rm { host } => {
                let list = ws.all::<KnownHost>().await?;
                let mut n = 0;
                for k in list.iter().filter(|k| {
                    k.data.host.eq_ignore_ascii_case(&host)
                        || format!("{}:{}", k.data.host, k.data.port) == host
                }) {
                    ws.remove::<KnownHost>(k.data.id).await?;
                    n += 1;
                }
                println!("{n} entries deleted.");
            }
        },
        Command::Sftp(cmd) => sftp(&ws, cmd, json).await?,
        Command::Forward {
            host,
            local,
            remote,
            dynamic,
        } => {
            let h = find_host(&ws, &host).await?;
            let conn = ws
                .connect(h.id, Arc::new(prompt::CliPrompter), false)
                .await?;
            let mut handles = Vec::new();
            for spec in local
                .iter()
                .map(|s| parse_forward(ForwardKind::Local, s))
                .chain(remote.iter().map(|s| parse_forward(ForwardKind::Remote, s)))
                .chain(
                    dynamic
                        .iter()
                        .map(|s| parse_forward(ForwardKind::Dynamic, s)),
                )
            {
                let spec = spec?;
                let handle = conn.start_forward(spec.clone()).await?;
                match spec.kind {
                    ForwardKind::Local => eprintln!(
                        "Local {}:{} → {}:{}",
                        spec.bind_address,
                        handle.bound_port,
                        spec.dest_host.clone().unwrap_or_default(),
                        spec.dest_port.unwrap_or(0)
                    ),
                    ForwardKind::Remote => eprintln!(
                        "Remote {}:{} (on {}) → {}:{}",
                        spec.bind_address,
                        handle.bound_port,
                        h.label,
                        spec.dest_host.clone().unwrap_or_default(),
                        spec.dest_port.unwrap_or(0)
                    ),
                    ForwardKind::Dynamic => {
                        eprintln!("SOCKS5 on {}:{}", spec.bind_address, handle.bound_port)
                    }
                }
                handles.push(handle);
            }
            if handles.is_empty() {
                bail!("specify at least one tunnel (-L, -R or -D)");
            }
            eprintln!("Tunnels active. Ctrl+C to close.");
            tokio::signal::ctrl_c().await?;
            for h in handles {
                h.stop().await;
            }
        }
        Command::Share {
            host,
            invite,
            control,
        } => {
            let api = data::need_server(&ws).await?;
            let h = find_host(&ws, &host).await?;
            let conn = ws
                .connect(h.id, Arc::new(prompt::CliPrompter), false)
                .await?;
            let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
            let t = ws.open_terminal(h.id, conn, cols, rows, false).await?;
            let share = termoak_client::relay::RelayShare::start(&api, t.clone(), &h.label).await?;
            // The terminal here cannot show requests: nobody waits to come in
            // and, with --control, the keyboard is granted when asked for.
            let permission = if control { "control" } else { "view" };
            for email in &invite {
                share
                    .invite(&serde_json::json!({"email": email, "permission": permission, "auto_grant": control}))
                    .await?;
                eprintln!("Invited: {email}");
            }
            let link = share
                .invite(&serde_json::json!({"link": true, "permission": permission, "expires_in_minutes": 24 * 60, "require_approval": false, "auto_grant": control}))
                .await?;
            eprintln!("Guest link (24 h): {}", link["link"].as_str().unwrap_or(""));
            eprintln!("In the app: {}", link["app_link"].as_str().unwrap_or(""));
            term::run_local(t).await?;
            share.stop().await;
        }
        Command::Login { url, email } => {
            let choice = match url {
                Some(u) => termoak_client::ServerChoice::Custom(u),
                None => termoak_client::ServerChoice::Official,
            };
            let acc = account::sign_in_interactive(&ws, choice, email).await?;
            let info = acc.info();
            println!("Signed in to {} as {}.", info.server_url, info.email);
            match acc.sync_once().await {
                Ok(r) => {
                    println!("Synced: {} sent, {} received.", r.pushed, r.pulled);
                    account::print_sync_notices(&r);
                }
                Err(e) => eprintln!("Could not sync yet: {e}"),
            }
        }
        Command::Register {
            url,
            email,
            name,
            invite,
        } => {
            let email = match email {
                Some(e) => e,
                None => prompt::ask_line("Email: ")?,
            };
            let password = match std::env::var("TERMOAK_PASSWORD") {
                Ok(p) if !p.is_empty() => p,
                _ => {
                    let p = rpassword::prompt_password("Password (min. 10 characters): ")?;
                    if p != rpassword::prompt_password("Repeat the password: ")? {
                        bail!("the passwords do not match");
                    }
                    p
                }
            };
            let acc = ws
                .sign_up(
                    termoak_client::ServerChoice::Custom(url.clone()),
                    &email,
                    &name,
                    &password,
                    invite.as_deref(),
                )
                .await?;
            if acc.status() == termoak_client::AccountStatus::Unverified {
                println!(
                    "Account created on {url}. Enter the code from the email with `termoak account verify <code>`."
                );
            } else {
                println!("Account created and signed in to {url}.");
            }
        }
        Command::Logout => {
            ws.logout().await?;
            println!("Signed out.");
        }
        Command::Sync { all } => {
            let accounts = if all {
                ws.account_list()
                    .into_iter()
                    .filter(|a| a.is_signed_in())
                    .collect()
            } else {
                vec![ws.current().context("not signed in to any server")?]
            };
            let mut reports = Vec::new();
            for acc in accounts {
                let r = acc.sync_once().await?;
                let info = acc.info();
                if !json {
                    println!(
                        "{} ({}): {} sent, {} received (rev {}).",
                        info.email, info.server_url, r.pushed, r.pulled, r.rev
                    );
                    account::print_sync_notices(&r);
                }
                reports.push(serde_json::json!({"account_id": acc.id, "report": r}));
            }
            if json {
                if all {
                    out(json, &reports, || {});
                } else if let Some(r) = reports.first() {
                    out(json, &r["report"], || {});
                }
            }
        }
        Command::Sessions(cmd) => {
            let api = data::need_server(&ws).await?;
            match cmd {
                SessionsCmd::List => {
                    let v: serde_json::Value = api.get("/api/v1/sessions").await?;
                    out(json, &v, || {
                        for s in v["active"].as_array().into_iter().flatten() {
                            println!(
                                "{}  {:24} {:10} {} viewer(s)",
                                s["id"].as_str().unwrap_or(""),
                                s["title"].as_str().unwrap_or(""),
                                s["state"]["state"].as_str().unwrap_or(""),
                                s["viewers"].as_array().map(|v| v.len()).unwrap_or(0)
                            );
                        }
                        for s in v["shared"].as_array().into_iter().flatten() {
                            println!(
                                "{}  {:24} shared ({})",
                                s["id"].as_str().unwrap_or(""),
                                s["title"].as_str().unwrap_or(""),
                                s["access"].as_str().unwrap_or("")
                            );
                        }
                    });
                }
                SessionsCmd::Open { host } => {
                    let h = find_host(&ws, &host).await?;
                    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
                    let s: serde_json::Value = api
                        .post(
                            "/api/v1/sessions",
                            &serde_json::json!({"host_id": h.id, "cols": cols, "rows": rows}),
                        )
                        .await?;
                    let id: Id = s["id"].as_str().unwrap_or_default().parse()?;
                    eprintln!("Session {id}. Ctrl+] to detach (it stays alive on the server).");
                    remote::attach(&api, id).await?;
                }
                SessionsCmd::Attach { id } => {
                    let id: Id = id.parse().context("invalid session id")?;
                    eprintln!("Ctrl+] to detach from the session.");
                    remote::attach(&api, id).await?;
                }
                SessionsCmd::Close { id } => {
                    api.delete(&format!("/api/v1/sessions/{id}")).await?;
                    println!("Signed out.");
                }
                SessionsCmd::Share {
                    id,
                    email,
                    team,
                    link,
                    control,
                    auto_grant,
                    approve,
                } => {
                    let permission = if control { "control" } else { "view" };
                    let mut body = if link {
                        serde_json::json!({"link": true, "permission": permission})
                    } else if let Some(team) = team {
                        let t = account::find_team(&api, &team).await?;
                        serde_json::json!({"team_id": t["id"], "permission": permission})
                    } else {
                        serde_json::json!({"email": email.context("specify --email, --team or --link")?, "permission": permission})
                    };
                    body["auto_grant"] = serde_json::json!(auto_grant);
                    if let Some(a) = approve {
                        body["require_approval"] = serde_json::json!(a);
                    }
                    let v: serde_json::Value = api
                        .post(&format!("/api/v1/sessions/{id}/shares"), &body)
                        .await?;
                    out(json, &v, || {
                        if let Some(l) = v["link"].as_str() {
                            println!("Link: {l}");
                        } else {
                            println!("Invitation sent.");
                        }
                    });
                }
            }
        }
        Command::Ai(cmd) => ai::run(&ws, cmd, json).await?,
        Command::TwoFa(cmd) => account::two_fa(&ws, cmd, json).await?,
        Command::Admin(cmd) => account::admin(&ws, cmd, json).await?,
        Command::Teams(cmd) => account::teams(&ws, cmd, json).await?,
        Command::Account(cmd) => account::account(&ws, cmd, json).await?,
    }
    Ok(())
}

fn cmd_hosts(cmd: HostsCmd) -> data::HostsAction {
    match cmd {
        HostsCmd::List { query } => data::HostsAction::List(query),
        HostsCmd::Add(a) => data::HostsAction::Add {
            label: a.label,
            address: a.address,
            port: a.port,
            user: a.user,
            key: a.key,
            password: a.password,
            group: a.group,
            jump: a.jump,
            tags: a.tag,
            device_only: a.device_only,
        },
        HostsCmd::Show { host } => data::HostsAction::Show(host),
        HostsCmd::Rm { host } => data::HostsAction::Rm(host),
        HostsCmd::Test { host } => data::HostsAction::Test(host),
        HostsCmd::Import { .. } => unreachable!("handled earlier"),
    }
}

/// `8080:localhost:80`, `0.0.0.0:8080:db:5432` or `1080` (dynamic).
fn parse_forward(kind: ForwardKind, s: &str) -> Result<ForwardSpec> {
    let parts: Vec<&str> = s.split(':').collect();
    let (bind_address, bind_port, dest) = match (kind, parts.as_slice()) {
        (ForwardKind::Dynamic, [port]) => ("127.0.0.1".to_string(), port.parse()?, None),
        (ForwardKind::Dynamic, [addr, port]) => (addr.to_string(), port.parse()?, None),
        (_, [port, host, dport]) => (
            "127.0.0.1".to_string(),
            port.parse()?,
            Some((host.to_string(), dport.parse()?)),
        ),
        (_, [addr, port, host, dport]) => (
            addr.to_string(),
            port.parse()?,
            Some((host.to_string(), dport.parse()?)),
        ),
        _ => bail!("invalid tunnel format: {s}"),
    };
    Ok(ForwardSpec {
        kind,
        bind_address,
        bind_port,
        dest_host: dest.as_ref().map(|(h, _)| h.clone()),
        dest_port: dest.map(|(_, p)| p),
    })
}

async fn keys(ws: &Workspace, cmd: KeysCmd, json: bool) -> Result<()> {
    match cmd {
        KeysCmd::List => {
            let list = ws.all::<SshKey>().await?;
            out(json, &list, || {
                for k in &list {
                    println!(
                        "{}  {:20} {:22} {}{}",
                        k.data.id,
                        k.data.label,
                        k.data.algorithm,
                        k.data.fingerprint,
                        if k.meta.sync_mode == SyncMode::DeviceOnly {
                            "  (this computer only)"
                        } else {
                            ""
                        }
                    );
                }
            });
        }
        KeysCmd::Generate {
            label,
            r#type,
            comment,
            passphrase,
            device_only,
        } => {
            let kind = termoak_ssh::keys::KeyType::parse(&r#type).context("invalid key type")?;
            let pass = if passphrase {
                let p = rpassword::prompt_password("Passphrase: ")?;
                (!p.is_empty()).then_some(p)
            } else {
                None
            };
            let comment = comment.unwrap_or_else(|| format!("{label}@termoak"));
            let m = termoak_ssh::keys::generate(kind, &comment, pass.as_deref())?;
            let rec = save_key(ws, label, m, device_only).await?;
            println!("{}", rec.data.public_key);
            eprintln!("Key created ({}).", rec.data.fingerprint);
        }
        KeysCmd::Import {
            label,
            file,
            device_only,
        } => {
            let pem = std::fs::read_to_string(&file)
                .with_context(|| format!("could not read {}", file.display()))?;
            let pass = if termoak_ssh::keys::is_encrypted(&pem) {
                Some(rpassword::prompt_password("Key passphrase: ")?)
            } else {
                None
            };
            let m = termoak_ssh::keys::import_private(&pem, pass.as_deref())?;
            let rec = save_key(ws, label, m, device_only).await?;
            println!("Key imported: {} ({})", rec.data.id, rec.data.fingerprint);
        }
        KeysCmd::Public { key } => println!("{}", find_key(ws, &key).await?.public_key),
        KeysCmd::Rm { key } => {
            let k = find_key(ws, &key).await?;
            ws.remove::<SshKey>(k.id).await?;
            println!("Key deleted.");
        }
    }
    Ok(())
}

async fn save_key(
    ws: &Workspace,
    label: String,
    m: termoak_ssh::keys::KeyMaterial,
    device_only: bool,
) -> Result<Record<SshKey>> {
    Ok(ws
        .put(
            SshKey {
                id: Id::nil(),
                label,
                algorithm: m.algorithm.clone(),
                public_key: m.public_openssh.clone(),
                fingerprint: m.fingerprint.clone(),
                comment: m.comment.clone(),
                has_passphrase: m.encrypted,
                certificate: None,
            },
            SecretUpdate::Set(SshKeySecret {
                private_key: Some(m.private_openssh.clone()),
                passphrase: None,
            }),
            device_only.then_some(SyncMode::DeviceOnly),
        )
        .await?)
}

async fn snippets(ws: &Workspace, cmd: SnippetsCmd, json: bool) -> Result<()> {
    match cmd {
        SnippetsCmd::List => {
            let list = ws.all::<Snippet>().await?;
            out(json, &list, || {
                for s in &list {
                    let vars = s.data.variables();
                    println!(
                        "{}  {:24} {}{}",
                        s.data.id,
                        s.data.name,
                        s.data.description,
                        if vars.is_empty() {
                            String::new()
                        } else {
                            format!("  [{}]", vars.join(", "))
                        }
                    );
                }
            });
        }
        SnippetsCmd::Add {
            name,
            script,
            file,
            description,
        } => {
            let script = match (script, file) {
                (Some(s), None) => s,
                (None, Some(f)) => std::fs::read_to_string(f)?,
                _ => bail!("specify --script or --file"),
            };
            let rec = ws
                .put(
                    Snippet {
                        id: Id::nil(),
                        name,
                        script,
                        description,
                        tags: vec![],
                    },
                    SecretUpdate::Keep,
                    None,
                )
                .await?;
            println!("Snippet created: {}", rec.data.id);
        }
        SnippetsCmd::Run {
            snippet,
            hosts,
            vars,
        } => {
            let s = find_snippet(ws, &snippet).await?;
            let mut values = BTreeMap::new();
            for v in vars {
                let (k, val) = v.split_once('=').context("use --var name=value")?;
                values.insert(k.to_string(), val.to_string());
            }
            for var in s.variables() {
                if !values.contains_key(&var) {
                    values.insert(var.clone(), prompt::ask_line(&format!("{var}: "))?);
                }
            }
            let script = s.render(&values)?;
            let targets = data::find_hosts(ws, &hosts).await?;
            let results = futures::future::join_all(targets.into_iter().map(|h| {
                let ws = ws.clone();
                let script = script.clone();
                async move {
                    let r = async {
                        let conn = ws
                            .connect(h.id, Arc::new(prompt::NoInteractive), false)
                            .await?;
                        let o = conn.exec(&script, &ExecOptions::default()).await?;
                        conn.disconnect().await;
                        anyhow::Ok(o)
                    }
                    .await;
                    (h, r)
                }
            }))
            .await;
            for (h, r) in results {
                match r {
                    Ok(o) => {
                        if json {
                            println!(
                                "{}",
                                serde_json::json!({"host": h.label, "exit_code": o.exit_code, "stdout": o.stdout_text(), "stderr": o.stderr_text()})
                            );
                        } else {
                            println!(
                                "── {} (exit code {})",
                                h.label,
                                o.exit_code.map(|c| c.to_string()).unwrap_or("?".into())
                            );
                            print!("{}", o.stdout_text());
                            eprint!("{}", o.stderr_text());
                        }
                    }
                    Err(e) => eprintln!("── {}: {e:#}", h.label),
                }
            }
        }
        SnippetsCmd::Rm { snippet } => {
            let s = find_snippet(ws, &snippet).await?;
            ws.remove::<Snippet>(s.id).await?;
            println!("Snippet deleted.");
        }
    }
    Ok(())
}

async fn sftp(ws: &Workspace, cmd: SftpCmd, json: bool) -> Result<()> {
    let host_ref = match &cmd {
        SftpCmd::Ls { host, .. }
        | SftpCmd::Get { host, .. }
        | SftpCmd::Put { host, .. }
        | SftpCmd::Mkdir { host, .. }
        | SftpCmd::Rm { host, .. } => host.clone(),
    };
    let h = find_host(ws, &host_ref).await?;
    let conn = ws
        .connect(h.id, Arc::new(prompt::CliPrompter), false)
        .await?;
    let sftp = conn.sftp().await?;
    match cmd {
        SftpCmd::Ls { path, .. } => {
            let path = match path {
                Some(p) => p,
                None => sftp.home().await?,
            };
            let list = sftp.list(&path).await?;
            out(json, &list, || {
                for e in &list {
                    let date = e
                        .modified
                        .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
                        .map(|d| d.format("%Y-%m-%d %H:%M").to_string())
                        .unwrap_or_default();
                    println!(
                        "{:10} {:>12} {:16} {}{}",
                        e.mode_string,
                        e.size,
                        date,
                        e.name,
                        if e.kind == termoak_ssh::FileKind::Dir {
                            "/"
                        } else {
                            ""
                        }
                    );
                }
            });
        }
        SftpCmd::Get { remote, local, .. } => {
            let local = local.unwrap_or_else(|| {
                std::path::PathBuf::from(remote.rsplit('/').next().unwrap_or("download"))
            });
            let file = tokio::fs::File::create(&local).await?;
            let progress = |n: u64| eprint!("\r{n} bytes");
            let n = sftp.download(&remote, file, Some(&progress)).await?;
            eprintln!("\rDownloaded {} ({n} bytes)", local.display());
        }
        SftpCmd::Put { local, remote, .. } => {
            let file = tokio::fs::File::open(&local).await?;
            let progress = |n: u64| eprint!("\r{n} bytes");
            let n = sftp.upload(file, &remote, Some(&progress)).await?;
            eprintln!("\rUploaded {remote} ({n} bytes)");
        }
        SftpCmd::Mkdir { path, .. } => {
            sftp.mkdir_all(&path).await?;
            println!("Created {path}");
        }
        SftpCmd::Rm {
            path, recursive, ..
        } => {
            let e = sftp.stat(&path).await?;
            if e.kind == termoak_ssh::FileKind::Dir {
                sftp.remove_dir(&path, recursive).await?;
            } else {
                sftp.remove_file(&path).await?;
            }
            println!("Deleted {path}");
        }
    }
    sftp.close().await;
    conn.disconnect().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_parsing() {
        let f = parse_forward(ForwardKind::Local, "8080:localhost:80").unwrap();
        assert_eq!(
            (f.bind_port, f.dest_host.as_deref(), f.dest_port),
            (8080, Some("localhost"), Some(80))
        );
        let f = parse_forward(ForwardKind::Dynamic, "1080").unwrap();
        assert_eq!(f.bind_port, 1080);
        let f = parse_forward(ForwardKind::Remote, "0.0.0.0:9000:127.0.0.1:3000").unwrap();
        assert_eq!(f.bind_address, "0.0.0.0");
        assert!(parse_forward(ForwardKind::Local, "nothing").is_err());
    }
}

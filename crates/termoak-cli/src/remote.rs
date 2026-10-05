//! Terminal attached to a session that lives on the server.

use std::io::Write;
use std::time::Duration;

use anyhow::Result;
use crossterm::terminal;
use termoak_client::ApiClient;
use termoak_client::remote::{RemoteEvent, RemoteTerminal};
use termoak_core::Id;

use crate::term::{RawGuard, stdin_channel};

/// Ctrl+] detaches from the session (it stays alive on the server).
const DETACH: u8 = 0x1d;

pub async fn attach(api: &ApiClient, session: Id) -> Result<()> {
    let (remote, mut events) = RemoteTerminal::attach(api, session).await?;
    let raw = RawGuard::enable()?;
    let mut stdout = std::io::stdout();
    let mut input = stdin_channel();
    let mut size = terminal::size().unwrap_or((80, 24));
    remote.resize(size.0, size.1).await;
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let mut reason: Option<String> = None;
    loop {
        tokio::select! {
            ev = events.recv() => match ev {
                Some(RemoteEvent::Output(b)) => { stdout.write_all(&b)?; stdout.flush()?; }
                Some(RemoteEvent::Resync) => { stdout.write_all(b"\x1bc")?; }
                Some(RemoteEvent::Status(s)) => {
                    match s["state"].as_str() {
                        Some("closed") => { reason = Some(s["reason"].as_str().unwrap_or("session closed").to_string()); break; }
                        Some("connecting") => { let _ = write!(stdout, "\r\n[{}]\r\n", s["message"].as_str().unwrap_or("connecting…")); stdout.flush()?; }
                        _ => {}
                    }
                }
                Some(RemoteEvent::Prompt(p)) => {
                    // Prompts are answered outside raw mode.
                    let _ = terminal::disable_raw_mode();
                    let id: Id = p["prompt_id"].as_str().unwrap_or_default().parse().unwrap_or_default();
                    match p["kind"].as_str() {
                        Some("hostkey") => {
                            let ok = crate::prompt::ask_line(&format!("\n{}\nTrust it? [y/N] ", p["message"].as_str().unwrap_or("")))
                                .map(|a| matches!(a.trim().to_lowercase().as_str(), "y" | "yes"))
                                .unwrap_or(false);
                            remote.answer_prompt(id, Some(ok), None).await;
                        }
                        _ => {
                            eprintln!("\n{}", p["message"].as_str().unwrap_or(""));
                            let answers: Vec<String> = p["prompts"].as_array().into_iter().flatten().map(|q| {
                                let text = q["text"].as_str().unwrap_or("Answer: ").to_string();
                                if q["echo"].as_bool().unwrap_or(false) {
                                    crate::prompt::ask_line(&text).unwrap_or_default()
                                } else {
                                    rpassword::prompt_password(text).unwrap_or_default()
                                }
                            }).collect();
                            remote.answer_prompt(id, None, Some(answers)).await;
                        }
                    }
                    let _ = terminal::enable_raw_mode();
                }
                Some(RemoteEvent::Error(e)) => { let _ = write!(stdout, "\r\n[{e}]\r\n"); stdout.flush()?; }
                Some(RemoteEvent::Ended { message, .. }) => { reason = Some(message); break; }
                Some(RemoteEvent::Waiting(_)) => { let _ = write!(stdout, "\r\n[waiting for the owner to let you in…]\r\n"); stdout.flush()?; }
                Some(RemoteEvent::JoinRequest(p)) => { let _ = write!(stdout, "\r\n[{} is waiting to join: let them in from the app or the web]\r\n", p.name); stdout.flush()?; }
                Some(RemoteEvent::ControlRequest(p)) => { let _ = write!(stdout, "\r\n[{} asks for the keyboard: grant it from the app or the web]\r\n", p.name); stdout.flush()?; }
                Some(RemoteEvent::Control { can_write, driver_name, .. }) => {
                    let who = driver_name.unwrap_or_else(|| "the owner".into());
                    let _ = write!(stdout, "\r\n[{}]\r\n", if can_write { "you have the keyboard".to_string() } else { format!("read-only: {who} has the keyboard") });
                    stdout.flush()?;
                }
                Some(RemoteEvent::Closed) | None => break,
                Some(_) => {}
            },
            data = input.recv() => match data {
                Some(bytes) if bytes.contains(&DETACH) => { reason = Some("detached: the session stays alive on the server".into()); remote.detach().await; break; }
                Some(bytes) => remote.input(bytes).await,
                None => break,
            },
            _ = tick.tick() => {
                if let Ok(now) = terminal::size() && now != size {
                    size = now;
                    remote.resize(now.0, now.1).await;
                }
            }
        }
    }
    drop(raw);
    if let Some(r) = reason {
        eprintln!("\r\n{r}");
    }
    Ok(())
}

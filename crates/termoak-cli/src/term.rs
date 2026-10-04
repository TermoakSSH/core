//! Local interactive terminal: raw mode, input, output and resizing.

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use crossterm::terminal;
use termoak_ssh::{TermStatus, TerminalSession};
use tokio::sync::broadcast::error::RecvError;

/// Restores the terminal on exit (also on panic or error).
pub struct RawGuard;

impl RawGuard {
    pub fn enable() -> Result<Self> {
        terminal::enable_raw_mode()?;
        Ok(RawGuard)
    }
}

impl Drop for RawGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

/// Reads standard input on a thread and sends it over a channel.
pub fn stdin_channel() -> tokio::sync::mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    rx
}

/// Runs a local terminal until it closes.
pub async fn run_local(term: Arc<TerminalSession>) -> Result<()> {
    let _raw = RawGuard::enable()?;
    let mut stdout = std::io::stdout();
    let (snapshot, mut output) = term.attach();
    stdout.write_all(&snapshot)?;
    stdout.flush()?;
    let mut input = stdin_channel();
    let mut status = term.watch_status();
    let mut size = terminal::size().unwrap_or((80, 24));
    let mut resize_tick = tokio::time::interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            out = output.recv() => match out {
                Ok(bytes) => { stdout.write_all(&bytes)?; stdout.flush()?; }
                Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => break,
            },
            data = input.recv() => match data {
                Some(bytes) => term.write(bytes).await?,
                None => break,
            },
            _ = resize_tick.tick() => {
                if let Ok(now) = terminal::size() && now != size {
                    size = now;
                    let _ = term.resize(now.0, now.1).await;
                }
            }
            changed = status.changed() => {
                if changed.is_err() { break; }
                if let TermStatus::Closed { reason, .. } = status.borrow().clone() {
                    drop(_raw);
                    if let Some(r) = reason {
                        eprintln!("\r\nConnection closed: {r}");
                    }
                    return Ok(());
                }
            }
        }
    }
    Ok(())
}

//! Session recording in asciicast v2 format (playable with asciinema and with
//! the app's player).

use std::path::{Path, PathBuf};
use std::time::Instant;

use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;

enum Event {
    Output(Vec<u8>),
    Input(Vec<u8>),
    Resize(u16, u16),
}

/// Async recorder: events are queued and a tokio task writes them.
pub struct Recorder {
    tx: mpsc::UnboundedSender<(f64, Event)>,
    started: Instant,
    path: PathBuf,
    record_input: bool,
}

impl Recorder {
    /// Creates the file and writes the header.
    pub async fn create(
        path: &Path,
        cols: u16,
        rows: u16,
        title: &str,
        record_input: bool,
    ) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let file = tokio::fs::File::create(path).await?;
        let mut writer = BufWriter::new(file);
        let header = serde_json::json!({
            "version": 2,
            "width": cols,
            "height": rows,
            "timestamp": chrono::Utc::now().timestamp(),
            "title": title,
            "env": { "TERM": "xterm-256color" },
        });
        writer.write_all(header.to_string().as_bytes()).await?;
        writer.write_all(b"\n").await?;

        let (tx, mut rx) = mpsc::unbounded_channel::<(f64, Event)>();
        tokio::spawn(async move {
            // Incomplete UTF-8 bytes left over from the previous chunk.
            let mut pending_out: Vec<u8> = Vec::new();
            let mut pending_in: Vec<u8> = Vec::new();
            let mut since_flush = 0usize;
            while let Some((t, ev)) = rx.recv().await {
                let line = match ev {
                    Event::Output(data) => {
                        let text = take_utf8(&mut pending_out, &data);
                        if text.is_empty() {
                            continue;
                        }
                        serde_json::json!([t, "o", text])
                    }
                    Event::Input(data) => {
                        let text = take_utf8(&mut pending_in, &data);
                        if text.is_empty() {
                            continue;
                        }
                        serde_json::json!([t, "i", text])
                    }
                    Event::Resize(c, r) => serde_json::json!([t, "r", format!("{c}x{r}")]),
                };
                let s = line.to_string();
                if writer.write_all(s.as_bytes()).await.is_err()
                    || writer.write_all(b"\n").await.is_err()
                {
                    break;
                }
                since_flush += s.len();
                if since_flush > 64 * 1024 || rx.is_empty() {
                    let _ = writer.flush().await;
                    since_flush = 0;
                }
            }
            let _ = writer.flush().await;
        });
        Ok(Self {
            tx,
            started: Instant::now(),
            path: path.to_path_buf(),
            record_input,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn elapsed(&self) -> f64 {
        (self.started.elapsed().as_micros() as f64 / 1_000_000.0 * 1000.0).round() / 1000.0
    }

    pub fn output(&self, data: &[u8]) {
        let _ = self.tx.send((self.elapsed(), Event::Output(data.to_vec())));
    }

    /// Input is only recorded if explicitly requested (it may contain passwords).
    pub fn input(&self, data: &[u8]) {
        if self.record_input {
            let _ = self.tx.send((self.elapsed(), Event::Input(data.to_vec())));
        }
    }

    pub fn resize(&self, cols: u16, rows: u16) {
        let _ = self.tx.send((self.elapsed(), Event::Resize(cols, rows)));
    }
}

/// Joins `pending` + `data` and returns the valid UTF-8 prefix, keeping in
/// `pending` the bytes of an incomplete character at the end.
fn take_utf8(pending: &mut Vec<u8>, data: &[u8]) -> String {
    pending.extend_from_slice(data);
    match std::str::from_utf8(pending) {
        Ok(s) => {
            let out = s.to_string();
            pending.clear();
            out
        }
        Err(e) => {
            let valid = e.valid_up_to();
            // If the error is not an incomplete character at the end, replace it.
            if e.error_len().is_some() {
                let out = String::from_utf8_lossy(pending).into_owned();
                pending.clear();
                return out;
            }
            let out = String::from_utf8_lossy(&pending[..valid]).into_owned();
            pending.drain(..valid);
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_split_across_chunks() {
        let mut pending = Vec::new();
        let bytes = "ñ".as_bytes();
        assert_eq!(take_utf8(&mut pending, &bytes[..1]), "");
        assert_eq!(take_utf8(&mut pending, &bytes[1..]), "ñ");
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn writes_asciicast() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rec.cast");
        let rec = Recorder::create(&path, 80, 24, "test", false)
            .await
            .unwrap();
        rec.output(b"hello\r\n");
        rec.input(b"secret");
        rec.resize(100, 30);
        drop(rec);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("\"version\":2"));
        assert!(lines[1].contains("\"o\""));
        assert!(!content.contains("secret"));
        assert!(lines[2].contains("100x30"));
    }
}

//! SFTP: browse, read, write, upload, download, rename, delete and permissions.

use std::sync::Arc;

use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{FileAttributes, FileType, OpenFlags};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::client::Connection;
use crate::error::{Result, SshError};

/// Entry type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    Dir,
    File,
    Symlink,
    Other,
}

/// Remote directory entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub kind: FileKind,
    pub size: u64,
    /// Unix permissions (e.g. 0o644), if the server reports them.
    pub mode: Option<u32>,
    /// Permissions as text (`drwxr-xr-x`).
    pub mode_string: String,
    /// Last modification (Unix seconds).
    pub modified: Option<i64>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub owner: Option<String>,
    pub group: Option<String>,
}

/// Transfer progress.
pub type Progress<'a> = &'a (dyn Fn(u64) + Send + Sync);

/// SFTP session over a connection.
pub struct Sftp {
    session: SftpSession,
    _conn: Arc<Connection>,
}

const CHUNK: usize = 256 * 1024;

fn kind_of(attrs: &FileAttributes) -> FileKind {
    match attrs.file_type() {
        FileType::Dir => FileKind::Dir,
        FileType::File => FileKind::File,
        FileType::Symlink => FileKind::Symlink,
        FileType::Other => FileKind::Other,
    }
}

/// `drwxr-xr-x` from the mode bits.
pub fn mode_string(kind: FileKind, mode: Option<u32>) -> String {
    let Some(mode) = mode else {
        return String::new();
    };
    let t = match kind {
        FileKind::Dir => 'd',
        FileKind::Symlink => 'l',
        FileKind::File => '-',
        FileKind::Other => '?',
    };
    let mut s = String::with_capacity(10);
    s.push(t);
    for shift in [6u32, 3, 0] {
        let bits = (mode >> shift) & 0o7;
        s.push(if bits & 4 != 0 { 'r' } else { '-' });
        s.push(if bits & 2 != 0 { 'w' } else { '-' });
        s.push(if bits & 1 != 0 { 'x' } else { '-' });
    }
    s
}

fn entry(name: String, path: String, attrs: &FileAttributes) -> FileEntry {
    let kind = kind_of(attrs);
    let mode = attrs.permissions.map(|p| p & 0o7777);
    FileEntry {
        mode_string: mode_string(kind, mode),
        name,
        path,
        kind,
        size: attrs.size.unwrap_or(0),
        mode,
        modified: attrs.mtime.map(|m| m as i64),
        uid: attrs.uid,
        gid: attrs.gid,
        owner: attrs.user.clone(),
        group: attrs.group.clone(),
    }
}

/// Joins `dir` and `name` with `/`.
pub fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() || dir == "." {
        name.to_string()
    } else if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

impl Connection {
    /// Opens the SFTP subsystem.
    pub async fn sftp(self: &Arc<Self>) -> Result<Sftp> {
        let channel = self.open_session_channel().await?;
        channel.request_subsystem(true, "sftp").await?;
        let session = SftpSession::new(channel.into_stream()).await?;
        Ok(Sftp {
            session,
            _conn: self.clone(),
        })
    }
}

impl Sftp {
    /// The user's initial (home) directory.
    pub async fn home(&self) -> Result<String> {
        Ok(self.session.canonicalize(".").await?)
    }

    pub async fn canonicalize(&self, path: &str) -> Result<String> {
        Ok(self.session.canonicalize(path).await?)
    }

    /// Lists a directory: folders first, then by name. Without `.` or `..`.
    pub async fn list(&self, path: &str) -> Result<Vec<FileEntry>> {
        let dir = self.session.read_dir(path).await?;
        let mut out: Vec<FileEntry> = dir
            .filter(|e| {
                let n = e.file_name();
                n != "." && n != ".."
            })
            .map(|e| {
                let name = e.file_name();
                let full = join(path, &name);
                entry(name, full, &e.metadata())
            })
            .collect();
        out.sort_by(|a, b| {
            (a.kind != FileKind::Dir)
                .cmp(&(b.kind != FileKind::Dir))
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        Ok(out)
    }

    pub async fn stat(&self, path: &str) -> Result<FileEntry> {
        let attrs = self.session.metadata(path).await?;
        let name = path.rsplit('/').next().unwrap_or(path).to_string();
        Ok(entry(name, path.to_string(), &attrs))
    }

    pub async fn exists(&self, path: &str) -> Result<bool> {
        Ok(self.session.try_exists(path).await?)
    }

    /// Reads a whole file (with a size cap).
    pub async fn read(&self, path: &str, max_bytes: u64) -> Result<Vec<u8>> {
        let size = self.session.metadata(path).await?.size.unwrap_or(0);
        if size > max_bytes {
            return Err(SshError::Sftp(format!(
                "the file is {size} bytes, more than the allowed maximum ({max_bytes})"
            )));
        }
        let mut file = self.session.open(path).await?;
        let mut buf = Vec::with_capacity(size as usize);
        (&mut file)
            .take(max_bytes + 1)
            .read_to_end(&mut buf)
            .await?;
        if buf.len() as u64 > max_bytes {
            return Err(SshError::Sftp("the file grew while being read".into()));
        }
        Ok(buf)
    }

    /// Writes (creates or overwrites) a file.
    pub async fn write(&self, path: &str, data: &[u8], mode: Option<u32>) -> Result<()> {
        let mut file = self
            .session
            .open_with_flags(
                path,
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            )
            .await?;
        for chunk in data.chunks(CHUNK) {
            file.write_all(chunk).await?;
        }
        file.flush().await?;
        file.shutdown().await?;
        if let Some(mode) = mode {
            self.chmod(path, mode).await?;
        }
        Ok(())
    }

    /// Downloads to any async destination. Returns the bytes copied.
    pub async fn download<W: AsyncWrite + Unpin>(
        &self,
        path: &str,
        mut dest: W,
        progress: Option<Progress<'_>>,
    ) -> Result<u64> {
        let mut file = self.session.open(path).await?;
        let mut buf = vec![0u8; CHUNK];
        let mut total = 0u64;
        loop {
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            dest.write_all(&buf[..n]).await?;
            total += n as u64;
            if let Some(p) = progress {
                p(total);
            }
        }
        dest.flush().await?;
        Ok(total)
    }

    /// Uploads from any async source. Returns the bytes copied.
    pub async fn upload<R: AsyncRead + Unpin>(
        &self,
        mut src: R,
        path: &str,
        progress: Option<Progress<'_>>,
    ) -> Result<u64> {
        let mut file = self
            .session
            .open_with_flags(
                path,
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            )
            .await?;
        let mut buf = vec![0u8; CHUNK];
        let mut total = 0u64;
        loop {
            let n = src.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n]).await?;
            total += n as u64;
            if let Some(p) = progress {
                p(total);
            }
        }
        file.flush().await?;
        file.shutdown().await?;
        Ok(total)
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        Ok(self.session.create_dir(path).await?)
    }

    /// Creates the directory and any missing parents.
    pub async fn mkdir_all(&self, path: &str) -> Result<()> {
        let mut current = if path.starts_with('/') {
            String::from("/")
        } else {
            String::new()
        };
        for part in path.split('/').filter(|p| !p.is_empty()) {
            current = join(&current, part);
            if !self.session.try_exists(current.as_str()).await? {
                self.session.create_dir(current.as_str()).await?;
            }
        }
        Ok(())
    }

    pub async fn remove_file(&self, path: &str) -> Result<()> {
        Ok(self.session.remove_file(path).await?)
    }

    /// Removes a directory; with `recursive`, its contents too.
    pub async fn remove_dir(&self, path: &str, recursive: bool) -> Result<()> {
        if recursive {
            let mut stack = vec![(path.to_string(), false)];
            while let Some((dir, visited)) = stack.pop() {
                if visited {
                    self.session.remove_dir(dir.as_str()).await?;
                    continue;
                }
                stack.push((dir.clone(), true));
                for e in self.list(&dir).await? {
                    match e.kind {
                        FileKind::Dir => stack.push((e.path, false)),
                        _ => self.session.remove_file(e.path.as_str()).await?,
                    }
                }
            }
            Ok(())
        } else {
            Ok(self.session.remove_dir(path).await?)
        }
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<()> {
        Ok(self.session.rename(from, to).await?)
    }

    pub async fn chmod(&self, path: &str, mode: u32) -> Result<()> {
        let attrs = FileAttributes {
            permissions: Some(mode & 0o7777),
            ..FileAttributes::empty()
        };
        Ok(self.session.set_metadata(path, attrs).await?)
    }

    pub async fn symlink(&self, path: &str, target: &str) -> Result<()> {
        Ok(self.session.symlink(path, target).await?)
    }

    pub async fn read_link(&self, path: &str) -> Result<String> {
        Ok(self.session.read_link(path).await?)
    }

    pub async fn close(&self) {
        let _ = self.session.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes() {
        assert_eq!(mode_string(FileKind::Dir, Some(0o755)), "drwxr-xr-x");
        assert_eq!(mode_string(FileKind::File, Some(0o640)), "-rw-r-----");
        assert_eq!(join("/home/a", "b"), "/home/a/b");
        assert_eq!(join("/", "etc"), "/etc");
    }
}

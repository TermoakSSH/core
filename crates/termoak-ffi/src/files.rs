//! Files through the server: SFTP on the synced hosts (the server makes the
//! SSH connection) and session recordings. Everything is streamed straight
//! to disk, with progress.
//!
//! Useful for hosts the phone cannot reach directly (only the server has a
//! network route to them) or whose keys only live on the server.

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{Value, json};
use termoak_ssh::sftp::FileEntry;

use crate::accounts::AccountHandle;
use crate::error::{Result, TermoakError};
use crate::models::parse_id;
use crate::ssh::{RemoteFile, TransferListener};
use crate::transfer::{TransferHandle, cancellable};
use crate::vault::TermoakCore;

fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn check_remote(path: &str) -> Result<()> {
    if path.is_empty() || path.contains('\0') {
        return Err(TermoakError::Invalid("invalid remote path".into()));
    }
    Ok(())
}

/// `<local_path>.part`, where a download is written until it completes.
fn part_of(local_path: &str) -> PathBuf {
    PathBuf::from(format!("{local_path}.part"))
}

/// Largest file `server_sftp_read` reads when the app passes 0.
const DEFAULT_READ_MAX: u64 = 16 * 1024 * 1024;

/// Progress towards the app's `TransferListener` (if any).
fn progress(listener: Option<Arc<dyn TransferListener>>) -> impl FnMut(u64, Option<u64>) + Send {
    move |done, total| {
        if let Some(l) = &listener {
            l.on_progress(done, total);
        }
    }
}

#[uniffi::export]
impl TermoakCore {
    /// The user's home directory on a host, over SFTP from the server.
    #[uniffi::method(default(account_id))]
    pub async fn server_sftp_home(
        &self,
        host_id: String,
        account_id: Option<String>,
    ) -> Result<String> {
        let id = parse_id(&host_id)?;
        self.with_host_api(id, &account_id, move |api| async move {
            let v: Value = api.get(&format!("/api/v1/hosts/{id}/sftp/home")).await?;
            Ok(v["path"].as_str().unwrap_or("/").to_string())
        })
        .await
    }

    /// Lists a directory over SFTP from the server.
    #[uniffi::method(default(account_id))]
    pub async fn server_sftp_list(
        &self,
        host_id: String,
        path: String,
        account_id: Option<String>,
    ) -> Result<Vec<RemoteFile>> {
        let id = parse_id(&host_id)?;
        check_remote(&path)?;
        self.with_host_api(id, &account_id, move |api| async move {
            let list: Vec<FileEntry> = api
                .get(&format!("/api/v1/hosts/{id}/sftp/list?path={}", enc(&path)))
                .await?;
            Ok(list.into_iter().map(Into::into).collect())
        })
        .await
    }

    /// Downloads a remote file to `local_path` (streamed; while in progress it
    /// is written to `local_path.part`). Returns the number of bytes.
    /// `cancel` stops it (`Cancelled`, the `.part` file is removed).
    #[uniffi::method(default(account_id = None, cancel = None))]
    pub async fn server_sftp_download(
        &self,
        host_id: String,
        remote_path: String,
        local_path: String,
        listener: Option<Arc<dyn TransferListener>>,
        account_id: Option<String>,
        cancel: Option<Arc<TransferHandle>>,
    ) -> Result<u64> {
        let id = parse_id(&host_id)?;
        check_remote(&remote_path)?;
        self.with_host_api(id, &account_id, move |api| async move {
            let path = format!(
                "/api/v1/hosts/{id}/sftp/download?path={}",
                enc(&remote_path)
            );
            let part = part_of(&local_path);
            cancellable(
                cancel,
                async {
                    Ok(api
                        .download_to(&path, &PathBuf::from(&local_path), progress(listener))
                        .await?)
                },
                || async move {
                    let _ = tokio::fs::remove_file(part).await;
                },
            )
            .await
        })
        .await
    }

    /// Uploads a local file to `remote_path` (replacing it if it exists).
    /// Returns the number of bytes. `cancel` stops it (`Cancelled`; the
    /// server keeps whatever arrived, as with a dropped connection).
    #[uniffi::method(default(account_id = None, cancel = None))]
    pub async fn server_sftp_upload(
        &self,
        host_id: String,
        local_path: String,
        remote_path: String,
        listener: Option<Arc<dyn TransferListener>>,
        account_id: Option<String>,
        cancel: Option<Arc<TransferHandle>>,
    ) -> Result<u64> {
        let id = parse_id(&host_id)?;
        check_remote(&remote_path)?;
        self.with_host_api(id, &account_id, move |api| async move {
            let path = format!("/api/v1/hosts/{id}/sftp/upload?path={}", enc(&remote_path));
            cancellable(
                cancel,
                async {
                    let v = api
                        .upload_from(&path, &PathBuf::from(local_path), progress(listener))
                        .await?;
                    Ok(v["bytes"].as_u64().unwrap_or(0))
                },
                || async {},
            )
            .await
        })
        .await
    }

    /// Details of a remote file or directory (size, permissions, dates),
    /// over SFTP from the server.
    #[uniffi::method(default(account_id))]
    pub async fn server_sftp_stat(
        &self,
        host_id: String,
        path: String,
        account_id: Option<String>,
    ) -> Result<RemoteFile> {
        let id = parse_id(&host_id)?;
        check_remote(&path)?;
        self.with_host_api(id, &account_id, move |api| async move {
            let e: FileEntry = api
                .get(&format!("/api/v1/hosts/{id}/sftp/stat?path={}", enc(&path)))
                .await?;
            Ok(e.into())
        })
        .await
    }

    /// Changes the permissions of a remote file (e.g. `0o644`, `0o755`).
    #[uniffi::method(default(account_id))]
    pub async fn server_sftp_chmod(
        &self,
        host_id: String,
        path: String,
        mode: u32,
        account_id: Option<String>,
    ) -> Result<()> {
        let id = parse_id(&host_id)?;
        check_remote(&path)?;
        if mode > 0o7777 {
            return Err(TermoakError::Invalid(format!(
                "invalid permissions: {mode:o} (at most 7777 in octal)"
            )));
        }
        self.with_host_api(id, &account_id, move |api| async move {
            let _: Value = api
                .post(
                    &format!("/api/v1/hosts/{id}/sftp/chmod"),
                    &json!({"path": path, "mode": format!("{mode:o}")}),
                )
                .await?;
            Ok(())
        })
        .await
    }

    /// Reads a whole remote file into memory (viewers and editors). Fails
    /// with `Invalid` above `max_bytes` (0 = 16 MiB).
    #[uniffi::method(default(max_bytes = 0, account_id = None))]
    pub async fn server_sftp_read(
        &self,
        host_id: String,
        path: String,
        max_bytes: u64,
        account_id: Option<String>,
    ) -> Result<Vec<u8>> {
        let id = parse_id(&host_id)?;
        check_remote(&path)?;
        let max = if max_bytes == 0 {
            DEFAULT_READ_MAX
        } else {
            max_bytes
        };
        self.with_host_api(id, &account_id, move |api| async move {
            Ok(api
                .download_bytes(
                    &format!("/api/v1/hosts/{id}/sftp/download?path={}", enc(&path)),
                    max,
                )
                .await?)
        })
        .await
    }

    /// Writes (creates or replaces) a remote file with `data`. Returns the
    /// number of bytes written.
    #[uniffi::method(default(account_id))]
    pub async fn server_sftp_write(
        &self,
        host_id: String,
        path: String,
        data: Vec<u8>,
        account_id: Option<String>,
    ) -> Result<u64> {
        let id = parse_id(&host_id)?;
        check_remote(&path)?;
        self.with_host_api(id, &account_id, move |api| async move {
            let v = api
                .upload_bytes(
                    &format!("/api/v1/hosts/{id}/sftp/upload?path={}", enc(&path)),
                    data,
                )
                .await?;
            Ok(v["bytes"].as_u64().unwrap_or(0))
        })
        .await
    }

    /// Creates a remote directory (`parents` = also the intermediate ones).
    #[uniffi::method(default(account_id))]
    pub async fn server_sftp_mkdir(
        &self,
        host_id: String,
        path: String,
        parents: bool,
        account_id: Option<String>,
    ) -> Result<()> {
        let id = parse_id(&host_id)?;
        check_remote(&path)?;
        self.with_host_api(id, &account_id, move |api| async move {
            let _: Value = api
                .post(
                    &format!("/api/v1/hosts/{id}/sftp/mkdir"),
                    &json!({"path": path, "parents": parents}),
                )
                .await?;
            Ok(())
        })
        .await
    }

    /// Renames or moves a remote file.
    #[uniffi::method(default(account_id))]
    pub async fn server_sftp_rename(
        &self,
        host_id: String,
        from: String,
        to: String,
        account_id: Option<String>,
    ) -> Result<()> {
        let id = parse_id(&host_id)?;
        check_remote(&from)?;
        check_remote(&to)?;
        self.with_host_api(id, &account_id, move |api| async move {
            let _: Value = api
                .post(
                    &format!("/api/v1/hosts/{id}/sftp/rename"),
                    &json!({"from": from, "to": to}),
                )
                .await?;
            Ok(())
        })
        .await
    }

    /// Deletes a remote file or directory (`recursive` for non-empty
    /// directories).
    #[uniffi::method(default(account_id))]
    pub async fn server_sftp_delete(
        &self,
        host_id: String,
        path: String,
        recursive: bool,
        account_id: Option<String>,
    ) -> Result<()> {
        let id = parse_id(&host_id)?;
        check_remote(&path)?;
        self.with_host_api(id, &account_id, move |api| async move {
            let _: Value = api
                .post(
                    &format!("/api/v1/hosts/{id}/sftp/delete"),
                    &json!({"path": path, "recursive": recursive}),
                )
                .await?;
            Ok(())
        })
        .await
    }

    /// Downloads the recording (asciicast v2, `.cast`) of a server session to
    /// `local_path`. Returns the number of bytes. `cancel` stops it.
    #[uniffi::method(default(cancel))]
    pub async fn download_recording(
        &self,
        session_id: String,
        local_path: String,
        listener: Option<Arc<dyn TransferListener>>,
        cancel: Option<Arc<TransferHandle>>,
    ) -> Result<u64> {
        let id = parse_id(&session_id)?;
        self.with_api(move |api| async move {
            let part = part_of(&local_path);
            cancellable(
                cancel,
                async {
                    Ok(api
                        .download_to(
                            &format!("/api/v1/sessions/{id}/recording"),
                            &PathBuf::from(&local_path),
                            progress(listener),
                        )
                        .await?)
                },
                || async move {
                    let _ = tokio::fs::remove_file(part).await;
                },
            )
            .await
        })
        .await
    }
}

/// Files through this account's server.
#[uniffi::export]
impl AccountHandle {
    #[uniffi::method(default(cancel))]
    pub async fn server_sftp_download(
        &self,
        host_id: String,
        remote_path: String,
        local_path: String,
        listener: Option<Arc<dyn TransferListener>>,
        cancel: Option<Arc<TransferHandle>>,
    ) -> Result<u64> {
        self.core()
            .server_sftp_download(
                host_id,
                remote_path,
                local_path,
                listener,
                Some(self.id()),
                cancel,
            )
            .await
    }

    #[uniffi::method(default(cancel))]
    pub async fn server_sftp_upload(
        &self,
        host_id: String,
        local_path: String,
        remote_path: String,
        listener: Option<Arc<dyn TransferListener>>,
        cancel: Option<Arc<TransferHandle>>,
    ) -> Result<u64> {
        self.core()
            .server_sftp_upload(
                host_id,
                local_path,
                remote_path,
                listener,
                Some(self.id()),
                cancel,
            )
            .await
    }

    pub async fn server_sftp_mkdir(
        &self,
        host_id: String,
        path: String,
        parents: bool,
    ) -> Result<()> {
        self.core()
            .server_sftp_mkdir(host_id, path, parents, Some(self.id()))
            .await
    }

    pub async fn server_sftp_rename(
        &self,
        host_id: String,
        from: String,
        to: String,
    ) -> Result<()> {
        self.core()
            .server_sftp_rename(host_id, from, to, Some(self.id()))
            .await
    }

    pub async fn server_sftp_delete(
        &self,
        host_id: String,
        path: String,
        recursive: bool,
    ) -> Result<()> {
        self.core()
            .server_sftp_delete(host_id, path, recursive, Some(self.id()))
            .await
    }

    pub async fn server_sftp_stat(&self, host_id: String, path: String) -> Result<RemoteFile> {
        self.core()
            .server_sftp_stat(host_id, path, Some(self.id()))
            .await
    }

    pub async fn server_sftp_chmod(&self, host_id: String, path: String, mode: u32) -> Result<()> {
        self.core()
            .server_sftp_chmod(host_id, path, mode, Some(self.id()))
            .await
    }

    #[uniffi::method(default(max_bytes = 0))]
    pub async fn server_sftp_read(
        &self,
        host_id: String,
        path: String,
        max_bytes: u64,
    ) -> Result<Vec<u8>> {
        self.core()
            .server_sftp_read(host_id, path, max_bytes, Some(self.id()))
            .await
    }

    pub async fn server_sftp_write(
        &self,
        host_id: String,
        path: String,
        data: Vec<u8>,
    ) -> Result<u64> {
        self.core()
            .server_sftp_write(host_id, path, data, Some(self.id()))
            .await
    }

    /// Downloads the recording of one of this account's server sessions.
    #[uniffi::method(default(cancel))]
    pub async fn download_recording(
        &self,
        session_id: String,
        local_path: String,
        listener: Option<Arc<dyn TransferListener>>,
        cancel: Option<Arc<TransferHandle>>,
    ) -> Result<u64> {
        self.core()
            .download_recording(session_id, local_path, listener, cancel)
            .await
    }
}

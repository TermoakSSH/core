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

use crate::error::{Result, TermoakError};
use crate::models::parse_id;
use crate::ssh::{RemoteFile, TransferListener};
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
    #[uniffi::method(default(account_id))]
    pub async fn server_sftp_download(
        &self,
        host_id: String,
        remote_path: String,
        local_path: String,
        listener: Option<Arc<dyn TransferListener>>,
        account_id: Option<String>,
    ) -> Result<u64> {
        let id = parse_id(&host_id)?;
        check_remote(&remote_path)?;
        self.with_host_api(id, &account_id, move |api| async move {
            let path = format!(
                "/api/v1/hosts/{id}/sftp/download?path={}",
                enc(&remote_path)
            );
            Ok(api
                .download_to(&path, &PathBuf::from(local_path), progress(listener))
                .await?)
        })
        .await
    }

    /// Uploads a local file to `remote_path` (replacing it if it exists).
    /// Returns the number of bytes.
    #[uniffi::method(default(account_id))]
    pub async fn server_sftp_upload(
        &self,
        host_id: String,
        local_path: String,
        remote_path: String,
        listener: Option<Arc<dyn TransferListener>>,
        account_id: Option<String>,
    ) -> Result<u64> {
        let id = parse_id(&host_id)?;
        check_remote(&remote_path)?;
        self.with_host_api(id, &account_id, move |api| async move {
            let path = format!("/api/v1/hosts/{id}/sftp/upload?path={}", enc(&remote_path));
            let v = api
                .upload_from(&path, &PathBuf::from(local_path), progress(listener))
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
    /// `local_path`. Returns the number of bytes.
    pub async fn download_recording(
        &self,
        session_id: String,
        local_path: String,
        listener: Option<Arc<dyn TransferListener>>,
    ) -> Result<u64> {
        let id = parse_id(&session_id)?;
        self.with_api(move |api| async move {
            Ok(api
                .download_to(
                    &format!("/api/v1/sessions/{id}/recording"),
                    &PathBuf::from(local_path),
                    progress(listener),
                )
                .await?)
        })
        .await
    }
}

//! Termoak automatic updates.
//!
//! Flow:
//! 1. While the app runs, [`Updater::check`] fetches a JSON manifest (by
//!    default, the one of the latest GitHub Release).
//! 2. If there is a new version, [`Updater::download`] fetches it in the
//!    background into a staging directory and checks **SHA-256 and the Ed25519
//!    signature** (the public key is compiled into the app).
//! 3. On restart, [`Updater::apply_pending`] replaces the installation before
//!    opening the window and the app relaunches already updated.
//!
//! Formats: standalone executable (Windows/Linux), AppImage (Linux) and a
//! `.app` bundle packed as `.tar.gz` (macOS). System-managed installations
//! (`.deb`, `.rpm`, `.msi` in Program Files) are only notified.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sha2_10::{Digest, Sha256};
use thiserror::Error;
use tokio::io::AsyncWriteExt;

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("network: {0}")]
    Network(String),
    #[error("invalid manifest: {0}")]
    Manifest(String),
    #[error("the update is not correctly signed")]
    BadSignature,
    #[error("the downloaded file does not match its hash")]
    BadHash,
    #[error("this installation is managed by the system; update it with its package manager")]
    Managed,
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T, E = UpdateError> = std::result::Result<T, E>;

/// Manifest published with each version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub pub_date: String,
    /// Platform (`linux-x86_64`, `windows-x86_64`, `macos-universal`...) → asset.
    pub platforms: BTreeMap<String, Asset>,
}

/// Asset for one platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub url: String,
    pub sha256: String,
    #[serde(default)]
    pub size: u64,
    /// Ed25519 signature (base64) of [`signing_message`].
    pub signature: String,
    /// `bin`, `appimage` or `app.tar.gz`.
    pub format: String,
}

/// How the app is installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Install {
    /// Standalone executable that can be replaced.
    Binary(PathBuf),
    /// Linux AppImage.
    AppImage(PathBuf),
    /// macOS `.app` bundle (path of the bundle).
    MacApp(PathBuf),
    /// Managed by the system (notification only).
    Managed,
}

impl Install {
    /// Detects the current installation.
    pub fn detect() -> Install {
        if let Ok(appimage) = std::env::var("APPIMAGE")
            && !appimage.is_empty()
        {
            return Install::AppImage(PathBuf::from(appimage));
        }
        let Ok(exe) = std::env::current_exe() else {
            return Install::Managed;
        };
        let exe = exe.canonicalize().unwrap_or(exe);
        let s = exe.to_string_lossy().to_string();
        if let Some(idx) = s.find(".app/Contents/MacOS/") {
            return Install::MacApp(PathBuf::from(&s[..idx + 4]));
        }
        let managed_prefixes = ["/usr/", "/opt/", "/snap/", "/nix/"];
        if cfg!(target_os = "linux") && managed_prefixes.iter().any(|p| s.starts_with(p)) {
            return Install::Managed;
        }
        match exe.parent() {
            Some(dir) if is_writable(dir) => Install::Binary(exe),
            _ => Install::Managed,
        }
    }

    pub fn format(&self) -> &'static str {
        match self {
            Install::Binary(_) => "bin",
            Install::AppImage(_) => "appimage",
            Install::MacApp(_) => "app.tar.gz",
            Install::Managed => "managed",
        }
    }
}

fn is_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".termoak-write-test-{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(probe);
            true
        }
        Err(_) => false,
    }
}

/// Platform identifier of this build.
pub fn current_target() -> String {
    let os = std::env::consts::OS;
    if os == "macos" {
        return "macos-universal".into();
    }
    format!("{os}-{}", std::env::consts::ARCH)
}

/// Signed message: binds version, platform and contents.
pub fn signing_message(target: &str, version: &str, sha256: &str) -> Vec<u8> {
    // The "aceitunoak-update" prefix is frozen: clients released before the rename
    // verify Termoak updates with it.
    format!(
        "aceitunoak-update:v1:{target}:{version}:{}",
        sha256.to_lowercase()
    )
    .into_bytes()
}

/// Signs an asset (used by CI when publishing).
pub fn sign(secret: &SigningKey, target: &str, version: &str, sha256: &str) -> String {
    STANDARD.encode(
        secret
            .sign(&signing_message(target, version, sha256))
            .to_bytes(),
    )
}

/// Verifies the signature of an asset.
pub fn verify(public: &VerifyingKey, target: &str, version: &str, asset: &Asset) -> Result<()> {
    let raw = STANDARD
        .decode(asset.signature.trim())
        .map_err(|_| UpdateError::BadSignature)?;
    let bytes: [u8; 64] = raw.try_into().map_err(|_| UpdateError::BadSignature)?;
    let sig = Signature::from_bytes(&bytes);
    public
        .verify(&signing_message(target, version, &asset.sha256), &sig)
        .map_err(|_| UpdateError::BadSignature)
}

/// Public key from base64.
pub fn public_key_from_base64(b64: &str) -> Option<VerifyingKey> {
    let raw = STANDARD.decode(b64.trim()).ok()?;
    let bytes: [u8; 32] = raw.try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

/// Available update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Available {
    pub version: String,
    pub notes: String,
    pub asset: Asset,
    /// The installation is managed: it can only be notified.
    pub notify_only: bool,
}

/// Downloaded and verified update, ready to apply on restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Pending {
    version: String,
    target: String,
    format: String,
    file: PathBuf,
    sha256: String,
}

/// Result of applying on startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applied {
    Nothing,
    /// Updated to this version: the app should relaunch.
    Updated(String),
}

/// Updater configuration.
#[derive(Debug, Clone)]
pub struct UpdateConfig {
    pub manifest_url: String,
    pub public_key: VerifyingKey,
    pub current_version: semver::Version,
    pub target: String,
    pub install: Install,
    pub staging_dir: PathBuf,
}

/// Updater.
pub struct Updater {
    cfg: UpdateConfig,
    http: reqwest::Client,
}

impl Updater {
    pub fn new(cfg: UpdateConfig) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(concat!("Termoak-updater/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("HTTP client");
        Self { cfg, http }
    }

    pub fn config(&self) -> &UpdateConfig {
        &self.cfg
    }

    fn pending_path(&self) -> PathBuf {
        self.cfg.staging_dir.join("pending.json")
    }

    /// Checks whether there is a newer version for this platform.
    pub async fn check(&self) -> Result<Option<Available>> {
        let manifest: Manifest = self
            .http
            .get(&self.cfg.manifest_url)
            .send()
            .await
            .map_err(|e| UpdateError::Network(e.to_string()))?
            .error_for_status()
            .map_err(|e| UpdateError::Network(e.to_string()))?
            .json()
            .await
            .map_err(|e| UpdateError::Manifest(e.to_string()))?;
        let version = semver::Version::parse(manifest.version.trim_start_matches('v'))
            .map_err(|e| UpdateError::Manifest(e.to_string()))?;
        if version <= self.cfg.current_version {
            return Ok(None);
        }
        let Some(asset) = manifest.platforms.get(&self.cfg.target).cloned() else {
            return Ok(None);
        };
        verify(
            &self.cfg.public_key,
            &self.cfg.target,
            &manifest.version,
            &asset,
        )?;
        let notify_only =
            self.cfg.install == Install::Managed || asset.format != self.cfg.install.format();
        Ok(Some(Available {
            version: manifest.version,
            notes: manifest.notes,
            asset,
            notify_only,
        }))
    }

    /// Downloads and verifies the update; it is ready for the next startup.
    pub async fn download(&self, available: &Available, progress: impl Fn(u64, u64)) -> Result<()> {
        if available.notify_only {
            return Err(UpdateError::Managed);
        }
        let dir = self.cfg.staging_dir.join(&available.version);
        tokio::fs::create_dir_all(&dir).await?;
        let file = dir.join(format!("update.{}", available.asset.format));
        let resp = self
            .http
            .get(&available.asset.url)
            .send()
            .await
            .map_err(|e| UpdateError::Network(e.to_string()))?
            .error_for_status()
            .map_err(|e| UpdateError::Network(e.to_string()))?;
        let total = resp.content_length().unwrap_or(available.asset.size);
        let mut out = tokio::fs::File::create(&file).await?;
        let mut hasher = Sha256::new();
        let mut done = 0u64;
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| UpdateError::Network(e.to_string()))?;
            hasher.update(&chunk);
            out.write_all(&chunk).await?;
            done += chunk.len() as u64;
            progress(done, total);
        }
        out.flush().await?;
        drop(out);
        let digest = hex::encode(hasher.finalize());
        if !digest.eq_ignore_ascii_case(&available.asset.sha256) {
            let _ = tokio::fs::remove_file(&file).await;
            return Err(UpdateError::BadHash);
        }
        let pending = Pending {
            version: available.version.clone(),
            target: self.cfg.target.clone(),
            format: available.asset.format.clone(),
            file,
            sha256: digest,
        };
        tokio::fs::write(
            self.pending_path(),
            serde_json::to_vec_pretty(&pending).unwrap_or_default(),
        )
        .await?;
        Ok(())
    }

    /// Is there a downloaded update waiting for a restart?
    pub fn pending_version(&self) -> Option<String> {
        let text = std::fs::read_to_string(self.pending_path()).ok()?;
        serde_json::from_str::<Pending>(&text)
            .ok()
            .map(|p| p.version)
    }

    /// Applies the pending update (call on startup, before the UI).
    pub fn apply_pending(&self) -> Result<Applied> {
        let Ok(text) = std::fs::read_to_string(self.pending_path()) else {
            return Ok(Applied::Nothing);
        };
        let _ = std::fs::remove_file(self.pending_path());
        let pending: Pending = match serde_json::from_str(&text) {
            Ok(p) => p,
            Err(_) => return Ok(Applied::Nothing),
        };
        let version = semver::Version::parse(pending.version.trim_start_matches('v'))
            .map_err(|e| UpdateError::Manifest(e.to_string()))?;
        if version <= self.cfg.current_version || pending.target != self.cfg.target {
            let _ = std::fs::remove_file(&pending.file);
            return Ok(Applied::Nothing);
        }
        // Check the hash again in case the file was altered on disk.
        let mut f = std::fs::File::open(&pending.file)?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        if !hex::encode(hasher.finalize()).eq_ignore_ascii_case(&pending.sha256) {
            return Err(UpdateError::BadHash);
        }
        install(&self.cfg.install, &pending.file, &pending.format)?;
        let _ = std::fs::remove_dir_all(pending.file.parent().unwrap_or(Path::new("")));
        Ok(Applied::Updated(pending.version))
    }
}

/// Replaces the installation with the asset.
fn install(target: &Install, file: &Path, format: &str) -> Result<()> {
    match (target, format) {
        (Install::Binary(exe), "bin") => {
            set_executable(file)?;
            let current = std::env::current_exe()
                .ok()
                .and_then(|p| p.canonicalize().ok());
            if current.as_deref() == Some(exe.as_path()) {
                self_replace::self_replace(file)?;
            } else {
                replace_file(exe, file)?;
            }
            Ok(())
        }
        (Install::AppImage(path), "appimage") => {
            set_executable(file)?;
            replace_file(path, file)
        }
        (Install::MacApp(bundle), "app.tar.gz") => {
            let parent = bundle.parent().unwrap_or(Path::new("/Applications"));
            let extract = parent.join(format!(".termoak-update-{}", std::process::id()));
            std::fs::create_dir_all(&extract)?;
            let gz = flate2::read::GzDecoder::new(std::fs::File::open(file)?);
            tar::Archive::new(gz).unpack(&extract)?;
            let new_app = std::fs::read_dir(&extract)?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .find(|p| p.extension().is_some_and(|x| x == "app"))
                .ok_or_else(|| {
                    UpdateError::Manifest("the package does not contain a .app".into())
                })?;
            let old = bundle.with_extension("app.old");
            let _ = std::fs::remove_dir_all(&old);
            std::fs::rename(bundle, &old)?;
            if let Err(e) = std::fs::rename(&new_app, bundle) {
                let _ = std::fs::rename(&old, bundle);
                return Err(e.into());
            }
            let _ = std::fs::remove_dir_all(&old);
            let _ = std::fs::remove_dir_all(&extract);
            Ok(())
        }
        (Install::Managed, _) => Err(UpdateError::Managed),
        _ => Err(UpdateError::Manifest(format!(
            "format {format} is not valid for this installation"
        ))),
    }
}

/// Atomic replacement: copy next to the destination and rename.
fn replace_file(dest: &Path, src: &Path) -> Result<()> {
    let tmp = dest.with_extension("termoak-new");
    std::fs::copy(src, &tmp)?;
    set_executable(&tmp)?;
    std::fs::rename(&tmp, dest)?;
    Ok(())
}

fn set_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(path)?.permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(path, perm)?;
    }
    let _ = path;
    Ok(())
}

/// Relaunches the app (after applying an update) and exits this process.
/// Only returns if the new instance could not be launched: this process then
/// stays alive and the app can continue.
pub fn relaunch(install: &Install) -> std::io::Error {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let spawned = match install {
        Install::MacApp(bundle) => std::process::Command::new("open")
            .arg("-n")
            .arg(bundle)
            .arg("--args")
            .args(&args)
            .spawn(),
        // On Linux, after replacing the binary, `current_exe()` points to the
        // old, already deleted file: relaunch the installation path.
        Install::AppImage(path) | Install::Binary(path) => {
            std::process::Command::new(path).args(&args).spawn()
        }
        Install::Managed => match std::env::current_exe() {
            Ok(exe) => std::process::Command::new(exe).args(&args).spawn(),
            Err(e) => Err(e),
        },
    };
    match spawned {
        Ok(_) => std::process::exit(0),
        Err(e) => e,
    }
}

/// Generates a signing key pair (secret, public) in base64.
pub fn generate_keypair() -> (String, String) {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("system randomness");
    let secret = SigningKey::from_bytes(&seed);
    (
        STANDARD.encode(secret.to_bytes()),
        STANDARD.encode(secret.verifying_key().to_bytes()),
    )
}

/// Secret key from base64.
pub fn signing_key_from_base64(b64: &str) -> Option<SigningKey> {
    let raw = STANDARD.decode(b64.trim()).ok()?;
    let bytes: [u8; 32] = raw.try_into().ok()?;
    Some(SigningKey::from_bytes(&bytes))
}

/// Hex SHA-256 of a file.
pub fn sha256_file(path: &Path) -> Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let (secret, public) = generate_keypair();
        let sk = signing_key_from_base64(&secret).unwrap();
        let pk = public_key_from_base64(&public).unwrap();
        let asset = Asset {
            url: "u".into(),
            sha256: "ab".repeat(32),
            size: 1,
            signature: sign(&sk, "linux-x86_64", "1.2.3", &"ab".repeat(32)),
            format: "bin".into(),
        };
        verify(&pk, "linux-x86_64", "1.2.3", &asset).unwrap();
        assert!(verify(&pk, "linux-x86_64", "1.2.4", &asset).is_err());
        assert!(verify(&pk, "windows-x86_64", "1.2.3", &asset).is_err());
    }

    #[tokio::test]
    async fn full_update_flow_for_binary() {
        let dir = tempfile::tempdir().unwrap();
        let installed = dir.path().join("termoak");
        std::fs::write(&installed, b"old version").unwrap();
        let new_bin = b"new version".to_vec();
        let sha = hex::encode(Sha256::digest(&new_bin));

        let (secret, public) = generate_keypair();
        let sk = signing_key_from_base64(&secret).unwrap();
        let target = "linux-x86_64";

        // Mock update server.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let manifest = Manifest {
            version: "9.9.9".into(),
            notes: "What's new".into(),
            pub_date: "2026-09-26".into(),
            platforms: BTreeMap::from([(
                target.to_string(),
                Asset {
                    url: format!("http://{addr}/bin"),
                    sha256: sha.clone(),
                    size: new_bin.len() as u64,
                    signature: sign(&sk, target, "9.9.9", &sha),
                    format: "bin".into(),
                },
            )]),
        };
        let manifest_json = serde_json::to_string(&manifest).unwrap();
        let app = axum::Router::new()
            .route(
                "/latest.json",
                axum::routing::get(move || async move { manifest_json }),
            )
            .route("/bin", axum::routing::get(move || async move { new_bin }));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let updater = Updater::new(UpdateConfig {
            manifest_url: format!("http://{addr}/latest.json"),
            public_key: public_key_from_base64(&public).unwrap(),
            current_version: semver::Version::new(0, 1, 0),
            target: target.into(),
            install: Install::Binary(installed.clone()),
            staging_dir: dir.path().join("staging"),
        });
        let available = updater.check().await.unwrap().unwrap();
        assert_eq!(available.version, "9.9.9");
        assert!(!available.notify_only);
        updater.download(&available, |_, _| {}).await.unwrap();
        assert_eq!(updater.pending_version().as_deref(), Some("9.9.9"));
        // "Restart": it is applied.
        assert_eq!(
            updater.apply_pending().unwrap(),
            Applied::Updated("9.9.9".into())
        );
        assert_eq!(std::fs::read(&installed).unwrap(), b"new version");
        assert_eq!(updater.apply_pending().unwrap(), Applied::Nothing);

        // A signature from another key is rejected.
        let (other_secret, _) = generate_keypair();
        let mut bad = available.asset.clone();
        bad.signature = sign(
            &signing_key_from_base64(&other_secret).unwrap(),
            target,
            "9.9.9",
            &sha,
        );
        assert!(
            verify(
                &public_key_from_base64(&public).unwrap(),
                target,
                "9.9.9",
                &bad
            )
            .is_err()
        );
    }
}

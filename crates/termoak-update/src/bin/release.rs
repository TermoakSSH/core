//! `termoak-release`: release tool (used by CI).
//!
//! - `keygen`: generates the signing key pair. The secret key goes to the
//!   GitHub secrets (`TERMOAK_UPDATE_SECRET`); the public key is compiled into
//!   the app (`TERMOAK_UPDATE_PUBKEY`).
//! - `check-keys`: checks that the public key (the one compiled into the app)
//!   matches the secret key, before building anything.
//! - `sign`: signs an asset and adds it to the `latest.json` manifest.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use termoak_update::{
    Asset, Manifest, public_key_from_base64, sha256_file, sign, signing_key_from_base64,
};

#[derive(Parser)]
#[command(
    name = "termoak-release",
    about = "Signs and publishes Termoak updates"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generates an Ed25519 key pair (base64).
    Keygen,
    /// Checks that the public key matches the secret key.
    CheckKeys {
        #[arg(
            long,
            env = "TERMOAK_UPDATE_SECRET",
            hide_env_values = true,
            default_value = ""
        )]
        secret: String,
        #[arg(long, env = "TERMOAK_UPDATE_PUBKEY", default_value = "")]
        public_key: String,
    },
    /// Signs an asset and adds (or updates) it in the manifest.
    Sign {
        /// Secret key in base64 (or the TERMOAK_UPDATE_SECRET variable).
        #[arg(long, env = "TERMOAK_UPDATE_SECRET", hide_env_values = true)]
        secret: String,
        #[arg(long)]
        version: String,
        /// Platform: linux-x86_64, linux-aarch64, windows-x86_64, macos-universal...
        #[arg(long)]
        target: String,
        /// bin | appimage | app.tar.gz
        #[arg(long)]
        format: String,
        /// Asset file.
        #[arg(long)]
        file: PathBuf,
        /// Public download URL of the asset.
        #[arg(long)]
        url: String,
        /// Manifest to create or update.
        #[arg(long, default_value = "latest.json")]
        manifest: PathBuf,
        #[arg(long, default_value = "")]
        notes: String,
    },
}

fn main() -> anyhow_like::Result {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen => {
            let (secret, public) = termoak_update::generate_keypair();
            println!("TERMOAK_UPDATE_SECRET={secret}");
            println!("TERMOAK_UPDATE_PUBKEY={public}");
            Ok(())
        }
        Cmd::CheckKeys { secret, public_key } => {
            if public_key.trim().is_empty() {
                return Err(
                    "TERMOAK_UPDATE_PUBKEY is missing: create it on GitHub, in Settings > \
                     Secrets and variables > Actions, \"Variables\" tab (not as a secret). \
                     Without it the app is built without automatic updates"
                        .into(),
                );
            }
            if secret.trim().is_empty() {
                return Err(
                    "the TERMOAK_UPDATE_SECRET secret is missing (Settings > Secrets and \
                     variables > Actions, \"Secrets\" tab)"
                        .into(),
                );
            }
            let public = public_key_from_base64(&public_key)
                .ok_or("TERMOAK_UPDATE_PUBKEY is not a valid Ed25519 public key")?;
            let key = signing_key_from_base64(&secret)
                .ok_or("TERMOAK_UPDATE_SECRET is not a valid Ed25519 secret key")?;
            if key.verifying_key() != public {
                return Err(
                    "TERMOAK_UPDATE_PUBKEY does not match TERMOAK_UPDATE_SECRET: \
                     the apps would reject every update"
                        .into(),
                );
            }
            println!("update keys are correct");
            Ok(())
        }
        Cmd::Sign {
            secret,
            version,
            target,
            format,
            file,
            url,
            manifest,
            notes,
        } => {
            let key = signing_key_from_base64(&secret).ok_or("invalid secret key")?;
            let sha = sha256_file(&file).map_err(|e| e.to_string())?;
            let size = std::fs::metadata(&file).map_err(|e| e.to_string())?.len();
            let mut m: Manifest = match std::fs::read_to_string(&manifest) {
                Ok(text) => serde_json::from_str(&text).map_err(|e| e.to_string())?,
                Err(_) => Manifest {
                    version: version.clone(),
                    notes: notes.clone(),
                    pub_date: chrono::Utc::now().to_rfc3339(),
                    platforms: Default::default(),
                },
            };
            if m.version != version {
                return Err(
                    format!("the manifest is for version {}, not {version}", m.version).into(),
                );
            }
            if !notes.is_empty() {
                m.notes = notes;
            }
            m.platforms.insert(
                target.clone(),
                Asset {
                    url,
                    signature: sign(&key, &target, &version, &sha),
                    sha256: sha,
                    size,
                    format,
                },
            );
            std::fs::write(
                &manifest,
                serde_json::to_string_pretty(&m).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            println!("{target} signed in {}", manifest.display());
            Ok(())
        }
    }
}

mod anyhow_like {
    pub type Result = std::result::Result<(), Box<dyn std::error::Error>>;
}

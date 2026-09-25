//! Local config file recording this device's identity and the
//! coordination-plane address to use — written here on successful
//! `yadorilink device register`, read by `yadorilink-daemon` on startup.
//!
//! YadoriLink has not shipped yet. `device.json` therefore has one canonical
//! shape; development builds are not required to read configs written by older
//! development revisions.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub device_id: String,
    pub coordination_addr: String,
    /// Base64-encoded public half of the registered Ed25519 change-signing
    /// key -- this device's one real key.
    pub signing_public_key: String,
    /// Exact development config shape. Pre-release builds intentionally do not
    /// migrate older `device.json` revisions; a mismatch must be recreated by
    /// registering the device with the current build.
    pub config_version: u32,
}

/// Current pre-release `device.json` shape. This is an exact-match marker, not
/// a migration boundary: older development shapes are intentionally rejected.
pub const CONFIG_VERSION: u32 = 3;

pub fn config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("YADORILINK_CONFIG_DIR") {
        return PathBuf::from(dir);
    }
    yadorilink_local_storage::SegmentBlockStore::default_root()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn config_path() -> PathBuf {
    config_dir().join("device.json")
}

pub fn control_socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("YADORILINK_CONTROL_SOCKET") {
        return PathBuf::from(p);
    }
    config_dir().join("daemon.sock")
}

/// The Windows equivalent of `control_socket_path` — a pipe name, not a
/// filesystem path. Mirrors the daemon's derivation.
#[cfg(windows)]
pub fn control_pipe_name() -> String {
    if let Ok(name) = std::env::var("YADORILINK_CONTROL_PIPE") {
        return name;
    }
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "default".into());
    format!(r"\\.\pipe\yadorilink-ctl-{user}")
}

pub fn save(cfg: &DeviceConfig) -> std::io::Result<()> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let cfg = DeviceConfig { config_version: CONFIG_VERSION, ..cfg.clone() };
    write_config_file(&path, &serde_json::to_string_pretty(&cfg)?)
}

/// Reads the canonical pre-release device config. No development-version
/// migration or compatibility fallback is attempted.
pub fn load() -> std::io::Result<DeviceConfig> {
    let contents = std::fs::read_to_string(config_path())?;
    let config: DeviceConfig = serde_json::from_str(&contents)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if config.config_version != CONFIG_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "unsupported device.json version {}; this pre-release build requires exactly version {CONFIG_VERSION}. Re-register the device with the current build instead of migrating an old development config",
                config.config_version,
            ),
        ));
    }
    Ok(config)
}

#[cfg(unix)]
fn write_config_file(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(contents.as_bytes())
}

#[cfg(not(unix))]
fn write_config_file(path: &Path, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

/// `YADORILINK_CONFIG_DIR` is process-global and Rust runs tests concurrently.
#[cfg(test)]
pub(crate) static CONFIG_DIR_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests;

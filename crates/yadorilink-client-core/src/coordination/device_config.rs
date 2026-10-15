//! Local config file recording this device's identity and the
//! coordination-plane address to use — written here on successful
//! `yadorilink device register`, read by `yadorilink-daemon` on startup.
//!
//! YadoriLink has not shipped yet. `device.json` therefore has one canonical
//! shape; development builds are not required to read configs written by older
//! development revisions.

use std::path::{Path, PathBuf};

pub use yadorilink_local_storage::device_config::{DeviceConfig, CONFIG_VERSION};

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
        yadorilink_fs_platform::durable_dir::create_dir_all_durably(parent)?;
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

/// The points in [`write_config_file`] after which a crash or I/O error can
/// strike, in order. Tests inject a failure at each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteStep {
    TempWritten,
    TempSynced,
    Renamed,
}

/// Replaces `path` atomically. `device.json` is this device's registered
/// identity: the daemon refuses to start on an empty or partial file, so a
/// crash must leave either the previous document or the complete new one.
///
/// A sibling temporary file (owner-only from creation) is written and
/// fsynced, and published over the target by a durable move, so the new name
/// is on disk when this returns.
fn write_config_file(path: &Path, contents: &str) -> std::io::Result<()> {
    write_config_file_with(path, contents, &mut |_| Ok(()))
}

fn write_config_file_with(
    path: &Path,
    contents: &str,
    after: &mut dyn FnMut(WriteStep) -> std::io::Result<()>,
) -> std::io::Result<()> {
    use std::io::Write;

    let name = path.file_name().map_or_else(|| "device.json".into(), |n| n.to_string_lossy());
    let temporary = path.with_file_name(format!(".{name}.tmp-{}", std::process::id()));
    // A leftover from an earlier crash would make `create_new` fail forever;
    // the name carries this process's id, so it cannot be another writer's.
    let _ = std::fs::remove_file(&temporary);

    let result = (|| -> std::io::Result<()> {
        let mut file = create_owner_only(&temporary)?;
        file.write_all(contents.as_bytes())?;
        after(WriteStep::TempWritten)?;
        file.sync_all()?;
        drop(file);
        after(WriteStep::TempSynced)?;
        // A durable publish: the new name is on disk when this returns.
        yadorilink_fs_platform::durable_dir::publish_durably(
            &temporary,
            path,
            yadorilink_fs_platform::durable_dir::Replace::Yes,
        )?;
        after(WriteStep::Renamed)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
fn create_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let file = std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(path)?;
    // `mode` is masked by the umask at creation; set it explicitly too.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

#[cfg(not(unix))]
fn create_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().create_new(true).write(true).open(path)
}

/// `YADORILINK_CONFIG_DIR` is process-global and Rust runs tests concurrently.
#[cfg(test)]
pub(crate) static CONFIG_DIR_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests;

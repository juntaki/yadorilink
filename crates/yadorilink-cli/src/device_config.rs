//! Local config file recording this device's identity and the
//! coordination-plane/relay addresses to use — written here on successful
//! `yadorilink device register`, read by `yadorilink-daemon` on startup.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub device_id: String,
    pub coordination_addr: String,
    pub relay_addr: String,
    /// Mirrors
    /// `yadorilink_daemon::device_config::DeviceConfig::config_version` —
    /// see that field's doc comment for the full rationale. `#[serde(default)]`
    /// so a `device.json` from before this field existed decodes as
    /// `config_version: 0` (the correct "pre-versioning" value) instead of
    /// failing to parse.
    #[serde(default)]
    pub config_version: u32,
}

/// The current `device.json` shape, as of the first public beta baseline.
pub const CONFIG_VERSION: u32 = 1;

pub fn config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("YADORILINK_CONFIG_DIR") {
        return PathBuf::from(dir);
    }
    yadorilink_local_storage::FsBlockStore::default_root()
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

/// windows-local-ipc-support : the Windows equivalent of
/// `control_socket_path()` — a pipe name, not a filesystem path. Mirrors
/// `yadorilink_daemon::device_config::control_pipe_name()` exactly (same env
/// var, same derivation); duplicated rather than shared because
/// `yadorilink-cli`'s production code doesn't depend on `yadorilink-daemon` (only
/// its integration tests do), the same reason `config_dir()` above is
/// already duplicated between the two crates rather than shared.
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
    // Always stamp the current version on write, regardless of what
    // `cfg.config_version` the caller happened to pass in — mirrors the DB
    // migrations' "stamp unconditionally" idempotency (see
    // `SyncState::init`'s doc comment on its own `pragma_update` call).
    let cfg = DeviceConfig { config_version: CONFIG_VERSION, ..cfg.clone() };
    write_config_file(&path, &serde_json::to_string_pretty(&cfg)?)
}

/// Reads back this device's local identity, written by a prior successful
/// `yadorilink device register` (see `save` above). Used by `share accept`
/// so the invitee doesn't have to pass an explicit `--device-id` — "which
/// device am I" is already recorded locally.
pub fn load() -> std::io::Result<DeviceConfig> {
    let contents = std::fs::read_to_string(config_path())?;
    let config: DeviceConfig = serde_json::from_str(&contents)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    // Downgrade blocked: this `device.json` was written by a newer
    // CLI/daemon than this one — refuse it with a clear message rather
    // than silently using a config this build may not fully understand.
    // Mirrors
    // `SyncState::init`'s `check_schema_not_newer_than_supported`/
    // `SyncError::UnsupportedSchemaDowngrade` for the DB case.
    if config.config_version > CONFIG_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "device.json version {} is newer than this build supports (supports up to \
                 version {CONFIG_VERSION}) — this looks like an unsupported downgrade; \
                 reinstall the version that last wrote this file, or a newer one",
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

/// `YADORILINK_CONFIG_DIR` is process-global and Rust runs `#[test]`
/// functions concurrently by default, so *every* test anywhere in this
/// crate that sets it (this module's own version-safety tests below, and
/// `commands::account`'s pre-existing `export_then_import_round_trips_
/// through_real_files`) must serialize on this lock — otherwise two of
/// them race and one reads back a directory the other wrote (or removed a
/// file from), exactly what surfaced as a spurious
/// `std::fs::remove_file(...).unwrap()` "No such file or directory" panic
/// in `commands::account`'s test once more tests were added that touch
/// the same env var. `pub(crate)` (not private to this module's own
/// `#[cfg(test)]` block) specifically so `commands::account`'s test can
/// share it.
#[cfg(test)]
pub(crate) static CONFIG_DIR_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    fn with_isolated_config_dir<R>(f: impl FnOnce() -> R) -> R {
        let _guard = CONFIG_DIR_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
        let result = f();
        std::env::remove_var("YADORILINK_CONFIG_DIR");
        result
    }

    /// `save` always writes the current `CONFIG_VERSION`, even
    /// if the caller (as every real call site does — `save` always
    /// overwrites it) passed a different value — mirrors the DB
    /// migrations' unconditional version-stamping idempotency.
    #[test]
    fn save_always_stamps_current_config_version() {
        with_isolated_config_dir(|| {
            save(&DeviceConfig {
                device_id: "device-a".into(),
                coordination_addr: "http://127.0.0.1:1".into(),
                relay_addr: "127.0.0.1:2".into(),
                config_version: 0,
            })
            .unwrap();

            let loaded = load().unwrap();
            assert_eq!(loaded.config_version, CONFIG_VERSION);
        });
    }

    /// A `device.json` written before this
    /// field existed (no `config_version` key at all) still parses, with
    /// `config_version` defaulting to 0, not a deserialization error —
    /// the same "no behavior change without opt-in" guarantee the DB
    /// migrations document.
    #[test]
    fn load_defaults_a_pre_versioning_file_to_version_zero() {
        with_isolated_config_dir(|| {
            std::fs::write(
                config_path(),
                r#"{"device_id":"device-a","coordination_addr":"http://127.0.0.1:1","relay_addr":"127.0.0.1:2"}"#,
            )
            .unwrap();

            let loaded = load().unwrap();
            assert_eq!(loaded.config_version, 0);
            assert_eq!(loaded.device_id, "device-a");
        });
    }

    /// spec "Downgrade blocked": a `device.json` stamped with a
    /// version newer than this build supports must make `load` fail
    /// clearly, not silently return a config this build doesn't fully
    /// understand.
    #[test]
    fn load_rejects_a_newer_config_version_as_unsupported_downgrade() {
        with_isolated_config_dir(|| {
            std::fs::write(
                config_path(),
                format!(
                    r#"{{"device_id":"device-a","coordination_addr":"http://127.0.0.1:1","relay_addr":"127.0.0.1:2","config_version":{}}}"#,
                    CONFIG_VERSION + 1
                ),
            )
            .unwrap();

            let err = load().unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
            assert!(err.to_string().contains("unsupported downgrade"));
        });
    }

    #[cfg(unix)]
    #[test]
    fn write_config_file_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.json");

        write_config_file(&path, "{}").unwrap();

        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn write_config_file_tightens_existing_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.json");
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_config_file(&path, "{\"device_id\":\"device-1\"}").unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(path).unwrap(), "{\"device_id\":\"device-1\"}");
    }
}

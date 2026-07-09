//! Small local config file recording this device's identity and the
//! coordination-plane/relay addresses to use, written by `yadorilink device
//! register` (CLI) and read by the daemon on startup — shared local state
//! that must persist across daemon restarts (task 7.1).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub device_id: String,
    pub coordination_addr: String,
    pub relay_addr: String,
    /// This config file's version — mirrors the DB `SCHEMA_VERSION`
    /// marker's rationale (`yadorilink_sync_core::index::SCHEMA_VERSION`'s
    /// doc comment), but for `device.json` rather than SQLite (no
    /// `PRAGMA user_version` equivalent for a plain JSON file, hence a
    /// real field here instead).
    /// `#[serde(default)]` makes an on-disk file from before this field
    /// existed decode as `config_version: 0` rather than failing to parse
    /// — that's also the correct "pre-versioning" sentinel value, always
    /// `<= CONFIG_VERSION`, so an old config never trips the downgrade
    /// check in `load()` below.
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

/// windows-local-ipc-support : the Windows equivalent of a Unix
/// socket path for the CLI-daemon control protocol — named pipes live in
/// the `\\.\pipe\` namespace, not the filesystem, so this returns a pipe
/// name rather than a path. `yadorilink-cli` depends on `yadorilink-daemon` (not
/// the reverse), so this lives here and both the daemon's own
/// `windows_transport` wiring and the CLI's `control_client` call into it,
/// rather than each independently deriving the same name.
#[cfg(windows)]
pub fn control_pipe_name() -> String {
    if let Ok(name) = std::env::var("YADORILINK_CONTROL_PIPE") {
        return name;
    }
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "default".into());
    format!(r"\\.\pipe\yadorilink-ctl-{user}")
}

/// windows-local-ipc-support : the Windows equivalent of the
/// shell-integration IPC socket path, mirroring `control_pipe_name()`.
#[cfg(windows)]
pub fn shell_ipc_pipe_name() -> String {
    if let Ok(name) = std::env::var("YADORILINK_SHELL_IPC_PIPE") {
        return name;
    }
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "default".into());
    format!(r"\\.\pipe\yadorilink-{user}")
}

pub fn load() -> Option<DeviceConfig> {
    let contents = std::fs::read_to_string(config_path()).ok()?;
    let config: DeviceConfig = serde_json::from_str(&contents).ok()?;
    // A config written by a newer build than this one is exactly the same
    // "unsupported downgrade" shape as a too-new DB schema (see
    // `SyncState::init`'s `check_schema_not_newer_than_supported`) —
    // refuse to use it rather than risk this older daemon misinterpreting
    // a field it predates.
    // `load()`'s existing signature already collapses every failure mode
    // (missing file, unreadable, unparseable) to `None` — "keep behaving
    // as if this device were never registered" is the daemon's own
    // pre-existing fallback for that, so this reuses it rather than
    // introducing a new, narrower error path here.
    if config.config_version > CONFIG_VERSION {
        tracing::warn!(
            on_disk_version = config.config_version,
            supported_version = CONFIG_VERSION,
            "device.json was written by a newer version of yadorilink; ignoring it rather than \
             risking misinterpreting a field this build predates"
        );
        return None;
    }
    Some(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `YADORILINK_CONFIG_DIR` is process-global and Rust runs tests
    /// concurrently by default — serializes every test in this module that
    /// touches it, mirroring `yadorilink_cli::device_config`'s identical
    /// guard. Shared with `daemon_state.rs` and `reporting/retry.rs` (see
    /// `crate::test_support`'s doc comment) — a module-local mutex here
    /// alone does not serialize against those other modules' own tests
    /// touching the same env var. `blocking_lock` (rather than `.lock()`)
    /// because these are plain synchronous `#[test]` functions with no
    /// async runtime to `.await` on.
    use crate::test_support::CONFIG_ENV_MUTEX;

    fn with_isolated_config_dir<R>(f: impl FnOnce() -> R) -> R {
        let _guard = CONFIG_ENV_MUTEX.blocking_lock();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
        let result = f();
        std::env::remove_var("YADORILINK_CONFIG_DIR");
        result
    }

    /// task 1.1/2.2: a `device.json` from before `config_version` existed
    /// still loads, defaulting to version 0 rather than being treated as
    /// unreadable (which would make the daemon start up as if this device
    /// were never registered — a real behavior regression this task must
    /// not introduce).
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

    /// spec "Downgrade blocked": a `device.json` stamped newer
    /// than this build supports must not be used — `load()`'s existing
    /// `Option` signature (every other failure mode already collapses to
    /// `None`) means this surfaces as "behave as if never registered"
    /// rather than a distinct error, which is the correct fail-safe here:
    /// worse than an ordinary "not registered yet" state, never silent
    /// corruption from misreading a field this build predates.
    #[test]
    fn load_ignores_a_newer_config_version_as_unsupported_downgrade() {
        with_isolated_config_dir(|| {
            std::fs::write(
                config_path(),
                format!(
                    r#"{{"device_id":"device-a","coordination_addr":"http://127.0.0.1:1","relay_addr":"127.0.0.1:2","config_version":{}}}"#,
                    CONFIG_VERSION + 1
                ),
            )
            .unwrap();

            assert!(load().is_none());
        });
    }
}

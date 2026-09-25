//! Local device identity/configuration consumed by the daemon.
//!
//! YadoriLink has not shipped yet, so this file intentionally accepts only the
//! current `device.json` shape. Development revisions are not a compatibility
//! boundary: stale configs should be recreated by registering the device with
//! the current build instead of being migrated or silently defaulted.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceConfig {
    pub device_id: String,
    pub coordination_addr: String,
    /// Base64-encoded public half of this device's registered Ed25519
    /// change-signing key -- this device's one key, and the one that
    /// authenticates its transport. Required: a config that cannot
    /// identify the registered key is not a valid current config.
    pub signing_public_key: String,
    /// Current config shape marker. Missing markers are rejected by serde;
    /// configs written by newer builds are rejected explicitly below.
    pub config_version: u32,
}

/// Current pre-release `device.json` shape. Older development files are not
/// migrated; absence of this required field fails deserialization.
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

#[cfg(windows)]
pub fn control_pipe_name() -> String {
    if let Ok(name) = std::env::var("YADORILINK_CONTROL_PIPE") {
        return name;
    }
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "default".into());
    format!(r"\\.\pipe\yadorilink-ctl-{user}")
}

#[cfg(windows)]
pub fn shell_ipc_pipe_name() -> String {
    if let Ok(name) = std::env::var("YADORILINK_SHELL_IPC_PIPE") {
        return name;
    }
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "default".into());
    format!(r"\\.\pipe\yadorilink-{user}")
}

/// Why an existing `device.json` could not be turned into a usable
/// [`DeviceConfig`]. Genuine absence is reported separately as `Ok(None)`.
#[derive(Debug, thiserror::Error)]
pub enum DeviceConfigError {
    #[error("failed to read {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{} is not a valid current device config: {source}", path.display())]
    Corrupt {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    /// Retained as the explicit fail-fast error for a config written by a newer
    /// build. This is not a migration path: the daemon refuses the file before
    /// touching persistent sync state.
    #[error(
        "device.json version {on_disk_version} is newer than this build supports (supports up to version {supported_version}) — reinstall the version that wrote this file, or recreate the pre-release device registration with the current build"
    )]
    UnsupportedConfigDowngrade { on_disk_version: u32, supported_version: u32 },

    /// A config from an older development revision. There is no migration
    /// path for pre-release configs, but the device this file names is still
    /// registered — the caller must not treat this the same as a corrupt or
    /// absent config (see `UnsupportedConfigDowngrade`, above).
    #[error(
        "device.json version {on_disk_version} is older than this build supports (requires exactly version {supported_version}) — this is a pre-release build with no config migration path"
    )]
    StaleConfigVersion { on_disk_version: u32, supported_version: u32 },
}

/// Reads the current pre-release device config. No legacy fields, missing
/// identity fingerprints, or pre-versioning sentinel are accepted.
pub fn load() -> Result<Option<DeviceConfig>, DeviceConfigError> {
    let path = config_path();
    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(DeviceConfigError::Read { path, source }),
    };
    let config: DeviceConfig = serde_json::from_str(&contents)
        .map_err(|source| DeviceConfigError::Corrupt { path, source })?;
    if config.config_version > CONFIG_VERSION {
        return Err(DeviceConfigError::UnsupportedConfigDowngrade {
            on_disk_version: config.config_version,
            supported_version: CONFIG_VERSION,
        });
    }
    if config.config_version < CONFIG_VERSION {
        return Err(DeviceConfigError::StaleConfigVersion {
            on_disk_version: config.config_version,
            supported_version: CONFIG_VERSION,
        });
    }
    Ok(Some(config))
}

#[cfg(test)]
mod tests;

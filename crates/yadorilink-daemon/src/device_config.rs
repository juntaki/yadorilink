//! Local device identity/configuration consumed by the daemon.
//!
//! YadoriLink has not shipped yet, so this file intentionally accepts only the
//! current `device.json` shape. Development revisions are not a compatibility
//! boundary: stale configs should be recreated by registering the device with
//! the current build instead of being migrated or silently defaulted.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub device_id: String,
    pub coordination_addr: String,
    /// NAT-traversal settings for establishing direct peer connections. The
    /// top-level `nat` object is required in the canonical config shape;
    /// individual settings may still be omitted and filled from `NatConfig`'s
    /// defaults so manual configuration stays practical.
    pub nat: NatConfig,
    /// Base64-encoded public half of this device's registered WireGuard/X25519
    /// key. Required: a config that cannot identify the registered key is not a
    /// valid current config.
    pub wireguard_public_key: String,
    /// Base64-encoded public half of this device's registered Ed25519
    /// change-signing key. Required for the same reason as the transport key.
    pub signing_public_key: String,
    /// Current config shape marker. Missing markers are rejected by serde;
    /// configs written by newer builds are rejected explicitly below.
    pub config_version: u32,
}

/// NAT-traversal settings, mapped onto the transport's STUN and port-mapping
/// configuration when gathering direct candidates.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NatConfig {
    /// STUN servers (`host:port`) queried to discover this device's
    /// server-reflexive address. An empty list disables STUN.
    pub stun_servers: Vec<String>,
    /// How often, in seconds, to re-probe STUN.
    pub stun_refresh_secs: u64,
    /// Whether to actively request a router port mapping.
    pub port_mapping_enabled: bool,
    /// Lifetime, in seconds, requested for a router port-mapping lease.
    pub port_mapping_lease_secs: u32,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            stun_servers: default_stun_servers(),
            stun_refresh_secs: 300,
            port_mapping_enabled: true,
            port_mapping_lease_secs: 3600,
        }
    }
}

fn default_stun_servers() -> Vec<String> {
    vec!["stun.l.google.com:19302".to_string(), "stun1.l.google.com:19302".to_string()]
}

/// Current pre-release `device.json` shape. Older development files are not
/// migrated; absence of this required field fails deserialization.
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
mod tests {
    use super::*;

    use crate::test_support::CONFIG_ENV_MUTEX;

    fn with_isolated_config_dir<R>(f: impl FnOnce() -> R) -> R {
        let _guard = CONFIG_ENV_MUTEX.blocking_lock();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
        let result = f();
        std::env::remove_var("YADORILINK_CONFIG_DIR");
        result
    }

    fn current_config_json(version: u32) -> String {
        format!(
            r#"{{"device_id":"device-a","coordination_addr":"http://127.0.0.1:1","nat":{{}},"wireguard_public_key":"wg-public","signing_public_key":"signing-public","config_version":{version}}}"#
        )
    }

    #[test]
    fn load_on_a_missing_file_is_ok_none_not_an_error() {
        with_isolated_config_dir(|| {
            assert!(load().unwrap().is_none());
        });
    }

    #[test]
    fn load_on_corrupt_json_is_an_error_not_absence() {
        with_isolated_config_dir(|| {
            std::fs::write(config_path(), "{ this is not valid json").unwrap();

            assert!(matches!(load(), Err(DeviceConfigError::Corrupt { .. })));
        });
    }

    #[test]
    fn load_on_an_unreadable_file_is_an_error_not_absence() {
        with_isolated_config_dir(|| {
            std::fs::create_dir(config_path()).unwrap();

            assert!(matches!(load(), Err(DeviceConfigError::Read { .. })));
        });
    }

    #[test]
    fn load_rejects_a_pre_release_config_missing_current_required_fields() {
        with_isolated_config_dir(|| {
            std::fs::write(
                config_path(),
                r#"{"device_id":"device-a","coordination_addr":"http://127.0.0.1:1"}"#,
            )
            .unwrap();

            assert!(matches!(load(), Err(DeviceConfigError::Corrupt { .. })));
        });
    }

    #[test]
    fn load_rejects_a_newer_config_version_before_startup() {
        with_isolated_config_dir(|| {
            std::fs::write(config_path(), current_config_json(CONFIG_VERSION + 1)).unwrap();

            let err = load().unwrap_err();
            assert!(matches!(
                err,
                DeviceConfigError::UnsupportedConfigDowngrade {
                    on_disk_version,
                    supported_version,
                } if on_disk_version == CONFIG_VERSION + 1 && supported_version == CONFIG_VERSION
            ));
        });
    }

    #[test]
    fn load_rejects_an_older_config_version_before_startup() {
        with_isolated_config_dir(|| {
            std::fs::write(config_path(), current_config_json(CONFIG_VERSION - 1)).unwrap();

            let err = load().unwrap_err();
            assert!(matches!(
                err,
                DeviceConfigError::StaleConfigVersion {
                    on_disk_version,
                    supported_version,
                } if on_disk_version == CONFIG_VERSION - 1 && supported_version == CONFIG_VERSION
            ));
        });
    }

    #[test]
    fn load_accepts_only_the_current_complete_identity_shape() {
        with_isolated_config_dir(|| {
            std::fs::write(config_path(), current_config_json(CONFIG_VERSION)).unwrap();

            let loaded = load().unwrap().unwrap();
            assert_eq!(loaded.device_id, "device-a");
            assert_eq!(loaded.wireguard_public_key, "wg-public");
            assert_eq!(loaded.signing_public_key, "signing-public");
            assert_eq!(loaded.config_version, CONFIG_VERSION);
        });
    }
}

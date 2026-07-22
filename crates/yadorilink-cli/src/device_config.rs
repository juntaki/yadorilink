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
    /// NAT-traversal settings written at registration time and consumed by the
    /// daemon. The top-level field is required; `NatConfig` itself still uses
    /// defaults so a user can edit only the settings they want to override.
    pub nat: NatConfig,
    /// Base64-encoded public half of the registered WireGuard/X25519 identity.
    pub wireguard_public_key: String,
    /// Base64-encoded public half of the registered Ed25519 change-signing key.
    pub signing_public_key: String,
    /// Exact development config shape. Pre-release builds intentionally do not
    /// migrate older `device.json` revisions; a mismatch must be recreated by
    /// registering the device with the current build.
    pub config_version: u32,
}

/// NAT-traversal settings written into `device.json`. Duplicated from
/// `yadorilink_daemon::device_config::NatConfig` because the CLI owns creation
/// of the file while the daemon owns consumption of it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NatConfig {
    /// STUN servers (`host:port`); empty disables STUN.
    pub stun_servers: Vec<String>,
    /// STUN re-probe interval, in seconds.
    pub stun_refresh_secs: u64,
    /// Whether to actively request a router port mapping.
    pub port_mapping_enabled: bool,
    /// Requested router port-mapping lease lifetime, in seconds.
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

/// Current pre-release `device.json` shape. This is an exact-match marker, not
/// a migration boundary: older development shapes are intentionally rejected.
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

    fn current_config() -> DeviceConfig {
        DeviceConfig {
            device_id: "device-a".into(),
            coordination_addr: "http://127.0.0.1:1".into(),
            nat: NatConfig::default(),
            wireguard_public_key: "wg-public".into(),
            signing_public_key: "signing-public".into(),
            config_version: 0,
        }
    }

    #[test]
    fn save_stamps_and_round_trips_the_current_shape() {
        with_isolated_config_dir(|| {
            save(&current_config()).unwrap();

            let loaded = load().unwrap();
            assert_eq!(loaded.config_version, CONFIG_VERSION);
            assert_eq!(loaded.device_id, "device-a");
            assert_eq!(loaded.wireguard_public_key, "wg-public");
            assert_eq!(loaded.signing_public_key, "signing-public");
        });
    }

    #[test]
    fn load_rejects_a_pre_versioning_development_config() {
        with_isolated_config_dir(|| {
            std::fs::write(
                config_path(),
                r#"{"device_id":"device-a","coordination_addr":"http://127.0.0.1:1","nat":{}}"#,
            )
            .unwrap();

            let err = load().unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        });
    }

    #[test]
    fn load_requires_the_exact_current_config_version() {
        with_isolated_config_dir(|| {
            std::fs::write(
                config_path(),
                format!(
                    r#"{{"device_id":"device-a","coordination_addr":"http://127.0.0.1:1","nat":{{}},"wireguard_public_key":"wg","signing_public_key":"signing","config_version":{}}}"#,
                    CONFIG_VERSION + 1
                ),
            )
            .unwrap();

            let err = load().unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
            assert!(err.to_string().contains("requires exactly"));
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

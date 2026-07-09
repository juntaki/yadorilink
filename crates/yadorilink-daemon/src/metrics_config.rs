//! add-observability-and-metrics task 4.2: on-disk persistence for the
//! daemon's opt-in `/metrics` endpoint toggle — mirrors
//! `governance_config::GovernanceConfigStore` exactly (small, independent
//! JSON file under the config directory, `#[serde(default)]` +
//! `#[derive(Default)]`, tempfile-then-rename writes), so a pre-existing
//! install with no `metrics_config.json` at all loads the safe,
//! spec-mandated default (**disabled**, design.md's "Default off /
//! localhost-only") with no migration step.
//!
//! Unlike `GovernanceConfigStore` (whose rate/headroom changes must apply
//! to an already-running daemon without a restart, task 2.5), enabling or
//! changing the metrics bind address only takes effect on the *next* daemon
//! start (binding a new listener isn't something a running process can do
//! to itself mid-flight) — `main.rs` reads this once at startup, and
//! `yadorilink daemon metrics` (the CLI command that writes this file) says
//! so explicitly.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// design.md "Default off / localhost-only; bind address configurable.
/// Never exposed publicly by default." `bind_addr` deliberately defaults to
/// a loopback-only address (never a wildcard) so an operator who enables
/// this without also overriding the address still gets the "never exposed
/// publicly by default" guarantee.
pub const DEFAULT_BIND_ADDR: &str = "127.0.0.1:9184";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub bind_addr: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        MetricsConfig { enabled: false, bind_addr: DEFAULT_BIND_ADDR.to_string() }
    }
}

pub struct MetricsConfigStore {
    path: PathBuf,
}

impl MetricsConfigStore {
    pub fn new(config_dir: impl AsRef<Path>) -> Self {
        MetricsConfigStore { path: config_dir.as_ref().join("metrics_config.json") }
    }

    /// Deliberately does **not** write anything to disk just by loading —
    /// same "safe to call from any test/startup path" contract as
    /// `GovernanceConfigStore::load`.
    pub fn load(&self) -> std::io::Result<MetricsConfig> {
        match std::fs::read_to_string(&self.path) {
            Ok(contents) => serde_json::from_str(&contents)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(MetricsConfig::default()),
            Err(e) => Err(e),
        }
    }

    pub fn load_or_default(&self) -> MetricsConfig {
        match self.load() {
            Ok(config) => config,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %self.path.display(),
                    "metrics-config: failed to load config; defaulting to disabled"
                );
                MetricsConfig::default()
            }
        }
    }

    pub fn save(&self, config: &MetricsConfig) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(config)?;
        let tmp_path = self.path.with_extension("json.tmp");
        std::fs::write(&tmp_path, json)?;
        std::fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }

    pub fn set(&self, enabled: bool, bind_addr: Option<String>) -> std::io::Result<MetricsConfig> {
        let mut config = self.load_or_default();
        config.enabled = enabled;
        if let Some(bind_addr) = bind_addr {
            config.bind_addr = bind_addr;
        }
        self.save(&config)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, MetricsConfigStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = MetricsConfigStore::new(dir.path());
        (dir, store)
    }

    /// task 3.1/5.1: default off, and loopback-only if ever enabled without
    /// an explicit address override.
    #[test]
    fn fresh_store_defaults_to_disabled_and_loopback_only() {
        let (dir, store) = store();
        let config = store.load().unwrap();
        assert!(!config.enabled);
        assert!(config.bind_addr.starts_with("127.0.0.1:"));
        assert!(!dir.path().join("metrics_config.json").exists());
    }

    #[test]
    fn set_enables_and_persists_a_custom_bind_addr() {
        let (_dir, store) = store();
        let config = store.set(true, Some("127.0.0.1:9999".to_string())).unwrap();
        assert!(config.enabled);
        assert_eq!(config.bind_addr, "127.0.0.1:9999");

        let reloaded = store.load().unwrap();
        assert_eq!(reloaded, config);
    }

    #[test]
    fn set_without_an_addr_keeps_the_previously_configured_one() {
        let (_dir, store) = store();
        store.set(true, Some("127.0.0.1:9999".to_string())).unwrap();
        let config = store.set(false, None).unwrap();
        assert!(!config.enabled);
        assert_eq!(config.bind_addr, "127.0.0.1:9999");
    }
}

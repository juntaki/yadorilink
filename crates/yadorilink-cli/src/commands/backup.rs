//! Backup/disaster-recovery CLI helpers.
//!
//! Sensitive export/import is intentionally delegated to the existing
//! account key-bundle implementation so there is one encryption format and
//! one import path to audit.

use std::path::PathBuf;

use crate::commands::account;
use crate::device_config;
use crate::error::CliError;

pub fn status() {
    let status = BackupStatus::detect();
    println!("Backup readiness:");
    println!("  device config: {}", present(status.device_config));
    println!("  device key: {}", present(status.device_key));
    println!("  sync database: {}", present(status.sync_database));
    println!("  block store: {}", present(status.block_store));
    println!("  recovery codes: not stored locally; generate and store them separately");
    println!("  encrypted key bundle: not tracked locally; run `yadorilink backup export <path>`");
    println!();
    println!("Recovery coverage:");
    println!("  lost one device: recover by adding a new device from a surviving device");
    println!("  all devices lost: requires recovery codes for login plus an encrypted key bundle for data access");
    println!("  local corruption: restore config/key from key bundle; synced content rehydrates from peers when available");
}

pub async fn export(output_path: PathBuf, passphrase: String) -> Result<(), CliError> {
    account::export_key_bundle(output_path, passphrase).await
}

pub async fn import(input_path: PathBuf, passphrase: String, yes: bool) -> Result<(), CliError> {
    let status = BackupStatus::detect();
    if status.device_config || status.device_key {
        if !yes {
            return Err(CliError::Other(
                "local device state already exists; re-run with --yes to overwrite it".into(),
            ));
        }
        eprintln!("warning: overwriting existing local device state from imported backup bundle");
    }
    account::import_key_bundle(input_path, passphrase).await
}

fn present(value: bool) -> &'static str {
    if value {
        "present"
    } else {
        "missing"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BackupStatus {
    device_config: bool,
    device_key: bool,
    sync_database: bool,
    block_store: bool,
}

impl BackupStatus {
    fn detect() -> Self {
        let config_dir = device_config::config_dir();
        Self {
            device_config: device_config::config_path().is_file(),
            device_key: config_dir.join("wg_key").is_file(),
            sync_database: config_dir.join("sync-state.sqlite3").is_file(),
            block_store: config_dir.join("blocks").is_dir(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn present_labels_are_stable() {
        assert_eq!(present(true), "present");
        assert_eq!(present(false), "missing");
    }
}

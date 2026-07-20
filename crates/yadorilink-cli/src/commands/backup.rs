//! Backup/disaster-recovery CLI helpers.
//!
//! Backup covers only non-sensitive local state: this device's
//! coordination-plane address and NAT preferences, plus the list of linked
//! folders. It deliberately never exports device identity keys, session
//! tokens, or any other secret. A lost or replaced device re-establishes its
//! identity by signing in with Google and registering as a new device, then
//! re-joins its folders and re-fetches their content from peers that still
//! hold it -- so there is nothing secret to back up here and nothing secret
//! to restore.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::ListLinksRequest;

use crate::control_client;
use crate::device_config::{self, NatConfig};
use crate::error::CliError;

/// The one-line recovery model every backup surface repeats: identity is
/// re-established by Google login on a new device, not restored from a file.
/// Kept as a function so the `status`/`import` output and the tests assert on
/// the exact same wording.
pub fn recovery_guidance() -> String {
    "Device identity is recovered by signing in with Google on a new device and registering it, \
not restored from an exported artifact. After registering, re-join your folders and their content \
re-fetches from peers that still hold it."
        .to_string()
}

/// A single linked folder in a backup document: the local path and the
/// folder group it maps to. Neither is a secret, and neither is a device
/// identity key.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LinkEntry {
    local_path: String,
    group_id: String,
}

/// The on-disk backup document: non-sensitive config plus link metadata. By
/// construction it carries no device id, no private keys, and no tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NonSensitiveBackup {
    /// The coordination-plane address recorded in `device.json`, if this
    /// device has been registered.
    coordination_addr: Option<String>,
    /// NAT-traversal preferences from `device.json`, if present.
    nat: Option<NatConfig>,
    /// Linked-folder mappings (local path -> folder group).
    links: Vec<LinkEntry>,
}

pub fn status() {
    let inv = BackupInventory::detect();
    println!("Backup readiness (non-sensitive config and link metadata only):");
    println!("  device config: {}", present(inv.device_config));
    println!("  link metadata (sync database): {}", present(inv.sync_database));
    println!();
    println!("{}", recovery_guidance());
    println!();
    println!("Recovery coverage:");
    println!(
        "  lost one device: sign in with Google on a new device, re-join your folders, and \
re-fetch their content from the surviving authorized peers that hold it"
    );
    println!(
        "  all devices lost: sign in with Google to regain your account and folder list; any \
folder whose content no authorized peer still holds cannot be recovered, since there is no \
operator-held copy"
    );
}

/// Writes a non-sensitive backup document (coordination address, NAT
/// preferences, and link metadata) to `output_path`. It never contains a
/// device id, a private key, or a session token, so it is written as plain
/// JSON with no encryption step.
pub async fn export(output_path: PathBuf) -> Result<(), CliError> {
    let (coordination_addr, nat) = match device_config::load() {
        Ok(cfg) => (Some(cfg.coordination_addr), Some(cfg.nat)),
        Err(_) => (None, None),
    };
    let links = fetch_link_metadata().await;

    let backup = NonSensitiveBackup { coordination_addr, nat, links };
    let contents = serde_json::to_string_pretty(&backup)
        .map_err(|e| CliError::Other(format!("serializing backup: {e}")))?;
    std::fs::write(&output_path, contents)?;

    println!(
        "Wrote a non-sensitive backup to {}.\n\n\
         It contains only this device's coordination address, NAT preferences, and linked-folder \
metadata -- no device identity keys, no session tokens, no secrets. {}",
        output_path.display(),
        recovery_guidance()
    );
    Ok(())
}

/// Applies a non-sensitive backup document to this device's local
/// configuration. It only updates the coordination address and NAT
/// preferences of an already-registered device; it never creates or restores
/// a device identity (that comes from Google login + `device register`). The
/// saved link metadata is printed as a re-link checklist rather than
/// re-registered automatically.
pub async fn import(input_path: PathBuf, yes: bool) -> Result<(), CliError> {
    let contents = std::fs::read_to_string(&input_path)?;
    let backup: NonSensitiveBackup = serde_json::from_str(&contents)
        .map_err(|e| CliError::Other(format!("not a valid backup document: {e}")))?;

    match device_config::load() {
        Ok(mut cfg) => {
            if !yes {
                return Err(CliError::Other(
                    "local device config already exists; re-run with --yes to overwrite its \
non-sensitive settings from the backup"
                        .into(),
                ));
            }
            if let Some(addr) = backup.coordination_addr {
                cfg.coordination_addr = addr;
            }
            if let Some(nat) = backup.nat {
                cfg.nat = nat;
            }
            device_config::save(&cfg)?;
            println!("Restored non-sensitive config (coordination address and NAT preferences).");
        }
        Err(_) => {
            return Err(CliError::Other(
                "no local device identity yet -- sign in with `yadorilink login` and run \
`yadorilink device register` to establish this device's identity first (it is not restored from a \
backup), then re-run import to apply the saved non-sensitive settings"
                    .into(),
            ));
        }
    }

    if backup.links.is_empty() {
        println!("No linked-folder metadata was saved in this backup.");
    } else {
        println!(
            "\nRe-join these folders (re-run the link for each once the device is registered):"
        );
        for link in &backup.links {
            println!("  {}  ->  group {}", link.local_path, link.group_id);
        }
    }
    println!("\n{}", recovery_guidance());
    Ok(())
}

/// Best-effort read of the linked-folder list from the running daemon. An
/// unreachable daemon (or any other failure) yields an empty list rather than
/// aborting the export -- link metadata is a convenience, not a secret, and
/// re-linking is always possible afterwards.
async fn fetch_link_metadata() -> Vec<LinkEntry> {
    match control_client::send(ReqPayload::ListLinks(ListLinksRequest {})).await {
        Ok(resp) => match resp.payload {
            Some(RespPayload::ListLinks(list)) => list
                .links
                .into_iter()
                .map(|l| LinkEntry { local_path: l.local_path, group_id: l.group_id })
                .collect(),
            _ => Vec::new(),
        },
        Err(_) => Vec::new(),
    }
}

fn present(value: bool) -> &'static str {
    if value {
        "present"
    } else {
        "missing"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BackupInventory {
    device_config: bool,
    sync_database: bool,
}

impl BackupInventory {
    fn detect() -> Self {
        let config_dir = device_config::config_dir();
        Self {
            device_config: device_config::config_path().is_file(),
            sync_database: config_dir.join("sync-state.sqlite3").is_file(),
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

    /// The recovery guidance describes the Google-login/new-device model.
    #[test]
    fn recovery_guidance_describes_google_login_new_device_model() {
        let guidance = recovery_guidance();
        let lower = guidance.to_lowercase();
        assert!(guidance.contains("Google"));
        assert!(lower.contains("new device"));
        assert!(lower.contains("register"));
    }
}

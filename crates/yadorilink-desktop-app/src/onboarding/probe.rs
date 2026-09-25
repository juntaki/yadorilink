//! Gather the actual system state
//! the wizard's start phase is derived from. This is the impure counterpart to
//! `machine::derive_initial` — it reads the keychain session, the local
//! `device.json`, and the daemon's link list — so it is not unit-tested; the
//! flow decision it feeds (`derive_initial`) is the pure, tested part.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::ListLinksRequest;

use super::machine::Probe;
use crate::ipc_client;

/// Read the three probes the start step is derived from. Never fails: an
/// unreachable daemon is treated as "no links" (best-effort, matching the
/// CLI's own `fetch_existing_link_paths`), so the wizard still opens — worst
/// case at the share step rather than when adding another folder.
pub async fn gather() -> Probe {
    Probe {
        // `unwrap_or_default`, deliberately, and only here: this probe drives
        // which screen the wizard opens on, and a credential store it cannot
        // read is a wizard that should start at "sign in" rather than one that
        // refuses to open. Every path that actually *uses* a credential
        // reports the store's error instead.
        signed_in: yadorilink_client_core::coordination::credential_store::installation()
            .unwrap_or_default()
            .is_some(),
        // The enrolled credential does not carry the account email, so no
        // specific account label is available to show.
        account: None,
        device_registered: ipc_client::is_device_registered(),
        has_links: has_links().await,
        default_device_name: default_device_name(),
    }
}

async fn has_links() -> bool {
    match ipc_client::send(ReqPayload::ListLinks(ListLinksRequest {})).await {
        Ok(resp) => matches!(resp.payload, Some(RespPayload::ListLinks(l)) if !l.links.is_empty()),
        Err(_) => false,
    }
}

/// A sensible default for the device-name field the user can edit. Best-effort
/// hostname: the platform env vars first, then the `hostname` command, then a
/// generic fallback — this only prefills an editable field, so an approximate
/// answer is fine.
fn default_device_name() -> String {
    for var in ["COMPUTERNAME", "HOSTNAME", "HOST"] {
        if let Ok(value) = std::env::var(var) {
            if !value.trim().is_empty() {
                return value.trim().to_string();
            }
        }
    }
    if let Ok(output) = std::process::Command::new("hostname").output() {
        if output.status.success() {
            let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !name.is_empty() {
                return name;
            }
        }
    }
    "My Device".to_string()
}

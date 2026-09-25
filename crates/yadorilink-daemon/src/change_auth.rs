//! The daemon's implementation of `yadorilink-peer-session`'s
//! [`ChangeAuthenticator`] -- under the proof-carrying-change model this
//! trait has exactly one job: resolve the authority key this device's own
//! verified policy chain considers valid for a checkpoint's `(signer_key_id,
//! policy_head)`. Change authorship/signature verification itself is fully
//! self-contained on the wire (the author's raw signing key travels with
//! the checkpoint envelope) and needs no daemon-side lookup at all.
//!
//! Also home to `effective_servable_groups`, the netmap-refresh-time filter
//! that keeps a group whose policy has gone stale (or was never introduced)
//! from being announced to peers at all.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use ed25519_dalek::VerifyingKey;
use yadorilink_peer_session::peer_session::ChangeAuthenticator;

use crate::daemon_state::{DaemonState, GroupPolicyResolution};

pub struct NetmapChangeAuthenticator {
    state: Arc<DaemonState>,
}

impl NetmapChangeAuthenticator {
    pub fn new(state: Arc<DaemonState>) -> Arc<Self> {
        Arc::new(Self { state })
    }

    /// Filters `raw_groups` down to the groups this device's own verified
    /// policy state currently considers servable -- a group whose policy
    /// has gone stale (own verification failure, or coordinator-flagged
    /// invalid) or has not loaded yet this run is withheld from peer
    /// announcement entirely, rather than being served against a policy
    /// snapshot this device can no longer vouch for.
    ///
    /// `validation_cache` scopes this (cheap, but still a lock + map read
    /// per group) result to one netmap-update pass's worth of calls, so a
    /// group shared by many peers is resolved once, not once per peer
    /// sharing it.
    pub(crate) fn effective_servable_groups(
        state: Arc<DaemonState>,
        raw_groups: &HashSet<String>,
        validation_cache: &Mutex<HashMap<String, bool>>,
    ) -> HashSet<String> {
        raw_groups
            .iter()
            .filter_map(|group_id| {
                if let Some(cached_ok) = validation_cache
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .get(group_id)
                    .copied()
                {
                    return cached_ok.then(|| group_id.clone());
                }
                let ok = state.group_is_servable(group_id);
                validation_cache
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(group_id.clone(), ok);
                ok.then(|| group_id.clone())
            })
            .collect()
    }

    /// This device's own signing identity if `device_id` names this device,
    /// otherwise the netmap-pinned signing key for a peer, otherwise the
    /// set-once historical `signing_keys.json` pin archive for a device no
    /// longer present in the live netmap. Only ever used for the raw
    /// frontier-change verification of a base a peer offers to merge
    /// (`rebootstrap_handler.rs`, `verify_each_frontier_change`) --
    /// ordinary Change admission resolves the author's key straight off the
    /// wire-carried checkpoint envelope and never needs this lookup at all.
    pub(crate) fn signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
        if device_id == self.state.device_id {
            return self
                .state
                .device_signing_key
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_ref()
                .map(|key| key.verifying_key().to_bytes());
        }
        self.state
            .authority
            .peer_signing_key(device_id)
            .or_else(|| Self::historical_pinned_signing_key(device_id))
    }

    fn historical_pinned_signing_key(device_id: &str) -> Option<[u8; 32]> {
        let path = crate::device_config::config_dir().join("signing_keys.json");
        let contents = std::fs::read_to_string(path).ok()?;
        let pins: HashMap<String, String> = serde_json::from_str(&contents).ok()?;
        let encoded = pins.get(device_id)?;
        let bytes = hex::decode(encoded).ok()?;
        <[u8; 32]>::try_from(bytes.as_slice()).ok()
    }
}

impl ChangeAuthenticator for NetmapChangeAuthenticator {
    fn resolve_authority_key(
        &self,
        group_id: &str,
        signer_key_id: &[u8; 32],
        policy_head: &[u8; 32],
    ) -> Option<VerifyingKey> {
        match self.state.resolve_group_policy(group_id) {
            GroupPolicyResolution::Verified(policy) => {
                policy.resolve_authority_key(signer_key_id, policy_head)
            }
            GroupPolicyResolution::Bootstrap | GroupPolicyResolution::Withhold => None,
        }
    }
}

#[cfg(test)]
mod tests;

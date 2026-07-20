//! The daemon's implementation of `yadorilink_sync_core`'s
//! [`ChangeAuthenticator`], backed by netmap-derived state: pinned Ed25519
//! signing keys and per-group write authorizations.
//!
//! The same resolver also feeds `authenticated_history`: live admission and
//! retained-history re-validation therefore share one signature/authorization
//! rule rather than drifting into two subtly different trust models. Historical
//! authors that have since been revoked are resolved from the existing
//! set-once `signing_keys.json` pin archive when they are no longer present in
//! the live netmap.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use yadorilink_sync_core::authenticated_history::{
    validate_retained_group, AuthenticatedHistoryError, AuthenticatedHistoryReport,
};
use yadorilink_sync_core::change::ChangeAuth;
use yadorilink_sync_core::peer_session::ChangeAuthenticator;

use crate::daemon_state::{DaemonState, GroupPolicyResolution};

pub struct NetmapChangeAuthenticator {
    state: Arc<DaemonState>,
}

impl NetmapChangeAuthenticator {
    pub fn new(state: Arc<DaemonState>) -> Arc<Self> {
        let authenticator = Arc::new(Self { state });
        authenticator.validate_linked_history_best_effort();
        authenticator
    }

    /// Intersects raw coordination-plane authorization with the local policy
    /// and authenticated-retained-history boundary. Callers must use this
    /// result for both existing-session reauthorization and brand-new session
    /// construction; falling back to the raw ACL would let a netmap refresh
    /// silently undo quarantine.
    ///
    /// `validation_cache` scopes `validate_retained_group`'s (expensive: full
    /// DAG re-walk + full signature re-verification) result to one netmap
    /// snapshot's worth of calls. The caller creates one fresh, empty cache
    /// per netmap-update pass and passes the same instance for every peer in
    /// that pass, so a group shared by many peers is re-walked once, not once
    /// per peer sharing it — and because the cache never outlives that one
    /// pass, it needs no invalidation logic: the next pass starts fresh and
    /// always re-validates against current state.
    pub(crate) fn effective_servable_groups(
        state: Arc<DaemonState>,
        raw_groups: &HashSet<String>,
        validation_cache: &Mutex<HashMap<String, bool>>,
    ) -> HashSet<String> {
        let authenticator = Arc::new(Self { state });
        raw_groups
            .iter()
            .filter_map(|group_id| {
                if matches!(
                    authenticator.state.resolve_group_policy(group_id),
                    GroupPolicyResolution::Withhold
                ) {
                    authenticator.quarantine_group_sessions(group_id);
                    return None;
                }
                if let Some(cached_ok) =
                    validation_cache.lock().unwrap_or_else(|p| p.into_inner()).get(group_id).copied()
                {
                    return cached_ok.then(|| group_id.clone());
                }
                let ok = match authenticator.validate_retained_group(group_id) {
                    Ok(_) => true,
                    Err(AuthenticatedHistoryError::TrustUnavailable { device_id }) => {
                        authenticator.quarantine_group_sessions(group_id);
                        tracing::warn!(
                            group_id,
                            author_device_id = %device_id,
                            "withholding group from peer session: retained-history trust is unavailable"
                        );
                        false
                    }
                    Err(error @ AuthenticatedHistoryError::InvalidHistory(_)) => {
                        authenticator.quarantine_group_sessions(group_id);
                        authenticator.state.mark_group_policy_stale(group_id);
                        tracing::error!(
                            group_id,
                            %error,
                            "withholding group from peer session: retained history failed authentication"
                        );
                        false
                    }
                    Err(error @ AuthenticatedHistoryError::Store(_)) => {
                        authenticator.quarantine_group_sessions(group_id);
                        tracing::error!(
                            group_id,
                            %error,
                            "withholding group from peer session: retained history could not be read"
                        );
                        false
                    }
                };
                validation_cache
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(group_id.clone(), ok);
                ok.then(|| group_id.clone())
            })
            .collect()
    }

    /// Re-runs signature and historical-authorization verification over every
    /// retained Change reachable from this group's repaired DAG frontier.
    ///
    /// Callers should invoke this after the group's verified policy snapshot is
    /// available. `TrustUnavailable` is a deferral signal; `InvalidHistory` is a
    /// hard integrity failure. Both are unservable states: a peer must not be
    /// shown heads or Change bodies from history this device has not positively
    /// authenticated yet.
    pub fn validate_retained_group(
        &self,
        group_id: &str,
    ) -> Result<AuthenticatedHistoryReport, AuthenticatedHistoryError> {
        validate_retained_group(self.state.sync_state.as_ref(), group_id, self)
    }

    /// Withdraws one group's live authorization from every already-published
    /// peer session. `PeerSyncSession::shares_group` gates heads announcements,
    /// ChangeBatch serving, block serving, and peer apply, so reusing the same
    /// live authorization switch quarantines both inbound and outbound data
    /// flow without inventing a second session-state mechanism.
    fn quarantine_group_sessions(&self, group_id: &str) {
        let sessions: Vec<_> = self
            .state
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .cloned()
            .collect();
        for session in sessions {
            session.revoke_group(group_id);
        }
    }

    /// Re-enables a positively-authenticated group only for peers that are
    /// still authorized by the current netmap, and only while the group's
    /// policy resolver itself is not withholding. Snapshot the session map
    /// before consulting peer metadata so no sessions-lock -> metadata-lock
    /// inversion is introduced.
    fn restore_group_sessions_if_currently_authorized(&self, group_id: &str) {
        let policy_servable =
            !matches!(self.state.resolve_group_policy(group_id), GroupPolicyResolution::Withhold);
        let sessions: Vec<_> = self
            .state
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|(peer_id, session)| (peer_id.clone(), session.clone()))
            .collect();
        for (peer_id, session) in sessions {
            if policy_servable && self.state.peer_is_writer(&peer_id, group_id) {
                session.grant_group(group_id);
            } else {
                session.revoke_group(group_id);
            }
        }
    }

    /// Every real peer-session construction re-runs this validator after
    /// netmap/policy trust has begun arriving. A group is quarantined unless
    /// validation positively succeeds:
    /// - missing author trust: temporary quarantine, retry later;
    /// - store/read failure: quarantine rather than serving unverified history;
    /// - bad signature/auth/history invariant: quarantine and mark policy stale;
    /// - success: re-grant only currently-authorized sessions.
    ///
    /// The session-publication ordering for a brand-new session is tracked as a
    /// separate release blocker in the DAG task list: the session must be in the
    /// daemon session map before this gate runs, otherwise only pre-existing
    /// sessions can be quarantined by this pass.
    pub(crate) fn validate_linked_history_best_effort(&self) {
        let links = match self.state.sync_state.list_links() {
            Ok(links) => links,
            Err(error) => {
                tracing::error!(%error, "could not enumerate linked groups for retained-history authentication");
                return;
            }
        };
        let groups: HashSet<String> =
            links.into_iter().filter(|link| !link.orphaned).map(|link| link.group_id).collect();
        for group_id in groups {
            match self.validate_retained_group(&group_id) {
                Ok(report) => {
                    self.restore_group_sessions_if_currently_authorized(&group_id);
                    tracing::debug!(
                        group_id,
                        verified_changes = report.verified_changes,
                        "re-authenticated retained change history and restored currently-authorized sessions"
                    );
                }
                Err(AuthenticatedHistoryError::TrustUnavailable { device_id }) => {
                    self.quarantine_group_sessions(&group_id);
                    tracing::warn!(
                        group_id,
                        author_device_id = %device_id,
                        "retained-history authentication deferred; quarantining group from peer serving until author trust material is available"
                    );
                }
                Err(error @ AuthenticatedHistoryError::InvalidHistory(_)) => {
                    self.quarantine_group_sessions(&group_id);
                    tracing::error!(
                        group_id,
                        %error,
                        "retained change history failed cryptographic authentication; quarantining peer serving and failing group policy closed"
                    );
                    self.state.mark_group_policy_stale(&group_id);
                }
                Err(error @ AuthenticatedHistoryError::Store(_)) => {
                    self.quarantine_group_sessions(&group_id);
                    tracing::error!(
                        group_id,
                        %error,
                        "retained change history could not be read for authentication; quarantining group rather than serving unverified history"
                    );
                }
            }
        }
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
    fn signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
        // Store-and-forward can legitimately bring one of this device's own
        // historical Changes back through another peer. The netmap metadata map
        // contains peers, not necessarily self, so resolve the local author's
        // key from the process-lifetime signing identity first.
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
            .peer_signing_key(device_id)
            .or_else(|| Self::historical_pinned_signing_key(device_id))
    }

    fn is_writer(&self, device_id: &str, group_id: &str) -> bool {
        self.state.peer_is_writer(device_id, group_id)
    }

    fn accepts_change_auth(
        &self,
        device_id: &str,
        group_id: &str,
        signing_key_fingerprint: [u8; 32],
        auth: ChangeAuth,
    ) -> bool {
        // Resolve the group's policy state through the daemon's single
        // group-policy resolver, so inbound admission and retained-history
        // validation fail closed on the same conditions local emission
        // withholds on: own-verification-stale, coordinator-flagged invalid,
        // and an already-introduced group whose verified policy has not loaded.
        match self.state.resolve_group_policy(group_id) {
            GroupPolicyResolution::Verified(policy) => {
                policy.author_was_writer_at(device_id, signing_key_fingerprint, auth)
            }
            GroupPolicyResolution::Bootstrap => {
                // Match DaemonState's local-change auth provider exactly: in the
                // genuine pre-policy bootstrap window this device's own local
                // emission is stamped PLACEHOLDER without consulting the peer
                // writer map. Remote authors still require the existing netmap
                // writer authorization.
                auth == ChangeAuth::PLACEHOLDER
                    && (device_id == self.state.device_id
                        || self.state.peer_is_writer(device_id, group_id))
            }
            GroupPolicyResolution::Withhold => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ed25519_dalek::SigningKey;
    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_sync_core::index::SyncState;

    use super::*;

    fn test_state() -> Arc<DaemonState> {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(SyncState::open_in_memory().unwrap());
        DaemonState::new("device-a".into(), sync_state, store)
    }

    #[tokio::test]
    async fn policy_invalid_group_id_stops_new_peer_admission_for_that_group() {
        let state = test_state();
        let group = "policy-invalid-group";
        state.set_peer_group_writer("device-b", group, true);

        let authenticator = NetmapChangeAuthenticator::new(state);

        assert!(
            !authenticator.accepts_change_auth(
                "device-b",
                group,
                [0u8; 32],
                ChangeAuth::PLACEHOLDER,
            ),
            "a group with no verified policy loaded must fail closed for peer admission rather than trusting a placeholder-auth writer"
        );
    }

    #[tokio::test]
    async fn signing_key_resolver_includes_this_devices_own_signing_identity() {
        let state = test_state();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        state.set_device_signing_key(key.clone());
        let authenticator = NetmapChangeAuthenticator::new(state);

        assert_eq!(authenticator.signing_key("device-a"), Some(key.verifying_key().to_bytes()));
    }

    #[tokio::test]
    async fn bootstrap_auth_matches_local_emission_for_this_device() {
        let state = test_state();
        let authenticator = NetmapChangeAuthenticator::new(state);
        assert!(authenticator.accepts_change_auth(
            "device-a",
            "brand-new-group",
            [0u8; 32],
            ChangeAuth::PLACEHOLDER,
        ));
    }

    /// A cached `false` must be honored without re-running
    /// `validate_retained_group` -- a fresh (uncached) validation of this
    /// never-touched bootstrap group would say it is fine, so an empty
    /// result here can only come from the cache actually being consulted.
    #[tokio::test]
    async fn effective_servable_groups_short_circuits_on_a_cached_result() {
        let state = test_state();
        let raw_groups: HashSet<String> = HashSet::from(["group-x".to_string()]);
        let cache: Mutex<HashMap<String, bool>> = Mutex::new(HashMap::new());
        cache.lock().unwrap().insert("group-x".to_string(), false);

        let result = NetmapChangeAuthenticator::effective_servable_groups(state, &raw_groups, &cache);
        assert!(result.is_empty());
    }

    /// A validation miss populates the cache with its outcome, so a group
    /// shared by many peers in one netmap-update pass is walked once, not
    /// once per peer.
    #[tokio::test]
    async fn effective_servable_groups_populates_the_validation_cache_on_a_miss() {
        let state = test_state();
        let raw_groups: HashSet<String> = HashSet::from(["group-y".to_string()]);
        let cache: Mutex<HashMap<String, bool>> = Mutex::new(HashMap::new());

        let result =
            NetmapChangeAuthenticator::effective_servable_groups(state, &raw_groups, &cache);
        assert_eq!(result, raw_groups);
        assert_eq!(cache.lock().unwrap().get("group-y").copied(), Some(true));
    }
}

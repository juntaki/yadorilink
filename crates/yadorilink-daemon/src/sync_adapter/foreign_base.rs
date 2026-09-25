//! Peers that, by their own account, stand on a different history base.
//!
//! This is the explicit "merge required" state. It exists so that a peer
//! on another base is neither silently ignored nor acted on: a later merge
//! can find out whom it would have to merge with and what each of them
//! claimed, and until then nothing happens.
//!
//! Every entry is a claim, held as one. A claim alone switches nothing and
//! starts nothing: acting on a foreign base takes the signed snapshot
//! manifest, the snapshot whose hash the manifest names, and a summary
//! verified against them -- none of which an advertisement carries.
//! [`merge_claimed_foreign_base`] is the one place a claim is acted on, and
//! only once the base fetched from that peer has verified and turned out to
//! be exactly the base it claimed.
//!
//! In memory only: one entry per peer device per group, replaced on every
//! negotiation with that peer and dropped when one is refused. A restart
//! forgets them, and the next session with each peer re-establishes them.
//! Membership is checked when the claims are read, not when they are
//! heard, so a device that has since lost the group is never reported.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use yadorilink_replica_domain::base_negotiation::{BaseAdvertisement, ForeignBase};
use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_replica_domain::rebootstrap::{HistoryEpoch, SnapshotManifest};
use yadorilink_sync_sqlite::rebootstrap_store::CommittedMerge;

use crate::rebootstrap_handler::{DaemonRebootstrapHandler, ForeignBaseMergeError};

/// One peer's claim to stand on a base this device does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignBaseClaim {
    /// The device whose connection carried the claim.
    pub peer_device: String,
    /// The base this device stood on when it heard the claim.
    pub local_epoch: HistoryEpoch,
    /// The peer's advertisement, exactly as it made it. Unverified.
    pub claim: BaseAdvertisement,
}

/// Whether `device` (first) is a member of `group` (second) right now.
pub type Membership = Arc<dyn Fn(&str, &str) -> bool + Send + Sync>;

/// The merge-required state for every group, per peer device.
pub struct ForeignBaseClaims {
    claims: Mutex<BTreeMap<(String, String), ForeignBaseClaim>>,
    is_member: Membership,
}

impl std::fmt::Debug for ForeignBaseClaims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForeignBaseClaims").field("claims", &*self.lock()).finish_non_exhaustive()
    }
}

impl ForeignBaseClaims {
    /// `is_member` is asked on every read; a claim from a device it
    /// rejects is not reported.
    pub fn new(is_member: Membership) -> Self {
        Self { claims: Mutex::default(), is_member }
    }

    /// A negotiation with `peer_device` found it on a different base.
    pub fn record(&self, group: &FolderGroupId, peer_device: &str, foreign: ForeignBase) {
        let claim = ForeignBaseClaim {
            peer_device: peer_device.to_owned(),
            local_epoch: foreign.local_epoch,
            claim: foreign.claim,
        };
        self.lock().insert((group.0.clone(), peer_device.to_owned()), claim);
    }

    /// A negotiation with `peer_device` found it on this device's base, or
    /// was refused; either way, whatever it claimed before no longer
    /// describes it.
    pub fn forget(&self, group: &FolderGroupId, peer_device: &str) {
        self.lock().remove(&(group.0.clone(), peer_device.to_owned()));
    }

    /// Peers of `group` whose last negotiation found them on a base other
    /// than `current` -- the base this device stands on now -- and that
    /// are still members of `group`.
    ///
    /// A claim heard while this device stood on another base is not
    /// returned: it was a comparison against a history this device has
    /// since left, and says nothing about the one it holds now.
    pub fn merge_required(
        &self,
        group: &FolderGroupId,
        current: HistoryEpoch,
    ) -> Vec<ForeignBaseClaim> {
        self.lock()
            .iter()
            .filter(|((claim_group, device), claim)| {
                claim_group == &group.0
                    && claim.local_epoch == current
                    && (self.is_member)(device, claim_group)
            })
            .map(|(_, claim)| claim.clone())
            .collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<(String, String), ForeignBaseClaim>> {
        self.claims.lock().expect("foreign base claims poisoned")
    }
}

/// Merges the base `peer_device` claimed to stand on into this device's
/// history for `group`.
///
/// The claim is what asks for the merge, never what authorizes it: the
/// peer must hold a live claim for this device's current base, the
/// manifest and snapshot fetched from it must verify
/// ([`DaemonRebootstrapHandler::verify_foreign_base`]), and they must be
/// exactly the checkpoint and summary it advertised. Only then is the merge
/// committed, and the claim, answered, is forgotten.
pub fn merge_claimed_foreign_base(
    claims: &ForeignBaseClaims,
    handler: &DaemonRebootstrapHandler,
    group: &FolderGroupId,
    peer_device: &str,
    manifest: &SnapshotManifest,
    snapshot_bytes: &[u8],
) -> Result<CommittedMerge, ForeignBaseMergeError> {
    let current = HistoryEpoch::from_installed_base(
        handler
            .coordinator()
            .rebootstrap_store_repository()
            .history_base(group.as_str())
            .map_err(|error| ForeignBaseMergeError::Merge(error.into()))?,
    );
    let claim = claims
        .merge_required(group, current)
        .into_iter()
        .find(|claim| claim.peer_device == peer_device)
        .ok_or_else(|| ForeignBaseMergeError::NotClaimed { peer: peer_device.to_owned() })?;
    let returning = handler.verify_foreign_base(group.as_str(), manifest, snapshot_bytes)?;
    if !returning.matches_advertisement(&claim.claim.base) {
        return Err(ForeignBaseMergeError::NotAdvertised { peer: peer_device.to_owned() });
    }
    let merged = handler.coordinator().commit_foreign_merge(&returning)?;
    claims.forget(group, peer_device);
    Ok(merged)
}

#[cfg(test)]
mod tests {
    use yadorilink_replica_domain::base_negotiation::AdvertisedBase;
    use yadorilink_replica_domain::rebootstrap::{Checkpoint, HistoryBase};

    use super::*;

    fn group() -> FolderGroupId {
        FolderGroupId("group-foreign-base".into())
    }

    fn claim_of(snapshot_seed: u8) -> BaseAdvertisement {
        use yadorilink_replica_domain::base_negotiation::SummaryIdentity;
        BaseAdvertisement::new(
            group(),
            AdvertisedBase::Installed {
                checkpoint: Box::new(Checkpoint::new(group(), Vec::new(), [snapshot_seed; 32])),
                summary: SummaryIdentity([1; 32]),
            },
            Vec::new(),
        )
        .unwrap()
    }

    /// A claim is measured against the base this device stood on when it
    /// heard it. Once this device stands elsewhere, the claim describes a
    /// comparison with a history it no longer holds.
    #[test]
    fn a_claim_heard_against_a_base_this_device_has_left_is_not_reported() {
        let claims = ForeignBaseClaims::new(Arc::new(|_: &str, _: &str| true));
        claims.record(
            &group(),
            "device-peer",
            ForeignBase { local_epoch: HistoryEpoch::Genesis, claim: claim_of(5) },
        );
        assert_eq!(claims.merge_required(&group(), HistoryEpoch::Genesis).len(), 1);

        let moved_to = HistoryEpoch::Base(HistoryBase([9; 32]));
        assert!(claims.merge_required(&group(), moved_to).is_empty());
    }

    #[test]
    fn the_latest_claim_per_peer_replaces_the_previous_one() {
        let claims = ForeignBaseClaims::new(Arc::new(|_: &str, _: &str| true));
        for seed in [5, 6] {
            claims.record(
                &group(),
                "device-peer",
                ForeignBase { local_epoch: HistoryEpoch::Genesis, claim: claim_of(seed) },
            );
        }
        let reported = claims.merge_required(&group(), HistoryEpoch::Genesis);
        assert_eq!(reported.len(), 1);
        assert_eq!(reported[0].claim, claim_of(6));

        claims.forget(&group(), "device-peer");
        assert!(claims.merge_required(&group(), HistoryEpoch::Genesis).is_empty());
    }

    /// A claim asks for a merge; it does not authorize one. Without a live
    /// claim from the peer nothing is fetched into the store, a verified
    /// base that is not the one the peer advertised is refused, and only
    /// the advertised base reaches the merge -- which, on a device with no
    /// base of its own to merge it with, is refused in turn and leaves the
    /// claim standing.
    #[tokio::test]
    async fn a_claim_is_acted_on_only_for_the_base_it_advertised() {
        use ed25519_dalek::SigningKey;
        use yadorilink_local_storage::SegmentBlockStore;
        use yadorilink_replica_domain::ids::{AuthorSeq, ChangeHash, DeviceId};
        use yadorilink_replica_engine::rebootstrap_snapshot::{
            RebootstrapSnapshot, SnapshotAuthorState,
        };
        use yadorilink_sync_sqlite::rebootstrap_store::{ForeignMergeError, ForeignMergeRefusal};

        let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
        let coordinator =
            Arc::new(crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap());
        let state = crate::daemon_state::DaemonState::new("device-a".into(), coordinator, store);
        let key = SigningKey::from_bytes(&[7; 32]);
        state.set_device_signing_key(key.clone());
        let handler = DaemonRebootstrapHandler::new(state);

        let snapshot = RebootstrapSnapshot::new(
            group(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![SnapshotAuthorState {
                device_id: "device-b".into(),
                watermark: AuthorSeq(1),
                tip_change_hash: ChangeHash([3; 32]),
            }],
            Vec::new(),
            1,
        )
        .unwrap();
        let checkpoint = Checkpoint::new(group(), Vec::new(), snapshot.snapshot_hash());
        let manifest = SnapshotManifest::new_signed(
            checkpoint.clone(),
            Vec::new(),
            None,
            DeviceId("device-a".into()),
            &key,
        )
        .unwrap();
        let bytes = snapshot.canonical_encoding();
        let claims = ForeignBaseClaims::new(Arc::new(|_: &str, _: &str| true));
        let merge = || {
            merge_claimed_foreign_base(&claims, &handler, &group(), "device-b", &manifest, &bytes)
        };

        assert!(matches!(merge(), Err(ForeignBaseMergeError::NotClaimed { .. })));

        claims.record(
            &group(),
            "device-b",
            ForeignBase { local_epoch: HistoryEpoch::Genesis, claim: claim_of(5) },
        );
        assert!(matches!(merge(), Err(ForeignBaseMergeError::NotAdvertised { .. })));

        let advertised = BaseAdvertisement::new(
            group(),
            AdvertisedBase::Installed {
                checkpoint: Box::new(checkpoint),
                summary: snapshot.summary_identity(),
            },
            Vec::new(),
        )
        .unwrap();
        claims.record(
            &group(),
            "device-b",
            ForeignBase { local_epoch: HistoryEpoch::Genesis, claim: advertised },
        );
        let refused = merge();
        assert!(
            matches!(
                refused,
                Err(ForeignBaseMergeError::Merge(ForeignMergeError::Refused(
                    ForeignMergeRefusal::NoBaseInstalled
                )))
            ),
            "got {refused:?}"
        );
        assert_eq!(claims.merge_required(&group(), HistoryEpoch::Genesis).len(), 1);
    }
}

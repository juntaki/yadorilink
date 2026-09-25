//! The daemon's authority over a history base a peer offers: who may found
//! one, under which key, and whether everything the base carries verifies.
//!
//! Sync-core owns the signed objects, the merge and the atomic install
//! (`rebootstrap_store::commit_foreign_merge`). The daemon supplies the
//! process identity and a base-specific trust resolver -- deliberately NOT
//! the same resolver ordinary retained-history Change verification uses. See
//! `trust_key`'s doc comment for why.
//!
//! The legacy wire re-bootstrap (a peer answering a request for a pruned
//! hash with a signed `RebootstrapRequired`, installed over this device's
//! history with its frontier bodies kept and its witnesses taken on trust)
//! is gone. A base reaches this device only through
//! [`DaemonRebootstrapHandler::verify_foreign_base`], which verifies every
//! witness before the merge installs it.

use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::sync_error::SyncError;
use yadorilink_replica_domain::change;
use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_replica_engine::rebootstrap::SnapshotManifest;
use yadorilink_replica_engine::rebootstrap_snapshot::RebootstrapSnapshot;
use yadorilink_sync_sqlite::rebootstrap_store::{
    verify_returning_base, BaseSignerAuthority, ForeignMergeError, VerifiedBaseSummary,
};

use crate::daemon_state::{DaemonState, GroupPolicyResolution};

pub struct DaemonRebootstrapHandler {
    state: Arc<DaemonState>,
}

impl DaemonRebootstrapHandler {
    pub fn new(state: Arc<DaemonState>) -> Arc<Self> {
        Arc::new(Self { state })
    }

    /// Resolves a re-bootstrap control message's claimed signer to a LIVE
    /// key only — self, or a peer's *current* netmap-pinned signing key.
    ///
    /// This deliberately does NOT fall back to the historical pinned-key
    /// archive (`NetmapChangeAuthenticator::historical_pinned_signing_key`)
    /// the way ordinary retained-history Change verification does. That
    /// fallback exists to keep OLD, already-admitted Change signatures
    /// verifiable after their author is revoked — necessary, since history
    /// must remain checkable no matter who has since left. A re-bootstrap
    /// control message is different in kind: it is NOT verifying something
    /// already admitted, it is authorizing a BRAND NEW HistoryBase install
    /// going forward. If a device's private key were compromised or simply
    /// retained after revocation, the historical-pin fallback would let that
    /// key sign a new snapshot/checkpoint and have it accepted here — a
    /// revoked writer forging a new baseline. Restricting this resolver to
    /// live keys only closes that gap: a revoked device has no live key
    /// entry to resolve against.
    fn trust_key(&self, device_id: &str) -> Option<[u8; 32]> {
        if device_id == self.state.device_id {
            return self.state.device_signing_key().map(|key| key.verifying_key().to_bytes());
        }
        self.state.authority.peer_signing_key(device_id)
    }

    /// Beyond signature validity (which only proves the manifest's signer
    /// key produced these exact bytes), a base's manifest must also be
    /// authorized to introduce a NEW baseline for its specific group right
    /// now: the signer must be a device this policy currently recognizes as
    /// a writer, the manifest's actual signing key must be the exact key the
    /// signed policy chain bound to that writer, and — since a compaction
    /// snapshot materializes the group's *entire* retained history — the
    /// signer must be a full replica of it. None of these is implied by a
    /// valid signature alone; `RebootstrapTrust::signing_key` has no group
    /// context to check them itself, so this runs as a second, explicit gate
    /// after signature verification, before a base is believed.
    ///
    /// The writer-role-and-key-binding check (first two conditions above)
    /// now fully mirrors the pattern `NetmapChangeAuthenticator::
    /// accepts_change_auth` (`change_auth.rs`) uses for ordinary Change
    /// admission, via `GroupPolicyState::author_was_writer_at`: resolve the
    /// group's signed policy chain, check the signer's role against it (real,
    /// role-aware writer authorization -- NOT `state.authority.peer_is_writer`, which
    /// is populated from plain netmap membership, every authorized group
    /// member including Viewer; see `replace_peer_netmap_metadata`), AND
    /// require the manifest's actual signer key (`self.trust_key(signer)`,
    /// the SAME key already used to verify the manifest's own signature) to
    /// hash to the exact `AuthorizedWriter::signing_key_fingerprint` the
    /// policy chain bound to that writer -- the same two-part test
    /// `author_was_writer_at` ends on (`role.is_writer() &&
    /// fingerprint_admits(...)`, `change_policy.rs`). Without this second
    /// half, the writer-role check would pass on `device_id` alone while
    /// still trusting whatever key the NETMAP currently has pinned for that
    /// device to have produced the signature actually verified above --
    /// exactly the weak trust root this whole check exists to stop relying
    /// on for write-authorization decisions. Unlike ordinary Change
    /// admission, this call site has no `ChangeAuth` policy-watermark stamp
    /// to check the signer against a specific historical seq -- it only has
    /// the bare signer device id -- so this checks `current_writers()`,
    /// `GroupPolicyState`'s existing "writer set as of the policy's own
    /// current/latest verified position" accessor, rather than a historical
    /// one.
    ///
    /// The full-replica check (the THIRD condition, `peer_group_is_full_
    /// replica` below) is intentionally and unavoidably netmap-derived only,
    /// with no signed-policy equivalent to bind against: `WriterRole`/the
    /// signed policy chain has no storage-mode/full-replica concept at all,
    /// so there is nothing in the policy chain for this to check the netmap
    /// claim against. Do not assume the fingerprint-binding fix above
    /// extends to this check too -- it does not, and cannot with the policy
    /// chain's current shape.
    ///
    /// `signing_key` is the key the manifest's signature was verified under,
    /// which must be the one the signed policy bound to `signer`. `None` (no
    /// live key) fails closed.
    fn authorize_base_signer(
        &self,
        group_id: &str,
        signer: &str,
        signing_key: Option<&[u8; 32]>,
    ) -> Result<(), SyncError> {
        if signer == self.state.device_id {
            return Ok(());
        }
        let is_writer = match self.state.resolve_group_policy(group_id) {
            GroupPolicyResolution::Verified(policy) => {
                // A verified policy whose `current_writers()` is empty -- a
                // genuinely empty signed log, or a chain where every past
                // writer has since been revoked or downgraded to Viewer --
                // is treated as "no authorized writer for this group, full
                // stop": `find` below returns `None` and `is_writer` resolves
                // to `false` unconditionally, with no netmap-derived
                // fallback of any kind. This is a deliberate, fail-closed
                // choice, and it differs on purpose from how the SAME
                // scenario is handled elsewhere in this codebase:
                //   - `local_change_auth_provider` (daemon_state.rs) falls
                //     through to `author_was_writer_at`'s own empty-log
                //     special case, which ALLOWS local emission (treats an
                //     empty verified log the same as the pre-policy
                //     Bootstrap window);
                //   - `repair_election_provider` (daemon_state.rs) falls
                //     back to the netmap's role-blind member set (see the
                //     comment on that function).
                // Re-bootstrap is different in kind from both: it installs a
                // BRAND NEW HistoryBase for the group, wholesale replacing
                // retained history, on the strength of a single signer claim
                // with no group-wide quorum or merge to fall back on if that
                // signer turns out to be wrong. An empty verified writer set
                // gives this function no signed authority to point to at
                // all, so rejecting outright -- rather than guessing via
                // netmap membership, or treating "empty" as "still
                // bootstrapping" -- is the only answer that cannot be
                // exploited by a compromised or spoofed netmap entry. This
                // is a real behavior change from the pre-fix
                // membership-based version (which relied on
                // `peer_is_writer` and so would have allowed this); see
                // `authorize_base_signer_rejects_every_signer_when_the_verified_policy_names_no_writers`
                // below for regression coverage.
                policy
                    .current_writers()
                    .into_iter()
                    .find(|writer| writer.device_id == signer)
                    .is_some_and(|writer| {
                        // Fail closed if there is no LIVE netmap-pinned key
                        // to compare against (matches `trust_key`'s own
                        // fail-closed behavior for signature verification).
                        signing_key
                            .map(|signer_key| {
                                let presented_fingerprint: [u8; 32] =
                                    Sha256::digest(signer_key).into();
                                presented_fingerprint == writer.signing_key_fingerprint
                            })
                            .unwrap_or(false)
                    })
            }
            GroupPolicyResolution::Bootstrap => {
                // Genuine pre-policy bootstrap window: no signed policy
                // chain has ever existed for this group, so there is no
                // role data -- and so no signing-key binding either -- to
                // check against. Fall back to netmap membership, exactly
                // matching `local_change_auth_provider`'s and
                // `accepts_change_auth`'s own Bootstrap-arm behavior (both
                // documented as legitimate on this narrow pre-role window;
                // see their own comments).
                self.state.authority.peer_is_writer(signer, group_id)
            }
            GroupPolicyResolution::Withhold => {
                return Err(SyncError::CorruptState(format!(
                    "cannot accept re-bootstrap manifest for group {group_id}: group policy is \
                     currently withheld"
                )));
            }
        };
        if !is_writer {
            return Err(SyncError::CorruptState(format!(
                "re-bootstrap manifest signer {signer} is not a current writer for group \
                 {group_id}, or its signing key does not match the key the signed policy chain \
                 bound to that writer; refusing to install a HistoryBase it is not authorized to \
                 introduce"
            )));
        }
        if !self.state.authority.peer_group_is_full_replica(signer, group_id) {
            return Err(SyncError::CorruptState(format!(
                "re-bootstrap manifest signer {signer} is not a current full replica for group \
                 {group_id}; only a device holding the group's complete retained history can \
                 attest a compaction snapshot of it"
            )));
        }
        Ok(())
    }

    /// Trusting the outer `SnapshotManifest` signer only proves the snapshot
    /// bytes were not tampered with in transit (`snapshot_hash` equality) —
    /// it does NOT prove any individual `Change` embedded in
    /// `snapshot.frontier_changes` was itself legitimately authorized at the
    /// time it was created, which may be a DIFFERENT device's Change than
    /// the manifest signer. This independently re-verifies each embedded
    /// Change's own signature and historical authorization, the same
    /// signature/authentication boundary `authenticated_history::validate_retained_group`
    /// and live peer admission both already use, so a merged base
    /// can never adopt a Change whose own authorization this device has not
    /// positively checked.
    fn verify_each_frontier_change(&self, snapshot: &RebootstrapSnapshot) -> Result<(), SyncError> {
        let authenticator = crate::change_auth::NetmapChangeAuthenticator::new(self.state.clone());
        for encoded in &snapshot.frontier_changes {
            let frontier_change = Change::from_wire_bytes(encoded).map_err(|error| {
                SyncError::CorruptState(format!(
                    "re-bootstrap snapshot contains an invalid frontier change: {error}"
                ))
            })?;
            let hash = frontier_change.compute_hash();
            let key_bytes =
                authenticator.signing_key(frontier_change.device_id.as_str()).ok_or_else(|| {
                    SyncError::CorruptState(format!(
                        "cannot verify re-bootstrap frontier change {}: no pinned signing key \
                         for author {}",
                        hash.to_hex(),
                        frontier_change.device_id.as_str()
                    ))
                })?;
            let verifying_key = change::verifying_key_from_bytes(&key_bytes).map_err(|error| {
                SyncError::CorruptState(format!(
                    "frontier change author {} has an invalid pinned signing key: {error}",
                    frontier_change.device_id.as_str()
                ))
            })?;
            // Raw-frontier verification: this checks that the pinned
            // author is a CURRENT netmap writer for the group (frontier
            // changes here carry no `AuthorizationCheckpoint` of their
            // own).
            change::verify_change(
                &frontier_change,
                &hash,
                &verifying_key,
                |device_id, group_id| {
                    self.state.authority.peer_is_writer(device_id.as_str(), group_id.as_str())
                },
            )
            .map_err(|error| {
                SyncError::CorruptState(format!(
                    "re-bootstrap frontier change {} by {} failed signature/authorization \
                     verification: {error}",
                    hash.to_hex(),
                    frontier_change.device_id.as_str()
                ))
            })?;
        }
        Ok(())
    }
}

/// The group's authority over who may found a base, for verifying a base a
/// peer offers to merge: the same three conditions a re-bootstrap manifest
/// is held to, asked about the key the manifest's signature was verified
/// under.
impl BaseSignerAuthority for DaemonRebootstrapHandler {
    fn may_found_base(
        &self,
        group_id: &str,
        signer_device_id: &str,
        signing_key: &[u8; 32],
    ) -> bool {
        self.authorize_base_signer(group_id, signer_device_id, Some(signing_key)).is_ok()
    }
}

impl DaemonRebootstrapHandler {
    /// The store this handler installs into.
    pub fn coordinator(&self) -> &crate::replica_coordinator::ReplicaCoordinator {
        &self.state.replica_coordinator
    }

    /// A base a peer offers to merge, checked before anything of it is
    /// believed: the manifest verified under the signer's live key, the
    /// signer one the group lets found a base, the snapshot bytes the ones
    /// the manifest commits to, its summary consistent and its content
    /// carried, and each frontier change and each witness it carries
    /// independently verified.
    pub fn verify_foreign_base(
        &self,
        group_id: &str,
        manifest: &SnapshotManifest,
        snapshot_bytes: &[u8],
    ) -> Result<VerifiedBaseSummary, ForeignBaseMergeError> {
        let trust = |device_id: &str| self.trust_key(device_id);
        let returning = verify_returning_base(group_id, manifest, snapshot_bytes, &trust, self)
            .map_err(ForeignMergeError::from)?;
        self.verify_each_frontier_change(returning.snapshot())
            .map_err(ForeignBaseMergeError::FrontierUnverified)?;
        self.verify_each_witness(group_id, returning.snapshot())?;
        Ok(returning)
    }

    /// Every witness a base carries, verified against this device's own
    /// verified policy chain for the group, as a received change's
    /// evidence is. A merge keeps no frontier body behind, so every row
    /// the base carries is served on the strength of its witness alone.
    ///
    /// A witness must also name the author the summary gives its change:
    /// a head's author is its position, and evidence published by another
    /// device says nothing about that position. No verified policy for the
    /// group verifies nothing.
    fn verify_each_witness(
        &self,
        group_id: &str,
        snapshot: &RebootstrapSnapshot,
    ) -> Result<(), ForeignBaseMergeError> {
        let policy = match self.state.resolve_group_policy(group_id) {
            GroupPolicyResolution::Verified(policy) => Some(policy),
            GroupPolicyResolution::Bootstrap | GroupPolicyResolution::Withhold => None,
        };
        for witness in &snapshot.published_change_witnesses {
            let unverified = |detail: String| ForeignBaseMergeError::WitnessUnverified {
                change: witness.change_hash,
                detail,
            };
            let checkpoint = witness
                .verify(group_id, |key_id, policy_head| {
                    policy.as_ref()?.resolve_authority_key(key_id, policy_head)
                })
                .map_err(|error| unverified(error.to_string()))?;
            let named = snapshot
                .path_heads
                .iter()
                .map(|head| (head.change_hash, head.device_id.as_str()))
                .chain(
                    snapshot
                        .author_state
                        .iter()
                        .map(|author| (author.tip_change_hash, author.device_id.as_str())),
                )
                .find(|(change, device)| {
                    *change == witness.change_hash && *device != checkpoint.device_id
                });
            if let Some((_, device)) = named {
                return Err(unverified(format!(
                    "published by {} but written by {device}",
                    checkpoint.device_id
                )));
            }
        }
        Ok(())
    }
}

/// Why a peer's base was not merged.
#[derive(Debug, thiserror::Error)]
pub enum ForeignBaseMergeError {
    /// No live claim by this peer to stand on another base: nothing asked
    /// for a merge with it, or the claim was heard on a base this device
    /// has since left.
    #[error("{peer} does not claim a base this device must merge with")]
    NotClaimed { peer: String },
    /// The base fetched from the peer is not the one it advertised.
    #[error("the base fetched from {peer} is not the one it advertised")]
    NotAdvertised { peer: String },
    /// A frontier change the base carries did not verify.
    #[error("a frontier change of the offered base does not verify: {0}")]
    FrontierUnverified(SyncError),
    /// The evidence the base carries for a change did not verify.
    #[error("the offered base's evidence for {} does not verify: {detail}", .change.to_hex())]
    WitnessUnverified { change: ChangeHash, detail: String },
    /// The merge was refused, or the store failed.
    #[error(transparent)]
    Merge(#[from] ForeignMergeError),
}

#[cfg(test)]
mod tests;

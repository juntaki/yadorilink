//! Exact-version custody verification for destructive storage operations.
//!
//! The verification entry points ([`verify_reclaim_custody`] and, for
//! callers' own tests, [`verify_reclaim_custody_for_test`]) are the only way
//! to obtain a [`VerifiedCustody`] -- its fields stay private and it exposes
//! only the accessors a reclaim caller needs, so a caller can never
//! construct or forge one from outside this module.

use yadorilink_replica_domain::file::VersionBlock;
use yadorilink_replica_domain::ids::VersionHash;

/// Physical on-demand cache reclamation remains disabled until the responder
/// can issue a crash-durable, exact-version lease that its GC treats as a live
/// root. An instantaneous VersionPresent acknowledgement is not a custody
/// lifetime: the responder may advance and reclaim that version immediately
/// afterward without any membership change.
pub const REMOTE_CUSTODY_LEASES_SUPPORTED: bool = false;

/// Identity and authorization epoch of the peer that confirmed custody.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyStamp {
    peer_id: String,
    membership_generation: u64,
}

impl CustodyStamp {
    pub fn new(peer_id: String, membership_generation: u64) -> Self {
        Self { peer_id, membership_generation }
    }

    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    pub fn membership_generation(&self) -> u64 {
        self.membership_generation
    }
}

/// Content-blind custody oracle. A confirmation must identify the authorized
/// full replica and the membership generation under which it answered. The
/// same oracle must be able to revalidate that stamp immediately before the
/// destructive operation commits.
pub trait FullReplicaCustody {
    fn confirm_exact_version(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<CustodyStamp>;

    fn confirmation_still_valid(&self, group_id: &str, stamp: &CustodyStamp) -> bool;
}

// Unit tests (this crate's own, and -- via the `test-support` feature --
// other crates' tests, e.g. yadorilink-sync-core's) use closures as
// deterministic custody oracles. Production callers must provide an
// explicit implementation that carries an epoch and revalidates it; the
// closure shortcut is deliberately absent from normal builds.
#[cfg(any(test, feature = "test-support"))]
impl<F: Fn(&str, &str, &VersionHash, &[VersionBlock]) -> bool> FullReplicaCustody for F {
    fn confirm_exact_version(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<CustodyStamp> {
        self(group_id, path, version_hash, blocks).then(|| CustodyStamp::new("test-peer".into(), 0))
    }

    fn confirmation_still_valid(&self, _group_id: &str, _stamp: &CustodyStamp) -> bool {
        true
    }
}

/// Linear, crate-private deletion capability issued only after exact-version
/// confirmation. It retains the issuing oracle so authorization can be
/// revalidated under the physical-deletion guard. Fields are private:
/// obtained only via [`verify_reclaim_custody`]/[`verify_reclaim_custody_for_test`],
/// never constructed directly.
pub struct VerifiedCustody<'a> {
    oracle: &'a dyn FullReplicaCustody,
    stamp: CustodyStamp,
    group_id: String,
    path: String,
    version_hash: VersionHash,
    blocks: Vec<VersionBlock>,
}

impl VerifiedCustody<'_> {
    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn version_hash(&self) -> &VersionHash {
        &self.version_hash
    }

    pub fn blocks(&self) -> &[VersionBlock] {
        &self.blocks
    }

    pub fn confirmation_still_valid(&self) -> bool {
        self.oracle.confirmation_still_valid(&self.group_id, &self.stamp)
    }
}

fn issue_verified<'a>(
    oracle: &'a dyn FullReplicaCustody,
    group_id: &str,
    path: &str,
    version_hash: &VersionHash,
    blocks: &[VersionBlock],
) -> Option<VerifiedCustody<'a>> {
    let stamp = oracle.confirm_exact_version(group_id, path, version_hash, blocks)?;
    Some(VerifiedCustody {
        oracle,
        stamp,
        group_id: group_id.to_owned(),
        path: path.to_owned(),
        version_hash: *version_hash,
        blocks: blocks.to_vec(),
    })
}

/// Verifies exact-version custody for a reclaim decision -- the sole
/// production entry point. Fails closed (`None`) while
/// [`REMOTE_CUSTODY_LEASES_SUPPORTED`] is `false`, since an instantaneous
/// confirmation is not a durable custody lease (see that const's own doc
/// comment).
pub fn verify_reclaim_custody<'a>(
    oracle: &'a dyn FullReplicaCustody,
    group_id: &str,
    path: &str,
    version_hash: &VersionHash,
    blocks: &[VersionBlock],
) -> Option<VerifiedCustody<'a>> {
    if !REMOTE_CUSTODY_LEASES_SUPPORTED {
        return None;
    }
    issue_verified(oracle, group_id, path, version_hash, blocks)
}

/// Test-only counterpart to [`verify_reclaim_custody`] that bypasses the
/// [`REMOTE_CUSTODY_LEASES_SUPPORTED`] gate, so a test oracle can exercise
/// [`VerifiedCustody`]'s own behavior without waiting on the real lease
/// feature. `#[cfg(any(test, feature = "test-support"))]`, matching this
/// crate's own convention for exposing test-only helpers to another crate's
/// test builds (mirrors `yadorilink-sync-core`'s established `test-support`
/// feature pattern).
#[cfg(any(test, feature = "test-support"))]
pub fn verify_reclaim_custody_for_test<'a>(
    oracle: &'a dyn FullReplicaCustody,
    group_id: &str,
    path: &str,
    version_hash: &VersionHash,
    blocks: &[VersionBlock],
) -> Option<VerifiedCustody<'a>> {
    issue_verified(oracle, group_id, path, version_hash, blocks)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version() -> (VersionHash, Vec<VersionBlock>) {
        use yadorilink_replica_domain::ids::BlockHash;
        (VersionHash([7; 32]), vec![VersionBlock { hash: BlockHash(vec![3; 32]), size: 9 }])
    }

    #[test]
    fn verifier_fails_closed_without_positive_exact_version_confirmation() {
        let (version_hash, blocks) = version();
        let rejecting = |_: &str, _: &str, _: &VersionHash, _: &[VersionBlock]| false;
        assert!(verify_reclaim_custody_for_test(
            &rejecting,
            "group",
            "file",
            &version_hash,
            &blocks
        )
        .is_none());
    }

    #[test]
    fn verifier_binds_token_to_the_confirmed_identity() {
        let (version_hash, blocks) = version();
        let exact = |group: &str,
                     path: &str,
                     candidate_hash: &VersionHash,
                     candidate_blocks: &[VersionBlock]| {
            group == "group"
                && path == "file"
                && candidate_hash == &version_hash
                && candidate_blocks == blocks
        };
        let verified =
            verify_reclaim_custody_for_test(&exact, "group", "file", &version_hash, &blocks)
                .unwrap();

        assert_eq!(verified.group_id(), "group");
        assert_eq!(verified.path(), "file");
        assert_eq!(verified.version_hash(), &version_hash);
        assert_eq!(verified.blocks(), blocks);
        assert!(verified.confirmation_still_valid());
        assert!(verify_reclaim_custody_for_test(
            &exact,
            "group",
            "other-file",
            &version_hash,
            &blocks
        )
        .is_none());
    }

    #[test]
    fn production_verifier_refuses_instantaneous_confirmation_without_lease() {
        let (version_hash, blocks) = version();
        let accepting = |_: &str, _: &str, _: &VersionHash, _: &[VersionBlock]| true;
        assert!(
            verify_reclaim_custody(&accepting, "group", "file", &version_hash, &blocks).is_none()
        );
    }
}

//! Exact-version custody verification for destructive storage operations.
//!
//! The issuer is intentionally not part of the public crate API:
//! ```compile_fail
//! use yadorilink_sync_core::custody::CustodyVerifier;
//! ```

use crate::change::{VersionBlock, VersionHash};

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

// Unit tests use closures as deterministic custody oracles. Production
// callers must provide an explicit implementation that carries an epoch and
// revalidates it; the closure shortcut is deliberately absent from normal
// builds.
#[cfg(test)]
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
/// revalidated under the physical-deletion guard.
pub(crate) struct VerifiedCustody<'a> {
    oracle: &'a dyn FullReplicaCustody,
    stamp: CustodyStamp,
    group_id: String,
    path: String,
    version_hash: VersionHash,
    blocks: Vec<VersionBlock>,
}

impl VerifiedCustody<'_> {
    pub(crate) fn group_id(&self) -> &str {
        &self.group_id
    }

    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    pub(crate) fn version_hash(&self) -> &VersionHash {
        &self.version_hash
    }

    pub(crate) fn blocks(&self) -> &[VersionBlock] {
        &self.blocks
    }

    pub(crate) fn confirmation_still_valid(&self) -> bool {
        self.oracle.confirmation_still_valid(&self.group_id, &self.stamp)
    }
}

pub(crate) struct CustodyVerifier<'a> {
    oracle: &'a dyn FullReplicaCustody,
}

impl<'a> CustodyVerifier<'a> {
    pub(crate) fn new(oracle: &'a dyn FullReplicaCustody) -> Self {
        Self { oracle }
    }

    pub(crate) fn verify_exact_version(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<VerifiedCustody<'a>> {
        if !REMOTE_CUSTODY_LEASES_SUPPORTED {
            return None;
        }
        self.issue_verified(group_id, path, version_hash, blocks)
    }

    pub(crate) fn verify_for_reclaim(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<VerifiedCustody<'a>> {
        #[cfg(test)]
        {
            self.verify_exact_version_for_test(group_id, path, version_hash, blocks)
        }
        #[cfg(not(test))]
        {
            self.verify_exact_version(group_id, path, version_hash, blocks)
        }
    }

    #[cfg(test)]
    pub(crate) fn verify_exact_version_for_test(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<VerifiedCustody<'a>> {
        self.issue_verified(group_id, path, version_hash, blocks)
    }

    fn issue_verified(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<VerifiedCustody<'a>> {
        let stamp = self.oracle.confirm_exact_version(group_id, path, version_hash, blocks)?;
        Some(VerifiedCustody {
            oracle: self.oracle,
            stamp,
            group_id: group_id.to_owned(),
            path: path.to_owned(),
            version_hash: *version_hash,
            blocks: blocks.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::BlockHash;

    fn version() -> (VersionHash, Vec<VersionBlock>) {
        (VersionHash([7; 32]), vec![VersionBlock { hash: BlockHash(vec![3; 32]), size: 9 }])
    }

    #[test]
    fn verifier_fails_closed_without_positive_exact_version_confirmation() {
        let (version_hash, blocks) = version();
        let rejecting = |_: &str, _: &str, _: &VersionHash, _: &[VersionBlock]| false;
        assert!(CustodyVerifier::new(&rejecting)
            .verify_exact_version_for_test("group", "file", &version_hash, &blocks)
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
        let verifier = CustodyVerifier::new(&exact);
        let verified = verifier
            .verify_exact_version_for_test("group", "file", &version_hash, &blocks)
            .unwrap();

        assert_eq!(verified.group_id(), "group");
        assert_eq!(verified.path(), "file");
        assert_eq!(verified.version_hash(), &version_hash);
        assert_eq!(verified.blocks(), blocks);
        assert!(verified.confirmation_still_valid());
        assert!(verifier
            .verify_exact_version_for_test("group", "other-file", &version_hash, &blocks)
            .is_none());
    }

    #[test]
    fn production_verifier_refuses_instantaneous_confirmation_without_lease() {
        let (version_hash, blocks) = version();
        let accepting = |_: &str, _: &str, _: &VersionHash, _: &[VersionBlock]| true;
        assert!(CustodyVerifier::new(&accepting)
            .verify_exact_version("group", "file", &version_hash, &blocks)
            .is_none());
    }
}

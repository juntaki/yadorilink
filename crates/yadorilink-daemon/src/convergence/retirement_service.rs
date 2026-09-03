//! Runs the ephemeral-conflict-copy retirement audit for one group at a
//! time. Extracted out of `engine_wrapper.rs`'s `run_retirement_pass`,
//! which used to pick among `crate::hydration::candidate_sessions` (this
//! device's currently-connected peer sessions for a group) purely because
//! `retire_conflict_copies_only` happened to live on `PeerSyncSession` --
//! see `DaemonState::local_retirement_session`'s own doc comment for why
//! that dependency was never actually load-bearing for retirement's own
//! decision, which is driven entirely by local DAG/file-index/disk state.
//!
//! `reconcile_group` still prefers an already-live candidate session when
//! one exists (identical to `process_group_via_obligations`'s zero-work
//! pre-check and `run_hazard_recheck_pass`'s own session choice, both in
//! `convergence::engine`/`engine_wrapper`), falling back to the cached
//! local-only session only when there are none -- see `reconcile_group`'s
//! own doc comment for why unconditionally constructing the local session
//! is itself a hazard, not merely an unnecessary dependency.
//!
//! Deliberately thin: this commit moves WHICH session object runs the
//! audit (a cached local-only one, not a live peer's), not the audit logic
//! itself, nor the `MaterializationAuditGuard` contention `RetirementAttempt::
//! Busy` still reports -- that guard is still shared with `reconcile_local_
//! materialization_audit`/`reconcile_paths_directly` through `PeerSyncSession`
//! internals unchanged. A dedicated retirement-only single-flight (so a full
//! audit in flight can no longer make a retirement pass report `Busy` at
//! all) is later work, not this one.
use std::sync::Arc;

use yadorilink_peer_session::peer_session::RetirementAttempt;
use yadorilink_peer_session::PeerSessionError;

use crate::daemon_state::DaemonState;

pub struct ConvergenceRetirementService {
    state: Arc<DaemonState>,
}

impl ConvergenceRetirementService {
    pub fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    /// Runs `PeerSyncSession::retire_conflict_copies_only` for `group_id`,
    /// preferring an already-live candidate session for the group when one
    /// exists and falling back to this device's own cached local-only
    /// session (`DaemonState::local_retirement_session`) only when there
    /// are none -- identical to `process_group_via_obligations`'s zero-work
    /// pre-check guard (`convergence::engine`) and `run_hazard_recheck_pass`'s
    /// session choice (`convergence::engine_wrapper`), and for the same
    /// reason: retirement's own decision is driven entirely by this
    /// device's local DAG/file-index/disk state, so which session object
    /// runs it is never actually load-bearing (see `local_retirement_
    /// session`'s own doc comment) -- but `local_retirement_session`'s
    /// first-ever construction for a group triggers `NetmapChangeAuthenticator
    /// ::new` -> `validate_linked_history_best_effort`, which can transiently
    /// quarantine every OTHER already-connected session's authorization for
    /// this group if that validation briefly comes back `TrustUnavailable`/
    /// `Store(_)`. Because that session is cached per group per process,
    /// there is no later tick to self-heal from a quarantine triggered this
    /// way -- skipping the construction whenever a live candidate already
    /// exists avoids ever triggering that side effect in the overwhelmingly
    /// common case where it isn't needed at all.
    ///
    /// See that method's and `RetirementAttempt`'s own doc comments for
    /// what each outcome means to a caller tracking completion by
    /// generation.
    pub async fn reconcile_group(
        &self,
        group_id: &str,
    ) -> Result<RetirementAttempt, PeerSessionError> {
        let session = crate::hydration::candidate_sessions(&self.state, group_id)
            .into_iter()
            .min_by(|a, b| a.0.cmp(&b.0))
            .map(|(_, session)| session)
            .unwrap_or_else(|| self.state.local_retirement_session(group_id));
        session.retire_conflict_copies_only(group_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::collections::HashMap;
    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_peer_session::peer_session::PeerSyncSession;
    use yadorilink_peer_session::ports::{PeerBlockStream, PeerMessageChannel};
    use yadorilink_replica_domain::change::{Change, ChangeAuth, Op, PutOrigin};
    use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind};
    use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId, SyncPath};
    use yadorilink_root_authority::root_identity::VerifiedRoot;
    use yadorilink_transport::TransportError;

    const GROUP_A: &str = "group-a";
    const GROUP_B: &str = "group-b";

    /// A channel with nothing on the far end -- mirrors `convergence::
    /// engine`'s own test-only `NoopChannel`. Nothing in this test ever
    /// needs a real block fetch or reply.
    struct NoopChannel;

    #[async_trait::async_trait]
    impl PeerMessageChannel for NoopChannel {
        async fn send(&self, _payload: Vec<u8>) -> Result<(), TransportError> {
            Ok(())
        }
        fn try_send(&self, _payload: Vec<u8>) -> bool {
            true
        }
        async fn recv(&self) -> Option<Vec<u8>> {
            std::future::pending().await
        }
        async fn open_block_stream(&self) -> Result<Box<dyn PeerBlockStream>, TransportError> {
            Err(TransportError::ChannelClosed)
        }
        async fn accept_block_stream(&self) -> Option<Box<dyn PeerBlockStream>> {
            std::future::pending().await
        }
    }

    fn empty_version(mtime: i64) -> FileVersion {
        FileVersion::new(
            vec![],
            0,
            FileMeta {
                mtime_unix_nanos: mtime,
                unix_mode: None,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        )
    }

    /// `GROUP_A` is fully adopted (link + verified root + startup-ready),
    /// with one already-live candidate `PeerSyncSession` registered for it
    /// -- standing in for a real peer that connected before this tick, the
    /// precondition `reconcile_group`'s guard needs in order to avoid ever
    /// constructing `local_retirement_session` at all.
    ///
    /// `GROUP_B` is linked but otherwise unrelated to the call under test,
    /// with its own already-live candidate session (standing in for "some
    /// OTHER already-connected session") and one retained change authored
    /// by a device id this process can never resolve a signing key for --
    /// not the local device, no netmap pin, no `signing_keys.json` pin.
    /// `NetmapChangeAuthenticator::signing_key` therefore returns `None`
    /// for it, so re-validating `GROUP_B`'s retained history deterministically
    /// hits `AuthenticatedHistoryError::TrustUnavailable` -- the exact
    /// transient condition `local_retirement_session`'s and
    /// `reconcile_group`'s own doc comments describe, forced here instead
    /// of relying on a flaky real SQLite/trust-material timing window.
    async fn build_state_with_two_linked_groups() -> (
        Arc<DaemonState>,
        tempfile::TempDir,
        tempfile::TempDir,
        Arc<PeerSyncSession>,
        Arc<PeerSyncSession>,
    ) {
        let root_a_dir = tempfile::tempdir().unwrap();
        let root_b_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let root_a = root_a_dir.path().canonicalize().unwrap();
        let root_b = root_b_dir.path().canonicalize().unwrap();
        let replica_coordinator =
            Arc::new(crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap());
        let block_store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());

        replica_coordinator.link_repository().add_link(&root_a.to_string_lossy(), GROUP_A).unwrap();
        VerifiedRoot::open(&root_a, GROUP_A, replica_coordinator.as_ref()).unwrap();
        let generation = replica_coordinator.startup_readiness().begin_group_startup(GROUP_A);
        replica_coordinator.startup_readiness().mark_group_ready(GROUP_A, generation);

        replica_coordinator.link_repository().add_link(&root_b.to_string_lossy(), GROUP_B).unwrap();

        let build =
            DaemonState::build("device-local".to_string(), replica_coordinator, block_store);
        let state = build.state;
        state.test_root_commit_authorities.lock().unwrap().insert(
            GROUP_A.to_string(),
            Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
        );

        let key = SigningKey::from_bytes(&[77u8; 32]);
        let version = empty_version(1_700_002_000);
        let bystander_change = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            DeviceId("device-untrusted-for-hazard-test".to_string()),
            FolderGroupId(GROUP_B.to_string()),
            vec![Op::Put {
                path: SyncPath("bystander.txt".to_string()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key,
        );
        state
            .replica_coordinator
            .change_history_repository()
            .dag_admit_change_with_versions(&bystander_change, std::slice::from_ref(&version), true)
            .unwrap();

        let deps_a = crate::peer_orchestrator::peer_sync_session_deps(&state);
        let session_a = PeerSyncSession::new_with_dependencies(
            Arc::new(NoopChannel),
            "device-local".to_string(),
            "device-peer-a".to_string(),
            state.replica_coordinator.clone(),
            Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
                state.block_store.clone(),
            )),
            vec![GROUP_A.to_string()],
            HashMap::from([(GROUP_A.to_string(), root_a.clone())]),
            Some(state.forward_tx.clone()),
            deps_a,
        );
        let session_a_handle = session_a.clone();
        state.peers.register_session("device-peer-a".to_string(), session_a);

        let deps_b = crate::peer_orchestrator::peer_sync_session_deps(&state);
        let session_b = PeerSyncSession::new_with_dependencies(
            Arc::new(NoopChannel),
            "device-local".to_string(),
            "device-peer-b".to_string(),
            state.replica_coordinator.clone(),
            Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
                state.block_store.clone(),
            )),
            vec![GROUP_B.to_string()],
            HashMap::from([(GROUP_B.to_string(), root_b.clone())]),
            Some(state.forward_tx.clone()),
            deps_b,
        );
        let session_b_handle = session_b.clone();
        state.peers.register_session("device-peer-b".to_string(), session_b);

        // `peer_orchestrator::peer_sync_session_deps` itself constructs a
        // fresh `NetmapChangeAuthenticator` on EVERY call (see its own doc
        // comment/field), independent of `local_retirement_session` -- so
        // each of the two `peer_sync_session_deps` calls above already ran
        // a full `validate_linked_history_best_effort` sweep as an
        // ordinary, expected side effect of constructing a session at all.
        // In a real daemon that sweep's `restore_group_sessions_if_
        // currently_authorized` re-grants a session only when the current
        // netmap says it's still a writer; this bare unit-test harness
        // wires no netmap "writer" membership at all, so that re-grant
        // never fires and a session built before a LATER session merely
        // ends up revoked of its own group as an artifact of setup
        // ordering -- nothing to do with the hazard this test exercises.
        // Re-grant both sessions their own group explicitly (the same
        // stand-in `convergence::engine`'s own
        // `a_settled_path_is_never_handed_to_a_second_candidate_in_the_
        // same_tick` test uses for an identical harness gap) so the test
        // starts from "both already-connected sessions are authorized",
        // and the one assertion that matters is entirely about what
        // `reconcile_group` itself does next.
        session_a_handle.grant_group(GROUP_A);
        session_b_handle.grant_group(GROUP_B);

        (state, root_a_dir, root_b_dir, session_a_handle, session_b_handle)
    }

    /// The hazard this guards against: `reconcile_group`'s target
    /// (`GROUP_A`) already has a live candidate session, so this call must
    /// never construct `local_retirement_session` at all -- and therefore
    /// must never trigger `NetmapChangeAuthenticator::new`'s linked-history
    /// re-validation sweep, which would hit `GROUP_B`'s unresolvable-author
    /// change and quarantine `GROUP_B`'s own already-connected session even
    /// though nothing about `GROUP_B` was ever asked for.
    ///
    /// Before the fix, `reconcile_group` unconditionally called
    /// `local_retirement_session`, so `GROUP_B`'s live session lost its
    /// authorization as a side effect of reconciling a completely
    /// different group -- confirmed RED against the pre-fix body (`let
    /// session = self.state.local_retirement_session(group_id);`), where
    /// this assertion fails because `bystander_session.shares_group
    /// (GROUP_B)` becomes `false`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reconcile_group_never_quarantines_an_unrelated_groups_live_session() {
        let (state, _root_a_dir, _root_b_dir, session_a, bystander_session) =
            build_state_with_two_linked_groups().await;

        assert!(
            session_a.shares_group(GROUP_A),
            "sanity: group-a's own live candidate session starts authorized"
        );
        assert!(
            bystander_session.shares_group(GROUP_B),
            "sanity: group-b's session starts authorized"
        );

        let service = ConvergenceRetirementService::new(state.clone());
        service.reconcile_group(GROUP_A).await.expect("reconciling group-a must not itself error");

        assert!(
            bystander_session.shares_group(GROUP_B),
            "reconciling group-a must never quarantine group-b's own already-connected \
             session -- group-a already had a live candidate session, so `local_retirement_\
             session` (whose first-ever construction re-validates EVERY linked group's \
             retained history) must never have been constructed at all"
        );
    }
}

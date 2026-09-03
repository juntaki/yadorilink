//! `LinkStatusReadPort` backed by `DaemonState` -- moved verbatim (in
//! logic; only the output type changed, from the IPC-proto `LinkStatus` to
//! the plain `LinkStatusView`) from `control_socket::list_link_statuses`.
//! Still holds `Arc<DaemonState>` (a deliberate strangler step -- see
//! `crate::queries::link_status`'s own doc comment); nothing outside this
//! file and `adapters/query/` is allowed to depend on `DaemonState` for
//! this read model.

use std::sync::Arc;

#[cfg(windows)]
use yadorilink_replica_domain::file::RecordKind;
#[cfg(windows)]
use yadorilink_sync_sqlite::MaterializationStatePort;

use crate::daemon_state::DaemonState;
use crate::queries::link_status::{
    DegradedLinkView, FetchAvailability, HeldFileView, LinkStatusReadPort, LinkStatusView,
    LinkTransferView, LocalStorageState,
};
use crate::replica_coordinator::ReplicaCoordinator;

pub(crate) struct DaemonLinkStatusReader {
    state: Arc<DaemonState>,
}

impl DaemonLinkStatusReader {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl LinkStatusReadPort for DaemonLinkStatusReader {
    fn list_links(&self) -> Result<Vec<LinkStatusView>, crate::sync_error::SyncError> {
        let state = &self.state;
        let links = state.replica_coordinator.link_repository().list_links()?;
        let mut out = Vec::with_capacity(links.len());
        for link in links {
            let files =
                state.replica_coordinator.file_index_repository().list_files(&link.group_id)?;
            // Same targeted query `FileHistoryQueryService::list_conflicts` reads
            // from (not a predicate re-applied to `files` above, which -- unlike
            // this query -- doesn't filter tombstones), so the two can never
            // disagree about which paths count.
            let conflict_count = state
                .replica_coordinator
                .file_index_repository()
                .list_live_conflict_copies(&link.group_id)?
                .len() as u64;
            let materialization = state
                .replica_coordinator
                .materialization_state_repository()
                .materialization_counts(&link.group_id)?;
            // NOT `?`: this resolver refuses an ambiguous group, and propagating
            // that would fail the ENTIRE status listing -- for every group on the
            // device, not just the offending one. Status is the surface that MAKES
            // the ambiguity visible (see `ambiguous_local_paths` below), so letting
            // it be the thing an ambiguous group breaks would hide the refusal
            // behind a bare error string and leave the user with no way to see which
            // folders collided. It would also turn a per-GROUP refusal into a
            // per-DEVICE one, which is exactly what this invariant must never do.
            //
            // `false` is the safe default and costs nothing here: it only classifies
            // symlinks as "skipped" for a cosmetic count, and an ambiguous group is
            // refusing to sync anyway, so there is no materialization for it to be
            // wrong about.
            let windows_symlink_opt_in = state
                .replica_coordinator
                .link_repository()
                .windows_symlink_opt_in_for_group(&link.group_id)
                .unwrap_or_else(|e| {
                    tracing::warn!(
                        group_id = %link.group_id,
                        error = %e,
                        "cannot read this group's symlink policy for status; reporting the default"
                    );
                    false
                });
            let mut held_files = Vec::new();
            let mut skipped_symlink_count = 0u64;
            for file in files.iter().filter(|f| !f.deleted) {
                if let Some(held) = state
                    .replica_coordinator
                    .materialization_state_repository()
                    .get_held_state(&link.group_id, &file.path)?
                {
                    held_files.push(HeldFileView {
                        path: file.path.clone(),
                        reason: held.reason,
                        held_since_unix_nanos: held.since_unix_nanos,
                    });
                }
                if is_skipped_windows_symlink(
                    &state.replica_coordinator,
                    &link.group_id,
                    &file.path,
                    windows_symlink_opt_in,
                )? {
                    skipped_symlink_count += 1;
                }
            }
            // Independent of `paused` (a link can be paused and/or degraded
            // at once -- see `DegradedLinkInfo`'s doc comment).
            let degraded = state
                .degraded_link_info(&link.local_path)
                .map(|info| DegradedLinkView { reason: info.reason });
            // This link's active-transfer rollup, if any is currently in
            // flight.
            let transfer =
                state.telemetry.link_transfer_rollup(&link.group_id).map(|r| LinkTransferView {
                    bytes_done: r.bytes_done,
                    bytes_total: r.bytes_total,
                    blocks_done: r.blocks_done,
                    blocks_total: r.blocks_total,
                    eta_seconds: r.eta_seconds,
                });
            let durability_status = state.group_durability_status(&link.group_id);
            let fully_hydrated_locally =
                materialization.placeholder == 0 && materialization.hydrating == 0;
            let local_storage_state = match link.materialization_policy {
                yadorilink_replica_domain::session_state::MaterializationPolicy::Eager => {
                    if fully_hydrated_locally {
                        LocalStorageState::FullCopy
                    } else {
                        LocalStorageState::PartiallyMaterialized
                    }
                }
                yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand => {
                    LocalStorageState::OnDemand
                }
            };
            // Local certainty comes first, unconditionally: whether THIS
            // device's own disk state is legible has nothing to do with the
            // daemon-wide "cannot currently confirm PEER custody" facts
            // `daemon_wide_evidence_uncertain` checks -- gating it behind
            // that check (an earlier version of this derivation did) would
            // report `Unknown` for content this daemon already knows for
            // certain is available (M4 Pass 2 Codex review #2 finding #5).
            let fetch_availability = if fully_hydrated_locally {
                FetchAvailability::AvailableNow
            } else if state.daemon_wide_evidence_uncertain(&link.group_id) {
                FetchAvailability::Unknown
            } else if state.fetch_available_via_confirmed_peer(&link.group_id) {
                FetchAvailability::AvailableNow
            } else {
                FetchAvailability::UnavailableNow
            };
            // Every live folder registered for this group. More than one is the
            // refusing state; the paths ARE the remedy, since unlinking is keyed by
            // path. An unreadable link table surfaces as "not ambiguous" rather than
            // failing the whole status listing: status must keep rendering, and the
            // group is already refusing to sync on the paths that matter.
            let ambiguous_local_paths = state
                .replica_coordinator
                .link_repository()
                .live_link_paths_for_group(&link.group_id)
                .unwrap_or_else(|e| {
                    tracing::warn!(
                        group_id = %link.group_id,
                        error = %e,
                        "cannot read this group's links to report whether it is linked twice"
                    );
                    Vec::new()
                });
            out.push(LinkStatusView {
                local_path: link.local_path.clone(),
                group_id: link.group_id.clone(),
                paused: link.paused,
                conflict_count,
                materialization_policy: link.materialization_policy.as_db_str().to_string(),
                hydrated_count: materialization.hydrated,
                placeholder_count: materialization.placeholder,
                hydrating_count: materialization.hydrating,
                held_files,
                skipped_symlink_count,
                degraded,
                transfer,
                durability_status,
                // Surfaces the same staleness gate admission and local emission
                // fail closed on, so a group whose policy this daemon distrusts
                // (own verification failure or coordinator-flagged invalid) is
                // distinguishable in status from a healthy one.
                policy_stale: state.is_group_policy_stale(&link.group_id),
                local_storage_state,
                fetch_availability,
                ambiguous_local_paths,
                full_replica_device_ids: state.full_replica_devices_for_group(&link.group_id),
            });
        }
        Ok(out)
    }
}

/// A skipped-on-materialize Windows symlink (real POSIX symlinks
/// materialize via the ordinary atomic temp-path-then-rename path,
/// `chunker::materialize_symlink`) -- moved verbatim, including its
/// platform split, from `control_socket::is_skipped_windows_symlink`.
#[cfg(windows)]
fn is_skipped_windows_symlink(
    state: &ReplicaCoordinator,
    group_id: &str,
    path: &str,
    windows_symlink_opt_in: bool,
) -> Result<bool, crate::sync_error::SyncError> {
    if windows_symlink_opt_in {
        return Ok(false);
    }
    Ok(state.get_record_kind(group_id, path)?.is_some_and(|kind| kind == RecordKind::Symlink))
}

#[cfg(not(windows))]
fn is_skipped_windows_symlink(
    _state: &ReplicaCoordinator,
    _group_id: &str,
    _path: &str,
    _windows_symlink_opt_in: bool,
) -> Result<bool, crate::sync_error::SyncError> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
    use yadorilink_replica_domain::session_state::{MaterializationPolicy, MaterializationState};

    pub(super) const GROUP: &str = "group-1";
    pub(super) const PATH: &str = "/tmp/photos";

    pub(super) fn test_state() -> Arc<DaemonState> {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        DaemonState::new("device-a".into(), sync_state, store)
    }

    /// Indexes one current file record. `upsert_file` mimics a LOCAL write
    /// (this device authoring new content), so it defaults to `Hydrated`
    /// -- explicitly overridden to `Placeholder` when `hydrated` is
    /// `false`, to simulate a record synced in from a peer whose content
    /// hasn't been fetched yet.
    pub(super) fn upsert_file(state: &DaemonState, path: &str, hydrated: bool) {
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: path.into(),
                    size: 4,
                    mtime_unix_nanos: 0,
                    blocks: vec![BlockInfo { hash: vec![1u8; 32], offset: 0, size: 4 }],
                    deleted: false,
                },
                &permit,
            )
            .unwrap();
        let target = if hydrated {
            MaterializationState::Hydrated
        } else {
            MaterializationState::Placeholder
        };
        state
            .replica_coordinator
            .materialization_state_repository()
            .set_materialization_state(GROUP, path, target, &permit)
            .unwrap();
    }

    /// The group's REAL current durability-root digest -- confirmation
    /// records must carry this exact digest to read as fresh, per
    /// `DaemonState::fetch_available_via_confirmed_peer`'s content-binding
    /// check, so tests that plant a confirmation directly (rather than
    /// through a real peer round-trip) need the real value, not an
    /// arbitrary placeholder.
    pub(super) fn real_digest(state: &DaemonState) -> [u8; 32] {
        state.durability_roots_for_group(GROUP).unwrap().digest
    }

    fn reader_for(state: Arc<DaemonState>) -> DaemonLinkStatusReader {
        DaemonLinkStatusReader::new(state)
    }

    /// An eager link, every current file already hydrated locally, reports
    /// `FullCopy` -- never derived from `materialization_policy` alone.
    #[tokio::test]
    async fn eager_link_fully_hydrated_is_full_copy() {
        let state = test_state();
        state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
        upsert_file(&state, "a.bin", true);

        let views = reader_for(state).list_links().unwrap();
        assert_eq!(views[0].local_storage_state, LocalStorageState::FullCopy);
        assert_eq!(views[0].fetch_availability, FetchAvailability::AvailableNow);
    }

    /// An eager link still catching up (a placeholder present) must NOT
    /// report `FullCopy` -- the exact conflation M4 Pass 2 fixes (the
    /// prior CLI-side reconstruction only distinguished on-demand from
    /// "everything else").
    #[tokio::test]
    async fn eager_link_still_catching_up_is_partially_materialized() {
        let state = test_state();
        state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
        upsert_file(&state, "a.bin", true);
        upsert_file(&state, "b.bin", false);

        let views = reader_for(state).list_links().unwrap();
        assert_eq!(views[0].local_storage_state, LocalStorageState::PartiallyMaterialized);
    }

    /// An on-demand link reports `OnDemand` regardless of hydration state
    /// -- placeholders are its normal steady state, not "catching up."
    #[tokio::test]
    async fn on_demand_link_is_on_demand_regardless_of_hydration() {
        let state = test_state();
        state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
        state
            .replica_coordinator
            .link_repository()
            .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
            .unwrap();
        upsert_file(&state, "a.bin", false);

        let views = reader_for(state).list_links().unwrap();
        assert_eq!(views[0].local_storage_state, LocalStorageState::OnDemand);
    }

    /// A file not yet hydrated locally, with NO reachable full-replica
    /// peer, is `UnavailableNow` -- not merely "durability unknown," a
    /// distinct claim.
    #[tokio::test]
    async fn missing_content_with_no_reachable_peer_is_unavailable_now() {
        let state = test_state();
        state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
        state
            .replica_coordinator
            .link_repository()
            .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
            .unwrap();
        upsert_file(&state, "a.bin", false);

        let views = reader_for(state).list_links().unwrap();
        assert_eq!(views[0].fetch_availability, FetchAvailability::UnavailableNow);
    }

    /// A file not yet hydrated locally, but a peer holds a REAL,
    /// content-confirmed custody record for this group (not merely a
    /// netmap "declared full-replica" claim -- see
    /// `DaemonState::fetch_available_via_confirmed_peer`'s own doc comment
    /// for why content-blind netmap metadata alone isn't sufficient
    /// evidence, per M4 Pass 2 Codex review #2 finding #1) AND is
    /// currently reachable, is `AvailableNow`.
    #[tokio::test]
    async fn missing_content_with_a_confirmed_reachable_peer_is_available_now() {
        let state = test_state();
        state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
        state
            .replica_coordinator
            .link_repository()
            .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
            .unwrap();
        upsert_file(&state, "a.bin", false);
        state.peers.set_reachability(
            "peer-b".to_string(),
            crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct),
        );
        let digest = real_digest(&state);
        state.record_custody_confirmation_outcome(
            GROUP,
            crate::daemon_state::CustodyConfirmationOutcome::Confirmed {
                peer_device_id: Some("peer-b".into()),
                digest,
            },
            state.membership_generation(),
            0,
        );

        let views = reader_for(state).list_links().unwrap();
        assert_eq!(views[0].fetch_availability, FetchAvailability::AvailableNow);
    }

    /// A REAL content-confirmed custody record whose confirming peer is
    /// NOT currently reachable must not be trusted as `AvailableNow` -- the
    /// confirmation proves the peer held the content as of its own
    /// staleness window, not that it can be reached right now.
    #[tokio::test]
    async fn confirmed_peer_that_is_not_currently_reachable_is_unavailable_now() {
        let state = test_state();
        state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
        state
            .replica_coordinator
            .link_repository()
            .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
            .unwrap();
        upsert_file(&state, "a.bin", false);
        // No reachability recorded for peer-b at all.
        let digest = real_digest(&state);
        state.record_custody_confirmation_outcome(
            GROUP,
            crate::daemon_state::CustodyConfirmationOutcome::Confirmed {
                peer_device_id: Some("peer-b".into()),
                digest,
            },
            state.membership_generation(),
            0,
        );

        let views = reader_for(state).list_links().unwrap();
        assert_eq!(views[0].fetch_availability, FetchAvailability::UnavailableNow);
    }

    /// A netmap-declared full-replica writer that is reachable, but has
    /// NEVER been content-confirmed, must not be trusted as `AvailableNow`
    /// -- this is the exact gap M4 Pass 2 Codex review #2 finding #1
    /// closed: declared role + reachability alone is not content proof.
    #[tokio::test]
    async fn declared_full_replica_without_content_confirmation_is_unavailable_now() {
        let state = test_state();
        state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
        state
            .replica_coordinator
            .link_repository()
            .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
            .unwrap();
        upsert_file(&state, "a.bin", false);
        state.set_peer_group_writer("peer-b", GROUP, true);
        state.set_peer_group_full_replica("peer-b", GROUP, true);
        state.peers.set_reachability(
            "peer-b".to_string(),
            crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct),
        );

        let views = reader_for(state).list_links().unwrap();
        assert_eq!(
            views[0].fetch_availability,
            FetchAvailability::UnavailableNow,
            "a declared-but-never-confirmed full-replica peer must not make AvailableNow"
        );
    }

    /// The exact HIGH-severity gap M4 Pass 2 Codex review #2's follow-up
    /// round found: a peer confirms the group's root set, then a NEW file
    /// arrives locally as a placeholder (changing the group's real
    /// durability-root set) WITHOUT bumping `membership_generation`
    /// (content/root-set changes never do -- only peer authorization
    /// changes do). The confirmation's own digest no longer matches the
    /// group's current root digest, so it must stop counting as fresh
    /// evidence, even though its generation binding alone would still
    /// consider it valid.
    #[tokio::test]
    async fn confirmation_predating_a_new_placeholder_is_unavailable_now() {
        let state = test_state();
        state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
        state
            .replica_coordinator
            .link_repository()
            .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
            .unwrap();
        upsert_file(&state, "a.bin", true);
        state.peers.set_reachability(
            "peer-b".to_string(),
            crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct),
        );
        // Confirmed while the root set was just {a.bin}.
        let digest_before = real_digest(&state);
        state.record_custody_confirmation_outcome(
            GROUP,
            crate::daemon_state::CustodyConfirmationOutcome::Confirmed {
                peer_device_id: Some("peer-b".into()),
                digest: digest_before,
            },
            state.membership_generation(),
            0,
        );

        // A new file arrives as a placeholder -- the root set changes, but
        // membership_generation does not.
        let generation_before = state.membership_generation();
        upsert_file(&state, "b.bin", false);
        assert_eq!(
            state.membership_generation(),
            generation_before,
            "sanity check: a content change alone must not bump membership_generation"
        );
        assert_ne!(
            real_digest(&state),
            digest_before,
            "sanity check: the root digest must actually change when a new file is indexed"
        );

        let views = reader_for(state).list_links().unwrap();
        assert_eq!(
            views[0].fetch_availability,
            FetchAvailability::UnavailableNow,
            "a confirmation whose digest predates a new placeholder must not read as AvailableNow"
        );
    }

    /// A group latched `Unknown` (a `--force` override bypassed
    /// the handoff gate) must ALSO report `fetch_availability: Unknown`,
    /// even with an otherwise-fresh confirmed+reachable peer -- M4 Pass 2
    /// Codex review #2 finding #2: `daemon_wide_evidence_uncertain` had
    /// omitted this per-group latch, so a group could show `durability
    /// unknown` while `fetch_availability` still read `AvailableNow`.
    #[tokio::test]
    async fn latched_unknown_group_reports_fetch_availability_unknown() {
        let state = test_state();
        state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
        state
            .replica_coordinator
            .link_repository()
            .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
            .unwrap();
        upsert_file(&state, "a.bin", false);
        state.peers.set_reachability(
            "peer-b".to_string(),
            crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct),
        );
        let digest = real_digest(&state);
        state.record_custody_confirmation_outcome(
            GROUP,
            crate::daemon_state::CustodyConfirmationOutcome::Confirmed {
                peer_device_id: Some("peer-b".into()),
                digest,
            },
            state.membership_generation(),
            0,
        );
        state.latch_group_durability_unknown(GROUP).unwrap();

        let views = reader_for(state).list_links().unwrap();
        assert_eq!(views[0].fetch_availability, FetchAvailability::Unknown);
    }

    /// Local certainty must win outright: every current file already
    /// hydrated locally is `AvailableNow` even while this group is
    /// latched `Unknown` -- daemon-wide "cannot confirm PEER
    /// custody" uncertainty has nothing to do with whether THIS device's
    /// own disk state is legible (M4 Pass 2 Codex review #2 finding #5).
    #[tokio::test]
    async fn fully_hydrated_locally_is_available_now_even_when_latched_unknown() {
        let state = test_state();
        state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
        upsert_file(&state, "a.bin", true);
        state.latch_group_durability_unknown(GROUP).unwrap();

        let views = reader_for(state).list_links().unwrap();
        assert_eq!(views[0].fetch_availability, FetchAvailability::AvailableNow);
    }

    /// A REACHABLE peer that is NOT a full-replica writer for this group
    /// proves nothing about fetchability -- `FetchAvailability` must not
    /// degrade into a bare alias for `PeerReachability`.
    #[tokio::test]
    async fn a_reachable_peer_that_is_not_a_full_replica_does_not_count() {
        let state = test_state();
        state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
        state
            .replica_coordinator
            .link_repository()
            .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
            .unwrap();
        upsert_file(&state, "a.bin", false);
        // Reachable, but never declared a full replica or writer for this
        // group.
        state.peers.set_reachability(
            "peer-b".to_string(),
            crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct),
        );

        let views = reader_for(state).list_links().unwrap();
        assert_eq!(
            views[0].fetch_availability,
            FetchAvailability::UnavailableNow,
            "a reachable non-full-replica peer must not make fetch_availability AvailableNow"
        );
    }

    /// A group whose policy is marked stale must report `Unknown`, not
    /// `UnavailableNow` -- "cannot currently confirm" is a distinct claim
    /// from "confirmed not obtainable," and reuses the SAME daemon-wide
    /// uncertainty signal `durability_status` itself fails closed on.
    #[tokio::test]
    async fn policy_stale_group_reports_fetch_availability_unknown() {
        let state = test_state();
        state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
        upsert_file(&state, "a.bin", false);
        state.mark_group_policy_stale(GROUP);

        let views = reader_for(state).list_links().unwrap();
        assert_eq!(views[0].fetch_availability, FetchAvailability::Unknown);
    }
}

/// M4 Pass 6: the full acceptance matrix -- 12 named scenarios (A-L) the
/// directive requires, automated at this domain/read-model level. Each
/// test asserts the FULL cross-dimension tuple (durability_status,
/// local_storage_state, fetch_availability, and where relevant the peer
/// connection/relay facts) for its scenario, not just one field in
/// isolation -- the point of this matrix is proving the dimensions stay
/// correctly independent/correctly coupled exactly where each scenario
/// requires, not re-testing any single formula already covered above.
/// H (last safe-copy removal attempt -> backend rejects) and L (restart
/// with stale cached Protected -> no false green before revalidation) are
/// NOT duplicated here -- they're already covered by dedicated,
/// already-reviewed suites (`tests/unlink_and_removal_durability.rs`'s 10
/// tests and `control_socket.rs`'s `forced_unlink_latches_group_
/// durability_unknown`/friends for H; `daemon_state.rs`'s
/// `restart_never_shows_a_stale_healthy_status` for L) -- each doc
/// comment below says so explicitly rather than re-deriving weaker
/// coverage under a new name.
#[cfg(test)]
mod m4_acceptance_matrix {
    use super::tests::{real_digest, test_state, upsert_file, GROUP, PATH};
    use super::*;
    use crate::durability_service::GroupDurabilityStatus;
    use yadorilink_replica_domain::session_state::MaterializationPolicy;

    fn reader_for(state: std::sync::Arc<DaemonState>) -> DaemonLinkStatusReader {
        DaemonLinkStatusReader::new(state)
    }

    /// Scenario A: verified full replica online + On-Demand client online
    /// + direct route -> Protected / OnDemand / Available.
    #[tokio::test]
    async fn scenario_a_confirmed_direct_peer_is_protected_ondemand_available() {
        let state = test_state();
        state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
        state
            .replica_coordinator
            .link_repository()
            .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
            .unwrap();
        upsert_file(&state, "a.bin", false);
        // The confirming peer must genuinely hold the writer + full-replica
        // role -- a confirmation for a peer with no such role is a state
        // production can never reach (M4 Pass 6 Codex review follow-up
        // finding #1).
        state.set_peer_group_writer("nas", GROUP, true);
        state.set_peer_group_full_replica("nas", GROUP, true);
        state.peers.set_reachability(
            "nas".to_string(),
            crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct),
        );
        assert_eq!(
            state.peers.reachability("nas"),
            Some(crate::peer_registry::PeerReachability::Connected(
                crate::route::RouteKind::Direct
            )),
            "sanity check: this is genuinely a direct route"
        );
        let digest = real_digest(&state);
        state.record_custody_confirmation_outcome(
            GROUP,
            crate::daemon_state::CustodyConfirmationOutcome::Confirmed {
                peer_device_id: Some("nas".into()),
                digest,
            },
            state.membership_generation(),
            0,
        );

        let views = reader_for(state).list_links().unwrap();
        assert_eq!(views[0].durability_status, GroupDurabilityStatus::Protected, "A: Protected");
        assert_eq!(views[0].local_storage_state, LocalStorageState::OnDemand, "A: OnDemand");
        assert_eq!(views[0].fetch_availability, FetchAvailability::AvailableNow, "A: Available");
        assert_eq!(
            views[0].full_replica_device_ids,
            vec!["nas".to_string()],
            "A: the confirmed peer's real full-replica role is reflected in the read model"
        );
    }

    /// Scenario B: identical to A, but the confirming peer is reachable
    /// ONLY via relay -- still Protected/OnDemand/Available (the peer
    /// round-trip that produced the confirmation already succeeded
    /// through whatever route was live at confirmation time; content
    /// confirmation and current reachability are route-agnostic by
    /// design -- `fetch_available_via_confirmed_peer` calls `is_connected()`,
    /// which is true for `Connected(Direct)` and `Connected(Relay)` alike).
    /// Relay routing must NEVER be read as ITSELF implying durability --
    /// pinned by scenario I below (a relay-capable, non-full-replica peer
    /// has zero effect on durability_status).
    #[tokio::test]
    async fn scenario_b_confirmed_relay_only_peer_is_still_protected_ondemand_available() {
        let state = test_state();
        state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
        state
            .replica_coordinator
            .link_repository()
            .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
            .unwrap();
        upsert_file(&state, "a.bin", false);
        state.set_peer_group_writer("nas", GROUP, true);
        state.set_peer_group_full_replica("nas", GROUP, true);
        state.peers.set_reachability(
            "nas".to_string(),
            crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Relay),
        );
        // Sanity check the setup is genuinely a RELAY route (proves this
        // test isn't accidentally identical to A's direct-route setup --
        // M4 Pass 6 Codex review follow-up finding #3).
        assert_eq!(
            state.peers.reachability("nas"),
            Some(crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Relay)),
            "sanity check: this is genuinely a relay-only route, not direct"
        );
        let digest = real_digest(&state);
        state.record_custody_confirmation_outcome(
            GROUP,
            crate::daemon_state::CustodyConfirmationOutcome::Confirmed {
                peer_device_id: Some("nas".into()),
                digest,
            },
            state.membership_generation(),
            0,
        );

        let views = reader_for(state).list_links().unwrap();
        assert_eq!(views[0].durability_status, GroupDurabilityStatus::Protected, "B: Protected");
        assert_eq!(views[0].local_storage_state, LocalStorageState::OnDemand, "B: OnDemand");
        assert_eq!(
            views[0].full_replica_device_ids,
            vec!["nas".to_string()],
            "B: the confirmed peer's real full-replica role is reflected in the read model"
        );
        assert_eq!(
            views[0].fetch_availability,
            FetchAvailability::AvailableNow,
            "B: Available via relay-connected peer"
        );
    }

    /// Scenario C: the confirming peer is now UNREACHABLE, but the
    /// confirmation itself is still fresh (within the staleness bound,
    /// current membership generation, matching root digest) -- durability
    /// stays whatever the still-valid evidence justifies (Protected),
    /// while fetch_availability is separately, honestly `UnavailableNow`.
    /// This is the exact `Durability != Connectivity` pairing the M4
    /// directive singles out: "protected but currently unreachable" must
    /// never read as data loss.
    #[tokio::test]
    async fn scenario_c_confirmed_but_now_unreachable_peer_stays_protected_but_unavailable() {
        let state = test_state();
        state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
        state
            .replica_coordinator
            .link_repository()
            .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
            .unwrap();
        upsert_file(&state, "a.bin", false);
        state.set_peer_group_writer("nas", GROUP, true);
        state.set_peer_group_full_replica("nas", GROUP, true);
        let digest = real_digest(&state);
        state.record_custody_confirmation_outcome(
            GROUP,
            crate::daemon_state::CustodyConfirmationOutcome::Confirmed {
                peer_device_id: Some("nas".into()),
                digest,
            },
            state.membership_generation(),
            0,
        );
        // The peer has since gone offline -- no reachability recorded at
        // all (equally valid: an explicit Unreachable would produce the
        // same fetch_availability outcome).

        let views = reader_for(state).list_links().unwrap();
        assert_eq!(
            views[0].durability_status,
            GroupDurabilityStatus::Protected,
            "C: durability reflects the still-valid confirmation, not current reachability"
        );
        assert_eq!(
            views[0].fetch_availability,
            FetchAvailability::UnavailableNow,
            "C: cannot fetch right now -- a separate, honest claim from durability"
        );
    }

    /// Scenario D: no verified required custody -- structurally, no other
    /// full-replica peer is configured at all -- even though SOME peer is
    /// reachable. AtRisk despite connectivity: reachability
    /// of a peer that isn't even a full-replica writer proves nothing.
    #[tokio::test]
    async fn scenario_d_no_full_replica_peer_configured_is_at_risk_despite_a_reachable_peer() {
        let state = test_state();
        state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
        // NOT locally hydrated, so `fetch_availability` genuinely exercises
        // the peer-dependent path too, not just local content.
        upsert_file(&state, "a.bin", false);
        // "peer" is reachable but never declared writer/full-replica for
        // this group at all.
        state.peers.set_reachability(
            "peer".to_string(),
            crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct),
        );
        state.refresh_custody_confirmation(GROUP).await; // establishes ever_confirmation_swept

        let views = reader_for(state).list_links().unwrap();
        assert_eq!(
            views[0].durability_status,
            GroupDurabilityStatus::AtRisk,
            "D: AtRisk -- structurally no full-replica peer exists, connectivity is irrelevant"
        );
        assert_eq!(
            views[0].fetch_availability,
            FetchAvailability::UnavailableNow,
            "D: connectivity to a non-role peer does not grant fetch access either"
        );
    }

    /// Scenario E: a full-replica peer IS configured and reachable, but
    /// custody has never actually been confirmed -- Unknown despite
    /// connectivity (distinct from D: here the ROLE is real, just
    /// unconfirmed; in D there is no role at all).
    ///
    /// This device's OWN policy is On-Demand (not eager) so the local
    /// "still catching up" `Protecting` branch never fires here -- if this
    /// device were itself an eager full replica with a placeholder still
    /// pending, the correct/distinct answer would be `Protecting`
    /// (scenario F), not `Unknown`; using an on-demand local policy is
    /// what genuinely isolates "peer configured+reachable+unconfirmed" as
    /// the ONLY fact in play.
    #[tokio::test]
    async fn scenario_e_configured_but_unconfirmed_peer_is_unknown_despite_connectivity() {
        let state = test_state();
        state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
        state
            .replica_coordinator
            .link_repository()
            .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
            .unwrap();
        // NOT locally hydrated, so `fetch_availability` genuinely exercises
        // the peer-dependent path too, not just local content.
        upsert_file(&state, "a.bin", false);
        state.set_peer_group_writer("nas", GROUP, true);
        state.set_peer_group_full_replica("nas", GROUP, true);
        state.peers.set_reachability(
            "nas".to_string(),
            crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct),
        );
        // Sweep runs, but never actually confirms (no real custody
        // round-trip infrastructure in this unit test -- the point is
        // "declared, reachable, never confirmed").
        state.refresh_custody_confirmation(GROUP).await;

        let views = reader_for(state).list_links().unwrap();
        assert_eq!(
            views[0].durability_status,
            GroupDurabilityStatus::Unknown,
            "E: Unknown -- a real role exists but was never actually confirmed"
        );
        assert_eq!(
            views[0].fetch_availability,
            FetchAvailability::UnavailableNow,
            "E: reachability to a never-confirmed peer does not grant fetch access either"
        );
    }

    /// Scenario F: this device itself is a full replica still catching up
    /// (a "protection operation running") -> Protecting.
    #[tokio::test]
    async fn scenario_f_local_full_replica_still_catching_up_is_protecting() {
        let state = test_state();
        state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
        // Eager (the default materialization policy) + a peer full
        // replica configured (so the structural AtRisk check doesn't
        // preempt Protecting) + still-partial local hydration.
        state.set_peer_group_writer("nas", GROUP, true);
        state.set_peer_group_full_replica("nas", GROUP, true);
        upsert_file(&state, "a.bin", false);
        state.refresh_custody_confirmation(GROUP).await;

        let views = reader_for(state).list_links().unwrap();
        assert_eq!(
            views[0].durability_status,
            GroupDurabilityStatus::Protecting,
            "F: Protecting -- this device is still becoming a full replica"
        );
    }

    /// Scenario G: this device holds a full local copy, but the group's
    /// durability policy is otherwise insufficient (no OTHER full-replica
    /// peer is configured/confirmed at all) -- must NOT infer stronger
    /// group protection than the policy actually proves. This is the
    /// exact conflation M4 Pass 1 fixed: `LocalStorageState::FullCopy`
    /// (a true statement about THIS device) must not leak into
    /// `durability_status` (a claim about the GROUP).
    #[tokio::test]
    async fn scenario_g_local_full_copy_alone_does_not_imply_group_protection() {
        let state = test_state();
        state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
        upsert_file(&state, "a.bin", true); // fully hydrated locally
        state.refresh_custody_confirmation(GROUP).await; // no peer -> not confirmed

        let views = reader_for(state).list_links().unwrap();
        assert_eq!(
            views[0].local_storage_state,
            LocalStorageState::FullCopy,
            "G: this device genuinely does hold a full local copy"
        );
        assert_eq!(
            views[0].durability_status,
            GroupDurabilityStatus::AtRisk,
            "G: but group-wide protection is NOT inferred from local completeness alone"
        );
    }

    /// Scenario I: a relay ANCHOR (`RelayCapability::Capable` --
    /// independent of, and not to be confused with, `RouteKind::Relay`
    /// which describes a specific connection's path, not a peer's own
    /// declared capability) is available, but holds no storage role for
    /// this group at all (never declared writer/full-replica) --
    /// connectivity benefit only. Establishes a genuine Protected BASELINE
    /// first (a real confirmed full-replica peer), then adds the relay
    /// anchor and proves durability_status is unchanged -- proving "zero
    /// effect" against an established baseline, not merely re-observing
    /// the already-AtRisk default a group with zero peers at all
    /// would trivially show regardless (M4 Pass 6 Codex review follow-up
    /// finding #2).
    #[tokio::test]
    async fn scenario_i_relay_anchor_without_storage_role_has_zero_durability_effect() {
        let state = test_state();
        state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
        upsert_file(&state, "a.bin", false);
        state.set_peer_group_writer("nas", GROUP, true);
        state.set_peer_group_full_replica("nas", GROUP, true);
        state.peers.set_reachability(
            "nas".to_string(),
            crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct),
        );
        let digest = real_digest(&state);
        state.record_custody_confirmation_outcome(
            GROUP,
            crate::daemon_state::CustodyConfirmationOutcome::Confirmed {
                peer_device_id: Some("nas".into()),
                digest,
            },
            state.membership_generation(),
            0,
        );
        let baseline = reader_for(state.clone()).list_links().unwrap();
        assert_eq!(
            baseline[0].durability_status,
            GroupDurabilityStatus::Protected,
            "sanity check: a genuine Protected baseline is established before adding the anchor"
        );
        assert_eq!(
            baseline[0].fetch_availability,
            FetchAvailability::AvailableNow,
            "sanity check: a genuine AvailableNow baseline is established before adding the \
             anchor, so the post-anchor assertion below actually proves \"unchanged\", not \
             merely \"happens to also be AvailableNow\""
        );

        // Now add a relay ANCHOR (declared capability, not just a route
        // kind) with NO storage role for this group at all.
        state.replace_peer_netmap_metadata(
            "relay-anchor",
            None,
            &std::collections::HashSet::new(),
            &std::collections::HashSet::new(),
            true,
        );
        state.peers.set_reachability(
            "relay-anchor".to_string(),
            crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Relay),
        );
        assert_eq!(
            state.peer_relay_capability("relay-anchor"),
            crate::route::RelayCapability::Capable,
            "sanity check: the anchor's relay capability is genuinely declared"
        );

        let views = reader_for(state).list_links().unwrap();
        assert_eq!(
            views[0].durability_status,
            GroupDurabilityStatus::Protected,
            "I: adding a relay anchor with no storage role leaves the established Protected \
             baseline completely unchanged -- zero durability effect"
        );
        assert_eq!(
            views[0].fetch_availability,
            FetchAvailability::AvailableNow,
            "I: fetch availability is unaffected too -- it was already available via the \
             REAL storage peer \"nas\", and the relay anchor with no storage role provides \
             zero benefit for THIS group's content -- \"connectivity benefit only\" means it \
             not that it can serve this group's content"
        );
    }

    /// Scenario J: a confirmed full-replica peer is available, but its
    /// own relay CAPABILITY is disabled -- storage benefit only, and this
    /// must not gate or reduce durability/fetch_availability at all
    /// (`relay_capability` describes whether a peer can forward OTHER
    /// peers' traffic, not whether it holds this group's data).
    #[tokio::test]
    async fn scenario_j_full_replica_with_relay_disabled_still_provides_full_storage_benefit() {
        let state = test_state();
        state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
        state
            .replica_coordinator
            .link_repository()
            .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
            .unwrap();
        upsert_file(&state, "a.bin", false);
        state.set_peer_group_writer("nas", GROUP, true);
        state.set_peer_group_full_replica("nas", GROUP, true);
        state.peers.set_reachability(
            "nas".to_string(),
            crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct),
        );
        // relay_capable is never set for "nas" -- Disabled by default.
        let digest = real_digest(&state);
        state.record_custody_confirmation_outcome(
            GROUP,
            crate::daemon_state::CustodyConfirmationOutcome::Confirmed {
                peer_device_id: Some("nas".into()),
                digest,
            },
            state.membership_generation(),
            0,
        );

        assert_eq!(
            state.peer_relay_capability("nas"),
            crate::route::RelayCapability::Disabled,
            "sanity check: relay capability is genuinely disabled"
        );
        let views = reader_for(state).list_links().unwrap();
        assert_eq!(
            views[0].durability_status,
            GroupDurabilityStatus::Protected,
            "J: still Protected"
        );
        assert_eq!(
            views[0].full_replica_device_ids,
            vec!["nas".to_string()],
            "J: the confirmed peer's real full-replica role is reflected in the read model"
        );
        assert_eq!(
            views[0].fetch_availability,
            FetchAvailability::AvailableNow,
            "J: still Available -- relay incapability of the STORAGE peer is irrelevant"
        );
    }

    /// Scenario K: a confirmed peer's route changes (direct -> relay ->
    /// unreachable) across three snapshots -- fetch_availability tracks
    /// each transition, but durability_status stays Protected throughout
    /// (unchanged custody evidence), never flickering with connectivity.
    #[tokio::test]
    async fn scenario_k_route_transitions_change_availability_never_durability() {
        let state = test_state();
        state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
        state
            .replica_coordinator
            .link_repository()
            .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
            .unwrap();
        upsert_file(&state, "a.bin", false);
        state.set_peer_group_writer("nas", GROUP, true);
        state.set_peer_group_full_replica("nas", GROUP, true);
        let digest = real_digest(&state);
        state.record_custody_confirmation_outcome(
            GROUP,
            crate::daemon_state::CustodyConfirmationOutcome::Confirmed {
                peer_device_id: Some("nas".into()),
                digest,
            },
            state.membership_generation(),
            0,
        );

        for (reachability, expected_fetch) in [
            (
                crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct),
                FetchAvailability::AvailableNow,
            ),
            (
                crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Relay),
                FetchAvailability::AvailableNow,
            ),
            (
                crate::peer_registry::PeerReachability::Unreachable(
                    crate::peer_registry::UnreachableCategory::NoResponse,
                ),
                FetchAvailability::UnavailableNow,
            ),
        ] {
            state.peers.set_reachability("nas".to_string(), reachability);
            // Prove each iteration's setup is genuinely distinct (M4 Pass 6
            // Codex review follow-up finding #3: an earlier version never
            // asserted the actual route/reachability transition itself,
            // only its downstream fetch_availability effect).
            assert_eq!(
                state.peers.reachability("nas"),
                Some(reachability),
                "K sanity check: this iteration's route/reachability is genuinely set"
            );
            let views = DaemonLinkStatusReader::new(state.clone()).list_links().unwrap();
            assert_eq!(
                views[0].durability_status,
                GroupDurabilityStatus::Protected,
                "K: durability must never change across a pure connectivity transition"
            );
            assert_eq!(views[0].fetch_availability, expected_fetch, "K: availability tracks route");
        }
    }
}

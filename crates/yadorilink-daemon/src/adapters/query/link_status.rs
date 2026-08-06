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

use crate::daemon_state::DaemonState;
use crate::replica_coordinator::ReplicaCoordinator;
use crate::queries::link_status::{
    DegradedLinkView, HeldFileView, LinkStatusReadPort, LinkStatusView, LinkTransferView,
};

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
            let files = state.replica_coordinator.file_index_repository().list_files(&link.group_id)?;
            let conflict_count =
                files.iter().filter(|f| f.path.contains("(conflicted copy")).count() as u64;
            let materialization = state.replica_coordinator.materialization_state_repository().materialization_counts(&link.group_id)?;
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
                .link_repository().windows_symlink_opt_in_for_group(&link.group_id)
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
                if let Some(held) = state.replica_coordinator.materialization_state_repository().get_held_state(&link.group_id, &file.path)? {
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
            // Every live folder registered for this group. More than one is the
            // refusing state; the paths ARE the remedy, since unlinking is keyed by
            // path. An unreadable link table surfaces as "not ambiguous" rather than
            // failing the whole status listing: status must keep rendering, and the
            // group is already refusing to sync on the paths that matter.
            let ambiguous_local_paths =
                state.replica_coordinator.link_repository().live_link_paths_for_group(&link.group_id).unwrap_or_else(|e| {
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
                ambiguous_local_paths,
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

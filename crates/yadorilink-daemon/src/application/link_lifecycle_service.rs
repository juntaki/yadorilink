use std::sync::Arc;

use super::ports::{LinkCommand, LinkRepositoryPort, LinkWatcherPort};
use crate::error::DaemonError;

/// The single entry point for creating a link -- both the plain
/// `yadorilink link` command (the control socket's own `Link` handler)
/// and `EnrollmentService::create_and_link`/`join_and_link` (via
/// `EnrollmentLinkPort`, which calls this service directly rather than
/// looping back into the transport layer) converge here, never a second,
/// independent commit path.
///
/// Owns the real orchestration the daemon's original `link` handler body
/// used to embody: duplicate-group prevention, nested-path preflight, the
/// pending-enrollment marker's same-transaction coupling, watcher setup,
/// and rollback-on-setup-failure. `LinkRepositoryPort`/`LinkWatcherPort`
/// are narrow, mostly-single-`SyncState`-call ports; every decision about
/// WHEN to call which, and how to roll back, lives here.
pub(crate) struct LinkLifecycleService {
    repository: Arc<dyn LinkRepositoryPort>,
    watcher: Arc<dyn LinkWatcherPort>,
}

impl LinkLifecycleService {
    pub(crate) fn new(
        repository: Arc<dyn LinkRepositoryPort>,
        watcher: Arc<dyn LinkWatcherPort>,
    ) -> Self {
        Self { repository, watcher }
    }

    pub(crate) async fn link(&self, command: LinkCommand) -> Result<(), DaemonError> {
        // Deliberately NOT gated by `!command.acknowledge_risks` the way the
        // nested-path preflight below is: a second live root on one group is
        // never acceptable at any confirmation level, because each root's
        // scan tombstones the other's files on every device.
        //
        // `any(|p| p != &command.local_path)` rather than `!is_empty()`:
        // re-linking the SAME folder to the same group is idempotent and
        // must stay allowed -- it is exactly what a `share join` retry does
        // after a failed link's rollback.
        let live_for_group = self.repository.live_link_paths_for_group(&command.group_id)?;
        if live_for_group.iter().any(|p| p != &command.local_path) {
            return Err(DaemonError::Config(format!(
                "folder group {} is already linked at {}; a folder group can only be linked to \
                 one folder on a device -- two would make each folder's scan delete the other's \
                 files on every device. Unlink the other folder first, or link this folder to a \
                 different group",
                command.group_id,
                live_for_group.join(", ")
            )));
        }
        if command.pending_enrollment.is_none()
            && live_for_group.iter().any(|path| path == &command.local_path)
            && self.watcher.is_ready(&command.local_path)
        {
            return Ok(());
        }

        let existing_paths = self.repository.list_link_paths()?;
        let preflight = yadorilink_local_storage::link_preflight::run_preflight(
            std::path::Path::new(&command.local_path),
            &existing_paths,
            None,
        );
        if !preflight.nested_conflicts.is_empty() && !command.acknowledge_risks {
            let conflict_summary = preflight
                .nested_conflicts
                .iter()
                .map(|c| match c.relation {
                    yadorilink_local_storage::link_preflight::NestedLinkRelation::Ancestor => {
                        format!(
                            "{} is already linked and is an ancestor of this folder",
                            c.other_path
                        )
                    }
                    yadorilink_local_storage::link_preflight::NestedLinkRelation::Descendant => {
                        format!(
                            "{} is already linked and is nested inside this folder",
                            c.other_path
                        )
                    }
                    yadorilink_local_storage::link_preflight::NestedLinkRelation::Same => {
                        format!("{} is already linked", c.other_path)
                    }
                })
                .collect::<Vec<_>>()
                .join("; ");
            return Err(DaemonError::Config(format!(
                "link preflight rejected (nested-link conflict): {conflict_summary} -- re-run \
                 with acknowledge_risks/--yes to proceed"
            )));
        }

        // From here on the link (and, if `pending_enrollment` was set, its
        // marker) is durably committed. Every caller treats any `Err` this
        // method returns as "nothing was created", so a failure past this
        // point must roll the just-committed row(s) back rather than return
        // `Err` with local state left behind.
        match &command.pending_enrollment {
            None => self.repository.commit_plain_link(&command.local_path, &command.group_id)?,
            Some(marker) => self.repository.commit_link_with_pending_enrollment(
                &command.local_path,
                &command.group_id,
                marker,
            )?,
        }

        if let Err(e) = self
            .watcher
            .start(
                &command.local_path,
                &command.group_id,
                command.on_demand,
                command.max_local_size_bytes,
            )
            .await
        {
            // The rollback itself is best-effort against the same SQLite
            // database the commit above just used, so it is expected to
            // succeed in practice -- but it is not guaranteed to (e.g. a
            // concurrent `SQLITE_BUSY`/`SQLITE_LOCKED` that outlasts the
            // pool's own retry budget). A rollback failure must never be
            // silently swallowed: the caller is about to be told the whole
            // link setup failed and to treat nothing as created, so a link/
            // marker that is actually still committed underneath would be a
            // live, reconcile-eligible link this device's own logs are the
            // only record of.
            let rollback_result = match &command.pending_enrollment {
                None => self.repository.remove_link(&command.local_path),
                Some(marker) => self.repository.rollback_local_setup_to_cancel_pending(
                    &command.local_path,
                    &marker.operation_id,
                    &e.to_string(),
                ),
            };
            return Err(match rollback_result {
                Ok(()) => e,
                Err(rollback_err) => {
                    tracing::error!(
                        error = %rollback_err,
                        local_path = %command.local_path,
                        "failed to roll back a link (and its pending-enrollment marker, if any) \
                         after its post-commit setup failed -- this local link may still be \
                         committed even though link setup is being reported as failed"
                    );
                    DaemonError::Config(format!(
                        "link setup failed ({e}), and rolling back the partially-committed local \
                         state also failed -- this device's local link state may now be \
                         inconsistent with what was reported; check the daemon log and run \
                         `yadorilink link list` to verify before retrying"
                    ))
                }
            });
        }

        // Local setup (watcher registration, on-demand config) is confirmed
        // -- ONLY now may the pending-enrollment reconciler attempt remote
        // activation.
        if let Some(marker) = &command.pending_enrollment {
            let activation_ready =
                match self.repository.mark_enrollment_activation_pending(&marker.operation_id) {
                    Ok(ready) => ready,
                    Err(e) => {
                        // The watcher was already registered; this DB-level
                        // failure to record that must not leave it running.
                        self.watcher.stop(&command.local_path).await;
                        return Err(e.into());
                    }
                };
            if !activation_ready {
                // The row is no longer `LocalSetupPending` -- most likely a
                // concurrent recovery sweep rolled it back to
                // `CancelPending` after this row sat past its age-gate. The
                // local setup that just finished is NOT rolled back here on
                // the theory it may have raced that rollback and lost --
                // rolling it back ourselves risks deleting a link the
                // reconciler's own rollback already deleted (a double-
                // delete is harmless) or, worse, one it never touched
                // (which would then be a wrongly-discarded, fully live
                // link). Reporting failure and refusing to attempt
                // activation is the one response safe under either
                // interpretation. The in-memory watcher IS stopped here
                // regardless.
                self.watcher.stop(&command.local_path).await;
                return Err(DaemonError::Config(
                    "local setup completed but the enrollment operation could not advance to \
                     ActivationPending; remote activation was not attempted -- check `yadorilink \
                     link list` and the daemon log before retrying"
                        .to_string(),
                ));
            }
        }

        Ok(())
    }
}

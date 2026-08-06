//! Per-group startup-readiness state and the local-change-processor
//! construction it gates: `GroupStartupReadyGuard` (the fail-closed RAII
//! barrier `LinkRuntimeFactory::build` arms before any fallible setup step,
//! and the spawned executor task in [`super::tasks`] resolves once its own
//! scan+redrive loop completes or exhausts its retries) and
//! `build_change_processor`/`ensure_initial_change_history` (wiring a
//! link's `LocalChangeProcessor` with change-history emission once this
//! device has both a registered identity and a signing key).
//!
//! Moved here from the daemon's own `LinkRuntimeController` as a pure relocation -- every method's
//! logic is byte-identical to before the move.

use std::sync::Arc;

use yadorilink_local_capture::LocalChangeProcessor;
use crate::sync_error::SyncError;

use crate::link_runtime::dependencies::LinkRuntimeDependencies;

/// Builds a linked folder's local-change processor, wiring in change-history
/// (change-DAG) emission when this device has both a registered identity and
/// a signing key.
///
/// Emission is enabled only *after* the group's existing on-disk index has
/// been established as the root of its change history
/// (`ensure_initial_import`). That ordering is required: the import must
/// precede the first live mutation or any admitted peer change so history
/// starts at the observed present rather than fabricating a past. Behavior
/// is byte-identical to before change history existed only for a genuinely
/// *unregistered* device (empty `device_id`) — a *registered* device with no
/// signing key wired is a fail-closed condition instead, not a legitimate
/// no-emitter path; see `ensure_initial_change_history`'s own doc comment.
pub(crate) fn build_change_processor(
    deps: &Arc<LinkRuntimeDependencies>,
    group_id: &str,
    root_lease: Arc<yadorilink_root_authority::root_commit::RootLease>,
) -> Result<LocalChangeProcessor, SyncError> {
    let processor = LocalChangeProcessor::new(
        deps.replica_coordinator.clone(),
        Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
            deps.block_store.clone(),
        )),
        deps.device_id.clone(),
        root_lease,
    );
    // Emission needs a stable device id to attribute changes to. A device
    // with no identity leaves emission off — behavior byte-identical to
    // before change history existed. A registered device with no signing
    // key is NOT handled here: `ensure_initial_change_history` below fails
    // closed for that case instead of silently leaving emission off.
    if deps.device_id.is_empty() {
        return Ok(processor);
    }
    Ok(processor.with_change_emitter(ensure_initial_change_history(deps, group_id)?))
}

pub(crate) fn ensure_initial_change_history(
    deps: &Arc<LinkRuntimeDependencies>,
    group_id: &str,
) -> Result<Arc<yadorilink_sync_sqlite::dag_store::ChangeEmitter>, SyncError> {
    // A *registered* device (non-empty `device_id`, checked by the caller)
    // with no signing key wired is a fail-closed condition, not a legitimate
    // no-emitter path: without a `ChangeEmitter`, local edits get indexed but
    // never recorded as DAG `Change`s, so this device's own edits would never
    // reach a peer through change-history sync at all -- silent data loss
    // from the group's perspective, not merely "emission off." Only a
    // genuinely *unregistered* device (empty `device_id`, handled entirely by
    // `build_change_processor`'s own early return above) is exempt.
    let signing_key = deps.device_signing_key().ok_or_else(|| {
        SyncError::CorruptState(format!(
            "registered device {} has no signing key; refusing index-only sync",
            deps.device_id
        ))
    })?;
    let emitter = Arc::new(yadorilink_sync_sqlite::dag_store::ChangeEmitter::new(
        deps.device_id.clone(),
        signing_key,
    ));
    // Idempotent, so it is safe both before and after the asynchronous initial
    // disk scan. The post-scan call matters for a newly linked, populated
    // folder: the first call sees an empty index, while the batched scan writes
    // index rows without going through the per-change DAG emitter.
    match crate::dag_import::ensure_initial_import(
        deps.replica_coordinator.as_ref(),
        group_id,
        &emitter,
    ) {
        Ok(outcome) => {
            tracing::debug!(?outcome, group_id, "change-history initial import checked");
            Ok(emitter)
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                group_id,
                "change-history initial import failed; emission disabled for this folder"
            );
            Err(e)
        }
    }
}

/// Resolves a group's startup-readiness barrier exactly once, fail-*closed*.
/// Mirrors `HydrationStateGuard`: an explicit success call (`mark_ready`)
/// publishes the good state, while `Drop` on the unfinished path — an early
/// return, a panic that unwinds the executor, or a task abort — transitions the
/// group to `Failed` instead of Ready. A startup that does not complete
/// therefore DEFERS (fail-closed) peer apply for the group rather than opening
/// the gate over a half-built index, where an incoming peer change could
/// overwrite un-indexed local content or skip an offline edit the dirty-journal
/// redrive never got to re-apply. Recovery is a subsequent `begin_group_startup`
/// (relink / watcher restart / the executor's own bounded retry), which
/// supersedes the failure and re-runs startup.
///
/// The guard carries the `StartupGeneration` it owns, and every transition
/// routes through the generation-checked `SyncState` methods, so an aborted old
/// executor's late `Drop` can neither open nor fail a newer generation's gate.
pub(crate) struct GroupStartupReadyGuard {
    deps: Arc<LinkRuntimeDependencies>,
    group_id: String,
    generation: crate::sync_runtime::startup_readiness::StartupGeneration,
    resolved: bool,
}

impl GroupStartupReadyGuard {
    pub(crate) fn new(
        deps: Arc<LinkRuntimeDependencies>,
        group_id: String,
        generation: crate::sync_runtime::startup_readiness::StartupGeneration,
    ) -> Self {
        Self { deps, group_id, generation, resolved: false }
    }

    /// Success path: publish `Ready` for this generation and defuse the
    /// fail-closed `Drop`.
    pub(crate) fn mark_ready(&mut self) {
        self.deps.replica_coordinator.startup_readiness().mark_group_ready(&self.group_id, self.generation);
        self.resolved = true;
    }

    /// Explicit failure path — a caught scan/redrive error, or a `JoinError`
    /// from a scan task that panicked inside `spawn_blocking` (which does NOT
    /// unwind this future). Publishes `Failed` for this generation and defuses
    /// the `Drop`.
    pub(crate) fn mark_failed(&mut self, reason: impl Into<String>) {
        self.deps.replica_coordinator.startup_readiness().mark_group_failed(&self.group_id, self.generation, reason);
        self.resolved = true;
    }

    /// Re-arm for a retry: adopt the fresh generation returned by a new
    /// `begin_group_startup` so a subsequent `mark_*`/`Drop` targets the
    /// generation actually in flight.
    pub(crate) fn begin_generation(
        &mut self,
        generation: crate::sync_runtime::startup_readiness::StartupGeneration,
    ) {
        self.generation = generation;
        self.resolved = false;
    }
}

impl Drop for GroupStartupReadyGuard {
    fn drop(&mut self) {
        if !self.resolved {
            // Unwound before completing (panic / early return / task abort):
            // fail-closed. The generation check inside `mark_group_failed` makes
            // this a no-op when a newer startup has already superseded us.
            self.deps.replica_coordinator.startup_readiness().mark_group_failed(
                &self.group_id,
                self.generation,
                "startup task did not complete (panicked, aborted, or returned early)",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;

    use super::*;
    use crate::link_runtime::dependencies::LinkRuntimeHostPort;

    /// A `LinkRuntimeHostPort` that does nothing -- these tests only exercise
    /// `GroupStartupReadyGuard`'s own `sync_state`-based ready/failed
    /// bookkeeping, never the daemon-wide broadcast/write-activity/signing-key
    /// operations the real host implementation reaches.
    struct NoopHost;

    impl LinkRuntimeHostPort for NoopHost {
        fn broadcast_change<'a>(
            &'a self,
            _group_id: &'a str,
            _records: Vec<yadorilink_replica_domain::file::FileRecord>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            Box::pin(async {})
        }

        fn begin_write_activity(&self) -> Box<dyn Send + '_> {
            Box::new(())
        }

        fn device_signing_key(&self) -> Option<ed25519_dalek::SigningKey> {
            None
        }
    }

    fn test_deps() -> Arc<LinkRuntimeDependencies> {
        let store_dir = tempfile::tempdir().unwrap();
        let block_store =
            Arc::new(yadorilink_local_storage::FsBlockStore::new(store_dir.path()).unwrap());
        let replica_coordinator = Arc::new(
            crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap(),
        );
        Arc::new(LinkRuntimeDependencies {
            replica_coordinator,
            block_store,
            telemetry: Arc::new(crate::runtime_telemetry::RuntimeTelemetry::new(
                tokio::sync::broadcast::channel(16).0,
            )),
            device_id: "device-a".to_string(),
            host: Arc::new(NoopHost),
        })
    }

    /// A startup that unwinds/returns early before calling `mark_ready` (its
    /// guard drops while unresolved) must transition the group to `Failed`, so
    /// peer apply fail-closes — it must NOT be released as ready over the
    /// half-built index. This is the core of the fail-open fix: a startup panic
    /// can no longer open the gate.
    #[tokio::test]
    async fn startup_panic_must_not_release_peer_apply_as_ready() {
        let deps = test_deps();
        let generation = deps.replica_coordinator.startup_readiness().begin_group_startup("g");
        // Model a startup that panics / returns early before `mark_ready`: the
        // guard is dropped while still unresolved.
        {
            let _guard = GroupStartupReadyGuard::new(deps.clone(), "g".to_string(), generation);
        }
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            deps.replica_coordinator.wait_group_ready("g"),
        )
        .await
        .expect("wait must resolve, not hang");
        assert!(
            result.is_err(),
            "a startup that dropped its guard without completing must fail-close peer apply, \
             never open the gate as ready over a half-built index"
        );
    }

    /// Aborting the startup task (as `LinkRuntimeController::stop` does with
    /// `handle.abort()`) drops its guard mid-startup, which must transition the
    /// group to `Failed` (fail-closed) rather than leaving it wedged in
    /// `Starting` or opening it as ready.
    #[tokio::test]
    async fn startup_task_abort_transitions_group_to_failed() {
        let deps = test_deps();
        let generation = deps.replica_coordinator.startup_readiness().begin_group_startup("g");

        let task_deps = deps.clone();
        let handle = tokio::spawn(async move {
            let _guard = GroupStartupReadyGuard::new(task_deps, "g".to_string(), generation);
            // Startup is "in progress": hold the guard across an await that
            // parks until the task is aborted.
            std::future::pending::<()>().await;
        });

        // Let the task reach the park point so its guard is actually constructed
        // and held across the await, then abort mid-startup.
        tokio::task::yield_now().await;
        handle.abort();
        let _ = handle.await;

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            deps.replica_coordinator.wait_group_ready("g"),
        )
        .await
        .expect("wait must resolve, not hang");
        assert!(
            result.is_err(),
            "aborting the startup task must transition the group to Failed (fail-closed), \
             not leave it wedged or open it as ready"
        );
    }
}

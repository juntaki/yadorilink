//! Narrow, per-link dependency bundle threaded through this module tree
//! (`link_runtime.rs` and `link_runtime/operations/*.rs`) in place of a
//! handle to the daemon's full runtime state -- so this module tree names
//! only what the per-link watch/capture/repair machinery actually uses,
//! not every other subsystem (peer sessions, governance config, update
//! management, ...) that lives alongside it at the daemon-wide level.
//!
//! Constructed once per relevant call from the daemon-wide state (see that
//! type's own `link_runtime_dependencies` constructor) and threaded down
//! into [`super::LinkRuntime`]'s construction, its per-link operations, and
//! every one of the per-link background tasks the daemon's own `LinkRuntimeController` spawns.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use yadorilink_local_storage::BlockStore;
use yadorilink_replica_domain::file::FileRecord;

use crate::replica_coordinator::ReplicaCoordinator;

/// The handful of operations this per-link dependency bundle cannot itself
/// perform without reaching into daemon-wide coordination state that has no
/// per-link narrowing: fanning a batch of changes out to every connected
/// peer session (`broadcast_change`), marking daemon-wide write activity
/// for the idle-GC scheduler and the "Safe Update Windows" write-safe-point
/// signal (`begin_write_activity`), and reading this device's change-history
/// signing key (`device_signing_key`). Implemented by the daemon's runtime
/// state itself, elsewhere in this crate, so [`LinkRuntimeDependencies`] can
/// still reach these three without naming that type.
pub(crate) trait LinkRuntimeHostPort: Send + Sync {
    fn broadcast_change<'a>(
        &'a self,
        group_id: &'a str,
        records: Vec<FileRecord>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

    /// An opaque write-activity RAII guard, released on drop. Boxed and
    /// type-erased because its real return type borrows fields of the
    /// implementor that this bundle has no business naming -- the same
    /// erasure `yadorilink_peer_session::peer_session::BlockWriteActivityProvider`
    /// already uses for the identical guard.
    fn begin_write_activity(&self) -> Box<dyn Send + '_>;

    fn device_signing_key(&self) -> Option<ed25519_dalek::SigningKey>;
}

/// Everything the per-link runtime machinery actually needs, narrowed down
/// from the daemon's full runtime state. Cheap to clone (every field is an
/// `Arc`/`String`/trait-object handle), so it is passed around freely and
/// captured into every per-link background task the same way a full state
/// handle used to be.
#[derive(Clone)]
pub(crate) struct LinkRuntimeDependencies {
    /// The one replica/DAG/materialization composition-root handle this
    /// bundle threads down into the per-link runtime machinery
    /// (`factory.rs`/`startup.rs`'s startup-readiness calls/`tasks.rs`/
    /// `operations/repair_materialization.rs`, `startup.rs`'s
    /// `build_change_processor`). Phase 7D-10.9 removed the `sync_state:
    /// Arc<yadorilink_sync_core::index::SyncState>` field this used to
    /// coexist additively alongside: `ReplicaCoordinator` already
    /// implements `MaterializationStatePort`/`MaterializationExecutionPort`/
    /// `PeerReplicaStatePort`/`LocalMutationStore` in full (the last one,
    /// `replica_coordinator/local_mutation.rs`, closed the one remaining
    /// blocker -- `build_change_processor`'s `LocalChangeProcessor`
    /// construction -- named in this field's own prior doc comment), so
    /// nothing in this module tree needs the concrete `SyncState` anymore.
    pub(crate) replica_coordinator: Arc<ReplicaCoordinator>,
    pub(crate) block_store: Arc<dyn BlockStore + Send + Sync>,
    pub(crate) telemetry: Arc<crate::runtime_telemetry::RuntimeTelemetry>,
    pub(crate) device_id: String,
    /// Reaches the three daemon-wide operations `LinkRuntimeHostPort`
    /// covers -- see that trait's own doc for why they cannot be plain
    /// fields on this bundle.
    pub(crate) host: Arc<dyn LinkRuntimeHostPort>,
}

impl LinkRuntimeDependencies {
    pub(crate) async fn broadcast_change(&self, group_id: &str, records: Vec<FileRecord>) {
        self.host.broadcast_change(group_id, records).await;
    }

    pub(crate) fn begin_write_activity(&self) -> Box<dyn Send + '_> {
        self.host.begin_write_activity()
    }

    pub(crate) fn device_signing_key(&self) -> Option<ed25519_dalek::SigningKey> {
        self.host.device_signing_key()
    }
}

//! `MaterializationIntentGuard`/`MaterializationIntentJournal`, independently
//! duplicated from `yadorilink_sync_core::materialization`'s equivalent
//! types (Phase 7D-10.11 "temporary coexistence" pattern -- see
//! `crate::sync_runtime`'s own module doc comment for the same reasoning
//! applied to the lock/readiness registries).
//!
//! Unlike those registries, this one could not simply be given an
//! independent copy without also duplicating three marker-trait impls:
//! `yadorilink_peer_session::ports::OpenMaterializationIntent`,
//! `yadorilink_filesystem_sync::materialization_execution::
//! OpenMaterializationIntent`, and `yadorilink_sync_sqlite::
//! OpenMaterializationIntent` are each foreign traits owned by a different
//! crate, and Rust's orphan rule requires the `impl` to live in a crate that
//! owns either the trait or the type. `yadorilink-sync-core` could write all
//! three because the guard type is local there and it sits above
//! `yadorilink-peer-session`/`yadorilink-filesystem-sync`/
//! `yadorilink-sync-sqlite` in the dependency graph (so it can name all
//! three foreign traits) while still sitting below `yadorilink-daemon` (so
//! `ReplicaCoordinator` could reach it generically). Hoisting the guard type
//! itself to a lower shared crate (`yadorilink-replica-domain`, the 7D-9D
//! precedent's destination) does not work here: `yadorilink-peer-session`
//! already depends on `yadorilink-sync-sqlite`, so any crate that could
//! write `impl yadorilink_sync_sqlite::OpenMaterializationIntent for
//! <the guard type>` and ALSO `impl yadorilink_peer_session::ports::
//! OpenMaterializationIntent for <the guard type>` needs to depend on BOTH,
//! which `yadorilink-replica-domain` cannot without inverting the very
//! dependency order the 7D-9D hoist relies on (nothing above
//! `yadorilink-replica-domain` could still depend on it for its plain-data
//! types).  `yadorilink-daemon`, by contrast, already depends on all three
//! consumer crates directly (it is the composition root) -- so this crate
//! duplicating the guard, with its OWN three marker-trait impls written
//! here, is legal under the orphan rule for the exact same structural
//! reason `yadorilink-sync-core`'s original copy is: the type is local,
//! the traits are foreign, and every dependency edge already exists.
//!
//! `yadorilink_sync_core::materialization::MaterializationIntentGuard` is
//! left untouched -- `SyncState` (the one implementor left in that crate)
//! has no remaining production callers, so that copy is exercised only by
//! `yadorilink-sync-core`'s own test suite and disappears with the crate.

use yadorilink_root_authority::root_commit::RootCommitPermit;

use crate::sync_error::SyncError;

/// The narrow capability [`MaterializationIntentGuard`] needs from whatever
/// concrete state type backs it: access to the one repository that durably
/// tracks materialization intents. See
/// `yadorilink_sync_core::materialization::MaterializationIntentJournal`'s
/// doc comment (this crate's module doc comment above) for why this is an
/// independent copy of that trait, not the same one.
pub trait MaterializationIntentJournal: Sync {
    fn materialization_intent_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::MaterializationIntentRepository;
}

/// See `yadorilink_sync_core::materialization::MaterializationIntentGuard`'s
/// doc comment for the full crash-safety discipline this type enforces --
/// identical here, just backed by this crate's own
/// [`MaterializationIntentJournal`].
#[must_use = "an intent guard that is neither cleared nor deliberately dropped leaves a durable \
              materialization intent behind"]
pub struct MaterializationIntentGuard<'a, T: MaterializationIntentJournal> {
    state: &'a T,
    group_id: &'a str,
    path: &'a str,
    permit: &'a RootCommitPermit<'a>,
}

impl<'a, T: MaterializationIntentJournal> MaterializationIntentGuard<'a, T> {
    /// Opens (durably writes) the materialization intent for `(group_id, path)`
    /// targeting `target_version_hash`'s content. MUST be called before the
    /// bytes are written and before any `Hydrated` row is committed for this
    /// path. See `yadorilink_sync_core::materialization::
    /// MaterializationIntentGuard::open`'s doc comment for the full
    /// reasoning (identical here).
    pub fn open(
        state: &'a T,
        group_id: &'a str,
        path: &'a str,
        target_version_hash: &[u8],
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<Self, yadorilink_sync_sqlite::SyncSqliteError> {
        state.materialization_intent_repository().begin_materialization_intent(
            group_id,
            path,
            target_version_hash,
            permit,
        )?;
        Ok(Self { state, group_id, path, permit })
    }

    /// Clears the intent. Call ONLY after the temp-write-then-rename is
    /// durable, or when the write has been abandoned to a `Placeholder`.
    pub fn clear(self) -> Result<(), yadorilink_sync_sqlite::SyncSqliteError> {
        self.state.materialization_intent_repository().clear_materialization_intent(
            self.group_id,
            self.path,
            self.permit,
        )
    }
}

impl<'a, T: MaterializationIntentJournal> yadorilink_peer_session::ports::OpenMaterializationIntent
    for MaterializationIntentGuard<'a, T>
{
    fn clear(self: Box<Self>) -> Result<(), yadorilink_peer_session::PeerSessionError> {
        MaterializationIntentGuard::clear(*self)
            .map_err(SyncError::from)
            .map_err(yadorilink_peer_session::PeerSessionError::from)
    }
}

impl<'a, T: MaterializationIntentJournal>
    yadorilink_filesystem_sync::materialization_execution::OpenMaterializationIntent
    for MaterializationIntentGuard<'a, T>
{
    fn clear(
        self: Box<Self>,
    ) -> Result<
        (),
        yadorilink_filesystem_sync::materialization_execution::MaterializationExecutionError,
    > {
        MaterializationIntentGuard::clear(*self).map_err(SyncError::from).map_err(Into::into)
    }
}

impl<'a, T: MaterializationIntentJournal> yadorilink_sync_sqlite::OpenMaterializationIntent
    for MaterializationIntentGuard<'a, T>
{
    fn clear(self: Box<Self>) -> Result<(), yadorilink_sync_sqlite::SyncSqliteError> {
        MaterializationIntentGuard::clear(*self)
    }
}

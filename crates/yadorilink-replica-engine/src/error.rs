//! Errors surfaced by the replica-engine's own ports. Deliberately not
//! `yadorilink_sync_core::SyncError` -- this crate must never depend back
//! on `yadorilink-sync-core`, so its ports own a narrower error type and
//! sync-core's port adapters convert `SyncError` into it at the boundary.

/// General-purpose port error for every port except `ChangeAdmissionPort`
/// (which has its own narrower error -- see [`AdmissionStoreError`] -- so
/// callers can distinguish a permanent, already-recorded rejection from a
/// transient storage failure without string-matching).
#[derive(Debug, thiserror::Error)]
pub enum ReplicaEngineError {
    #[error("replica storage operation failed: {0}")]
    Storage(String),
    #[error("corrupt replica state: {0}")]
    CorruptState(String),
    #[error("invalid replica input: {0}")]
    InvalidInput(String),
}

/// `rebootstrap.rs`'s `prepare_rebootstrap_required`/`verify_and_install_
/// rebootstrap` (7D-9D move from `yadorilink-sync-core`) call
/// `SnapshotManifest`/`RebootstrapRequired`'s own sign/verify methods,
/// which return `yadorilink_replica_domain::codec::ChangeError` -- mirrors
/// `yadorilink-sync-core::SyncError`'s own identical bridge for the same
/// type, collapsed to `CorruptState` for the same reason: a signature or
/// encoding failure on an already-received protocol object is a corrupt/
/// untrustworthy input, not a storage failure.
impl From<yadorilink_replica_domain::codec::ChangeError> for ReplicaEngineError {
    fn from(error: yadorilink_replica_domain::codec::ChangeError) -> Self {
        ReplicaEngineError::CorruptState(error.to_string())
    }
}

/// `ChangeAdmissionPort::admit_unprojected_change`'s own error. Narrower
/// than [`ReplicaEngineError`] on purpose: `PeerReplicaEngine::
/// admit_authenticated_change` treats a reserved-namespace collision or a
/// non-portable path as a *permanent*, already-durably-recorded rejection
/// (never re-requested), and every other admission failure as an ordinary
/// transient one -- collapsing all three into one string-typed error would
/// force callers back to matching on the message text to preserve that
/// distinction.
#[derive(Debug, thiserror::Error)]
pub enum AdmissionStoreError {
    #[error("reserved namespace collision: {path}")]
    ReservedNamespaceCollision { path: String },
    #[error("non-portable path: {path}")]
    NonPortablePath { path: String },
    #[error("{0}")]
    Other(String),
}

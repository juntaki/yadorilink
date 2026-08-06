//! Pure value types describing the outcome of admitting a verified
//! [`crate::change::Change`] into a device's local history, plus the
//! signing identity a device uses to author its own changes. No storage,
//! no I/O — moved out of `yadorilink-sync-core`'s `dag_store` (which keeps
//! the SQL admission logic) because these types are shared by every
//! consumer of admission results, not just that module's own callers.

use crate::ids::ChangeHash;

/// How two changes relate in DAG ancestry order, derived purely from
/// ancestry, never from per-file counters — the version-vector model it
/// replaced could be advanced by a peer, while ancestry is fixed by the
/// signed change bytes themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeOrdering {
    /// The same change.
    Equal,
    /// The left change is an ancestor of the right one.
    Before,
    /// The left change is a descendant of the right one.
    After,
    /// Neither is an ancestor of the other: a genuine fork.
    Concurrent,
}

/// Outcome of admitting a verified change from a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitOutcome {
    /// The change's ancestry was complete; it (and any orphans it unblocked)
    /// were inserted into `changes`.
    Applied,
    /// The change's parents are not all present yet; it is held in the
    /// bounded orphan buffer until they arrive.
    Orphaned,
}

/// The full result of admitting a verified change: its outcome plus the hashes
/// of every change that actually landed in `changes` as a side-effect of this
/// admission. `newly_admitted` is the current change followed by every orphan
/// its arrival unblocked, in the order they were appended. It is empty for
/// `Orphaned`.
///
/// The caller needs the promoted-orphan hashes, not just the current one: when
/// a child change arrives before its parent it is buffered, and the parent's
/// later admission both applies the parent AND promotes the child. Both changes
/// become durable in the same call, so both must have their paths projected and
/// their `applied` flag gated in the same batch — otherwise a promoted orphan's
/// paths would not materialize until the periodic reprojection backstop runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmitResult {
    pub outcome: AdmitOutcome,
    pub newly_admitted: Vec<ChangeHash>,
}

/// The material a device needs to sign the changes it originates: its own
/// id and its Ed25519 signing key. Held separately from the store so the
/// store never touches secret key material.
pub struct ChangeEmitter {
    device_id: String,
    signing_key: ed25519_dalek::SigningKey,
}

impl ChangeEmitter {
    pub fn new(device_id: impl Into<String>, signing_key: ed25519_dalek::SigningKey) -> Self {
        Self { device_id: device_id.into(), signing_key }
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn signing_key(&self) -> &ed25519_dalek::SigningKey {
        &self.signing_key
    }

    pub fn signing_key_fingerprint(&self) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(self.signing_key.verifying_key().as_bytes()).into()
    }
}

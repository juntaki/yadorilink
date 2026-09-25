//! The daemon-side half
//! of checkpoint issuance — collecting a group's pending (uncheckpointed)
//! Changes into a batch, requesting a signed `AuthorizationCheckpoint`
//! for it, and attaching the result locally so `published_view`'s
//! functions start reporting those Changes as published.
//!
//! A trait so tests can supply a fake without any network dependency, and
//! a thin production implementation wrapping
//! `coordination_client::request_authorization_checkpoint`.
//!
//! Wired into the daemon's reconnect event loop by
//! `peer_orchestrator.rs::spawn_flush_pending_checkpoints_on_reconnect` and
//! surfaced by `connection_trace.rs`'s `checkpoint_pending` doctor
//! category. This is the ONLY local-publication path (design doc §14) —
//! there is no second way for a locally authored Change to become
//! `Published`.

use std::future::Future;
use std::pin::Pin;

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_sync_sqlite::dag_store::published_view;

use yadorilink_replica_domain::authorization_checkpoint::{
    build_merkle_proof, encode_merkle_proof, merkle_root, verify_change_admission,
    AuthorizationCheckpoint, CheckpointAdmissionError, MerkleProof,
};

/// How this device obtains a signed [`AuthorizationCheckpoint`] for a
/// batch of its own pending Changes. [`ProductionCheckpointSource`]
/// (below) is the real implementation; tests supply a fake.
pub trait CheckpointSource: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    fn request_authorization_checkpoint<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
        request_id: &'a str,
        merkle_root: [u8; 32],
        leaf_count: u64,
    ) -> Pin<Box<dyn Future<Output = Option<(AuthorizationCheckpoint, [u8; 64])>> + Send + 'a>>;
}

/// The real [`CheckpointSource`] — a thin wrapper over
/// `coordination_client::request_authorization_checkpoint`, holding plain
/// values rather than an `Arc<DaemonState>` back-reference.
pub struct ProductionCheckpointSource {
    coordination_addr: String,
    auth: yadorilink_fapi_client::CoordinationAuth,
}

impl ProductionCheckpointSource {
    pub fn new(coordination_addr: String, auth: yadorilink_fapi_client::CoordinationAuth) -> Self {
        Self { coordination_addr, auth }
    }
}

impl CheckpointSource for ProductionCheckpointSource {
    fn request_authorization_checkpoint<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
        request_id: &'a str,
        merkle_root: [u8; 32],
        leaf_count: u64,
    ) -> Pin<Box<dyn Future<Output = Option<(AuthorizationCheckpoint, [u8; 64])>> + Send + 'a>>
    {
        Box::pin(async move {
            crate::coordination_client::request_authorization_checkpoint(
                &self.coordination_addr,
                &self.auth,
                group_id,
                device_id,
                request_id,
                merkle_root,
                leaf_count,
            )
            .await
        })
    }
}

/// Deterministic `request_id` for a pending batch: SHA-256 of
/// `group_id || device_id || sorted change hashes`. Two calls presented
/// with the EXACT SAME pending set (the common case: an isolate crashed
/// or a response was lost before this device could attach the returned
/// evidence, so the same Changes are still pending on the next attempt)
/// derive the SAME `request_id` and therefore replay the SAME decision
/// (design doc §3.4's corrected retry semantics) — no local persistence
/// of in-flight request state is needed for this property to hold.
///
/// If the pending set has changed (more Changes accumulated locally
/// before the retry), this naturally derives a DIFFERENT `request_id`,
/// which `decideCheckpointIssuance` correctly treats as a new logical
/// request — re-evaluating current writer status, exactly as it should
/// for content the previous attempt never actually covered.
pub fn pending_batch_request_id(group_id: &str, device_id: &str, hashes: &[ChangeHash]) -> String {
    let mut sorted: Vec<&ChangeHash> = hashes.iter().collect();
    sorted.sort();
    let mut hasher = Sha256::new();
    hasher.update(group_id.as_bytes());
    hasher.update([0u8]); // separator -- group_id/device_id are variable-length,
    hasher.update(device_id.as_bytes()); // this hash need not be a signed preimage,
    hasher.update([0u8]); // only collision-resistant for THIS module's own use.
    for hash in sorted {
        hasher.update(hash.0);
    }
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushOutcome {
    /// Nothing was pending; no request was made.
    NothingPending,
    /// A checkpoint was obtained (or replayed), verified against every
    /// Change it covers, and evidence attached for all of them.
    Flushed { batch_size: usize, checkpoint_seq: u64 },
    /// The source refused or was unreachable — e.g. not currently a
    /// writer. The pending set is unchanged; a later call will retry the
    /// SAME batch (assuming nothing new was captured meanwhile) via the
    /// same deterministic `request_id`.
    Refused,
}

/// Everything that can stop a flush from attaching evidence. Distinct
/// from [`FlushOutcome::Refused`] on purpose: a refusal is an EXPECTED
/// outcome (not currently a writer, transient network failure) a caller
/// retries later exactly as-is; [`FlushError::CheckpointDidNotVerify`] is
/// NOT expected under normal operation — it means the coordination plane
/// returned a checkpoint that fails independent verification against the
/// Changes it claims to cover, which should never happen from a
/// correctly-behaving server and is worth surfacing loudly (a bug, a
/// misconfigured authority key, or active tampering) rather than folded
/// into the same quiet-retry path as an ordinary permission refusal.
#[derive(Debug)]
pub enum FlushError {
    Storage(yadorilink_sync_sqlite::SyncSqliteError),
    CheckpointDidNotVerify { change_index: usize, error: CheckpointAdmissionError },
}

impl std::fmt::Display for FlushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "checkpoint flush storage error: {e}"),
            Self::CheckpointDidNotVerify { change_index, error } => write!(
                f,
                "checkpoint returned by coordination plane failed verification for batch leaf \
                 {change_index}: {error:?} -- refusing to attach any evidence from this batch"
            ),
        }
    }
}

impl std::error::Error for FlushError {}

impl From<yadorilink_sync_sqlite::SyncSqliteError> for FlushError {
    fn from(e: yadorilink_sync_sqlite::SyncSqliteError) -> Self {
        Self::Storage(e)
    }
}

/// Collects `device_id`'s own pending Changes in `group_id`, requests a
/// signed checkpoint for the whole batch, INDEPENDENTLY VERIFIES it
/// against every Change it claims to cover, and only then attaches
/// evidence for all of them, in one transaction.
///
/// The verification step is not optional or best-effort: `published_view`'s
/// own doc comment states its contract plainly — "callers MUST call
/// `verify_change_admission` before calling `attach_authorization_evidence`"
/// — and a green round-trip test against a well-behaved `FakeSource` in
/// this module's own test suite is not evidence that a REAL, untrusted
/// coordination-plane response is safe to trust unchecked. If even one
/// Change in the batch fails verification, NO evidence is attached for
/// any of them (`published_view::attach_authorization_evidence`'s own
/// one-transaction guarantee makes "attach some, skip others" impossible
/// by construction here, since this function simply never calls it when
/// any leaf fails).
///
/// `resolve_authority_key` must be backed by this device's own verified
/// `change_policy::GroupPolicyState` for `group_id` — `authorization_checkpoint::verify_change_admission`'s
/// own doc comment explains why a bare, caller-supplied key is never
/// accepted here either.
///
/// Idempotent and crash-safe by construction: `request_id` is re-derived
/// from the CURRENT pending set on every call (never persisted
/// separately), so a repeated call after a crash or a lost response
/// naturally retries the same logical request rather than starting a new
/// one, per [`pending_batch_request_id`]'s own doc comment.
///
/// Takes a [`SyncDatabase`] (a connection POOL), not a bare
/// `rusqlite::Connection` — this daemon's real database access always
/// goes through `SyncDatabase::read`/`write`'s short-lived, synchronous
/// closures (see e.g. `replica_coordinator.rs`'s `CheckpointStore` impl),
/// never a connection handle held open across an `await`, since pooled
/// connections must be checked back in promptly for other callers. This
/// function therefore checks out a connection TWICE — once (`read`) to
/// collect the pending batch before the network round trip, and once
/// (`write`) to attach evidence after verification succeeds — rather than
/// holding one connection for its entire duration. An earlier revision
/// took a bare `&Connection` for the whole function, which cannot
/// actually be wired into this daemon's real connection-pool discipline
/// (found only when working out how to call this from `peer_orchestrator.rs`,
/// not from first-principles review of this module alone).
pub async fn flush_pending_checkpoint(
    db: &yadorilink_sqlite_runtime::SyncDatabase,
    source: &dyn CheckpointSource,
    group_id: &str,
    device_id: &str,
    own_signing_public_key: &VerifyingKey,
    resolve_authority_key: &(dyn Fn(&[u8; 32], &[u8; 32]) -> Option<VerifyingKey> + Send + Sync),
) -> Result<FlushOutcome, FlushError> {
    let pending: Vec<ChangeHash> =
        db.read(|conn| published_view::pending_local_changes_for_group(conn, group_id, device_id))?;
    if pending.is_empty() {
        return Ok(FlushOutcome::NothingPending);
    }

    let request_id = pending_batch_request_id(group_id, device_id, &pending);
    let hash_arrays: Vec<[u8; 32]> = pending.iter().map(|h| h.0).collect();
    let root = merkle_root(&hash_arrays);
    let leaf_count = hash_arrays.len() as u64;

    let Some((checkpoint, signature)) = source
        .request_authorization_checkpoint(group_id, device_id, &request_id, root, leaf_count)
        .await
    else {
        return Ok(FlushOutcome::Refused);
    };

    // Verify EVERY leaf before attaching anything -- see this function's
    // own doc comment. A proof is built per-leaf here rather than reused
    // from `entries` below so verification runs against exactly the
    // bytes an independent verifier would compute, not anything this
    // function might otherwise be tempted to shortcut.
    let mut proofs: Vec<MerkleProof> = Vec::with_capacity(pending.len());
    for (index, hash) in pending.iter().enumerate() {
        let proof = build_merkle_proof(&hash_arrays, index);
        verify_change_admission(
            group_id,
            device_id,
            own_signing_public_key,
            hash.0,
            &proof,
            &checkpoint,
            &signature,
            |key_id, policy_head| resolve_authority_key(key_id, policy_head),
        )
        .map_err(|error| FlushError::CheckpointDidNotVerify { change_index: index, error })?;
        proofs.push(proof);
    }

    let checkpoint_encoded =
        yadorilink_replica_domain::authorization_checkpoint::canonical_signing_bytes(&checkpoint);
    let checkpoint_hash = yadorilink_replica_domain::authorization_checkpoint::checkpoint_hash(
        &checkpoint_encoded,
        &signature,
    );

    let entries: Vec<(ChangeHash, Vec<u8>)> = pending
        .iter()
        .zip(proofs.iter())
        .map(|(hash, proof)| (*hash, encode_merkle_proof(proof)))
        .collect();

    let own_signing_public_key_bytes = own_signing_public_key.to_bytes();
    db.write(|conn| {
        published_view::attach_authorization_evidence(
            conn,
            &checkpoint_hash,
            group_id,
            device_id,
            checkpoint.checkpoint_seq,
            &checkpoint_encoded,
            &signature,
            &own_signing_public_key_bytes,
            &entries,
        )
    })?;

    Ok(FlushOutcome::Flushed {
        batch_size: pending.len(),
        checkpoint_seq: checkpoint.checkpoint_seq,
    })
}

#[cfg(test)]
mod tests;

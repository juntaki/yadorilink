//! Cryptographic re-validation of retained change history.
//!
//! `dag_store` (in `yadorilink-sync-core`) owns structural SQLite integrity
//! and runs before the daemon has learned the current netmap/policy trust
//! material. Signature and historical authorization therefore live in this
//! separate, storage-free component: once a caller has a trust resolver, it
//! walks every retained change reachable from the repaired group frontier
//! and re-runs the same signature/authentication boundary used for peer
//! admission.
//!
//! Missing trust material is deliberately distinct from invalid history. A
//! daemon reconnecting to the coordination plane may temporarily lack a peer's
//! pinned key or verified policy chain; that is a `TrustUnavailable` deferral,
//! never evidence that the stored change is corrupt. Conversely, once trust is
//! available, a bad signature, rejected historical authorization, or a causal
//! authorization-coordinate regression is a hard `InvalidHistory` result and
//! must not be projected or forwarded as trusted.

use std::collections::HashSet;

use sha2::{Digest, Sha256};

use yadorilink_replica_domain::change;
use yadorilink_replica_domain::change::{Change, ChangeAuth};
use yadorilink_replica_domain::ids::ChangeHash;

/// Read-only history surface needed by the validator. Keeping this narrow
/// makes the cryptographic validator independently testable and prevents it
/// from acquiring write responsibilities from `dag_store`. `Error` is an
/// associated type, not `yadorilink_sync_core::SyncError` -- this crate must
/// never depend on `yadorilink-sync-core`, so the implementor (`SyncState`,
/// in `yadorilink-sync-core`'s own bridge `impl`) picks its own error type,
/// which this module wraps opaquely (`AuthenticatedHistoryError::Store`).
pub trait AuthenticatedHistorySource {
    type Error: std::fmt::Display;

    fn retained_heads(&self, group_id: &str) -> Result<Vec<ChangeHash>, Self::Error>;
    fn retained_change(&self, hash: &ChangeHash) -> Result<Option<Change>, Self::Error>;
    /// Authorization coordinates proving a *missing* parent is a legitimate
    /// compacted checkpoint-boundary parent under the group's *current*
    /// HistoryBase, not arbitrary history loss. `Ok(None)` means no such
    /// proof exists and callers must fail closed rather than assume the
    /// parent was compacted.
    fn compacted_parent_auth(
        &self,
        group_id: &str,
        child_hash: &ChangeHash,
        parent_hash: &ChangeHash,
    ) -> Result<Option<(u64, u64)>, Self::Error>;
}

/// Trust material needed to re-authenticate a retained change.
pub trait AuthenticatedHistoryTrust {
    fn signing_key(&self, device_id: &str) -> Option<[u8; 32]>;
    fn accepts_change_auth(
        &self,
        device_id: &str,
        group_id: &str,
        signing_key_fingerprint: [u8; 32],
        auth: ChangeAuth,
    ) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedHistoryReport {
    pub verified_changes: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthenticatedHistoryError {
    #[error("trust material for retained change author {device_id} is not available yet")]
    TrustUnavailable { device_id: String },
    #[error("retained history is cryptographically invalid: {0}")]
    InvalidHistory(String),
    #[error("retained-history store failed: {0}")]
    Store(String),
}

fn store_err<E: std::fmt::Display>(error: E) -> AuthenticatedHistoryError {
    AuthenticatedHistoryError::Store(error.to_string())
}

/// Re-checks the causal authorization-coordinate rule enforced by live change
/// admission. A non-bootstrap child may never pin an older `auth_seq` or
/// `auth_epoch` than one of its retained parents: otherwise a revoked writer can
/// replay an older, once-valid grant coordinate on a causally newer branch.
///
/// A parent body absent because it was compacted is checked against
/// `compacted_parent_auth` — the boundary-parent authorization coordinates
/// recorded (and re-anchored to the group's current HistoryBase, see
/// `AuthenticatedHistorySource::compacted_parent_auth`) when the checkpoint
/// proving that boundary was installed. A missing parent with no such proof
/// is arbitrary history loss, not compaction, and fails closed.
fn validate_retained_parent_auth_monotonicity<S>(
    source: &S,
    change_hash: &ChangeHash,
    change: &Change,
) -> Result<(), AuthenticatedHistoryError>
where
    S: AuthenticatedHistorySource + ?Sized,
{
    let auth = ChangeAuth {
        auth_seq: change.auth_seq,
        auth_epoch: change.auth_epoch,
        policy_head_hash: change.policy_head_hash,
    };
    if auth == ChangeAuth::PLACEHOLDER {
        return Ok(());
    }

    for parent_hash in &change.parents {
        let (parent_auth_seq, parent_auth_epoch) =
            match source.retained_change(parent_hash).map_err(store_err)? {
                Some(parent) => (parent.auth_seq, parent.auth_epoch),
                None => {
                    let Some(coords) = source
                        .compacted_parent_auth(change.group_id.as_str(), change_hash, parent_hash)
                        .map_err(store_err)?
                    else {
                        return Err(AuthenticatedHistoryError::InvalidHistory(format!(
                            "change {}'s parent {} is missing and not proven to be a compacted \
                             checkpoint-boundary parent under the group's current HistoryBase",
                            change_hash.to_hex(),
                            parent_hash.to_hex(),
                        )));
                    };
                    coords
                }
            };
        if change.auth_seq < parent_auth_seq || change.auth_epoch < parent_auth_epoch {
            return Err(AuthenticatedHistoryError::InvalidHistory(format!(
                "change {} pins auth seq/epoch {}/{} older than retained parent {} at {}/{}",
                change_hash.to_hex(),
                change.auth_seq,
                change.auth_epoch,
                parent_hash.to_hex(),
                parent_auth_seq,
                parent_auth_epoch,
            )));
        }
    }
    Ok(())
}

/// Re-authenticates every retained change in one group.
///
/// The structural startup repair has already established that the SQL frontier
/// and parent indexes describe the retained DAG. We therefore start at every
/// repaired head and walk signed parent hashes. A parent body absent because it
/// was explicitly compacted is a normal boundary and is not re-opened here; the
/// prune-proof validator owns that decision. Any retained parent body we can
/// read is verified exactly once.
pub fn validate_retained_group<S, T>(
    source: &S,
    group_id: &str,
    trust: &T,
) -> Result<AuthenticatedHistoryReport, AuthenticatedHistoryError>
where
    S: AuthenticatedHistorySource + ?Sized,
    T: AuthenticatedHistoryTrust + ?Sized,
{
    let mut stack = source.retained_heads(group_id).map_err(store_err)?;
    let mut visited = HashSet::<[u8; 32]>::new();
    let mut verified_changes = 0usize;

    while let Some(hash) = stack.pop() {
        if !visited.insert(hash.0) {
            continue;
        }
        let change = source.retained_change(&hash).map_err(store_err)?.ok_or_else(|| {
            AuthenticatedHistoryError::InvalidHistory(format!(
                "frontier/parent hash {} is marked retained but its Change body is missing",
                hash.to_hex()
            ))
        })?;
        if change.group_id.as_str() != group_id {
            return Err(AuthenticatedHistoryError::InvalidHistory(format!(
                "change {} belongs to group {}, expected {group_id}",
                hash.to_hex(),
                change.group_id.as_str()
            )));
        }

        let key_bytes = trust.signing_key(change.device_id.as_str()).ok_or_else(|| {
            AuthenticatedHistoryError::TrustUnavailable {
                device_id: change.device_id.as_str().to_string(),
            }
        })?;
        let verifying_key = change::verifying_key_from_bytes(&key_bytes).map_err(|error| {
            AuthenticatedHistoryError::InvalidHistory(format!(
                "author {} has an invalid pinned signing key: {error}",
                change.device_id.as_str()
            ))
        })?;
        let signing_key_fingerprint: [u8; 32] = Sha256::digest(key_bytes).into();
        let auth = ChangeAuth {
            auth_seq: change.auth_seq,
            auth_epoch: change.auth_epoch,
            policy_head_hash: change.policy_head_hash,
        };
        change::verify_change(&change, &hash, &verifying_key, |device_id, change_group| {
            trust.accepts_change_auth(
                device_id.as_str(),
                change_group.as_str(),
                signing_key_fingerprint,
                auth,
            )
        })
        .map_err(|error| {
            AuthenticatedHistoryError::InvalidHistory(format!(
                "change {} by {} failed signature/authorization verification: {error}",
                hash.to_hex(),
                change.device_id.as_str()
            ))
        })?;
        validate_retained_parent_auth_monotonicity(source, &hash, &change)?;

        // A retained parent body continues the traversal. A missing body is
        // only a legitimate compaction boundary — not arbitrary history
        // loss — if `compacted_parent_auth` can prove it under the group's
        // current HistoryBase; otherwise this fails closed the same way
        // `validate_retained_parent_auth_monotonicity` does (that check
        // alone is not sufficient here: it short-circuits for
        // `ChangeAuth::PLACEHOLDER` changes, so this is the only site that
        // covers a missing parent on a placeholder-auth change).
        for parent in &change.parents {
            if source.retained_change(parent).map_err(store_err)?.is_some() {
                stack.push(*parent);
                continue;
            }
            if source.compacted_parent_auth(group_id, &hash, parent).map_err(store_err)?.is_none()
            {
                return Err(AuthenticatedHistoryError::InvalidHistory(format!(
                    "change {} parent {} is missing and not proven to be a compacted \
                     checkpoint-boundary parent under the group's current HistoryBase",
                    hash.to_hex(),
                    parent.to_hex(),
                )));
            }
        }
        verified_changes += 1;
    }

    Ok(AuthenticatedHistoryReport { verified_changes })
}

#[cfg(test)]
mod tests;

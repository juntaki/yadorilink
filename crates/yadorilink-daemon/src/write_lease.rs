//! **SUPERSEDED — kept only for the pinning test at the bottom of this
//! file and for the reusable Ed25519 signing-bytes pattern.** Do not wire
//! this into admission. Use `authorization_checkpoint.rs` instead.
//!
//! This is an earlier authorization shape: a short-lived, signed
//! `WriteLease` a Change carries so a receiver can verify authorization
//! fully offline. `verify_change_authorization` has a structural defect: the `signed_at_unix` value
//! it checks against the lease's validity window is written and signed by
//! the author themselves. Nothing here can tell a truthful timestamp from
//! a forged one, so a revoked device can replay an old, still-valid-
//! looking lease with a claimed `signed_at_unix` inside the original
//! window while actually signing long after revocation. The TTL length is
//! irrelevant to this — 10 minutes or 10 seconds, the forgery is the same
//! shape. `a_revoked_author_can_forge_signed_at_unix_to_appear_pre_revocation`
//! below pins this.
//!
//! `authorization_checkpoint.rs` fixes this by removing self-reported
//! time from the trust computation entirely: the authority signs a Merkle
//! root over a batch of Changes only after checking the author is
//! CURRENTLY a writer, at the moment of the request — there is no window
//! for the client to lie about, because there is no client-supplied
//! timestamp anywhere in what gets verified.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Distinct from `change_policy.rs`'s `POLICY_DOMAIN_TAG` (`b"ylpolic1"`) so
/// a signature over one can never be replayed as a signature over the
/// other, even though both are signed by the same per-group
/// `service_signing_key` on the coordination plane.
const WRITE_LEASE_DOMAIN_TAG: &[u8; 8] = b"ylwrlse1";

/// A signed, time-bounded grant that a specific device (identified by its
/// current signing key) may author Changes in one group, valid for the
/// window `[issued_at_unix, valid_until_unix]`. Signed by the group's
/// coordination-plane authority key (the same key that signs
/// `change_policy::PolicyRecord`s), over [`canonical_signing_bytes`].
///
/// Every field the signature covers is here; there is no field this type
/// omits and expects the verifier to supply out of band (that would be
/// exactly the "ask the deliverer" shape this type exists to avoid).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteLease {
    pub group_id: String,
    pub device_id: String,
    /// SHA-256 of the device's pinned Ed25519 signing key, matching
    /// `change_policy::PolicyRecord::signing_key_fingerprint`'s encoding.
    pub signing_key_fingerprint: [u8; 32],
    /// The policy chain point this lease was issued against —
    /// `GroupPolicyState::current_epoch`/`current_seq`/`policy_head` at
    /// issuance. A Change authored under this lease must carry a
    /// `ChangeAuth` pinned to this SAME point (checked by
    /// `verify_change_authorization` below, reusing
    /// `author_was_writer_at`'s existing historical-pin check
    /// unmodified) — a lease is not a substitute for that check, only an
    /// additional bound on WHEN the pin was fresh.
    pub policy_epoch: u64,
    pub policy_seq: u64,
    pub policy_head: [u8; 32],
    pub issued_at_unix: u64,
    pub valid_until_unix: u64,
    /// Distinguishes leases that would otherwise be byte-identical (same
    /// device, group, policy point, and — if ever reissued at the same
    /// second — the same timestamps). Not itself a security boundary;
    /// only makes every issued lease's signing bytes unique so two leases
    /// for the same device never collide.
    pub lease_id: [u8; 16],
}

/// Everything that can make a Change's authorization fail under a
/// `WriteLease`, kept distinct so tests (and, later, diagnostics) can
/// assert on which check actually fired rather than a bare `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteLeaseError {
    /// The lease's own signature does not verify under the group's pinned
    /// authority key — the lease is forged, corrupted, or signed for a
    /// different group's authority key.
    BadLeaseSignature,
    /// The lease is for a different group than the Change claims.
    GroupMismatch,
    /// The lease is for a different device than the Change's author.
    DeviceMismatch,
    /// The lease was issued to a different signing key than the one
    /// currently pinned for this device — e.g. the device rotated keys
    /// after the lease was issued.
    SigningKeyFingerprintMismatch,
    /// The Change's `ChangeAuth` pin does not match the policy point the
    /// lease was issued against. A lease from policy point P only
    /// authorizes Changes pinned to P, not to some other point the author
    /// might separately claim.
    PolicyPointMismatch,
    /// `lease_issued_at_on_change` (the Change's own copy of when it was
    /// signed, bound to the lease) falls outside
    /// `[issued_at_unix, valid_until_unix]`. This is the check that makes
    /// laundering impossible: it depends only on numbers the authority
    /// minted at lease-issuance time, never on anything a relay or the
    /// verifier's own clock supplies.
    SignedOutsideLeaseWindow,
}

fn write_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn write_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    write_u64(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

/// The exact preimage `WriteLease`'s signature covers. Field order and
/// framing are part of the wire contract the moment a coordination-worker
/// implementation exists to mirror this (see the design doc's §3.3) —
/// changing this function's output for an already-issued lease shape
/// would be exactly the kind of incompatible change
/// `change_policy.rs::ACTION_GRANT_WITH_ROLE`'s doc comment warns against
/// making silently.
pub fn canonical_signing_bytes(lease: &WriteLease) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(WRITE_LEASE_DOMAIN_TAG);
    write_len_prefixed(&mut buf, lease.group_id.as_bytes());
    write_len_prefixed(&mut buf, lease.device_id.as_bytes());
    buf.extend_from_slice(&lease.signing_key_fingerprint);
    write_u64(&mut buf, lease.policy_epoch);
    write_u64(&mut buf, lease.policy_seq);
    buf.extend_from_slice(&lease.policy_head);
    write_u64(&mut buf, lease.issued_at_unix);
    write_u64(&mut buf, lease.valid_until_unix);
    buf.extend_from_slice(&lease.lease_id);
    buf
}

/// Signs `lease` with the coordination-plane authority key. Test/reference
/// implementation of what a `WriteLeaseSource` (the client-side consumer of
/// a future `POST .../write-lease` endpoint) receives already-signed from
/// the wire; production code never calls this directly, since the
/// authority key never leaves the coordination plane.
pub fn sign_lease(lease: &WriteLease, authority_key: &SigningKey) -> [u8; 64] {
    authority_key.sign(&canonical_signing_bytes(lease)).to_bytes()
}

fn verify_lease_signature(
    lease: &WriteLease,
    signature: &[u8; 64],
    authority_key: &VerifyingKey,
) -> Result<(), WriteLeaseError> {
    let sig = Signature::from_bytes(signature);
    authority_key
        .verify(&canonical_signing_bytes(lease), &sig)
        .map_err(|_| WriteLeaseError::BadLeaseSignature)
}

/// Fully offline verification that `author_device_id`/`author_key`'s
/// authorship of a Change pinned to `change_auth` — signed at
/// `signed_at_unix` — is backed by `lease`/`lease_signature`, for
/// `expected_group_id`.
///
/// Deliberately takes no "current time" and no notion of who delivered the
/// Change. `signed_at_unix` is a value the AUTHOR commits to (carried on
/// the Change itself, alongside the lease, once this is wired into the
/// wire format) — the verifier is checking "was this signed inside a
/// window the authority bounded in advance," not "is the lease valid at
/// the moment I happen to be checking." A verifier with a skewed clock, or
/// one checking a Change that arrived a week late, reaches the same
/// verdict either way. This is what makes a relay's opinion irrelevant:
/// there is nothing left in this function that a relay could have vouched
/// for.
#[allow(clippy::too_many_arguments)]
pub fn verify_change_authorization(
    expected_group_id: &str,
    author_device_id: &str,
    author_key_fingerprint: [u8; 32],
    change_auth_epoch: u64,
    change_auth_seq: u64,
    change_policy_head: [u8; 32],
    signed_at_unix: u64,
    lease: &WriteLease,
    lease_signature: &[u8; 64],
    authority_key: &VerifyingKey,
) -> Result<(), WriteLeaseError> {
    verify_lease_signature(lease, lease_signature, authority_key)?;

    if lease.group_id != expected_group_id {
        return Err(WriteLeaseError::GroupMismatch);
    }
    if lease.device_id != author_device_id {
        return Err(WriteLeaseError::DeviceMismatch);
    }
    if lease.signing_key_fingerprint != author_key_fingerprint {
        return Err(WriteLeaseError::SigningKeyFingerprintMismatch);
    }
    if lease.policy_epoch != change_auth_epoch
        || lease.policy_seq != change_auth_seq
        || lease.policy_head != change_policy_head
    {
        return Err(WriteLeaseError::PolicyPointMismatch);
    }
    if signed_at_unix < lease.issued_at_unix || signed_at_unix > lease.valid_until_unix {
        return Err(WriteLeaseError::SignedOutsideLeaseWindow);
    }
    Ok(())
}

/// Re-exported so this retired module's own tests keep working without a
/// second implementation of the same hash: the one canonical
/// implementation now lives in
/// `yadorilink_replica_domain::authorization_checkpoint`, which every live
/// authorization path (checkpoint issuance, checkpoint verification,
/// `change_policy::PolicyRecord::signing_key_fingerprint`) uses too.
pub use yadorilink_replica_domain::authorization_checkpoint::fingerprint_signing_key;

#[cfg(test)]
mod tests;

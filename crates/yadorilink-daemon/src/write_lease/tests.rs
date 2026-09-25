#![cfg(test)]

use super::*;
use ed25519_dalek::SigningKey;
use std::sync::atomic::{AtomicU8, Ordering as AtomicOrdering};

/// Deterministic, distinct 32-byte seeds per call -- test-only, never a
/// real key source. Avoids depending on any particular `rand` version's
/// `OsRng` path, which differs across the several `rand` majors this
/// workspace pulls in transitively.
fn next_seed() -> [u8; 32] {
    static COUNTER: AtomicU8 = AtomicU8::new(1);
    let n = COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
    let mut seed = [0u8; 32];
    seed[0] = n;
    seed[31] = n.wrapping_mul(31).wrapping_add(7);
    seed
}

fn authority_keypair() -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::from_bytes(&next_seed());
    let vk = sk.verifying_key();
    (sk, vk)
}

fn device_fingerprint() -> [u8; 32] {
    let (_, vk) = authority_keypair();
    fingerprint_signing_key(&vk)
}

fn base_lease(fingerprint: [u8; 32]) -> WriteLease {
    WriteLease {
        group_id: "group-1".to_string(),
        device_id: "device-A".to_string(),
        signing_key_fingerprint: fingerprint,
        policy_epoch: 3,
        policy_seq: 7,
        policy_head: [9u8; 32],
        issued_at_unix: 1_000,
        valid_until_unix: 1_600, // 10 minute TTL, matching the design doc's proposed default
        lease_id: [1u8; 16],
    }
}

#[test]
fn a_change_signed_inside_the_lease_window_verifies() {
    let (authority_sk, authority_vk) = authority_keypair();
    let fp = device_fingerprint();
    let lease = base_lease(fp);
    let sig = sign_lease(&lease, &authority_sk);

    let result = verify_change_authorization(
        "group-1",
        "device-A",
        fp,
        lease.policy_epoch,
        lease.policy_seq,
        lease.policy_head,
        1_300, // inside [1000, 1600]
        &lease,
        &sig,
        &authority_vk,
    );
    assert_eq!(result, Ok(()));
}

#[test]
fn a_tampered_lease_field_fails_signature_verification() {
    let (authority_sk, authority_vk) = authority_keypair();
    let fp = device_fingerprint();
    let lease = base_lease(fp);
    let sig = sign_lease(&lease, &authority_sk);

    // Attacker (or a buggy relay) extends the window after the fact --
    // exactly the shape of a laundering attempt. The signature was
    // computed over the ORIGINAL valid_until_unix, so it must not
    // verify against the tampered copy.
    let mut tampered = lease.clone();
    tampered.valid_until_unix = 999_999;

    let result = verify_change_authorization(
        "group-1",
        "device-A",
        fp,
        tampered.policy_epoch,
        tampered.policy_seq,
        tampered.policy_head,
        500_000,
        &tampered,
        &sig,
        &authority_vk,
    );
    assert_eq!(result, Err(WriteLeaseError::BadLeaseSignature));
}

#[test]
fn a_change_signed_after_the_lease_expires_is_rejected_even_with_a_valid_signature() {
    let (authority_sk, authority_vk) = authority_keypair();
    let fp = device_fingerprint();
    let lease = base_lease(fp);
    let sig = sign_lease(&lease, &authority_sk);

    // This is the laundering scenario from
    // relay_change_admission.rs::the_laundering_case_and_the_legitimate_case_are_indistinguishable_at_the_boundary
    // recast under WriteLease: an author who went offline signs a
    // Change well after their lease's valid_until_unix, hoping a
    // receiver has no way to tell. Here the receiver can tell,
    // offline, using only numbers the authority minted at issuance.
    let result = verify_change_authorization(
        "group-1",
        "device-A",
        fp,
        lease.policy_epoch,
        lease.policy_seq,
        lease.policy_head,
        1_700, // one second past valid_until_unix = 1_600
        &lease,
        &sig,
        &authority_vk,
    );
    assert_eq!(result, Err(WriteLeaseError::SignedOutsideLeaseWindow));
}

#[test]
fn a_change_signed_before_the_lease_was_issued_is_rejected() {
    let (authority_sk, authority_vk) = authority_keypair();
    let fp = device_fingerprint();
    let lease = base_lease(fp);
    let sig = sign_lease(&lease, &authority_sk);

    let result = verify_change_authorization(
        "group-1",
        "device-A",
        fp,
        lease.policy_epoch,
        lease.policy_seq,
        lease.policy_head,
        999, // one second before issued_at_unix = 1_000
        &lease,
        &sig,
        &authority_vk,
    );
    assert_eq!(result, Err(WriteLeaseError::SignedOutsideLeaseWindow));
}

#[test]
fn a_legitimate_pre_revocation_change_stays_valid_forever_even_after_the_author_is_revoked() {
    // Models: author was a writer at policy point (epoch=3, seq=7),
    // signed a Change at t=1300 (inside the lease window), and was
    // revoked at a LATER policy point (epoch=4, seq=8) that this
    // Change's ChangeAuth does not reference at all. Verification
    // here only ever looks at the policy point the Change/lease
    // claim, never "is this device a writer right now" -- so nothing
    // about the later revocation can retroactively invalidate this
    // Change. (The floor that prevents a REVOKED device from
    // continuing to author NEW changes lives in lease issuance,
    // which simply refuses to issue a fresh lease to a
    // non-writer. This function only re-validates a Change against
    // whatever lease it already carries.)
    let (authority_sk, authority_vk) = authority_keypair();
    let fp = device_fingerprint();
    let lease = base_lease(fp);
    let sig = sign_lease(&lease, &authority_sk);

    let result = verify_change_authorization(
        "group-1",
        "device-A",
        fp,
        lease.policy_epoch,
        lease.policy_seq,
        lease.policy_head,
        1_300,
        &lease,
        &sig,
        &authority_vk,
    );
    assert_eq!(result, Ok(()));
}

#[test]
fn a_revoked_author_can_forge_signed_at_unix_to_appear_pre_revocation() {
    // Pins the vulnerability that superseded this module. Timeline:
    //   00:00  authority issues lease [00:00, 00:10] to device-A
    //   00:05  device-A is revoked (irrelevant to this function --
    //          it never looks at current writer status, only at the
    //          lease it's handed, which is still cryptographically
    //          valid until 00:10 and stays byte-for-byte valid
    //          forever after that too, since nothing here expires
    //          the LEASE OBJECT, only the window it can be cited for)
    //   01:00  device-A, now revoked, signs a brand-new Change and
    //          writes signed_at_unix = 00:04 into it -- a value
    //          INSIDE the original window that device-A can pick
    //          freely, because device-A holds its own signing key and
    //          nothing forces this field to reflect a real clock
    //          reading anyone else witnessed.
    //
    // A legitimate Change actually signed at 00:04 and this forged
    // Change claiming 00:04 produce IDENTICAL inputs to
    // verify_change_authorization -- there is no field anywhere in
    // this function's signature that differs between the two cases.
    // That is the same "indistinguishable at the boundary" shape as
    // relay_change_admission.rs's laundering proof on
    // c4/track-sync-convergence-fix, one level down: moving the
    // attestation from "the relay's serve-time view" to "the lease's
    // validity window" did not remove the self-reported-time
    // dependency, it only relocated it.
    let (authority_sk, authority_vk) = authority_keypair();
    let fp = device_fingerprint();
    let lease = base_lease(fp); // [1_000, 1_600] in this test's units
    let sig = sign_lease(&lease, &authority_sk);

    let forged_signed_at = 1_030; // "00:04" in this test's units -- freely chosen by the attacker, inside the window
    let result = verify_change_authorization(
        "group-1",
        "device-A",
        fp,
        lease.policy_epoch,
        lease.policy_seq,
        lease.policy_head,
        forged_signed_at,
        &lease,
        &sig,
        &authority_vk,
    );

    // This is the bug, pinned, not the fix: the function has no way
    // to reject the forgery, so it returns Ok. Do not "fix" this by
    // tightening the window further -- see the module doc comment.
    // The actual fix is authorization_checkpoint.rs, which removes
    // this field from the trust computation rather than trying to
    // make it trustworthy.
    assert_eq!(result, Ok(()));
}

#[test]
fn a_lease_for_a_different_group_does_not_authorize_this_change() {
    let (authority_sk, authority_vk) = authority_keypair();
    let fp = device_fingerprint();
    let lease = base_lease(fp);
    let sig = sign_lease(&lease, &authority_sk);

    let result = verify_change_authorization(
        "group-2", // Change claims a different group than the lease
        "device-A",
        fp,
        lease.policy_epoch,
        lease.policy_seq,
        lease.policy_head,
        1_300,
        &lease,
        &sig,
        &authority_vk,
    );
    assert_eq!(result, Err(WriteLeaseError::GroupMismatch));
}

#[test]
fn a_lease_issued_to_a_different_device_does_not_authorize_this_change() {
    let (authority_sk, authority_vk) = authority_keypair();
    let fp = device_fingerprint();
    let lease = base_lease(fp);
    let sig = sign_lease(&lease, &authority_sk);

    let result = verify_change_authorization(
        "group-1",
        "device-B", // a relay carrying device-A's lease cannot claim it
        fp,
        lease.policy_epoch,
        lease.policy_seq,
        lease.policy_head,
        1_300,
        &lease,
        &sig,
        &authority_vk,
    );
    assert_eq!(result, Err(WriteLeaseError::DeviceMismatch));
}

#[test]
fn a_rotated_signing_key_invalidates_a_lease_issued_to_the_old_key() {
    let (authority_sk, authority_vk) = authority_keypair();
    let old_fp = device_fingerprint();
    let lease = base_lease(old_fp);
    let sig = sign_lease(&lease, &authority_sk);

    let new_fp = device_fingerprint(); // a freshly generated, different key
    let result = verify_change_authorization(
        "group-1",
        "device-A",
        new_fp,
        lease.policy_epoch,
        lease.policy_seq,
        lease.policy_head,
        1_300,
        &lease,
        &sig,
        &authority_vk,
    );
    assert_eq!(result, Err(WriteLeaseError::SigningKeyFingerprintMismatch));
}

#[test]
fn a_change_pinned_to_a_different_policy_point_than_the_lease_is_rejected() {
    let (authority_sk, authority_vk) = authority_keypair();
    let fp = device_fingerprint();
    let lease = base_lease(fp);
    let sig = sign_lease(&lease, &authority_sk);

    // The lease was issued against (epoch=3, seq=7, head=[9;32]); the
    // Change claims a different seq. A lease from one policy point
    // must not authorize a Change pinned to a DIFFERENT one, even if
    // both are otherwise well-formed and within the time window --
    // that would let an old lease "cover" a later policy transition
    // it was never issued against.
    let result = verify_change_authorization(
        "group-1",
        "device-A",
        fp,
        lease.policy_epoch,
        lease.policy_seq + 1,
        lease.policy_head,
        1_300,
        &lease,
        &sig,
        &authority_vk,
    );
    assert_eq!(result, Err(WriteLeaseError::PolicyPointMismatch));
}

#[test]
fn an_authority_signature_from_the_wrong_key_never_verifies() {
    let (_, authority_vk) = authority_keypair();
    let (wrong_sk, _) = authority_keypair(); // a different, unrelated authority
    let fp = device_fingerprint();
    let lease = base_lease(fp);
    let forged_sig = sign_lease(&lease, &wrong_sk);

    let result = verify_change_authorization(
        "group-1",
        "device-A",
        fp,
        lease.policy_epoch,
        lease.policy_seq,
        lease.policy_head,
        1_300,
        &lease,
        &forged_sig,
        &authority_vk,
    );
    assert_eq!(result, Err(WriteLeaseError::BadLeaseSignature));
}

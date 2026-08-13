//! M3 Pass 5: the coordination-plane-issued authorization boundary for
//! Peer Relay. Mirrors `change_policy`'s own stated independence
//! principle (see that module's doc comment) -- this has no dependency on
//! the coordination plane's transport or wire format, only on plain data
//! types owned here, so it can be verified in isolation from how a grant
//! actually arrived.
//!
//! **What a `RelayGrant` is, and is not.** The coordination plane's job is
//! authorization ONLY -- it never sees a byte of relayed traffic (see
//! `crate::route`'s own doc comment for the parallel `Durability !=
//! Connectivity` invariant; this is the analogous `Authorization !=
//! Data-plane` boundary for relay). A grant does not CREATE any
//! connectivity authority: it names one already-authorized communication
//! (`source_device_id` <-> `destination_device_id`, both members of
//! `group_id`) and permits ONE already relay-capable member of that SAME
//! group (`relay_device_id`) to carry it. The full verification pipeline
//! (`verify_relay_grant`, this module) checks everything a grant's
//! signature alone cannot prove: exactly one function reachable from
//! outside this module actually decides admission, so there is one place
//! to audit, not several call sites that could each get it slightly
//! wrong.
//!
//! **What this module does NOT check** (left to the caller, `relay_
//! session.rs`, deliberately -- see that module's own doc comment for
//! why): whether the presenting `PeerChannel`'s authenticated identity
//! actually matches `grant.source_device_id`; whether `relay_device_id`/
//! `source_device_id`/`destination_device_id` are ALL still, right now,
//! members of `group_id` per this device's own live authorization view
//! (a validly-signed grant can still be STALE if membership changed since
//! issuance -- the signature proves the plane issued it once, not that it
//! is still valid); grant-id replay tracking; relay-slot resource limits;
//! or whether this device has a live DIRECT route to the destination (no
//! relay chaining). Those all require live daemon state this module is
//! deliberately kept free of, mirroring `change_policy`'s own split
//! between pure signature verification (module) and stateful admission
//! (caller).

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

const RELAY_GRANT_DOMAIN_TAG: &[u8; 8] = b"ylrelay1";
/// The only grant version this build accepts. Deliberately exact-match,
/// not "less than or equal to" -- an unknown FUTURE version might encode
/// fields this build's signing-bytes computation doesn't know to include,
/// silently verifying a signature over an incomplete view of the grant's
/// own authorization scope. A newer plane issuing a newer version to an
/// older device should fail closed, not degrade gracefully into checking
/// less than the issuer intended.
const RELAY_GRANT_VERSION: u32 = 1;
const SIGNATURE_LEN: usize = 64;
const SERVICE_KEY_LEN: usize = 32;

/// A short-lived, coordination-plane-signed capability: `relay_device_id`
/// may forward opaque WireGuard datagrams between `source_device_id` and
/// `destination_device_id`, both members of `group_id`, from `not_before_
/// unix` until `expires_at_unix`. See this module's own doc comment for
/// what this does and does not authorize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayGrant {
    pub version: u32,
    /// Opaque, plane-assigned, unique per issuance -- the replay-tracking
    /// key (`relay_session.rs`'s job, not this module's; see this module's
    /// own doc comment).
    pub grant_id: String,
    pub group_id: String,
    /// "A" in this whole feature's own design conversation.
    pub source_device_id: String,
    /// "B" -- the device this grant permits to relay.
    pub relay_device_id: String,
    /// "C".
    pub destination_device_id: String,
    pub not_before_unix: i64,
    pub expires_at_unix: i64,
    /// Optional cap on total bytes carried under this grant, enforced by
    /// the relay-session forwarding actor (`relay_session.rs`'s job), not
    /// this module. `None` means no plane-issued cap (the relay's own
    /// local resource limits still apply regardless).
    pub max_session_bytes: Option<u64>,
    /// 64-byte Ed25519 signature over `signing_bytes(&self)`, by the
    /// coordination plane's own service signing key (the SAME pinned key
    /// `change_policy::verify_group_policy_log` already trusts, delivered
    /// on the netmap's `serviceSigningPublicKeyBase64` field).
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RelayGrantError {
    #[error("relay grant version {found} is not the only version this build accepts ({expected})")]
    UnsupportedVersion { found: u32, expected: u32 },
    #[error("relay grant signature is malformed: {0}")]
    MalformedSignature(String),
    #[error("relay grant signature does not verify against the pinned coordination service key")]
    InvalidSignature,
    #[error("relay grant is not yet valid (not_before={not_before_unix}, now={now_unix})")]
    NotYetValid { not_before_unix: i64, now_unix: i64 },
    #[error("relay grant has expired (expires_at={expires_at_unix}, now={now_unix})")]
    Expired { expires_at_unix: i64, now_unix: i64 },
    #[error(
        "relay grant names relay_device_id={grant_relay_device_id}, but this device is \
         {this_device_id} -- a grant issued for a DIFFERENT relay may not be used here"
    )]
    NotThisDevice { grant_relay_device_id: String, this_device_id: String },
}

/// Verifies EVERYTHING a `RelayGrant`'s signature and its own fields alone
/// can prove: the plane's signature is genuine, the grant is within its
/// validity window, and it actually names THIS device as the relay. Does
/// NOT verify current group membership, presenting-peer identity, replay,
/// resource limits, or direct-route availability -- see this module's own
/// doc comment for why those are the caller's job, not this function's.
///
/// `service_public_key` must be the CURRENTLY PINNED coordination service
/// key for this device (the same trust anchor `change_policy::
/// verify_group_policy_log` uses) -- passing an unpinned or attacker-
/// supplied key defeats this function's whole purpose; that pinning
/// decision itself is the caller's responsibility, exactly as it already
/// is for group policy log verification.
pub fn verify_relay_grant(
    grant: &RelayGrant,
    service_public_key: &[u8; SERVICE_KEY_LEN],
    now_unix: i64,
    this_device_id: &str,
) -> Result<(), RelayGrantError> {
    if grant.version != RELAY_GRANT_VERSION {
        return Err(RelayGrantError::UnsupportedVersion {
            found: grant.version,
            expected: RELAY_GRANT_VERSION,
        });
    }
    if grant.relay_device_id != this_device_id {
        return Err(RelayGrantError::NotThisDevice {
            grant_relay_device_id: grant.relay_device_id.clone(),
            this_device_id: this_device_id.to_string(),
        });
    }
    if now_unix < grant.not_before_unix {
        return Err(RelayGrantError::NotYetValid {
            not_before_unix: grant.not_before_unix,
            now_unix,
        });
    }
    if now_unix > grant.expires_at_unix {
        return Err(RelayGrantError::Expired { expires_at_unix: grant.expires_at_unix, now_unix });
    }

    let signature_bytes: [u8; SIGNATURE_LEN] = grant
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| RelayGrantError::MalformedSignature("signature is not 64 bytes".into()))?;
    let signature = Signature::from_bytes(&signature_bytes);
    let verifying_key = VerifyingKey::from_bytes(service_public_key)
        .map_err(|e| RelayGrantError::MalformedSignature(e.to_string()))?;
    verifying_key
        .verify(&signing_bytes(grant), &signature)
        .map_err(|_| RelayGrantError::InvalidSignature)?;

    Ok(())
}

/// The canonical byte encoding a grant issuer signs over and this module
/// verifies against -- every field EXCEPT `signature` itself, in a fixed
/// order, length-prefixed strings, big-endian integers. Domain-tagged
/// (`RELAY_GRANT_DOMAIN_TAG`) so a signature over this structure can never
/// be replayed as a valid signature over a DIFFERENT signed structure this
/// codebase defines (e.g. a `PolicyRecord`) even if some field values
/// happened to coincide.
fn signing_bytes(grant: &RelayGrant) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(RELAY_GRANT_DOMAIN_TAG);
    put_u32(&mut buf, grant.version);
    put_str(&mut buf, &grant.grant_id);
    put_str(&mut buf, &grant.group_id);
    put_str(&mut buf, &grant.source_device_id);
    put_str(&mut buf, &grant.relay_device_id);
    put_str(&mut buf, &grant.destination_device_id);
    put_i64(&mut buf, grant.not_before_unix);
    put_i64(&mut buf, grant.expires_at_unix);
    match grant.max_session_bytes {
        Some(bytes) => {
            buf.push(1);
            put_u64(&mut buf, bytes);
        }
        None => buf.push(0),
    }
    buf
}

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn put_i64(buf: &mut Vec<u8>, v: i64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn put_str(buf: &mut Vec<u8>, s: &str) {
    put_u32(buf, s.len() as u32);
    buf.extend_from_slice(s.as_bytes());
}

/// Signs `grant` with `key`, filling in `signature`. Test/fake-coordination
/// only in this crate today -- production issuance lives on the
/// coordination plane, outside this repo -- but kept `pub` (not `#[cfg(
/// test)]`) so `tests/support/fake_coordination.rs` (a separate crate) can
/// call it too, mirroring how `change_policy`'s own test helpers are
/// reached from outside this module in this crate's test suite.
pub fn sign_relay_grant(mut grant: RelayGrant, key: &ed25519_dalek::SigningKey) -> RelayGrant {
    use ed25519_dalek::Signer;
    grant.signature = Vec::new();
    let signature = key.sign(&signing_bytes(&grant));
    grant.signature = signature.to_bytes().to_vec();
    grant
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn service_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn other_service_key() -> SigningKey {
        SigningKey::from_bytes(&[11u8; 32])
    }

    fn valid_grant(key: &SigningKey, now: i64) -> RelayGrant {
        let grant = RelayGrant {
            version: RELAY_GRANT_VERSION,
            grant_id: "grant-1".to_string(),
            group_id: "group-1".to_string(),
            source_device_id: "device-a".to_string(),
            relay_device_id: "device-b".to_string(),
            destination_device_id: "device-c".to_string(),
            not_before_unix: now - 10,
            expires_at_unix: now + 300,
            max_session_bytes: None,
            signature: Vec::new(),
        };
        sign_relay_grant(grant, key)
    }

    /// 1. valid A-B-C grant -> OPEN (this module's own share of that
    /// check: signature/version/window/relay-identity all pass).
    #[test]
    fn valid_grant_verifies() {
        let key = service_key();
        let now = 1_000_000;
        let grant = valid_grant(&key, now);
        assert_eq!(
            verify_relay_grant(&grant, &key.verifying_key().to_bytes(), now, "device-b"),
            Ok(())
        );
    }

    /// 2 (partial -- this module's share): grant for B presented to a
    /// DIFFERENT device B2 -> reject.
    #[test]
    fn grant_for_a_different_relay_device_is_rejected() {
        let key = service_key();
        let now = 1_000_000;
        let grant = valid_grant(&key, now);
        let result = verify_relay_grant(&grant, &key.verifying_key().to_bytes(), now, "device-b2");
        assert_eq!(
            result,
            Err(RelayGrantError::NotThisDevice {
                grant_relay_device_id: "device-b".to_string(),
                this_device_id: "device-b2".to_string(),
            })
        );
    }

    /// 7. expired grant -> reject.
    #[test]
    fn expired_grant_is_rejected() {
        let key = service_key();
        let now = 1_000_000;
        let grant = valid_grant(&key, now);
        let after_expiry = grant.expires_at_unix + 1;
        let result =
            verify_relay_grant(&grant, &key.verifying_key().to_bytes(), after_expiry, "device-b");
        assert_eq!(
            result,
            Err(RelayGrantError::Expired {
                expires_at_unix: grant.expires_at_unix,
                now_unix: after_expiry,
            })
        );
    }

    /// 8. future-dated (not-yet-valid) grant -> reject.
    #[test]
    fn not_yet_valid_grant_is_rejected() {
        let key = service_key();
        let now = 1_000_000;
        let grant = valid_grant(&key, now);
        let before_window = grant.not_before_unix - 1;
        let result =
            verify_relay_grant(&grant, &key.verifying_key().to_bytes(), before_window, "device-b");
        assert_eq!(
            result,
            Err(RelayGrantError::NotYetValid {
                not_before_unix: grant.not_before_unix,
                now_unix: before_window,
            })
        );
    }

    /// 9. tampered token -> reject. Exercises both a mutated payload field
    /// (signature no longer matches) and a signature verified against the
    /// WRONG service key (a forged/substituted signer).
    #[test]
    fn tampered_grant_is_rejected() {
        let key = service_key();
        let now = 1_000_000;
        let mut grant = valid_grant(&key, now);
        grant.destination_device_id = "device-x".to_string();
        assert_eq!(
            verify_relay_grant(&grant, &key.verifying_key().to_bytes(), now, "device-b"),
            Err(RelayGrantError::InvalidSignature)
        );
    }

    #[test]
    fn grant_signed_by_an_unpinned_key_is_rejected() {
        let key = service_key();
        let wrong_key = other_service_key();
        let now = 1_000_000;
        let grant = valid_grant(&key, now);
        assert_eq!(
            verify_relay_grant(&grant, &wrong_key.verifying_key().to_bytes(), now, "device-b"),
            Err(RelayGrantError::InvalidSignature)
        );
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let key = service_key();
        let now = 1_000_000;
        let mut grant = valid_grant(&key, now);
        grant.version = RELAY_GRANT_VERSION + 1;
        // Version is checked before signature verification (it's the
        // grant's own explicit claim about how to interpret every other
        // field, including what the signature was even computed over) --
        // re-sign so this test isolates the version check specifically,
        // not incidentally failing on a stale signature over the old
        // version's byte layout instead.
        let grant = sign_relay_grant(grant, &key);
        assert_eq!(
            verify_relay_grant(&grant, &key.verifying_key().to_bytes(), now, "device-b"),
            Err(RelayGrantError::UnsupportedVersion {
                found: RELAY_GRANT_VERSION + 1,
                expected: RELAY_GRANT_VERSION,
            })
        );
    }

    #[test]
    fn boundary_at_exactly_not_before_and_exactly_expires_at_is_accepted() {
        let key = service_key();
        let now = 1_000_000;
        let grant = valid_grant(&key, now);
        assert_eq!(
            verify_relay_grant(
                &grant,
                &key.verifying_key().to_bytes(),
                grant.not_before_unix,
                "device-b"
            ),
            Ok(())
        );
        assert_eq!(
            verify_relay_grant(
                &grant,
                &key.verifying_key().to_bytes(),
                grant.expires_at_unix,
                "device-b"
            ),
            Ok(())
        );
    }
}

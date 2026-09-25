#![cfg(test)]

use super::*;

/// The encode and decode halves have to be exact inverses, because one
/// runs on what this device presents and the other on what it accepts.
#[test]
fn an_spki_this_device_emits_decodes_back_to_the_same_key() {
    let device = DeviceSigningKeyPair::generate();
    let spki = ed25519_spki(&device.public_bytes());
    assert_eq!(spki.len(), ED25519_SPKI_LEN);
    assert_eq!(ed25519_key_from_spki(&spki), Some(device.public_bytes()));
}

/// Every one of these arrives from an unauthenticated peer, so the
/// requirement is `None` rather than a panic -- a truncated prefix in
/// particular is what a naive fixed-offset slice would fault on.
#[test]
fn malformed_subject_public_key_info_is_rejected_without_panicking() {
    let good = ed25519_spki(&[7u8; 32]);

    assert_eq!(ed25519_key_from_spki(&[]), None, "empty");
    assert_eq!(ed25519_key_from_spki(&good[..5]), None, "truncated inside the prefix");
    assert_eq!(ed25519_key_from_spki(&good[..ED25519_SPKI_LEN - 1]), None, "short key");

    let mut long = good.clone();
    long.push(0);
    assert_eq!(ed25519_key_from_spki(&long), None, "trailing bytes");

    let mut wrong_oid = good.clone();
    wrong_oid[8] = 0x71;
    assert_eq!(ed25519_key_from_spki(&wrong_oid), None, "a different algorithm identifier");
}

/// The identity a peer receives and the key that signs the transcript
/// have to be the same key. Disagreement between them would fail only at
/// the peer, during a handshake, for a reason nothing local reports.
///
/// `CertifiedKey::keys_match` is deliberately not used: it parses the
/// first entry as an X.509 certificate, which under RFC 7250 it is not.
#[test]
fn the_presented_public_key_matches_the_key_that_signs() {
    let device = DeviceSigningKeyPair::generate();
    let certified = device_certified_key(&device);

    let presented = certified.end_entity_cert().expect("an identity is present");
    assert_eq!(
        ed25519_key_from_spki(presented.as_ref()),
        Some(device.public_bytes()),
        "the key a peer is shown"
    );
    let advertised = certified.key.public_key().expect("the signing key exposes its SPKI");
    assert_eq!(advertised.as_ref(), presented.as_ref(), "the key that signs");
}

/// Only Ed25519, and specifically not "the first thing offered".
#[test]
fn no_scheme_other_than_ed25519_is_accepted() {
    let device = DeviceSigningKeyPair::generate();
    let key = DeviceSigningIdentity {
        signing: device.signing.clone(),
        spki: ed25519_spki(&device.public_bytes()),
    };

    assert!(key.choose_scheme(&[SignatureScheme::RSA_PSS_SHA256]).is_none());
    assert!(key.choose_scheme(&[]).is_none());
    let chosen = key
        .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256, SignatureScheme::ED25519])
        .expect("Ed25519 was on offer");
    assert_eq!(chosen.scheme(), SignatureScheme::ED25519);
}

/// The signature the TLS layer will hand to a peer must verify under the
/// public key this device advertises.
#[test]
fn a_produced_signature_verifies_under_the_advertised_key() {
    use ed25519_dalek::Verifier as _;

    let device = DeviceSigningKeyPair::generate();
    let key = DeviceSigningIdentity {
        signing: device.signing.clone(),
        spki: ed25519_spki(&device.public_bytes()),
    };
    let signer = key.choose_scheme(&[SignatureScheme::ED25519]).expect("Ed25519 signer");

    let signature = signer.sign(b"a transcript stand-in").expect("sign");
    let signature = ed25519_dalek::Signature::from_slice(&signature).expect("64-byte signature");
    assert!(device.verifying.verify(b"a transcript stand-in", &signature).is_ok());
}

/// The membership test itself, in both directions and with the empty set
/// included, without needing a handshake to reach it.
#[test]
fn only_pinned_keys_are_accepted_by_either_verifier() {
    let provider = provider();
    let pinned = DeviceSigningKeyPair::generate();
    let stranger = DeviceSigningKeyPair::generate();

    let verifier = PinnedPeerKeys::new([pinned.public_bytes()], &provider);
    let good = CertificateDer::from(ed25519_spki(&pinned.public_bytes()));
    let bad = CertificateDer::from(ed25519_spki(&stranger.public_bytes()));

    assert!(verifier.accept(&good, &[]).is_ok());
    assert!(verifier.accept(&bad, &[]).is_err());
    // A pinned key with anything appended to it is still a refusal: the
    // profile is one key, alone.
    assert!(verifier.accept(&good, std::slice::from_ref(&bad)).is_err());

    let refuses_everyone = PinnedPeerKeys::new([], &provider);
    assert!(refuses_everyone.accept(&good, &[]).is_err(), "an empty set must fail closed");
}

/// The membership test reads the live set, not a copy taken when the
/// verifier was built. Without this the whole point of the shared set is
/// lost: `quic_server_config` would still be answering with whatever the
/// netmap said at endpoint-construction time.
///
/// The handshake-level counterpart -- a key removed from a *running*
/// endpoint's set being refused on the next connection -- is in
/// `tests/quic_peer_identity.rs`; this one pins the decision itself.
#[test]
fn the_verifier_reads_the_live_set_rather_than_a_snapshot() {
    let provider = provider();
    let peer = DeviceSigningKeyPair::generate();
    let presented = CertificateDer::from(ed25519_spki(&peer.public_bytes()));

    let authorized = AuthorizedPeerKeys::new();
    let verifier = PinnedPeerKeys::with_live_set(authorized.clone(), &provider);
    assert!(verifier.accept(&presented, &[]).is_err(), "nobody authorized yet");

    assert!(authorized.authorize(peer.public_bytes()), "newly added");
    assert!(verifier.accept(&presented, &[]).is_ok(), "authorized after construction");

    assert!(authorized.revoke(&peer.public_bytes()), "was authorized");
    assert!(verifier.accept(&presented, &[]).is_err(), "refused once revoked");

    // A whole-set replacement is how a netmap push lands, and it has to
    // move membership in both directions at once.
    let other = DeviceSigningKeyPair::generate();
    let _ = authorized.replace([peer.public_bytes(), other.public_bytes()]);
    assert!(verifier.accept(&presented, &[]).is_ok(), "restored by a replacement");
    // The replacement must also REPORT what it dropped: a caller that
    // only learned the new membership could not finish revoking the
    // peers this removed.
    let removed = authorized.replace([other.public_bytes()]);
    assert_eq!(removed, vec![peer.public_bytes()], "a replacement must report what it drops");
    assert!(verifier.accept(&presented, &[]).is_err(), "dropped by a replacement");

    // And an emptying replacement still fails closed, which is the state
    // a device with no peers left should be in.
    assert_eq!(authorized.replace([]), vec![other.public_bytes()]);
    assert!(authorized.is_empty());
    assert!(verifier.accept(&presented, &[]).is_err(), "an emptied set must fail closed");
}

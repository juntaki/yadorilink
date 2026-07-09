use boringtun::x25519::{PublicKey, StaticSecret};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Computes this client's proof-of-possession MAC for a relay registration
/// challenge. Returns `None` if the resulting client/server shared secret
/// is non-contributory (security hardening): X25519 has a small set of low-order
/// points whose Diffie-Hellman output is a known, fixed value (e.g.
/// all-zeros) regardless of the other side's secret, so a MAC computed
/// from it would prove nothing. `verify_proof` performs the same check on
/// the server side; checking it here too means a client never wastes a
/// round trip signing a proof the server is guaranteed to reject, and it
/// protects a legitimate client against a malicious/buggy relay handing
/// out a degenerate challenge key.
pub fn proof_mac(
    client_secret: &StaticSecret,
    server_public: &PublicKey,
    nonce: &[u8],
) -> Option<Vec<u8>> {
    let shared = client_secret.diffie_hellman(server_public);
    if !shared.was_contributory() {
        return None;
    }
    Some(mac(shared.as_bytes(), nonce))
}

/// Verifies a relay registration proof-of-possession.
///
/// security hardening: rejects a non-contributory (low-order) client public key
/// *before* verifying the MAC. Without this check, a client registering
/// such a key gets a known all-zeros Diffie-Hellman shared secret and can
/// compute `HMAC(all-zeros, nonce)` — a valid-looking proof — without ever
/// possessing a private key at all.
pub fn verify_proof(
    client_public: &PublicKey,
    server_secret: &StaticSecret,
    nonce: &[u8],
    proof: &[u8],
) -> bool {
    let shared = server_secret.diffie_hellman(client_public);
    if !shared.was_contributory() {
        return false;
    }
    let Ok(mut mac) = HmacSha256::new_from_slice(shared.as_bytes()) else {
        return false;
    };
    mac.update(nonce);
    mac.verify_slice(proof).is_ok()
}

fn mac(key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any size");
    mac.update(nonce);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_verifies_only_for_matching_keypair_and_nonce() {
        let client_secret = StaticSecret::from([1u8; 32]);
        let client_public = PublicKey::from(&client_secret);
        let server_secret = StaticSecret::from([2u8; 32]);
        let server_public = PublicKey::from(&server_secret);
        let nonce = [3u8; 32];

        let proof = proof_mac(&client_secret, &server_public, &nonce)
            .expect("a genuine keypair produces a contributory shared secret");

        assert!(verify_proof(&client_public, &server_secret, &nonce, &proof));
        assert!(!verify_proof(&client_public, &server_secret, &[4u8; 32], &proof));
    }

    /// security hardening (the relevant behavior): a client registering the all-zeros X25519
    /// public key — a well-known low-order (non-contributory) point —
    /// gets a known all-zeros Diffie-Hellman shared secret independent of
    /// the server's actual secret key, so it could otherwise compute a
    /// valid-looking `HMAC(all-zeros, nonce)` proof without ever
    /// possessing a private key. `verify_proof` must reject it before MAC
    /// verification even runs.
    #[test]
    fn verify_proof_rejects_low_order_client_key() {
        let server_secret = StaticSecret::from([2u8; 32]);
        let nonce = [3u8; 32];

        let low_order_client_public = PublicKey::from([0u8; 32]);
        assert!(
            !server_secret.diffie_hellman(&low_order_client_public).was_contributory(),
            "test precondition: the all-zeros point must be non-contributory"
        );

        // The "proof" here is exactly what an attacker who knows the
        // shared secret is all-zeros could compute without any private
        // key — even this must not verify.
        let mut forged = HmacSha256::new_from_slice(&[0u8; 32]).unwrap();
        forged.update(&nonce);
        let forged_proof = forged.finalize().into_bytes().to_vec();

        assert!(!verify_proof(&low_order_client_public, &server_secret, &nonce, &forged_proof));
    }

    /// The client-side counterpart: `proof_mac` must refuse to produce a
    /// proof at all when the shared secret it would sign over is
    /// non-contributory, matching `verify_proof`'s check.
    #[test]
    fn proof_mac_refuses_low_order_server_key() {
        let client_secret = StaticSecret::from([1u8; 32]);
        let low_order_server_public = PublicKey::from([0u8; 32]);
        let nonce = [3u8; 32];

        assert!(proof_mac(&client_secret, &low_order_server_public, &nonce).is_none());
    }
}

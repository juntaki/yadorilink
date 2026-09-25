#![cfg(test)]

//! Test-only helpers for signing a manifest with a throwaway keypair
//! instead of `TRUSTED_KEYS`'s real (dev-placeholder) key — used by
//! this module's own tests and by `policy`/`manager` tests elsewhere
//! in this crate that need a realistic signed-envelope fixture.
use super::*;
use ed25519_dalek::{Signer, SigningKey};

pub const TEST_KEY_ID: &str = "test-key-1";

pub fn test_signing_key() -> SigningKey {
    // Fixed, obviously-not-secret seed: deterministic test fixtures,
    // never used outside `#[cfg(test)]`.
    SigningKey::from_bytes(&[7u8; 32])
}

pub fn test_trusted_keys() -> Vec<(String, [u8; 32])> {
    vec![(TEST_KEY_ID.to_string(), test_signing_key().verifying_key().to_bytes())]
}

pub fn sign_manifest(manifest: &UpdateManifest) -> SignedManifestEnvelope {
    let manifest_json = serde_json::to_string(manifest).unwrap();
    let signing_key = test_signing_key();
    let signature = signing_key.sign(manifest_json.as_bytes());
    use base64::Engine;
    SignedManifestEnvelope {
        key_id: TEST_KEY_ID.to_string(),
        manifest_json,
        signature_base64: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
    }
}

/// Turns `test_trusted_keys()`'s `(String, [u8; 32])` pairs into real
/// `TrustedKey`s a verifier can use. `TrustedKey.public_key_hex` is
/// `&'static str`; leaking the hex string is fine for a
/// `#[cfg(test)]`-only helper that runs a bounded number of times per
/// test binary.
pub fn trusted_keys_hex(keys: &[(String, [u8; 32])]) -> Vec<TrustedKey> {
    keys.iter()
        .map(|(id, pk)| TrustedKey {
            key_id: Box::leak(id.clone().into_boxed_str()),
            public_key_hex: Box::leak(hex::encode(pk).into_boxed_str()),
        })
        .collect()
}

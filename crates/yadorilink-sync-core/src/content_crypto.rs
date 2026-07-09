//! The group content-encryption key
//! (`K_g`), block/path AEAD, and wrapped-key distribution to trusted
//! devices.
//!
//! This module is the *only* place `K_g` is generated, wrapped, unwrapped,
//! or used to encrypt/decrypt bytes. `peer_session.rs` calls into it at the
//! two chokepoints (block send/receive,
//! index-entry send/receive) but never manipulates key material itself.
//! Per the encrypted-peer spec's "Group
//! Content Key Stays On Trusted Devices" requirement: `K_g` and its wrapped
//! forms are produced/consumed only by trusted devices, are never sent to
//! the coordination plane (this module has zero knowledge of the
//! coordination plane or any RPC — it is pure, in-memory cryptography), and
//! `peer_session.rs` is responsible for never invoking the wrap path
//! against a peer flagged storage-only (see `PeerSyncSession::
//! live_storage_only_flags` and `send_wrapped_group_key_if_due`).
//!
//! ## Algorithm choices
//! - AEAD: XChaCha20-Poly1305 — chosen
//!   over AES-256-GCM-SIV specifically because its 24-byte extended nonce
//!   gives comfortable collision margin for the *deterministic*
//!   convergent-mode nonce (the relevant behavior: `nonce = KDF(K_g, h)`), which by
//!   construction repeats across peers/devices that independently encrypt
//!   the same block — a 12-byte GCM-style nonce would carry meaningfully
//!   more birthday-bound risk under that reuse-by-design scheme.
//! - KDF: a single-step HMAC-SHA256(key, info) — deliberately not a full
//!   two-step HKDF-extract-then-expand. Every input this module feeds the
//!   KDF (a 32-byte `K_g`, or an X25519 Diffie-Hellman shared secret) is
//!   already uniformly-random, full-entropy key material, so the
//!   "extract" step (meant to concentrate entropy out of a *non-uniform*
//!   source, e.g. a raw DH output before this codebase's specific choice
//!   of curve) buys nothing extra here; one HMAC call as a keyed PRF is
//!   the standard simplification in that case and avoids an additional
//!   `hkdf` crate dependency for a single call site.
//! - Key wrapping: an authenticated ECIES-style construction — X25519
//!   ephemeral-static *and* static-static Diffie-Hellman
//!   (mirroring the ephemeral+static combination of an X3DH-style
//!   handshake, minus prekeys) so the recipient can verify the wrap was
//!   produced by someone holding the claimed sender's real identity secret
//!   (the "authenticated" part — a bare ephemeral-static ECIES wrap alone
//!   would let anyone who merely knows the recipient's public key produce
//!   a wrap that *looks* valid, with no sender authentication at all).

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key as ChaChaKey, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// The nonce length XChaCha20-Poly1305 uses (24 bytes) — exported so callers
/// (wire (de)serialization in `peer_session.rs`) don't need to depend on
/// `chacha20poly1305` directly just to know this constant.
pub const NONCE_LEN: usize = 24;
/// The raw key length for `GroupKey` and any derived AEAD/wrap key.
pub const KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum ContentCryptoError {
    #[error("AEAD encryption failed")]
    Encrypt,
    /// Deliberately doesn't echo any detail about *why* (wrong key, tampered
    /// ciphertext, wrong nonce length) — see the encrypted-peer spec's "A
    /// malicious storage peer returning wrong bytes is detected" scenario;
    /// the caller (`peer_session.rs`) reacts to any decrypt failure
    /// identically (reject and re-fetch), so there is no information a
    /// finer-grained error would let a legitimate caller act on, and
    /// finer-grained errors are exactly what you don't want to hand back
    /// toward a potentially-malicious peer's inputs.
    #[error("AEAD decryption failed (tampered ciphertext, wrong key, or wrong nonce)")]
    Decrypt,
    #[error("nonce must be exactly {NONCE_LEN} bytes, got {0}")]
    BadNonceLen(usize),
    #[error("key must be exactly {KEY_LEN} bytes, got {0}")]
    BadKeyLen(usize),
}

/// A folder group's symmetric content-encryption key ("Group
/// content key", `K_g`). Lives only on trusted devices — see this module's
/// doc comment. Zeroized on drop; deliberately has no `Debug`/`Display`
/// impl that would print the raw bytes (the derived `Debug` below only
/// prints a fixed placeholder).
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct GroupKey([u8; KEY_LEN]);

impl std::fmt::Debug for GroupKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GroupKey(..)")
    }
}

impl GroupKey {
    /// generates a fresh, uniformly-random `K_g`. Also the
    /// 's key rotation calls to mint `K_g'` — rotation is
    /// "generate a new key the same way as the first one, then re-wrap and
    /// re-encrypt with it," not a distinct code path.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        rand::fill(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.0
    }

    fn chacha_key(&self) -> &ChaChaKey {
        ChaChaKey::from_slice(&self.0)
    }
}

/// `nonce = KDF(K_g, h)` — deterministic, so two trusted devices
/// (or the same device on two occasions) encrypting the same plaintext
/// block under the same group key produce byte-identical ciphertext,
/// letting an untrusted storage peer dedup on ciphertext hash alone
/// (the convergent-encryption trade-off; see `encrypt_block`'s
/// `convergent` parameter for the per-group opt-out).
pub fn derive_block_nonce(key: &GroupKey, plaintext_hash: &[u8]) -> [u8; NONCE_LEN] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key.0).expect("HMAC accepts any key length");
    mac.update(b"yadorilink-block-nonce-v1");
    mac.update(plaintext_hash);
    let digest = mac.finalize().into_bytes();
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&digest[..NONCE_LEN]);
    nonce
}

/// a fresh random nonce, used instead of `derive_block_nonce` when
/// a group has convergent encryption disabled (so identical plaintext
/// blocks get *distinct* ciphertext and don't cross-dedup on the untrusted
/// peer — see `encrypt_block`), and also used for encrypting index path/
/// metadata entries (the relevant behavior), which have no dedup requirement to justify
/// a deterministic nonce and should not leak equal-path correlation the way
/// deterministic block nonces intentionally trade off for dedup.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::fill(&mut nonce);
    nonce
}

fn aead_encrypt(
    key: &GroupKey,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, ContentCryptoError> {
    let cipher = XChaCha20Poly1305::new(key.chacha_key());
    cipher.encrypt(XNonce::from_slice(nonce), plaintext).map_err(|_| ContentCryptoError::Encrypt)
}

fn aead_decrypt(
    key: &GroupKey,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ContentCryptoError> {
    if nonce.len() != NONCE_LEN {
        return Err(ContentCryptoError::BadNonceLen(nonce.len()));
    }
    let cipher = XChaCha20Poly1305::new(key.chacha_key());
    cipher.decrypt(XNonce::from_slice(nonce), ciphertext).map_err(|_| ContentCryptoError::Decrypt)
}

/// A block encrypted for an untrusted storage peer: the nonce (needed to
/// decrypt — always sent alongside the ciphertext, never secret) and the
/// AEAD ciphertext+tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedBlock {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl EncryptedBlock {
    /// the untrusted peer addresses/dedups this block by
    /// `H(ciphertext)` (SHA-256, matching the plaintext content-hash
    /// algorithm this codebase already uses everywhere else — see
    /// `peer_session::block_data_matches`), never by the plaintext hash.
    pub fn ciphertext_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.ciphertext);
        hasher.finalize().into()
    }
}

/// encrypts one plaintext block for storage on an untrusted peer.
/// `plaintext_hash` is `h` — this block's plaintext content-hash identity,
/// exactly as already computed by `peer_session::block_data_matches`'s
/// caller.
///
/// `convergent = true` (the default, the relevant behavior) derives the nonce
/// deterministically from `(K_g, h)`, so identical plaintext anywhere in
/// the group produces identical ciphertext and dedups on the untrusted
/// peer — a disclosed equal-block-correlation trade-off.
/// `convergent = false` (the relevant behavior, a per-group opt-out for higher-
/// sensitivity groups) uses a fresh random nonce every call instead, so the
/// same plaintext block encrypted twice produces two unrelated ciphertexts
/// and the untrusted peer cannot tell they're equal.
pub fn encrypt_block(
    key: &GroupKey,
    plaintext_hash: &[u8],
    plaintext: &[u8],
    convergent: bool,
) -> Result<EncryptedBlock, ContentCryptoError> {
    let nonce = if convergent { derive_block_nonce(key, plaintext_hash) } else { random_nonce() };
    let ciphertext = aead_encrypt(key, &nonce, plaintext)?;
    Ok(EncryptedBlock { nonce, ciphertext })
}

/// decrypts a block fetched (by ciphertext hash) from an
/// untrusted peer. Returns `Err` on any AEAD authentication failure —
/// tampered ciphertext, wrong nonce, or a peer that returned some other
/// block's ciphertext wholesale. `peer_session.rs` treats this identically
/// to a plaintext-hash mismatch: reject, don't persist, re-fetch from
/// another source (see the encrypted-peer spec's "A malicious storage peer
/// returning wrong bytes is detected" scenario). Callers MUST additionally
/// re-check `H(plaintext) == h` after a successful decrypt — AEAD
/// authentication alone only proves "this ciphertext was produced with
/// `K_g` and this nonce," not "this is the block I actually asked for";
/// under convergent encryption in particular, a peer could return a
/// *different, validly-encrypted* block's ciphertext, which decrypts
/// cleanly under its own correct nonce/key but is the wrong content — the
/// plaintext-hash re-check is what catches that substitution.
pub fn decrypt_block(
    key: &GroupKey,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ContentCryptoError> {
    aead_decrypt(key, nonce, ciphertext)
}

/// encrypts index metadata (a file's path and its ordered list of
/// plaintext block hashes — see `peer_session::EncryptedFileMeta`) for
/// inclusion in an encrypted index entry. Always uses a random nonce
/// (returned alongside the ciphertext) — this data has no dedup
/// requirement, and a deterministic nonce here would additionally leak
/// "these two entries have the exact same encrypted metadata," an
/// unnecessary correlation with no benefit here.
pub fn encrypt_metadata(
    key: &GroupKey,
    plaintext: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), ContentCryptoError> {
    let nonce = random_nonce();
    let ciphertext = aead_encrypt(key, &nonce, plaintext)?;
    Ok((nonce, ciphertext))
}

/// The decrypt counterpart to `encrypt_metadata`, used by a trusted device
/// that holds `K_g` to recover a file's real path and block-hash list from
/// an `EncryptedFileEntry` it received (whether directly from the
/// encrypting device, or relayed unchanged through an untrusted storage
/// peer that cannot itself decrypt it — acting purely as a
/// relay).
pub fn decrypt_metadata(
    key: &GroupKey,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ContentCryptoError> {
    aead_decrypt(key, nonce, ciphertext)
}

/// a wrapped copy of `K_g`, addressed to one recipient trusted
/// device by their X25519 identity public key. Everything in this struct
/// is safe to transit via peers (never the coordination plane)
/// — it reveals nothing about `K_g` without the recipient's
/// identity secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedGroupKey {
    /// The wrapping device's own X25519 identity public key — the
    /// recipient needs this to recompute the static-static half of the
    /// shared secret below (see this module's doc comment on why wrapping
    /// is authenticated, not bare ephemeral-static ECIES).
    pub sender_identity_public: [u8; 32],
    /// A fresh ephemeral X25519 public key, generated per wrap call.
    pub ephemeral_public: [u8; 32],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

fn derive_wrap_key(dh_ephemeral: &[u8; 32], dh_static: &[u8; 32]) -> GroupKey {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(dh_ephemeral).expect("HMAC accepts any key length");
    mac.update(dh_static);
    mac.update(b"yadorilink-group-key-wrap-v1");
    let digest = mac.finalize().into_bytes();
    let mut bytes = [0u8; KEY_LEN];
    bytes.copy_from_slice(&digest[..KEY_LEN]);
    GroupKey(bytes)
}

/// wraps `K_g` to one trusted device's identity key. Uses both an
/// ephemeral-static and a static-static X25519 Diffie-Hellman (see this
/// module's doc comment) so `unwrap_group_key` implicitly authenticates
/// that whoever produced this wrap held `sender_identity_secret` — a bare
/// ephemeral-static ECIES wrap would let anyone who merely knows the
/// recipient's public key produce a wrap that decrypts "successfully" but
/// was not actually sent by a real trusted device.
pub fn wrap_group_key(
    key: &GroupKey,
    sender_identity_secret: &StaticSecret,
    recipient_identity_public: &X25519PublicKey,
) -> Result<WrappedGroupKey, ContentCryptoError> {
    let ephemeral_secret = EphemeralSecret::random();
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let dh_ephemeral = ephemeral_secret.diffie_hellman(recipient_identity_public);
    let dh_static = sender_identity_secret.diffie_hellman(recipient_identity_public);
    let wrap_key = derive_wrap_key(dh_ephemeral.as_bytes(), dh_static.as_bytes());
    let nonce = random_nonce();
    let ciphertext = aead_encrypt(&wrap_key, &nonce, &key.0)?;
    Ok(WrappedGroupKey {
        sender_identity_public: X25519PublicKey::from(sender_identity_secret).to_bytes(),
        ephemeral_public: ephemeral_public.to_bytes(),
        nonce,
        ciphertext,
    })
}

/// The unwrap counterpart to `wrap_group_key`, called by the recipient
/// trusted device with its own identity secret.
pub fn unwrap_group_key(
    wrapped: &WrappedGroupKey,
    recipient_identity_secret: &StaticSecret,
) -> Result<GroupKey, ContentCryptoError> {
    let ephemeral_public = X25519PublicKey::from(wrapped.ephemeral_public);
    let sender_identity_public = X25519PublicKey::from(wrapped.sender_identity_public);
    let dh_ephemeral = recipient_identity_secret.diffie_hellman(&ephemeral_public);
    let dh_static = recipient_identity_secret.diffie_hellman(&sender_identity_public);
    let wrap_key = derive_wrap_key(dh_ephemeral.as_bytes(), dh_static.as_bytes());
    if wrapped.nonce.len() != NONCE_LEN {
        return Err(ContentCryptoError::BadNonceLen(wrapped.nonce.len()));
    }
    let plaintext = aead_decrypt(&wrap_key, &wrapped.nonce, &wrapped.ciphertext)?;
    if plaintext.len() != KEY_LEN {
        return Err(ContentCryptoError::BadKeyLen(plaintext.len()));
    }
    let mut bytes = [0u8; KEY_LEN];
    bytes.copy_from_slice(&plaintext);
    Ok(GroupKey(bytes))
}

/// mints a fresh `K_g'` and wraps it to every remaining trusted
/// device in one call — the composition a revocation handler runs
/// (generate once, re-wrap per remaining recipient). Deliberately returns
/// the new key *and* the per-recipient wraps together rather than making
/// the caller call `GroupKey::generate()` and `wrap_group_key()`
/// separately, since both halves of a rotation must always happen
/// together (a rotation that mints a new key but forgets to re-wrap it to
/// some remaining device would silently strand that device without
/// access — this signature makes that split harder to accidentally do).
///
/// **Documented, accepted cost:** this only mints and
/// distributes the new key. It does not re-encrypt any block already
/// stored under the old key — those ciphertexts remain decryptable by
/// anyone who held `K_g` (including a now-revoked device, if it retained a
/// copy of ciphertext it fetched before revocation) until they are
/// re-uploaded (re-encrypted fresh under `K_g'` the next time their
/// content is synced) or garbage-collected from the untrusted peer. Only
/// *new* writes after rotation are guaranteed to use `K_g'`.
pub fn rotate_and_rewrap(
    sender_identity_secret: &StaticSecret,
    remaining_recipients: &[X25519PublicKey],
) -> Result<(GroupKey, Vec<WrappedGroupKey>), ContentCryptoError> {
    let new_key = GroupKey::generate();
    let wraps = remaining_recipients
        .iter()
        .map(|recipient| wrap_group_key(&new_key, sender_identity_secret, recipient))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((new_key, wraps))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> GroupKey {
        GroupKey::generate()
    }

    #[test]
    fn convergent_encryption_of_the_same_plaintext_produces_identical_ciphertext() {
        let k = key();
        let h = Sha256::digest(b"same content").to_vec();
        let a = encrypt_block(&k, &h, b"same content", true).unwrap();
        let b = encrypt_block(&k, &h, b"same content", true).unwrap();
        assert_eq!(a.nonce, b.nonce);
        assert_eq!(a.ciphertext, b.ciphertext);
        assert_eq!(a.ciphertext_hash(), b.ciphertext_hash());
    }

    /// convergent mode dedups identical plaintext across
    /// independent encryption calls (different "devices"/occasions using
    /// the same group key) — the untrusted peer sees the same ciphertext
    /// hash both times and can store one copy.
    #[test]
    fn convergent_dedup_holds_across_independently_derived_keys_of_the_same_bytes() {
        let k = GroupKey::from_bytes([7u8; 32]);
        let h = Sha256::digest(b"shared block").to_vec();
        let first = encrypt_block(&k, &h, b"shared block", true).unwrap();
        let second = encrypt_block(&k, &h, b"shared block", true).unwrap();
        assert_eq!(first.ciphertext_hash(), second.ciphertext_hash());
    }

    /// (the disable-convergence half): with convergence disabled,
    /// two encryptions of identical plaintext under the identical key
    /// produce *distinct* ciphertext, so an untrusted peer under this mode
    /// cannot correlate them.
    #[test]
    fn non_convergent_encryption_of_the_same_plaintext_produces_distinct_ciphertext() {
        let k = key();
        let h = Sha256::digest(b"same content").to_vec();
        let a = encrypt_block(&k, &h, b"same content", false).unwrap();
        let b = encrypt_block(&k, &h, b"same content", false).unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_ne!(a.ciphertext_hash(), b.ciphertext_hash());
    }

    #[test]
    fn decrypting_with_the_right_key_and_nonce_recovers_the_plaintext() {
        let k = key();
        let h = Sha256::digest(b"round trip").to_vec();
        let enc = encrypt_block(&k, &h, b"round trip", true).unwrap();
        let dec = decrypt_block(&k, &enc.nonce, &enc.ciphertext).unwrap();
        assert_eq!(dec, b"round trip");
    }

    /// The AEAD-authentication half a bit-flipped ciphertext
    /// (as a malicious storage peer might return) fails to decrypt at all,
    /// rather than silently producing garbage plaintext.
    #[test]
    fn tampered_ciphertext_fails_to_decrypt() {
        let k = key();
        let h = Sha256::digest(b"integrity").to_vec();
        let mut enc = encrypt_block(&k, &h, b"integrity", true).unwrap();
        let last = enc.ciphertext.len() - 1;
        enc.ciphertext[last] ^= 0x01;
        assert!(decrypt_block(&k, &enc.nonce, &enc.ciphertext).is_err());
    }

    /// The plaintext-hash-substitution half a malicious peer
    /// that returns a *different*, validly-encrypted block (correctly
    /// AEAD-authenticated under its own correct nonce) decrypts cleanly —
    /// AEAD alone cannot catch this, which is exactly why
    /// `decrypt_block`'s doc comment requires callers to separately
    /// re-verify `H(plaintext) == h` afterward (done in `peer_session.rs`,
    /// not in this module).
    #[test]
    fn a_different_validly_encrypted_block_decrypts_but_is_the_wrong_content() {
        let k = key();
        let h_wanted = Sha256::digest(b"wanted content").to_vec();
        let h_other = Sha256::digest(b"other content").to_vec();
        let wanted_ct_hash =
            encrypt_block(&k, &h_wanted, b"wanted content", true).unwrap().ciphertext_hash();
        let substituted = encrypt_block(&k, &h_other, b"other content", true).unwrap();
        // A malicious peer serves `substituted` when asked for `wanted_ct_hash`'s
        // content (simulated directly here, without a fetch round trip).
        assert_ne!(substituted.ciphertext_hash().as_slice(), wanted_ct_hash.as_slice());
        let decrypted = decrypt_block(&k, &substituted.nonce, &substituted.ciphertext).unwrap();
        // Decrypts fine (it's a validly-encrypted block)...
        assert_eq!(decrypted, b"other content");
        // ...but its plaintext hash does not match what was actually requested.
        assert_ne!(Sha256::digest(&decrypted).to_vec(), h_wanted);
    }

    #[test]
    fn wrap_and_unwrap_round_trips_the_group_key() {
        let sender_secret = StaticSecret::random();
        let recipient_secret = StaticSecret::random();
        let recipient_public = X25519PublicKey::from(&recipient_secret);
        let k = key();
        let wrapped = wrap_group_key(&k, &sender_secret, &recipient_public).unwrap();
        let unwrapped = unwrap_group_key(&wrapped, &recipient_secret).unwrap();
        assert_eq!(k, unwrapped);
    }

    /// groundwork: the wrapped form reveals nothing recoverable
    /// without the recipient's identity secret — a third party (or a
    /// storage-only peer that merely relays the bytes) holding only the
    /// wrapped struct cannot unwrap it.
    #[test]
    fn unwrap_fails_for_the_wrong_recipient() {
        let sender_secret = StaticSecret::random();
        let recipient_secret = StaticSecret::random();
        let recipient_public = X25519PublicKey::from(&recipient_secret);
        let wrong_secret = StaticSecret::random();
        let k = key();
        let wrapped = wrap_group_key(&k, &sender_secret, &recipient_public).unwrap();
        assert!(unwrap_group_key(&wrapped, &wrong_secret).is_err());
    }

    /// The wrap is authenticated (this module's doc comment): tampering
    /// with the claimed sender identity in transit breaks the static-static
    /// DH the recipient recomputes, so unwrap fails rather than silently
    /// accepting a wrap claiming to be from a different device.
    #[test]
    fn unwrap_fails_if_the_claimed_sender_identity_is_substituted() {
        let sender_secret = StaticSecret::random();
        let impostor_secret = StaticSecret::random();
        let recipient_secret = StaticSecret::random();
        let recipient_public = X25519PublicKey::from(&recipient_secret);
        let k = key();
        let mut wrapped = wrap_group_key(&k, &sender_secret, &recipient_public).unwrap();
        wrapped.sender_identity_public = X25519PublicKey::from(&impostor_secret).to_bytes();
        assert!(unwrap_group_key(&wrapped, &recipient_secret).is_err());
    }

    /// the relevant behavior: rotation mints a new key distinct from the old one and
    /// re-wraps it to every remaining recipient; each remaining recipient
    /// can unwrap and gets the *same* new key.
    #[test]
    fn rotation_produces_a_new_key_and_rewraps_to_all_remaining_recipients() {
        let sender_secret = StaticSecret::random();
        let old_key = key();
        let remaining_secrets: Vec<StaticSecret> =
            (0..3).map(|_| StaticSecret::random()).collect();
        let remaining_publics: Vec<X25519PublicKey> =
            remaining_secrets.iter().map(X25519PublicKey::from).collect();

        let (new_key, wraps) = rotate_and_rewrap(&sender_secret, &remaining_publics).unwrap();

        assert_ne!(new_key, old_key);
        assert_eq!(wraps.len(), remaining_secrets.len());
        for (secret, wrapped) in remaining_secrets.iter().zip(wraps.iter()) {
            let unwrapped = unwrap_group_key(wrapped, secret).unwrap();
            assert_eq!(unwrapped, new_key);
        }

        // Old ciphertext under the old key stays decryptable by whoever has
        // the old key (documented, accepted cost — see `rotate_and_rewrap`'s
        // doc comment) — rotation does not retroactively invalidate it.
        let h = Sha256::digest(b"pre-rotation content").to_vec();
        let old_enc = encrypt_block(&old_key, &h, b"pre-rotation content", true).unwrap();
        assert!(decrypt_block(&old_key, &old_enc.nonce, &old_enc.ciphertext).is_ok());
        // ...but the new key cannot decrypt it (rotation is a real key
        // change, not a no-op).
        assert!(decrypt_block(&new_key, &old_enc.nonce, &old_enc.ciphertext).is_err());
    }
}

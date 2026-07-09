//! Untrusted-side ciphertext block store (`encrypted-peer` capability,
//! `local-storage` spec: "storage of opaque ciphertext blocks keyed by
//! ciphertext hash on an untrusted peer, distinct from a trusted device's
//! plaintext store").
//!
//! [`CiphertextBlockStore`] deliberately does **not** implement the
//! [`BlockStore`](crate::BlockStore) trait, and deliberately has no
//! inherent method that accepts or returns a plaintext content hash (the
//! [`ContentHash`] this crate's plaintext side uses to address blocks by
//! `H(plaintext)`). Every method on this type only ever handles opaque
//! ciphertext bytes and the hash *of that ciphertext* — there is no type or
//! parameter anywhere on this struct's public API through which a plaintext
//! block, a plaintext hash, or anything that implies plaintext awareness
//! could pass. That is a deliberate structural argument, not just a
//! convention: a caller cannot accidentally hand this store plaintext
//! through the same interface the trusted plaintext `FsBlockStore` uses
//! (there is no shared trait object surface), and a future maintainer
//! extending this type has no existing "plaintext hash" parameter shape to
//! copy-paste a mistake from. This is what makes an untrusted storage peer
//! *structurally* incapable of ever seeing plaintext, rather than merely
//! discouraged from decrypting it.

use std::path::Path;

use crate::error::StorageError;
use crate::fs_backend::FsBlockStore;
// `BlockStore` is only used here to call through to the inner delegate's
// trait methods — `CiphertextBlockStore` itself never implements this
// trait (see the module doc comment), so this import does not create a
// plaintext-store trait-object surface on this type.
use crate::traits::BlockStore;
use crate::traits::{ContentHash, StorageUsage};

/// Content-addressed store for opaque ciphertext blocks, for use only on an
/// untrusted/storage-only peer for a folder group.
///
/// Internally this delegates all sharding, hashing, checksum-verify-on-read,
/// and disk-usage accounting to an inner [`FsBlockStore`] pointed at its own
/// storage root (never shared with a trusted device's plaintext
/// `FsBlockStore` — see [`open`](Self::open)), so the on-disk layout and
/// corruption-detection behavior match the trusted store exactly. The keys
/// stored here are `SHA-256(ciphertext)`, never `SHA-256(plaintext)`: this
/// store never receives, computes, or is told about a plaintext hash.
pub struct CiphertextBlockStore {
    inner: FsBlockStore,
}

impl CiphertextBlockStore {
    /// Opens (creating if necessary) a ciphertext block store rooted at
    /// `root`. Callers must point this at a directory dedicated to
    /// ciphertext storage — never the same root a trusted device's
    /// plaintext `FsBlockStore` uses, since the two stores' keys
    /// (ciphertext hash vs. plaintext hash) are drawn from different
    /// namespaces and must never be confused on disk.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StorageError> {
        Ok(Self { inner: FsBlockStore::new(root.as_ref().to_path_buf())? })
    }

    /// Stores `ciphertext`, returning `H(ciphertext)` (hex-encoded SHA-256).
    /// Storing bytes that hash to an already-present key is a no-op that
    /// still returns the same hash — this is exactly the content-addressed
    /// dedup the `encrypted-peer` spec's "Content-addressed dedup on
    /// ciphertext" scenario requires: two blocks that convergently encrypt
    /// to identical ciphertext (identical plaintext, same group key) are
    /// stored once here, without this store ever knowing the plaintext was
    /// identical (or existing at all).
    pub fn put_ciphertext(&self, ciphertext: &[u8]) -> Result<ContentHash, StorageError> {
        self.inner.put(ciphertext)
    }

    /// Reads back a ciphertext block by its ciphertext hash, re-verifying
    /// the checksum on every read (matching `FsBlockStore::get`'s
    /// contract): returns `StorageError::ChecksumMismatch` if the on-disk
    /// bytes don't hash to `ciphertext_hash` (corruption or tampering —
    /// self-healed the same way `FsBlockStore::get` does, by removing the
    /// bad file), and `StorageError::NotFound` if absent.
    pub fn get_ciphertext(&self, ciphertext_hash: &str) -> Result<Vec<u8>, StorageError> {
        self.inner.get(ciphertext_hash)
    }

    /// Reports whether a block with this ciphertext hash is currently
    /// stored.
    pub fn exists_ciphertext(&self, ciphertext_hash: &str) -> Result<bool, StorageError> {
        self.inner.exists(ciphertext_hash)
    }

    /// Deletes the ciphertext block stored under `ciphertext_hash`, if
    /// present. A no-op if it does not exist.
    pub fn delete_ciphertext(&self, ciphertext_hash: &str) -> Result<(), StorageError> {
        self.inner.delete(ciphertext_hash)
    }

    /// Lists stored ciphertext hashes beginning with `prefix` — a dedup
    /// verification helper (e.g. confirming only one ciphertext hash exists
    /// for a given prefix after two convergent encryptions of the same
    /// plaintext).
    pub fn list_by_prefix(&self, prefix: &str) -> Result<Vec<ContentHash>, StorageError> {
        self.inner.list_by_prefix(prefix)
    }

    /// Reports current ciphertext block-store usage (block count, total
    /// bytes).
    pub fn usage(&self) -> Result<StorageUsage, StorageError> {
        self.inner.usage()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (CiphertextBlockStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = CiphertextBlockStore::open(dir.path()).unwrap();
        (store, dir)
    }

    /// `encrypted-peer` "Content-addressed dedup on ciphertext" scenario:
    /// two "different" encrypt calls that happen to produce identical
    /// ciphertext (simulating convergent encryption of identical plaintext
    /// under the same group key) dedup to the same hash and a single file
    /// on disk. We inspect the real bytes on disk directly, not just call
    /// `get_ciphertext`, to prove there is genuinely one file — the same
    /// discipline this crate's other on-disk tests use (see
    /// `identical_content_stored_once` in `tests/fs_backend.rs`).
    #[test]
    fn identical_ciphertext_dedups_to_one_file_on_disk() {
        let (store, dir) = store();
        let ciphertext = b"convergent ciphertext bytes";

        let hash_a = store.put_ciphertext(ciphertext).unwrap();
        let hash_b = store.put_ciphertext(ciphertext).unwrap();
        assert_eq!(hash_a, hash_b);

        let mut count = 0;
        for entry in walkdir(dir.path()) {
            let name = entry.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if entry.is_file() && name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit()) {
                count += 1;
            }
        }
        assert_eq!(count, 1, "expected exactly one ciphertext block file on disk");
    }

    /// Round-trip: `get_ciphertext` returns exactly the bytes stored.
    #[test]
    fn get_ciphertext_roundtrips() {
        let (store, _dir) = store();
        let hash = store.put_ciphertext(b"opaque ciphertext blob").unwrap();
        let data = store.get_ciphertext(&hash).unwrap();
        assert_eq!(data, b"opaque ciphertext blob");
    }

    /// Mirrors `checksum_mismatch_detected_on_corruption` in
    /// `tests/fs_backend.rs`: a tampered on-disk ciphertext file is
    /// detected on read, exactly like `FsBlockStore::get`'s contract.
    #[test]
    fn tampered_ciphertext_is_detected_on_read() {
        let (store, dir) = store();
        let hash = store.put_ciphertext(b"trustworthy ciphertext").unwrap();

        let path = dir.path().join(&hash[0..2]).join(&hash[2..4]).join(&hash);
        std::fs::write(&path, b"tampered ciphertext!!!").unwrap();

        let err = store.get_ciphertext(&hash).unwrap_err();
        assert!(matches!(err, StorageError::ChecksumMismatch { .. }));
    }

    #[test]
    fn exists_and_delete_ciphertext_work() {
        let (store, _dir) = store();
        let hash = store.put_ciphertext(b"some ciphertext").unwrap();
        assert!(store.exists_ciphertext(&hash).unwrap());

        store.delete_ciphertext(&hash).unwrap();
        assert!(!store.exists_ciphertext(&hash).unwrap());
    }

    #[test]
    fn list_by_prefix_and_usage_report_stored_blocks() {
        let (store, _dir) = store();
        let hash_a = store.put_ciphertext(b"ciphertext a").unwrap();
        let _hash_b = store.put_ciphertext(b"ciphertext bbbbb").unwrap();

        let matches = store.list_by_prefix(&hash_a[0..2]).unwrap();
        assert!(matches.contains(&hash_a));

        let usage = store.usage().unwrap();
        assert_eq!(usage.block_count, 2);
        assert_eq!(usage.total_bytes, 12 + 16);
    }

    #[test]
    fn missing_ciphertext_block_is_not_found() {
        let (store, _dir) = store();
        let fake_hash = "c".repeat(64);
        let err = store.get_ciphertext(&fake_hash).unwrap_err();
        assert!(matches!(err, StorageError::NotFound(_)));
    }

    fn walkdir(root: &Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(read_dir) = std::fs::read_dir(&dir) else { continue };
            for entry in read_dir.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    out.push(path);
                }
            }
        }
        out
    }
}

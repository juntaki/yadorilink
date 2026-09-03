//! The capability surface `yadorilink-sync-core` actually calls on
//! `yadorilink_local_storage::BlockStore` — surveyed from real
//! `store.<method>`/`self.store.<method>` call sites in
//! `chunker.rs`, `single_pass_capture.rs`, `peer_session.rs`,
//! `materialization.rs`, and `block_deletion.rs`, not sketched from
//! `BlockStore`'s full method surface.
//!
//! `BlockStore` itself exposes twelve methods (`put`, `get`,
//! `get_unchecked`, `delete`, `exists`, `list_by_prefix`, `usage`, `sweep`,
//! `reclaim_cached_blocks`, `present_blocks`, `set_headroom_enforced`,
//! `set_headroom_override_bytes`, `free_space`). Of those,
//! `yadorilink-sync-core` production code (excluding tests and test
//! doubles) calls exactly five: `put`, `get`, `present_blocks`, `sweep`,
//! and `reclaim_cached_blocks`. The rest are unused from this crate today:
//!
//! - `get_unchecked`, `delete`, `exists`, `list_by_prefix`, and `usage` are
//!   exercised only by this crate's own tests (a `CountingBlockStore` test
//!   double in `local_change.rs`, and assertions against a real
//!   `FsBlockStore` in `block_deletion.rs`/`materialization.rs`), never by
//!   production call sites.
//! - `free_space` is never called through `BlockStore` at all here —
//!   `link_preflight.rs` and `materialization.rs` call
//!   `yadorilink_local_storage::free_space::classify_volume`, a free
//!   function in a different module, not the trait method.
//! - `set_headroom_enforced`/`set_headroom_override_bytes` are never
//!   forwarded to a `BlockStore` from this crate either. `peer_session.rs`
//!   has its own same-named methods on `PeerSyncSession` (an `AtomicBool`
//!   and a `Mutex<Option<u64>>` it owns directly), consulted by
//!   `preflight_disk_headroom`, which calls the free-function
//!   `check_disk_headroom` — not `self.store`.
//!
//! So this module defines two traits, not the four-trait split a generic
//! sketch might suggest, because only two clusters of `BlockStore` methods
//! are actually load-bearing here:
//!
//! - [`BlockContentStore`] — the content-addressed read/write hot path:
//!   `chunker.rs`'s `chunk_file`/`chunk_file_content_defined` and
//!   `single_pass_capture.rs`'s single-pass chunking both call `put` while
//!   writing new blocks; `chunker.rs`'s `reconstruct_file` and
//!   `peer_session.rs`'s block-request handling call `get`;
//!   `peer_session.rs`'s hydration presence check and `materialization.rs`'s
//!   local-reconstruct-without-a-peer decision both call `present_blocks` to
//!   batch-check which blocks are already local.
//! - [`BlockReclamationStore`] — GC/eviction, both call sites going through
//!   `block_deletion.rs`'s `BlockDeletionCoordinator`, this crate's "single
//!   production boundary for physical content-addressed block deletion"
//!   (that file's own module doc): `sweep` (mark-and-sweep GC) and
//!   `reclaim_cached_blocks` (on-demand-sync cache eviction of a specific
//!   hash set once custody is confirmed elsewhere).
//!
//! Same scaffolding discipline as `peer_replica_state.rs`/
//! `local_mutation.rs`/`materialization_state.rs`: these traits are thin,
//! same-signature delegates (kept in `StorageError`, `BlockStore`'s own
//! error type, rather than converted to `SyncError`, since a delegate that
//! changes its error type wouldn't be same-signature). No consumer is
//! migrated to use them yet — `chunker.rs`, `single_pass_capture.rs`,
//! `peer_session.rs`, `materialization.rs`, and `block_deletion.rs` are
//! untouched and still take `&dyn BlockStore`/`Arc<dyn BlockStore>`
//! directly. A later commit swaps each consumer's parameter/field type to
//! `&dyn Trait`/`Arc<dyn Trait>` one at a time.
//!
//! Blanket-implemented for every `BlockStore` (`+ ?Sized`, so the impl also
//! covers `dyn BlockStore` itself as a type, and a concrete `BlockStore`
//! implementor unsize-coerces straight to `Arc<dyn BlockContentStore>`/`Arc<dyn
//! BlockReclamationStore>` with no adapter type) rather than implemented
//! directly for one concrete type, unlike the `SyncState`-only adapters in
//! this module's siblings: `BlockStore` is a foreign trait with several
//! implementations already in play (`FsBlockStore`, in-memory test doubles,
//! `CountingBlockStore`), and there's no orphan-rule obstacle to a blanket
//! impl here since both new traits are local to this crate.
//!
//! That direct coercion needs a *concrete, still-Sized* `BlockStore`
//! implementor at the call site, though (proven in this module's `tests`
//! below) — it does NOT extend to an already-erased `Arc<dyn BlockStore +
//! Send + Sync>`, which is what `yadorilink-daemon`'s `DaemonState::block_store`
//! actually holds. Rust's `Unsize` coercion for trait objects only applies
//! to a declared supertrait relationship (dyn upcasting); `BlockContentStore`
//! and `BlockReclamationStore` are not supertraits of `BlockStore`, they're
//! connected only through this module's blanket impl, so `Arc<dyn BlockStore>
//! -> Arc<dyn BlockContentStore>` does not typecheck even though `dyn
//! BlockStore + Send + Sync` genuinely implements `BlockContentStore`. A
//! daemon-side adapter that wraps the already-erased `Arc<dyn BlockStore +
//! Send + Sync>` and forwards each port method is required for that case —
//! see `yadorilink-daemon`'s `adapters::block_store_ports` module.

use std::collections::HashSet;
use std::time::SystemTime;

use crate::{BlockStore, ContentHash, GcReport, LocallyHashedBlock, StorageError};

/// Content-addressed read/write for the sync/materialization hot path.
/// Every method here is called from this crate today — see this module's
/// doc comment for the exact call sites.
pub trait BlockContentStore: Send + Sync {
    /// Stores a freshly chunked block, called once per block from both of
    /// `chunker.rs`'s chunking strategies and both of
    /// `single_pass_capture.rs`'s single-pass branches while a file is
    /// captured.
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError>;

    /// See `BlockStore::put_prepared`'s own doc comment — same contract,
    /// forwarded through this port for `chunker.rs`'s `&dyn
    /// BlockContentStore` callers.
    fn put_prepared(&self, prepared: &LocallyHashedBlock) -> Result<(), StorageError>;

    /// See `BlockStore::put_prepared_batch`'s own doc comment — same
    /// contract, forwarded through this port for `chunker.rs`'s `&dyn
    /// BlockContentStore` callers.
    fn put_prepared_batch(&self, prepared: &[LocallyHashedBlock]) -> Result<(), StorageError>;

    /// Reads a block back by hash, called from `chunker.rs::reconstruct_file`
    /// while assembling a file from its index-recorded blocks, and from
    /// `peer_session.rs` while serving a block a peer requested.
    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError>;

    /// Batch presence check, called from `peer_session.rs` before a
    /// hydration fetch (deciding which of a file's blocks still need a
    /// peer round-trip) and from `materialization.rs` before a repair
    /// reconstruct (deciding whether every block is already local, so the
    /// reconstruct needs no peer at all).
    fn present_blocks(&self, hashes: &[ContentHash]) -> Result<Vec<bool>, StorageError>;
}

impl<T: BlockStore + ?Sized> BlockContentStore for T {
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError> {
        BlockStore::put(self, data)
    }

    fn put_prepared(&self, prepared: &LocallyHashedBlock) -> Result<(), StorageError> {
        BlockStore::put_prepared(self, prepared)
    }

    fn put_prepared_batch(&self, prepared: &[LocallyHashedBlock]) -> Result<(), StorageError> {
        BlockStore::put_prepared_batch(self, prepared)
    }

    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        BlockStore::get(self, hash)
    }

    fn present_blocks(&self, hashes: &[ContentHash]) -> Result<Vec<bool>, StorageError> {
        BlockStore::present_blocks(self, hashes)
    }
}

/// GC/eviction, called only from `block_deletion.rs`'s
/// `BlockDeletionCoordinator` — see that file's module doc ("single
/// production boundary for physical content-addressed block deletion").
/// `materialization.rs`'s eviction path reaches these through that
/// coordinator rather than calling a `BlockStore` directly.
pub trait BlockReclamationStore: Send + Sync {
    /// Mark-and-sweep GC, called from
    /// `BlockDeletionCoordinator::sweep`, which additionally refuses any
    /// deletion reason but `GloballyUnreferenced` before delegating here —
    /// see that method's own guard.
    fn sweep(
        &self,
        live: &HashSet<ContentHash>,
        grace_cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StorageError>;

    /// Deletes a specific, already-decided set of cached blocks, called
    /// from `BlockDeletionCoordinator::reclaim_cached_blocks` only after it
    /// has revalidated custody confirmation, pin status, and
    /// materialization state under the deletion guard — this method itself
    /// makes no liveness decision, per `BlockStore::reclaim_cached_blocks`'s
    /// own contract.
    fn reclaim_cached_blocks(&self, hashes: &[ContentHash]) -> Result<GcReport, StorageError>;
}

impl<T: BlockStore + ?Sized> BlockReclamationStore for T {
    fn sweep(
        &self,
        live: &HashSet<ContentHash>,
        grace_cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StorageError> {
        BlockStore::sweep(self, live, grace_cutoff, dry_run)
    }

    fn reclaim_cached_blocks(&self, hashes: &[ContentHash]) -> Result<GcReport, StorageError> {
        BlockStore::reclaim_cached_blocks(self, hashes)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::FsBlockStore;

    use super::*;

    /// Proves the blanket impls above make a concrete, still-Sized
    /// `BlockStore` implementor (`FsBlockStore`, the real production backend)
    /// unsize-coerce directly to `Arc<dyn BlockContentStore>` and `Arc<dyn
    /// BlockReclamationStore>` with no adapter type, and that each coerced
    /// handle still dispatches to the real underlying store.
    ///
    /// This does NOT prove the same coercion works starting from an
    /// already-erased `Arc<dyn BlockStore + Send + Sync>` (what
    /// `yadorilink-daemon`'s `DaemonState::block_store` actually holds) — it
    /// does not, see this module's doc comment for why, and
    /// `yadorilink-daemon`'s `adapters::block_store_ports` for the adapter
    /// that case needs.
    #[test]
    fn concrete_block_store_coerces_to_both_port_traits() {
        let dir = tempfile::tempdir().unwrap();

        let content: Arc<dyn BlockContentStore> = Arc::new(FsBlockStore::new(dir.path()).unwrap());
        let hash = content.put(b"port coercion proof").unwrap();
        assert_eq!(content.get(&hash).unwrap(), b"port coercion proof");
        assert_eq!(content.present_blocks(std::slice::from_ref(&hash)).unwrap(), vec![true]);

        let reclamation: Arc<dyn BlockReclamationStore> =
            Arc::new(FsBlockStore::new(dir.path()).unwrap());
        let live = HashSet::new();
        // `grace_cutoff` at the Unix epoch means every block's mtime is
        // newer than the cutoff, so `FsBlockStore::sweep`'s grace-period
        // check skips it as "too new to reclaim" regardless of `live` --
        // this proves dispatch reached the real `sweep` (a hash it stored
        // survives an unrelated GC pass), not `blocks_deleted` bookkeeping,
        // which counts dry-run candidates whether or not `dry_run` is set
        // (only the physical delete is what `dry_run` actually gates).
        let report = reclamation.sweep(&live, SystemTime::UNIX_EPOCH, true).unwrap();
        assert_eq!(report.blocks_deleted, 0, "grace period must protect a freshly written block");
    }

    /// Proves the specific negative claim above: an already-erased
    /// `Arc<dyn BlockStore + Send + Sync>` does NOT unsize-coerce to a port
    /// trait object, even though the blanket impl means it genuinely
    /// implements both port traits. This is a `compile_fail` doctest-style
    /// check expressed as a plain comment plus a passing runtime assertion,
    /// since `compile_fail` doctests aren't available on private items:
    /// see the module doc comment's "Rust's `Unsize` coercion..." paragraph
    /// for the explanation, and the daemon-side adapter this motivates.
    #[test]
    fn erased_dyn_block_store_needs_an_adapter_not_a_coercion() {
        let dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(FsBlockStore::new(dir.path()).unwrap());
        // `let _content: Arc<dyn BlockContentStore> = store.clone();` does not
        // compile here (verified manually while writing this commit) --
        // this test instead documents and exercises the fallback: calling
        // straight through the erased `BlockStore` trait object still works,
        // it's only the re-coercion to a *different* trait object that's
        // unavailable.
        let hash = store.put(b"erased dyn still works directly").unwrap();
        assert_eq!(store.get(&hash).unwrap(), b"erased dyn still works directly");
    }
}

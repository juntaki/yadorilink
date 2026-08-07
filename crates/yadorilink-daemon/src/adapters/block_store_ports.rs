//! Wraps `DaemonState::block_store` (`Arc<dyn BlockStore + Send + Sync>`) so
//! it can be handed to code that only wants
//! `yadorilink_local_storage::{BlockContentStore, BlockReclamationStore}`.
//!
//! `yadorilink-local-storage`'s `content_ports` module blanket-implements
//! both port traits for every `BlockStore` implementor, including `dyn
//! BlockStore` itself, so a concrete, still-Sized `BlockStore` implementor
//! (e.g. a freshly constructed `FsBlockStore`) unsize-coerces straight to
//! `Arc<dyn BlockContentStore>`/`Arc<dyn BlockReclamationStore>` with no
//! wrapper needed. `DaemonState::block_store` isn't that, though -- it's
//! already type-erased to `Arc<dyn BlockStore + Send + Sync>` by the time any
//! composition site sees it, and Rust's `Unsize` coercion for trait objects
//! only covers a declared supertrait relationship (dyn upcasting), not a
//! relationship established solely through a blanket impl. So `Arc<dyn
//! BlockStore> -> Arc<dyn BlockContentStore>` does not typecheck even though
//! `dyn BlockStore + Send + Sync` genuinely implements `BlockContentStore`
//! (see `yadorilink-local-storage`'s `content_ports` module doc and its
//! `erased_dyn_block_store_needs_an_adapter_not_a_coercion` test for the
//! confirmed negative case this adapter exists to work around).
//!
//! This is plumbing proof, not production wiring: nothing in this crate
//! constructs one of these outside tests yet -- see this module's own test
//! and the daemon-wide ports-reachability proof test for what it establishes.
//! `#![allow(dead_code)]` below for the same reason `yadorilink-sync-core`'s
//! own `ports` module carries one: no production composition site
//! constructs `BlockStorePortsAdapter` yet, only its own test and the
//! `adapters::ports_reachability` proof test do, so `new` and the struct
//! itself are legitimately unreferenced from production code until a later
//! commit wires a real composition site to it.
#![allow(dead_code)]

use std::collections::HashSet;
use std::sync::Arc;
use std::time::SystemTime;

use yadorilink_local_storage::{
    BlockContentStore, BlockReclamationStore, BlockStore, ContentHash, GcReport, StorageError,
};

/// Adapts an already-erased `Arc<dyn BlockStore + Send + Sync>` to
/// `BlockContentStore`/`BlockReclamationStore` by forwarding each port method
/// to the wrapped store. Every method here is a thin, same-signature
/// delegate, matching the delegation discipline `yadorilink-sync-core`'s own
/// port adapters use.
pub struct BlockStorePortsAdapter(Arc<dyn BlockStore + Send + Sync>);

impl BlockStorePortsAdapter {
    pub fn new(store: Arc<dyn BlockStore + Send + Sync>) -> Self {
        Self(store)
    }
}

impl BlockContentStore for BlockStorePortsAdapter {
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError> {
        self.0.put(data)
    }

    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        self.0.get(hash)
    }

    fn present_blocks(&self, hashes: &[ContentHash]) -> Result<Vec<bool>, StorageError> {
        self.0.present_blocks(hashes)
    }
}

impl BlockReclamationStore for BlockStorePortsAdapter {
    fn sweep(
        &self,
        live: &HashSet<ContentHash>,
        grace_cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StorageError> {
        self.0.sweep(live, grace_cutoff, dry_run)
    }

    fn reclaim_cached_blocks(&self, hashes: &[ContentHash]) -> Result<GcReport, StorageError> {
        self.0.reclaim_cached_blocks(hashes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Proves the adapter above lets `DaemonState::block_store`'s actual
    /// type, `Arc<dyn BlockStore + Send + Sync>`, reach both port traits
    /// after all -- the case direct unsize coercion can't handle (see this
    /// module's doc comment) -- and that calls through the coerced port
    /// handles still dispatch to the real underlying store.
    #[test]
    fn erased_dyn_block_store_reaches_both_port_traits_via_adapter() {
        let dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(yadorilink_local_storage::FsBlockStore::new(dir.path()).unwrap());

        let content: Arc<dyn BlockContentStore> =
            Arc::new(BlockStorePortsAdapter::new(store.clone()));
        let hash = content.put(b"adapter proof").unwrap();
        assert_eq!(content.get(&hash).unwrap(), b"adapter proof");
        assert_eq!(content.present_blocks(std::slice::from_ref(&hash)).unwrap(), vec![true]);

        let reclamation: Arc<dyn BlockReclamationStore> =
            Arc::new(BlockStorePortsAdapter::new(store));
        let live = HashSet::new();
        // `grace_cutoff` at the Unix epoch means every block's mtime is
        // newer than the cutoff, so `FsBlockStore::sweep`'s grace-period
        // check skips it as "too new to reclaim" regardless of `live` --
        // this proves dispatch reached the real `sweep` through the adapter
        // (a hash it stored survives an unrelated GC pass), not
        // `blocks_deleted` bookkeeping, which counts dry-run candidates
        // whether or not `dry_run` is set (only the physical delete is what
        // `dry_run` actually gates).
        let report = reclamation.sweep(&live, SystemTime::UNIX_EPOCH, true).unwrap();
        assert_eq!(report.blocks_deleted, 0, "grace period must protect a freshly written block");
    }
}

use std::collections::HashSet;
use std::time::SystemTime;

use crate::error::StorageError;
use crate::free_space::VolumeFreeSpace;

/// Hex-encoded SHA-256 content hash, used as the sole addressing key for
/// stored blocks (per `local-storage` spec: "content-derived keys, not
/// user-supplied paths").
pub type ContentHash = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StorageUsage {
    pub block_count: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GcReport {
    pub blocks_deleted: u64,
    pub bytes_reclaimed: u64,
}

/// Storage backend interface used by the sync engine on each device.
/// Implementations MUST NOT resolve any path outside their configured
/// storage root, regardless of what `list_by_prefix` prefixes are supplied.
pub trait BlockStore: Send + Sync {
    /// Stores `data`, returning its content hash. Storing a block whose
    /// hash already exists is a no-op that still returns the same hash
    /// (identical content is stored once).
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError>;

    /// Reads back a block by hash, verifying its checksum. Returns
    /// `StorageError::ChecksumMismatch` if the stored bytes don't hash to
    /// the requested key (corruption), and `NotFound` if absent.
    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError>;

    /// Reads back a block by hash WITHOUT re-verifying its checksum
    /// against the stored bytes (`sync-performance` ).
    ///
    /// # Safety contract (not a Rust `unsafe fn` — a correctness contract)
    ///
    /// This is a performance fast path, not a general-purpose substitute
    /// for [`get`](Self::get). Callers MUST only use it when integrity is
    /// *already independently guaranteed* for this exact read, e.g.:
    /// - re-serving bytes that this same process already checksum-verified
    ///   earlier in the same request/response flow (no intervening
    ///   untrusted write to that path), or
    /// - reading content this process just wrote via [`put`](Self::put) in
    ///   the same operation, before any possibility of external tampering
    ///   or corruption of that specific write.
    ///
    /// Any path that handles peer-supplied bytes or content this process
    /// has not itself verified during this run (a "first read") MUST keep
    /// using `get`, per `security-hardening` — `get`'s mandatory
    /// verify-on-read is what limits to a DoS vector instead of a
    /// silent-corruption/integrity vector, and `get_unchecked` does not
    /// preserve that guarantee.
    ///
    /// The default implementation simply delegates to `get`, so it is
    /// always at least as safe as `get` unless a backend explicitly
    /// overrides it to skip verification (as `FsBlockStore` does). No
    /// call site in this repository calls `get_unchecked` yet as of this
    /// change — it is added for a future, deliberate opt-in at specific
    /// call sites.
    fn get_unchecked(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        self.get(hash)
    }

    fn delete(&self, hash: &str) -> Result<(), StorageError>;

    fn exists(&self, hash: &str) -> Result<bool, StorageError>;

    /// Lists stored content hashes beginning with `prefix`.
    fn list_by_prefix(&self, prefix: &str) -> Result<Vec<ContentHash>, StorageError>;

    /// Reports current block-store usage. Backends with direct metadata
    /// access should override this to avoid reading block contents; the
    /// default stays correct for in-memory/test implementations using
    /// only the trait's existing API surface.
    fn usage(&self) -> Result<StorageUsage, StorageError> {
        let hashes = self.list_by_prefix("")?;
        let mut usage = StorageUsage { block_count: hashes.len() as u64, total_bytes: 0 };
        for hash in hashes {
            usage.total_bytes += self.get_unchecked(&hash)?.len() as u64;
        }
        Ok(usage)
    }

    /// Mark-and-sweep — deletes every stored block not in `live` and older
    /// (by on-disk mtime) than `grace_cutoff`, or (`dry_run`) reports what
    /// would be deleted without calling [`delete`](Self::delete). No
    /// default implementation: the grace-window check is inherently
    /// backend-specific (it keys off on-disk mtime, which only a real
    /// filesystem backend has), so unlike `usage` above there is no
    /// generically-correct fallback. This
    /// lives on the trait — mirroring `set_headroom_enforced`'s doc
    /// comment's own precedent — because `yadorilink-daemon`'s
    /// `DaemonState` only ever holds an `Arc<dyn BlockStore>`, never the
    /// concrete `FsBlockStore`, and the periodic/on-demand GC scheduler
    /// needs to call this through that trait object.
    fn sweep(
        &self,
        live: &HashSet<ContentHash>,
        grace_cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StorageError>;

    /// Reclaims (deletes) a specific set of cached blocks, freeing their
    /// real on-disk space, and reports how many blocks/bytes were freed.
    ///
    /// This is deliberately distinct from [`sweep`](Self::sweep). `sweep`
    /// enforces the version-liveness rule: a block referenced by any
    /// retained version is kept alive. This method is the single, explicit
    /// exception to that rule — the reclamation of an on-demand device's
    /// block cache. On such a device the block store for non-hydrated,
    /// non-pinned content is a cache: those blocks may be deleted to free
    /// space even though a retained version still references them, because
    /// the content is durably held elsewhere (a full-replica device for the
    /// group). The block store itself cannot see that liveness or custody
    /// context, so this method deletes exactly the hashes it is given and
    /// makes no liveness decision of its own: the caller is responsible for
    /// having established, fail-closed, that (a) this device syncs the group
    /// as a reclaimable cache rather than a full replica, (b) a full replica
    /// is confirmed to hold these blocks, and (c) no locally hydrated or
    /// pinned file still needs them. `sweep` must never be given this
    /// exception; a full-replica device (and any hydrated/pinned file) keeps
    /// the ordinary version-liveness guarantee and is never reclaimed this
    /// way.
    ///
    /// Idempotent per hash: a hash already absent contributes nothing to the
    /// report rather than erroring, so a retried or partially-completed
    /// reclamation is safe. The default implementation sizes each block
    /// before deleting it; a backend with direct metadata access should
    /// override this to avoid reading block contents (as `FsBlockStore`
    /// does).
    fn reclaim_cached_blocks(&self, hashes: &[ContentHash]) -> Result<GcReport, StorageError> {
        let mut report = GcReport::default();
        for hash in hashes {
            let bytes = match self.get_unchecked(hash) {
                Ok(block) => block.len() as u64,
                Err(StorageError::NotFound(_)) => continue,
                Err(e) => return Err(e),
            };
            self.delete(hash)?;
            report.blocks_deleted += 1;
            report.bytes_reclaimed += bytes;
        }
        Ok(report)
    }

    /// Reports, for each of `hashes` (in the same order), whether it's
    /// already present locally — `on-demand-sync`: lets a caller
    /// (hydration, in particular) know which of a file's blocks it still
    /// needs to fetch from a peer without probing them one at a time.
    /// Default implementation checks each hash individually via `exists`;
    /// a backend with an indexed batch-lookup path may override this for
    /// efficiency, but the default is always correct.
    ///
    /// `sync-performance` this is called from async call sites
    /// (`peer_session.rs`, `hydration.rs`) without an intervening
    /// `.await`, so an override MUST NOT synchronously perform a large
    /// amount of blocking filesystem work directly on a tokio worker
    /// thread without compensating for it (e.g. via
    /// `tokio::task::block_in_place` when actually running on a
    /// multi-threaded tokio runtime) — see `FsBlockStore::present_blocks`
    /// for the pattern this repo uses, kept behind this same sync
    /// signature so existing callers need no changes.
    fn present_blocks(&self, hashes: &[ContentHash]) -> Result<Vec<bool>, StorageError> {
        hashes.iter().map(|h| self.exists(h.as_str())).collect()
    }

    /// Turns this backend's disk-space headroom preflight on `put` on or
    /// off. Exposed on the trait (rather than only on the concrete
    /// `FsBlockStore`) so
    /// `yadorilink-daemon`'s `DaemonState`, which only ever holds an
    /// `Arc<dyn BlockStore>` (not the concrete type), can wire governance
    /// config into whatever backend is actually running. Default: a no-op
    /// — a backend with no real disk-headroom concept (e.g. an in-memory
    /// test double) simply ignores this; only `FsBlockStore` overrides it
    /// with real enforcement. See `FsBlockStore::headroom_enforced`'s doc
    /// comment for why enforcement itself defaults to off.
    fn set_headroom_enforced(&self, _enforced: bool) {}

    /// Sets or clears an explicit headroom override (`None` = the default
    /// `max(1 GiB, 5%)` formula). Default: a no-op, mirroring
    /// `set_headroom_enforced`.
    fn set_headroom_override_bytes(&self, _headroom_bytes: Option<u64>) {}

    /// This backend's current free-space snapshot (available/total/headroom
    /// bytes, from which the caller can derive the ok/low/critical
    /// classification via `VolumeFreeSpace::classify` — ), for
    /// `yadorilink status`'s per-volume reporting. `None` when this backend
    /// has no real underlying volume to report on. Default: `None` — an
    /// in-memory/test double has no real disk concept; only `FsBlockStore`
    /// overrides this with a real query.
    fn free_space(&self) -> Result<Option<VolumeFreeSpace>, StorageError> {
        Ok(None)
    }
}

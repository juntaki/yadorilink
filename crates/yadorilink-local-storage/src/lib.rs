//! On-device content-addressed block store.

pub mod chunker;
mod content_ports;
pub mod disk_verification;
mod error;
pub mod free_space;
mod fs_backend;
/// Shared link preflight model (folder existence/empty-state/free-space/
/// ignored-summary/risky-location checks) used by both `yadorilink-cli`'s
/// client-side dry-run/confirmation gate and `yadorilink-daemon`'s
/// defense-in-depth re-check. Moved from `yadorilink-sync-core` in Phase
/// 7D-9B. Placed here rather than `yadorilink-root-authority` (the ledger's
/// nominal destination) because it needs both this crate's own
/// `free_space` and `yadorilink_root_authority::ignore_patterns` --
/// `yadorilink-local-storage` already depends on `yadorilink-root-authority`
/// (for `fs_identity::bytes_to_target`), so the reverse edge
/// root-authority-depends-on-local-storage that the nominal destination
/// would require is a real crate-dependency cycle, not just inconvenient.
pub mod link_preflight;
pub mod materialize_write;
mod traits;

pub use chunker::{
    block_size_for, chunk_file, chunk_file_content_defined, owner_exec_bit_from_metadata,
    CDC_AVG_SIZE, CDC_MAX_SIZE, CDC_MIN_SIZE, CDC_SIZE_THRESHOLD, DEFAULT_BLOCK_SIZE,
};
pub use content_ports::{BlockContentStore, BlockReclamationStore};
pub use disk_verification::{
    check_disk_headroom, disk_bytes_match_indexed_blocks, disk_content_comparison,
    intent_target_hash, DiskContentComparison,
};
pub use error::StorageError;
pub use materialize_write::{
    apply_exec_bit, reconstruct_file, verify_delete_target_within_canonical_root,
    verify_delete_target_within_root, verify_write_target_within_canonical_root,
    verify_write_target_within_root, write_placeholder,
};
#[cfg(unix)]
pub use materialize_write::materialize_symlink;
#[cfg(windows)]
pub use materialize_write::materialize_symlink_windows;
pub use free_space::{FreeSpaceState, VolumeFreeSpace};
pub use fs_backend::FsBlockStore;
pub use traits::{BlockStore, ContentHash, GcReport, StorageUsage};

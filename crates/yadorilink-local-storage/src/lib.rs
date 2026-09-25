//! On-device content-addressed block store.
//!
//! Blocks live in append-only segment files with a persistent SQLite
//! index; many blocks share one durability barrier. See
//! [`segment_store`]'s module documentation for the design and for the
//! `staged -> durable -> authoritative` contract every caller depends on.

pub mod chunker;
mod content_ports;
pub mod disk_verification;
mod error;
pub mod free_space;
mod fs_ops;
pub use fs_ops::{remove_empty_dir, EmptyDirectoryRemoval};
pub mod io_diag;
/// Shared link preflight model (folder existence/empty-state/free-space/
/// ignored-summary/risky-location checks) used by both `yadorilink-cli`'s
/// client-side dry-run/confirmation gate and `yadorilink-daemon`'s
/// defense-in-depth re-check. Placed here rather than
/// `yadorilink-root-authority` because
/// it needs both this crate's own `free_space` and
/// `yadorilink_root_authority::ignore_patterns` --
/// `yadorilink-local-storage` already depends on
/// `yadorilink-root-authority` (for `fs_identity::bytes_to_target`), so
/// the reverse edge root-authority-depends-on-local-storage that the
/// nominal destination would require is a real crate-dependency cycle, not
/// just inconvenient.
pub mod link_preflight;
pub mod materialize_write;
pub mod segment_store;
mod traits;

pub use chunker::{
    block_size_for, chunk_file, chunk_file_content_defined,
    chunk_file_content_defined_with_callback, chunk_file_fixed_with_callback, chunk_open_file,
    chunk_open_file_content_defined_with_callback, chunk_open_file_fixed_with_callback,
    hash_file_blocks, hash_open_file_blocks, read_replicated_xattrs, unix_mode_from_metadata,
    CDC_AVG_SIZE, CDC_MAX_SIZE, CDC_MIN_SIZE, CDC_SIZE_THRESHOLD, DEFAULT_BLOCK_SIZE,
};
pub use content_ports::{BlockContentStore, BlockReclamationStore};
pub use disk_verification::{
    check_disk_headroom, disk_bytes_match_indexed_blocks, disk_content_comparison,
    disk_matches_expected_object, intent_target_hash, intent_target_hash_for_bytes,
    DiskContentComparison, ExpectedObject,
};
pub use error::StorageError;
pub use free_space::{FreeSpaceState, VolumeFreeSpace};
#[cfg(unix)]
pub use materialize_write::materialize_symlink;
#[cfg(windows)]
pub use materialize_write::materialize_symlink_windows;
pub use materialize_write::{
    apply_file_metadata, apply_file_metadata_verified, apply_unix_mode, apply_xattrs,
    create_dir_all_never_through_a_symlink, create_explicit_directory, create_or_defer_placeholder,
    create_or_defer_placeholder_if_absent, mint_windows_placeholder_generation,
    mtime_already_matches_disk, persist_reconstructed_file, reconstruct_file,
    reconstruct_file_to_temp, resolve_read_path_without_traversal, stamp_mtime_at_path,
    unix_mode_already_matches_disk, verify_delete_target_within_canonical_root,
    verify_delete_target_within_root, verify_replicated_xattrs_exact,
    verify_write_target_within_canonical_root, verify_write_target_within_root, write_placeholder,
    write_placeholder_if_absent, xattrs_already_match_disk, AppliedFileMetadata,
    ExplicitDirectoryCreation, PlaceholderDiskIdentity, PlaceholderIdentityToRecord,
    StructuralDirectoryLedger, XattrEvidence, XattrProofRefused, XattrsConfirmedInAttempt,
    XattrsNotConfirmed, INTERNAL_INODE_PROVIDER_KIND, WINDOWS_CFAPI_GENERATION_PROVIDER_KIND,
};
pub use segment_store::{
    CommitPoint, CompactionReport, DurableReceipt, FaultPlan, GroupCommitLimits, RecoveryReport,
    SegmentBlockStore, SegmentStoreUsage, COMPACTION_DEAD_RATIO, COMPACTION_MIN_DEAD_BYTES,
};
pub use traits::{
    hash_block_bytes, BlockStore, ContentHash, GcReport, LocallyHashedBlock, StorageUsage,
};

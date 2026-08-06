//! Domain-level bounds the canonical `Change` encoding and its
//! constituent records enforce on untrusted input. These are not
//! implementation details of any one component that happens to also
//! respect them (the local chunker, for instance) -- they are the actual
//! contract a peer's encoded bytes must satisfy to be admitted at all, so
//! this crate owns them.

/// The largest single block a `VersionBlock`/`BlockInfo` may declare.
/// `yadorilink-sync-core`'s local chunker never produces a block larger
/// than this, but the bound itself belongs here: it is what
/// `Change::validate`'s untrusted-input check enforces against a peer's
/// encoded bytes, not merely a local chunking policy.
pub const MAX_BLOCK_SIZE_BYTES: u32 = 16 * 1024 * 1024;

/// The largest number of parent change-hashes a single `Change` may name.
pub const MAX_PARENTS: usize = 1024;

/// The largest number of `Op`s a single `Change` may carry.
pub const MAX_OPS: usize = 1 << 16;

/// The largest number of blocks a single file version may declare.
pub const MAX_BLOCKS: usize = 1 << 20;

/// The largest encoded length, in bytes, of a single path.
pub const MAX_PATH_BYTES: usize = 4096;

/// The largest number of `/`-separated segments a single path may have.
pub const MAX_PATH_SEGMENTS: usize = 255;

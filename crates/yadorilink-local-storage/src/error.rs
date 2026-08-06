#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("block not found: {0}")]
    NotFound(String),

    #[error("checksum mismatch for block {expected}: computed {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    #[error("invalid path: {0}")]
    InvalidPath(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A block write was rejected before any bytes were written because
    /// completing it would breach the configured free-space headroom on the
    /// volume hosting the block-store root — deliberately a distinct
    /// variant (not `Io`, and never constructed via `#[from]`) so callers
    /// can tell "disk is full, back off differently" from a transient I/O
    /// error and retry accordingly.
    #[error(
        "insufficient free space to write block at {path:?}: {available_bytes} bytes available \
         on {volume:?}, headroom requires at least {headroom_bytes} bytes free"
    )]
    DiskPressure {
        /// The block file path the write would have gone to (never
        /// created — the check runs before any temp file exists).
        path: std::path::PathBuf,
        /// The volume the headroom check was evaluated against — the
        /// block-store root for this variant.
        volume: std::path::PathBuf,
        available_bytes: u64,
        headroom_bytes: u64,
    },

    /// A materialization write/delete target resolved outside its
    /// designated root (a symlinked intermediate path component, planted
    /// locally or raced in) -- defense-in-depth, distinct from `InvalidPath`
    /// so callers can tell "this specific escape check refused it" apart
    /// from a generically malformed path.
    #[error("materialization target {0:?} resolved outside its sync root (symlinked path component?)")]
    PathEscapesRoot(String),

    /// `chunker::chunk_file`/`chunk_file_content_defined` decode a
    /// content-store `put` result (a hex-encoded content hash) back into
    /// raw bytes for `BlockInfo::hash` -- this is that decode failing.
    /// Distinct from `Io` so a caller can tell "the store returned a
    /// malformed hash" apart from a filesystem failure. Moved here
    /// alongside `chunker.rs` in Phase 7D-8.1; `yadorilink-sync-core`'s
    /// `From<StorageError> for SyncError` maps this back to its own
    /// `SyncError::Hex` variant so the observable error category is
    /// unchanged from before the move.
    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    /// `chunker::chunk_file_content_defined`: an error from the `fastcdc`
    /// streaming chunker (I/O failure reading the source file, or an
    /// internal chunker error) -- distinct from `Io` since it's
    /// specifically about the CDC chunk-boundary-finding process, not a
    /// bare filesystem call. Moved here alongside `chunker.rs` in Phase
    /// 7D-8.1; `yadorilink-sync-core`'s `From<StorageError> for SyncError`
    /// maps this back to its own `SyncError::Chunking` variant so the
    /// observable error category is unchanged from before the move.
    #[error("content-defined chunking error: {0}")]
    Chunking(String),
}

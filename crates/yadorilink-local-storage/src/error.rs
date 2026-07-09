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

    /// add-resource-governance task 1.4/3.1: a block write was rejected
    /// before any bytes were written because completing it would breach the
    /// configured free-space headroom on the volume hosting the block-store
    /// root — deliberately a distinct variant (not `Io`, and never
    /// constructed via `#[from]`) so callers can tell "disk is full, back
    /// off differently" from a transient I/O error and retry accordingly
    /// (task 1.5).
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
}

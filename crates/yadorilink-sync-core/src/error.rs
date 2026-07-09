#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("not yet implemented: {0}")]
    NotImplemented(&'static str),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    // add-resource-governance task 1.4: no longer `#[from]`-derived — see
    // the manual `From<StorageError>` impl below, which special-cases
    // `StorageError::DiskPressure` into `SyncError::DiskPressure` instead of
    // burying it in this generic variant, so a caller can still tell "disk
    // is full" from every other storage error by matching on `SyncError`
    // alone, regardless of which layer (this crate's own preflight, or
    // `yadorilink-local-storage`'s block-store preflight) detected it.
    #[error("storage error: {0}")]
    Storage(yadorilink_local_storage::StorageError),

    #[error("transport error: {0}")]
    Transport(#[from] yadorilink_transport::TransportError),

    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("db error: {0}")]
    Db(#[from] rusqlite::Error),

    /// sync-performance PERF-3: `SyncState` checks out a connection from a
    /// pool (`r2d2`) for every call instead of locking one shared
    /// `Connection`, so a checkout can now fail on its own (pool
    /// exhausted past its wait timeout, or the pool's own setup/teardown
    /// erroring) in a way the old `Mutex<Connection>` never could — that
    /// lock always eventually succeeded (or ran the poison-recovery path)
    /// rather than returning an error.
    #[error("db connection pool error: {0}")]
    Pool(#[from] r2d2::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("filesystem watcher error: {0}")]
    Watch(#[from] notify::Error),

    #[error("protobuf decode error: {0}")]
    Decode(#[from] prost::DecodeError),

    /// content-defined-chunking: an error from the `fastcdc` streaming
    /// chunker (I/O failure reading the source file, or an internal
    /// chunker error) — distinct from `Io` since it's specifically about
    /// the CDC chunk-boundary-finding process, not a bare filesystem call.
    #[error("content-defined chunking error: {0}")]
    Chunking(String),

    #[error("not found: {0}")]
    NotFound(String),

    /// on-demand-sync design D5: a hydration request that couldn't obtain
    /// all of a file's blocks within the bounded timeout, either because
    /// the peer never responded or explicitly reported some as not found.
    #[error("hydration of {0:?} timed out or failed: no reachable peer holds all required blocks")]
    HydrationFailed(String),

    /// add-file-version-history spec "Restore With Missing Blocks Fails
    /// Clearly": a restore (`yadorilink restore`/`trash restore`) whose
    /// chosen version needs blocks that are missing locally and
    /// unavailable from every currently-reachable, authorized peer.
    /// Deliberately a distinct variant from `HydrationFailed` — both are
    /// "couldn't get these blocks from a peer in time," but callers (the
    /// CLI, the control-socket IPC layer) need to tell "restoring version
    /// content specifically failed" apart from "this on-demand file's
    /// current content failed to hydrate," since the two surface with
    /// different, specific user-facing messages (spec: "an error that
    /// specifically identifies unavailable version content, rather than a
    /// generic I/O or not-found error"). The payload identifies the
    /// specific version that failed to resolve (`"<group_id>/<path>@
    /// <version_seq>"`).
    #[error(
        "restoring {0:?} failed: the chosen version's content is unavailable — required blocks \
         are missing locally and no reachable, authorized peer holds them"
    )]
    VersionContentUnavailable(String),

    /// on-demand-sync spec "Pinned files cannot be evicted".
    #[error("cannot evict {0:?}: it is pinned")]
    EvictionRejected(String),

    /// add-folder-direction-modes task 3.1/3.2: `override`/`revert` are
    /// each valid against exactly one mode (`override` only reconciles a
    /// `send-only` link, `revert` only a `receive-only` one — design.md's
    /// "Override / revert" section) and neither reconciles a paused link
    /// (design.md: "pause still trumps everything"). Carries a
    /// human-readable explanation of which precondition failed, surfaced
    /// to the CLI user as-is.
    #[error("{0}")]
    InvalidLinkMode(String),

    /// SEC-SYNC-5 defense-in-depth: after resolving a peer-advertised path
    /// under a folder group's sync root, canonicalizing the resolved
    /// parent directory landed outside that root — most likely because a
    /// pre-existing symlink at an intermediate path component was
    /// followed. `is_safe_relative_path` already rejects `..` and
    /// absolute-path components, but can't (without an actual filesystem
    /// check) catch a symlink a local actor planted in advance.
    #[error(
        "materialization target {0:?} resolved outside its sync root (symlinked path component?)"
    )]
    PathEscapesRoot(String),

    /// add-resource-governance task 1.4: a distinct disk-pressure error,
    /// carrying the affected path and volume — constructed directly by this
    /// crate's own hydration/materialization preflight
    /// (`materialization::check_disk_headroom`), or converted from
    /// `yadorilink_local_storage::StorageError::DiskPressure` by the `From`
    /// impl below when the block store's own preflight rejects a write.
    /// Never produced via a generic `?`-conversion from an ordinary I/O
    /// error — task 1.5 requires this stay distinguishable from a
    /// transient/network failure so callers (the daemon's Degraded-state
    /// tracking, in particular) can back off differently for "disk is
    /// full" than for "peer/network blip, just retry".
    #[error(
        "insufficient free space to write {path:?}: {available_bytes} bytes available on \
         {volume:?}, headroom requires at least {headroom_bytes} bytes free"
    )]
    DiskPressure { path: String, volume: String, available_bytes: u64, headroom_bytes: u64 },

    /// add-update-migration-safety task 1.3: this local database's stamped
    /// `PRAGMA user_version` is newer than the schema version this binary
    /// supports — it was opened (and migrated) by a newer build. Refusing
    /// to proceed here is deliberate: an older binary blindly continuing
    /// could reinterpret or overwrite columns it has no knowledge of.
    /// Callers (daemon startup) should surface this as a clear "downgrade
    /// not supported, reinstall the newer version" message rather than a
    /// generic database error.
    #[error(
        "database schema version {on_disk_version} is newer than this build supports \
         (supports up to version {supported_version}) — this looks like an unsupported \
         downgrade; reinstall the version that last wrote this data, or a newer one"
    )]
    UnsupportedSchemaDowngrade { on_disk_version: i32, supported_version: i32 },
}

impl SyncError {
    /// add-observability-and-metrics section 2: a coarse, stable,
    /// privacy-safe category slug for this error — the recent-error
    /// ring buffer's (`yadorilink-daemon::recent_errors`) and the
    /// `/metrics` endpoint's `yadorilink_sync_errors_total{category}`
    /// taxonomy, mirroring design.md's "Categories mirror the sync
    /// engine's error taxonomy (e.g. peer-unreachable, block-integrity,
    /// disk-pressure, permission)". Deliberately derived only from the
    /// variant/kind itself, never from `Display`/`to_string()` — this
    /// crate's error messages can embed a path, volume, or hash (see e.g.
    /// `DiskPressure`'s own fields), exactly what the recent-error buffer
    /// and metrics labels must never carry (task 2.1/3.3's redaction
    /// requirement). "block_integrity" (a peer returning block data that
    /// fails its expected hash/size) has no dedicated variant here — it's
    /// recorded directly by the daemon's hydration dispatcher at the point
    /// that check happens, not through this method.
    pub fn category(&self) -> &'static str {
        match self {
            SyncError::NotImplemented(_) => "not_implemented",
            // `Io`'s `Display` can embed a path (e.g. a `NotFound` for a
            // specific file) — only the stable `ErrorKind` is ever used
            // here, never the message text.
            SyncError::Io(e) => match e.kind() {
                std::io::ErrorKind::PermissionDenied => "permission",
                _ => "io",
            },
            SyncError::Storage(_) => "storage",
            SyncError::Transport(_) => "peer_unreachable",
            SyncError::Hex(_) => "protocol",
            SyncError::Db(_) => "storage",
            SyncError::Pool(_) => "storage",
            SyncError::Json(_) => "protocol",
            SyncError::Watch(_) => "io",
            SyncError::Decode(_) => "protocol",
            SyncError::Chunking(_) => "io",
            SyncError::NotFound(_) => "not_found",
            SyncError::HydrationFailed(_) => "peer_unreachable",
            SyncError::VersionContentUnavailable(_) => "peer_unreachable",
            SyncError::EvictionRejected(_) => "policy",
            SyncError::InvalidLinkMode(_) => "policy",
            SyncError::PathEscapesRoot(_) => "permission",
            SyncError::DiskPressure { .. } => "disk_pressure",
            SyncError::UnsupportedSchemaDowngrade { .. } => "storage",
        }
    }
}

impl From<yadorilink_local_storage::StorageError> for SyncError {
    fn from(err: yadorilink_local_storage::StorageError) -> Self {
        match err {
            yadorilink_local_storage::StorageError::DiskPressure {
                path,
                volume,
                available_bytes,
                headroom_bytes,
            } => SyncError::DiskPressure {
                path: path.display().to_string(),
                volume: volume.display().to_string(),
                available_bytes,
                headroom_bytes,
            },
            other => SyncError::Storage(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// task 1.5: a `StorageError::DiskPressure` from the block store
    /// converts to `SyncError::DiskPressure`, not the generic `Storage`
    /// wrapper — a caller matching on `SyncError` alone (not reaching into
    /// the wrapped `StorageError`) can still tell disk pressure apart from
    /// every other storage error.
    #[test]
    fn disk_pressure_survives_conversion_from_storage_error_undisguised() {
        let storage_err = yadorilink_local_storage::StorageError::DiskPressure {
            path: "/root/blocks/ab/cd/abcd".into(),
            volume: "/root/blocks".into(),
            available_bytes: 100,
            headroom_bytes: 1000,
        };
        let sync_err: SyncError = storage_err.into();
        assert!(matches!(sync_err, SyncError::DiskPressure { .. }));
    }

    /// The converse: an ordinary storage error (not disk pressure) still
    /// wraps as `Storage`, not `DiskPressure` — the conversion only
    /// special-cases the one variant it needs to.
    #[test]
    fn other_storage_errors_still_wrap_as_the_generic_storage_variant() {
        let storage_err = yadorilink_local_storage::StorageError::NotFound("deadbeef".into());
        let sync_err: SyncError = storage_err.into();
        assert!(matches!(sync_err, SyncError::Storage(_)));
        assert!(!matches!(sync_err, SyncError::DiskPressure { .. }));
    }

    /// add-observability-and-metrics task 2.1: spot-checks the category
    /// taxonomy's coarse, stable slugs for a representative sample of
    /// variants — these are exactly the strings the recent-error ring
    /// buffer and `/metrics` labels surface, so a typo here is a
    /// user-visible regression.
    #[test]
    fn category_returns_stable_coarse_slugs() {
        assert_eq!(
            SyncError::Transport(yadorilink_transport::TransportError::RelayClosed).category(),
            "peer_unreachable"
        );
        assert_eq!(
            SyncError::DiskPressure {
                path: "a.bin".into(),
                volume: "/root".into(),
                available_bytes: 1,
                headroom_bytes: 2,
            }
            .category(),
            "disk_pressure"
        );
        assert_eq!(SyncError::NotFound("x".into()).category(), "not_found");
        assert_eq!(SyncError::PathEscapesRoot("x".into()).category(), "permission");
        assert_eq!(
            SyncError::Io(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"))
                .category(),
            "permission"
        );
        assert_eq!(SyncError::Io(std::io::Error::other("transient")).category(), "io");
    }

    /// task 1.5: `DiskPressure` must never be confused with `Io` — a plain
    /// transient I/O error stays `Io`, never `DiskPressure`, so callers can
    /// branch on "disk full, back off differently" versus "network/I/O
    /// blip, just retry" by matching the `SyncError` variant alone.
    #[test]
    fn disk_pressure_is_a_distinct_variant_from_io_errors() {
        let io_err: SyncError = std::io::Error::other("transient").into();
        assert!(matches!(io_err, SyncError::Io(_)));
        assert!(!matches!(io_err, SyncError::DiskPressure { .. }));

        let disk_pressure = SyncError::DiskPressure {
            path: "a.bin".into(),
            volume: "/root".into(),
            available_bytes: 1,
            headroom_bytes: 2,
        };
        assert!(!matches!(disk_pressure, SyncError::Io(_)));
    }
}

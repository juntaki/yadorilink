//! Native Rust types mirroring `yadorilink_ipc_proto::sync`'s wire messages,
//! plus conversions, so the rest of this crate doesn't work directly with
//! generated protobuf types (whose `Vec<u8>` hashes and raw maps are
//! awkward to use as, e.g., `HashMap`/`BTreeMap` keys).

use serde::{Deserialize, Serialize};
use yadorilink_ipc_proto::sync as proto;

use crate::version_vector::VersionVector;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockInfo {
    pub hash: Vec<u8>,
    pub offset: u64,
    pub size: u32,
}

impl From<BlockInfo> for proto::BlockInfo {
    fn from(b: BlockInfo) -> Self {
        proto::BlockInfo { hash: b.hash, offset: b.offset, size: b.size }
    }
}

impl From<proto::BlockInfo> for BlockInfo {
    fn from(b: proto::BlockInfo) -> Self {
        BlockInfo { hash: b.hash, offset: b.offset, size: b.size }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct FileRecord {
    pub path: String,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    pub version: VersionVector,
    pub blocks: Vec<BlockInfo>,
    pub deleted: bool,
}

impl From<FileRecord> for proto::FileInfo {
    fn from(f: FileRecord) -> Self {
        proto::FileInfo {
            path: f.path,
            size: f.size,
            mtime_unix_nanos: f.mtime_unix_nanos,
            version: Some(proto::VersionVector {
                counters: f.version.counters().clone().into_iter().collect(),
            }),
            blocks: f.blocks.into_iter().map(Into::into).collect(),
            deleted: f.deleted,
            // Wire-schema gap (documented, not
            // hidden — see `peer_session::materialize_symlink_at`'s and
            // `try_apply_metadata_only_update`'s doc comments for the full
            // story): `FileRecord` deliberately does not carry
            // `record_kind`/`symlink_target`/`symlink_out_of_root`/
            // `exec_bit` (section 1's design choice, to avoid touching
            // every one of the dozens of existing `FileRecord { .. }`
            // construction sites across the workspace). This `From` impl
            // therefore cannot populate the new wire fields from `f`
            // alone — they decode as their proto3 zero values
            // (`RECORD_KIND_UNSPECIFIED`/absent/`false`) here, which a
            // receiver treats the same as a pre-this-change record.
            // Actually populating them correctly (by looking up this
            // device's own `SyncState::get_record_kind`/
            // `get_symlink_target`/`get_symlink_out_of_root`/
            // `get_exec_bit` for `f.path` before sending) requires a call
            // site with `SyncState` access — `peer_session.rs`'s
            // `send_full_index`/`send_index_update`, which build these
            // `proto::FileInfo` values via `.into()` today. That wiring is
            // out of this section's scope (a parallel agent owns
            // `peer_session.rs` concurrently) and is the documented
            // handoff for whoever finishes closing this gap.
            ..Default::default()
        }
    }
}

/// **Same gap as the `From<FileRecord>` impl
/// above, mirrored on the receive side**: `f.record_kind`/
/// `f.symlink_target`/`f.symlink_out_of_root_or_absolute`/`f.exec_bit`
/// (now present on the wire — see `sync.proto`) are read by nothing here,
/// because `FileRecord` has no field to hold them. A caller that needs an
/// incoming peer's advertised kind/target/exec-bit (`peer_session.rs`'s
/// `reconcile_one_file`/`reconcile_files_if_authorized`, ahead of
/// `materialize_symlink_at`/`try_apply_metadata_only_update`) must read
/// those fields off the original `proto::FileInfo` directly — e.g. via
/// `SyncState::set_record_kind`/`set_symlink_target`/
/// `set_symlink_out_of_root`/`set_exec_bit` calls alongside `upsert_file`
/// — before or instead of relying on this conversion, since converting
/// through `FileRecord` silently drops them. That wiring is the
/// documented handoff into `peer_session.rs`, out of this section's scope.
impl From<proto::FileInfo> for FileRecord {
    fn from(f: proto::FileInfo) -> Self {
        FileRecord {
            path: f.path,
            size: f.size,
            mtime_unix_nanos: f.mtime_unix_nanos,
            version: VersionVector::from_counters(
                f.version.unwrap_or_default().counters.into_iter().collect(),
            ),
            blocks: f.blocks.into_iter().map(Into::into).collect(),
            deleted: f.deleted,
        }
    }
}

/// Whether a file's content is actually present on disk. Purely local —
/// never sent to peers (see `on-demand-sync` ): two devices can
/// disagree about a file's materialization state while agreeing on its
/// version and content, so this deliberately isn't a `FileRecord` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MaterializationState {
    /// Full content is present on disk.
    Hydrated,
    /// Only metadata is present; content must be fetched before reading.
    Placeholder,
    /// A hydration fetch is in progress.
    Hydrating,
}

impl MaterializationState {
    pub fn as_db_str(self) -> &'static str {
        match self {
            MaterializationState::Hydrated => "hydrated",
            MaterializationState::Placeholder => "placeholder",
            MaterializationState::Hydrating => "hydrating",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "placeholder" => MaterializationState::Placeholder,
            "hydrating" => MaterializationState::Hydrating,
            _ => MaterializationState::Hydrated,
        }
    }
}

/// A folder group's default materialization behavior for newly-adopted
/// files (`on-demand-sync` ).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MaterializationPolicy {
    /// Fetch and write full content immediately — the original MVP behavior.
    Eager,
    /// Write a placeholder; fetch content only on access or pin.
    OnDemand,
}

impl MaterializationPolicy {
    pub fn as_db_str(self) -> &'static str {
        match self {
            MaterializationPolicy::Eager => "eager",
            MaterializationPolicy::OnDemand => "ondemand",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "ondemand" => MaterializationPolicy::OnDemand,
            _ => MaterializationPolicy::Eager,
        }
    }
}

/// The kind of filesystem entry a file-index row represents
/// () — deliberately **not** a
/// `FileRecord` field: like `MaterializationState`/`pinned` before it, this
/// is index-local metadata surfaced through dedicated `SyncState`
/// getters/setters (`SyncState::get_record_kind`/`set_record_kind`) rather
/// than round-tripped through `upsert_file`'s `FileRecord` parameter. That
/// keeps every existing `FileRecord { .. }` construction site across the
/// workspace (there are dozens, in crates this task doesn't own) compiling
/// unchanged — populating this meaningfully at scan/watch time is a later
/// section's job, not this one's.
///
/// Deliberately **orthogonal to `FileRecord::deleted`**, not a superset of
/// it: there is no `Tombstone` variant here. A tombstoned symlink keeps
/// `record_kind = Symlink` (`deleted` is set separately) so that
/// tombstone-application code (the symlink-tombstone requirement)
/// can tell "remove the symlink itself" apart from "remove a regular
/// file/directory" — collapsing that into a single `Tombstone` variant
/// would destroy exactly the information that distinction needs. `deleted`
/// remains the sole, unchanged source of truth for "is this a tombstone,"
/// matching every one of its ~20 existing call sites across the workspace.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordKind {
    /// A regular file. The default for every record that predates this
    /// change, and for any record built by code that hasn't been updated
    /// (yet) to classify entries explicitly — scan/watch today only ever
    /// produce regular-file records.
    #[default]
    File,
    /// A directory. Not synced as its own content-bearing record today,
    /// but reserved here since the on-disk entry it corresponds to is a
    /// real, distinct kind from a regular file.
    Directory,
    /// A symlink; see `symlink_target` accessor for its raw, unresolved
    /// target text.
    Symlink,
}

impl RecordKind {
    pub fn as_db_str(self) -> &'static str {
        match self {
            RecordKind::File => "file",
            RecordKind::Directory => "directory",
            RecordKind::Symlink => "symlink",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "directory" => RecordKind::Directory,
            "symlink" => RecordKind::Symlink,
            _ => RecordKind::File,
        }
    }
}

/// A folder link's directional propagation mode, governed by a
/// "Propagation gating" table (see each variant below) — persisted
/// alongside `paused` on
/// `links`, device-local like `chunking_policy`/`materialization_policy`
/// above (each side of a link independently chooses its own mode; there is
/// no requirement that both peers of a link agree, matching those two
/// existing per-link policies' own precedent).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkMode {
    /// Sends local changes and applies incoming peer changes — the
    /// unchanged, original behavior every link had before this feature
    /// existed, and the default for every pre-existing and newly-created
    /// link.
    #[default]
    SendReceive,
    /// Sends local changes; an incoming peer change is never applied —
    /// recorded as an out-of-sync item instead.
    SendOnly,
    /// Applies incoming peer changes; a local modification is never sent —
    /// recorded as a receive-only-changed item instead.
    ReceiveOnly,
}

impl LinkMode {
    pub fn as_db_str(self) -> &'static str {
        match self {
            LinkMode::SendReceive => "send_receive",
            LinkMode::SendOnly => "send_only",
            LinkMode::ReceiveOnly => "receive_only",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "send_only" => LinkMode::SendOnly,
            "receive_only" => LinkMode::ReceiveOnly,
            _ => LinkMode::SendReceive,
        }
    }
}

/// A folder link's chunking algorithm (`content-defined-chunking` design
/// D3) — device-local, opt-in; see for why this doesn't need
/// cross-device agreement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChunkingPolicy {
    /// The original fixed-size chunking ('s default).
    Fixed,
    /// Content-defined chunking for files at or above the size threshold
    /// (`chunker::CDC_SIZE_THRESHOLD`); smaller files still use `Fixed`.
    ContentDefined,
}

impl ChunkingPolicy {
    pub fn as_db_str(self) -> &'static str {
        match self {
            ChunkingPolicy::Fixed => "fixed",
            ChunkingPolicy::ContentDefined => "content_defined",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "content_defined" => ChunkingPolicy::ContentDefined,
            _ => ChunkingPolicy::Fixed,
        }
    }
}

/// Reads the POSIX owner-executable bit off
/// `metadata` — the capture-side counterpart to `chunker::apply_exec_bit`'s
/// materialization-side apply. Always `false` on non-Unix platforms (no error,
/// no attempted read of a bit that doesn't exist there).
///
/// **Cross-section call-site note**: this needs to be called from
/// `local_change.rs`'s record-building code — the scanner's per-entry
/// `std::fs::Metadata` read (`LocalChangeProcessor::scan_existing_files`)
/// and the watcher's per-event metadata read (`process_event`) — for a
/// path classified as a regular file (never for a symlink; see
/// `RecordKind::Symlink`, which carries no exec bit of its own), with the
/// result persisted via `SyncState::set_exec_bit` the same way
/// `record_kind`/`symlink_target` already are for symlinks. That call
/// site lives in a file owned by this change's section 2 (scan/watch
/// symlink classification), developed in parallel with this section —
/// this function is the ready-to-call capture primitive; wiring the
/// actual call site is intentionally left to whoever lands it, to avoid
/// two agents editing `local_change.rs` at once.
#[cfg(unix)]
pub fn owner_exec_bit_from_metadata(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o100 != 0
}

/// See the `#[cfg(unix)]` `owner_exec_bit_from_metadata` above — the
/// no-op-and-always-`false` Windows/other-platform counterpart explicitly
/// requires (Windows has no owner-exec permission bit to read).
#[cfg(not(unix))]
pub fn owner_exec_bit_from_metadata(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod owner_exec_bit_tests {
    use super::owner_exec_bit_from_metadata;

    /// a freshly-created file (default create mode, no exec
    /// bits) reads as not executable, and setting the owner-exec bit via
    /// `chunker::apply_exec_bit` (exercised indirectly here through a
    /// plain `set_permissions`, to keep this test self-contained within
    /// `types.rs`) flips what this function reads back — the capture and
    /// apply sides agree on the same bit.
    #[cfg(unix)]
    #[test]
    fn reads_the_owner_exec_bit_poxis_permissions_actually_carry() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("maybe-script");
        std::fs::write(&path, b"echo hi").unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!owner_exec_bit_from_metadata(&std::fs::metadata(&path).unwrap()));

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o744)).unwrap();
        assert!(owner_exec_bit_from_metadata(&std::fs::metadata(&path).unwrap()));
    }

    /// this must never error or panic, on any platform, for an
    /// ordinary file's metadata — the only branch actually reachable on a
    /// non-Unix build always returns `false` unconditionally.
    #[test]
    fn never_panics_on_ordinary_file_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.txt");
        std::fs::write(&path, b"hello").unwrap();
        let _ = owner_exec_bit_from_metadata(&std::fs::metadata(&path).unwrap());
    }
}

//! Canonical materialized-state snapshot used by R3.3 history re-bootstrap.
//!
//! A checkpoint's `snapshot_hash` commits to the bytes produced here. The
//! snapshot deliberately contains more than the current file index: it also
//! carries retained version-history rows, the checkpoint-frontier `Change`
//! bodies, every `FileVersion` those rows/frontier changes need, and the
//! Lamport/authorization coordinates of direct parents removed by compaction.
//! That last component lets startup/authenticated-history validation distinguish
//! an intentional compacted boundary from a missing/corrupt parent without
//! inventing causal or authorization coordinates.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use crate::change::{Change, ChangeHash, FileVersion, FolderGroupId, VersionHash};
use crate::compaction::Checkpoint;
use crate::error::SyncError;
use crate::types::{BlockInfo, FileRecord, RecordKind};
use crate::version_vector::VersionVector;

const SNAPSHOT_DOMAIN: &[u8; 8] = b"YLNKsnp\x01";
const MAX_SNAPSHOT_FILES: usize = 1_000_000;
const MAX_FRONTIER_CHANGES: usize = 4096;
const MAX_FILE_VERSIONS: usize = 1_000_000;
const MAX_BOUNDARY_EDGES: usize = 1_000_000;
const MAX_STRING_BYTES: usize = 1024 * 1024;
const MAX_BLOB_BYTES: usize = 64 * 1024 * 1024;
const MAX_BLOCKS_PER_FILE: usize = 1_000_000;
const MAX_VERSION_COUNTERS: usize = 100_000;

/// Durable version-history state mirrored from the `files.state` column.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SnapshotVersionState {
    Current,
    Superseded,
    Trashed,
}

impl SnapshotVersionState {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Superseded => "superseded",
            Self::Trashed => "trashed",
        }
    }

    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "current" => Some(Self::Current),
            "superseded" => Some(Self::Superseded),
            "trashed" => Some(Self::Trashed),
            _ => None,
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::Current => 0,
            Self::Superseded => 1,
            Self::Trashed => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, SyncError> {
        match tag {
            0 => Ok(Self::Current),
            1 => Ok(Self::Superseded),
            2 => Ok(Self::Trashed),
            _ => Err(SyncError::CorruptState(
                "re-bootstrap snapshot has unknown version-history state".into(),
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SnapshotFile {
    pub record: FileRecord,
    pub version_seq: i64,
    pub state: SnapshotVersionState,
    pub origin_device_id: Option<String>,
    pub record_kind: RecordKind,
    pub symlink_target: Option<String>,
    pub symlink_out_of_root: bool,
    pub exec_bit: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BoundaryParentAuth {
    pub child_hash: ChangeHash,
    pub parent_hash: ChangeHash,
    pub parent_lamport: u64,
    pub parent_auth_seq: u64,
    pub parent_auth_epoch: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RebootstrapSnapshot {
    pub group_id: FolderGroupId,
    pub files: Vec<SnapshotFile>,
    pub frontier_changes: Vec<Vec<u8>>,
    pub file_versions: Vec<Vec<u8>>,
    pub boundary_parent_auth: Vec<BoundaryParentAuth>,
}

impl RebootstrapSnapshot {
    pub fn new(
        group_id: FolderGroupId,
        mut files: Vec<SnapshotFile>,
        frontier_changes: Vec<Vec<u8>>,
        file_versions: Vec<Vec<u8>>,
        mut boundary_parent_auth: Vec<BoundaryParentAuth>,
    ) -> Result<Self, SyncError> {
        files.sort_by(|a, b| {
            a.record
                .path
                .cmp(&b.record.path)
                .then(a.version_seq.cmp(&b.version_seq))
                .then(a.state.cmp(&b.state))
        });
        if files.windows(2).any(|pair| {
            pair[0].record.path == pair[1].record.path
                && pair[0].version_seq == pair[1].version_seq
        }) {
            return Err(SyncError::CorruptState(
                "re-bootstrap snapshot contains duplicate (path, version_seq) rows".into(),
            ));
        }
        let mut current_paths = BTreeSet::new();
        for file in &files {
            if file.state == SnapshotVersionState::Current
                && !current_paths.insert(file.record.path.clone())
            {
                return Err(SyncError::CorruptState(
                    "re-bootstrap snapshot contains more than one current row for a path".into(),
                ));
            }
        }

        let mut canonical_changes = Vec::with_capacity(frontier_changes.len());
        for encoded in frontier_changes {
            let change = Change::from_wire_bytes(&encoded).map_err(|error| {
                SyncError::CorruptState(format!(
                    "re-bootstrap snapshot contains an invalid frontier change: {error}"
                ))
            })?;
            if change.group_id != group_id {
                return Err(SyncError::CorruptState(
                    "re-bootstrap snapshot frontier change belongs to another group".into(),
                ));
            }
            canonical_changes.push((change.compute_hash(), encoded));
        }
        canonical_changes.sort_by_key(|(hash, _)| *hash);
        if canonical_changes.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(SyncError::CorruptState(
                "re-bootstrap snapshot contains duplicate frontier changes".into(),
            ));
        }

        let mut canonical_versions = Vec::with_capacity(file_versions.len());
        for encoded in file_versions {
            let version = FileVersion::from_canonical_encoding(&encoded).map_err(|error| {
                SyncError::CorruptState(format!(
                    "re-bootstrap snapshot contains an invalid file version: {error}"
                ))
            })?;
            canonical_versions.push((version.version_hash, encoded));
        }
        canonical_versions.sort_by_key(|(hash, _)| *hash);
        if canonical_versions.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(SyncError::CorruptState(
                "re-bootstrap snapshot contains duplicate file versions".into(),
            ));
        }

        boundary_parent_auth.sort();
        boundary_parent_auth.dedup();

        let snapshot = Self {
            group_id,
            files,
            frontier_changes: canonical_changes.into_iter().map(|(_, bytes)| bytes).collect(),
            file_versions: canonical_versions.into_iter().map(|(_, bytes)| bytes).collect(),
            boundary_parent_auth,
        };
        snapshot.validate_bounds()?;
        Ok(snapshot)
    }

    fn validate_bounds(&self) -> Result<(), SyncError> {
        if self.files.len() > MAX_SNAPSHOT_FILES
            || self.frontier_changes.len() > MAX_FRONTIER_CHANGES
            || self.file_versions.len() > MAX_FILE_VERSIONS
            || self.boundary_parent_auth.len() > MAX_BOUNDARY_EDGES
        {
            return Err(SyncError::CorruptState(
                "re-bootstrap snapshot exceeds a collection bound".into(),
            ));
        }
        for file in &self.files {
            if file.version_seq < 0
                || file.record.path.len() > MAX_STRING_BYTES
                || file.origin_device_id.as_ref().is_some_and(|v| v.len() > MAX_STRING_BYTES)
                || file.symlink_target.as_ref().is_some_and(|v| v.len() > MAX_STRING_BYTES)
                || file.record.blocks.len() > MAX_BLOCKS_PER_FILE
                || file.record.version.counters().len() > MAX_VERSION_COUNTERS
            {
                return Err(SyncError::CorruptState(
                    "re-bootstrap snapshot file exceeds a field bound".into(),
                ));
            }
        }
        if self.frontier_changes.iter().any(|v| v.len() > MAX_BLOB_BYTES)
            || self.file_versions.iter().any(|v| v.len() > MAX_BLOB_BYTES)
        {
            return Err(SyncError::CorruptState(
                "re-bootstrap snapshot blob exceeds the per-item bound".into(),
            ));
        }
        Ok(())
    }

    pub fn snapshot_hash(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_encoding()).into()
    }

    pub fn canonical_encoding(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SNAPSHOT_DOMAIN);
        put_str(&mut out, self.group_id.as_str());

        put_u32(&mut out, self.files.len() as u32);
        for file in &self.files {
            put_str(&mut out, &file.record.path);
            put_u64(&mut out, file.record.size);
            put_i64(&mut out, file.record.mtime_unix_nanos);
            out.push(file.record.deleted as u8);
            put_i64(&mut out, file.version_seq);
            out.push(file.state.tag());

            put_u32(&mut out, file.record.version.counters().len() as u32);
            for (device, counter) in file.record.version.counters() {
                put_str(&mut out, device);
                put_u64(&mut out, *counter);
            }

            put_u32(&mut out, file.record.blocks.len() as u32);
            for block in &file.record.blocks {
                put_bytes(&mut out, &block.hash);
                put_u64(&mut out, block.offset);
                put_u32(&mut out, block.size);
            }

            put_opt_str(&mut out, file.origin_device_id.as_deref());
            out.push(match file.record_kind {
                RecordKind::File => 0,
                RecordKind::Directory => 1,
                RecordKind::Symlink => 2,
            });
            put_opt_str(&mut out, file.symlink_target.as_deref());
            out.push(file.symlink_out_of_root as u8);
            out.push(file.exec_bit as u8);
        }

        put_u32(&mut out, self.frontier_changes.len() as u32);
        for encoded in &self.frontier_changes {
            put_bytes(&mut out, encoded);
        }

        put_u32(&mut out, self.file_versions.len() as u32);
        for encoded in &self.file_versions {
            put_bytes(&mut out, encoded);
        }

        put_u32(&mut out, self.boundary_parent_auth.len() as u32);
        for edge in &self.boundary_parent_auth {
            out.extend_from_slice(edge.child_hash.as_bytes());
            out.extend_from_slice(edge.parent_hash.as_bytes());
            put_u64(&mut out, edge.parent_lamport);
            put_u64(&mut out, edge.parent_auth_seq);
            put_u64(&mut out, edge.parent_auth_epoch);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SyncError> {
        let mut reader = Reader::new(bytes);
        reader.expect(SNAPSHOT_DOMAIN)?;
        let group_id = FolderGroupId(reader.string(MAX_STRING_BYTES)?);

        let file_count = reader.count(MAX_SNAPSHOT_FILES)?;
        let mut files = Vec::with_capacity(file_count);
        for _ in 0..file_count {
            let path = reader.string(MAX_STRING_BYTES)?;
            let size = reader.u64()?;
            let mtime_unix_nanos = reader.i64()?;
            let deleted = reader.bool()?;
            let version_seq = reader.i64()?;
            let state = SnapshotVersionState::from_tag(reader.byte()?)?;

            let counter_count = reader.count(MAX_VERSION_COUNTERS)?;
            let mut counters = BTreeMap::new();
            for _ in 0..counter_count {
                let device = reader.string(MAX_STRING_BYTES)?;
                let counter = reader.u64()?;
                if counters.insert(device, counter).is_some() {
                    return Err(SyncError::CorruptState(
                        "re-bootstrap snapshot has duplicate version-vector device".into(),
                    ));
                }
            }

            let block_count = reader.count(MAX_BLOCKS_PER_FILE)?;
            let mut blocks = Vec::with_capacity(block_count);
            for _ in 0..block_count {
                blocks.push(BlockInfo {
                    hash: reader.bytes(MAX_BLOB_BYTES)?,
                    offset: reader.u64()?,
                    size: reader.u32()?,
                });
            }

            let origin_device_id = reader.opt_string(MAX_STRING_BYTES)?;
            let record_kind = match reader.byte()? {
                0 => RecordKind::File,
                1 => RecordKind::Directory,
                2 => RecordKind::Symlink,
                _ => {
                    return Err(SyncError::CorruptState(
                        "re-bootstrap snapshot has unknown record kind".into(),
                    ));
                }
            };
            let symlink_target = reader.opt_string(MAX_STRING_BYTES)?;
            let symlink_out_of_root = reader.bool()?;
            let exec_bit = reader.bool()?;

            files.push(SnapshotFile {
                record: FileRecord {
                    path,
                    size,
                    mtime_unix_nanos,
                    version: VersionVector::from_counters(counters),
                    blocks,
                    deleted,
                },
                version_seq,
                state,
                origin_device_id,
                record_kind,
                symlink_target,
                symlink_out_of_root,
                exec_bit,
            });
        }

        let change_count = reader.count(MAX_FRONTIER_CHANGES)?;
        let mut frontier_changes = Vec::with_capacity(change_count);
        for _ in 0..change_count {
            frontier_changes.push(reader.bytes(MAX_BLOB_BYTES)?);
        }

        let version_count = reader.count(MAX_FILE_VERSIONS)?;
        let mut file_versions = Vec::with_capacity(version_count);
        for _ in 0..version_count {
            file_versions.push(reader.bytes(MAX_BLOB_BYTES)?);
        }

        let boundary_count = reader.count(MAX_BOUNDARY_EDGES)?;
        let mut boundary_parent_auth = Vec::with_capacity(boundary_count);
        for _ in 0..boundary_count {
            boundary_parent_auth.push(BoundaryParentAuth {
                child_hash: ChangeHash(reader.array32()?),
                parent_hash: ChangeHash(reader.array32()?),
                parent_lamport: reader.u64()?,
                parent_auth_seq: reader.u64()?,
                parent_auth_epoch: reader.u64()?,
            });
        }
        reader.finish()?;
        Self::new(group_id, files, frontier_changes, file_versions, boundary_parent_auth)
    }

    pub fn validate_against_checkpoint(&self, checkpoint: &Checkpoint) -> Result<(), SyncError> {
        if self.group_id != checkpoint.group_id {
            return Err(SyncError::CorruptState(
                "re-bootstrap snapshot group does not match checkpoint".into(),
            ));
        }
        if self.snapshot_hash() != checkpoint.snapshot_hash {
            return Err(SyncError::CorruptState(
                "re-bootstrap snapshot hash does not match checkpoint".into(),
            ));
        }

        let snapshot_frontier: BTreeSet<ChangeHash> = self
            .frontier_changes
            .iter()
            .map(|encoded| {
                Change::from_wire_bytes(encoded)
                    .map(|change| change.compute_hash())
                    .map_err(|error| {
                        SyncError::CorruptState(format!(
                            "re-bootstrap snapshot contains an invalid frontier change: {error}"
                        ))
                    })
            })
            .collect::<Result<_, _>>()?;
        let checkpoint_frontier: BTreeSet<ChangeHash> = checkpoint.frontier.iter().copied().collect();
        if snapshot_frontier != checkpoint_frontier {
            return Err(SyncError::CorruptState(
                "re-bootstrap snapshot frontier changes do not match checkpoint frontier".into(),
            ));
        }

        let version_hashes: BTreeSet<VersionHash> = self
            .file_versions
            .iter()
            .map(|encoded| {
                FileVersion::from_canonical_encoding(encoded)
                    .map(|version| version.version_hash)
                    .map_err(|error| {
                        SyncError::CorruptState(format!(
                            "re-bootstrap snapshot contains an invalid file version: {error}"
                        ))
                    })
            })
            .collect::<Result<_, _>>()?;
        for encoded in &self.frontier_changes {
            let change = Change::from_wire_bytes(encoded).map_err(|error| {
                SyncError::CorruptState(format!(
                    "re-bootstrap snapshot contains an invalid frontier change: {error}"
                ))
            })?;
            for op in &change.ops {
                let version = match op {
                    crate::change::Op::Create { version, .. }
                    | crate::change::Op::Update { version, .. }
                    | crate::change::Op::Move { version, .. } => Some(*version),
                    crate::change::Op::Delete { .. } => None,
                };
                if version.is_some_and(|hash| !version_hashes.contains(&hash)) {
                    return Err(SyncError::CorruptState(
                        "re-bootstrap snapshot is missing a frontier-referenced file version".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn put_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}
fn put_str(out: &mut Vec<u8>, value: &str) {
    put_bytes(out, value.as_bytes());
}
fn put_opt_str(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            out.push(1);
            put_str(out, value);
        }
        None => out.push(0),
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], SyncError> {
        let end = self.pos.checked_add(len).ok_or_else(|| {
            SyncError::CorruptState("re-bootstrap snapshot length overflow".into())
        })?;
        if end > self.bytes.len() {
            return Err(SyncError::CorruptState(
                "truncated re-bootstrap snapshot".into(),
            ));
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn expect(&mut self, expected: &[u8]) -> Result<(), SyncError> {
        if self.take(expected.len())? != expected {
            return Err(SyncError::CorruptState(
                "re-bootstrap snapshot domain/version mismatch".into(),
            ));
        }
        Ok(())
    }

    fn byte(&mut self) -> Result<u8, SyncError> {
        Ok(self.take(1)?[0])
    }

    fn bool(&mut self) -> Result<bool, SyncError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(SyncError::CorruptState(
                "re-bootstrap snapshot contains non-canonical boolean".into(),
            )),
        }
    }

    fn u32(&mut self) -> Result<u32, SyncError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, SyncError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn i64(&mut self) -> Result<i64, SyncError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn count(&mut self, max: usize) -> Result<usize, SyncError> {
        let count = self.u32()? as usize;
        if count > max {
            return Err(SyncError::CorruptState(
                "re-bootstrap snapshot count exceeds bound".into(),
            ));
        }
        Ok(count)
    }

    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, SyncError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(SyncError::CorruptState(
                "re-bootstrap snapshot item exceeds bound".into(),
            ));
        }
        Ok(self.take(len)?.to_vec())
    }

    fn string(&mut self, max: usize) -> Result<String, SyncError> {
        String::from_utf8(self.bytes(max)?).map_err(|_| {
            SyncError::CorruptState("re-bootstrap snapshot contains invalid UTF-8".into())
        })
    }

    fn opt_string(&mut self, max: usize) -> Result<Option<String>, SyncError> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(self.string(max)?)),
            _ => Err(SyncError::CorruptState(
                "re-bootstrap snapshot contains non-canonical option tag".into(),
            )),
        }
    }

    fn array32(&mut self) -> Result<[u8; 32], SyncError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn finish(self) -> Result<(), SyncError> {
        if self.pos != self.bytes.len() {
            return Err(SyncError::CorruptState(
                "re-bootstrap snapshot has trailing bytes".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::change::{ChangeAuth, DeviceId, FileMeta, Op, SyncPath, VersionBlock};

    #[test]
    fn canonical_snapshot_round_trips_and_hashes_identically() {
        let group = FolderGroupId("g".into());
        let version = FileVersion::new(
            vec![VersionBlock { hash: crate::change::BlockHash(vec![7; 32]), size: 3 }],
            3,
            FileMeta {
                mtime_unix_nanos: 11,
                record_kind: RecordKind::File,
                symlink_target: None,
                exec_bit: false,
            },
        );
        let change = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            DeviceId("d".into()),
            group.clone(),
            vec![Op::Create { path: SyncPath("a".into()), version: version.version_hash }],
            &SigningKey::from_bytes(&[3; 32]),
        );
        let snapshot = RebootstrapSnapshot::new(
            group.clone(),
            vec![SnapshotFile {
                record: FileRecord {
                    path: "a".into(),
                    size: 3,
                    mtime_unix_nanos: 11,
                    version: VersionVector::new(),
                    blocks: vec![BlockInfo { hash: vec![7; 32], offset: 0, size: 3 }],
                    deleted: false,
                },
                version_seq: 0,
                state: SnapshotVersionState::Current,
                origin_device_id: Some("d".into()),
                record_kind: RecordKind::File,
                symlink_target: None,
                symlink_out_of_root: false,
                exec_bit: false,
            }],
            vec![change.to_wire_bytes()],
            vec![version.canonical_encoding()],
            vec![],
        )
        .unwrap();
        let encoded = snapshot.canonical_encoding();
        let decoded = RebootstrapSnapshot::decode(&encoded).unwrap();
        assert_eq!(decoded, snapshot);
        assert_eq!(decoded.snapshot_hash(), snapshot.snapshot_hash());
        let checkpoint = Checkpoint::new(group, vec![change.compute_hash()], snapshot.snapshot_hash());
        decoded.validate_against_checkpoint(&checkpoint).unwrap();
    }

    #[test]
    fn snapshot_can_retain_multiple_versions_for_one_path() {
        let group = FolderGroupId("g".into());
        let record = |mtime| FileRecord {
            path: "a".into(),
            size: 0,
            mtime_unix_nanos: mtime,
            version: VersionVector::new(),
            blocks: vec![],
            deleted: false,
        };
        let snapshot = RebootstrapSnapshot::new(
            group,
            vec![
                SnapshotFile {
                    record: record(1),
                    version_seq: 1,
                    state: SnapshotVersionState::Superseded,
                    origin_device_id: None,
                    record_kind: RecordKind::File,
                    symlink_target: None,
                    symlink_out_of_root: false,
                    exec_bit: false,
                },
                SnapshotFile {
                    record: record(2),
                    version_seq: 2,
                    state: SnapshotVersionState::Current,
                    origin_device_id: None,
                    record_kind: RecordKind::File,
                    symlink_target: None,
                    symlink_out_of_root: false,
                    exec_bit: false,
                },
            ],
            vec![],
            vec![],
            vec![],
        )
        .unwrap();
        assert_eq!(snapshot.files.len(), 2);
    }
}

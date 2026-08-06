//! A minimal, versioned binary encoding for
//! [`FileIdentity`](yadorilink_root_authority::fs_identity::FileIdentity),
//! plus [`GenerationId`] -- the opaque identity type
//! `yadorilink-sync-core`'s `materialized_generation` module mints for each
//! `path_materialized_generations` row.
//!
//! Split out of `materialized_generation` (Phase 7D-7.2) because
//! `filesystem_transaction`'s epoch rows persist `FileIdentity` too
//! (`staged_identity`/`displaced_identity`) and reuse this exact encoding
//! rather than defining a second one -- both modules needed it once
//! `filesystem_transaction` moved into this crate. At that point,
//! `record_materialized_generation`/`lookup_materialized_generation` (the
//! rest of the original module) stayed in `yadorilink-sync-core` because
//! they called `dag_store::intern_causal_basis`, which had not moved yet;
//! `dag_store` moved into this crate in Phase 7D-7.3, and the rest of
//! `materialized_generation` followed in Phase 7D-7.5, landing in this
//! crate's sibling [`crate::materialized_generation`] module. This module
//! itself has no dependency on `dag_store` or any other sync-core-internal
//! type, so it moved first and stayed put across both phases.
//! `yadorilink-sync-core`'s `materialized_generation` module re-exports
//! everything here (and everything in [`crate::materialized_generation`])
//! under its old names, so its own ~10 in-crate consumers did not need
//! their `use` paths touched by either split.

use yadorilink_root_authority::fs_identity::{
    FileIdentity, ObjectKind, PlatformObjectId, VolumeIdentity, WindowsObjectId,
};

use crate::error::SyncSqliteError;

/// Version stamp for this module's `FileIdentity` binary encoding -- stored
/// once per row (by `materialized_generation::record_materialized_generation`)
/// so a future layout change is detectable rather than silently misread. A
/// blob at an old version fails closed on decode (see
/// `decoding_an_unknown_encoding_version_fails_closed`) rather than being
/// reinterpreted -- delete and re-import rebuilds it.
pub const MATERIALIZED_GENERATION_ENCODING_VERSION: i32 = 3;

/// A materialized generation's own identity: minted fresh on every
/// `record_materialized_generation` call, never reused, never edited in
/// place. Opaque past that -- nothing compares two `GenerationId`s.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GenerationId(pub String);

fn object_kind_encoding_tag(k: ObjectKind) -> u8 {
    match k {
        ObjectKind::RegularFile => 0,
        ObjectKind::Directory => 1,
        ObjectKind::Symlink => 2,
        ObjectKind::Fifo => 3,
        ObjectKind::Socket => 4,
        ObjectKind::BlockDevice => 5,
        ObjectKind::CharDevice => 6,
        ObjectKind::ReparsePoint => 7,
        ObjectKind::Other => 8,
    }
}

fn object_kind_from_encoding_tag(tag: u8) -> Result<ObjectKind, SyncSqliteError> {
    match tag {
        0 => Ok(ObjectKind::RegularFile),
        1 => Ok(ObjectKind::Directory),
        2 => Ok(ObjectKind::Symlink),
        3 => Ok(ObjectKind::Fifo),
        4 => Ok(ObjectKind::Socket),
        5 => Ok(ObjectKind::BlockDevice),
        6 => Ok(ObjectKind::CharDevice),
        7 => Ok(ObjectKind::ReparsePoint),
        8 => Ok(ObjectKind::Other),
        other => Err(SyncSqliteError::CorruptState(format!(
            "unknown fs_identity::ObjectKind tag {other} in a stored filesystem_identity blob"
        ))),
    }
}

fn volume_identity_tag(v: VolumeIdentity) -> u8 {
    match v {
        VolumeIdentity::Unix { .. } => 0,
        VolumeIdentity::Windows { .. } => 1,
    }
}

fn platform_object_id_tag(o: PlatformObjectId) -> u8 {
    match o {
        PlatformObjectId::Unix { .. } => 0,
        PlatformObjectId::Windows(_) => 1,
    }
}

/// Sub-tag distinguishing `PlatformObjectId::Windows`'s two `WindowsObjectId`
/// cases -- only meaningful once `platform_object_id_tag` above is `1`.
fn windows_object_id_subtag(w: WindowsObjectId) -> u8 {
    match w {
        WindowsObjectId::Fallback { .. } => 0,
        WindowsObjectId::Proven { .. } => 1,
    }
}

/// Encodes a [`FileIdentity`] as a versioned, self-describing byte blob.
/// Not content-addressed like `causal_basis`'s encoding: this is a direct
/// field encoding of one observation, not a hash naming a deduplicated set.
pub fn encode_file_identity(identity: &FileIdentity) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(MATERIALIZED_GENERATION_ENCODING_VERSION as u8);
    buf.push(volume_identity_tag(identity.volume_identity));
    match identity.volume_identity {
        VolumeIdentity::Unix { device_id } => buf.extend_from_slice(&device_id.to_be_bytes()),
        VolumeIdentity::Windows { volume_serial_number } => {
            buf.extend_from_slice(&volume_serial_number.to_be_bytes())
        }
    }
    buf.push(platform_object_id_tag(identity.object_id));
    match identity.object_id {
        PlatformObjectId::Unix { inode } => buf.extend_from_slice(&inode.to_be_bytes()),
        PlatformObjectId::Windows(w) => {
            buf.push(windows_object_id_subtag(w));
            match w {
                WindowsObjectId::Fallback { file_index } => {
                    buf.extend_from_slice(&file_index.to_be_bytes())
                }
                WindowsObjectId::Proven { file_id } => buf.extend_from_slice(&file_id),
            }
        }
    }
    buf.push(object_kind_encoding_tag(identity.object_kind));
    match identity.generation_or_usn {
        Some(g) => {
            buf.push(1);
            buf.extend_from_slice(&g.to_be_bytes());
        }
        None => buf.push(0),
    }
    match identity.birth_or_creation_time {
        Some(t) => {
            buf.push(1);
            buf.extend_from_slice(&t.seconds_since_unix_epoch.to_be_bytes());
            buf.extend_from_slice(&t.subsec_nanos.to_be_bytes());
        }
        None => buf.push(0),
    }
    buf.extend_from_slice(&identity.observed_size.to_be_bytes());
    buf.extend_from_slice(&identity.metadata_fingerprint);
    match identity.link_count {
        Some(l) => {
            buf.push(1);
            buf.extend_from_slice(&l.to_be_bytes());
        }
        None => buf.push(0),
    }
    match identity.symlink_target_digest {
        Some(d) => {
            buf.push(1);
            buf.extend_from_slice(&d);
        }
        None => buf.push(0),
    }
    buf
}

/// A minimal cursor over a byte slice for [`decode_file_identity`] --
/// errors on truncation rather than panicking, since this reads a stored
/// BLOB a future encoding-version mismatch or on-disk corruption could have
/// shortened. `pub(crate)`: `crate::filesystem_transaction` reuses it for
/// its own `DirectoryIdentity` encoding rather than writing a second
/// cursor -- both live in this crate now, so no re-export is needed for
/// that reuse.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], SyncSqliteError> {
        let end = self.pos.checked_add(n).ok_or_else(|| {
            SyncSqliteError::CorruptState("filesystem_identity blob length overflow".to_string())
        })?;
        let slice = self.buf.get(self.pos..end).ok_or_else(|| {
            SyncSqliteError::CorruptState("filesystem_identity blob truncated".to_string())
        })?;
        self.pos = end;
        Ok(slice)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, SyncSqliteError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u32(&mut self) -> Result<u32, SyncSqliteError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, SyncSqliteError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub(crate) fn u128(&mut self) -> Result<u128, SyncSqliteError> {
        Ok(u128::from_be_bytes(self.take(16)?.try_into().unwrap()))
    }

    fn i64(&mut self) -> Result<i64, SyncSqliteError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub(crate) fn bool_flag(&mut self) -> Result<bool, SyncSqliteError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(SyncSqliteError::CorruptState(format!(
                "invalid boolean flag byte {other} in a stored filesystem_identity blob"
            ))),
        }
    }
}

pub fn decode_file_identity(blob: &[u8]) -> Result<FileIdentity, SyncSqliteError> {
    let mut r = Reader::new(blob);
    let encoding_version = r.u8()?;
    if encoding_version != MATERIALIZED_GENERATION_ENCODING_VERSION as u8 {
        return Err(SyncSqliteError::CorruptState(format!(
            "filesystem_identity blob encoding_version {encoding_version} is not this build's \
             {MATERIALIZED_GENERATION_ENCODING_VERSION}"
        )));
    }
    let volume_identity = match r.u8()? {
        0 => VolumeIdentity::Unix { device_id: r.u64()? },
        1 => VolumeIdentity::Windows { volume_serial_number: r.u64()? },
        other => {
            return Err(SyncSqliteError::CorruptState(format!(
                "unknown VolumeIdentity tag {other} in a stored filesystem_identity blob"
            )))
        }
    };
    let object_id = match r.u8()? {
        0 => PlatformObjectId::Unix { inode: r.u64()? },
        1 => match r.u8()? {
            0 => PlatformObjectId::Windows(WindowsObjectId::Fallback { file_index: r.u64()? }),
            1 => {
                let file_id: [u8; 16] =
                    r.take(16)?.try_into().expect("Reader::take(16) always returns 16 bytes");
                PlatformObjectId::Windows(WindowsObjectId::Proven { file_id })
            }
            other => {
                return Err(SyncSqliteError::CorruptState(format!(
                    "unknown WindowsObjectId subtag {other} in a stored filesystem_identity blob"
                )))
            }
        },
        other => {
            return Err(SyncSqliteError::CorruptState(format!(
                "unknown PlatformObjectId tag {other} in a stored filesystem_identity blob"
            )))
        }
    };
    let object_kind = object_kind_from_encoding_tag(r.u8()?)?;
    let generation_or_usn = if r.bool_flag()? { Some(r.u128()?) } else { None };
    let birth_or_creation_time = if r.bool_flag()? {
        let seconds_since_unix_epoch = r.i64()?;
        let subsec_nanos = r.u32()?;
        Some(yadorilink_root_authority::fs_identity::Timestamp {
            seconds_since_unix_epoch,
            subsec_nanos,
        })
    } else {
        None
    };
    let observed_size = r.u64()?;
    let metadata_fingerprint: [u8; 32] =
        r.take(32)?.try_into().expect("Reader::take(32) always returns exactly 32 bytes");
    let link_count = if r.bool_flag()? { Some(r.u64()?) } else { None };
    // See `MATERIALIZED_GENERATION_ENCODING_VERSION`'s doc for why this is
    // part of the encoding as of version 3: it is the only reuse
    // discriminator a symlink identity can ever carry, and
    // `optimistic_placement`'s commit-window binding compares a decoded
    // `staged_identity` (this function's output) against a live
    // re-observation through `FileIdentity::compare`, which needs it.
    let symlink_target_digest = if r.bool_flag()? {
        let bytes: [u8; 32] =
            r.take(32)?.try_into().expect("Reader::take(32) always returns exactly 32 bytes");
        Some(bytes)
    } else {
        None
    };
    Ok(FileIdentity {
        volume_identity,
        object_id,
        object_kind,
        generation_or_usn,
        birth_or_creation_time,
        observed_size,
        metadata_fingerprint,
        link_count,
        symlink_target_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_root_authority::fs_identity::Timestamp;

    fn sample_identity() -> FileIdentity {
        FileIdentity {
            volume_identity: VolumeIdentity::Unix { device_id: 7 },
            object_id: PlatformObjectId::Unix { inode: 42 },
            object_kind: ObjectKind::RegularFile,
            generation_or_usn: Some(3),
            birth_or_creation_time: Some(Timestamp {
                seconds_since_unix_epoch: 1_700_000_000,
                subsec_nanos: 123,
            }),
            observed_size: 1024,
            metadata_fingerprint: [9; 32],
            link_count: Some(1),
            symlink_target_digest: None,
        }
    }

    #[test]
    fn file_identity_round_trips_through_its_stored_encoding() {
        let identity = sample_identity();
        let blob = encode_file_identity(&identity);
        let decoded = decode_file_identity(&blob).unwrap();
        assert_eq!(decoded, identity);
    }

    #[test]
    fn a_real_symlinks_identity_round_trips_through_its_stored_encoding_digest_included() {
        // The round-trip tests above all construct a `FileIdentity` with
        // `symlink_target_digest` already `None`, so they pass regardless
        // of whether this encoding actually carries that field -- they
        // never observe it being anything else. This test exercises a
        // genuine decoded row: a real `FileIdentity::observe_path` call
        // against an actual symlink, which -- unlike every constructed
        // identity above -- populates `symlink_target_digest` with
        // `Some(_)` before encoding. See `MATERIALIZED_GENERATION_ENCODING_
        // VERSION`'s doc (bumped 2 -> 3 for exactly this) for why this
        // field is part of the encoding: it is the only reuse
        // discriminator a symlink identity can ever carry, so a decoded row
        // that lost it left `FileIdentity::compare` unable to conclude
        // `SameObject` for a symlink at all on a coarse-clock volume.
        let dir = tempfile::tempdir().unwrap();
        let link_path = dir.path().join("a-symlink");
        #[cfg(unix)]
        std::os::unix::fs::symlink("wherever-this-points", &link_path).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file("wherever-this-points", &link_path).unwrap();
        let live = FileIdentity::observe_path(&link_path).unwrap();
        assert!(
            live.symlink_target_digest.is_some(),
            "a live observation of a real symlink must populate symlink_target_digest"
        );

        let blob = encode_file_identity(&live);
        let decoded = decode_file_identity(&blob).unwrap();

        assert_eq!(decoded, live);
    }

    #[test]
    fn file_identity_round_trips_with_every_optional_field_absent() {
        let identity = FileIdentity {
            volume_identity: VolumeIdentity::Unix { device_id: 1 },
            object_id: PlatformObjectId::Unix { inode: 1 },
            object_kind: ObjectKind::Directory,
            generation_or_usn: None,
            birth_or_creation_time: None,
            observed_size: 0,
            metadata_fingerprint: [0; 32],
            link_count: None,
            symlink_target_digest: None,
        };
        let blob = encode_file_identity(&identity);
        let decoded = decode_file_identity(&blob).unwrap();
        assert_eq!(decoded, identity);
    }

    #[test]
    fn file_identity_round_trips_the_windows_fallback_variant_even_off_windows() {
        // Pure data encoding, no platform syscalls -- this must hold on
        // every build host, not just Windows, since a peer database could
        // in principle carry a Windows-observed identity.
        let identity = FileIdentity {
            volume_identity: VolumeIdentity::Windows { volume_serial_number: 0xdead_beef },
            object_id: PlatformObjectId::Windows(WindowsObjectId::Fallback {
                file_index: 0x1122_3344_5566_7788,
            }),
            object_kind: ObjectKind::ReparsePoint,
            generation_or_usn: None,
            birth_or_creation_time: None,
            observed_size: 5,
            metadata_fingerprint: [7; 32],
            link_count: None,
            symlink_target_digest: None,
        };
        let blob = encode_file_identity(&identity);
        let decoded = decode_file_identity(&blob).unwrap();
        assert_eq!(decoded, identity);
    }

    #[test]
    fn file_identity_round_trips_the_windows_proven_variant_even_off_windows() {
        // Same premise as the fallback-variant test above, for the proven
        // 128-bit `FILE_ID_INFO` case -- a 64-bit volume serial and a
        // 16-byte file id, both wider than the legacy fallback fields.
        let identity = FileIdentity {
            volume_identity: VolumeIdentity::Windows {
                volume_serial_number: 0x1122_3344_5566_7788,
            },
            object_id: PlatformObjectId::Windows(WindowsObjectId::Proven { file_id: [0xab; 16] }),
            object_kind: ObjectKind::ReparsePoint,
            generation_or_usn: None,
            birth_or_creation_time: None,
            observed_size: 5,
            metadata_fingerprint: [7; 32],
            link_count: None,
            symlink_target_digest: None,
        };
        let blob = encode_file_identity(&identity);
        let decoded = decode_file_identity(&blob).unwrap();
        assert_eq!(decoded, identity);
    }

    #[test]
    fn decoding_a_truncated_filesystem_identity_blob_fails_closed_not_panics() {
        let identity = sample_identity();
        let blob = encode_file_identity(&identity);
        let truncated = &blob[..blob.len() - 5];
        let result = decode_file_identity(truncated);
        assert!(matches!(result, Err(SyncSqliteError::CorruptState(_))));
    }

    #[test]
    fn decoding_an_unknown_encoding_version_fails_closed() {
        let identity = sample_identity();
        let mut blob = encode_file_identity(&identity);
        blob[0] = 0xff;
        let result = decode_file_identity(&blob);
        assert!(matches!(result, Err(SyncSqliteError::CorruptState(_))));
    }
}

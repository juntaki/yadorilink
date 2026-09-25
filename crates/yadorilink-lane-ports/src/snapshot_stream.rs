//! Moving a re-bootstrap snapshot over a history stream.
//!
//! A snapshot holds one entry per file in the group, plus its frontier
//! changes and file versions. At a hundred thousand files that is not a
//! message, and treating it as one would keep the old memory architecture on
//! a new transport: the wire would be better and the peak just as bad.
//!
//! So neither side ever holds a second copy:
//!
//! ```text
//!   sender    borrowed bytes  →  bounded chunks  →  stream
//!   receiver  stream  →  bounded chunks  →  incremental hash  →  spool file
//!                     →  EOF  →  hash == manifest.snapshot_hash  →  install
//! ```
//!
//! The receiver never reserves memory on a peer's say-so. There is no
//! declared length to believe: the stream ends when it ends, the spool grows
//! only as bytes actually arrive, and a ceiling stops an endless one. What
//! makes the result trustworthy is not the length but the hash — which the
//! *manifest* already fixed, and which is recomputed here over what actually
//! arrived.

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yadorilink_sync_substrate::LaneStream;

/// How much of a snapshot is read or written at a time.
const CHUNK_BYTES: usize = 64 * 1024;

/// The largest snapshot this device will accept. A peer that keeps sending
/// past this is not sending a snapshot.
pub const MAX_SNAPSHOT_BYTES: u64 = 4 << 30;

#[derive(Debug, thiserror::Error)]
pub enum SnapshotTransferError {
    #[error("snapshot stream io: {0}")]
    Io(#[from] std::io::Error),

    #[error("snapshot exceeded {MAX_SNAPSHOT_BYTES} bytes without ending")]
    TooLarge,

    /// What arrived is not what the signed manifest named. Reported rather
    /// than installed: the manifest is the authority on which snapshot this
    /// is, and the bytes have to answer to it.
    #[error("snapshot hashes to {actual} but its manifest names {expected}")]
    HashMismatch { expected: String, actual: String },
}

/// Write `bytes` to `stream` in bounded chunks and end the direction.
///
/// Borrows rather than owning: the caller is holding the only copy and this
/// must not make a second one.
pub async fn send_snapshot(
    stream: &mut LaneStream,
    bytes: &[u8],
) -> Result<(), SnapshotTransferError> {
    for chunk in bytes.chunks(CHUNK_BYTES) {
        stream.write_all(chunk).await?;
    }
    stream.flush().await?;
    // Ending the direction is how the far end learns the snapshot is
    // complete. There is deliberately no length prefix to disagree with it.
    let _ = stream.finish();
    Ok(())
}

/// Read a snapshot from `stream` into `spool`, verifying it against the hash
/// its manifest named.
///
/// Returns the number of bytes written. On any failure the spool is left for
/// the caller to discard; nothing here installs anything.
pub async fn receive_snapshot_into<W>(
    stream: &mut LaneStream,
    spool: &mut W,
    expected_hash: &[u8; 32],
) -> Result<u64, SnapshotTransferError>
where
    W: AsyncWriteExt + Unpin,
{
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; CHUNK_BYTES];
    let mut written: u64 = 0;

    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        written += read as u64;
        if written > MAX_SNAPSHOT_BYTES {
            return Err(SnapshotTransferError::TooLarge);
        }
        hasher.update(&buffer[..read]);
        spool.write_all(&buffer[..read]).await?;
    }
    spool.flush().await?;

    let actual: [u8; 32] = hasher.finalize().into();
    if actual != *expected_hash {
        return Err(SnapshotTransferError::HashMismatch {
            expected: hex::encode(expected_hash),
            actual: hex::encode(actual),
        });
    }
    Ok(written)
}

//! Current-only length-prefixed protobuf framing, shared by local non-gRPC
//! channels in the project (for example the daemon control socket).
//!
//! YadoriLink is not released yet, so development-build wire compatibility is
//! deliberately not preserved. Every frame starts with an explicit magic /
//! framing-generation marker. Bytes emitted by a pre-marker build are rejected
//! before protobuf decoding instead of being interpreted through unknown-field
//! or zero-default compatibility behavior.

use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const FRAME_MAGIC: [u8; 8] = *b"YDLK\0\0\0\x01";

/// The largest protobuf body one frame may carry. Public so a message
/// builder can size its own output against the real limit instead of a
/// guess -- see `RewindPreviewResponse`'s listing budget for the case that
/// needs it.
pub const MAX_FRAME_LEN: u32 = 1024 * 1024;

/// Refuses to emit a frame the reader below would reject anyway.
///
/// The limit was previously enforced on read only, so a writer could emit
/// an oversized frame and the failure surfaced at the far end as an opaque
/// "frame too large" on a message the reader could no longer identify.
/// Checked before any byte is written, so the stream is left clean and the
/// caller can respond with something smaller instead (the control socket
/// does exactly that).
pub async fn write_message<T: Message>(
    stream: &mut (impl AsyncWrite + Unpin),
    msg: &T,
) -> std::io::Result<()> {
    let body = msg.encode_to_vec();
    if body.len() > MAX_FRAME_LEN as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "refusing to write an oversized frame: {} bytes exceeds {MAX_FRAME_LEN}",
                body.len()
            ),
        ));
    }
    stream.write_all(&FRAME_MAGIC).await?;
    stream.write_all(&(body.len() as u32).to_be_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await
}

/// Returns `Ok(None)` on a clean EOF between frames.
pub async fn read_message<T: Message + Default>(
    stream: &mut (impl AsyncRead + Unpin),
) -> std::io::Result<Option<T>> {
    let mut magic = [0u8; FRAME_MAGIC.len()];
    match stream.read_exact(&mut magic).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    if magic != FRAME_MAGIC {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported YadoriLink framing generation",
        ));
    }

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame too large: {len} bytes"),
        ));
    }
    let mut body = vec![0u8; len as usize];
    stream.read_exact(&mut body).await?;
    T::decode(body.as_slice())
        .map(Some)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemonctl::DaemonControlRequest;

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_body_allocation() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            client.write_all(&FRAME_MAGIC).await.unwrap();
            client.write_all(&(MAX_FRAME_LEN + 1).to_be_bytes()).await.unwrap();
        });

        let err = read_message::<DaemonControlRequest>(&mut server).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// The write side enforces the same limit the read side does, before
    /// putting anything on the wire -- so an oversized message fails where
    /// it can still be diagnosed and replaced, not at a reader that has
    /// lost all context about what the frame was.
    #[tokio::test]
    async fn an_oversized_frame_is_refused_by_the_writer_with_the_stream_untouched() {
        use crate::daemonctl::{daemon_control_response::Payload, DaemonControlResponse};
        let (mut client, mut server) = tokio::io::duplex(64);
        let oversized = DaemonControlResponse {
            daemon_protocol_version: 0,
            payload: Some(Payload::Error("x".repeat(MAX_FRAME_LEN as usize + 1))),
        };

        let err = write_message(&mut client, &oversized).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("oversized frame"), "{err}");

        // Nothing reached the stream, so the connection is still usable for
        // a smaller reply rather than being left mid-frame.
        let small = DaemonControlResponse {
            daemon_protocol_version: 7,
            payload: Some(Payload::Error("too large".to_string())),
        };
        write_message(&mut client, &small).await.unwrap();
        let read = read_message::<DaemonControlResponse>(&mut server).await.unwrap().unwrap();
        assert_eq!(read.daemon_protocol_version, 7);
    }

    #[tokio::test]
    async fn pre_marker_frame_is_rejected_instead_of_decoded_compatibly() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            // Historical framing started directly with the four-byte body
            // length. Pad enough bytes for the current reader's magic read;
            // the mismatch must fail before any protobuf decode is attempted.
            client.write_all(&0u32.to_be_bytes()).await.unwrap();
            client.write_all(&[0u8; 4]).await.unwrap();
        });

        let err = read_message::<DaemonControlRequest>(&mut server).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("unsupported YadoriLink framing generation"));
    }
}

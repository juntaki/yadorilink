//! One block request, one bidirectional QUIC stream.
//!
//! ## Why a stream per request
//!
//! The control stream ([`crate::quic_peer_channel`]) is a conversation: an
//! ordered sequence of small messages whose meaning depends on the order
//! they arrived in. Block transfer is not that. It is a large, independent,
//! self-contained request/response, and putting it on the shared control
//! stream forced two things that a stream of its own removes outright.
//!
//! The first is correlation. An inline reply had to carry a `request_id`
//! so the requester could match an answer to a question, because several
//! answers shared one byte stream. A bidirectional stream *is* that
//! correlation: the answer arrives on the same stream the question went
//! out on, and nothing else does.
//!
//! The second is chunking. A control frame has a maximum length, so a block
//! larger than that had to be split across several messages, reassembled on
//! arrival, and tracked until every piece landed -- with each piece copied
//! out of the block's own buffer into a protobuf field on the way. Here the
//! body is written straight onto the stream and read straight off it: QUIC's
//! own flow control does the pacing, and the block's bytes are copied once
//! into the receiver's buffer rather than twice through an intermediate
//! encoding.
//!
//! ## The shape
//!
//! ```text
//! open_bi()
//!   requester -> length-prefixed BlockRequestHeader, FIN
//!   responder -> length-prefixed BlockResponseHeader
//!   responder -> raw body bytes (only when the header says Found), FIN
//! ```
//!
//! The two headers are length-prefixed with the same `u32` big-endian
//! prefix the control stream uses, checked against a ceiling before
//! anything is allocated. The body is not framed at all: its length is
//! declared in the response header the receiver has already read, so the
//! receiver knows exactly how many bytes to expect and reads exactly that
//! many. FIN is what makes an abandoned or truncated response observable as
//! an error rather than as a hang.

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::error::TransportError;

/// Bytes of length prefix in front of each header message, matching the
/// control stream's own framing so there is one length encoding in the peer
/// protocol rather than two.
const LENGTH_PREFIX_BYTES: usize = 4;

/// The largest header message either direction will send or accept.
///
/// Both headers are small and bounded by construction: a folder group id, a
/// path (itself capped at 4 KiB by the domain's own `MAX_PATH_BYTES`), a
/// 32-byte hash, and a handful of scalars. 64 KiB is far above anything
/// legitimate while still being a bound a hostile peer cannot turn four
/// bytes into a large allocation with.
pub const MAX_BLOCK_STREAM_HEADER_BYTES: usize = 64 * 1024;

/// The largest block body this device will read off a stream.
///
/// Restated here rather than imported from the domain crate that owns it
/// (`yadorilink_replica_domain::limits::MAX_BLOCK_SIZE_BYTES`), for the same
/// reason [`crate::quic_peer_channel`] restates its own inline-reply size:
/// the constant belongs to a crate that depends on this one, and the
/// dependency must not be inverted just to hold a number.
///
/// This is a backstop, not the real check. The caller knows the exact size
/// the response header declared and passes it in, and it also knows what
/// its own protocol considers a legal block; this ceiling exists so that a
/// caller which ever forgets to bound the declared size cannot turn a
/// peer's claim into an unbounded allocation here.
pub const MAX_BLOCK_STREAM_BODY_BYTES: usize = 16 * 1024 * 1024;

/// One block request's bidirectional QUIC stream.
///
/// Held by whichever side is currently driving the exchange: the requester
/// gets one from [`crate::QuicPeerChannel::open_block_stream`], the
/// responder from [`crate::QuicPeerChannel::accept_block_stream`]. Dropping
/// it before the exchange finishes resets the stream, which is exactly the
/// signal the far side needs -- a reset read reports an error rather than
/// waiting out a timeout for bytes that are never coming.
pub struct QuicBlockStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicBlockStream {
    pub(crate) fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }

    /// Writes one length-prefixed header message.
    pub async fn send_message(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        write_length_prefixed(&mut self.send, payload).await
    }

    /// Reads one length-prefixed header message, refusing a declared length
    /// above `max_len` before allocating anything.
    pub async fn recv_message(&mut self, max_len: usize) -> Result<Vec<u8>, TransportError> {
        read_length_prefixed(&mut self.recv, max_len).await
    }

    /// Writes the raw body bytes and ends this direction of the stream.
    ///
    /// Also the way a response with no body ends: an empty slice writes
    /// nothing and finishes, so every response path -- found or not -- ends
    /// the same way and the requester always sees a clean FIN rather than
    /// having to distinguish "no body coming" from "body not sent yet".
    pub async fn send_body(&mut self, body: &[u8]) -> Result<(), TransportError> {
        if !body.is_empty() {
            write_raw(&mut self.send, body).await?;
        }
        // `finish` only announces the end of this direction; it does not
        // wait for the peer, and its only failure mode is a stream that was
        // already reset, which the write above would have reported first.
        let _ = self.send.finish();
        Ok(())
    }

    /// Reads exactly `len` body bytes, then confirms the stream ends there.
    ///
    /// `len` comes from the response header the caller has already read and
    /// validated against its own protocol's block-size bound;
    /// [`MAX_BLOCK_STREAM_BODY_BYTES`] is the backstop for that check.
    ///
    /// The end-of-stream check is not decoration. It is what makes the
    /// declared size binding rather than merely advisory: a responder that
    /// writes more bytes than it declared is caught here instead of leaving
    /// them to be read as the front of some later message. And it is what
    /// lets the stream close cleanly -- quinn resets a receive stream that
    /// is dropped before its FIN is observed, so a reader that stops exactly
    /// on the last byte ends every single transfer with a `STOP_SENDING` to
    /// a peer that did nothing wrong.
    pub async fn recv_body(&mut self, len: usize) -> Result<Vec<u8>, TransportError> {
        if len > MAX_BLOCK_STREAM_BODY_BYTES {
            return Err(TransportError::MessageTooLarge(len, MAX_BLOCK_STREAM_BODY_BYTES));
        }
        let body = read_raw(&mut self.recv, len).await?;
        expect_end_of_stream(&mut self.recv).await?;
        Ok(body)
    }

    /// Ends this side's sending direction with nothing further to send.
    ///
    /// The requester calls this straight after its header: it has nothing
    /// else to say, and the FIN tells the responder so rather than leaving
    /// it to infer it.
    pub fn finish_send(&mut self) {
        let _ = self.send.finish();
    }
}

/// Writes `payload` behind a `u32` big-endian length prefix.
///
/// Shared rather than reimplemented per stream type: the in-memory channel
/// the sync session uses for simulation and tests speaks this same framing,
/// and a second copy of it is a second thing that can drift from the one on
/// the wire.
pub async fn write_length_prefixed<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), TransportError> {
    let Ok(length) = u32::try_from(payload.len()) else {
        return Err(TransportError::MessageTooLarge(payload.len(), u32::MAX as usize));
    };
    // One write for prefix and body together, for the same reason the
    // control stream does it: two writes would let a header reach the peer
    // arbitrarily long before its body, which is the state a reader would
    // otherwise have to hold an allocation open across.
    let mut framed = Vec::with_capacity(LENGTH_PREFIX_BYTES + payload.len());
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(payload);
    write_raw(writer, &framed).await
}

/// Writes every byte of `bytes`, as a `TransportError` rather than an
/// `io::Error` so every path in this module reports failures the same way.
async fn write_raw<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
) -> Result<(), TransportError> {
    writer.write_all(bytes).await.map_err(TransportError::Io)
}

/// Confirms the peer has finished sending: the next read must report
/// end-of-stream rather than more bytes.
async fn expect_end_of_stream<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<(), TransportError> {
    let mut extra = [0u8; 1];
    match reader.read(&mut extra).await {
        Ok(0) => Ok(()),
        Ok(_) => Err(TransportError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "peer sent more body bytes than its response header declared",
        ))),
        Err(error) => Err(TransportError::Io(error)),
    }
}

/// Reads exactly `len` bytes, or reports the stream ending early.
async fn read_raw<R: AsyncRead + Unpin>(
    reader: &mut R,
    len: usize,
) -> Result<Vec<u8>, TransportError> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut buffer = vec![0u8; len];
    reader.read_exact(&mut buffer).await.map_err(TransportError::Io)?;
    Ok(buffer)
}

/// Reads one `u32` big-endian length-prefixed message, refusing a declared
/// length above `max_len` *before* allocating for it.
pub async fn read_length_prefixed<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_len: usize,
) -> Result<Vec<u8>, TransportError> {
    let mut length = [0u8; LENGTH_PREFIX_BYTES];
    reader.read_exact(&mut length).await.map_err(TransportError::Io)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > max_len {
        return Err(TransportError::MessageTooLarge(length, max_len));
    }
    read_raw(reader, length).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two halves must be exact inverses: one runs on what this device
    /// emits, the other on what it accepts from a peer.
    #[tokio::test]
    async fn a_length_prefixed_message_round_trips() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        write_length_prefixed(&mut a, b"header bytes").await.unwrap();
        let read = read_length_prefixed(&mut b, MAX_BLOCK_STREAM_HEADER_BYTES).await.unwrap();
        assert_eq!(read, b"header bytes");
    }

    /// The bound is enforced on the declared length, not after reading the
    /// body: a peer that announces a huge frame must be refused while it
    /// has only spent four bytes.
    #[tokio::test]
    async fn an_oversized_declared_length_is_refused_before_allocating() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        a.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        let error = read_length_prefixed(&mut b, MAX_BLOCK_STREAM_HEADER_BYTES).await.unwrap_err();
        assert!(matches!(error, TransportError::MessageTooLarge(_, _)));
    }
}

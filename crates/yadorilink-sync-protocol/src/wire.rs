//! Framing for the reconciliation and bundle lanes.
//!
//! Every frame is length-prefixed and every length is checked against a hard
//! bound before a single byte is allocated. The peer on the other end may be
//! adversarial, so a declared length is a claim, never an instruction: a
//! decoder that allocates first and validates second hands a remote peer an
//! allocation primitive.
//!
//! The encoding is deliberately explicit rather than derived. There is no
//! compatibility to preserve — the protocol this replaces is being deleted —
//! so the format is written out where it can be read, bounded and reasoned
//! about.

use yadorilink_rbsr::{Fingerprint, ItemId, Range, RangeEnd, RbsrMessage};

use crate::error::WireError;

/// Bumped if the encoding below ever changes, or if the canonical encoding
/// of what the bundle lane carries changes. A peer speaking a different
/// version fails the handshake rather than silently misreading frames.
///
/// Version 2 adds `PutOrigin::Reasserted` to the change op encoding. The
/// framing here is untouched, but a version-1 peer decoding a bundle that
/// contains one fails deep inside the change decoder with an "unknown
/// put-origin discriminant" error, at a point where the only available
/// response is to reject history it cannot read. Failing the handshake
/// instead reports the actual problem -- the peers are not the same
/// protocol -- rather than surfacing it as unexplained history corruption.
///
/// Version 3 opens every reconciliation with an exchange of history-base
/// advertisements. A version-2 peer would read the advertisement frame as
/// a reconciliation round and fail somewhere inside it; failing the
/// handshake says what is actually wrong.
pub const PROTOCOL_VERSION: u32 = 3;

/// The largest reconciliation round accepted, in bytes.
pub const MAX_ROUND_BYTES: usize = 1 << 20;
/// The largest number of statements accepted in one round.
pub const MAX_ROUND_MESSAGES: usize = 1024;
/// The largest number of identifiers accepted in one listing.
pub const MAX_LISTING_IDS: usize = 4096;
/// The largest bundle payload accepted, in bytes.
pub const MAX_BUNDLE_BYTES: usize = 16 << 20;
/// The largest number of bundles requested in one go.
pub const MAX_BUNDLE_REQUEST: usize = 1024;
/// The largest group identifier accepted, in bytes.
pub const MAX_GROUP_BYTES: usize = 512;
/// The largest history-base advertisement accepted, in bytes. Room for a
/// full checkpoint frontier and a full head list, both bounded at 1024
/// hashes, with headroom for the rest.
pub const MAX_ADVERTISEMENT_BYTES: usize = 128 << 10;

const KIND_FINGERPRINT: u8 = 1;
const KIND_ITEMS: u8 = 2;

const END_OPEN: u8 = 0;
const END_EXCLUDED: u8 = 1;

// --- handshake -------------------------------------------------------------

/// Encode the opening of a lane: which protocol version, and which group.
///
/// A lane stream carries no context of its own, so the side that opens it has
/// to say what it is for before anything else happens. The receiving side
/// needs the group in hand to decide whether this peer may be told anything
/// about it, which has to be settled before a fingerprint is computed.
pub fn encode_hello(group: &str) -> Result<Vec<u8>, WireError> {
    if group.len() > MAX_GROUP_BYTES {
        return Err(WireError::GroupTooLong { declared: group.len(), limit: MAX_GROUP_BYTES });
    }

    let mut body = Vec::with_capacity(6 + group.len());
    body.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    body.extend_from_slice(&(group.len() as u16).to_be_bytes());
    body.extend_from_slice(group.as_bytes());

    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Decode a hello. A version this node does not speak is refused outright
/// rather than being parsed on the hope that the parts it recognises still
/// mean what they used to.
pub fn decode_hello(body: &[u8]) -> Result<String, WireError> {
    let mut cursor = Cursor::new(body);
    let version = cursor.u32()?;
    if version != PROTOCOL_VERSION {
        return Err(WireError::UnsupportedVersion { theirs: version, ours: PROTOCOL_VERSION });
    }

    let length = cursor.u16()? as usize;
    if length > MAX_GROUP_BYTES {
        return Err(WireError::GroupTooLong { declared: length, limit: MAX_GROUP_BYTES });
    }
    let bytes = cursor.take(length)?;
    if !cursor.is_exhausted() {
        return Err(WireError::TrailingBytes(cursor.remaining()));
    }

    String::from_utf8(bytes.to_vec()).map_err(|_| WireError::MalformedGroupId)
}

// --- base advertisement ----------------------------------------------------

/// Frame a history-base advertisement. Its content is opaque here; the
/// layer that owns history decodes and judges it.
pub fn encode_advertisement(advertisement: &[u8]) -> Result<Vec<u8>, WireError> {
    if advertisement.len() > MAX_ADVERTISEMENT_BYTES {
        return Err(WireError::AdvertisementTooLarge {
            declared: advertisement.len(),
            limit: MAX_ADVERTISEMENT_BYTES,
        });
    }
    let mut frame = Vec::with_capacity(4 + advertisement.len());
    frame.extend_from_slice(&(advertisement.len() as u32).to_be_bytes());
    frame.extend_from_slice(advertisement);
    Ok(frame)
}

// --- reconciliation lane ---------------------------------------------------

/// Encode one round of reconciliation statements.
pub fn encode_round(messages: &[RbsrMessage]) -> Result<Vec<u8>, WireError> {
    if messages.len() > MAX_ROUND_MESSAGES {
        return Err(WireError::RoundTooLarge {
            declared: messages.len(),
            limit: MAX_ROUND_MESSAGES,
        });
    }

    let mut body = Vec::new();
    body.extend_from_slice(&(messages.len() as u16).to_be_bytes());

    for message in messages {
        match message {
            RbsrMessage::Fingerprint { range, fingerprint } => {
                body.push(KIND_FINGERPRINT);
                encode_range(&mut body, range);
                body.extend_from_slice(fingerprint.as_bytes());
            }
            RbsrMessage::Items { range, ids, reply_requested } => {
                if ids.len() > MAX_LISTING_IDS {
                    return Err(WireError::ListingTooLarge {
                        declared: ids.len(),
                        limit: MAX_LISTING_IDS,
                    });
                }
                body.push(KIND_ITEMS);
                encode_range(&mut body, range);
                body.push(u8::from(*reply_requested));
                body.extend_from_slice(&(ids.len() as u16).to_be_bytes());
                for id in ids {
                    body.extend_from_slice(id.as_bytes());
                }
            }
        }
    }

    if body.len() > MAX_ROUND_BYTES {
        return Err(WireError::RoundTooLarge { declared: body.len(), limit: MAX_ROUND_BYTES });
    }

    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Decode one round's body — the bytes after the length prefix.
pub fn decode_round(body: &[u8]) -> Result<Vec<RbsrMessage>, WireError> {
    let mut cursor = Cursor::new(body);
    let count = cursor.u16()? as usize;
    if count > MAX_ROUND_MESSAGES {
        return Err(WireError::RoundTooLarge { declared: count, limit: MAX_ROUND_MESSAGES });
    }

    let mut messages = Vec::with_capacity(count.min(64));
    for _ in 0..count {
        let kind = cursor.u8()?;
        let range = decode_range(&mut cursor)?;
        match kind {
            KIND_FINGERPRINT => messages.push(RbsrMessage::Fingerprint {
                range,
                fingerprint: Fingerprint::from_bytes(cursor.array32()?),
            }),
            KIND_ITEMS => {
                let reply_requested = match cursor.u8()? {
                    0 => false,
                    1 => true,
                    other => return Err(WireError::MalformedFlag(other)),
                };
                let listed = cursor.u16()? as usize;
                if listed > MAX_LISTING_IDS {
                    return Err(WireError::ListingTooLarge {
                        declared: listed,
                        limit: MAX_LISTING_IDS,
                    });
                }
                // The declared count is only trusted once the bytes to back
                // it are known to be present.
                cursor.require(listed * 32)?;
                let mut ids = Vec::with_capacity(listed);
                for _ in 0..listed {
                    ids.push(ItemId::from_bytes(cursor.array32()?));
                }
                messages.push(RbsrMessage::Items { range, ids, reply_requested });
            }
            other => return Err(WireError::UnknownMessageKind(other)),
        }
    }

    if !cursor.is_exhausted() {
        return Err(WireError::TrailingBytes(cursor.remaining()));
    }
    Ok(messages)
}

fn encode_range(out: &mut Vec<u8>, range: &Range) {
    out.extend_from_slice(range.start.as_bytes());
    match range.end {
        RangeEnd::Open => out.push(END_OPEN),
        RangeEnd::Excluded(end) => {
            out.push(END_EXCLUDED);
            out.extend_from_slice(end.as_bytes());
        }
    }
}

fn decode_range(cursor: &mut Cursor<'_>) -> Result<Range, WireError> {
    let start = ItemId::from_bytes(cursor.array32()?);
    let end = match cursor.u8()? {
        END_OPEN => RangeEnd::Open,
        END_EXCLUDED => RangeEnd::Excluded(ItemId::from_bytes(cursor.array32()?)),
        other => return Err(WireError::MalformedRangeEnd(other)),
    };
    Ok(Range::new(start, end))
}

// --- bundle lane -----------------------------------------------------------

/// A proof-carrying Change bundle, opaque at this layer.
///
/// The protocol moves these; it does not decode, verify or interpret them.
/// Verification belongs to the layer that owns Change semantics, and putting
/// it here would make the transport a second place where authorization is
/// decided.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OpaqueBundle {
    pub change_hash: ItemId,
    pub payload: Vec<u8>,
}

/// Encode a request for specific bundles.
pub fn encode_bundle_request(hashes: &[ItemId]) -> Result<Vec<u8>, WireError> {
    if hashes.len() > MAX_BUNDLE_REQUEST {
        return Err(WireError::RequestTooLarge {
            declared: hashes.len(),
            limit: MAX_BUNDLE_REQUEST,
        });
    }
    let mut body = Vec::with_capacity(4 + hashes.len() * 32);
    body.extend_from_slice(&(hashes.len() as u32).to_be_bytes());
    for hash in hashes {
        body.extend_from_slice(hash.as_bytes());
    }

    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

pub fn decode_bundle_request(body: &[u8]) -> Result<Vec<ItemId>, WireError> {
    let mut cursor = Cursor::new(body);
    let count = cursor.u32()? as usize;
    if count > MAX_BUNDLE_REQUEST {
        return Err(WireError::RequestTooLarge { declared: count, limit: MAX_BUNDLE_REQUEST });
    }
    cursor.require(count * 32)?;

    let mut hashes = Vec::with_capacity(count);
    for _ in 0..count {
        hashes.push(ItemId::from_bytes(cursor.array32()?));
    }
    if !cursor.is_exhausted() {
        return Err(WireError::TrailingBytes(cursor.remaining()));
    }
    Ok(hashes)
}

/// Encode one bundle.
pub fn encode_bundle(bundle: &OpaqueBundle) -> Result<Vec<u8>, WireError> {
    if bundle.payload.len() > MAX_BUNDLE_BYTES {
        return Err(WireError::BundleTooLarge {
            declared: bundle.payload.len(),
            limit: MAX_BUNDLE_BYTES,
        });
    }
    let body_len = 32 + bundle.payload.len();
    let mut frame = Vec::with_capacity(4 + body_len);
    frame.extend_from_slice(&(body_len as u32).to_be_bytes());
    frame.extend_from_slice(bundle.change_hash.as_bytes());
    frame.extend_from_slice(&bundle.payload);
    Ok(frame)
}

pub fn decode_bundle(body: &[u8]) -> Result<OpaqueBundle, WireError> {
    let mut cursor = Cursor::new(body);
    let change_hash = ItemId::from_bytes(cursor.array32()?);
    Ok(OpaqueBundle { change_hash, payload: cursor.rest().to_vec() })
}

// --- bounded cursor --------------------------------------------------------

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn require(&self, count: usize) -> Result<(), WireError> {
        if self.bytes.len() - self.at < count {
            return Err(WireError::Truncated {
                needed: count,
                available: self.bytes.len() - self.at,
            });
        }
        Ok(())
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], WireError> {
        self.require(count)?;
        let slice = &self.bytes[self.at..self.at + count];
        self.at += count;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("2 bytes")))
    }

    fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }

    fn array32(&mut self) -> Result<[u8; 32], WireError> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }

    fn rest(&mut self) -> &'a [u8] {
        let slice = &self.bytes[self.at..];
        self.at = self.bytes.len();
        slice
    }

    fn is_exhausted(&self) -> bool {
        self.at == self.bytes.len()
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }
}

#[cfg(test)]
mod tests;

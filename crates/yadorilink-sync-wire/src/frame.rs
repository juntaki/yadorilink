//! Protobuf-free domain equivalents of the wire messages
//! `crates/yadorilink-ipc-proto/proto/sync.proto` defines. Mirrors the
//! `DurableVersionQuery` pattern `peer_replica_engine.rs` already
//! established (Phase 7B): a frame holds only the fields its consumer
//! actually reads, not a 1:1 mirror of every proto field. Growing this enum
//! family-by-family as each is migrated (see
//! `docs/design/phase7-peer-handler-inventory.md` for the full handler
//! catalog) -- `VersionPresentAck` is first because it is pure correlation
//! with no state coupling and no permit/ordering invariant to preserve.

/// A peer's answer to a `VersionPresentQuery`: whether it durably holds
/// every queried block. Only `request_id` (correlation key) and `present`
/// are read by `handle_version_present_ack` -- `folder_group_id`/
/// `file_path`/`signature` are on the wire message but unused by that
/// handler today, so they are not carried here (same "only what's needed"
/// principle as `peer_replica_engine::DurableVersionQuery`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionPresentAckFrame {
    pub request_id: u64,
    pub present: bool,
}

/// Resolves the pending `request_handoff_lease_from_peer` awaiting this
/// reply. Carries every field `handle_handoff_lease_grant` reads --
/// unlike `VersionPresentAckFrame`, this handler does its own non-trivial
/// parsing (root-digest length validation, `PeerHandoffLeaseGrant`
/// construction) from the raw fields, so that logic stays in the handler
/// body unchanged; this frame is a plain field mirror, not a pre-parsed
/// result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffLeaseGrantFrame {
    pub request_id: u64,
    pub granted: bool,
    pub lease_id: String,
    pub root_digest: Vec<u8>,
    pub expires_at_unix: i64,
}

/// Resolves the pending `request_handoff_ticket_from_peer` awaiting this
/// reply. Plain field mirror, same rationale as `HandoffLeaseGrantFrame`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffTicketGrantFrame {
    pub request_id: u64,
    pub granted: bool,
    pub lease_id: String,
    pub expires_at_unix: i64,
    pub target_device_id: String,
}

/// Resolves the pending `request_rebootstrap_snapshot_from_peer` awaiting
/// this reply. Plain field mirror -- `handle_rebootstrap_snapshot_response`
/// decodes `required_encoded` into a `RebootstrapRequired` and checks its
/// claimed signer itself, unchanged, from these raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebootstrapSnapshotResponseFrame {
    pub request_id: u64,
    pub granted: bool,
    pub required_encoded: Vec<u8>,
    pub snapshot_bytes: Vec<u8>,
}

/// A peer's request to confirm whether this device durably holds a queried
/// version. Unlike `peer_replica_engine::DurableVersionQuery` (which
/// deliberately excludes `request_id` -- see its own doc comment, the
/// engine's read logic never needs it), this frame mirrors every field of
/// the wire message 1:1: `handle_version_present_query` needs `request_id`
/// itself, to build the `VersionPresentAck` reply, alongside everything
/// `DurableVersionQuery` needs for the actual durability check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionPresentQueryFrame {
    pub request_id: u64,
    pub folder_group_id: String,
    pub file_path: String,
    pub block_hashes: Vec<Vec<u8>>,
    pub for_handoff: bool,
    pub version_hash: Vec<u8>,
    pub block_sizes: Vec<u32>,
}

/// A peer's request for a handoff lease on a folder group. Plain field
/// mirror -- `handle_handoff_lease_request` does its own authorization
/// (`shares_group`) and delegate-to-responder logic from these raw fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffLeaseRequestFrame {
    pub request_id: u64,
    pub folder_group_id: String,
}

/// A peer's best-effort release of a lease it holds. `request_id` is on the
/// wire message but `handle_handoff_lease_release` never reads it (a
/// fire-and-forget release, nothing correlates a reply to it), so it is not
/// carried here -- same "only what's needed" principle as
/// `peer_replica_engine::DurableVersionQuery`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffLeaseReleaseFrame {
    pub folder_group_id: String,
    pub lease_id: String,
}

/// A peer's request for a removed-device handoff ticket on a folder group.
/// Plain field mirror, same rationale as `HandoffLeaseRequestFrame`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffTicketRequestFrame {
    pub request_id: u64,
    pub folder_group_id: String,
}

/// A peer's best-effort cancellation of a ticket. `request_id` is unread by
/// `handle_handoff_ticket_release`, same rationale as
/// `HandoffLeaseReleaseFrame`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffTicketReleaseFrame {
    pub folder_group_id: String,
    pub target_device_id: String,
    pub lease_id: String,
}

/// A peer's request for a re-bootstrap snapshot proving it intentionally
/// pruned `requested_hash`. Plain field mirror --
/// `handle_rebootstrap_snapshot_request` does its own `requested_hash`
/// length validation and delegate-to-handler logic from these raw fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebootstrapSnapshotRequestFrame {
    pub request_id: u64,
    pub folder_group_id: String,
    pub requested_hash: Vec<u8>,
}

/// A peer's announcement of its current DAG heads for a folder group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadsAnnounceFrame {
    pub folder_group_id: String,
    pub heads: Vec<Vec<u8>>,
}

/// A peer's request for the encoded changes behind a set of change hashes
/// it is missing, alongside the requester's own current local heads
/// (`have_heads`, untrusted -- see `PeerReplicaEngine::changes_for_request`'s
/// own doc comment for how the responder must treat it). Plain field mirror
/// -- `handle_change_request` delegates the hash decode and delta
/// computation to `PeerReplicaEngine`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeRequestFrame {
    pub folder_group_id: String,
    pub want_heads: Vec<Vec<u8>>,
    pub have_heads: Vec<Vec<u8>>,
}

/// A bounded batch of encoded changes answering a `ChangeRequest`, or sent
/// unsolicited as part of ordinary replication. Plain field mirror --
/// `handle_change_batch` reads all four of these fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeBatchFrame {
    pub folder_group_id: String,
    pub changes: Vec<Vec<u8>>,
    pub file_versions: Vec<Vec<u8>>,
    pub more: bool,
}

/// The session-start handshake message. Omits `folder_group_ids` /
/// `known_peer_device_ids` (advertised outbound only, nothing on any
/// receiving side consults them) and 2 of the 4 serve-engine advisory
/// hints, `available_worker_slots` / `estimated_queue_delay_ms`
/// (outbound-only today, no receiving-side consumer exists yet).
///
/// What it no longer carries is a capability set. Compression support, the
/// change DAG, the custody query and its exact-version check were all
/// advertised here and all required by the handshake that read them, so no
/// two peers that could reach a running session could differ on any of
/// them; they went with the generation check itself, which now rides the
/// ALPN. What is left is the genuinely dynamic part -- how loaded the
/// peer's serve engine is right now -- plus the delivery confirmation the
/// handshake retry loop needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterConfigFrame {
    pub acked_peer_cluster_config: bool,
    pub max_inflight_requests: u32,
    pub max_inflight_bytes: u64,
}

/// A peer's request for one block's content: the first message on a block
/// stream.
///
/// Plain field mirror of the wire message, and all three fields are read:
/// `folder_group_id`/`file_path` for the authorization/reference/
/// declared-size lookups, `block_hash` for the store read. There is no
/// correlation id, because the stream is the correlation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRequestHeaderFrame {
    pub folder_group_id: String,
    pub file_path: String,
    pub block_hash: Vec<u8>,
}

/// Domain form of `proto::block_response_header::Outcome`'s oneof.
///
/// Both directions use this one type, unlike the inline reply it replaces,
/// which needed a separate sending-side enum because the receiver ignored
/// fields the sender always set. Every field here is read on both sides:
/// the requester acts on `queue_depth` when choosing a source, and `Found`
/// carries exactly what the receiver needs to read the body that follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockResponseOutcomeFrame {
    /// `size` is the number of raw body bytes that follow on the stream --
    /// post-compression, so it is what to read, not what will be left after
    /// decompressing. `hash` is echoed from the request so the requester can
    /// refuse a response bound to a different block than the one it asked
    /// for.
    Found { size: u64, hash: Vec<u8>, compression: i32 },
    DontHave,
    Busy { retry_after_ms: u32, queue_depth: u32 },
    Rejected { reason: String },
}

/// A peer's answer to a block request: the second message on a block
/// stream. Under exact-generation ALPN a same-generation peer's
/// `BlockResponseHeader` always sets exactly one `outcome`; an absent oneof
/// is malformed for this generation and is rejected at decode time (see
/// `ProtobufPeerWireCodec::decode_block_response_header`), never treated as
/// `DontHave`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockResponseHeaderFrame {
    pub outcome: BlockResponseOutcomeFrame,
}

/// M3 Pass 5: a serialized `relay_grant::RelayGrant`, opening a relay
/// session with the RECEIVING device acting as relay. Plain field mirror
/// of every wire field -- the receiving side's `relay_session::
/// admit_relay_open` independently re-verifies every one of these against
/// its own live state, so nothing here is pre-validated or trimmed the
/// way other inbound frames sometimes are. Same shape on both directions
/// (the sender always sets every field the receiver reads), so `Outbound
/// Frame` reuses this type directly rather than a dedicated `*Outbound
/// Frame` -- see `OutboundFrame`'s own doc comment for that convention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayOpenFrame {
    pub version: u32,
    pub grant_id: String,
    pub group_id: String,
    pub source_device_id: String,
    pub relay_device_id: String,
    pub destination_device_id: String,
    pub not_before_unix: i64,
    pub expires_at_unix: i64,
    /// `0` means "no plane-issued cap" (`RelayGrant.max_session_bytes:
    /// None`) -- mirrors the wire message's own convention.
    pub max_session_bytes: u64,
    pub signature: Vec<u8>,
}

/// M3 Pass 5: the relay's answer to `RelayOpenFrame`. `granted = false`
/// covers every admission failure uniformly -- see the `.proto` message's
/// own doc comment for why the wire deliberately does not distinguish
/// which check failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayOpenedFrame {
    pub grant_id: String,
    pub granted: bool,
    pub session_id: u64,
}

/// M3 Pass 5: one opaque, already-encrypted datagram carried through a
/// relay session. The relay never parses `payload` -- see the `.proto`
/// message's own doc comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayDataFrame {
    pub session_id: u64,
    pub payload: Vec<u8>,
}

/// M3 Pass 5: ends a relay session before its grant's own expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCloseFrame {
    pub session_id: u64,
    pub reason: String,
}

/// A decoded inbound wire message, in domain form. Every current
/// `SyncMessage.payload` oneof variant has an explicit case here. There is
/// no `Unknown` fallback: under exact-generation ALPN, a same-generation
/// peer's `SyncMessage` always sets a recognized `payload`, so a genuinely
/// empty or unrecognized payload is a protocol violation, rejected at
/// decode time (see `ProtobufPeerWireCodec::decode`) rather than silently
/// ignored.
#[derive(Debug, Clone)]
pub enum InboundFrame {
    VersionPresentQuery(VersionPresentQueryFrame),
    VersionPresentAck(VersionPresentAckFrame),
    HeadsAnnounce(HeadsAnnounceFrame),
    ChangeRequest(ChangeRequestFrame),
    ChangeBatch(ChangeBatchFrame),
    ClusterConfig(ClusterConfigFrame),
    HandoffLeaseRequest(HandoffLeaseRequestFrame),
    HandoffLeaseGrant(HandoffLeaseGrantFrame),
    HandoffLeaseRelease(HandoffLeaseReleaseFrame),
    HandoffTicketRequest(HandoffTicketRequestFrame),
    HandoffTicketGrant(HandoffTicketGrantFrame),
    HandoffTicketRelease(HandoffTicketReleaseFrame),
    RebootstrapSnapshotRequest(RebootstrapSnapshotRequestFrame),
    RebootstrapSnapshotResponse(RebootstrapSnapshotResponseFrame),
    RelayOpen(RelayOpenFrame),
    RelayOpened(RelayOpenedFrame),
    RelayData(RelayDataFrame),
    RelayClose(RelayCloseFrame),
}

/// This build's handshake advertisement -- every field `cluster_config_
/// message` (the sole production constructor) actually sets. Identical to
/// the inbound `ClusterConfigFrame` -- both directions of this message read
/// and write the same fields today.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterConfigOutboundFrame {
    pub acked_peer_cluster_config: bool,
    pub max_inflight_requests: u32,
    pub max_inflight_bytes: u64,
}

/// This device's own DAG heads announcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadsAnnounceOutboundFrame {
    pub folder_group_id: String,
    pub heads: Vec<Vec<u8>>,
}

/// A bounded batch of encoded changes, as sent by `send_change_batch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeBatchOutboundFrame {
    pub folder_group_id: String,
    pub changes: Vec<Vec<u8>>,
    pub file_versions: Vec<Vec<u8>>,
    pub more: bool,
}

/// `handle_version_present_query`'s reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionPresentAckOutboundFrame {
    pub request_id: u64,
    pub present: bool,
}

/// `release_handoff_lease_to_peer`'s message -- fire-and-forget, identical
/// to the inbound `HandoffLeaseReleaseFrame`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffLeaseReleaseOutboundFrame {
    pub folder_group_id: String,
    pub lease_id: String,
}

/// `release_handoff_ticket_to_peer`'s message -- fire-and-forget, identical
/// to the inbound `HandoffTicketReleaseFrame`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffTicketReleaseOutboundFrame {
    pub folder_group_id: String,
    pub target_device_id: String,
    pub lease_id: String,
}

/// An outbound wire message, in domain form, ready to be encoded and sent.
/// Every `SyncMessage.payload` oneof variant is represented -- most reuse
/// their corresponding inbound `*Frame` type exactly (the sending side
/// happens to set every field that type carries: `ChangeRequestFrame`,
/// `VersionPresentQueryFrame`,
/// `HandoffLeaseRequestFrame`, `HandoffLeaseGrantFrame`,
/// `HandoffTicketRequestFrame`, `HandoffTicketGrantFrame`,
/// `RebootstrapSnapshotRequestFrame`, `RebootstrapSnapshotResponseFrame`);
/// the other 7 need a dedicated `*OutboundFrame` type because the sending
/// side sets fields the inbound type deliberately omits (see each
/// dedicated type's own doc comment for exactly which field and why).
#[derive(Debug, Clone)]
pub enum OutboundFrame {
    ClusterConfig(ClusterConfigOutboundFrame),
    HeadsAnnounce(HeadsAnnounceOutboundFrame),
    ChangeRequest(ChangeRequestFrame),
    ChangeBatch(ChangeBatchOutboundFrame),
    VersionPresentQuery(VersionPresentQueryFrame),
    VersionPresentAck(VersionPresentAckOutboundFrame),
    HandoffLeaseRequest(HandoffLeaseRequestFrame),
    HandoffLeaseGrant(HandoffLeaseGrantFrame),
    HandoffLeaseRelease(HandoffLeaseReleaseOutboundFrame),
    HandoffTicketRequest(HandoffTicketRequestFrame),
    HandoffTicketGrant(HandoffTicketGrantFrame),
    HandoffTicketRelease(HandoffTicketReleaseOutboundFrame),
    RebootstrapSnapshotRequest(RebootstrapSnapshotRequestFrame),
    RebootstrapSnapshotResponse(RebootstrapSnapshotResponseFrame),
    RelayOpen(RelayOpenFrame),
    RelayOpened(RelayOpenedFrame),
    RelayData(RelayDataFrame),
    RelayClose(RelayCloseFrame),
}

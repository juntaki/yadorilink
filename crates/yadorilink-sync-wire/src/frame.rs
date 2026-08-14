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
/// `frontier_hint` is on the wire message but `handle_heads_announce` never
/// reads it today, so it is not carried here -- same "only what's needed"
/// principle as `peer_replica_engine::DurableVersionQuery`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadsAnnounceFrame {
    pub folder_group_id: String,
    pub heads: Vec<Vec<u8>>,
}

/// A peer's request for the encoded changes behind a set of change hashes
/// it is missing. Plain field mirror -- `handle_change_request` delegates
/// the hash decode and ancestry expansion to `PeerReplicaEngine`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeRequestFrame {
    pub folder_group_id: String,
    pub want: Vec<Vec<u8>>,
}

/// A bounded batch of encoded changes answering a `ChangeRequest`, or sent
/// unsolicited as part of ordinary replication. Plain field mirror --
/// `handle_change_batch` reads all four of these fields (`changes.len()`,
/// iterating `changes`, an emptiness check on `compressed_changes`, and
/// `file_versions`); `compression` itself is on the wire message but never
/// read (only `compressed_changes`'s emptiness matters today), so it is not
/// carried here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeBatchFrame {
    pub folder_group_id: String,
    pub changes: Vec<Vec<u8>>,
    pub compressed_changes: Vec<u8>,
    pub file_versions: Vec<Vec<u8>>,
}

/// The mandatory capability-negotiation handshake message. Omits
/// `folder_group_ids` / `known_peer_device_ids` (advertised outbound only,
/// nothing on any receiving side consults them) and 2 of the 4 serve-
/// engine advisory hints, `available_worker_slots` / `estimated_queue_
/// delay_ms` (outbound-only today, no receiving-side consumer exists
/// yet). `max_inflight_requests` / `max_inflight_bytes` ARE carried,
/// despite `handle_cluster_config` itself not reading them: the public
/// wrapper's `PeerSyncSession::validate_exact_peer_config` (`peer_session_
/// public.rs`) is a second, independent inbound consumer of this same
/// wire message, and it does check both (`> 0`) as part of the exact-
/// generation handshake preflight -- this frame type is shared by both
/// consumers rather than split further per-consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterConfigFrame {
    pub acked_peer_cluster_config: bool,
    pub supported_compression: Vec<i32>,
    pub supports_reliable_delivery: bool,
    pub supports_change_dag: bool,
    pub supports_version_present: bool,
    pub supports_version_hash_exact: bool,
    pub max_inflight_requests: u32,
    pub max_inflight_bytes: u64,
    pub protocol_version: u32,
}

/// A peer's request for one block's content. Plain field mirror of every
/// field on the wire message -- `handle_block_request` and
/// `handle_block_request_with_credit` (and their shared helpers) read all
/// four: `folder_group_id`/`file_path` for the authorization/reference/
/// declared-size lookups, `block_hash` for the store read and reply
/// correlation payload, `request_id` for reply correlation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRequestFrame {
    pub folder_group_id: String,
    pub file_path: String,
    pub block_hash: Vec<u8>,
    pub request_id: u64,
}

/// Domain form of `proto::block_reply::Outcome`'s oneof. Each variant
/// carries only the fields `handle_block_reply` actually reads:
/// `BlockReplyBusy.queue_depth` is on the wire but unread there, so `Busy`
/// only carries `retry_after_ms`; `BlockReplyDontHave`'s wire value is
/// always `true` and unread (only the variant itself matters), so `DontHave`
/// carries nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReplyOutcomeFrame {
    Found { data: Vec<u8>, compression: i32 },
    DontHave,
    Busy { retry_after_ms: u32 },
    Redirect { candidate_device_ids: Vec<String> },
    Rejected { reason: String },
}

/// A peer's answer to a `BlockRequest`. `outcome` mirrors the wire
/// message's own `Option` -- a genuinely absent oneof (an old peer, or a
/// forward-incompatible reply this build doesn't recognize) is treated
/// identically to `DontHave` by `handle_block_reply`, same as the proto
/// side's own `None` arm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockReplyFrame {
    pub block_hash: Vec<u8>,
    pub outcome: Option<BlockReplyOutcomeFrame>,
    pub request_id: u64,
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

/// A decoded inbound wire message, in domain form. Grows one variant per
/// migrated message family; `Unknown` covers both a genuinely-empty
/// `SyncMessage.payload` and a forward-incompatible oneof case (a newer
/// peer's message type this build doesn't recognize) -- mirrors
/// `handle_message`'s existing `None => Ok(())` silent-ignore behavior for
/// both, not yet distinguishing them at this layer.
#[derive(Debug, Clone)]
pub enum InboundFrame {
    VersionPresentQuery(VersionPresentQueryFrame),
    VersionPresentAck(VersionPresentAckFrame),
    HeadsAnnounce(HeadsAnnounceFrame),
    ChangeRequest(ChangeRequestFrame),
    ChangeBatch(ChangeBatchFrame),
    ClusterConfig(ClusterConfigFrame),
    BlockRequest(BlockRequestFrame),
    BlockReply(BlockReplyFrame),
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
    Unknown { message_kind: Option<u32> },
}

/// This build's handshake advertisement -- every field `cluster_config_
/// message` (the sole production constructor) actually sets, unlike the
/// inbound `ClusterConfigFrame`, which omits everything the receiving side
/// never reads. Outbound and inbound diverge here on purpose: the sender
/// and receiver of the same wire message read different subsets of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterConfigOutboundFrame {
    pub folder_group_ids: Vec<String>,
    pub known_peer_device_ids: Vec<String>,
    pub supported_compression: Vec<i32>,
    pub supports_reliable_delivery: bool,
    pub acked_peer_cluster_config: bool,
    pub supports_change_dag: bool,
    pub supports_version_present: bool,
    pub supports_version_hash_exact: bool,
    pub max_inflight_requests: u32,
    pub max_inflight_bytes: u64,
    pub available_worker_slots: u32,
    pub estimated_queue_delay_ms: u32,
    pub protocol_version: u32,
}

/// This device's own DAG heads announcement -- unlike the inbound
/// `HeadsAnnounceFrame` (which omits `frontier_hint`, unread by
/// `handle_heads_announce`), the sending side always sets it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadsAnnounceOutboundFrame {
    pub folder_group_id: String,
    pub heads: Vec<Vec<u8>>,
    pub frontier_hint: Vec<u8>,
}

/// A bounded batch of encoded changes, as sent by `send_change_batch`.
/// `compression` is not a field here because the one production sender
/// always sends uncompressed (`Compression::None`) -- see
/// `ProtobufPeerWireCodec::encode`'s `ChangeBatch` arm, which hardcodes it
/// to match exactly, rather than modeling a choice nothing ever makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeBatchOutboundFrame {
    pub folder_group_id: String,
    pub changes: Vec<Vec<u8>>,
    pub compressed_changes: Vec<u8>,
    pub file_versions: Vec<Vec<u8>>,
}

/// `handle_version_present_query`'s reply -- unlike the inbound
/// `VersionPresentAckFrame` (which omits `folder_group_id`/`file_path`/
/// `signature`, unread by `handle_version_present_ack`), the sending side
/// echoes the query's own `folder_group_id`/`file_path` and always sets
/// `signature` to empty (reserved for a future signed attestation; see the
/// production constructor's own comment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionPresentAckOutboundFrame {
    pub request_id: u64,
    pub folder_group_id: String,
    pub file_path: String,
    pub present: bool,
    pub signature: Vec<u8>,
}

/// `release_handoff_lease_to_peer`'s message -- unlike the inbound
/// `HandoffLeaseReleaseFrame` (which omits `request_id`, unread by
/// `handle_handoff_lease_release`, a fire-and-forget release with no
/// reply), the sending side always assigns one from its own counter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffLeaseReleaseOutboundFrame {
    pub request_id: u64,
    pub folder_group_id: String,
    pub lease_id: String,
}

/// `release_handoff_ticket_to_peer`'s message -- same rationale as
/// `HandoffLeaseReleaseOutboundFrame` for why `request_id` is present here
/// but not on the inbound `HandoffTicketReleaseFrame`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffTicketReleaseOutboundFrame {
    pub request_id: u64,
    pub folder_group_id: String,
    pub target_device_id: String,
    pub lease_id: String,
}

/// Domain form of `proto::block_reply::Outcome`'s oneof, for the SENDING
/// side. Unlike the inbound `BlockReplyOutcomeFrame` (which omits `Busy`'s
/// `queue_depth`, unread by `handle_block_reply`, and carries no payload
/// for `DontHave`), the sending side sets every field the wire message
/// has: `block_reply_busy_message` always supplies a real `queue_depth`,
/// and `block_request_dont_have_message` always sends the wire's `true`
/// explicitly (kept here for schema-completeness even though the only
/// value ever sent is `true` -- the receiving side already treats the
/// variant itself as the signal, not this value, per
/// `BlockReplyOutcomeFrame::DontHave`'s own doc comment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReplyOutboundOutcome {
    Found { data: Vec<u8>, compression: i32 },
    DontHave,
    Busy { retry_after_ms: u32, queue_depth: u32 },
    Redirect { candidate_device_ids: Vec<String> },
    Rejected { reason: String },
}

/// A block-serving reply, for the SENDING side -- see
/// `BlockReplyOutboundOutcome`'s own doc comment for why this needs its
/// own outcome enum rather than reusing `BlockReplyOutcomeFrame`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockReplyOutboundFrame {
    pub block_hash: Vec<u8>,
    pub outcome: BlockReplyOutboundOutcome,
    pub request_id: u64,
}

/// An outbound wire message, in domain form, ready to be encoded and sent.
/// All 16 `SyncMessage.payload` oneof variants are represented -- 9 reuse
/// their corresponding inbound `*Frame` type exactly (the sending side
/// happens to set every field that type carries: `BlockRequestFrame`,
/// `ChangeRequestFrame`, `VersionPresentQueryFrame`,
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
    BlockRequest(BlockRequestFrame),
    BlockReply(BlockReplyOutboundFrame),
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

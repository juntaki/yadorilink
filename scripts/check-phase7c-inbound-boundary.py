#!/usr/bin/env python3
"""Phase 7C completion checkpoint: verify every `SyncMessage.payload` oneof
variant's INBOUND handler signature in `peer_session.rs` takes a
`yadorilink_sync_wire::*Frame` domain type, not `proto::*` directly.

This is deliberately narrower than a "zero `proto::` in peer_session.rs"
gate -- that invariant does not hold yet and was never the plan for 7C. Every
7C commit's own commit message documents the same boundary: only each
handler's INBOUND parameter type moved off `proto::*`. Several handlers'
OUTBOUND reply construction (e.g. `send_change_batch`, `cluster_config_
message`, `block_request_rejected_message`) still builds `proto::*`
directly, and `handle_message`/`run`'s recv loop still decode the whole
`SyncMessage` envelope via `prost::Message::decode` rather than routing
through `PeerWireCodec`. Both are real, known, un-closed gaps -- Phase 7C's
own staged plan explicitly scoped this phase to the inbound side only,
deferring outbound/envelope unification to whenever `PeerSyncSession` grows
a session-level `codec: Arc<dyn PeerWireCodec>` field (not yet done).

What this script actually checks: for each of the 16 `handle_*` functions
behind `SyncMessage.payload`'s 15 oneof variants (`ClusterConfig` fans out
to `handle_cluster_config`; `HandoffLease{Request,Grant,Release}` each get
their own handler; etc.), the function's own parameter list must reference
`yadorilink_sync_wire::<ExpectedFrame>` and must NOT reference the
corresponding `proto::<Message>` type. This is the concrete, load-bearing
claim every 7C-1 through 7C-8 commit message made -- this script exists so
that claim stays true as the codebase keeps changing, not just true on the
day each commit landed.

Same brace/substring-matching approach as this repo's other phase-boundary
gate scripts (`check-phase7b-engine-boundary.py`) -- not a real Rust parser.
"""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Phase 7D-6 physically moved peer_session.rs into yadorilink-peer-session;
# this gate's own file target needs to follow it. The invariant this script
# checks (each handler takes a yadorilink_sync_wire::*Frame parameter, not
# proto::* directly) is unaffected by the move itself.
SESSION_FILE = ROOT / "crates/yadorilink-peer-session/src/peer_session.rs"

# (handler function name, expected peer_wire frame type, corresponding
# proto message type that must NOT appear in the parameter list).
HANDLERS = [
    ("handle_cluster_config", "ClusterConfigFrame", "proto::ClusterConfig"),
    ("handle_block_request", "BlockRequestFrame", "proto::BlockRequest"),
    ("handle_block_request_with_credit", "BlockRequestFrame", "proto::BlockRequest"),
    ("handle_block_reply", "BlockReplyFrame", "proto::BlockReply"),
    ("handle_heads_announce", "HeadsAnnounceFrame", "proto::HeadsAnnounce"),
    ("handle_change_request", "ChangeRequestFrame", "proto::ChangeRequest"),
    ("handle_change_batch", "ChangeBatchFrame", "proto::ChangeBatch"),
    ("handle_version_present_query", "VersionPresentQueryFrame", "proto::VersionPresentQuery"),
    ("handle_version_present_ack", "VersionPresentAckFrame", "proto::VersionPresentAck"),
    ("handle_handoff_lease_request", "HandoffLeaseRequestFrame", "proto::HandoffLeaseRequest"),
    ("handle_handoff_lease_grant", "HandoffLeaseGrantFrame", "proto::HandoffLeaseGrant"),
    ("handle_handoff_lease_release", "HandoffLeaseReleaseFrame", "proto::HandoffLeaseRelease"),
    ("handle_handoff_ticket_request", "HandoffTicketRequestFrame", "proto::HandoffTicketRequest"),
    ("handle_handoff_ticket_grant", "HandoffTicketGrantFrame", "proto::HandoffTicketGrant"),
    ("handle_handoff_ticket_release", "HandoffTicketReleaseFrame", "proto::HandoffTicketRelease"),
    (
        "handle_rebootstrap_snapshot_request",
        "RebootstrapSnapshotRequestFrame",
        "proto::RebootstrapSnapshotRequest",
    ),
    (
        "handle_rebootstrap_snapshot_response",
        "RebootstrapSnapshotResponseFrame",
        "proto::RebootstrapSnapshotResponse",
    ),
]


def extract_signature(text: str, fn_name: str) -> str | None:
    """Finds `fn {fn_name}(` and returns the text from the opening paren
    through its matching close paren (simple depth counting, ignoring
    parens inside string literals -- signatures here never have any)."""
    marker = f"fn {fn_name}("
    idx = text.find(marker)
    if idx == -1:
        return None
    start = idx + len(marker) - 1  # position of the opening '('
    depth = 0
    i = start
    n = len(text)
    while i < n:
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
        i += 1
    return None


def check_handlers(text: str) -> list[str]:
    failures: list[str] = []
    for fn_name, expected_frame, forbidden_proto in HANDLERS:
        signature = extract_signature(text, fn_name)
        if signature is None:
            failures.append(f"{fn_name}: function not found in {SESSION_FILE.name}")
            continue
        if f"yadorilink_sync_wire::{expected_frame}" not in signature:
            failures.append(
                f"{fn_name}: parameter list does not reference "
                f"yadorilink_sync_wire::{expected_frame} -- {signature.strip()}"
            )
        if forbidden_proto in signature:
            failures.append(
                f"{fn_name}: parameter list still references {forbidden_proto} directly -- "
                f"{signature.strip()}"
            )
    return failures


def self_test() -> None:
    clean = (
        "async fn handle_cluster_config(\n"
        "    &self,\n"
        "    config: yadorilink_sync_wire::ClusterConfigFrame,\n"
        ") -> Result<(), SyncError> {\n"
        "    Ok(())\n"
        "}\n"
    )
    failures = check_handlers(clean)
    assert not any(f.startswith("handle_cluster_config") for f in failures), (
        "a handler already taking the expected frame type must not be flagged"
    )

    dirty = (
        "async fn handle_cluster_config(\n"
        "    &self,\n"
        "    config: proto::ClusterConfig,\n"
        ") -> Result<(), SyncError> {\n"
        "    Ok(())\n"
        "}\n"
    )
    failures = check_handlers(dirty)
    assert any("proto::ClusterConfig" in f for f in failures), (
        "a handler still taking the raw proto type must be flagged"
    )

    missing = "// handle_cluster_config was renamed or removed\n"
    failures = check_handlers(missing)
    assert any("function not found" in f for f in failures), (
        "a missing handler must be flagged, not silently skipped"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("Phase 7C inbound boundary self-test passed")
        return 0

    text = SESSION_FILE.read_text(encoding="utf-8")
    failures = check_handlers(text)
    if failures:
        print("Phase 7C inbound boundary violations:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print(
        f"Phase 7C inbound boundary check passed: all {len(HANDLERS)} SyncMessage "
        "payload handlers take a yadorilink_sync_wire::*Frame parameter, not proto::* directly."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

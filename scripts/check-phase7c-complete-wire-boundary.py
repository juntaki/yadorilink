#!/usr/bin/env python3
"""Phase 7D-2 exit gate (supersedes 7C.5's own version of this check):
verify `yadorilink-sync-core` has ZERO production-code dependency on
`yadorilink_ipc_proto`/`prost` peer-wire types anywhere.

## History

7C.5's version of this script allowed two documented exceptions in
production code: `yadorilink_ipc_proto::sync::Compression` (used directly
by `compress_block`/`decompress_block` and the `ClusterConfig` handshake)
and `proto::FileInfo`/`proto::RecordKind` (an in-process-only record
carrier for the materialization-repair path, never sent on the wire). Both
are now closed:

- Phase 7D-2.1a moved `Compression` to `yadorilink_sync_wire::
  {COMPRESSION_NONE, COMPRESSION_ZSTD}` plain `i32` constants.
- Phase 7D-2.1b replaced the `proto::FileInfo` in-process carrier with a
  direct `(FileRecord, IncomingWireMeta)` pair, deleting
  `peer_wire/protobuf_file_info.rs` entirely.
- Phase 7D-2.3 moved the wire codec/frame layer itself
  (`peer_wire/{codec,error,frame,protobuf}.rs`, the one place `proto::`
  was ever meant to live) out of this crate into the standalone
  `yadorilink-sync-wire` crate. `crates/yadorilink-sync-core/src/peer_wire/`
  no longer exists.

So the invariant this script now enforces is simple: no production
(non-`#[cfg(test)]`) line anywhere under `yadorilink-sync-core/src`
references `proto::`, `yadorilink_ipc_proto`, or `prost::Message`. A
`#[cfg(test)]` span keeps a narrow allowance -- pre-existing test fixtures
(`peer_session.rs`'s own `version_hash_exact_capability_tests`,
`tests/peer_session.rs`, `tests/dag_wire_support/`) construct wire proto
messages directly to exercise `PeerSyncSession`'s own handling logic, and
closing that is a separate, unrelated refactor from this phase's scope.

Same substring-matching approach as this repo's other phase-boundary gate
scripts -- not a real Rust parser; a deliberate `use prost as p;`-style
rename evades it, same limitation those scripts document for themselves.
"""

from __future__ import annotations

import argparse
import re
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYNC_CORE_SRC = ROOT / "crates/yadorilink-sync-core/src"

TRIGGERS = ("proto::", "yadorilink_ipc_proto", "prost::Message")

COMMENT_LINE = re.compile(r"^\s*(///|//!|//)")
CFG_TEST_ATTR = re.compile(r"#\[cfg\(\s*test\s*\)\]")


def cfg_test_line_ranges(text: str) -> list[tuple[int, int]]:
    """Same brace-matching technique as this repo's other Phase 2-7 gate
    scripts."""
    ranges: list[tuple[int, int]] = []
    i = 0
    n = len(text)
    while i < n:
        m = CFG_TEST_ATTR.search(text, i)
        if not m:
            break
        brace_start = text.find("{", m.end())
        if brace_start == -1:
            i = m.end()
            continue
        depth = 0
        j = brace_start
        while j < n:
            c = text[j]
            if c == '"':
                j += 1
                while j < n and text[j] != '"':
                    if text[j] == "\\":
                        j += 1
                    j += 1
                j += 1
                continue
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            j += 1
        start_line = text.count("\n", 0, m.start()) + 1
        end_line = text.count("\n", 0, j) + 1
        ranges.append((start_line, end_line))
        i = j
    return ranges


def check_file(path: Path, sync_core_src: Path = SYNC_CORE_SRC) -> list[str]:
    failures: list[str] = []
    if not path.is_file():
        return failures
    rel = path.relative_to(sync_core_src).as_posix()

    text = path.read_text(encoding="utf-8")
    test_ranges = cfg_test_line_ranges(text)

    def in_test_span(line_no: int, _ranges=test_ranges) -> bool:
        return any(start <= line_no <= end for start, end in _ranges)

    for i, line in enumerate(text.splitlines(), start=1):
        if COMMENT_LINE.match(line):
            continue
        if not any(trigger in line for trigger in TRIGGERS):
            continue
        if in_test_span(i):
            continue
        failures.append(
            f"{rel}:{i} references a wire proto type in production code -- "
            f"this crate's peer-wire protobuf dependency must live entirely in "
            f"yadorilink-sync-wire: {line.strip()}"
        )
    return failures


def all_source_files(sync_core_src: Path = SYNC_CORE_SRC) -> list[Path]:
    return sorted(sync_core_src.rglob("*.rs"))


def structural_checks(sync_core_src: Path = SYNC_CORE_SRC) -> list[str]:
    """Beyond proto:: confinement: the concrete structural claims Phase
    7D-2.3/7D-2.5 made -- codec ownership and frame-typed dispatch now
    route through yadorilink_sync_wire::, and the old peer_wire/ module is
    gone entirely."""
    failures: list[str] = []

    old_peer_wire = sync_core_src / "peer_wire"
    if old_peer_wire.exists():
        failures.append(
            "peer_wire/ still exists under yadorilink-sync-core/src -- the wire "
            "codec/frame layer must live only in yadorilink-sync-wire (Phase 7D-2.3)"
        )

    session = sync_core_src / "peer_session.rs"
    if session.is_file():
        text = session.read_text(encoding="utf-8")
        if "codec: Arc<dyn yadorilink_sync_wire::PeerWireCodec>" not in text:
            failures.append(
                "peer_session.rs: PeerSyncSession no longer owns a "
                "codec: Arc<dyn yadorilink_sync_wire::PeerWireCodec> field"
            )
        if "async fn send_frame(&self, frame: yadorilink_sync_wire::OutboundFrame)" not in text:
            failures.append(
                "peer_session.rs: send_frame no longer takes yadorilink_sync_wire::OutboundFrame"
            )
        if "fn try_send_frame(&self, frame: yadorilink_sync_wire::OutboundFrame)" not in text:
            failures.append(
                "peer_session.rs: try_send_frame no longer takes yadorilink_sync_wire::OutboundFrame"
            )
        if (
            "async fn handle_message(\n        self: Arc<Self>,\n        frame: yadorilink_sync_wire::InboundFrame,"
            not in text
        ):
            failures.append(
                "peer_session.rs: handle_message no longer takes yadorilink_sync_wire::InboundFrame directly"
            )
        if "VecDeque<(yadorilink_sync_wire::InboundFrame, usize)>" not in text:
            failures.append(
                "peer_session.rs: run's pending queue no longer holds yadorilink_sync_wire::InboundFrame"
            )

    public_wrapper = sync_core_src / "peer_session_public.rs"
    if public_wrapper.is_file():
        text = public_wrapper.read_text(encoding="utf-8")
        if "codec: yadorilink_sync_wire::ProtobufPeerWireCodec" not in text:
            failures.append(
                "peer_session_public.rs: PeerSyncSession no longer owns a codec field"
            )
        if "StdMutex<yadorilink_sync_wire::ClusterConfigOutboundFrame>" not in text:
            failures.append(
                "peer_session_public.rs: exact_cluster_config is no longer a "
                "yadorilink_sync_wire::ClusterConfigOutboundFrame"
            )

    return failures


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        src_root = Path(directory)

        # A production-code proto:: reference must be flagged, anywhere.
        prod_file = src_root / "types.rs"
        prod_file.write_text("let x = proto::FileInfo::default();\n", encoding="utf-8")
        found = check_file(prod_file, src_root)
        assert found, "a production proto:: reference must be flagged"

        # A #[cfg(test)]-gated reference must not be flagged.
        test_file = src_root / "peer_session.rs"
        test_file.write_text(
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    use yadorilink_ipc_proto::sync as proto;\n"
            "    fn f() -> proto::VersionPresentQuery { unimplemented!() }\n"
            "}\n",
            encoding="utf-8",
        )
        found = check_file(test_file, src_root)
        assert not found, "a #[cfg(test)]-gated reference must not be flagged"

        # A doc-comment mention must never be flagged.
        doc_file = src_root / "doc.rs"
        doc_file.write_text("/// See proto::SyncMessage's own doc comment.\nfn f() {}\n", encoding="utf-8")
        found = check_file(doc_file, src_root)
        assert not found, "a doc-comment mention must not be flagged"

        # structural_checks: a stale tree missing every required marker.
        stale_session = src_root / "peer_session.rs"
        stale_session.write_text("struct PeerSyncSession {}\n", encoding="utf-8")
        found = structural_checks(src_root)
        assert any("codec" in f for f in found), "a missing codec field must be flagged"

        # structural_checks: an old peer_wire/ directory must be flagged.
        (src_root / "peer_wire").mkdir(exist_ok=True)
        found = structural_checks(src_root)
        assert any("peer_wire/ still exists" in f for f in found)
        (src_root / "peer_wire").rmdir()

        # structural_checks: a fully-compliant tree passes clean.
        stale_session.write_text(
            "struct PeerSyncSession {\n"
            "    codec: Arc<dyn yadorilink_sync_wire::PeerWireCodec>,\n"
            "}\n"
            "async fn send_frame(&self, frame: yadorilink_sync_wire::OutboundFrame) {}\n"
            "fn try_send_frame(&self, frame: yadorilink_sync_wire::OutboundFrame) {}\n"
            "async fn handle_message(\n"
            "        self: Arc<Self>,\n"
            "        frame: yadorilink_sync_wire::InboundFrame,\n"
            "    ) {}\n"
            "let mut pending: VecDeque<(yadorilink_sync_wire::InboundFrame, usize)> = VecDeque::new();\n",
            encoding="utf-8",
        )
        public_file = src_root / "peer_session_public.rs"
        public_file.write_text(
            "codec: yadorilink_sync_wire::ProtobufPeerWireCodec,\n"
            "exact_cluster_config: StdMutex<yadorilink_sync_wire::ClusterConfigOutboundFrame>,\n",
            encoding="utf-8",
        )
        found = structural_checks(src_root)
        assert not found, f"a fully-compliant tree must pass structural_checks cleanly, got: {found}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("Phase 7D-2 complete wire boundary self-test passed")
        return 0

    failures: list[str] = []
    for path in all_source_files():
        failures.extend(check_file(path))
    failures.extend(structural_checks())

    if failures:
        print("Phase 7D-2 complete wire boundary violations:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print(
        "Phase 7D-2 complete wire boundary check passed: yadorilink-sync-core has "
        "zero production-code proto:: dependency -- the wire codec/frame layer "
        "lives entirely in yadorilink-sync-wire."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

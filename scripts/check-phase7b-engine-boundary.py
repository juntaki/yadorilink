#!/usr/bin/env python3
"""Enforce Phase 7B's `PeerReplicaEngine`/`PeerSyncSession` ownership split,
the same way `check-sync-repository-boundary.py` enforces Phase 5's
repository-split invariants.

Phase 7B (commits landed on `main`: PeerReplicaEngine extraction through
`handle_change_batch`'s DAG-mutation-stage move, plus this closure pass)
moved DAG/index mutation logic out of `peer_session.rs`'s wire handlers into
`crates/yadorilink-sync-core/src/peer_replica_engine.rs`. Two invariants keep
that split from silently eroding as more handlers move in future phases:

## Check 1: `PeerReplicaEngine` has no reverse/protocol dependency

`peer_replica_engine.rs` must never depend on the session/protocol layer it
was extracted out of, or on the wire codec -- a prerequisite for ever
splitting it into its own crate (Phase 7D), which must not need
`__peer_session_impl`, `yadorilink_ipc_proto`/`proto::`, the
`PeerMessageChannel` transport port, or any direct `.send(`/`.recv(` wire
I/O. Any of those substrings appearing in *code* (not a doc comment) in this
file is a violation.

## Check 2: DAG mutation calls stay off `PeerSyncSession`

`dag_admit_change_with_versions` and `record_acknowledged_frontier` are the
two DAG writes that stay engine-owned (`ChangeAdmissionPort`/
`FrontierStorePort`, now in `yadorilink-replica-engine`, Phase 7D-3).
`peer_session.rs` (production code -- a `#[cfg(test)]` span setting up DAG
state directly for a test fixture is not a production call site and is
exempt, same convention as this repo's other phase-boundary gates) must
never call either directly again; every production path must go through
`self.replica_engine.*`.

`materialization_enqueue_pending` is deliberately NOT in this list as of
Phase 7D-3.5: `PeerReplicaEngine::enqueue_batch_materialization` split into
a pure `yadorilink_replica_engine::materialization_plan::
plan_batch_materialization` (which paths need a job, with which trigger)
and sync-core's own execution loop (the actual SQLite write, wall-clock
read, `dst_trace`, wake, and logging) -- none of which the engine crate can
own, since it has no SQL/time/tracing dependency at all. `peer_session.rs`
calling `self.state.materialization_enqueue_pending(...)` directly is the
correct, intended shape now, not a boundary violation.

Same substring/brace-matching tradeoffs as this repo's other gate scripts in
this family -- not a real Rust parser.
"""

from __future__ import annotations

import argparse
import re
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYNC_CORE_SRC = ROOT / "crates/yadorilink-sync-core/src"
ENGINE_FILE = SYNC_CORE_SRC / "peer_replica_engine.rs"
SESSION_FILE = SYNC_CORE_SRC / "peer_session.rs"

ENGINE_FORBIDDEN = (
    "__peer_session_impl",
    "yadorilink_ipc_proto",
    "proto::",
    "PeerMessageChannel",
    ".send(",
    ".recv(",
)

SESSION_MUTATION_FORBIDDEN = (
    "dag_admit_change_with_versions",
    "record_acknowledged_frontier",
)

CFG_TEST_ATTR = re.compile(r"#\[cfg\(\s*test\s*\)\]")
COMMENT_LINE = re.compile(r"^\s*//")


def cfg_test_line_ranges(text: str) -> list[tuple[int, int]]:
    """Same brace-matching technique as this repo's other Phase 2-5/6 gate
    scripts (originally `gen-daemon-production-graph.py`'s
    `strip_cfg_test_blocks`)."""
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


def engine_boundary_violations(engine_file: Path) -> list[str]:
    """Check 1: `peer_replica_engine.rs` must never reference the
    session/protocol layer, in real code (doc-comment mentions are fine)."""
    failures: list[str] = []
    if not engine_file.is_file():
        return failures
    for i, line in enumerate(engine_file.read_text(encoding="utf-8").splitlines(), start=1):
        if COMMENT_LINE.match(line):
            continue
        for forbidden in ENGINE_FORBIDDEN:
            if forbidden in line:
                failures.append(
                    f"{engine_file}:{i} references {forbidden!r} -- PeerReplicaEngine must not "
                    "depend on the session/protocol/transport layer"
                )
    return failures


def session_mutation_violations(session_file: Path) -> list[str]:
    """Check 2: `peer_session.rs` production code must never call the DAG/
    index mutation functions Phase 7B moved onto PeerReplicaEngine."""
    failures: list[str] = []
    if not session_file.is_file():
        return failures
    text = session_file.read_text(encoding="utf-8")
    test_ranges = cfg_test_line_ranges(text)

    def in_test_span(line_no: int, _ranges=test_ranges) -> bool:
        return any(start <= line_no <= end for start, end in _ranges)

    for i, line in enumerate(text.splitlines(), start=1):
        if in_test_span(i):
            continue
        for forbidden in SESSION_MUTATION_FORBIDDEN:
            if forbidden in line:
                failures.append(
                    f"{session_file}:{i} calls {forbidden!r} directly -- this mutation must go "
                    "through self.replica_engine.*, not PeerSyncSession"
                )
    return failures


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        engine_dir = Path(directory)
        engine_file = engine_dir / "peer_replica_engine.rs"

        clean = (
            "//! Domain-level equivalent of `proto::VersionPresentQuery`.\n"
            "pub struct PeerReplicaEngine {\n"
            "    state: Arc<dyn PeerReplicaStatePort>,\n"
            "}\n"
        )
        engine_file.write_text(clean, encoding="utf-8")
        assert not engine_boundary_violations(
            engine_file
        ), "a doc-comment mention of proto:: must not be flagged"

        dirty = clean + "        let msg = proto::SyncMessage::decode(bytes)?;\n"
        engine_file.write_text(dirty, encoding="utf-8")
        found = engine_boundary_violations(engine_file)
        assert any(
            "proto::" in f for f in found
        ), "a real proto:: reference in code must be flagged"

        dirty2 = clean + "        crate::__peer_session_impl::op_version_hash(op)\n"
        engine_file.write_text(dirty2, encoding="utf-8")
        found = engine_boundary_violations(engine_file)
        assert any(
            "__peer_session_impl" in f for f in found
        ), "a reverse dependency on __peer_session_impl must be flagged"

    with tempfile.TemporaryDirectory() as directory:
        session_dir = Path(directory)
        session_file = session_dir / "peer_session.rs"

        clean = (
            "async fn handle_change_batch(&self) -> Result<(), SyncError> {\n"
            "    self.replica_engine.admit_authenticated_change(...)?;\n"
            "    Ok(())\n"
            "}\n"
        )
        session_file.write_text(clean, encoding="utf-8")
        assert not session_mutation_violations(
            session_file
        ), "delegating to self.replica_engine must not be flagged"

        dirty = (
            "async fn handle_change_batch(&self) -> Result<(), SyncError> {\n"
            "    self.state.dag_admit_change_with_versions(&change, &versions, false)?;\n"
            "    Ok(())\n"
            "}\n"
        )
        session_file.write_text(dirty, encoding="utf-8")
        found = session_mutation_violations(session_file)
        assert any(
            "dag_admit_change_with_versions" in f for f in found
        ), "a direct dag_admit_change_with_versions call from session code must be flagged"

        test_gated = (
            "#[cfg(test)]\n"
            "mod dag_convergence_authority_tests {\n"
            "    fn setup() {\n"
            "        state.dag_admit_change_with_versions(&change, &versions, true).unwrap();\n"
            "    }\n"
            "}\n"
        )
        session_file.write_text(test_gated, encoding="utf-8")
        assert not session_mutation_violations(
            session_file
        ), "a #[cfg(test)]-gated fixture call must not be flagged"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("Phase 7B engine boundary self-test passed")
        return 0

    failures = engine_boundary_violations(ENGINE_FILE)
    failures += session_mutation_violations(SESSION_FILE)
    if failures:
        print("Phase 7B engine boundary violations:")
        for failure in failures:
            print(f"- {failure.replace(str(ROOT) + '/', '')}")
        return 1

    print("Phase 7B engine boundary check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

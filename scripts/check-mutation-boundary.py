#!/usr/bin/env python3
"""Fail when production code bypasses the change-emitting index-mutation seam.

Every LOCAL current-row mutation must append its signed change to the history
DAG in the same transaction — the job of the `*_emitting_change` family in
`index.rs`. This guard forbids the raw, non-emitting current-row writers
(`upsert_file`, `upsert_files_batch`, `set_exec_bit`, `set_record_kind`,
`mark_deleted_at`) from being called in production local-capture, peer-session,
or daemon code outside the SQLite repository and its narrow port adapters, so
a new DAG-silent local write cannot quietly reappear.

Allowed unconditionally:
  - the `*_emitting_change` family (an emitting local write), and
  - `upsert_file_with_origin` (applying a peer's already-signed change,
    correctly index-only / DAG-silent — the Projected seam).
Both are excluded by construction: the forbidden tokens require a `(`
immediately after the bare name, so `upsert_file_emitting_change(`,
`upsert_files_batch_emitting_change(`, and `upsert_file_with_origin(` never
match.

A small allowlist pins the handful of known-legit raw calls that remain:
index-only Projected metadata application in peer-session, and the two
sanctioned non-emitting local-capture paths (a group whose change
DAG has not been seeded yet, and the standalone no-emitter build). The total
allowed-hit count is pinned so a new raw call — even one that happens to share
an allowlisted snippet — trips the guard for review.
"""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOTS = [
    ROOT / "crates/yadorilink-local-capture/src",
    ROOT / "crates/yadorilink-peer-session/src",
    ROOT / "crates/yadorilink-daemon/src",
]

# The SQLite file-index module defines both raw primitives and the emitting
# wrappers; it is the repository boundary this check protects.
EXEMPT_FILES = {
    "crates/yadorilink-sync-sqlite/src/file_index.rs",
}

# Composition-root implementations of narrow capability ports. These files
# are not exempt: a raw writer is accepted only inside the identically named
# trait method, i.e. as the one direct repository delegation the port exists
# to provide.
PORT_ADAPTER_FILES = {
    "crates/yadorilink-daemon/src/replica_coordinator/local_mutation.rs",
    "crates/yadorilink-daemon/src/replica_coordinator/materialization_state.rs",
    "crates/yadorilink-daemon/src/replica_coordinator/peer_replica_state.rs",
}

# Entire modules compiled only behind `#[cfg(test)]` in their parent. The
# per-file scanner cannot see that parent attribute, so record that structural
# fact explicitly instead of treating test fixtures as production adapters.
TEST_ONLY_FILES = {
    "crates/yadorilink-local-capture/src/test_support.rs",
}

# The non-emitting current-row writers. Each needs a `(` right after the bare
# name so the emitting/Projected wrappers (`*_emitting_change(`,
# `upsert_file_with_origin(`) never match.
FORBIDDEN = (
    "upsert_file(",
    "upsert_files_batch(",
    "set_exec_bit(",
    "set_record_kind(",
    "mark_deleted_at(",
)

# Known-legit raw calls, keyed by repo-relative path -> list of substrings that
# must appear on the offending line for it to be permitted. Every entry is a
# non-emitting write that is provably NOT a DAG-silent local mutation:
#   * peer_session.rs: Projected — applying a peer's already-resolved change /
#     advertised metadata to the local index (index-only by design).
#   * local_change.rs: a group with no change DAG yet (seeded by the chunked
#     initial import right after the scan) and the standalone no-emitter build,
#     neither of which has a DAG to diverge from.
ALLOWLIST = {
    "crates/yadorilink-peer-session/src/peer_session.rs": [
        # Projected: apply a peer's advertised metadata (index-only).
        "state.set_record_kind(",
        "state.set_exec_bit(",
    ],
    "crates/yadorilink-local-capture/src/local_change.rs": [
        # No change DAG yet: the initial import seeds these rows into history.
        "self.state.upsert_files_batch(",
        # Standalone (no change emitter) delete path.
        "self.state.mark_deleted_at(",
        # Local-column bookkeeping applied right after the emitting write that
        # already carried the same exec bit / symlink kind in its FileVersion.
        "self.state.set_exec_bit(",
        "self.state.set_record_kind(",
    ],
}

# Pinned total number of allowlisted raw calls across the tree. Bump this (and
# add the ALLOWLIST snippet) only for a reviewed, provably-non-silent site.
EXPECTED_ALLOWED = 8


def _code_only(line: str) -> str:
    """Drop a trailing line comment so brace counting ignores commented braces.

    Approximate (does not model `{`/`}` inside string literals), which is safe
    here: over-counting a brace only ever skips MORE lines as test code, never
    fewer, so a real production mutation can never be hidden by it — and the
    pinned allowed-hit count would change and fail the guard if it happened.
    """
    marker = line.find("//")
    return line[:marker] if marker != -1 else line


def production_lines(path: Path) -> list[tuple[int, str]]:
    """Yield `(1-based line number, line)` for every PRODUCTION line.

    Excludes the body of any `#[cfg(test)]`-attributed item — a braced module
    (`#[cfg(test)] mod tests { ... }`) or a single gated statement/item
    (`#[cfg(test)]\\n    hook(...);`) — wherever it appears in the file, then
    keeps scanning. The earlier "truncate at the first `#[cfg(test)]`" rule
    silently stopped checking every production mutation that followed a mid-file
    test-only hook, so such a hook could hide a real seam bypass after it.
    """
    raw = path.read_text(encoding="utf-8").splitlines()
    out: list[tuple[int, str]] = []
    index = 0
    total = len(raw)
    while index < total:
        if raw[index].strip() == "#[cfg(test)]":
            index += 1
            # Consume any stacked attributes on the same item.
            while index < total and raw[index].strip().startswith("#["):
                index += 1
            # Skip the attributed item: a brace-delimited block up to its
            # matching close, or a single statement/item terminated by `;`.
            depth = 0
            opened = False
            while index < total:
                code = _code_only(raw[index])
                depth += code.count("{") - code.count("}")
                if "{" in code:
                    opened = True
                index += 1
                if opened:
                    if depth <= 0:
                        break
                elif code.rstrip().endswith(";"):
                    break
            continue
        out.append((index + 1, raw[index]))
        index += 1
    return out


def in_matching_port_method(
    lines: list[tuple[int, str]], index: int, method: str
) -> bool:
    """Recognize only a port method's delegation to its same-named writer."""
    for _, candidate in reversed(lines[: index + 1]):
        stripped = candidate.strip()
        if stripped.startswith("fn "):
            return stripped.startswith(f"fn {method}(")
    return False


def main() -> int:
    violations: list[str] = []
    allowed_hits = 0
    for source_root in SOURCE_ROOTS:
        for path in sorted(source_root.rglob("*.rs")):
            rel = str(path.relative_to(ROOT))
            if rel in EXEMPT_FILES or rel in TEST_ONLY_FILES:
                continue
            allowed_snippets = ALLOWLIST.get(rel, [])
            lines = production_lines(path)
            for index, (lineno, line) in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith("//"):
                    continue
                for token in FORBIDDEN:
                    if token not in line:
                        continue
                    if ("fn " + token[:-1]) in line:
                        continue
                    method = token[:-1]
                    adapter_delegation = (
                        rel in PORT_ADAPTER_FILES
                        and in_matching_port_method(lines, index, method)
                    )
                    if adapter_delegation:
                        continue
                    if any(snippet in line for snippet in allowed_snippets):
                        allowed_hits += 1
                    else:
                        violations.append(
                            f"{rel}:{lineno}: raw `{token[:-1]}` bypasses the "
                            f"change-emitting mutation seam"
                        )

    exit_code = 0
    if violations:
        print(
            "local current-row mutations must go through the *_emitting_change "
            "family (or upsert_file_with_origin for Projected peer changes)",
            file=sys.stderr,
        )
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        exit_code = 1
    if allowed_hits != EXPECTED_ALLOWED:
        print(
            f"allowlisted raw-mutation call count changed: expected "
            f"{EXPECTED_ALLOWED}, found {allowed_hits}. Review the new/removed "
            f"site and update EXPECTED_ALLOWED (and ALLOWLIST) in this script.",
            file=sys.stderr,
        )
        exit_code = 1
    if exit_code == 0:
        print("mutation boundary: ok")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

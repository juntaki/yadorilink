#!/usr/bin/env python3
"""Fail when production code bypasses the change-emitting index-mutation seam.

Every LOCAL current-row mutation must append its signed change to the history
DAG in the same transaction — the job of the `*_emitting_change` family in
`index.rs`. This guard forbids the raw, non-emitting current-row writers
(`upsert_file`, `upsert_files_batch`, `set_exec_bit`, `set_record_kind`,
`mark_deleted_at`) from being called in production sync-core / daemon code
outside `index.rs` (which owns the primitives and the emitting wrappers), so a
new DAG-silent local write cannot quietly reappear.

Allowed unconditionally:
  - the `*_emitting_change` family (an emitting local write), and
  - `upsert_file_with_origin` (applying a peer's already-signed change,
    correctly index-only / DAG-silent — the Projected seam).
Both are excluded by construction: the forbidden tokens require a `(`
immediately after the bare name, so `upsert_file_emitting_change(`,
`upsert_files_batch_emitting_change(`, and `upsert_file_with_origin(` never
match.

A small allowlist pins the handful of known-legit raw calls that remain:
index-only Projected metadata application in `peer_session.rs`, and the two
sanctioned non-emitting local paths in `local_change.rs` (a group whose change
DAG has not been seeded yet, and the standalone no-emitter build). The total
allowed-hit count is pinned so a new raw call — even one that happens to share
an allowlisted snippet — trips the guard for review.
"""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOTS = [
    ROOT / "crates/yadorilink-sync-core/src",
    ROOT / "crates/yadorilink-daemon/src",
]

# `index.rs` defines the raw primitives, the `*_emitting_change` family, and
# `upsert_file_with_origin`; it is the mutation module the boundary is drawn
# around, so it is exempt in full (mirrors check-block-deletion-boundary.py's
# COORDINATOR exemption).
EXEMPT_FILES = {
    "crates/yadorilink-sync-core/src/index.rs",
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
    "crates/yadorilink-sync-core/src/peer_session.rs": [
        # Projected: apply a peer's advertised metadata (index-only).
        "set_record_kind(group_id, &record.path, meta.record_kind)",
        "set_exec_bit(group_id, &record.path, meta.exec_bit)",
    ],
    "crates/yadorilink-sync-core/src/local_change.rs": [
        # No change DAG yet: the initial import seeds these rows into history.
        "upsert_files_batch(group_id, &records",
        # Standalone (no change emitter) delete path.
        "mark_deleted_at(",
        # Local-column bookkeeping applied right after the emitting write that
        # already carried the same exec bit / symlink kind in its FileVersion.
        "set_exec_bit(group_id, path, *exec_bit)",
        "set_exec_bit(group_id, &rel_path, exec_bit)",
        "set_record_kind(group_id, rel_path, RecordKind::Symlink)",
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


def main() -> int:
    violations: list[str] = []
    allowed_hits = 0
    for source_root in SOURCE_ROOTS:
        for path in sorted(source_root.rglob("*.rs")):
            rel = str(path.relative_to(ROOT))
            if rel in EXEMPT_FILES:
                continue
            allowed_snippets = ALLOWLIST.get(rel, [])
            for lineno, line in production_lines(path):
                stripped = line.strip()
                if stripped.startswith("//"):
                    continue
                for token in FORBIDDEN:
                    if token not in line:
                        continue
                    if ("fn " + token[:-1]) in line:
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

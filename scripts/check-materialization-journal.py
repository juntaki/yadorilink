#!/usr/bin/env python3
"""Fail when a content-materialization write bypasses a crash-safe journal seam.

A file's blocks reach disk through exactly one low-level primitive,
`chunker::reconstruct_file`. Startup/periodic repair
(`materialization::repair_interrupted_materializations`) has to tell a
crash-mid-materialize (a `Hydrated` row whose file is missing but whose blocks
are present -> RECONSTRUCT) from an offline user-delete (same state ->
tombstone). That disambiguation only works if EVERY path that commits a
`Hydrated` content row with a still-pending disk write first records a durable
signal it can read back after a crash. Three such disciplines exist:

  * the materialization-intent journal (`MaterializationIntentGuard` in
    `materialization.rs`): write a durable intent BEFORE the bytes, clear it
    only AFTER the rename. Used by repair's own reconstruct and by the live peer
    materialize path.
  * the `Placeholder`/`Hydrating` -> `Hydrated` atomic flip: the row is only
    flipped to `Hydrated` AFTER the rename, so a crash leaves a non-`Hydrated`
    row that repair's pre-filter skips. Used by the hydrate paths.
  * the durable `restore_operations` journal: the intended version is recorded
    before the atomic replacement and reconciled against disk on restart. Used
    by the restore path.

This guard makes the class un-reintroducible in two ways:

1. The materialization-intent WRITE primitives
   (`begin_materialization_intent`, `clear_materialization_intent`) may be
   called only from the seam module (`materialization.rs`, which owns
   `MaterializationIntentGuard` and repair) and `index.rs` (their definitions).
   A new path may not hand-roll intent bookkeeping — it must go through the
   guard. (The `has_materialization_intent` READ is unrestricted: repair, the
   live invariant `debug_assert`, and tests all consult it.)

2. Every production `reconstruct_file(` call site must live in one of the
   sanctioned seam files above, and the total number of such call sites is
   pinned. A new content write anywhere — even an extra one inside an
   already-sanctioned file — trips the guard for review, forcing the author to
   confirm it is bracketed by one of the three disciplines.
"""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOTS = [
    ROOT / "crates/yadorilink-sync-core/src",
    ROOT / "crates/yadorilink-daemon/src",
]

# The intent-journal WRITE primitives. A trailing `(` keeps the bare-name match
# from also catching `has_materialization_intent(` (a read, allowed anywhere).
INTENT_WRITE_TOKENS = (
    "begin_materialization_intent(",
    "clear_materialization_intent(",
)

# Files permitted to call the intent-write primitives: `index.rs` defines them,
# `materialization.rs` owns the `MaterializationIntentGuard` seam and repair.
INTENT_WRITE_ALLOWED_FILES = {
    "crates/yadorilink-sync-core/src/index.rs",
    "crates/yadorilink-sync-core/src/materialization.rs",
}

# The single low-level content-to-disk writer.
RECONSTRUCT_TOKEN = "reconstruct_file("

# The sanctioned content-write seam files (each upholds one of the three
# crash-safe disciplines described above). A `reconstruct_file(` call anywhere
# else is a violation.
RECONSTRUCT_ALLOWED_FILES = {
    # Intent-journal seam (repair's own reconstruct).
    "crates/yadorilink-sync-core/src/materialization.rs",
    # Intent-journal seam (live peer materialize) + Hydrating->Hydrated flip
    # (hydrate_file).
    "crates/yadorilink-sync-core/src/peer_session.rs",
    # Hydrating->Hydrated flip (daemon hydrate) + restore_operations journal
    # (restore).
    "crates/yadorilink-daemon/src/hydration.rs",
}

# Pinned total number of production `reconstruct_file(` call sites across the
# sanctioned files. Bump this ONLY when adding a reviewed, provably crash-safe
# content-write site (and confirm it is bracketed by one of the three
# disciplines). Current sites:
#   materialization.rs: reconstruct_file_journaled                       (1)
#   peer_session.rs:    hydrate_file + materialize's two retry attempts  (3)
#   hydration.rs:       daemon hydrate + restore                         (2)
EXPECTED_RECONSTRUCT_CALLS = 6


def _code_only(line: str) -> str:
    """Drop a trailing line comment so brace counting ignores commented braces."""
    marker = line.find("//")
    return line[:marker] if marker != -1 else line


def production_lines(path: Path) -> list[tuple[int, str]]:
    """Yield `(1-based line number, line)` for every PRODUCTION line.

    Excludes the body of any `#[cfg(test)]`-attributed item (a braced module or
    a single gated statement), wherever it appears, then keeps scanning. Mirrors
    `check-mutation-boundary.py`'s scanner so test fixtures (which legitimately
    seed intents and call `reconstruct_file` directly) never count.
    """
    raw = path.read_text(encoding="utf-8").splitlines()
    out: list[tuple[int, str]] = []
    index = 0
    total = len(raw)
    while index < total:
        if raw[index].strip() == "#[cfg(test)]":
            index += 1
            while index < total and raw[index].strip().startswith("#["):
                index += 1
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
    reconstruct_hits = 0
    for source_root in SOURCE_ROOTS:
        for path in sorted(source_root.rglob("*.rs")):
            rel = str(path.relative_to(ROOT))
            for lineno, line in production_lines(path):
                stripped = line.strip()
                if stripped.startswith("//"):
                    continue

                for token in INTENT_WRITE_TOKENS:
                    if token not in line:
                        continue
                    # Skip the primitive's own definition.
                    if ("fn " + token[:-1]) in line:
                        continue
                    if rel not in INTENT_WRITE_ALLOWED_FILES:
                        violations.append(
                            f"{rel}:{lineno}: raw `{token[:-1]}` outside the "
                            f"MaterializationIntentGuard seam — route intent "
                            f"bookkeeping through the guard"
                        )

                if RECONSTRUCT_TOKEN in line and "fn reconstruct_file" not in line:
                    if rel in RECONSTRUCT_ALLOWED_FILES:
                        reconstruct_hits += 1
                    else:
                        violations.append(
                            f"{rel}:{lineno}: `reconstruct_file` writes content to disk "
                            f"outside a sanctioned crash-safe materialization seam"
                        )

    exit_code = 0
    if violations:
        print(
            "content materialization must go through a crash-safe journal seam "
            "(MaterializationIntentGuard, the Hydrating->Hydrated flip, or the "
            "restore_operations journal)",
            file=sys.stderr,
        )
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        exit_code = 1

    if reconstruct_hits != EXPECTED_RECONSTRUCT_CALLS:
        print(
            f"expected {EXPECTED_RECONSTRUCT_CALLS} production `reconstruct_file` call "
            f"site(s) in sanctioned seams, found {reconstruct_hits}. A new content-write "
            f"site must be confirmed crash-safe and this count bumped; a removed one must "
            f"lower it.",
            file=sys.stderr,
        )
        exit_code = 1

    if exit_code == 0:
        print(
            f"materialization journal: ok "
            f"({reconstruct_hits} sanctioned content-write sites)"
        )
    return exit_code


if __name__ == "__main__":
    sys.exit(main())

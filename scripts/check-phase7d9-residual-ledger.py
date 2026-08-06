#!/usr/bin/env python3
"""Phase 7D-9A boundary gate: registration completeness for the
`yadorilink-sync-core` residual ledger.

`docs/design/phase7d9-sync-core-residual-ledger.toml` is a machine-checkable,
more structured version of the prose ledgers Phase 7D-7 and Phase 7D-8 wrote
by hand (`docs/design/phase7d7-residual-ledger.md`,
`docs/design/phase7d8-local-change-boundary-ledger.md`). It registers every
production `.rs` file under `crates/yadorilink-sync-core/src/` as one or more
`[[module]]` entries (a file can split into several entries at
responsibility granularity -- see `index.rs`, 9,549 lines, registered as
several entries rather than one).

This gate is deliberately narrow, matching this sub-phase's own scope
(inventory/registration, not execution):

- Every production `.rs` file under `crates/yadorilink-sync-core/src/`
  (excluding anything under a `tests/` directory and excluding files whose
  entire contents are `#[cfg(test)]`-gated, e.g. `compaction/tests.rs`,
  `rebootstrap/tests.rs`) must have at least one ledger entry whose `path`
  matches it. Zero unregistered files.
- Every ledger entry must have a non-empty `destinations` array.
- Every ledger entry must have a non-empty `removal_phase` string.
- A TOML syntax error prevents parsing -> hard failure.

It deliberately does NOT fail merely because `status = "pending"` entries
exist -- that is the expected state for the entire rest of Phase 7D-9 (this
gate's job is registration completeness at 7D-9A, not completion). Instead
it prints a summary table of entry counts by `status`, and by
`removal_phase`, so later phases can watch `pending` trend toward zero.

Same substring/regex-based approach as this repo's other phase-boundary gate
scripts (see `check-phase7d6-peer-session-boundary.py`,
`check-phase7d8-local-capture-boundary.py`) -- not a real Rust or TOML
validator beyond the standard library `tomllib` parse itself. Reviewer
judgment remains the backstop.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from collections import Counter
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - repo's CI pins a modern python3
    import tomli as tomllib  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]
SYNC_CORE_SRC = ROOT / "crates/yadorilink-sync-core/src"
LEDGER_PATH = ROOT / "docs/design/phase7d9-sync-core-residual-ledger.toml"

# `status` vocabulary. "pending" is 7D-9A's own initial value (every entry).
# "migrated" is added in Phase 7D-9B for entries whose real code has
# physically moved to its `destinations` -- e.g. `fs_commit.rs`,
# `link_preflight.rs`, `root_identity.rs`'s value-type slice. Deliberately
# not a stronger claim than that: a "migrated" entry's *destination* code
# exists and every real caller was repointed; it says nothing about whether
# every OTHER entry sharing the same `path` (a large multi-group file like
# `index.rs`) has also moved -- check the sibling entries' own `status` for
# that.
KNOWN_STATUSES = {"pending", "migrated"}

# Files whose entire contents are `#[cfg(test)]`-only support modules, never
# reachable from a non-test build of the crate. These are exempt from the
# "every production file must be registered" requirement, mirroring how the
# ledger's own `test-only support` category exists for files that DO get
# registered but are known-not-production; these particular files are pure
# `mod tests { ... }` leaves declared from a sibling production file
# (`compaction.rs` declares `mod tests;`, `rebootstrap.rs` declares `mod
# tests;`) and contain zero production code of their own.
TEST_ONLY_FILE_BASENAMES = {"tests.rs"}


class LedgerError(Exception):
    pass


def production_rs_files(src_dir: Path) -> list[Path]:
    files = []
    for path in sorted(src_dir.rglob("*.rs")):
        if "tests" in path.relative_to(src_dir).parts[:-1]:
            # a `tests/` directory component anywhere in the relative path
            continue
        if path.name in TEST_ONLY_FILE_BASENAMES:
            continue
        files.append(path)
    return files


def load_ledger(ledger_path: Path) -> list[dict]:
    if not ledger_path.is_file():
        raise LedgerError(f"{ledger_path} does not exist")
    try:
        data = tomllib.loads(ledger_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise LedgerError(f"{ledger_path} is not valid TOML: {exc}") from exc
    modules = data.get("module")
    if modules is None:
        raise LedgerError(f"{ledger_path} defines no [[module]] entries")
    if not isinstance(modules, list):
        raise LedgerError(f"{ledger_path}'s 'module' key is not an array of tables")
    return modules


def registered_paths(modules: list[dict]) -> set[str]:
    paths = set()
    for entry in modules:
        p = entry.get("path")
        if isinstance(p, str) and p:
            paths.add(p)
    return paths


def violations(
    src_dir: Path = SYNC_CORE_SRC, ledger_path: Path = LEDGER_PATH
) -> tuple[list[str], list[dict]]:
    """Returns (failures, modules). `modules` is [] if the ledger itself
    failed to parse (that failure is included in `failures`)."""
    failures: list[str] = []

    try:
        modules = load_ledger(ledger_path)
    except LedgerError as exc:
        return [str(exc)], []

    for i, entry in enumerate(modules):
        path = entry.get("path")
        if not isinstance(path, str) or not path:
            failures.append(f"module entry #{i} has no non-empty 'path'")
            continue
        destinations = entry.get("destinations")
        if not isinstance(destinations, list) or not destinations:
            failures.append(f"module {path!r}: 'destinations' is missing or empty")
        removal_phase = entry.get("removal_phase")
        if not isinstance(removal_phase, str) or not removal_phase.strip():
            failures.append(f"module {path!r}: 'removal_phase' is missing or empty")
        status = entry.get("status")
        if status is not None and status not in KNOWN_STATUSES:
            failures.append(
                f"module {path!r}: unknown 'status' {status!r} -- expected one of "
                f"{sorted(KNOWN_STATUSES)}"
            )

    registered = registered_paths(modules)
    prod_files = production_rs_files(src_dir)
    rel_files = {str(p.relative_to(src_dir)) for p in prod_files}
    unregistered = sorted(rel_files - registered)
    for path in unregistered:
        failures.append(f"unregistered production file: {path}")

    return failures, modules


def print_status_summary(modules: list[dict]) -> None:
    status_counts = Counter(entry.get("status", "<missing>") for entry in modules)
    phase_counts = Counter(entry.get("removal_phase", "<missing>") for entry in modules)

    print(f"module entries: {len(modules)}")
    print("by status:")
    for status, count in sorted(status_counts.items()):
        print(f"  {status:<12} {count}")
    print("by removal_phase:")
    for phase, count in sorted(phase_counts.items()):
        print(f"  {phase:<12} {count}")


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        src_dir = root / "sync-core-src"
        src_dir.mkdir(parents=True, exist_ok=True)
        ledger_path = root / "ledger.toml"

        def write_source_tree() -> None:
            for f in src_dir.rglob("*"):
                if f.is_file():
                    f.unlink()
            (src_dir / "a.rs").write_text("pub fn a() {}\n", encoding="utf-8")
            sub = src_dir / "sub"
            sub.mkdir(exist_ok=True)
            (sub / "b.rs").write_text("pub fn b() {}\n", encoding="utf-8")
            (sub / "tests.rs").write_text(
                "#[cfg(test)]\nmod x { }\n", encoding="utf-8"
            )
            tests_dir = src_dir / "tests"
            tests_dir.mkdir(exist_ok=True)
            (tests_dir / "helper.rs").write_text(
                "pub fn helper() {}\n", encoding="utf-8"
            )

        def write_good_ledger() -> None:
            ledger_path.write_text(
                """
[[module]]
path = "a.rs"
lines = 1
responsibilities = ["pure domain / policy / planning"]
destinations = ["yadorilink-replica-engine"]
status = "pending"
blocked_by = []
removal_phase = "7D-9D"

[[module]]
path = "sub/b.rs"
lines = 1
responsibilities = ["SQLite SQL / row mapping"]
destinations = ["yadorilink-sync-sqlite"]
status = "pending"
blocked_by = []
removal_phase = "7D-9C"
""",
                encoding="utf-8",
            )

        # 1. Clean state: no violations.
        write_source_tree()
        write_good_ledger()
        failures, modules = violations(src_dir, ledger_path)
        assert not failures, failures
        assert len(modules) == 2, modules

        # 2. Unregistered production file must be caught.
        (src_dir / "c.rs").write_text("pub fn c() {}\n", encoding="utf-8")
        failures, _ = violations(src_dir, ledger_path)
        assert any("unregistered production file: c.rs" in f for f in failures), failures
        (src_dir / "c.rs").unlink()
        failures, _ = violations(src_dir, ledger_path)
        assert not failures, failures

        # 3. A `tests.rs` leaf and files under a `tests/` directory must NOT
        #    be required to register (they're not production files).
        assert not any("tests.rs" in f for f in failures)
        assert not any("tests/helper.rs" in f for f in failures)

        # 4. Missing 'destinations' must be caught.
        ledger_path.write_text(
            """
[[module]]
path = "a.rs"
lines = 1
responsibilities = ["pure domain / policy / planning"]
destinations = []
status = "pending"
blocked_by = []
removal_phase = "7D-9D"

[[module]]
path = "sub/b.rs"
lines = 1
responsibilities = ["SQLite SQL / row mapping"]
destinations = ["yadorilink-sync-sqlite"]
status = "pending"
blocked_by = []
removal_phase = "7D-9C"
""",
            encoding="utf-8",
        )
        failures, _ = violations(src_dir, ledger_path)
        assert any("'destinations' is missing or empty" in f for f in failures), failures

        # 5. Missing 'removal_phase' must be caught.
        write_good_ledger()
        text = ledger_path.read_text(encoding="utf-8").replace(
            'removal_phase = "7D-9C"', 'removal_phase = ""'
        )
        ledger_path.write_text(text, encoding="utf-8")
        failures, _ = violations(src_dir, ledger_path)
        assert any("'removal_phase' is missing or empty" in f for f in failures), failures

        # 6. A `status = "pending"` ledger (the expected 7D-9A state) must NOT
        #    fail on that basis alone.
        write_good_ledger()
        failures, modules = violations(src_dir, ledger_path)
        assert not failures, failures
        assert all(m.get("status") == "pending" for m in modules)

        # 6b. A `status = "migrated"` entry (Phase 7D-9B's new value) must
        #     NOT fail, and an unknown status value must be caught.
        write_good_ledger()
        text = ledger_path.read_text(encoding="utf-8").replace(
            'path = "a.rs"\nlines = 1\nresponsibilities = ["pure domain / policy / planning"]\n'
            'destinations = ["yadorilink-replica-engine"]\nstatus = "pending"',
            'path = "a.rs"\nlines = 1\nresponsibilities = ["pure domain / policy / planning"]\n'
            'destinations = ["yadorilink-replica-engine"]\nstatus = "migrated"',
        )
        ledger_path.write_text(text, encoding="utf-8")
        failures, modules = violations(src_dir, ledger_path)
        assert not failures, failures
        text = ledger_path.read_text(encoding="utf-8").replace(
            'status = "migrated"', 'status = "done"'
        )
        ledger_path.write_text(text, encoding="utf-8")
        failures, _ = violations(src_dir, ledger_path)
        assert any("unknown 'status'" in f for f in failures), failures

        # 7. A TOML syntax error must be caught as a hard failure.
        ledger_path.write_text("[[module]\npath = broken", encoding="utf-8")
        failures, modules = violations(src_dir, ledger_path)
        assert failures and modules == [], failures

        # 8. A missing ledger file entirely must be caught.
        ledger_path.unlink()
        failures, modules = violations(src_dir, ledger_path)
        assert any("does not exist" in f for f in failures), failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("phase 7d9 residual ledger self-test passed")
        return 0

    failures, modules = violations()

    if modules:
        print_status_summary(modules)

    if failures:
        print("phase 7d9 residual ledger violations:")
        for failure in failures:
            print(f"- {str(failure).replace(str(ROOT) + '/', '')}")
        return 1

    print("Phase 7D-9A residual ledger registration check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

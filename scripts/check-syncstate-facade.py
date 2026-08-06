#!/usr/bin/env python3
"""Enforce Phase 6's `SyncState` facade-purity invariant: after the Phase 5
repository split and Phase 6 Commit 1's cleanup, `impl SyncState` in
`crates/yadorilink-sync-core/src/index.rs` should contain NOTHING but thin,
same-signature delegates to repository types (`crate::repository::*`) --
`SyncState` itself must never touch SQL or a raw database connection again,
and must never make a business decision that spans more than one repository
(that belongs on a repository, or a future named cross-repository type, not
on the facade).

Four checks, each independently disprovable by a self-test case:

All four checks scan every `impl SyncState { ... }` block found in the
file -- the inherent impl AND any `impl <Trait> for SyncState { ... }`
block (e.g. `CompactionDagStore`/`DeviceFrontierStore`/`CheckpointStore`).
A trait impl is just as much "the facade" as the inherent impl; scanning
only the inherent block was a real blind spot until Phase 6 Commit 1's
independent review (not this gate) caught three trait impls bypassing the
writer-gate with raw pool access.

1. **No SQL/rusqlite tokens inside `impl SyncState` method bodies** --
   `rusqlite::`, `Connection`, `Transaction`, `.execute(`, `query_row`,
   `prepare(`, `conn.`, `tx.` -- except the three legitimate infra methods
   `open`/`open_in_memory`/`pool`, which must own the connection pool itself.
   A regression here means someone wrote a new query directly on `SyncState`
   instead of adding it to (or calling into) the owning repository.

2. **No repository/`SyncDatabase` construction outside `open`/
   `open_in_memory`** -- the same invariant `check-sync-repository-boundary.py`
   already enforces crate-wide; this check is index.rs-scoped and kept here
   too since it's cheap and this gate is meant to be the one-stop check for
   `SyncState`'s own purity specifically.

3. **No multi-repository business branching** -- a method in `impl SyncState`
   that references two or more distinct `self.<name>_repository.` fields AND
   contains an `if`/`match` is flagged: that shape is a business DECISION
   spanning repositories, which does not belong on the facade (it belongs on
   a repository, or a future named cross-repository type -- see
   `docs/design/syncstate-repositories-phase5-exit-report.md`'s "no formal
   commit-store abstraction was built" note for why this stays a plain
   textual gate rather than a type-system-enforced rule). A method that
   resolves one value from one repository and passes it into another (the
   established `ChangeAuth`/pinned-set parameter-passing pattern) is NOT
   branching and is not flagged -- it has no `if`/`match`.

4. **Every repository struct has exactly one field, `database:
   Arc<SyncDatabase>`** -- catches BOTH a repository holding another
   repository (true repository-to-repository coupling, not the already-
   established `Type::associated_fn(&tx, ...)` cross-module call pattern,
   which takes no `&self` and therefore never appears as a struct field) and
   a repository constructing its own independent `SyncDatabase` instead of
   sharing the one `Arc` every repository is handed at construction (which
   would silently break `SyncDatabase`'s writer-serialization guarantee --
   see `check-sync-repository-boundary.py`'s own doc comment for why that
   matters).

Same substring/brace-matching tradeoffs as this repo's other gate scripts in
this family -- not a real Rust parser.
"""

from __future__ import annotations

import argparse
import re
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX_RS = ROOT / "crates/yadorilink-sync-core/src/index.rs"
REPOSITORY_DIR = ROOT / "crates/yadorilink-sync-core/src/repository"

SQL_TOKENS = (
    "conn.",
    "tx.",
    ".execute(",
    "query_row",
    "prepare(",
    "rusqlite::",
    "Connection",
    "Transaction",
)
ALLOWED_SQL_METHODS = {"open", "open_in_memory", "pool"}

FN_RE = re.compile(r"^\s*(pub(\(crate\))?\s+)?(async\s+)?fn\s+(\w+)")
REPO_FIELD_RE = re.compile(r"self\.(\w+_repository)\.")
BRANCH_RE = re.compile(r"\bif\b|\bmatch\b")
REPO_TYPE_NEW_RE = re.compile(r"\b(\w*Repository|SyncDatabase|RecoverySnapshotReader)::new\(")


IMPL_SYNCSTATE_RE = re.compile(r"^impl(?:<[^>]*>)? (?:\w+(?:<[^>]*>)? for )?SyncState(?:<[^>]*>)? \{")


def extract_impl_syncstate_blocks(text: str) -> list[list[str]]:
    """Every `impl SyncState { ... }` AND `impl <Trait> for SyncState { ... }`
    block -- not just the inherent impl. A trait impl on `SyncState` is just
    as much "the facade" as the inherent impl and must obey the same purity
    rules; scanning only the inherent block let three trait impls
    (`CompactionDagStore`/`DeviceFrontierStore`/`CheckpointStore`) bypass raw
    SQL/writer-gate checks entirely until this was caught during Phase 6
    Commit 1's independent review, not by this gate."""
    lines = text.split("\n")
    blocks: list[list[str]] = []
    i = 0
    while i < len(lines):
        if IMPL_SYNCSTATE_RE.match(lines[i].strip()):
            start = i
            depth = 0
            end = len(lines)
            for j in range(start, len(lines)):
                depth += lines[j].count("{") - lines[j].count("}")
                if j > start and depth == 0:
                    end = j
                    break
            blocks.append(lines[start:end])
            i = end + 1
        else:
            i += 1
    return blocks


def split_methods(block: list[str]) -> dict[str, str]:
    fn_bodies: dict[str, str] = {}
    i = 0
    while i < len(block):
        m = FN_RE.match(block[i])
        if m:
            name = m.group(4)
            depth = 0
            started = False
            j = i
            body_lines = []
            while j < len(block):
                depth += block[j].count("{") - block[j].count("}")
                body_lines.append(block[j])
                if "{" in block[j]:
                    started = True
                if started and depth == 0:
                    break
                j += 1
            fn_bodies[name] = "\n".join(body_lines)
            i = j + 1
        else:
            i += 1
    return fn_bodies


def violations_index(text: str) -> list[str]:
    failures: list[str] = []
    for block in extract_impl_syncstate_blocks(text):
        header = block[0].strip()
        fn_bodies = split_methods(block)

        for name, body in fn_bodies.items():
            if name in ALLOWED_SQL_METHODS:
                continue
            if REPO_TYPE_NEW_RE.search(body):
                failures.append(
                    f"{header} :: {name} constructs a repository/SyncDatabase "
                    "outside open/open_in_memory"
                )
            if any(tok in body for tok in SQL_TOKENS):
                failures.append(f"{header} :: {name} contains raw SQL/rusqlite usage")
            repos = set(REPO_FIELD_RE.findall(body))
            if len(repos) >= 2 and BRANCH_RE.search(body):
                failures.append(
                    f"{header} :: {name} branches (if/match) across {len(repos)} "
                    f"repositories ({', '.join(sorted(repos))}) -- multi-repository "
                    "business logic must not live on the facade"
                )
    return failures


def violations_repository_fields(repo_dir: Path) -> list[str]:
    failures: list[str] = []
    if not repo_dir.is_dir():
        return failures
    struct_re = re.compile(r"pub\(crate\) struct (\w+) \{")
    for path in sorted(repo_dir.glob("*.rs")):
        if path.name == "mod.rs":
            text = path.read_text(encoding="utf-8")
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("pub mod "):
                    failures.append(f"{path}: repository/mod.rs exposes a `pub mod` (must be pub(crate))")
            continue
        text = path.read_text(encoding="utf-8")
        for m in struct_re.finditer(text):
            struct_name = m.group(1)
            brace_start = text.find("{", m.end() - 1)
            brace_end = text.find("}", brace_start)
            body = text[brace_start + 1 : brace_end]
            fields = [f.split(":")[0].strip() for f in body.strip().split("\n") if f.strip()]
            if fields != ["database"]:
                failures.append(
                    f"{path}: struct {struct_name} has fields {fields}, expected exactly "
                    "['database'] (a repository must hold nothing but its own "
                    "Arc<SyncDatabase>)"
                )
    return failures


def violations() -> list[str]:
    failures: list[str] = []
    if INDEX_RS.is_file():
        failures.extend(violations_index(INDEX_RS.read_text(encoding="utf-8")))
    failures.extend(violations_repository_fields(REPOSITORY_DIR))
    return failures


def self_test() -> None:
    # Check 1/2: SQL/rusqlite usage and repository construction outside the
    # allowlist are both flagged; the three infra methods are exempt.
    clean = """
impl SyncState {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SyncError> {
        let conn = pool.get()?;
        Ok(Self {})
    }
    pub fn delegate(&self, group_id: &str) -> Result<(), SyncError> {
        self.link_repository.add_link(group_id)
    }
}
"""
    assert not violations_index(clean), "a clean facade must produce no violations"

    dirty_sql = clean.replace(
        "self.link_repository.add_link(group_id)",
        "self.pool().get()?.execute(\"DELETE FROM links\", [])?;\n        Ok(())",
    )
    found = violations_index(dirty_sql)
    assert any("raw SQL" in f for f in found), "raw SQL inside a non-infra method must be flagged"

    dirty_construct = clean.replace(
        "self.link_repository.add_link(group_id)",
        "let repo = LinkRepository::new(database.clone());\n        Ok(())",
    )
    found = violations_index(dirty_construct)
    assert any(
        "constructs a repository" in f for f in found
    ), "a repository construction outside open/open_in_memory must be flagged"

    # A trait impl on SyncState is scanned the same as the inherent impl --
    # raw SQL there must be caught too, not just inside `impl SyncState {`.
    dirty_trait_impl = """
impl SomeTrait for SyncState {
    fn leaky(&self) -> Result<(), SyncError> {
        self.pool().get()?.execute("DELETE FROM links", [])?;
        Ok(())
    }
}
"""
    found = violations_index(dirty_trait_impl)
    assert any(
        "raw SQL" in f for f in found
    ), "raw SQL inside a trait impl on SyncState must be flagged, not just the inherent impl"

    # Check 3: multi-repository branching is flagged; a plain resolve-then-
    # delegate (no branch) is not.
    branching = """
impl SyncState {
    pub fn mixed(&self, group_id: &str) -> Result<(), SyncError> {
        if self.link_repository.is_paused_for_group(group_id)? {
            self.enrollment_repository.record_pending_enrollment(marker)?;
        }
        Ok(())
    }
}
"""
    found = violations_index(branching)
    assert any("branches" in f for f in found), "multi-repository if/match must be flagged"

    resolve_then_delegate = """
impl SyncState {
    pub fn resolve_then_delegate(&self, group_id: &str) -> Result<(), SyncError> {
        let pinned = self.handoff_lease_repository.leased_version_keys_for_group(group_id, 0)?;
        self.file_index_repository.expire_superseded_and_trashed_versions(group_id, 0, &pinned)
    }
}
"""
    assert not violations_index(
        resolve_then_delegate
    ), "a branch-free resolve-then-delegate across two repositories must NOT be flagged"

    # Check 4: repository struct field shape.
    with tempfile.TemporaryDirectory() as directory:
        repo_dir = Path(directory)

        good = repo_dir / "link.rs"
        good.write_text(
            "pub(crate) struct LinkRepository {\n    database: Arc<SyncDatabase>,\n}\n",
            encoding="utf-8",
        )
        assert not violations_repository_fields(repo_dir), "the standard single-field shape must pass"
        good.unlink()

        bad = repo_dir / "link.rs"
        bad.write_text(
            "pub(crate) struct LinkRepository {\n"
            "    database: Arc<SyncDatabase>,\n"
            "    enrollment_repository: EnrollmentRepository,\n"
            "}\n",
            encoding="utf-8",
        )
        found = violations_repository_fields(repo_dir)
        assert any(
            "LinkRepository" in f for f in found
        ), "a repository holding another repository as a field must be flagged"
        bad.unlink()

        leaked = repo_dir / "mod.rs"
        leaked.write_text("pub mod link;\n", encoding="utf-8")
        found = violations_repository_fields(repo_dir)
        assert any("pub mod" in f for f in found), "a `pub mod` in repository/mod.rs must be flagged"
        leaked.unlink()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("syncstate facade purity self-test passed")
        return 0

    failures = violations()
    if failures:
        print("syncstate facade purity violations:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("syncstate facade purity check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Enforce Phase 5's `SyncState` repository-split ownership invariants, the
same way `check-daemon-composition-root.py`/`check-link-runtime-ownership.py`/
`check-maintenance-ownership.py` enforce their own phase's.

## Check 1: single composition point

`crates/yadorilink-sync-core/src/storage/sync_database.rs`'s `SyncDatabase`
owns the connection pool and the in-process writer-serialization gate
(`locked_write`) that makes this crate's own-process `SQLITE_BUSY`/
`SQLITE_LOCKED` contention structurally impossible (see that type's own doc
comment). Every one of the 12 repository types under
`crates/yadorilink-sync-core/src/repository/` holds a CLONE of the same
`Arc<SyncDatabase>` `SyncState` itself holds -- constructed exactly once per
`SyncState`, in `SyncState::open`/`open_in_memory`. If a second `SyncDatabase`
(or a second instance of a repository type wrapping a DIFFERENT
`SyncDatabase`) were ever constructed for the same file-backed database, its
own independent `writer_gate` mutex would no longer serialize against the
first one's -- silently reopening exactly the own-process write race
`locked_write` exists to close, invisibly (both would still individually
"work"; only concurrent behavior degrades). This gate keeps that invariant
mechanical rather than tribal: `SyncDatabase::new(` and every
`<RepositoryName>Repository::new(` construction call is allowed ONLY from
`index.rs` (the two composition points) or from inside a `#[cfg(test)]` span
anywhere in this crate.

## Check 2: no `repository/**` -> `crate::index` dependency

A Phase 4B-5 closure fix (a user code review found this) made
`state_model.rs` the true leaf of this crate's internal dependency graph:
`index::SyncState -> repository -> state_model`, never the reverse. Before
that fix, `repository/*.rs` imported ~59 domain types/row-decoders/SQL
helpers back from `crate::index`, a real circular dependency that is
harmless within one crate today but would hard-block ever splitting the
repository layer into its own crate later (a Cargo crate cannot depend on
the crate that depends on it). This check keeps that fix from silently
eroding: any `use crate::index::` (or `crate::index::`-qualified path) inside
`repository/*.rs` is a violation, no exceptions.

## Check 3: no `storage/**` -> `crate::index` dependency, except one documented case

Same reasoning as check 2, for `storage/*.rs` (which owns `SyncDatabase` and
schema init/migration -- also meant to stay a dependency-free leaf).
`storage/schema.rs` has ONE standing, documented exception: it calls
`crate::index::rebootstrap_store::init_rebootstrap_schema` --
`rebootstrap_store` is a submodule declared *inside* `index.rs`
(`pub(crate) mod rebootstrap_store;`), a separate concern from the
`SyncState`<->repository cycle these checks target, and deliberately out of
scope for this closure. Any OTHER `crate::index::` reference in `storage/*.rs`
is a violation.

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
REPOSITORY_DIR = SYNC_CORE_SRC / "repository"
STORAGE_DIR = SYNC_CORE_SRC / "storage"

# The one standing, documented exception to check 3 -- see this script's own
# module doc comment for why.
STORAGE_INDEX_EXCEPTION = "crate::index::rebootstrap_store::init_rebootstrap_schema"

REPOSITORY_TYPES = (
    "SyncDatabase",
    "LinkRepository",
    "EnrollmentRepository",
    "FileIndexRepository",
    "MaterializationStateRepository",
    "ChangeHistoryRepository",
    "MaterializationJobRepository",
    "PolicyWatermarkRepository",
    "DirtyPathRepository",
    "RestoreOperationRepository",
    "HandoffLeaseRepository",
    "RoleLossOperationRepository",
    "MembershipOperationRepository",
)

# The sole composition point for every one of the types above.
ALLOWED_CALLERS = {
    "index.rs": set(REPOSITORY_TYPES),
}

CFG_TEST_ATTR = re.compile(r"#\[cfg\(\s*test\s*\)\]")


def cfg_test_line_ranges(text: str) -> list[tuple[int, int]]:
    """Same brace-matching technique as this repo's other Phase 2-5 gate
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


def violations(src_dir: Path) -> list[str]:
    failures: list[str] = []

    for path in sorted(src_dir.rglob("*.rs")):
        rel_name = path.name
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        test_ranges = cfg_test_line_ranges(text)

        def in_test_span(line_no: int, _ranges=test_ranges) -> bool:
            return any(start <= line_no <= end for start, end in _ranges)

        allowed_here = ALLOWED_CALLERS.get(rel_name, set())

        for i, line in enumerate(lines, start=1):
            for repo in REPOSITORY_TYPES:
                token = f"{repo}::new("
                if token not in line:
                    continue
                # The type's own `impl` block (`pub(crate) fn new(...) ->
                # Self` inside `impl RepoName { ... }`) is not a construction
                # call site -- skip lines that are plainly the definition
                # itself, not a `Type::new(` call.
                if re.search(r"\bfn\s+new\s*\(", line) and repo not in line.split("fn new")[0]:
                    continue
                if repo in allowed_here:
                    continue
                if in_test_span(i):
                    continue
                failures.append(
                    f"{path}:{i} constructs {repo}::new outside its sole composition "
                    "point (index.rs) and outside a #[cfg(test)] span"
                )

    return failures


def repository_index_dependency_violations(repository_dir: Path) -> list[str]:
    """Check 2: `repository/*.rs` must never reference `crate::index`."""
    failures: list[str] = []
    if not repository_dir.is_dir():
        return failures
    for path in sorted(repository_dir.glob("*.rs")):
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if "crate::index::" in line or "crate::index;" in line:
                failures.append(f"{path}:{i} references crate::index -- repository/*.rs must not")
    return failures


def storage_index_dependency_violations(storage_dir: Path) -> list[str]:
    """Check 3: `storage/*.rs` must never reference `crate::index`, except the
    one documented `rebootstrap_store` exception."""
    failures: list[str] = []
    if not storage_dir.is_dir():
        return failures
    for path in sorted(storage_dir.rglob("*.rs")):
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if "crate::index::" not in line and "crate::index;" not in line:
                continue
            if STORAGE_INDEX_EXCEPTION in line:
                continue
            failures.append(
                f"{path}:{i} references crate::index -- storage/*.rs must not, except the "
                f"documented {STORAGE_INDEX_EXCEPTION} exception"
            )
    return failures


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        src_dir = Path(directory)

        allowed = src_dir / "index.rs"
        allowed.write_text(
            "let database = Arc::new(SyncDatabase::new(pool));\n"
            "let link_repository = LinkRepository::new(database.clone());\n",
            encoding="utf-8",
        )
        assert not violations(src_dir), "index.rs must be allowed to construct every repository"
        allowed.unlink()

        disallowed = src_dir / "some_handler.rs"
        disallowed.write_text(
            "let link_repository = LinkRepository::new(database.clone());\n", encoding="utf-8"
        )
        found = violations(src_dir)
        assert any(
            "some_handler.rs" in f for f in found
        ), "a non-allowlisted, non-test construction must be flagged"
        disallowed.unlink()

        # A second SyncDatabase construction outside index.rs is exactly
        # the regression this gate exists to catch -- same rule, same type.
        disallowed_db = src_dir / "some_other_module.rs"
        disallowed_db.write_text(
            "let rogue = Arc::new(SyncDatabase::new(pool));\n", encoding="utf-8"
        )
        found = violations(src_dir)
        assert any(
            "some_other_module.rs" in f for f in found
        ), "a second SyncDatabase construction outside index.rs must be flagged"
        disallowed_db.unlink()

        test_gated = src_dir / "some_handler.rs"
        test_gated.write_text(
            "#[cfg(test)]\nmod tests {\n"
            "    fn helper() {\n"
            "        let link_repository = LinkRepository::new(database.clone());\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        assert not violations(src_dir), "a #[cfg(test)]-gated construction must pass"
        test_gated.unlink()

        # The repository type's own `impl X { pub(crate) fn new(...) }`
        # definition line must not be mistaken for a construction call site.
        definition = src_dir / "repository" / "link.rs"
        definition.parent.mkdir(parents=True, exist_ok=True)
        definition.write_text(
            "impl LinkRepository {\n"
            "    pub(crate) fn new(database: Arc<SyncDatabase>) -> Self {\n"
            "        Self { database }\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        assert not violations(src_dir), "a type's own `fn new` definition must not be flagged"

    # Check 2: repository/*.rs -> crate::index is always a violation.
    with tempfile.TemporaryDirectory() as directory:
        repository_dir = Path(directory)
        clean = repository_dir / "link.rs"
        clean.write_text("use crate::state_model::FolderLink;\n", encoding="utf-8")
        assert not repository_index_dependency_violations(
            repository_dir
        ), "a repository file with no crate::index reference must pass"
        clean.unlink()

        dirty = repository_dir / "link.rs"
        dirty.write_text("use crate::index::FolderLink;\n", encoding="utf-8")
        found = repository_index_dependency_violations(repository_dir)
        assert any(
            "link.rs" in f for f in found
        ), "a repository file referencing crate::index must be flagged, no exceptions"

    # Check 3: storage/*.rs -> crate::index is a violation, except the one
    # documented rebootstrap_store exception.
    with tempfile.TemporaryDirectory() as directory:
        storage_dir = Path(directory)
        allowed = storage_dir / "schema.rs"
        allowed.write_text(
            "crate::index::rebootstrap_store::init_rebootstrap_schema(conn)?;\n", encoding="utf-8"
        )
        assert not storage_index_dependency_violations(
            storage_dir
        ), "the one documented rebootstrap_store exception must pass"
        allowed.unlink()

        disallowed = storage_dir / "schema.rs"
        disallowed.write_text(
            "crate::index::migrate_files_table_widen_primary_key(conn)?;\n", encoding="utf-8"
        )
        found = storage_index_dependency_violations(storage_dir)
        assert any(
            "schema.rs" in f for f in found
        ), "any other crate::index reference from storage/*.rs must be flagged"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("sync repository boundary self-test passed")
        return 0

    failures = violations(SYNC_CORE_SRC)
    failures += repository_index_dependency_violations(REPOSITORY_DIR)
    failures += storage_index_dependency_violations(STORAGE_DIR)
    if failures:
        print("sync repository boundary violations:")
        for failure in failures:
            print(f"- {failure.replace(str(ROOT) + '/', '')}")
        return 1

    print("sync repository boundary check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

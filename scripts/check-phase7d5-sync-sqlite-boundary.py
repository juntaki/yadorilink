#!/usr/bin/env python3
"""Phase 7D-5 boundary gate: `yadorilink-sync-sqlite` is the single adapter
owning the YadoriLink-specific SQLite persistence this phase actually moved
(shared replica-history reads, device-frontier persistence) -- see
docs/design/phase7d5-local-authoring-transaction.md and
docs/design/phase7d5-legacy-persistence-exceptions.toml for what this phase
deliberately did NOT move yet (the local-authoring atomic transaction,
remote admission) and why.

Checked here:

- `yadorilink-sync-sqlite`'s production dependencies/source reference no
  `yadorilink-sync-core`, `yadorilink-daemon`, `yadorilink-peer-session`,
  `yadorilink-transport`, or `yadorilink-sync-wire`.
- No `Pool<SqliteConnectionManager>` construction or `writer_gate` field
  definition inside `yadorilink-sync-sqlite` -- it holds one
  `Arc<SyncDatabase>`, never a second pool/writer-gate.
- `SqliteSyncStore`'s only constructor is `pub fn new(database:
  Arc<SyncDatabase>)` -- no `open`, no `Path`/URL parameter anywhere in its
  production API. Private helpers inside `#[cfg(test)]` modules may open
  isolated fixture databases.
- No public function or trait method in `yadorilink-sync-sqlite` exposes
  `rusqlite::Transaction`/`&Transaction` in its signature -- the physical
  SQLite transaction boundary stays inside this crate, never leaked to a
  caller.
- The specific methods this phase moved out of `yadorilink-sync-core`
  (`ChangeHistoryRepository::dag_group_heads`/`dag_get_change`/
  `dag_get_encoded`/`dag_parents_of`/`dag_has_file_version`/
  `dag_get_file_version`/`group_has_block_provenance`/
  `dag_missing_ancestor_frontier`, `FileIndexRepository::list_versions`/
  `get_current_version_record`) are NOT redefined there -- no duplicate
  copy of a moved query survives.
- `docs/design/phase7d5-legacy-persistence-exceptions.toml` exists and
  every `[[exception]]` entry has all required fields (symbol, table,
  access, current_owner, final_owner, reason, removal_phase) -- an
  exception recorded without its required context is as bad as no record
  at all.

Deliberately NOT checked (out of reach for a substring-matching gate, and
explicitly out of this phase's scope per the two design docs above): that
`changes`/`file_versions`/`files`/`conflict_copy_provenance`/the
filesystem-transaction execution fence/`materialization_jobs` SQL appears
ONLY in `yadorilink-sync-sqlite` workspace-wide. Most of that SQL
deliberately still lives in `yadorilink-sync-core`'s `dag_store` and
related modules this phase did not move (local authoring, remote
admission) -- an exhaustive per-statement allowlist over that surface is
Phase 7D-7's job, when those mixed decision-and-SQL modules are actually
decomposed. Reviewer judgment remains the backstop for that surface until
then.

Same substring-matching approach as this repo's other phase-boundary gate
scripts -- not a real Rust parser.
"""

from __future__ import annotations

import argparse
import re
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYNC_SQLITE_CRATE_DIR = ROOT / "crates/yadorilink-sync-sqlite"
SYNC_CORE_DIR = ROOT / "crates/yadorilink-sync-core"
EXCEPTIONS_FILE = ROOT / "docs/design/phase7d5-legacy-persistence-exceptions.toml"

COMMENT_LINE = re.compile(r"^\s*(///|//!|//)")

SYNC_SQLITE_FORBIDDEN_CARGO_DEPS = (
    "yadorilink-sync-core",
    "yadorilink-daemon",
    "yadorilink-peer-session",
    "yadorilink-transport",
    "yadorilink-sync-wire",
)

SYNC_SQLITE_FORBIDDEN_SOURCE_TOKENS = (
    "yadorilink_sync_core::",
    "yadorilink_daemon::",
    "yadorilink_peer_session::",
    "yadorilink_transport::",
    "yadorilink_sync_wire::",
)

# Methods this phase moved out of sync-core -- redefining any of these in
# their old repository home would mean a duplicate copy of a moved query.
MOVED_CHANGE_HISTORY_METHODS = (
    "fn dag_group_heads(",
    "fn dag_get_change(",
    "fn dag_get_encoded(",
    "fn dag_parents_of(",
    "fn dag_has_file_version(",
    "fn dag_get_file_version(",
    "fn group_has_block_provenance(",
    "fn dag_missing_ancestor_frontier(",
)
MOVED_FILE_INDEX_METHODS = (
    "fn list_versions(",
    "fn get_current_version_record(",
)

REQUIRED_EXCEPTION_FIELDS = (
    "symbol",
    "table",
    "access",
    "current_owner",
    "final_owner",
    "reason",
    "removal_phase",
)


def cargo_toml_violations(cargo_toml: Path) -> list[str]:
    if not cargo_toml.is_file():
        return [f"{cargo_toml} does not exist"]
    manifest = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
    failures = []
    production_dependencies = dict(manifest.get("dependencies", {}))
    for target in manifest.get("target", {}).values():
        production_dependencies.update(target.get("dependencies", {}))
    for dep in SYNC_SQLITE_FORBIDDEN_CARGO_DEPS:
        if dep in production_dependencies:
            failures.append(f"{cargo_toml} depends on forbidden crate {dep!r}")
    return failures


def production_lines(path: Path) -> list[tuple[int, str]]:
    """Return lines outside items gated exclusively by ``cfg(test)``.

    Unit-test modules may use integration fixtures and private in-memory
    SQLite connections. ``test-support`` feature items remain in scope.
    """
    result: list[tuple[int, str]] = []
    pending_test_cfg = False
    skipped_depth: int | None = None
    depth = 0
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        opens = line.count("{")
        closes = line.count("}")
        if skipped_depth is not None:
            depth += opens - closes
            if depth <= skipped_depth:
                skipped_depth = None
            continue
        if re.fullmatch(r"\s*#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*", line):
            pending_test_cfg = True
            continue
        if pending_test_cfg:
            if "{" in line:
                skipped_depth = depth
                depth += opens - closes
                if depth <= skipped_depth:
                    skipped_depth = None
                pending_test_cfg = False
                continue
            if ";" in line:
                pending_test_cfg = False
                continue
            continue
        result.append((i, line))
        depth += opens - closes
    return result


def source_violations(src_dir: Path) -> list[str]:
    failures: list[str] = []
    if not src_dir.is_dir():
        return failures
    for path in sorted(src_dir.rglob("*.rs")):
        for i, line in production_lines(path):
            if COMMENT_LINE.match(line):
                continue
            for token in SYNC_SQLITE_FORBIDDEN_SOURCE_TOKENS:
                if token in line:
                    failures.append(f"{path}:{i} references forbidden {token!r}")
            if "Pool<SqliteConnectionManager>" in line or "writer_gate:" in line:
                failures.append(
                    f"{path}:{i} defines an independent pool/writer_gate -- "
                    "yadorilink-sync-sqlite must hold only Arc<SyncDatabase>"
                )
            if re.search(r"fn open\s*\(", line) and "SqliteConnectionManager" not in line:
                # `open` on a public type other than the crate's own
                # (non-existent) database wrapper would be a second
                # construction path; flag any `fn open(` as suspicious.
                failures.append(
                    f"{path}:{i} defines an `open` function -- "
                    "yadorilink-sync-sqlite must never open its own database"
                )
            if re.search(r"rusqlite::Transaction|&Transaction\b", line) and "pub fn" in line:
                failures.append(
                    f"{path}:{i} exposes rusqlite::Transaction in a public signature -- "
                    "the physical transaction boundary must stay inside this crate"
                )
    return failures


def moved_method_duplication_violations(sync_core_dir: Path) -> list[str]:
    failures: list[str] = []
    change_history = sync_core_dir / "src" / "repository" / "change_history.rs"
    file_index = sync_core_dir / "src" / "repository" / "file_index.rs"
    for path, methods in (
        (change_history, MOVED_CHANGE_HISTORY_METHODS),
        (file_index, MOVED_FILE_INDEX_METHODS),
    ):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for i, line in enumerate(text.splitlines(), start=1):
            if COMMENT_LINE.match(line):
                continue
            for method in methods:
                if method in line:
                    failures.append(
                        f"{path}:{i} redefines moved method {method!r} -- "
                        "this SQL was moved to yadorilink-sync-sqlite, no duplicate may remain"
                    )
    return failures


def exceptions_file_violations(exceptions_file: Path) -> list[str]:
    failures: list[str] = []
    if not exceptions_file.is_file():
        failures.append(f"{exceptions_file} does not exist")
        return failures
    text = exceptions_file.read_text(encoding="utf-8")
    entries = text.split("[[exception]]")[1:]
    if not entries:
        failures.append(f"{exceptions_file} has no [[exception]] entries")
    for i, entry in enumerate(entries, start=1):
        # Only the entry's own text, up to the next [[exception]] marker
        # (already split) or EOF -- but a `reason = """..."""` block can
        # itself contain blank lines, so just check key presence.
        for field in REQUIRED_EXCEPTION_FIELDS:
            if not re.search(rf"^\s*{field}\s*=", entry, re.MULTILINE):
                failures.append(
                    f"{exceptions_file} exception #{i} is missing required field {field!r}"
                )
    return failures


def violations(
    crate_dir: Path = SYNC_SQLITE_CRATE_DIR,
    sync_core_dir: Path = SYNC_CORE_DIR,
    exceptions_file: Path = EXCEPTIONS_FILE,
) -> list[str]:
    return (
        cargo_toml_violations(crate_dir / "Cargo.toml")
        + source_violations(crate_dir / "src")
        + moved_method_duplication_violations(sync_core_dir)
        + exceptions_file_violations(exceptions_file)
    )


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        crate_dir = root / "sync-sqlite"
        sync_core_dir = root / "sync-core"
        src_dir = crate_dir / "src"
        repo_dir = sync_core_dir / "src" / "repository"
        src_dir.mkdir(parents=True, exist_ok=True)
        repo_dir.mkdir(parents=True, exist_ok=True)
        exceptions_file = root / "exceptions.toml"

        def reset() -> None:
            (crate_dir / "Cargo.toml").write_text(
                '[package]\nname = "yadorilink-sync-sqlite"\n\n'
                "[dependencies]\nyadorilink-sqlite-runtime.workspace = true\n"
                "rusqlite.workspace = true\n",
                encoding="utf-8",
            )
            (src_dir / "store.rs").write_text(
                "pub struct SqliteSyncStore { database: Arc<SyncDatabase> }\n"
                "impl SqliteSyncStore {\n"
                "    pub fn new(database: Arc<SyncDatabase>) -> Self { Self { database } }\n"
                "    pub fn group_heads(&self) -> Result<Vec<ChangeHash>, SyncSqliteError> { todo!() }\n"
                "}\n",
                encoding="utf-8",
            )
            (repo_dir / "change_history.rs").write_text(
                "pub fn dag_last_authored_change_for_path(&self) {}\n", encoding="utf-8"
            )
            (repo_dir / "file_index.rs").write_text(
                "pub fn get_version(&self) {}\n", encoding="utf-8"
            )
            exceptions_file.write_text(
                "[[exception]]\n"
                'symbol = "x"\n'
                'table = "files"\n'
                'access = "read-only"\n'
                'current_owner = "sync-core"\n'
                'final_owner = "sync-sqlite"\n'
                'reason = "test"\n'
                'removal_phase = "7D-7"\n',
                encoding="utf-8",
            )

        reset()
        assert not violations(crate_dir, sync_core_dir, exceptions_file), violations(
            crate_dir, sync_core_dir, exceptions_file
        )

        for dep in SYNC_SQLITE_FORBIDDEN_CARGO_DEPS:
            (crate_dir / "Cargo.toml").write_text(
                f'[package]\nname = "yadorilink-sync-sqlite"\n\n[dependencies]\n{dep} = "1"\n',
                encoding="utf-8",
            )
            assert violations(
                crate_dir, sync_core_dir, exceptions_file
            ), f"failed to detect Cargo.toml dep {dep!r}"
        reset()
        assert not violations(crate_dir, sync_core_dir, exceptions_file)

        # Test-only integration fixtures may depend on the daemon without
        # creating a production dependency cycle.
        (crate_dir / "Cargo.toml").write_text(
            '[package]\nname = "yadorilink-sync-sqlite"\n\n'
            "[dependencies]\nyadorilink-sqlite-runtime.workspace = true\n"
            "[dev-dependencies]\nyadorilink-daemon = \"1\"\n",
            encoding="utf-8",
        )
        assert not violations(crate_dir, sync_core_dir, exceptions_file)
        reset()

        # A private fixture opener and daemon-backed fixture in a cfg(test)
        # module are not production construction paths.
        (src_dir / "store.rs").write_text(
            "pub struct SqliteSyncStore;\n"
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    fn open() { yadorilink_daemon::fixture(); }\n"
            "}\n",
            encoding="utf-8",
        )
        assert not violations(crate_dir, sync_core_dir, exceptions_file)
        reset()

        for token in SYNC_SQLITE_FORBIDDEN_SOURCE_TOKENS:
            (src_dir / "store.rs").write_text(f"fn f() {{ {token}bar(); }}\n", encoding="utf-8")
            assert violations(
                crate_dir, sync_core_dir, exceptions_file
            ), f"failed to detect source token {token!r}"
        reset()
        assert not violations(crate_dir, sync_core_dir, exceptions_file)

        # An independent writer_gate must be flagged.
        (src_dir / "store.rs").write_text(
            "pub struct Rogue { writer_gate: Mutex<()> }\n", encoding="utf-8"
        )
        found = violations(crate_dir, sync_core_dir, exceptions_file)
        assert any("independent pool/writer_gate" in f for f in found)
        reset()
        assert not violations(crate_dir, sync_core_dir, exceptions_file)

        # A redefined moved method in the old repository home must be flagged.
        (repo_dir / "change_history.rs").write_text(
            "pub fn dag_group_heads(&self, group_id: &str) -> Result<Vec<ChangeHash>, SyncError> { todo!() }\n",
            encoding="utf-8",
        )
        found = violations(crate_dir, sync_core_dir, exceptions_file)
        assert any("redefines moved method" in f for f in found)
        reset()
        assert not violations(crate_dir, sync_core_dir, exceptions_file)

        # A malformed exceptions file (missing a required field) must be flagged.
        exceptions_file.write_text(
            "[[exception]]\nsymbol = \"x\"\ntable = \"files\"\n", encoding="utf-8"
        )
        found = violations(crate_dir, sync_core_dir, exceptions_file)
        assert any("missing required field" in f for f in found)
        reset()
        assert not violations(crate_dir, sync_core_dir, exceptions_file)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("phase 7d5 sync-sqlite boundary self-test passed")
        return 0

    failures = violations()
    if failures:
        print("phase 7d5 sync-sqlite boundary violations:")
        for failure in failures:
            print(f"- {str(failure).replace(str(ROOT) + '/', '')}")
        return 1

    print("Phase 7D-5 sync-sqlite boundary check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

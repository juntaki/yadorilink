#!/usr/bin/env python3
"""Phase 7D-4 boundary gate: `yadorilink-sqlite-runtime` owns exactly the
connection pool, the in-process writer gate, connection init/PRAGMA
settings, the `read`/`write`/`write_immediate` transaction helpers, and the
core schema-bootstrap/migration DDL for the shared SQLite database file --
nothing else. `yadorilink-sync-core` (and every future SQLite-backed crate)
reaches all of that through exactly one shared `Arc<SyncDatabase>`, built at
exactly one production call site, never through a second pool/writer-gate of
its own.

Checked here:

- `yadorilink-sqlite-runtime`'s `Cargo.toml` names no dependency on
  `yadorilink-sync-core`, `yadorilink-replica-domain`,
  `yadorilink-replica-engine`, or `yadorilink-sync-wire` -- the runtime must
  know nothing about domain concepts, replica policy, or wire framing.
- `Pool<SqliteConnectionManager>` construction and `writer_gate` field
  definitions appear only inside `yadorilink-sqlite-runtime`'s own source,
  never in `yadorilink-sync-core`.
- `yadorilink-sync-core` no longer references `r2d2_sqlite::` directly, and
  its old `storage/database.rs`/`storage/sync_database.rs` files (and any
  `pub use yadorilink_sqlite_runtime::SyncDatabase;` compatibility
  re-export) are gone.
- Exactly one production call site (`crates/yadorilink-sync-core/src/index.rs`)
  calls `SyncDatabase::open`/`SyncDatabase::open_in_memory` -- every other
  `.rs` file in the workspace (test fixtures aside) is forbidden from
  calling either directly.
- No `crate::repository::*` constructor (`fn new`) takes a `Path`/database
  URL parameter -- every repository is handed an already-open
  `Arc<SyncDatabase>`, never allowed to open its own.
- `yadorilink-sqlite-runtime`'s own source never names a domain-specific
  schema concept (`pre_dag_schema`/`post_dag_schema`/`dag_store`/
  `filesystem_transaction`/`materialization_jobs`) -- `SyncDatabase::open`/
  `open_in_memory` take exactly one opaque `schema_init` closure, sequenced
  entirely by the caller (the composition root in
  `yadorilink-sync-core/src/index.rs`).

Same substring-matching approach as this repo's other phase-boundary gate
scripts -- not a real Rust parser. Reviewer judgment remains the backstop.
"""

from __future__ import annotations

import argparse
import re
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_CRATE_DIR = ROOT / "crates/yadorilink-sqlite-runtime"
SYNC_CORE_DIR = ROOT / "crates/yadorilink-sync-core"

COMMENT_LINE = re.compile(r"^\s*(///|//!|//)")

RUNTIME_FORBIDDEN_CARGO_DEPS = (
    "yadorilink-sync-core",
    "yadorilink-replica-domain",
    "yadorilink-replica-engine",
    "yadorilink-sync-wire",
)

RUNTIME_FORBIDDEN_SOURCE_TOKENS = (
    "yadorilink_sync_core::",
    "yadorilink_replica_domain::",
    "yadorilink_replica_engine::",
    "yadorilink_sync_wire::",
)

SYNC_CORE_FORBIDDEN_TOKENS = (
    "r2d2_sqlite::",
    "Pool<SqliteConnectionManager>",
    "writer_gate:",
    "pub use yadorilink_sqlite_runtime::SyncDatabase;",
)

# `SyncDatabase::open`/`open_in_memory` take exactly one caller-supplied
# `schema_init` closure and never sequence, name, or know about any
# domain-specific schema piece -- these tokens must never appear in this
# crate's own source (comments aside): if they do, some domain-specific
# ordering concept has leaked back into the crate that must stay ignorant
# of it (Phase 7D-5's own rescope from a two-named-hook `SchemaHooks`
# struct to a single opaque closure exists specifically to close this).
RUNTIME_FORBIDDEN_SCHEMA_NAME_TOKENS = (
    "pre_dag_schema",
    "post_dag_schema",
    "dag_store",
    "filesystem_transaction",
    "materialization_jobs",
)


def cargo_toml_violations(cargo_toml: Path) -> list[str]:
    if not cargo_toml.is_file():
        return [f"{cargo_toml} does not exist"]
    text = cargo_toml.read_text(encoding="utf-8")
    failures = []
    for dep in RUNTIME_FORBIDDEN_CARGO_DEPS:
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(f"{dep} ") or stripped.startswith(f"{dep}="):
                failures.append(f"{cargo_toml} depends on forbidden crate {dep!r}")
    return failures


def runtime_source_violations(src_dir: Path) -> list[str]:
    failures: list[str] = []
    if not src_dir.is_dir():
        return failures
    for path in sorted(src_dir.rglob("*.rs")):
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if COMMENT_LINE.match(line):
                continue
            for token in RUNTIME_FORBIDDEN_SOURCE_TOKENS:
                if token in line:
                    failures.append(f"{path}:{i} references forbidden {token!r}")
    return failures


def sync_core_ownership_violations(sync_core_dir: Path) -> list[str]:
    """`yadorilink-sync-core` must no longer own a pool, a writer_gate, or a
    direct `r2d2_sqlite` reference -- and must carry no compatibility
    re-export of `SyncDatabase`."""
    failures: list[str] = []
    src_dir = sync_core_dir / "src"
    if not src_dir.is_dir():
        return failures
    for path in sorted(src_dir.rglob("*.rs")):
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if COMMENT_LINE.match(line):
                continue
            for token in SYNC_CORE_FORBIDDEN_TOKENS:
                if token in line:
                    failures.append(f"{path}:{i} still references {token!r}")
    for stale in ("storage/database.rs", "storage/sync_database.rs"):
        stale_path = src_dir / stale
        if stale_path.exists():
            failures.append(
                f"{stale_path} still exists -- pool/writer-gate ownership must live only "
                "in yadorilink-sqlite-runtime"
            )
    return failures


def single_open_call_site_violations(sync_core_dir: Path) -> list[str]:
    """Exactly one production call site may construct a `SyncDatabase` --
    every repository/consumer must be handed an already-open
    `Arc<SyncDatabase>` instead."""
    failures: list[str] = []
    src_dir = sync_core_dir / "src"
    if not src_dir.is_dir():
        return failures
    allowed = src_dir / "index.rs"
    call = re.compile(r"SyncDatabase::open(_in_memory)?\(")
    for path in sorted(src_dir.rglob("*.rs")):
        if path == allowed:
            continue
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if COMMENT_LINE.match(line):
                continue
            if call.search(line):
                failures.append(
                    f"{path}:{i} calls SyncDatabase::open/open_in_memory -- only "
                    f"{allowed.relative_to(sync_core_dir.parent.parent)} may construct one"
                )
    return failures


def repository_constructor_violations(sync_core_dir: Path) -> list[str]:
    """No `crate::repository::*` constructor may take a `Path`/URL -- every
    repository must be constructed from an already-open `Arc<SyncDatabase>`,
    never allowed to open its own."""
    failures: list[str] = []
    repo_dir = sync_core_dir / "src" / "repository"
    if not repo_dir.is_dir():
        return failures
    ctor = re.compile(r"pub\(crate\) fn new\(")
    forbidden_param_tokens = ("impl AsRef<Path>", ": &Path", ": PathBuf", "db_url", "database_url")
    for path in sorted(repo_dir.rglob("*.rs")):
        lines = path.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines, start=1):
            if COMMENT_LINE.match(line):
                continue
            if ctor.search(line):
                # Constructor signatures in this codebase are one line;
                # check the same line and, defensively, the next for a
                # wrapped parameter list.
                window = line + (lines[i] if i < len(lines) else "")
                for token in forbidden_param_tokens:
                    if token in window:
                        failures.append(
                            f"{path}:{i} repository constructor takes {token!r} -- must take "
                            "only Arc<SyncDatabase>"
                        )
    return failures


def schema_name_leak_violations(runtime_src: Path) -> list[str]:
    """`yadorilink-sqlite-runtime`'s own source must never name a
    domain-specific schema concept -- it takes exactly one opaque
    `schema_init` closure from its caller and sequences nothing itself."""
    failures: list[str] = []
    if not runtime_src.is_dir():
        return failures
    for path in sorted(runtime_src.rglob("*.rs")):
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if COMMENT_LINE.match(line):
                continue
            for token in RUNTIME_FORBIDDEN_SCHEMA_NAME_TOKENS:
                if token in line:
                    failures.append(f"{path}:{i} references forbidden domain-specific name {token!r}")
    return failures


def violations(
    runtime_dir: Path = RUNTIME_CRATE_DIR, sync_core_dir: Path = SYNC_CORE_DIR
) -> list[str]:
    return (
        cargo_toml_violations(runtime_dir / "Cargo.toml")
        + runtime_source_violations(runtime_dir / "src")
        + sync_core_ownership_violations(sync_core_dir)
        + single_open_call_site_violations(sync_core_dir)
        + repository_constructor_violations(sync_core_dir)
        + schema_name_leak_violations(runtime_dir / "src")
    )


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        runtime_dir = root / "sqlite-runtime"
        sync_core_dir = root / "sync-core"
        runtime_src = runtime_dir / "src"
        sync_core_src = sync_core_dir / "src"
        repo_dir = sync_core_src / "repository"
        runtime_src.mkdir(parents=True, exist_ok=True)
        repo_dir.mkdir(parents=True, exist_ok=True)
        (sync_core_src / "storage").mkdir(parents=True, exist_ok=True)

        def reset() -> None:
            (runtime_dir / "Cargo.toml").write_text(
                '[package]\nname = "yadorilink-sqlite-runtime"\n\n'
                "[dependencies]\nrusqlite.workspace = true\nr2d2.workspace = true\n"
                "r2d2_sqlite.workspace = true\nthiserror.workspace = true\n",
                encoding="utf-8",
            )
            (runtime_src / "database.rs").write_text(
                "pub struct SyncDatabase { pool: ConnectionPool, writer_gate: Mutex<()> }\n"
                "impl SyncDatabase {\n"
                "    pub fn open(path: impl AsRef<Path>, schema_init: impl FnOnce(&Connection) "
                "-> Result<(), DatabaseError>) -> Result<Self, DatabaseError> { todo!() }\n"
                "}\n",
                encoding="utf-8",
            )
            (runtime_src / "schema.rs").write_text(
                "pub fn init_schema(conn: &Connection) -> Result<(), DatabaseError> { Ok(()) }\n",
                encoding="utf-8",
            )
            (sync_core_src / "index.rs").write_text(
                "let database = Arc::new(SyncDatabase::open(path, schema_init).map_err(SyncError::from)?);\n",
                encoding="utf-8",
            )
            (sync_core_src / "storage" / "schema.rs").write_text(
                "pub(crate) fn pre_dag_schema(conn: &Connection) -> Result<(), DatabaseError> { Ok(()) }\n"
                "pub(crate) fn post_dag_schema(conn: &Connection) -> Result<(), DatabaseError> { Ok(()) }\n",
                encoding="utf-8",
            )
            (repo_dir / "link.rs").write_text(
                "pub(crate) fn new(database: Arc<SyncDatabase>) -> Self { Self { database } }\n",
                encoding="utf-8",
            )

        reset()
        assert not violations(runtime_dir, sync_core_dir), violations(runtime_dir, sync_core_dir)

        for dep in RUNTIME_FORBIDDEN_CARGO_DEPS:
            (runtime_dir / "Cargo.toml").write_text(
                f'[package]\nname = "yadorilink-sqlite-runtime"\n\n[dependencies]\n{dep} = "1"\n',
                encoding="utf-8",
            )
            assert violations(runtime_dir, sync_core_dir), f"failed to detect Cargo.toml dep {dep!r}"
        reset()
        assert not violations(runtime_dir, sync_core_dir)

        for token in RUNTIME_FORBIDDEN_SOURCE_TOKENS:
            (runtime_src / "database.rs").write_text(f"fn f() {{ {token}bar(); }}\n", encoding="utf-8")
            assert violations(runtime_dir, sync_core_dir), f"failed to detect runtime source token {token!r}"
        reset()
        assert not violations(runtime_dir, sync_core_dir)

        for token in SYNC_CORE_FORBIDDEN_TOKENS:
            (sync_core_src / "leak.rs").write_text(f"// marker\n{token} thing\n", encoding="utf-8")
            found = violations(runtime_dir, sync_core_dir)
            assert found, f"failed to detect sync-core token {token!r}"
            (sync_core_src / "leak.rs").unlink()
        assert not violations(runtime_dir, sync_core_dir)

        # A stale storage/database.rs must be flagged.
        (sync_core_src / "storage" / "database.rs").write_text("// stale\n", encoding="utf-8")
        found = violations(runtime_dir, sync_core_dir)
        assert any("still exists" in f for f in found)
        (sync_core_src / "storage" / "database.rs").unlink()
        assert not violations(runtime_dir, sync_core_dir)

        # A second production open() call site must be flagged.
        (sync_core_src / "rogue.rs").write_text(
            "let extra = SyncDatabase::open(path, schema_init)?;\n", encoding="utf-8"
        )
        found = violations(runtime_dir, sync_core_dir)
        assert any("only" in f and "may construct one" in f for f in found)
        (sync_core_src / "rogue.rs").unlink()
        assert not violations(runtime_dir, sync_core_dir)

        # A repository constructor taking a Path must be flagged.
        (repo_dir / "link.rs").write_text(
            "pub(crate) fn new(path: impl AsRef<Path>) -> Self { todo!() }\n", encoding="utf-8"
        )
        found = violations(runtime_dir, sync_core_dir)
        assert any("repository constructor takes" in f for f in found)
        reset()
        assert not violations(runtime_dir, sync_core_dir)

        # A domain-specific schema name leaking into the runtime crate's own
        # source must be flagged.
        for token in RUNTIME_FORBIDDEN_SCHEMA_NAME_TOKENS:
            (runtime_src / "database.rs").write_text(f"fn f() {{ {token}(); }}\n", encoding="utf-8")
            found = violations(runtime_dir, sync_core_dir)
            assert found, f"failed to detect domain-specific schema name {token!r}"
        reset()
        assert not violations(runtime_dir, sync_core_dir)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("phase 7d4 sqlite-runtime boundary self-test passed")
        return 0

    failures = violations()
    if failures:
        print("phase 7d4 sqlite-runtime boundary violations:")
        for failure in failures:
            print(f"- {str(failure).replace(str(ROOT) + '/', '')}")
        return 1

    print("Phase 7D-4 sqlite-runtime boundary check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

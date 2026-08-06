#!/usr/bin/env python3
"""Phase 7D-3 boundary gate: `yadorilink-replica-engine` stays a pure,
synchronous, dependency-free policy crate -- DAG admission, causal
authorization, custody/durability evidence checks, and deterministic
conflict-repair election, with nothing beneath it but
`yadorilink-replica-domain`, `thiserror`, and `sha2`.

Checked here:

- `Cargo.toml` names no forbidden dependency (async runtime, database,
  wire/protobuf, filesystem/transport crate, `tracing`, or
  `yadorilink-sync-core` itself).
- No source file references a forbidden crate path, `std::fs`, `std::net`,
  or `tracing::`.
- `yadorilink-sync-core` no longer defines `PeerReplicaEngine`,
  `change_ops`, `authenticated_history`'s pure trait/algorithm, `custody`'s
  verifier, or `repair_election` locally, and carries no compatibility
  re-export of any of them.

Same substring-matching approach as this repo's other phase-boundary gate
scripts -- not a real Rust parser. Reviewer judgment remains the backstop.
"""

from __future__ import annotations

import argparse
import re
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CRATE_DIR = ROOT / "crates/yadorilink-replica-engine"
SYNC_CORE_SRC = ROOT / "crates/yadorilink-sync-core/src"

COMMENT_LINE = re.compile(r"^\s*(///|//!|//)")

FORBIDDEN_CARGO_DEPS = (
    "tokio",
    "async-trait",
    "rusqlite",
    "r2d2",
    "r2d2_sqlite",
    "prost",
    "yadorilink-ipc-proto",
    "yadorilink-local-storage",
    "yadorilink-transport",
    "yadorilink-sync-core",
    "yadorilink-sync-wire",
    "notify",
    "fs2",
    "walkdir",
    "fastcdc",
    "tracing",
)

FORBIDDEN_SOURCE_TOKENS = (
    "tokio::",
    "async_trait::",
    "rusqlite::",
    "r2d2::",
    "r2d2_sqlite::",
    "prost::",
    "yadorilink_ipc_proto::",
    "yadorilink_local_storage::",
    "yadorilink_transport::",
    "yadorilink_sync_core::",
    "yadorilink_sync_wire::",
    "notify::",
    "fs2::",
    "walkdir::",
    "fastcdc::",
    "tracing::",
    "std::fs",
    "std::net",
)


def cargo_toml_violations(cargo_toml: Path) -> list[str]:
    if not cargo_toml.is_file():
        return [f"{cargo_toml} does not exist"]
    text = cargo_toml.read_text(encoding="utf-8")
    failures = []
    for dep in FORBIDDEN_CARGO_DEPS:
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(f"{dep} ") or stripped.startswith(f"{dep}="):
                failures.append(f"{cargo_toml} depends on forbidden crate {dep!r}")
    return failures


def source_violations(src_dir: Path) -> list[str]:
    failures: list[str] = []
    if not src_dir.is_dir():
        return failures
    for path in sorted(src_dir.rglob("*.rs")):
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if COMMENT_LINE.match(line):
                continue
            for token in FORBIDDEN_SOURCE_TOKENS:
                if token in line:
                    failures.append(f"{path}:{i} references forbidden {token!r}")
    return failures


def sync_core_moved_definition_violations(sync_core_src: Path) -> list[str]:
    """Every symbol Phase 7D-3 moved must have zero remaining definition
    or compatibility re-export in yadorilink-sync-core."""
    failures: list[str] = []
    if not sync_core_src.is_dir():
        return failures
    # Deliberately excludes generically-named functions (`op_version_hash`,
    # `collect_op_paths`, `validate_retained_group`) -- this repo has
    # unrelated local helpers that coincidentally share those names (see
    # dag_store/retention_roots.rs's own `op_version_hash`, a distinct
    # by-reference variant), so a bare `fn <name>` substring produces false
    # positives. `mod change_ops`/`mod repair_election` plus the
    # module-qualified re-export check already catch the real violation.
    forbidden_defs = (
        "struct PeerReplicaEngine",
        "mod change_ops",
        "mod repair_election",
        "struct CustodyVerifier",
        "struct VerifiedCustody",
    )
    forbidden_reexports = (
        "pub use yadorilink_replica_engine::",
    )
    for path in sorted(sync_core_src.rglob("*.rs")):
        text = path.read_text(encoding="utf-8")
        for i, line in enumerate(text.splitlines(), start=1):
            if COMMENT_LINE.match(line):
                continue
            for token in forbidden_defs + forbidden_reexports:
                if token in line:
                    failures.append(f"{path}:{i} still references moved symbol {token!r}")
    if (sync_core_src / "peer_replica_engine.rs").exists():
        failures.append(
            f"{sync_core_src / 'peer_replica_engine.rs'} still exists -- PeerReplicaEngine "
            "must live only in yadorilink-replica-engine"
        )
    return failures


def violations(
    crate_dir: Path = CRATE_DIR, sync_core_src: Path = SYNC_CORE_SRC
) -> list[str]:
    return (
        cargo_toml_violations(crate_dir / "Cargo.toml")
        + source_violations(crate_dir / "src")
        + sync_core_moved_definition_violations(sync_core_src)
    )


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        crate_dir = root / "replica-engine"
        sync_core_src = root / "sync-core-src"
        src_dir = crate_dir / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        sync_core_src.mkdir(parents=True, exist_ok=True)

        (crate_dir / "Cargo.toml").write_text(
            '[package]\nname = "yadorilink-replica-engine"\n\n'
            "[dependencies]\nyadorilink-replica-domain.workspace = true\n"
            "thiserror.workspace = true\nsha2.workspace = true\n",
            encoding="utf-8",
        )
        (src_dir / "lib.rs").write_text("pub struct PeerReplicaEngine;\n", encoding="utf-8")
        (sync_core_src / "peer_session.rs").write_text(
            "use yadorilink_replica_engine::ports::ReplicaHistoryPort;\n", encoding="utf-8"
        )
        assert not violations(crate_dir, sync_core_src), violations(crate_dir, sync_core_src)

        for dep in FORBIDDEN_CARGO_DEPS:
            (crate_dir / "Cargo.toml").write_text(
                f'[package]\nname = "yadorilink-replica-engine"\n\n[dependencies]\n{dep} = "1"\n',
                encoding="utf-8",
            )
            assert violations(crate_dir, sync_core_src), f"failed to detect Cargo.toml dep {dep!r}"
        (crate_dir / "Cargo.toml").write_text(
            '[package]\nname = "yadorilink-replica-engine"\n\n'
            "[dependencies]\nyadorilink-replica-domain.workspace = true\n"
            "thiserror.workspace = true\nsha2.workspace = true\n",
            encoding="utf-8",
        )
        assert not violations(crate_dir, sync_core_src)

        for token in FORBIDDEN_SOURCE_TOKENS:
            (src_dir / "lib.rs").write_text(f"fn f() {{ {token}bar(); }}\n", encoding="utf-8")
            assert violations(crate_dir, sync_core_src), f"failed to detect source token {token!r}"
        (src_dir / "lib.rs").write_text("pub struct PeerReplicaEngine;\n", encoding="utf-8")
        assert not violations(crate_dir, sync_core_src)

        # A moved symbol still defined in sync-core must be flagged.
        (sync_core_src / "peer_replica_engine.rs").write_text(
            "pub struct PeerReplicaEngine;\n", encoding="utf-8"
        )
        found = violations(crate_dir, sync_core_src)
        assert any("still exists" in f for f in found)
        (sync_core_src / "peer_replica_engine.rs").unlink()
        assert not violations(crate_dir, sync_core_src)

        # A compatibility re-export must be flagged.
        (sync_core_src / "lib.rs").write_text(
            "pub use yadorilink_replica_engine::ports::ReplicaHistoryPort;\n", encoding="utf-8"
        )
        found = violations(crate_dir, sync_core_src)
        assert any("moved symbol" in f for f in found)
        (sync_core_src / "lib.rs").unlink()
        assert not violations(crate_dir, sync_core_src)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("phase 7d3 replica-engine boundary self-test passed")
        return 0

    failures = violations()
    if failures:
        print("phase 7d3 replica-engine boundary violations:")
        for failure in failures:
            print(f"- {str(failure).replace(str(ROOT) + '/', '')}")
        return 1

    print("Phase 7D-3 replica-engine boundary check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Phase 7D-1 boundary gate: `yadorilink-replica-domain` stays a pure,
synchronous, dependency-free domain crate -- identities, file/version
records, the signed canonical `Change`, and deterministic conflict policy,
with nothing beneath it but the standard library and cryptography.

Checked here (7D-1.1's own minimal gate; extended across the phase as
content actually moves into the crate):

- `Cargo.toml` names no forbidden dependency (async runtime, database,
  wire/protobuf, or any other workspace crate).
- No source file references a forbidden crate path
  (`tokio::`, `async_trait::`, `rusqlite::`, `r2d2::`, `r2d2_sqlite::`,
  `prost::`, `yadorilink_ipc_proto::`, `yadorilink_local_storage::`,
  `yadorilink_transport::`, `yadorilink_sync_core::`, `notify::`,
  `fs2::`, `walkdir::`, `fastcdc::`).
- No source file touches `std::fs` or `std::net` directly.
- The crate has no dependency edge back onto `yadorilink-sync-core` (the
  crate this domain model is being extracted OUT of -- a dependency in
  that direction would silently recreate the cycle this phase exists to
  cut).

Same substring-matching approach as this repo's other phase-boundary gate
scripts (`check-phase7b-engine-boundary.py`,
`check-daemon-application-dependencies.py`) -- not a real Rust parser; a
deliberate `use tokio as t;`-style rename evades it, same limitation those
scripts document for themselves. Reviewer judgment remains the backstop.
"""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CRATE_DIR = ROOT / "crates/yadorilink-replica-domain"
CARGO_TOML = CRATE_DIR / "Cargo.toml"
SRC_DIR = CRATE_DIR / "src"

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
    "notify",
    "fs2",
    "walkdir",
    "fastcdc",
)

# Matched as `<crate>::` so a local identifier merely sharing a crate's
# name (unlikely, but same reasoning as the daemon application-dependency
# check's own trailing-`::` choice) is never a false positive.
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
    "notify::",
    "fs2::",
    "walkdir::",
    "fastcdc::",
    "std::fs",
    "std::net",
)


def cargo_toml_violations(cargo_toml: Path) -> list[str]:
    if not cargo_toml.is_file():
        return [f"{cargo_toml} does not exist"]
    text = cargo_toml.read_text(encoding="utf-8")
    failures = []
    for dep in FORBIDDEN_CARGO_DEPS:
        # A dependency line names the crate at the start of a line (bare
        # `name = "..."` or `name = { ... }`), never merely as a substring
        # of some longer, unrelated crate name -- anchor on that shape.
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
        text = path.read_text(encoding="utf-8")
        for token in FORBIDDEN_SOURCE_TOKENS:
            if token in text:
                failures.append(f"{path} references forbidden {token!r}")
    return failures


def violations(crate_dir: Path) -> list[str]:
    return cargo_toml_violations(crate_dir / "Cargo.toml") + source_violations(
        crate_dir / "src"
    )


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        crate_dir = Path(directory)
        cargo_toml = crate_dir / "Cargo.toml"
        src_dir = crate_dir / "src"
        src_dir.mkdir(parents=True, exist_ok=True)

        cargo_toml.write_text(
            '[package]\nname = "yadorilink-replica-domain"\n\n'
            "[dependencies]\nserde.workspace = true\n",
            encoding="utf-8",
        )
        (src_dir / "lib.rs").write_text("pub struct Change;\n", encoding="utf-8")
        assert not violations(crate_dir)

        for dep in FORBIDDEN_CARGO_DEPS:
            cargo_toml.write_text(
                f'[package]\nname = "yadorilink-replica-domain"\n\n'
                f"[dependencies]\n{dep} = \"1\"\n",
                encoding="utf-8",
            )
            assert violations(crate_dir), f"failed to detect Cargo.toml dep {dep!r}"

        cargo_toml.write_text(
            '[package]\nname = "yadorilink-replica-domain"\n\n'
            "[dependencies]\nserde.workspace = true\n",
            encoding="utf-8",
        )
        assert not violations(crate_dir)

        for token in FORBIDDEN_SOURCE_TOKENS:
            (src_dir / "lib.rs").write_text(f"fn f() {{ {token}bar(); }}\n", encoding="utf-8")
            assert violations(crate_dir), f"failed to detect source token {token!r}"

        (src_dir / "lib.rs").write_text("pub struct Change;\n", encoding="utf-8")
        assert not violations(crate_dir)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("phase 7d1 domain boundary self-test passed")
        return 0

    failures = violations(CRATE_DIR)
    if failures:
        print("phase 7d1 domain boundary violations:")
        for failure in failures:
            print(f"- {failure.replace(str(ROOT) + '/', '')}")
        return 1

    print("Phase 7D-1 domain boundary check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

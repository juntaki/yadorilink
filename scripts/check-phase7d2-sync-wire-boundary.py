#!/usr/bin/env python3
"""Phase 7D-2 boundary gate: `yadorilink-sync-wire` stays a standalone
peer wire codec/frame crate -- `prost`/`yadorilink-ipc-proto` and the
standard library only, no dependency on `yadorilink-sync-core`,
`yadorilink-replica-domain`, or any storage/transport/async-runtime crate.

Checked here:

- `Cargo.toml` names no forbidden dependency (async runtime, database,
  domain model, or `yadorilink-sync-core` itself -- a dependency in that
  direction would recreate the exact cycle Phase 7D-2 exists to cut).
- No source file references a forbidden crate path.
- The crate's public API never names a generated `yadorilink_ipc_proto`
  type outside its own internal `protobuf` module (that module is the one
  place this dependency is meant to live; `lib.rs`'s own re-export list
  and every other module must stay protobuf-free).
- `yadorilink-sync-core` has zero `crate::peer_wire::`,
  `yadorilink_sync_core::peer_wire::`, or `pub use yadorilink_sync_wire::`
  references anywhere -- the temporary compatibility alias Phase 7D-2.3
  added is fully migrated away and deleted (Phase 7D-2.5).

Same substring-matching approach as this repo's other phase-boundary gate
scripts -- not a real Rust parser. Reviewer judgment remains the backstop.
"""

from __future__ import annotations

import argparse
import re
import tempfile
from pathlib import Path

COMMENT_LINE = re.compile(r"^\s*(///|//!|//)")

ROOT = Path(__file__).resolve().parents[1]
CRATE_DIR = ROOT / "crates/yadorilink-sync-wire"
CARGO_TOML = CRATE_DIR / "Cargo.toml"
SRC_DIR = CRATE_DIR / "src"
SYNC_CORE_SRC = ROOT / "crates/yadorilink-sync-core/src"

FORBIDDEN_CARGO_DEPS = (
    "tokio",
    "async-trait",
    "rusqlite",
    "r2d2",
    "r2d2_sqlite",
    "yadorilink-local-storage",
    "yadorilink-transport",
    "yadorilink-replica-domain",
    "yadorilink-sync-core",
    "notify",
    "fs2",
    "walkdir",
    "fastcdc",
)

FORBIDDEN_SOURCE_TOKENS = (
    "tokio::",
    "async_trait::",
    "rusqlite::",
    "r2d2::",
    "r2d2_sqlite::",
    "yadorilink_local_storage::",
    "yadorilink_transport::",
    "yadorilink_replica_domain::",
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


def public_api_leak_violations(src_dir: Path) -> list[str]:
    """`lib.rs` (and any module other than `protobuf.rs`) must never name
    a generated `yadorilink_ipc_proto` type -- that dependency is confined
    to `protobuf.rs`, the crate's sole encode/decode implementation."""
    failures: list[str] = []
    if not src_dir.is_dir():
        return failures
    for path in sorted(src_dir.rglob("*.rs")):
        if path.name == "protobuf.rs":
            continue
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if COMMENT_LINE.match(line):
                continue
            for token in ("yadorilink_ipc_proto", "prost::"):
                if token in line:
                    failures.append(
                        f"{path}:{i} references {token!r} outside protobuf.rs -- the crate's "
                        "protobuf dependency must be confined to its own codec implementation"
                    )
    return failures


def sync_core_alias_violations(sync_core_src: Path) -> list[str]:
    """Zero crate::peer_wire::, yadorilink_sync_core::peer_wire::, or
    pub use yadorilink_sync_wire:: may remain in yadorilink-sync-core --
    the Phase 7D-2.3 compatibility alias was deleted in Phase 7D-2.5."""
    failures: list[str] = []
    if not sync_core_src.is_dir():
        return failures
    forbidden = ("crate::peer_wire::", "yadorilink_sync_core::peer_wire::", "pub use yadorilink_sync_wire::")
    for path in sorted(sync_core_src.rglob("*.rs")):
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            if token in text:
                failures.append(f"{path} references {token!r} -- migrate to yadorilink_sync_wire:: directly")
    if (sync_core_src / "peer_wire").exists():
        failures.append(f"{sync_core_src / 'peer_wire'} still exists -- the wire layer must live only in yadorilink-sync-wire")
    return failures


def violations(crate_dir: Path = CRATE_DIR, sync_core_src: Path = SYNC_CORE_SRC) -> list[str]:
    return (
        cargo_toml_violations(crate_dir / "Cargo.toml")
        + source_violations(crate_dir / "src")
        + public_api_leak_violations(crate_dir / "src")
        + sync_core_alias_violations(sync_core_src)
    )


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        crate_dir = root / "sync-wire"
        sync_core_src = root / "sync-core-src"
        cargo_toml = crate_dir / "Cargo.toml"
        src_dir = crate_dir / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        sync_core_src.mkdir(parents=True, exist_ok=True)

        cargo_toml.write_text(
            '[package]\nname = "yadorilink-sync-wire"\n\n'
            "[dependencies]\nyadorilink-ipc-proto.workspace = true\nprost = \"0.14\"\n",
            encoding="utf-8",
        )
        (src_dir / "lib.rs").write_text("pub struct InboundFrame;\n", encoding="utf-8")
        (src_dir / "protobuf.rs").write_text(
            "use yadorilink_ipc_proto::sync as proto;\nuse prost::Message;\n", encoding="utf-8"
        )
        (sync_core_src / "peer_session.rs").write_text(
            "use yadorilink_sync_wire::InboundFrame;\n", encoding="utf-8"
        )
        assert not violations(crate_dir, sync_core_src), violations(crate_dir, sync_core_src)

        for dep in FORBIDDEN_CARGO_DEPS:
            cargo_toml.write_text(
                f'[package]\nname = "yadorilink-sync-wire"\n\n[dependencies]\n{dep} = "1"\n',
                encoding="utf-8",
            )
            assert violations(crate_dir, sync_core_src), f"failed to detect Cargo.toml dep {dep!r}"
        cargo_toml.write_text(
            '[package]\nname = "yadorilink-sync-wire"\n\n'
            "[dependencies]\nyadorilink-ipc-proto.workspace = true\nprost = \"0.14\"\n",
            encoding="utf-8",
        )
        assert not violations(crate_dir, sync_core_src)

        for token in FORBIDDEN_SOURCE_TOKENS:
            (src_dir / "lib.rs").write_text(f"fn f() {{ {token}bar(); }}\n", encoding="utf-8")
            assert violations(crate_dir, sync_core_src), f"failed to detect source token {token!r}"
        (src_dir / "lib.rs").write_text("pub struct InboundFrame;\n", encoding="utf-8")
        assert not violations(crate_dir, sync_core_src)

        # A generated-proto reference outside protobuf.rs must be flagged.
        (src_dir / "frame.rs").write_text("use yadorilink_ipc_proto::sync as proto;\n", encoding="utf-8")
        found = violations(crate_dir, sync_core_src)
        assert any("frame.rs" in f for f in found), "a leaked proto reference outside protobuf.rs must be flagged"
        (src_dir / "frame.rs").write_text("pub struct Frame;\n", encoding="utf-8")
        assert not violations(crate_dir, sync_core_src)

        # A stale crate::peer_wire:: reference in sync-core must be flagged.
        (sync_core_src / "peer_session.rs").write_text("use crate::peer_wire::InboundFrame;\n", encoding="utf-8")
        found = violations(crate_dir, sync_core_src)
        assert any("crate::peer_wire::" in f for f in found)
        (sync_core_src / "peer_session.rs").write_text("use yadorilink_sync_wire::InboundFrame;\n", encoding="utf-8")
        assert not violations(crate_dir, sync_core_src)

        # A leftover sync-core peer_wire/ directory must be flagged.
        (sync_core_src / "peer_wire").mkdir()
        found = violations(crate_dir, sync_core_src)
        assert any("still exists" in f for f in found)
        (sync_core_src / "peer_wire").rmdir()
        assert not violations(crate_dir, sync_core_src)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("phase 7d2 sync-wire boundary self-test passed")
        return 0

    failures = violations()
    if failures:
        print("phase 7d2 sync-wire boundary violations:")
        for failure in failures:
            print(f"- {str(failure).replace(str(ROOT) + '/', '')}")
        return 1

    print("Phase 7D-2 sync-wire boundary check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

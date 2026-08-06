#!/usr/bin/env python3
"""Phase 7D-8 boundary gate: `yadorilink-local-capture` owns
`LocalChangeProcessor` and the `LocalMutationStore` port it consumes -- see
docs/design/phase7d8-local-change-boundary-ledger.md and
docs/design/phase7d8-exit-report.md for the full move history.

That ledger's 7D-8.4 finding originally concluded this crate keeps a real,
permanent dependency on `yadorilink-sync-core` specifically *for*
`root_identity::VerifiedRoot`. Phase 7D-9B resolved exactly that one
dependency (VerifiedRoot moved to `yadorilink-root-authority`, which this
crate already depended on) -- this gate's `root_identity_violations` check
below is the machine-checkable proof of that, added in 7D-9B. It is
narrower than the phase7d9-dependency-plan.md "final dependency shape"
table's aspirational "yadorilink-local-capture -> yadorilink-sync-core:
FORBIDDEN, must be zero" line: this crate's own Cargo.toml still documents
several other real, still-needed sync-core symbols (DebounceFlush,
FsChangeEvent/FsChangeKind, chunker::write_placeholder,
change::PolicyUnavailable, dag_import, plus SyncState/SyncError for
`impl LocalMutationStore for SyncState`) that are 7D-9C/9E/9F's routing
targets, not 7D-9B's -- the crate's production dependency on
`yadorilink-sync-core` is NOT zero after 7D-9B, and this gate does not
falsely claim it is. What it does check:

- `yadorilink-local-capture/src/` no longer references
  `yadorilink_sync_core::root_identity` anywhere (Phase 7D-9B).

- `yadorilink-local-capture`'s `Cargo.toml` names no direct `rusqlite`/`r2d2`
  dependency (no SQL of its own -- all persistence goes through
  `LocalMutationStore`/`SyncState`) and no `notify` dependency (it consumes
  `yadorilink_sync_core::watcher::{FsChangeEvent, FsChangeKind}` as already-
  built value types, it does not run its own OS file-watcher).
- No source file in `yadorilink-local-capture/src/` references
  `rusqlite::`/`r2d2::`/`r2d2_sqlite::`/`notify::`.
- `yadorilink-sync-core/src/` no longer defines `LocalChangeProcessor` or the
  `LocalMutationStore` trait locally -- both moved to this crate; sync-core
  may still `impl` foreign traits against its own concrete types (the orphan
  rule shape every prior 7D-* move has used) but must not redefine either
  name.
- No compatibility re-export anywhere in the workspace of
  `yadorilink_sync_core::local_change` -- that module path must not exist in
  `yadorilink-sync-core` at all anymore, not even as a `pub use` pointing at
  the new crate.

Same substring-matching approach as this repo's other phase-boundary gate
scripts -- not a real Rust parser. Reviewer judgment remains the backstop.
"""

from __future__ import annotations

import argparse
import re
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCAL_CAPTURE_CRATE_DIR = ROOT / "crates/yadorilink-local-capture"
SYNC_CORE_SRC = ROOT / "crates/yadorilink-sync-core/src"
WORKSPACE_CRATES_DIR = ROOT / "crates"

COMMENT_LINE = re.compile(r"^\s*(///|//!|//)")

LOCAL_CAPTURE_FORBIDDEN_CARGO_DEPS = (
    "rusqlite",
    "r2d2",
    "r2d2_sqlite",
    "notify",
)

LOCAL_CAPTURE_FORBIDDEN_SOURCE_TOKENS = (
    "rusqlite::",
    "r2d2::",
    "r2d2_sqlite::",
    "notify::",
)

FORBIDDEN_SYNC_CORE_DEFINITIONS = (
    (re.compile(r"\bstruct\s+LocalChangeProcessor\b"), "struct LocalChangeProcessor"),
    (re.compile(r"\btrait\s+LocalMutationStore\b"), "trait LocalMutationStore"),
)

FORBIDDEN_SYNC_CORE_MODULE_PATHS = ("local_change",)


def _non_comment_lines(path: Path) -> list[tuple[int, str]]:
    lines = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if COMMENT_LINE.match(line):
            continue
        lines.append((i, line))
    return lines


def cargo_toml_violations(cargo_toml: Path) -> list[str]:
    if not cargo_toml.is_file():
        return [f"{cargo_toml} does not exist"]
    text = cargo_toml.read_text(encoding="utf-8")
    failures = []
    for dep in LOCAL_CAPTURE_FORBIDDEN_CARGO_DEPS:
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(f"{dep} ") or stripped.startswith(f"{dep}="):
                failures.append(f"{cargo_toml} depends on forbidden crate/package {dep!r}")
    return failures


def local_capture_source_violations(src_dir: Path) -> list[str]:
    failures: list[str] = []
    if not src_dir.is_dir():
        return failures
    for path in sorted(src_dir.rglob("*.rs")):
        for i, line in _non_comment_lines(path):
            for token in LOCAL_CAPTURE_FORBIDDEN_SOURCE_TOKENS:
                if token in line:
                    failures.append(f"{path}:{i} references forbidden {token!r}")
    return failures


def sync_core_violations(src_dir: Path) -> list[str]:
    failures: list[str] = []
    if not src_dir.is_dir():
        return failures

    mod_decl = re.compile(
        r"^\s*(pub\s+)?mod\s+(" + "|".join(FORBIDDEN_SYNC_CORE_MODULE_PATHS) + r")\b"
    )
    for path in sorted(src_dir.rglob("*.rs")):
        for i, line in _non_comment_lines(path):
            if mod_decl.match(line):
                failures.append(f"{path}:{i} declares forbidden sync-core module {line.strip()!r}")
            for name, label in FORBIDDEN_SYNC_CORE_DEFINITIONS:
                if name.search(line):
                    failures.append(f"{path}:{i} redefines {label} inside yadorilink-sync-core")
            if "pub use" in line:
                for forbidden in FORBIDDEN_SYNC_CORE_MODULE_PATHS:
                    if re.search(rf"::{forbidden}\b", line) or re.search(
                        rf"\bas\s+{forbidden}\b", line
                    ):
                        failures.append(
                            f"{path}:{i} re-exports forbidden module path "
                            f"{forbidden!r} from sync-core: {line.strip()!r}"
                        )
    return failures


def compatibility_reexport_violations(crates_dir: Path) -> list[str]:
    """No crate anywhere in the workspace may re-export
    `yadorilink_sync_core::local_change` pointing at the moved module."""
    failures: list[str] = []
    if not crates_dir.is_dir():
        return failures
    pattern = re.compile(
        r"pub\s+use\s+yadorilink_sync_core::(" + "|".join(FORBIDDEN_SYNC_CORE_MODULE_PATHS) + r")\b"
    )
    for path in sorted(crates_dir.rglob("*.rs")):
        for i, line in _non_comment_lines(path):
            if pattern.search(line):
                failures.append(
                    f"{path}:{i} re-exports a forbidden yadorilink_sync_core module path: "
                    f"{line.strip()!r}"
                )
    return failures


def root_identity_violations(src_dir: Path) -> list[str]:
    """Phase 7D-9B: `VerifiedRoot` moved to `yadorilink-root-authority`, so
    no file in this crate's own `src/` may reach it (or anything else) via
    `yadorilink_sync_core::root_identity` anymore."""
    failures: list[str] = []
    if not src_dir.is_dir():
        return failures
    for path in sorted(src_dir.rglob("*.rs")):
        for i, line in _non_comment_lines(path):
            if "yadorilink_sync_core::root_identity" in line:
                failures.append(
                    f"{path}:{i} still reaches root_identity through yadorilink-sync-core "
                    "-- yadorilink_root_authority::root_identity moved this in Phase 7D-9B"
                )
    return failures


def violations(
    crate_dir: Path = LOCAL_CAPTURE_CRATE_DIR,
    sync_core_src: Path = SYNC_CORE_SRC,
    crates_dir: Path = WORKSPACE_CRATES_DIR,
) -> list[str]:
    return (
        cargo_toml_violations(crate_dir / "Cargo.toml")
        + local_capture_source_violations(crate_dir / "src")
        + sync_core_violations(sync_core_src)
        + compatibility_reexport_violations(crates_dir)
        + root_identity_violations(crate_dir / "src")
    )


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        crate_dir = root / "local-capture"
        sync_core_src = root / "sync-core-src"
        crates_dir = root / "crates"
        other_crate_dir = crates_dir / "yadorilink-other" / "src"
        for d in (crate_dir / "src", sync_core_src, other_crate_dir):
            d.mkdir(parents=True, exist_ok=True)

        def reset() -> None:
            (crate_dir / "Cargo.toml").write_text(
                '[package]\nname = "yadorilink-local-capture"\n\n'
                "[dependencies]\nyadorilink-sync-core = { path = \"../yadorilink-sync-core\" }\n"
                "yadorilink-local-storage.workspace = true\n"
                'walkdir = "2"\n',
                encoding="utf-8",
            )
            (crate_dir / "src" / "local_change.rs").write_text(
                "pub struct LocalChangeProcessor { state: Arc<dyn crate::ports::LocalMutationStore> }\n",
                encoding="utf-8",
            )
            (crate_dir / "src" / "ports.rs").write_text(
                "pub trait LocalMutationStore {}\n"
                "impl LocalMutationStore for yadorilink_sync_core::index::SyncState {}\n",
                encoding="utf-8",
            )
            (sync_core_src / "index.rs").write_text(
                "pub struct SyncState;\n", encoding="utf-8"
            )
            for f in (crate_dir, sync_core_src, other_crate_dir):
                for stray in f.glob("*.rs"):
                    if stray not in (
                        crate_dir / "src" / "local_change.rs",
                        crate_dir / "src" / "ports.rs",
                        sync_core_src / "index.rs",
                    ):
                        stray.unlink()

        reset()
        assert not violations(crate_dir, sync_core_src, crates_dir), violations(
            crate_dir, sync_core_src, crates_dir
        )

        for dep in LOCAL_CAPTURE_FORBIDDEN_CARGO_DEPS:
            (crate_dir / "Cargo.toml").write_text(
                f'[package]\nname = "yadorilink-local-capture"\n\n[dependencies]\n{dep} = "1"\n',
                encoding="utf-8",
            )
            assert violations(
                crate_dir, sync_core_src, crates_dir
            ), f"failed to detect Cargo.toml dep {dep!r}"
        reset()
        assert not violations(crate_dir, sync_core_src, crates_dir)

        for token in LOCAL_CAPTURE_FORBIDDEN_SOURCE_TOKENS:
            (crate_dir / "src" / "local_change.rs").write_text(
                f"fn f() {{ {token}bar(); }}\n", encoding="utf-8"
            )
            assert violations(
                crate_dir, sync_core_src, crates_dir
            ), f"failed to detect source token {token!r}"
        reset()
        assert not violations(crate_dir, sync_core_src, crates_dir)

        # sync-core redefining LocalChangeProcessor must be flagged.
        (sync_core_src / "local_change.rs").write_text(
            "pub struct LocalChangeProcessor;\n", encoding="utf-8"
        )
        found = violations(crate_dir, sync_core_src, crates_dir)
        assert any("redefines struct LocalChangeProcessor" in f for f in found)
        (sync_core_src / "local_change.rs").unlink()
        reset()
        assert not violations(crate_dir, sync_core_src, crates_dir)

        # sync-core redefining the LocalMutationStore trait must be flagged.
        (sync_core_src / "ports.rs").write_text(
            "pub trait LocalMutationStore {}\n", encoding="utf-8"
        )
        found = violations(crate_dir, sync_core_src, crates_dir)
        assert any("redefines trait LocalMutationStore" in f for f in found)
        (sync_core_src / "ports.rs").unlink()
        reset()
        assert not violations(crate_dir, sync_core_src, crates_dir)

        # A forbidden module declaration in sync-core must be flagged.
        (sync_core_src / "local_change.rs").write_text(
            "pub struct Rogue;\n", encoding="utf-8"
        )
        (sync_core_src / "lib.rs").write_text("pub mod local_change;\n", encoding="utf-8")
        found = violations(crate_dir, sync_core_src, crates_dir)
        assert any("declares forbidden sync-core module" in f for f in found)
        (sync_core_src / "local_change.rs").unlink()
        (sync_core_src / "lib.rs").unlink()
        reset()
        assert not violations(crate_dir, sync_core_src, crates_dir)

        # A compatibility re-export in sync-core pointing at the new crate
        # must be flagged.
        (sync_core_src / "compat.rs").write_text(
            "pub use yadorilink_local_capture::local_change;\n", encoding="utf-8"
        )
        found = violations(crate_dir, sync_core_src, crates_dir)
        assert any("re-exports forbidden module path" in f for f in found)
        (sync_core_src / "compat.rs").unlink()
        reset()
        assert not violations(crate_dir, sync_core_src, crates_dir)

        # A compatibility re-export hiding in some OTHER crate must also be
        # flagged.
        (other_crate_dir / "shim.rs").write_text(
            "pub use yadorilink_sync_core::local_change::LocalChangeProcessor;\n",
            encoding="utf-8",
        )
        found = violations(crate_dir, sync_core_src, crates_dir)
        assert any("re-exports a forbidden yadorilink_sync_core module path" in f for f in found)
        (other_crate_dir / "shim.rs").unlink()
        reset()
        assert not violations(crate_dir, sync_core_src, crates_dir)

        # Phase 7D-9B: reaching VerifiedRoot (or anything else) through
        # yadorilink_sync_core::root_identity from this crate's own src/
        # must be flagged.
        (crate_dir / "src" / "ports.rs").write_text(
            "pub trait LocalMutationStore {}\n"
            "impl LocalMutationStore for yadorilink_sync_core::index::SyncState {}\n"
            "fn f() -> yadorilink_sync_core::root_identity::VerifiedRoot { todo!() }\n",
            encoding="utf-8",
        )
        found = violations(crate_dir, sync_core_src, crates_dir)
        assert any("still reaches root_identity through yadorilink-sync-core" in f for f in found), found
        reset()
        assert not violations(crate_dir, sync_core_src, crates_dir)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("phase 7d8 local-capture boundary self-test passed")
        return 0

    failures = violations()
    if failures:
        print("phase 7d8 local-capture boundary violations:")
        for failure in failures:
            print(f"- {str(failure).replace(str(ROOT) + '/', '')}")
        return 1

    print("Phase 7D-8 local-capture boundary check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

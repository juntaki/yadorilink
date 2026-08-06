#!/usr/bin/env python3
"""Phase 7D-6 boundary gate: `yadorilink-peer-session` owns `PeerSyncSession`
and its supporting modules (`peer_session_public.rs`, `adaptive_window.rs`,
`rate_limiter.rs`, `block_serve.rs`, `hazard.rs`, and the two peer-session-
only ports `PeerReplicaStatePort`/`PeerMessageChannel`) as a crate with zero
dependency back on `yadorilink-sync-core`, and zero SQLite/filesystem-watch
dependency of its own -- see
docs/design/phase7d6-peer-session-extraction-boundary.md for the full
port/module fan-out analysis that drove this shape.

Checked here:

- `yadorilink-peer-session`'s `Cargo.toml` names no `yadorilink-sync-core`,
  `rusqlite`/`r2d2`, or `notify`/`walkdir` dependency.
- No source file in `yadorilink-peer-session/src/` references
  `yadorilink_sync_core::` or `rusqlite::`/`r2d2::`/`notify::`/`walkdir::`.
- No manual protobuf-style wire codec (`prost::Message` impl, hand-rolled
  `fn encode(`/`fn decode(` byte framing) inside
  `yadorilink-peer-session/src/` -- this crate must only use
  `yadorilink-sync-wire`'s existing encode/decode. `hazard.rs` is filename-
  hazard detection (case-fold/NFC-NFD/reserved-name checks), not wire
  encoding, despite the phase's own kickoff flagging it as a place wire code
  might have ended up -- confirmed by direct read, not assumed; this gate
  still scans it like every other file in the crate rather than special-
  casing it, so a genuine future regression there is still caught.
- `yadorilink-sync-core/src/` no longer defines `PeerSyncSession`,
  `PeerReplicaStatePort`, or `PeerMessageChannel` locally (only trait
  re-exports/adapter impls against the new crate's traits, which is the
  intended shape -- `SyncState` is sync-core's own concrete type
  implementing a foreign trait, allowed by the orphan rule and required so
  `yadorilink-peer-session` never depends back on `yadorilink-sync-core`).
- No compatibility re-export anywhere in the workspace of
  `yadorilink_sync_core::peer_session`/`peer_session_public`/
  `adaptive_window`/`rate_limiter`/`block_serve` -- these module paths must
  not exist in `yadorilink-sync-core` at all anymore (not even as a
  `pub use` pointing at the new crate).
- Production `PeerSyncSession`/`InnerPeerSyncSession` constructors
  (`new`, `new_with_dependencies`, `new_with_forwarding`) are only called
  outside `#[cfg(test)]`/`tests/` from `yadorilink-daemon`'s composition
  root (`peer_orchestrator.rs`) -- no other non-test workspace crate
  constructs a session directly.

Same substring-matching approach as this repo's other phase-boundary gate
scripts -- not a real Rust parser. Reviewer judgment remains the backstop.
"""

from __future__ import annotations

import argparse
import re
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PEER_SESSION_CRATE_DIR = ROOT / "crates/yadorilink-peer-session"
SYNC_CORE_SRC = ROOT / "crates/yadorilink-sync-core/src"
WORKSPACE_CRATES_DIR = ROOT / "crates"

COMMENT_LINE = re.compile(r"^\s*(///|//!|//)")

PEER_SESSION_FORBIDDEN_CARGO_DEPS = (
    "yadorilink-sync-core",
    "rusqlite",
    "r2d2",
    "r2d2_sqlite",
    "notify",
    "walkdir",
)

PEER_SESSION_FORBIDDEN_SOURCE_TOKENS = (
    "yadorilink_sync_core::",
    "rusqlite::",
    "r2d2::",
    "r2d2_sqlite::",
    "notify::",
    "walkdir::",
)

# A duplicated hand-rolled wire codec would show up as one of these -- a
# real `prost::Message` impl, or manual `encode`/`decode` framing functions.
# `yadorilink-sync-wire`'s own codec is the only place these are allowed to
# be defined workspace-wide; this crate must only call into it.
WIRE_CODEC_DUPLICATION_TOKENS = (
    "prost::Message",
    "impl Message for",
)
WIRE_CODEC_FN_PATTERN = re.compile(r"\bfn\s+(encode|decode)\s*\(")

# Module paths that must not exist in sync-core anymore -- not as a real
# module, not as a `pub use` compatibility re-export pointing at the new
# crate.
FORBIDDEN_SYNC_CORE_MODULE_PATHS = (
    "peer_session",
    "peer_session_public",
    "adaptive_window",
    "rate_limiter",
    "block_serve",
)

FORBIDDEN_SYNC_CORE_DEFINITIONS = (
    (re.compile(r"\bstruct\s+PeerSyncSession\b"), "struct PeerSyncSession"),
    (re.compile(r"\btrait\s+PeerReplicaStatePort\b"), "trait PeerReplicaStatePort"),
    (re.compile(r"\btrait\s+PeerMessageChannel\b"), "trait PeerMessageChannel"),
)

SESSION_CONSTRUCTOR_PATTERN = re.compile(
    r"PeerSyncSession::(new|new_with_dependencies|new_with_forwarding)\s*\("
)


def _is_test_path(path: Path) -> bool:
    parts = path.parts
    return "tests" in parts or path.name.endswith("_test.rs") or "test_support" in path.name


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
    for dep in PEER_SESSION_FORBIDDEN_CARGO_DEPS:
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(f"{dep} ") or stripped.startswith(f"{dep}="):
                failures.append(f"{cargo_toml} depends on forbidden crate/package {dep!r}")
    return failures


def peer_session_source_violations(src_dir: Path) -> list[str]:
    failures: list[str] = []
    if not src_dir.is_dir():
        return failures
    for path in sorted(src_dir.rglob("*.rs")):
        for i, line in _non_comment_lines(path):
            for token in PEER_SESSION_FORBIDDEN_SOURCE_TOKENS:
                if token in line:
                    failures.append(f"{path}:{i} references forbidden {token!r}")
            for token in WIRE_CODEC_DUPLICATION_TOKENS:
                if token in line:
                    failures.append(
                        f"{path}:{i} defines a manual wire codec ({token!r}) -- "
                        "yadorilink-peer-session must only call yadorilink-sync-wire's codec"
                    )
            m = WIRE_CODEC_FN_PATTERN.search(line)
            if m and "self" not in line.split("(", 1)[0]:
                # A free-standing `fn encode(`/`fn decode(` (not a method
                # taking `self`, e.g. `fn encode(&self, ...)` on an
                # unrelated type) is the shape a hand-rolled byte-framing
                # codec would take. Method-style encode/decode on domain
                # types (e.g. base64/hex helpers) are common enough that a
                # bare substring match would be too noisy; this narrows to
                # the free-function shape a duplicated wire codec would use.
                failures.append(
                    f"{path}:{i} defines a free function {m.group(0)!r} -- "
                    "verify this is not a duplicated wire-codec function "
                    "(yadorilink-sync-wire is this crate's only wire codec)"
                )
    return failures


def sync_core_violations(src_dir: Path) -> list[str]:
    failures: list[str] = []
    if not src_dir.is_dir():
        return failures

    # Module paths: both a real `mod X;`/`pub mod X;` declaration and a
    # compatibility `pub use ... as X`/`pub use yadorilink_peer_session::X`
    # re-export under one of the forbidden names are violations.
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
                    # A re-export naming one of the forbidden module paths
                    # as its own path segment, e.g.
                    # `pub use yadorilink_peer_session::peer_session;` or
                    # `pub use foo::bar as peer_session;`.
                    if re.search(rf"::{forbidden}\b", line) or re.search(
                        rf"\bas\s+{forbidden}\b", line
                    ):
                        failures.append(
                            f"{path}:{i} re-exports forbidden module path "
                            f"{forbidden!r} from sync-core: {line.strip()!r}"
                        )
    return failures


def compatibility_reexport_violations(crates_dir: Path) -> list[str]:
    """No crate anywhere in the workspace may re-export one of the
    forbidden sync-core module paths pointing at the new crate -- this
    catches the case where the re-export was hidden in a crate other than
    sync-core itself (e.g. a thin shim crate)."""
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


def composition_root_violations(
    crates_dir: Path,
    allowed_dirs: tuple[str, ...] = ("yadorilink-daemon/src",),
) -> list[str]:
    """Production `PeerSyncSession` construction must only happen from the
    daemon's composition root. Test code (anything under `tests/`, or
    `#[cfg(test)]` source within a crate, approximated here by scanning only
    non-test files and skipping any line inside a `#[cfg(test)]`-gated
    module by file-path heuristic) is exempt."""
    failures: list[str] = []
    if not crates_dir.is_dir():
        return failures
    for path in sorted(crates_dir.rglob("*.rs")):
        if _is_test_path(path):
            continue
        rel = path.relative_to(crates_dir).as_posix()
        text = path.read_text(encoding="utf-8")
        # Skip files that are entirely (or start with) a cfg(test) module --
        # a cheap approximation: if the whole file's only constructor calls
        # sit after a `#[cfg(test)]` marker earlier in the file, treat them
        # as test code. This mirrors the other phase gates' "comment-line
        # only" precision trade-off: substring-matching, not a real parser.
        cfg_test_at = text.find("#[cfg(test)]")
        for i, line in _non_comment_lines(path):
            if not SESSION_CONSTRUCTOR_PATTERN.search(line):
                continue
            offset = sum(len(l) + 1 for l in text.splitlines()[: i - 1])
            if cfg_test_at != -1 and offset > cfg_test_at:
                continue
            if not any(rel.startswith(prefix) for prefix in allowed_dirs) and not rel.startswith(
                "yadorilink-peer-session/src"
            ):
                failures.append(
                    f"{path}:{i} constructs PeerSyncSession outside the daemon composition root: "
                    f"{line.strip()!r}"
                )
    return failures


def violations(
    crate_dir: Path = PEER_SESSION_CRATE_DIR,
    sync_core_src: Path = SYNC_CORE_SRC,
    crates_dir: Path = WORKSPACE_CRATES_DIR,
) -> list[str]:
    return (
        cargo_toml_violations(crate_dir / "Cargo.toml")
        + peer_session_source_violations(crate_dir / "src")
        + sync_core_violations(sync_core_src)
        + compatibility_reexport_violations(crates_dir)
        + composition_root_violations(crates_dir)
    )


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        crate_dir = root / "peer-session"
        sync_core_src = root / "sync-core-src"
        crates_dir = root / "crates"
        daemon_dir = crates_dir / "yadorilink-daemon" / "src"
        peer_session_crate_dir = crates_dir / "yadorilink-peer-session"
        src_dir = peer_session_crate_dir / "src"
        other_crate_dir = crates_dir / "yadorilink-other" / "src"
        for d in (crate_dir / "src", sync_core_src, daemon_dir, src_dir, other_crate_dir):
            d.mkdir(parents=True, exist_ok=True)

        def reset() -> None:
            (crate_dir / "Cargo.toml").write_text(
                '[package]\nname = "yadorilink-peer-session"\n\n'
                "[dependencies]\nyadorilink-sync-wire.workspace = true\n"
                "yadorilink-replica-engine.workspace = true\n",
                encoding="utf-8",
            )
            (crate_dir / "src" / "peer_session.rs").write_text(
                "pub struct PeerSyncSession { state: Arc<dyn crate::ports::PeerReplicaStatePort> }\n"
                "impl PeerSyncSession {\n"
                "    pub fn new() -> Self { todo!() }\n"
                "}\n",
                encoding="utf-8",
            )
            (sync_core_src / "index.rs").write_text(
                "impl crate::ports::PeerReplicaStatePort for SyncState {}\n",
                encoding="utf-8",
            )
            (sync_core_src / "ports.rs").write_text(
                "pub use yadorilink_peer_session::ports::{PeerMessageChannel, PeerReplicaStatePort};\n",
                encoding="utf-8",
            )
            for f in (crate_dir, sync_core_src, daemon_dir, src_dir, other_crate_dir):
                for stray in f.glob("*.rs"):
                    if stray not in (
                        crate_dir / "src" / "peer_session.rs",
                        sync_core_src / "index.rs",
                        sync_core_src / "ports.rs",
                    ):
                        stray.unlink()
            (daemon_dir / "peer_orchestrator.rs").write_text(
                "fn spawn() { let s = PeerSyncSession::new_with_dependencies(a, b); }\n",
                encoding="utf-8",
            )
            (src_dir / "peer_session.rs").write_text(
                "pub struct PeerSyncSession;\n", encoding="utf-8"
            )

        reset()
        assert not violations(crate_dir, sync_core_src, crates_dir), violations(
            crate_dir, sync_core_src, crates_dir
        )

        for dep in PEER_SESSION_FORBIDDEN_CARGO_DEPS:
            (crate_dir / "Cargo.toml").write_text(
                f'[package]\nname = "yadorilink-peer-session"\n\n[dependencies]\n{dep} = "1"\n',
                encoding="utf-8",
            )
            assert violations(
                crate_dir, sync_core_src, crates_dir
            ), f"failed to detect Cargo.toml dep {dep!r}"
        reset()
        assert not violations(crate_dir, sync_core_src, crates_dir)

        for token in PEER_SESSION_FORBIDDEN_SOURCE_TOKENS:
            (crate_dir / "src" / "peer_session.rs").write_text(
                f"fn f() {{ {token}bar(); }}\n", encoding="utf-8"
            )
            assert violations(
                crate_dir, sync_core_src, crates_dir
            ), f"failed to detect source token {token!r}"
        reset()
        assert not violations(crate_dir, sync_core_src, crates_dir)

        # A duplicated wire codec must be flagged.
        (crate_dir / "src" / "codec.rs").write_text(
            "impl Message for SyncMessage {\n"
            "    fn encode(&self, buf: &mut Vec<u8>) { todo!() }\n"
            "}\n",
            encoding="utf-8",
        )
        found = violations(crate_dir, sync_core_src, crates_dir)
        assert any("manual wire codec" in f for f in found)
        (crate_dir / "src" / "codec.rs").unlink()
        reset()
        assert not violations(crate_dir, sync_core_src, crates_dir)

        # sync-core redefining PeerSyncSession must be flagged.
        (sync_core_src / "peer_session.rs").write_text(
            "pub struct PeerSyncSession;\n", encoding="utf-8"
        )
        found = violations(crate_dir, sync_core_src, crates_dir)
        assert any("redefines struct PeerSyncSession" in f for f in found)
        (sync_core_src / "peer_session.rs").unlink()
        reset()
        assert not violations(crate_dir, sync_core_src, crates_dir)

        # A forbidden module declaration in sync-core must be flagged.
        (sync_core_src / "rate_limiter.rs").write_text(
            "pub struct Rogue;\n", encoding="utf-8"
        )
        (sync_core_src / "lib.rs").write_text("pub mod rate_limiter;\n", encoding="utf-8")
        found = violations(crate_dir, sync_core_src, crates_dir)
        assert any("declares forbidden sync-core module" in f for f in found)
        (sync_core_src / "rate_limiter.rs").unlink()
        (sync_core_src / "lib.rs").unlink()
        reset()
        assert not violations(crate_dir, sync_core_src, crates_dir)

        # A compatibility re-export in sync-core pointing at the new crate
        # under one of the forbidden module names must be flagged.
        (sync_core_src / "compat.rs").write_text(
            "pub use yadorilink_peer_session::peer_session;\n", encoding="utf-8"
        )
        found = violations(crate_dir, sync_core_src, crates_dir)
        assert any("re-exports forbidden module path" in f for f in found)
        (sync_core_src / "compat.rs").unlink()
        reset()
        assert not violations(crate_dir, sync_core_src, crates_dir)

        # A compatibility re-export hiding in some OTHER crate must also be
        # flagged.
        (other_crate_dir / "shim.rs").write_text(
            "pub use yadorilink_sync_core::block_serve::BlockServeEngine;\n", encoding="utf-8"
        )
        found = violations(crate_dir, sync_core_src, crates_dir)
        assert any("re-exports a forbidden yadorilink_sync_core module path" in f for f in found)
        (other_crate_dir / "shim.rs").unlink()
        reset()
        assert not violations(crate_dir, sync_core_src, crates_dir)

        # A PeerSyncSession construction outside the daemon composition
        # root must be flagged.
        (other_crate_dir / "rogue.rs").write_text(
            "fn f() { PeerSyncSession::new_with_forwarding(a, b); }\n", encoding="utf-8"
        )
        found = violations(crate_dir, sync_core_src, crates_dir)
        assert any("constructs PeerSyncSession outside the daemon composition root" in f for f in found)
        (other_crate_dir / "rogue.rs").unlink()
        reset()
        assert not violations(crate_dir, sync_core_src, crates_dir)

        # ... but the same construction inside a tests/ directory is exempt.
        rogue_tests_dir = crates_dir / "yadorilink-other" / "tests"
        rogue_tests_dir.mkdir(parents=True, exist_ok=True)
        (rogue_tests_dir / "it.rs").write_text(
            "fn f() { PeerSyncSession::new(a, b); }\n", encoding="utf-8"
        )
        assert not violations(crate_dir, sync_core_src, crates_dir)
        (rogue_tests_dir / "it.rs").unlink()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("phase 7d6 peer-session boundary self-test passed")
        return 0

    failures = violations()
    if failures:
        print("phase 7d6 peer-session boundary violations:")
        for failure in failures:
            print(f"- {str(failure).replace(str(ROOT) + '/', '')}")
        return 1

    print("Phase 7D-6 peer-session boundary check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

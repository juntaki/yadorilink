#!/usr/bin/env python3
"""Enforce that `yadorilink-daemon`'s composition-root functions
(`adapters::build_application_services`, `adapters::build_query_services`,
`maintenance_coordinator::start`) are only ever CALLED from an allowed set
of files -- the production composition root (`app.rs`), the one
compatibility wrapper that still owns its own construction
(`daemon_state.rs`'s `DaemonState::new`, and the periodic membership-
recovery sweep it schedules -- see `ALLOWED_BUILD_CALLERS` below), the
test-construction helper (`control_context.rs`'s `ControlContext::
from_state`, a normal `pub fn` used by both this crate's own unit tests
and the external integration-test binaries under `tests/`, so never
`#[cfg(test)]`-gated itself), and `#[cfg(test)]`-gated call sites in
`control_socket.rs`/`diagnostics_ipc.rs`.

This is a substring/brace-matching scan, not a real Rust parser -- same
class of tool as `check-daemon-application-dependencies.py`, with the
same false-positive/evasion tradeoffs documented there. `#[cfg(test)]`
span detection reuses `gen-daemon-production-graph.py`'s own brace-
matching approach (see that script's `strip_cfg_test_blocks` for the
same technique, doc comment included).

Phase 2E: this gate exists specifically to keep "build the whole
application/query layer fresh on every single request/tick" (the
pattern every one of Phase 2's slices worked to eliminate) from quietly
reappearing at a new call site once this check is in place -- new
violations must be treated as real regressions, not adjusted into the
allowlist without a documented reason.
"""

from __future__ import annotations

import argparse
import re
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DAEMON_SRC = ROOT / "crates/yadorilink-daemon/src"

CALL_TOKENS = {
    "build_application_services(": "build_application_services",
    "build_query_services(": "build_query_services",
}
MAINTENANCE_START_TOKEN = "maintenance_coordinator::start("

DEFINITION_FILE = "adapters/mod.rs"

# Files allowed to call the composition-root builders, relative to
# DAEMON_SRC. `daemon_state.rs` is allowed twice over: `DaemonState::new`
# (the Section B compatibility wrapper every existing test call site still
# uses) and `run_membership_recovery_sweep` (the periodic sweep
# `maintenance_coordinator` schedules) -- the latter rebuilds
# `ApplicationServices` on every tick rather than reusing a shared
# instance, a known, documented gap (see this repo's Phase 2 exit report),
# not a silent oversight; narrowing it requires reordering `app.rs`'s
# startup sequence (building `ApplicationServices` before starting
# `MaintenanceCoordinator`, which currently starts first -- Section B's own
# ordering guarantee) and is deliberately left for a later pass rather than
# risking that ordering here.
ALLOWED_BUILD_CALLERS = {
    "app.rs",
    "control_context.rs",
    "daemon_state.rs",
}

# `control_socket.rs`/`diagnostics_ipc.rs` may call the builders ONLY from
# inside a `#[cfg(test)]` span.
TEST_GATED_ONLY_CALLERS = {
    "control_socket.rs",
    "diagnostics_ipc.rs",
}

# `maintenance_coordinator::start` -- production's `app.rs` and the
# `DaemonState::new` compatibility wrapper (Section B) are the only two
# legitimate callers; nothing else should ever start the maintenance
# background-task set a second time.
ALLOWED_MAINTENANCE_START_CALLERS = {
    "app.rs",
    "daemon_state.rs",
}

CFG_TEST_ATTR = re.compile(r"#\[cfg\(\s*test\s*\)\]")


def cfg_test_line_ranges(text: str) -> list[tuple[int, int]]:
    """Every `#[cfg(test)] <item> { ... }` span, as (start_line, end_line)
    1-indexed inclusive line numbers -- brace-matched from the `{` after
    the attribute, same technique as `gen-daemon-production-graph.py`'s
    `strip_cfg_test_blocks`.
    """
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
        rel = path.relative_to(src_dir).as_posix()
        rel_name = path.name
        if rel == DEFINITION_FILE:
            continue
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        test_ranges = cfg_test_line_ranges(text)

        def in_test_span(line_no: int) -> bool:
            return any(start <= line_no <= end for start, end in test_ranges)

        for i, line in enumerate(lines, start=1):
            for token, label in CALL_TOKENS.items():
                if token not in line:
                    continue
                if rel_name in TEST_GATED_ONLY_CALLERS:
                    if not in_test_span(i):
                        failures.append(
                            f"{path}:{i} calls {label} outside a #[cfg(test)] span in a "
                            "test-only-allowed file"
                        )
                elif rel_name not in ALLOWED_BUILD_CALLERS:
                    failures.append(
                        f"{path}:{i} calls {label} from a file not in the composition-root "
                        "allowlist"
                    )

            if MAINTENANCE_START_TOKEN in line and rel_name not in ALLOWED_MAINTENANCE_START_CALLERS:
                failures.append(
                    f"{path}:{i} calls maintenance_coordinator::start from a file not in "
                    "its allowlist"
                )

    return failures


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        src_dir = Path(directory)

        allowed = src_dir / "app.rs"
        allowed.write_text(
            "crate::adapters::build_application_services(state.clone());\n", encoding="utf-8"
        )
        assert not violations(src_dir), "app.rs must be allowed to call the builder"
        allowed.unlink()

        disallowed = src_dir / "some_handler.rs"
        disallowed.write_text(
            "crate::adapters::build_application_services(state.clone());\n", encoding="utf-8"
        )
        found = violations(src_dir)
        assert any("some_handler.rs" in f for f in found), "non-allowlisted caller must be flagged"
        disallowed.unlink()

        start_disallowed = src_dir / "some_handler.rs"
        start_disallowed.write_text(
            "maintenance_coordinator::start(&state, rx);\n", encoding="utf-8"
        )
        found = violations(src_dir)
        assert any(
            "maintenance_coordinator::start" in f for f in found
        ), "non-allowlisted maintenance_coordinator::start caller must be flagged"
        start_disallowed.unlink()

        test_gated_ok = src_dir / "control_socket.rs"
        test_gated_ok.write_text(
            "#[cfg(test)]\nmod tests {\n"
            "    fn helper() {\n"
            "        crate::adapters::build_application_services(state.clone());\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        assert not violations(src_dir), "a #[cfg(test)]-gated call in control_socket.rs must pass"

        test_gated_ok.write_text(
            "crate::adapters::build_application_services(state.clone());\n"
            "#[cfg(test)]\nmod tests {}\n",
            encoding="utf-8",
        )
        found = violations(src_dir)
        assert any(
            "control_socket.rs" in f for f in found
        ), "an UN-gated call in control_socket.rs must be flagged"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("daemon composition-root self-test passed")
        return 0

    failures = violations(DAEMON_SRC)
    if failures:
        print("daemon composition-root violations:")
        for failure in failures:
            print(f"- {failure.replace(str(ROOT) + '/', '')}")
        return 1

    print("daemon composition-root check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

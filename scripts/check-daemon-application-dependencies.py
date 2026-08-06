#!/usr/bin/env python3
"""Enforce that `yadorilink-daemon::application` never depends on a
concrete adapter, transport, or infrastructure type directly -- only on
`application::ports` traits and `application::model` value types.

Phase 2 (application-layer dependency-inversion refactor) landed this
narrowing incrementally across Commits 1-5 (ports/composition-root
scaffold, Materialization/Enrollment, enrollment recovery, Membership,
ReplicaRole); this is now a CI gate (Commit 6) -- see this repo's CI
workflow for the invocation, alongside `check-phase1b-application-
boundary.py`. That older, narrower check is NOT superseded by this one:
it also covers `yadorilink-cli` (raw coordination-plane bypasses) and
`control_socket.rs` (direct `coordination_client`/role-loss calls that
skip `application`), neither of which this check scans -- both stay in
place.

This is a substring check, not a real Rust parser: it catches every
organic form a forbidden import can take (`use crate::daemon_state::X;`,
a grouped `use crate::{daemon_state::X, ...};`, a relative `use
super::super::daemon_state::X;`), but a deliberate `use
crate::daemon_state as state;` rename is not something this check (or
its `check-phase1b-application-boundary.py` sibling, which has the same
limitation) can detect short of a full import parser -- reviewer
judgment remains the backstop against a genuinely adversarial evasion,
same as it always has been for every other string-pattern check in this
repo.
"""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APPLICATION = ROOT / "crates/yadorilink-daemon/src/application"

FORBIDDEN = (
    # Matched as `<module>::` rather than `crate::<module>` alone -- a plain
    # `crate::`-prefix substring check misses a `use` that reaches the same
    # module through grouping (`use crate::{daemon_state::DaemonState,
    # error::DaemonError};` -- a shape `rustfmt` itself produces when
    # merging adjacent single-item `use crate::` lines) or a relative path
    # (`use super::super::daemon_state::DaemonState;`). The trailing `::`
    # means an unrelated local variable/field happening to share one of
    # these names (e.g. a `hydration` field) is never a false positive --
    # only an actual path segment counts.
    "daemon_state::",
    "coordination_client::",
    "control_socket::",
    "hydration::",
    "link_manager::",
    # Phase 2B's daemon-runtime decomposition modules (PeerRegistry/
    # LinkRegistry/DurabilityService/RuntimeTelemetry/MaintenanceCoordinator)
    # are concrete `DaemonState`-internal storage, exactly the class of
    # dependency this check exists to keep out of `application` -- same
    # reasoning as `daemon_state::` itself, just for the pieces that moved
    # out of it.
    "peer_registry::",
    "link_registry::",
    "durability_service::",
    "runtime_telemetry::",
    "maintenance_coordinator::",
    "yadorilink_ipc_proto",
    "reqwest::",
)


def violations(application_dir: Path) -> list[str]:
    failures: list[str] = []

    for path in sorted(application_dir.rglob("*.rs")):
        text = path.read_text(encoding="utf-8")

        for token in FORBIDDEN:
            if token in text:
                failures.append(f"{path} contains forbidden dependency {token!r}")

    return failures


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        application_dir = Path(directory) / "application"
        clean = application_dir / "service.rs"
        clean.parent.mkdir(parents=True, exist_ok=True)
        clean.write_text("pub(crate) struct Service;\n", encoding="utf-8")
        assert not violations(application_dir)

        for token in FORBIDDEN:
            clean.write_text(f"use {token}foo;\n", encoding="utf-8")
            assert violations(application_dir), f"failed to detect {token!r}"

        clean.write_text("pub(crate) struct Service;\n", encoding="utf-8")
        assert not violations(application_dir)

        # A grouped `use crate::{...}` (the shape `rustfmt` produces when
        # merging adjacent single-item `use crate::` lines) or a relative
        # `super::` path must be caught just as reliably as the plain
        # `use crate::daemon_state::...;` form above.
        clean.write_text(
            "use crate::{daemon_state::DaemonState, error::DaemonError};\n",
            encoding="utf-8",
        )
        assert violations(application_dir), "grouped use crate::{...} imports must be detected"
        clean.write_text("use super::super::daemon_state::DaemonState;\n", encoding="utf-8")
        assert violations(application_dir), "relative super:: imports must be detected"
        clean.write_text("pub(crate) struct Service;\n", encoding="utf-8")
        assert not violations(application_dir)

        nested = application_dir / "ports" / "enrollment.rs"
        nested.parent.mkdir(parents=True, exist_ok=True)
        nested.write_text("use crate::daemon_state::DaemonState;\n", encoding="utf-8")
        assert violations(application_dir), "nested application/ports files must be scanned too"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("daemon application dependency self-test passed")
        return 0

    failures = violations(APPLICATION)
    if failures:
        print("daemon application dependency violations:")
        for failure in failures:
            print(f"- {failure.replace(str(ROOT) + '/', '')}")
        return 1

    print("daemon application dependency check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

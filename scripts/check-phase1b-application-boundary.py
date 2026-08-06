#!/usr/bin/env python3
"""Enforce the Phase 1b CLI-to-daemon application ownership boundary."""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

CLI_FORBIDDEN = (
    "guard_against_forced_replica_loss",
    "obtain_handoff_ticket_from_device",
    "release_handoff_ticket_from_device",
    "LatchGroupDurabilityUnknown",
    "activate_create(",
    "activate_join(",
    "cancel_create(",
    "cancel_join(",
    # Membership-coordination endpoints must only ever be reached through a
    # daemon command (RevokeDeviceCommand/RemoveDeviceCommand/
    # RevokeEdgeCommand) — a raw HTTP call to any of these from the CLI is
    # exactly the `revoke_edge` boundary bypass this check exists to catch.
    '"/shares/{edge_id}"',
    "/shares/groups/{group_id}/revoke",
    "/devices/{device_id}/handoff-remove",
    'format!("/devices/{device_id}")',
)

APPLICATION_FORBIDDEN = ("yadorilink_ipc_proto",)

CONTROL_FORBIDDEN = (
    "coordination_client::commit_handoff_role_loss(",
    ".open_role_loss_operation(",
)


def violations(root: Path) -> list[str]:
    checks = {
        root / "crates/yadorilink-cli/src/commands/device.rs": CLI_FORBIDDEN,
        root / "crates/yadorilink-cli/src/commands/share.rs": CLI_FORBIDDEN,
        root / "crates/yadorilink-cli/src/commands/link.rs": CLI_FORBIDDEN,
        root / "crates/yadorilink-daemon/src/control_socket.rs": CONTROL_FORBIDDEN,
    }
    application = root / "crates/yadorilink-daemon/src/application"
    for path in application.glob("*.rs"):
        checks[path] = APPLICATION_FORBIDDEN

    failures: list[str] = []
    for path, patterns in checks.items():
        if not path.exists():
            failures.append(f"missing boundary file: {path.relative_to(root)}")
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in patterns:
            if pattern in text:
                failures.append(f"{path.relative_to(root)} contains forbidden {pattern!r}")
    return failures


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        paths = (
            "crates/yadorilink-cli/src/commands/device.rs",
            "crates/yadorilink-cli/src/commands/share.rs",
            "crates/yadorilink-cli/src/commands/link.rs",
            "crates/yadorilink-daemon/src/control_socket.rs",
            "crates/yadorilink-daemon/src/application/service.rs",
        )
        for relative in paths:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("application_service.call();\n", encoding="utf-8")
        assert not violations(root)

        cases = (
            (paths[0], "guard_against_forced_replica_loss"),
            (paths[1], "activate_create("),
            (paths[2], "LatchGroupDurabilityUnknown"),
            (paths[3], "coordination_client::commit_handoff_role_loss("),
            (paths[4], "yadorilink_ipc_proto"),
        )
        for relative, forbidden in cases:
            path = root / relative
            path.write_text(forbidden, encoding="utf-8")
            assert violations(root), f"failed to detect {forbidden!r}"
            path.write_text("application_service.call();\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("phase1b application boundary self-test passed")
        return 0

    failures = violations(ROOT)
    if failures:
        print("Phase 1b application boundary violations:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print("phase1b application boundary check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

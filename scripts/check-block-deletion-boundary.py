#!/usr/bin/env python3
"""Fail when production sync code bypasses BlockDeletionCoordinator."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOTS = [
    ROOT / "crates/yadorilink-daemon/src",
    ROOT / "crates/yadorilink-filesystem-sync/src",
    ROOT / "crates/yadorilink-sync-sqlite/src",
]
COORDINATORS = {
    ROOT / "crates/yadorilink-filesystem-sync/src/block_deletion.rs",
    ROOT / "crates/yadorilink-sync-sqlite/src/block_deletion.rs",
}
FORWARDING_ADAPTER = ROOT / "crates/yadorilink-daemon/src/adapters/block_store_ports.rs"


def production_prefix(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        if line.strip() == "#[cfg(test)]":
            return lines[:index]
    return lines


def main() -> int:
    violations: list[str] = []

    adapter = "\n".join(production_prefix(FORWARDING_ADAPTER))
    for method in (".sweep(", ".reclaim_cached_blocks("):
        count = adapter.count(method)
        if count != 1:
            violations.append(
                f"{FORWARDING_ADAPTER.relative_to(ROOT)}: expected exactly one {method[:-1]} "
                f"capability forwarding call, found {count}"
            )

    for source_root in SOURCE_ROOTS:
        for path in source_root.rglob("*.rs"):
            if (
                path in COORDINATORS
                or path == FORWARDING_ADAPTER
                or any(part.startswith("reporting") for part in path.parts)
            ):
                continue
            lines = production_prefix(path)
            block_store_context = any(
                token in "\n".join(lines) for token in ("BlockStore", "BlockReclamationStore")
            )
            for index, line in enumerate(lines):
                if block_store_context and ".delete(" in line:
                    violations.append(f"{path.relative_to(ROOT)}:{index + 1}: direct delete")
                for method in (".sweep(", ".reclaim_cached_blocks("):
                    if method not in line:
                        continue
                    context = "\n".join(lines[max(0, index - 3) : index + 1])
                    if "BlockDeletionCoordinator" not in context:
                        violations.append(
                            f"{path.relative_to(ROOT)}:{index + 1}: {method[:-1]} bypasses coordinator"
                        )

    if violations:
        print("physical block deletion must go through BlockDeletionCoordinator", file=sys.stderr)
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        return 1
    print("block deletion boundary: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

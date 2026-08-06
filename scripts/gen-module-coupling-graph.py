#!/usr/bin/env python3
"""Generates a weighted top-level-module coupling DOT graph for one crate.

Counts `crate::<module>::...` reference occurrences in each source file and
attributes them to the file's owning top-level module (the first path
component under `src/`). This is a static-reference count, not a call
graph -- it does not resolve `super::`, macros, or trait dispatch, and it
counts textual references, not distinct call sites.

Usage:
    scripts/gen-module-coupling-graph.py <crate-name> <src-dir>
        > architecture/graphs/generated/<crate>-coupling.dot
"""
import re
import sys
from collections import defaultdict
from pathlib import Path

CRATE_REF = re.compile(r"crate::([A-Za-z_][A-Za-z0-9_]*)")

# Files at the crate root that are not module owners in their own right.
ROOT_NON_MODULE_STEMS = {"lib", "main", "test_support"}


def owning_module(src_dir: Path, path: Path) -> str | None:
    rel = path.relative_to(src_dir)
    parts = rel.parts
    if len(parts) == 1:
        stem = rel.stem
        if stem in ROOT_NON_MODULE_STEMS or stem == "bin":
            return None
        return stem
    if parts[0] == "bin":
        return None
    return parts[0]


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <crate-name> <src-dir>", file=sys.stderr)
        return 1
    crate_name, src_dir_arg = sys.argv[1], sys.argv[2]
    src_dir = Path(src_dir_arg).resolve()

    counts: dict[tuple[str, str], int] = defaultdict(int)
    modules: set[str] = set()

    for path in sorted(src_dir.rglob("*.rs")):
        from_module = owning_module(src_dir, path)
        if from_module is None:
            continue
        modules.add(from_module)
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in CRATE_REF.finditer(text):
            to_module = match.group(1)
            if to_module == from_module:
                continue
            counts[(from_module, to_module)] += 1

    # Drop references to modules that don't exist under src/ (e.g. crate::VERSION
    # constants declared directly in lib.rs) so nodes stay meaningful.
    modules_seen_as_target = {to for (_, to) in counts}
    valid_targets = modules | modules_seen_as_target
    # Keep only edges whose target is itself a real top-level module directory/file.
    known_module_names = {owning_module(src_dir, p) for p in src_dir.iterdir()} - {None}
    edges = {
        (frm, to): n
        for (frm, to), n in counts.items()
        if to in known_module_names
    }

    print(f'digraph "{crate_name}_coupling" {{')
    print(f'    label="{crate_name} module coupling (crate:: reference counts)";')
    print('    labelloc="t";')
    print('    rankdir="LR";')
    print('    node [shape=box, fontname="Helvetica"];')
    print('    edge [fontname="Helvetica", fontsize=10];')

    for module in sorted(modules | known_module_names):
        print(f'    "{module}";')

    for (frm, to), n in sorted(edges.items()):
        penwidth = 1 + min(n, 200) ** 0.5 / 2
        print(f'    "{frm}" -> "{to}" [label="{n}", penwidth={penwidth:.2f}];')

    print("}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

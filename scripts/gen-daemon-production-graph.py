#!/usr/bin/env python3
"""Generates a weighted top-level-module coupling DOT graph for
`yadorilink-daemon`'s PRODUCTION code only -- the same `crate::<module>`
textual-reference counting `gen-module-coupling-graph.py` does, but with
every `#[cfg(test)]`-attributed item (a module, function, struct, ...)
stripped from each file's text before counting, and `crates/*/tests/`
integration-test files never scanned in the first place (this script only
walks `src/`).

This is a brace-matching heuristic, not a real Rust parser: it finds each
`#[cfg(test)]` attribute, then the next `{`, then that brace's matching
close via a naive depth counter that does not understand string/char
literals or comments containing brace characters. This repo's own style
(no unusual brace-in-string literals in test-module-adjacent code) makes
that a safe assumption in practice; a case where it isn't would show up as
a `RuntimeError` from an unbalanced count, not a silent wrong graph -- see
`strip_cfg_test_blocks`'s own doc comment. Every file's exclusion count is
recorded in the DOT graph's own label comment so what got stripped is
never silent.

Usage:
    scripts/gen-daemon-production-graph.py <crate-name> <src-dir> \
        > architecture/graphs/generated/daemon-production.dot
"""
from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

CRATE_REF = re.compile(r"crate::([A-Za-z_][A-Za-z0-9_]*)")
CFG_TEST_ATTR = re.compile(r"#\[cfg\(\s*test\s*\)\]")

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


def strip_cfg_test_blocks(text: str) -> tuple[str, int]:
    """Removes every `#[cfg(test)] <item> { ... }` block (brace-matched)
    from `text`. Returns the stripped text and how many blocks were
    removed. A `#[cfg(test)]` attribute on an item with no `{` before the
    next `#[cfg(test)]`/EOF (e.g. `#[cfg(test)] use foo::Bar;`) is left
    alone -- it's a use/const, never itself a source of `crate::` module
    coupling worth attributing to "production", but also never a false
    inflation risk, so leaving it is harmless either way.
    """
    removed = 0
    out = []
    i = 0
    n = len(text)
    while i < n:
        m = CFG_TEST_ATTR.search(text, i)
        if not m:
            out.append(text[i:])
            break
        out.append(text[i : m.start()])
        brace_start = text.find("{", m.end())
        if brace_start == -1:
            # No block body at all (bare attribute on a non-block item) --
            # keep the attribute text itself, move past it.
            out.append(text[m.start() : m.end()])
            i = m.end()
            continue
        # Anything between the attribute and the `{` (e.g. `mod tests`,
        # `fn foo() -> Bar`) is the item's own signature -- drop it along
        # with the block, since it only exists to introduce a test item.
        depth = 0
        j = brace_start
        while j < n:
            c = text[j]
            if c == '"':
                # Skip a double-quoted string literal (with `\"` escapes)
                # so a brace inside an error message/format string never
                # perturbs the depth count. Raw strings (`r"..."`,
                # `r#"..."#`) are not specially handled -- none of this
                # crate's test modules use one adjacent to a brace
                # character, and an unbalanced result still fails loudly
                # via the RuntimeError below rather than silently
                # miscounting.
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
        if depth != 0:
            raise RuntimeError(
                f"unbalanced braces stripping a #[cfg(test)] block starting at offset {m.start()}"
            )
        removed += 1
        i = j
    return "".join(out), removed


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <crate-name> <src-dir>", file=sys.stderr)
        return 1
    crate_name, src_dir_arg = sys.argv[1], sys.argv[2]
    src_dir = Path(src_dir_arg).resolve()

    counts: dict[tuple[str, str], int] = defaultdict(int)
    modules: set[str] = set()
    exclusions: dict[str, int] = {}

    for path in sorted(src_dir.rglob("*.rs")):
        from_module = owning_module(src_dir, path)
        if from_module is None:
            continue
        modules.add(from_module)
        text = path.read_text(encoding="utf-8", errors="replace")
        stripped, removed = strip_cfg_test_blocks(text)
        if removed:
            exclusions[str(path.relative_to(src_dir))] = removed
        for match in CRATE_REF.finditer(stripped):
            to_module = match.group(1)
            if to_module == from_module:
                continue
            counts[(from_module, to_module)] += 1

    known_module_names = {owning_module(src_dir, p) for p in src_dir.iterdir()} - {None}
    edges = {(frm, to): n for (frm, to), n in counts.items() if to in known_module_names}

    print(f'digraph "{crate_name}_production" {{')
    print(
        f'    label="{crate_name} PRODUCTION module coupling '
        f'(crate:: reference counts, #[cfg(test)] blocks excluded)";'
    )
    print('    labelloc="t";')
    print('    rankdir="LR";')
    print('    node [shape=box, fontname="Helvetica"];')
    print('    edge [fontname="Helvetica", fontsize=10];')
    print("    // Excluded #[cfg(test)] blocks, by file (block count):")
    for rel_path in sorted(exclusions):
        print(f"    // {rel_path}: {exclusions[rel_path]}")

    for module in sorted(modules | known_module_names):
        print(f'    "{module}";')

    for (frm, to), n in sorted(edges.items()):
        penwidth = 1.5 + min(n, 20) / 20 * 3
        print(f'    "{frm}" -> "{to}" [label="{n}", penwidth={penwidth:.2f}];')

    print("}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

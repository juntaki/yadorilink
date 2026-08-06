#!/usr/bin/env python3
"""Computes strongly-connected components (Tarjan) over a module coupling
DOT graph (as produced by `gen-daemon-production-graph.py`/
`gen-module-coupling-graph.py`) and emits a condensed DOT graph (one node
per SCC, singleton SCCs kept as themselves) plus a JSON summary and a
handful of per-node "hotspot" subgraphs (a node and its direct
neighbors only).

Usage:
    scripts/gen-scc-condensation.py <commit-sha> <input.dot> \
        --condensed-out <condensed.dot> \
        --summary-out <summary.json> \
        --hotspot node1=<out.dot> [node2=<out.dot> ...]

Output is fully sorted (nodes, edges, SCC members) so re-running against
an unchanged graph never produces a diff; only `<commit-sha>` (passed in
explicitly, never `git rev-parse` run internally -- see the project's own
"no Date.now()-equivalent in generators" convention) varies run to run.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

EDGE_RE = re.compile(r'^\s*"([^"]+)"\s*->\s*"([^"]+)"\s*\[label="(\d+)"')
NODE_RE = re.compile(r'^\s*"([^"]+)"\s*;\s*$')


def parse_dot(path: Path) -> tuple[set[str], list[tuple[str, str, int]]]:
    nodes: set[str] = set()
    edges: list[tuple[str, str, int]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        m = EDGE_RE.match(line)
        if m:
            src, dst, weight = m.group(1), m.group(2), int(m.group(3))
            nodes.add(src)
            nodes.add(dst)
            edges.append((src, dst, weight))
            continue
        m = NODE_RE.match(line)
        if m:
            nodes.add(m.group(1))
    return nodes, edges


def strongly_connected_components(
    nodes: set[str],
    edges: list[tuple[str, str]],
) -> list[list[str]]:
    graph: dict[str, list[str]] = {node: [] for node in nodes}
    for source, target in edges:
        graph.setdefault(source, []).append(target)
        graph.setdefault(target, [])

    index = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[list[str]] = []

    def visit(start: str) -> None:
        nonlocal index
        # Explicit work-stack DFS (not recursion) -- this graph is small
        # today, but a recursive Tarjan on a much larger future module
        # graph risks a real stack overflow; the iterative form costs
        # nothing here and never needs revisiting later.
        call_stack: list[tuple[str, int]] = [(start, 0)]
        while call_stack:
            node, child_idx = call_stack[-1]
            if child_idx == 0:
                indices[node] = index
                lowlinks[node] = index
                index += 1
                stack.append(node)
                on_stack.add(node)
            children = sorted(graph[node])
            if child_idx < len(children):
                call_stack[-1] = (node, child_idx + 1)
                target = children[child_idx]
                if target not in indices:
                    call_stack.append((target, 0))
                elif target in on_stack:
                    lowlinks[node] = min(lowlinks[node], indices[target])
                continue
            call_stack.pop()
            if call_stack:
                parent, _ = call_stack[-1]
                lowlinks[parent] = min(lowlinks[parent], lowlinks[node])
            if lowlinks[node] == indices[node]:
                component: list[str] = []
                while True:
                    member = stack.pop()
                    on_stack.remove(member)
                    component.append(member)
                    if member == node:
                        break
                components.append(sorted(component))

    for node in sorted(graph):
        if node not in indices:
            visit(node)

    return sorted(components, key=lambda component: (-len(component), component))


def write_condensed_dot(
    out_path: Path,
    commit_sha: str,
    nodes: set[str],
    edges: list[tuple[str, str, int]],
    components: list[list[str]],
) -> None:
    member_to_component: dict[str, int] = {}
    for idx, component in enumerate(components):
        for member in component:
            member_to_component[member] = idx

    condensed_edges: dict[tuple[int, int], int] = {}
    for src, dst, weight in edges:
        c_src = member_to_component[src]
        c_dst = member_to_component[dst]
        if c_src == c_dst:
            continue
        key = (c_src, c_dst)
        condensed_edges[key] = condensed_edges.get(key, 0) + weight

    lines = [
        'digraph "daemon_scc_condensed" {',
        f'    label="yadorilink-daemon SCC condensation @ {commit_sha}";',
        '    labelloc="t";',
        '    rankdir="LR";',
        '    node [shape=box, fontname="Helvetica"];',
        '    edge [fontname="Helvetica", fontsize=10];',
    ]
    for idx, component in enumerate(components):
        if len(component) == 1:
            label = component[0]
            color = "black"
        else:
            label = "\\n".join(component)
            color = "red"
        lines.append(f'    "scc{idx}" [label="{label}", color="{color}"];')
    for (c_src, c_dst), weight in sorted(condensed_edges.items()):
        lines.append(f'    "scc{c_src}" -> "scc{c_dst}" [label="{weight}"];')
    lines.append("}")
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_hotspot_dot(
    out_path: Path,
    commit_sha: str,
    center: str,
    nodes: set[str],
    edges: list[tuple[str, str, int]],
) -> None:
    if center not in nodes:
        raise SystemExit(f"hotspot node {center!r} not found in graph")
    neighbors = {
        src if dst == center else dst
        for src, dst, _ in edges
        if src == center or dst == center
    }
    relevant_nodes = {center} | neighbors
    relevant_edges = sorted(
        (src, dst, weight)
        for src, dst, weight in edges
        if src in relevant_nodes and dst in relevant_nodes
    )
    lines = [
        f'digraph "daemon_hotspot_{center}" {{',
        f'    label="yadorilink-daemon hotspot: {center} @ {commit_sha}";',
        '    labelloc="t";',
        '    rankdir="LR";',
        '    node [shape=box, fontname="Helvetica"];',
        '    edge [fontname="Helvetica", fontsize=10];',
    ]
    for node in sorted(relevant_nodes):
        style = ' style="filled", fillcolor="lightyellow"' if node == center else ""
        lines.append(f'    "{node}" [{style}];' if style else f'    "{node}";')
    for src, dst, weight in relevant_edges:
        lines.append(f'    "{src}" -> "{dst}" [label="{weight}"];')
    lines.append("}")
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("commit_sha")
    parser.add_argument("input_dot", type=Path)
    parser.add_argument("--condensed-out", type=Path, required=True)
    parser.add_argument("--summary-out", type=Path, required=True)
    parser.add_argument("--hotspot", action="append", default=[], metavar="NODE=OUT.dot")
    args = parser.parse_args()

    nodes, edges = parse_dot(args.input_dot)
    components = strongly_connected_components(nodes, [(s, d) for s, d, _ in edges])

    write_condensed_dot(args.condensed_out, args.commit_sha, nodes, edges, components)

    fan_in: dict[str, int] = {}
    fan_out: dict[str, int] = {}
    for src, dst, weight in edges:
        fan_out[src] = fan_out.get(src, 0) + 1
        fan_in[dst] = fan_in.get(dst, 0) + 1

    control_socket_to_daemon_state = sum(
        weight for src, dst, weight in edges if src == "control_socket" and dst == "daemon_state"
    )

    summary = {
        "commit": args.commit_sha,
        "nodeCount": len(nodes),
        "edgeCount": len(edges),
        "sccCount": len(components),
        "maxSccSize": max((len(c) for c in components), default=0),
        "maxSccMembers": components[0] if components else [],
        "metrics": {
            "daemonStateFanIn": fan_in.get("daemon_state", 0),
            "daemonStateFanOut": fan_out.get("daemon_state", 0),
            "controlSocketToDaemonStateWeight": control_socket_to_daemon_state,
        },
    }
    args.summary_out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    for spec in args.hotspot:
        node, _, out_path_str = spec.partition("=")
        if not out_path_str:
            print(f"invalid --hotspot spec: {spec!r} (want NODE=OUT.dot)", file=sys.stderr)
            return 1
        write_hotspot_dot(Path(out_path_str), args.commit_sha, node, nodes, edges)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Enforce that Phase 6's capability ports (`yadorilink-sync-core/src/ports/`)
are actually ACTIVATED, not just defined -- the invariant a code review found
missing after an earlier pass added the port traits themselves but left every
consumer holding the old concrete types. Five checks, each independently
disprovable by a self-test case:

1. **`PeerSyncSession` (`peer_session.rs`) and its public wrapper
   (`peer_session_public.rs`) must not declare a struct field of type
   `Arc<SyncState>`, `Arc<PeerChannel>`, or `Arc<dyn BlockStore...>`** -- all
   three are proven port-coercible (`Arc<dyn PeerReplicaStatePort>` /
   `Arc<dyn PeerMessageChannel>` / `Arc<dyn BlockContentStore>`) and have
   real production consumers using the trait-object form. `PeerSyncSession::
   store` used to be a documented exception (three call sites forwarded it
   into `chunker::reconstruct_file`, which was not migrated and needed the
   full trait); that function is now migrated to `&dyn BlockContentStore`
   too, so the exception is gone and this field is checked like the other
   two.

2. **`LocalChangeProcessor` (`local_change.rs`) must not declare a struct
   field of type `Arc<SyncState>` or `Arc<dyn BlockStore...>`** -- unlike
   `PeerSyncSession::store`, both of this consumer's fields are fully
   migrated with no exception.

3. **No setter-replay-after-construction pattern for one-time dependencies**
   -- `PeerSyncSessionDeps::install` (the method that used to replay 9+
   setter calls immediately after a bare constructor) must not exist, and no
   call site may call `.install(&` on a freshly constructed session. A
   regression here means someone reintroduced the "partially-wired session
   escapes its own constructor" gap Commit 06 closed.

4. **Every port trait must have at least one production (non-test) reference
   outside its own defining module** -- catches a port trait becoming
   unused again (e.g. a future refactor accidentally reverting a consumer to
   the concrete type).

5. **`ports/mod.rs` must not carry `#![allow(dead_code)]` or
   `#![allow(unused_imports)]`** -- these were legitimate while no consumer
   existed; now that every port has a real caller, their reappearance is a
   compiler warning being silenced instead of fixed, i.e. a regression
   signal.

Same substring/brace-matching tradeoffs as this repo's other gate scripts in
this family -- not a real Rust parser.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYNC_CORE_SRC = ROOT / "crates/yadorilink-sync-core/src"
PEER_SESSION_RS = SYNC_CORE_SRC / "peer_session.rs"
PEER_SESSION_PUBLIC_RS = SYNC_CORE_SRC / "peer_session_public.rs"
LOCAL_CHANGE_RS = SYNC_CORE_SRC / "local_change.rs"
PORTS_MOD_RS = SYNC_CORE_SRC / "ports/mod.rs"

FORBIDDEN_FIELD_TYPES_PEER_SESSION = ("Arc<SyncState>", "Arc<PeerChannel>", "Arc<dyn BlockStore")
FORBIDDEN_FIELD_TYPES_LOCAL_CHANGE = ("Arc<SyncState>", "Arc<dyn BlockStore")

PORT_TRAITS = (
    "PeerReplicaStatePort",
    "LocalMutationStore",
    "MaterializationStatePort",
    "PeerMessageChannel",
    "BlockContentStore",
    "BlockReclamationStore",
)


def extract_struct_block(text: str, struct_name: str) -> list[str]:
    """The `struct <struct_name> { ... }` block (`pub struct`/`struct`,
    single- or multi-line brace open), brace-matched to its close."""
    lines = text.split("\n")
    pattern = re.compile(rf"^\s*(pub(\(crate\))?\s+)?struct {re.escape(struct_name)}\b")
    start = None
    for i, line in enumerate(lines):
        if pattern.match(line):
            start = i
            break
    if start is None:
        return []
    depth = 0
    end = len(lines)
    started = False
    for i in range(start, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if "{" in lines[i]:
            started = True
        if started and i > start and depth == 0:
            end = i
            break
        if started and i == start and depth == 0:
            end = i
            break
    return lines[start : end + 1]


def field_type_violations(block: list[str], forbidden: tuple[str, ...], label: str) -> list[str]:
    failures = []
    for line in block:
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("///"):
            continue
        for tok in forbidden:
            if tok in line:
                failures.append(f"{label}: struct field declares forbidden type `{tok}`: {stripped}")
    return failures


def violations_peer_session_fields(text: str) -> list[str]:
    block = extract_struct_block(text, "PeerSyncSession")
    if not block:
        return ["peer_session.rs: could not locate `struct PeerSyncSession { ... }`"]
    return field_type_violations(block, FORBIDDEN_FIELD_TYPES_PEER_SESSION, "peer_session.rs::PeerSyncSession")


def violations_peer_session_public_fields(text: str) -> list[str]:
    block = extract_struct_block(text, "PeerSyncSession")
    if not block:
        return ["peer_session_public.rs: could not locate `struct PeerSyncSession { ... }`"]
    return field_type_violations(
        block, FORBIDDEN_FIELD_TYPES_PEER_SESSION, "peer_session_public.rs::PeerSyncSession"
    )


def violations_local_change_fields(text: str) -> list[str]:
    block = extract_struct_block(text, "LocalChangeProcessor")
    if not block:
        return ["local_change.rs: could not locate `struct LocalChangeProcessor { ... }`"]
    return field_type_violations(
        block, FORBIDDEN_FIELD_TYPES_LOCAL_CHANGE, "local_change.rs::LocalChangeProcessor"
    )


def violations_no_setter_replay(peer_session_public_text: str, peer_session_text: str) -> list[str]:
    failures = []
    if re.search(r"fn install\s*\(\s*&self\s*,\s*session\s*:", peer_session_public_text):
        failures.append(
            "peer_session_public.rs: `PeerSyncSessionDeps::install` setter-replay method "
            "has reappeared -- one-time dependencies must be passed to the constructor "
            "directly, not replayed via setters after construction"
        )
    if ".install(&inner)" in peer_session_public_text or ".install(&session)" in peer_session_public_text:
        failures.append(
            "peer_session_public.rs: a call site replays dependencies onto an "
            "already-constructed session via `.install(...)`"
        )
    for name in (
        "set_pending_local_change_flush",
        "set_root_commit_authority_provider",
        "set_change_authenticator",
        "set_handoff_lease_responder",
        "set_rebootstrap_handler",
        "set_block_write_activity_provider",
        "set_handoff_ticket_responder",
        "set_change_emitter",
    ):
        if re.search(rf"fn {name}\s*\(", peer_session_text):
            failures.append(
                f"peer_session.rs: one-time-dependency setter `{name}` has reappeared -- "
                "this capability must be a constructor argument, not a post-construction setter"
            )
    return failures


def violations_port_trait_production_usage(sync_core_src: Path) -> list[str]:
    failures = []
    for trait_name in PORT_TRAITS:
        found_production_use = False
        for path in sync_core_src.rglob("*.rs"):
            if path.name == "mod.rs" and path.parent.name == "ports":
                continue
            if path.parent.name == "ports":
                # Definitions/self-tests inside the ports module itself
                # don't count as "a consumer" -- must be referenced from
                # OUTSIDE the module that defines it.
                continue
            text = path.read_text(encoding="utf-8")
            in_test_module = False
            depth_at_test_start = None
            depth = 0
            for line in text.split("\n"):
                depth += line.count("{") - line.count("}")
                if re.match(r"\s*#\[cfg\(test\)\]", line):
                    in_test_module = "pending"
                    continue
                if in_test_module == "pending" and re.match(r"\s*mod\s+\w+\s*\{", line):
                    in_test_module = True
                    depth_at_test_start = depth
                    continue
                if in_test_module is True and depth_at_test_start is not None and depth < depth_at_test_start:
                    in_test_module = False
                if in_test_module is True:
                    continue
                if trait_name in line:
                    found_production_use = True
                    break
            if found_production_use:
                break
        if not found_production_use:
            failures.append(
                f"ports: `{trait_name}` has no production (non-test) reference outside "
                "its own defining module -- the port is defined but unused again"
            )
    return failures


def violations_ports_mod_allow(text: str) -> list[str]:
    failures = []
    if re.search(r"#!\[allow\([^)]*dead_code", text):
        failures.append("ports/mod.rs: `#![allow(dead_code...)]` has reappeared")
    if re.search(r"#!\[allow\([^)]*unused_imports", text):
        failures.append("ports/mod.rs: `#![allow(unused_imports...)]` has reappeared")
    return failures


def violations() -> list[str]:
    failures: list[str] = []
    if PEER_SESSION_RS.is_file():
        text = PEER_SESSION_RS.read_text(encoding="utf-8")
        failures.extend(violations_peer_session_fields(text))
    if PEER_SESSION_PUBLIC_RS.is_file():
        peer_session_public_text = PEER_SESSION_PUBLIC_RS.read_text(encoding="utf-8")
        failures.extend(violations_peer_session_public_fields(peer_session_public_text))
    else:
        peer_session_public_text = ""
    if LOCAL_CHANGE_RS.is_file():
        failures.extend(violations_local_change_fields(LOCAL_CHANGE_RS.read_text(encoding="utf-8")))
    if PEER_SESSION_RS.is_file() and PEER_SESSION_PUBLIC_RS.is_file():
        failures.extend(
            violations_no_setter_replay(peer_session_public_text, PEER_SESSION_RS.read_text(encoding="utf-8"))
        )
    if SYNC_CORE_SRC.is_dir():
        failures.extend(violations_port_trait_production_usage(SYNC_CORE_SRC))
    if PORTS_MOD_RS.is_file():
        failures.extend(violations_ports_mod_allow(PORTS_MOD_RS.read_text(encoding="utf-8")))
    return failures


def self_test() -> None:
    # Check 1: PeerSyncSession field violations.
    clean = """
pub struct PeerSyncSession {
    channel: Arc<dyn crate::ports::PeerMessageChannel>,
    state: Arc<dyn crate::ports::PeerReplicaStatePort>,
    store: Arc<dyn crate::ports::BlockContentStore>,
}
"""
    assert not violations_peer_session_fields(clean), "a fully migrated PeerSyncSession must pass"

    dirty = clean.replace(
        "state: Arc<dyn crate::ports::PeerReplicaStatePort>,", "state: Arc<SyncState>,"
    )
    found = violations_peer_session_fields(dirty)
    assert any("Arc<SyncState>" in f for f in found), "a concrete Arc<SyncState> field must be flagged"

    dirty_channel = clean.replace(
        "channel: Arc<dyn crate::ports::PeerMessageChannel>,", "channel: Arc<PeerChannel>,"
    )
    found = violations_peer_session_fields(dirty_channel)
    assert any("Arc<PeerChannel>" in f for f in found), "a concrete Arc<PeerChannel> field must be flagged"

    dirty_store = clean.replace(
        "store: Arc<dyn crate::ports::BlockContentStore>,",
        "store: Arc<dyn BlockStore + Send + Sync>,",
    )
    found = violations_peer_session_fields(dirty_store)
    assert any(
        "Arc<dyn BlockStore" in f for f in found
    ), "PeerSyncSession's store field has no exception anymore and must be flagged if concrete"

    # Check 2: LocalChangeProcessor -- store has NO exception here, unlike PeerSyncSession.
    clean_lcp = """
pub struct LocalChangeProcessor {
    state: Arc<dyn crate::ports::LocalMutationStore>,
    store: Arc<dyn crate::ports::BlockContentStore>,
}
"""
    assert not violations_local_change_fields(clean_lcp), "a fully migrated LocalChangeProcessor must pass"

    dirty_lcp = clean_lcp.replace(
        "store: Arc<dyn crate::ports::BlockContentStore>,",
        "store: Arc<dyn BlockStore + Send + Sync>,",
    )
    found = violations_local_change_fields(dirty_lcp)
    assert any(
        "Arc<dyn BlockStore" in f for f in found
    ), "LocalChangeProcessor's store field has no exception and must be flagged if concrete"

    # Check 3: setter-replay pattern.
    clean_wrapper = "impl PeerSyncSessionDeps {\n    pub fn standalone() -> Self { todo!() }\n}\n"
    found = violations_no_setter_replay(clean_wrapper, "impl PeerSyncSession {}\n")
    assert not found, "a wrapper with no install() method must pass"

    dirty_wrapper = "impl PeerSyncSessionDeps {\n    fn install(&self, session: &InnerPeerSyncSession) {}\n}\n"
    found = violations_no_setter_replay(dirty_wrapper, "impl PeerSyncSession {}\n")
    assert any("install" in f for f in found), "a reintroduced install() method must be flagged"

    dirty_setter = "impl PeerSyncSession {\n    pub fn set_change_authenticator(&self, x: Arc<dyn ChangeAuthenticator>) {}\n}\n"
    found = violations_no_setter_replay(clean_wrapper, dirty_setter)
    assert any(
        "set_change_authenticator" in f for f in found
    ), "a reintroduced one-time-dependency setter must be flagged"

    # Check 5: ports/mod.rs allow-attribute regression.
    clean_mod = "//! doc\n\nmod block_store;\n"
    assert not violations_ports_mod_allow(clean_mod), "a clean ports/mod.rs must pass"

    dirty_mod = "//! doc\n#![allow(dead_code, unused_imports)]\n\nmod block_store;\n"
    found = violations_ports_mod_allow(dirty_mod)
    assert len(found) == 2, "both allow(dead_code) and allow(unused_imports) must be flagged"

    # Check 4 is exercised against the real tree in the no-arg run below
    # (it needs real files to walk, self-testing it against fixtures would
    # just re-implement the real port list).


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("sync-core port activation self-test passed")
        return 0

    failures = violations()
    if failures:
        print("sync-core port activation violations:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("sync-core port activation check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

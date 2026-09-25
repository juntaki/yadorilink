#!/usr/bin/env python3
"""Reject compatibility fallbacks that are invalid before the first release.

The check guards exact-generation decisions without banning crash recovery,
retry, journals, audits, retention, or integrity repair.

RESOLVED, and worth reading before touching the schema gate below.
    `resource_lock.rs` used to carry a startup gate
    (`CURRENT_SYNC_SCHEMA_VERSION` / `reject_retired_payloads`) that counted
    rows holding retired version-vector payloads and retired v1
    re-bootstrap snapshots and refused to start. `dccf6059` removed it, and
    that commit's own message says the tree was left "not yet compiling", so
    it was fair to suspect an accidental regression rather than a completed
    consolidation.

    It is not a regression. `index.rs::check_schema_version_supported`
    refuses `on_disk_version > SCHEMA_VERSION` AND
    `on_disk_version != 0 && on_disk_version < SCHEMA_VERSION` -- an exact
    match, with only an unstamped (brand new) database allowed through. That
    subsumes the row-level checks, but only because of TWO decisions
    together: the exact match, and this codebase carrying no cross-version
    data migrations. A database old enough to hold a retired payload
    necessarily carries a stamped version below the current one and is
    refused at open; a database at the current version was created by a
    build that never wrote those payloads, and nothing migrates one into the
    other.

    So the property is still enforced, by a different mechanism, and this
    guard now checks THAT mechanism. If either decision is ever revisited --
    an inexact version check, or a real migration path -- the row-level
    checks stop being redundant and must come back. That is what the entry
    below is watching for.

RESOLVED, and worth reading before touching the ALPN gate below.
    `peer_session_public.rs` (a facade since removed) used to carry its own
    exact-generation preflight:
    a `PROTOCOL_VERSION` constant plus five capability bits, checked against
    the peer's first `ClusterConfig` frame after the QUIC/TLS handshake
    completed. `09477fcf` ("session: fetch and serve blocks on their own
    streams, and stop negotiating") deleted all of it -- the constant, the
    capability fields on the outbound frame, and `validate_exact_peer_config`
    itself (renamed to `validate_peer_handshake`, which now only checks the
    two serve-budget bounds, not a generation).

    It is not a regression. `yadorilink-transport/src/quic_identity.rs`'s
    `YADORILINK_P2P_ALPN` is set as the sole ALPN
    protocol on both the client and server QUIC/TLS configs, so a peer
    advertising a different generation's ALPN string is refused during the
    TLS handshake itself -- strictly before any application frame, including
    the old post-handshake `ClusterConfig` check, could ever exist. That is
    an earlier and equally exact rejection point, not a looser one; the
    generation number lives in the ALPN string, not a separate field, so
    there is nothing left for an app-level equality check to add.
    `quic_peer_identity.rs::a_peer_of_another_generation_is_refused` is a
    dedicated test for exactly this: it constructs a peer whose ALPN differs
    by one byte from `YADORILINK_P2P_ALPN` and asserts the handshake is
    refused.

    So the property is still enforced, by a different (and now watched)
    mechanism. If ALPN is ever no longer generation-specific, or a peer of
    another generation could otherwise reach a running session, the
    app-level check stops being redundant and must come back. That is what
    the entry below is watching for.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN = {
    "crates/yadorilink-daemon/src/device_config.rs": (
        "#[serde(default)]\npub struct DeviceConfig",
        "relay_addr",
    ),
    "crates/yadorilink-ipc-proto/src/lib.rs": (
        "legacy_index_shaped_field",
        "legacy_full_index_and_index_update_bytes_decode_as_an_unset_payload",
    ),
    "coordination-worker/src/db/schema.ts": (
        "assertSchemaNotNewerThanSupported",
        "UnsupportedSchemaDowngradeError",
        "row.version >",
    ),
    # The plane sends these on every netmap push, empty arrays included, so
    # `#[serde(default)]` here would let a truncated or corrupted message
    # apply as "nothing changed" instead of failing the push closed.
    "crates/yadorilink-daemon/src/peer_orchestrator/ws_netmap.rs": (
        '#[serde(default, rename = "groupPolicyLogs")]',
        '#[serde(default, rename = "policyInvalidGroupIds")]',
    ),
    # Post-construction dependency setters, retired when the session's
    # dependencies moved into `PeerSyncSessionDeps` -- see REQUIRED below.
    "crates/yadorilink-peer-session/src/peer_session.rs": (
        "pub fn set_block_serve_engine",
        "pub fn set_headroom_override_bytes",
        "pub fn set_headroom_enforced",
        "pub fn set_maintenance_reconcile_interval",
        "pub fn new_with_dependencies",
        "pub fn new_with_forwarding",
    ),
    # `version_vector.rs` itself was fully deleted (not just emptied) once the
    # authoring-identity migration to change-hash/DAG ancestry completed; see
    # the `RETIRED_FILES_MUST_NOT_EXIST` check below for its replacement.
    "crates/yadorilink-replica-engine/src/rebootstrap_snapshot.rs": (
        "MAX_VERSION_COUNTERS",
        "counter_count",
        "version.counters()",
        'b"YLNKsnp\\x01"',
    ),
}

# Files a completed migration retired outright. Their compatibility fallback
# was "this file no longer exists"; regressing that is exactly what this
# script exists to catch, so their reappearance is itself the forbidden
# marker rather than any string inside them.
RETIRED_FILES_MUST_NOT_EXIST = (
    "crates/yadorilink-sync-core",
    "crates/yadorilink-sync-core/src/version_vector.rs",
    # The facade that wrapped `PeerSyncSession` and forwarded to it. Its
    # dependency setters are what let a session be reconfigured after
    # construction.
    "crates/yadorilink-peer-session/src/peer_session_public.rs",
)

REQUIRED = {
    "coordination-worker/src/db/schema.ts": (
        "assertCurrentSchema",
        "row.version !== CURRENT_SCHEMA_VERSION",
    ),
    # A session's dependencies are fixed when it is constructed, not
    # installed by setters afterwards. This used to be a runtime assertion
    # ("dependencies are immutable after run() starts") in a facade over
    # `PeerSyncSession`; the facade is gone and the property is structural
    # now: one `PeerSyncSessionDeps`, taken by the one constructor. The
    # setters it retired are pinned as FORBIDDEN in `peer_session.rs`.
    "crates/yadorilink-peer-session/src/peer_session/deps.rs": (
        "pub struct PeerSyncSessionDeps",
    ),
    "crates/yadorilink-peer-session/src/peer_session.rs": (
        "pub fn over_substrate(",
        "deps: PeerSyncSessionDeps,",
    ),
    # The exact-generation preflight that `peer_session_public.rs` used to
    # perform after the handshake now happens *during* it -- see the
    # `RESOLVED` note above. This is what actually delivers the property
    # today; watch it, not a post-handshake application check.
    #
    # The generation number in the marker below is expected to move: it is a
    # single pinned literal precisely so that bumping the constant forces a
    # deliberate edit here, rather than letting the ALPN quietly stop being
    # generation-specific. Whoever bumps the constant updates this line in
    # the same change.
    "crates/yadorilink-transport/src/quic_identity.rs": (
        "pub const YADORILINK_P2P_ALPN: &[u8] = b\"yadorilink-p2p/",
        "crypto.alpn_protocols = vec![YADORILINK_P2P_ALPN.to_vec()];",
    ),
    "crates/yadorilink-replica-domain/src/file.rs": (
        # `CurrentFileRecord` was renamed to `FileRecord` once the legacy
        # version-vector-carrying `FileRecord` it disambiguated against was
        # deleted outright, freeing the shorter name.
        "pub struct FileRecord",
        "pub struct FileProjection",
        "pub origin_device_id: String",
        "pub authoring_change_hash: ChangeHash",
    ),
    "crates/yadorilink-sync-sqlite/src/file_index.rs": (
        "invalid authoring_change_hash",
    ),
    # `rebootstrap_snapshot_v2.rs` was folded back into `rebootstrap_snapshot.rs`
    # once it became the sole canonical implementation; the file's own domain
    # tag is what tracks its generation now, not a `_v2`-style filename. The
    # exact tag byte is intentionally NOT pinned here -- it is expected to
    # keep advancing on every incompatible encoding change (see the file's
    # module doc), and a guard that pins the current byte would fail every
    # time that counter is correctly advanced (see the `schema_meta` check
    # below for the same lesson learned the hard way). `check_snapshot_domain_tag`
    # verifies the *shape* of the tag and that it is the sole domain used for
    # both encode and decode instead.
    "crates/yadorilink-replica-engine/src/rebootstrap_snapshot.rs": (
        "out.extend_from_slice(SNAPSHOT_DOMAIN)",
        "reader.expect(SNAPSHOT_DOMAIN)",
        "the retired version-vector section",
    ),
    # The retired-payload rejection that `resource_lock.rs` used to perform
    # row by row now follows from `check_schema_version_supported` refusing
    # any stamped version that is not exactly the current one -- see the
    # module doc. Watch the mechanism that actually delivers it: both halves
    # of the exact match must stay, because dropping the `<` half alone would
    # silently readmit every database old enough to hold a retired payload.
    # Both halves of the exact match must stay. The `!= 0` term is NOT the
    # guarded property -- it is a wart: `user_version == 0` is also what a
    # brand-new file reports, so this function cannot tell one from a
    # database written before stamping existed. `check_replica_schema_
    # generation` is what draws that line, and the replica index opens
    # through it; watch that it keeps doing so.
    "crates/yadorilink-sqlite-runtime/src/schema.rs": (
        "if on_disk_version > SCHEMA_VERSION {",
        "if on_disk_version != 0 && on_disk_version < SCHEMA_VERSION {",
        "pub fn check_replica_schema_generation",
        "if tables > 0 {",
    ),
    "crates/yadorilink-daemon/src/replica_coordinator.rs": (
        "check_replica_schema_generation(conn)?;",
    ),
    # Present AND without `default` -- see the FORBIDDEN entry above.
    "crates/yadorilink-daemon/src/peer_orchestrator/ws_netmap.rs": (
        '#[serde(rename = "groupPolicyLogs")]',
        '#[serde(rename = "policyInvalidGroupIds")]',
    ),
}


# Identifiers a completed retirement removed from EVERY source file. Unlike
# `FORBIDDEN`, these are not tied to one path: the point is that no file
# reintroduces them, including one that does not exist yet.
#
# `wg_public_key` and its wire/config spellings named the WireGuard transport
# key. A device has one key -- its Ed25519 signing key -- and the CLI used to
# send that same key a second time under the retired name purely because the
# coordination plane's column was `NOT NULL`.
#
# `relay_capable` was a per-device flag on a relay-selection path that no
# longer exists; it survived as a column nothing read or wrote.
FORBIDDEN_TREE_WIDE = (
    "wg_public_key",
    "wgPublicKey",
    "wireguard_public_key",
    "wireguardPublicKeyBase64",
    "relay_capable",
    "relayCapable",
    "ChangeBatchFrame",
    "ChangeRequestFrame",
)

TREE_WIDE_ROOTS = ("crates", "coordination-worker/src", "coordination-worker/test",
                   "coordination-worker/migrations")
TREE_WIDE_SUFFIXES = (".rs", ".ts", ".sql", ".proto")


def check_forbidden_tree_wide() -> list[str]:
    """Scan every source file for identifiers a retirement removed outright.

    Skips `target/` and `node_modules/`, and this script itself -- which
    necessarily contains every one of these strings.
    """
    failures: list[str] = []
    for root in TREE_WIDE_ROOTS:
        base = ROOT / root
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix not in TREE_WIDE_SUFFIXES:
                continue
            parts = path.parts
            if "target" in parts or "node_modules" in parts:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for needle in FORBIDDEN_TREE_WIDE:
                if needle in text:
                    rel = path.relative_to(ROOT)
                    failures.append(
                        f"{rel}: retired identifier reintroduced: {needle!r}"
                    )
    return failures


SNAPSHOT_DOMAIN_RE = re.compile(
    r'const SNAPSHOT_DOMAIN: &\[u8; 8\] = b"YLNKsnp\\x[0-9a-fA-F]{2}";'
)


def check_snapshot_domain_tag() -> list[str]:
    """Verify the re-bootstrap snapshot format still declares exactly one
    domain tag, used symmetrically for encode and decode.

    Deliberately does NOT pin the tag's current byte: that byte is meant to
    keep advancing every time the encoding changes incompatibly (see the
    file's own module doc), so pinning it here would make this guard fail on
    every legitimate advance -- the same mistake the `schema_meta` check used
    to make (see `check_schema_meta_initialization`).
    """
    relative_path = "crates/yadorilink-replica-engine/src/rebootstrap_snapshot.rs"
    path = ROOT / relative_path
    if not path.exists():
        return [f"missing required exact-generation file: {relative_path}"]
    text = path.read_text(encoding="utf-8")
    if not SNAPSHOT_DOMAIN_RE.search(text):
        return [
            f"{relative_path}: no single `SNAPSHOT_DOMAIN: &[u8; 8] = b\"YLNKsnp\\xNN\"` "
            "constant found (an exact-generation domain tag is required)"
        ]
    return []


SCHEMA_META_INSERT_RE = re.compile(
    r"INSERT INTO schema_meta \(id, version\) VALUES \(1, (\d+)\);"
)
CURRENT_SCHEMA_VERSION_RE = re.compile(r"CURRENT_SCHEMA_VERSION\s*=\s*(\d+)")


def check_schema_meta_initialization() -> list[str]:
    """Verify the canonical D1 schema initializes `schema_meta`, and that the
    version it stamps agrees with `coordination-worker/src/db/schema.ts`'s
    `CURRENT_SCHEMA_VERSION`.

    Deliberately does NOT pin the literal current version number: that number
    is a generation counter this same script's own `REQUIRED`/`FORBIDDEN`
    tables exist to let advance freely pre-release. A check that hard-codes
    the current value of the counter it is guarding fails every time that
    counter is correctly advanced -- it must check the *property* (schema_meta
    is initialized, and the two sides agree), not a pinned literal.
    """
    failures: list[str] = []
    baseline = ROOT / "coordination-worker/migrations/0001_initial.sql"
    schema_ts = ROOT / "coordination-worker/src/db/schema.ts"

    if not baseline.exists():
        return failures

    baseline_text = baseline.read_text(encoding="utf-8")
    baseline_match = SCHEMA_META_INSERT_RE.search(baseline_text)
    if not baseline_match:
        failures.append("canonical D1 schema does not initialize schema_meta")
        return failures

    if not schema_ts.exists():
        return failures

    schema_ts_text = schema_ts.read_text(encoding="utf-8")
    schema_ts_match = CURRENT_SCHEMA_VERSION_RE.search(schema_ts_text)
    if not schema_ts_match:
        failures.append(
            "coordination-worker/src/db/schema.ts does not define CURRENT_SCHEMA_VERSION"
        )
        return failures

    baseline_version = int(baseline_match.group(1))
    schema_ts_version = int(schema_ts_match.group(1))
    if baseline_version != schema_ts_version:
        failures.append(
            "canonical D1 schema initializes schema_meta at version "
            f"{baseline_version}, but coordination-worker/src/db/schema.ts's "
            f"CURRENT_SCHEMA_VERSION is {schema_ts_version}"
        )
    return failures


def main() -> int:
    failures: list[str] = []

    for relative_path, needles in FORBIDDEN.items():
        path = ROOT / relative_path
        if not path.exists():
            # The coordination service is not part of every checkout; its
            # markers are validated only where its sources are present.
            if relative_path.startswith("coordination-worker/"):
                continue
            failures.append(f"missing guarded file: {relative_path}")
            continue
        text = path.read_text(encoding="utf-8")
        for needle in needles:
            if needle in text:
                failures.append(
                    f"{relative_path}: forbidden compatibility fallback marker: {needle!r}"
                )

    for relative_path, needles in REQUIRED.items():
        path = ROOT / relative_path
        if not path.exists():
            if relative_path.startswith("coordination-worker/"):
                continue
            failures.append(f"missing required exact-generation file: {relative_path}")
            continue
        text = path.read_text(encoding="utf-8")
        for needle in needles:
            if needle not in text:
                failures.append(
                    f"{relative_path}: missing exact-generation marker: {needle!r}"
                )

    failures.extend(check_forbidden_tree_wide())

    for relative_path in RETIRED_FILES_MUST_NOT_EXIST:
        if (ROOT / relative_path).exists():
            failures.append(f"retired file still exists: {relative_path}")

    failures.extend(check_snapshot_domain_tag())

    coordination_root = ROOT / "coordination-worker"
    if coordination_root.exists():
        migrations = sorted((coordination_root / "migrations").glob("*.sql"))
        migration_names = [path.name for path in migrations]
        if migration_names != ["0001_initial.sql"]:
            failures.append(
                "coordination-worker/migrations: expected only canonical 0001_initial.sql, "
                f"found {migration_names!r}"
            )

    failures.extend(check_schema_meta_initialization())

    if failures:
        print("pre-release compatibility debt check failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print("pre-release compatibility debt check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

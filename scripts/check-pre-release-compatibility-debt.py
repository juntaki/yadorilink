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
    "crates/yadorilink-sync-core/src/lib.rs": (
        '#[path = "peer_session.rs"]\npub mod peer_session;',
    ),
    # `version_vector.rs` itself was fully deleted (not just emptied) once the
    # authoring-identity migration to change-hash/DAG ancestry completed; see
    # the `RETIRED_FILES_MUST_NOT_EXIST` check below for its replacement.
    "crates/yadorilink-sync-core/src/rebootstrap_snapshot.rs": (
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
    "crates/yadorilink-sync-core/src/version_vector.rs",
)

REQUIRED = {
    "coordination-worker/src/db/schema.ts": (
        "assertCurrentSchema",
        "row.version !== CURRENT_SCHEMA_VERSION",
    ),
    "crates/yadorilink-sync-core/src/peer_session_public.rs": (
        "pub struct PeerSyncSessionDeps",
        "pub fn new_with_dependencies",
        # Not a pinned literal: an earlier attempt hard-coded this generation
        # number as its own wrapper-only constant (`= 3`) and had to be
        # reverted (`fix: keep exact handshake generation consistent with
        # session wire`) because a wrapper-only generation is
        # self-contradictory -- the inner session re-announces its own
        # `ClusterConfig` after this preflight. The property that matters is
        # that the public wrapper never diverges from the inner
        # implementation's own generation constant.
        "pub const PROTOCOL_VERSION: u32 = InnerPeerSyncSession::PROTOCOL_VERSION;",
        "exact_generation_preflight",
        "dependencies are immutable after run() starts",
        "config.protocol_version == Self::PROTOCOL_VERSION",
    ),
    "crates/yadorilink-sync-core/src/types.rs": (
        # `CurrentFileRecord` was renamed to `FileRecord` once the legacy
        # version-vector-carrying `FileRecord` it disambiguated against was
        # deleted outright, freeing the shorter name.
        "pub struct FileRecord",
        "pub struct FileProjection",
        "impl TryFrom<proto::FileInfo> for FileProjection",
        "missing origin_device_id",
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
    "crates/yadorilink-sync-core/src/rebootstrap_snapshot.rs": (
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
    "crates/yadorilink-sync-core/src/index.rs": (
        "if on_disk_version > SCHEMA_VERSION {",
        "if on_disk_version != 0 && on_disk_version < SCHEMA_VERSION {",
    ),
}


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
    relative_path = "crates/yadorilink-sync-core/src/rebootstrap_snapshot.rs"
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
            failures.append(f"missing required exact-generation file: {relative_path}")
            continue
        text = path.read_text(encoding="utf-8")
        for needle in needles:
            if needle not in text:
                failures.append(
                    f"{relative_path}: missing exact-generation marker: {needle!r}"
                )

    for relative_path in RETIRED_FILES_MUST_NOT_EXIST:
        if (ROOT / relative_path).exists():
            failures.append(f"retired file still exists: {relative_path}")

    failures.extend(check_snapshot_domain_tag())

    migrations = sorted((ROOT / "coordination-worker/migrations").glob("*.sql"))
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

#!/usr/bin/env bash
#
# Residual-symbol guard for the simplified peer-to-peer product surface.
#
# Several advanced features were removed to keep the product to a small set of
# concepts (account, device, synced folder, and two storage modes) — folders
# sync across a single account's own devices only. This script fails if any of
# those removed features' active-use
# symbols reappear in shippable code, protocol definitions, the CLI, the
# desktop app, or non-archived docs — so a feature deleted in one change cannot
# be silently reintroduced by a later one. It is meant to run in CI as a
# required check.
#
# What counts as a violation is *active use* (a type, function, field, or
# column that only exists when the feature is present). Legitimate
# documentation of a removal is intentionally NOT a violation and is filtered
# out:
#   - protobuf `reserved` field-number/name declarations (they prevent reuse;
#     reintroducing a reserved field number is itself a compile error),
#   - SQL `DROP` statements and the dedicated `*_drop_*` removal migrations
#     (append-only D1 history: a column created by the initial migration and
#     later dropped is proven-removed, not reintroduced — see the positive
#     drop-migration assertions at the end),
#   - the dedicated removal-guard test that lists forbidden symbols as data.
#
# Excluded from the scan: the VCS/build/dependency trees, lock files, the
# archived internal planning-document history, and this script's own term
# list -- planning documents necessarily name the features they describe
# removing, so referencing a removed feature there is not itself a
# violation.

set -euo pipefail

cd "$(dirname "$0")/.."

# Shippable surfaces the guard scans for active-use residual symbols.
ROOTS=(
  crates
  coordination-worker/src
  coordination-worker/test
  oss-public
  docs
)

# Lines that document a removal rather than reintroduce a feature. Filtered out
# before a match is treated as a violation:
#   - protobuf `reserved` declarations and SQL `DROP` statements,
#   - comment-only lines (Rust `//` `///` `//!`, block-comment `*`
#     continuations, SQL `--`) — a symbol that appears only in a comment (e.g.
#     "Field 4 was `storage_only`, removed") documents the removal and is not
#     active use.
ALLOWED_DOC_LINES='reserved |reserved"|DROP COLUMN|DROP TABLE|drop column|drop table'
COMMENT_ONLY_LINE='^[[:space:]]*(//|/\*|\*|--)'
# Files that are themselves removal enforcement (their term lists name the
# removed symbols as data, not as active use).
GUARD_FILES='check_removed_features\.sh|recovery_model\.rs'

# Each entry: "<feature label>|<space-separated active-use symbols>".
# Symbols are word-matched (grep -w), so bare prose like "the removed
# introducer flow" does not match snake_case / CamelCase identifiers.
#
# Two of the relay symbols the removal spec lists are deliberately omitted
# because they are ambiguous in this codebase and would only ever match
# legitimate code: `relayed` is a plain English word (a change is "relayed"
# peer-to-peer; XPC-relayed bytes), and the sole remaining `relay_addr` use is
# the back-compat handler that detects and warns about a stale `device.json`
# key — the opposite of reintroducing the relay. The unambiguous data-path
# types below (`RelayHub`, `RelayClient`, `relay_server`, `TransportMode::Relay`,
# `PathKind::Relay`) are what actually guard against the relay returning.
FEATURES=(
  "operator relay data path|relay_server RelayHub RelayClient TransportMode::Relay PathKind::Relay"
  "untrusted storage-only peer|StorageOnly storage_only require_storage_only"
  "share access roles|ShareRole share_role AccessRole"
  "directional sync modes|ReceiveOnly SendOnly receive_only send_only SyncDirection out_of_sync_count receive_only_changed_count"
  "device introduction / introducer|Introducer introduce_device introducer_device introducer_device_id IntroductionRequest is_introducer device_introductions"
  "gRPC coordination server|GrpcCoordination coordination_server http-coordination"
  "legacy password / key-bundle auth|export_key_bundle import_key_bundle KeyBundle derive_bundle_key recovery_bundle"
  "cross-account folder sharing|createShareInvite acceptShareInvite revokeSharePartner addFolderSharePartner isFolderSharePartner listFolderSharePartners removeFolderSharePartnerCascade insertInvite findInviteByCodeHash tryConsumeInvite markInviteConsumed countInvitesCreatedSince listInvitesCreatedByUser enforceInviteRateQuota InviteRow FolderSharePartnerRow folder_share_partners"
)

# Drop migrations that must remain present: they are the append-only proof that
# the corresponding D1 schema columns/tables are removed, not just absent from
# a fresh database.
REQUIRED_DROP_MIGRATIONS=(
  coordination-worker/migrations/0008_drop_storage_only.sql
  coordination-worker/migrations/0009_drop_device_introduction.sql
  coordination-worker/migrations/0012_remove_cross_account_sharing.sql
)

fail=0

echo "Scanning shippable surfaces for removed-feature symbols..."
for entry in "${FEATURES[@]}"; do
  label="${entry%%|*}"
  symbols="${entry#*|}"
  for sym in $symbols; do
    # -w so `storage_only` does not match e.g. `not_storage_only_ever`; the
    # `::` symbols contain no word chars at the boundary and match literally.
    # grep -rInw prefixes each hit as `path:line:content`; strip that prefix
    # before testing the comment-only pattern so a `path//...` never confuses it.
    if hits=$(grep -rInw "${ROOTS[@]}" -e "$sym" 2>/dev/null \
        | grep -vE "$ALLOWED_DOC_LINES" \
        | grep -vE "$GUARD_FILES" \
        | grep -vE ":[0-9]+:${COMMENT_ONLY_LINE#^}"); then
      if [ -n "$hits" ]; then
        echo
        echo "VIOLATION [$label]: removed symbol \`$sym\` is still used:"
        echo "$hits" | sed 's/^/  /'
        fail=1
      fi
    fi
  done
done

echo
echo "Verifying schema-removal migrations are present..."
for mig in "${REQUIRED_DROP_MIGRATIONS[@]}"; do
  if [ ! -f "$mig" ]; then
    echo "VIOLATION: missing schema-removal migration \`$mig\`"
    fail=1
  fi
done

echo
if [ "$fail" -ne 0 ]; then
  echo "check_removed_features: FAILED — a removed feature's symbols are present."
  exit 1
fi
echo "check_removed_features: OK — no residual removed-feature symbols."

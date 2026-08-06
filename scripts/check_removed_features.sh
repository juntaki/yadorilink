#!/usr/bin/env bash
#
# Residual-symbol guard for the simplified peer-to-peer product surface.
#
# Several advanced features were removed to keep the product to a small set of
# concepts (account, device, synced folder, and two storage modes) — folders
# sync across a single account's own devices only. This script fails if any of
# those removed features' active-use symbols reappear in shippable code,
# protocol definitions, the CLI, the desktop app, or non-archived docs.
#
# Pre-release policy: migration history is not itself a compatibility boundary.
# Removed development-only tables/columns should be folded out of the canonical
# fresh schema, not kept alive by requiring historical migration files that add
# a column and later drop it again. Therefore this guard checks active product
# symbols only; it does not require old removal migrations to remain present.
#
# What counts as a violation is *active use* (a type, function, field, or column
# that only exists when the feature is present). Legitimate documentation of a
# removal is intentionally NOT a violation and is filtered out:
#   - protobuf `reserved` field-number/name declarations (they prevent reuse),
#   - SQL `DROP` statements in any still-relevant migration,
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
#     continuations, SQL `--`) — a symbol that appears only in a comment
#     documents the removal and is not active use.
ALLOWED_DOC_LINES='reserved |reserved"|DROP COLUMN|DROP TABLE|drop column|drop table'
COMMENT_ONLY_LINE='^[[:space:]]*(//|/\*|\*|--)'
# Files that are themselves removal enforcement (their term lists name the
# removed symbols as data, not as active use).
GUARD_FILES='check_removed_features\.sh|recovery_model\.rs'

# Each entry: "<feature label>|<space-separated active-use symbols>".
# Symbols are word-matched (grep -w), so bare prose does not match snake_case /
# CamelCase identifiers.
FEATURES=(
  "operator relay data path|relay_server RelayHub RelayClient TransportMode::Relay PathKind::Relay relay_addr warn_once_about_ignored_relay_addr"
  "untrusted storage-only peer|StorageOnly storage_only require_storage_only"
  "share access roles|ShareRole share_role AccessRole"
  "directional sync modes|ReceiveOnly SendOnly receive_only send_only SyncDirection out_of_sync_count receive_only_changed_count"
  "device introduction / introducer|Introducer introduce_device introducer_device introducer_device_id IntroductionRequest is_introducer device_introductions"
  "gRPC coordination server|GrpcCoordination coordination_server http-coordination"
  "legacy password / key-bundle auth|export_key_bundle import_key_bundle KeyBundle derive_bundle_key recovery_bundle"
  "cross-account folder sharing|createShareInvite acceptShareInvite revokeSharePartner addFolderSharePartner isFolderSharePartner listFolderSharePartners removeFolderSharePartnerCascade insertInvite findInviteByCodeHash tryConsumeInvite markInviteConsumed countInvitesCreatedSince listInvitesCreatedByUser enforceInviteRateQuota InviteRow FolderSharePartnerRow folder_share_partners"
)

fail=0

echo "Scanning shippable surfaces for removed-feature symbols..."
for entry in "${FEATURES[@]}"; do
  label="${entry%%|*}"
  symbols="${entry#*|}"
  for sym in $symbols; do
    # -w so `storage_only` does not match e.g. `not_storage_only_ever`; the
    # `::` symbols contain no word chars at the boundary and match literally.
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
if [ "$fail" -ne 0 ]; then
  echo "check_removed_features: FAILED — a removed feature's symbols are present."
  exit 1
fi
echo "check_removed_features: OK — no residual removed-feature symbols."

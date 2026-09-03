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
  # `relay_addr` was in this list and does not belong: the removed feature is
  # the OPERATOR-run relay server, while the peer relay is a kept feature, so
  # the bare identifier recurs legitimately. It matched nothing but a
  # test-local binding in relay_forwarder.rs. The specific removed symbol,
  # warn_once_about_ignored_relay_addr, stays and is correctly absent.
  "operator relay data path|relay_server RelayHub RelayClient TransportMode::Relay PathKind::Relay warn_once_about_ignored_relay_addr"
  "untrusted storage-only peer|StorageOnly storage_only require_storage_only"
  "share access roles|ShareRole share_role AccessRole"
  "directional sync modes|ReceiveOnly SendOnly receive_only send_only SyncDirection out_of_sync_count receive_only_changed_count"
  "device introduction / introducer|Introducer introduce_device introducer_device introducer_device_id IntroductionRequest is_introducer device_introductions"
  "gRPC coordination server|GrpcCoordination coordination_server http-coordination"
  "legacy password / key-bundle auth|export_key_bundle import_key_bundle KeyBundle derive_bundle_key recovery_bundle"
  "cross-account folder sharing|createShareInvite acceptShareInvite revokeSharePartner addFolderSharePartner isFolderSharePartner listFolderSharePartners removeFolderSharePartnerCascade insertInvite findInviteByCodeHash tryConsumeInvite markInviteConsumed countInvitesCreatedSince listInvitesCreatedByUser enforceInviteRateQuota InviteRow FolderSharePartnerRow folder_share_partners"
)

# ---------------------------------------------------------------------------
# Transport consolidation (Phase A): the machinery QUIC replaced.
#
# Scanned over CODE ONLY, not docs. The list above is about product features,
# which design documents describe in prose; this list is about deleted
# implementation types, and the documents that record why they were deleted
# necessarily name them. Excluding Markdown is what lets those documents stay
# honest instead of being edited around a grep.
CODE_ROOTS=(
  crates
  coordination-worker/src
  oss-public
)
CODE_EXCLUDE='\.(md|txt):[0-9]+:'

# Each entry: "<label>|<symbols>". These are the types deleted when the
# bespoke reliability, framing, WireGuard and bulk-selector layers were
# replaced by QUIC. Reintroducing one means reintroducing a state machine
# QUIC already implements.
TRANSPORT_REMOVED=(
  "custom ARQ / retransmission|ReliableSend ReliableRecv RttEstimator RttState UnackedEntry RetransmitOutcome DecodedFrame"
  "custom fragmentation / framing|Reassembler PartialMessage fragment_message build_fragment wrap_ipv unwrap_ipv"
  "WireGuard transport|WgTunnel WireGuardEngine tunn_wrapper X25519"
  "bulk transport selector|BulkDataPlane BulkConnection BulkQuicError bulk_transport_config"
  # `chunk_offset`/`total_size` are deliberately NOT listed here: both
  # collide with unrelated live identifiers elsewhere (e.g.
  # multi_peer_hydration.rs's own `total_size` fixture field), and the
  # specific BlockReplyFound-shape regression they used to guard is already
  # pinned by stage2_block_serve_contract.rs, which checks the real message
  # shape rather than a bare grep. `reliable_enabled`/`enable_reliable_delivery`/
  # `supports_reliable_delivery` are also left out: the wire field is already
  # `reserved` in sync.proto, which this guard's own ALLOWED_DOC_LINES
  # filter would exempt, so the pattern buys nothing a bare `reserved` grep
  # doesn't already assert once, more precisely, in the schema.
  "inline block-reply chunking|PartialBlockReply MAX_BLOCK_REPLY_CHUNK_BYTES"
)

# Each entry: "<label>|<symbols>". Rejected storage-backend prototypes --
# evaluated and explicitly turned down (see docs/design/
# phase-c-packstore-characterization.md's own "Recommendation" section),
# never shipped, no fallback/shim/feature-flag retained on removal (Phase
# D1R). Reintroducing one of these symbols without new evidence re-opens
# a question this project already closed.
STORAGE_REMOVED=(
  "rejected packed block-store prototype|PackStore enable_packed_bulk_ingest packed_store packed_bulk"
)

# Verification bypasses. These are not merely dead code: nothing above the
# transport encrypts file content, so a config that skips peer verification
# puts plaintext on the wire. `with_no_client_auth` additionally contradicts
# the mandatory-mutual-auth invariant -- a QUIC server that does not demand a
# client certificate cannot know which device it is serving.
#
# One deliberate exception, named rather than pattern-matched, so that adding
# another requires editing this line: the socket-bridge test builds an
# unauthenticated endpoint pair to exercise the AsyncUdpSocket shim itself.
FORBIDDEN_TLS='SkipServerVerification with_no_client_auth dangerous_configuration'
TLS_EXCEPTIONS='crates/yadorilink-transport/tests/quic_socket_bridge\.rs'

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

echo "Scanning code surfaces for consolidated-away transport machinery..."
for entry in "${TRANSPORT_REMOVED[@]}"; do
  label="${entry%%|*}"
  symbols="${entry#*|}"
  for sym in $symbols; do
    if hits=$(grep -rInw "${CODE_ROOTS[@]}" -e "$sym" 2>/dev/null \
        | grep -vE "$CODE_EXCLUDE" \
        | grep -vE "$GUARD_FILES" \
        | grep -vE ":[0-9]+:${COMMENT_ONLY_LINE#^}"); then
      if [ -n "$hits" ]; then
        echo
        echo "VIOLATION [$label]: consolidated-away symbol \`$sym\` is back:"
        echo "$hits" | sed 's/^/  /'
        fail=1
      fi
    fi
  done
done

echo "Scanning code surfaces for rejected storage-backend prototypes..."
for entry in "${STORAGE_REMOVED[@]}"; do
  label="${entry%%|*}"
  symbols="${entry#*|}"
  for sym in $symbols; do
    if hits=$(grep -rInw "${CODE_ROOTS[@]}" -e "$sym" 2>/dev/null \
        | grep -vE "$CODE_EXCLUDE" \
        | grep -vE "$GUARD_FILES" \
        | grep -vE ":[0-9]+:${COMMENT_ONLY_LINE#^}"); then
      if [ -n "$hits" ]; then
        echo
        echo "VIOLATION [$label]: rejected symbol \`$sym\` is back:"
        echo "$hits" | sed 's/^/  /'
        fail=1
      fi
    fi
  done
done

echo
echo "Scanning code surfaces for TLS verification bypasses..."
for sym in $FORBIDDEN_TLS; do
  if hits=$(grep -rInw "${CODE_ROOTS[@]}" -e "$sym" 2>/dev/null \
      | grep -vE "$CODE_EXCLUDE" \
      | grep -vE "$GUARD_FILES" \
      | grep -vE "$TLS_EXCEPTIONS" \
      | grep -vE ":[0-9]+:${COMMENT_ONLY_LINE#^}"); then
    if [ -n "$hits" ]; then
      echo
      echo "VIOLATION [TLS verification bypass]: \`$sym\` appears outside the"
      echo "named exception. Nothing above the transport encrypts file content,"
      echo "so this puts plaintext on the wire:"
      echo "$hits" | sed 's/^/  /'
      fail=1
    fi
  fi
done

echo
if [ "$fail" -ne 0 ]; then
  echo "check_removed_features: FAILED — a removed feature's symbols are present."
  exit 1
fi
echo "check_removed_features: OK — no residual removed-feature symbols."

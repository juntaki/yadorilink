use super::*;

const ALL: [AttentionItem; 23] = [
    AttentionItem::FolderStopped,
    AttentionItem::LinkedTwice,
    AttentionItem::OwnershipLost,
    AttentionItem::VolumeChanged,
    AttentionItem::NoSafeCopy,
    AttentionItem::SafeCopyUnconfirmed,
    AttentionItem::ContentUnavailable,
    AttentionItem::ContentAvailabilityUnknown,
    AttentionItem::ConflictNeedsReview,
    AttentionItem::FileHeld,
    AttentionItem::UnsupportedFilename,
    AttentionItem::FileNotReadable,
    AttentionItem::StrandedDirectory,
    AttentionItem::ProviderNotReady,
    AttentionItem::ProviderFilesFailing,
    AttentionItem::EditsKeptBeside,
    AttentionItem::ProviderOrphan,
    AttentionItem::DiskFull,
    AttentionItem::DiskLow,
    AttentionItem::PeerUnavailable,
    AttentionItem::RetryableFailure,
    AttentionItem::UpdateFailed,
    AttentionItem::Unrecognized,
];

#[test]
fn keys_are_unique_snake_case() {
    let mut seen = std::collections::HashSet::new();
    for item in ALL {
        assert!(seen.insert(item.key()), "duplicate {}", item.key());
        assert!(item.key().bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
    }
}

#[test]
fn every_rollup_code_the_daemon_emits_is_recognized() {
    for raw in [
        "degraded:g",
        "ambiguous:g",
        "ownership_lost:g",
        "volume_changed:g",
        "durability_at_risk:g",
        "durability_unknown:g",
        "fetch_unavailable:g",
        "fetch_availability_unknown:g",
        "conflict:g",
        "conflict_pending:g",
        "held:g",
        "stranded_directory:g",
        "provider_not_ready:r",
        "provider_not_ready:removals",
        "provider_stuck:r",
        "kept_edits:r",
        "provider_orphan_domain:d",
        "low_disk_critical:/p",
        "low_disk:/p",
        "peer_disconnected:dev",
        "recent_error:cat",
        "update_failed:cat",
    ] {
        assert_ne!(Attention::from_reason(raw).item, AttentionItem::Unrecognized, "{raw}");
    }
}

#[test]
fn scope_is_the_reported_subject() {
    let a = Attention::from_reason("low_disk:/data:x");
    assert_eq!(a.item, AttentionItem::DiskLow);
    assert_eq!(a.scope, AttentionScope::Volume("/data:x".into()));
    assert_eq!(
        Attention::from_reason("conflict_pending:g1").scope,
        AttentionScope::Folder("g1".into())
    );
    assert_eq!(
        Attention::from_reason("peer_disconnected:d1").scope,
        AttentionScope::Device("d1".into())
    );
    assert_eq!(Attention::from_reason("recent_error:cat").scope, AttentionScope::General);
}

#[test]
fn an_unknown_code_is_unrecognized_and_offers_details() {
    let a = Attention::from_reason("brand_new:x");
    assert_eq!(a.item, AttentionItem::Unrecognized);
    assert_eq!(a.item.primary_action(), ProductAction::ViewDetails);
}

#[test]
fn held_reasons_read_their_code_before_the_detail() {
    for raw in [
        "case_collision: collides with 'A'",
        "invalid_name: bad",
        "normalization_collision",
        "case_and_normalization_collision",
    ] {
        assert_eq!(Attention::from_held_reason(raw).item, AttentionItem::UnsupportedFilename);
    }
    assert_eq!(
        Attention::from_held_reason("metadata_unprovable: x").item,
        AttentionItem::FileNotReadable
    );
    assert_eq!(Attention::from_held_reason("other").item, AttentionItem::FileHeld);
}

#[test]
fn actions_follow_the_kind() {
    assert_eq!(AttentionItem::DiskLow.primary_action(), ProductAction::FreeUpSpace);
    assert_eq!(AttentionItem::ConflictNeedsReview.primary_action(), ProductAction::ReviewConflict);
    assert_eq!(AttentionItem::PeerUnavailable.kind(), AttentionKind::Waiting);
    assert_eq!(AttentionItem::RetryableFailure.kind(), AttentionKind::Retryable);
    assert_eq!(
        AttentionItem::RetryableFailure.secondary_action(),
        Some(ProductAction::ViewDetails)
    );
    assert_eq!(AttentionItem::DiskLow.secondary_action(), None);
}

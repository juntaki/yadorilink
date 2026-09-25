#![cfg(test)]

use super::Lane;

#[test]
fn tags_round_trip_and_are_distinct() {
    let mut seen = Vec::new();
    for lane in Lane::ALL {
        let tag = lane.tag();
        assert!(!seen.contains(&tag), "duplicate lane tag {tag}");
        seen.push(tag);
        assert_eq!(Lane::from_tag(tag), Some(lane));
    }
}

#[test]
fn reconciliation_is_never_subject_to_a_concurrency_budget() {
    let limits = super::LaneLimits::default();
    assert_eq!(limits.for_lane(Lane::Reconciliation), None);
    assert_eq!(limits.for_lane(Lane::History), Some(limits.history));
    assert_eq!(limits.for_lane(Lane::Block), Some(limits.block));
    assert_eq!(limits.for_lane(Lane::Service), Some(limits.service));
}

#[test]
fn history_stream_kinds_round_trip_and_reject_the_unknown() {
    use super::HistoryStreamKind;
    for kind in [HistoryStreamKind::ProofBundle, HistoryStreamKind::RebootstrapSnapshot] {
        assert_eq!(HistoryStreamKind::from_tag(kind.tag()), Some(kind));
    }
    assert_eq!(HistoryStreamKind::from_tag(0), None);
    assert_eq!(HistoryStreamKind::from_tag(3), None);
}

#[test]
fn unknown_tag_is_rejected_not_guessed() {
    assert_eq!(Lane::from_tag(0), None);
    assert_eq!(Lane::from_tag(5), None);
    assert_eq!(Lane::from_tag(u8::MAX), None);
}

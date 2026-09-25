#![cfg(test)]

use super::*;
use yadorilink_ipc_proto::daemonctl::{
    RewindActionCounts as WireRewindActionCounts, RewindPathEntry as WireRewindPathEntry,
    RewindRenameCandidate as WireRewindRenameCandidate,
};

fn entry(path: &str, action: &str, reason: Option<&str>) -> WireRewindPathEntry {
    WireRewindPathEntry {
        path: path.to_string(),
        action: action.to_string(),
        to_version_seq: None,
        from_version_seq: None,
        unavailable_reason: reason.map(str::to_string),
    }
}

/// The verbose-mode shape: every path listed, and the counts (which
/// the daemon always computes over the whole plan) agreeing with them.
fn sample_plan() -> RewindPreviewResponse {
    RewindPreviewResponse {
        group_id: "g".to_string(),
        target_unix_nanos: 1_750_000_000_000_000_000,
        entries: vec![
            entry("a.txt", "create", None),
            entry("b.txt", "delete", None),
            entry("c.txt", "replace", None),
            entry("d.txt", "unchanged", None),
            entry("e.txt", "unavailable", Some("expired by retention")),
        ],
        rename_candidates: vec![WireRewindRenameCandidate {
            from_path: "b.txt".to_string(),
            to_path: "a.txt".to_string(),
        }],
        counts: Some(WireRewindActionCounts {
            create: 1,
            delete: 1,
            replace: 1,
            unchanged: 1,
            unavailable: 1,
        }),
        total_entry_count: 5,
        total_rename_candidate_count: 1,
        listing_truncated: false,
    }
}

#[test]
fn summary_mode_reports_every_action_count_and_the_rename_list() {
    let rendered = format_rewind_plan(&sample_plan(), false);
    assert!(rendered.contains("1 to create, 1 to delete, 1 to replace"));
    assert!(rendered.contains("1 unchanged, 1 unavailable"));
    assert!(rendered.contains("b.txt -> a.txt"));
    // Summary mode does not list individual paths.
    assert!(!rendered.contains("d.txt"));
}

#[test]
fn verbose_mode_lists_every_path_with_its_action() {
    let rendered = format_rewind_plan(&sample_plan(), true);
    for path in ["a.txt", "b.txt", "c.txt", "d.txt", "e.txt"] {
        assert!(rendered.contains(path), "{path} missing from verbose output");
    }
    assert!(rendered.contains("expired by retention"));
}

/// An unavailable path must be visible as such -- never folded into the
/// unchanged count, which would read as "nothing to worry about".
#[test]
fn unavailable_paths_are_called_out_separately_from_unchanged() {
    let rendered = format_rewind_plan(&sample_plan(), false);
    assert!(rendered.contains("1 unavailable"));
    assert!(rendered.contains("cannot restore them"));
}

#[test]
fn a_plan_with_no_renames_says_so_rather_than_printing_nothing() {
    let mut plan = sample_plan();
    plan.rename_candidates.clear();
    // The whole-plan total is the authority here too, for the same
    // reason the action counts are: the list itself can be shortened.
    plan.total_rename_candidate_count = 0;
    assert!(format_rewind_plan(&plan, false).contains("No renames detected."));
}

/// The real default-mode response: the daemon omits `unchanged`
/// entries from the listing, but its counts still cover them. Rendering
/// must read those counts, not re-derive them from the entries that
/// happened to arrive -- otherwise the headline summary silently
/// under-reports the moment a folder is big enough to matter.
#[test]
fn summary_counts_come_from_the_daemons_tally_not_from_the_listing() {
    let mut plan = sample_plan();
    plan.entries.retain(|entry| entry.action != "unchanged");
    plan.counts = Some(WireRewindActionCounts {
        create: 1,
        delete: 1,
        replace: 1,
        unchanged: 4_000,
        unavailable: 1,
    });
    plan.total_entry_count = 4_004;

    let rendered = format_rewind_plan(&plan, false);
    assert!(
        rendered.contains("4000 unchanged"),
        "the count must come from the daemon's whole-plan tally: {rendered}"
    );
    assert!(rendered.contains("1 unavailable"));
}

/// A shortened listing must say so. A partial list presented as
/// complete is the one outcome worse than not listing at all.
#[test]
fn a_shortened_listing_is_called_out_rather_than_read_as_complete() {
    let mut plan = sample_plan();
    plan.listing_truncated = true;
    plan.total_entry_count = 90_000;
    let rendered = format_rewind_plan(&plan, true);
    assert!(rendered.contains("Listing shortened to fit"), "{rendered}");
    assert!(rendered.contains("of 90000 path(s)"), "{rendered}");
}

/// Summary mode prints no path listing at all, so a "showing N of M
/// path(s)" line there would describe something the reader was never
/// shown. The counts, which do cover every path, carry that mode on
/// their own.
#[test]
fn summary_mode_does_not_report_a_shortened_path_listing_it_never_prints() {
    let mut plan = sample_plan();
    plan.listing_truncated = true;
    plan.total_entry_count = 90_000;
    let rendered = format_rewind_plan(&plan, false);
    assert!(
        !rendered.contains("path(s)"),
        "summary mode shows no path listing, so it must not describe one as shortened: \
         {rendered}"
    );
    assert!(rendered.contains("1 unavailable"), "the whole-plan counts still stand");
}

/// The rename list, unlike the path listing, IS printed in summary
/// mode -- so when it is the half that got cut, saying so belongs there
/// too.
#[test]
fn summary_mode_still_reports_a_shortened_rename_listing() {
    let mut plan = sample_plan();
    plan.listing_truncated = true;
    plan.total_rename_candidate_count = 4_000;
    let rendered = format_rewind_plan(&plan, false);
    assert!(rendered.contains("Rename list shortened to fit"), "{rendered}");
    assert!(rendered.contains("1 of 4000 rename(s)"), "{rendered}");
}

#[test]
fn at_accepts_absolute_unix_nanos() {
    assert_eq!(parse_at("1750000000000000000", 0).unwrap(), 1_750_000_000_000_000_000);
}

#[test]
fn at_accepts_offsets_back_from_now() {
    let now = 10_000_000_000_000i64;
    assert_eq!(parse_at("2s", now).unwrap(), now - 2_000_000_000);
    assert_eq!(parse_at("3m", now).unwrap(), now - 180_000_000_000);
    assert_eq!(parse_at("1h", now).unwrap(), now - 3_600_000_000_000);
    assert_eq!(parse_at(" 1d ", now).unwrap(), now - 86_400_000_000_000);
}

#[test]
fn at_rejects_anything_it_cannot_read_exactly() {
    for raw in ["yesterday", "2026-09-04", "2w", "", "h", "-"] {
        assert!(parse_at(raw, 0).is_err(), "{raw:?} should not parse");
    }
}

/// A negative target is never what someone meant: an absolute one is
/// before the Unix epoch, and a negative offset asks to rewind into the
/// future. Both used to be accepted and answered with a confident,
/// useless plan.
#[test]
fn at_rejects_a_target_before_the_epoch_or_in_the_future() {
    let now = 10_000_000_000_000i64;
    for raw in ["-1", "-1750000000000000000", "-5s", "-3m", "-2h", "-7d"] {
        assert!(parse_at(raw, now).is_err(), "{raw:?} should not parse");
    }
    // Zero is still a legitimate (if unusual) absolute target.
    assert_eq!(parse_at("0", now).unwrap(), 0);
}

#![cfg(test)]

use super::*;

fn base_folder() -> FolderSummary {
    let link = yadorilink_ipc_proto::daemonctl::LinkStatus {
        local_path: "/Users/alice/Photos".into(),
        ..Default::default()
    };
    FolderSummary::from(&link)
}

#[test]
fn hydration_summary_shows_every_bucket_even_when_zero() {
    let mut folder = base_folder();
    folder.files_hydrated = 1204;
    folder.files_placeholder = 38;
    folder.files_hydrating = 0;
    assert_eq!(hydration_summary(&folder), "1204 hydrated · 38 placeholder · 0 hydrating");
}

#[test]
fn gc_report_message_distinguishes_dry_run_from_real_sweep() {
    let report = GcResponse { blocks_deleted: 3, bytes_reclaimed: 1024 };
    let dry = gc_report_message(&report, true);
    assert!(dry.starts_with("Dry run"), "got {dry:?}");
    assert!(dry.contains("3 internal block(s)"), "got {dry:?}");
    let real = gc_report_message(&report, false);
    assert!(real.starts_with("Deleted 3 internal block(s)"), "got {real:?}");
    assert!(!real.starts_with("Dry run"), "got {real:?}");
}

#[test]
fn last_gc_summary_reports_never_when_no_sweep_has_completed() {
    assert_eq!(last_gc_summary(0), "never");
    assert_eq!(last_gc_summary(-1), "never");
}

#[test]
fn last_gc_summary_reports_a_relative_bucket() {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        as i64;
    assert_eq!(last_gc_summary(now - 90), "1m ago");
}

#[test]
fn format_bytes_scales_to_a_human_readable_unit() {
    assert_eq!(format_bytes(0), "0 B");
    assert_eq!(format_bytes(3 * 1024 * 1024), "3.0 MiB");
}

fn kept(group: &str, path: &str, size: u64, reachable: bool) -> RetainedOriginal {
    RetainedOriginal {
        group_id: group.into(),
        group_removed: !reachable,
        path: path.into(),
        recovery_id: "rid".into(),
        size,
        reachable,
    }
}

#[test]
fn no_kept_originals_show_no_section() {
    assert_eq!(retained_summary(&[]), None);
    assert!(retained_rows(&[]).is_empty());
}

#[test]
fn kept_originals_are_counted_with_their_known_size() {
    let items = [kept("g", "a.txt", 1024, true), kept("g", "b.txt", 2048, true)];
    let summary = retained_summary(&items).unwrap();
    assert!(summary.contains("2 original(s)") && summary.contains("3.0 KiB"), "{summary}");
    assert!(!summary.contains("unknown"), "{summary}");
}

#[test]
fn an_original_of_an_unwatched_folder_says_its_size_is_unknown() {
    let items = [kept("g", "a.txt", 1024, true), kept("gone", "b.txt", 0, false)];
    let summary = retained_summary(&items).unwrap();
    assert!(summary.contains("size unknown for 1"), "{summary}");
    let rows = retained_rows(&items);
    assert!(rows[0].contains("a.txt") && rows[0].contains("1.0 KiB"), "{rows:?}");
    assert!(rows[1].contains("b.txt") && rows[1].contains("size unknown"), "{rows:?}");
}

#[test]
fn a_release_says_what_went_and_what_stayed() {
    let release = |outcome: &str| RetainedRelease {
        path: "p".into(),
        outcome: outcome.into(),
        detail: String::new(),
    };
    let message = release_message(&[
        release("removed"),
        release("gone"),
        release("saved_then_removed"),
        release("still_retained"),
        release("saved_still_retained"),
        release("left"),
    ]);
    assert!(message.contains("3 released"), "{message}");
    assert!(message.contains("3 kept"), "{message}");
    assert!(message.contains("2 changed and saved"), "{message}");
    assert!(release_message(&[]).contains("nothing"), "an empty release has a message");
}

#[test]
fn clean_up_is_named_and_explained_as_internal_not_folder_files() {
    assert_eq!(CLEAN_UP_ACTION, "Clean up YadoriLink data");
    assert!(CLEAN_UP_EXPLANATION.contains("does not change the files in your folders"));
    assert!(CLEAN_UP_EXPLANATION.contains("online only"));
    assert!(CLEANABLE_LABEL.contains("Internal"));
    assert!(!INTERNAL_TOTAL_LABEL.contains("Stored") && FILES_SECTION == "Files on this Mac");
    assert!(FILES_EXPLANATION.contains("counts only"));
}

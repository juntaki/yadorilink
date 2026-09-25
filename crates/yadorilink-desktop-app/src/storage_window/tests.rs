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
    assert!(dry.contains("3 block(s)"), "got {dry:?}");
    let real = gc_report_message(&report, false);
    assert!(real.starts_with("Deleted 3 block(s)"), "got {real:?}");
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

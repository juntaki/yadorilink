#![cfg(test)]

use super::*;

#[test]
fn format_mib_renders_unlimited_as_empty() {
    assert_eq!(format_mib(0), "");
}

#[test]
fn format_mib_renders_exact_value() {
    assert_eq!(format_mib(1024 * 1024), "1.00");
    assert_eq!(format_mib(5 * 1024 * 1024), "5.00");
}

#[test]
fn parse_mib_round_trips_format_mib() {
    assert_eq!(parse_mib(&format_mib(1024 * 1024)), 1024 * 1024);
    assert_eq!(parse_mib(&format_mib(10 * 1024 * 1024)), 10 * 1024 * 1024);
}

#[test]
fn parse_mib_treats_blank_and_garbage_as_unlimited() {
    assert_eq!(parse_mib(""), 0);
    assert_eq!(parse_mib("   "), 0);
    assert_eq!(parse_mib("not a number"), 0);
}

#[test]
fn limits_draft_from_response_round_trips_through_parse() {
    let r = LimitsShowResponse { upload_bytes_per_sec: 2 * 1024 * 1024, download_bytes_per_sec: 0 };
    let draft = LimitsDraft::from_response(&r);
    assert_eq!(parse_mib(&draft.up_mib), 2 * 1024 * 1024);
    assert_eq!(parse_mib(&draft.down_mib), 0);
}

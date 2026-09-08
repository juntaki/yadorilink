//! `yadorilink rewind <group> --at <timestamp> [--verbose]`: Folder
//! Rewind's read-only preview, over the daemon control socket -- the same
//! round-trip shape `gc.rs`/`limits.rs` already establish for a simple
//! single-request-response daemon command.
//!
//! Preview only. This command shows what a rewind WOULD change and stops
//! there: it applies nothing, and there is no flag that makes it apply
//! anything.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{RewindPreviewRequest, RewindPreviewResponse};

use crate::control_client;
use crate::error::CliError;

pub async fn run(group: String, at: String, verbose: bool) -> Result<(), CliError> {
    let at_unix_nanos = parse_at(&at, now_unix_nanos())?;
    let resp = control_client::send(ReqPayload::RewindPreview(RewindPreviewRequest {
        group_id: group,
        at_unix_nanos,
        // `--verbose` decides what is REQUESTED, not just what is printed.
        // A whole-folder plan has one entry per path the daemon has ever
        // indexed, and for a large folder the paths a rewind would leave
        // alone are far more than one control-socket frame can carry -- so
        // asking for them and then discarding them at render time would
        // simply fail the command for exactly the folders it matters most
        // for. The summary below is built from the daemon's own whole-plan
        // tallies, which arrive either way.
        include_unchanged: verbose,
    }))
    .await?;
    let Some(RespPayload::RewindPreview(plan)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    println!("{}", format_rewind_plan(&plan, verbose));
    Ok(())
}

fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Parses `--at` into nanoseconds since the Unix epoch.
///
/// Two accepted forms, and deliberately no more: a bare integer is taken as
/// absolute unix nanoseconds (the unit every timestamp on this control
/// protocol already uses -- `mtime_unix_nanos`, `deleted_at_unix_nanos`),
/// and a relative offset (`90s`, `30m`, `2h`, `7d`) is subtracted from
/// `now`. There is no calendar-date form, because parsing one correctly
/// (time zones, DST, locale) needs a date library this workspace does not
/// depend on, and a half-correct one silently rewinding to the wrong
/// instant is worse than not offering it.
///
/// Both forms are rejected when negative. A negative absolute value is a
/// time before the Unix epoch, and a negative offset means "rewind to the
/// future" -- neither can be what anyone meant, and both would otherwise be
/// accepted silently and answered with a confident, useless plan (every
/// path `delete` for the first; today's state reported as "unchanged" for
/// the second).
fn parse_at(raw: &str, now_unix_nanos: i64) -> Result<i64, CliError> {
    let raw = raw.trim();
    if let Ok(absolute) = raw.parse::<i64>() {
        if absolute < 0 {
            return Err(invalid_at(raw));
        }
        return Ok(absolute);
    }
    const NANOS_PER_SECOND: i64 = 1_000_000_000;
    let (digits, unit_nanos) = match raw.as_bytes().last() {
        Some(b's') => (&raw[..raw.len() - 1], NANOS_PER_SECOND),
        Some(b'm') => (&raw[..raw.len() - 1], 60 * NANOS_PER_SECOND),
        Some(b'h') => (&raw[..raw.len() - 1], 3_600 * NANOS_PER_SECOND),
        Some(b'd') => (&raw[..raw.len() - 1], 86_400 * NANOS_PER_SECOND),
        _ => return Err(invalid_at(raw)),
    };
    let count: i64 = digits.parse().map_err(|_| invalid_at(raw))?;
    if count < 0 {
        return Err(invalid_at(raw));
    }
    let offset = count.checked_mul(unit_nanos).ok_or_else(|| invalid_at(raw))?;
    Ok(now_unix_nanos.saturating_sub(offset))
}

fn invalid_at(raw: &str) -> CliError {
    CliError::Other(format!(
        "cannot read --at value {raw:?}: expected unix nanoseconds (e.g. 1750000000000000000) \
         or an offset back from now (e.g. 90s, 30m, 2h, 7d)"
    ))
}

/// Two modes, same split `gc.rs`'s own `format_gc_report` uses: the default
/// is the decision-sized summary (how many paths fall into each action,
/// plus the derived rename list), and `--verbose` additionally lists every
/// path.
///
/// The counts come from the daemon's own tally over the WHOLE plan, never
/// from counting the entries that arrived: the response deliberately
/// carries only a subset of them (see `include_unchanged` above and the
/// listing budget on the daemon side), so counting what is in hand would
/// under-report exactly the folders where the summary matters most.
///
/// `unavailable` is always reported on its own line, never merged into
/// `unchanged` and never omitted when zero, because "some paths have no
/// answer at this target time" is exactly the thing someone deciding
/// whether to rewind needs to see.
fn format_rewind_plan(plan: &RewindPreviewResponse, verbose: bool) -> String {
    let counts = plan.counts.unwrap_or_default();
    let (create, delete, replace, unchanged, unavailable) =
        (counts.create, counts.delete, counts.replace, counts.unchanged, counts.unavailable);

    let mut out = format!(
        "Rewind preview for group {} at {} (nothing has been changed)\n",
        plan.group_id, plan.target_unix_nanos
    );
    out.push_str(&format!(
        "  {create} to create, {delete} to delete, {replace} to replace, \
         {unchanged} unchanged, {unavailable} unavailable\n"
    ));
    if unavailable > 0 {
        out.push_str(
            "  Unavailable paths have no recoverable state at that time on this device; \
             a rewind cannot restore them.\n",
        );
    }

    if plan.total_rename_candidate_count == 0 {
        out.push_str("  No renames detected.\n");
    } else {
        out.push_str(&format!(
            "  {} likely rename(s) (matched on identical content; advisory only):\n",
            plan.total_rename_candidate_count
        ));
        for candidate in &plan.rename_candidates {
            out.push_str(&format!("    {} -> {}\n", candidate.from_path, candidate.to_path));
        }
    }

    if verbose {
        out.push_str("  Paths:\n");
        for entry in &plan.entries {
            match entry.unavailable_reason.as_deref() {
                Some(reason) => {
                    out.push_str(&format!("    {:<12} {} ({reason})\n", entry.action, entry.path))
                }
                None => out.push_str(&format!("    {:<12} {}\n", entry.action, entry.path)),
            }
        }
    }
    // Said out loud rather than letting a partial list read as complete.
    // The counts above are still the whole plan's; only the listing was
    // cut, and only because the whole of it does not fit in one message.
    //
    // Scoped to the listings actually on screen. `listing_truncated` is one
    // flag covering both of them, and summary mode prints no path listing
    // at all -- so repeating the daemon's "showing N of M path(s)" there
    // would describe a partial list the reader was never shown, which reads
    // as if paths had been hidden from a listing that is simply not part of
    // that mode. The rename list IS printed in both modes, so its own
    // shortening is reported in both.
    let renames_cut = (plan.rename_candidates.len() as u64) < plan.total_rename_candidate_count;
    if plan.listing_truncated && verbose {
        out.push_str(&format!(
            "  Listing shortened to fit: showing {} of {} path(s) and {} of {} rename(s). \
             The counts above still cover every path.\n",
            plan.entries.len(),
            plan.total_entry_count,
            plan.rename_candidates.len(),
            plan.total_rename_candidate_count,
        ));
    } else if plan.listing_truncated && renames_cut {
        out.push_str(&format!(
            "  Rename list shortened to fit: showing {} of {} rename(s). The counts above \
             still cover every path.\n",
            plan.rename_candidates.len(),
            plan.total_rename_candidate_count,
        ));
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
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
}

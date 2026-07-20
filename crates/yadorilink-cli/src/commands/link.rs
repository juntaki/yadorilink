use std::io::{BufRead, IsTerminal, Write};

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    HandoffResult, LinkRequest, LinkStatus, ListLinksRequest, PendingEnrollmentKind, UnlinkRequest,
};
use yadorilink_sync_core::link_preflight::{self, LinkPreflightReport};

use crate::commands::share::resolve_group_id;
use crate::control_client;
use crate::error::CliError;
use crate::http_client::require_access_token;

/// The fields the daemon needs to write a pending-enrollment marker in the
/// same transaction as the link itself, for a caller running the crash-safe
/// create/join protocol. `None` (the plain `link` command, and
/// `link_resolved`'s desktop-onboarding callers, which don't yet run the
/// prepare/activate protocol) means "no enrollment to track".
pub struct PendingEnrollmentFields {
    pub operation_id: String,
    pub kind: PendingEnrollmentKind,
    pub device_id: String,
}

/// The ` skipped_symlinks=N` suffix appended to a link's summary line
/// in `link list` — empty (no suffix) when the link has none, matching
/// the same "no new fields rendered when a link has none" contract
/// (see `status.rs`'s `held_summary_suffix` for the
/// identical pattern used there). Always 0 on a non-Windows daemon
/// (`LinkStatus::skipped_symlink_count`'s own doc comment), so this
/// suffix never appears on this dev/CI environment's own real runs —
/// reviewed by inspection and covered by the unit test below, the same
/// honest limitation already documented for the Windows-only mechanism
/// itself.
fn skipped_symlink_suffix(link: &LinkStatus) -> String {
    if link.skipped_symlink_count == 0 {
        String::new()
    } else {
        format!("  skipped_symlinks={}", link.skipped_symlink_count)
    }
}

/// Supports `yadorilink link --on-demand [--max-local-size <SIZE>]`.
/// `max_local_size_bytes` is only meaningful when `on_demand` is set (the
/// daemon ignores it otherwise, matching the "no cap configured = no automatic
/// eviction" default). Version retention is a fixed built-in policy (10
/// versions / 30 days) applied to every link, with nothing to configure here.
///
/// `--dry-run` runs the local preflight
/// (`yadorilink_sync_core::link_preflight`) and prints its findings
/// without ever contacting the daemon to register a link (so nothing is
/// persisted; no persisted writes occur). Otherwise, the same
/// preflight always runs first and its summary is always printed;
/// if it found a risky condition (non-empty folder, low disk
/// space, a nested-link conflict, or a risky location), the link is only
/// sent on if `--yes` was passed or (in an interactive terminal) the
/// user confirms — a risky link attempted non-interactively without
/// `--yes` exits non-zero instead (spec.md's "Risk acknowledgement"
/// scenario).
pub async fn link(
    local_path: String,
    group_name: String,
    on_demand: bool,
    max_local_size_bytes: Option<i64>,
    dry_run: bool,
    yes: bool,
) -> Result<(), CliError> {
    let (absolute, preflight) = run_link_preflight(&local_path).await?;
    print_preflight_report(&preflight);

    if dry_run {
        println!(
            "dry run: no link registered ({})",
            if preflight.is_risky() { "risky conditions found" } else { "looks safe to link" }
        );
        return Ok(());
    }

    let acknowledged = acknowledge_if_risky(&preflight, yes)?;

    let access_token = require_access_token()?;
    let group_id = resolve_group_id(&access_token, &group_name).await?;
    control_client::send(ReqPayload::Link(LinkRequest {
        local_path: absolute.to_string_lossy().to_string(),
        group_id,
        on_demand,
        max_local_size_bytes,
        acknowledge_risks: acknowledged,
        // The plain `link` command never runs the crash-safe create/join
        // protocol, so there is no pending enrollment to track.
        pending_enrollment_operation_id: String::new(),
        pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
        pending_enrollment_device_id: String::new(),
    }))
    .await?;
    println!("Linked {local_path} to {group_name}{}", if on_demand { " (on-demand)" } else { "" },);
    Ok(())
}

/// The onboarding window's link
/// step runs the *same* preflight the CLI runs — canonicalize the path,
/// gather already-linked paths for nested-link detection, and compute the
/// shared [`LinkPreflightReport`]. Returns the canonicalized path alongside
/// the report so the caller can pass it straight to [`link_resolved`]
/// without canonicalizing a second time. No printing: the window renders
/// the report's `warnings` as per-warning acknowledgement cards.
pub async fn run_link_preflight(
    local_path: &str,
) -> Result<(std::path::PathBuf, LinkPreflightReport), CliError> {
    let absolute = std::fs::canonicalize(local_path)
        .map_err(|_| CliError::Other(format!("no such directory: {local_path}")))?;
    let existing_paths = fetch_existing_link_paths().await;
    let report = link_preflight::run_preflight(&absolute, &existing_paths, None);
    Ok((absolute, report))
}

/// Register a link for a
/// caller-resolved `group_id` (the window already has it from the share
/// step) through the exact same daemon `Link` request the CLI's `link`
/// builds, carrying the caller's aggregate acknowledgement. The window
/// gates `acknowledge_risks` behind per-warning acknowledgement of every
/// `LinkPreflightReport::warnings` entry; the daemon still re-checks
/// preflight as defense-in-depth (`control_socket::link`), so an
/// unacknowledged risky link is refused there too. Onboarding links use
/// the default link options (eager, schema-default retention); the
/// on-demand option remains CLI-only for now.
pub async fn link_resolved(
    absolute_path: std::path::PathBuf,
    group_id: String,
    acknowledge_risks: bool,
) -> Result<(), CliError> {
    link_resolved_with_mode(absolute_path, group_id, false, acknowledge_risks, None).await
}

/// Like [`link_resolved`], but with an explicit storage mode instead of always
/// eager — `link_resolved` is the `on_demand = false` special case. No preflight
/// is re-run (the caller already did it), matching `link_resolved`.
///
/// `pending_enrollment` is `Some` only for `share create`/`share join`'s
/// crash-safe protocol: when set, the daemon writes a pending-enrollment
/// marker in the same SQLite transaction as the link itself, so a failure
/// here means neither was created (see
/// `yadorilink_sync_core::index::SyncState::add_link_with_pending_enrollment`'s
/// doc comment for why that ordering matters). `None` is the plain `link`
/// command's case: nothing to track.
pub async fn link_resolved_with_mode(
    absolute_path: std::path::PathBuf,
    group_id: String,
    on_demand: bool,
    acknowledge_risks: bool,
    pending_enrollment: Option<PendingEnrollmentFields>,
) -> Result<(), CliError> {
    let (pending_enrollment_operation_id, pending_enrollment_kind, pending_enrollment_device_id) =
        match pending_enrollment {
            Some(fields) => (fields.operation_id, fields.kind as i32, fields.device_id),
            None => (String::new(), PendingEnrollmentKind::Unspecified as i32, String::new()),
        };
    control_client::send(ReqPayload::Link(LinkRequest {
        local_path: absolute_path.to_string_lossy().to_string(),
        group_id,
        on_demand,
        max_local_size_bytes: None,
        acknowledge_risks,
        pending_enrollment_operation_id,
        pending_enrollment_kind,
        pending_enrollment_device_id,
    }))
    .await?;
    Ok(())
}

/// Preflight a local path and resolve the risk acknowledgement, printing the
/// report. The shared front half of establishing a link, exposed so a caller
/// (e.g. `share create`/`share join`) can preflight BEFORE creating any
/// coordination-plane state, and only then commit the link (and its
/// pending-enrollment marker, written atomically by the daemon) with
/// [`link_resolved_with_mode`], rolling the server state back if the link
/// fails.
pub async fn preflight_and_acknowledge(
    local_path: &str,
    yes: bool,
) -> Result<(std::path::PathBuf, bool), CliError> {
    let (absolute, preflight) = run_link_preflight(local_path).await?;
    print_preflight_report(&preflight);
    let acknowledged = acknowledge_if_risky(&preflight, yes)?;
    Ok((absolute, acknowledged))
}

/// Best-effort: an unreachable daemon (or any other `ListLinks` failure)
/// is treated as "no known existing links" rather than aborting the whole
/// preflight — nested-link detection then just can't find anything,
/// which is acceptable since perfect prediction of every conflict isn't
/// a goal here. A real (non-dry-run) link attempt still fails clearly
/// right after, when `control_client::send`'s own `Link` call hits the
/// same unreachable daemon.
async fn fetch_existing_link_paths() -> Vec<String> {
    match control_client::send(ReqPayload::ListLinks(ListLinksRequest {})).await {
        Ok(resp) => match resp.payload {
            Some(RespPayload::ListLinks(list)) => {
                list.links.into_iter().map(|l| l.local_path).collect()
            }
            _ => Vec::new(),
        },
        Err(_) => Vec::new(),
    }
}

/// always prints a short factual summary of what preflight found
/// (empty/non-empty, ignored-entry count, free-space state), then one
/// `warning:` line per risky condition — printed
/// separately from the factual summary so a risky link's output is
/// unambiguous even when scrolled past quickly.
fn print_preflight_report(report: &LinkPreflightReport) {
    if !report.path_exists {
        for warning in report.warnings() {
            println!("warning: {warning}");
        }
        return;
    }
    println!(
        "preflight: {} ({} entr{}{}{})",
        if report.is_empty_folder() { "empty folder" } else { "non-empty folder" },
        report.entry_count,
        if report.entry_count == 1 { "y" } else { "ies" },
        if report.ignored_entry_count > 0 {
            format!(", {} ignored", report.ignored_entry_count)
        } else {
            String::new()
        },
        if report.scan_truncated { ", scan capped" } else { "" },
    );
    if let Some(space) = report.free_space {
        println!(
            "preflight: {} free space on target volume ({} bytes free, headroom {} bytes)",
            space.classify().as_str(),
            space.available_bytes,
            space.headroom_bytes,
        );
    }
    for warning in report.warnings() {
        println!("warning: {warning}");
    }
}

/// The acknowledgement gate. Returns whether the caller has
/// (or needed to) acknowledge a risky preflight result; only ever
/// `Err`ors when the preflight is risky and there is no way to
/// acknowledge it (non-interactive without `--yes`, or an interactive "no"
/// answer) — spec.md's "Risk acknowledgement" scenario ("exits non-zero
/// unless the matching acknowledgement flag is provided").
fn acknowledge_if_risky(report: &LinkPreflightReport, yes: bool) -> Result<bool, CliError> {
    if !report.is_risky() {
        return Ok(false);
    }
    if yes {
        return Ok(true);
    }
    if std::io::stdin().is_terminal() && confirm_risky(&report.warnings()) {
        return Ok(true);
    }
    Err(CliError::Other(format!(
        "link preflight found risky condition(s): {} -- re-run with --yes to proceed",
        report.warnings().join("; ")
    )))
}

/// Interactive risky-condition confirmation, factored the same way
/// `commands::report::confirm_with_reader` is: the prompt-reading itself is
/// unit-testable without a real terminal.
fn confirm_risky_with_reader(warnings: &[String], reader: &mut impl BufRead) -> bool {
    println!("This link has {} risk(s) listed above.", warnings.len());
    print!("Proceed with this risky link anyway? [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn confirm_risky(warnings: &[String]) -> bool {
    let stdin = std::io::stdin();
    let mut lock = stdin.lock();
    confirm_risky_with_reader(warnings, &mut lock)
}

/// Send an unlink to the daemon without printing — the reusable primitive
/// behind [`unlink`], also used as best-effort compensation when a join fails
/// after the local link was already created (always `force: false` there --
/// a compensating unlink of a just-created link should still respect the
/// durability gate, not silently override it). Returns the coordination-plane
/// handoff-commit result when this unlink actually went through one (see
/// `control_socket::ensure_unlink_keeps_a_full_replica`'s doc comment for
/// when it does) — `None` for every other unlink.
pub async fn send_unlink(local_path: &str, force: bool) -> Result<Option<HandoffResult>, CliError> {
    let resp = control_client::send(ReqPayload::Unlink(UnlinkRequest {
        local_path: local_path.to_string(),
        force,
    }))
    .await?;
    Ok(match resp.payload {
        Some(RespPayload::Unlink(r)) => r.handoff_result,
        _ => None,
    })
}

/// `yadorilink unlink [--force]`. If this device is an eager full replica for
/// the folder's group, the daemon refuses the unlink fail-closed unless
/// another full replica is confirmed ready to durably hold every file
/// (`control_socket::ensure_unlink_keeps_a_full_replica`) -- without central
/// storage, this device could be giving up the group's only complete copy.
/// `--force` bypasses that gate for a genuinely dead sole replica that would
/// otherwise have no way to ever unlink; the daemon logs every forced
/// override as an audit trail regardless of whether it turned out to be
/// needed.
pub async fn unlink(local_path: String, force: bool) -> Result<(), CliError> {
    if force {
        eprintln!(
            "warning: --force set -- if this device is the sole full replica for this \
             folder's group with no other confirmed-ready replica, unlinking anyway may \
             permanently lose the only copy of that data"
        );
    }
    let handoff_result = send_unlink(&local_path, force).await?;
    println!("Unlinked {local_path}");
    if let Some(result) = handoff_result {
        crate::commands::durability_force::print_handoff_result(&result);
    }
    Ok(())
}

pub async fn list() -> Result<(), CliError> {
    let resp = control_client::send(ReqPayload::ListLinks(ListLinksRequest {})).await?;
    let Some(RespPayload::ListLinks(list)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    if list.links.is_empty() {
        println!("No linked folders.");
    }
    for link in &list.links {
        println!(
            "{}  group={}  {}{}{}{}",
            link.local_path,
            link.group_id,
            if link.paused { "paused" } else { "syncing" },
            if link.conflict_count > 0 {
                format!("  conflicts={}", link.conflict_count)
            } else {
                String::new()
            },
            // Only show the materialization
            // breakdown for `ondemand` folders — an `eager` folder's files
            // are always hydrated, so the summary would be pure noise.
            if link.materialization_policy == "ondemand" {
                format!(
                    "  on-demand (hydrated={} placeholder={} hydrating={})",
                    link.hydrated_count, link.placeholder_count, link.hydrating_count
                )
            } else {
                String::new()
            },
            skipped_symlink_suffix(link),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_link() -> LinkStatus {
        LinkStatus {
            local_path: "/tmp/photos".into(),
            group_id: "group-1".into(),
            paused: false,
            conflict_count: 0,
            materialization_policy: "eager".into(),
            hydrated_count: 0,
            placeholder_count: 0,
            hydrating_count: 0,
            held_file_count: 0,
            held_files: vec![],
            skipped_symlink_count: 0,
            degraded: false,
            degraded_reason: String::new(),
            has_active_transfer: false,
            transfer_bytes_done: 0,
            transfer_bytes_total: 0,
            transfer_blocks_done: 0,
            transfer_blocks_total: 0,
            transfer_eta_seconds: 0,
            durability_status: 0,
            policy_stale: false,
            ambiguous: false,
            ambiguous_local_paths: Vec::new(),
        }
    }

    /// a link with no skipped symlinks renders no new output.
    #[test]
    fn no_skipped_symlinks_renders_no_new_output() {
        assert_eq!(skipped_symlink_suffix(&base_link()), "");
    }

    /// a link with skipped symlinks (the Windows default-skip
    /// policy) shows the count alongside the existing sync-state summary.
    #[test]
    fn skipped_symlinks_render_the_count() {
        let mut link = base_link();
        link.skipped_symlink_count = 3;
        assert_eq!(skipped_symlink_suffix(&link), "  skipped_symlinks=3");
    }

    // -- acknowledgement gate -------------------------------------------

    fn risky_report() -> LinkPreflightReport {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"x").unwrap();
        // Leak the tempdir so the returned report's path stays valid for the
        // duration of the calling test; these tests only inspect the report
        // fields the function under test cares about (`is_risky`/
        // `warnings`), not the filesystem itself, so the directory need not
        // be cleaned up.
        let path = dir.keep();
        link_preflight::run_preflight(&path, &[], Some(0))
    }

    fn safe_report() -> LinkPreflightReport {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep();
        link_preflight::run_preflight(&path, &[], Some(0))
    }

    /// spec.md "Risk acknowledgement": `--yes` bypasses a risky preflight
    /// without needing an interactive prompt at all.
    #[test]
    fn yes_flag_acknowledges_a_risky_report() {
        let report = risky_report();
        assert!(report.is_risky());
        assert!(acknowledge_if_risky(&report, true).unwrap());
    }

    /// A non-risky report never needs acknowledgement, `--yes` or not.
    #[test]
    fn non_risky_report_never_needs_acknowledgement() {
        let report = safe_report();
        assert!(!report.is_risky());
        assert!(!acknowledge_if_risky(&report, false).unwrap());
        assert!(!acknowledge_if_risky(&report, true).unwrap());
    }

    /// spec.md "Risk acknowledgement": a risky preflight without `--yes`
    /// (and, in this unit test, without a real terminal to prompt on)
    /// genuinely blocks — `acknowledge_if_risky` returns `Err`, which
    /// `commands::link::link` propagates as a non-zero exit.
    #[test]
    fn risky_report_without_yes_or_a_terminal_is_rejected() {
        let report = risky_report();
        let result = acknowledge_if_risky(&report, false);
        assert!(result.is_err(), "expected risky link without --yes to be rejected");
    }

    /// The interactive confirmation prompt itself: "y"/"yes" (any case)
    /// acknowledges, anything else (including empty input) does not.
    #[test]
    fn confirm_risky_reader_accepts_y_or_yes_case_insensitively() {
        let warnings = vec!["folder is not empty".to_string()];
        assert!(confirm_risky_with_reader(&warnings, &mut "y\n".as_bytes()));
        assert!(confirm_risky_with_reader(&warnings, &mut "YES\n".as_bytes()));
        assert!(!confirm_risky_with_reader(&warnings, &mut "n\n".as_bytes()));
        assert!(!confirm_risky_with_reader(&warnings, &mut "\n".as_bytes()));
    }
}

use std::io::{BufRead, IsTerminal, Write};

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    LinkRequest, LinkStatus, ListLinksRequest, OverrideRequest, RevertRequest, SetModeRequest,
    UnlinkRequest,
};
use yadorilink_sync_core::link_preflight::{self, LinkPreflightReport};

use crate::control_client;
use crate::error::CliError;
use crate::grpc::{require_access_token, resolve_group_id};

/// add-folder-direction-modes task 4.3: the `  mode=<mode>` suffix
/// appended to a link's summary line — same "empty unless applicable"
/// discipline as `skipped_symlink_suffix`/`status.rs`'s `held_summary_
/// suffix`, except `send-receive` (the default, unchanged-behavior mode)
/// is itself treated as "nothing to call out", so an existing link's
/// output stays exactly as it was before this feature existed unless the
/// user actually opted into a directional mode.
fn mode_suffix(link: &LinkStatus) -> String {
    if link.mode.is_empty() || link.mode == "send_receive" {
        String::new()
    } else {
        format!("  mode={}", link.mode.replace('_', "-"))
    }
}

/// add-folder-direction-modes task 4.3: the out-of-sync (send-only) /
/// locally-changed (receive-only) divergence-count suffix. Empty when
/// both counts are zero, matching the same discipline.
fn divergence_suffix(link: &LinkStatus) -> String {
    let mut parts = Vec::new();
    if link.out_of_sync_count > 0 {
        parts.push(format!("out_of_sync={}", link.out_of_sync_count));
    }
    if link.receive_only_changed_count > 0 {
        parts.push(format!("receive_only_changed={}", link.receive_only_changed_count));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("  {}", parts.join(" "))
    }
}

/// add-sync-fidelity task 6.2: the `  skipped_symlinks=N` suffix appended
/// to a link's summary line in `link list` — empty (no suffix) when the
/// link has none, matching the same "no new fields rendered when a link
/// has none" contract task 6.3 requires (see `status.rs`'s
/// `held_summary_suffix` for the identical pattern used there). Always 0
/// on a non-Windows daemon (`LinkStatus::skipped_symlink_count`'s own doc
/// comment), so this suffix never appears on this dev/CI environment's
/// own real runs — reviewed by inspection and covered by the unit test
/// below, the same honest limitation already documented for the
/// Windows-only mechanism itself (section 3.2/5.4's `tasks.md` notes).
fn skipped_symlink_suffix(link: &LinkStatus) -> String {
    if link.skipped_symlink_count == 0 {
        String::new()
    } else {
        format!("  skipped_symlinks={}", link.skipped_symlink_count)
    }
}

/// `on_demand_sync` task 5.1: `yadorilink link --on-demand [--max-local-size <SIZE>]`.
/// `max_local_size_bytes` is only meaningful when `on_demand` is set (the
/// daemon ignores it otherwise, matching design D6's "no cap configured =
/// no automatic eviction" default). content-defined-chunking task 4.3:
/// `--content-defined-chunking` opts this link into content-defined
/// chunking for files at or above the size threshold (design D3);
/// unrelated to `on_demand` and may be combined freely with it.
/// add-folder-direction-modes task 4.3: `--mode <mode>` at link time.
/// `None` (the flag omitted) sends an empty `mode` string, which the
/// daemon's `LinkMode::from_db_str` decodes as `SendReceive` — the same
/// "absent means unchanged default behavior" contract every other
/// optional link-time setting here already follows.
///
/// add-file-version-history task 6.4: `--keep-versions <n>`/`--keep-days
/// <t>` at link time (design D2's defaults, 10/30, apply when both are
/// omitted — see `control_socket.rs`'s `link()` for the "absent = use the
/// column's own `DEFAULT`" contract this mirrors).
///
/// add-first-run-safety-onboarding tasks 1.2/1.3/2.1/2.2: `--dry-run` runs
/// the local preflight (`yadorilink_sync_core::link_preflight`) and prints
/// its findings without ever contacting the daemon to register a link (so
/// nothing is persisted — task 1.2's "no persisted writes"). Otherwise, the
/// same preflight always runs first and its summary is always printed
/// (task 2.2); if it found a risky condition (non-empty folder, low disk
/// space, a nested-link conflict, or a risky location), the link is only
/// sent on if `--yes` was passed or (in an interactive terminal) the user
/// confirms — a risky link attempted non-interactively without `--yes`
/// exits non-zero instead (spec.md's "Risk acknowledgement" scenario).
#[allow(clippy::too_many_arguments)]
pub async fn link(
    local_path: String,
    group_name: String,
    on_demand: bool,
    max_local_size_bytes: Option<i64>,
    content_defined_chunking: bool,
    mode: Option<String>,
    keep_versions: Option<i64>,
    keep_days: Option<i64>,
    dry_run: bool,
    yes: bool,
) -> Result<(), CliError> {
    let absolute = std::fs::canonicalize(&local_path)
        .map_err(|_| CliError::Other(format!("no such directory: {local_path}")))?;
    let existing_paths = fetch_existing_link_paths().await;
    let preflight = link_preflight::run_preflight(&absolute, &existing_paths, None);
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
    let mode_db_str = mode.as_deref().map(normalize_mode_arg).transpose()?.unwrap_or_default();
    control_client::send(ReqPayload::Link(LinkRequest {
        local_path: absolute.to_string_lossy().to_string(),
        group_id,
        on_demand,
        max_local_size_bytes,
        content_defined_chunking,
        mode: mode_db_str,
        keep_versions,
        keep_days,
        acknowledge_risks: acknowledged,
    }))
    .await?;
    println!(
        "Linked {local_path} to {group_name}{}{}{}{}",
        if on_demand { " (on-demand)" } else { "" },
        if content_defined_chunking { " (content-defined chunking)" } else { "" },
        mode.as_deref().map(|m| format!(" (mode={m})")).unwrap_or_default(),
        retention_suffix(keep_versions, keep_days),
    );
    Ok(())
}

/// Best-effort: an unreachable daemon (or any other `ListLinks` failure)
/// is treated as "no known existing links" rather than aborting the whole
/// preflight — nested-link detection then just can't find anything, which
/// is acceptable per design.md's "Non-Goals: perfect prediction of every
/// conflict". A real (non-dry-run) link attempt still fails clearly right
/// after, when `control_client::send`'s own `Link` call hits the same
/// unreachable daemon.
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

/// task 2.2: always prints a short factual summary of what preflight found
/// (empty/non-empty, ignored-entry count, free-space state), then one
/// `warning:` line per risky condition (task 1.1's scenarios) — printed
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

/// task 1.3/2.1: the acknowledgement gate. Returns whether the caller has
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

/// add-file-version-history task 6.4: only mentioned in the link summary
/// when the caller actually passed `--keep-versions`/`--keep-days` —
/// matches `mode`'s own "say nothing when the default applies" discipline
/// above.
fn retention_suffix(keep_versions: Option<i64>, keep_days: Option<i64>) -> String {
    if keep_versions.is_none() && keep_days.is_none() {
        return String::new();
    }
    format!(
        " (keep-versions={} keep-days={})",
        keep_versions.unwrap_or(10),
        keep_days.unwrap_or(30)
    )
}

/// Accepts either dash- or underscore-separated spelling (`send-only` or
/// `send_only`) and normalizes to the daemon's underscore db-string form —
/// user-facing CLI args conventionally use dashes (`content-defined-chunking`
/// elsewhere in this same command), while `LinkMode::as_db_str`/`from_db_str`
/// use underscores (matching `materialization_policy`/`chunking_policy`'s
/// existing wire convention).
///
/// Rejects anything that isn't one of the three known modes. This matters
/// because `LinkMode::from_db_str` on the daemon side silently falls back to
/// `SendReceive` for an unrecognized string (the same "absent means
/// unchanged default" contract that lets an omitted `--mode` flag work) —
/// without validating here first, a typo like `--mode send-olny` would
/// silently fail OPEN to the fully bidirectional default instead of
/// erroring, defeating the entire point of a mode a user picked specifically
/// to restrict propagation.
fn normalize_mode_arg(mode: &str) -> Result<String, CliError> {
    let normalized = mode.replace('-', "_");
    match normalized.as_str() {
        "send_receive" | "send_only" | "receive_only" => Ok(normalized),
        _ => Err(CliError::Other(format!(
            "invalid mode '{mode}': expected one of send-receive, send-only, receive-only"
        ))),
    }
}

pub async fn unlink(local_path: String) -> Result<(), CliError> {
    control_client::send(ReqPayload::Unlink(UnlinkRequest { local_path: local_path.clone() }))
        .await?;
    println!("Unlinked {local_path}");
    Ok(())
}

/// add-folder-direction-modes task 4.3: `yadorilink link-set-mode <path>
/// <mode>` — changes an existing link's mode and triggers the daemon's
/// rescan/reconcile.
pub async fn set_mode(local_path: String, mode: String) -> Result<(), CliError> {
    control_client::send(ReqPayload::SetMode(SetModeRequest {
        local_path: local_path.clone(),
        mode: normalize_mode_arg(&mode)?,
    }))
    .await?;
    println!("Set {local_path} to mode={mode}");
    Ok(())
}

/// add-folder-direction-modes task 4.3: `yadorilink override <path>`.
pub async fn override_link(local_path: String) -> Result<(), CliError> {
    let resp = control_client::send(ReqPayload::Override(OverrideRequest {
        local_path: local_path.clone(),
    }))
    .await?;
    let Some(RespPayload::Override(result)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    println!("Overrode {local_path}: reconciled {} out-of-sync path(s)", result.reconciled_count);
    Ok(())
}

/// add-folder-direction-modes task 4.3: `yadorilink revert <path>`.
pub async fn revert(local_path: String) -> Result<(), CliError> {
    let resp =
        control_client::send(ReqPayload::Revert(RevertRequest { local_path: local_path.clone() }))
            .await?;
    let Some(RespPayload::Revert(result)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    println!("Reverted {local_path}: {} receive-only-changed path(s)", result.reverted_count);
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
            "{}  group={}  {}{}{}{}{}{}{}",
            link.local_path,
            link.group_id,
            if link.paused { "paused" } else { "syncing" },
            if link.conflict_count > 0 {
                format!("  conflicts={}", link.conflict_count)
            } else {
                String::new()
            },
            // on-demand-sync task 5.4: only show the materialization
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
            // content-defined-chunking task 4.4: only show the chunking
            // policy when it differs from the default — a `fixed` link is
            // unremarkable and matches every link before this feature
            // existed, so calling it out would be noise.
            if link.chunking_policy == "content_defined" {
                "  content-defined-chunking".to_string()
            } else {
                String::new()
            },
            // add-sync-fidelity task 6.2.
            skipped_symlink_suffix(link),
            // add-folder-direction-modes task 4.3.
            mode_suffix(link),
            divergence_suffix(link),
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
            pending_changes: 0,
            conflict_count: 0,
            materialization_policy: "eager".into(),
            hydrated_count: 0,
            placeholder_count: 0,
            hydrating_count: 0,
            open_elsewhere_count: 0,
            chunking_policy: "fixed".into(),
            held_file_count: 0,
            held_files: vec![],
            skipped_symlink_count: 0,
            degraded: false,
            degraded_reason: String::new(),
            mode: "send_receive".into(),
            out_of_sync_count: 0,
            receive_only_changed_count: 0,
            has_active_transfer: false,
            transfer_bytes_done: 0,
            transfer_bytes_total: 0,
            transfer_blocks_done: 0,
            transfer_blocks_total: 0,
            transfer_eta_seconds: 0,
        }
    }

    /// task 6.3: a link with no skipped symlinks renders no new output.
    #[test]
    fn no_skipped_symlinks_renders_no_new_output() {
        assert_eq!(skipped_symlink_suffix(&base_link()), "");
    }

    /// task 6.2: a link with skipped symlinks (the Windows default-skip
    /// policy) shows the count alongside the existing sync-state summary.
    #[test]
    fn skipped_symlinks_render_the_count() {
        let mut link = base_link();
        link.skipped_symlink_count = 3;
        assert_eq!(skipped_symlink_suffix(&link), "  skipped_symlinks=3");
    }

    /// add-folder-direction-modes task 4.3: a `send-receive` (default)
    /// link renders no mode suffix at all — an unaffected existing link's
    /// output is unchanged from before this feature existed.
    #[test]
    fn send_receive_mode_renders_no_new_output() {
        assert_eq!(mode_suffix(&base_link()), "");
    }

    #[test]
    fn non_default_mode_renders_with_dashes() {
        let mut link = base_link();
        link.mode = "send_only".into();
        assert_eq!(mode_suffix(&link), "  mode=send-only");

        link.mode = "receive_only".into();
        assert_eq!(mode_suffix(&link), "  mode=receive-only");
    }

    #[test]
    fn no_divergence_renders_no_new_output() {
        assert_eq!(divergence_suffix(&base_link()), "");
    }

    /// A typo'd or garbage `--mode`/`link-set-mode` argument must be
    /// rejected, not silently normalized into something that falls back to
    /// the fully bidirectional default on the daemon side — see
    /// `normalize_mode_arg`'s doc comment for why a silent fallback here
    /// would defeat the purpose of choosing a restrictive mode at all.
    #[test]
    fn invalid_mode_is_rejected_not_silently_defaulted() {
        assert!(normalize_mode_arg("send-olny").is_err());
        assert!(normalize_mode_arg("bogus").is_err());
        assert!(normalize_mode_arg("").is_err());
    }

    #[test]
    fn valid_modes_accept_dash_or_underscore_spelling() {
        assert_eq!(normalize_mode_arg("send-receive").unwrap(), "send_receive");
        assert_eq!(normalize_mode_arg("send_receive").unwrap(), "send_receive");
        assert_eq!(normalize_mode_arg("send-only").unwrap(), "send_only");
        assert_eq!(normalize_mode_arg("receive-only").unwrap(), "receive_only");
    }

    /// task 6.4: omitting both retention flags renders no new output —
    /// the schema defaults (10/30) apply silently, matching `mode`'s own
    /// "unaffected existing behavior" discipline.
    #[test]
    fn no_retention_flags_renders_no_new_output() {
        assert_eq!(retention_suffix(None, None), "");
    }

    #[test]
    fn retention_flags_render_with_defaults_filled_in() {
        assert_eq!(retention_suffix(Some(3), Some(7)), " (keep-versions=3 keep-days=7)");
        assert_eq!(retention_suffix(Some(3), None), " (keep-versions=3 keep-days=30)");
        assert_eq!(retention_suffix(None, Some(7)), " (keep-versions=10 keep-days=7)");
    }

    #[test]
    fn divergence_counts_render_only_the_nonzero_ones() {
        let mut link = base_link();
        link.out_of_sync_count = 2;
        assert_eq!(divergence_suffix(&link), "  out_of_sync=2");

        link.out_of_sync_count = 0;
        link.receive_only_changed_count = 5;
        assert_eq!(divergence_suffix(&link), "  receive_only_changed=5");

        link.out_of_sync_count = 2;
        assert_eq!(divergence_suffix(&link), "  out_of_sync=2 receive_only_changed=5");
    }

    // -- add-first-run-safety-onboarding: acknowledgement gate --------------

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

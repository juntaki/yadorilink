//! `yadorilink` CLI.

use clap::{Parser, Subcommand};
use yadorilink_cli::commands;
use yadorilink_cli::error::CliError;

#[derive(Parser)]
#[command(name = "yadorilink", version, about = "Peer-to-peer file sync")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Log in to the coordination plane. Google OIDC login opens a
    /// device-authorization flow: no email or password, and a first login
    /// automatically creates the account.
    Login,
    /// Log out and revoke the local session.
    Logout,
    /// Manage registered devices.
    Device {
        #[command(subcommand)]
        action: DeviceAction,
    },
    /// Manage folder-group sharing/ACLs.
    Share {
        #[command(subcommand)]
        action: ShareAction,
    },
    /// Link a local directory to a folder group.
    Link {
        local_path: String,
        group_name: String,
        /// on-demand-sync: create placeholders instead of fetching full
        /// content immediately; content is fetched on first access.
        #[arg(long)]
        on_demand: bool,
        /// Automatic-eviction disk-usage cap in bytes for an `--on-demand`
        /// folder; only meaningful together with `--on-demand`.
        #[arg(long)]
        max_local_size: Option<i64>,
        /// Run the link preflight and print its findings without
        /// registering the link (no daemon writes at all).
        #[arg(long)]
        dry_run: bool,
        /// Acknowledge a risky preflight result (non-empty folder, low disk
        /// space, a nested-link conflict, or a risky location)
        /// non-interactively, matching `backup import`'s existing `--yes`
        /// precedent.
        #[arg(long)]
        yes: bool,
    },
    /// Unlink a local directory.
    Unlink {
        local_path: String,
        /// Bypass the durability handoff gate (refuses to unlink this
        /// device's last confirmed-ready full replica for the folder's
        /// group) for a genuinely dead sole replica that would otherwise
        /// have no way to ever unlink. Data-loss risk: this may permanently
        /// lose the only complete copy of the folder's data; every forced
        /// override is logged by the daemon as an audit trail.
        #[arg(long)]
        force: bool,
    },
    /// List currently linked folders.
    Links,
    /// List every retained version of a file (current, superseded, and
    /// trashed alike), newest first.
    Versions { local_path: String },
    /// Restore a file to a chosen (or, by default, the most recently
    /// superseded) version, as a new current version.
    Restore {
        local_path: String,
        /// The specific version to restore to; omitted defaults to the
        /// most recently superseded version (spec "Restore without a
        /// version defaults to the most recent superseded version").
        #[arg(long)]
        version: Option<i64>,
    },
    /// List and recover deleted files still within their link's retention
    /// window. A genuine `list`/`restore` verb pair under one noun (unlike
    /// `Link`, which takes
    /// positional args at its own top level) — nested under `trash` the
    /// same way `Daemon`/`DaemonAction` and `Report`/`ReportAction` already
    /// nest below.
    Trash {
        #[command(subcommand)]
        action: TrashAction,
    },
    /// Force-hydrate a placeholder file and keep it hydrated (on-demand-sync).
    Pin { local_path: String },
    /// Allow a pinned file to become a placeholder again (on-demand-sync).
    Unpin { local_path: String },
    /// Manually convert a hydrated file back into a placeholder to
    /// reclaim local disk space (on-demand-sync).
    Evict { local_path: String },
    /// Control the sync daemon.
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
    /// Show sync status.
    Status {
        /// Re-poll and re-render status on an interval instead of exiting
        /// after one snapshot — useful for watching a big sync's
        /// per-transfer progress live.
        #[arg(long)]
        watch: bool,
    },
    /// Manually trigger block-store garbage collection.
    Gc {
        /// Compute and report what would be deleted without actually
        /// deleting anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Manage global transfer rate limits.
    Limits {
        #[command(subcommand)]
        action: LimitsAction,
    },
    /// Inspect per-link ignore patterns.
    Ignore {
        #[command(subcommand)]
        action: IgnoreAction,
    },
    /// OSS usage/error reporting: preview or export a usage summary,
    /// preview/export/submit a local error report, and manage reporting
    /// consent.
    Report {
        #[command(subcommand)]
        action: ReportAction,
    },
    /// Point beta testers at the
    /// project's existing GitHub issue templates (there is no separate in-app
    /// feedback system) and remind them how automatic crash reporting stays
    /// local and consent-gated.
    Feedback,
    /// Preview or export a privacy-safe diagnostics support bundle.
    Diagnose {
        #[command(subcommand)]
        action: DiagnoseAction,
    },
    /// Self-service account management -- request/confirm/cancel/status for
    /// account deletion, and a machine-readable export of your
    /// coordination-plane records.
    Account {
        #[command(subcommand)]
        action: AccountAction,
    },
    /// Inspect and manage local backup/disaster-recovery material.
    Backup {
        #[command(subcommand)]
        action: BackupAction,
    },
    /// Check update status, trigger a manual check/install, and configure
    /// automatic checks/install.
    Update {
        #[command(subcommand)]
        action: UpdateAction,
    },
    /// Connectivity-doctor summary
    /// (daemon/listener/discovery/coordination-plane/authorization/
    /// clock/policy categories).
    Doctor,
    /// Recent connection-attempt history, optionally filtered to one peer
    /// device id.
    Connections {
        #[arg(long)]
        peer: Option<String>,
    },
}

/// Check update status, trigger a manual check/install, and configure
/// automatic checks/install.
#[derive(Subcommand)]
enum UpdateAction {
    /// Print current version, channel, install source, last check,
    /// available version, rollout/holdback state, and last update error.
    Status,
    /// Ask the daemon to check the signed update manifest immediately and
    /// print whether an update is available.
    Check,
    /// Ask the daemon to install a verified update at the next safe
    /// point, or report the platform-specific handoff required.
    Install,
    /// Configure automatic update checks and/or automatic install mode.
    Config {
        /// `on` or `off`.
        #[arg(long)]
        checks: Option<String>,
        /// `automatic` or `manual`.
        #[arg(long)]
        install: Option<String>,
    },
}

#[derive(Subcommand)]
enum BackupAction {
    /// Show which non-sensitive recovery artifacts (config, link metadata)
    /// exist locally and what is still missing.
    Status,
    /// Export non-sensitive config and link metadata (no secrets, no device
    /// identity keys).
    Export { output_path: std::path::PathBuf },
    /// Import non-sensitive config and link metadata written by `export`.
    Import {
        input_path: std::path::PathBuf,
        /// Confirm overwriting existing local config.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum AccountAction {
    /// Self-service account deletion --
    /// request, confirm, cancel, or check status. Deletion removes your
    /// server-side coordination records and revokes device access; it never
    /// deletes the folders synced on your machines.
    Delete {
        #[command(subcommand)]
        action: AccountDeleteAction,
    },
    /// Export a machine-readable copy of
    /// your coordination-plane records (account, devices, groups, shares).
    /// Never includes file contents, file/folder names, or paths.
    /// Writes to `output_path` if given, otherwise prints to stdout.
    Export { output_path: Option<std::path::PathBuf> },
}

/// Self-service account-deletion actions.
#[derive(Subcommand)]
enum AccountDeleteAction {
    /// Request account deletion. Returns a one-time confirmation token;
    /// nothing is deleted until you confirm.
    Request,
    /// Confirm a requested deletion with its confirmation token, starting
    /// the bounded, cancellable grace period.
    Confirm { confirmation_token: String },
    /// Cancel an in-progress deletion (any time before the grace period
    /// ends) and fully restore the account.
    Cancel,
    /// Show whether the account is active, deletion-requested, or in the
    /// grace window (with the time remaining).
    Status,
}

#[derive(Subcommand)]
enum ReportAction {
    /// Preview or export a usage summary. Usage summaries are never sent
    /// over the network — this command only prints the report or writes
    /// it to a file.
    Usage {
        /// Print the exact report envelope that would be exported.
        #[arg(long)]
        preview: bool,
        /// Write the report envelope as JSON to this path.
        #[arg(long)]
        export: Option<std::path::PathBuf>,
    },
    /// Preview, export, or submit a local error report candidate.
    Error {
        /// Use the most recently captured error candidate (the default
        /// when neither --last nor --id is given).
        #[arg(long)]
        last: bool,
        /// Use a specific error candidate by id.
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        preview: bool,
        #[arg(long)]
        export: Option<std::path::PathBuf>,
        #[arg(long)]
        submit: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Reporting consent controls.
    Consent {
        #[command(subcommand)]
        action: ReportConsentAction,
    },
}

#[derive(Subcommand)]
enum DiagnoseAction {
    /// Print a redacted diagnostics summary without writing a bundle.
    Preview,
    /// Write a redacted diagnostics bundle to the requested path.
    Export { output_path: std::path::PathBuf },
}

#[derive(Subcommand)]
enum IgnoreAction {
    /// Print the effective ignore patterns for a linked folder.
    List { link_path: std::path::PathBuf },
    /// Test whether a path is ignored by the inferred link root's rules.
    Test { path: std::path::PathBuf },
    /// Explain why a path is (or isn't) ignored — the winning rule's text,
    /// source file, `#include` chain, line number, and case-sensitivity
    /// mode, using the exact same evaluator `test` uses.
    Explain { path: std::path::PathBuf },
}

#[derive(Subcommand)]
enum LimitsAction {
    /// Set the global upload/download rate limits (bytes/sec, `0` =
    /// unlimited), persisted and applied to the running daemon without a
    /// restart.
    Set {
        #[arg(long)]
        up: u64,
        #[arg(long)]
        down: u64,
    },
    /// Show the currently configured upload/download rate limits.
    Show,
}

#[derive(Subcommand)]
enum ReportConsentAction {
    /// Show current consent state, queue size, and local candidate count.
    Status,
    /// Opt in to automatic crash/error reporting.
    Enable,
    /// Disable all network submission (usage and automatic error).
    Disable,
    /// Enable/disable the local "you could report this" hint shown after
    /// reportable command failures (`true`/`false`).
    Prompts {
        // Any explicit `#[arg(...)]` (even value_name-only) opts a `bool`
        // field out of clap's auto-flag inference (which would otherwise
        // make this a presence-only `--enabled` switch): this is meant
        // to be a positional `true`/`false` value instead.
        #[arg(value_name = "true|false")]
        enabled: bool,
    },
}

#[derive(Subcommand)]
enum DeviceAction {
    Register {
        #[arg(long, default_value = "this device")]
        name: String,
    },
    List,
    /// De-register a device, revoking its access to every folder group at
    /// once. Takes effect promptly, not just eventually: any
    /// currently-connected peer of this device is pushed an updated
    /// netmap immediately and tears its WireGuard tunnel/sync session
    /// down; a peer that's offline at removal time gets the
    /// already-updated (device-absent) netmap the next time it
    /// reconnects.
    Remove {
        device_id: String,
        /// Bypass the durability readiness pre-check (refuses when this
        /// device would leave a folder group without another
        /// confirmed-ready full replica) for a device that must be removed
        /// regardless. Data-loss risk: this may permanently lose the only
        /// complete copy of a folder group's data; every forced override is
        /// logged as an audit trail. The coordination plane's own
        /// access-count guard still applies regardless of this flag.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum ShareAction {
    /// Create a new folder group and link it locally in one step. The
    /// creating device becomes the group's first full replica ('eager'), so
    /// a local copy must exist before the group is advertised. Uses the
    /// coordination plane's crash-safe Pending -> Active enrollment protocol
    /// (prepare the group, commit the local link, then activate); a failure
    /// at any step compensates by canceling the still-Pending group so a
    /// create never leaves a phantom full replica with no local copy.
    Create {
        group_name: String,
        /// Local directory to link the new folder group into.
        #[arg(long)]
        path: String,
        /// Acknowledge a risky link preflight (non-empty folder, low disk
        /// space, a nested-link conflict, or a risky location) non-interactively.
        #[arg(long)]
        yes: bool,
    },
    Grant {
        group_name: String,
        device_id: String,
    },
    /// Revoke a device's access to one folder group, or (given a single
    /// argument) revoke one edge listed by `share list` by its edge id —
    /// the `yadorilink share revoke <edge>` form. Takes effect promptly for a
    /// currently-connected peer (bounded, sub-second propagation target)
    /// rather than only on its next poll: if the two devices still share
    /// another folder group, their WireGuard tunnel stays up and only this
    /// group's sync activity stops; otherwise the tunnel is torn down
    /// entirely, same as `device remove`.
    Revoke {
        /// A folder-group name (when `device_id` is also given, the
        /// original owner-only form) or an edge id from
        /// `share list` (when `device_id` is omitted).
        group_name_or_edge: String,
        device_id: Option<String>,
        /// Bypass the durability readiness pre-check (refuses when the
        /// revoked device would leave the group without another
        /// confirmed-ready full replica) for a device that must be revoked
        /// regardless. Data-loss risk: this may permanently lose the only
        /// complete copy of the group's data; every forced override is
        /// logged as an audit trail. The coordination plane's own
        /// access-count guard still applies regardless of this flag.
        #[arg(long)]
        force: bool,
    },
    /// List every ACL edge visible to this account — folder groups it
    /// owns, and its own devices' shares.
    List,
    /// Same-account onboarding: list the folder groups this account owns and
    /// can join on this device, by name. A newly-registered device lists
    /// these, then joins the ones it wants with `share join`.
    Joinable,
    /// Same-account onboarding: join one of the joinable folder groups on this
    /// device. Authorizes this device for the group (the explicit act of
    /// selecting it) and links it locally at `--path` with the chosen
    /// `--storage-mode`.
    Join {
        group_name: String,
        /// Local directory to link the folder group into.
        #[arg(long)]
        path: String,
        /// `eager` (store everything) or `on-demand` (store only needed
        /// files, fetched on first access). Defaults to `eager`.
        #[arg(long, default_value = "eager")]
        storage_mode: String,
        /// Acknowledge a risky link preflight (non-empty folder, low disk
        /// space, a nested-link conflict, or a risky location)
        /// non-interactively, matching `link --yes`.
        #[arg(long)]
        yes: bool,
    },
    /// Change this device's storage mode for a folder group it already
    /// links. Switching FROM eager (full replica) TO on-demand is refused
    /// unless another full replica can be confirmed to durably hold every
    /// file in the group first — without central storage, a full replica is
    /// the group's only durable copy, so giving that status up without a
    /// confirmed handoff would risk permanent data loss. Switching TO eager
    /// has no such hazard and always succeeds.
    SetStorageMode {
        group_name: String,
        /// `eager` (store everything) or `on-demand` (store only needed
        /// files, fetched on first access).
        #[arg(long)]
        mode: String,
    },
}

#[derive(Subcommand)]
enum DaemonAction {
    Start,
    Stop,
    Pause,
    Resume,
    /// View/toggle the daemon's opt-in `/metrics` endpoint. Persists to
    /// the same config directory
    /// the daemon itself reads at startup (`metrics_config.json`) — a
    /// change here takes effect on the daemon's *next* start, not the
    /// currently-running process (binding a new listener isn't something
    /// a running process can do to itself mid-flight).
    Metrics {
        /// Enable the endpoint on the daemon's next start.
        #[arg(long, conflicts_with = "disable")]
        enable: bool,
        /// Disable the endpoint on the daemon's next start.
        #[arg(long, conflicts_with = "enable")]
        disable: bool,
        /// Bind address to use when enabling (default: 127.0.0.1:9184,
        /// loopback-only). Ignored with `--disable`.
        #[arg(long)]
        addr: Option<String>,
        /// Print the currently-persisted configuration without changing it.
        #[arg(long)]
        show: bool,
    },
}

/// List and recover deleted files still within their link's retention
/// window.
#[derive(Subcommand)]
enum TrashAction {
    /// List deleted files still within their link's retention window.
    List,
    /// Recover a deleted file's last version before deletion as a new
    /// current version.
    Restore { local_path: String },
}

#[tokio::main]
async fn main() {
    // Best-effort: installs a stderr subscriber so `tracing::warn!` audit
    // lines (e.g. a `--force` durability-gate override on
    // `unlink`/`share revoke`/`device remove`) are actually visible, rather
    // than silently dropped with no subscriber registered at all. Ignored on
    // failure (e.g. a test harness that already installed one) since this is
    // purely diagnostic logging, never load-bearing for command behavior.
    let _ = tracing_subscriber::fmt().with_writer(std::io::stderr).try_init();
    let cli = Cli::parse();
    let result = run(cli.command).await;
    if let Err(e) = result {
        eprintln!("error: {e}");
        // A reportable failure gets a local-only candidate plus a hint,
        // entirely after the fact — this never changes `e`/the exit code
        // below, and makes no network call (see
        // `commands::report::handle_reportable_error`).
        if e.is_reportable() {
            commands::report::handle_reportable_error(&e).await;
        }
        std::process::exit(e.exit_code());
    }
}

async fn run(command: Command) -> Result<(), CliError> {
    match command {
        Command::Login => commands::auth::login().await,
        Command::Logout => commands::auth::logout().await,
        Command::Device { action } => match action {
            DeviceAction::Register { name } => commands::device::register(name).await,
            DeviceAction::List => commands::device::list().await,
            DeviceAction::Remove { device_id, force } => {
                commands::device::remove(device_id, force).await
            }
        },
        Command::Share { action } => match action {
            ShareAction::Create { group_name, path, yes } => {
                commands::share::create(group_name, path, yes).await
            }
            ShareAction::Grant { group_name, device_id } => {
                commands::share::grant(group_name, device_id).await
            }
            ShareAction::Revoke { group_name_or_edge, device_id, force } => match device_id {
                Some(device_id) => {
                    commands::share::revoke(group_name_or_edge, device_id, force).await
                }
                None => commands::share::revoke_edge(group_name_or_edge, force).await,
            },
            ShareAction::List => commands::share::list_shares().await,
            ShareAction::Joinable => commands::share::list_joinable().await,
            ShareAction::Join { group_name, path, storage_mode, yes } => {
                commands::share::join(group_name, path, storage_mode, yes).await
            }
            ShareAction::SetStorageMode { group_name, mode } => {
                commands::share::set_storage_mode(group_name, mode).await
            }
        },
        Command::Link { local_path, group_name, on_demand, max_local_size, dry_run, yes } => {
            commands::link::link(local_path, group_name, on_demand, max_local_size, dry_run, yes)
                .await
        }
        Command::Unlink { local_path, force } => commands::link::unlink(local_path, force).await,
        Command::Links => commands::link::list().await,
        Command::Versions { local_path } => commands::version_history::versions(local_path).await,
        Command::Restore { local_path, version } => {
            commands::version_history::restore(local_path, version).await
        }
        Command::Trash { action } => match action {
            TrashAction::List => commands::version_history::trash_list().await,
            TrashAction::Restore { local_path } => {
                commands::version_history::trash_restore(local_path).await
            }
        },
        Command::Pin { local_path } => commands::materialization::pin(local_path).await,
        Command::Unpin { local_path } => commands::materialization::unpin(local_path).await,
        Command::Evict { local_path } => commands::materialization::evict(local_path).await,
        Command::Daemon { action } => match action {
            DaemonAction::Start => commands::daemon::start().await,
            DaemonAction::Stop => commands::daemon::stop().await,
            DaemonAction::Pause => commands::daemon::pause().await,
            DaemonAction::Resume => commands::daemon::resume().await,
            DaemonAction::Metrics { enable, disable, addr, show } => {
                commands::daemon::metrics(enable, disable, addr, show)
            }
        },
        Command::Status { watch } => commands::status::status(watch).await,
        Command::Feedback => commands::feedback::run(),
        Command::Gc { dry_run } => commands::gc::run(dry_run).await,
        Command::Limits { action } => match action {
            LimitsAction::Set { up, down } => commands::limits::set(up, down).await,
            LimitsAction::Show => commands::limits::show().await,
        },
        Command::Ignore { action } => match action {
            IgnoreAction::List { link_path } => commands::ignore::list(link_path),
            IgnoreAction::Test { path } => commands::ignore::test(path),
            IgnoreAction::Explain { path } => commands::ignore::explain(path),
        },
        Command::Report { action } => match action {
            ReportAction::Usage { preview, export } => {
                commands::report::usage(preview, export).await
            }
            ReportAction::Error { last: _, id, preview, export, submit, yes } => {
                commands::report::error(id, preview, export, submit, yes).await
            }
            ReportAction::Consent { action } => match action {
                ReportConsentAction::Status => commands::report::consent_status().await,
                ReportConsentAction::Enable => commands::report::consent_enable().await,
                ReportConsentAction::Disable => commands::report::consent_disable().await,
                ReportConsentAction::Prompts { enabled } => {
                    commands::report::consent_prompts(enabled).await
                }
            },
        },
        Command::Diagnose { action } => match action {
            DiagnoseAction::Preview => commands::diagnose::preview().await,
            DiagnoseAction::Export { output_path } => commands::diagnose::export(output_path).await,
        },
        Command::Account { action } => match action {
            AccountAction::Delete { action } => match action {
                AccountDeleteAction::Request => commands::account::delete_request().await,
                AccountDeleteAction::Confirm { confirmation_token } => {
                    commands::account::delete_confirm(confirmation_token).await
                }
                AccountDeleteAction::Cancel => commands::account::delete_cancel().await,
                AccountDeleteAction::Status => commands::account::delete_status().await,
            },
            AccountAction::Export { output_path } => commands::account::export(output_path).await,
        },
        Command::Backup { action } => match action {
            BackupAction::Status => {
                commands::backup::status();
                Ok(())
            }
            BackupAction::Export { output_path } => commands::backup::export(output_path).await,
            BackupAction::Import { input_path, yes } => {
                commands::backup::import(input_path, yes).await
            }
        },
        Command::Update { action } => match action {
            UpdateAction::Status => commands::update::status().await,
            UpdateAction::Check => commands::update::check().await,
            UpdateAction::Install => commands::update::install().await,
            UpdateAction::Config { checks, install } => {
                commands::update::config(checks, install).await
            }
        },
        Command::Doctor => commands::connection_ops::doctor().await,
        Command::Connections { peer } => commands::connection_ops::traces(peer).await,
    }
}

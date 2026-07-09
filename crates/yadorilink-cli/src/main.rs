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
    /// Register a new account on the coordination plane. gRPC transport only
    /// -- under Google OIDC login there is no separate registration step
    /// (see `Login`).
    #[cfg(not(feature = "http-coordination"))]
    Register {
        #[arg(long)]
        email: String,
    },
    /// Log in to the coordination plane. Under Google OIDC login (the
    /// default transport) this opens a device-authorization flow: no email
    /// or password, and a first login automatically creates the account.
    #[cfg(feature = "http-coordination")]
    Login,
    /// Log in to the coordination plane with an email and password.
    /// gRPC transport only.
    #[cfg(not(feature = "http-coordination"))]
    Login {
        #[arg(long)]
        email: String,
    },
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
        /// folder (); only meaningful together with `--on-demand`.
        #[arg(long)]
        max_local_size: Option<i64>,
        /// content-defined-chunking: opt this folder into content-defined
        /// chunking for files at or above the size threshold, instead of
        /// the default fixed-size chunking. Independent of `--on-demand`.
        #[arg(long)]
        content_defined_chunking: bool,
        /// This link's directional propagation mode — `send-receive`
        /// (default), `send-only`, or `receive-only`.
        #[arg(long)]
        mode: Option<String>,
        /// Maximum number of superseded/trashed versions to retain per file
        /// (default: 10, `0` = unlimited). Only applies to
        /// superseded/trashed versions — the current live version is never
        /// subject to this policy.
        #[arg(long)]
        keep_versions: Option<i64>,
        /// Maximum age in days of a superseded/trashed version (default: 30, `0` = unlimited).
        #[arg(long)]
        keep_days: Option<i64>,
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
    Unlink { local_path: String },
    /// List currently linked folders.
    Links,
    /// `yadorilink link retention <local-path> --keep-versions <n>
    /// --keep-days <t>`. Named `link-retention` (rather
    /// than truly nested under `link`) for the same reason `LinkSetMode`
    /// above is `link-set-mode` instead of nesting under `link`: `Link`
    /// takes flat positional args
    /// (`<local_path> <group_name>`), not a subcommand-only group, and
    /// clap's derive macro has no way to disambiguate "is this positional
    /// token `local_path`, or the subcommand name `retention`?" without an
    /// external-subcommand escape hatch that would lose typed argument
    /// parsing for every other `link` invocation. This keeps `main.rs`'s
    /// existing enum shape unchanged (judgment call — the smallest,
    /// most-consistent-with-precedent option) rather than reworking `Link`
    /// into a subcommand group.
    LinkRetention {
        local_path: String,
        #[arg(long)]
        keep_versions: Option<i64>,
        #[arg(long)]
        keep_days: Option<i64>,
    },
    /// List every retained version of a file (current, superseded, and
    /// trashed alike), newest first.
    Versions { local_path: String },
    /// Restore a file to a chosen (or, by default, the most recently
    /// superseded) version, as a new current version.
    Restore {
        local_path: String,
        /// The specific version to restore to; omitted defaults to the
        /// most recently superseded version.
        #[arg(long)]
        version: Option<i64>,
    },
    /// List and recover deleted files still within their link's retention
    /// window. A genuine `list`/`restore` verb pair under one noun (unlike
    /// `Link`, which takes
    /// positional args at its own top level) — nested under `trash` the
    /// same way `Daemon`/`DaemonAction` and `Report`/`ReportQueue` already
    /// nest below.
    Trash {
        #[command(subcommand)]
        action: TrashAction,
    },
    /// Change an existing link's directional mode, triggering a
    /// rescan/reconcile of the new gating and divergence sets. Named
    /// `link-set-mode` (rather than nested under
    /// `link`, since `Link`/`Unlink`/`Links` are already flat top-level
    /// commands in this CLI, not a `link <verb>` subcommand group).
    LinkSetMode {
        local_path: String,
        /// `send-receive` | `send-only` | `receive-only`.
        mode: String,
    },
    /// Re-assert this device's local state as authoritative for every
    /// out-of-sync path on a send-only link, clearing the out-of-sync set.
    /// Only valid on a send-only link.
    Override { local_path: String },
    /// Discard this device's un-sent local changes for every
    /// receive-only-changed path on a receive-only link and re-adopt
    /// peer-authoritative state, clearing the receive-only-changed set.
    /// Only valid on a receive-only link.
    Revert { local_path: String },
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
    /// OSS usage/error reporting: preview, export, or submit usage/error
    /// reports, manage consent, and manage the local unsent-report queue.
    Report {
        #[command(subcommand)]
        action: ReportAction,
    },
    /// Preview or export a privacy-safe diagnostics support bundle.
    Diagnose {
        #[command(subcommand)]
        action: DiagnoseAction,
    },
    /// Account-level recovery -- one-time recovery codes, a
    /// recovery-code-based password reset, and a passphrase-encrypted
    /// device key-bundle backup for when every device is lost. See each
    /// subcommand's help for the login-vs-data-access distinction (a
    /// password reset alone never grants E2E data access).
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
    /// Divergence summaries and guarded dry-run/confirm resolution for
    /// directional folder modes.
    FolderOps {
        #[command(subcommand)]
        action: FolderOpsAction,
    },
    /// Connectivity-doctor summary
    /// (daemon/listener/discovery/coordination-plane/relay/authorization/
    /// clock/policy categories).
    Doctor,
    /// Recent connection-attempt history, optionally filtered to one peer
    /// device id.
    Connections {
        #[arg(long)]
        peer: Option<String>,
    },
    /// Introducer trust flags, scoped auto-accept policies, and
    /// introduction proposal/accept/reject.
    Introduce {
        #[command(subcommand)]
        action: IntroduceAction,
    },
}

/// Divergence summaries and guarded dry-run/confirm resolution actions for
/// directional folder modes.
#[derive(Subcommand)]
enum FolderOpsAction {
    /// Send-only/receive-only divergence counts and a bounded sample of
    /// affected paths for a linked folder.
    Divergence { local_path: String },
    /// Computes (without mutating anything) what an `override`/`revert`/
    /// `mode-change` action would affect right now, and prints a
    /// `preview_id` to pass to `folder-ops confirm`.
    Preview {
        local_path: String,
        /// `override` | `revert` | `mode-change`.
        action: String,
        /// Only meaningful (and required) for `mode-change`:
        /// `send-receive` | `send-only` | `receive-only`.
        #[arg(long)]
        mode: Option<String>,
    },
    /// Applies the action named by a prior `preview`'s `preview_id`,
    /// rejected as stale if the folder's state changed since the preview
    /// was taken.
    Confirm { preview_id: String },
    /// Recent resolution-action audit entries, optionally filtered to one
    /// linked folder.
    Audit { local_path: Option<String> },
}

/// Introducer trust flags, scoped auto-accept policies, and introduction
/// proposal/accept/reject.
#[derive(Subcommand)]
enum IntroduceAction {
    /// Mark (or, with `--unset`, unmark) a device as a trusted introducer.
    SetIntroducer {
        device_id: String,
        #[arg(long)]
        unset: bool,
    },
    /// Create a scoped auto-accept policy. An omitted `--introducer`/
    /// `--group` applies to any introducer/group on that axis.
    AutoAcceptPolicy {
        #[command(subcommand)]
        action: AutoAcceptPolicyAction,
    },
    /// Propose that `target_device_id` join `group_id`, on behalf of
    /// `introducer_device_id` — auto-accepted immediately if a matching
    /// policy exists, otherwise left pending. `group_id` is the internal
    /// id shown by `share list`, not the human-readable group name (this
    /// command works with raw account/device/group ids throughout, like
    /// `propose`/`pending`/`accept`/`reject`'s other id arguments).
    Propose { introducer_device_id: String, target_device_id: String, group_id: String },
    /// List this account's pending introductions, optionally filtered to
    /// one target device.
    Pending {
        #[arg(long)]
        target_device: Option<String>,
    },
    /// Accept a pending introduction, granting ACL access.
    Accept { introduction_id: String },
    /// Reject a pending introduction.
    Reject { introduction_id: String },
}

#[derive(Subcommand)]
enum AutoAcceptPolicyAction {
    Set {
        #[arg(long)]
        introducer_device_id: Option<String>,
        /// Internal folder-group id (from `share list`), not the
        /// human-readable group name.
        #[arg(long)]
        group_id: Option<String>,
        #[arg(long)]
        destination_root_prefix: Option<String>,
        #[arg(long)]
        require_storage_only: bool,
        /// `send-receive` | `send-only` | `receive-only` (default `send-receive`).
        #[arg(long)]
        mode: Option<String>,
    },
    List,
    Revoke {
        policy_id: String,
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
    /// Show which recovery artifacts exist locally and what is still missing.
    Status,
    /// Export a passphrase-encrypted key bundle.
    Export { output_path: std::path::PathBuf },
    /// Import a passphrase-encrypted key bundle.
    Import {
        input_path: std::path::PathBuf,
        /// Confirm overwriting existing local device state.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum AccountAction {
    /// Generate (or regenerate) this account's one-time recovery codes.
    /// gRPC transport only -- there is no password to recover under Google
    /// OIDC login.
    #[cfg(not(feature = "http-coordination"))]
    RecoveryCodes {
        #[command(subcommand)]
        action: RecoveryCodesAction,
    },
    /// Reset your account password using a recovery code. Restores
    /// account/login access only -- NOT access to end-to-end-encrypted
    /// data (that needs a surviving device or an imported key bundle).
    /// gRPC transport only -- there is no password to reset under Google
    /// OIDC login.
    #[cfg(not(feature = "http-coordination"))]
    ResetPassword {
        #[arg(long)]
        email: String,
    },
    /// Export a passphrase-encrypted backup of this device's identity/key
    /// material to `output_path`, for re-establishing a device and
    /// regaining data access if every device is ever lost. The passphrase
    /// and plaintext bundle never leave this machine -- the coordination
    /// plane is not contacted at all.
    ExportKeyBundle { output_path: std::path::PathBuf },
    /// Import a passphrase-encrypted key bundle (from `export-key-bundle`)
    /// on a fresh device with no surviving peer, to re-establish this
    /// device's identity.
    ImportKeyBundle { input_path: std::path::PathBuf },
}

#[cfg(not(feature = "http-coordination"))]
#[derive(Subcommand)]
enum RecoveryCodesAction {
    /// Generate a fresh batch of recovery codes and display them exactly
    /// once. Regenerating immediately invalidates any codes issued before.
    Generate,
}

#[derive(Subcommand)]
enum ReportAction {
    /// Preview, export, or submit a usage summary.
    Usage {
        /// Print the exact report envelope that would be exported/submitted.
        #[arg(long)]
        preview: bool,
        /// Write the report envelope as JSON to this path.
        #[arg(long)]
        export: Option<std::path::PathBuf>,
        /// Submit the report to the configured reporting endpoint
        /// (requires the daemon and either usage-submission consent or
        /// interactive confirmation).
        #[arg(long)]
        submit: bool,
        /// Skip the interactive submit confirmation (for scripting).
        #[arg(long)]
        yes: bool,
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
    /// Local unsent-report queue management (requires the daemon).
    Queue {
        #[command(subcommand)]
        action: ReportQueueAction,
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
    /// Opt in to usage and/or automatic error submission.
    Enable {
        #[arg(long)]
        usage: bool,
        #[arg(long)]
        error: bool,
    },
    /// Disable all network submission (usage and automatic error).
    Disable,
    /// Generate a fresh anonymous reporter id, discarding the old one.
    ResetId,
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
    /// Enable/disable automatic background retry of queued reports
    /// (`true`/`false`).
    QueueRetry {
        #[arg(value_name = "true|false")]
        enabled: bool,
    },
    /// Set (or, with no value, clear) the reporting endpoint override.
    Endpoint { url: Option<String> },
}

#[derive(Subcommand)]
enum ReportQueueAction {
    List,
    Show { report_id: String },
    Delete { report_id: String },
    Flush,
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
    },
}

#[derive(Subcommand)]
enum ShareAction {
    Create {
        group_name: String,
    },
    Grant {
        group_name: String,
        device_id: String,
    },
    /// Revoke a device's access to one folder group, or (given a single
    /// argument) revoke one edge listed by `share list` by its edge id —
    /// the `yadorilink share revoke <edge>` form, which also works for a
    /// cross-account edge and can be issued by either the group owner or
    /// the invitee (see `share revoke-edge`'s
    /// underlying `RevokeShareEdge` RPC). Takes effect promptly for a
    /// currently-connected peer (bounded, sub-second propagation target)
    /// rather than only on its next poll: if the two devices still share
    /// another folder group, their WireGuard tunnel stays up and only this
    /// group's sync activity stops; otherwise the tunnel is torn down
    /// entirely, same as `device remove`.
    Revoke {
        /// A folder-group name (when `device_id` is also given, the
        /// original same-account owner-only form) or an edge id from
        /// `share list` (when `device_id` is omitted).
        group_name_or_edge: String,
        device_id: Option<String>,
    },
    /// Mint a one-time, expiring invite so another account can gain access
    /// to this folder group. Prints the plaintext code exactly once —
    /// transmit it out-of-band to the invitee, who redeems it with `share
    /// accept <code>`. Accepting widens the trust boundary: the invitee's
    /// device becomes a fully authorized peer with a direct WireGuard
    /// tunnel to this group's other devices.
    Invite {
        group_name: String,
        /// `read` or `write`; defaults to `write` (matches the ACL
        /// schema's default role for an edge).
        #[arg(long, default_value = "write")]
        role: String,
        /// Invite lifetime, e.g. "30m", "24h", "7d" (defaults to 24h).
        #[arg(long)]
        expires: Option<String>,
    },
    /// Redeem a share-invite code under this device's own account.
    /// Requires a device already registered on this machine (`yadorilink
    /// device register`).
    Accept {
        code: String,
    },
    /// List every ACL edge visible to this account — folder groups it
    /// owns, and its own devices' shares (including cross-account edges
    /// accepted from another account).
    List,
    /// Designate (or un-designate, with `--unset`) `device_id` as
    /// storage-only/untrusted for
    /// `group_name`. The device must already have an ACL edge for this
    /// group (e.g. via `share grant`) — this only flips the storage-only
    /// flag on an existing grant. A storage-only device never receives the
    /// group content key or plaintext; trusted devices only ever exchange
    /// ciphertext blocks and an encrypted index with it (see
    /// `encrypted-peer` capability).
    MarkStorageOnly {
        group_name: String,
        device_id: String,
        /// Un-designate: this device goes back to being a normal
        /// (trusted) peer for this group.
        #[arg(long)]
        unset: bool,
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
        #[cfg(not(feature = "http-coordination"))]
        Command::Register { email } => {
            let password = prompt_new_password()?;
            commands::auth::register(email, password).await
        }
        #[cfg(feature = "http-coordination")]
        Command::Login => commands::auth::login().await,
        #[cfg(not(feature = "http-coordination"))]
        Command::Login { email } => {
            let password = prompt_password("Password: ")?;
            commands::auth::login(email, password).await
        }
        Command::Logout => commands::auth::logout().await,
        Command::Device { action } => match action {
            DeviceAction::Register { name } => commands::device::register(name).await,
            DeviceAction::List => commands::device::list().await,
            DeviceAction::Remove { device_id } => commands::device::remove(device_id).await,
        },
        Command::Share { action } => match action {
            ShareAction::Create { group_name } => commands::share::create(group_name).await,
            ShareAction::Grant { group_name, device_id } => {
                commands::share::grant(group_name, device_id).await
            }
            ShareAction::Revoke { group_name_or_edge, device_id } => match device_id {
                Some(device_id) => commands::share::revoke(group_name_or_edge, device_id).await,
                None => commands::share::revoke_edge(group_name_or_edge).await,
            },
            ShareAction::Invite { group_name, role, expires } => {
                commands::share::invite(group_name, role, expires).await
            }
            ShareAction::Accept { code } => commands::share::accept(code).await,
            ShareAction::List => commands::share::list_shares().await,
            ShareAction::MarkStorageOnly { group_name, device_id, unset } => {
                commands::share::mark_storage_only(group_name, device_id, unset).await
            }
        },
        Command::Link {
            local_path,
            group_name,
            on_demand,
            max_local_size,
            content_defined_chunking,
            mode,
            keep_versions,
            keep_days,
            dry_run,
            yes,
        } => {
            commands::link::link(
                local_path,
                group_name,
                on_demand,
                max_local_size,
                content_defined_chunking,
                mode,
                keep_versions,
                keep_days,
                dry_run,
                yes,
            )
            .await
        }
        Command::Unlink { local_path } => commands::link::unlink(local_path).await,
        Command::Links => commands::link::list().await,
        Command::LinkRetention { local_path, keep_versions, keep_days } => {
            commands::version_history::link_retention(
                local_path,
                keep_versions.unwrap_or(10),
                keep_days.unwrap_or(30),
            )
            .await
        }
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
        Command::LinkSetMode { local_path, mode } => {
            commands::link::set_mode(local_path, mode).await
        }
        Command::Override { local_path } => commands::link::override_link(local_path).await,
        Command::Revert { local_path } => commands::link::revert(local_path).await,
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
            ReportAction::Usage { preview, export, submit, yes } => {
                commands::report::usage(preview, export, submit, yes).await
            }
            ReportAction::Error { last: _, id, preview, export, submit, yes } => {
                commands::report::error(id, preview, export, submit, yes).await
            }
            ReportAction::Consent { action } => match action {
                ReportConsentAction::Status => commands::report::consent_status().await,
                ReportConsentAction::Enable { usage, error } => {
                    commands::report::consent_enable(usage, error).await
                }
                ReportConsentAction::Disable => commands::report::consent_disable().await,
                ReportConsentAction::ResetId => commands::report::consent_reset_id().await,
                ReportConsentAction::Prompts { enabled } => {
                    commands::report::consent_prompts(enabled).await
                }
                ReportConsentAction::QueueRetry { enabled } => {
                    commands::report::consent_queue_retry(enabled).await
                }
                ReportConsentAction::Endpoint { url } => {
                    commands::report::consent_endpoint(url).await
                }
            },
            ReportAction::Queue { action } => match action {
                ReportQueueAction::List => commands::report::queue_list().await,
                ReportQueueAction::Show { report_id } => {
                    commands::report::queue_show(report_id).await
                }
                ReportQueueAction::Delete { report_id } => {
                    commands::report::queue_delete(report_id).await
                }
                ReportQueueAction::Flush => commands::report::queue_flush().await,
            },
        },
        Command::Diagnose { action } => match action {
            DiagnoseAction::Preview => commands::diagnose::preview().await,
            DiagnoseAction::Export { output_path } => commands::diagnose::export(output_path).await,
        },
        Command::Account { action } => match action {
            #[cfg(not(feature = "http-coordination"))]
            AccountAction::RecoveryCodes { action } => match action {
                RecoveryCodesAction::Generate => commands::account::generate_recovery_codes().await,
            },
            #[cfg(not(feature = "http-coordination"))]
            AccountAction::ResetPassword { email } => {
                let recovery_code = prompt_password("Recovery code: ")?;
                let new_password = prompt_new_password()?;
                commands::account::reset_password(email, recovery_code, new_password).await
            }
            AccountAction::ExportKeyBundle { output_path } => {
                let passphrase = prompt_confirmed("Key bundle passphrase")?;
                commands::account::export_key_bundle(output_path, passphrase).await
            }
            AccountAction::ImportKeyBundle { input_path } => {
                let passphrase = prompt_password("Key bundle passphrase: ")?;
                commands::account::import_key_bundle(input_path, passphrase).await
            }
        },
        Command::Backup { action } => match action {
            BackupAction::Status => {
                commands::backup::status();
                Ok(())
            }
            BackupAction::Export { output_path } => {
                let passphrase = prompt_confirmed("Backup passphrase")?;
                commands::backup::export(output_path, passphrase).await
            }
            BackupAction::Import { input_path, yes } => {
                let passphrase = prompt_password("Backup passphrase: ")?;
                commands::backup::import(input_path, passphrase, yes).await
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
        Command::FolderOps { action } => match action {
            FolderOpsAction::Divergence { local_path } => {
                commands::folder_ops::divergence(local_path).await
            }
            FolderOpsAction::Preview { local_path, action, mode } => {
                commands::folder_ops::preview(local_path, action, mode).await
            }
            FolderOpsAction::Confirm { preview_id } => {
                commands::folder_ops::confirm(preview_id).await
            }
            FolderOpsAction::Audit { local_path } => commands::folder_ops::audit(local_path).await,
        },
        Command::Doctor => commands::connection_ops::doctor().await,
        Command::Connections { peer } => commands::connection_ops::traces(peer).await,
        Command::Introduce { action } => match action {
            IntroduceAction::SetIntroducer { device_id, unset } => {
                commands::introduce::set_introducer(device_id, !unset).await
            }
            IntroduceAction::AutoAcceptPolicy { action } => match action {
                AutoAcceptPolicyAction::Set {
                    introducer_device_id,
                    group_id,
                    destination_root_prefix,
                    require_storage_only,
                    mode,
                } => {
                    let mode = mode.map(|m| match m.as_str() {
                        "send-receive" => "send_receive".to_string(),
                        "send-only" => "send_only".to_string(),
                        "receive-only" => "receive_only".to_string(),
                        other => other.to_string(),
                    });
                    commands::introduce::set_auto_accept_policy(
                        introducer_device_id,
                        group_id,
                        destination_root_prefix,
                        require_storage_only,
                        mode,
                    )
                    .await
                }
                AutoAcceptPolicyAction::List => {
                    commands::introduce::list_auto_accept_policies().await
                }
                AutoAcceptPolicyAction::Revoke { policy_id } => {
                    commands::introduce::revoke_auto_accept_policy(policy_id).await
                }
            },
            IntroduceAction::Propose { introducer_device_id, target_device_id, group_id } => {
                commands::introduce::propose(introducer_device_id, target_device_id, group_id).await
            }
            IntroduceAction::Pending { target_device } => {
                commands::introduce::list_pending(target_device).await
            }
            IntroduceAction::Accept { introduction_id } => {
                commands::introduce::accept(introduction_id).await
            }
            IntroduceAction::Reject { introduction_id } => {
                commands::introduce::reject(introduction_id).await
            }
        },
    }
}

fn prompt_password(prompt: &str) -> Result<String, CliError> {
    rpassword::prompt_password(prompt).map_err(|e| CliError::Other(e.to_string()))
}

/// Prompts for `label` twice (masked) and requires both entries to match --
/// shared by the new-password flow (`Register`) and the new-passphrase flow
/// (`export-key-bundle`).
fn prompt_confirmed(label: &str) -> Result<String, CliError> {
    let value = prompt_password(&format!("{label}: "))?;
    let confirm = prompt_password(&format!("Confirm {}: ", label.to_lowercase()))?;
    if value != confirm {
        return Err(CliError::Other(format!("{label}s do not match")));
    }
    Ok(value)
}

#[cfg(not(feature = "http-coordination"))]
fn prompt_new_password() -> Result<String, CliError> {
    prompt_confirmed("Password")
}

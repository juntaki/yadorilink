//! Long-running sync daemon: loads persistent local state,
//! opens the CLI control socket, and — once logged in and registered —
//! connects to the coordination plane's netmap and establishes peer sync
//! sessions.
//!
//! The whole daemon lifecycle lives here in the library, behind
//! [`run`], rather than inline in `main.rs`. `main.rs` is now only a thin
//! entry point that builds the real (production) tokio runtime and calls
//! [`run`]; keeping the lifecycle in the library is what lets a
//! deterministic-simulation node drive an in-process daemon instance by
//! calling [`run`] with a simulated [`DaemonConfig`] directly, instead of
//! going through the real process entry point.
//!
//! Every essential task (control socket, shell-integration IPC,
//! peer orchestrator) is supervised together in one [`EssentialTasks`] set
//! at the bottom of [`run`] — if *any* of them exits or panics, the daemon
//! logs it clearly and exits non-zero so a process supervisor restarts it,
//! instead of coupling liveness solely to the control socket (the old
//! `control_socket_task.await?`) and silently continuing as a zombie with
//! broken sync. The same top-level `select!` also races that
//! against SIGTERM/SIGINT (and the control socket's `Shutdown` request,
//! routed in via `DaemonState::shutdown_tx`) to run a graceful shutdown
//! instead.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use yadorilink_local_storage::FsBlockStore;
// The `BlockStore` trait itself is only named in the simulator-only
// pre-built-store seam (see `DaemonConfig::block_store_override` and its use
// in `run`); production builds only ever construct the concrete
// `FsBlockStore`, so importing the trait there would be an unused import.
#[cfg(madsim)]
use yadorilink_local_storage::BlockStore;
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::materialization;
use yadorilink_transport::DeviceKeyPair;

use crate::daemon_state::DaemonState;
use crate::device_config::config_dir;
use crate::supervise::EssentialTasks;
use crate::{device_config, link_manager, peer_orchestrator, token_store};
// The control-socket and shell-IPC transports are not started under the
// deterministic simulator (their essential tasks are `cfg(not(madsim))` —
// see `run`), so their modules go unused there.
#[cfg(not(madsim))]
use crate::{control_socket, shell_ipc};

/// Names used both for the essential-task logging and for
/// `DaemonState::task_liveness` (health surface) — kept as
/// constants so the two always agree.
// Under the deterministic simulator the control-socket and shell-IPC
// essential tasks are not started (their Unix-domain-socket transports
// have no in-sim equivalent — see `run`), so these two names go unused
// there; the `allow(dead_code)` keeps that intentional gap warning-free
// without changing the production build in any way.
#[cfg_attr(madsim, allow(dead_code))]
const TASK_CONTROL_SOCKET: &str = "control-socket";
#[cfg_attr(madsim, allow(dead_code))]
const TASK_SHELL_IPC: &str = "shell-ipc-server";
const TASK_PEER_ORCHESTRATOR: &str = "peer-orchestrator";
#[cfg(not(madsim))]
const DAEMON_INSTANCE_LOCK_FILE: &str = ".daemon.lock";

/// Process-lifetime ownership of one config directory. The OS releases the
/// advisory lock when the process exits, including SIGKILL/crash paths; the
/// file itself deliberately remains so restart never relies on PID parsing or
/// stale-file deletion.
#[cfg(not(madsim))]
#[derive(Debug)]
struct DaemonInstanceLock {
    _file: std::fs::File,
}

#[cfg(not(madsim))]
impl DaemonInstanceLock {
    fn acquire(config_dir: &std::path::Path) -> anyhow::Result<Self> {
        use std::fs::OpenOptions;

        std::fs::create_dir_all(config_dir)?;
        let lock_path = config_dir.join(DAEMON_INSTANCE_LOCK_FILE);
        let file = OpenOptions::new().create(true).read(true).write(true).open(&lock_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600))?;
        }
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => Ok(Self { _file: file }),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => anyhow::bail!(
                "another YadoriLink daemon is already running for {}",
                config_dir.display()
            ),
            Err(error) => Err(anyhow::anyhow!(
                "failed to acquire daemon instance lock {}: {error}",
                lock_path.display()
            )),
        }
    }
}

/// How often `pending_enrollment::reconcile` re-runs after its first pass at
/// startup. A few minutes: far below `daemon_state`'s hour-scale
/// retention-expiry sweep (retrying a coordination-plane call is cheap, so
/// there's no reason to wait that long), but well above its sub-two-minute
/// materialization-repair/disk-reconcile cadences (this is a crash-recovery
/// backstop for a killed CLI process, not a live sync path racing user-visible
/// staleness).
#[cfg_attr(madsim, allow(dead_code))]
const PENDING_ENROLLMENT_RECONCILE_SWEEP_INTERVAL: Duration = Duration::from_secs(300);

/// A slot a deterministic-simulation smoke test passes into
/// [`DaemonConfig::state_probe`] so it can obtain the in-process
/// [`DaemonState`](crate::daemon_state::DaemonState) that [`run`] builds —
/// `run` never returns its state (it owns the whole lifecycle), so this is
/// how an in-sim driver reaches in to link folders and request shutdown.
/// Exists only under `--cfg madsim`; production has no such seam.
#[cfg(madsim)]
pub type StateProbe =
    std::sync::Arc<std::sync::Mutex<Option<Arc<crate::daemon_state::DaemonState>>>>;

/// Filesystem locations the daemon operates over. Extracted from the
/// process environment for the real binary ([`DaemonConfig::from_env`]),
/// but passed in explicitly so a single OS process running many simulated
/// daemon instances can give each its own isolated paths rather than
/// sharing one set of process-global environment variables / socket paths.
// `Debug` and `Clone` are derived only in production. Under the simulator
// the added `state_probe` slot holds an `Arc<DaemonState>` (not `Debug`),
// and the `sim_discovery` slot holds a pre-bound `UdpSocket` (not `Clone`);
// deriving either there would fail, and nothing in-sim clones or debugs a
// `DaemonConfig` (it is always moved by value into `run`).
#[cfg_attr(not(madsim), derive(Debug, Clone))]
pub struct DaemonConfig {
    /// Base configuration directory; also where per-daemon config files
    /// (device config, metrics config, ...) are read from.
    pub config_dir: PathBuf,
    pub block_store_root: PathBuf,
    pub sync_db_path: PathBuf,
    #[cfg(unix)]
    pub control_socket_path: PathBuf,
    #[cfg(unix)]
    pub shell_ipc_socket_path: PathBuf,
    pub keypair_path: PathBuf,
    /// (simulator only) When `Some`, [`run`] publishes the `DaemonState` it
    /// builds into this slot so an in-sim smoke test can drive it. Always
    /// `None`/absent in production ([`DaemonConfig::from_env`] never sets it).
    #[cfg(madsim)]
    pub state_probe: Option<StateProbe>,
    /// (simulator only) When `Some`, [`run`] starts the peer orchestrator's
    /// static-netmap seam ([`peer_orchestrator::run_sim`]) with this
    /// harness-supplied discovery input instead of the real coordination
    /// netmap stream, and uses its `local_device_id` for the `DaemonState`
    /// device identity. This is how two in-sim daemons pair up and sync
    /// without the (not-in-simulation) coordination server. Always `None` in
    /// production ([`DaemonConfig::from_env`] never sets it).
    #[cfg(madsim)]
    pub sim_discovery: Option<peer_orchestrator::SimDiscovery>,
    /// (simulator only) When `Some`, [`run`] uses this pre-built block store
    /// verbatim instead of constructing a plain [`FsBlockStore`] over
    /// [`block_store_root`](Self::block_store_root). This is the fault-injection
    /// seam: a deterministic-simulation test can hand the daemon a
    /// `FaultingBlockStore` wrapping the real `FsBlockStore` so the
    /// materialization/hydration error paths (ENOSPC / EIO / torn writes)
    /// are exercised through the real daemon end to end. Always `None` in
    /// production ([`DaemonConfig::from_env`] never sets it), so the real
    /// binary's storage behavior is unchanged.
    #[cfg(madsim)]
    pub block_store_override: Option<Arc<dyn BlockStore + Send + Sync>>,
}

impl DaemonConfig {
    /// Builds the configuration exactly as the real daemon binary always
    /// has: `config_dir()` plus the same `YADORILINK_*` environment
    /// overrides, each defaulting to a path under the config directory.
    pub fn from_env() -> Self {
        let dir = config_dir();

        let block_store_root = std::env::var("YADORILINK_BLOCK_STORE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| dir.join("blocks"));
        let sync_db_path = std::env::var("YADORILINK_SYNC_DB")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| dir.join("sync-state.sqlite3"));
        #[cfg(unix)]
        let control_socket_path = std::env::var("YADORILINK_CONTROL_SOCKET")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| dir.join("daemon.sock"));
        #[cfg(unix)]
        let shell_ipc_socket_path = std::env::var("YADORILINK_SHELL_IPC_SOCKET")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| dir.join("shell.sock"));
        let keypair_path = std::env::var("YADORILINK_WG_KEY")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| dir.join("wg_key"));

        Self {
            config_dir: dir,
            block_store_root,
            sync_db_path,
            #[cfg(unix)]
            control_socket_path,
            #[cfg(unix)]
            shell_ipc_socket_path,
            keypair_path,
            // The real binary is never driven by an in-sim probe.
            #[cfg(madsim)]
            state_probe: None,
            // The real binary always discovers peers over the coordination
            // netmap stream, never a harness-supplied static netmap.
            #[cfg(madsim)]
            sim_discovery: None,
            // The real binary always builds its own `FsBlockStore`; only an
            // in-sim fault-injection test supplies a decorated store.
            #[cfg(madsim)]
            block_store_override: None,
        }
    }
}

/// Runs the daemon to completion (graceful shutdown) or a fatal
/// essential-task death. This is the whole daemon lifecycle; `main` only
/// builds the real runtime and awaits this.
/// Release-only trust-root tripwire, run as the very first step of daemon
/// startup: a binary built with the `enforce-release-trust-root` feature
/// requires compile-time release public-key configuration and refuses to start
/// (hard error, before serving anything) if it is malformed or still pins the
/// forgeable development key, unless the explicit dev override is set.
/// Developer builds (feature off) compile this to a no-op and are unaffected. See
/// `update::manifest::enforce_release_trust_root_gate`.
#[cfg(feature = "enforce-release-trust-root")]
fn enforce_trust_root_gate_at_startup() -> anyhow::Result<()> {
    crate::update::manifest::enforce_release_trust_root_gate().map_err(|reason| {
        anyhow::anyhow!(
            "refusing to start: update trust-root release gate rejected this build: {reason}"
        )
    })
}

pub async fn run(config: DaemonConfig) -> anyhow::Result<()> {
    #[cfg(feature = "enforce-release-trust-root")]
    enforce_trust_root_gate_at_startup()?;

    let dir = config.config_dir;
    std::fs::create_dir_all(&dir)?;
    // Acquire before opening the block store/SQLite or touching either Unix
    // socket. In particular, a losing process must never unlink the live
    // daemon's socket before discovering that it does not own this config.
    #[cfg(not(madsim))]
    let _instance_lock = DaemonInstanceLock::acquire(&dir)?;

    // Validate this device's identity config before any data-plane startup
    // work: everything below this point mutates persistent state. The resource
    // locks create the block-store root and the database's parent directory,
    // `SyncState::open` runs schema migrations, and the repair pass rewrites
    // files inside every linked folder. An unsupported downgrade is precisely
    // the case where none of that may happen — a newer build wrote this
    // config, so a newer database schema is likely on disk beside it, and
    // migrating or repairing that with this build's older understanding is how
    // a downgrade turns into permanent damage. Refusing here is free: `load`
    // reads a single file and depends on neither the database nor the block
    // store, so the only ordering constraint is the instance lock above, which
    // still comes first so a daemon that does not own this config dir never
    // reports on its contents.
    let device_config = match device_config::load() {
        // Genuine absence (`Ok(None)`) legitimately means "not registered
        // yet" and is the only condition allowed to mean that.
        Ok(cfg) => cfg,
        // Each failure names its own condition and its own remedy. They must
        // not collapse into one message: the remedy for a corrupt file
        // ("remove it and register again") is destructive when applied to a
        // downgrade, where the device *is* registered and re-registering
        // mints a second identity for one physical device that nothing can
        // merge back afterwards (see `DeviceConfigError`'s doc comment).
        // Matched exhaustively with no catch-all arm, so a variant added
        // later must state its own case here instead of silently inheriting
        // a wrong one.
        Err(e @ device_config::DeviceConfigError::UnsupportedConfigDowngrade { .. }) => {
            return Err(anyhow::anyhow!(
                "refusing to start: {e}. Nothing on disk has been modified, and this device is \
                 still registered: do not delete device.json and do not run `yadorilink device \
                 register` again, which would register a second identity for this one device."
            ));
        }
        Err(e @ device_config::DeviceConfigError::Read { .. }) => {
            return Err(anyhow::anyhow!(
                "refusing to start: {e}. device.json exists but could not be read, so this \
                 device's registration is unknown rather than absent -- usually a permissions \
                 problem, and often transient. Restore access to the file and start again rather \
                 than registering this device again."
            ));
        }
        Err(e @ device_config::DeviceConfigError::Corrupt { .. }) => {
            return Err(anyhow::anyhow!(
                "refusing to start: {e}. Restore device.json from a backup if one exists. \
                 Running `yadorilink device register` again registers a new identity for this \
                 device rather than recovering the old one, and changes already made under the \
                 previous device id stay attributed to it."
            ));
        }
    };

    let block_store_root = config.block_store_root;
    let sync_db_path = config.sync_db_path;
    let keypair_path = config.keypair_path;

    // Registration makes both private keys immutable identity state. Validate
    // them together before acquiring data-resource locks, opening the block
    // store/SQLite, running migrations, or repairing linked files. Keep these
    // exact loaded values for later wiring so no second read can observe a
    // different file after persistent startup work has begun. Not cfg-gated:
    // `load_existing` is plain synchronous file I/O with no tokio/madsim
    // dependency, and the coordination-plane connect branch below needs the
    // transport keypair (to seed the shared hub's static public key) under
    // the simulator too, not just in production.
    let registered_identity = if device_config.is_some() {
        Some((
            Arc::new(DeviceKeyPair::load_existing(&keypair_path)?),
            yadorilink_transport::DeviceSigningKeyPair::load_existing(dir.join("signing_key"))?,
        ))
    } else {
        None
    };

    // Additive to the config-dir lock above: take exclusive OS locks on the
    // block-store root and the sync-state database *before* opening either
    // (`FsBlockStore::new`/`SyncState::open` below), so a losing daemon never
    // mutates them. The config-dir lock alone does not cover this: the store
    // root and database paths are independently overridable, so two daemons
    // with distinct config dirs could otherwise be aimed at the same store/DB
    // and corrupt them. Deterministic acquisition order (config dir → block
    // store → DB) prevents cross-instance deadlock; on conflict the
    // already-acquired lock is released (RAII) as `run` returns the error.
    #[cfg(not(madsim))]
    let _data_resource_locks =
        crate::resource_lock::DataResourceLocks::acquire(&block_store_root, &sync_db_path)?;

    #[cfg(unix)]
    let control_socket_path = config.control_socket_path;
    #[cfg(unix)]
    let shell_ipc_socket_path = config.shell_ipc_socket_path;
    #[cfg(madsim)]
    let state_probe = config.state_probe;
    #[cfg(madsim)]
    let sim_discovery = config.sim_discovery;
    #[cfg(madsim)]
    let block_store_override = config.block_store_override;

    // A severe-error hook for the
    // two fallible startup calls that would otherwise abort startup before
    // `DaemonState` (and therefore `state.reporting`) exists — opens a
    // throwaway `ReportingStorage` over the same config directory rather
    // than waiting for `DaemonState::new`, since a failure here is exactly
    // the kind of thing a maintainer would want a local candidate for.
    #[cfg(not(madsim))]
    let block_store = Arc::new(FsBlockStore::new(&block_store_root).inspect_err(|e| {
        record_startup_error_best_effort("daemon_startup", "block-store", e.to_string());
    })?);
    // (simulator only) Prefer a harness-supplied, pre-built block store (a
    // fault-injecting decorator over the real `FsBlockStore`) when present, so
    // storage-layer faults are exercised through the identical production
    // materialization/hydration code path. Absent an override this builds the
    // exact same `FsBlockStore` production does. The `Arc<dyn BlockStore>`
    // annotation matches `DaemonState`'s own field type, into which this is
    // handed unchanged below.
    #[cfg(madsim)]
    let block_store: Arc<dyn BlockStore + Send + Sync> = match block_store_override {
        Some(store) => store,
        None => Arc::new(FsBlockStore::new(&block_store_root).inspect_err(|e| {
            record_startup_error_best_effort("daemon_startup", "block-store", e.to_string());
        })?),
    };
    let sync_state = Arc::new(SyncState::open(&sync_db_path).inspect_err(|e| {
        record_startup_error_best_effort("daemon_startup", "sync-state", e.to_string());
    })?);

    // Recover any file left permanently stuck `Hydrating` by a
    // previous crash before anything else runs — see
    // `SyncState::reset_stale_hydrating_to_placeholder`'s doc comment.
    match sync_state.reset_stale_hydrating_to_placeholder() {
        Ok(0) => {}
        Ok(n) => tracing::info!(count = n, "reset stale Hydrating rows to Placeholder on startup"),
        Err(e) => tracing::warn!(error = %e, "failed to reset stale Hydrating rows on startup"),
    }

    // Recover any file left permanently stuck `Evicting` by a crash mid-eviction
    // (before its placeholder commit) — otherwise nothing ever reconciles it and
    // the file is wedged. Reset to `Placeholder` (blocks are always still
    // retained at this point), the state safe for both interrupted-eviction disk
    // cases — see `SyncState::reset_stale_evicting_to_placeholder`'s doc comment.
    match sync_state.reset_stale_evicting_to_placeholder() {
        Ok(0) => {}
        Ok(n) => tracing::info!(count = n, "reset stale Evicting rows to Placeholder on startup"),
        Err(e) => tracing::warn!(error = %e, "failed to reset stale Evicting rows on startup"),
    }

    // Run before any link
    // watcher starts or any new write happens, so nothing new can be
    // mistaken for one of last run's orphaned temp files, and no on-demand
    // hydration/materialize can race the repair pass below. Order matters:
    // the block-store root's own stale temp files are cleaned first
    // (`FsBlockStore::put` uses the identical `unique_tmp_path` naming
    // scheme as `chunker.rs`), then each link's local folder, then the
    // per-link `Hydrated`-but-inconsistent repair — see
    // `materialization::repair_interrupted_materializations`'s doc comment
    // for exactly which crash window this closes (the one the
    // `Hydrating` reset above does not: a crash between the index commit
    // and the completed rename of an *eager* materialization write).
    let stale_block_store_tmp = materialization::cleanup_stale_temp_files(&block_store_root);
    if !stale_block_store_tmp.is_empty() {
        tracing::info!(
            count = stale_block_store_tmp.len(),
            "removed stale temp files from block store on startup"
        );
    }
    // Links (by `local_path`) whose startup interrupted-materialization repair
    // errored this boot. Their initial reconcile scan must NOT emit any
    // missing-file tombstone this boot: repair is the crash-vs-offline-delete
    // disambiguator, and without it a `Hydrated`-but-missing file (a crash
    // mid-materialize, reconstructable from present blocks) is indistinguishable
    // from a genuine offline deletion. Fail-closed — defer the delete decision
    // to a later boot on which repair succeeds. Consulted at the
    // `start_link_watch_gating_tombstones` call below.
    let mut repair_failed_local_paths: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    // Enumerate the links ONCE, for both the repair pass here and the watcher
    // resume further down, and fail startup if the table cannot be read.
    // Collapsing this error into "there are no links" would silently skip both
    // passes -- no crash-recovery repair, and no watcher or startup scan for any
    // folder -- while the peer path, which resolves its roots from the same
    // table independently, would carry on applying changes into folders this
    // boot never scanned. A daemon that cannot read its own link table has
    // nothing safe to do, so it must not pretend it has no work.
    let links = sync_state.list_links()?;
    for link in &links {
        // An orphaned link's coordination-side authorization is confirmed
        // gone -- this repair pass writes to disk (removing temp files,
        // reconstructing/rewriting placeholders), which would violate
        // "orphaned never touches on-disk files" the same way any other
        // sync activity would.
        if link.orphaned {
            continue;
        }
        let root = PathBuf::from(&link.local_path);
        match materialization::reconcile_restore_operations(&sync_state, &root, &link.group_id) {
            Ok(report)
                if report.committed.is_empty()
                    && report.discarded_unstarted.is_empty()
                    && report.preserved_divergent.is_empty() => {}
            Ok(report) => tracing::info!(
                local_path = %link.local_path,
                committed = report.committed.len(),
                discarded_unstarted = report.discarded_unstarted.len(),
                preserved_divergent = report.preserved_divergent.len(),
                "reconciled interrupted restore operations on startup"
            ),
            Err(e) => {
                return Err(e.into());
            }
        }
        let stale_tmp = materialization::cleanup_stale_temp_files(&root);
        if !stale_tmp.is_empty() {
            tracing::info!(
                count = stale_tmp.len(),
                local_path = %link.local_path,
                "removed stale temp files from linked folder on startup"
            );
        }
        match materialization::repair_interrupted_materializations(
            &sync_state,
            block_store.as_ref(),
            &root,
            &link.group_id,
        ) {
            Ok(report) if report.is_empty() => {}
            Ok(report) => tracing::info!(
                local_path = %link.local_path,
                reconstructed = report.reconstructed.len(),
                demoted_to_placeholder = report.demoted_to_placeholder.len(),
                "repaired interrupted materializations found on startup"
            ),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    local_path = %link.local_path,
                    "failed to run startup materialization repair for linked folder; \
                     deferring this boot's initial-scan delete emission for it"
                );
                repair_failed_local_paths.insert(link.local_path.clone());
            }
        }
    }

    #[cfg(not(madsim))]
    let device_id = device_config.as_ref().map(|c| c.device_id.clone()).unwrap_or_default();
    // Under the simulator a harness-supplied static netmap carries this
    // device's identity directly (an in-sim daemon is not "logged in", so
    // `device_config` is absent and every daemon would otherwise share the
    // same empty device id -- which version vectors and peer-session
    // identity depend on being distinct).
    #[cfg(madsim)]
    let device_id = match &sim_discovery {
        Some(sim) => sim.local_device_id.clone(),
        None => device_config.as_ref().map(|c| c.device_id.clone()).unwrap_or_default(),
    };

    let state = DaemonState::new(device_id.clone(), sync_state.clone(), block_store.clone());
    // Only the real `yadorilink-daemon`
    // binary itself opts into disk-headroom enforcement — see
    // `DaemonState::enable_disk_headroom_enforcement`'s doc comment for why
    // this is not done inside `DaemonState::new` (which every test in this
    // crate also goes through).
    state.enable_disk_headroom_enforcement();

    // Wire the generation-stamped peer custody confirmer. Physical cache
    // reclamation remains disabled until the responder can persist a custody
    // lease as a GC root; the real daemon keeps the exact-version protocol
    // available for diagnostics and that future lease flow.
    #[cfg(not(madsim))]
    state.install_p2p_custody_confirmer();

    // Wire this device's change-history signing key once, so linked folders
    // emit signed changes. Only for a registered device (an unregistered one
    // has no identity to attribute changes to), and not under the simulator,
    // whose in-process daemons drive emission through their own seams.
    #[cfg(not(madsim))]
    if let Some((_, signing)) = registered_identity.as_ref() {
        state.set_device_signing_key(signing.signing.clone());
    }

    // Deterministic-simulation seam: hand the just-built `DaemonState` to an
    // in-sim smoke-test driver (if one supplied a probe) so it can link
    // folders and request shutdown against this exact instance. Published
    // here — after `DaemonState::new` but before the essential-task set and
    // the top-level `select!` — so the driver observes the daemon at steady
    // state. A no-op in production (`state_probe` is always `None` there).
    #[cfg(madsim)]
    if let Some(probe) = state_probe {
        *probe.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(state.clone());
    }

    // Opt-in `/metrics`
    // endpoint — off/localhost-only by default. The env var (if set)
    // always wins over the persisted `metrics_config.json` toggle
    // (`yadorilink daemon metrics`), so an operator's explicit env-based
    // override takes precedence, with the persisted config as this
    // binary's own additional, CLI-settable fallback.
    let metrics_addr = std::env::var("YADORILINK_DAEMON_METRICS_ADDR").ok().or_else(|| {
        let config = crate::metrics_config::MetricsConfigStore::new(&dir).load_or_default();
        config.enabled.then_some(config.bind_addr)
    });
    if let Some(metrics_addr) = metrics_addr {
        match tokio::net::TcpListener::bind(&metrics_addr).await {
            Ok(metrics_listener) => {
                let metrics = crate::metrics::DaemonMetrics::new(state.clone());
                tracing::info!(addr = metrics_addr, "yadorilink-daemon metrics listening");
                crate::supervise::spawn_logged("daemon-metrics-http", async move {
                    serve_metrics(metrics_listener, metrics).await;
                    Ok(())
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, addr = metrics_addr, "failed to bind daemon metrics listener; metrics endpoint disabled for this run");
            }
        }
    }

    // Resume watching every previously-linked folder (local
    // state persistence across restarts: links survive, and their
    // watchers are simply restarted). An orphaned link's watcher is never
    // restarted here -- it was stopped the moment `pending_enrollment::
    // reconcile` marked it orphaned, and staying stopped across restarts is
    // exactly what "no longer a live sync target" means; its on-disk files
    // are untouched either way.
    for link in &links {
        if link.orphaned {
            continue;
        }
        // Suppress this link's initial-scan tombstone emission for this boot
        // when its startup materialization repair errored above (fail-closed:
        // a crash-mid-materialize that repair could not disambiguate this boot
        // must not be misread as an offline delete and propagated group-wide).
        //
        // The additive-scan flag a two-live-roots recovery arms on the survivor
        // is NOT consulted here: `start_link_watch_inner` reads it itself and
        // ANDs it with this, so every entry point that starts a watch honours it
        // rather than only the one caller that remembered to.
        let emit_tombstones = !repair_failed_local_paths.contains(&link.local_path);
        if let Err(e) = link_manager::start_link_watch_gating_tombstones(
            state.clone(),
            link.local_path.clone(),
            link.group_id.clone(),
            emit_tombstones,
        ) {
            // Continuing is deliberate: one unwatchable folder must not stop the
            // daemon for every other link. It is only safe because
            // `start_link_watch_inner` arms this group's startup gate before any
            // fallible step, so the failure leaves the gate Failed and peer apply
            // for this group defers rather than overwriting un-indexed local
            // content. Error, not warn: this folder syncs nothing until fixed.
            tracing::error!(error = %e, local_path = %link.local_path, "failed to resume watching linked folder; this folder will not sync until startup succeeds for it");
        }
    }

    // Every essential task lives in this one supervisor set instead
    // of a bare `tokio::spawn` with its handle dropped (shell-IPC, peer
    // orchestrator) or awaited on its own at the very end (control
    // socket, coupling process liveness to just that one task). Spawning
    // directly into the set (rather than wrapping `supervise::spawn_logged`
    // handles) means `essential.shutdown()` during graceful shutdown
    // actually aborts the running task itself, not just a wrapper awaiting
    // it.
    let mut essential = EssentialTasks::new();

    // Not started under the deterministic simulator: the control socket's
    // Unix-domain-socket transport has no in-sim equivalent, and a smoke
    // test drives the daemon through `DaemonState`/`shutdown_tx` directly
    // (see the `state_probe` seam above) rather than over this socket.
    // Production (`not(madsim)`) is byte-for-byte unchanged.
    #[cfg(all(unix, not(madsim)))]
    {
        let state = state.clone();
        let path = control_socket_path.clone();
        state.set_task_alive(TASK_CONTROL_SOCKET, true);
        essential.spawn(async move {
            if let Err(e) = control_socket::unix_transport::serve(&path, state.clone()).await {
                tracing::error!(error = %e, task = TASK_CONTROL_SOCKET, "essential task failed");
            } else {
                tracing::warn!(task = TASK_CONTROL_SOCKET, "essential task exited");
            }
            state.set_task_alive(TASK_CONTROL_SOCKET, false);
            TASK_CONTROL_SOCKET
        });
    }
    #[cfg(windows)]
    {
        let state = state.clone();
        let pipe_name = device_config::control_pipe_name();
        state.set_task_alive(TASK_CONTROL_SOCKET, true);
        essential.spawn(async move {
            if let Err(e) =
                control_socket::windows_transport::serve(&pipe_name, state.clone()).await
            {
                tracing::error!(error = %e, task = TASK_CONTROL_SOCKET, "essential task failed");
            } else {
                tracing::warn!(task = TASK_CONTROL_SOCKET, "essential task exited");
            }
            state.set_task_alive(TASK_CONTROL_SOCKET, false);
            TASK_CONTROL_SOCKET
        });
    }

    // Not started under the simulator, same rationale as the control
    // socket above (no in-sim Unix-domain-socket transport).
    #[cfg(all(unix, not(madsim)))]
    {
        let state = state.clone();
        let path = shell_ipc_socket_path.clone();
        state.set_task_alive(TASK_SHELL_IPC, true);
        essential.spawn(async move {
            if let Err(e) = shell_ipc::unix_transport::serve(&path, state.clone()).await {
                tracing::error!(error = %e, task = TASK_SHELL_IPC, "essential task failed");
            } else {
                tracing::warn!(task = TASK_SHELL_IPC, "essential task exited");
            }
            state.set_task_alive(TASK_SHELL_IPC, false);
            TASK_SHELL_IPC
        });
    }
    #[cfg(windows)]
    {
        let state = state.clone();
        let pipe_name = device_config::shell_ipc_pipe_name();
        state.set_task_alive(TASK_SHELL_IPC, true);
        essential.spawn(async move {
            if let Err(e) = shell_ipc::windows_transport::serve(&pipe_name, state.clone()).await {
                tracing::error!(error = %e, task = TASK_SHELL_IPC, "essential task failed");
            } else {
                tracing::warn!(task = TASK_SHELL_IPC, "essential task exited");
            }
            state.set_task_alive(TASK_SHELL_IPC, false);
            TASK_SHELL_IPC
        });
    }

    match (device_config, token_store::load_access_token()) {
        (Some(cfg), Some(access_token)) => {
            // A persisted registration pins this device's public transport key
            // at the coordination plane. Missing key material is therefore a
            // fatal identity-loss error, never an invitation to mint a new key
            // peers do not recognize.
            let keypair = registered_identity
                .as_ref()
                .expect("registered device keys were validated before persistent startup")
                .0
                .clone();
            tracing::info!(device_id = %cfg.device_id, "connecting to coordination plane");

            // Best-effort, production-only coordination-plane wiring, spawned
            // before the orchestrator moves `cfg`/`access_token` into its
            // config. Not run under the deterministic simulator (no real
            // coordination plane, network, or gateway):
            //  - a one-time, idempotent signing-key backfill so a device
            //    registered before change-history signing keys existed still
            //    gets its key recorded and distributed to peers (set-once on
            //    the server, so re-running it every startup is a no-op);
            //  - NAT-traversal candidate gathering (STUN + router port
            //    mapping) that keeps the coordination plane's view of this
            //    device's direct-connection candidates current.
            // Seed the device static public key before any transport-using
            // task binds the shared hub, so the hub's MAC1 initiation gate is
            // keyed on this device from the first bind.
            state.set_device_static_public(keypair.public_bytes());

            #[cfg(not(madsim))]
            {
                let addr = cfg.coordination_addr.clone();
                let token = access_token.clone();
                let device_id = cfg.device_id.clone();
                let nat_config = cfg.nat.clone();
                let nat_state = state.clone();

                // Recorded once, up front, so any control-socket request the
                // CLI issues from this point on (currently only the
                // full-replica-handoff lease request) can make its own
                // coordination-plane calls without needing `coordination_addr`/
                // `access_token` threaded through as extra parameters -- see
                // `DaemonState::coordination_client_config`'s doc comment.
                state.set_coordination_client_config(addr.clone(), token.clone());

                if let Some((_, signing)) = registered_identity.as_ref() {
                    let addr = addr.clone();
                    let token = token.clone();
                    let device_id = device_id.clone();
                    let signing_public_key = signing.public_bytes().to_vec();
                    crate::supervise::spawn_logged("signing-key-backfill", async move {
                        crate::coordination_client::upload_signing_key(
                            &addr,
                            &token,
                            device_id,
                            signing_public_key,
                        )
                        .await;
                        Ok(())
                    });
                }

                // Crash-safe create/join enrollment (see `pending_enrollment`'s
                // module doc): finish confirming (or, failing that, cancel) any
                // local link this device committed whose matching
                // coordination-plane activation never got confirmed -- the CLI
                // process that would have done so was killed first, or its own
                // confirmation call never reached the daemon. Runs once
                // immediately (covering a marker left over from before this
                // startup) and then on a fixed interval, so a marker left
                // behind by a killed CLI process is retried without needing a
                // daemon restart to notice it. Best-effort and self-healing
                // like the signing-key backfill above: a sweep that can't reach
                // the coordination plane leaves its marker in place for the
                // next one.
                {
                    let addr = addr.clone();
                    let token = token.clone();
                    let state = state.clone();
                    crate::supervise::spawn_logged("pending-enrollment-reconcile", async move {
                        let mut interval =
                            tokio::time::interval(PENDING_ENROLLMENT_RECONCILE_SWEEP_INTERVAL);
                        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                        loop {
                            interval.tick().await;
                            crate::pending_enrollment::reconcile(&state, &addr, &token).await;
                        }
                    });
                }

                crate::supervise::spawn_logged("nat-traversal", async move {
                    crate::nat_traversal::run(nat_config, addr, token, device_id, nat_state).await;
                    Ok(())
                });
            }

            let orchestrator_config = peer_orchestrator::OrchestratorConfig {
                coordination_addr: cfg.coordination_addr,
                access_token,
                device_id: cfg.device_id,
            };
            let state = state.clone();
            state.set_task_alive(TASK_PEER_ORCHESTRATOR, true);
            essential.spawn(async move {
                if let Err(e) = peer_orchestrator::run(orchestrator_config, keypair, state.clone()).await
                {
                    tracing::error!(error = %e, task = TASK_PEER_ORCHESTRATOR, "essential task failed");
                } else {
                    tracing::warn!(task = TASK_PEER_ORCHESTRATOR, "essential task exited");
                }
                state.set_task_alive(TASK_PEER_ORCHESTRATOR, false);
                TASK_PEER_ORCHESTRATOR
            });
        }
        _ => {
            tracing::warn!(
                "not logged in or no device registered yet — running with local link management only; run `yadorilink login` and `yadorilink device register` to enable P2P sync"
            );
        }
    }

    // Deterministic-simulation discovery seam: when the harness supplies a
    // static netmap, run the peer orchestrator's `run_sim` variant (peer
    // channels over madsim's simulated UDP) as the same supervised
    // essential task the real `peer_orchestrator::run` would occupy.
    // Production never takes this path (`sim_discovery` is always `None`
    // there).
    #[cfg(madsim)]
    if let Some(sim) = sim_discovery {
        let state = state.clone();
        state.set_task_alive(TASK_PEER_ORCHESTRATOR, true);
        essential.spawn(async move {
            if let Err(e) = peer_orchestrator::run_sim(sim, state.clone()).await {
                tracing::error!(error = %e, task = TASK_PEER_ORCHESTRATOR, "essential task failed");
            } else {
                tracing::warn!(task = TASK_PEER_ORCHESTRATOR, "essential task exited");
            }
            state.set_task_alive(TASK_PEER_ORCHESTRATOR, false);
            TASK_PEER_ORCHESTRATOR
        });
    }

    #[cfg(unix)]
    let socket_paths = vec![control_socket_path.clone(), shell_ipc_socket_path.clone()];
    #[cfg(windows)]
    let socket_paths: Vec<PathBuf> = Vec::new(); // named pipes have no filesystem entry to remove

    let mut shutdown_rx = state.shutdown_tx.subscribe();
    tokio::select! {
        reason = wait_for_shutdown_request(&mut shutdown_rx) => {
            tracing::info!(reason, "shutdown requested; starting graceful shutdown");
            graceful_shutdown(&state, &socket_paths, &mut essential).await;
            Ok(())
        }
        Some(joined) = essential.join_next() => {
            // `essential`'s own tasks never panic (each body already
            // catches and logs its inner `Result`), so `joined` is only
            // ever `Err` if the task was aborted from outside — which
            // only happens from `graceful_shutdown` below, by which point
            // we've already returned. Treat any other outcome as fatal.
            let name = joined.unwrap_or("unknown-task");
            tracing::error!(task = name, "essential task died; exiting non-zero so a process supervisor restarts the daemon");
            // An essential
            // supervised task dying is exactly the kind of severe,
            // maintainer-actionable failure this hook exists for — a
            // local-only candidate, never submitted automatically.
            crate::reporting::hooks::record_severe_error(
                &state.reporting,
                "essential_task_died",
                name,
                vec![format!("essential task '{name}' exited or was aborted unexpectedly")],
            );
            // Best-effort: still try to leave sockets/links in a clean
            // state before the hard exit below, but don't let a slow or
            // wedged cleanup delay the non-zero exit indefinitely — a
            // supervisor restarting an unhealthy daemon is the point.
            let cleanup = graceful_shutdown(&state, &socket_paths, &mut essential);
            let _ = tokio::time::timeout(Duration::from_secs(5), cleanup).await;
            std::process::exit(1);
        }
    }
}

/// Races SIGTERM/SIGINT (Unix) or Ctrl-C (Windows, which has no SIGTERM)
/// against the control socket's `Shutdown` request signaled through
/// `DaemonState::shutdown_tx` — either way, returns a short tag
/// naming which one fired, purely for the log line at the call site.
async fn wait_for_shutdown_request(
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> &'static str {
    tokio::select! {
        signal_name = wait_for_os_signal() => signal_name,
        _ = shutdown_rx.changed() => "control-socket Shutdown request",
    }
}

#[cfg(all(unix, not(madsim)))]
async fn wait_for_os_signal() -> &'static str {
    use tokio::signal::unix::{signal, SignalKind};
    // `signal()` only fails if the underlying OS signal registration
    // fails (e.g. an invalid `SignalKind`, never the case for a constant
    // here) — a daemon that can't even install its shutdown handler is
    // already in a bad enough state that panicking at startup is
    // reasonable, matching how the rest of startup treats setup failures
    // (`?` on `Connection::open`, etc.).
    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    tokio::select! {
        _ = sigterm.recv() => "SIGTERM",
        _ = tokio::signal::ctrl_c() => "SIGINT",
    }
}

/// Records a severe-error
/// candidate for a startup failure that happens before `DaemonState`
/// exists. Opens its own short-lived `ReportingStorage` handle (cheap —
/// see that type's doc comment on not writing anything just by opening)
/// rather than restructuring startup to build `DaemonState` earlier.
fn record_startup_error_best_effort(category: &str, subsystem: &str, message: String) {
    let storage = crate::reporting::ReportingStorage::open_default();
    crate::reporting::hooks::record_severe_error(&storage, category, subsystem, vec![message]);
}

/// Windows has no SIGTERM; a process supervisor there typically stops a
/// service via `Ctrl-C`/service-control events, which `tokio::signal::ctrl_c`
/// already covers cross-platform — no Windows-specific signal API needed
/// for this MVP — cfg-split only where the platforms genuinely differ,
/// e.g. named pipes vs Unix sockets.
#[cfg(all(windows, not(madsim)))]
async fn wait_for_os_signal() -> &'static str {
    let _ = tokio::signal::ctrl_c().await;
    "Ctrl-C"
}

/// Under the deterministic simulator there are no OS signals — madsim's
/// tokio shim has no `signal` module at all. A simulated daemon is shut
/// down exclusively through `DaemonState::shutdown_tx` (the same channel
/// the control socket's `Shutdown` request uses), so this side of the
/// `select!` simply never fires and the watch-channel branch drives every
/// in-sim shutdown.
#[cfg(madsim)]
async fn wait_for_os_signal() -> &'static str {
    std::future::pending().await
}

/// The one graceful-shutdown path both SIGTERM/SIGINT and the
/// control socket's `Shutdown` request (via `DaemonState::shutdown_tx`)
/// funnel into — previously the latter was a second, independent path
/// (`std::process::exit(0)` after a sleep) that skipped all of this.
async fn graceful_shutdown(
    state: &Arc<DaemonState>,
    socket_paths: &[PathBuf],
    essential: &mut EssentialTasks,
) {
    // Give an in-flight control-socket response (e.g. this shutdown
    // request's own ack) a moment to actually flush to its client before
    // sockets disappear and tasks get aborted out from under it —
    // matching the old control-socket-only code's 200ms grace period,
    // now applied uniformly to every shutdown path.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Stop generating new local changes first: abort every link's
    // watcher/executor tasks (the debounce accumulator and the flush
    // executor) before anything else,
    // so nothing new gets queued while the rest of shutdown runs.
    let link_tasks: Vec<_> =
        state.link_tasks.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).drain().collect();
    for (local_path, handles) in link_tasks {
        tracing::debug!(local_path, count = handles.len(), "aborting link watcher tasks");
        for handle in handles {
            handle.abort();
        }
    }

    // Drain in-flight broadcasts (bounded — see
    // `DaemonState::wait_for_broadcasts_to_drain`'s doc comment) before
    // tearing down the sessions that would otherwise cut them off.
    state.wait_for_broadcasts_to_drain(Duration::from_secs(3)).await;

    // SQLite checkpoint/flush: `yadorilink_sync_core::index::SyncState`
    // currently exposes no explicit checkpoint/close method (its
    // `rusqlite::Connection` is a private field with no `Drop` impl
    // beyond the default) — there is nothing in this crate's scope to
    // call here. Every write already goes through normal SQLite commits
    // (see `SyncState`'s per-call `Connection` usage), so this is a
    // WAL-checkpoint-on-clean-exit gap, not a durability gap; flagged as
    // a follow-up rather than inventing new `yadorilink-sync-core` API
    // from here.

    // Remove the socket files last, once nothing should be listening
    // through them anymore — a stale socket left behind after an
    // ungraceful kill is already handled by `unix_transport::serve`'s
    // own cleanup-on-bind, but doing it here too means a *graceful* exit
    // never leaves one lying around even briefly.
    for path in socket_paths {
        let _ = std::fs::remove_file(path);
    }

    // Finally, stop the essential tasks themselves (control socket,
    // shell IPC, peer orchestrator) — aborts whichever of them are still
    // running and awaits their abort, so this doesn't return until
    // they're actually gone.
    essential.shutdown().await;
}

/// The daemon's `/metrics`
/// listener loop — deliberately a minimal, dependency-free raw-HTTP
/// responder rather than a new framework: "don't invent a different metrics
/// framework" for the daemon and coordination metrics endpoints.
async fn serve_metrics(listener: tokio::net::TcpListener, metrics: crate::metrics::DaemonMetrics) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let Ok((mut stream, peer_addr)) = listener.accept().await else {
            continue;
        };
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let mut request = [0u8; 1024];
            let Ok(n) = stream.read(&mut request).await else { return };
            let first_line = std::str::from_utf8(&request[..n])
                .ok()
                .and_then(|req| req.lines().next())
                .unwrap_or("");
            let (status, body) = if first_line.starts_with("GET /metrics ") {
                ("200 OK", metrics.render_openmetrics())
            } else {
                ("404 Not Found", "not found\n".to_string())
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            if stream.write_all(response.as_bytes()).await.is_err() {
                tracing::debug!(%peer_addr, "failed to write daemon metrics response");
            }
        });
    }
}

#[cfg(all(test, feature = "enforce-release-trust-root"))]
mod trust_root_startup_tests {
    //! Only compiled/run when the `enforce-release-trust-root` feature is on,
    //! proving that a release-configured build's startup path actually
    //! enforces the update trust-root gate (rather than defining a gate with
    //! no caller). Exercises the exact helper `run` calls as its first step.
    use super::*;

    /// The startup gate's verdict must track
    /// `update::manifest::enforce_release_trust_root_gate` exactly, and when
    /// it rejects it must be a HARD error naming the reason -- so a release
    /// build with an invalid root cannot boot. Conditioned on the live gate
    /// result so it is deterministic
    /// regardless of whether a dev override is set in this environment.
    #[test]
    fn startup_path_enforces_the_trust_root_gate() {
        let startup = enforce_trust_root_gate_at_startup();
        if crate::update::manifest::enforce_release_trust_root_gate().is_ok() {
            // A real root is pinned (or the dev override is set): startup allowed.
            assert!(startup.is_ok());
        } else {
            // Placeholder/empty root and no override: startup MUST be refused.
            let err = startup.expect_err("startup must refuse a rejected trust root");
            let msg = format!("{err:#}");
            assert!(msg.contains("refusing to start"), "unexpected error: {msg}");
            assert!(msg.contains("trust-root"), "unexpected error: {msg}");
        }
    }
}

#[cfg(all(test, not(madsim)))]
mod instance_lock_tests {
    use super::*;

    #[test]
    fn second_daemon_for_the_same_config_is_rejected_until_owner_exits() {
        let dir = tempfile::tempdir().unwrap();
        let owner = DaemonInstanceLock::acquire(dir.path()).unwrap();

        let error = DaemonInstanceLock::acquire(dir.path())
            .err()
            .expect("a second daemon must not acquire the same config lock");
        assert!(error.to_string().contains("already running"));

        drop(owner);
        DaemonInstanceLock::acquire(dir.path())
            .expect("a stale lock file must be reusable after its OS lock is released");
    }

    #[cfg(unix)]
    #[test]
    fn rejected_second_daemon_cannot_unlink_the_live_control_socket() {
        use std::os::unix::net::{UnixListener, UnixStream};

        let dir = tempfile::tempdir().unwrap();
        let _owner = DaemonInstanceLock::acquire(dir.path()).unwrap();
        let socket_path = dir.path().join("daemon.sock");
        let _listener = UnixListener::bind(&socket_path).unwrap();

        assert!(DaemonInstanceLock::acquire(dir.path()).is_err());
        UnixStream::connect(&socket_path)
            .expect("the rejected process must leave the owner's live socket untouched");
    }

    #[test]
    fn unrelated_lock_open_errors_are_not_reported_as_already_running() {
        let dir = tempfile::tempdir().unwrap();
        let not_a_directory = dir.path().join("plain-file");
        std::fs::write(&not_a_directory, b"x").unwrap();

        let error = DaemonInstanceLock::acquire(&not_a_directory).unwrap_err();
        assert!(!error.to_string().contains("already running"));
    }
}

#[cfg(all(test, not(madsim)))]
mod startup_config_validation_tests {
    use super::*;
    use crate::test_support::CONFIG_ENV_MUTEX;

    /// One complete `run` attempt against a throwaway config directory. The
    /// error is captured as a `String` and the interesting paths are copied
    /// out so every assertion can run *after* the process-global config-dir
    /// env var has been restored — a failing assertion must not leak that var
    /// into whichever test acquires the mutex next.
    struct StartupAttempt {
        error: String,
        sync_db_path: PathBuf,
        stale_temp_file: PathBuf,
        _config_dir: tempfile::TempDir,
    }

    /// A syntactically valid `device.json` stamped one version past what this
    /// build supports — the "unsupported downgrade" case.
    fn too_new_device_json() -> String {
        format!(
            r#"{{"device_id":"device-a","coordination_addr":"http://127.0.0.1:1","config_version":{}}}"#,
            device_config::CONFIG_VERSION + 1
        )
    }

    /// Runs daemon startup against a config directory holding exactly
    /// `device_json`, and seeds the block-store root with a file named to the
    /// `.yadorilink-tmp.<pid>.<counter>` scheme that
    /// `materialization::cleanup_stale_temp_files` deletes on sight, with no
    /// age threshold. That file surviving is the observable proof that
    /// startup stopped before the sweep-and-repair pass rather than merely
    /// returning the right error at the end of it.
    async fn start_daemon_with_device_json(device_json: &str) -> StartupAttempt {
        start_daemon_with_device_json_and_keys(device_json, false, false).await
    }

    async fn start_daemon_with_device_json_and_keys(
        device_json: &str,
        create_transport_key: bool,
        create_signing_key: bool,
    ) -> StartupAttempt {
        let _env_guard = CONFIG_ENV_MUTEX.lock().await;
        let config_dir = tempfile::tempdir().unwrap();
        let block_store_root = config_dir.path().join("blocks");
        let sync_db_path = config_dir.path().join("sync-state.sqlite3");

        // The store/DB paths are pinned explicitly rather than left to
        // `from_env`'s defaults so that a `YADORILINK_BLOCK_STORE` or
        // `YADORILINK_SYNC_DB` already set in the developer's shell cannot
        // aim this test at a real install.
        std::env::set_var("YADORILINK_CONFIG_DIR", config_dir.path());
        std::env::set_var("YADORILINK_BLOCK_STORE", &block_store_root);
        std::env::set_var("YADORILINK_SYNC_DB", &sync_db_path);

        std::fs::write(config_dir.path().join("device.json"), device_json).unwrap();
        if create_transport_key {
            DeviceKeyPair::generate_and_persist(config_dir.path().join("wg_key")).unwrap();
        }
        if create_signing_key {
            yadorilink_transport::DeviceSigningKeyPair::generate_and_persist(
                config_dir.path().join("signing_key"),
            )
            .unwrap();
        }
        std::fs::create_dir_all(&block_store_root).unwrap();
        let stale_temp_file = block_store_root.join("block.yadorilink-tmp.1.0");
        std::fs::write(&stale_temp_file, b"leftover").unwrap();

        let error = run(DaemonConfig::from_env())
            .await
            .expect_err("startup must refuse a device.json this build cannot support")
            .to_string();

        std::env::remove_var("YADORILINK_CONFIG_DIR");
        std::env::remove_var("YADORILINK_BLOCK_STORE");
        std::env::remove_var("YADORILINK_SYNC_DB");

        StartupAttempt { error, sync_db_path, stale_temp_file, _config_dir: config_dir }
    }

    fn current_device_json() -> String {
        format!(
            r#"{{"device_id":"device-a","coordination_addr":"http://127.0.0.1:1","config_version":{}}}"#,
            device_config::CONFIG_VERSION
        )
    }

    #[tokio::test]
    async fn registered_keys_are_both_validated_before_persistent_startup() {
        for (transport, signing, missing_name) in
            [(false, true, "transport"), (true, false, "signing")]
        {
            let attempt =
                start_daemon_with_device_json_and_keys(&current_device_json(), transport, signing)
                    .await;
            assert!(
                !attempt.sync_db_path.exists(),
                "missing {missing_name} key must abort before SQLite creation"
            );
            assert!(
                attempt.stale_temp_file.exists(),
                "missing {missing_name} key must abort before startup repair"
            );
        }
    }

    /// A `device.json` from a newer build must abort startup before anything
    /// on disk changes.
    ///
    /// Asserting only the error type would pass even with the validation
    /// still sequenced *after* the database migration and the repair pass,
    /// so the untouched-state assertions below are the point of this test: a
    /// build that cannot understand this config must not migrate a schema, or
    /// sweep and rewrite files, that a newer build may have written beside it.
    #[tokio::test]
    async fn a_too_new_device_config_aborts_startup_before_touching_disk() {
        let attempt = start_daemon_with_device_json(&too_new_device_json()).await;

        assert!(
            !attempt.sync_db_path.exists(),
            "the sync database must not be created or migrated before device.json is validated, \
             but {} exists after a refused startup",
            attempt.sync_db_path.display()
        );
        assert!(
            attempt.stale_temp_file.exists(),
            "no startup temp-file sweep or materialization repair may run before device.json is \
             validated, but {} was already swept",
            attempt.stale_temp_file.display()
        );
    }

    /// Every unusable-but-present `device.json` must reach the operator as its
    /// own case. A shared catch-all message is what makes a corrupt or too-new
    /// config read as "this device was never registered" — the one reading
    /// that invites registering a second identity for a device that already
    /// has one, which nothing afterwards can merge back.
    #[tokio::test]
    async fn each_unusable_device_config_reports_its_own_cause() {
        let corrupt = start_daemon_with_device_json("{ not json").await;
        let too_new = start_daemon_with_device_json(&too_new_device_json()).await;

        assert!(
            corrupt.error.contains("is not a valid device config"),
            "a corrupt device.json must say so: {}",
            corrupt.error
        );
        assert!(
            too_new.error.contains("newer than this build supports"),
            "a too-new device.json must name the version conflict: {}",
            too_new.error
        );
        for error in [&corrupt.error, &too_new.error] {
            assert!(
                !error.contains("unregistered"),
                "a device.json that exists but cannot be used must never be described as an \
                 unregistered device: {error}"
            );
        }
    }
}

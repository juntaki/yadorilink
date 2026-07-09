//! Long-running sync daemon (the relevant behavior): loads persistent local state,
//! opens the CLI control socket, and — once logged in and registered —
//! connects to the coordination plane's netmap and establishes peer sync
//! sessions.
//!
//! reliability hardening: every essential task (control socket, shell-integration IPC,
//! peer orchestrator) is supervised together in one `JoinSet` at the
//! bottom of `main` — if *any* of them exits or panics, the daemon logs
//! it clearly and exits non-zero so a process supervisor restarts it,
//! instead of coupling liveness solely to the control socket (the old
//! `control_socket_task.await?`) and silently continuing as a zombie with
//! broken sync. reliability hardening: the same top-level `select!` also races that
//! against SIGTERM/SIGINT (and the control socket's `Shutdown` request,
//! routed in via `DaemonState::shutdown_tx`) to run a graceful shutdown
//! instead.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinSet;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::device_config::config_dir;
use yadorilink_daemon::{
    control_socket, device_config, link_manager, peer_orchestrator, shell_ipc, token_store,
};
use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::materialization;
use yadorilink_transport::DeviceKeyPair;

/// Names used both for `essential.spawn`'s logging and for
/// `DaemonState::task_liveness` (reliability hardening's health surface) — kept as
/// constants so the two always agree.
const TASK_CONTROL_SOCKET: &str = "control-socket";
const TASK_SHELL_IPC: &str = "shell-ipc-server";
const TASK_PEER_ORCHESTRATOR: &str = "peer-orchestrator";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let dir = config_dir();
    std::fs::create_dir_all(&dir)?;

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

    // A severe-error hook for the two fallible startup calls that would
    // otherwise abort `main` before `DaemonState` (and therefore
    // `state.reporting`) exists — opens a
    // throwaway `ReportingStorage` over the same config directory rather
    // than waiting for `DaemonState::new`, since a failure here is exactly
    // the kind of thing a maintainer would want a local candidate for.
    let block_store = Arc::new(FsBlockStore::new(&block_store_root).inspect_err(|e| {
        record_startup_error_best_effort("daemon_startup", "block-store", e.to_string());
    })?);
    let sync_state = Arc::new(SyncState::open(&sync_db_path).inspect_err(|e| {
        record_startup_error_best_effort("daemon_startup", "sync-state", e.to_string());
    })?);

    // COR-7: recover any file left permanently stuck `Hydrating` by a
    // previous crash before anything else runs — see
    // `SyncState::reset_stale_hydrating_to_placeholder`'s doc comment.
    match sync_state.reset_stale_hydrating_to_placeholder() {
        Ok(0) => {}
        Ok(n) => tracing::info!(count = n, "reset stale Hydrating rows to Placeholder on startup"),
        Err(e) => tracing::warn!(error = %e, "failed to reset stale Hydrating rows on startup"),
    }

    // Run before any link watcher starts or any new write happens, so
    // nothing new can be
    // mistaken for one of last run's orphaned temp files, and no on-demand
    // hydration/materialize can race the repair pass below. Order matters:
    // the block-store root's own stale temp files are cleaned first
    // (`FsBlockStore::put` uses the identical `unique_tmp_path` naming
    // scheme as `chunker.rs`), then each link's local folder, then the
    // per-link `Hydrated`-but-inconsistent repair — see
    // `materialization::repair_interrupted_materializations`'s doc comment
    // for exactly which crash window this closes (the one `COR-7`'s
    // `Hydrating` reset above does not: a crash between the index commit
    // and the completed rename of an *eager* materialization write).
    let stale_block_store_tmp = materialization::cleanup_stale_temp_files(&block_store_root);
    if !stale_block_store_tmp.is_empty() {
        tracing::info!(
            count = stale_block_store_tmp.len(),
            "removed stale temp files from block store on startup"
        );
    }
    for link in sync_state.list_links().unwrap_or_default() {
        let root = PathBuf::from(&link.local_path);
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
            Err(e) => tracing::warn!(
                error = %e,
                local_path = %link.local_path,
                "failed to run startup materialization repair for linked folder"
            ),
        }
    }

    let device_config = device_config::load();
    let device_id = device_config.as_ref().map(|c| c.device_id.clone()).unwrap_or_default();

    let state = DaemonState::new(device_id.clone(), sync_state.clone(), block_store.clone());
    // Only the real `yadorilink-daemon` binary itself opts into
    // disk-headroom enforcement (the relevant behavior) — see
    // `DaemonState::enable_disk_headroom_enforcement`'s doc comment for why
    // this is not done inside `DaemonState::new` (which every test in this
    // crate also goes through).
    state.enable_disk_headroom_enforcement();

    // Opt-in `/metrics` endpoint — off/localhost-only by default,
    // mirroring `yadorilink-relay`'s own `YADORILINK_RELAY_METRICS_ADDR`
    // convention exactly. The env var (if set) always wins over the persisted
    // `metrics_config.json` toggle (`yadorilink daemon metrics`, the relevant behavior)
    // so an operator's explicit env-based override behaves identically to
    // the relay's, with the persisted config as this binary's own
    // additional, CLI-settable fallback.
    let metrics_addr = std::env::var("YADORILINK_DAEMON_METRICS_ADDR").ok().or_else(|| {
        let config =
            yadorilink_daemon::metrics_config::MetricsConfigStore::new(&dir).load_or_default();
        config.enabled.then_some(config.bind_addr)
    });
    if let Some(metrics_addr) = metrics_addr {
        match tokio::net::TcpListener::bind(&metrics_addr).await {
            Ok(metrics_listener) => {
                let metrics = yadorilink_daemon::metrics::DaemonMetrics::new(state.clone());
                tracing::info!(addr = metrics_addr, "yadorilink-daemon metrics listening");
                yadorilink_daemon::supervise::spawn_logged("daemon-metrics-http", async move {
                    serve_metrics(metrics_listener, metrics).await;
                    Ok(())
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, addr = metrics_addr, "failed to bind daemon metrics listener; metrics endpoint disabled for this run");
            }
        }
    }

    // Resume watching every previously-linked folder (the relevant behavior "local
    // state persistence across restarts": links survive, and their
    // watchers are simply restarted).
    for link in sync_state.list_links().unwrap_or_default() {
        if let Err(e) =
            link_manager::start_link_watch(state.clone(), link.local_path.clone(), link.group_id)
        {
            tracing::warn!(error = %e, local_path = %link.local_path, "failed to resume watching linked folder");
        }
    }

    // reliability hardening: every essential task lives in this one `JoinSet` instead of
    // a bare `tokio::spawn` with its handle dropped (shell-IPC, peer
    // orchestrator) or awaited on its own at the very end (control
    // socket, coupling process liveness to just that one task). Spawning
    // directly into the `JoinSet` (rather than wrapping
    // `supervise::spawn_logged` handles) means `essential.shutdown()`
    // during graceful shutdown actually aborts the running task itself,
    // not just a wrapper awaiting it.
    let mut essential: JoinSet<&'static str> = JoinSet::new();

    #[cfg(unix)]
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

    #[cfg(unix)]
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
            let keypair = Arc::new(DeviceKeyPair::load_or_generate(&keypair_path)?);
            let relay_addr = cfg.relay_addr.parse()?;
            tracing::info!(device_id = %cfg.device_id, "connecting to coordination plane");
            let orchestrator_config = peer_orchestrator::OrchestratorConfig {
                coordination_addr: cfg.coordination_addr,
                relay_addr,
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
            // An essential supervised task (reliability hardening) dying is exactly the
            // kind of severe, maintainer-actionable failure this hook
            // exists for — a local-only candidate, never submitted
            // automatically.
            yadorilink_daemon::reporting::hooks::record_severe_error(
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
/// `DaemonState::shutdown_tx` (reliability hardening) — either way, returns a short tag
/// naming which one fired, purely for the log line at the call site.
async fn wait_for_shutdown_request(
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> &'static str {
    tokio::select! {
        signal_name = wait_for_os_signal() => signal_name,
        _ = shutdown_rx.changed() => "control-socket Shutdown request",
    }
}

#[cfg(unix)]
async fn wait_for_os_signal() -> &'static str {
    use tokio::signal::unix::{signal, SignalKind};
    // `signal()` only fails if the underlying OS signal registration
    // fails (e.g. an invalid `SignalKind`, never the case for a constant
    // here) — a daemon that can't even install its shutdown handler is
    // already in a bad enough state that panicking at startup is
    // reasonable, matching how the rest of `main` treats setup failures
    // (`?` on `Connection::open`, etc.).
    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    tokio::select! {
        _ = sigterm.recv() => "SIGTERM",
        _ = tokio::signal::ctrl_c() => "SIGINT",
    }
}

/// Records a severe-error candidate for a startup failure that happens
/// before `DaemonState`
/// exists. Opens its own short-lived `ReportingStorage` handle (cheap —
/// see that type's doc comment on not writing anything just by opening)
/// rather than restructuring startup to build `DaemonState` earlier.
fn record_startup_error_best_effort(category: &str, subsystem: &str, message: String) {
    let storage = yadorilink_daemon::reporting::ReportingStorage::open_default();
    yadorilink_daemon::reporting::hooks::record_severe_error(
        &storage,
        category,
        subsystem,
        vec![message],
    );
}

/// Windows has no SIGTERM; a process supervisor there typically stops a
/// service via `Ctrl-C`/service-control events, which `tokio::signal::ctrl_c`
/// already covers cross-platform — no Windows-specific signal API needed
/// for this MVP (cfg-split only where the platforms genuinely differ, e.g.
/// named pipes vs Unix sockets).
#[cfg(windows)]
async fn wait_for_os_signal() -> &'static str {
    let _ = tokio::signal::ctrl_c().await;
    "Ctrl-C"
}

/// reliability hardening: the one graceful-shutdown path both SIGTERM/SIGINT and the
/// control socket's `Shutdown` request (via `DaemonState::shutdown_tx`)
/// funnel into — previously the latter was a second, independent path
/// (`std::process::exit(0)` after a sleep) that skipped all of this.
async fn graceful_shutdown(
    state: &Arc<DaemonState>,
    socket_paths: &[PathBuf],
    essential: &mut JoinSet<&'static str>,
) {
    // Give an in-flight control-socket response (e.g. this shutdown
    // request's own ack) a moment to actually flush to its client before
    // sockets disappear and tasks get aborted out from under it —
    // matching the old control-socket-only code's 200ms grace period,
    // now applied uniformly to every shutdown path.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Stop generating new local changes first: abort every link's
    // watcher/executor tasks (the debounce accumulator and the flush
    // executor, ) before anything else, so nothing new gets
    // queued while the rest of shutdown runs.
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
    // WAL-checkpoint-on-clean-exit gap, not a durability gap; flagged as a
    // follow-up rather than inventing new `yadorilink-sync-core` API from
    // here.

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

/// The daemon's `/metrics` listener loop — deliberately the same minimal,
/// dependency-free raw-HTTP responder as `yadorilink-relay`'s own
/// `serve_metrics`
/// (`crates/yadorilink-transport/src/bin/yadorilink-relay.rs`), not a new
/// framework: "don't invent a different metrics framework" for this
/// change's daemon/coordination endpoints.
async fn serve_metrics(
    listener: tokio::net::TcpListener,
    metrics: yadorilink_daemon::metrics::DaemonMetrics,
) {
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

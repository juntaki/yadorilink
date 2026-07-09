use std::time::Duration;

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    ListLinksRequest, PauseRequest, ResumeRequest, ShutdownRequest, StatusRequest,
};

use crate::control_client;
use crate::error::CliError;

/// Launches the daemon if it isn't already running (per the `cli` spec's
/// "Start daemon" scenario: "launched (or confirmed already running)").
pub async fn start() -> Result<(), CliError> {
    if control_client::send(ReqPayload::Status(StatusRequest {})).await.is_ok() {
        println!("Daemon already running.");
        return Ok(());
    }

    let daemon_binary = daemon_binary_path();
    std::process::Command::new(&daemon_binary).spawn().map_err(|e| {
        CliError::Other(format!("failed to launch {}: {e}", daemon_binary.display()))
    })?;

    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        if control_client::send(ReqPayload::Status(StatusRequest {})).await.is_ok() {
            println!("Daemon started.");
            return Ok(());
        }
    }
    Err(CliError::Other("daemon did not become reachable after starting".into()))
}

pub async fn stop() -> Result<(), CliError> {
    control_client::send(ReqPayload::Shutdown(ShutdownRequest {})).await?;
    println!("Daemon stopping.");
    Ok(())
}

/// Interpreted as pausing every currently-linked folder (the CLI spec's
/// "daemon pause/resume" is a whole-daemon action; the underlying control
/// protocol tracks pause per-link, per the `sync-engine` spec, so this
/// applies it to all of them).
pub async fn pause() -> Result<(), CliError> {
    set_all_paused(true).await?;
    println!("Sync paused.");
    Ok(())
}

pub async fn resume() -> Result<(), CliError> {
    set_all_paused(false).await?;
    println!("Sync resumed.");
    Ok(())
}

async fn set_all_paused(paused: bool) -> Result<(), CliError> {
    let resp = control_client::send(ReqPayload::ListLinks(ListLinksRequest {})).await?;
    let Some(RespPayload::ListLinks(list)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    for link in list.links {
        let payload = if paused {
            ReqPayload::Pause(PauseRequest { local_path: link.local_path })
        } else {
            ReqPayload::Resume(ResumeRequest { local_path: link.local_path })
        };
        control_client::send(payload).await?;
    }
    Ok(())
}

/// View/toggle the daemon's opt-in `/metrics` endpoint by writing
/// directly to the same `metrics_config.json` `yadorilink-daemon`'s
/// `main.rs` reads at startup
/// (`yadorilink_daemon::metrics_config::MetricsConfigStore`) — both
/// processes already share the same config directory convention
/// (`crate::device_config::config_dir`), the same way `token_store`/
/// `device_config` are shared, local-file-based config rather than a
/// control-socket round trip. A running daemon only picks up a change here
/// on its next start (see `DaemonAction::Metrics`'s doc comment in
/// `main.rs`).
pub fn metrics(
    enable: bool,
    disable: bool,
    addr: Option<String>,
    show: bool,
) -> Result<(), CliError> {
    let store = yadorilink_daemon::metrics_config::MetricsConfigStore::new(
        crate::device_config::config_dir(),
    );
    if show || (!enable && !disable && addr.is_none()) {
        let config = store.load_or_default();
        println!(
            "metrics: {}  addr={}",
            if config.enabled { "enabled" } else { "disabled" },
            config.bind_addr
        );
        return Ok(());
    }
    let enabled = if disable { false } else { enable || addr.is_some() };
    let config = store
        .set(enabled, addr)
        .map_err(|e| CliError::Other(format!("failed to save metrics config: {e}")))?;
    println!(
        "metrics: {}  addr={}  (takes effect on the daemon's next start)",
        if config.enabled { "enabled" } else { "disabled" },
        config.bind_addr
    );
    Ok(())
}

fn daemon_binary_path() -> std::path::PathBuf {
    let name = if cfg!(windows) { "yadorilink-daemon.exe" } else { "yadorilink-daemon" };
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(name)))
        .filter(|p| p.exists())
        .unwrap_or_else(|| std::path::PathBuf::from(name)) // fall back to PATH lookup
}

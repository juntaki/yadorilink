use yadorilink_client_core::ops::daemon::{self as ops, DaemonStartOutcome};
use yadorilink_client_core::ops::folders;

use crate::error::CliError;

/// Launches the daemon if it isn't already running (per the `cli` spec's
/// "Start daemon" scenario: "launched (or confirmed already running)").
pub async fn start() -> Result<(), CliError> {
    match ops::start_daemon().await? {
        DaemonStartOutcome::AlreadyRunning => println!("Daemon already running."),
        DaemonStartOutcome::Started => println!("Daemon started."),
    }
    Ok(())
}

pub async fn stop() -> Result<(), CliError> {
    ops::stop_daemon().await?;
    println!("Daemon stopping.");
    Ok(())
}

/// Interpreted as pausing every currently-linked folder (the CLI spec's
/// "daemon pause/resume" is a whole-daemon action; the underlying control
/// protocol tracks pause per-link, per the `sync-engine` spec, so this
/// applies it to all of them).
pub async fn pause() -> Result<(), CliError> {
    folders::pause_all().await?;
    println!("Sync paused.");
    Ok(())
}

pub async fn resume() -> Result<(), CliError> {
    folders::resume_all().await?;
    println!("Sync resumed.");
    Ok(())
}

/// View/toggle the daemon's opt-in `/metrics` endpoint by writing
/// directly to the same `metrics_config.json` `yadorilink-daemon` reads at
/// startup (`yadorilink_reporting::metrics_config::MetricsConfigStore`,
/// which the daemon uses too) — both processes already share the same config directory convention
/// (`crate::device_config::config_dir`), the same way `credential_store`/
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
    let store = yadorilink_reporting::metrics_config::MetricsConfigStore::new(
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

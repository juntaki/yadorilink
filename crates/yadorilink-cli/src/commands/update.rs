//! `yadorilink update status|check|install|config` — mirrors
//! `commands::limits`'s exact shape (a thin wrapper per subcommand over
//! `yadorilink_client_core::ops::updates`, printing the daemon's response).

use yadorilink_client_core::ops::updates;
use yadorilink_ipc_proto::daemonctl::UpdateStatusResponse;

use crate::error::CliError;

/// Shared by `status`/`check` — both end up printing the exact same
/// shape of information ("current version, channel, install
/// source, last check time, available version if any, rollout/holdback
/// state, and last update error if any").
fn print_status(status: &UpdateStatusResponse) {
    println!(
        "version: {}  channel: {}  install_source: {}",
        status.current_version, status.channel, status.install_source
    );
    if status.last_check_unix == 0 {
        println!("last check: never");
    } else {
        println!("last check: {} (unix seconds)", status.last_check_unix);
    }
    println!("state: {}", status.state);
    if !status.available_version.is_empty() {
        println!("available version: {}", status.available_version);
        if !status.release_notes_url.is_empty() {
            println!("release notes: {}", status.release_notes_url);
        }
        if status.mandatory {
            println!("mandatory: yes (security/compatibility update)");
        }
        if !status.holdback_reason.is_empty() {
            println!("held back: {}", status.holdback_reason);
        }
        if status.waiting_for_safe_point {
            println!("waiting for a safe point to install");
        }
    }
    if !status.last_error_category.is_empty() {
        println!(
            "last error: {} ({})",
            status.last_error_category,
            if status.last_error_message.is_empty() {
                "no further detail"
            } else {
                &status.last_error_message
            }
        );
    }
    println!(
        "automatic checks: {}  automatic install: {}",
        if status.automatic_checks_enabled { "on" } else { "off" },
        status.automatic_install_mode
    );
}

/// `yadorilink update status` (spec "Show update status").
pub async fn status() -> Result<(), CliError> {
    let status = updates::update_status().await?;
    print_status(&status);
    Ok(())
}

/// `yadorilink update check` (spec "Manual update check").
pub async fn check() -> Result<(), CliError> {
    let check = updates::check_for_updates().await?;
    let Some(status) = check.status else {
        return Err(CliError::Other("daemon returned no update status".into()));
    };
    if status.available_version.is_empty() {
        println!("no update available (current version: {})", status.current_version);
    } else {
        println!("update available: {}", status.available_version);
    }
    print_status(&status);
    Ok(())
}

/// `yadorilink update install` (spec "Manual install request").
pub async fn install() -> Result<(), CliError> {
    let resp = updates::install_update().await?;
    match resp.outcome.as_str() {
        "installing" => println!("installing update..."),
        "deferred" => println!("update install deferred until the daemon reaches a safe point"),
        "store_managed" => println!("{}", resp.guidance),
        other => println!("install outcome: {other}"),
    }
    Ok(())
}

/// `yadorilink update config --checks <on|off> --install <automatic|manual>`
/// (spec "Configure automatic updates").
pub async fn config(checks: Option<String>, install: Option<String>) -> Result<(), CliError> {
    let automatic_checks_enabled = match checks.as_deref() {
        Some("on") => Some(true),
        Some("off") => Some(false),
        Some(other) => {
            return Err(CliError::Other(format!("--checks must be 'on' or 'off', got {other:?}")))
        }
        None => None,
    };
    if let Some(mode) = install.as_deref() {
        if mode != "automatic" && mode != "manual" {
            return Err(CliError::Other(format!(
                "--install must be 'automatic' or 'manual', got {mode:?}"
            )));
        }
    }
    let config = updates::set_update_config(automatic_checks_enabled, install).await?;
    println!(
        "automatic checks: {}  automatic install: {}",
        if config.automatic_checks_enabled { "on" } else { "off" },
        config.automatic_install_mode
    );
    Ok(())
}

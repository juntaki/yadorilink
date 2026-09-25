//! With no override set, the app looks for its config files and the daemon's
//! control socket where the daemon actually keeps them, not in a directory of
//! its own. This file runs as its own process because it rewrites `HOME`.
#![cfg(unix)]

use yadorilink_client_core::coordination::device_config as client_config;
use yadorilink_daemon::app::DaemonConfig;
use yadorilink_daemon::device_config as daemon_config;
use yadorilink_desktop_app::ipc_client;

#[test]
fn the_app_uses_the_daemons_config_directory_and_socket_by_default() {
    let home = tempfile::tempdir().unwrap();
    for var in ["YADORILINK_CONFIG_DIR", "YADORILINK_CONTROL_SOCKET", "XDG_DATA_HOME", "APPDATA"] {
        std::env::remove_var(var);
    }
    std::env::set_var("HOME", home.path());

    let app_dir = ipc_client::config_dir_public();
    assert_eq!(app_dir, daemon_config::config_dir());
    assert!(app_dir.starts_with(home.path()), "{}", app_dir.display());
    assert_ne!(app_dir, home.path().join(".yadorilink"));

    assert_eq!(client_config::control_socket_path(), DaemonConfig::from_env().control_socket_path);

    // A device registered where the daemon reads it counts as registered.
    assert!(!ipc_client::is_device_registered());
    let device_json = daemon_config::config_path();
    std::fs::create_dir_all(device_json.parent().unwrap()).unwrap();
    std::fs::write(&device_json, "{}").unwrap();
    assert!(ipc_client::is_device_registered());
}

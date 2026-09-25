//! `yadorilink device ...`: this account's device registry.

use yadorilink_client_core::ops::devices as ops;

use crate::error::CliError;

use yadorilink_client_core::ops::devices::DeviceInfo;

/// `yadorilink device register [--name <name>]`.
pub async fn register(device_name: String) -> Result<(), CliError> {
    let device_id = ops::register_device(device_name).await?;
    println!("Registered device: {device_id}");
    Ok(())
}

fn device_line(device: &DeviceInfo) -> String {
    format!(
        "{}  {}  {}",
        device.device_id,
        device.device_name,
        if device.online { "online" } else { "offline" }
    )
}

/// `yadorilink device list`.
pub async fn list() -> Result<(), CliError> {
    for device in ops::list_devices().await? {
        println!("{}", device_line(&device));
    }
    Ok(())
}

/// `yadorilink device remove <device> [--force]`. Before de-registering the
/// device on the coordination plane, the daemon checks that doing so would
/// not leave any folder group without a confirmed-ready full replica.
/// `--force` bypasses a refusal with a data-loss warning and an audit log
/// line.
pub async fn remove(device_id: String, force: bool) -> Result<(), CliError> {
    let outcome = ops::remove_device(&device_id, force).await?;
    crate::commands::membership_render::render_membership_outcome("remove", &outcome);
    println!("Removed device: {device_id}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_line_is_pinned_verbatim() {
        let mut device = DeviceInfo {
            device_id: "device-1".into(),
            device_name: "my-laptop".into(),
            online: true,
        };
        assert_eq!(device_line(&device), "device-1  my-laptop  online");
        device.online = false;
        assert_eq!(device_line(&device), "device-1  my-laptop  offline");
    }
}

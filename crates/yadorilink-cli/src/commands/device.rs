fn keypair_path() -> std::path::PathBuf {
    crate::device_config::config_dir().join("wg_key")
}

/// The device's Ed25519 change-history signing key, kept next to the
/// WireGuard key and generated on first use. Its public half is registered
/// alongside the WireGuard key so peers can pin it and verify this device's
/// signed change history.
fn signing_keypair_path() -> std::path::PathBuf {
    crate::device_config::config_dir().join("signing_key")
}

mod http {
    //! HTTP client for the coordination service's `/devices/*` routes.

    use base64::Engine;
    use serde::{Deserialize, Serialize};
    use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
    use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
    use yadorilink_ipc_proto::daemonctl::{
        remove_device_command_response, RemoveDeviceCommandRequest,
    };

    use crate::control_client;
    use crate::error::CliError;
    use crate::http_client::{get_json, post_json, require_access_token};

    #[derive(Serialize)]
    struct RegisterDeviceRequest<'a> {
        device_name: &'a str,
        wireguard_public_key_base64: String,
        signing_public_key_base64: String,
    }
    #[derive(Deserialize)]
    struct RegisterDeviceResponse {
        device_id: String,
    }

    #[derive(Deserialize)]
    struct DeviceInfo {
        device_id: String,
        device_name: String,
        online: bool,
    }
    #[derive(Deserialize)]
    struct ListDevicesResponse {
        devices: Vec<DeviceInfo>,
    }

    /// The library form the onboarding wizard drives — registers the device and
    /// persists the one canonical pre-release `device.json` shape, returning the
    /// assigned `device_id` as a typed result instead of printing it.
    pub async fn register_device(device_name: String) -> Result<String, CliError> {
        let access_token = require_access_token()?;
        let keypair = yadorilink_transport::DeviceKeyPair::load_or_generate(super::keypair_path())
            .map_err(|e| CliError::Other(e.to_string()))?;
        let signing_keypair = yadorilink_transport::DeviceSigningKeyPair::load_or_generate(
            super::signing_keypair_path(),
        )
        .map_err(|e| CliError::Other(e.to_string()))?;

        let wireguard_public_key_base64 =
            base64::engine::general_purpose::STANDARD.encode(keypair.public_bytes());
        let signing_public_key_base64 =
            base64::engine::general_purpose::STANDARD.encode(signing_keypair.public_bytes());

        let resp: RegisterDeviceResponse = post_json(
            "/devices/register",
            &RegisterDeviceRequest {
                device_name: &device_name,
                wireguard_public_key_base64: wireguard_public_key_base64.clone(),
                signing_public_key_base64: signing_public_key_base64.clone(),
            },
            Some(&access_token),
        )
        .await?;

        crate::device_config::save(&crate::device_config::DeviceConfig {
            device_id: resp.device_id.clone(),
            coordination_addr: crate::http_client::coordination_addr(),
            nat: crate::device_config::NatConfig::default(),
            wireguard_public_key: wireguard_public_key_base64,
            signing_public_key: signing_public_key_base64,
            config_version: crate::device_config::CONFIG_VERSION,
        })?;
        Ok(resp.device_id)
    }

    pub async fn register(device_name: String) -> Result<(), CliError> {
        let device_id = register_device(device_name).await?;
        println!("Registered device: {device_id}");
        Ok(())
    }

    pub async fn list() -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let resp: ListDevicesResponse = get_json("/devices", Some(&access_token)).await?;
        for d in resp.devices {
            println!(
                "{}  {}  {}",
                d.device_id,
                d.device_name,
                if d.online { "online" } else { "offline" }
            );
        }
        Ok(())
    }

    /// `yadorilink device remove <device> [--force]`. Before de-registering
    /// the device on the coordination plane, asks the local daemon whether
    /// doing so would leave any folder group this device knows about without
    /// a confirmed-ready full replica, AND asks the coordination Worker to
    /// enumerate every folder group the removed device is an eager full
    /// replica of (so a group the acting daemon doesn't itself link is still
    /// covered. The daemon owns that fail-closed decision while the Worker's
    /// count guard remains an independent final check. `--force` bypasses a
    /// refusal with a data-loss warning and an audit log line.
    pub async fn remove(device_id: String, force: bool) -> Result<(), CliError> {
        let response =
            control_client::send(ReqPayload::RemoveDeviceCommand(RemoveDeviceCommandRequest {
                device_id: device_id.clone(),
                force,
            }))
            .await?;
        match response.payload {
            Some(RespPayload::RemoveDeviceCommand(response)) => match response.result {
                Some(remove_device_command_response::Result::Outcome(outcome)) => {
                    crate::commands::membership_render::render_membership_outcome("remove", &outcome);
                }
                Some(remove_device_command_response::Result::Error(error)) => {
                    return Err(CliError::Other(error.message));
                }
                None => {
                    return Err(CliError::Other("daemon returned an empty remove result".into()))
                }
            },
            Some(RespPayload::Error(error)) => return Err(CliError::Other(error)),
            _ => {
                return Err(CliError::Other("unexpected daemon response to device removal".into()))
            }
        }
        println!("Removed device: {device_id}");
        Ok(())
    }
}

pub use http::{list, register, register_device, remove};

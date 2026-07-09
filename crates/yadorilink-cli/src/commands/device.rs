fn keypair_path() -> std::path::PathBuf {
    crate::device_config::config_dir().join("wg_key")
}

#[cfg(feature = "http-coordination")]
mod http {
    //! migrate-coordination-plane-to-cloudflare task 7.1: HTTP client for
    //! the HTTP coordination service's `/devices/*` routes.

    use base64::Engine;
    use serde::{Deserialize, Serialize};

    use crate::error::CliError;
    use crate::grpc::require_access_token;
    use crate::http_client::{get_json, post_json, post_json_no_content};

    #[derive(Serialize)]
    struct RegisterDeviceRequest<'a> {
        device_name: &'a str,
        wireguard_public_key_base64: String,
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

    pub async fn register(device_name: String) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let keypair = yadorilink_transport::DeviceKeyPair::load_or_generate(super::keypair_path())
            .map_err(|e| CliError::Other(e.to_string()))?;

        let resp: RegisterDeviceResponse = post_json(
            "/devices/register",
            &RegisterDeviceRequest {
                device_name: &device_name,
                wireguard_public_key_base64: base64::engine::general_purpose::STANDARD
                    .encode(keypair.public_bytes()),
            },
            Some(&access_token),
        )
        .await?;

        crate::device_config::save(&crate::device_config::DeviceConfig {
            device_id: resp.device_id.clone(),
            coordination_addr: crate::grpc::coordination_addr(),
            relay_addr: crate::grpc::relay_addr(),
            config_version: 0,
        })?;
        println!("Registered device: {}", resp.device_id);
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

    pub async fn remove(device_id: String) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        post_json_no_content::<()>(&format!("/devices/{device_id}"), &(), Some(&access_token))
            .await?;
        println!("Removed device: {device_id}");
        Ok(())
    }
}

#[cfg(feature = "http-coordination")]
pub use http::{list, register, remove};

#[cfg(not(feature = "http-coordination"))]
mod grpc_impl {
    use yadorilink_ipc_proto::coordination::device_service_client::DeviceServiceClient;
    use yadorilink_ipc_proto::coordination::{
        ListDevicesRequest, RegisterDeviceRequest, RemoveDeviceRequest,
    };
    use yadorilink_transport::DeviceKeyPair;

    use crate::device_config::{self, DeviceConfig};
    use crate::error::CliError;
    use crate::grpc::{
        authed_request, coordination_addr, coordination_channel, relay_addr, require_access_token,
    };

    pub async fn register(device_name: String) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let keypair = DeviceKeyPair::load_or_generate(super::keypair_path())
            .map_err(|e| CliError::Other(e.to_string()))?;

        let mut client = DeviceServiceClient::new(coordination_channel().await?);
        let resp = client
            .register_device(authed_request(
                RegisterDeviceRequest {
                    device_name,
                    wireguard_public_key: keypair.public_bytes().to_vec(),
                },
                &access_token,
            ))
            .await?
            .into_inner();

        device_config::save(&DeviceConfig {
            device_id: resp.device_id.clone(),
            coordination_addr: coordination_addr(),
            relay_addr: relay_addr(),
            // `save` always overwrites this with the current `CONFIG_VERSION`
            // (add-update-migration-safety task 1.1) — the value here is never
            // persisted.
            config_version: 0,
        })?;
        println!("Registered device: {}", resp.device_id);
        Ok(())
    }

    pub async fn list() -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let mut client = DeviceServiceClient::new(coordination_channel().await?);
        let resp = client
            .list_devices(authed_request(ListDevicesRequest {}, &access_token))
            .await?
            .into_inner();
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

    pub async fn remove(device_id: String) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let mut client = DeviceServiceClient::new(coordination_channel().await?);
        client
            .remove_device(authed_request(
                RemoveDeviceRequest { device_id: device_id.clone() },
                &access_token,
            ))
            .await?;
        println!("Removed device: {device_id}");
        Ok(())
    }
}

#[cfg(not(feature = "http-coordination"))]
pub use grpc_impl::{list, register, remove};

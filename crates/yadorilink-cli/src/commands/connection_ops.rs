//! CLI surface for the connectivity doctor and recent connection-attempt
//! traces — mirrors `yadorilink_daemon::connection_trace`'s wire shape
//! exactly.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{ConnectivityDoctorRequest, ListConnectionTracesRequest};

use crate::control_client;
use crate::error::CliError;

pub async fn doctor() -> Result<(), CliError> {
    let resp =
        control_client::send(ReqPayload::ConnectivityDoctor(ConnectivityDoctorRequest {})).await?;
    let Some(RespPayload::ConnectivityDoctor(result)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    for category in result.categories {
        let marker = match category.status.as_str() {
            "ok" => "OK",
            "warn" => "WARN",
            _ => "ERROR",
        };
        println!("[{marker}] {}: {}", category.name, category.detail);
    }
    Ok(())
}

pub async fn traces(peer_device_id: Option<String>) -> Result<(), CliError> {
    let resp =
        control_client::send(ReqPayload::ListConnectionTraces(ListConnectionTracesRequest {
            peer_device_id: peer_device_id.unwrap_or_default(),
        }))
        .await?;
    let Some(RespPayload::ListConnectionTraces(list)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    if list.traces.is_empty() {
        println!("No connection attempts recorded yet.");
    }
    for trace in list.traces {
        let peer =
            if trace.peer_device_id.is_empty() { "-".to_string() } else { trace.peer_device_id };
        let failure = if trace.failure_category.is_empty() {
            String::new()
        } else {
            format!(" ({})", trace.failure_category)
        };
        println!(
            "{}  peer={peer}  source={}  class={}  outcome={}{failure}  auth={}  selected={}",
            trace.recorded_at_unix_nanos,
            trace.candidate_source,
            trace.address_class,
            trace.outcome,
            trace.authorization_decision,
            trace.selected,
        );
    }
    Ok(())
}

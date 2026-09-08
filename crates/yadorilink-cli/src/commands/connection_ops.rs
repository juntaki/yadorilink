//! CLI surface for the connectivity doctor, recent connection-attempt
//! traces, and the LAN-discovered addresses currently held as dial
//! candidates — mirrors `yadorilink_daemon::connection_trace`'s wire shape
//! exactly.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    ConnectivityDoctorRequest, LanDiscoveredCandidate, ListConnectionTracesRequest,
    ListLanDiscoveredCandidatesRequest,
};

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

/// Both halves of "why isn't this peer connecting": the resolved
/// connection-attempt history, then the LAN-discovered addresses currently
/// held as dial candidates. The second section is what makes an announced
/// peer that has never actually connected visible at all -- an attempt
/// leaves a trace only once it has resolved, so a candidate that has never
/// been the winning one appears in no trace.
pub async fn traces(peer_device_id: Option<String>) -> Result<(), CliError> {
    let resp =
        control_client::send(ReqPayload::ListConnectionTraces(ListConnectionTracesRequest {
            peer_device_id: peer_device_id.clone().unwrap_or_default(),
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

    print_lan_discovered_candidates(peer_device_id).await;
    Ok(())
}

/// Prints the LAN-discovery section of `yadorilink connections`.
///
/// A candidate listed here is an address a device on this network
/// announced, kept as a dial target because this daemon already has that
/// device's key pinned. It is a place to dial, never authorization to
/// connect: every connection is still authenticated and authorized
/// exactly as it would be for any other candidate.
///
/// Infallible on purpose. This is a second request on a second connection,
/// made after the trace section above has already printed complete and
/// correct output, so a daemon that stops between the two would otherwise
/// turn a command that had just answered the operator's question into a
/// non-zero failure with its answer still on screen -- and a
/// partway-down daemon is exactly when someone runs this. A section that
/// cannot be fetched says so, and names why, rather than vanishing. The
/// command still fails when the FIRST request fails, which is the case
/// where there is genuinely nothing to report.
async fn print_lan_discovered_candidates(peer_device_id: Option<String>) {
    println!();
    match fetch_lan_discovered_candidates(peer_device_id).await {
        Ok(candidates) => {
            println!(
                "LAN-discovered candidates (announced and held as dial targets, not connections):"
            );
            if candidates.is_empty() {
                println!("  None currently held.");
            }
            for candidate in candidates {
                // `peer_has_any_session` rather than anything shaped like
                // "connected": the daemon resolves it per PEER, and a peer
                // announcing two LAN addresses while connected over a
                // coordination-supplied one prints `true` on both rows. It
                // says the peer is reachable somehow, never that this
                // address is the one in use.
                println!(
                    "  peer={}  class={}  last_seen_ms_ago={}  peer_has_any_session={}",
                    candidate.peer_device_id,
                    candidate.address_class,
                    candidate.last_seen_ms_ago,
                    candidate.peer_has_any_session,
                );
            }
        }
        Err(e) => println!("LAN-discovered candidates: unavailable ({e})"),
    }
}

async fn fetch_lan_discovered_candidates(
    peer_device_id: Option<String>,
) -> Result<Vec<LanDiscoveredCandidate>, CliError> {
    let resp = control_client::send(ReqPayload::ListLanDiscoveredCandidates(
        ListLanDiscoveredCandidatesRequest { peer_device_id: peer_device_id.unwrap_or_default() },
    ))
    .await?;
    let Some(RespPayload::ListLanDiscoveredCandidates(list)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    Ok(list.candidates)
}

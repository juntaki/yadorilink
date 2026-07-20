//! Gathers this device's direct-connection candidates and keeps the
//! coordination plane's view of them current, so peers behind NATs can reach
//! each other without an operator-run relay.
//!
//! STUN (server-reflexive discovery) and router port mapping both run over the
//! device's single shared UDP socket — the same socket every `PeerChannel`
//! sends and receives WireGuard traffic on. That is what makes the discovered
//! candidates correct: a NAT mapping is tied to the exact local port packets
//! left from, so the reflexive/port-mapped address a peer is told to dial is
//! only reachable because the data answering it flows on that same binding.
//! The transport's shared socket demultiplexes STUN responses back to the
//! prober by the STUN magic cookie.
//!
//! The merged candidate set and the passive NAT observations both live on
//! [`DaemonState`](crate::daemon_state::DaemonState): the tasks here write
//! them, the peer orchestrator reads candidates when offering a rendezvous,
//! and the connectivity doctor classifies the observations.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use yadorilink_transport::{
    local_candidates_classified, Candidate, CandidateClass, CandidateSink, HubStunSocket,
    PortMapConfig, PortMapper, StunConfig, StunProber,
};

use crate::coordination_client::{self, EndpointCandidate};
use crate::daemon_state::DaemonState;
use crate::device_config::NatConfig;

/// Runs candidate gathering (STUN + port mapping) and candidate reporting for
/// as long as the daemon lives. Everything runs over the device's single
/// shared UDP socket, so the reflexive/port-mapped candidates it discovers
/// describe the exact NAT binding peer data flows on. Returns early — leaving
/// the daemon otherwise unaffected — if that socket can't be bound; NAT
/// traversal is a best-effort enhancement, never a reason to bring the daemon
/// down.
pub async fn run(
    nat: NatConfig,
    coordination_addr: String,
    access_token: String,
    device_id: String,
    state: Arc<DaemonState>,
) {
    let shared = match state.ensure_shared_socket().await {
        Ok(shared) => shared,
        Err(e) => {
            tracing::warn!(error = %e, "NAT traversal disabled: could not bind the shared socket");
            return;
        }
    };
    let local_port = shared.local_port();

    let sink = state.nat_sink.clone();
    let observations = state.nat_observations.clone();

    // Seed the always-available candidate classes (LAN interfaces, global
    // IPv6 hosts) so a report goes out even before STUN answers, and record
    // the local addresses so classification can tell a private-address CGNAT
    // apart from a public one.
    let classified = local_candidates_classified(local_port);
    observations.set_local_addrs(local_addrs(&classified));
    seed_local_candidates(&sink, classified);

    let stun_config = StunConfig {
        servers: resolve_stun_servers(&nat.stun_servers).await,
        refresh_interval: Duration::from_secs(nat.stun_refresh_secs.max(1)),
    };
    // STUN binding requests leave from the shared socket; the demultiplexer
    // routes their responses back to this prober by the STUN magic cookie.
    let stun_socket = Arc::new(HubStunSocket::new(shared.clone()));
    let prober = StunProber::new(stun_socket, stun_config, sink.clone(), observations.clone());

    let mut port_map_config = PortMapConfig::new(local_port);
    port_map_config.enabled = nat.port_mapping_enabled;
    port_map_config.lease = Duration::from_secs(u64::from(nat.port_mapping_lease_secs).max(1));
    let mapper = PortMapper::new(port_map_config, sink.clone(), observations);

    // Held for the lifetime of this task: dropping the sender would close the
    // prober's network-change channel and make it shut down. We don't yet
    // detect network changes; STUN refreshes on its own interval.
    let (_network_change_tx, network_change_rx) = tokio::sync::mpsc::channel::<()>(1);

    // Release a held port mapping cleanly on graceful shutdown rather than
    // leaving the router to time the lease out.
    let mut shutdown_rx = state.shutdown_tx.subscribe();
    let mapper_shutdown = async move {
        let _ = shutdown_rx.changed().await;
    };

    let report = report_candidates_on_change(
        coordination_addr,
        access_token,
        device_id,
        state.nat_candidates.clone(),
    );

    // All three run concurrently for the daemon's lifetime; the essential-
    // task supervisor aborts this task on shutdown.
    tokio::join!(prober.run(network_change_rx), mapper.run(mapper_shutdown), report);
}

/// Groups the classified local candidates by class and publishes each class
/// into the shared sink.
fn seed_local_candidates(sink: &CandidateSink, classified: Vec<Candidate>) {
    let mut by_class: BTreeMap<CandidateClass, Vec<SocketAddr>> = BTreeMap::new();
    for candidate in classified {
        by_class.entry(candidate.class).or_default().push(candidate.addr);
    }
    for (class, addrs) in by_class {
        sink.publish(class, addrs);
    }
}

/// The distinct local interface IP addresses among the classified
/// candidates, for the NAT classifier's private-vs-public comparison.
fn local_addrs(classified: &[Candidate]) -> Vec<IpAddr> {
    let mut addrs: Vec<IpAddr> = classified.iter().map(|c| c.addr.ip()).collect();
    addrs.sort();
    addrs.dedup();
    addrs
}

/// Resolves each configured `host:port` STUN server to a socket address. An
/// unresolvable entry is skipped (a normal transient condition), and an empty
/// result simply disables STUN — no packets are sent.
async fn resolve_stun_servers(servers: &[String]) -> Vec<SocketAddr> {
    let mut resolved = Vec::new();
    for server in servers {
        match tokio::net::lookup_host(server).await {
            Ok(addrs) => {
                if let Some(addr) = addrs.into_iter().next() {
                    resolved.push(addr);
                }
            }
            Err(e) => {
                tracing::debug!(server = %server, error = %e, "could not resolve STUN server")
            }
        }
    }
    resolved
}

/// Reports the merged candidate set to the coordination plane whenever it
/// changes. The sink already suppresses no-op republishes, so this only fires
/// on a real change, keeping candidate-report traffic minimal.
async fn report_candidates_on_change(
    coordination_addr: String,
    access_token: String,
    device_id: String,
    mut candidates_rx: tokio::sync::watch::Receiver<Vec<Candidate>>,
) {
    loop {
        let candidates: Vec<EndpointCandidate> = {
            let current = candidates_rx.borrow_and_update();
            current
                .iter()
                .map(|c| EndpointCandidate { address: c.addr.to_string(), priority: c.priority() })
                .collect()
        };
        coordination_client::report_endpoint(
            &coordination_addr,
            &access_token,
            device_id.clone(),
            &candidates,
        )
        .await;
        if candidates_rx.changed().await.is_err() {
            return; // the sink was dropped: daemon shutting down
        }
    }
}

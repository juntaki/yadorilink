//! Router port mapping: ask the local gateway to forward an external UDP port
//! to this device's shared data socket, giving peers a reachable endpoint that
//! needs no hole punching for as long as the mapping holds.
//!
//! The protocol work — PCP, NAT-PMP, and UPnP-IGD probing, gateway discovery,
//! mapping acquisition, lease renewal, external-address change events, and
//! re-probing on network change — is handled by the `portmapper` crate. This
//! module is a thin adapter: it points the mapper at the shared socket's local
//! port, then feeds each granted external endpoint into the shared
//! [`CandidateSink`] (at port-mapped priority) and records the outcome in
//! [`ObservationLog`]. Because it does OS-level gateway discovery and
//! multicast, the mapper has no meaning under deterministic simulation and is
//! compiled out there, exactly as LAN multicast discovery is.
//!
//! Failure is the common case (the feature is off by default on many ISP
//! routers) and is recorded as an observation, never surfaced as an error.

#[cfg(not(madsim))]
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[cfg(not(madsim))]
use super::PortMappingStatus;
use super::{CandidateClass, CandidateSink, CandidateSource, ObservationLog};

/// Default requested lease. Kept for configuration compatibility; the
/// `portmapper` crate manages lease lifetimes and renewal internally, so this
/// is advisory rather than sent verbatim.
const DEFAULT_LEASE: Duration = Duration::from_secs(3600);

/// Configuration for the port mapper, from device config. Disabled by an
/// explicit flag; when disabled no discovery or mapping traffic is sent.
#[derive(Debug, Clone)]
pub struct PortMapConfig {
    pub enabled: bool,
    /// The shared socket's local UDP port to map an external port onto.
    pub internal_port: u16,
    /// Requested lease lifetime (advisory — see [`DEFAULT_LEASE`]).
    pub lease: Duration,
}

impl PortMapConfig {
    pub fn new(internal_port: u16) -> Self {
        Self { enabled: true, internal_port, lease: DEFAULT_LEASE }
    }
}

/// Long-lived port mapper. Drives the `portmapper` crate against the shared
/// socket's local port, advertises each granted external endpoint as a
/// high-priority candidate, and retracts it when the mapping goes away or on
/// shutdown.
pub struct PortMapper {
    config: PortMapConfig,
    sink: Arc<CandidateSink>,
    observations: ObservationLog,
}

impl CandidateSource for PortMapper {
    fn name(&self) -> &'static str {
        "port-mapping"
    }
    fn class(&self) -> CandidateClass {
        CandidateClass::PortMapped
    }
}

impl PortMapper {
    pub fn new(
        config: PortMapConfig,
        sink: Arc<CandidateSink>,
        observations: ObservationLog,
    ) -> Self {
        Self { config, sink, observations }
    }

    /// Runs until `shutdown` resolves. Acquires a mapping for the shared
    /// socket's port, republishes the port-mapped candidate on every external-
    /// address change, and releases the mapping on the way out.
    #[cfg(not(madsim))]
    pub async fn run(self, shutdown: impl std::future::Future<Output = ()>) {
        use std::num::NonZeroU16;

        if !self.config.enabled {
            return;
        }
        let Some(port) = NonZeroU16::new(self.config.internal_port) else {
            // Port 0 means the shared socket has no stable port to map.
            self.observations.set_port_mapping(PortMappingStatus::Unavailable);
            return;
        };

        // The client spawns its own service task (which uses its own sockets to
        // talk to the gateway) and is aborted when dropped.
        let client = portmapper::Client::new(portmapper::Config::default());
        client.update_local_port(port);
        client.procure_mapping();
        let mut external = client.watch_external_address();

        tokio::pin!(shutdown);
        loop {
            match *external.borrow_and_update() {
                Some(addr) => {
                    self.observations.set_port_mapping(PortMappingStatus::Mapped);
                    self.sink.publish(CandidateClass::PortMapped, vec![SocketAddr::V4(addr)]);
                }
                None => {
                    self.sink.publish(CandidateClass::PortMapped, Vec::new());
                }
            }
            tokio::select! {
                _ = &mut shutdown => break,
                changed = external.changed() => {
                    if changed.is_err() {
                        break; // the mapper's service task ended
                    }
                }
            }
        }

        // Release the mapping cleanly rather than leaving the router to age
        // the lease out, then retract the candidate.
        client.deactivate();
        self.sink.publish(CandidateClass::PortMapped, Vec::new());
    }

    /// Port mapping has no meaning under deterministic simulation (no real
    /// gateway, no multicast); this is a no-op that parks until shutdown.
    #[cfg(madsim)]
    pub async fn run(self, shutdown: impl std::future::Future<Output = ()>) {
        let _ = (&self.config, &self.sink, &self.observations);
        shutdown.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_to_enabled_with_the_given_internal_port() {
        let config = PortMapConfig::new(41641);
        assert!(config.enabled);
        assert_eq!(config.internal_port, 41641);
        assert_eq!(config.lease, DEFAULT_LEASE);
    }
}

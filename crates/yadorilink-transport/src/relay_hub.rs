//! One relay connection per device, shared across every `PeerChannel` that
//! device has open (fixing a real bug found via `yadorilink-daemon`'s 3-device
//! end-to-end test): the relay server registers exactly one TCP connection
//! per public key (see `relay_server.rs`), so if each `PeerChannel` opened
//! its own relay connection, a device with more than one peer would have
//! its later connections silently overwrite the registry entry the
//! earlier ones depend on, breaking delivery for all but the
//! most-recently-connected peer. `RelayHub` holds the connection and
//! demultiplexes incoming `Forwarded` frames to the right `PeerChannel` by
//! sender public key.
//!
//! The relay TCP connection is not one-shot.
//! `connect` performs (and requires to succeed, so callers get a fast
//! failure on totally-unreachable config) exactly one handshake, then
//! hands the connection to a supervised loop (`crate::supervise::
//! spawn_restarting`) that keeps it alive forever after: on any
//! disconnect it reconnects with backoff and repeats the *entire*
//! Hello handshake ("re-Hello"), which is also how the relay server's
//! route-registry entry for this device gets re-registered (a TCP
//! disconnect immediately removes it server-side, see
//! `relay_server.rs::remove_route`). `routes` (this device's own local
//! dispatch table, keyed by sender) lives on `RelayHub` itself rather
//! than the connection, so registered `PeerChannel`s need no action of
//! their own across a reconnect — they just keep working once the next
//! connection attempt succeeds.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::sync::mpsc;
use yadorilink_ipc_proto::relay::relay_message::Payload;
use yadorilink_ipc_proto::relay::{Forward, Hello, HelloProof, RelayMessage};

use crate::error::TransportError;
use crate::relay_client::{self, RelayConnection};
use crate::supervise::{self, BackoffConfig};

type PublicKeyBytes = [u8; 32];

pub struct RelayHub {
    relay_addr: SocketAddr,
    my_secret: StaticSecret,
    // Unbounded, matching this crate's pre-existing outbound-queue
    // behavior (a single large application message fragments into many
    // datagrams sent back-to-back with no per-fragment backpressure from
    // the writer task — a small bounded queue would silently drop
    // fragments mid-message). This means a prolonged relay outage queues
    // sends unboundedly rather than erroring immediately; bounding that
    // with real backpressure/retry is a separate concern (per-peer pending/unacked tracking).
    outbound_tx: mpsc::UnboundedSender<RelayMessage>,
    observed_address: Mutex<String>,
    routes: Mutex<HashMap<PublicKeyBytes, mpsc::Sender<Vec<u8>>>>,
}

impl RelayHub {
    pub async fn connect(
        relay_addr: SocketAddr,
        my_secret: StaticSecret,
    ) -> Result<Arc<Self>, TransportError> {
        // The very first attempt is synchronous and fallible, matching
        // the existing contract callers (`peer_orchestrator.rs`) depend
        // on for fast failure on unreachable/misconfigured relays; every
        // attempt after this one is handled by the reconnect supervisor
        // spawned below instead.
        let first_conn = relay_client::connect(relay_addr, &my_secret).await?;
        let observed_address = first_conn.observed_address.clone();
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<RelayMessage>();

        let hub = Arc::new(Self {
            relay_addr,
            my_secret,
            outbound_tx,
            observed_address: Mutex::new(observed_address),
            routes: Mutex::new(HashMap::new()),
        });

        // Reused across every (re)connection so a new writer task can
        // simply keep draining it — outbound senders never need to
        // change out from under callers of `send_forward`.
        let outbound_rx = Arc::new(tokio::sync::Mutex::new(outbound_rx));
        // `spawn_restarting` requires a `Fn` (callable repeatedly), but
        // the already-established first connection can only be consumed
        // once — stash it behind a lock the closure drains exactly once.
        let pending_first: Arc<Mutex<Option<RelayConnection>>> =
            Arc::new(Mutex::new(Some(first_conn)));
        let supervised_hub = hub.clone();
        supervise::spawn_restarting("relay-connection", BackoffConfig::RECONNECT, move || {
            let hub = supervised_hub.clone();
            let outbound_rx = outbound_rx.clone();
            let pending_first = pending_first.clone();
            async move {
                let pending =
                    pending_first.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take();
                let conn = match pending {
                    Some(conn) => conn,
                    None => match relay_client::connect(hub.relay_addr, &hub.my_secret).await {
                        Ok(conn) => {
                            tracing::info!(relay_addr = %hub.relay_addr, "relay reconnected");
                            conn
                        }
                        Err(error) => {
                            tracing::warn!(
                                relay_addr = %hub.relay_addr,
                                %error,
                                "relay reconnect attempt failed"
                            );
                            return;
                        }
                    },
                };
                *hub.observed_address.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
                    conn.observed_address.clone();
                hub.run_connection_until_disconnected(conn, outbound_rx).await;
                tracing::warn!(relay_addr = %hub.relay_addr, "relay connection lost; reconnecting");
            }
        });

        Ok(hub)
    }

    /// Drives one connection's writer + reader/dispatch tasks until
    /// either side ends (write failure, read error/EOF, or the relay
    /// closing the connection). The caller (the reconnect supervisor
    /// spawned in `connect`) is responsible for looping this with
    /// backoff and a fresh Hello each time.
    async fn run_connection_until_disconnected(
        self: &Arc<Self>,
        conn: RelayConnection,
        outbound_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<RelayMessage>>>,
    ) {
        let RelayConnection { mut read_half, mut write_half, .. } = conn;

        let mut writer = tokio::spawn(async move {
            loop {
                let msg = { outbound_rx.lock().await.recv().await };
                let Some(msg) = msg else { break };
                if crate::relay_io::write_relay_message(&mut write_half, &msg).await.is_err() {
                    break;
                }
            }
        });

        let dispatch_hub = self.clone();
        let mut reader = tokio::spawn(async move {
            loop {
                match crate::relay_io::read_relay_message(&mut read_half).await {
                    Ok(Some(RelayMessage { payload: Some(Payload::Forwarded(f)) })) => {
                        let Ok(from): Result<PublicKeyBytes, _> =
                            f.from_public_key.as_slice().try_into()
                        else {
                            continue;
                        };
                        let route = dispatch_hub
                            .routes
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .get(&from)
                            .cloned();
                        if let Some(route) = route {
                            let _ = route.send(f.payload).await;
                        }
                        // No registered route (yet, or ever): silently
                        // dropped — matches "not all traffic has a
                        // listener" being a normal, non-fatal condition
                        // for a fan-out dispatcher, same as the relay
                        // server's own absent-destination handling.
                    }
                    // Registration-renewal handshake: the relay
                    // answers our periodic renewal `Hello` (sent by the
                    // ticker task below) with a fresh challenge. Compute
                    // and send the proof the exact same way the initial
                    // connect handshake does (`relay_auth::proof_mac`),
                    // reusing the hardened, already-scrutinized mechanism
                    // rather than a separate renewal-specific one.
                    Ok(Some(RelayMessage {
                        payload: Some(Payload::HelloChallenge(challenge)),
                    })) => {
                        let Ok(server_public_key): Result<PublicKeyBytes, _> =
                            challenge.server_public_key.as_slice().try_into()
                        else {
                            continue;
                        };
                        let server_public_key = PublicKey::from(server_public_key);
                        if let Some(proof) = crate::relay_auth::proof_mac(
                            &dispatch_hub.my_secret,
                            &server_public_key,
                            &challenge.nonce,
                        ) {
                            let _ = dispatch_hub.outbound_tx.send(RelayMessage {
                                payload: Some(Payload::HelloProof(HelloProof { mac: proof })),
                            });
                        }
                        // A non-contributory challenge key or
                        // a send failure (outbound channel closing during
                        // shutdown) isn't fatal here: worst case this
                        // renewal attempt is skipped and the next tick
                        // gets another chance before the registration TTL
                        // actually elapses.
                    }
                    Ok(Some(_)) => continue,
                    Ok(None) => break,
                    Err(error) => {
                        tracing::warn!(%error, "relay connection read error");
                        break;
                    }
                }
            }
        });

        // Registration renewal ticker: proactively re-proves
        // key ownership well before the relay's registration TTL
        // (`relay_server::REGISTRATION_TTL`) would otherwise lapse, so a
        // healthy, long-lived connection never actually hits server-side
        // expiry. Scoped to this connection (aborted below alongside
        // reader/writer) so a reconnect doesn't accumulate one ticker per
        // past connection.
        let renewal_hub = self.clone();
        let renewal_ticker = tokio::spawn(async move {
            let renewal_interval = crate::relay_server::REGISTRATION_TTL / 3;
            loop {
                tokio::time::sleep(renewal_interval).await;
                let my_public_key = PublicKey::from(&renewal_hub.my_secret).to_bytes();
                if renewal_hub
                    .outbound_tx
                    .send(RelayMessage {
                        payload: Some(Payload::Hello(Hello { public_key: my_public_key.to_vec() })),
                    })
                    .is_err()
                {
                    break; // hub shutting down; nothing left to renew.
                }
            }
        });

        // Either task ending means the connection is no longer usable;
        // stop the others too so the reconnect supervisor can retry
        // promptly instead of leaking half-alive tasks.
        tokio::select! {
            _ = &mut writer => {},
            _ = &mut reader => {},
        }
        writer.abort();
        reader.abort();
        renewal_ticker.abort();
    }

    /// This device's public endpoint as observed by the relay on the most
    /// recent (re)connection.
    pub fn observed_address(&self) -> String {
        self.observed_address.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
    }

    /// Registers interest in frames from `peer_public_key`, returning the
    /// channel they'll arrive on. Call once per `PeerChannel`. Survives
    /// relay reconnects untouched — dispatch always consults this same
    /// map regardless of which underlying TCP connection is current.
    pub fn register(&self, peer_public_key: PublicKeyBytes) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel(64);
        self.routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(peer_public_key, tx);
        rx
    }

    pub fn unregister(&self, peer_public_key: &PublicKeyBytes) {
        self.routes.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(peer_public_key);
    }

    pub fn send_forward(
        &self,
        dest_public_key: PublicKeyBytes,
        payload: Vec<u8>,
    ) -> Result<(), TransportError> {
        self.outbound_tx
            .send(RelayMessage {
                payload: Some(Payload::Forward(Forward {
                    dest_public_key: dest_public_key.to_vec(),
                    payload,
                })),
            })
            .map_err(|_| TransportError::RelayClosed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boringtun::x25519::PublicKey;
    use std::time::Duration;
    use tokio::net::TcpListener;

    async fn start_relay() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = crate::relay_server::serve(listener).await;
        });
        addr
    }

    /// registering interest in a peer's traffic and sending a
    /// `Forward` to that peer's key must deliver the payload on the
    /// registered route.
    #[tokio::test]
    async fn register_and_dispatch_delivers_forwarded_payload_to_registered_route() {
        let relay_addr = start_relay().await;
        let secret_a = StaticSecret::from([51u8; 32]);
        let secret_b = StaticSecret::from([52u8; 32]);
        let key_a = PublicKey::from(&secret_a).to_bytes();
        let key_b = PublicKey::from(&secret_b).to_bytes();

        let hub_a = RelayHub::connect(relay_addr, secret_a).await.unwrap();
        let hub_b = RelayHub::connect(relay_addr, secret_b).await.unwrap();

        let mut inbound = hub_b.register(key_a);
        hub_a.send_forward(key_b, b"hello".to_vec()).unwrap();

        let received =
            tokio::time::timeout(Duration::from_secs(2), inbound.recv()).await.unwrap().unwrap();
        assert_eq!(received, b"hello");
    }

    /// Testing "absent-dest behavior" at the hub's local dispatch
    /// layer: a `Forwarded` frame from a sender nobody `register`ed
    /// interest in must be silently dropped — not panic, not disrupt
    /// dispatch to other, already-registered routes on the same
    /// connection, and not get queued somewhere a later `register` call
    /// would unexpectedly receive it from.
    #[tokio::test]
    async fn forwarded_frame_for_unregistered_sender_is_dropped_without_disrupting_other_routes() {
        let relay_addr = start_relay().await;
        let secret_a = StaticSecret::from([53u8; 32]);
        let secret_b = StaticSecret::from([54u8; 32]);
        let secret_c = StaticSecret::from([55u8; 32]);
        let key_a = PublicKey::from(&secret_a).to_bytes();
        let key_b = PublicKey::from(&secret_b).to_bytes();
        let key_c = PublicKey::from(&secret_c).to_bytes();

        let hub_a = RelayHub::connect(relay_addr, secret_a).await.unwrap();
        let hub_b = RelayHub::connect(relay_addr, secret_b).await.unwrap();
        let hub_c = RelayHub::connect(relay_addr, secret_c).await.unwrap();

        // hub_b registers interest only in traffic from C, never from A.
        let mut inbound_from_c = hub_b.register(key_c);

        hub_a.send_forward(key_b, b"nobody is listening for me".to_vec()).unwrap();
        hub_c.send_forward(key_b, b"from c".to_vec()).unwrap();

        let received = tokio::time::timeout(Duration::from_secs(2), inbound_from_c.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, b"from c", "the registered route must still work");

        // Confirm A's frame really was dropped rather than queued
        // anywhere: registering interest in A now must not retroactively
        // receive it.
        let mut inbound_from_a = hub_b.register(key_a);
        let late = tokio::time::timeout(Duration::from_millis(200), inbound_from_a.recv()).await;
        assert!(
            late.is_err(),
            "no message should have been queued for a route that didn't exist yet"
        );
    }
}

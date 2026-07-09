//! Low-level relay wire protocol: the Hello/HelloChallenge/HelloProof/
//! HelloAck handshake over a fresh TCP connection, producing the raw
//! split read/write halves that follow it.
//!
//! Deliberately owns no long-lived tasks or reconnect logic — see
//! `relay_hub.rs`'s `RelayHub`, the one place a relay connection's
//! lifetime (including reconnects) is managed. [`connect`] is
//! called once for the initial connection *and* once per reconnect
//! attempt, so every reconnect re-runs this exact same handshake
//! ("re-Hello"): the relay server drops a device's route registry entry
//! the instant its TCP connection closes (`relay_server.rs::remove_route`),
//! so only a fresh Hello re-registers it.

use std::net::SocketAddr;

use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use yadorilink_ipc_proto::relay::relay_message::Payload;
use yadorilink_ipc_proto::relay::{Hello, HelloProof, RelayMessage};

use crate::error::TransportError;

/// One successfully-authenticated relay TCP connection, split for
/// independent read/write tasks.
///
/// Split via the generic `tokio::io::split` (a `Mutex`-backed
/// `ReadHalf`/`WriteHalf` pair over any `AsyncRead + AsyncWrite`), not
/// `TcpStream::into_split` (a lock-free `BiLock`-based split specific to
/// real tokio's own `TcpStream`) — `madsim`'s simulated `TcpStream`
/// implements real tokio's `AsyncRead`/`AsyncWrite` traits but has no
/// `into_split` method of its own, so the generic split is the one form
/// that works unmodified under both the real and `madsim`-simulated
/// runtime.
#[derive(Debug)]
pub struct RelayConnection {
    pub read_half: ReadHalf<TcpStream>,
    pub write_half: WriteHalf<TcpStream>,
    /// This device's public IP:port as observed by the relay for *this*
    /// connection — a minimal STUN-like "netcheck".
    pub observed_address: String,
}

/// Performs the Hello/HelloChallenge/HelloProof/HelloAck handshake over a
/// fresh TCP connection to `relay_addr`, registering `my_secret`'s public
/// key with the relay.
pub async fn connect(
    relay_addr: SocketAddr,
    my_secret: &StaticSecret,
) -> Result<RelayConnection, TransportError> {
    let my_public_key = PublicKey::from(my_secret).to_bytes();
    let stream = TcpStream::connect(relay_addr).await?;
    let (mut read_half, mut write_half) = tokio::io::split(stream);

    crate::relay_io::write_relay_message(
        &mut write_half,
        &RelayMessage {
            payload: Some(Payload::Hello(Hello { public_key: my_public_key.to_vec() })),
        },
    )
    .await?;

    let (server_public_key, nonce) = match crate::relay_io::read_relay_message(&mut read_half)
        .await?
    {
        Some(RelayMessage { payload: Some(Payload::HelloChallenge(challenge)) }) => {
            let server_public_key: [u8; 32] =
                challenge.server_public_key.as_slice().try_into().map_err(|_| {
                    TransportError::RelayProtocol(
                        "relay challenge public key must be 32 bytes".into(),
                    )
                })?;
            (server_public_key, challenge.nonce)
        }
        _ => {
            return Err(TransportError::RelayProtocol("expected HelloChallenge after Hello".into()))
        }
    };
    let server_public_key = PublicKey::from(server_public_key);
    // security hardening: `proof_mac` refuses to sign over a non-contributory
    // (low-order) shared secret; a relay handing out such a challenge
    // key is either broken or malicious, either way not worth completing
    // the handshake against.
    let proof =
        crate::relay_auth::proof_mac(my_secret, &server_public_key, &nonce).ok_or_else(|| {
            TransportError::RelayProtocol(
                "relay challenge key produced a non-contributory shared secret".into(),
            )
        })?;
    crate::relay_io::write_relay_message(
        &mut write_half,
        &RelayMessage { payload: Some(Payload::HelloProof(HelloProof { mac: proof })) },
    )
    .await?;

    // The relay replies to a valid proof with HelloAck before forwarding anything else.
    let observed_address = match crate::relay_io::read_relay_message(&mut read_half).await? {
        Some(RelayMessage { payload: Some(Payload::HelloAck(ack)) }) => ack.observed_address,
        _ => {
            return Err(TransportError::RelayProtocol("expected HelloAck after HelloProof".into()))
        }
    };

    Ok(RelayConnection { read_half, write_half, observed_address })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// The handshake this module performs must succeed end-to-end against
    /// a real relay server and report an observed address — the
    /// foundation every reconnect attempt in `relay_hub.rs`
    /// repeats verbatim.
    #[tokio::test]
    async fn connect_completes_handshake_and_reports_observed_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = crate::relay_server::serve(listener).await;
        });

        let secret = StaticSecret::from([12u8; 32]);
        let conn = connect(addr, &secret).await.unwrap();

        assert!(!conn.observed_address.is_empty());
        assert!(
            conn.observed_address.starts_with("127.0.0.1:"),
            "expected a loopback observed address, got {}",
            conn.observed_address
        );
    }

    /// A relay that never speaks the protocol (e.g. an unrelated service
    /// on that port) must surface as an error rather than hanging forever
    /// or panicking — the reconnect supervisor in `relay_hub.rs` depends
    /// on every attempt eventually resolving so backoff can proceed.
    #[tokio::test]
    async fn connect_fails_when_relay_closes_before_challenge() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                drop(stream); // close immediately, no handshake at all
            }
        });

        let secret = StaticSecret::from([13u8; 32]);
        let err = connect(addr, &secret).await.unwrap_err();
        assert!(matches!(err, TransportError::RelayProtocol(_) | TransportError::Io(_)));
    }
}

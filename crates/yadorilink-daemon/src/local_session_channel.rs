//! An inert `PeerMessageChannel` for `DaemonState::local_retirement_session`
//! -- a `PeerSyncSession` this device constructs bound to no live peer at
//! all, so purely-local session methods (currently just `retire_conflict_
//! copies_only`) can run without a currently-connected peer to route
//! through. `.run()` is never called on that session: only its specific
//! methods are, and none of them read from or write to a peer channel for
//! a purely local tombstone materialize (no fetch, no announce). `recv()`
//! therefore never resolving is never observed in practice -- it is
//! implemented as a pending future rather than `unreachable!()` so a
//! future caller that DOES accidentally exercise this channel (e.g. calls
//! `.run()` on a local-only session) fails safe (hangs/no-ops) instead of
//! panicking the whole daemon.

use yadorilink_peer_session::ports::PeerBlockStream;
use yadorilink_transport::TransportError;

pub(crate) struct LoopbackPeerMessageChannel;

#[async_trait::async_trait]
impl yadorilink_peer_session::ports::PeerMessageChannel for LoopbackPeerMessageChannel {
    async fn send(&self, _payload: Vec<u8>) -> Result<(), TransportError> {
        Ok(())
    }

    fn try_send(&self, _payload: Vec<u8>) -> bool {
        true
    }

    async fn recv(&self) -> Option<Vec<u8>> {
        std::future::pending().await
    }

    /// There is no peer, so there is no stream to open. Reported as a
    /// closed channel rather than as a pending future: unlike `recv`, whose
    /// caller is a loop that should simply never see anything, a fetch has
    /// a caller waiting on an answer, and "this session cannot fetch"
    /// is one -- the same answer it would get from a connection that had
    /// gone away.
    async fn open_block_stream(&self) -> Result<Box<dyn PeerBlockStream>, TransportError> {
        Err(TransportError::ChannelClosed)
    }

    /// Never resolves, for the same reason `recv` does not: a local-only
    /// session serves nothing, and a serving loop parked here is a serving
    /// loop that does nothing rather than one that spins.
    async fn accept_block_stream(&self) -> Option<Box<dyn PeerBlockStream>> {
        std::future::pending().await
    }
}

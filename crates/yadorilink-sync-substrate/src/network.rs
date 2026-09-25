//! The domain-facing network boundary.
//!
//! The point of this trait is not portability between transports — Yadori is
//! on iroh and there is no second backend to keep alive. It is that the layers
//! above (`YadoriSyncProtocol`, the verified inbox, admission) name only
//! [`PeerId`], [`PeerAddress`], [`PeerLink`] and [`Lane`]. Nothing above this
//! crate can come to depend on an iroh API detail, so a transport change is a
//! change to one adapter.
//!
//! It is deliberately small. Anything richer would be speculative.

use std::future::Future;

use crate::address::PeerAddress;
use crate::error::SubstrateError;
use crate::link::PeerLink;
use crate::peer::PeerId;

/// A running network that can dial peers and accept their connections.
pub trait YadoriNetwork: Send + Sync + 'static {
    /// The address the coordination plane should publish for this node.
    fn local_address(&self) -> PeerAddress;

    /// Dial a peer by identity. Where that peer currently answers is the
    /// address lookup's question, not this caller's -- see
    /// `crate::directory`.
    fn connect(
        &self,
        peer: PeerId,
    ) -> impl Future<Output = Result<PeerLink, SubstrateError>> + Send;

    /// Tear the network down. After this returns, every link is closed and no
    /// session state survives; reconciliation restarts from durable state.
    fn shutdown(&self) -> impl Future<Output = ()> + Send;
}

impl YadoriNetwork for crate::node::SubstrateNode {
    fn local_address(&self) -> PeerAddress {
        self.local_address()
    }

    async fn connect(&self, peer: PeerId) -> Result<PeerLink, SubstrateError> {
        self.connect(peer).await
    }

    async fn shutdown(&self) {
        self.shutdown().await;
    }
}

//! The independent flow-control domains of `YadoriSyncProtocol`.
//!
//! A lane is a *class* of QUIC bidirectional streams within one connection,
//! not a single stream. QUIC applies flow control per stream, so a stalled or
//! saturated lane cannot head-of-line block another one. This is the
//! structural replacement for the single shared control stream, on which a
//! bulk `ChangeBatch` could indefinitely starve a `HeadsAnnounce`.
//!
//! Splitting streams removes *stream-level* head-of-line blocking only.
//! Connection-level congestion and flow-control credit stay shared, so the
//! lane classes also carry concurrency limits: reconciliation is a single
//! always-drained stream, and the two bulk classes are bounded (see
//! [`LaneLimits`]). Should block transfer alone be measured to exhaust
//! connection-level credit, the next step is a separate ALPN and connection
//! for it — not a return to one shared stream.

use std::fmt;

/// A flow-control domain within one peer connection.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Lane {
    /// Range fingerprints, range splits and identifier sets. Small, latency
    /// sensitive, and never allowed to queue behind bulk traffic.
    Reconciliation,
    /// History and metadata bulk: proof-carrying change bundles, and
    /// re-bootstrap snapshots.
    ///
    /// A *class*, not one protocol. What rides here is anything that is
    /// verifiable history rather than latency-sensitive control or raw
    /// content — large, self-describing, and safe to make another stream wait
    /// for. Which of them a given stream carries is its first byte
    /// ([`HistoryStreamKind`]), read by the stream dispatcher and by nothing
    /// below it: the reconciliation protocol must not learn that re-bootstrap
    /// exists, and re-bootstrap must not learn how bundles are framed.
    History,
    /// File block / content hydration traffic. The bulkiest lane by orders of
    /// magnitude.
    Block,
    /// Small request/response service RPCs: version-present, handoff leases
    /// and tickets, durability, re-bootstrap requests.
    ///
    /// Durability has no RPC of its own — it is a `for_handoff`
    /// version-present query — so it rides here by construction rather than
    /// by being moved.
    ///
    /// One stream per logical RPC, deliberately — not one shared stream with
    /// a receive loop and a request-id map behind it. That shape is what the
    /// lane classes exist to remove, and rebuilding it here on iroh would put
    /// it back: a slow RPC would again delay every other one, and the
    /// correlation table would again be a thing that can leak, mismatch or
    /// grow. A QUIC stream already *is* the correlation between a request and
    /// its response.
    ///
    /// Classified by shape rather than by which legacy frame carried it:
    ///
    /// ```text
    ///   small request / control metadata  →  Service
    ///   proof-carrying or history bulk    →  Bundle
    ///   content bytes                     →  Block
    /// ```
    Service,
}

impl Lane {
    /// Every lane, in declaration order.
    pub const ALL: [Lane; 4] = [Lane::Reconciliation, Lane::History, Lane::Block, Lane::Service];

    /// The one-byte tag written as the first byte of a lane's stream so the
    /// accepting side can dispatch a newly accepted stream to its handler.
    pub const fn tag(self) -> u8 {
        match self {
            Lane::Reconciliation => 1,
            Lane::History => 2,
            Lane::Block => 3,
            Lane::Service => 4,
        }
    }

    /// Inverse of [`Lane::tag`]. Returns `None` for an unknown tag, which a
    /// peer must treat as a protocol violation rather than as a lane to guess.
    pub const fn from_tag(tag: u8) -> Option<Lane> {
        match tag {
            1 => Some(Lane::Reconciliation),
            2 => Some(Lane::History),
            3 => Some(Lane::Block),
            4 => Some(Lane::Service),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Lane::Reconciliation => "reconciliation",
            Lane::History => "history",
            Lane::Block => "block",
            Lane::Service => "service",
        }
    }
}

impl fmt::Debug for Lane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl fmt::Display for Lane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What a [`Lane::History`] stream carries.
///
/// On the wire it is the first byte of the history protocol payload — that
/// is, *after* the lane tag and the common lane/group hello every lane
/// stream begins with, not the first byte of the stream:
///
/// ```text
///   lane tag  →  lane/group hello  →  HistoryStreamKind  →  payload
/// ```
///
/// Deliberately not known to `yadorilink-sync-protocol`. That crate moves
/// bytes and compares sets; teaching it that re-bootstrap exists would put a
/// daemon concept underneath the protocol boundary, which is the thing that
/// made adding a whole extra lane look necessary in the first place. The
/// stream dispatcher reads this byte and hands the rest of the stream to
/// whichever handler owns that kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HistoryStreamKind {
    /// The proof-carrying change bundles reconciliation asks for.
    ProofBundle,
    /// A re-bootstrap snapshot, requested by the hash a signed manifest
    /// already bound it to.
    RebootstrapSnapshot,
}

impl HistoryStreamKind {
    pub const fn tag(self) -> u8 {
        match self {
            HistoryStreamKind::ProofBundle => 1,
            HistoryStreamKind::RebootstrapSnapshot => 2,
        }
    }

    /// Inverse of [`tag`](Self::tag). `None` for an unknown kind, which fails
    /// the stream closed rather than guessing what a peer meant.
    pub const fn from_tag(tag: u8) -> Option<HistoryStreamKind> {
        match tag {
            1 => Some(HistoryStreamKind::ProofBundle),
            2 => Some(HistoryStreamKind::RebootstrapSnapshot),
            _ => None,
        }
    }
}

/// Per-connection concurrency budget for the bulk lane classes.
///
/// [`Lane::Reconciliation`] is deliberately absent: it is always exactly one
/// stream, opened for the life of the session and drained unconditionally. A
/// budget it could exhaust would reintroduce the starvation being removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneLimits {
    /// Concurrent history/metadata bulk transfers.
    pub history: usize,
    /// Concurrent block/content transfers.
    pub block: usize,
    /// Concurrent service RPCs.
    ///
    /// Bounded for a different reason than the bulk lanes: a service RPC is
    /// small on the wire but can cost a task and a database round trip, so
    /// without a budget a peer opening streams in a loop turns into unbounded
    /// work here. Higher than the bulk lanes because each one is short.
    pub service: usize,
}

impl LaneLimits {
    /// The budget for `lane`, or `None` for the unbounded-by-design
    /// reconciliation lane.
    pub const fn for_lane(&self, lane: Lane) -> Option<usize> {
        match lane {
            Lane::Reconciliation => None,
            Lane::History => Some(self.history),
            Lane::Block => Some(self.block),
            Lane::Service => Some(self.service),
        }
    }
}

impl Default for LaneLimits {
    fn default() -> Self {
        // Small enough that a peer cannot convert bulk concurrency into
        // connection-level credit exhaustion, large enough to keep the link
        // busy while any one transfer is waiting on storage.
        Self { history: 4, block: 8, service: 16 }
    }
}

#[cfg(test)]
mod tests;

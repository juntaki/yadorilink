//! Where the substrate, the protocol and the replica meet.
//!
//! ```text
//!   Coordination plane                  membership, policy, peer addresses
//!           │
//!           ▼
//!     SyncRuntime  ──────────────────►  SingleFlight: one reconciliation
//!           │                            per (peer, group)
//!           ▼
//!   yadorilink-sync-substrate           iroh: QUIC, NAT traversal, relay
//!           │                            one connection, three lane classes
//!           ▼
//!   yadorilink-sync-protocol            RBSR over the reconciliation lane,
//!           │                            proof bundles over the bundle lane
//!           ▼
//!        ReplicaPort                    verified possession, admission
//! ```
//!
//! This crate owns the lifecycle and nothing else. It decides when to
//! reconcile and with whom; it decides nothing about what is authorized,
//! what is admissible, or what a Change means.

mod runtime;

pub use runtime::{
    write_history_kind, AcceptedLinkHook, BehindHook, DialAttemptHook, DialedLinkHook,
    HistoryStreamHook, LaneStreamHook, ServeHandle, SyncOutcome, SyncRuntime, SyncRuntimeError,
    SyncSummary,
};

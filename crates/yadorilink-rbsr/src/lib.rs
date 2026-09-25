//! Range-based set reconciliation over a one-dimensional identifier set.
//!
//! # Why this exists
//!
//! The protocol this replaces discovered differences by announcing heads. A
//! head announcement that was never delivered left the receiving peer with no
//! way to learn that the Change existed at all: there was nothing to
//! re-derive the gap from, so a single lost announcement became a permanent
//! one — for example, a `HeadsAnnounce` that repeatedly fails to reach the
//! receiver's handler with no transport error logged.
//!
//! Reconciliation removes the class. Two peers compare the sets they actually
//! hold, so no individual message is load-bearing: whatever is lost, the next
//! comparison finds the same difference again. Nothing about correctness
//! depends on a timer, a retry, an acknowledgement table, or state that
//! survived the last session.
//!
//! # What is not here
//!
//! This crate knows nothing about Changes, groups, authorization, storage or
//! transport. It reconciles opaque 32-byte identifiers. What makes an
//! identifier a member of the set — verified possession, held evidence, and
//! disclosability to the peer being spoken to — is stated at
//! [`ReconciliationIndex`] and enforced by its implementor.

mod error;
mod fingerprint;
mod id;
mod index;
mod message;
mod range;
mod session;

pub use error::RbsrError;
pub use fingerprint::{fingerprint, Fingerprint};
pub use id::ItemId;
pub use index::{MemoryIndex, ReconciliationIndex};
pub use message::RbsrMessage;
pub use range::{Range, RangeEnd};
pub use session::{RbsrConfig, Reconciler};

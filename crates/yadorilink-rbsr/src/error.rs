//! Protocol violations.
//!
//! Every variant here describes something a peer did, not something that went
//! wrong locally. Reconciliation runs against peers that may be adversarial,
//! so malformed input is a named, rejectable condition rather than something
//! the state machine tries to interpret.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RbsrError {
    /// The peer sent more statements in one round than are accepted.
    #[error("peer sent {received} statements in one round, limit is {limit}")]
    RoundTooLarge { received: usize, limit: usize },

    /// The peer listed more identifiers in one message than are accepted.
    #[error("peer listed {received} identifiers in one message, limit is {limit}")]
    ListingTooLarge { received: usize, limit: usize },

    /// The peer spoke about a range that can hold nothing.
    #[error("peer sent a statement about an empty range")]
    EmptyRange,

    /// The peer listed an identifier outside the range it claimed to describe.
    #[error("peer listed an identifier outside the range it described")]
    ItemOutsideRange,

    /// The peer's listing was not in ascending order without duplicates.
    #[error("peer's listing was not strictly ascending")]
    ListingNotAscending,
}

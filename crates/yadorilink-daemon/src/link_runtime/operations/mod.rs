//! Per-link operations dispatched through [`super::RootLease`]. Each
//! submodule wraps one thing this crate does to a link's on-disk/indexed
//! state, admitting a `LinkOperation` for the whole call rather than
//! leaving each caller to remember to.
//!
//! Two of the three operations named in this crate's `link_runtime` design
//! are represented here: [`capture_local_change`] and
//! [`repair_materialization`] -- see each module's own doc for what it
//! covers. The third, "ApplyPeerChange", has no daemon-owned operation
//! module of its own (the mutation logic stays in `yadorilink-sync-core`,
//! on the other side of a dependency direction this crate does not invert)
//! -- this crate's only contribution to it is an authority lookup that
//! lives in the daemon's own `root_commit_authority` module, outside this
//! module tree entirely, since it needs `DaemonState` directly rather than
//! the narrow per-link bundle every operation here is built against.

pub(crate) mod capture_local_change;
pub(crate) mod repair_materialization;

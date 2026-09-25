//! Which UDP socket this crate's real networking is built on.
//!
//! There is one socket type here and two builds that reach it, and the
//! whole point is that only this file knows which is which:
//!
//! * **native** -- `tokio::net::UdpSocket`, the real thing.
//! * **`--cfg turmoil`** -- the real `tokio` is kept, so the swap has to be
//!   explicit: `turmoil::net::UdpSocket`, which mirrors tokio's type name,
//!   method signatures and error semantics.
//!
//! # Why this is a type alias and not a trait
//!
//! A `PeerTransport` trait with a real and a simulated implementation would
//! mean the simulator exercises an implementation production never runs,
//! which is the failure mode a deterministic simulator exists to avoid --
//! every bug living in the gap between the two would be invisible by
//! construction. Re-pointing one name costs nothing at runtime and leaves
//! exactly one implementation of everything above it.
//!
//! # What the simulated socket does not have
//!
//! No synchronous `poll_send_ready`, and no `from_std`. The code above
//! already accounts for it: quinn's synchronous `try_send` hands the
//! datagram to a writer task whose queue is the only place backpressure
//! comes from (see `quic_socket.rs`), and the dual-stack v6 half is not
//! bound under simulation at all.

#[cfg(not(turmoil))]
pub use tokio::net::UdpSocket;

#[cfg(turmoil)]
pub use turmoil::net::UdpSocket;

/// True when this build's sockets are simulated. Spelled out at each use site rather than hidden behind a
/// build-script cfg alias, so that `grep` still finds every place the two
/// builds diverge.
#[cfg(turmoil)]
pub const SIMULATED: bool = true;
#[cfg(not(turmoil))]
pub const SIMULATED: bool = false;

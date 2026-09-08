//! Pure replica domain model -- identities, file/version records, the
//! signed canonical `Change`, and deterministic conflict policy. No
//! filesystem, network, database, or async runtime dependency: everything
//! here is a synchronous, deterministic function of its inputs. The
//! boundary is declared in `architecture.toml` (this crate is the base of
//! the `domain` layer) and enforced by `scripts/check-architecture.py`.

pub mod admission;
pub mod change;
pub mod codec;
pub mod conflict;
pub mod file;
pub mod ids;
pub mod limits;
pub mod rebootstrap;
pub mod recovery;
pub mod reserved_paths;
pub mod rewind;
pub mod session_state;

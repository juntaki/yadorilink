//! Pure replica domain model -- identities, file/version records, the
//! signed canonical `Change`, and deterministic conflict policy. No
//! filesystem, network, database, or async runtime dependency: everything
//! here is a synchronous, deterministic function of its inputs. See
//! `scripts/check-phase7d1-domain-boundary.py` for the enforced boundary
//! and `docs/design/phase7d1-replica-domain-exit-report.md` for what did
//! and did not move here from `yadorilink-sync-core`.

pub mod admission;
pub mod change;
pub mod conflict;
pub mod codec;
pub mod file;
pub mod filesystem_placement;
pub mod ids;
pub mod limits;
pub mod rebootstrap;
pub mod recovery;
pub mod reserved_paths;
pub mod session_state;

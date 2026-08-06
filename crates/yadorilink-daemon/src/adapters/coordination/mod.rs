//! HTTP-backed implementations of `application::ports::*Coordination`
//! traits -- the only place in this crate that builds a coordination-plane
//! request URL or `reqwest::Client` for these use cases. Populated
//! alongside each service's own Phase 2 commit (Enrollment: Commit 2;
//! Membership: Commit 4; Replica-role: Commit 5).

pub(crate) mod enrollment;
pub(crate) mod membership;
pub(crate) mod role_loss;

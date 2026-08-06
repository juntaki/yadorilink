//! The composition root's own output type: `application`/`queries`, built
//! exactly once (in production, by `app.rs`, the sole composition root;
//! in tests -- both this crate's own unit tests and the integration test
//! binaries under `tests/`, which link against this crate as an ordinary
//! dependency and so never see `#[cfg(test)]` -- by
//! `ControlContext::from_state`) and handed down through every
//! connection. Deliberately has NO `Arc<DaemonState>` field --
//! `handle_request`'s match arms all go through `application`/`queries`
//! now, and any future one that would need `DaemonState` directly is a
//! signal to add a narrow port/query instead, not to widen this struct
//! back out.
//!
//! `pub`, not `pub(crate)`: `control_socket::unix_transport::serve`/
//! `windows_transport::serve` are themselves `pub` (every integration
//! test under `tests/` calls them directly), so their `Arc<ControlContext>`
//! parameter must be constructible from outside this crate too.

use std::sync::Arc;

use crate::application::ApplicationServices;
use crate::queries::QueryServices;

pub struct ControlContext {
    pub(crate) application: Arc<ApplicationServices>,
    pub(crate) queries: Arc<QueryServices>,
}

impl ControlContext {
    pub(crate) fn new(application: Arc<ApplicationServices>, queries: Arc<QueryServices>) -> Self {
        Self { application, queries }
    }

    /// Builds both from a real `Arc<DaemonState>`, matching the exact
    /// composition `crate::adapters::build_application_services`/
    /// `build_query_services` (and, in production, `app.rs`) perform. Not
    /// used by `app.rs` itself, which already holds the two `Arc`s
    /// separately -- this exists for test call sites that only have a
    /// `DaemonState` to start from.
    pub fn from_state(state: Arc<crate::daemon_state::DaemonState>) -> Self {
        let application = crate::adapters::build_application_services(state.clone());
        let queries = crate::adapters::build_query_services(state);
        Self::new(application, queries)
    }
}

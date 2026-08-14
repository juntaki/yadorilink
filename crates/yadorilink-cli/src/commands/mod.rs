pub mod account;
pub mod auth;
pub mod backup;
pub mod connection_ops;
pub mod daemon;
pub mod device;
pub mod diagnose;
pub mod feedback;
pub mod gc;
pub mod ignore;
pub mod limits;
// link.rs keeps two semantic status enums in its shared import block for its
// test-only rendering coverage; the non-test library build does not reference
// them. Scope the lint allowance to this module rather than weakening the
// workspace-wide `-D warnings` gate.
#[allow(unused_imports)]
pub mod link;
pub mod materialization;
pub(crate) mod membership_render;
pub mod recovery;
pub mod report;
pub mod share;
pub mod status;
pub mod update;
pub mod version_history;

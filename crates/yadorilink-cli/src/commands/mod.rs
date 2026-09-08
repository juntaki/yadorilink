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
// Public rather than crate-private since the desktop app's share window
// reuses this module's warning wording verbatim for its own forced-revoke
// reporting -- a data-loss warning paraphrased a second time is a data-loss
// warning that can be softened by accident.
pub mod membership_render;
pub mod recovery;
pub mod report;
pub mod rewind;
pub mod send;
pub mod share;
pub mod status;
pub mod update;
pub mod version_history;

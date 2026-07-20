//! The onboarding wizard, split into a
//! pure state machine (`machine`), an off-thread effect executor mapping the
//! machine's effects onto `yadorilink_cli` calls (`executor`), and the
//! system-state probe the start step is derived from (`probe`). The eframe
//! window that renders the machine lives in `crate::window` (a separate
//! process entry); everything here is display-server-free and — apart from
//! the inherently impure `probe` — unit-tested.

pub mod executor;
pub mod machine;
pub mod probe;

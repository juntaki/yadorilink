//! Library half of `yadorilink-desktop-app`, split out purely so this
//! crate's `tests/` integration suite (and any future consumer) can
//! exercise `actions`/`ipc_client`/`status_model`/`login_item` directly —
//! mirrors `yadorilink-cli`'s own lib-plus-bin split (`src/lib.rs` +
//! `src/main.rs`) for the identical reason.
pub mod account;
pub mod actions;
pub mod google_login;
pub mod ipc_client;
pub mod login_item;
pub mod onboarding;
pub mod status_model;
pub mod window;

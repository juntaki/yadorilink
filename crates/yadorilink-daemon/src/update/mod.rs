//! add-automatic-updates: signed update discovery, verification, download,
//! install orchestration, and rollback/recovery for desktop builds
//! (design.md). See each submodule's doc comment for its slice of the
//! design:
//!   - `manifest`: the signed update manifest (task 1).
//!   - `verify`: downloaded-artifact checksum/publisher-signature checks (task 1.4).
//!   - `policy`: persisted daemon update policy/state (task 2.1).
//!   - `manager`: check/download/verify/install orchestration, background
//!     scheduling, and interrupted-update recovery (task 2).
//!   - `install_macos` / `install_windows`: platform install handoff (task 4).

pub mod install_macos;
pub mod install_windows;
pub mod manager;
pub mod manifest;
pub mod policy;
pub mod verify;

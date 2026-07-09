//! Signed update discovery, verification, download, install
//! orchestration, and rollback/recovery for desktop builds. See each
//! submodule's doc comment for its slice of the design:
//!   - `manifest`: the signed update manifest (the relevant behavior).
//!   - `verify`: downloaded-artifact checksum/publisher-signature checks (the relevant behavior).
//!   - `policy`: persisted daemon update policy/state (the relevant behavior).
//!   - `manager`: check/download/verify/install orchestration, background
//!     scheduling, and interrupted-update recovery (the relevant behavior).
//!   - `install_macos` / `install_windows`: platform install handoff (the relevant behavior).

pub mod install_macos;
pub mod install_windows;
pub mod manager;
pub mod manifest;
pub mod policy;
pub mod verify;

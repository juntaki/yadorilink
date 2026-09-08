//! Signed update discovery, verification, download, install
//! orchestration, and rollback/recovery for desktop builds. See each
//! submodule's doc comment for its slice of the design:
//!  - `manifest`: the signed update manifest.
//!  - `verify`: downloaded-artifact checksum/publisher-signature checks.
//!  - `policy`: persisted daemon update policy/state.
//!  - `manager`: check/download/verify/install orchestration, background
//!    scheduling, and interrupted-update recovery.
//!  - `install_macos` / `install_windows`: platform install handoff.
//!  - `install_linux`: install-source detection only — Linux has no
//!    self-update installer handoff yet (see that module's doc comment).

pub mod install_linux;
pub mod install_macos;
pub mod install_windows;
pub mod manager;
pub mod manifest;
pub mod policy;
pub mod verify;

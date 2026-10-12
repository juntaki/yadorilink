//! Signed update discovery for desktop builds (v1 ships manual updates:
//! the daemon checks and reports a new version, the user downloads and
//! installs it). See each submodule's doc comment:
//!  - `manifest`: the signed update manifest.
//!  - `policy`: persisted daemon update policy/state.
//!  - `manager`: check orchestration and background scheduling.
//!  - `install_source`: how this copy was installed (apt, Homebrew,
//!    Microsoft Store, WinGet, standalone).

pub mod install_source;
pub mod manager;
pub mod manifest;
pub mod policy;

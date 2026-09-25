//! Product-facing DTO layer for the desktop and CLI product shells.
//!
//! `FolderSummary`/`DeviceSummary` and their derivation from
//! `yadorilink-ipc-proto`'s `LinkStatus`/`StatusResponse` and the
//! coordination plane's per-group member listing live here. Every
//! derivation here is pure: the member listing is fetched by the caller
//! (see `device.rs`), so this crate depends on no interface crate. It
//! must never depend on `yadorilink-transport`, `yadorilink-peer-session`,
//! `yadorilink-sync-substrate`, or any other sync-engine crate, and must
//! never pull in a GUI toolchain (`eframe`/`tao`/`tray-icon`) — both are
//! enforced by this crate's `Cargo.toml` simply not listing them as
//! dependencies, not by any lint here.

pub mod conflict;
pub mod device;
pub mod folder;

pub use conflict::{conflict_detail, ConflictDetail, ConflictReason};
pub use device::{device_summaries, distinct_group_ids, peer_count, peer_counts, DeviceSummary};
pub use folder::{
    DurabilityStatus, FetchAvailability, FolderMode, FolderState, FolderSummary, FolderTransfer,
    LocalStorageState,
};

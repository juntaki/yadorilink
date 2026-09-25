//! The typed operations every front end drives. Each returns a typed result
//! or a [`crate::CoreError`] and prints nothing.

pub mod account;
pub mod auth;
pub mod daemon;
pub mod devices;
pub mod diagnostics;
pub mod files;
pub mod folders;
pub mod links;
pub mod shares;
pub mod storage;
pub mod transfers;
pub mod updates;

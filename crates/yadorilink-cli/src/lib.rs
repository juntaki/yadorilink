//! Library surface for `yadorilink-cli`, split out so integration tests (and
//! `main.rs`) share the same command implementations.

pub mod commands;
pub mod control_client;
pub mod device_config;
pub mod error;
#[cfg(feature = "http-coordination")]
pub mod google_auth;
pub mod grpc;
#[cfg(feature = "http-coordination")]
pub mod http_client;
pub mod token_store;

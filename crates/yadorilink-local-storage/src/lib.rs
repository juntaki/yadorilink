//! On-device content-addressed block store (see openspec `local-storage` spec).

mod ciphertext_store;
mod error;
pub mod free_space;
mod fs_backend;
mod traits;

pub use ciphertext_store::CiphertextBlockStore;
pub use error::StorageError;
pub use free_space::{FreeSpaceState, VolumeFreeSpace};
pub use fs_backend::FsBlockStore;
pub use traits::{BlockStore, ContentHash, GcReport, StorageUsage};

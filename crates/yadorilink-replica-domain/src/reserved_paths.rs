//! Names reserved at the top level of every sync root -- domain constants,
//! not local filesystem policy: they are excluded from the synced set by
//! definition, the same fact on every device and every peer regardless of
//! which component happens to be checking for them.

/// The per-link ignore-pattern file's name. Excluded from sync so it is
/// never indexed, never transmitted, and can never spawn a conflicted
/// copy.
pub const IGNORE_FILE_NAME: &str = ".yadorilinkignore";

/// The sync-root marker file's name, at the top level of a sync root.
/// Excluded from sync so it is never indexed, never transmitted, and can
/// never spawn a conflicted copy: each device mints its own token, so a
/// synced marker would overwrite a peer's identity with ours.
pub const ROOT_MARKER_FILE_NAME: &str = ".yadorilink-root";

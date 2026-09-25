//! The OS-native backend.
//!
//! One entry holds the whole document. The two `token_store.rs` modules this
//! replaces used three entries under `(yadorilink, access_token)` and
//! `(yadorilink, refresh_token)`; one entry is used here because the record's
//! fields are only meaningful together, and because a keyring offers no
//! transaction -- three writes can be interrupted after two, and the result is
//! a store that looks enrolled and cannot authenticate.
//!
//! This module used to carry the names of those two legacy entries as a
//! `RETIRED_KEYS` constant, and `clear` swept them on every logout. Both are
//! gone. The entries they named belonged to the `sessions` credential plane,
//! whose server-side tables `migrations/0021_drop_legacy_session_plane.sql`
//! drops: what a pre-cutover build left in an OS keyring now authenticates
//! against nothing, because there is no longer anything on the other end to
//! authenticate against.
//!
//! Keeping the sweep would have meant the running product permanently knowing
//! the key names of a plane it does not implement -- a list that reads as
//! documentation of where credentials used to live, and the natural place for
//! someone to put a third name. A cleanup that can only ever delete a dead
//! value is not a security measure; it is a legacy shape kept alive by a
//! comment explaining why it is still here.

use super::{StoreError, StoreResult};

/// Unchanged from the modules this replaces, so an OS keyring that already
/// holds YadoriLink entries keeps them under one service.
const SERVICE: &str = "yadorilink";
/// The single entry this build reads and writes, and the only entry name this
/// crate knows.
const CREDENTIALS_KEY: &str = "credentials";

/// The one entry this crate touches.
///
/// Takes no argument on purpose. It used to take the key, which is what made a
/// second entry name expressible at all -- `clear_retired` was three lines that
/// called this helper in a loop over a list of old names. With the parameter
/// gone, "this crate knows one keyring entry" is a fact about the code rather
/// than a claim in a comment: there is nowhere to put a second name.
fn entry() -> StoreResult<keyring::Entry> {
    keyring::Entry::new(SERVICE, CREDENTIALS_KEY).map_err(|e| StoreError::Keyring(e.to_string()))
}

pub(super) fn read() -> StoreResult<Option<String>> {
    match entry()?.get_password() {
        Ok(document) => Ok(Some(document)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(StoreError::Keyring(e.to_string())),
    }
}

pub(super) fn write(document: &str) -> StoreResult<()> {
    entry()?.set_password(document).map_err(|e| StoreError::Keyring(e.to_string()))
}

pub(super) fn clear() -> StoreResult<()> {
    match entry()?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(StoreError::Keyring(e.to_string())),
    }
}

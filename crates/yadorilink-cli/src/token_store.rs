//! OS-native credential store access for coordination-plane
//! session tokens. `yadorilink-daemon` has its own read-only copy of the
//! loader half, since it needs to authenticate its netmap stream using
//! whatever the CLI most recently logged in with.

const SERVICE: &str = "yadorilink";
const ACCESS_TOKEN_KEY: &str = "access_token";
const REFRESH_TOKEN_KEY: &str = "refresh_token";

pub fn save_tokens(access_token: &str, refresh_token: &str) -> keyring::Result<()> {
    keyring::Entry::new(SERVICE, ACCESS_TOKEN_KEY)?.set_password(access_token)?;
    keyring::Entry::new(SERVICE, REFRESH_TOKEN_KEY)?.set_password(refresh_token)?;
    Ok(())
}

pub fn load_access_token() -> Option<String> {
    keyring::Entry::new(SERVICE, ACCESS_TOKEN_KEY).ok()?.get_password().ok()
}

pub fn load_refresh_token() -> Option<String> {
    keyring::Entry::new(SERVICE, REFRESH_TOKEN_KEY).ok()?.get_password().ok()
}

pub fn clear_tokens() {
    // A failed delete leaves a stale token in the OS keyring after logout;
    // surface it (at least in the log) rather than swallowing it silently, so a
    // credential that outlives the logout is diagnosable instead of invisible.
    // `NoEntry` is not a failure here — clearing an already-absent token is the
    // intended end state — so it is filtered out to avoid noise on repeat
    // logouts.
    for key in [ACCESS_TOKEN_KEY, REFRESH_TOKEN_KEY] {
        match keyring::Entry::new(SERVICE, key) {
            Ok(entry) => {
                if let Err(e) = entry.delete_credential() {
                    if !matches!(e, keyring::Error::NoEntry) {
                        tracing::warn!(
                            credential = key,
                            error = %e,
                            "failed to delete a session credential from the OS keyring on logout; \
                             a stale token may remain"
                        );
                    }
                }
            }
            Err(e) => tracing::warn!(
                credential = key,
                error = %e,
                "failed to open the OS keyring entry to clear a session credential on logout; \
                 a stale token may remain"
            ),
        }
    }
}

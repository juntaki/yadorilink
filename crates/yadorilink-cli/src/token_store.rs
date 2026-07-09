//! OS-native credential store access (design.md D9) for coordination-plane
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
    if let Ok(entry) = keyring::Entry::new(SERVICE, ACCESS_TOKEN_KEY) {
        let _ = entry.delete_credential();
    }
    if let Ok(entry) = keyring::Entry::new(SERVICE, REFRESH_TOKEN_KEY) {
        let _ = entry.delete_credential();
    }
}

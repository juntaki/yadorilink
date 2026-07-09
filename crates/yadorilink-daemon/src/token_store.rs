//! OS-native credential store access (design.md D9) for the coordination
//! plane session token — written by `yadorilink login` (the CLI), read here
//! so the daemon can authenticate its own netmap stream without a
//! separate login step.

const SERVICE: &str = "yadorilink";
const ACCESS_TOKEN_KEY: &str = "access_token";

pub fn load_access_token() -> Option<String> {
    keyring::Entry::new(SERVICE, ACCESS_TOKEN_KEY).ok()?.get_password().ok()
}

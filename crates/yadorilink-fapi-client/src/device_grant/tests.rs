#![cfg(test)]

use super::*;

#[test]
fn an_absent_interval_is_the_specifications_five_seconds_rather_than_zero() {
    let authorization = DeviceAuthorization {
        device_code: "dc".into(),
        user_code: "AAAA-BBBB-CCCC".into(),
        verification_uri: "https://as.test/device".into(),
        verification_uri_complete: None,
        expires_in: 600,
        interval: None,
    };
    assert_eq!(authorization.poll_interval(), Duration::from_secs(5));
}

/// A zero from the server would otherwise become a hot loop against the
/// token endpoint, which is the one thing `slow_down` exists to stop.
#[test]
fn a_zero_interval_is_clamped_rather_than_spun_on() {
    let authorization = DeviceAuthorization {
        device_code: "dc".into(),
        user_code: "AAAA-BBBB-CCCC".into(),
        verification_uri: "https://as.test/device".into(),
        verification_uri_complete: None,
        expires_in: 600,
        interval: Some(0),
    };
    assert_eq!(authorization.poll_interval(), Duration::from_secs(1));
}

/// The combined URI carries the user code, and the platform logs request
/// URLs. What is printed to the user must not be the one that ends up in
/// an access log.
#[test]
fn the_printed_instructions_never_carry_the_completed_verification_uri() {
    let authorization = DeviceAuthorization {
        device_code: "dc".into(),
        user_code: "AAAA-BBBB-CCCC".into(),
        verification_uri: "https://as.test/device".into(),
        verification_uri_complete: Some("https://as.test/device?user_code=AAAA-BBBB-CCCC".into()),
        expires_in: 600,
        interval: Some(5),
    };
    let printed = authorization.instructions();
    assert!(printed.contains("https://as.test/device"));
    assert!(printed.contains("AAAA-BBBB-CCCC"));
    assert!(
        !printed.contains("user_code="),
        "the code must not be printed inside a URL a user will paste into an address bar"
    );
}

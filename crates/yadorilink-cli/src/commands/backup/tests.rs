#![cfg(test)]

use super::*;

#[test]
fn present_labels_are_stable() {
    assert_eq!(present(true), "present");
    assert_eq!(present(false), "missing");
}

/// The recovery guidance describes the Google-login/new-device model.
#[test]
fn recovery_guidance_describes_google_login_new_device_model() {
    let guidance = recovery_guidance();
    let lower = guidance.to_lowercase();
    assert!(guidance.contains("Google"));
    assert!(lower.contains("new device"));
    assert!(lower.contains("register"));
}

use std::time::Duration;

use super::*;
use crate::error::DaemonUnavailableReason;

#[test]
fn sign_in_steps_pass_through_and_the_client_layers_signed_in_is_left_to_the_session() {
    use ops::auth::LoginEvent as Step;
    assert_eq!(login_event(Step::Enrolling), Some(LoginEvent::Enrolling));
    assert_eq!(
        login_event(Step::OpenBrowser {
            url: "https://a".into(),
            purpose: ops::auth::BrowserPurpose::SignIn
        }),
        Some(LoginEvent::OpenBrowser { url: "https://a".into(), purpose: BrowserPurpose::SignIn })
    );
    assert_eq!(
        login_event(Step::WaitingForApproval { expires_in: Duration::from_secs(9) }),
        Some(LoginEvent::WaitingForApproval { expires_in: Duration::from_secs(9) })
    );
    assert_eq!(
        login_event(Step::ShowDeviceCode { verification_uri: "u".into(), user_code: "c".into() }),
        Some(LoginEvent::ShowDeviceCode { verification_uri: "u".into(), user_code: "c".into() })
    );
    assert_eq!(
        login_event(Step::WaitingForAuthorization),
        Some(LoginEvent::WaitingForAuthorization)
    );
    assert_eq!(login_event(Step::SignedIn { client_id: "x".into() }), None);
}

#[test]
fn refusals_name_the_argument_and_offer_force_only_to_an_unforced_call() {
    assert_eq!(
        about("group_id")(CoreError::InvalidInput("not linked".into())),
        DesktopError::InvalidInput { message: "not linked".into(), field: Some("group_id".into()) }
    );
    assert!(matches!(
        about("group_id")(CoreError::DaemonNotRunning),
        DesktopError::DaemonUnavailable { reason: DaemonUnavailableReason::NotRunning, .. }
    ));
    let blocked = || CoreError::DurabilityBlocked { message: "m".into(), group_ids: vec![] };
    assert!(matches!(
        offering_force(false)(blocked()),
        DesktopError::DurabilityBlocked { can_force: true, .. }
    ));
    assert!(matches!(
        offering_force(true)(blocked()),
        DesktopError::DurabilityBlocked { can_force: false, .. }
    ));
}

#[test]
fn a_path_that_does_not_resolve_is_invalid_input_about_the_path() {
    assert!(matches!(
        existing_directory("/no/such/place/for/yadorilink"),
        Err(DesktopError::InvalidInput { field: Some(f), .. }) if f == "local_path"
    ));
}

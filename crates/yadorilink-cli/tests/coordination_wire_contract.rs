//! Round-trips this workspace's real coordination-plane client code against a
//! real, locally running coordination service.
//!
//! Every other test of these code paths asserts against something a human
//! wrote: either the Rust request struct is built and inspected directly
//! (never becoming JSON at all), or it is sent to a mock HTTP server whose
//! canned response is itself a hand-written guess at what the service sends.
//! Both sides of that arrangement can drift together without any test going
//! red — a request struct that serializes `refresh_token` where the service
//! reads `refreshToken` still passes a mock that was written to expect
//! `refresh_token`, and the service keeps answering `204` either way.
//!
//! These tests remove the guess. They drive the same public functions the CLI
//! and the desktop app call, pointed at a real running coordination service,
//! and assert the round trip actually works. A field name that does not match
//! is a failure here.
//!
//! The case worth being precise about is co-drift, not a lone edit. Changing
//! a request struct by itself usually does trip whichever mock-based test
//! pins the old key — and then the author updates that test to agree with the
//! struct, because it looks like the test is the thing that is out of date.
//! Two hand-written descriptions of the same JSON now agree with each other
//! and disagree with the service, every existing gate is green again, and
//! only a real round trip can still tell. That is how the field-name bugs
//! this workspace has shipped actually got in; see
//! `signing_out_revokes_the_session_on_the_service` for the worked example.
//!
//! They are inert unless `YADORILINK_WIRE_CONTRACT_ADDR` names a running
//! service, so an ordinary `cargo test` run compiles them and skips them.
//! Each one announces itself with [`RAN_MARKER`] the moment it has an
//! address, which is what makes a skipped run distinguishable from a real
//! one — libtest's own summary is not (see that constant).
//!
//! ## Why this file lives in `yadorilink-cli`
//!
//! It covers three client surfaces at once:
//!
//!   * the CLI's own commands (`commands::{account, auth, device, share}`,
//!     `google_auth`),
//!   * the desktop app's account and sign-in screens, which issue no HTTP of
//!     their own — `yadorilink-desktop-app`'s `account.rs` and
//!     `google_login.rs` delegate every coordination request to
//!     `yadorilink_cli::commands::account` and
//!     `yadorilink_cli::google_auth`, so the wire types under test here are
//!     exactly the ones those screens depend on (and the desktop crate does
//!     not build on Linux, where this runs),
//!   * `yadorilink_daemon::coordination_client`, whose enrollment and share
//!     lookup calls need a real session and a real registered device to
//!     exercise, both of which the CLI's own login and registration paths
//!     produce here.
//!
//! `yadorilink-cli` is the one crate that depends on all of that, so keeping
//! the file here lets every request in it be built by production code rather
//! than by a bootstrap that re-guesses the JSON a third time.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Once, OnceLock};

use keyring::credential::{Credential, CredentialApi, CredentialBuilderApi, CredentialPersistence};
use oauth2::PkceCodeVerifier;
use tokio::sync::Mutex;

use yadorilink_cli::commands::{account, auth, device, share};
use yadorilink_cli::error::CliError;
use yadorilink_cli::{google_auth, http_client, token_store};
use yadorilink_daemon::coordination_client::{ActivateOutcome, EnrollmentPrepareOutcome};

/// Serializes the whole file. Every test signs in, which replaces the
/// process-wide credential store's session, and several point
/// `YADORILINK_CONFIG_DIR` at their own directory — both are process
/// globals. The contract script also passes `--test-threads=1`; this lock
/// keeps a hand-run `cargo test` of this file correct too.
static WORLD: Mutex<()> = Mutex::const_new(());

static KEYRING: Once = Once::new();

/// Distinguishes ids minted by this run from each other. Enrollment
/// operation ids must be unique per attempt, and reusing one across tests
/// would exercise the service's replay handling rather than the wire shape.
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn unique(prefix: &str) -> String {
    let n = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_nanos();
    format!("{prefix}-{nanos}-{n}")
}

/// The coordination service to talk to, or `None` when this file is being
/// compiled by an ordinary test run with no service around.
fn worker_addr() -> Option<String> {
    match std::env::var("YADORILINK_WIRE_CONTRACT_ADDR") {
        Ok(addr) if !addr.is_empty() => Some(addr),
        _ => None,
    }
}

/// Prefix of the line every test prints once it has a service address in
/// hand, and before it does any work.
///
/// It exists because libtest cannot distinguish a test that ran from one
/// that skipped itself: the skip below is a plain `return`, which libtest
/// counts as a pass, so `test result: ok. 7 passed` is the identical line
/// whether all seven round-tripped against a real service or all seven
/// found no address and did nothing. Counting these markers instead
/// measures executions, which is the thing worth asserting.
const RAN_MARKER: &str = "wire-contract: ran";

macro_rules! worker_addr_or_skip {
    ($test:literal) => {
        match worker_addr() {
            Some(addr) => {
                // The marker above only proves `YADORILINK_WIRE_CONTRACT_ADDR`
                // was set -- the real request traffic is driven by
                // `coordination_http_addr`/`coordination_addr`, which read
                // DIFFERENT env vars with their own hardcoded loopback
                // fallbacks (http_client.rs). The launching script sets all
                // three vars to the same value, but nothing enforced that
                // agreement: on a persistent runner, a stray leftover service
                // already bound to a fallback port would let every test print
                // this marker while silently talking to the wrong server.
                // Assert the vars the client code ACTUALLY uses resolved to
                // this same address before trusting the marker.
                assert_eq!(
                    yadorilink_cli::http_client::coordination_http_addr(),
                    addr,
                    "YADORILINK_COORDINATION_HTTP_ADDR must resolve to the same address as \
                     YADORILINK_WIRE_CONTRACT_ADDR, or every request below silently targets \
                     the wrong service"
                );
                assert_eq!(
                    yadorilink_cli::http_client::coordination_addr(),
                    addr,
                    "YADORILINK_COORDINATION_ADDR must resolve to the same address as \
                     YADORILINK_WIRE_CONTRACT_ADDR, or every request below silently targets \
                     the wrong service"
                );
                // Emitted before any request, so a marker means "this test
                // reached the service", never "this test finished". The
                // leading newline closes libtest's own unterminated
                // `test <name> ... ` prefix, which under `--nocapture` would
                // otherwise share this line and hide it from a line-anchored
                // search.
                println!("\n{} {}", RAN_MARKER, $test);
                addr
            }
            None => return,
        }
    };
}

/// Secrets held in memory, keyed the way a real keystore keys a credential:
/// by (service, user).
type CredentialStore = std::sync::Mutex<HashMap<(String, String), Vec<u8>>>;

/// Backing store for [`InProcessCredential`].
fn credential_store() -> &'static CredentialStore {
    static STORE: OnceLock<CredentialStore> = OnceLock::new();
    STORE.get_or_init(Default::default)
}

/// A credential that lives in this process and nowhere else.
///
/// `keyring`'s own `mock` store cannot be used for this: it keeps the secret
/// inside the `Entry` object (`CredentialPersistence::EntryOnly`), and
/// `token_store` opens a fresh `Entry` for every read and write, so a token
/// written through one would never be readable through the next.
#[derive(Debug)]
struct InProcessCredential {
    service: String,
    user: String,
}

impl InProcessCredential {
    fn key(&self) -> (String, String) {
        (self.service.clone(), self.user.clone())
    }
}

impl CredentialApi for InProcessCredential {
    fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
        credential_store()
            .lock()
            .expect("credential store lock")
            .insert(self.key(), secret.to_vec());
        Ok(())
    }

    fn get_secret(&self) -> keyring::Result<Vec<u8>> {
        credential_store()
            .lock()
            .expect("credential store lock")
            .get(&self.key())
            .cloned()
            .ok_or(keyring::Error::NoEntry)
    }

    fn delete_credential(&self) -> keyring::Result<()> {
        match credential_store().lock().expect("credential store lock").remove(&self.key()) {
            Some(_) => Ok(()),
            None => Err(keyring::Error::NoEntry),
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Debug)]
struct InProcessCredentialBuilder;

impl CredentialBuilderApi for InProcessCredentialBuilder {
    fn build(
        &self,
        _target: Option<&str>,
        service: &str,
        user: &str,
    ) -> keyring::Result<Box<Credential>> {
        Ok(Box::new(InProcessCredential { service: service.to_string(), user: user.to_string() }))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::ProcessOnly
    }
}

/// Points `token_store` at the store above for the lifetime of this test
/// binary.
///
/// This is not a shortcut around the code under test: `token_store`,
/// `http_client::require_access_token` and every command that calls them run
/// exactly as shipped, credential lookups included. It only replaces the
/// backing store the `keyring` crate itself would select, which keeps a
/// contract run from overwriting the developer's real login session and
/// works on a CI host whose kernel keyring a container cannot reach.
fn use_in_process_credential_store() {
    KEYRING.call_once(|| {
        keyring::set_default_credential_builder(Box::new(InProcessCredentialBuilder));
    });
}

/// Points `device.json` and the generated device signing key at a fresh
/// directory. The returned handle must stay alive for as long as the test
/// needs the registered device's files.
fn fresh_config_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("a temporary config directory");
    std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    dir
}

/// Signs a fresh account in through the real desktop loopback-redirect
/// exchange (`POST /auth/google/desktop/exchange`) and returns its access
/// token. This is the desktop app's own sign-in path: `google_login.rs`
/// collects the authorization code on its loopback listener and hands it to
/// this exact function.
///
/// The local service brokers the exchange against a stand-in for Google, so
/// the code and PKCE verifier below are accepted as any real pair would be;
/// everything from the request body onwards is production code.
async fn sign_in_a_fresh_account() -> String {
    use_in_process_credential_store();
    let code = unique("wire-contract-authorization-code");
    let verifier = PkceCodeVerifier::new(unique(
        "wire-contract-pkce-verifier-that-is-long-enough-to-be-realistic",
    ));
    google_auth::exchange_authorization_code_for_session(
        code,
        verifier,
        "http://127.0.0.1:37411/callback",
    )
    .await
    .expect("the desktop authorization-code exchange should return a session");
    token_store::load_access_token()
        .expect("a completed exchange should have stored an access token")
}

/// Registers a device for the signed-in account and returns its id.
async fn register_a_device(label: &str) -> (String, tempfile::TempDir) {
    let config_dir = fresh_config_dir();
    let device_id =
        device::register_device(unique(label)).await.expect("device registration should succeed");
    assert!(!device_id.is_empty(), "the service should assign a device id");
    (device_id, config_dir)
}

/// Creates an active folder group through the daemon's own two-phase
/// enrollment calls and returns `(group_id, group_name)`.
async fn create_an_active_group(
    addr: &str,
    access_token: &str,
    device_id: &str,
) -> (String, String) {
    let operation_id = unique("create-operation");
    let name = unique("wire-contract-group");
    let prepared = yadorilink_daemon::coordination_client::prepare_create(
        addr,
        access_token,
        &operation_id,
        &name,
        device_id,
    )
    .await;
    let group_id = match prepared {
        EnrollmentPrepareOutcome::Prepared { group_id } => group_id,
        other => panic!("create prepare should return a group id, got {other:?}"),
    };
    let activated = yadorilink_daemon::coordination_client::activate_create(
        addr,
        access_token,
        &group_id,
        &operation_id,
    )
    .await;
    assert!(
        matches!(activated, ActivateOutcome::Success | ActivateOutcome::AlreadyActive),
        "create activate should confirm the group, got {activated:?}"
    );
    (group_id, name)
}

/// The desktop app's sign-in screen and its account screen, end to end.
///
/// `yadorilink-desktop-app`'s `google_login.rs` and `account.rs` had no
/// coverage of any kind against the service before this: every request they
/// make is built by the `yadorilink_cli` functions exercised here, and
/// nothing checked those request or response shapes against the service that
/// has to read and produce them.
#[tokio::test]
async fn desktop_sign_in_and_account_lifecycle_round_trip() {
    let _addr = worker_addr_or_skip!("desktop_sign_in_and_account_lifecycle_round_trip");
    let _world = WORLD.lock().await;

    sign_in_a_fresh_account().await;

    let status = account::deletion_status()
        .await
        .expect("reading the account deletion status should succeed");
    assert_eq!(status.state, "active", "a fresh account should start active");

    let requested = account::request_deletion().await.expect("requesting deletion should succeed");
    assert!(
        !requested.confirmation_token.is_empty(),
        "the service should return a confirmation token to quote back"
    );

    let confirmed = account::confirm_deletion(requested.confirmation_token)
        .await
        .expect("confirming deletion should succeed");
    assert_eq!(confirmed.state, "grace", "confirming should open the grace window");
    assert!(
        confirmed.grace_expires_at_unix.is_some(),
        "the grace state should carry its expiry, so the app can count it down"
    );
    assert!(
        confirmed.remaining_secs.is_some(),
        "the grace state should carry the seconds remaining"
    );

    let cancelled = account::cancel_deletion().await.expect("cancelling deletion should succeed");
    assert_eq!(cancelled.state, "active", "cancelling should restore the account");

    let export = account::export_account().await.expect("exporting the account should succeed");
    assert!(export.is_object(), "the export should be a JSON document, got {export}");
}

/// `yadorilink login` on a machine with no browser.
#[tokio::test]
async fn device_grant_sign_in_round_trips() {
    let _addr = worker_addr_or_skip!("device_grant_sign_in_round_trips");
    let _world = WORLD.lock().await;

    use_in_process_credential_store();
    token_store::clear_tokens();

    google_auth::login_via_device_grant()
        .await
        .expect("the brokered device-grant sign-in should complete");

    assert!(
        token_store::load_access_token().is_some(),
        "a completed device sign-in should have stored an access token"
    );
    account::deletion_status()
        .await
        .expect("the session a device sign-in produced should be usable");
}

/// Signing out has to revoke the session on the service, not merely forget
/// it locally. It once did not: the request carried `refresh_token` where
/// the route reads `refreshToken`, so the service hashed nothing, matched no
/// session, and still answered `204` — the CLI printed "Logged out." while
/// the session stayed live. Nothing caught it, because the mock that stood
/// in for the service had been written to expect the same wrong key.
///
/// This asserts the outcome that actually matters: after signing out, the
/// access token that was working a moment ago is refused.
///
/// What it adds over the existing coverage of that field is worth stating
/// exactly, because the obvious experiment measures the wrong thing.
/// Reverting `LogoutRequest`'s `#[serde(rename_all = "camelCase")]` on its
/// own is caught already: two unit tests in `commands::auth` pin the
/// camelCase body and go red at once. Reproduce instead what an author who
/// trusted those tests would do — revert the attribute *and* update both
/// tests to expect the reverted key — and
/// `cargo test -p yadorilink-cli --lib` passes clean, as does
/// `cargo clippy -p yadorilink-cli --all-targets -- -D warnings`, while this
/// test fails with the panic below. That is the shape the original bug had,
/// and this is the only check that sees through it, because it asks the
/// service rather than a second copy of the same assumption.
#[tokio::test]
async fn signing_out_revokes_the_session_on_the_service() {
    let _addr = worker_addr_or_skip!("signing_out_revokes_the_session_on_the_service");
    let _world = WORLD.lock().await;

    let access_token = sign_in_a_fresh_account().await;
    let refresh_token =
        token_store::load_refresh_token().expect("signing in should have stored a refresh token");
    account::deletion_status().await.expect("the session should work before signing out");

    auth::logout().await.expect("signing out should succeed");

    // `logout` clears the local store on the way out, which would otherwise
    // make the next call fail as "not signed in" and prove nothing about the
    // service. Putting the same token back asks the only question worth
    // asking: does the service still honour it?
    token_store::save_tokens(&access_token, &refresh_token)
        .expect("the in-process credential store should accept a write");

    match account::deletion_status().await {
        Err(CliError::AuthFailed(_)) => {}
        Err(other) => panic!("expected the revoked session to be refused, got {other:?}"),
        Ok(status) => panic!(
            "the service still honoured a signed-out session (state {}); signing out did not \
             revoke it",
            status.state
        ),
    }
}

/// Device registration and listing.
#[tokio::test]
async fn device_registration_and_listing_round_trip() {
    let _addr = worker_addr_or_skip!("device_registration_and_listing_round_trip");
    let _world = WORLD.lock().await;

    sign_in_a_fresh_account().await;
    let (_device_id, _config_dir) = register_a_device("wire-contract-device").await;

    device::list().await.expect("listing devices should succeed");
}

/// Folder-group enrollment plus every share listing the CLI reads.
#[tokio::test]
async fn folder_group_enrollment_and_share_listings_round_trip() {
    let addr = worker_addr_or_skip!("folder_group_enrollment_and_share_listings_round_trip");
    let _world = WORLD.lock().await;

    let access_token = sign_in_a_fresh_account().await;
    let (device_id, _config_dir) = register_a_device("wire-contract-owner-device").await;
    let (group_id, group_name) = create_an_active_group(&addr, &access_token, &device_id).await;

    let groups = share::list_groups().await.expect("listing folder groups should succeed");
    assert!(
        groups.iter().any(|group| group.group_id == group_id && group.name == group_name),
        "the created group should appear in the owner's listing"
    );

    let resolved = share::resolve_group_id(&access_token, &group_name)
        .await
        .expect("resolving a group by name should succeed");
    assert_eq!(resolved, group_id, "name resolution should find the same group");

    share::list_shares().await.expect("listing shares should succeed");
    share::list_joinable().await.expect("listing joinable groups should succeed");
    share::list_pending_approvals().await.expect("listing pending approvals should succeed");
    share::list_invites().await.expect("listing pending invites should succeed");
    share::members(group_name.clone()).await.expect("listing members should succeed");

    // The daemon reads the same `/shares` listing through its own types. A
    // renamed key there fails deserialization rather than merely returning
    // nothing, so both calls below are real assertions about the response.
    let state = yadorilink_daemon::coordination_client::fetch_edge_state(
        &addr,
        &access_token,
        &group_id,
        &device_id,
    )
    .await
    .expect("reading the edge state should succeed");
    assert_eq!(
        state.as_deref(),
        Some("active"),
        "the creating device's own edge should be reported active"
    );

    yadorilink_daemon::coordination_client::resolve_edge(&addr, &access_token, "no-such-edge")
        .await
        .expect("resolving an unknown edge should still parse the listing");
}

/// Joining a second device to an existing group, and granting it access.
#[tokio::test]
async fn joining_and_granting_a_second_device_round_trips() {
    let addr = worker_addr_or_skip!("joining_and_granting_a_second_device_round_trips");
    let _world = WORLD.lock().await;

    let access_token = sign_in_a_fresh_account().await;
    let (owner_device_id, _owner_config) = register_a_device("wire-contract-owner-device").await;
    let (group_id, group_name) =
        create_an_active_group(&addr, &access_token, &owner_device_id).await;

    let (second_device_id, _second_config) = register_a_device("wire-contract-second-device").await;

    share::grant(group_name.clone(), second_device_id.clone(), Some("editor".to_string()))
        .await
        .expect("granting a second device access should succeed");

    let join_operation = unique("join-operation");
    let prepared = yadorilink_daemon::coordination_client::prepare_join(
        &addr,
        &access_token,
        &join_operation,
        &group_id,
        &second_device_id,
        "on-demand",
    )
    .await;
    assert!(
        matches!(prepared, EnrollmentPrepareOutcome::Prepared { .. }),
        "join prepare should be accepted, got {prepared:?}"
    );

    let activated = yadorilink_daemon::coordination_client::activate_join(
        &addr,
        &access_token,
        &group_id,
        &join_operation,
        &second_device_id,
    )
    .await;
    assert!(
        matches!(activated, ActivateOutcome::Success | ActivateOutcome::AlreadyActive),
        "join activate should confirm the membership, got {activated:?}"
    );

    let state = yadorilink_daemon::coordination_client::fetch_edge_state(
        &addr,
        &access_token,
        &group_id,
        &second_device_id,
    )
    .await
    .expect("reading the joined device's edge state should succeed");
    assert_eq!(
        state.as_deref(),
        Some("active"),
        "the joined device's edge should be reported active"
    );
}

/// Accepting an invite issued by another account.
#[tokio::test]
async fn cross_account_invite_accept_round_trips() {
    let addr = worker_addr_or_skip!("cross_account_invite_accept_round_trips");
    let _world = WORLD.lock().await;

    let owner_token = sign_in_a_fresh_account().await;
    let (owner_device_id, _owner_config) = register_a_device("wire-contract-owner-device").await;
    let (group_id, _group_name) =
        create_an_active_group(&addr, &owner_token, &owner_device_id).await;

    // Minting is setup, not the shape under test: the CLI mints through the
    // local daemon rather than over HTTP, so there is no shipped client
    // function here to drive. It still goes out through the CLI's own HTTP
    // client so a broken route surfaces as a failure rather than as a
    // hand-rolled request that happens to work.
    let minted: serde_json::Value = http_client::post_json(
        &format!("/shares/groups/{group_id}/invites"),
        &serde_json::json!({ "mintingDeviceId": owner_device_id, "role": "editor" }),
        Some(&owner_token),
    )
    .await
    .expect("minting a cross-account invite should succeed");
    let code =
        minted["code"].as_str().expect("a minted invite should carry its one-use code").to_string();

    let recipient_token = sign_in_a_fresh_account().await;
    let (recipient_device_id, _recipient_config) =
        register_a_device("wire-contract-recipient-device").await;

    let operation_id = unique("invite-accept-operation");
    let prepared = yadorilink_daemon::coordination_client::prepare_invite_accept(
        &addr,
        &recipient_token,
        &operation_id,
        &code,
        &recipient_device_id,
        "on-demand",
    )
    .await;
    let accepted_group_id = match prepared {
        EnrollmentPrepareOutcome::Prepared { group_id } => group_id,
        other => panic!("invite-accept prepare should name the group, got {other:?}"),
    };
    assert_eq!(
        accepted_group_id, group_id,
        "the accepted invite should name the group it was minted for"
    );

    let activated = yadorilink_daemon::coordination_client::activate_invite_accept(
        &addr,
        &recipient_token,
        &accepted_group_id,
        &operation_id,
        &recipient_device_id,
    )
    .await;
    assert!(
        matches!(activated, ActivateOutcome::Success | ActivateOutcome::AlreadyActive),
        "invite-accept activate should confirm the membership, got {activated:?}"
    );
}

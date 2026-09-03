//! P0-A: exercises `ProductionRelayGrantSource` -- and therefore
//! `coordination_client::request_relay_grant` -- against a REAL HTTP round
//! trip, not `FakeGrantSource`'s synchronous in-process bypass every other
//! relay-scenario test in this crate uses (`tests/support/topology.rs`).
//! `tests/support/fake_coordination.rs`'s `serve_relay_grant` is the one
//! route that fake actually answers over the wire rather than a blanket
//! `204`, specifically so this gap has coverage: the daemon's own HTTP
//! client (`Body`/`Resp` field names, camelCase, reconstructing the full
//! grant from what the caller asked for plus what the plane decided) had
//! never been exercised against anything before this file existed.

mod support;

use support::fake_coordination::FakeCoordination;
use yadorilink_daemon::relay_carrier::{ProductionRelayGrantSource, RelayGrantSource};
use yadorilink_daemon::relay_grant::{verify_relay_grant, RelayGrantError};

#[tokio::test]
async fn production_relay_grant_source_obtains_a_grant_that_verifies() {
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "http-relay-group";
    fake.register_device("a", [1; 32], [1; 32], "127.0.0.1:1".to_string(), &[group_id]);
    fake.register_device("b", [2; 32], [2; 32], "127.0.0.1:2".to_string(), &[group_id]);
    fake.register_device("c", [3; 32], [3; 32], "127.0.0.1:3".to_string(), &[group_id]);
    fake.set_relay_capable("b", true);

    let source =
        ProductionRelayGrantSource::new(fake.addr(), "test-token".to_string(), "a".to_string());
    let grant = source
        .request_relay_grant("c", "b", group_id)
        .await
        .expect("a real HTTP round trip should have issued a grant");

    assert_eq!(grant.source_device_id, "a");
    assert_eq!(grant.relay_device_id, "b");
    assert_eq!(grant.destination_device_id, "c");
    assert_eq!(grant.group_id, group_id);
    assert_eq!(grant.version, 1);
    assert!(grant.max_session_bytes.is_none());

    let service_key = fake.policy_signing_key().expect("enable_signed_policy installed one");
    let key_bytes = service_key.verifying_key().to_bytes();
    let now = grant.not_before_unix + 30;
    verify_relay_grant(&grant, &key_bytes, now, "b")
        .expect("a grant obtained over real HTTP must verify against the fake's own service key");
}

#[tokio::test]
async fn refuses_when_the_relay_device_has_not_declared_relay_capability() {
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "http-relay-noncapable-group";
    fake.register_device("a", [1; 32], [1; 32], "127.0.0.1:1".to_string(), &[group_id]);
    fake.register_device("b", [2; 32], [2; 32], "127.0.0.1:2".to_string(), &[group_id]);
    fake.register_device("c", [3; 32], [3; 32], "127.0.0.1:3".to_string(), &[group_id]);
    // Deliberately never marked relay-capable.

    let source =
        ProductionRelayGrantSource::new(fake.addr(), "test-token".to_string(), "a".to_string());
    assert!(source.request_relay_grant("c", "b", group_id).await.is_none());
}

#[tokio::test]
async fn refuses_when_the_destination_is_not_a_member_of_the_group() {
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "http-relay-nonmember-group";
    let other_group = "http-relay-other-group";
    fake.register_device("a", [1; 32], [1; 32], "127.0.0.1:1".to_string(), &[group_id]);
    fake.register_device("b", [2; 32], [2; 32], "127.0.0.1:2".to_string(), &[group_id]);
    // c belongs only to a different group -- never a member of `group_id`.
    fake.register_device("c", [3; 32], [3; 32], "127.0.0.1:3".to_string(), &[other_group]);
    fake.set_relay_capable("b", true);

    let source =
        ProductionRelayGrantSource::new(fake.addr(), "test-token".to_string(), "a".to_string());
    assert!(source.request_relay_grant("c", "b", group_id).await.is_none());
}

#[tokio::test]
async fn refuses_source_relay_and_destination_all_naming_the_same_device() {
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "http-relay-selfsame-group";
    fake.register_device("a", [1; 32], [1; 32], "127.0.0.1:1".to_string(), &[group_id]);

    let source =
        ProductionRelayGrantSource::new(fake.addr(), "test-token".to_string(), "a".to_string());
    assert!(source.request_relay_grant("a", "a", group_id).await.is_none());
}

/// P0-A explicit requirement: a grant's `not_before_unix` carries a
/// clock-skew allowance backward from issuance, so a relay (B) device whose
/// own clock reads meaningfully behind the issuer's still accepts an
/// otherwise-fresh grant immediately -- but the allowance is bounded, not
/// an invitation to ignore the validity window entirely.
#[tokio::test]
async fn tolerates_a_relay_clock_running_behind_within_the_skew_allowance_but_not_beyond_it() {
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "http-relay-skew-group";
    fake.register_device("a", [1; 32], [1; 32], "127.0.0.1:1".to_string(), &[group_id]);
    fake.register_device("b", [2; 32], [2; 32], "127.0.0.1:2".to_string(), &[group_id]);
    fake.register_device("c", [3; 32], [3; 32], "127.0.0.1:3".to_string(), &[group_id]);
    fake.set_relay_capable("b", true);

    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        as i64;

    let source =
        ProductionRelayGrantSource::new(fake.addr(), "test-token".to_string(), "a".to_string());
    let grant = source.request_relay_grant("c", "b", group_id).await.expect("grant issued");

    // The issuer stamped not_before_unix comfortably at or before "now".
    assert!(grant.not_before_unix <= now);
    let service_key = fake.policy_signing_key().unwrap();
    let key_bytes = service_key.verifying_key().to_bytes();

    // A relay clock running 25s behind the issuer's still accepts the
    // grant right away -- the whole point of the allowance.
    verify_relay_grant(&grant, &key_bytes, now - 25, "b")
        .expect("a 25s clock lag is within the issuer's clock-skew allowance");

    // But the allowance is bounded: a clock lagging past the grant's own
    // not_before_unix still correctly rejects as not-yet-valid.
    let result = verify_relay_grant(&grant, &key_bytes, grant.not_before_unix - 1, "b");
    assert!(matches!(result, Err(RelayGrantError::NotYetValid { .. })));
}

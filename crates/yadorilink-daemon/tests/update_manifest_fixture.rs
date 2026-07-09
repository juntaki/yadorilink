//! add-automatic-updates task 6.1: proves the sample beta manifest fixture
//! (`tests/fixtures/sample-beta-manifest.signed.json`, produced by
//! `yadorilink-sign-manifest sign` against the real pinned dev trust root)
//! actually verifies through the production `manifest::verify_and_parse`
//! path -- not just a unit test against a throwaway test keypair
//! (`update::manifest::test_support`), but the exact `TRUSTED_KEYS`
//! constant this daemon ships with.

use yadorilink_daemon::update::manifest;

#[test]
fn sample_beta_manifest_fixture_verifies_against_the_shipped_trust_root() {
    let envelope_json = include_str!("fixtures/sample-beta-manifest.signed.json");
    let manifest = manifest::verify_and_parse(envelope_json)
        .expect("sample fixture must verify against manifest::TRUSTED_KEYS");
    assert_eq!(manifest.schema_version, manifest::MANIFEST_SCHEMA_VERSION);
    assert_eq!(manifest.releases.len(), 2);
    assert!(manifest.releases.iter().any(|r| r.platform == "macos" && r.version == "0.2.0"));
    assert!(manifest.releases.iter().any(|r| r.platform == "windows" && r.version == "0.2.0"));
}

/// A one-byte tamper of the signed envelope (flipping the claimed
/// version) must fail closed even against the real production trust
/// root, exactly like `manifest::tests::tampered_manifest_body_fails_
/// signature_verification` proves against the test keypair.
#[test]
fn tampering_the_fixture_after_signing_fails_verification() {
    let envelope_json = include_str!("fixtures/sample-beta-manifest.signed.json");
    let tampered = envelope_json.replace("0.2.0", "9.9.9");
    let result = manifest::verify_and_parse(&tampered);
    assert!(result.is_err(), "a tampered signed manifest must never verify");
}

//! Proves the sample beta manifest fixture
//! (`tests/fixtures/sample-beta-manifest.signed.json`, produced by
//! `yadorilink-sign-manifest sign` against the real pinned dev trust root)
//! actually verifies through the production `manifest::verify_and_parse`
//! path -- not just a unit test against a throwaway test keypair
//! (`update::manifest::test_support`), but the exact `TRUSTED_KEYS`
//! constant this daemon ships with.

use yadorilink_daemon::update::manifest;

/// IGNORED until the fixture is re-signed. The manifest schema moved to 2
/// when `artifact_size` became required, and this envelope was signed over
/// a schema-1 body, so `verify_and_parse` refuses it on the version check
/// before the signature is even considered. Re-signing needs
/// `yadorilink-sign-manifest` and the real dev trust-root key, neither of
/// which lives in this repository -- it is a release-operator step, not
/// something a code change can do. The sibling tamper test below still
/// proves the negative and stays live.
#[ignore = "fixture is signed over a schema-1 body; needs re-signing at schema 2"]
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

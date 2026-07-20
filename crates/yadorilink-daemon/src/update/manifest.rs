//! The signed update manifest — data structures, strict parsing,
//! semantic-version comparison/applicability, and Ed25519 signature
//! verification against a pinned trust root.
//!
//! The manifest signature protects metadata (rollout, minimum supported
//! version, artifact URL/checksum) end-to-end over HTTPS *and* against a
//! compromised hosting/CDN — verified here, before anything is
//! downloaded. `verify::verify_artifact` (sibling module) separately
//! verifies the downloaded artifact's checksum and platform publisher
//! signature; neither check substitutes for the other.
//!
//! Every fallible step in this module is fail-closed by construction: a
//! parse error, an unknown signing key, an invalid signature, or an
//! unsupported schema version returns a distinct `ManifestError` variant
//! and never produces an `UpdateManifest` a caller could act on. Nothing
//! here downloads or installs anything — this module only ever decides
//! *whether* an update is applicable.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Bumped whenever the manifest schema's field set changes in a way that
/// could change how a daemon interprets it. A manifest declaring any
/// other value is rejected outright (rejecting unsupported
/// schema versions) rather than best-effort parsed, since a future
/// schema change might repurpose a field this version would otherwise
/// silently misinterpret.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

/// One pinned release-signing public key, identified by a stable
/// `key_id` so keys can be rotated without breaking older clients that
/// still only trust the previous one.
pub struct TrustedKey {
    pub key_id: &'static str,
    pub public_key_hex: &'static str,
}

/// Pinned update-manifest trust root. Key-compromise rotation is handled
/// by *adding* a new `TrustedKey` entry here and shipping it in a client
/// release before the new key is ever used to sign a manifest, never by
/// replacing this list in a way that invalidates a key still in use.
///
/// Ordinary developer builds pin a known development key so update fixtures
/// remain usable. A build with `enforce-release-trust-root` instead requires
/// the release key id and public key at compile time. This makes it impossible
/// for a release binary to silently fall back to the forgeable development
/// key; the matching private key remains exclusively offline or in an HSM.
/// Fail-closed applies regardless of which key is pinned here: an
/// unknown `key_id` or a signature that does not verify under the exact
/// key listed is always rejected, never treated as "trust on first use."
/// The `key_id` of the development/beta placeholder trust root. A real release
/// build must not ship with this pinned. It is a named constant, and the pinned
/// key below references it, purely for readability -- the release gate below
/// never relies on this label, since a `key_id` can be renamed without
/// changing which private key can forge a manifest (see
/// `is_placeholder_public_key`).
pub const PLACEHOLDER_TRUST_ROOT_KEY_ID: &str = "yadorilink-beta-dev-2026";

#[cfg(not(feature = "enforce-release-trust-root"))]
pub const TRUSTED_KEYS: &[TrustedKey] = &[TrustedKey {
    key_id: PLACEHOLDER_TRUST_ROOT_KEY_ID,
    public_key_hex: "00e033f866c263139ff4afd165e75bae3cfca67eb32399dddd6e33a3251af1e3",
}];

#[cfg(feature = "enforce-release-trust-root")]
pub const TRUSTED_KEYS: &[TrustedKey] = &[TrustedKey {
    key_id: env!(
        "YADORILINK_RELEASE_MANIFEST_KEY_ID",
        "release builds require YADORILINK_RELEASE_MANIFEST_KEY_ID"
    ),
    public_key_hex: env!(
        "YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX",
        "release builds require YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX"
    ),
}];

/// The placeholder keypair's actual PUBLIC KEY BYTES (lowercase hex). The
/// release gate below detects the placeholder by this key MATERIAL, not by
/// `PLACEHOLDER_TRUST_ROOT_KEY_ID`: a `key_id` is only a label, so a build
/// that renamed it (or otherwise pinned this exact public key under a
/// different id) would still trust a key whose private half is not secret,
/// and must still be caught.
const PLACEHOLDER_TRUST_ROOT_PUBLIC_KEY_HEX: &str =
    "00e033f866c263139ff4afd165e75bae3cfca67eb32399dddd6e33a3251af1e3";

/// Whether the given `key_id` is the known development/beta placeholder's
/// usual label. Informational/logging only -- the release gate itself never
/// relies on this; see `is_placeholder_public_key` for the check that
/// actually matters.
pub fn key_id_is_placeholder(key_id: &str) -> bool {
    key_id == PLACEHOLDER_TRUST_ROOT_KEY_ID
}

/// Whether `public_key_hex` IS the placeholder keypair's public key bytes,
/// compared case-insensitively (and trimmed) so encoding differences can't
/// evade detection. This is what the release gate actually keys off, rather
/// than a `key_id` label.
fn is_placeholder_public_key(public_key_hex: &str) -> bool {
    public_key_hex.trim().eq_ignore_ascii_case(PLACEHOLDER_TRUST_ROOT_PUBLIC_KEY_HEX)
}

/// Whether any pinned trust-root key IS the development/beta placeholder,
/// detected by key material (`is_placeholder_public_key`) so a renamed
/// `key_id` can never hide it. A release pipeline SHALL treat `true` as a
/// hard failure: serving real update manifests to real users while the
/// placeholder key is pinned cannot guarantee the update path's
/// authenticity. See `enforce_release_trust_root_gate` for the gate built on
/// this that a release pipeline actually runs.
pub fn trust_root_has_placeholder() -> bool {
    TRUSTED_KEYS.iter().any(|k| is_placeholder_public_key(k.public_key_hex))
}

/// Whether `trusted_keys` configures at least one REAL trusted key: not
/// empty, and not made up entirely of blank/whitespace or placeholder key
/// material. An empty or placeholder-only trusted-key set is exactly as
/// forgeable as shipping no signature check at all, so it is never accepted
/// as a valid production trust root.
/// Pure release-gate logic: is `trusted_keys` safe to enforce as a real
/// release's trust root? Rejects if the placeholder key's MATERIAL is present
/// under any `key_id`, if no key is configured, or if an id/public key is
/// malformed. Validating the Ed25519 point here prevents a release that builds
/// successfully but can never verify any update manifest.
fn release_gate_result(trusted_keys: &[TrustedKey]) -> Result<(), String> {
    if trusted_keys.iter().any(|k| is_placeholder_public_key(k.public_key_hex)) {
        return Err(format!(
            "trust root pins the placeholder public key '{PLACEHOLDER_TRUST_ROOT_PUBLIC_KEY_HEX}' \
             (its matching private key is not secret, so anyone can forge a manifest that \
             passes this check); replace it with a real offline/HSM-generated release key \
             before serving updates"
        ));
    }
    if trusted_keys.is_empty() {
        return Err("trust root configures no trusted key; at least one real release-signing key \
             must be pinned before serving updates"
            .to_string());
    }
    let mut key_ids = std::collections::HashSet::new();
    for key in trusted_keys {
        if key.key_id.trim().is_empty() {
            return Err("trust root contains a blank key id".to_string());
        }
        if !key_ids.insert(key.key_id) {
            return Err(format!("trust root contains duplicate key id '{}'", key.key_id));
        }
        let bytes = hex::decode(key.public_key_hex.trim())
            .map_err(|_| format!("trust root key '{}' is not valid hex", key.key_id))?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            format!(
                "trust root key '{}' must decode to exactly 32 bytes, got {}",
                key.key_id,
                v.len()
            )
        })?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| {
            format!("trust root key '{}' is not a valid Ed25519 public key", key.key_id)
        })?;
    }
    Ok(())
}

/// Combines `release_gate_result` with the local/dev opt-out: when
/// `dev_override` is `true` the gate is skipped entirely, for a build that is
/// explicitly acknowledging it is not producing a real release artifact.
fn evaluate_release_gate(trusted_keys: &[TrustedKey], dev_override: bool) -> Result<(), String> {
    if dev_override {
        return Ok(());
    }
    release_gate_result(trusted_keys)
}

/// Env var name for the release gate's local/dev opt-out below. Meant only
/// for a developer's own machine, or a CI run that is not producing a real
/// release artifact -- an actual release job must never set this, since
/// setting it disables the one check that stops a forgeable trust root from
/// shipping.
pub const ALLOW_PLACEHOLDER_TRUST_ROOT_ENV: &str = "YADORILINK_ALLOW_PLACEHOLDER_TRUST_ROOT";

/// The value the opt-out env var must hold EXACTLY (after trimming
/// surrounding whitespace) to bypass the gate: the single character `1`.
/// Deliberately strict so an accidental `=0`, `=false`, empty, or
/// present-but-blank value in release CI does NOT silently disable the gate
/// (fail-closed): only a deliberate `=1` opts out.
const ALLOW_PLACEHOLDER_TRUST_ROOT_VALUE: &str = "1";

/// Pure predicate for the opt-out value, split from the env read so it is
/// testable without mutating the process environment (which would race with
/// any other test in this binary reading the same var). A missing value
/// (`None`), or any value other than `1` (including `0`, `false`, empty, or
/// blank/whitespace), does NOT bypass the gate.
fn dev_override_value_enabled(raw: Option<&str>) -> bool {
    raw.map(|v| v.trim() == ALLOW_PLACEHOLDER_TRUST_ROOT_VALUE).unwrap_or(false)
}

/// Whether the opt-out env var is set to exactly the required value. Thin
/// wrapper over `dev_override_value_enabled` that supplies the live env.
fn dev_override_enabled() -> bool {
    dev_override_value_enabled(std::env::var(ALLOW_PLACEHOLDER_TRUST_ROOT_ENV).ok().as_deref())
}

/// The release gate: rejects a build that still pins the forgeable
/// development/beta placeholder root (or configures no real trusted key),
/// unless the local/dev opt-out `YADORILINK_ALLOW_PLACEHOLDER_TRUST_ROOT=1`
/// is set. Developer builds intentionally retain the placeholder for fixtures;
/// release builds replace it at compile time. The gate is wired as a
/// release-only startup tripwire behind the
/// `enforce-release-trust-root` cargo feature (see the daemon's `run`
/// startup path). **Release builds MUST enable that feature and provide the
/// compile-time key id/public key variables**. Missing variables fail the
/// build; rejected key material prevents daemon startup.
///
/// This replaces an earlier opt-IN scheme keyed on
/// `YADORILINK_ENFORCE_RELEASE_TRUST_ROOT`: under that scheme, a release job
/// that simply forgot to set the variable shipped the forgeable placeholder
/// root with nothing failing to catch it. Tying enforcement to a release
/// build feature (fail-closed) instead means the failure mode of "forgetting
/// to flip something" now points the safe way.
pub fn enforce_release_trust_root_gate() -> Result<(), String> {
    evaluate_release_gate(TRUSTED_KEYS, dev_override_enabled())
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest envelope is malformed: {0}")]
    MalformedEnvelope(String),
    #[error("manifest signed by unknown key id: {0}")]
    UnknownKey(String),
    #[error("pinned trust root key is invalid")]
    InvalidTrustRoot,
    #[error("manifest signature encoding is invalid")]
    InvalidSignatureEncoding,
    #[error("manifest signature verification failed")]
    SignatureVerificationFailed,
    #[error("manifest body is malformed: {0}")]
    MalformedBody(String),
    #[error("manifest schema version {found} is not supported (expected {expected})")]
    UnsupportedSchemaVersion { found: u32, expected: u32 },
}

/// One release entry within a manifest — the manifest field list plus
/// this file's own `rollout_percentage`/`kill_switch`/`mandatory`
/// controls. Scoped to exactly one (channel, platform, arch,
/// install_source) combination; a manifest lists one entry per
/// applicable combination, matching `LinkStatus`'s established
/// "string-typed enum" convention (`channel`/`platform`/`install_source`
/// are plain strings here too, validated by comparison against the local
/// context rather than a closed proto/Rust enum, so a manifest can name a
/// future channel/platform without every already-deployed client needing
/// a code change first — an unrecognized value simply never matches any
/// local context and is harmlessly ignored, never misinterpreted).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseEntry {
    pub channel: String,
    pub platform: String,
    pub arch: String,
    pub install_source: String,
    pub version: String,
    pub minimum_supported_version: String,
    /// 0-100. Interpreted as "this install is eligible once its pinned
    /// rollout bucket falls below this percentage" — see
    /// `rollout_selected`.
    #[serde(default)]
    pub rollout_percentage: u8,
    /// Kill switch: when set, this entry is never installed
    /// (automatically or manually) regardless of rollout/mandatory
    /// status — the release-operations equivalent of a fail-closed
    /// override for a bad release still being staged out.
    #[serde(default)]
    pub kill_switch: bool,
    /// Explicit mandatory flag — reserved for security/
    /// protocol-compatibility fixes, to guard against abuse. A version
    /// below `minimum_supported_version` is *also* treated as mandatory
    /// regardless of this flag — see `select_applicable`.
    #[serde(default)]
    pub mandatory: bool,
    pub artifact_url: String,
    /// Lowercase hex-encoded SHA-256, matching this repo's existing
    /// `scripts/ci/generate-release-checksums.py` sidecar convention.
    pub artifact_sha256: String,
    /// Signed (covered by the manifest signature exactly like every
    /// other field here) expected artifact size in bytes. Consulted by
    /// `manager::UpdateManager`'s download path to reject a response
    /// whose `Content-Length` exceeds this and to bound the download
    /// while it streams to disk, so a misconfigured or compromised
    /// signing key -- or a hostile host serving the artifact URL -- can
    /// never make a client stream an unbounded response to disk. `None`
    /// only for a manifest produced before this field existed; the
    /// download path falls back to a fixed hard cap in that case rather
    /// than downloading unbounded.
    #[serde(default)]
    pub artifact_size: Option<u64>,
    /// Expected platform publisher identity substring (e.g. a Developer
    /// ID Installer common name on macOS, or an Authenticode signer
    /// subject on Windows) — consulted by `verify::verify_artifact`.
    /// Empty means "no specific identity pinned for this entry" (`verify`
    /// still requires *a* valid platform signature; it simply can't also
    /// check *whose*).
    #[serde(default)]
    pub artifact_publisher_identity: String,
    #[serde(default)]
    pub release_notes_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateManifest {
    pub schema_version: u32,
    pub generated_at: String,
    pub releases: Vec<ReleaseEntry>,
}

/// The wire format actually fetched over HTTPS: the exact signed bytes
/// (`manifest_json`) carried alongside their signature, rather than a
/// manifest struct that gets re-serialized before verifying — mirrors
/// this workspace's existing `report_json`/`GenerateUsageReportResponse`
/// convention of signing/verifying literal bytes, never a
/// re-serialization that could differ byte-for-byte from what was
/// actually signed (a `serde_json` round-trip is not guaranteed to
/// reproduce identical bytes, e.g. key ordering or float formatting).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedManifestEnvelope {
    pub key_id: String,
    pub manifest_json: String,
    /// Standard base64 (not URL-safe) encoding of the raw 64-byte Ed25519
    /// signature.
    pub signature_base64: String,
}

/// Verifies `envelope_json` (the raw bytes fetched from the manifest URL)
/// against the pinned production trust root and, only if verification
/// succeeds, parses and returns the signed `UpdateManifest` body. Fails
/// closed on every error path: malformed envelope JSON, an unrecognized
/// `key_id`, invalid base64/signature encoding, a signature that doesn't
/// verify, or a manifest body with an unsupported `schema_version` or
/// that doesn't itself parse as valid JSON.
pub fn verify_and_parse(envelope_json: &str) -> Result<UpdateManifest, ManifestError> {
    verify_and_parse_with_keys(envelope_json, TRUSTED_KEYS)
}

/// The actual implementation, parameterized over the trusted-key set so
/// tests can exercise the exact same verification path against a
/// throwaway test keypair instead of the real pinned production trust
/// root (which this module never exposes a private key for, by design).
pub fn verify_and_parse_with_keys(
    envelope_json: &str,
    trusted_keys: &[TrustedKey],
) -> Result<UpdateManifest, ManifestError> {
    let envelope: SignedManifestEnvelope = serde_json::from_str(envelope_json)
        .map_err(|e| ManifestError::MalformedEnvelope(e.to_string()))?;

    let key = trusted_keys
        .iter()
        .find(|k| k.key_id == envelope.key_id)
        .ok_or_else(|| ManifestError::UnknownKey(envelope.key_id.clone()))?;

    let public_key_bytes =
        hex::decode(key.public_key_hex).map_err(|_| ManifestError::InvalidTrustRoot)?;
    let public_key_bytes: [u8; 32] =
        public_key_bytes.try_into().map_err(|_| ManifestError::InvalidTrustRoot)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key_bytes).map_err(|_| ManifestError::InvalidTrustRoot)?;

    use base64::Engine;
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(&envelope.signature_base64)
        .map_err(|_| ManifestError::InvalidSignatureEncoding)?;
    let signature_bytes: [u8; 64] =
        signature_bytes.try_into().map_err(|_| ManifestError::InvalidSignatureEncoding)?;
    let signature = Signature::from_bytes(&signature_bytes);

    verifying_key
        .verify(envelope.manifest_json.as_bytes(), &signature)
        .map_err(|_| ManifestError::SignatureVerificationFailed)?;

    let manifest: UpdateManifest = serde_json::from_str(&envelope.manifest_json)
        .map_err(|e| ManifestError::MalformedBody(e.to_string()))?;
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(ManifestError::UnsupportedSchemaVersion {
            found: manifest.schema_version,
            expected: MANIFEST_SCHEMA_VERSION,
        });
    }
    Ok(manifest)
}

/// This installation's coarse identity for manifest-entry matching
/// — deliberately nothing more identifying than this (see
/// update privacy rule): no device id, no
/// account id.
#[derive(Debug, Clone)]
pub struct LocalContext {
    pub current_version: semver::Version,
    pub channel: String,
    pub platform: String,
    pub arch: String,
    pub install_source: String,
    /// A stable value in `0..100`, persisted per-install (never derived
    /// from any identifier sent to a server) so repeated checks against
    /// the same rollout percentage give a consistent held-back/eligible
    /// answer instead of flapping — see `policy::UpdatePolicy::rollout_bucket`.
    pub rollout_bucket: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applicability {
    /// No release entry names a version newer than `current_version` for
    /// this exact (channel, platform, arch, install_source) — includes
    /// the case where the only newer-looking entries are malformed or
    /// are a downgrade/equal version, both of which are simply excluded
    /// from consideration rather than erroring the whole check.
    UpToDate,
    /// An applicable, installable update (rollout-selected or mandatory,
    /// and not kill-switched).
    Available { entry: ReleaseEntry, version: semver::Version, mandatory: bool },
    /// A newer version exists but staged rollout hasn't selected this
    /// install yet.
    HeldBack { entry: ReleaseEntry, version: semver::Version, reason: String },
    /// A newer version exists but its manifest entry is kill-switched —
    /// never installed, automatically or manually, until the kill switch
    /// is cleared in a later manifest.
    KillSwitched { entry: ReleaseEntry, version: semver::Version },
}

/// Selects the best applicable release entry for `ctx` out of an already
/// signature-verified `manifest`, or reports why none is currently
/// installable. Never selects a version `<=` `ctx.current_version`
/// (downgrade and minimum-version protection requirement) —
/// an entry whose `version`
/// fails to parse as semver, or that doesn't match the local
/// channel/platform/arch/install_source, is excluded from consideration
/// entirely rather than causing an error.
pub fn select_applicable(manifest: &UpdateManifest, ctx: &LocalContext) -> Applicability {
    let mut best: Option<(ReleaseEntry, semver::Version)> = None;
    for entry in &manifest.releases {
        if entry.channel != ctx.channel
            || entry.platform != ctx.platform
            || entry.arch != ctx.arch
            || entry.install_source != ctx.install_source
        {
            continue;
        }
        let Ok(version) = parse_semver(&entry.version) else { continue };
        if version <= ctx.current_version {
            continue; // downgrade or already-current: never selectable
        }
        let better = match &best {
            Some((_, best_version)) => version > *best_version,
            None => true,
        };
        if better {
            best = Some((entry.clone(), version));
        }
    }

    let Some((entry, version)) = best else { return Applicability::UpToDate };

    if entry.kill_switch {
        return Applicability::KillSwitched { entry, version };
    }

    let min_supported = parse_semver(&entry.minimum_supported_version).ok();
    let mandatory = entry.mandatory || min_supported.is_some_and(|min| ctx.current_version < min);

    if !mandatory && !rollout_selected(ctx.rollout_bucket, entry.rollout_percentage) {
        let reason = format!(
            "staged rollout at {}%; this install's bucket ({}) is not yet selected",
            entry.rollout_percentage, ctx.rollout_bucket
        );
        return Applicability::HeldBack { entry, version, reason };
    }

    Applicability::Available { entry, version, mandatory }
}

/// Tolerates a leading `v` (e.g. `v1.2.3`) since that's a common release
/// tag convention, but otherwise requires strict semver (rejecting malformed versions).
/// `pub(crate)` so `manager` can re-derive a clean, filesystem-safe
/// version string from an already-selected entry's `version` field
/// without ever trusting a raw string straight from the manifest (see
/// `manager::artifact_filename`).
pub(crate) fn parse_semver(raw: &str) -> Result<semver::Version, semver::Error> {
    semver::Version::parse(raw.strip_prefix('v').unwrap_or(raw))
}

fn rollout_selected(bucket: u8, rollout_percentage: u8) -> bool {
    u32::from(bucket) < u32::from(rollout_percentage.min(100))
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Test-only helpers for signing a manifest with a throwaway keypair
    //! instead of `TRUSTED_KEYS`'s real (dev-placeholder) key — used by
    //! this module's own tests and by `policy`/`manager` tests elsewhere
    //! in this crate that need a realistic signed-envelope fixture.
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    pub const TEST_KEY_ID: &str = "test-key-1";

    pub fn test_signing_key() -> SigningKey {
        // Fixed, obviously-not-secret seed: deterministic test fixtures,
        // never used outside `#[cfg(test)]`.
        SigningKey::from_bytes(&[7u8; 32])
    }

    pub fn test_trusted_keys() -> Vec<(String, [u8; 32])> {
        vec![(TEST_KEY_ID.to_string(), test_signing_key().verifying_key().to_bytes())]
    }

    pub fn sign_manifest(manifest: &UpdateManifest) -> SignedManifestEnvelope {
        let manifest_json = serde_json::to_string(manifest).unwrap();
        let signing_key = test_signing_key();
        let signature = signing_key.sign(manifest_json.as_bytes());
        use base64::Engine;
        SignedManifestEnvelope {
            key_id: TEST_KEY_ID.to_string(),
            manifest_json,
            signature_base64: base64::engine::general_purpose::STANDARD
                .encode(signature.to_bytes()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    fn sample_entry(version: &str) -> ReleaseEntry {
        ReleaseEntry {
            channel: "beta".into(),
            platform: "macos".into(),
            arch: "aarch64".into(),
            install_source: "standalone".into(),
            version: version.into(),
            minimum_supported_version: "0.1.0".into(),
            rollout_percentage: 100,
            kill_switch: false,
            mandatory: false,
            artifact_url: "https://example.invalid/yadorilink-x.pkg".into(),
            artifact_sha256: "0".repeat(64),
            artifact_size: Some(1024),
            artifact_publisher_identity: String::new(),
            release_notes_url: "https://example.invalid/notes".into(),
        }
    }

    fn sample_manifest(entries: Vec<ReleaseEntry>) -> UpdateManifest {
        UpdateManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            generated_at: "2026-07-01T00:00:00Z".into(),
            releases: entries,
        }
    }

    fn sample_ctx() -> LocalContext {
        LocalContext {
            current_version: semver::Version::parse("0.1.0").unwrap(),
            channel: "beta".into(),
            platform: "macos".into(),
            arch: "aarch64".into(),
            install_source: "standalone".into(),
            rollout_bucket: 0,
        }
    }

    fn trusted_keys_hex(keys: &[(String, [u8; 32])]) -> Vec<TrustedKey> {
        // `TrustedKey.public_key_hex` is `&'static str`; leak the hex
        // string for the lifetime of the test process, which is fine for
        // a `#[cfg(test)]`-only helper that runs a bounded number of
        // times per test binary.
        keys.iter()
            .map(|(id, pk)| TrustedKey {
                key_id: Box::leak(id.clone().into_boxed_str()),
                public_key_hex: Box::leak(hex::encode(pk).into_boxed_str()),
            })
            .collect()
    }

    /// A validly-signed manifest with a newer, fully-rolled-out entry is
    /// selected as available.
    #[test]
    fn valid_manifest_selects_an_applicable_update() {
        let manifest = sample_manifest(vec![sample_entry("0.2.0")]);
        let envelope = sign_manifest(&manifest);
        let keys = trusted_keys_hex(&test_trusted_keys());

        let parsed =
            verify_and_parse_with_keys(&serde_json::to_string(&envelope).unwrap(), &keys).unwrap();
        assert_eq!(parsed, manifest);

        match select_applicable(&parsed, &sample_ctx()) {
            Applicability::Available { version, mandatory, .. } => {
                assert_eq!(version, semver::Version::parse("0.2.0").unwrap());
                assert!(!mandatory);
            }
            other => panic!("expected Available, got {other:?}"),
        }
    }

    /// A tampered payload (one changed byte) fails signature
    /// verification and is never parsed into a usable manifest — this is
    /// the fail-closed "tampered manifest is genuinely rejected" proof.
    #[test]
    fn tampered_manifest_body_fails_signature_verification() {
        let manifest = sample_manifest(vec![sample_entry("0.2.0")]);
        let mut envelope = sign_manifest(&manifest);
        // Flip the version an attacker most wants to control, without
        // re-signing (they don't have the private key).
        envelope.manifest_json = envelope.manifest_json.replace("0.2.0", "9.9.9");
        let keys = trusted_keys_hex(&test_trusted_keys());

        let result = verify_and_parse_with_keys(&serde_json::to_string(&envelope).unwrap(), &keys);
        assert_eq!(result, Err(ManifestError::SignatureVerificationFailed));
    }

    /// A manifest "signed" under a key id this build doesn't recognize is
    /// rejected outright — never falls back to trusting it anyway.
    #[test]
    fn unknown_signing_key_is_rejected() {
        let manifest = sample_manifest(vec![sample_entry("0.2.0")]);
        let mut envelope = sign_manifest(&manifest);
        envelope.key_id = "some-other-key".into();
        let keys = trusted_keys_hex(&test_trusted_keys());

        let result = verify_and_parse_with_keys(&serde_json::to_string(&envelope).unwrap(), &keys);
        assert_eq!(result, Err(ManifestError::UnknownKey("some-other-key".into())));
    }

    /// `key_id_is_placeholder` checks the LABEL only, and is never what the
    /// release gate relies on -- see the tests below, which detect the
    /// placeholder by key MATERIAL instead, so a renamed `key_id` can't be
    /// used to sneak the placeholder past the gate. Tests the mechanism, not
    /// the current pinned state, so it keeps passing once a real key ships.
    #[test]
    fn key_id_is_placeholder_checks_the_label_only() {
        assert!(key_id_is_placeholder(PLACEHOLDER_TRUST_ROOT_KEY_ID));
        assert!(!key_id_is_placeholder("yadorilink-release-2026"));
    }

    /// The core bypass this gate closes: the placeholder public key, pinned
    /// under a `key_id` that no longer looks like the placeholder's usual
    /// label, must still be detected and rejected -- a naive `key_id`-only
    /// check would miss this entirely.
    #[test]
    fn release_gate_rejects_placeholder_key_material_under_any_key_id() {
        let renamed_but_still_placeholder = &[TrustedKey {
            key_id: "yadorilink-release-2026", // looks legitimate
            public_key_hex: PLACEHOLDER_TRUST_ROOT_PUBLIC_KEY_HEX,
        }];
        assert!(release_gate_result(renamed_but_still_placeholder).is_err());
    }

    /// An empty trusted-key set is exactly as forgeable as no signature
    /// check at all, so it must never pass the gate.
    #[test]
    fn release_gate_rejects_an_empty_trusted_key_set() {
        assert!(release_gate_result(&[]).is_err());
    }

    /// A trusted-key set containing only blank/whitespace key material is
    /// also never a real trust root, even though the list itself is
    /// non-empty.
    #[test]
    fn release_gate_rejects_a_blank_trusted_key_set() {
        let blank = &[TrustedKey { key_id: "blank", public_key_hex: "   " }];
        assert!(release_gate_result(blank).is_err());
    }

    #[test]
    fn release_gate_rejects_malformed_public_key_and_duplicate_id() {
        let malformed = &[TrustedKey { key_id: "release", public_key_hex: "abcd" }];
        assert!(release_gate_result(malformed).is_err());

        let duplicate = &[
            TrustedKey {
                key_id: "release",
                public_key_hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            },
            TrustedKey {
                key_id: "release",
                public_key_hex: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            },
        ];
        assert!(release_gate_result(duplicate).is_err());
    }

    /// A real, non-placeholder configured key is accepted.
    #[test]
    fn release_gate_accepts_a_real_configured_root() {
        // Distinct from the placeholder's public key material, but still a
        // syntactically valid 32-byte hex string.
        const REAL_TEST_ROOT_PUBLIC_KEY_HEX: &str =
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let real = &[TrustedKey {
            key_id: "yadorilink-release-2026",
            public_key_hex: REAL_TEST_ROOT_PUBLIC_KEY_HEX,
        }];
        assert!(release_gate_result(real).is_ok());
    }

    /// The local/dev opt-out, when explicitly enabled, bypasses the gate even
    /// for a placeholder root -- but that override never changes
    /// `release_gate_result` itself, only `evaluate_release_gate`'s handling
    /// of it.
    #[test]
    fn release_gate_dev_override_bypasses_a_placeholder_root() {
        let placeholder = &[TrustedKey {
            key_id: PLACEHOLDER_TRUST_ROOT_KEY_ID,
            public_key_hex: PLACEHOLDER_TRUST_ROOT_PUBLIC_KEY_HEX,
        }];
        assert!(evaluate_release_gate(placeholder, false).is_err());
        assert!(evaluate_release_gate(placeholder, true).is_ok());
    }

    /// The opt-out value must be EXACTLY `1` (after trimming): only that
    /// bypasses the gate. This is the fail-closed half of the fix -- an
    /// accidental `=0`, `=false`, empty, or blank value left in release CI
    /// must NOT disable the gate.
    #[test]
    fn dev_override_requires_exactly_one() {
        assert!(dev_override_value_enabled(Some("1")));
        assert!(dev_override_value_enabled(Some(" 1 "))); // surrounding whitespace trimmed
    }

    #[test]
    fn dev_override_rejects_zero_false_empty_and_missing() {
        // The exact accidental values that must NOT fail the gate open.
        assert!(!dev_override_value_enabled(Some("0")));
        assert!(!dev_override_value_enabled(Some("false")));
        assert!(!dev_override_value_enabled(Some("true")));
        assert!(!dev_override_value_enabled(Some(""))); // present-but-empty
        assert!(!dev_override_value_enabled(Some("   "))); // present-but-blank
        assert!(!dev_override_value_enabled(Some("11")));
        assert!(!dev_override_value_enabled(None)); // unset
    }

    /// The release gate a real release pipeline actually runs
    /// (`enforce_release_trust_root_gate`) reads the live pinned
    /// `TRUSTED_KEYS` and the live opt-out env. This asserts the composed
    /// function agrees with its parts without mutating the ambient
    /// environment (which would race with any other test in this binary
    /// reading the same var), so it is stable regardless of how this test
    /// binary happens to be invoked.
    #[test]
    fn enforce_gate_composes_live_trust_root_and_live_override() {
        assert_eq!(
            enforce_release_trust_root_gate(),
            evaluate_release_gate(TRUSTED_KEYS, dev_override_enabled())
        );
    }

    /// The schema-version half of "invalid manifest is rejected".
    #[test]
    fn unsupported_schema_version_is_rejected() {
        let mut manifest = sample_manifest(vec![sample_entry("0.2.0")]);
        manifest.schema_version = 999;
        let envelope = sign_manifest(&manifest);
        let keys = trusted_keys_hex(&test_trusted_keys());

        let result = verify_and_parse_with_keys(&serde_json::to_string(&envelope).unwrap(), &keys);
        assert_eq!(
            result,
            Err(ManifestError::UnsupportedSchemaVersion {
                found: 999,
                expected: MANIFEST_SCHEMA_VERSION
            })
        );
    }

    /// An entry offering a version lower than (or equal to) the running
    /// version is never selected, even though it's otherwise a perfectly
    /// well-formed, validly-signed, applicable-platform entry.
    #[test]
    fn downgrade_entry_is_never_selected() {
        let manifest = sample_manifest(vec![sample_entry("0.0.9"), sample_entry("0.1.0")]);
        let mut ctx = sample_ctx();
        ctx.current_version = semver::Version::parse("0.1.0").unwrap();
        assert_eq!(select_applicable(&manifest, &ctx), Applicability::UpToDate);
    }

    /// A malformed version string in one entry doesn't error the whole
    /// selection — it's simply excluded, and a valid newer entry
    /// elsewhere in the same manifest is still selected.
    #[test]
    fn malformed_version_entry_is_skipped_not_fatal() {
        let mut bad = sample_entry("not-a-version");
        bad.rollout_percentage = 100;
        let manifest = sample_manifest(vec![bad, sample_entry("0.3.0")]);
        match select_applicable(&manifest, &sample_ctx()) {
            Applicability::Available { version, .. } => {
                assert_eq!(version, semver::Version::parse("0.3.0").unwrap())
            }
            other => panic!("expected Available for the well-formed entry, got {other:?}"),
        }
    }

    /// A rollout percentage of 0 never selects any install (bucket is
    /// always `>= 0`), and is reported as held back rather than available.
    #[test]
    fn rollout_holdback_prevents_selection() {
        let mut entry = sample_entry("0.5.0");
        entry.rollout_percentage = 0;
        let manifest = sample_manifest(vec![entry]);
        match select_applicable(&manifest, &sample_ctx()) {
            Applicability::HeldBack { version, .. } => {
                assert_eq!(version, semver::Version::parse("0.5.0").unwrap())
            }
            other => panic!("expected HeldBack, got {other:?}"),
        }
    }

    /// The mirror case: full rollout (100%) always selects, regardless of
    /// this install's particular bucket value.
    #[test]
    fn full_rollout_always_selects() {
        let entry = sample_entry("0.5.0"); // rollout_percentage: 100
        let manifest = sample_manifest(vec![entry]);
        let mut ctx = sample_ctx();
        ctx.rollout_bucket = 99;
        assert!(matches!(select_applicable(&manifest, &ctx), Applicability::Available { .. }));
    }

    /// An entry marked `kill_switch: true` is reported distinctly and is
    /// never treated as installable even though it's otherwise a valid,
    /// newer, fully rolled-out entry.
    #[test]
    fn kill_switch_entry_is_never_available() {
        let mut entry = sample_entry("0.9.0");
        entry.kill_switch = true;
        let manifest = sample_manifest(vec![entry]);
        match select_applicable(&manifest, &sample_ctx()) {
            Applicability::KillSwitched { version, .. } => {
                assert_eq!(version, semver::Version::parse("0.9.0").unwrap())
            }
            other => panic!("expected KillSwitched, got {other:?}"),
        }
    }

    /// A version below `minimum_supported_version` is mandatory even
    /// without the explicit `mandatory` flag, and bypasses rollout
    /// holdback (a mandatory security fix must not be gated behind a
    /// staged percentage).
    #[test]
    fn below_minimum_supported_version_is_mandatory_and_bypasses_rollout() {
        let mut entry = sample_entry("0.5.0");
        entry.minimum_supported_version = "0.2.0".into();
        entry.rollout_percentage = 0; // would otherwise hold back
        let manifest = sample_manifest(vec![entry]);
        let mut ctx = sample_ctx();
        ctx.current_version = semver::Version::parse("0.1.0").unwrap(); // below minimum
        match select_applicable(&manifest, &ctx) {
            Applicability::Available { mandatory, .. } => assert!(mandatory),
            other => panic!("expected mandatory Available, got {other:?}"),
        }
    }

    /// Entries for a non-matching channel/platform/arch/install_source
    /// are never selected, even if they're a validly-signed newer
    /// version.
    #[test]
    fn non_matching_platform_entry_is_ignored() {
        let mut entry = sample_entry("0.9.0");
        entry.platform = "windows".into();
        let manifest = sample_manifest(vec![entry]);
        assert_eq!(select_applicable(&manifest, &sample_ctx()), Applicability::UpToDate);
    }
}

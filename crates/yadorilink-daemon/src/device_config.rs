//! Small local config file recording this device's identity and the
//! coordination-plane address to use, written by `yadorilink device
//! register` (CLI) and read by the daemon on startup — shared local state
//! that must persist across daemon restarts.

use std::path::PathBuf;
use std::sync::Once;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub device_id: String,
    pub coordination_addr: String,
    /// Retained only so a `device.json` written before the relay was
    /// removed still parses. The daemon no longer connects to any relay, so
    /// the value is ignored (with a one-time warning) rather than used.
    /// Absent on configs written since the relay was removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_addr: Option<String>,
    /// NAT-traversal settings for establishing direct peer connections.
    /// `#[serde(default)]` so a `device.json` from before this section
    /// existed decodes with the conservative defaults.
    #[serde(default)]
    pub nat: NatConfig,
    /// Hex-encoded public half of this device's WireGuard (X25519) key, as
    /// registered with the coordination plane.
    ///
    /// Recorded so the daemon can tell "the key file holds my identity" from
    /// "the key file holds *an* identity" — the private key alone cannot answer
    /// that, because every 32 random bytes are a structurally valid X25519
    /// secret. A key file restored from a different device's backup, or a
    /// keyring entry belonging to another install, therefore loads perfectly
    /// and produces a device that no peer will talk to; only a public-key
    /// comparison catches it. See [`check_public_key_fingerprint`].
    ///
    /// `Option` and not required: absent means "this config predates the
    /// field", which is emphatically not "mismatch" — refusing to start on
    /// absence would brick every install written before it. See
    /// [`FingerprintCheck::Unrecorded`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wireguard_public_key: Option<String>,
    /// Hex-encoded public half of this device's Ed25519 change-signing key.
    /// Same rationale and same absent-is-not-mismatch rule as
    /// [`Self::wireguard_public_key`], but the stakes are higher: the
    /// coordination plane records a device's signing key once, so a signing key
    /// that disagrees with the registered one is never re-distributed and every
    /// change this device emits stays unverifiable to peers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_public_key: Option<String>,
    /// This config file's version — mirrors the DB `SCHEMA_VERSION`
    /// marker's rationale (`yadorilink_sync_core::index::SCHEMA_VERSION`'s
    /// doc comment), but for `device.json` rather than SQLite (no
    /// `PRAGMA user_version` equivalent for a plain JSON file, hence a
    /// real field here instead).
    /// `#[serde(default)]` makes an on-disk file from before this field
    /// existed decode as `config_version: 0` rather than failing to parse
    /// — that's also the correct "pre-versioning" sentinel value, always
    /// `<= CONFIG_VERSION`, so an old config never trips the downgrade
    /// check in `load` below.
    #[serde(default)]
    pub config_version: u32,
}

/// NAT-traversal settings, mapped onto the transport's own STUN and
/// port-mapping configs when gathering direct candidates. Conservative
/// defaults: passive server-reflexive discovery (STUN) is on against a
/// well-known public server set; actively asking the router to open a port
/// is off until explicitly enabled. `#[serde(default)]` on the struct so a
/// partially-specified `[nat]` section fills the rest from these defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NatConfig {
    /// STUN servers (`host:port`) queried to discover this device's
    /// server-reflexive address for hole punching. An empty list disables
    /// STUN entirely — no packets are sent and no third party learns the
    /// device's address from this feature; only LAN and IPv6 host
    /// candidates remain.
    pub stun_servers: Vec<String>,
    /// How often, in seconds, to re-probe STUN so a changed public address
    /// is picked up without querying the servers more than necessary.
    pub stun_refresh_secs: u64,
    /// Whether to actively request a router port mapping
    /// (UPnP-IGD / NAT-PMP / PCP). On by default: without a relay, a mapped
    /// port is often the difference between connecting and "cannot connect",
    /// and the lease is finite, renewed, and released on shutdown.
    pub port_mapping_enabled: bool,
    /// Lifetime, in seconds, requested for a router port-mapping lease; it
    /// is renewed before expiry while `port_mapping_enabled` is set.
    pub port_mapping_lease_secs: u32,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            stun_servers: default_stun_servers(),
            stun_refresh_secs: 300,
            port_mapping_enabled: true,
            port_mapping_lease_secs: 3600,
        }
    }
}

/// The well-known public STUN servers used when a config specifies none.
fn default_stun_servers() -> Vec<String> {
    vec!["stun.l.google.com:19302".to_string(), "stun1.l.google.com:19302".to_string()]
}

/// The current `device.json` shape, as of the first public beta baseline.
pub const CONFIG_VERSION: u32 = 1;

pub fn config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("YADORILINK_CONFIG_DIR") {
        return PathBuf::from(dir);
    }
    yadorilink_local_storage::FsBlockStore::default_root()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn config_path() -> PathBuf {
    config_dir().join("device.json")
}

/// The Windows equivalent of a Unix
/// socket path for the CLI-daemon control protocol — named pipes live in
/// the `\\.\pipe\` namespace, not the filesystem, so this returns a pipe
/// name rather than a path. `yadorilink-cli` depends on `yadorilink-daemon` (not
/// the reverse), so this lives here and both the daemon's own
/// `windows_transport` wiring and the CLI's `control_client` call into it,
/// rather than each independently deriving the same name.
#[cfg(windows)]
pub fn control_pipe_name() -> String {
    if let Ok(name) = std::env::var("YADORILINK_CONTROL_PIPE") {
        return name;
    }
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "default".into());
    format!(r"\\.\pipe\yadorilink-ctl-{user}")
}

/// The Windows equivalent of the
/// shell-integration IPC socket path, mirroring `control_pipe_name`.
#[cfg(windows)]
pub fn shell_ipc_pipe_name() -> String {
    if let Ok(name) = std::env::var("YADORILINK_SHELL_IPC_PIPE") {
        return name;
    }
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "default".into());
    format!(r"\\.\pipe\yadorilink-{user}")
}

/// Why an existing `device.json` could not be turned into a usable
/// [`DeviceConfig`].
///
/// Every variant describes a file that *exists*. That is the whole reason
/// this type exists rather than a bare [`std::io::Error`]: genuine absence is
/// the only condition that means "this device was never registered", and it is
/// reported out-of-band as `Ok(None)`. An `io::Error` return would leave
/// callers distinguishing "never registered" from "registered, but I could not
/// read the proof" by inspecting `ErrorKind`, and the cost of getting that
/// wrong is asymmetric: treating a registered device as unregistered invites
/// registering a *second* identity for the same physical device, which then
/// diverges from the first — nothing later can merge them back.
#[derive(Debug, thiserror::Error)]
pub enum DeviceConfigError {
    /// The file exists but could not be read — a permissions problem, an
    /// unreadable/locked file, a filesystem error. Often transient, which is
    /// exactly why it must be loud: a config that reads fine on the next boot
    /// is a config whose device is still registered.
    #[error("failed to read {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The file was read but is not valid `DeviceConfig` JSON. The device's
    /// registration is unknown, not absent — refuse rather than guess.
    #[error("{} is not a valid device config: {source}", path.display())]
    Corrupt {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    /// The file is intact and readable but was stamped by a newer build than
    /// this one — the same "unsupported downgrade" shape as a too-new DB
    /// schema (see `SyncState::init`'s `check_schema_not_newer_than_supported`
    /// and `SyncError::UnsupportedSchemaDowngrade`), and refused for the same
    /// reason: this build cannot know what a field it predates means, and
    /// guessing risks acting on a misread identity.
    ///
    /// Deliberately not `Ok(None)`. "From the future" is not "never
    /// registered": the device on disk *is* registered, and reporting absence
    /// here would invite re-registering over that existing identity — the one
    /// outcome no downgrade is allowed to cause.
    #[error(
        "device.json version {on_disk_version} is newer than this build supports (supports up to \
         version {supported_version}) — this looks like an unsupported downgrade; reinstall the \
         version that last wrote this file, or a newer one"
    )]
    UnsupportedConfigDowngrade { on_disk_version: u32, supported_version: u32 },
}

/// Reads this device's local config.
///
/// The return type *is* the contract. `Ok(None)` carries exactly one meaning —
/// no `device.json` exists, so this device was genuinely never registered —
/// and no other condition can produce it. Every failure to derive a config
/// from a file that does exist is a [`DeviceConfigError`], because the correct
/// response to "not registered" (start with an empty device id and wait to be
/// registered) is precisely the wrong response to a registered device whose
/// config merely failed to load.
///
/// - `Ok(None)` — genuine absence: no `device.json` exists yet.
/// - `Ok(Some(_))` — a valid config this build supports.
/// - `Err(_)` — the file exists but is unreadable, corrupt, or from a newer
///   build. All are hard failures; none of them is "never registered".
pub fn load() -> Result<Option<DeviceConfig>, DeviceConfigError> {
    let path = config_path();
    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        // Absence is the one outcome that legitimately means "not registered
        // yet"; every other read failure is reported as itself so it cannot
        // masquerade as absence.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(DeviceConfigError::Read { path, source }),
    };
    let config: DeviceConfig = serde_json::from_str(&contents)
        .map_err(|source| DeviceConfigError::Corrupt { path, source })?;
    if config.config_version > CONFIG_VERSION {
        return Err(DeviceConfigError::UnsupportedConfigDowngrade {
            on_disk_version: config.config_version,
            supported_version: CONFIG_VERSION,
        });
    }
    warn_once_about_ignored_relay_addr(&config);
    Ok(Some(config))
}

/// What comparing a loaded private key against `device.json` established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintCheck {
    /// The loaded key's public half is the one this config records. The
    /// identity on disk is provably the registered one.
    Verified,
    /// This config records no fingerprint for the key, so there is nothing to
    /// compare against.
    ///
    /// Deliberately NOT an error, and deliberately distinct from
    /// [`FingerprintCheck::Verified`] rather than folded into it. A config
    /// written before the fingerprint fields existed has no fingerprint through
    /// no fault of its own — the device is registered and its key is fine, and
    /// failing here would take a working install offline over a field the build
    /// that wrote it could not have known about. The same reasoning, and the
    /// same conclusion, as `config_version`'s pre-versioning `0` sentinel.
    ///
    /// The honest reading is "unverifiable", not "verified": absence proves
    /// nothing either way. Callers that can record the fingerprint should do so
    /// on this arm, which upgrades every subsequent start to a real check.
    Unrecorded,
}

/// A private key on disk whose public half is not the one `device.json`
/// records for this device.
///
/// Always an error, never a warning. The device is registered under the
/// recorded public key: peers pin it, and the coordination plane hands it out.
/// A key that disagrees cannot be made to work by continuing — it can only
/// produce a device that fails every handshake, or worse, one that keeps
/// running while peers reject everything it signs.
#[derive(Debug, thiserror::Error)]
#[error(
    "the {key_name} on disk does not belong to this device: device.json registers public key \
     {recorded}, but the private key loaded here has public key {loaded}. Refusing to start \
     rather than run as an identity peers do not recognize — restore this device's key files \
     from backup, or re-register the device to obtain a new identity."
)]
pub struct FingerprintMismatch {
    /// Which key disagreed, in the words a user would recognize.
    pub key_name: &'static str,
    pub recorded: String,
    pub loaded: String,
}

/// Checks a just-loaded private key's public half against the fingerprint
/// `device.json` records for it.
///
/// `recorded` is the config field ([`DeviceConfig::wireguard_public_key`] or
/// [`DeviceConfig::signing_public_key`]); `loaded_public` is the public half
/// derived from the private key that was actually read off this machine.
///
/// A recorded fingerprint that is not decodable hex is treated as a mismatch,
/// not as absence: the field is present, so someone meant to pin something, and
/// a garbled pin is a reason to stop rather than to silently stop checking.
pub fn check_public_key_fingerprint(
    recorded: Option<&str>,
    loaded_public: &[u8; 32],
    key_name: &'static str,
) -> Result<FingerprintCheck, FingerprintMismatch> {
    let Some(recorded) = recorded else {
        return Ok(FingerprintCheck::Unrecorded);
    };
    let loaded = hex::encode(loaded_public);
    // Compared as decoded bytes, so hex case or stray whitespace cannot fail a
    // key that genuinely matches.
    let matches = hex::decode(recorded.trim())
        .is_ok_and(|recorded_bytes| recorded_bytes.as_slice() == loaded_public.as_slice());
    if matches {
        Ok(FingerprintCheck::Verified)
    } else {
        Err(FingerprintMismatch { key_name, recorded: recorded.to_string(), loaded })
    }
}

/// The relay was removed; a `relay_addr` left in an older `device.json` is
/// parsed (so the file still loads) but ignored. Logged at most once per
/// process so an unchanged legacy config doesn't warn on every read.
fn warn_once_about_ignored_relay_addr(config: &DeviceConfig) {
    static WARNED: Once = Once::new();
    if config.relay_addr.as_deref().is_some_and(|addr| !addr.is_empty()) {
        WARNED.call_once(|| {
            tracing::warn!(
                config_key = "relay_addr",
                "device.json contains a `relay_addr` key, which is no longer used; the daemon \
                 connects to peers directly and this key is ignored"
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `YADORILINK_CONFIG_DIR` is process-global and Rust runs tests
    /// concurrently by default — serializes every test in this module that
    /// touches it, mirroring `yadorilink_cli::device_config`'s identical
    /// guard. Shared with `daemon_state.rs` and `reporting/retry.rs` (see
    /// `crate::test_support`'s doc comment) — a module-local mutex here
    /// alone does not serialize against those other modules' own tests
    /// touching the same env var. `blocking_lock` (rather than `.lock`)
    /// because these are plain synchronous `#[test]` functions with no
    /// async runtime to `.await` on.
    use crate::test_support::CONFIG_ENV_MUTEX;

    fn with_isolated_config_dir<R>(f: impl FnOnce() -> R) -> R {
        let _guard = CONFIG_ENV_MUTEX.blocking_lock();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
        let result = f();
        std::env::remove_var("YADORILINK_CONFIG_DIR");
        result
    }

    /// A `device.json` from before `config_version` existed still loads,
    /// defaulting to version 0 rather than being treated as unreadable
    /// (which would make the daemon start up as if this device were never
    /// registered — a behavior regression this must avoid).
    #[test]
    fn load_defaults_a_pre_versioning_file_to_version_zero() {
        with_isolated_config_dir(|| {
            std::fs::write(
                config_path(),
                r#"{"device_id":"device-a","coordination_addr":"http://127.0.0.1:1","relay_addr":"127.0.0.1:2"}"#,
            )
            .unwrap();

            let loaded = load().unwrap().unwrap();
            assert_eq!(loaded.config_version, 0);
            assert_eq!(loaded.device_id, "device-a");
        });
    }

    /// Genuine absence — no `device.json` at all — is the one case that
    /// legitimately means "not registered yet", so it returns `Ok(None)`,
    /// never an error.
    #[test]
    fn load_on_a_missing_file_is_ok_none_not_an_error() {
        with_isolated_config_dir(|| {
            assert!(load().unwrap().is_none());
        });
    }

    /// A `device.json` that exists but is corrupt (unparseable JSON) must
    /// surface as an error, NOT collapse to `None` — otherwise a registered
    /// device with a momentarily corrupt config would be treated as never
    /// registered and stop syncing.
    #[test]
    fn load_on_corrupt_json_is_an_error_not_absence() {
        with_isolated_config_dir(|| {
            std::fs::write(config_path(), "{ this is not valid json").unwrap();

            assert!(matches!(load(), Err(DeviceConfigError::Corrupt { .. })));
        });
    }

    /// A `device.json` that exists but cannot be read (as opposed to one that
    /// is absent) must surface as `Read`, never as absence: an unreadable
    /// config belongs to a device that is, as far as anyone knows, registered.
    ///
    /// A directory standing where `device.json` should be is the portable way
    /// to force a non-`NotFound` read error — unlike a `chmod 000` file, it
    /// fails for root too, so this cannot quietly stop testing anything when
    /// the suite runs as root in a container.
    #[test]
    fn load_on_an_unreadable_file_is_an_error_not_absence() {
        with_isolated_config_dir(|| {
            std::fs::create_dir(config_path()).unwrap();

            assert!(matches!(load(), Err(DeviceConfigError::Read { .. })));
        });
    }

    /// A `device.json` stamped newer than this build supports must fail loudly
    /// rather than resolve to "never registered". The file is intact and its
    /// device *is* registered — reporting absence would let the daemon start
    /// with an empty device id and invite registering a second identity for
    /// this same device on top of the existing one.
    #[test]
    fn load_rejects_a_newer_config_version_as_unsupported_downgrade() {
        with_isolated_config_dir(|| {
            std::fs::write(
                config_path(),
                format!(
                    r#"{{"device_id":"device-a","coordination_addr":"http://127.0.0.1:1","relay_addr":"127.0.0.1:2","config_version":{}}}"#,
                    CONFIG_VERSION + 1
                ),
            )
            .unwrap();

            let err = load().unwrap_err();
            assert!(matches!(
                err,
                DeviceConfigError::UnsupportedConfigDowngrade {
                    on_disk_version,
                    supported_version,
                } if on_disk_version == CONFIG_VERSION + 1 && supported_version == CONFIG_VERSION
            ));
            assert!(err.to_string().contains("unsupported downgrade"));
        });
    }

    /// A private key whose public half is not the one this device registered
    /// must be a loud error. This is the case a `load_existing` that merely
    /// refuses to *generate* cannot catch: the key file is present and decodes
    /// fine, it just belongs to a different device (a backup restored onto the
    /// wrong machine, a stale keyring entry).
    #[test]
    fn a_key_that_disagrees_with_the_recorded_fingerprint_is_an_error() {
        let recorded = hex::encode([7u8; 32]);

        let err = check_public_key_fingerprint(Some(&recorded), &[9u8; 32], "signing key")
            .expect_err("a key that is not the registered one must not verify");

        assert_eq!(err.key_name, "signing key");
        assert_eq!(err.recorded, recorded);
        assert_eq!(err.loaded, hex::encode([9u8; 32]));
    }

    /// The matching key verifies — without this the mismatch test above would
    /// pass even if the check rejected everything.
    #[test]
    fn a_key_that_matches_the_recorded_fingerprint_verifies() {
        let key = [7u8; 32];

        let checked = check_public_key_fingerprint(Some(&hex::encode(key)), &key, "signing key");

        assert_eq!(checked.unwrap(), FingerprintCheck::Verified);
    }

    /// A `device.json` written before the fingerprint fields existed records
    /// nothing to compare against. That must report `Unrecorded` and let the
    /// daemon start: the device is registered and its key is genuine, and
    /// failing here would take a working install offline over the absence of a
    /// field the build that wrote the file never knew about.
    #[test]
    fn an_absent_fingerprint_is_unverifiable_not_a_mismatch() {
        let checked = check_public_key_fingerprint(None, &[9u8; 32], "signing key");

        assert_eq!(checked.unwrap(), FingerprintCheck::Unrecorded);
    }

    /// Absence must come only from a genuinely absent field. A *present* but
    /// unparseable fingerprint is a mismatch: someone meant to pin a key, and a
    /// garbled pin is a reason to stop, not to quietly stop checking.
    #[test]
    fn a_present_but_unparseable_fingerprint_is_a_mismatch_not_absence() {
        let err = check_public_key_fingerprint(Some("not-hex"), &[9u8; 32], "WireGuard key")
            .expect_err("a corrupt pin must not degrade into 'nothing to check'");

        assert_eq!(err.recorded, "not-hex");
    }

    /// A fingerprint that differs from the loaded key only in hex case or
    /// surrounding whitespace still names the same key, so it must verify —
    /// a hand-edited `device.json` should not strand the device.
    #[test]
    fn fingerprint_comparison_ignores_hex_case_and_surrounding_whitespace() {
        let key = [0xABu8; 32];
        let recorded = format!("  {}\n", hex::encode_upper(key));

        let checked = check_public_key_fingerprint(Some(&recorded), &key, "WireGuard key");

        assert_eq!(checked.unwrap(), FingerprintCheck::Verified);
    }

    /// The fingerprint fields are optional on the wire: a `device.json` that
    /// predates them parses with both absent, rather than failing to load and
    /// making a registered device look unregistered.
    #[test]
    fn load_accepts_a_config_written_before_the_fingerprint_fields_existed() {
        with_isolated_config_dir(|| {
            std::fs::write(
                config_path(),
                r#"{"device_id":"device-a","coordination_addr":"http://127.0.0.1:1"}"#,
            )
            .unwrap();

            let loaded = load().unwrap().unwrap();
            assert_eq!(loaded.device_id, "device-a");
            assert!(loaded.wireguard_public_key.is_none());
            assert!(loaded.signing_public_key.is_none());
        });
    }

    /// Recorded fingerprints survive a load, so a config that *does* pin its
    /// keys actually gets them checked rather than silently reading as absent.
    #[test]
    fn load_round_trips_recorded_key_fingerprints() {
        with_isolated_config_dir(|| {
            let wg = hex::encode([1u8; 32]);
            let signing = hex::encode([2u8; 32]);
            std::fs::write(
                config_path(),
                format!(
                    r#"{{"device_id":"device-a","coordination_addr":"http://127.0.0.1:1","wireguard_public_key":"{wg}","signing_public_key":"{signing}"}}"#
                ),
            )
            .unwrap();

            let loaded = load().unwrap().unwrap();
            assert_eq!(loaded.wireguard_public_key.as_deref(), Some(wg.as_str()));
            assert_eq!(loaded.signing_public_key.as_deref(), Some(signing.as_str()));
        });
    }
}

use std::path::{Path, PathBuf};

use boringtun::x25519::{PublicKey, StaticSecret};
use ed25519_dalek::{SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::error::TransportError;
use crate::key_secret_store;

/// Why an already-persisted device identity could not be loaded.
///
/// Split out of [`TransportError`] for the reason the daemon's
/// `device_config::DeviceConfigError` is split out of `io::Error`: absence has
/// to be a variant a caller is forced to name, not an `ErrorKind` it can
/// forget to check. The correct response to "there is no key yet" (mint one)
/// is precisely the wrong response for a device that is already registered,
/// and the cost of confusing the two is asymmetric — see [`Self::Missing`].
///
/// This crate deliberately does not model "missing *for a registered device*".
/// Whether a device is registered is the daemon's knowledge (its `device.json`),
/// not the transport's; the transport reports what it observed and the caller
/// supplies the meaning.
#[derive(Debug, thiserror::Error)]
pub enum KeyLoadError {
    /// Neither the key file nor the OS keyring holds a recoverable secret.
    ///
    /// Benign for an *unregistered* device: this is the normal starting state,
    /// and [`DeviceKeyPair::generate_and_persist`] is the right answer.
    ///
    /// Unrecoverable for a *registered* one. The identity peers pinned no
    /// longer exists on this device, and minting a replacement does not restore
    /// service — it produces a device that peers reject:
    ///  * a fresh transport key no longer matches the public key the
    ///    coordination plane holds, so no peer will complete a handshake;
    ///  * a fresh *signing* key is worse, because the device keeps working
    ///    locally while every change it emits is rejected by peers as
    ///    unverifiable against the signing key they still have pinned.
    ///
    /// A registered daemon must therefore treat this as fatal at startup.
    #[error(
        "no device private key found at {} (checked the key file and the OS keyring)",
        path.display()
    )]
    Missing { path: PathBuf },

    /// A key is present but could not be turned into a usable keypair — an I/O
    /// failure, or stored bytes that decode to no valid secret.
    ///
    /// Never collapsed into [`Self::Missing`]. These failures are often
    /// transient (a locked file, a keyring the user has not unlocked yet), and
    /// a key that reads fine on the next boot is a key that was there all
    /// along: treating it as absent would mint a second identity over a live
    /// one.
    #[error("failed to load the device private key at {}: {source}", path.display())]
    Unreadable {
        path: PathBuf,
        #[source]
        source: TransportError,
    },
}

/// A device's WireGuard identity ("generate/persist per-device keypairs").
pub struct DeviceKeyPair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl DeviceKeyPair {
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rand::fill(&mut bytes[..]);
        let secret = StaticSecret::from(*bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Loads the identity already persisted at `path`. Never creates one.
    ///
    /// The load half of the old load-or-generate pair, split out so that
    /// minting an identity is something a caller has to *ask* for by name
    /// ([`Self::generate_and_persist`]) rather than something it gets by
    /// default from a call that reads like a load. A registered daemon must
    /// use this and treat every error as fatal — see [`KeyLoadError::Missing`]
    /// for why replacing a registered identity is not a recovery.
    ///
    /// Storage-at-rest (OS keyring with a hardened-file fallback) is handled by
    /// [`key_secret_store`]; the 32-byte X25519 secret is the only thing that
    /// crosses that boundary.
    pub fn load_existing(path: impl AsRef<Path>) -> Result<Self, KeyLoadError> {
        let path = path.as_ref();
        match key_secret_store::load_persisted_secret(path) {
            Ok(Some(secret)) => Ok(Self::from_secret_bytes(&secret)),
            Ok(None) => Err(KeyLoadError::Missing { path: path.to_path_buf() }),
            Err(source) => Err(KeyLoadError::Unreadable { path: path.to_path_buf(), source }),
        }
    }

    /// Mints a new identity and persists it at `path`.
    ///
    /// Correct *only* where creating an identity is the point: registering this
    /// device. Calling it for a device that is already registered replaces the
    /// identity peers pinned and strands it — see [`KeyLoadError::Missing`].
    pub fn generate_and_persist(path: impl AsRef<Path>) -> Result<Self, TransportError> {
        let path = path.as_ref();
        let keypair = Self::generate();
        let secret_bytes = Zeroizing::new(keypair.secret.to_bytes());
        match key_secret_store::persist_new_secret(path, &secret_bytes) {
            Ok(()) => Ok(keypair),
            // `persist_new_secret` publishes with `link`, which fails rather
            // than clobbering, so a concurrent creator that won the race keeps
            // its identity and this one adopts it instead of silently using a
            // secret that is no longer the one on disk.
            Err(TransportError::Io(err)) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                key_secret_store::load_persisted_secret(path)?
                    .map(|secret| Self::from_secret_bytes(&secret))
                    .ok_or_else(|| {
                        TransportError::Io(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "private key appeared during creation but could not be loaded",
                        ))
                    })
            }
            Err(err) => Err(err),
        }
    }

    /// Loads the identity at `path`, minting and persisting one if absent.
    ///
    /// Registration-only. This is the correct shape for `yadorilink device
    /// register`, where "no key yet" is the expected starting state and
    /// re-registering an already-keyed device must reuse its existing key. It
    /// is the wrong shape for a daemon: a daemon whose `device.json` already
    /// names a device MUST call [`Self::load_existing`], because for a
    /// registered device the generate branch mints an identity peers do not
    /// know instead of failing.
    pub fn load_or_generate(path: impl AsRef<Path>) -> Result<Self, TransportError> {
        let path = path.as_ref();
        match Self::load_existing(path) {
            Ok(keypair) => Ok(keypair),
            Err(KeyLoadError::Missing { .. }) => Self::generate_and_persist(path),
            Err(KeyLoadError::Unreadable { source, .. }) => Err(source),
        }
    }

    fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        let secret = StaticSecret::from(*bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }
}

pub fn public_key_from_bytes(bytes: &[u8]) -> Result<PublicKey, TransportError> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| TransportError::InvalidKey("public key must be 32 bytes".into()))?;
    Ok(PublicKey::from(array))
}

/// A device's Ed25519 signing identity, used to sign every change this
/// device originates in the content-addressed history. Generated and
/// persisted next to the WireGuard identity with the identical lifecycle:
/// the 32-byte private seed is stored at rest through [`key_secret_store`] (OS
/// keyring with a hardened owner-only file fallback), zeroized in memory. The
/// public half is distributed to peers (via the coordination plane's netmaps)
/// and pinned there, exactly like the WireGuard public key.
pub struct DeviceSigningKeyPair {
    pub signing: SigningKey,
    pub verifying: VerifyingKey,
}

impl DeviceSigningKeyPair {
    pub fn generate() -> Self {
        // Draw the 32-byte seed the same way `DeviceKeyPair::generate` draws
        // its X25519 secret, then derive the keypair — avoids threading a
        // second RNG trait version through this crate just for key gen.
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::fill(&mut seed[..]);
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    /// Loads the signing identity already persisted at `path`. Never creates
    /// one. Mirrors [`DeviceKeyPair::load_existing`].
    ///
    /// A registered daemon must use this and must treat every error as fatal —
    /// including [`KeyLoadError::Missing`]. Continuing without a signing key is
    /// not a lesser evil here: a registered device that cannot sign emits no
    /// changes at all, so its local edits never enter the shared history.
    pub fn load_existing(path: impl AsRef<Path>) -> Result<Self, KeyLoadError> {
        let path = path.as_ref();
        match key_secret_store::load_persisted_secret(path) {
            Ok(Some(secret)) => Ok(Self::from_secret_bytes(&secret)),
            Ok(None) => Err(KeyLoadError::Missing { path: path.to_path_buf() }),
            Err(source) => Err(KeyLoadError::Unreadable { path: path.to_path_buf(), source }),
        }
    }

    /// Mints a new signing identity and persists it at `path`. Registration
    /// only; mirrors [`DeviceKeyPair::generate_and_persist`].
    ///
    /// Minting this key for an already-registered device is the most damaging
    /// form of the mistake: the coordination plane records a device's signing
    /// key once, so the replacement is never distributed, and peers go on
    /// rejecting everything this device signs.
    pub fn generate_and_persist(path: impl AsRef<Path>) -> Result<Self, TransportError> {
        let path = path.as_ref();
        let keypair = Self::generate();
        let secret_bytes = Zeroizing::new(keypair.signing.to_bytes());
        match key_secret_store::persist_new_secret(path, &secret_bytes) {
            Ok(()) => Ok(keypair),
            Err(TransportError::Io(err)) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                key_secret_store::load_persisted_secret(path)?
                    .map(|secret| Self::from_secret_bytes(&secret))
                    .ok_or_else(|| {
                        TransportError::Io(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "signing key appeared during creation but could not be loaded",
                        ))
                    })
            }
            Err(err) => Err(err),
        }
    }

    /// Loads the signing identity at `path`, minting and persisting one if
    /// absent. Registration-only, exactly as
    /// [`DeviceKeyPair::load_or_generate`] — see that method for why a daemon
    /// must call [`Self::load_existing`] instead.
    pub fn load_or_generate(path: impl AsRef<Path>) -> Result<Self, TransportError> {
        let path = path.as_ref();
        match Self::load_existing(path) {
            Ok(keypair) => Ok(keypair),
            Err(KeyLoadError::Missing { .. }) => Self::generate_and_persist(path),
            Err(KeyLoadError::Unreadable { source, .. }) => Err(source),
        }
    }

    fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(bytes);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.verifying.to_bytes()
    }
}

/// Reconstructs an Ed25519 verifying key from the 32 raw bytes a peer's
/// netmap entry carries — the signing-key counterpart to
/// [`public_key_from_bytes`].
pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, TransportError> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| TransportError::InvalidKey("signing public key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&array)
        .map_err(|e| TransportError::InvalidKey(format!("invalid signing public key: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn load_or_generate_creates_private_key_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wg_key");

        DeviceKeyPair::load_or_generate(&path).unwrap();

        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn load_or_generate_reuses_existing_private_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wg_key");
        let first = DeviceKeyPair::load_or_generate(&path).unwrap();

        let second = DeviceKeyPair::load_or_generate(&path).unwrap();

        assert_eq!(second.secret.to_bytes(), first.secret.to_bytes());
        assert_eq!(second.public_bytes(), first.public_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn signing_key_load_or_generate_creates_private_key_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sign_key");

        DeviceSigningKeyPair::load_or_generate(&path).unwrap();

        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn signing_key_load_or_generate_reuses_existing_private_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sign_key");
        let first = DeviceSigningKeyPair::load_or_generate(&path).unwrap();

        let second = DeviceSigningKeyPair::load_or_generate(&path).unwrap();

        assert_eq!(second.signing.to_bytes(), first.signing.to_bytes());
        assert_eq!(second.public_bytes(), first.public_bytes());
    }

    #[test]
    fn signing_public_key_round_trips_through_bytes() {
        let keypair = DeviceSigningKeyPair::generate();
        let recovered = verifying_key_from_bytes(&keypair.public_bytes()).unwrap();
        assert_eq!(recovered.to_bytes(), keypair.public_bytes());
    }

    #[test]
    fn verifying_key_from_bytes_rejects_wrong_length() {
        assert!(verifying_key_from_bytes(&[0u8; 31]).is_err());
    }

    /// The core of the split: a device whose key is simply absent gets
    /// `Missing` rather than a freshly minted identity. A registered daemon
    /// maps this to a startup failure; nothing in this crate can quietly turn
    /// it into a new key.
    #[test]
    fn load_existing_reports_a_missing_key_instead_of_generating_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wg_key");

        // `let ... else` rather than `unwrap_err`: that would need `Debug` on
        // `DeviceKeyPair`, and a `Debug` impl on a type holding a private key is
        // how secrets end up in log output.
        let Err(err) = DeviceKeyPair::load_existing(&path) else {
            panic!("load_existing must not mint an identity for a device that has none");
        };

        assert!(matches!(err, KeyLoadError::Missing { .. }), "got {err:?}");
        assert!(!path.exists(), "load_existing must not create a key file");
    }

    #[test]
    fn signing_key_load_existing_reports_a_missing_key_instead_of_generating_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sign_key");

        let Err(err) = DeviceSigningKeyPair::load_existing(&path) else {
            panic!("load_existing must not mint a signing identity for a device that has none");
        };

        assert!(matches!(err, KeyLoadError::Missing { .. }), "got {err:?}");
        assert!(!path.exists(), "load_existing must not create a signing key file");
    }

    /// A key that exists but cannot be read is `Unreadable`, never `Missing`.
    /// The distinction is the whole point: a caller that fails hard on both is
    /// safe, but one that regenerates on `Missing` would mint a second identity
    /// over a live one the moment a read hiccups.
    ///
    /// A directory standing where the key file belongs is the portable way to
    /// force a non-`NotFound` read error — unlike `chmod 000` it fails for root
    /// too, so this cannot quietly stop testing anything under a root CI
    /// container.
    #[test]
    fn load_existing_separates_an_unreadable_key_from_a_missing_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wg_key");
        std::fs::create_dir(&path).unwrap();

        let Err(err) = DeviceKeyPair::load_existing(&path) else {
            panic!("a key path that cannot be read must not load as a usable identity");
        };

        assert!(matches!(err, KeyLoadError::Unreadable { .. }), "got {err:?}");
    }

    /// `load_existing` returns the identity that is actually on disk, so the
    /// daemon path is not merely "always fails".
    #[test]
    fn load_existing_returns_the_persisted_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wg_key");
        let created = DeviceKeyPair::generate_and_persist(&path).unwrap();

        let loaded = DeviceKeyPair::load_existing(&path).unwrap();

        assert_eq!(loaded.secret.to_bytes(), created.secret.to_bytes());
        assert_eq!(loaded.public_bytes(), created.public_bytes());
    }

    #[test]
    fn signing_key_load_existing_returns_the_persisted_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sign_key");
        let created = DeviceSigningKeyPair::generate_and_persist(&path).unwrap();

        let loaded = DeviceSigningKeyPair::load_existing(&path).unwrap();

        assert_eq!(loaded.signing.to_bytes(), created.signing.to_bytes());
        assert_eq!(loaded.public_bytes(), created.public_bytes());
    }

    /// Registration must still work: an unregistered device with no key gets
    /// one. Guards against "fix" the vulnerability by making key creation
    /// impossible, which would leave no device able to register at all.
    #[test]
    fn load_or_generate_still_creates_an_identity_for_an_unkeyed_device() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wg_key");

        let created = DeviceKeyPair::load_or_generate(&path).unwrap();

        assert!(path.exists());
        assert_eq!(
            DeviceKeyPair::load_existing(&path).unwrap().public_bytes(),
            created.public_bytes()
        );
    }

    /// `generate_and_persist` must not clobber an identity that is already
    /// there: it adopts the existing one instead. This is the create-race
    /// contract the `link`-based publication in `key_secret_store` exists to
    /// provide — two daemons starting at once must converge on one identity,
    /// not each keep a secret the other overwrote.
    #[test]
    fn generate_and_persist_adopts_an_identity_that_already_exists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wg_key");
        let first = DeviceKeyPair::generate_and_persist(&path).unwrap();

        let second = DeviceKeyPair::generate_and_persist(&path).unwrap();

        assert_eq!(
            second.public_bytes(),
            first.public_bytes(),
            "the loser of a create race must adopt the winner's identity, not overwrite it"
        );
    }
}

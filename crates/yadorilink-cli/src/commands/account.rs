//! Account-level recovery.
//!
//! Two entirely separate mechanisms live in this file, addressing two
//! separable problems:
//!
//! - `generate_recovery_codes`/`reset_password` talk to the coordination
//!   plane's `AuthService` (new `GenerateRecoveryCodes`/`ResetPassword`
//!   RPCs) and restore *account/login* access only.
//! - `export_key_bundle`/`import_key_bundle` never make a coordination-plane
//!   call at all -- the passphrase-encrypted bundle is generated, written,
//!   read, and decrypted entirely on this machine. This is the
//!   zero-knowledge boundary the whole feature is built around: the server
//!   must never see the bundle plaintext or the passphrase used to protect
//!   it, so the only way to guarantee that is to never send either one
//!   anywhere.

use std::path::{Path, PathBuf};

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::device_config::{self, DeviceConfig};
use crate::error::CliError;

/// Bundle file format version (task 3.1/3.2): bumping this on any future
/// change to `KeyBundlePlaintext`'s shape lets `import_key_bundle` reject an
/// incompatible bundle up front with a clear error instead of a confusing
/// deserialization failure after a successful decrypt.
const KEY_BUNDLE_VERSION: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

// Recovery codes and password reset have no equivalent under Google OIDC
// login (there is no password to reset) -- these commands exist only for
// the legacy gRPC transport, already slated for decommission.
#[cfg(not(feature = "http-coordination"))]
mod grpc_impl {
    use yadorilink_ipc_proto::coordination::auth_service_client::AuthServiceClient;
    use yadorilink_ipc_proto::coordination::{GenerateRecoveryCodesRequest, ResetPasswordRequest};

    use crate::error::CliError;
    use crate::grpc::{authed_request, coordination_channel, require_access_token};

    /// Generates (or regenerates, invalidating the prior set) this account's
    /// one-time recovery codes and displays them exactly once -- the
    /// coordination plane never hands them back again after this call returns
    /// (per `user-auth` spec: it only ever persists a hash of each code).
    pub async fn generate_recovery_codes() -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let mut client = AuthServiceClient::new(coordination_channel().await?);
        let resp = client
            .generate_recovery_codes(authed_request(GenerateRecoveryCodesRequest {}, &access_token))
            .await?
            .into_inner();

        println!(
            "Recovery codes generated. Store them somewhere safe (e.g. a password manager) --\n\
             they are shown only this once: the coordination plane keeps only a hash of each\n\
             code and cannot show them to you again. Generating a new batch immediately\n\
             invalidates every code below."
        );
        for code in &resp.recovery_codes {
            println!("  {code}");
        }
        Ok(())
    }

    /// Resets the account password for `email` using a recovery code. Per the
    /// `user-auth` spec's "Reset Does Not Grant Encrypted-Data Access"
    /// requirement: this restores coordination-plane login only. It is
    /// deliberately unauthenticated (no access token is sent or required) --
    /// the whole point of a recovery code is to work when the user has already
    /// lost the ability to log in.
    pub async fn reset_password(
        email: String,
        recovery_code: String,
        new_password: String,
    ) -> Result<(), CliError> {
        let mut client = AuthServiceClient::new(coordination_channel().await?);
        client.reset_password(ResetPasswordRequest { email, recovery_code, new_password }).await?;
        println!(
            "Password reset. This restores account/login access only -- it does NOT grant access\n\
             to end-to-end-encrypted data. To read previously-synced content you still need either\n\
             a surviving device or an imported key bundle (`yadorilink account import-key-bundle`)."
        );
        Ok(())
    }
}

#[cfg(not(feature = "http-coordination"))]
pub use grpc_impl::{generate_recovery_codes, reset_password};

/// Where this device's WireGuard identity (its private key) lives --
/// mirrors `commands::device::keypair_path()` exactly (same file, same
/// derivation); duplicated locally because that helper is private to
/// `commands::device` and the file layout is a small enough contract to
/// keep in sync by inspection rather than plumbing a shared `pub` helper
/// through for this one path.
fn keypair_path() -> PathBuf {
    device_config::config_dir().join("wg_key")
}

/// The on-disk bundle: an opaque, versioned envelope. Every field is
/// already ciphertext/salt/nonce (or the version tag) -- nothing here is
/// sensitive on its own, which is why it's fine to serialize as plain JSON.
#[derive(Serialize, Deserialize)]
struct KeyBundleFile {
    version: u32,
    salt_hex: String,
    nonce_hex: String,
    ciphertext_hex: String,
}

/// What's actually encrypted inside the bundle: enough to re-establish this
/// device's identity on a fresh machine and point it at the same
/// coordination/relay endpoints. This is deliberately just the device's
/// WireGuard private key (its "content key" in this codebase
/// -- there is no separate per-file content-encryption key today; devices
/// authenticate to each other and sync over a WireGuard tunnel keyed by
/// this identity) plus the addressing the device needs to reconnect.
#[derive(Serialize, Deserialize)]
struct KeyBundlePlaintext {
    device_id: String,
    coordination_addr: String,
    relay_addr: String,
    wireguard_private_key_hex: String,
}

/// Serializes, passphrase-encrypts, and writes out this device's key
/// bundle. Nothing in this function ever constructs a network client or
/// imports any coordination-plane type -- that absence is the zero-
/// knowledge property, not an incidental omission.
pub async fn export_key_bundle(output_path: PathBuf, passphrase: String) -> Result<(), CliError> {
    let device_config = device_config::load().map_err(|_| {
        CliError::Other(
            "no local device identity found -- run `yadorilink device register` first".into(),
        )
    })?;
    let wireguard_private_key_hex = read_local_private_key()?;

    let plaintext = KeyBundlePlaintext {
        device_id: device_config.device_id,
        coordination_addr: device_config.coordination_addr,
        relay_addr: device_config.relay_addr,
        wireguard_private_key_hex,
    };
    let plaintext_bytes = Zeroizing::new(
        serde_json::to_vec(&plaintext)
            .map_err(|e| CliError::Other(format!("serializing key bundle: {e}")))?,
    );

    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let key = derive_bundle_key(&passphrase, &salt)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key[..]));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext_bytes.as_slice())
        .map_err(|e| CliError::Other(format!("encrypting key bundle: {e}")))?;

    let file = KeyBundleFile {
        version: KEY_BUNDLE_VERSION,
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce_bytes),
        ciphertext_hex: hex::encode(ciphertext),
    };
    let contents = serde_json::to_string_pretty(&file)
        .map_err(|e| CliError::Other(format!("serializing key bundle file: {e}")))?;
    write_bundle_file(&output_path, &contents)?;

    println!(
        "Key bundle written to {}.\n\n\
         WARNING: this bundle, once decrypted, is as sensitive as all of your synced data --\n\
         anyone who obtains the file AND your passphrase can impersonate this device. A weak\n\
         passphrase undermines the encryption protecting it. Store it somewhere safe and\n\
         separate from your recovery codes. Losing both every device and this bundle means\n\
         your end-to-end-encrypted data is unrecoverable by design -- the coordination plane\n\
         never held a copy of your keys to fall back on.",
        output_path.display()
    );
    Ok(())
}

/// Decrypts a key bundle written by `export_key_bundle` and re-establishes
/// this device's local identity from it (the WireGuard private key file
/// and `device.json`), on a fresh machine with no surviving peer to sync
/// state from. Like `export_key_bundle`, this makes no coordination-plane
/// call: the coordination plane already has an ACL entry for this
/// `device_id` from when it first registered, so simply restoring the same
/// key material locally is what lets this device "rejoin groups" -- there
/// is nothing to re-authorize server-side.
pub async fn import_key_bundle(input_path: PathBuf, passphrase: String) -> Result<(), CliError> {
    let contents = std::fs::read_to_string(&input_path)?;
    let file: KeyBundleFile = serde_json::from_str(&contents)
        .map_err(|e| CliError::Other(format!("not a valid key bundle file: {e}")))?;
    if file.version != KEY_BUNDLE_VERSION {
        return Err(CliError::Other(format!(
            "unsupported key bundle version {} (this build supports version {KEY_BUNDLE_VERSION})",
            file.version
        )));
    }

    let salt = hex::decode(&file.salt_hex)
        .map_err(|e| CliError::Other(format!("corrupt key bundle (salt): {e}")))?;
    let nonce_bytes = hex::decode(&file.nonce_hex)
        .map_err(|e| CliError::Other(format!("corrupt key bundle (nonce): {e}")))?;
    let ciphertext = hex::decode(&file.ciphertext_hex)
        .map_err(|e| CliError::Other(format!("corrupt key bundle (ciphertext): {e}")))?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(CliError::Other("corrupt key bundle (nonce length)".into()));
    }

    let key = derive_bundle_key(&passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key[..]));
    let plaintext_bytes =
        cipher.decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_slice()).map_err(|_| {
            CliError::Other(
                "could not decrypt key bundle -- wrong passphrase, or the file is corrupted".into(),
            )
        })?;
    let plaintext: KeyBundlePlaintext = serde_json::from_slice(&plaintext_bytes)
        .map_err(|e| CliError::Other(format!("decrypted key bundle is malformed: {e}")))?;

    write_local_private_key(&plaintext.wireguard_private_key_hex)?;
    device_config::save(&DeviceConfig {
        device_id: plaintext.device_id.clone(),
        coordination_addr: plaintext.coordination_addr,
        relay_addr: plaintext.relay_addr,
        // `save` always overwrites this with the current `CONFIG_VERSION`.
        config_version: 0,
    })?;

    println!(
        "Key bundle imported. This device's identity ({}) and content keys have been\n\
         restored -- run `yadorilink daemon start` to reconnect and resume syncing. Any\n\
         folder groups this device was previously authorized for are unaffected: the\n\
         coordination plane's ACL is keyed by device id, not by which machine holds it.",
        plaintext.device_id
    );
    Ok(())
}

/// Derives a 32-byte symmetric key from `passphrase` and `salt` with
/// Argon2id (same algorithm family `yadorilink-coordination` uses for
/// password/recovery-code hashing, applied here as a raw KDF instead of a
/// storable password hash). Runs entirely client-side -- neither the
/// passphrase nor the derived key is ever sent anywhere.
fn derive_bundle_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, CliError> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key[..])
        .map_err(|e| CliError::Other(format!("deriving key bundle encryption key: {e}")))?;
    Ok(key)
}

/// Reads this device's WireGuard private key file as an opaque hex string
/// (the same format `yadorilink_transport::DeviceKeyPair` reads/writes --
/// see its `keys.rs`), without depending on `yadorilink-transport`'s key
/// types at all: the bundle only ever needs to carry the bytes faithfully,
/// never parse or validate them as a real key (that happens downstream,
/// the next time something loads `wg_key` as a `DeviceKeyPair`).
fn read_local_private_key() -> Result<String, CliError> {
    let contents = std::fs::read_to_string(keypair_path()).map_err(|_| {
        CliError::Other(
            "no local device key found -- run `yadorilink device register` first".into(),
        )
    })?;
    let trimmed = contents.trim();
    if hex::decode(trimmed).map(|b| b.len()) != Ok(32) {
        return Err(CliError::Other("local device key file is not a valid 32-byte key".into()));
    }
    Ok(trimmed.to_string())
}

fn write_local_private_key(hex_key: &str) -> Result<(), CliError> {
    if hex::decode(hex_key).map(|b| b.len()) != Ok(32) {
        return Err(CliError::Other(
            "decrypted key bundle does not contain a valid 32-byte device key".into(),
        ));
    }
    let path = keypair_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_private_file(&path, hex_key)?;
    Ok(())
}

/// Writes `contents` to `path` with owner-only permissions where supported
/// -- mirrors `device_config.rs`'s `write_config_file` (private to that
/// module, so duplicated here; both this file and `device_config.rs`
/// already accept small duplication over threading a shared helper through
/// for a two-call-site need, per that module's own doc comment).
#[cfg(unix)]
fn write_private_file(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(contents.as_bytes())
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

/// The bundle file itself isn't secret (it's ciphertext), but there's no
/// reason to leave it world-readable either.
fn write_bundle_file(path: &Path, contents: &str) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_private_file(path, contents).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// exercises the encrypt/decrypt + (de)serialize path
    /// directly (without touching `device_config`/`keypair_path`, which are
    /// process-global paths export/import read from disk), which is the
    /// part of `export_key_bundle`/`import_key_bundle` worth a focused unit
    /// test.
    #[test]
    fn key_bundle_round_trips_under_the_correct_passphrase_and_rejects_a_wrong_one() {
        let plaintext = KeyBundlePlaintext {
            device_id: "device-123".to_string(),
            coordination_addr: "https://coord.example.com".to_string(),
            relay_addr: "127.0.0.1:7444".to_string(),
            wireguard_private_key_hex: hex::encode([7u8; 32]),
        };
        let plaintext_bytes = serde_json::to_vec(&plaintext).unwrap();

        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let key = derive_bundle_key("correct horse battery staple", &salt).unwrap();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key[..]));
        let ciphertext =
            cipher.encrypt(Nonce::from_slice(&nonce_bytes), plaintext_bytes.as_slice()).unwrap();

        // Correct passphrase decrypts and round-trips exactly.
        let right_key = derive_bundle_key("correct horse battery staple", &salt).unwrap();
        let right_cipher = ChaCha20Poly1305::new(Key::from_slice(&right_key[..]));
        let decrypted = right_cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_slice())
            .expect("correct passphrase must decrypt");
        let round_tripped: KeyBundlePlaintext = serde_json::from_slice(&decrypted).unwrap();
        assert_eq!(round_tripped.device_id, plaintext.device_id);
        assert_eq!(round_tripped.wireguard_private_key_hex, plaintext.wireguard_private_key_hex);

        // Wrong passphrase must fail to decrypt (AEAD authentication
        // failure), not silently produce garbage plaintext.
        let wrong_key = derive_bundle_key("a different passphrase entirely", &salt).unwrap();
        let wrong_cipher = ChaCha20Poly1305::new(Key::from_slice(&wrong_key[..]));
        assert!(wrong_cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_slice())
            .is_err());
    }

    #[test]
    fn derive_bundle_key_is_deterministic_for_the_same_passphrase_and_salt() {
        let salt = [3u8; SALT_LEN];
        let key1 = derive_bundle_key("a passphrase", &salt).unwrap();
        let key2 = derive_bundle_key("a passphrase", &salt).unwrap();
        assert_eq!(*key1, *key2);

        let key3 = derive_bundle_key("a different passphrase", &salt).unwrap();
        assert_ne!(*key1, *key3);
    }

    #[test]
    fn export_then_import_round_trips_through_real_files() {
        // `YADORILINK_CONFIG_DIR` is process-global; serialize on
        // `device_config`'s shared test lock so this doesn't race its own
        // version-safety tests, which touch the same env var — see that
        // lock's doc comment.
        let _env_guard =
            crate::device_config::CONFIG_DIR_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        // `export_key_bundle`/`import_key_bundle` read/write via
        // `device_config::config_dir()`, which honors this env var -- so
        // this test drives the *real* production code paths end to end,
        // not a re-implementation of them.
        std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());

        device_config::save(&DeviceConfig {
            device_id: "device-abc".to_string(),
            coordination_addr: "http://127.0.0.1:7443".to_string(),
            relay_addr: "127.0.0.1:7444".to_string(),
            config_version: 0,
        })
        .unwrap();
        write_local_private_key(&hex::encode([9u8; 32])).unwrap();

        let bundle_path = dir.path().join("bundle.json");
        futures_block_on(export_key_bundle(bundle_path.clone(), "s3cret-passphrase".to_string()))
            .unwrap();

        // Simulate a fresh device: wipe the local identity before import.
        std::fs::remove_file(keypair_path()).unwrap();
        std::fs::remove_file(device_config::config_path()).unwrap();

        futures_block_on(import_key_bundle(bundle_path.clone(), "s3cret-passphrase".to_string()))
            .unwrap();

        assert_eq!(read_local_private_key().unwrap(), hex::encode([9u8; 32]));
        assert_eq!(device_config::load().unwrap().device_id, "device-abc");

        // A wrong passphrase must not silently "succeed" with garbage.
        std::fs::remove_file(keypair_path()).unwrap();
        std::fs::remove_file(device_config::config_path()).unwrap();
        let err = futures_block_on(import_key_bundle(bundle_path, "wrong-passphrase".to_string()))
            .unwrap_err();
        assert!(matches!(err, CliError::Other(_)));

        std::env::remove_var("YADORILINK_CONFIG_DIR");
    }

    /// Tiny local block-on so these tests don't need to pull in
    /// `#[tokio::test]` machinery just to call two `async fn`s that don't
    /// actually await anything except infallible, already-ready I/O.
    fn futures_block_on<F: std::future::Future>(fut: F) -> F::Output {
        // export_key_bundle/import_key_bundle never hit a genuine async
        // yield point (no network I/O -- see the module doc comment), so a
        // minimal single-poll executor is sufficient and avoids adding a
        // `futures`/`pollster` dependency for two tests.
        use std::task::{Context, Poll};
        let waker = futures_noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut fut = Box::pin(fut);
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    fn futures_noop_waker() -> std::task::Waker {
        use std::task::{RawWaker, RawWakerVTable, Waker};
        fn no_op(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }
}

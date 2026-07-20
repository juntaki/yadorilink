//! Storage-at-rest for a device's 32-byte private key secrets (the WireGuard
//! X25519 static secret and the Ed25519 change-signing seed).
//!
//! Two layers are used, in defense-in-depth order:
//!
//!  1. The OS keyring (macOS Keychain / Windows Credential Manager / Linux
//!     Secret Service) via the `keyring` crate — the same OS-native credential
//!     store the coordination-token loader uses. Encrypted / access-controlled
//!     by the OS.
//!  2. A hardened on-disk file holding one hex-encoded 32-byte secret, created
//!     owner-only: unix `0o600`, and on Windows a DACL restricted to the
//!     current user with inheritance disabled (see `harden_key_file`) — the
//!     practical equivalent of `0o600`, because a freshly created file would
//!     otherwise inherit the parent directory's weaker ACL.
//!
//! The on-disk file is the SOURCE OF TRUTH for the device identity and is
//! never deleted: losing it de-identifies the device permanently. The keyring
//! copy is populated best-effort and serves two purposes — recovering the file
//! if it is lost or damaged, and adding at-rest protection where the OS keyring
//! is available.
//!
//! Durability rules, all enforced by the single [`write_secret_file`]
//! primitive. Every secret file this module creates goes through it, so a
//! future writer cannot reintroduce a half-written or world-readable key file:
//!
//!  * The secret is written to a temporary file, `sync_all`'d, and only then
//!    published under its final name. The final name therefore never exists in
//!    a partially written state, so a power cut can lose the write but can
//!    never corrupt an identity that was already there.
//!  * Publication uses `hard_link`, not `rename`. `rename` replaces the
//!    destination unconditionally, which would silently break the create-race
//!    recovery both callers in `keys.rs` depend on: two daemons starting
//!    concurrently would each publish their own freshly generated identity and
//!    the loser would keep using a secret that is no longer on disk. `link`
//!    fails with `AlreadyExists` instead, so the loser reliably re-reads the
//!    winner's file. [`Publish::Replace`] opts into clobbering, and is used
//!    only to repair a file whose bytes are already known to be garbage.
//!  * The file is made owner-only *before* any secret byte reaches it, and a
//!    hardening failure aborts the write rather than warning. A key file at the
//!    OS default ACL is not an acceptable outcome.
//!
//! Because a corrupt key file is recoverable from the keyring and an absent one
//! is regenerated, the identity survives every crash point in this module; the
//! one unrecoverable state — a file that decodes to the wrong secret — is the
//! state the atomic publication above makes unreachable.
//!
//! Note on guarantees: the file fallback stores the secret as plaintext-at-rest
//! protected only by filesystem permissions. The keyring is defense-in-depth,
//! not a guarantee on every platform — a headless Linux host with no Secret
//! Service simply keeps using the hardened file. Which path is in use is logged
//! at load/persist time.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::error::TransportError;

/// OS keyring service name. Shared with the coordination-token loader; device
/// key entries use path-derived usernames (see `keyring_username`) so they can
/// never collide with the token loader's fixed usernames.
#[cfg(all(not(test), not(madsim)))]
const KEYRING_SERVICE: &str = "yadorilink";

/// Decodes the hex-encoded 32-byte secret held in `contents`.
fn decode_secret(contents: &str) -> Result<Zeroizing<[u8; 32]>, TransportError> {
    let bytes = Zeroizing::new(
        hex::decode(contents.trim()).map_err(|e| TransportError::InvalidKey(e.to_string()))?,
    );
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| TransportError::InvalidKey("private key must be 32 bytes".into()))?;
    Ok(Zeroizing::new(array))
}

/// What a key file at a given path turned out to hold.
enum KeyFile {
    Secret(Zeroizing<[u8; 32]>),
    Missing,
    /// The file exists but holds no usable secret: empty, truncated, or
    /// non-UTF-8 garbage. This is distinct from an I/O failure because it is
    /// recoverable — the keyring may still hold the identity — whereas an
    /// unreadable file (EACCES, EIO) signals a sick system that we must not
    /// paper over by rewriting the key file from a second-hand copy.
    Corrupt(TransportError),
}

/// Reads and decodes the key file at `path`.
///
/// Reads bytes rather than a `String` so that non-UTF-8 content is classified
/// as [`KeyFile::Corrupt`] (recoverable) instead of surfacing as an I/O error;
/// a torn write can leave arbitrary bytes behind.
fn read_secret_file(path: &Path) -> Result<KeyFile, TransportError> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let bytes = Zeroizing::new(bytes);
            let Ok(text) = std::str::from_utf8(&bytes) else {
                return Ok(KeyFile::Corrupt(TransportError::InvalidKey(
                    "device key file is not valid UTF-8".into(),
                )));
            };
            Ok(match decode_secret(text) {
                Ok(secret) => KeyFile::Secret(secret),
                Err(err) => KeyFile::Corrupt(err),
            })
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(KeyFile::Missing),
        Err(err) => Err(err.into()),
    }
}

/// How [`write_secret_file`] publishes the finished file under its final name.
enum Publish {
    /// Fail with `AlreadyExists` if the name is already taken. Used whenever a
    /// new identity is recorded: a concurrent creator must lose the race and
    /// adopt the winner's identity rather than overwrite it.
    CreateNew,
    /// Replace whatever is at the name. Only for repairing a file already
    /// established to be corrupt, where the existing bytes carry no identity
    /// and there is nothing to lose.
    Replace,
}

/// Writes `secret` to `path` durably and owner-only.
///
/// The one primitive every secret file in this module is created through; see
/// the module docs for the durability and exclusivity rules it enforces.
fn write_secret_file(
    path: &Path,
    secret: &[u8; 32],
    publish: Publish,
) -> Result<(), TransportError> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        // A bare file name is relative to the current directory, which is also
        // where the temporary file has to land so the publishing link stays
        // within one filesystem.
        _ => PathBuf::from("."),
    };
    std::fs::create_dir_all(&parent)?;

    let (temp_path, file) = create_temp_secret_file(&parent, path)?;
    let published = write_and_publish(file, &temp_path, path, secret, publish);

    // Always drop the temporary name: on success it is a redundant second link
    // to the published file (or already consumed by a `Replace`), and on
    // failure it holds a secret that nobody will ever read.
    let _ = std::fs::remove_file(&temp_path);

    published?;

    // Make the new directory entry itself durable. Best-effort: the secret's
    // bytes are already fsync'd and the entry was published atomically, so the
    // only state losing this can produce is "file absent" — which the keyring
    // recovery and the caller's regenerate path both handle. Failing the whole
    // identity write here would trade a recoverable outcome for an outage, and
    // directory fsync has no portable meaning on Windows anyway.
    if let Err(err) = sync_dir(&parent) {
        tracing::warn!("could not flush the directory entry for the device key file: {err}");
    }
    Ok(())
}

/// Creates a uniquely named, owner-only, empty temporary file next to `path`.
///
/// The random suffix keeps two concurrent writers from colliding; a collision
/// that does happen is retried rather than surfaced, because callers read
/// `AlreadyExists` as "another process published the identity first" and a
/// temp-name clash must never be mistaken for that.
fn create_temp_secret_file(
    parent: &Path,
    path: &Path,
) -> Result<(PathBuf, std::fs::File), TransportError> {
    let file_name = path
        .file_name()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "device key path has no file name",
            )
        })?
        .to_string_lossy()
        .into_owned();

    for _ in 0..16 {
        let mut nonce = [0u8; 8];
        rand::fill(&mut nonce[..]);
        let temp_path = parent.join(format!("{file_name}.tmp.{:016x}", u64::from_le_bytes(nonce)));
        match create_owner_only_file(&temp_path) {
            Ok(file) => return Ok((temp_path, file)),
            Err(TransportError::Io(err)) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                continue
            }
            Err(err) => return Err(err),
        }
    }
    Err(std::io::Error::other("could not create a unique temporary device key file").into())
}

/// Creates `path` exclusively and restricts it to the current user, returning
/// the open handle.
///
/// Hardening happens here, on the still-empty file, so no secret byte is ever
/// written to a file at the OS default permissions — and a hardening failure is
/// fatal, because at this point there is nothing to lose by aborting.
fn create_owner_only_file(path: &Path) -> Result<std::fs::File, TransportError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Narrow the window: the file is owner-only from the instant it exists,
        // rather than briefly at the mode `harden_key_file` will re-assert.
        options.mode(0o600);
    }
    let file = options.open(path)?;

    if let Err(err) = harden_key_file(path) {
        let _ = std::fs::remove_file(path);
        return Err(err);
    }
    Ok(file)
}

/// Fills, flushes and publishes the temporary file created for `path`.
fn write_and_publish(
    mut file: std::fs::File,
    temp_path: &Path,
    path: &Path,
    secret: &[u8; 32],
    publish: Publish,
) -> Result<(), TransportError> {
    use std::io::Write;

    let encoded = Zeroizing::new(hex::encode(secret));
    file.write_all(encoded.as_bytes())?;
    // `sync_all`, not `flush`: flush only pushes the bytes out of the process,
    // which a power cut discards. The fsync must complete before the final name
    // exists, or the name could be published pointing at unwritten blocks.
    file.sync_all()?;
    drop(file);

    match publish {
        // Atomic *and* exclusive. See the module docs for why this is not a
        // `rename`.
        Publish::CreateNew => std::fs::hard_link(temp_path, path)?,
        Publish::Replace => std::fs::rename(temp_path, path)?,
    }
    Ok(())
}

/// Flushes a directory's entries so a newly published name survives a power
/// cut. No portable equivalent exists on Windows, where a directory cannot be
/// opened as a file.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Restricts a private-key file to the current user only.
///
/// On unix this re-asserts `0o600` even though the file is created with that
/// mode: `open`'s mode argument is masked by the process umask, and the load
/// path uses this to tighten a key file that was created before hardening
/// existed or had its mode loosened since. On Windows a newly created file
/// inherits the parent directory's DACL, so we replace it with a protected,
/// current-user-only DACL — the practical equivalent of `0o600`.
#[cfg(unix)]
fn harden_key_file(path: &Path) -> Result<(), TransportError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn harden_key_file(_path: &Path) -> Result<(), TransportError> {
    Ok(())
}

#[cfg(windows)]
fn harden_key_file(path: &Path) -> Result<(), TransportError> {
    windows_acl::restrict_to_current_user(path).map_err(TransportError::Io)
}

// --- Keyring layer -------------------------------------------------------
//
// Three build variants, mutually exclusive and exhaustive:
//   * cfg(test)                      -> in-memory store, never touches the real
//                                       OS keychain (avoids prompts / pollution
//                                       and keeps tests deterministic).
//   * not(test), not(madsim)         -> the real OS keyring.
//   * not(test), madsim              -> no-op (simulation stays deterministic
//                                       and never reaches for a real keychain).

/// Outcome of mirroring the on-disk secret into the OS keyring.
///
/// Simulation builds never reach a real keychain, so only `Unavailable` is
/// constructed there; the variants still have to exist for the shared load path
/// to match on.
#[cfg_attr(all(not(test), madsim), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyringMirror {
    /// The keyring holds this exact secret — it already did, or we wrote it and
    /// read it back.
    Present,
    /// The keyring is unavailable, locked, or failed. File-only at rest.
    Unavailable,
    /// The keyring holds a *different* secret for this path. Never resolved by
    /// overwriting: a mirror that the file silently overwrites is not an
    /// independent copy of anything, and whichever side is stale, destroying it
    /// is the one irreversible move available here.
    Conflict,
}

/// The keyring lookup key for a given on-disk key file: the file's absolute
/// path. Each device-key file therefore maps 1:1 to its own keyring entry and
/// cannot collide with another key file or with the coordination-token entries
/// (which use fixed, non-path usernames).
#[cfg(any(test, not(madsim)))]
fn keyring_username(path: &Path) -> String {
    let abs = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    format!("device-key:{}", abs.to_string_lossy())
}

#[cfg(all(not(test), not(madsim)))]
fn keyring_load(path: &Path) -> Option<Zeroizing<[u8; 32]>> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, &keyring_username(path)).ok()?;
    let hex = Zeroizing::new(entry.get_password().ok()?);
    decode_secret(&hex).ok()
}

/// Mirrors `secret` into the keyring. Best-effort: any keyring failure
/// (unavailable / locked / headless) reports `Unavailable` — the hardened file
/// remains the source of truth. Nothing is ever deleted based on the result.
#[cfg(all(not(test), not(madsim)))]
fn keyring_mirror(path: &Path, secret: &[u8; 32]) -> KeyringMirror {
    let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, &keyring_username(path)) else {
        return KeyringMirror::Unavailable;
    };
    if let Ok(existing) = entry.get_password() {
        let existing = Zeroizing::new(existing);
        match decode_secret(&existing) {
            Ok(existing) if existing.as_slice() == secret.as_slice() => {
                return KeyringMirror::Present
            }
            Ok(_) => return KeyringMirror::Conflict,
            // An entry we cannot decode holds no identity, so replacing it
            // destroys nothing and lets a damaged keyring entry self-heal.
            Err(_) => {}
        }
    }

    let encoded = Zeroizing::new(hex::encode(secret));
    if entry.set_password(&encoded).is_err() {
        return KeyringMirror::Unavailable;
    }
    // Independent round-trip read-back: only claim success when the keyring
    // actually returns the secret we just wrote.
    match keyring_load(path) {
        Some(v) if v.as_slice() == secret.as_slice() => KeyringMirror::Present,
        _ => KeyringMirror::Unavailable,
    }
}

#[cfg(all(not(test), madsim))]
fn keyring_load(_path: &Path) -> Option<Zeroizing<[u8; 32]>> {
    None
}

#[cfg(all(not(test), madsim))]
fn keyring_mirror(_path: &Path, _secret: &[u8; 32]) -> KeyringMirror {
    KeyringMirror::Unavailable
}

#[cfg(test)]
fn keyring_load(path: &Path) -> Option<Zeroizing<[u8; 32]>> {
    test_keyring::get(&keyring_username(path)).map(Zeroizing::new)
}

#[cfg(test)]
fn keyring_mirror(path: &Path, secret: &[u8; 32]) -> KeyringMirror {
    if let Some(existing) = test_keyring::get(&keyring_username(path)) {
        return if existing == *secret { KeyringMirror::Present } else { KeyringMirror::Conflict };
    }
    if !test_keyring::set(&keyring_username(path), secret) {
        return KeyringMirror::Unavailable;
    }
    match keyring_load(path) {
        Some(v) if v.as_slice() == secret.as_slice() => KeyringMirror::Present,
        _ => KeyringMirror::Unavailable,
    }
}

// --- Orchestration -------------------------------------------------------

/// Loads the persisted 32-byte secret for `path`, or `None` if neither the
/// hardened file nor the keyring holds one.
///
/// The on-disk file is the source of truth. If it decodes it is used, and the
/// keyring is brought up to date to mirror it (the migration path for
/// identities created before keyring storage existed). If the file is missing
/// or corrupt but the keyring still holds the identity, the secret is recovered
/// from the keyring and the hardened file is restored. The file is never
/// deleted, so the device identity cannot be lost.
pub(crate) fn load_persisted_secret(
    path: &Path,
) -> Result<Option<Zeroizing<[u8; 32]>>, TransportError> {
    match read_secret_file(path)? {
        KeyFile::Secret(secret) => {
            // Re-assert restrictive permissions on load, so a key file that a
            // previous write could not harden is tightened on the next daemon
            // start. Best-effort *here* — unlike the create path, the identity
            // already exists and refusing to load it over a permissions call we
            // cannot complete would lock the user out of their own device.
            if let Err(err) = harden_key_file(path) {
                tracing::warn!("could not re-restrict permissions on device key file: {err}");
            }
            match keyring_mirror(path, &secret) {
                KeyringMirror::Present => {
                    tracing::debug!(
                        "device key loaded from hardened file; OS keyring copy present"
                    );
                }
                KeyringMirror::Unavailable => {
                    tracing::debug!(
                        "device key loaded from hardened file; OS keyring unavailable, using file at rest"
                    );
                }
                KeyringMirror::Conflict => {
                    tracing::warn!(
                        "the OS keyring holds a different device key than the key file; \
                         keeping the key file as the source of truth and leaving the keyring \
                         entry untouched for inspection"
                    );
                }
            }
            Ok(Some(secret))
        }

        // The config directory was wiped while the OS credential store survived.
        KeyFile::Missing => recover_from_keyring(path),

        // A file that exists but does not decode is what a power cut during a
        // pre-atomic write leaves behind. The keyring may still hold the
        // identity, so this must not be reported before asking it — returning
        // the decode error here would strand a device whose key the OS keyring
        // could have handed back.
        KeyFile::Corrupt(err) => {
            let Some(secret) = keyring_load(path) else {
                return Err(err);
            };
            // Deliberately not a regenerate: the file is unreadable, not
            // absent, so `Replace` restores the identity the keyring vouches
            // for instead of minting a new one.
            write_secret_file(path, &secret, Publish::Replace)?;
            tracing::warn!(
                "device key file was unreadable ({err}); restored it from the OS keyring copy"
            );
            Ok(Some(secret))
        }
    }
}

/// Restores the on-disk source of truth from the keyring copy, if there is one.
fn recover_from_keyring(path: &Path) -> Result<Option<Zeroizing<[u8; 32]>>, TransportError> {
    let Some(secret) = keyring_load(path) else {
        return Ok(None);
    };
    match write_secret_file(path, &secret, Publish::CreateNew) {
        Ok(()) => {
            tracing::info!("device key recovered from OS keyring; rewrote hardened file on disk");
            Ok(Some(secret))
        }
        Err(TransportError::Io(err)) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            // Another process created the file first; prefer whatever is on
            // disk now, falling back to the keyring copy we already hold if the
            // winner's bytes are not readable.
            match read_secret_file(path)? {
                KeyFile::Secret(on_disk) => Ok(Some(on_disk)),
                _ => Ok(Some(secret)),
            }
        }
        Err(err) => Err(err),
    }
}

/// Persists a freshly generated secret. Writes the hardened file first, so the
/// device identity is durably recorded on disk before anything else, then
/// mirrors it into the keyring best-effort. Surfaces `AlreadyExists` so the
/// caller can run its create-race recovery.
pub(crate) fn persist_new_secret(path: &Path, secret: &[u8; 32]) -> Result<(), TransportError> {
    write_secret_file(path, secret, Publish::CreateNew)?;
    match keyring_mirror(path, secret) {
        KeyringMirror::Present => {
            tracing::debug!("device key persisted to hardened file and OS keyring");
        }
        KeyringMirror::Unavailable => {
            tracing::info!(
                "device key persisted to hardened file; OS keyring unavailable, using file at rest"
            );
        }
        KeyringMirror::Conflict => {
            tracing::warn!(
                "the OS keyring already holds a different device key for this path; \
                 keeping the new key file as the source of truth and leaving the keyring \
                 entry untouched for inspection"
            );
        }
    }
    Ok(())
}

/// Owner-only DACL hardening for private-key files on Windows.
#[cfg(windows)]
mod windows_acl {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::{null_mut, NonNull};

    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACL, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// Replaces `path`'s DACL with a protected (no inherited ACEs),
    /// current-user-only entry granting full file access — the Windows
    /// equivalent of unix `0o600`.
    pub(super) fn restrict_to_current_user(path: &Path) -> std::io::Result<()> {
        let sid = current_user_sid_string()?;
        // `D:` DACL, `P` protected (blocks inherited ACEs), one allow ACE
        // granting full access (`FA`) to the current user only.
        let sddl = widestr(&format!("D:P(A;;FA;;;{sid})"));

        let mut security_descriptor: *mut c_void = null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut security_descriptor,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let result = apply_dacl(path, security_descriptor);
        unsafe {
            LocalFree(security_descriptor);
        }
        result
    }

    fn apply_dacl(path: &Path, security_descriptor: *mut c_void) -> std::io::Result<()> {
        let mut dacl_present: i32 = 0;
        let mut dacl: *mut ACL = null_mut();
        let mut dacl_defaulted: i32 = 0;
        let ok = unsafe {
            GetSecurityDescriptorDacl(
                security_descriptor,
                &mut dacl_present,
                &mut dacl,
                &mut dacl_defaulted,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut wide_path: Vec<u16> =
            path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        // PROTECTED_DACL_SECURITY_INFORMATION strips inherited ACEs so the file
        // no longer inherits the parent directory's (weaker) permissions.
        let status = unsafe {
            SetNamedSecurityInfoW(
                wide_path.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl,
                null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    fn widestr(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn current_user_sid_string() -> std::io::Result<String> {
        let mut token: HANDLE = null_mut();
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let sid = unsafe { current_user_sid_string_from_token(token) };
        unsafe {
            CloseHandle(token);
        }
        sid
    }

    /// Reads the token's *user* SID.
    ///
    /// `TokenUser`, not `TokenOwner`: the owner SID is merely the default owner
    /// stamped on objects this process creates, and for an elevated process
    /// that is the Administrators *group*. Building the DACL from it would
    /// grant the key file to every local administrator instead of to the one
    /// account the key belongs to.
    unsafe fn current_user_sid_string_from_token(token: HANDLE) -> std::io::Result<String> {
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len);
        if len == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut buffer = vec![0u8; len as usize];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast::<c_void>(),
            len,
            &mut len,
        );
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let user = buffer.as_ptr().cast::<TOKEN_USER>().read_unaligned();
        let mut sid_string = null_mut();
        let ok = ConvertSidToStringSidW(user.User.Sid, &mut sid_string);
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let sid_string = NonNull::new(sid_string)
            .ok_or_else(|| std::io::Error::other("ConvertSidToStringSidW returned null"))?;
        let mut chars = 0usize;
        while *sid_string.as_ptr().add(chars) != 0 {
            chars += 1;
        }
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(sid_string.as_ptr(), chars));
        LocalFree(sid_string.as_ptr().cast::<c_void>());
        Ok(sid)
    }
}

/// In-memory keyring stand-in for tests: never touches the real OS keychain, so
/// unit tests neither prompt for keychain access nor pollute it, and stay
/// deterministic. Defaults to "unavailable" so the file-only fallback is the
/// path exercised unless a test explicitly opts in with `set_available(true)`.
#[cfg(test)]
mod test_keyring {
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    thread_local! {
        static STORE: RefCell<HashMap<String, [u8; 32]>> = RefCell::new(HashMap::new());
        static AVAILABLE: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn set_available(value: bool) {
        AVAILABLE.with(|a| a.set(value));
    }

    fn is_available() -> bool {
        AVAILABLE.with(Cell::get)
    }

    pub(super) fn reset() {
        STORE.with(|s| s.borrow_mut().clear());
        set_available(false);
    }

    pub(super) fn get(key: &str) -> Option<[u8; 32]> {
        if !is_available() {
            return None;
        }
        STORE.with(|s| s.borrow().get(key).copied())
    }

    pub(super) fn set(key: &str, value: &[u8; 32]) -> bool {
        if !is_available() {
            return false;
        }
        STORE.with(|s| s.borrow_mut().insert(key.to_string(), *value));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_secret() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        bytes
    }

    /// A second, clearly distinct secret, for the cases where two identities
    /// have to be told apart.
    fn other_secret() -> [u8; 32] {
        [0xAB; 32]
    }

    fn read_secret(path: &Path) -> Option<[u8; 32]> {
        match read_secret_file(path).unwrap() {
            KeyFile::Secret(secret) => Some(*secret),
            _ => None,
        }
    }

    /// Temporary files must never outlive a write: they hold the private key.
    fn temp_leftovers(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp."))
            .collect()
    }

    #[test]
    fn persist_then_load_round_trips_via_file_when_keyring_down() {
        test_keyring::reset(); // keyring unavailable
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k");
        let secret = sample_secret();

        persist_new_secret(&path, &secret).unwrap();
        assert!(path.exists());
        assert!(keyring_load(&path).is_none(), "keyring is down in this test");

        let loaded = load_persisted_secret(&path).unwrap().unwrap();
        assert_eq!(loaded.as_slice(), &secret);
        assert!(temp_leftovers(dir.path()).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn persist_creates_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;

        test_keyring::reset();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k");
        persist_new_secret(&path, &sample_secret()).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn migration_populates_keyring_without_losing_the_file() {
        test_keyring::reset();
        test_keyring::set_available(true);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k");
        let secret = sample_secret();

        // Simulate a pre-keyring plaintext identity file already on disk.
        std::fs::write(&path, hex::encode(secret)).unwrap();
        assert!(keyring_load(&path).is_none());

        let loaded = load_persisted_secret(&path).unwrap().unwrap();
        assert_eq!(loaded.as_slice(), &secret);
        // The identity file must survive migration untouched.
        assert!(path.exists(), "migration must never delete the identity file");
        // And the keyring now mirrors it.
        assert_eq!(keyring_load(&path).unwrap().as_slice(), &secret);

        test_keyring::reset();
    }

    #[test]
    fn recovers_identity_from_keyring_when_file_is_lost() {
        test_keyring::reset();
        test_keyring::set_available(true);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k");
        let secret = sample_secret();

        // Identity only in the keyring, nothing on disk yet.
        assert_eq!(keyring_mirror(&path, &secret), KeyringMirror::Present);
        assert!(!path.exists());

        let loaded = load_persisted_secret(&path).unwrap().unwrap();
        assert_eq!(loaded.as_slice(), &secret);
        // Recovery restores the on-disk source of truth.
        assert!(path.exists(), "recovery must rewrite the hardened file");

        test_keyring::reset();
    }

    #[test]
    fn missing_file_and_empty_keyring_returns_none() {
        test_keyring::reset();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent");
        assert!(load_persisted_secret(&path).unwrap().is_none());
    }

    /// A power cut can leave the key file empty or half-written. The identity
    /// is not lost when the keyring still has it, so a truncated file must send
    /// us to the keyring rather than straight to the caller as an error.
    #[test]
    fn truncated_key_file_is_restored_from_the_keyring() {
        test_keyring::reset();
        test_keyring::set_available(true);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k");
        let secret = sample_secret();

        persist_new_secret(&path, &secret).unwrap();
        assert_eq!(keyring_load(&path).unwrap().as_slice(), &secret);

        for damaged in [b"".as_slice(), b"0102030405".as_slice(), &[0xFF, 0xFE, 0x00]] {
            std::fs::write(&path, damaged).unwrap();

            let loaded = load_persisted_secret(&path).unwrap().unwrap();
            assert_eq!(loaded.as_slice(), &secret, "identity must survive a torn write");
            assert_eq!(
                read_secret(&path),
                Some(secret),
                "the damaged file must be repaired on disk, not just in memory"
            );
        }
        assert!(temp_leftovers(dir.path()).is_empty());

        test_keyring::reset();
    }

    /// The opposite guard rail: with no keyring copy to vouch for the identity,
    /// an unreadable key file is a hard error. Silently regenerating would mint
    /// a new identity and orphan the device's history.
    #[test]
    fn unreadable_key_file_without_a_keyring_copy_is_an_error() {
        test_keyring::reset(); // keyring unavailable
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k");
        std::fs::write(&path, b"not hex at all").unwrap();

        let err = load_persisted_secret(&path).unwrap_err();
        assert!(
            matches!(err, TransportError::InvalidKey(_)),
            "expected a decode error, got {err:?}"
        );
    }

    /// The keyring is only an independent copy if the file cannot silently
    /// overwrite it. On disagreement the file still wins as the source of
    /// truth, but the keyring entry has to survive for a human to inspect.
    #[test]
    fn a_disagreeing_keyring_entry_is_never_overwritten_by_the_file() {
        test_keyring::reset();
        test_keyring::set_available(true);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k");

        assert_eq!(
            keyring_mirror(&path, &other_secret()),
            KeyringMirror::Present,
            "seed the keyring with a different identity"
        );
        std::fs::write(&path, hex::encode(sample_secret())).unwrap();

        let loaded = load_persisted_secret(&path).unwrap().unwrap();
        assert_eq!(loaded.as_slice(), &sample_secret(), "the file stays the source of truth");
        assert_eq!(
            keyring_load(&path).unwrap().as_slice(),
            &other_secret(),
            "the keyring copy must survive as an independent anchor"
        );

        test_keyring::reset();
    }

    /// Two daemons starting at once must not both publish an identity: the
    /// loser has to lose the create race and adopt the winner's key, or it
    /// keeps running with a secret that is no longer the one on disk. This is
    /// exactly what publishing with `rename` instead of `hard_link` would break.
    #[test]
    fn publishing_an_identity_never_clobbers_one_that_appeared_first() {
        test_keyring::reset();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k");
        let winner = sample_secret();

        persist_new_secret(&path, &winner).unwrap();

        let err = persist_new_secret(&path, &other_secret()).unwrap_err();
        assert!(
            matches!(&err, TransportError::Io(e) if e.kind() == std::io::ErrorKind::AlreadyExists),
            "the loser must see AlreadyExists so it re-reads the winner's file, got {err:?}"
        );
        assert_eq!(
            read_secret(&path),
            Some(winner),
            "the identity already on disk must be untouched"
        );
        assert!(
            temp_leftovers(dir.path()).is_empty(),
            "a lost race must not strand a temporary file holding a private key"
        );
    }

    /// Loading tightens a key file that predates hardening — the load path's
    /// re-assert has to be real work on unix, not a no-op.
    #[cfg(unix)]
    #[test]
    fn loading_tightens_permissions_on_a_world_readable_key_file() {
        use std::os::unix::fs::PermissionsExt;

        test_keyring::reset();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k");
        std::fs::write(&path, hex::encode(sample_secret())).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        load_persisted_secret(&path).unwrap().unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a loosened key file must be tightened on load");
    }

    /// The parent directory is created on demand, and a bare relative file name
    /// (parent `""`) must not send the temporary file to another filesystem.
    #[test]
    fn creates_missing_parent_directories() {
        test_keyring::reset();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/deeper/k");
        let secret = sample_secret();

        persist_new_secret(&path, &secret).unwrap();

        assert_eq!(read_secret(&path), Some(secret));
        assert!(temp_leftovers(dir.path().join("nested/deeper").as_path()).is_empty());
    }
}

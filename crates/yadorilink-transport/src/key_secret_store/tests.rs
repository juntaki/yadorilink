#![cfg(test)]

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
    assert!(matches!(err, TransportError::InvalidKey(_)), "expected a decode error, got {err:?}");
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
    assert_eq!(read_secret(&path), Some(winner), "the identity already on disk must be untouched");
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

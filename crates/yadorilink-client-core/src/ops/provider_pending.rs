//! The durable retry identity of provider-folder creations, shared by every front end.
//!
//! A creation is identified to the daemon by a request token; the daemon answers a repeat of the same
//! token and request with the folder it already made, and a restart of the CLI or the app between
//! "request sent" and "answer read" must reuse that token or the retry creates a second group. So the
//! pending request is kept on disk: key = a signature of the whole payload, value = the token. It is
//! written BEFORE the request is sent and removed only on a terminal outcome (success, or a
//! definitive rejection); an ambiguous failure (a dropped connection, a timeout) leaves it in place.
//! A different payload is a different request and gets its own token.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

/// Syncs a directory so a rename inside it is durable.
fn sync_directory(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        // A directory cannot be opened for syncing here; the file itself was synced before the rename.
        let _ = dir;
        Ok(())
    }
}

pub(crate) struct PendingStore {
    path: PathBuf,
    /// How the parent directory is made durable (replaced by a failing one in tests).
    sync_parent: fn(&Path) -> io::Result<()>,
}

impl PendingStore {
    pub(crate) fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into(), sync_parent: sync_directory }
    }

    pub(crate) fn default_path() -> PathBuf {
        crate::coordination::device_config::config_dir().join("provider-pending.json")
    }

    /// Runs `body` holding an exclusive lock that every reader-modifier of this store takes, in this
    /// process and in any other (the CLI and the app share one file).
    fn locked<T>(&self, body: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.path.with_extension("json.lock"))?;
        lock.lock()?;
        let result = body();
        let _ = lock.unlock();
        result
    }

    /// The stored map. A missing file is an empty store; a file that cannot be read or parsed is an ERROR,
    /// never an empty store: treating it as empty would mint a second identity for a request whose first
    /// attempt may already have been made.
    fn load(&self) -> io::Result<BTreeMap<String, String>> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("the pending-request file {} is corrupt: {error}", self.path.display()),
                )
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(error) => Err(error),
        }
    }

    /// Replaces the file atomically and durably: a temp file of its own (unique per writer), synced, renamed,
    /// then the parent directory synced. Any failure is an error: the new content is not known to be durable.
    fn save(&self, map: &BTreeMap<String, String>) -> io::Result<()> {
        use std::io::Write;
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let tmp = parent.join(format!(
            ".{}.{}.{}.tmp",
            self.path.file_name().and_then(|n| n.to_str()).unwrap_or("pending"),
            std::process::id(),
            new_token()
        ));
        let written = (|| {
            let mut file = std::fs::File::create(&tmp)?;
            file.write_all(&serde_json::to_vec(map).map_err(io::Error::other)?)?;
            file.sync_all()
        })();
        if let Err(error) = written.and_then(|()| std::fs::rename(&tmp, &self.path)) {
            let _ = std::fs::remove_file(&tmp);
            return Err(error);
        }
        (self.sync_parent)(parent)
    }

    /// The token of the pending request with this payload signature, minted and made durable first if
    /// there is none. An error means the identity could not be read or made durable: the request must
    /// not be sent.
    pub(crate) fn token_for(&self, signature: &str) -> io::Result<String> {
        self.locked(|| {
            let mut map = self.load()?;
            if let Some(token) = map.get(signature) {
                return Ok(token.clone());
            }
            let token = new_token();
            map.insert(signature.to_string(), token.clone());
            self.save(&map)?;
            Ok(token)
        })
    }

    /// The request reached a terminal outcome: forget its identity. A failure leaves the identity in
    /// place, which is safe (a repeat of the same request is answered with what it already made).
    pub(crate) fn clear(&self, signature: &str) {
        let _ = self.locked(|| {
            let mut map = self.load()?;
            if map.remove(signature).is_some() {
                self.save(&map)?;
            }
            Ok(())
        });
    }
}

/// 128 random bits, hex.
fn new_token() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut token = String::new();
    for _ in 0..2 {
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        );
        token.push_str(&format!("{:016x}", hasher.finish()));
    }
    token
}

/// The signature of one creation request: everything that defines it.
pub(crate) fn signature(
    kind: &str,
    group: &str,
    group_name: &str,
    display: &str,
    on_demand: bool,
) -> String {
    format!("{kind}\u{1f}{group}\u{1f}{group_name}\u{1f}{display}\u{1f}{on_demand}")
}

/// Whether a daemon refusal is DEFINITIVE: nothing was created and a retry would be a new request.
pub(crate) fn is_definitive_rejection(error: &crate::CoreError) -> bool {
    use yadorilink_ipc_proto::daemonctl::ApplicationErrorCode as Code;
    matches!(
        error,
        crate::CoreError::DaemonCommand {
            code: Code::PreparationRejected
                | Code::OperationConflict
                | Code::ActivationRejected
                | Code::LocalIdentityUnavailable
                | Code::LocalLinkFailed,
            ..
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(dir: &tempfile::TempDir) -> PendingStore {
        PendingStore::at(dir.path().join("provider-pending.json"))
    }

    /// A restart (a new store over the same file) reuses the token of the same payload; another payload
    /// gets its own; a terminal outcome forgets the identity.
    #[test]
    fn the_token_survives_a_restart_and_is_bound_to_its_payload() {
        let dir = tempfile::tempdir().unwrap();
        let a = signature("create", "", "docs", "Docs", false);
        let b = signature("create", "", "docs", "Other", false);
        let first = store(&dir).token_for(&a).unwrap();
        // "Restart": nothing in memory survives, only the file.
        let after_restart = store(&dir).token_for(&a).unwrap();
        assert_eq!(first, after_restart, "a restart minted a new identity for the same request");
        let other = store(&dir).token_for(&b).unwrap();
        assert_ne!(first, other, "two payloads shared a token");
        store(&dir).clear(&a);
        let fresh = store(&dir).token_for(&a).unwrap();
        assert_ne!(first, fresh, "a finished request kept its identity");
        assert_eq!(store(&dir).token_for(&b).unwrap(), other, "clearing one cleared another");
    }

    /// The identity is durable before the request is sent: if it cannot be written the caller gets an
    /// error and must not send.
    #[test]
    fn an_unwritable_store_refuses_to_mint() {
        let dir = tempfile::tempdir().unwrap();
        let blocked = dir.path().join("file");
        std::fs::write(&blocked, b"x").unwrap();
        let store = PendingStore::at(blocked.join("nested").join("p.json"));
        assert!(store.token_for("sig").is_err());
    }

    /// The CLI and the app share the file: concurrent writers must all keep their tokens.
    #[test]
    fn concurrent_writers_keep_every_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider-pending.json");
        let handles: Vec<_> = (0..24)
            .map(|n| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let sig = signature("create", "", &format!("g{n}"), "D", false);
                    (sig.clone(), PendingStore::at(&path).token_for(&sig).unwrap())
                })
            })
            .collect();
        let minted: Vec<(String, String)> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();
        for (sig, token) in &minted {
            assert_eq!(&PendingStore::at(&path).token_for(sig).unwrap(), token, "a token was lost");
        }
        let distinct: std::collections::BTreeSet<_> = minted.iter().map(|(_, t)| t).collect();
        assert_eq!(distinct.len(), minted.len(), "two requests shared a token");
        assert!(
            std::fs::read_dir(dir.path()).unwrap().all(|e| !e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")),
            "a temp file was left behind"
        );
    }

    /// Racing requests for the SAME payload all get the one token (so a lost response can never
    /// mint a second group), alongside a different payload's own token.
    #[test]
    fn concurrent_requests_for_one_payload_share_one_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider-pending.json");
        let same = signature("create", "", "same", "D", false);
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let (path, same) = (path.clone(), same.clone());
                std::thread::spawn(move || PendingStore::at(&path).token_for(&same).unwrap())
            })
            .collect();
        let other = PendingStore::at(&path)
            .token_for(&signature("create", "", "other", "D", false))
            .unwrap();
        let tokens: std::collections::BTreeSet<String> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(tokens.len(), 1, "racing requests minted different tokens: {tokens:?}");
        assert!(!tokens.contains(&other));
        assert_eq!(
            &PendingStore::at(&path).token_for(&same).unwrap(),
            tokens.iter().next().unwrap()
        );
    }

    /// A store that cannot be read or parsed is an error, never an empty store (which would mint a second
    /// identity for a request that may already have been made), and it is left untouched.
    #[test]
    fn a_corrupt_or_unreadable_store_refuses_and_is_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider-pending.json");
        std::fs::write(&path, b"{ not json").unwrap();
        let error = PendingStore::at(&path).token_for("sig").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("corrupt"), "{error}");
        assert_eq!(std::fs::read(&path).unwrap(), b"{ not json", "a corrupt store was overwritten");
        PendingStore::at(&path).clear("sig");
        assert_eq!(std::fs::read(&path).unwrap(), b"{ not json", "clear overwrote a corrupt store");
        // Unreadable: a directory where the file should be.
        let other = dir.path().join("as-directory.json");
        std::fs::create_dir(&other).unwrap();
        assert!(PendingStore::at(&other).token_for("sig").is_err());
    }

    /// The replacement counts only once the parent directory is synced too: if that fails, the caller
    /// gets an error and must not send.
    #[test]
    fn a_failed_directory_sync_refuses_to_mint() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(&dir);
        store.sync_parent = |_| Err(std::io::Error::other("cannot sync the directory"));
        assert!(store.token_for("sig").is_err());
    }

    #[test]
    fn only_a_definitive_refusal_counts_as_terminal() {
        use yadorilink_ipc_proto::daemonctl::ApplicationErrorCode as Code;
        let command = |code| crate::CoreError::DaemonCommand {
            code,
            message: String::new(),
            group_ids: Vec::new(),
            operation_id: None,
        };
        assert!(is_definitive_rejection(&command(Code::PreparationRejected)));
        // A conflict leaves the operation blocked for good: the same token would block every retry.
        assert!(is_definitive_rejection(&command(Code::OperationConflict)));
        assert!(!is_definitive_rejection(&command(Code::CoordinationAmbiguous)));
        assert!(!is_definitive_rejection(&command(Code::RecoveryPending)));
        assert!(!is_definitive_rejection(&crate::CoreError::DaemonUnresponsive));
    }
}

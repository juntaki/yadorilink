//! Per-`(group_id, path)` weak-referenced lock registry. See
//! [`PathLockRegistry::path_lock`]'s own doc comment for the race it closes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

type PathLockKey = (String, String);
type PathLockMap = HashMap<PathLockKey, Weak<tokio::sync::Mutex<()>>>;

/// [`PathLockRegistry::path_lock`]'s lock-registry key for `path` — see that
/// function's doc comment for why every path is folded rather than only
/// paths on filesystems actually proven case/normalization-insensitive.
/// Delegates to `hazard::canonical_fold` rather than reimplementing an
/// equivalent-looking fold locally (an earlier version of this function
/// computed `nfc(p).to_lowercase()` directly): this must stay the SAME
/// function the hazard checks use, not merely one that happens to agree
/// with them on the cases tried so far, or a future divergence between the
/// two could silently reopen the exact race this key exists to close. In
/// particular, `canonical_fold` is also what
/// `hazard::case_and_normalization_collision` uses, so the lock this
/// function computes and the combined-axis hazard check it must be atomic
/// with can never drift apart from each other by construction.
fn path_lock_fold_key(path: &str) -> String {
    yadorilink_root_authority::canonical_fold::canonical_fold(path)
}

/// per-`(group_id, path)` locks serializing local-change
/// indexing (`LocalChangeProcessor::process_event`) against peer
/// reconciliation (`PeerSyncSession::reconcile_one_file`) for the
/// same path — see `path_lock`'s doc comment for the race this
/// closes. A `HashMap` of per-path `tokio::sync::Mutex` weak references
/// (not a single process-wide lock) means unrelated paths never contend
/// with each other. The registry lazily removes
/// expired entries, so deleted/renamed paths do not accumulate forever
/// while every concurrent user of a live path still shares one lock.
/// `tokio::sync::Mutex` specifically (not
/// `std::sync::Mutex`) because `reconcile_one_file` needs to hold the
/// guard across `.await` points (a block fetch can take real time) —
/// a `std::sync::MutexGuard` isn't `Send`, which broke `tokio::spawn`
/// on the per-connection message-handling task the first time this
/// was tried with a blocking mutex here. The registry map itself
/// (this outer `Mutex`) stays `std::sync::Mutex`: it's only ever held
/// briefly to look up/insert an entry, never across an await.
pub struct PathLockRegistry {
    locks: Mutex<PathLockMap>,
}

impl PathLockRegistry {
    pub fn new() -> Self {
        Self { locks: Mutex::new(HashMap::new()) }
    }

    /// returns the shared lock for `(group_id, path)`, creating it
    /// on first use. Lock it (`.lock.await`) and hold the guard for the
    /// *entire* read-compare-write critical section — re-reading the
    /// current index state after acquiring it, not before — so a local
    /// save (`LocalChangeProcessor::process_event`) and an incoming
    /// peer's newer version for the same path (`PeerSyncSession::
    /// reconcile_one_file`) can never interleave into a state where the
    /// just-saved content is overwritten on disk while the index records
    /// a version/blocks that don't match it (previously reachable: both
    /// paths span multiple independently-locked `SyncState` calls with
    /// no path-level lock at all).
    ///
    /// Keyed on [`path_lock_fold_key`], not the raw path string: two paths
    /// that case-fold or Unicode-normalize to the same logical name
    /// (`Photo.jpg`/`photo.jpg`) must serialize through the SAME lock, not
    /// two different ones. Without this, two concurrent materializations
    /// for such a pair each acquire a different mutex, both pass
    /// `hazard::case_fold_collision`/`normalization_collision` (since
    /// neither yet sees the other in the index), and both then write to
    /// what is physically one file on a case-insensitive or
    /// normalization-insensitive volume — the check exists specifically to
    /// prevent that outcome, and an unfolded lock key let two racing
    /// callers each observe a hazard-free snapshot on their way in.
    /// Deliberately unconditional (not gated on `hazard::is_case_
    /// insensitive_filesystem`/`is_normalization_insensitive_filesystem`
    /// for this specific root): those probes need a real filesystem round
    /// trip and this function has no `root: &Path` in scope at every call
    /// site, whereas folding the key is a pure string operation with no
    /// such dependency; the asymmetry this repo's own review history keeps
    /// landing on (a wrongly-*fine-grained* lock silently corrupts data, a
    /// wrongly-*coarse* one only costs a small amount of otherwise-legal
    /// concurrency between two paths that happen to fold together) makes
    /// "always fold" the correct default here rather than plumbing the
    /// probe through every caller for a rare case.
    pub fn path_lock(&self, group_id: &str, path: &str) -> Arc<tokio::sync::Mutex<()>> {
        let key = (group_id.to_string(), path_lock_fold_key(path));
        let mut locks = self.locks.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
            return lock;
        }

        // A path can disappear permanently after delete/rename. Prune stale
        // weak entries while the short registry lock is already held so a
        // stream of unique paths cannot grow this map without bound.
        locks.retain(|_, lock| lock.strong_count() > 0);
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(key, Arc::downgrade(&lock));
        lock
    }

    #[cfg(test)]
    fn live_lock_count(&self) -> usize {
        self.locks.lock().unwrap().len()
    }

    #[cfg(test)]
    fn contains_key(&self, group_id: &str, folded_path: &str) -> bool {
        self.locks.lock().unwrap().contains_key(&(group_id.to_string(), folded_path.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_lock_reuses_the_same_lock_while_it_is_live() {
        let registry = PathLockRegistry::new();
        let first = registry.path_lock("group-1", "file.txt");
        let second = registry.path_lock("group-1", "file.txt");

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(registry.live_lock_count(), 1);
    }

    /// Two paths that only differ by case must serialize through the SAME
    /// lock, not two independent ones — otherwise two concurrent
    /// materializations for `Photo.jpg`/`photo.jpg` can each acquire a
    /// different mutex, both pass the hazard check (neither yet sees the
    /// other in the index), and both then write to what is physically one
    /// file on a case-insensitive volume.
    #[test]
    fn path_lock_is_shared_across_a_case_only_difference() {
        let registry = PathLockRegistry::new();
        let first = registry.path_lock("group-1", "Photo.jpg");
        let second = registry.path_lock("group-1", "photo.jpg");

        assert!(
            Arc::ptr_eq(&first, &second),
            "Photo.jpg and photo.jpg must share one lock, or a concurrent pair racing the \
             hazard check can both win it"
        );
        assert_eq!(registry.live_lock_count(), 1);
    }

    /// Same property as the case-fold test above, for Unicode
    /// canonical-equivalence instead: two byte-different spellings of one
    /// logical name must not get independent locks either.
    #[test]
    fn path_lock_is_shared_across_a_normalization_only_difference() {
        let registry = PathLockRegistry::new();
        let composed = registry.path_lock("group-1", "caf\u{e9}.txt");
        let decomposed = registry.path_lock("group-1", "cafe\u{301}.txt");

        assert!(
            Arc::ptr_eq(&composed, &decomposed),
            "the composed and decomposed spellings of the same name must share one lock"
        );
        assert_eq!(registry.live_lock_count(), 1);
    }

    /// The lock key must dominate `hazard::case_and_normalization_
    /// collision`'s combined equivalence, not just the two single-axis
    /// checks: a pair differing in BOTH case and normalization at once
    /// (`hazard::canonical_fold`'s own doc comment has the reasoning) must
    /// share one lock exactly as reliably as a pair differing in only one
    /// axis does. `path_lock_fold_key` delegates to `canonical_fold`
    /// itself rather than reimplementing an equivalent-looking fold, so
    /// this is a consistency guarantee by construction -- this test pins
    /// it down as a regression check rather than an implementation detail.
    #[test]
    fn path_lock_is_shared_across_a_combined_case_and_normalization_difference() {
        let composed_upper = "Caf\u{e9}.txt"; // "Café.txt", composed é
        let decomposed_lower = "cafe\u{301}.txt"; // "café.txt", decomposed é

        let registry = PathLockRegistry::new();
        let a = registry.path_lock("group-1", composed_upper);
        let b = registry.path_lock("group-1", decomposed_lower);
        assert!(
            Arc::ptr_eq(&a, &b),
            "a pair differing in both case and normalization at once must still share one lock"
        );
    }

    #[test]
    fn path_lock_registry_prunes_paths_that_are_no_longer_live() {
        let registry = PathLockRegistry::new();
        let old = registry.path_lock("group-1", "deleted.txt");
        let old_weak = Arc::downgrade(&old);
        drop(old);
        assert!(old_weak.upgrade().is_none());

        let _current = registry.path_lock("group-1", "current.txt");
        assert_eq!(registry.live_lock_count(), 1);
        assert!(!registry.contains_key("group-1", "deleted.txt"));
    }
}

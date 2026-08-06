//! Step 2 of the short commit window: "acquire in-memory locks in the same
//! order" as the reservations were taken.
//!
//! # Why a second registry instead of `index::SyncState::path_lock`
//!
//! The crate already has a per-`(group_id, path)` lock registry, and reusing
//! it was the first thing tried. It cannot work here, for two independent
//! reasons:
//!
//! - Its locks are `tokio::sync::Mutex`. Taking one requires `.await`, and
//!   the commit boundary ([`super::orchestrator::run_slice`]) is synchronous
//!   all the way down -- it holds an open SQLite transaction across the
//!   acquisition, which is not a state that can be carried across an await
//!   point in this code. `blocking_lock` is not an escape: it panics when
//!   called from inside a runtime worker thread, which is exactly where the
//!   orchestrator runs.
//! - It hangs off `SyncState`, an index-layer type the transaction engine
//!   has no handle on and deliberately does not depend on.
//!
//! The two registries also protect different things and never need to be the
//! same lock: `SyncState::path_lock` serialises *index record* writes for a
//! path (local-change indexing against peer reconciliation), while this one
//! serialises the *physical placement* window for a path. The authoritative
//! exclusion for the latter is the reservation table, which is durable and
//! cross-process; this registry is the same-process, in-memory half design
//! §6.2 asks for on top of it.
//!
//! # Why the order matters, given the reservation table already excludes
//!
//! Two slices that want the same path cannot both hold reservations for it
//! ([`yadorilink_sync_sqlite::filesystem_transaction::acquire_reservations_in_open_transaction`]
//! refuses the second), so in the ordinary case there is no contention here
//! at all. The ordering rule exists because that argument must not be the
//! only thing standing between the process and a deadlock: locks are taken
//! one at a time while earlier ones are still held, so two callers taking
//! `{a, b}` in opposite orders would deadlock. Sorting by the *same*
//! `path_key` bytes [`acquire_reservations_in_open_transaction`] sorts by
//! makes the acquisition order a function of the path set alone, never of
//! the order the caller happened to list them.
//!
//! Acquisition is bounded rather than indefinite for the same reason: a
//! caller blocked here is blocked while holding an open `BEGIN IMMEDIATE`
//! transaction, so an unexpected cycle must surface as an error the slice
//! can fail on, not as a process that stops making progress with SQLite's
//! only write lock held.

use std::collections::HashSet;
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::Duration;

use crate::sync_error::SyncError;
use yadorilink_sync_sqlite::filesystem_transaction::path_key;

/// How long one path lock may be waited for before the acquisition is
/// declared a fault rather than contention. Generous: the reservation table
/// means a healthy slice never waits here at all.
const ACQUIRE_TIMEOUT_MILLIS: u64 = 30_000;

#[cfg(test)]
thread_local! {
    /// Per-thread, not global: the test binary runs tests in parallel, and a
    /// process-wide override let one test reset the bound out from under
    /// another test that was mid-wait, turning its 50ms expectation into the
    /// 30s default.
    static ACQUIRE_TIMEOUT_MILLIS_OVERRIDE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn acquire_timeout() -> Duration {
    #[cfg(test)]
    {
        let override_millis = ACQUIRE_TIMEOUT_MILLIS_OVERRIDE.with(std::cell::Cell::get);
        if override_millis != 0 {
            return Duration::from_millis(override_millis);
        }
    }
    Duration::from_millis(ACQUIRE_TIMEOUT_MILLIS)
}

/// Shortens the bound above so a test can observe the timeout branch without
/// waiting half a minute. `0` restores the default.
#[cfg(test)]
fn set_acquire_timeout_millis_for_test(millis: u64) {
    ACQUIRE_TIMEOUT_MILLIS_OVERRIDE.with(|c| c.set(millis));
}

/// The lock's identity: the group and the *normalized* [`path_key`] bytes,
/// not the raw path string. Two spellings that `path_key` folds to the same
/// bytes (e.g. `/` and `\` as separators) must contend on the same lock,
/// because that is exactly the identity the reservation layer -- whose
/// ordering this registry exists to mirror -- already uses. Keying by the
/// raw string instead would let two spellings of the same reservation path
/// obtain two different mutexes.
type LockKey = (String, Vec<u8>);

struct Registry {
    held: Mutex<HashSet<LockKey>>,
    released: Condvar,
}

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Registry { held: Mutex::new(HashSet::new()), released: Condvar::new() })
}

/// Every path lock one slice holds, released together on drop.
///
/// Drop order is not part of the contract -- releasing is a set removal, not
/// an unwind of a stack -- but acquisition order is, and
/// [`Self::acquired_order`] exposes it so that property is testable rather
/// than merely asserted in a comment.
///
/// Each entry pairs the lock's real identity ([`LockKey`], normalized) with
/// the original path string as the caller spelled it, kept only so a
/// diagnostic can still name the path a human recognises.
#[derive(Debug)]
pub(crate) struct SlicePathLocks {
    keys: Vec<(LockKey, String)>,
}

impl SlicePathLocks {
    /// The paths this guard took, in the order it took them: ascending by
    /// [`path_key`], the canonical order reservations are acquired in.
    ///
    /// Test-only: the acquisition order is not something a caller has any
    /// business reading, only something a reviewer must be able to see
    /// pinned by an assertion rather than by a comment.
    #[cfg(test)]
    pub(crate) fn acquired_order(&self) -> Vec<&str> {
        self.keys.iter().map(|(_, path)| path.as_str()).collect()
    }
}

impl Drop for SlicePathLocks {
    fn drop(&mut self) {
        let mut held = registry().held.lock().unwrap_or_else(|e| e.into_inner());
        for (key, _) in &self.keys {
            held.remove(key);
        }
        drop(held);
        registry().released.notify_all();
    }
}

/// Takes one in-memory lock per distinct path in `paths`, in canonical
/// `path_key` order, and returns a guard that releases all of them on drop.
///
/// Duplicate paths in `paths` are collapsed: a slice naming the same path
/// twice would otherwise wait on the lock it is itself already holding.
pub(crate) fn lock_slice_paths(
    group_id: &str,
    paths: &[String],
) -> Result<SlicePathLocks, SyncError> {
    let mut keyed: Vec<(Vec<u8>, String)> = Vec::with_capacity(paths.len());
    for path in paths {
        keyed.push((path_key(path)?, path.clone()));
    }
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    keyed.dedup_by(|a, b| a.0 == b.0);

    // The guard is created empty and grown as each lock is taken, so a
    // failure part-way through still releases whatever was already acquired
    // when the guard drops on the error return below.
    let mut guard = SlicePathLocks { keys: Vec::with_capacity(keyed.len()) };
    for (key_bytes, path) in keyed {
        let key: LockKey = (group_id.to_string(), key_bytes);
        let mut held = registry().held.lock().unwrap_or_else(|e| e.into_inner());
        while held.contains(&key) {
            let (next, timeout) = registry()
                .released
                .wait_timeout(held, acquire_timeout())
                .unwrap_or_else(|e| e.into_inner());
            held = next;
            if timeout.timed_out() && held.contains(&key) {
                return Err(SyncError::InvalidInput(format!(
                    "timed out taking the commit-window path lock for {path:?} in group \
                     {group_id:?}; the reservation table should already have excluded a second \
                     holder, so this is a lock-ordering fault, not contention"
                )));
            }
        }
        held.insert(key.clone());
        drop(held);
        guard.keys.push((key, path));
    }
    Ok(guard)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §6.2 step 2's "in the same order": the order locks are taken is a
    /// function of the path set, not of how the caller listed it. Two slices
    /// that name an overlapping set in opposite orders therefore cannot take
    /// them in opposite orders -- the property that makes the hold-while-
    /// waiting acquisition above deadlock-free.
    #[test]
    fn path_locks_are_taken_in_canonical_order_whatever_order_the_caller_lists_them() {
        let ascending = ["a.txt".to_string(), "m/b.txt".to_string(), "z.txt".to_string()];
        let descending = ["z.txt".to_string(), "m/b.txt".to_string(), "a.txt".to_string()];

        let forward = lock_slice_paths("g", &ascending).unwrap();
        let forward_order: Vec<String> =
            forward.acquired_order().into_iter().map(str::to_string).collect();
        drop(forward);

        let backward = lock_slice_paths("g", &descending).unwrap();
        let backward_order: Vec<String> =
            backward.acquired_order().into_iter().map(str::to_string).collect();
        drop(backward);

        assert_eq!(
            forward_order, backward_order,
            "two slices naming the same paths in opposite orders must still take the locks in \
             one order"
        );
        assert_eq!(forward_order, vec!["a.txt", "m/b.txt", "z.txt"]);
    }

    /// The ordering above is the reservation table's ordering, not a second
    /// one that happens to agree on this example. Sorting by `path_key`
    /// rather than by the path string is observable: `path_key` separates
    /// segments with a byte below `/`, so a directory sorts before a sibling
    /// file whose name merely extends it.
    #[test]
    fn path_lock_order_is_the_reservation_orders_key_not_the_raw_string() {
        // `path_key` terminates each segment with `0x00`, so `m/b.txt`
        // encodes as `m\0b.txt\0` and sorts BEFORE `m.txt`'s `m.txt\0` --
        // the opposite of the two paths' plain string order, where `.`
        // (0x2E) precedes `/` (0x2F). The literal below is therefore only
        // reachable by sorting on the reservation table's own key.
        let paths = ["m.txt".to_string(), "m/b.txt".to_string()];
        let locks = lock_slice_paths("g", &paths).unwrap();
        assert!("m.txt" < "m/b.txt", "the two orders really do disagree here");
        assert_eq!(locks.acquired_order(), vec!["m/b.txt", "m.txt"]);
    }

    #[test]
    fn a_path_named_twice_in_one_slice_is_locked_once() {
        let paths = ["dup.txt".to_string(), "dup.txt".to_string()];
        let locks = lock_slice_paths("g", &paths).unwrap();
        assert_eq!(locks.acquired_order(), vec!["dup.txt"]);
    }

    #[test]
    fn the_same_path_in_two_groups_is_two_independent_locks() {
        let first = lock_slice_paths("group-a", &["shared.txt".to_string()]).unwrap();
        let second = lock_slice_paths("group-b", &["shared.txt".to_string()]).unwrap();
        assert_eq!(first.acquired_order(), vec!["shared.txt"]);
        assert_eq!(second.acquired_order(), vec!["shared.txt"]);
    }

    fn is_held(group_id: &str, path: &str) -> bool {
        registry().held.lock().unwrap().contains(&(group_id.to_string(), path_key(path).unwrap()))
    }

    #[test]
    fn dropping_a_guard_releases_every_path_it_held() {
        let paths = ["release-x.txt".to_string(), "release-y.txt".to_string()];
        let locks = lock_slice_paths("g", &paths).unwrap();
        assert!(is_held("g", "release-x.txt") && is_held("g", "release-y.txt"));
        drop(locks);
        assert!(!is_held("g", "release-x.txt"));
        assert!(!is_held("g", "release-y.txt"));

        // Re-takeable, which is the observable half of "released".
        let again = lock_slice_paths("g", &paths).unwrap();
        assert_eq!(again.acquired_order().len(), 2);
    }

    /// A second holder really is excluded, not merely recorded, and a wait
    /// that cannot be satisfied ends as an error rather than as a process
    /// that stops making progress while holding SQLite's write lock. The
    /// second acquisition is made from this same thread deliberately: the
    /// registry is not re-entrant, and a caller that has already taken a
    /// path's lock must not be handed it twice.
    #[test]
    fn a_second_acquisition_of_a_held_path_is_refused_rather_than_granted() {
        set_acquire_timeout_millis_for_test(50);
        let held = lock_slice_paths("g", &["contended.txt".to_string()]).unwrap();

        let second = lock_slice_paths("g", &["contended.txt".to_string()]);
        assert!(
            matches!(second, Err(SyncError::InvalidInput(ref m)) if m.contains("contended.txt")),
            "a path already locked must not be handed to a second slice, got {second:?}"
        );

        drop(held);
        // And once released it is available again, so the refusal above was
        // exclusion and not a permanently poisoned key.
        let after = lock_slice_paths("g", &["contended.txt".to_string()]).unwrap();
        assert_eq!(after.acquired_order(), vec!["contended.txt"]);
        drop(after);
        set_acquire_timeout_millis_for_test(0);
    }

    /// Two spellings of the same path that `path_key` normalizes to the same
    /// bytes must contend on the SAME lock, because that is the identity the
    /// reservation layer already treats them as sharing. `/` and `\` are both
    /// treated as path separators by `normalized_reservation_segments`
    /// unconditionally -- not behind `cfg(windows)` -- so `"spelled/b.txt"`
    /// and `"spelled\\b.txt"` produce identical `path_key` bytes on every
    /// platform this crate builds for. If the registry instead keyed by the
    /// raw string (the defect this test guards against), the second
    /// acquisition below would succeed immediately instead of contending,
    /// because the two spellings would be treated as two different paths.
    #[test]
    fn two_spellings_that_normalize_to_the_same_key_contend_on_one_lock() {
        assert_eq!(
            path_key("spelled/b.txt").unwrap(),
            path_key("spelled\\b.txt").unwrap(),
            "the two spellings below must genuinely normalize together, or this test is theatre"
        );

        set_acquire_timeout_millis_for_test(50);
        let held = lock_slice_paths("g", &["spelled/b.txt".to_string()]).unwrap();

        let second = lock_slice_paths("g", &["spelled\\b.txt".to_string()]);
        assert!(
            matches!(second, Err(SyncError::InvalidInput(_))),
            "a differently-spelled path that normalizes to the same key must be refused as \
             already held, got {second:?}"
        );

        drop(held);
        // Released, so re-takeable under the ORIGINAL spelling too -- the
        // same identity, not two independent keys that happen to collide
        // once.
        let after = lock_slice_paths("g", &["spelled/b.txt".to_string()]).unwrap();
        drop(after);
        set_acquire_timeout_millis_for_test(0);
    }

    /// A failure part-way through a multi-path acquisition must not leave
    /// the earlier paths locked forever -- the guard is grown as it goes and
    /// dropped on the error return.
    #[test]
    fn a_partial_acquisition_releases_the_locks_it_had_already_taken() {
        set_acquire_timeout_millis_for_test(50);
        let blocker = lock_slice_paths("g", &["partial-z.txt".to_string()]).unwrap();

        let attempt =
            lock_slice_paths("g", &["partial-a.txt".to_string(), "partial-z.txt".to_string()]);
        assert!(matches!(attempt, Err(SyncError::InvalidInput(_))));
        assert!(
            !is_held("g", "partial-a.txt"),
            "the lock taken before the failing one must not be left held"
        );

        drop(blocker);
        set_acquire_timeout_millis_for_test(0);
    }
}

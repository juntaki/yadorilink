//! Owns this device's live per-link runtime state: which links currently
//! have a running watcher/executor/repair task set, the notification
//! primitive `stop_link_watch`/`start_link_watch` use to coordinate
//! concurrent transitions on the same path, the per-path locks serializing
//! overlapping `stop_link_watch` calls, and which links are currently
//! degraded by disk pressure. All four fields are private -- every caller
//! reaches them through this type's own methods.
//!
//! `LinkSlot` and the `StartingReservation` RAII guard live here too now
//! (moved from `link_runtime.rs`) -- they are this registry's own internal
//! coordination state, not `LinkRuntime`'s. `link_runtime.rs` depends on
//! this module (for `LinkRegistry`/`DrainedLink`), never the reverse.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::error::DaemonError;
use crate::link_runtime::LinkRuntime;

/// A `LinkRegistry` entry: either a start attempt in progress (nothing to
/// serve yet, but a real, visible placeholder — see [`StartingReservation`]'s
/// own doc for the race this closes) or a fully published, running link.
enum LinkSlot {
    Starting,
    Ready(Arc<LinkRuntime>),
}

/// RAII reservation for a `LinkSlot::Starting` entry, held for
/// `start_link_watch_inner`'s whole fallible setup.
///
/// Closes a start-vs-stop race `LinkRuntime`'s single-atomic-insert design
/// does not, on its own, prevent: before this guard existed,
/// `start_link_watch_inner` published nothing into the registry until every
/// fallible step had already succeeded, so a concurrent `stop_link_watch`
/// (or `control_socket::unlink`, which calls it) for the SAME path arriving
/// mid-start-attempt would find nothing, return immediately, and `unlink`
/// would go on to delete the link's DB row — only for the still-running
/// start attempt to finish moments later and publish a live `LinkRuntime`
/// for a link whose database row no longer exists, a genuine zombie:
/// watching, indexing, and broadcasting for a link `SyncState` itself no
/// longer knows about.
///
/// Reserving `Starting` as the very first step (`reserve_starting`, before
/// any other fallible work, including `begin_group_startup`) makes the
/// start attempt visible immediately, so `stop_link_watch` waits for it
/// (via `wait_and_take_ready`) instead of racing past it. Reservation
/// itself fails if an entry (starting OR ready) already exists for this
/// path -- two concurrent start attempts for the same path is a real shape
/// (a retried `link` control-socket call) that must refuse the second, not
/// let it clobber the first's slot.
pub(crate) struct StartingReservation {
    registry: Arc<LinkRegistry>,
    local_path: String,
    resolved: bool,
}

impl StartingReservation {
    /// Success path: replaces the `Starting` reservation with the fully
    /// built runtime, in one atomic map operation, and wakes any
    /// `stop_link_watch` call waiting on this path's slot to resolve.
    pub(crate) fn publish(mut self, runtime: Arc<LinkRuntime>) {
        self.registry.publish_ready(&self.local_path, runtime);
        self.resolved = true;
    }
}

impl Drop for StartingReservation {
    fn drop(&mut self) {
        if !self.resolved {
            // Every fallible step in `start_link_watch_inner` returns via
            // `?` on failure, unwinding straight past `publish` -- this is
            // the failure path's cleanup, symmetric with `GroupStartup
            // ReadyGuard`'s identical "explicit success call defuses a
            // fail-closed Drop" shape.
            self.registry.remove_starting_reservation(&self.local_path);
        }
    }
}

/// One drained entry from [`LinkRegistry::drain_for_shutdown`] -- a plain,
/// public shape so callers outside this module (whole-process shutdown)
/// never need to know about the private `LinkSlot` enum.
pub(crate) enum DrainedLink {
    Starting { local_path: String },
    Ready { local_path: String, runtime: Arc<LinkRuntime> },
}

/// A linked folder's Degraded (disk-pressure) state -- in-memory only,
/// deliberately not persisted (mirrors `paused_paths`'s "transient"
/// rationale): it's re-derived from live disk state on the very next
/// preflight/re-check either way, so persisting it across a restart would
/// only risk it going stale.
#[derive(Debug, Clone)]
pub struct DegradedLinkInfo {
    /// Human-readable cause (the triggering `SyncError::DiskPressure`'s
    /// `Display`), shown by `yadorilink status`.
    pub reason: String,
    pub since_unix: i64,
    /// how many consecutive re-checks have found the link still
    /// under pressure -- drives `BackoffConfig::DEGRADED_LINK_RECHECK`'s
    /// increasing interval. `0` for a link that just became degraded.
    pub backoff_attempt: u32,
    pub next_recheck_unix: i64,
}

pub struct LinkRegistry {
    /// local_path -> that link's single runtime record: `Starting`
    /// (published as soon as `start_link_watch` commits to bringing the
    /// link up, before any fallible step runs, so a racing
    /// `stop_link_watch` can see it and wait rather than finding nothing),
    /// replaced by `LinkSlot::Ready` once every fallible step has
    /// succeeded, and removed as a single entry by `stop_link_watch`.
    link_runtimes: Mutex<HashMap<String, LinkSlot>>,
    /// Notified whenever a `link_runtimes` entry transitions. A single,
    /// device-wide `Notify` rather than one per path: contention is a
    /// `stop_link_watch` call finding a `Starting` entry it must wait out,
    /// which is rare (link start is fast) and self-limiting, so the cost
    /// of every waiter re-checking its own path on every transition
    /// anywhere is not worth a per-path map's bookkeeping.
    link_lifecycle_notify: tokio::sync::Notify,
    /// local_path -> a lock serializing concurrent `stop_link_watch` calls
    /// for that same path. An `async` lock, not `std::sync::Mutex`: held
    /// across `stop_link_watch`'s own awaits. Entries are never removed (a
    /// link's local_path is reused across relink/unlink cycles, and a
    /// small number of long-lived per-path locks is not worth the
    /// bookkeeping to prune).
    link_watch_stop_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// local_path -> Degraded (disk-pressure) state for that link.
    degraded_links: Mutex<HashMap<String, DegradedLinkInfo>>,
}

impl LinkRegistry {
    pub(crate) fn new() -> Self {
        Self {
            link_runtimes: Mutex::new(HashMap::new()),
            link_lifecycle_notify: tokio::sync::Notify::new(),
            link_watch_stop_locks: Mutex::new(HashMap::new()),
            degraded_links: Mutex::new(HashMap::new()),
        }
    }

    fn lock_runtimes(&self) -> std::sync::MutexGuard<'_, HashMap<String, LinkSlot>> {
        self.link_runtimes.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn lock_degraded(&self) -> std::sync::MutexGuard<'_, HashMap<String, DegradedLinkInfo>> {
        self.degraded_links.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    // --- link_runtimes / lifecycle -----------------------------------

    /// Reserves `local_path` as `Starting`, the very first step of
    /// `start_link_watch_inner`'s fallible setup -- `Err` if any entry
    /// (`Starting` or `Ready`) already exists for this path. `registry`
    /// must be the same `Arc<LinkRegistry>` the caller holds (typically
    /// `Arc::clone(&state.links)`); the returned guard clones it so it can
    /// resolve itself on `publish`/`Drop` without needing `DaemonState`.
    pub(crate) fn reserve_starting(
        registry: &Arc<LinkRegistry>,
        local_path: String,
    ) -> Result<StartingReservation, DaemonError> {
        let mut map = registry.lock_runtimes();
        if map.contains_key(&local_path) {
            return Err(DaemonError::Config(format!(
                "a watch is already starting or running for {local_path}"
            )));
        }
        map.insert(local_path.clone(), LinkSlot::Starting);
        drop(map);
        Ok(StartingReservation { registry: Arc::clone(registry), local_path, resolved: false })
    }

    /// Replaces a `Starting` reservation with the fully built runtime and
    /// wakes every `stop_link_watch` call waiting on this path's slot to
    /// resolve. Only called by [`StartingReservation::publish`].
    fn publish_ready(&self, local_path: &str, runtime: Arc<LinkRuntime>) {
        self.lock_runtimes().insert(local_path.to_string(), LinkSlot::Ready(runtime));
        self.link_lifecycle_notify.notify_waiters();
    }

    /// Removes a `Starting` reservation (the failure path of
    /// [`StartingReservation`]'s `Drop`) and wakes any waiter.
    fn remove_starting_reservation(&self, local_path: &str) {
        self.lock_runtimes().remove(local_path);
        self.link_lifecycle_notify.notify_waiters();
    }

    /// The live runtime for `local_path`, if its slot is `Ready` -- `None`
    /// for `Starting` or absent alike (nothing to act on yet either way).
    pub fn runtime(&self, local_path: &str) -> Option<Arc<LinkRuntime>> {
        match self.lock_runtimes().get(local_path) {
            Some(LinkSlot::Ready(runtime)) => Some(runtime.clone()),
            Some(LinkSlot::Starting) | None => None,
        }
    }

    /// Whether any entry (`Starting` or `Ready`) exists for `local_path`.
    pub fn has_entry(&self, local_path: &str) -> bool {
        self.lock_runtimes().contains_key(local_path)
    }

    /// Waits out a `Starting` entry rather than treating it as absent (see
    /// [`StartingReservation`]'s own doc for the zombie-runtime race this
    /// closes), then removes and returns the `Ready` runtime, if any.
    /// Panics if the slot is somehow still `Starting` once the wait loop
    /// exits -- provably unreachable, since nothing between this method's
    /// own observation and its own removal can turn a `Ready` entry back
    /// into `Starting` (`reserve_starting` refuses a path that already
    /// has any entry), and callers serialize concurrent calls for the same
    /// path via [`Self::stop_lock`] before calling this.
    pub async fn wait_and_take_ready(&self, local_path: &str) -> Option<Arc<LinkRuntime>> {
        loop {
            let notified = self.link_lifecycle_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let is_starting =
                matches!(self.lock_runtimes().get(local_path), Some(LinkSlot::Starting));
            if is_starting {
                notified.await;
                continue;
            }
            break;
        }
        match self.lock_runtimes().remove(local_path) {
            None => None,
            Some(LinkSlot::Ready(runtime)) => Some(runtime),
            Some(LinkSlot::Starting) => {
                unreachable!(
                    "wait_and_take_ready: {local_path} was Ready and is now Starting again"
                )
            }
        }
    }

    /// Removes `local_path`'s entry unconditionally, returning the runtime
    /// only if it was `Ready` -- used by best-effort teardown paths that
    /// don't need `wait_and_take_ready`'s Starting-aware wait (e.g. a test
    /// harness tearing down between seeds).
    pub fn remove_if_ready(&self, local_path: &str) -> Option<Arc<LinkRuntime>> {
        match self.lock_runtimes().remove(local_path) {
            Some(LinkSlot::Ready(runtime)) => Some(runtime),
            _ => None,
        }
    }

    /// Drains every entry, for whole-process shutdown -- each link's
    /// runtime (or in-flight `Starting` reservation) is handed to the
    /// caller to shut down independently and concurrently. Returns
    /// [`DrainedLink`], not the private `LinkSlot`, so shutdown code
    /// outside this module never needs to know that type exists.
    pub(crate) fn drain_for_shutdown(&self) -> Vec<DrainedLink> {
        self.lock_runtimes()
            .drain()
            .map(|(local_path, slot)| match slot {
                LinkSlot::Starting => DrainedLink::Starting { local_path },
                LinkSlot::Ready(runtime) => DrainedLink::Ready { local_path, runtime },
            })
            .collect()
    }

    /// The per-path lock serializing concurrent `stop_link_watch` calls
    /// for `local_path`, creating one if this is the first call for it.
    pub fn stop_lock(&self, local_path: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.link_watch_stop_locks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(local_path.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    // --- degraded_links -------------------------------------------------

    /// Marks `local_path` Degraded (disk-pressure), scheduling its next
    /// re-check via `recheck_delay_secs` -- a link already degraded has its
    /// backoff attempt count bumped (spacing repeated pressure further
    /// apart) rather than reset, and keeps its original `since_unix` onset
    /// time. `recheck_delay_secs` takes the (possibly bumped) backoff
    /// attempt and returns how many seconds from now the next re-check is
    /// due, keeping the backoff policy itself in the caller
    /// (`supervise::BackoffConfig`) rather than duplicating it here.
    pub fn mark_degraded(
        &self,
        local_path: &str,
        reason: String,
        now_unix: i64,
        recheck_delay_secs: impl FnOnce(u32) -> i64,
    ) {
        let mut degraded = self.lock_degraded();
        let (since_unix, backoff_attempt) = match degraded.get(local_path) {
            Some(existing) => (existing.since_unix, existing.backoff_attempt + 1),
            None => (now_unix, 0),
        };
        let next_recheck_unix = now_unix + recheck_delay_secs(backoff_attempt);
        degraded.insert(
            local_path.to_string(),
            DegradedLinkInfo { reason, since_unix, backoff_attempt, next_recheck_unix },
        );
    }

    /// Clears `local_path`'s Degraded state, if any -- a no-op if it
    /// wasn't degraded.
    pub fn clear_degraded(&self, local_path: &str) {
        self.lock_degraded().remove(local_path);
    }

    pub fn is_degraded(&self, local_path: &str) -> bool {
        self.lock_degraded().contains_key(local_path)
    }

    pub fn degraded_info(&self, local_path: &str) -> Option<DegradedLinkInfo> {
        self.lock_degraded().get(local_path).cloned()
    }

    /// Every Degraded link whose `next_recheck_unix` has elapsed, as
    /// `(local_path, reason)` pairs -- the re-check sweep's own input.
    pub fn degraded_due_snapshot(&self, now_unix: i64) -> Vec<(String, String)> {
        self.lock_degraded()
            .iter()
            .filter(|(_, info)| info.next_recheck_unix <= now_unix)
            .map(|(path, info)| (path.clone(), info.reason.clone()))
            .collect()
    }

    /// Test/harness-only: forces `local_path`'s next re-check to be due
    /// immediately, so a test doesn't have to wait out a real backoff
    /// window.
    #[cfg(test)]
    pub(crate) fn force_degraded_recheck_due_now(&self, local_path: &str, now_unix: i64) {
        if let Some(info) = self.lock_degraded().get_mut(local_path) {
            info.next_recheck_unix = now_unix - 1;
        }
    }
}

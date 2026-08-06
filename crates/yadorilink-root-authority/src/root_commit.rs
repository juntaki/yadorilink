//! `RootLease`/`LinkOperation`: the capability every daemon-originated local
//! filesystem/index/DAG/materialization-state mutation must hold, and the
//! RAII guard that proves it for an operation's *whole* duration.
//!
//! # Why a held guard, not a momentary check
//!
//! An earlier version of this module defined a `RootAuthority` trait with a
//! single `fn verify(&self) -> Result<(), RootAuthorityError>` method, and
//! `RootCommitPermit::verify()` simply called it. That is a **check**, not a
//! **lease**: nothing stopped a caller from calling `verify()`, getting
//! `Ok`, and then taking real, unbounded time (a multi-block filesystem
//! reconstruct, a chunked scan) before its actual commit — during which
//! `stop_link_watch`'s `wait_drained` could observe no admitted operation
//! (the daemon-side `RootAuthority` impl minted and dropped its own
//! admission guard *inside* `verify()`, immediately, not for the caller's
//! whole operation) and proceed to release the sync-root OS lock while the
//! caller's write was still in flight. This is precisely K15's shape,
//! reopened by a check-based design no matter how many call sites call it.
//!
//! `RootLease`/`LinkOperation` closes this structurally: [`RootLease::
//! begin_operation`] returns a [`LinkOperation`] the caller MUST hold from
//! before its first filesystem write through its last DB/DAG commit — not
//! drop immediately. [`RootCommitPermit`] can only be constructed from a
//! live `&LinkOperation` ([`LinkOperation::permit`]), so a caller with a
//! permit in hand is, by construction (the borrow checker, not a runtime
//! check), still holding the same admission slot `wait_drained` waits to
//! drain. There is no way to call `.verify()` on a permit whose backing
//! `LinkOperation` has already dropped: that permit cannot exist.
//!
//! # Who owns a lease
//!
//! This crate defines `RootLease` and owns its mechanism (the
//! [`crate::sync_root_lock::SyncRootLock`] it wraps, and its own
//! stop/drain gate), but a lease's *lifecycle* — when a link starts, stops,
//! or restarts, i.e. when an `Arc<RootLease>` is actually constructed and
//! handed to callers — is `yadorilink-daemon`'s `link_manager` territory.
//! One `RootLease` is constructed per link, immediately after that link's
//! `SyncRootLock` is acquired, and shared (via `Arc`) by every subsystem
//! that mutates through this link: the local-change processor, the peer
//! session (through an injected per-group lookup), the periodic and
//! startup repair passes, the targeted-flush handle, and the disk-reconcile
//! backstop sweep. `stop_link_watch`/`graceful_shutdown` call
//! [`RootLease::begin_stopping`] then await [`RootLease::wait_drained`]
//! before dropping the lease (and, with it, the `SyncRootLock` — releasing
//! the OS-level lock only once every in-flight `LinkOperation` has
//! genuinely finished).
//!
//! Test code that has no real link lifecycle uses [`RootCommitPermit::
//! for_tests`], which is backed by one process-lifetime, always-succeeding
//! `RootLease`/`LinkOperation` pair. This is deliberately NOT reachable
//! from non-test code: there is no production code path that can construct
//! a permit without going through a real `RootLease::begin_operation`.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

use tokio::sync::Notify;

use crate::error::RootAuthorityError;
use crate::sync_root_lock::SyncRootLock;

/// One linked folder's root-mutation capability: the `SyncRootLock` proving
/// single-process ownership of this root, this link's group id and startup
/// generation, and the stop/drain gate every [`LinkOperation`] admits
/// through. Shared (`Arc<RootLease>`) by every subsystem that can mutate
/// this link's filesystem/index/DAG/materialization state — see this
/// module's own doc for the full list.
pub struct RootLease {
    /// `None` only for [`RootLease::for_tests`] — see that constructor's
    /// own doc for why test code has no real `SyncRootLock` to hold.
    root_lock: Option<SyncRootLock>,
    group_id: String,
    generation: u64,
    stopping: AtomicBool,
    active: AtomicI64,
    notify: Notify,
}

impl RootLease {
    /// Constructs a lease around an already-acquired `SyncRootLock`. Callers
    /// (`yadorilink-daemon::link_manager::start_link_watch_inner`) acquire
    /// the lock first and pass it in here immediately — there is no
    /// constructor that lets production code skip having a real lock.
    pub fn new(root_lock: SyncRootLock, group_id: String, generation: u64) -> Self {
        Self {
            root_lock: Some(root_lock),
            group_id,
            generation,
            stopping: AtomicBool::new(false),
            active: AtomicI64::new(0),
            notify: Notify::new(),
        }
    }

    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn root(&self) -> Option<&Path> {
        self.root_lock.as_ref().map(SyncRootLock::root)
    }

    /// Admits one operation unless this lease is already stopping, and
    /// re-verifies the underlying `SyncRootLock` still names the same
    /// physical object it was acquired against (closes the unlink-and-
    /// recreate root-swap hazard `SyncRootLock::verify_still_owns`'s own
    /// doc describes). The caller MUST hold the returned [`LinkOperation`]
    /// for this operation's whole duration — from before its first
    /// filesystem write through its last DB/DAG commit — not drop it
    /// immediately after admission. Holding it for less than that
    /// reintroduces exactly the gap this module exists to close.
    pub fn begin_operation(&self) -> Result<LinkOperation<'_>, RootAuthorityError> {
        if self.stopping.load(Ordering::SeqCst) {
            return Err(Self::stopping_error(&self.group_id));
        }
        self.active.fetch_add(1, Ordering::SeqCst);
        // Re-check: `begin_stopping` may have run between the load above and
        // this increment. Without this, our own count could make
        // `wait_drained` wait for an operation this call is about to refuse
        // to start.
        if self.stopping.load(Ordering::SeqCst) {
            self.release();
            return Err(Self::stopping_error(&self.group_id));
        }
        if let Some(root_lock) = &self.root_lock {
            if let Err(e) = root_lock.verify_still_owns() {
                self.release();
                return Err(e);
            }
        }
        Ok(LinkOperation { lease: self })
    }

    fn stopping_error(group_id: &str) -> RootAuthorityError {
        RootAuthorityError::NotFound(format!(
            "link for group {group_id} is stopping or stopped; refusing a new root-commit \
             operation"
        ))
    }

    fn release(&self) {
        if self.active.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.notify.notify_waiters();
        }
    }

    /// Refuses every new `begin_operation` call from this point on.
    /// Already-admitted `LinkOperation`s are unaffected and must still be
    /// allowed to finish — see [`RootLease::wait_drained`].
    pub fn begin_stopping(&self) {
        self.stopping.store(true, Ordering::SeqCst);
    }

    /// Waits until every `LinkOperation` admitted before (or racing, per
    /// `begin_operation`'s own re-check) `begin_stopping` has dropped.
    /// Callers must call `begin_stopping` first; awaiting this without
    /// having done so waits for a count that new operations can still keep
    /// nonzero forever.
    pub async fn wait_drained(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            // Technically redundant for `notify_waiters` specifically (a
            // `Notified` future is guaranteed to receive wakeups from
            // `notify_waiters()` as soon as it is created), but costs
            // nothing and keeps this loop correct even if this ever moves
            // to `notify_one`.
            notified.as_mut().enable();
            if self.active.load(Ordering::SeqCst) == 0 {
                return;
            }
            notified.await;
        }
    }

    /// A lease with no real `SyncRootLock`, an always-empty stop/drain gate
    /// starting point, and a stable `"test-group"` id — for tests that
    /// exercise `SyncState`'s own mutation behavior and have no real link
    /// lifecycle to check against. Kept in this crate (not duplicated per
    /// test module) so every test using it shares one obviously-inert
    /// instance. See [`RootCommitPermit::for_tests`] for the ergonomic,
    /// no-ceremony entry point most test code should actually call.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_tests() -> Self {
        Self {
            root_lock: None,
            group_id: "test-group".to_string(),
            generation: 0,
            stopping: AtomicBool::new(false),
            active: AtomicI64::new(0),
            notify: Notify::new(),
        }
    }
}

/// RAII proof of admission against one [`RootLease`], held by its caller
/// for an operation's whole duration. See this module's own doc for why
/// that duration (not a momentary check) is what makes
/// [`RootCommitPermit::verify`] trustworthy.
pub struct LinkOperation<'a> {
    lease: &'a RootLease,
}

impl Drop for LinkOperation<'_> {
    fn drop(&mut self) {
        self.lease.release();
    }
}

impl<'a> LinkOperation<'a> {
    pub fn group_id(&self) -> &str {
        self.lease.group_id()
    }

    pub fn lease(&self) -> &'a RootLease {
        self.lease
    }

    /// Re-verifies root identity right now (one `SyncRootLock::
    /// verify_still_owns` call — cheap, but not free) — for an operation
    /// that itself spans meaningfully long real I/O between `begin_
    /// operation` and its own commit, calling this again immediately
    /// before the commit closes the same unlink-and-recreate window a
    /// single check at admission cannot. `RootCommitPermit::verify` calls
    /// this on the caller's behalf; most callers never need to call it
    /// directly.
    fn reverify(&self) -> Result<(), RootAuthorityError> {
        match &self.lease.root_lock {
            Some(root_lock) => root_lock.verify_still_owns(),
            None => Ok(()),
        }
    }

    /// Mints a [`RootCommitPermit`] borrowing this operation. Cheap to call
    /// repeatedly — every gated `SyncState`/materialization call along this
    /// operation's path takes its own fresh permit from the same held
    /// `LinkOperation`, rather than the permit being stored anywhere.
    pub fn permit(&self) -> RootCommitPermit<'_> {
        RootCommitPermit { op: self }
    }
}

/// A capability proving [`LinkOperation::permit`] was called against a
/// still-live `LinkOperation` — see this module's own doc for why holding
/// one is, by construction, proof of live admission, not merely evidence
/// that admission held at some earlier instant.
pub struct RootCommitPermit<'a> {
    op: &'a LinkOperation<'a>,
}

impl<'a> RootCommitPermit<'a> {
    /// Called by every gated `SyncState`/materialization function, inside
    /// its own write transaction, immediately before commit. Re-verifies
    /// root identity (see `LinkOperation::reverify`'s doc) — NOT a
    /// liveness/fence check, since holding the live `&LinkOperation` this
    /// permit borrows from already IS the fence-liveness proof: the type
    /// system cannot construct this permit from an operation that has
    /// already been dropped (and therefore already released its gate
    /// slot), so there is nothing left for a runtime check to race.
    pub fn verify(&self) -> Result<(), RootAuthorityError> {
        self.op.reverify()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl RootCommitPermit<'static> {
    /// A permit backed by one process-lifetime, always-succeeding
    /// `RootLease`/`LinkOperation` pair — the ergonomic, no-ceremony entry
    /// point for test code that doesn't care about link lifecycle. Every
    /// call shares the SAME leaked `LinkOperation` (constructed exactly
    /// once via `OnceLock`), so this leaks one admission slot for the
    /// whole process rather than one per call.
    pub fn for_tests() -> Self {
        use std::sync::OnceLock;
        static LEASE: OnceLock<RootLease> = OnceLock::new();
        static OPERATION: OnceLock<LinkOperation<'static>> = OnceLock::new();
        let lease = LEASE.get_or_init(RootLease::for_tests);
        let op = OPERATION
            .get_or_init(|| lease.begin_operation().expect("a fresh for_tests lease never stops"));
        op.permit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_tests_permit_always_verifies() {
        assert!(RootCommitPermit::for_tests().verify().is_ok());
    }

    #[test]
    fn an_operation_admitted_before_stopping_is_not_refused_by_a_racing_begin_stopping() {
        let lease = RootLease::for_tests();
        let op = lease.begin_operation().unwrap();
        lease.begin_stopping();
        // The already-admitted operation's permit must still verify -- a
        // caller mid-operation when stop begins must be allowed to finish.
        assert!(op.permit().verify().is_ok());
    }

    #[test]
    fn begin_operation_refuses_once_stopping_has_begun() {
        let lease = RootLease::for_tests();
        lease.begin_stopping();
        assert!(lease.begin_operation().is_err());
    }

    #[tokio::test]
    async fn wait_drained_blocks_until_every_admitted_operation_drops() {
        let lease = RootLease::for_tests();
        let op = lease.begin_operation().unwrap();
        lease.begin_stopping();

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), lease.wait_drained())
                .await
                .is_err(),
            "wait_drained must not resolve while an admitted LinkOperation is still held"
        );
        drop(op);
        tokio::time::timeout(std::time::Duration::from_secs(1), lease.wait_drained())
            .await
            .expect("wait_drained must resolve promptly once the LinkOperation drops");
    }
}

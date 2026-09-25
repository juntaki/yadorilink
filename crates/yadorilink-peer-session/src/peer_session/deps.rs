//! `PeerSyncSession`'s injected capabilities: the ports the daemon (or a
//! test) hands a session at construction through `PeerSyncSessionDeps`, and
//! their deny-by-default / permissive stand-ins.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::rate_limiter::RateLimiters;

/// Lets `reconcile_one_file` ask whether the path it's about to reconcile
/// against a peer's update has a local change still sitting, undispatched,
/// in that link's debounce accumulator (`debounce::run_debouncer`'s
/// `FlushPathRequest` handling) — and if so, force it to flush and be
/// captured into the index *before* `reconcile_one_file`'s version-vector
/// `compare` runs or `materialize` writes to the path, so a peer's write
/// or tombstone for the same path can never race ahead of it. A
/// manually-written `Pin<Box<dyn Future>>`-returning method, not an `async
/// fn`, since this needs to be *dyn*-callable through `Arc<dyn
/// PendingLocalChangeFlush>` — native `async fn` in traits isn't
/// object-safe without this same boilerplate, and this crate has no
/// `async_trait` dependency to hide it behind. Outcome of a targeted
/// local-flush round trip
/// (`PendingLocalChangeFlush::flush_pending_local_change` /
/// `flush_case_fold_sibling`), through this link's debounce-accumulator
/// channel. That channel is small and shared by every concurrent peer
/// message handler reconciling a path against this link — under a
/// duplicate-delivery storm it can back up, so the round trip is bounded
/// rather than awaited unconditionally. `Settled` means the local side is
/// safely accounted for (flushed, or genuinely nothing pending) and the
/// peer change may proceed to DAG admission. `RetryRequired` means this
/// round trip could not complete its bound (the enqueue or the reply timed
/// out) — the local pending edit's state relative to the incoming peer
/// change is unknown, so admitting the peer change now would risk silently
/// clobbering it; the caller must defer this change instead (it will be
/// re-requested by anti-entropy).
///
/// `RetryRequired` also covers a local edit the flush could not capture (a
/// file that changed while it was read, a capture that failed): a caller
/// about to write to the path must not proceed on it.
#[must_use = "a caller about to write to the path must not proceed on RetryRequired"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingLocalFlushOutcome {
    Settled,
    RetryRequired,
}

impl PendingLocalFlushOutcome {
    /// Both guards settled only if each did.
    pub fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::Settled, Self::Settled) => Self::Settled,
            _ => Self::RetryRequired,
        }
    }
}

pub trait PendingLocalChangeFlush: Send + Sync {
    fn flush_pending_local_change<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>>;

    /// Like `flush_pending_local_change`, but for the *other* case-variant
    /// path that would collide with `rel_path` on a case-insensitive
    /// filesystem, rather than `rel_path` itself — see
    /// `PeerSyncSession::flush_case_fold_sibling_before_reconcile`'s doc
    /// comment for why this exists as a separate call.
    fn flush_case_fold_sibling<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>>;

    /// Captures whatever `rel_path` holds on disk right now, its absence
    /// included: like `flush_pending_local_change`, and in addition, when
    /// nothing answers to the path, the deletion of a path the index still
    /// holds live -- without waiting for a watcher event that may not have
    /// been processed yet. For a caller that has established the disk moved
    /// on from a change this device captured and must capture the newer
    /// state rather than project the older one.
    ///
    /// The default captures what `flush_pending_local_change` does, which
    /// leaves a deletion to the watcher.
    fn capture_local_path_state<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>> {
        self.flush_pending_local_change(group_id, rel_path)
    }
}

/// Mirrors `PendingLocalChangeFlush`'s injection shape exactly (see that
/// trait's own doc comment for why this crate needs the daemon to inject
/// per-group lookups like this rather than depending on `yadorilink-daemon`
/// directly), for a different seam: every `SyncState` mutation
/// `PeerSyncSession` makes (peer-driven index/DAG/materialization-state
/// writes) requires a `root_commit::RootCommitPermit`, minted from a
/// `LinkOperation` admitted against the per-link `root_commit::RootLease`
/// this provides for `group_id`. `None` means this device has no live,
/// established link for that group right now -- the caller must treat that
/// exactly like any other "this link isn't available" failure, never
/// synthesize a permissive fallback lease.
pub trait RootCommitAuthorityProvider: Send + Sync {
    fn root_lease_for(
        &self,
        group_id: &str,
    ) -> Option<Arc<yadorilink_root_authority::root_commit::RootLease>>;
}

/// Test-only default installed by [`PeerSyncSessionDeps::test_permissive`]
/// so that the hundreds of existing tests that construct a session and
/// exercise a real mutation path (`materialize`, `hold`, ...) without ever
/// calling `set_root_commit_authority_provider` keep working unchanged --
/// mirroring `RootCommitPermit::for_tests()`'s own "a test that doesn't
/// care about lifecycle shouldn't have to thread one through" rationale.
/// Still goes through a real `RootLease` (just one with no real
/// `SyncRootLock` behind it), so this is not a bypass of the lease
/// mechanism -- a production build has no equivalent default; see the
/// `cfg` at this field's initializer below.
#[cfg(any(test, feature = "test-support"))]
struct AlwaysValidRootCommitAuthorityProvider;

#[cfg(any(test, feature = "test-support"))]
impl RootCommitAuthorityProvider for AlwaysValidRootCommitAuthorityProvider {
    fn root_lease_for(
        &self,
        _group_id: &str,
    ) -> Option<Arc<yadorilink_root_authority::root_commit::RootLease>> {
        Some(Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()))
    }
}

/// Deny-by-default implementation of `RootCommitAuthorityProvider`, used
/// by [`PeerSyncSessionDeps::denied`] as the production-safe
/// default for the `root_commit_authority_provider` one-time dependency --
/// reports no live link for any group, matching what an absent provider
/// used to mean before this field became mandatory-at-construction.
struct DenyRootCommitAuthorityProvider;

impl RootCommitAuthorityProvider for DenyRootCommitAuthorityProvider {
    fn root_lease_for(
        &self,
        _group_id: &str,
    ) -> Option<Arc<yadorilink_root_authority::root_commit::RootLease>> {
        None
    }
}

/// Deny/no-op-by-default implementations of this session's other 5 one-time
/// capability traits, used by [`PeerSyncSessionDeps::denied`]. Each
/// mirrors the wrapper's own private equivalent in `peer_session_public.rs`
/// (`NoopPendingLocalChangeFlush`, `DenyAllChangeAuthenticator`,
/// `DenyHandoffLeaseResponder`, `NoopBlockWriteActivityProvider`, `DenyHandoffTicketResponder`)
/// exactly -- duplicated for the same layering reason as
/// `DenyRootCommitAuthorityProvider` above.
struct DeniedPendingLocalChangeFlush;

impl PendingLocalChangeFlush for DeniedPendingLocalChangeFlush {
    fn flush_pending_local_change<'a>(
        &'a self,
        _group_id: &'a str,
        _rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>> {
        Box::pin(async { PendingLocalFlushOutcome::Settled })
    }

    fn flush_case_fold_sibling<'a>(
        &'a self,
        _group_id: &'a str,
        _rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>> {
        Box::pin(async { PendingLocalFlushOutcome::Settled })
    }
}

struct DeniedChangeAuthenticator;

impl ChangeAuthenticator for DeniedChangeAuthenticator {
    fn resolve_authority_key(
        &self,
        _group_id: &str,
        _signer_key_id: &[u8; 32],
        _policy_head: &[u8; 32],
    ) -> Option<ed25519_dalek::VerifyingKey> {
        None
    }
}

struct DeniedHandoffLeaseResponder;

impl HandoffLeaseResponder for DeniedHandoffLeaseResponder {
    fn request_handoff_lease<'a>(
        &'a self,
        _group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffLeaseGrant>> + Send + 'a>> {
        Box::pin(async { None })
    }

    fn release_handoff_lease<'a>(
        &'a self,
        _group_id: &'a str,
        _lease_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
}

struct DeniedBlockWriteActivityProvider;

impl BlockWriteActivityProvider for DeniedBlockWriteActivityProvider {
    fn begin_block_write_activity(&self) -> Box<dyn Send + '_> {
        Box::new(())
    }
}

struct DeniedHandoffTicketResponder;

impl HandoffTicketResponder for DeniedHandoffTicketResponder {
    fn request_handoff_ticket<'a>(
        &'a self,
        _group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffTicketGrant>> + Send + 'a>> {
        Box::pin(async { None })
    }

    fn release_handoff_ticket<'a>(
        &'a self,
        _group_id: &'a str,
        _target_device_id: &'a str,
        _lease_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
}

/// Everything a session is given that is not its peer, its transport or
/// its storage: the 8 capability injections it routes requests through,
/// and the 4 runtime knobs the daemon sets from shared global state.
///
/// One struct rather than 12 more positional parameters, so a call site
/// that overrides one of them starts from [`Self::standalone`] and uses
/// struct-update syntax instead of repeating all 12.
pub struct PeerSyncSessionDeps {
    pub rate_limiters: Arc<RateLimiters>,
    /// `None` means no serve budget was installed, which
    /// `handle_block_request` treats as fail-closed -- see
    /// `block_serve_engine`'s field doc.
    pub block_serve_engine: Option<Arc<crate::block_serve::BlockServeEngine>>,
    pub pending_local_change_flush: Arc<dyn PendingLocalChangeFlush>,
    pub root_commit_authority_provider: Arc<dyn RootCommitAuthorityProvider>,
    pub change_authenticator: Arc<dyn ChangeAuthenticator>,
    pub handoff_lease_responder: Arc<dyn HandoffLeaseResponder>,
    pub block_write_activity_provider: Arc<dyn BlockWriteActivityProvider>,
    pub handoff_ticket_responder: Arc<dyn HandoffTicketResponder>,
    /// Unlike the other 6 fields, has no universal non-`None` default --
    /// see the `change_emitter` field's own doc comment.
    pub change_emitter: Option<Arc<yadorilink_replica_domain::admission::ChangeEmitter>>,
}

impl Clone for PeerSyncSessionDeps {
    fn clone(&self) -> Self {
        Self {
            rate_limiters: self.rate_limiters.clone(),
            block_serve_engine: self.block_serve_engine.clone(),
            pending_local_change_flush: self.pending_local_change_flush.clone(),
            root_commit_authority_provider: self.root_commit_authority_provider.clone(),
            change_authenticator: self.change_authenticator.clone(),
            handoff_lease_responder: self.handoff_lease_responder.clone(),
            block_write_activity_provider: self.block_write_activity_provider.clone(),
            handoff_ticket_responder: self.handoff_ticket_responder.clone(),
            change_emitter: self.change_emitter.clone(),
        }
    }
}

impl PeerSyncSessionDeps {
    /// Fail-closed/no-op defaults for every capability, and unlimited /
    /// default values for the knobs. `change_emitter` stays `None`: a
    /// device with no signing key must retain rather than author, so
    /// absence is its only safe default.
    ///
    /// Network-facing capabilities that need daemon or coordination-plane
    /// state deny requests; bookkeeping hooks with no standalone owner are
    /// no-ops. Nothing is represented by absence.
    pub fn standalone() -> Self {
        const GIB: u64 = 1024 * 1024 * 1024;
        Self {
            rate_limiters: Arc::new(RateLimiters::unlimited()),
            block_serve_engine: Some(crate::block_serve::BlockServeEngine::new(
                64 * GIB,
                16 * GIB,
                32 * GIB,
                64,
            )),
            pending_local_change_flush: Arc::new(DeniedPendingLocalChangeFlush),
            root_commit_authority_provider: Arc::new(DenyRootCommitAuthorityProvider),
            change_authenticator: Arc::new(DeniedChangeAuthenticator),
            handoff_lease_responder: Arc::new(DeniedHandoffLeaseResponder),
            block_write_activity_provider: Arc::new(DeniedBlockWriteActivityProvider),
            handoff_ticket_responder: Arc::new(DeniedHandoffTicketResponder),
            change_emitter: None,
        }
    }

    /// [`Self::standalone`] with no block-serve budget installed, which
    /// makes `handle_block_request` fail closed. The shape a caller
    /// constructing a session directly against this module -- with no
    /// device-wide serve engine to share -- gets.
    pub fn denied() -> Self {
        Self { block_serve_engine: None, ..Self::standalone() }
    }

    /// Like [`Self::denied`], but with `root_commit_authority_provider`
    /// replaced by the permissive [`AlwaysValidRootCommitAuthorityProvider`]
    /// -- the permissive behaviour tests want when they only need to
    /// override one of the other fields.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_permissive() -> Self {
        Self {
            root_commit_authority_provider: Arc::new(AlwaysValidRootCommitAuthorityProvider),
            ..Self::denied()
        }
    }
}

/// A target device's answer to its own `HandoffLeaseResponder`, carrying
/// exactly what the service-RPC lane's `HandoffLease` response needs: the
/// coordination-plane-issued lease id, the digest of the durability-root set
/// the target actually verified and pinned against that lease, and its
/// expiry. Kept as a plain struct here (rather than depending on a wire
/// type directly) so `HandoffLeaseResponder` implementors don't need to
/// reason about wire framing, mirroring how `request_version_present`'s own
/// `bool` return keeps its callers wire-free.
#[derive(Debug, Clone)]
pub struct PeerHandoffLeaseGrant {
    pub lease_id: String,
    /// This device's own durability-roots digest: the 32-byte SHA-256 over
    /// the sorted `(path, change::VersionHash)` set of every durability root
    /// it retains — the same digest a source-side readiness check computes.
    pub root_digest: [u8; 32],
    pub expires_at_unix: i64,
}

/// Returns `None` when this device could not obtain a live lease this
/// round (its own readiness check failed, it has no coordination-plane
/// config, the coordination-plane request itself failed, or the atomic
/// local pin aborted) — the responder answers the peer `granted = false`
/// in every one of those cases, exactly as if the request had never been
/// understood at all, never distinguishing the reason over the wire.
pub trait HandoffLeaseResponder: Send + Sync {
    fn request_handoff_lease<'a>(
        &'a self,
        group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffLeaseGrant>> + Send + 'a>>;

    fn release_handoff_lease<'a>(
        &'a self,
        group_id: &'a str,
        lease_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

/// Caller-injected guard factory that lets a session serialize creation of
/// new block references with daemon-level physical deletion.
pub trait BlockWriteActivityProvider: Send + Sync {
    fn begin_block_write_activity(&self) -> Box<dyn Send + '_>;
}

/// A device's answer to its own `HandoffTicketResponder`, carrying exactly
/// what the service-RPC lane's `HandoffTicket` response needs. Unlike
/// `PeerHandoffLeaseGrant`, there is no `root_digest` here: the requester
/// (the operating device removing/revoking this one) has no root set of its
/// own to compare against -- it trusts `granted` as this device's own
/// authenticated attestation of ITS OWN roots. `lease_id`/`target_device_id`
/// are both `None` when the device's root set was empty (vacuously ready --
/// nothing to hand off), and both `Some` otherwise: `target_device_id` is
/// the confirming peer (C) the lease was obtained from, which the operating
/// device must present alongside `lease_id` to the coordination plane's
/// lease-guarded role-loss commit -- a lease id alone does not identify
/// which `(group, target)` pair to atomically re-verify it against.
#[derive(Debug, Clone)]
pub struct PeerHandoffTicketGrant {
    pub lease_id: Option<String>,
    pub target_device_id: Option<String>,
    pub expires_at_unix: i64,
}

/// Lets a `PeerSyncSession` answer an incoming `HandoffTicketRequest` by
/// bridging to the daemon's own removed-device-ticket machinery
/// (`DaemonState::obtain_own_handoff_ticket`), the same caller-injected
/// trait-object shape as `HandoffLeaseResponder` above and for the same
/// reason. Returns `None` when this device could not obtain a live lease
/// for its own root set this round (no confirming peer holds its whole
/// root set, its own coordination-plane request failed, etc.) -- the
/// responder answers the peer `granted = false` in every one of those
/// cases, exactly as `HandoffLeaseResponder` already does.
pub trait HandoffTicketResponder: Send + Sync {
    fn request_handoff_ticket<'a>(
        &'a self,
        group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffTicketGrant>> + Send + 'a>>;

    fn release_handoff_ticket<'a>(
        &'a self,
        group_id: &'a str,
        target_device_id: &'a str,
        lease_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

/// Whether `incoming` might
/// actually need `reconcile_one_file`'s real, `path_lock`-guarded
/// read-compare-write, given `prefetched_local` — a *possibly stale*
/// snapshot of this device's local record for the same path, taken by one
/// batched `SyncState::get_files_by_paths` call before any `path_lock` is
/// acquired for this batch (`reconcile_files`).
///
/// `None` (no local record was found for this path at prefetch time)
/// always returns `true`: either this path is genuinely new, or a
/// concurrent local save created it after the prefetch ran — either way,
/// only the real locked path can tell which, so this never guesses.
///
/// `Some(local)` returns `false` (safe to skip) only when `local`'s
/// version already dominates `incoming`'s (`Equal` or `After` — "we've
/// already seen this exact version, or something newer"). This is safe
/// even though `local` may be stale by the time this runs, because a
/// `VersionVector` only ever grows monotonically (`increment`/`merge`,
/// see `version_vector.rs` — no operation ever decreases a counter): if a
/// *stale* local snapshot already dominates `incoming`, the *true,
/// current* local version — being component-wise greater-than-or-equal
/// to that stale snapshot — must dominate it too. So a skip decided here
/// can only ever be correct; the reverse (skipping a record that a fresh
/// read would have shown actually needs adopting or conflict-resolving)
/// is not reachable. Any other prefetched ordering (`Before` or
/// `Concurrent`) conservatively falls through to the real locked path,
/// exactly as if no batching happened at all.
/// Supplies the ONE piece of trust material peer-to-peer authorization
/// verification needs that this crate cannot compute itself: resolving
/// which authority key was valid, for a group, at a specific historical
/// policy point. Everything else `authorization_checkpoint::
/// verify_change_admission` needs (the author's raw signing key, the
/// checkpoint, the Merkle proof) travels self-contained on the wire with
/// the `PublishedChange` itself. Policy-chain verification is netmap-
/// derived state this crate has no direct access to (it has no
/// coordination client), so the daemon injects an implementation via
/// `set_change_authenticator`, mirroring how `set_rate_limiters` injects
/// the shared token buckets.
///
/// Until an authenticator is present, this session cannot resolve any
/// authority key, so it never admits a Change it received — matching the
/// trust rule that DAG sync with a device is unavailable until this
/// device's own policy chain for the group has verified. Serving already-
/// published changes out of the store and announcing heads do not need
/// it.
pub trait ChangeAuthenticator: Send + Sync {
    /// Resolves the authority key that this device's own verified policy
    /// chain for `group_id` considers valid for `signer_key_id` AT
    /// `policy_head` -- `None` if unknown, or if that key had already been
    /// rotated out by that point. Never a bare "trust this key" answer;
    /// see `authorization_checkpoint::verify_change_admission`'s own doc
    /// comment for why a checkpoint's signer must always be resolved
    /// through a caller's own verified chain rather than accepted as
    /// self-attested.
    fn resolve_authority_key(
        &self,
        group_id: &str,
        signer_key_id: &[u8; 32],
        policy_head: &[u8; 32],
    ) -> Option<ed25519_dalek::VerifyingKey>;
}

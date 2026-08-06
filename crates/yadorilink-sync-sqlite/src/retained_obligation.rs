//! Retained obligations (design `preimage-capture.md` §5.5/§12): the
//! durable lifecycle that owns a retained preimage once custody transfer
//! has moved it off the canonical path and captured authoring has (or has
//! not yet) published it into the group's causal history.
//!
//! # Crate split (7D-9D)
//!
//! This module owns the SQL-backed half of the retained-obligation
//! lifecycle: the `retained_preimages`/`retained_preimage_deletion_intents`
//! schema, the obligation CRUD state machine ([`create`], [`get`],
//! [`record_late_write`], [`record_captured_change`],
//! [`mark_authorization_permanently_lost`], [`set_capacity_degraded`]), the
//! durability-proof reads ([`verify_durable_representation`]), the
//! read-only deletion decision ([`evaluate_deletion`], orchestrating
//! `yadorilink-replica-engine::retained_obligation`'s pure guard stages
//! around this crate's own two durability SQL reads), and the orphaned
//! `captured_authoring` root sweep. None of this touches the real
//! filesystem. The identity-checked physical unlink that actually finalizes
//! a deletion (`delete_if_eligible`, `complete_deletion_after_unlink`,
//! `unlink_and_complete_deletion`, and the `DeletionOutcome` type they
//! return) stays in `yadorilink-sync-core::retained_obligation` -- it reads
//! `std::fs`, `yadorilink_root_authority::fs_identity`, and
//! `yadorilink_filesystem_sync::fs_commit::ParentDirHandle`, none of which
//! this crate may depend on. That module calls back into this one for
//! every SQL-shaped step ([`get`], [`evaluate_deletion`],
//! [`reject_time_regression`], [`load_deletion_intent`], [`require_enabled`]).
//!
//! # Why the placement epoch cannot own this
//!
//! The epoch that displaced an object completes at `CustodyTransferred`
//! (§8.1) — canonical-path exclusion is released at that point precisely so
//! ordinary materialization can keep moving. The retained object, however,
//! keeps existing on disk after that: quiescence, block storage and
//! authoring run afterward, in a lower-priority custody queue (§12), on a
//! timescale the epoch's own state machine has no reason to track. Something
//! has to own "does this object still need protecting, and can it ever be
//! deleted" independently of whether the epoch that created it is long since
//! finished. This module (together with its filesystem-execution
//! counterpart in `yadorilink-sync-core`) is that owner: one row per
//! retained object, surviving its originating epoch, tracked by its own
//! state and its own grace clock.
//!
//! # Positive proof of durable representation (§12/§13)
//!
//! Automatic deletion is refused unless durability is *proven*, not merely
//! unrefuted. Two independent facts must both hold, and this module checks
//! both explicitly in [`verify_durable_representation`] rather than trusting
//! either alone:
//!
//! 1. **DAG representation is durable**: [`yadorilink_sync_sqlite::dag_store::has_change_or_pruned`]
//!    (`crate::dag_store::has_change_or_pruned`) for `last_captured_change_hash`,
//!    in this obligation's own `group_id`. This is true for a change still
//!    fully retained *and* for one already compacted to a causal stub
//!    (§5.7/§13) — a stub is not a weaker proof here, because §13 already
//!    requires compaction to prove "no file-version/provenance consumer
//!    still requires the removed payload" before it is allowed to happen at
//!    all. This leg alone is **not** treated as sufficient: a bare change
//!    hash existing somewhere in this replica's history says the bytes were
//!    *signed and admitted*, not that they survive independently of the one
//!    retained file this obligation is about deleting.
//! 2. **The required conflict copy is durable**: a live `files` row (design
//!    §5.1's index, `deleted = 0`, any `state`) whose `authoring_change_hash`
//!    equals `last_captured_change_hash` **and** whose own content columns
//!    (`blocks_json`/`size`/`mtime_unix_nanos`/`record_kind`/
//!    `symlink_target`/`exec_bit`) re-derive, via the same
//!    [`yadorilink_replica_domain::file::FileVersion::from_index_row`] the durability-root
//!    enumeration already trusts, the exact `last_captured_version_hash`
//!    this obligation recorded at capture time. Column equality on
//!    `authoring_change_hash` alone is **not** sufficient: `index.rs`'s
//!    `upsert_file_in_tx` carries that column forward onto an upsert that
//!    supplies no fresh authoring hash of its own, so a path later
//!    overwritten with unrelated content can still carry a stale,
//!    no-longer-true `authoring_change_hash` pointing at a change that
//!    authored *different* bytes. Re-deriving the row's own version identity
//!    from its actual content and comparing that — not the column alone —
//!    is what makes this leg a proof about the captured bytes specifically,
//!    not merely about a label that survived an unrelated later write.
//!
//! Either leg alone is an absence-of-counter-evidence, not a proof: (1)
//! alone would accept a change that has never actually become a real file
//! anywhere, and (2) alone (an `authoring_change_hash` value with no backing
//! change) cannot happen through the ordinary write path but is not
//! structurally impossible to construct by mistake, so both are checked.
//! A checkpoint that later prunes the change to a stub does not later
//! invalidate a deletion already performed on both legs holding: deletion is
//! decided by a durable identity-bound intent (`delete_if_eligible`, in
//! `yadorilink-sync-core`) and finalized only after an identity-checked
//! unlink (`complete_deletion_after_unlink`, also there); a crash between
//! those steps keeps the obligation and retention root intact and is
//! resumed from the intent.
//!
//! # What happens when the fingerprint has changed
//!
//! A changed fingerprint is exactly what §12 exists for: a stale handle that
//! survived custody transfer wrote to the retained object after it was
//! captured (or after custody transfer, before it was ever captured). This
//! module never deletes such an object — [`evaluate_deletion`] compares a
//! **freshly observed** fingerprint (supplied by the caller, presumably from
//! rerunning [`yadorilink_filesystem_sync::single_pass_capture::classify_single_pass`] against the
//! object's current bytes) against `last_fingerprint`, and any mismatch (or
//! `last_fingerprint` never having been recorded at all) is
//! [`RetentionReason::FingerprintChanged`], never silently ignored. Noticing
//! it is [`record_late_write`]'s job: a caller that reruns the quiescence
//! pipeline and observes a fingerprint that no longer matches the obligation's
//! own recorded value calls it, which records the new fingerprint (so a
//! *subsequent* unrelated deletion attempt correctly compares against the
//! latest write, not a stale one), reclassifies the object `Divergent`
//! (§12: "any change reclassifies it divergent") if it was still `KnownOld`,
//! and restarts the grace clock — see "grace policy" below.
//!
//! It also **clears** `last_captured_change_hash`/`last_captured_version_hash`
//! if either was set. A change captured before this late write proves
//! durability of the *previous* bytes, not the ones just observed — pairing
//! a fresh fingerprint with a stale capture would let
//! [`verify_durable_representation`] pass on content that was never actually
//! authored anywhere (durability proven for bytes nobody is about to delete
//! says nothing about the bytes that are). Deletion eligibility is
//! [`RetentionReason::NoCapturedChange`] again until a fresh
//! [`record_captured_change`] call re-establishes the pairing for the
//! content this late write actually observed — [`record_late_write`] does
//! **not** itself decide whether the new write should be authored as a new
//! capture; that is late-write chaining, left to a future caller of
//! [`record_captured_change`]'s `previous_capture` parameter.
//!
//! # Grace policy
//!
//! `retain_until_unix_nanos` is the only clock. It is set by exactly two
//! internal call sites, both of which compute it as `now + `[`grace_period_nanos`]
//! from a fixed, non-configurable constant — no public function on this
//! module accepts a duration, an explicit `retain_until`, or any other way
//! to shorten it, so "a caller sets the grace period to zero" is not an
//! expressible call:
//! - [`create`] starts it, the moment an obligation first exists (§12:
//!   "known old object: retain 24h");
//! - [`record_late_write`] and [`record_captured_change`] restart it from
//!   `now` every time either fires, because each represents new activity a
//!   30-hours-old clock should not have already been running against —
//!   a late write is new content to protect, and authoring is the event
//!   after which durability even becomes checkable in the first place.
//!
//! [`mark_authorization_permanently_lost`] does not touch the clock at all —
//! `LocalRecoveryOnly` is excluded from automatic deletion regardless of
//! `retain_until` (see next section), so the clock is moot once reached.
//!
//! # Orphaned `captured_authoring` roots
//!
//! `delete_if_eligible` (in `yadorilink-sync-core`) is the *intended*
//! releaser of a `captured_authoring` `full_payload` root (see "positive
//! proof", above) — but only if this obligation's own lifecycle is actually
//! driven to that call. Two ways it might not be: the obligation row is
//! removed some other way after the root was registered, or nothing ever
//! drives this obligation's lifecycle that far. In either case the root
//! outlives its purpose: `commit_prune` honours a live root unconditionally
//! (by design — judging whether a root is still wanted is this lifecycle's
//! job, not the compactor's), so an orphaned root pins one change's full
//! payload forever, never the whole checkpoint.
//!
//! [`sweep_orphaned_captured_authoring_roots`] closes this. It is a second,
//! narrower recovery path over the *same* `dag_retention_roots` table
//! [`create`]/`delete_if_eligible` already use — not a second registry —
//! scoped to the one owner kind this lifecycle is the designated releaser
//! for ([`CAPTURED_AUTHORING_RETENTION_OWNER_KIND`]).
//!
//! **What makes a root an orphan.** `captured_authoring` registers its root
//! with `owner_id` set to the exact `retained_id` string this module's own
//! `retained_preimages` table is keyed on. That is sufficient to ask the
//! question directly: [`get`] on that same `(group_id, owner_id)` pair
//! either finds a live obligation row or it does not.
//!
//! **A present obligation always wins, regardless of state.** A root whose
//! `retained_id` still names a live [`RetainedObligation`] — `KnownOld`,
//! `Divergent`, not yet durable, not yet grace-expired, even
//! `LocalRecoveryOnly` — is retained. Only that obligation's own
//! `delete_if_eligible` call may release its root; the sweep never
//! substitutes its own judgment for the three-precondition rule
//! [`evaluate_deletion`] already enforces.
//!
//! **The window a naive presence check would get wrong.** A future
//! orchestrator that registers a `captured_authoring` root and creates this
//! module's obligation row as two separate steps would have an instant
//! where [`get`] finds nothing yet — not because the obligation is gone,
//! but because it does not exist *yet*. The sweep never relies on presence
//! alone: a root absent an obligation is only released once it has been
//! registered for at least [`ORPHAN_ROOT_GRACE_PERIOD`].
//! [`sweep_orphaned_captured_authoring_roots_unchecked`]'s own tests
//! exercise this window directly.
//!
//! **Concurrency.** The sweep runs its read (does an obligation exist for
//! this root) and its write (release the root) inside one `IMMEDIATE`
//! transaction it opens itself, for the same reason every other mutating
//! entry point in this module does.
//!
//! **What decides status but cannot be determined stays.** A row whose
//! `retention_class` does not decode, or any database error while reading
//! candidate roots or checking for a live obligation, aborts the whole sweep
//! transaction rather than defaulting an unreadable row to "orphan" — the
//! same fail-closed posture [`evaluate_deletion`] and
//! [`verify_durable_representation`] already take.

use std::time::Duration;

use rusqlite::{Connection, OptionalExtension};

use yadorilink_replica_domain::change::{Change, Op};
use yadorilink_replica_domain::file::{BlockInfo, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{ChangeHash, VersionHash};

use crate::dag_store::{self, RetentionClass};
use crate::error::SyncSqliteError;
use crate::filesystem_transaction;
use yadorilink_filesystem_sync::single_pass_capture::StabilityFingerprint;

// Pure deletion-decision policy (ObligationState, RetentionReason,
// DeletionDecision, WriterExclusionProven, and the guard/final-step
// functions `evaluate_deletion` below stitches its own SQL reads around)
// lives in `yadorilink-replica-engine` -- see that module's own doc comment
// for why only this narrower slice moved out (7D-9D).
use yadorilink_replica_engine::retained_obligation::{
    evaluate_deletion_final_step, evaluate_deletion_pre_durability, DeletionDecision,
    ObligationState, PreDurabilityOutcome, RetentionReason, WriterExclusionProven,
};

/// The owner tag `captured_authoring` registers its `full_payload`
/// [`yadorilink_sync_sqlite::dag_store::register_retention_root`] entries under — see that
/// module's own `RETENTION_OWNER_KIND` constant. Duplicated here (not
/// imported) because it is `captured_authoring`'s private constant; the
/// string itself is the actual contract between the two modules, documented
/// in both places, and asserted equal by
/// `releases_the_same_owner_kind_captured_authoring_registers_under` (in
/// `yadorilink-sync-core::retained_obligation`'s own test suite, which
/// exercises this whole lifecycle end to end).
pub const CAPTURED_AUTHORING_RETENTION_OWNER_KIND: &str = "captured_authoring";

/// §12's stated initial grace window. Not configurable by any caller — see
/// the module doc's "grace policy" section for why that is load-bearing.
const GRACE_PERIOD: Duration = Duration::from_secs(24 * 60 * 60);

/// Public for `yadorilink-sync-core::retained_obligation`'s own test suite,
/// which exercises this whole lifecycle (including the filesystem-execution
/// half that stays there) end to end and needs the same constant its
/// fixtures assert against.
pub fn grace_period_nanos() -> i64 {
    GRACE_PERIOD.as_nanos() as i64
}

/// How long an obligation-less `captured_authoring` root is left alone
/// before [`sweep_orphaned_captured_authoring_roots`] treats it as a genuine
/// orphan rather than a window in a multi-step registration — see the
/// module doc's "orphaned `captured_authoring` roots" section. Deliberately
/// much shorter than [`GRACE_PERIOD`]: that constant bounds a durability
/// grace window across devices and quiescence retries; this one only needs
/// to cover two ordinary, synchronous, local database writes completing —
/// generous margin over that, not a second definition of the same wait.
const ORPHAN_ROOT_GRACE_PERIOD: Duration = Duration::from_secs(60 * 60);

/// Public for the same cross-crate test reason as [`grace_period_nanos`].
pub fn orphan_root_grace_period_nanos() -> i64 {
    ORPHAN_ROOT_GRACE_PERIOD.as_nanos() as i64
}

/// One `retained_preimages` row (design §5.5), decoded.
#[derive(Debug, Clone)]
pub struct RetainedObligation {
    pub retained_id: String,
    pub originating_transaction_id: Option<String>,
    pub source_epoch: Option<i64>,
    pub group_id: String,
    pub original_path: String,
    pub custody_path: String,
    /// Opaque bytes from `yadorilink_root_authority::fs_identity` — this
    /// module never decodes them, matching the discipline
    /// `dag_retention_roots` documents for not decoding subsystem-specific
    /// BLOBs.
    pub parent_directory_identity: Vec<u8>,
    pub filesystem_identity: Option<Vec<u8>>,
    pub state: ObligationState,
    pub original_parent_basis_id: String,
    pub last_captured_change_hash: Option<ChangeHash>,
    /// The version identity ([`yadorilink_replica_domain::file::FileVersion::compute_hash`])
    /// the bytes captured under `last_captured_change_hash` actually had.
    /// Always `Some` exactly when `last_captured_change_hash` is —
    /// [`record_captured_change`] writes both together and
    /// [`record_late_write`] clears both together — see the module doc's
    /// "what happens when the fingerprint has changed" section for why the
    /// two must never be allowed to drift apart.
    pub last_captured_version_hash: Option<VersionHash>,
    pub last_fingerprint: Option<StabilityFingerprint>,
    pub retain_until_unix_nanos: i64,
    pub durable_copy_path: Option<String>,
    /// The §12 "capacity limit reached" row: "no automatic oldest-first
    /// deletion; mark link degraded". Deliberately not folded into `state`
    /// — capacity pressure is an operator-visible signal about *this*
    /// obligation's link, orthogonal to (and never a cause of) whether it
    /// is eligible for the ordinary three-precondition automatic deletion
    /// this module implements. Setting it never advances `retain_until`,
    /// never changes `state`, and [`evaluate_deletion`] does not read it.
    pub capacity_degraded: bool,
    pub encoding_version: u32,
    pub created_at_unix_nanos: i64,
    pub updated_at_unix_nanos: i64,
}

pub fn init_retained_obligations_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS retained_preimages (
            retained_id                 TEXT NOT NULL PRIMARY KEY,
            originating_transaction_id  TEXT,
            source_epoch                INTEGER,
            group_id                    TEXT NOT NULL,
            original_path                TEXT NOT NULL,
            custody_path                 TEXT NOT NULL,
            parent_directory_identity   BLOB NOT NULL,
            filesystem_identity         BLOB,
            state                       TEXT NOT NULL,
            original_parent_basis_id    TEXT NOT NULL,
            last_captured_change_hash   BLOB,
            last_captured_version_hash  BLOB,
            last_fingerprint            BLOB,
            retain_until_unix_nanos     INTEGER NOT NULL,
            durable_copy_path           TEXT,
            capacity_degraded           INTEGER NOT NULL DEFAULT 0,
            encoding_version            INTEGER NOT NULL,
            created_at_unix_nanos       INTEGER NOT NULL,
            updated_at_unix_nanos       INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS retained_preimages_by_group
            ON retained_preimages(group_id);

        CREATE TABLE IF NOT EXISTS retained_preimage_deletion_intents (
            group_id                         TEXT NOT NULL,
            retained_id                      TEXT NOT NULL,
            custody_path                     TEXT NOT NULL,
            filesystem_identity              BLOB NOT NULL,
            obligation_updated_at_unix_nanos INTEGER NOT NULL,
            state                            TEXT NOT NULL,
            prepared_at_unix_nanos           INTEGER NOT NULL,
            completed_at_unix_nanos          INTEGER,
            PRIMARY KEY (group_id, retained_id)
        );
        "#,
    )?;
    Ok(())
}

/// Current on-disk encoding version this module writes. No migration logic
/// exists yet (pre-release: [[memory:pre-release-no-compat-burden]] applies
/// to this table the same as every other one in this crate) — bumping it is
/// free until a real reader needs to distinguish encodings.
const ENCODING_VERSION: u32 = 1;

/// Everything [`create`] needs to start a new obligation. Borrowed, not
/// owned — every field is copied into the row synchronously.
pub struct NewObligation<'a> {
    pub retained_id: &'a str,
    pub originating_transaction_id: Option<&'a str>,
    pub source_epoch: Option<i64>,
    pub group_id: &'a str,
    pub original_path: &'a str,
    pub custody_path: &'a str,
    pub parent_directory_identity: &'a [u8],
    pub filesystem_identity: Option<&'a [u8]>,
    pub original_parent_basis_id: &'a str,
}

/// Failure modes shared by every mutating entry point in this module (and
/// by `yadorilink-sync-core::retained_obligation`'s filesystem-execution
/// entry points, which return this same type — see this crate's own
/// `retained_obligation` module doc's "crate split" section).
#[derive(Debug)]
pub enum RetainedObligationError {
    Sync(SyncSqliteError),
    /// [`filesystem_transaction::require_execution_enabled`] refused — only
    /// reachable through the gated entry points, never through the
    /// `_unchecked` ones.
    NotEnabled,
    /// [`create`] was called with a `retained_id` that already has a row
    /// whose identity-defining fields (`group_id`, `original_path`,
    /// `custody_path`) differ from what was supplied. A retry of the exact
    /// same creation is idempotent (see [`create`]'s own doc); this is the
    /// case where two genuinely different objects collided on one id —
    /// refused loudly rather than silently keeping whichever row happened
    /// to land first.
    ObligationIdentityConflict {
        retained_id: String,
    },
    /// A `record_*`/`delete_if_eligible` call named a `retained_id` with no
    /// row at all.
    NotFound {
        group_id: String,
        retained_id: String,
    },
    /// A `record_*` call reached an obligation already in
    /// [`ObligationState::LocalRecoveryOnly`] — terminal, per the module
    /// doc; only an operator action (out of this module's scope) may act on
    /// it further.
    Terminal {
        retained_id: String,
    },
    /// A caller supplied `now_unix_nanos` earlier than the last time this
    /// obligation's clock was legitimately advanced
    /// (`updated_at_unix_nanos`). Refused rather than silently applied —
    /// see the module doc's "grace policy" section: the non-configurable
    /// grace-period constant is only load-bearing if no caller, ordinary or
    /// out-of-order/replayed, can ever move this obligation's clock
    /// backward and overwrite a newer deadline with an older one.
    NonMonotonicTime {
        retained_id: String,
        now_unix_nanos: i64,
        last_seen_unix_nanos: i64,
    },
    /// [`record_captured_change`] was given a `captured_change_hash` this
    /// replica has not admitted, or whose ops do not actually write
    /// `captured_version_hash` — see the module doc's "positive proof"
    /// section and [`captured_change_binds_obligation`]: a wrong hand-off
    /// must never be allowed to pair an obligation with content that was
    /// not actually captured under that specific change.
    CapturedChangeVersionMismatch {
        retained_id: String,
    },
    /// A compare-and-delete/compare-and-write matched zero rows even though
    /// the same transaction had just proved the precondition that write
    /// depends on against the row it had just read. Structurally should
    /// never happen inside the enclosing `IMMEDIATE` transaction — surfaced
    /// as a hard error rather than silently treated as already-applied.
    StaleDecision {
        retained_id: String,
    },

    /// A durable identity-bound deletion intent already owns this obligation.
    /// No lifecycle mutation may advance or rewrite the row until that intent
    /// is either safely cancelled while the custody object still exists or
    /// completed after the exact object is unlinked. This is the write fence
    /// that prevents an update from landing between intent preparation and
    /// physical unlink.
    DeletionInProgress {
        retained_id: String,
    },
}

impl From<SyncSqliteError> for RetainedObligationError {
    fn from(e: SyncSqliteError) -> Self {
        RetainedObligationError::Sync(e)
    }
}

impl From<rusqlite::Error> for RetainedObligationError {
    fn from(e: rusqlite::Error) -> Self {
        RetainedObligationError::Sync(SyncSqliteError::Sqlite(e))
    }
}

/// Public so `yadorilink-sync-core`'s filesystem-execution entry points
/// (`delete_if_eligible`, `complete_deletion_after_unlink`,
/// `unlink_and_complete_deletion`, `sweep_orphaned_captured_authoring_roots`'s
/// own sibling gated wrapper) can enforce the exact same
/// `EXECUTION_ENABLED` gate this crate's own gated entry points do, without
/// duplicating `filesystem_transaction::require_execution_enabled`'s
/// error-mapping.
pub fn require_enabled() -> Result<(), RetainedObligationError> {
    filesystem_transaction::require_execution_enabled()
        .map_err(|_| RetainedObligationError::NotEnabled)
}

/// Refuses a caller-supplied `now_unix_nanos` older than
/// `last_seen_unix_nanos` (an obligation's own `updated_at_unix_nanos`) —
/// see [`RetainedObligationError::NonMonotonicTime`]'s doc. Public so
/// `yadorilink-sync-core`'s filesystem-execution entry points can enforce
/// the same invariant this crate's own mutating entry points do.
pub fn reject_time_regression(
    retained_id: &str,
    last_seen_unix_nanos: i64,
    now_unix_nanos: i64,
) -> Result<(), RetainedObligationError> {
    if now_unix_nanos < last_seen_unix_nanos {
        return Err(RetainedObligationError::NonMonotonicTime {
            retained_id: retained_id.to_string(),
            now_unix_nanos,
            last_seen_unix_nanos,
        });
    }
    Ok(())
}

type RawRow = (
    String,          // retained_id
    Option<String>,  // originating_transaction_id
    Option<i64>,     // source_epoch
    String,          // group_id
    String,          // original_path
    String,          // custody_path
    Vec<u8>,         // parent_directory_identity
    Option<Vec<u8>>, // filesystem_identity
    String,          // state
    String,          // original_parent_basis_id
    Option<Vec<u8>>, // last_captured_change_hash
    Option<Vec<u8>>, // last_captured_version_hash
    Option<Vec<u8>>, // last_fingerprint
    i64,             // retain_until_unix_nanos
    Option<String>,  // durable_copy_path
    i64,             // capacity_degraded
    i64,             // encoding_version
    i64,             // created_at_unix_nanos
    i64,             // updated_at_unix_nanos
);

const SELECT_COLUMNS: &str = "retained_id, originating_transaction_id, source_epoch, group_id, \
     original_path, custody_path, parent_directory_identity, filesystem_identity, state, \
     original_parent_basis_id, last_captured_change_hash, last_captured_version_hash, \
     last_fingerprint, retain_until_unix_nanos, durable_copy_path, capacity_degraded, \
     encoding_version, created_at_unix_nanos, updated_at_unix_nanos";

fn decode_row(row: RawRow) -> Result<RetainedObligation, SyncSqliteError> {
    let (
        retained_id,
        originating_transaction_id,
        source_epoch,
        group_id,
        original_path,
        custody_path,
        parent_directory_identity,
        filesystem_identity,
        state,
        original_parent_basis_id,
        last_captured_change_hash,
        last_captured_version_hash,
        last_fingerprint,
        retain_until_unix_nanos,
        durable_copy_path,
        capacity_degraded,
        encoding_version,
        created_at_unix_nanos,
        updated_at_unix_nanos,
    ) = row;

    let state = ObligationState::from_str(&state)?;
    let last_captured_change_hash = last_captured_change_hash
        .map(|bytes| hash_from_blob(&retained_id, "last_captured_change_hash", bytes))
        .transpose()?;
    let last_captured_version_hash = last_captured_version_hash
        .map(|bytes| version_hash_from_blob(&retained_id, bytes))
        .transpose()?;
    if last_captured_change_hash.is_some() != last_captured_version_hash.is_some() {
        return Err(SyncSqliteError::CorruptState(format!(
            "retained_preimages {retained_id} has last_captured_change_hash and \
             last_captured_version_hash set independently -- they must always be written \
             together"
        )));
    }
    let last_fingerprint =
        last_fingerprint.map(|bytes| fingerprint_from_blob(&retained_id, bytes)).transpose()?;

    Ok(RetainedObligation {
        retained_id,
        originating_transaction_id,
        source_epoch,
        group_id,
        original_path,
        custody_path,
        parent_directory_identity,
        filesystem_identity,
        state,
        original_parent_basis_id,
        last_captured_change_hash,
        last_captured_version_hash,
        last_fingerprint,
        retain_until_unix_nanos,
        durable_copy_path,
        capacity_degraded: capacity_degraded != 0,
        encoding_version: encoding_version as u32,
        created_at_unix_nanos,
        updated_at_unix_nanos,
    })
}

fn hash_from_blob(
    retained_id: &str,
    column: &str,
    bytes: Vec<u8>,
) -> Result<ChangeHash, SyncSqliteError> {
    let array: [u8; 32] = bytes.try_into().map_err(|_| {
        SyncSqliteError::CorruptState(format!(
            "retained_preimages.{column} for {retained_id} is not 32 bytes"
        ))
    })?;
    Ok(ChangeHash(array))
}

fn version_hash_from_blob(
    retained_id: &str,
    bytes: Vec<u8>,
) -> Result<VersionHash, SyncSqliteError> {
    let array: [u8; 32] = bytes.try_into().map_err(|_| {
        SyncSqliteError::CorruptState(format!(
            "retained_preimages.last_captured_version_hash for {retained_id} is not 32 bytes"
        ))
    })?;
    Ok(VersionHash(array))
}

/// Local copy of `dag_store`'s own `op_version_hash` helper (see
/// `dag_store::retention_roots`'s identical copy for precedent): the
/// original is `pub(crate)` inside a private submodule of `dag_store`, so it
/// is not reachable from here, and duplicating four lines is cheaper than
/// widening that module's visibility for one external caller.
fn op_version_hash(op: &Op) -> Option<&VersionHash> {
    match op {
        Op::Put { version, .. } | Op::Move { version, .. } => Some(version),
        Op::Delete { .. } => None,
    }
}

/// Whether `captured_change_hash` is a change this replica has admitted,
/// belongs to `obligation`'s own `group_id`, and has an op that writes
/// `captured_version_hash` at `obligation`'s own `original_path` — the
/// correlation [`record_captured_change`] refuses to skip. See the original
/// design note this doc used to carry in full at
/// `yadorilink-sync-core::retained_obligation`'s pre-7D-9D history: binding
/// to `group_id` alone is not sufficient either, since two unrelated paths
/// can be admitted in the same group in the same or adjacent changes, so the
/// path itself — not just the group — must match what the change's op
/// actually writes.
fn captured_change_binds_obligation(
    conn: &Connection,
    obligation: &RetainedObligation,
    captured_change_hash: &ChangeHash,
    captured_version_hash: &VersionHash,
) -> Result<bool, SyncSqliteError> {
    let Some(encoded) = dag_store::get_encoded(conn, captured_change_hash)? else {
        return Ok(false);
    };
    let change = Change::from_wire_bytes(&encoded).map_err(|error| {
        SyncSqliteError::CorruptState(format!(
            "corrupt stored change {}: {error}",
            captured_change_hash.to_hex()
        ))
    })?;
    if change.group_id.as_str() != obligation.group_id {
        return Ok(false);
    }
    Ok(change.ops.iter().any(|op| {
        op_version_hash(op) == Some(captured_version_hash)
            && op_destination_path(op) == obligation.original_path
    }))
}

/// The path an op writes to, if any — `Put`'s and `Move`'s destination
/// (`Move`'s `from` is deliberately not considered a match: this obligation
/// is about the object currently living at `original_path`, and a `Move`
/// whose `from` happens to equal that path but whose `to` moves the content
/// elsewhere does not write `original_path` at all). `Delete` writes no
/// path.
fn op_destination_path(op: &Op) -> &str {
    match op {
        Op::Put { path, .. } => path.as_str(),
        Op::Move { to, .. } => to.as_str(),
        Op::Delete { .. } => "",
    }
}

fn fingerprint_from_blob(
    retained_id: &str,
    bytes: Vec<u8>,
) -> Result<StabilityFingerprint, SyncSqliteError> {
    let array: [u8; 32] = bytes.try_into().map_err(|_| {
        SyncSqliteError::CorruptState(format!(
            "retained_preimages.last_fingerprint for {retained_id} is not 32 bytes"
        ))
    })?;
    Ok(StabilityFingerprint(array))
}

/// Reads one obligation, or `None` if `retained_id` has no row.
pub fn get(
    conn: &Connection,
    group_id: &str,
    retained_id: &str,
) -> Result<Option<RetainedObligation>, SyncSqliteError> {
    let row: Option<RawRow> = conn
        .query_row(
            &format!(
                "SELECT {SELECT_COLUMNS} FROM retained_preimages \
                 WHERE group_id = ?1 AND retained_id = ?2"
            ),
            rusqlite::params![group_id, retained_id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                    r.get(11)?,
                    r.get(12)?,
                    r.get(13)?,
                    r.get(14)?,
                    r.get(15)?,
                    r.get(16)?,
                    r.get(17)?,
                    r.get(18)?,
                ))
            },
        )
        .optional()?;
    row.map(decode_row).transpose()
}

/// Starts a new obligation in [`ObligationState::KnownOld`], grace clock
/// running from `now_unix_nanos`. Idempotent on `retained_id`: a retry with
/// byte-for-byte the same `group_id`/`original_path`/`custody_path` returns
/// the existing row unchanged (a custody-transfer retry after a crash before
/// its own caller observed success must not restart the grace clock, or
/// worse, refuse outright). A retry with any of those three fields
/// different from what is already recorded is
/// [`RetainedObligationError::ObligationIdentityConflict`] — two distinct
/// objects must never share one `retained_id`'s row.
pub fn create(
    conn: &Connection,
    new: &NewObligation<'_>,
    now_unix_nanos: i64,
) -> Result<RetainedObligation, RetainedObligationError> {
    reject_deletion_in_progress(conn, new.group_id, new.retained_id)?;
    if let Some(existing) = get(conn, new.group_id, new.retained_id)? {
        if existing.group_id == new.group_id
            && existing.original_path == new.original_path
            && existing.custody_path == new.custody_path
        {
            return Ok(existing);
        }
        return Err(RetainedObligationError::ObligationIdentityConflict {
            retained_id: new.retained_id.to_string(),
        });
    }

    conn.execute(
        "INSERT INTO retained_preimages \
         (retained_id, originating_transaction_id, source_epoch, group_id, original_path, \
          custody_path, parent_directory_identity, filesystem_identity, state, \
          original_parent_basis_id, retain_until_unix_nanos, capacity_degraded, \
          encoding_version, created_at_unix_nanos, updated_at_unix_nanos) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, ?12, ?13, ?13)",
        rusqlite::params![
            new.retained_id,
            new.originating_transaction_id,
            new.source_epoch,
            new.group_id,
            new.original_path,
            new.custody_path,
            new.parent_directory_identity,
            new.filesystem_identity,
            ObligationState::KnownOld.as_str(),
            new.original_parent_basis_id,
            now_unix_nanos.saturating_add(grace_period_nanos()),
            ENCODING_VERSION,
            now_unix_nanos,
        ],
    )?;

    Ok(get(conn, new.group_id, new.retained_id)?.ok_or_else(|| {
        SyncSqliteError::CorruptState(format!(
            "retained_preimages row for {} vanished immediately after insert",
            new.retained_id
        ))
    })?)
}

/// A late write was observed on the retained object after it entered
/// custody (§12) — see the module doc's "what happens when the fingerprint
/// has changed" section. Records `observed_fingerprint` as the obligation's
/// new `last_fingerprint`, reclassifies `KnownOld -> Divergent` (a no-op if
/// already `Divergent`), restarts the grace clock from `now_unix_nanos`, and
/// clears `last_captured_change_hash`/`last_captured_version_hash` if either
/// was set.
///
/// Refuses (does not apply) a `now_unix_nanos` older than this obligation's
/// own `updated_at_unix_nanos` — see
/// [`RetainedObligationError::NonMonotonicTime`].
///
/// Reads and writes inside one `IMMEDIATE` transaction this function opens
/// itself: `IMMEDIATE` takes SQLite's write lock at `BEGIN`, so two
/// concurrent calls against the same obligation are provably serialized,
/// never interleaved. The final `UPDATE` is additionally conditional on
/// `updated_at_unix_nanos` matching what was just read in this same
/// transaction; a mismatch here would mean this module's own invariants
/// broke, so it is surfaced as [`RetainedObligationError::StaleDecision`]
/// rather than silently ignored.
pub fn record_late_write(
    conn: &mut Connection,
    group_id: &str,
    retained_id: &str,
    observed_fingerprint: StabilityFingerprint,
    now_unix_nanos: i64,
) -> Result<RetainedObligation, RetainedObligationError> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    reject_deletion_in_progress(&tx, group_id, retained_id)?;

    let existing = require_live(&tx, group_id, retained_id)?;
    reject_time_regression(retained_id, existing.updated_at_unix_nanos, now_unix_nanos)?;

    let updated_rows = tx.execute(
        "UPDATE retained_preimages SET last_fingerprint = ?1, state = ?2, \
         retain_until_unix_nanos = ?3, updated_at_unix_nanos = ?4, \
         last_captured_change_hash = NULL, last_captured_version_hash = NULL \
         WHERE group_id = ?5 AND retained_id = ?6 AND updated_at_unix_nanos = ?7",
        rusqlite::params![
            observed_fingerprint.0.to_vec(),
            ObligationState::Divergent.as_str(),
            now_unix_nanos.saturating_add(grace_period_nanos()),
            now_unix_nanos,
            group_id,
            retained_id,
            existing.updated_at_unix_nanos,
        ],
    )?;
    if updated_rows != 1 {
        return Err(RetainedObligationError::StaleDecision {
            retained_id: retained_id.to_string(),
        });
    }
    let updated =
        get(&tx, group_id, retained_id)?.ok_or_else(|| RetainedObligationError::NotFound {
            group_id: group_id.to_string(),
            retained_id: retained_id.to_string(),
        })?;
    tx.commit()?;
    Ok(updated)
}

/// Captured authoring published a change for this retained object (§11.2).
/// Records `captured_change_hash` paired with `captured_version_hash` (the
/// version identity — [`yadorilink_replica_domain::file::FileVersion::compute_hash`] — the
/// captured bytes actually have), moves the obligation to
/// [`ObligationState::Divergent`] (a no-op if already there) and restarts
/// the grace clock.
///
/// Refuses [`RetainedObligationError::CapturedChangeVersionMismatch`] unless
/// `captured_change_hash` is a change this replica has admitted, in this
/// obligation's own `group_id`, with an op that writes
/// `captured_version_hash` at this obligation's own `original_path` — see
/// [`captured_change_binds_obligation`]'s doc. Also refuses (does not apply)
/// a `now_unix_nanos` older than this obligation's own
/// `updated_at_unix_nanos` — see [`RetainedObligationError::NonMonotonicTime`].
///
/// Reads and writes inside one `IMMEDIATE` transaction this function opens
/// itself — see [`record_late_write`]'s doc for why.
pub fn record_captured_change(
    conn: &mut Connection,
    group_id: &str,
    retained_id: &str,
    captured_change_hash: ChangeHash,
    captured_version_hash: VersionHash,
    now_unix_nanos: i64,
) -> Result<RetainedObligation, RetainedObligationError> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    reject_deletion_in_progress(&tx, group_id, retained_id)?;

    let existing = require_live(&tx, group_id, retained_id)?;
    reject_time_regression(retained_id, existing.updated_at_unix_nanos, now_unix_nanos)?;

    if !captured_change_binds_obligation(
        &tx,
        &existing,
        &captured_change_hash,
        &captured_version_hash,
    )? {
        return Err(RetainedObligationError::CapturedChangeVersionMismatch {
            retained_id: retained_id.to_string(),
        });
    }

    let updated_rows = tx.execute(
        "UPDATE retained_preimages SET last_captured_change_hash = ?1, \
         last_captured_version_hash = ?2, state = ?3, retain_until_unix_nanos = ?4, \
         updated_at_unix_nanos = ?5 WHERE group_id = ?6 AND retained_id = ?7 \
         AND updated_at_unix_nanos = ?8",
        rusqlite::params![
            captured_change_hash.0.to_vec(),
            captured_version_hash.0.to_vec(),
            ObligationState::Divergent.as_str(),
            now_unix_nanos.saturating_add(grace_period_nanos()),
            now_unix_nanos,
            group_id,
            retained_id,
            existing.updated_at_unix_nanos,
        ],
    )?;
    if updated_rows != 1 {
        return Err(RetainedObligationError::StaleDecision {
            retained_id: retained_id.to_string(),
        });
    }
    let updated =
        get(&tx, group_id, retained_id)?.ok_or_else(|| RetainedObligationError::NotFound {
            group_id: group_id.to_string(),
            retained_id: retained_id.to_string(),
        })?;
    tx.commit()?;
    Ok(updated)
}

/// This device can no longer prove authorization to act on this obligation
/// (§16). Terminal: moves to [`ObligationState::LocalRecoveryOnly`]
/// unconditionally, from any prior state, and idempotent if already there.
/// Nothing in this module ever transitions out of this state again — only
/// an operator export/restore/delete, outside this module's scope, does.
pub fn mark_authorization_permanently_lost(
    conn: &Connection,
    group_id: &str,
    retained_id: &str,
    now_unix_nanos: i64,
) -> Result<RetainedObligation, RetainedObligationError> {
    let Some(existing) = get(conn, group_id, retained_id)? else {
        return Err(RetainedObligationError::NotFound {
            group_id: group_id.to_string(),
            retained_id: retained_id.to_string(),
        });
    };
    reject_time_regression(retained_id, existing.updated_at_unix_nanos, now_unix_nanos)?;
    let updated_rows = conn.execute(
        "UPDATE retained_preimages SET state = ?1, updated_at_unix_nanos = ?2 \
         WHERE group_id = ?3 AND retained_id = ?4 AND updated_at_unix_nanos = ?5 \
         AND NOT EXISTS (SELECT 1 FROM retained_preimage_deletion_intents \
                         WHERE group_id = ?3 AND retained_id = ?4)",
        rusqlite::params![
            ObligationState::LocalRecoveryOnly.as_str(),
            now_unix_nanos,
            group_id,
            retained_id,
            existing.updated_at_unix_nanos,
        ],
    )?;
    if updated_rows != 1 {
        reject_deletion_in_progress(conn, group_id, retained_id)?;
        return Err(RetainedObligationError::StaleDecision {
            retained_id: retained_id.to_string(),
        });
    }
    get(conn, group_id, retained_id)?.ok_or_else(|| RetainedObligationError::NotFound {
        group_id: group_id.to_string(),
        retained_id: retained_id.to_string(),
    })
}

/// Sets or clears the §12 capacity-degraded signal — see
/// [`RetainedObligation::capacity_degraded`]'s doc for why this never
/// affects `state`, the grace clock, or deletion eligibility.
pub fn set_capacity_degraded(
    conn: &Connection,
    group_id: &str,
    retained_id: &str,
    degraded: bool,
    now_unix_nanos: i64,
) -> Result<RetainedObligation, RetainedObligationError> {
    let Some(existing) = get(conn, group_id, retained_id)? else {
        return Err(RetainedObligationError::NotFound {
            group_id: group_id.to_string(),
            retained_id: retained_id.to_string(),
        });
    };
    reject_time_regression(retained_id, existing.updated_at_unix_nanos, now_unix_nanos)?;
    let updated_rows = conn.execute(
        "UPDATE retained_preimages SET capacity_degraded = ?1, updated_at_unix_nanos = ?2 \
         WHERE group_id = ?3 AND retained_id = ?4 AND updated_at_unix_nanos = ?5 \
         AND NOT EXISTS (SELECT 1 FROM retained_preimage_deletion_intents \
                         WHERE group_id = ?3 AND retained_id = ?4)",
        rusqlite::params![
            degraded as i64,
            now_unix_nanos,
            group_id,
            retained_id,
            existing.updated_at_unix_nanos,
        ],
    )?;
    if updated_rows != 1 {
        reject_deletion_in_progress(conn, group_id, retained_id)?;
        return Err(RetainedObligationError::StaleDecision {
            retained_id: retained_id.to_string(),
        });
    }
    get(conn, group_id, retained_id)?.ok_or_else(|| RetainedObligationError::NotFound {
        group_id: group_id.to_string(),
        retained_id: retained_id.to_string(),
    })
}

fn require_live(
    conn: &Connection,
    group_id: &str,
    retained_id: &str,
) -> Result<RetainedObligation, RetainedObligationError> {
    let Some(existing) = get(conn, group_id, retained_id)? else {
        return Err(RetainedObligationError::NotFound {
            group_id: group_id.to_string(),
            retained_id: retained_id.to_string(),
        });
    };
    if existing.state == ObligationState::LocalRecoveryOnly {
        return Err(RetainedObligationError::Terminal { retained_id: retained_id.to_string() });
    }
    Ok(existing)
}

/// See the module doc's "positive proof of durable representation" section.
/// Checks both legs explicitly; a database error from either check
/// propagates as `Err` rather than being folded into `false` — an
/// undetermined answer must never look identical to a proven-false one to a
/// caller that only branches on the boolean.
///
/// Leg 2 does not stop at `authoring_change_hash` column equality: that
/// column can be carried forward by `index.rs`'s `upsert_file_in_tx` onto a
/// later upsert that overwrites the path with unrelated content, so a row
/// can claim `captured_change_hash` while no longer describing the bytes it
/// authored. Every live candidate row is re-derived into its own version
/// identity from its actual content columns (the same derivation the
/// durability-root enumeration already trusts) and only accepted if that
/// identity is `captured_version_hash` itself.
pub fn verify_durable_representation(
    conn: &Connection,
    group_id: &str,
    captured_change_hash: &ChangeHash,
    captured_version_hash: &VersionHash,
) -> Result<bool, SyncSqliteError> {
    if !dag_store::has_change_or_pruned(conn, group_id, captured_change_hash)? {
        return Ok(false);
    }

    let mut stmt = conn.prepare(
        "SELECT blocks_json, size, mtime_unix_nanos, record_kind, symlink_target, exec_bit \
         FROM files WHERE group_id = ?1 AND authoring_change_hash = ?2 AND deleted = 0",
    )?;
    let mut candidates = stmt.query(rusqlite::params![group_id, &captured_change_hash.0[..]])?;
    while let Some(row) = candidates.next()? {
        let blocks_json: String = row.get(0)?;
        let size: u64 = row.get(1)?;
        let mtime_unix_nanos: i64 = row.get(2)?;
        let record_kind: String = row.get(3)?;
        let symlink_target: Option<Vec<u8>> = row.get(4)?;
        let exec_bit: i64 = row.get(5)?;

        // Fail closed on a corrupt stored block list rather than skipping
        // the row silently — matching `index.rs`'s own convention for this
        // exact column (see its `version_record`/`row_to_record`).
        let blocks: Vec<BlockInfo> = serde_json::from_str(&blocks_json).map_err(|error| {
            SyncSqliteError::CorruptState(format!(
                "stored block list for a durability-proof candidate in group {group_id} is \
                 corrupt: {error}"
            ))
        })?;
        let row_version_hash = FileVersion::from_index_row(
            blocks,
            size,
            mtime_unix_nanos,
            RecordKind::from_db_str(&record_kind),
            exec_bit != 0,
            symlink_target,
        )
        .version_hash;
        if &row_version_hash == captured_version_hash {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The read-only decision at the center of automatic deletion: expiry,
/// unchanged fingerprint, positive durability proof, AND proven writer
/// exclusion, or retain. Any one missing is `Retain`, never a partial
/// credit.
///
/// The actual policy lives in `yadorilink-replica-engine::
/// retained_obligation` as two `Connection`-free stages -- see that
/// module's own doc comment. This function is the orchestration around
/// them: it runs `evaluate_deletion_pre_durability` first (no SQL), and
/// only if that hands back a captured-change/-version pair still needing
/// proof does it run this module's own two durability-proof SQL reads
/// (`dag_store::has_change_or_pruned`, [`verify_durable_representation`])
/// before calling `evaluate_deletion_final_step` -- preserving the
/// original single function's exact short-circuiting: a durability query
/// never runs once an earlier guard has already resolved a `Retain`.
pub fn evaluate_deletion(
    conn: &Connection,
    obligation: &RetainedObligation,
    now_unix_nanos: i64,
    observed_fingerprint: StabilityFingerprint,
    writer_exclusion: &dyn WriterExclusionProven,
) -> Result<DeletionDecision, SyncSqliteError> {
    let fingerprint_matches =
        matches!(obligation.last_fingerprint, Some(recorded) if recorded == observed_fingerprint);
    let (captured_change_hash, captured_version_hash) = match evaluate_deletion_pre_durability(
        &obligation.retained_id,
        obligation.state,
        obligation.retain_until_unix_nanos,
        now_unix_nanos,
        fingerprint_matches,
        obligation.last_captured_change_hash,
        obligation.last_captured_version_hash,
    )? {
        PreDurabilityOutcome::Decided(decision) => return Ok(decision),
        PreDurabilityOutcome::NeedsDurabilityProof { captured_change_hash, captured_version_hash } => {
            (captured_change_hash, captured_version_hash)
        }
    };
    if !dag_store::has_change_or_pruned(conn, &obligation.group_id, &captured_change_hash)? {
        return Ok(DeletionDecision::Retain(RetentionReason::DagRepresentationUnproven));
    }
    if !verify_durable_representation(
        conn,
        &obligation.group_id,
        &captured_change_hash,
        &captured_version_hash,
    )? {
        return Ok(DeletionDecision::Retain(RetentionReason::ConflictCopyUnproven));
    }
    Ok(evaluate_deletion_final_step(&obligation.group_id, &obligation.retained_id, writer_exclusion))
}

/// One `retained_preimage_deletion_intents` row, decoded. Public so
/// `yadorilink-sync-core`'s filesystem-execution deletion entry points
/// (`delete_if_eligible_unchecked`, `complete_deletion_after_unlink_unchecked`)
/// can read it directly -- they are the ones that actually act on the
/// custody path it names, which this crate must never touch.
#[derive(Debug)]
pub struct DeletionIntent {
    pub custody_path: String,
    pub filesystem_identity: Vec<u8>,
    pub obligation_updated_at_unix_nanos: i64,
    pub state: String,
}

pub fn load_deletion_intent(
    conn: &Connection,
    group_id: &str,
    retained_id: &str,
) -> Result<Option<DeletionIntent>, SyncSqliteError> {
    conn.query_row(
        "SELECT custody_path, filesystem_identity, \
                 obligation_updated_at_unix_nanos, state \
         FROM retained_preimage_deletion_intents \
         WHERE group_id = ?1 AND retained_id = ?2",
        rusqlite::params![group_id, retained_id],
        |row| {
            Ok(DeletionIntent {
                custody_path: row.get(0)?,
                filesystem_identity: row.get(1)?,
                obligation_updated_at_unix_nanos: row.get(2)?,
                state: row.get(3)?,
            })
        },
    )
    .optional()
    .map_err(SyncSqliteError::Sqlite)
}

fn deletion_intent_exists(
    conn: &Connection,
    group_id: &str,
    retained_id: &str,
) -> Result<bool, SyncSqliteError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM retained_preimage_deletion_intents \
         WHERE group_id = ?1 AND retained_id = ?2)",
        rusqlite::params![group_id, retained_id],
        |row| row.get(0),
    )
    .map_err(SyncSqliteError::Sqlite)
}

fn reject_deletion_in_progress(
    conn: &Connection,
    group_id: &str,
    retained_id: &str,
) -> Result<(), RetainedObligationError> {
    if deletion_intent_exists(conn, group_id, retained_id)? {
        return Err(RetainedObligationError::DeletionInProgress {
            retained_id: retained_id.to_string(),
        });
    }
    Ok(())
}

/// One `dag_retention_roots` row registered under
/// [`CAPTURED_AUTHORING_RETENTION_OWNER_KIND`], decoded. Local to this
/// module's orphan sweep — `dag_store::retention_roots` does not expose a
/// generic "list roots by owner" query, and this module already duplicates
/// small pieces of that private table's encoding elsewhere (see
/// [`op_version_hash`]'s own doc for the precedent) rather than widening
/// that module's surface for one caller.
struct CapturedAuthoringRoot {
    retained_id: String,
    group_id: String,
    change_hash: ChangeHash,
    retention_class: RetentionClass,
    registered_at_unix_nanos: i64,
}

/// Local decode of `dag_retention_roots.retention_class`, matching
/// `dag_store::retention_roots::RetentionClass::as_str`'s private encoding
/// (that method is not visible from here). Fails closed on an unrecognized
/// value rather than guessing a default class to release under — see
/// [`sweep_orphaned_captured_authoring_roots_unchecked`]'s fail-closed
/// discipline.
fn decode_retention_class(retained_id: &str, s: &str) -> Result<RetentionClass, SyncSqliteError> {
    match s {
        "full_payload" => Ok(RetentionClass::FullPayload),
        "causal_stub" => Ok(RetentionClass::CausalStub),
        other => Err(SyncSqliteError::CorruptState(format!(
            "dag_retention_roots.retention_class {other:?} for {retained_id} is not a \
             recognized retention class"
        ))),
    }
}

/// Every `dag_retention_roots` row currently registered under
/// [`CAPTURED_AUTHORING_RETENTION_OWNER_KIND`], across every group — the
/// candidate set [`sweep_orphaned_captured_authoring_roots_unchecked`] walks.
fn captured_authoring_roots(conn: &Connection) -> Result<Vec<CapturedAuthoringRoot>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT owner_id, group_id, change_hash, retention_class, registered_at_unix_nanos \
         FROM dag_retention_roots WHERE owner_kind = ?1",
    )?;
    let rows = stmt.query_map(rusqlite::params![CAPTURED_AUTHORING_RETENTION_OWNER_KIND], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Vec<u8>>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, i64>(4)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (owner_id, group_id, hash_bytes, class_str, registered_at_unix_nanos) = row?;
        out.push(CapturedAuthoringRoot {
            change_hash: hash_from_blob(&owner_id, "change_hash", hash_bytes)?,
            retention_class: decode_retention_class(&owner_id, &class_str)?,
            retained_id: owner_id,
            group_id,
            registered_at_unix_nanos,
        });
    }
    Ok(out)
}

/// Outcome of one [`sweep_orphaned_captured_authoring_roots`] pass — see the
/// module doc's "orphaned `captured_authoring` roots" section.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OrphanRootSweepReport {
    /// Roots released: no obligation named them, and they had been
    /// registered longer than the orphan-root grace period.
    pub released: usize,
    /// Roots kept because a live obligation still names them, whatever its
    /// state — only that obligation's own `delete_if_eligible` may release
    /// them.
    pub retained_live_obligation: usize,
    /// Roots kept because no obligation names them yet, but they were
    /// registered too recently to distinguish a genuine orphan from a
    /// multi-step registration still in progress.
    pub retained_within_grace: usize,
}

/// Gated entry point: refuses while
/// [`filesystem_transaction::EXECUTION_ENABLED`] is `false`. See
/// [`sweep_orphaned_captured_authoring_roots_unchecked`] for the ungated
/// core this delegates to, and the module doc's "orphaned `captured_authoring`
/// roots" section for the full contract.
pub fn sweep_orphaned_captured_authoring_roots(
    conn: &mut Connection,
    now_unix_nanos: i64,
) -> Result<OrphanRootSweepReport, RetainedObligationError> {
    require_enabled()?;
    sweep_orphaned_captured_authoring_roots_unchecked(conn, now_unix_nanos)
}

/// The ungated core of [`sweep_orphaned_captured_authoring_roots`] — see
/// that function's doc and the module doc's "orphaned `captured_authoring`
/// roots" section for the full contract: a candidate root is released only
/// if no live obligation names its `retained_id` *and* it has been
/// registered for at least the orphan-root grace period, closing the window
/// where a root and its obligation are registered as two separate steps.
///
/// Every candidate's read (does an obligation exist) and every release run
/// inside one `IMMEDIATE` transaction this function opens itself.
pub fn sweep_orphaned_captured_authoring_roots_unchecked(
    conn: &mut Connection,
    now_unix_nanos: i64,
) -> Result<OrphanRootSweepReport, RetainedObligationError> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let mut report = OrphanRootSweepReport::default();

    for root in captured_authoring_roots(&tx)? {
        if get(&tx, &root.group_id, &root.retained_id)?.is_some() {
            report.retained_live_obligation += 1;
            continue;
        }
        // A root with no recorded registration time is retained, never
        // released. The column defaults to zero, and zero reads as
        // "registered at the epoch" -- i.e. arbitrarily old, i.e. instantly
        // past any grace period. That would turn the mechanism protecting a
        // captured payload into the thing that discards it, on the strength
        // of a value that means "unknown" rather than "ancient".
        if root.registered_at_unix_nanos <= 0 {
            report.retained_within_grace += 1;
            continue;
        }
        if now_unix_nanos.saturating_sub(root.registered_at_unix_nanos)
            < orphan_root_grace_period_nanos()
        {
            report.retained_within_grace += 1;
            continue;
        }
        dag_store::release_retention_root(
            &tx,
            CAPTURED_AUTHORING_RETENTION_OWNER_KIND,
            &root.retained_id,
            &root.group_id,
            &root.change_hash,
            root.retention_class,
        )?;
        report.released += 1;
    }

    tx.commit()?;
    Ok(report)
}

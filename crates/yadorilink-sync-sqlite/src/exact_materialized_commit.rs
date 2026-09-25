//! The two ways a path may come to claim `Hydrated`, kept deliberately
//! apart.
//!
//! `MaterializationState::Hydrated` is an exact claim about disk, not a UI
//! label, and the claim is only worth anything alongside the proof that
//! earns it: a materialized generation carrying the version that was
//! written, published under the mutation-fence epoch the write itself
//! produced. The invariant this module exists to make structural is
//!
//! > if `Hydrated` is observable, a usable actual-state generation exists
//! > in that same durable commit.
//!
//! "Usable" is exact. [`crate::materialized_generation::
//! lookup_materialized_generation`] returns a row only while its
//! `published_under_mutation_generation` still equals the path's live
//! fence, and every non-`Absent` reader additionally demands a version --
//! `resolved_path_state_hash` encodes version presence, so a versionless
//! proof matches no desired resolution at all and can never close
//! anything. Such a row is not a weaker proof; it is a row that looks
//! healthy while the path is re-materialized forever.
//!
//! # The two lanes
//!
//! **An internal mutator** controls when the mutation happens. It bumps
//! the fence to `N` *before* its first mutating syscall, performs the
//! write, and then publishes under exactly `N` --
//! [`commit_internal_materialized_state_if_fence_current`]. If anything
//! advanced the fence in between, this writer no longer knows what is on
//! disk and must publish nothing.
//!
//! **Recovery** did not mutate anything. It found a path that already
//! claims `Hydrated` whose proof is missing or stale, re-verified the disk
//! bytes under a held path lock, and is restoring the evidence for state
//! that was already true --
//! [`reprove_verified_hydrated_state`]. It has no epoch of its own to CAS
//! against, and inventing one by bumping the fence would be claiming a
//! physical mutation that never happened.
//!
//! A third lane lives elsewhere and must stay there: genuine **external
//! local capture**, where an editor changed disk before the daemon could
//! know. There is no "before the syscall" moment to have bumped against,
//! so minting a fresh epoch is correct -- see
//! [`crate::file_index::adopt_local_capture_actual_state`]. Routing an
//! internal mutator through it is the specific mistake this module
//! replaces: that API advances the fence from `N` to `N+1` on its way to
//! recording what the caller did, so the caller's own settlement evidence,
//! which CASes on `N`, can never win. The healthier the filesystem, the
//! more reliably the path stayed outstanding.

use rusqlite::Transaction;

use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::ids::{ChangeHash, VersionHash};
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::fs_identity::FileIdentity;
use yadorilink_root_authority::root_commit::RootCommitPermit;

use crate::error::SyncSqliteError;
use crate::materialized_generation::{
    publish_materialized_generation_if_fence_current, snapshot_mutation_fence, DiskGenerationBasis,
    MaterializedObjectKind,
};
use crate::{MaterializationIntentRepository, MaterializationStateRepository};

/// Exactly what a path was materialized as, in a shape that cannot express
/// the combination that breaks settlement.
///
/// A non-`Absent` object carries its [`VersionHash`] by value: there is no
/// way to spell "an object, but no version". That is the whole point of
/// the type rather than a validated parameter -- seven production writers
/// previously passed `None` through an `Option<&VersionHash>` that
/// accepted it, and every one of those proofs was unusable.
///
/// `identity` stays optional, and the asymmetry is deliberate. An
/// observation can fail on a write that genuinely completed, and usability
/// is decided by the mutation fence, not by the identity -- so a failed
/// observation costs the proof its identity and nothing else. The version
/// is not contingent in the same way: the write materialized it either
/// way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExactMaterializedState {
    /// Disk holds this exact object at this exact version.
    Object {
        kind: RecordKind,
        version: VersionHash,
        /// Boxed to keep this variant's size near `Absent`'s; only this
        /// arm carries a `FileIdentity`.
        identity: Box<Option<FileIdentity>>,
    },
    /// Disk holds this path's exact absence. A first-class materialized
    /// state, not the absence of one.
    Absent,
}

impl ExactMaterializedState {
    fn object_kind(&self) -> MaterializedObjectKind {
        match self {
            ExactMaterializedState::Object { kind, .. } => match kind {
                RecordKind::File => MaterializedObjectKind::RegularFile,
                RecordKind::Directory => MaterializedObjectKind::Directory,
                RecordKind::Symlink => MaterializedObjectKind::Symlink,
            },
            ExactMaterializedState::Absent => MaterializedObjectKind::Absent,
        }
    }

    fn version(&self) -> Option<&VersionHash> {
        match self {
            ExactMaterializedState::Object { version, .. } => Some(version),
            ExactMaterializedState::Absent => None,
        }
    }

    fn identity(&self) -> Option<&FileIdentity> {
        match self {
            ExactMaterializedState::Object { identity, .. } => identity.as_ref().as_ref(),
            ExactMaterializedState::Absent => None,
        }
    }
}

/// An additional condition the row itself must still satisfy for the
/// commit to land, for a writer whose attempt was bound to one particular
/// authored version.
///
/// A hydration attempt reconstructs the bytes for the version that was
/// current when it started. It re-checks that before committing, but the
/// check and the commit are not one step on their own -- a concurrent
/// update can land in between while the same path lock is held, because
/// the lock serializes daemon-internal work and the supersession comes
/// from the DAG side. Passing the guard here folds the check into the
/// same transaction as the proof, so the attempt either records bytes
/// that are still current or records nothing.
///
/// Without it, the attempt would stamp `Hydrated` for a version it never
/// materialized: the bytes on disk are stale for whatever is current now.
#[derive(Debug, Clone, Copy)]
pub struct ExpectedAuthoring<'a> {
    /// The materialization state the row must still be in -- normally
    /// `Hydrating`, the marker this attempt set when it began.
    pub state: MaterializationState,
    /// The authoring change hash the row must still carry. `None` means
    /// it must still carry no authoring hash at all, which is a distinct
    /// condition from "any".
    pub authoring_change_hash: Option<&'a ChangeHash>,
    /// The version the current row must still name, checked explicitly
    /// rather than inferred from `authoring_change_hash`.
    ///
    /// `None` skips it, for a caller whose authoring binding was taken in
    /// the same breath as the version it is committing. A caller whose
    /// version came from a SNAPSHOT read in an EARLIER transaction -- the
    /// repair sweep -- passes it, because between that snapshot and this
    /// commit the row can be superseded, and an authoring check alone
    /// would not catch a supersession that kept the authoring hash while
    /// changing the content the version is derived from.
    ///
    /// The version is not a stored column; it is recomputed here from the
    /// same current row this guard reads, which is why the comparison
    /// belongs inside this transaction rather than at the call site.
    pub expected_version: Option<&'a VersionHash>,
}

/// What [`commit_internal_materialized_state_if_fence_current`] did.
///
/// Neither refusal is an error. `FenceLost` means another mutator touched
/// this path between this writer's own write and its commit, so this
/// writer no longer knows what is on disk. `AuthoringSuperseded` means the
/// version this attempt materialized is no longer the one the path wants.
/// In both cases publishing nothing is the correct outcome and the
/// caller's work will be re-driven.
#[derive(Debug, Clone)]
pub enum InternalMaterializedCommit {
    /// The proof landed, the state was stamped, and the intent was
    /// cleared -- all in the caller's transaction.
    Published(Box<DiskGenerationBasis>),
    /// The fence had moved. Nothing was written: no generation, no state
    /// change, and in particular the materialization intent is still
    /// open, because it is the only record that a write was ever in
    /// flight.
    FenceLost {
        /// The fence value found instead, for logging. `None` when the
        /// path has no fence row at all.
        live_mutation_generation: Option<i64>,
    },
    /// An [`ExpectedAuthoring`] guard was supplied and the row no longer
    /// satisfies it: this attempt's bytes are stale for whatever version
    /// the path now wants. Nothing was written, the intent included.
    AuthoringSuperseded,
}

/// Commits everything an internal physical mutation proved, atomically.
///
/// The caller bumped the fence to `expected_mutation_generation` before
/// its first mutating syscall, performed the write, and is now recording
/// it. On success, and only inside the caller's own transaction, this
/// performs all three of:
///
/// ```text
/// publish a versioned generation under `expected_mutation_generation`
/// materialization state -> Hydrated
/// clear the materialization intent
/// ```
///
/// They are one commit because any subset of them is a state the system
/// has no way to read correctly. A proof without `Hydrated` re-drives work
/// that is already done; `Hydrated` without a proof is a claim nothing can
/// verify and the readers fail closed on; and a cleared intent without
/// either erases the only record that a write was ever attempted, so
/// nothing retries.
///
/// On `FenceLost` none of the three happens. Clearing the intent anyway
/// would manufacture the unprovable-claim state from the recovery side,
/// which is the failure this whole module exists to make unreachable.
///
/// `Absent` publishes its generation and clears the intent but stamps no
/// `Hydrated`: a path that is exactly absent holds no content, and saying
/// it does would be the same false claim in the other direction. Its
/// materialization state belongs to whatever tombstoned it.
///
/// `causal_basis` is the frontier these physical writes actually realized.
/// A writer that resolved a specific frontier -- a projected upsert
/// realizing one particular winner -- must pass it, because re-deriving it
/// here would attribute the write to whatever resolution happens to be
/// current when it lands. `None` derives the group's current heads inside
/// this same transaction, which is the honest basis for a writer whose
/// work simply reconstructs whatever the path currently resolves to.
///
/// `expected_authoring`, when supplied, must still hold or nothing is
/// written -- see [`ExpectedAuthoring`]. It is checked first, so a
/// superseded attempt leaves the row exactly as it found it.
pub fn commit_internal_materialized_state_if_fence_current(
    tx: &Transaction<'_>,
    group_id: &str,
    path: &str,
    causal_basis: Option<&[ChangeHash]>,
    exact_state: &ExactMaterializedState,
    expected_mutation_generation: i64,
    expected_authoring: Option<ExpectedAuthoring<'_>>,
    now_unix_nanos: i64,
) -> Result<InternalMaterializedCommit, SyncSqliteError> {
    // Checked before anything is written, so a superseded attempt leaves
    // the row exactly as it found it -- including its still-open intent.
    if let Some(guard) = expected_authoring {
        let still_matches: i64 = match guard.authoring_change_hash {
            Some(hash) => tx.query_row(
                "SELECT COUNT(*) FROM files \
                 WHERE group_id = ?1 AND path = ?2 AND state = 'current' \
                   AND materialization_state = ?3 AND authoring_change_hash = ?4",
                rusqlite::params![group_id, path, guard.state.as_db_str(), &hash.0[..]],
                |r| r.get(0),
            )?,
            None => tx.query_row(
                "SELECT COUNT(*) FROM files \
                 WHERE group_id = ?1 AND path = ?2 AND state = 'current' \
                   AND materialization_state = ?3 AND authoring_change_hash IS NULL",
                rusqlite::params![group_id, path, guard.state.as_db_str()],
                |r| r.get(0),
            )?,
        };
        if still_matches == 0 {
            return Ok(InternalMaterializedCommit::AuthoringSuperseded);
        }
        if let Some(expected_version) = guard.expected_version {
            // Recomputed from the current row inside this same
            // transaction, via the one canonical reader, so this compares
            // against exactly the row the proof is about to describe.
            let current = crate::store::read_canonical_current_row(tx, group_id, path)?;
            let matches =
                current.as_ref().is_some_and(|row| row.version_hash() == *expected_version);
            if !matches {
                return Ok(InternalMaterializedCommit::AuthoringSuperseded);
            }
            if let Some(row) = current.as_ref() {
                require_state_describes_row(path, exact_state, expected_version, row)?;
            }
        }
    }

    // Derived here, inside the caller's own transaction, when the caller
    // has no frontier of its own to name. Reading it outside would cost a
    // second connection round-trip on a hot path for the same answer.
    let derived;
    let causal_basis = match causal_basis {
        Some(basis) => basis,
        None => {
            derived = crate::dag_store::group_heads(tx, group_id)?;
            &derived
        }
    };
    let published = publish_materialized_generation_if_fence_current(
        tx,
        group_id,
        path,
        causal_basis,
        exact_state.object_kind(),
        exact_state.version(),
        exact_state.identity(),
        expected_mutation_generation,
        now_unix_nanos,
    )?;

    let Some(basis) = published else {
        let live: Option<i64> = tx
            .query_row(
                "SELECT mutation_generation FROM path_actual_mutation_fences \
                 WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![group_id, path],
                |r| r.get(0),
            )
            .ok();
        return Ok(InternalMaterializedCommit::FenceLost { live_mutation_generation: live });
    };

    if matches!(exact_state, ExactMaterializedState::Object { .. }) {
        MaterializationStateRepository::set_materialization_state_in_tx(
            tx,
            group_id,
            path,
            MaterializationState::Hydrated,
        )?;
    }
    MaterializationIntentRepository::clear_materialization_intent_in_tx(tx, group_id, path)?;

    Ok(InternalMaterializedCommit::Published(Box::new(basis)))
}

/// The reader half of this module's invariant: whether the proof standing
/// for `(group_id, path)` right now is a proof about the version the row
/// currently names.
///
/// [`crate::materialized_generation::lookup_materialized_generation`]
/// already fails closed on staleness and on a versionless present object.
/// What it cannot see is the row. A proof is published for one specific
/// version, and a path moves on: an admission supersedes the row without
/// touching the fence, so the proof stays usable while describing content
/// the path no longer wants. Every caller that treats "a proof exists" as
/// "this path is exactly materialized" is reading the answer to a
/// different question.
///
/// So the comparison is against the version the row itself derives, the
/// one canonical way -- the same derivation the commit guards use, which
/// is the point of there being only one.
///
/// Fail-closed: no row, no proof, an `Absent` proof for a present row, or
/// any disagreement all answer `false`. `false` costs the caller the work
/// it would have done anyway; `true` is the only answer anything skips
/// work on.
pub fn usable_proof_names_current_version(
    conn: &rusqlite::Connection,
    group_id: &str,
    path: &str,
) -> Result<bool, SyncSqliteError> {
    let Some(row) = crate::store::read_canonical_current_row(conn, group_id, path)? else {
        return Ok(false);
    };
    let Some(basis) =
        crate::materialized_generation::lookup_materialized_generation(conn, group_id, path)?
    else {
        return Ok(false);
    };
    Ok(basis.version == Some(row.version_hash()))
}

/// Whether the state a caller is about to publish actually describes the
/// row it is being published for.
///
/// Every caller passes these two things separately -- the exact state it
/// observed, and the guard naming the row it verified against -- so
/// nothing but a check stops them from disagreeing. They agree today at
/// every call site, which is exactly when a check is cheap to add and
/// exactly when it stops being true silently later.
///
/// Fail-closed: a disagreement is a caller bug, not a race, so it is an
/// error rather than a refusal. A refusal would be re-driven forever.
fn require_state_describes_row(
    path: &str,
    exact_state: &ExactMaterializedState,
    expected_version: &VersionHash,
    row: &crate::store::CanonicalCurrentRow,
) -> Result<(), SyncSqliteError> {
    let ExactMaterializedState::Object { kind, version, .. } = exact_state else {
        return Ok(());
    };
    if version != expected_version {
        return Err(SyncSqliteError::CorruptState(format!(
            "publishing a proof for {path} whose version is not the one the caller verified \
             against: the guard and the state describe different versions"
        )));
    }
    if *kind != row.snapshot.record_kind {
        return Err(SyncSqliteError::CorruptState(format!(
            "publishing a {kind:?} proof for {path}, whose current row is a \
             {:?}",
            row.snapshot.record_kind
        )));
    }
    Ok(())
}

/// What [`commit_recovered_materialized_state`] did.
#[derive(Debug, Clone)]
pub enum RecoveredMaterializedCommit {
    /// The proof landed, the state was stamped and the intent was
    /// cleared -- all in the caller's transaction.
    Published(Box<DiskGenerationBasis>),
    /// The row no longer satisfies the guard the caller verified disk
    /// against. Nothing was written, the intent included.
    Superseded,
}

/// The recovery lane's commit, for a path repair has just verified byte
/// for byte and now has to finish.
///
/// It is neither of the other two, and the gap between them is what this
/// exists to close. [`commit_internal_materialized_state_if_fence_current`]
/// is anchored on an epoch its caller bumped before its own first mutating
/// syscall; recovery mutated nothing and owns no such epoch, and minting
/// one would claim a write that never happened and invalidate whatever a
/// concurrent internal mutator is holding. [`reprove_verified_hydrated_state`]
/// is fence-free and correct for a row that is ALREADY `Hydrated` -- it
/// deliberately does not touch the state, because there is no claim to
/// make, only footing to restore.
///
/// Neither fits a row that is mid-flight. A materialization interrupted
/// between its index commit and its finalizer leaves the row in the
/// transient state with its intent open, and repair that finds the bytes
/// already correct has to do all three things the finalizer would have:
/// publish, promote, and clear the intent. Doing them as three calls is
/// three transactions, and the path lock does not span them -- it
/// serializes daemon-internal work, while a supersession comes from the
/// DAG side. Between the publish and the promotion the row can move from
/// V1 to V2, and the promotion then stamps `Hydrated` on a V2 row whose
/// only proof describes V1. That is the precise combination this module
/// exists to make unreachable, reached through its own repair path.
///
/// So: one transaction, and the guard is re-evaluated inside it against
/// the live row rather than against the snapshot the caller read earlier.
/// `expected` is required, not optional -- a caller that verified disk
/// against a row read in an earlier transaction has, by construction,
/// something to be superseded.
///
/// Publishes under the LIVE fence without bumping it, exactly as the
/// re-proving lane does and for the same reason.
pub fn commit_recovered_materialized_state(
    tx: &Transaction<'_>,
    group_id: &str,
    path: &str,
    causal_basis: Option<&[ChangeHash]>,
    exact_state: &ExactMaterializedState,
    expected: ExpectedAuthoring<'_>,
    now_unix_nanos: i64,
) -> Result<RecoveredMaterializedCommit, SyncSqliteError> {
    // Checked first, and against the row as it is NOW -- the whole point
    // of folding these writes together. A caller's snapshot is older than
    // this transaction by at least one commit boundary.
    let Some(current) = crate::store::read_canonical_current_row(tx, group_id, path)? else {
        return Ok(RecoveredMaterializedCommit::Superseded);
    };
    if current.materialization_state != Some(expected.state) {
        return Ok(RecoveredMaterializedCommit::Superseded);
    }
    if current.authoring_change_hash.as_ref() != expected.authoring_change_hash {
        return Ok(RecoveredMaterializedCommit::Superseded);
    }
    // Not optional here, unlike the guard's own `Option`: the version is
    // what the caller compared the bytes on disk against, so a commit
    // that did not check it would be publishing for content it never
    // verified.
    let Some(expected_version) = expected.expected_version else {
        return Err(SyncSqliteError::CorruptState(format!(
            "recovering {path} without an expected version: the bytes were verified against a \
             version, so the commit has to be guarded on it"
        )));
    };
    if current.version_hash() != *expected_version {
        return Ok(RecoveredMaterializedCommit::Superseded);
    }
    require_state_describes_row(path, exact_state, expected_version, &current)?;

    let derived;
    let causal_basis = match causal_basis {
        Some(basis) => basis,
        None => {
            derived = crate::dag_store::group_heads(tx, group_id)?;
            &derived
        }
    };
    // The live value, read and published under in this same transaction's
    // write lock. Not a bump: nothing was mutated, so advancing the fence
    // would supersede evidence a concurrent internal mutator is holding
    // for a write that really did happen.
    let live = snapshot_mutation_fence(tx, group_id, path)?;
    let published = publish_materialized_generation_if_fence_current(
        tx,
        group_id,
        path,
        causal_basis,
        exact_state.object_kind(),
        exact_state.version(),
        exact_state.identity(),
        live,
        now_unix_nanos,
    )?
    .ok_or_else(|| {
        SyncSqliteError::CorruptState(format!(
            "recovering {path} lost its publish against the live fence {live} it had just read"
        ))
    })?;

    // Only an object earns the claim. An exactly-absent path holds no
    // content, the same rule the internal commit applies to its own
    // `Absent` arm.
    if matches!(exact_state, ExactMaterializedState::Object { .. }) {
        MaterializationStateRepository::set_materialization_state_in_tx(
            tx,
            group_id,
            path,
            MaterializationState::Hydrated,
        )?;
    }
    MaterializationIntentRepository::clear_materialization_intent_in_tx(tx, group_id, path)?;
    Ok(RecoveredMaterializedCommit::Published(Box::new(published)))
}

/// Restores the proof for a path that is already `Hydrated` and whose disk
/// state has just been re-verified.
///
/// This is the healing lane, and it is deliberately not
/// [`commit_internal_materialized_state_if_fence_current`]. Nothing was
/// mutated here: a repair pass found a path claiming `Hydrated` whose
/// proof was missing or stale, compared its on-disk bytes against the
/// index under a held path lock, and is re-recording evidence for state
/// that was already true. It has no epoch of its own to CAS against.
///
/// The combination this exists for is a genuine wedge:
/// `Hydrated` + disk bytes that match exactly + no usable proof. Hydration
/// refuses it (fail closed, no proof), pinning refuses it, and a repair
/// pass that merely observed "disk matches" and moved on would leave it
/// permanently stuck. Publishing under the *live* fence is what makes the
/// row usable again immediately.
///
/// It deliberately does not bump the fence: doing so would claim a
/// physical mutation that never happened, and would invalidate any
/// evidence a concurrent internal mutator is holding. It also does not
/// touch the materialization state -- the row is already `Hydrated`, and
/// this call is restoring that claim's footing, not making it.
///
/// `permit` is verified here, inside `tx`, once the guard has passed and
/// before anything is written. A root swapped since the caller's disk
/// check therefore fails the call with nothing published: verifying after
/// the caller's commit instead would leave a durable proof about a root
/// this device no longer owns behind an `Err`. A superseded row still
/// writes nothing and answers `None` without consulting the permit.
// The permit is the eighth argument because it must be checked inside this
// transaction; bundling it with unrelated inputs would hide that.
#[allow(clippy::too_many_arguments)]
pub fn reprove_verified_hydrated_state(
    tx: &Transaction<'_>,
    group_id: &str,
    path: &str,
    causal_basis: Option<&[ChangeHash]>,
    exact_state: &ExactMaterializedState,
    expected: Option<ExpectedAuthoring<'_>>,
    now_unix_nanos: i64,
    permit: &RootCommitPermit<'_>,
) -> Result<Option<DiskGenerationBasis>, SyncSqliteError> {
    // Recovery verified the disk bytes against a row snapshot taken in an
    // EARLIER transaction. If that row has since been superseded, the
    // bytes it verified are no longer what this path wants, and re-proving
    // them would restore a proof for a version the path has moved off.
    // Returning `None` writes nothing at all.
    if let Some(guard) = expected {
        let current = crate::store::read_canonical_current_row(tx, group_id, path)?;
        let Some(current) = current else {
            return Ok(None);
        };
        if current.materialization_state != Some(guard.state) {
            return Ok(None);
        }
        if current.authoring_change_hash.as_ref() != guard.authoring_change_hash {
            return Ok(None);
        }
        if let Some(expected_version) = guard.expected_version {
            if current.version_hash() != *expected_version {
                return Ok(None);
            }
        }
    }
    // Root identity is re-verified before the publish, inside the same
    // transaction, so a lost root rolls the whole heal back.
    permit.verify()?;
    // Derived here, inside the caller's own transaction, when the caller
    // has no frontier of its own to name -- same reasoning as the internal
    // commit above. It matters more here: the repair sweep calls this once
    // per wedged row, so a second connection round-trip would be paid per
    // row across the whole scan.
    let derived;
    let causal_basis = match causal_basis {
        Some(basis) => basis,
        None => {
            derived = crate::dag_store::group_heads(tx, group_id)?;
            &derived
        }
    };
    // Read the live fence and publish under it. Not a bump: the value is
    // whatever is already current, so this republication supersedes no
    // other writer's evidence.
    let live = snapshot_mutation_fence(tx, group_id, path)?;
    let published = publish_materialized_generation_if_fence_current(
        tx,
        group_id,
        path,
        causal_basis,
        exact_state.object_kind(),
        exact_state.version(),
        exact_state.identity(),
        live,
        now_unix_nanos,
    )?;
    published
        .ok_or_else(|| {
            // Only reachable if another writer advanced the fence between
            // the read above and the publish, inside this same
            // transaction's write lock -- report it rather than silently
            // leaving the path unproven.
            SyncSqliteError::CorruptState(format!(
                "re-proving {path} lost its publish against the live fence {live} it had just read"
            ))
        })
        .map(Some)
}

/// The zero-work close of a claimed obligation: the disk already holds
/// exactly what the path resolves to, so the obligation closes with no
/// physical work -- and the proof it closes against is re-anchored on the
/// frontier that resolution was made from.
///
/// Closing alone is not enough. The proof's causal basis is also the
/// parent set a later local edit of those bytes is signed onto
/// ([`crate::file_index`]'s `local_edit_parents_in_tx`). A proof whose
/// basis predates changes the close has just accepted as already
/// reflected on disk leaves those changes concurrent with the user's
/// next edit, and a concurrent content head beats a delete: a peer's
/// conflict-copy merge resolution that re-put bytes this device already
/// had, followed by the user deleting that copy here, resurrected the
/// copy on every device.
///
/// One transaction. The close's own CAS establishes that the obligation's
/// DAG generation, the proof's fence epoch and its resolved state are all
/// still what the caller verified; only then is the same object -- kind,
/// version and identity unchanged -- republished under the live fence,
/// with no bump (nothing was mutated), on the group's current heads. A
/// proof already on those heads is left as it is, generation included. The
/// heads read here cannot include an unreflected change to this path: any
/// admission touching it since the claim moves the obligation's
/// generation, and the close above would have refused.
pub fn complete_zero_work_obligation_rebasing_proof(
    tx: &Transaction<'_>,
    group_id: &str,
    path: &str,
    claimed_invalidation_generation: i64,
    claimed_obligation_incarnation: i64,
    desired_resolved_path_state_hash: &[u8],
    now_unix_nanos: i64,
) -> Result<bool, SyncSqliteError> {
    let closed = crate::projection_obligations::complete_obligation_if_exact_proof_current(
        tx,
        group_id,
        path,
        claimed_invalidation_generation,
        claimed_obligation_incarnation,
        desired_resolved_path_state_hash,
    )?;
    if !closed {
        return Ok(false);
    }
    let Some(proof) =
        crate::materialized_generation::lookup_materialized_generation(tx, group_id, path)?
    else {
        return Ok(true);
    };
    let heads = crate::dag_store::group_heads(tx, group_id)?;
    // Already on this frontier: nothing to re-anchor, and the proof keeps
    // its generation.
    if crate::dag_store::lookup_causal_basis_members(tx, &proof.causal_basis_id.0)?.as_ref()
        == Some(&heads)
    {
        return Ok(true);
    }
    let live = snapshot_mutation_fence(tx, group_id, path)?;
    publish_materialized_generation_if_fence_current(
        tx,
        group_id,
        path,
        &heads,
        proof.object_kind,
        proof.version.as_ref(),
        proof.filesystem_identity.as_ref(),
        live,
        now_unix_nanos,
    )?
    .ok_or_else(|| {
        SyncSqliteError::CorruptState(format!(
            "re-anchoring {path}'s proof lost its publish against the live fence {live} it had \
             just read"
        ))
    })?;
    Ok(true)
}

#[cfg(test)]
mod tests;

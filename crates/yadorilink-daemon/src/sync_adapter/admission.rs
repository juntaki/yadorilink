//! Driving staged Changes into the canonical DAG.
//!
//! # Two kinds of liveness, kept apart
//!
//! ```text
//!   delivery liveness   →  RBSR: peers compare durable sets, so nothing
//!                          delivered can stay undiscovered
//!
//!   admission liveness  →  this coordinator: something that unblocks a
//!                          staged Change wakes a drain
//! ```
//!
//! Neither depends on a timer. Reconciliation finds every difference by
//! comparing sets, and promotion happens because a transition that could have
//! unblocked something says so.
//!
//! # Promotable is not the same as re-evaluated
//!
//! A staged Change becomes promotable the moment its last parent lands or its
//! last capture barrier settles — that is derived from current state, with no
//! stored status to update. But *becoming* promotable and *being promoted* are
//! different events, and nothing observes the first on its own. So every
//! transition that can unblock something wakes the coordinator:
//!
//! * a Change was staged
//! * a Change became canonical
//! * a local capture barrier settled
//! * the daemon started
//!
//! A wake is cheap, non-blocking and coalescing. It is never a correctness
//! mechanism on its own: a lost wake costs the delay until the next one,
//! because a drain always recomputes what is promotable from current state.
//! A periodic sweep exists only to audit lost wakes and crashes; ordinary
//! convergence must complete with it switched off.
//!
//! # Draining to a fixed point
//!
//! One drain per group at a time. A drain promotes what it can, and since a
//! promotion can unblock a child, it goes round again — until a pass promotes
//! nothing. Every promotion is its own plan, its own capture-token
//! revalidation and its own short transaction; nothing is swept in alongside
//! anything else.

use std::sync::Arc;

use yadorilink_replica_domain::ids::{ChangeHash, FolderGroupId};
use yadorilink_sync_protocol::single_flight::{Flight, SingleFlight};
use yadorilink_sync_sqlite::remote_admission::{AdmissionOutcome, Stale};

use super::async_store::AsyncReplicaStore;

/// How many candidates one pass considers. Bounds a single pass's work; the
/// loop keeps going while anything is still moving, so this caps latency per
/// pass rather than total progress.
const CANDIDATES_PER_PASS: usize = 256;

/// What a drain achieved.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DrainOutcome {
    /// Changes promoted into the canonical DAG.
    pub promoted: Vec<ChangeHash>,
    /// Passes made. More than one means a promotion unblocked another Change.
    pub passes: usize,
    /// Candidates left staged because a precondition is still unmet.
    pub still_blocked: usize,
}

#[derive(Debug, thiserror::Error)]
#[error("admission drain failed: {0}")]
pub struct AdmissionError(String);

/// Promotes staged Changes when something unblocks them.
/// Told that a drain promoted something in `group`.
pub type PromotionObserver = Arc<dyn Fn(&FolderGroupId) + Send + Sync>;

pub struct AdmissionCoordinator {
    store: AsyncReplicaStore,
    flight: Arc<SingleFlight<String>>,
    /// Raised after a drain that promoted anything.
    ///
    /// Promotion is the moment a Change becomes part of this device's
    /// published history, and several subsystems are waiting on exactly that:
    /// materialization has a new obligation to run, retirement may have just
    /// had a conflict copy lose its justification, and a held path's hazard
    /// may have just resolved. The legacy admission path raised all three;
    /// each of them also has its own periodic backstop, so without this
    /// nothing breaks — it just waits, up to that backstop's interval.
    promoted: Option<PromotionObserver>,
}

impl AdmissionCoordinator {
    pub fn new(store: AsyncReplicaStore) -> Self {
        Self { store, flight: Arc::new(SingleFlight::new()), promoted: None }
    }

    /// Raise `observer` after any drain that promoted something.
    pub fn notifying(mut self, observer: PromotionObserver) -> Self {
        self.promoted = Some(observer);
        self
    }

    /// Note that something may have unblocked a staged Change in `group`, and
    /// make sure a drain happens.
    ///
    /// This is the only entry point unblocking transitions should use. Marking
    /// the group stale and starting a drain are one operation on purpose: as
    /// two, every call site would carry the contract "and then start a drain",
    /// and the one that forgot would leave a Change promotable forever with
    /// nothing to notice.
    ///
    /// Cheap and non-blocking. If a drain is already running, the epoch bump
    /// is what earns the further pass and the task spawned here finds the
    /// group claimed and returns at once — a burst of transitions does not
    /// become a burst of drains.
    pub fn schedule(self: &Arc<Self>, group: &FolderGroupId) {
        self.flight.wake(&group.0);

        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            // No runtime to drain on. The epoch bump stands, so the next drain
            // from any source honours it; nothing is lost beyond latency.
            tracing::debug!(
                group = %group.0,
                "admission scheduled with no runtime available; the wake stands"
            );
            return;
        };

        let coordinator = self.clone();
        let group = group.clone();
        handle.spawn(async move {
            if let Err(error) = coordinator.drain(&group).await {
                // Nothing is repaired in place. Promotability is recomputed
                // from current state by the next drain, whatever caused this
                // one to stop.
                tracing::warn!(group = %group.0, %error, "admission drain ended early");
            }
        });
    }

    /// Mark `group` stale without starting anything.
    ///
    /// Only for a caller that is about to drain itself. Everything else wants
    /// [`schedule`](Self::schedule).
    pub fn mark_stale(&self, group: &FolderGroupId) {
        self.flight.wake(&group.0);
    }

    /// Promote everything promotable in `group`, to a fixed point.
    ///
    /// At most one drain per group runs at a time. A concurrent call is
    /// coalesced into the running one rather than starting a second.
    pub async fn drain(
        &self,
        group: &FolderGroupId,
    ) -> Result<Option<DrainOutcome>, AdmissionError> {
        let accumulated = std::sync::Mutex::new(DrainOutcome::default());

        let flight = self.flight.clone();
        let outcome = flight
            .run(group.0.clone(), || async {
                let pass = self.drain_to_fixed_point(group).await?;
                let mut total = accumulated.lock().expect("drain outcome poisoned");
                total.promoted.extend(pass.promoted);
                total.passes += pass.passes;
                total.still_blocked = pass.still_blocked;
                Ok::<_, AdmissionError>(())
            })
            .await?;

        match outcome {
            Flight::Ran { .. } => {
                let total = accumulated.into_inner().expect("drain outcome poisoned");
                if !total.promoted.is_empty() {
                    if let Some(observer) = &self.promoted {
                        observer(group);
                    }
                }
                Ok(Some(total))
            }
            Flight::Coalesced => Ok(None),
        }
    }

    async fn drain_to_fixed_point(
        &self,
        group: &FolderGroupId,
    ) -> Result<DrainOutcome, AdmissionError> {
        let mut outcome = DrainOutcome::default();

        loop {
            let candidates = self
                .store
                .admissible_candidates(group.clone(), CANDIDATES_PER_PASS)
                .await
                .map_err(|error| AdmissionError(error.to_string()))?;

            if candidates.is_empty() {
                break;
            }

            outcome.passes += 1;
            let promoted_before = outcome.promoted.len();
            let mut blocked = 0usize;
            // Refusals are progress too: each one removes a staged row and
            // records a verdict that can make that row's staged descendants
            // candidates. Those descendants are only selected by the next
            // candidate query, so a pass that refused something must be
            // followed by another pass, or a parent refused together with its
            // staged children would leave them possessed and never settled.
            let mut settled = 0usize;

            for hash in candidates {
                // Planning runs with no writer transaction held: decoding, the
                // parent walk and the fence reads all happen outside the gate.
                //
                // A failure here is this candidate's failure, not the group's.
                // Propagating it would let one Change that cannot be promoted
                // stop every other Change in the group from being promoted
                // too, indefinitely and silently — a whole group held back by
                // one member. Row14 on the reconciliation path found exactly
                // that: a Change whose referenced file version had not
                // arrived yet ended the drain on every pass, so nothing else
                // in the group ever moved either.
                //
                // Treating it as blocked is not swallowing it. Promotability
                // is recomputed from current state on every pass, so a
                // candidate that fails for a transient reason is retried by
                // the next drain, and one that fails permanently stays
                // counted in `still_blocked` rather than disappearing.
                let plan = match self.store.plan_admission(hash).await {
                    Ok(plan) => plan,
                    Err(error) => {
                        tracing::debug!(
                            group = %group.0,
                            change = %hex::encode(hash.0),
                            %error,
                            "could not plan this Change's promotion; leaving it staged"
                        );
                        blocked += 1;
                        continue;
                    }
                };
                let Some(plan) = plan else {
                    // Promoted by someone else between the query and here.
                    continue;
                };

                // The writer transaction holds only comparison and insertion.
                let committed = match self.store.commit_admission(plan).await {
                    Ok(committed) => committed,
                    Err(error) => {
                        tracing::debug!(
                            group = %group.0,
                            change = %hex::encode(hash.0),
                            %error,
                            "could not commit this Change's promotion; leaving it staged"
                        );
                        blocked += 1;
                        continue;
                    }
                };

                match committed {
                    AdmissionOutcome::Promoted { newly_admitted } => {
                        outcome.promoted.extend(newly_admitted)
                    }
                    AdmissionOutcome::AlreadyCanonical => {}
                    AdmissionOutcome::Stale(
                        Stale::CaptureBarrierOpen { .. } | Stale::CaptureFenceMoved { .. },
                    ) => blocked += 1,
                    // A parent moved, or someone else got there first. Both
                    // are re-drives, and the next pass sees current state.
                    AdmissionOutcome::Stale(_) => blocked += 1,
                    // Not blocked: nothing is waiting on anything. The
                    // Change is gone from the staging area and recorded as
                    // permanently rejected, so counting it as blocked would
                    // keep this drain looping over work that no longer
                    // exists.
                    AdmissionOutcome::RefusedAuthorChain(refusal) => {
                        settled += 1;
                        tracing::warn!(
                            group = %group.0,
                            change = %hex::encode(hash.0),
                            reason = %refusal,
                            "discarded a staged Change its own author chain refuses"
                        );
                    }
                    // Not blocked either, and for a stronger reason: the
                    // Change belongs to a history this device is not on,
                    // so there is nothing here for it to wait for.
                    AdmissionOutcome::RefusedForeignHistoryBase { local, incoming } => {
                        settled += 1;
                        tracing::warn!(
                            group = %group.0,
                            change = %hex::encode(hash.0),
                            local = %local,
                            incoming = %incoming,
                            "discarded a staged Change written on another history"
                        );
                    }
                    // Not blocked: the path is fixed by the Change's own
                    // bytes, so there is nothing left to wait for.
                    AdmissionOutcome::RefusedPath(refusal) => {
                        settled += 1;
                        tracing::warn!(
                            group = %group.0,
                            change = %hex::encode(hash.0),
                            reason = %refusal,
                            "discarded a staged Change naming a path no replica may store"
                        );
                    }
                    AdmissionOutcome::RefusedBehindRejectedParent { parent } => {
                        settled += 1;
                        tracing::warn!(
                            group = %group.0,
                            change = %hex::encode(hash.0),
                            parent = %hex::encode(parent.0),
                            "discarded a staged Change whose DAG parent is permanently refused"
                        );
                    }
                }
            }

            outcome.still_blocked = blocked;

            // A pass that neither promoted nor refused anything is a fixed
            // point: everything left is waiting on something this drain
            // cannot cause. The loop still ends, because every promotion and
            // every refusal removes a staged row.
            if outcome.promoted.len() == promoted_before && settled == 0 {
                break;
            }
        }

        Ok(outcome)
    }
}

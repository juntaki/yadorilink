//! Where a Change got to on one device, layer by layer -- and where it
//! stopped.
//!
//! A single "the file did not appear" assertion cannot say which component is
//! at fault. Guessing from one cost two wrong conclusions in a row on this
//! codebase: an empty `file_index` on an *unlinked* device was read as "the
//! apply path is missing from the architecture", when it was correct
//! store-and-forward behaviour by a device with no link. The fix is not to be
//! more careful; it is to measure each layer separately, so a failure names
//! its own component.
//!
//! ```text
//! 1 VerifiedStaging      the device could serve it over RBSR
//! 2 CanonicalDag         admission promoted it out of staging
//! 3 ObligationRaised     admission's bump scheduled a projection
//! 4 ObligationClosed     the convergence engine finished that projection
//! 5 FileIndex            the group's index has a row for the path
//! 6 DiskContent          the bytes are in the linked folder
//! ```
//!
//! # Which layers a test may assert on
//!
//! All six, on a device assembled from `SyncStack` and a
//! `ReconciliationDriver`. That device is a whole device.
//!
//! Layers 4-6 need a content source, and a content source is a
//! `PeerSyncSession` for the peer that holds the blocks: the convergence
//! engine draws its block-fetch and hydration candidates from one. Since G2
//! a session exists for exactly the peers that are **authorized and
//! reachable over the substrate** -- pinned in `PeerAuthorityState`, with a
//! live iroh connection -- which is what
//! `peer_connectivity_runtime::peer_sessions` keeps. Nothing about it is a
//! fixture concern: `pin`, `SyncStack::spawn` and
//! `install_reconciliation_driver` are the whole of it.
//!
//! This is recent, and the shape it replaced is worth remembering because a
//! regression back to it would look like a network problem. A session used
//! to require an established legacy QUIC channel -- both
//! `PeerSyncSession::new` call sites in `peer_orchestrator.rs` took one --
//! so a device reached only over the substrate admitted the Change, raised
//! the obligation, and had nowhere to fetch its blocks from. The obligation
//! stayed pending for ever, and layers 4-6 were reachable only for a Change
//! carrying **no blocks**, where there was nothing to fetch.
//!
//! `sync_adapter::local_capture_tests::a_written_file_advances_through_every_layer_to_the_peers_disk`
//! is the acceptance test for that, and it is green: it walks all six layers
//! with neither device holding a legacy transport of any kind.
//!
//! **A test must still not give its fixture a session by hand.** Registering
//! one is what made the difference between a device that could fetch content
//! and one that could not, so a fixture that registers its own tests the
//! fixture -- and would stay green through a regression to a transport
//! deciding whether content can flow.
//!
//! # A test about a gate must not read someone else's hold as its own
//!
//! Anything whose subject is *not* content -- a pause gate, an authorization
//! refusal, a partition -- sees the same picture whenever a Change is held
//! before projection: admitted, obligation raised, nothing on disk. Reading
//! that as "my gate worked" is worse than reading it as "my gate failed",
//! because it passes.
//!
//! Per-item pause is the sharpest case, because it is *identical* at every
//! layer. `claim_runnable_obligations` excludes a path covered by a paused
//! item, so its obligation stays exactly as admission left it, pending --
//! character for character what a device that cannot fetch the blocks looks
//! like. [`LayerReport::held_by_the_pause_gate`] tells them apart with one
//! extra read, of `paused_items`, and
//! [`LayerReport::held_before_projection_but_not_paused`] is the other side
//! of it. A test that asserted the six-layer shape alone would credit pause
//! with a hold it had nothing to do with, or the reverse, depending only on
//! which one it set out to prove.
//!
//! Before G2 the second of those was the expected state of every device, and
//! meant "this run cannot tell". It no longer is, so today it means a Change
//! is held by something the test has not named -- a finding, not a known
//! state.
//!
//! ## Worked example: per-item Pause/Resume (Program D, D1b)
//!
//! Pause stops two things and nothing else: a local change propagating to
//! peers, and a remote change projecting to the local filesystem. Receiving,
//! storing and DAG admission continue. Which layer each requirement is read
//! at:
//!
//! | D1b requirement | Where to read it |
//! |---|---|
//! | A local change to a paused path is not sent to the peer | Assert the *peer's* [`LayerReport::servable`] stays false. Nothing about disk, so no projection question arises at all |
//! | A remote change for a paused path is not projected locally | Receiving and admission are not blocked, so layers 1-3 must still be reached, and the obligation stays pending -- [`LayerReport::held_by_the_pause_gate`] is what says pause is why, by reading `paused_items`. The control is an unpaused path on the same device reaching layer 6, which is now available |
//! | Resume catches up without loss | Both halves: the peer's servable set gains exactly what was written while paused, and the paused path's own obligation closes onto disk |
//!
//! All three are writable end to end now. The table survives its second
//! column, which said which halves had to wait for the cutover, because what
//! it recorded is still the right discipline: a pause test that only watched
//! a projection *not* happen would have passed on a device that could not
//! project anything.

use std::cell::Cell;
use std::path::PathBuf;
use std::sync::Arc;

use yadorilink_replica_domain::ids::{ChangeHash, FolderGroupId};

use crate::daemon_state::DaemonState;

/// The layers a Change passes through on the device that receives it, in the
/// order it passes through them.
///
/// `Ord` follows that order, so `report.deepest() >= Some(Layer::CanonicalDag)`
/// says what it looks like it says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Layer {
    /// Verified staging holds the hash: what RBSR could serve.
    VerifiedStaging,
    /// Admission promoted it into the canonical change-history DAG.
    CanonicalDag,
    /// Admission's bump scheduled a projection for the group.
    ObligationRaised,
    /// The convergence engine closed every projection obligation.
    ObligationClosed,
    /// The group's `file_index` has a row for the path.
    FileIndex,
    /// The bytes are in the linked folder.
    DiskContent,
}

impl Layer {
    /// What a failure message should call this layer.
    pub fn name(self) -> &'static str {
        match self {
            Layer::VerifiedStaging => "1 verified staging (RBSR possession)",
            Layer::CanonicalDag => "2 canonical DAG admission",
            Layer::ObligationRaised => "3 projection obligation raised",
            Layer::ObligationClosed => "4 projection obligation closed",
            Layer::FileIndex => "5 file_index row",
            Layer::DiskContent => "6 bytes on disk",
        }
    }
}

/// Reads one device's layers, for one group.
///
/// Holds the device rather than borrowing it so a probe can be captured by the
/// polling closures every test writes (`within(budget, || ...)`).
pub struct LayerProbe {
    state: Arc<DaemonState>,
    group: FolderGroupId,
    /// The linked folder, when the caller has one. Without it layer 6 is not
    /// observable and a report says so rather than reporting a false absence.
    root: Option<PathBuf>,
    /// Latched, because layer 3 is transient: once the engine closes the
    /// obligation the pending count is zero again, and "raised, then closed"
    /// and "never raised" are then indistinguishable from one sample. Every
    /// read updates it, so a test that polls sees the transition.
    ever_raised: Cell<bool>,
}

impl LayerProbe {
    pub fn new(state: &Arc<DaemonState>, group: &str) -> Self {
        Self {
            state: state.clone(),
            group: FolderGroupId(group.into()),
            root: None,
            ever_raised: Cell::new(false),
        }
    }

    /// The same, for a device whose linked folder the caller knows -- which is
    /// what makes layers 5 and 6 observable.
    pub fn with_root(mut self, root: &std::path::Path) -> Self {
        self.root = Some(root.to_path_buf());
        self
    }

    // -- layer 1 ------------------------------------------------------------

    /// Every Change this device could serve over RBSR.
    pub fn servable(&self) -> Vec<ChangeHash> {
        super::sync_stack_fixture::possessed(&self.state, &self.group)
    }

    pub fn is_servable(&self, hash: &ChangeHash) -> bool {
        self.servable().contains(hash)
    }

    // -- layer 2 ------------------------------------------------------------

    /// Whether admission promoted the Change out of staging.
    ///
    /// `..._or_pruned`, because a Change that was admitted and later pruned
    /// did reach this layer: a probe that answered "no" for it would report a
    /// regression where there is retention policy.
    pub fn in_canonical_dag(&self, hash: &ChangeHash) -> bool {
        self.state
            .replica_coordinator
            .change_history_repository()
            .dag_has_change_or_pruned(self.group.0.as_str(), hash)
            .unwrap_or(false)
    }

    /// The paths a Change's ops name, as this device holds it.
    ///
    /// Layer 2's content rather than its presence. "The Change arrived" and
    /// "the Change said what it should have said" are different claims, and a
    /// rename is the case where the difference shows: it has to arrive naming
    /// *both* paths, and a test that only counted Changes would pass on one
    /// that had lost half of what it meant.
    ///
    /// Empty when the Change is not in the canonical DAG -- so a caller
    /// asserts layer 2 first, or it cannot tell "said nothing" from "is not
    /// here".
    pub fn paths_touched(&self, hash: &ChangeHash) -> Vec<String> {
        use yadorilink_replica_domain::change::Op;

        let Ok(Some(change)) = self.state.replica_coordinator.sqlite().dag_get_change(hash) else {
            return Vec::new();
        };
        let mut paths: Vec<String> = change
            .ops
            .iter()
            .flat_map(|op| match op {
                Op::Put { path, .. } | Op::Delete { path } => vec![path.0.clone()],
                // Both, because a Move names both and a caller asking "which
                // paths did this Change touch" means both of them.
                Op::Move { from, to, .. } => vec![from.0.clone(), to.0.clone()],
            })
            .collect();
        paths.sort();
        paths.dedup();
        paths
    }

    // -- layers 3 and 4 -----------------------------------------------------

    /// How many projections this group still owes.
    ///
    /// Reading it latches [`LayerProbe::obligation_ever_raised`].
    pub fn pending_obligations(&self) -> u64 {
        let pending = self
            .state
            .replica_coordinator
            .sqlite()
            .dag_count_pending_projection_obligations(self.group.0.as_str())
            .unwrap_or(0);
        if pending > 0 {
            self.ever_raised.set(true);
        }
        pending
    }

    /// Whether this probe has grounds to say a projection was ever scheduled
    /// for the group.
    ///
    /// **Polls.** Reading the latch alone would be a stale read, and in a
    /// `within(budget, || ...)` loop a stale read never becomes fresh: the
    /// loop spins for the whole budget on a value nothing is updating, then
    /// fails with a report that prints every layer green, because building
    /// the report is what finally went and looked. That happened, to
    /// `a_peer_admits_a_change_and_schedules_its_projection`.
    ///
    /// Group-scoped, so it cannot use the `file_index` row that
    /// [`LayerReport::was_scheduled`] settles it with. A test that has a path
    /// should poll a report and ask that instead; this is for the cases that
    /// genuinely have no path in hand.
    pub fn obligation_ever_raised(&self) -> bool {
        self.pending_obligations();
        self.ever_raised.get()
    }

    /// Whether a paused item covers `path` for this group.
    ///
    /// Read because a pause and anything else that holds a projection stop a
    /// Change at exactly the same place. `claim_runnable_obligations`
    /// excludes a paused path, so its obligation "stays exactly as admission
    /// left it, pending" -- which is character for character what a Change
    /// waiting on something else looks like. Without this read the two are
    /// indistinguishable, and a probe that could not tell them apart would
    /// credit pause with a hold it had nothing to do with, or the reverse.
    pub fn is_paused(&self, path: &str) -> bool {
        let paused = self
            .state
            .replica_coordinator
            .paused_item_repository()
            .list(self.group.0.as_str())
            .unwrap_or_default();
        yadorilink_sync_sqlite::paused_items::path_is_covered(&paused, path)
    }

    // -- layers 5 and 6 -----------------------------------------------------

    /// Whether the group's index has a row for `path`.
    ///
    /// Reading it latches [`LayerProbe::obligation_ever_raised`], because a
    /// row here is proof that layer 3 happened: admission's bump is what
    /// creates a projection obligation, and the convergence engine is what
    /// turns one into this row. There is no path to an indexed projection
    /// that did not pass through an obligation.
    ///
    /// Without that, layer 3 is only ever *sampled*, and it is the one layer
    /// that is transient -- an obligation is raised and then closed. A run
    /// where the engine finished between two polls reported "3 NO, 5 ok, 6
    /// ok": the file on disk with the right bytes, and the probe pointing at
    /// the step that scheduled it. Measured, not reasoned about: that is
    /// exactly how it failed under a loaded full-suite run while passing
    /// alone.
    pub fn in_file_index(&self, path: &str) -> bool {
        let present = self
            .state
            .replica_coordinator
            .file_index_repository()
            .get_file(self.group.0.as_str(), path)
            .ok()
            .flatten()
            .is_some();
        if present {
            self.ever_raised.set(true);
        }
        present
    }

    /// The bytes in the linked folder, when there is a folder to look in.
    ///
    /// `None` for "no root was given", not for "no file": a probe with no root
    /// cannot distinguish an absent file from an unobservable one, and
    /// reporting the second as the first is how a fixture gap becomes a
    /// product verdict.
    pub fn on_disk(&self, path: &str) -> Option<Option<Vec<u8>>> {
        let root = self.root.as_ref()?;
        Some(std::fs::read(root.join(path)).ok())
    }

    // -- all six -----------------------------------------------------------

    /// Every layer at once, for one Change and the path it writes.
    pub fn report(&self, hash: &ChangeHash, path: &str) -> LayerReport {
        // Both of these latch `ever_raised`, so both run before it is read.
        // Struct-literal fields evaluate in source order, and reading the
        // latch above `in_file_index` is what made a report say "3 NO, 5 ok".
        let pending = self.pending_obligations();
        let in_file_index = self.in_file_index(path);
        LayerReport {
            servable: self.is_servable(hash),
            in_canonical_dag: self.in_canonical_dag(hash),
            obligation_ever_raised: self.ever_raised.get(),
            pending_obligations: pending,
            in_file_index,
            disk: self.on_disk(path),
            paused: self.is_paused(path),
            path: path.to_string(),
        }
    }
}

/// One device's six layers, at one moment.
#[derive(Debug, Clone)]
pub struct LayerReport {
    pub servable: bool,
    pub in_canonical_dag: bool,
    pub obligation_ever_raised: bool,
    pub pending_obligations: u64,
    pub in_file_index: bool,
    /// `None` when the probe had no root to look in; `Some(None)` when there
    /// is a root and no file.
    pub disk: Option<Option<Vec<u8>>>,
    /// Whether a paused item covers the path. Pause holds an obligation in
    /// exactly the state the content-source gap does, so nothing below can
    /// name one without reading this.
    pub paused: bool,
    pub path: String,
}

impl LayerReport {
    /// Whether a projection was ever scheduled for this path.
    ///
    /// `obligation_ever_raised` is a *sample*: layer 3 is the one transient
    /// layer, and a run where the engine raised and closed the obligation
    /// between two polls never observes it. An indexed row settles it the
    /// other way round -- admission's bump is the only thing that creates an
    /// obligation, and the engine turning one into that row is the only
    /// thing that closes it, so a row cannot exist without layer 3 having
    /// happened.
    ///
    /// Without this, a completed projection reports "3 NO, 5 ok, 6 ok": the
    /// file on disk with the right bytes, and the probe naming the step that
    /// scheduled it as the failure. Measured, not reasoned about -- the
    /// acceptance test failed exactly that way under a loaded full-suite run
    /// while passing alone.
    pub fn was_scheduled(&self) -> bool {
        self.obligation_ever_raised || self.in_file_index
    }

    /// Whether this path's projection finished.
    ///
    /// The pending count is the *group's*, so a second path still waiting
    /// would otherwise hold this one open. An indexed row is about this path
    /// and settles it directly.
    fn was_projected(&self) -> bool {
        self.in_file_index || (self.was_scheduled() && self.pending_obligations == 0)
    }

    /// The deepest layer this Change reached, or `None` if it reached none.
    pub fn deepest(&self) -> Option<Layer> {
        let mut deepest = None;
        for (reached, layer) in [
            (self.servable, Layer::VerifiedStaging),
            (self.in_canonical_dag, Layer::CanonicalDag),
            (self.was_scheduled(), Layer::ObligationRaised),
            (self.was_projected(), Layer::ObligationClosed),
            (self.in_file_index, Layer::FileIndex),
            (matches!(&self.disk, Some(Some(_))), Layer::DiskContent),
        ] {
            if !reached {
                break;
            }
            deepest = Some(layer);
        }
        deepest
    }

    /// The first layer that did not advance, or `None` if all six did.
    pub fn stopped_at(&self) -> Option<Layer> {
        match self.deepest() {
            None => Some(Layer::VerifiedStaging),
            Some(Layer::DiskContent) => None,
            Some(Layer::VerifiedStaging) => Some(Layer::CanonicalDag),
            Some(Layer::CanonicalDag) => Some(Layer::ObligationRaised),
            Some(Layer::ObligationRaised) => Some(Layer::ObligationClosed),
            Some(Layer::ObligationClosed) => Some(Layer::FileIndex),
            Some(Layer::FileIndex) => Some(Layer::DiskContent),
        }
    }

    /// Admitted, scheduled, still waiting -- and no pause on this path to
    /// account for it.
    ///
    /// The shape: the device holds the Change, admitted it, raised a
    /// projection obligation, and the obligation is still pending.
    ///
    /// Before G2 this was the expected state of every device assembled from
    /// `SyncStack` alone -- no session, so nowhere to fetch the blocks -- and
    /// the method existed so a test about a gate could recognise it and
    /// conclude nothing. A session now exists for every authorized, reachable
    /// peer, so it is no longer anyone's normal state: a report that answers
    /// true is a Change held by something the test has not named. Worth
    /// printing rather than asserting past.
    pub fn held_before_projection_but_not_paused(&self) -> bool {
        self.held_before_projection() && !self.paused
    }

    /// Whether the projection is being withheld by a pause on this path.
    ///
    /// The same shape as the report above, told apart by one read:
    /// `claim_runnable_obligations` excludes a paused path, so its obligation
    /// stays pending exactly as one waiting on anything else does. A test
    /// that asserted the shape alone would credit pause with a hold it had
    /// nothing to do with, or the reverse -- depending only on which one it
    /// was written to prove.
    ///
    /// Note what this does *not* say: that pause is the *only* reason. It
    /// says the pause gate is doing its part. The control that makes it mean
    /// more is an unpaused path on the same device reaching layer 6, which is
    /// a thing a test can now ask for.
    pub fn held_by_the_pause_gate(&self) -> bool {
        self.held_before_projection() && self.paused
    }

    /// Admitted, scheduled, and still waiting -- whatever is holding it.
    fn held_before_projection(&self) -> bool {
        self.servable
            && self.in_canonical_dag
            && self.was_scheduled()
            && self.pending_obligations > 0
            && !self.in_file_index
    }
}

impl std::fmt::Display for LayerReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mark = |reached: bool| if reached { "ok " } else { "NO " };
        writeln!(f, "layers for {:?}:", self.path)?;
        writeln!(f, "  {} {}", mark(self.servable), Layer::VerifiedStaging.name())?;
        writeln!(f, "  {} {}", mark(self.in_canonical_dag), Layer::CanonicalDag.name())?;
        writeln!(f, "  {} {}", mark(self.was_scheduled()), Layer::ObligationRaised.name())?;
        writeln!(
            f,
            "  {} {} (pending={})",
            mark(self.was_projected()),
            Layer::ObligationClosed.name(),
            self.pending_obligations
        )?;
        writeln!(f, "  {} {}", mark(self.in_file_index), Layer::FileIndex.name())?;
        match &self.disk {
            None => writeln!(f, "  -- {} (no root given to the probe)", Layer::DiskContent.name())?,
            Some(bytes) => writeln!(
                f,
                "  {} {} ({})",
                mark(bytes.is_some()),
                Layer::DiskContent.name(),
                bytes.as_ref().map_or("absent".to_string(), |b| format!("{} bytes", b.len()))
            )?,
        }
        match self.stopped_at() {
            None => write!(f, "  -> every layer advanced"),
            Some(layer) => write!(f, "  -> stopped at {}", layer.name()),
        }?;
        if self.held_before_projection_but_not_paused() {
            write!(
                f,
                "\n  -> admitted and scheduled, and nothing on this path is paused, so \
                 something unnamed is holding the projection. Until G2 this was every \
                 device's normal state -- no session, nowhere to fetch the blocks -- and it \
                 is not any more"
            )?;
        } else if self.held_by_the_pause_gate() {
            write!(
                f,
                "\n  -> a paused item covers this path, so the obligation is held by the \
                 pause gate. That it is doing its part; the control for \"pause is why\" is \
                 an unpaused path on this device reaching disk"
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(servable: bool, dag: bool, raised: bool, pending: u64, index: bool) -> LayerReport {
        LayerReport {
            servable,
            in_canonical_dag: dag,
            obligation_ever_raised: raised,
            pending_obligations: pending,
            in_file_index: index,
            disk: Some(None),
            paused: false,
            path: "a.txt".into(),
        }
    }

    /// The whole point of the type: the first layer that did not advance is
    /// what a failure message should name.
    #[test]
    fn a_report_names_the_first_layer_that_did_not_advance() {
        assert_eq!(
            report(false, false, false, 0, false).stopped_at(),
            Some(Layer::VerifiedStaging)
        );
        assert_eq!(report(true, false, false, 0, false).stopped_at(), Some(Layer::CanonicalDag));
        assert_eq!(report(true, true, false, 0, false).stopped_at(), Some(Layer::ObligationRaised));
        assert_eq!(report(true, true, true, 1, false).stopped_at(), Some(Layer::ObligationClosed));
        assert_eq!(report(true, true, true, 0, false).stopped_at(), Some(Layer::FileIndex));
        assert_eq!(report(true, true, true, 0, true).stopped_at(), Some(Layer::DiskContent));
    }

    /// Layer 3 is the only transient layer, and a probe that could only
    /// sample it reports the step that scheduled a projection as the step
    /// that failed -- while layers 5 and 6 sit there saying it worked.
    ///
    /// This is that report, written out. It is not hypothetical: the
    /// acceptance test failed exactly this way under a loaded full-suite run
    /// and passed alone, because the engine raised and closed the obligation
    /// between two polls.
    #[test]
    fn a_projection_that_completed_is_not_a_projection_that_was_never_scheduled() {
        let finished = report(true, true, false, 0, true);

        assert!(
            finished.in_file_index,
            "precondition: this is the shape of a projection that ran to completion"
        );
        assert_eq!(
            finished.deepest(),
            Some(Layer::FileIndex),
            "a completed projection was reported as having stopped before it was scheduled: \
             an indexed row is proof the obligation existed, because admission's bump is the \
             only thing that creates one"
        );
        assert_eq!(
            finished.stopped_at(),
            Some(Layer::DiskContent),
            "the only layer this report leaves unreached is the disk one, because this \
             builder puts no bytes there"
        );

        // And the same row with another path's projection still outstanding.
        // The pending count is the group's, so a second path's work would
        // otherwise hold this one's obligation open for ever.
        let mut busy_group = finished.clone();
        busy_group.pending_obligations = 1;
        assert_eq!(busy_group.deepest(), Some(Layer::FileIndex));
    }

    /// "Raised then closed" and "never raised" are different failures, and a
    /// probe that collapsed them would report the engine for admission's bug.
    #[test]
    fn an_obligation_that_was_never_raised_is_not_a_closed_one() {
        let never = report(true, true, false, 0, false);
        let closed = report(true, true, true, 0, false);

        assert_eq!(never.deepest(), Some(Layer::CanonicalDag));
        assert_eq!(closed.deepest(), Some(Layer::ObligationClosed));
    }

    /// The discriminator a gate test depends on: a Change held between its
    /// obligation and the disk is recognised as that, and a run that stopped
    /// anywhere else is not.
    #[test]
    fn only_a_change_held_before_projection_is_reported_as_held() {
        assert!(report(true, true, true, 1, false).held_before_projection_but_not_paused());

        // Never arrived: whatever held it back, it was not the projection.
        assert!(!report(false, false, false, 0, false).held_before_projection_but_not_paused());
        // Arrived and was never admitted: that is admission, not projection.
        assert!(!report(true, false, false, 0, false).held_before_projection_but_not_paused());
        // Admitted, nothing scheduled: that is admission's bump, not projection.
        assert!(!report(true, true, false, 0, false).held_before_projection_but_not_paused());
        // Everything closed and indexed: nothing is being held back at all.
        assert!(!report(true, true, true, 0, true).held_before_projection_but_not_paused());
    }

    /// A probe with no root says "unobservable", never "absent". Reporting the
    /// second as the first is how a fixture gap becomes a product verdict.
    #[test]
    fn a_probe_without_a_root_does_not_report_disk_as_absent() {
        let mut unrooted = report(true, true, true, 0, true);
        unrooted.disk = None;

        assert_eq!(unrooted.deepest(), Some(Layer::FileIndex));
        assert!(format!("{unrooted}").contains("no root given to the probe"));
    }

    /// A pause and anything else that holds a projection produce the same
    /// six layers, and the probe must not credit either with the other's
    /// work. This is the one bit that tells them apart, so it gets its own
    /// test.
    #[test]
    fn a_paused_path_is_not_reported_as_an_unexplained_hold() {
        let mut paused = report(true, true, true, 1, false);
        paused.paused = true;

        assert!(!paused.held_before_projection_but_not_paused());
        assert!(paused.held_by_the_pause_gate());

        // And the same shape with nothing paused is unexplained, not the gate.
        let unpaused = report(true, true, true, 1, false);
        assert!(unpaused.held_before_projection_but_not_paused());
        assert!(!unpaused.held_by_the_pause_gate());
    }

    /// Neither verdict is available for a Change that never got this far --
    /// a pause on a path whose Change was never admitted is not what held it.
    #[test]
    fn neither_verdict_applies_before_the_obligation_exists() {
        let mut paused_but_unadmitted = report(true, false, false, 0, false);
        paused_but_unadmitted.paused = true;

        assert!(!paused_but_unadmitted.held_by_the_pause_gate());
        assert!(!paused_but_unadmitted.held_before_projection_but_not_paused());
    }

    /// The rendering carries the warning, because the place a person reads
    /// this is a failure message rather than this file.
    #[test]
    fn the_rendered_report_says_when_a_projection_is_being_held() {
        let held = format!("{}", report(true, true, true, 1, false));
        assert!(held.contains("something unnamed is holding the projection"), "{held}");

        let arrived = format!("{}", report(true, true, true, 0, true));
        assert!(!arrived.contains("holding the projection"), "{arrived}");

        let mut paused = report(true, true, true, 1, false);
        paused.paused = true;
        let paused = format!("{paused}");
        assert!(paused.contains("pause gate"), "{paused}");
        assert!(
            !paused.contains("something unnamed"),
            "a paused path was reported as an unexplained hold: {paused}"
        );
    }
}

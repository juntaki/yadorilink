//! From the preserved barrier to an installed target under the freeze: the
//! quarantine of what may no longer be authored, the install transaction and what
//! survives a crash anywhere in between.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::native_checkpoint_install::{CLEARED_BY_INSTALL, PRESERVED_BY_INSTALL};
use crate::native_rebootstrap::{
    rebootstrap_status, recover_after_restart, BlockedReason, CaptureBarrier, Crash,
    PreservationFailure, PreserveContext, Preserved, RebootstrapState, RestartOutcome,
};
use crate::native_rebootstrap_install::{
    install_rebootstrap, quarantined_items, InstallContext, InstallError, InstallPoint,
    InstallStep, Installed, Observed, QuarantineRoot, QuarantineStatus,
};
use crate::native_rebootstrap_recovery::RecoveryArea;

use super::history_lifecycle_red::{
    dots_at, frontier_seq, incarnation_of, offline_base, put_op, rem, scenario, signed, Scenario,
};
use super::rebootstrap_preserve::{
    begin_custom, begin_with, device_b, no_hook, private_tempdir, publish_past_the_freeze,
    recovery_dirs_of, SeedContent, Setup, Viewer, Writer,
};
use super::*;

// --- the harness ------------------------------------------------------------------------------

/// A sync root on a real directory: what the daemon's root-confined operations
/// reach, minus the confinement.
pub(super) struct FsRoot<'a> {
    pub(super) dir: PathBuf,
    pub(super) removed: RefCell<Vec<String>>,
    /// Run just before anything is removed.
    before_remove: Option<&'a dyn Fn(&str)>,
}

impl<'a> FsRoot<'a> {
    pub(super) fn new(dir: &Path) -> Self {
        Self { dir: dir.to_path_buf(), removed: RefCell::new(Vec::new()), before_remove: None }
    }

    fn checking(dir: &Path, before_remove: &'a dyn Fn(&str)) -> Self {
        Self { before_remove: Some(before_remove), ..Self::new(dir) }
    }
}

impl FsRoot<'_> {
    fn observe_at(&self, full: &Path) -> Result<Observed, String> {
        let Ok(meta) = fs::symlink_metadata(full) else { return Ok(Observed::Absent) };
        if meta.file_type().is_symlink() {
            let target = fs::read_link(full).map_err(|e| e.to_string())?;
            return Ok(Observed::Symlink { target: target.to_string_lossy().as_bytes().to_vec() });
        }
        if meta.is_dir() {
            return Ok(Observed::Directory);
        }
        if meta.is_file() {
            let bytes = fs::read(full).map_err(|e| e.to_string())?;
            return Ok(Observed::File {
                size: bytes.len() as u64,
                sha256: Sha256::digest(&bytes).into(),
            });
        }
        Ok(Observed::Other)
    }
}

impl QuarantineRoot for FsRoot<'_> {
    fn observe(&self, path: &str) -> Result<Observed, String> {
        self.observe_at(&self.dir.join(path))
    }

    fn read_file(&self, path: &str) -> Result<Vec<u8>, String> {
        fs::read(self.dir.join(path)).map_err(|e| e.to_string())
    }

    fn remove(&self, path: &str, expected: &Observed) -> Result<(), String> {
        if self.observe(path)? != *expected {
            return Err(format!("{path} changed since it was observed"));
        }
        if let Some(check) = self.before_remove {
            check(path);
        }
        // As a real root does: rename aside inside the root, verify, then unlink.
        let full = self.dir.join(path);
        let aside = self.dir.join(format!(".{}.quarantining", path.replace('/', "_")));
        fs::rename(&full, &aside).map_err(|e| e.to_string())?;
        let now = FsRoot::new(&self.dir).observe_at(&aside)?;
        if now != *expected {
            fs::rename(&aside, &full).map_err(|e| e.to_string())?;
            return Err(format!("{path} changed while it was being removed"));
        }
        fs::remove_file(&aside).map_err(|e| e.to_string())?;
        self.removed.borrow_mut().push(path.to_owned());
        Ok(())
    }
}

fn preserve_context<'a>(
    recovery_root: &'a Path,
    capture: CaptureBarrier,
    authority: &'a dyn crate::native_rebootstrap::ReassertAuthority,
) -> PreserveContext<'a> {
    PreserveContext {
        recovery_root,
        items_root: super::rebootstrap_preserve::items_root_of(recovery_root),
        sync_roots: &[],
        available_bytes: None,
        capture,
        final_capture: &super::rebootstrap_preserve::NoCapture,
        content: &SeedContent,
        authority,
        now_unix: 2000,
    }
}

/// Installs the rebootstrap the journal of `local` names, from the barrier.
pub(super) fn install_with(
    local: &Connection,
    recovery_root: &Path,
    root: &dyn QuarantineRoot,
    authority: &dyn crate::native_rebootstrap::ReassertAuthority,
    hook: &mut dyn FnMut(InstallPoint) -> Result<(), Crash>,
) -> Result<Installed, InstallError> {
    let status = rebootstrap_status(local, &group()).unwrap().expect("a rebootstrap");
    let preserve = preserve_context(recovery_root, CaptureBarrier::Completed, authority);
    // A writer: this device signs the closure of its old incarnation.
    let own = crate::author_incarnation::current_author(local).unwrap().device;
    let key = device_key(device_seed(own.as_str()));
    install_rebootstrap(
        local,
        &InstallContext { preserve: &preserve, root, closure_key: Some(&key) },
        &group(),
        &status.recovery_id,
        hook,
    )
}

pub(super) fn install(
    local: &Connection,
    recovery_root: &Path,
    root: &dyn QuarantineRoot,
) -> Result<Installed, InstallError> {
    install_with(local, recovery_root, root, &Writer, &mut |_| Ok(()))
}

fn crash_on(point: InstallPoint) -> impl FnMut(InstallPoint) -> Result<(), Crash> {
    move |reached| if reached == point { Err(Crash) } else { Ok(()) }
}

/// The scenario every test starts from: a device `B` whose undelivered edit of
/// `x` (v2) the sealer's target does not cover, preserved.
struct Preserved2 {
    w: Scenario,
    recovery_root: tempfile::TempDir,
    root: tempfile::TempDir,
    preserved: Preserved,
}

fn preserved_scenario(authority: &dyn crate::native_rebootstrap::ReassertAuthority) -> Preserved2 {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let recovery_root = private_tempdir();
    let root = tempfile::tempdir().unwrap();
    let setup = Setup { authority, ..Setup::default() };
    let preserved =
        begin_custom(&w.b, built(&w.sealer), recovery_root.path(), &setup, &mut no_hook).unwrap();
    Preserved2 { w, recovery_root, root, preserved }
}

fn heads_of(c: &Connection) -> yadorilink_replica_domain::native_state::NativeState {
    crate::native_store::load_state(c, &group()).unwrap()
}

// --- the install ---------------------------------------------------------------------------------

/// The native state becomes the target's, this device authors as a new
/// incarnation, the old one is fenced at the target's position, and the group
/// stays frozen until the rebootstrap is finished.
#[test]
fn the_install_replaces_the_native_state_rotates_and_fences_and_the_group_stays_frozen() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let old_author = crate::author_incarnation::current_author(&p.w.b).unwrap();
    let before_roots = roots_of(&p.w.b);
    assert_ne!(before_roots, roots_of(&p.w.sealer), "sanity: B has state the target lacks");

    let installed = install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();

    // The target's state, whole.
    assert_eq!(roots_of(&p.w.b), roots_of(&p.w.sealer));
    assert_eq!(heads_of(&p.w.b), heads_of(&p.w.sealer));
    // A new incarnation, minted for this, and the old one fenced at the target's position.
    let record = crate::author_incarnation::incarnation_record(&p.w.b).unwrap().unwrap();
    assert_eq!(
        record.minted_reason,
        yadorilink_replica_domain::author::IncarnationMintReason::Rebootstrap
    );
    assert_eq!(record.previous, Some(old_author.incarnation));
    assert_ne!(record.author, old_author);
    assert_eq!(installed.new_author, record.author);
    assert_eq!(installed.old_authors, vec![old_author.clone()]);
    assert_eq!(
        unexported_rotation_cutoff(&p.w.b, &group(), &old_author),
        Some(Some(yadorilink_replica_domain::ids::AuthorSeq(1))),
        "the fence is the old author's position in the target"
    );
    // The changes of the old incarnation the target lacks are gone from the log, but
    // not from the recovery area.
    assert_eq!(frontier_seq(&p.w.b, &old_author), Some(1));
    assert!(crate::native_store::fetch_delta_body(
        &p.w.b,
        &group(),
        &old_author,
        yadorilink_replica_domain::ids::AuthorSeq(2)
    )
    .unwrap()
    .is_none());
    let area = RecoveryArea::open_dir(&p.preserved.dir).unwrap();
    assert!(area.read_delta(&p.w.undelivered.delta_hash()).is_ok(), "the area keeps the old delta");
    // The journal, and the freeze it keeps.
    assert_eq!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::CatchingUp
    );
    assert!(crate::native_rebootstrap::group_frozen(&p.w.b, group().as_str()).unwrap());
    let _ = dots_at(&p.w.b, "x");
}

/// Installing again after the install is the same answer, and changes nothing.
#[test]
fn installing_twice_is_idempotent() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let first = install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();
    let state = heads_of(&p.w.b);

    let second = install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();

    assert_eq!(second, first);
    assert_eq!(heads_of(&p.w.b), state);
    assert_eq!(
        crate::author_incarnation::current_author(&p.w.b).unwrap(),
        first.new_author,
        "a second install must not rotate again"
    );
}

// --- crash safety ----------------------------------------------------------------------------------

const TX_STEPS: [InstallStep; 5] = [
    InstallStep::NativeStateCleared,
    InstallStep::TargetInstalled,
    InstallStep::ProjectionArmed,
    InstallStep::Rotated,
    InstallStep::Recorded,
];

/// A crash anywhere inside the transaction leaves the old state, the old
/// incarnation, no fence and the journal at `quarantining`; the install then
/// completes from there.
#[test]
fn a_crash_inside_the_install_transaction_changes_nothing_and_the_install_resumes() {
    for step in TX_STEPS {
        let p = preserved_scenario(&Writer);
        let fs_root = FsRoot::new(p.root.path());
        let old_author = crate::author_incarnation::current_author(&p.w.b).unwrap();
        let state = heads_of(&p.w.b);
        let roots = roots_of(&p.w.b);

        let crashed = install_with(
            &p.w.b,
            p.recovery_root.path(),
            &fs_root,
            &Writer,
            &mut crash_on(InstallPoint::InTransaction(step)),
        );

        assert!(matches!(crashed, Err(InstallError::Crashed)), "{step:?}: {crashed:?}");
        assert_eq!(heads_of(&p.w.b), state, "{step:?}: the state changed");
        assert_eq!(roots_of(&p.w.b), roots, "{step:?}");
        assert_eq!(
            crate::author_incarnation::current_author(&p.w.b).unwrap(),
            old_author,
            "{step:?}"
        );
        assert_eq!(
            unexported_rotation_cutoff(&p.w.b, &group(), &old_author),
            None,
            "{step:?}: a fence was written by a transaction that did not commit"
        );
        assert_eq!(
            rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
            RebootstrapState::Quarantining,
            "{step:?}"
        );
        assert!(
            crate::native_rebootstrap::group_frozen(&p.w.b, group().as_str()).unwrap(),
            "{step:?}: the freeze survives the crash"
        );

        let installed = install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();
        assert_eq!(roots_of(&p.w.b), roots_of(&p.w.sealer), "{step:?}");
        assert_eq!(installed.old_authors, vec![old_author], "{step:?}");
    }
}

/// A crash right after the commit finds it committed: the install is done and a
/// second call does nothing.
#[test]
fn a_crash_after_the_commit_finds_the_install_done() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());

    let crashed = install_with(
        &p.w.b,
        p.recovery_root.path(),
        &fs_root,
        &Writer,
        &mut crash_on(InstallPoint::AfterCommit),
    );
    assert!(matches!(crashed, Err(InstallError::Crashed)));
    let author = crate::author_incarnation::current_author(&p.w.b).unwrap();

    let restart = recover_after_restart(&p.w.b, p.recovery_root.path(), &group()).unwrap();
    assert!(matches!(restart, RestartOutcome::CatchingUp(_)), "{restart:?}");
    let again = install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();
    assert_eq!(again.new_author, author);
}

// --- the freeze comes first -----------------------------------------------------------------------------

/// The journal says `Quarantining` (the group has been frozen since the capture)
/// before any original leaves the root.
#[test]
fn the_quarantine_is_recorded_before_the_first_original_leaves_the_root() {
    let p = preserved_scenario(&Viewer);
    let fs_root = FsRoot::new(p.root.path());
    fs::write(p.root.path().join("x"), [2]).unwrap();

    let crashed = install_with(
        &p.w.b,
        p.recovery_root.path(),
        &fs_root,
        &Viewer,
        &mut crash_on(InstallPoint::AfterBeginQuarantine),
    );

    assert!(matches!(crashed, Err(InstallError::Crashed)));
    assert!(fs_root.removed.borrow().is_empty(), "an original left before the quarantine began");
    assert_eq!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::Quarantining
    );
    assert!(p.root.path().join("x").exists());
}

// --- quarantine ---------------------------------------------------------------------------------------------

/// An original this device may no longer author leaves the root once its verified
/// copy is in the area, and is reported with its recovery id and path.
#[test]
fn an_unauthorable_original_leaves_the_root_after_its_copy_is_verified() {
    let p = preserved_scenario(&Viewer);
    // At the moment the original leaves, the journal says the root is being
    // modified and the group is frozen.
    let hold_stands = |_: &str| {
        assert!(crate::native_rebootstrap::group_frozen(&p.w.b, group().as_str()).unwrap());
        assert_eq!(
            rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
            RebootstrapState::Quarantining
        );
    };
    let fs_root = FsRoot::checking(p.root.path(), &hold_stands);
    fs::write(p.root.path().join("x"), [2]).unwrap();

    let installed =
        install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(())).unwrap();

    assert!(!p.root.path().join("x").exists(), "the original is still in the root");
    assert_eq!(*fs_root.removed.borrow(), vec!["x".to_string()]);
    let area = RecoveryArea::open_dir(&p.preserved.dir).unwrap();
    let manifest = area.read_intent().unwrap().manifest;
    let items = quarantined_items(&p.w.b, &group(), Some(&manifest)).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].path, "x");
    assert_eq!(items[0].recovery_id, p.preserved.recovery_id);
    assert_eq!(items[0].status, QuarantineStatus::Removed);
    assert!(!items[0].versions.is_empty(), "the status names the versions the area holds");
    // Nothing re-authors it: the installed projection decides what stands there.
    assert_eq!(installed.old_authors.len(), 1);
}

/// An edit made after the barrier is not the copy in the area: it is saved under
/// its own digest before the original leaves.
#[test]
fn an_edit_made_after_the_barrier_is_kept_before_the_original_leaves() {
    let p = preserved_scenario(&Viewer);
    let fs_root = FsRoot::new(p.root.path());
    fs::write(p.root.path().join("x"), b"typed after the barrier").unwrap();

    install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(())).unwrap();

    assert!(!p.root.path().join("x").exists());
    let digest: [u8; 32] = Sha256::digest(b"typed after the barrier").into();
    let area = RecoveryArea::open_dir(&p.preserved.dir).unwrap();
    assert_eq!(area.read_late_edit(&digest).unwrap(), b"typed after the barrier");
    let items = quarantined_items(&p.w.b, &group(), None).unwrap();
    assert_eq!(items[0].status, QuarantineStatus::RemovedLateEdit { sha256: digest });
}

/// An original already gone, or a directory in its place, is never an error and
/// never removes anything it should not.
#[test]
fn an_absent_original_and_a_directory_in_its_place_are_handled() {
    let p = preserved_scenario(&Viewer);
    let fs_root = FsRoot::new(p.root.path());
    install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(())).unwrap();
    assert_eq!(
        quarantined_items(&p.w.b, &group(), None).unwrap()[0].status,
        QuarantineStatus::AlreadyAbsent
    );

    let q = preserved_scenario(&Viewer);
    let fs_root = FsRoot::new(q.root.path());
    fs::create_dir(q.root.path().join("x")).unwrap();
    fs::write(q.root.path().join("x/inside"), b"another path").unwrap();
    install_with(&q.w.b, q.recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(())).unwrap();
    assert_eq!(
        quarantined_items(&q.w.b, &group(), None).unwrap()[0].status,
        QuarantineStatus::LeftInPlace
    );
    assert!(q.root.path().join("x/inside").exists());
}

/// A change this device may still author keeps its file in the root.
#[test]
fn a_reassertable_original_is_never_removed() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    fs::write(p.root.path().join("x"), [2]).unwrap();

    install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();

    assert!(p.root.path().join("x").exists(), "a re-assertable file was removed");
    assert!(fs_root.removed.borrow().is_empty());
    assert!(quarantined_items(&p.w.b, &group(), None).unwrap().is_empty());
}

/// A crash between two quarantine steps removes each original exactly once on
/// the way to the install.
#[test]
fn a_crash_between_quarantine_steps_removes_each_original_exactly_once() {
    let o = offline_base(false);
    let d1 = signed(&o.b1, 1, None, vec![put_op("p", 2, Vec::new())]);
    let d2 = signed(&o.b1, 2, Some(d1.delta_hash()), vec![put_op("q", 3, Vec::new())]);
    for d in [&d1, &d2] {
        publish(&o.b, &o.b1, &device_key(2), d.clone());
    }
    let recovery_root = private_tempdir();
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("p"), [2]).unwrap();
    fs::write(root.path().join("q"), [3]).unwrap();
    let setup = Setup { authority: &Viewer, ..Setup::default() };
    begin_custom(&o.b, built(&o.sealer), recovery_root.path(), &setup, &mut no_hook).unwrap();
    let fs_root = FsRoot::new(root.path());

    let crashed = install_with(
        &o.b,
        recovery_root.path(),
        &fs_root,
        &Viewer,
        &mut crash_on(InstallPoint::AfterQuarantineItem(0)),
    );
    assert!(matches!(crashed, Err(InstallError::Crashed)));
    assert_eq!(fs_root.removed.borrow().len(), 1);

    install_with(&o.b, recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(())).unwrap();

    let mut removed = fs_root.removed.borrow().clone();
    removed.sort();
    assert_eq!(removed, vec!["p".to_string(), "q".to_string()], "each original is removed once");
}

// --- the install runs from the stored target and nothing else -------------------------------------------

/// A later, different target is offered while the first waits at the barrier. The
/// install takes the recovery id and installs what is stored there.
#[test]
fn installing_uses_the_preserved_target_not_a_later_received_one() {
    let p = preserved_scenario(&Writer);
    let first_roots = roots_of(&p.w.sealer);
    // The sealer moves on: a later target exists, and nothing ever hands it to the install.
    let c = incarnation_of("device-c", 1);
    publish(&p.w.sealer, &c, &device_key(3), signed(&c, 1, None, vec![put_op("w", 5, Vec::new())]));
    assert_ne!(roots_of(&p.w.sealer), first_roots);
    let fs_root = FsRoot::new(p.root.path());

    install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();

    assert_eq!(roots_of(&p.w.b), first_roots, "the later target was installed");
    assert!(dots_at(&p.w.b, "w").is_empty());
}

/// A stored bundle that was changed after the barrier is refused before anything
/// is touched.
#[test]
fn a_stored_target_that_changed_is_not_installed() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let bundle = p.preserved.dir.join("target.bundle");
    let mut bytes = fs::read(&bundle).unwrap();
    bytes[0] ^= 0xff;
    fs::write(&bundle, bytes).unwrap();
    let state = heads_of(&p.w.b);

    let outcome = install(&p.w.b, p.recovery_root.path(), &fs_root);

    assert!(matches!(outcome, Err(InstallError::Blocked(_))), "{outcome:?}");
    assert_eq!(heads_of(&p.w.b), state);
    assert_eq!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::Preserved,
        "the quarantine began for a target that cannot be installed"
    );
}

/// The install is for the recovery id the journal names.
#[test]
fn another_recovery_id_is_not_installable() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let preserve = preserve_context(p.recovery_root.path(), CaptureBarrier::Completed, &Writer);
    let outcome = install_rebootstrap(
        &p.w.b,
        &InstallContext { preserve: &preserve, root: &fs_root, closure_key: None },
        &group(),
        "00000000000000000000000000000000",
        &mut |_| Ok(()),
    );
    assert!(matches!(outcome, Err(InstallError::NotInstallable(_))), "{outcome:?}");
}

// --- the protected set is checked when the root is about to change --------------------------------------

/// Something written past the freeze between the barrier and the install makes
/// what the barrier protected stale: the install refuses before it touches
/// anything, and the old state, the area and the root stay as they were.
#[test]
fn a_write_past_the_freeze_stops_the_install_before_anything_changes() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let d3 =
        signed(&p.w.b1, 3, Some(p.w.undelivered.delta_hash()), vec![put_op("z", 5, Vec::new())]);
    publish_past_the_freeze(&p.w.b, &p.w.b1, &device_key(2), d3);
    let state = heads_of(&p.w.b);

    let outcome = install(&p.w.b, p.recovery_root.path(), &fs_root);

    assert!(matches!(outcome, Err(InstallError::FrontierChanged)), "{outcome:?}");
    assert_eq!(heads_of(&p.w.b), state, "the old state was cleared");
    assert_eq!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::Preserved,
        "the quarantine began over a stale barrier"
    );
    assert_eq!(recovery_dirs_of(p.recovery_root.path()), vec![p.preserved.dir.clone()]);
    assert!(fs_root.removed.borrow().is_empty());
}

/// A capture pass that did not complete is no basis for the install.
#[test]
fn a_partial_capture_pass_blocks_the_install() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let status = rebootstrap_status(&p.w.b, &group()).unwrap().unwrap();
    let preserve = preserve_context(
        p.recovery_root.path(),
        CaptureBarrier::Partial { detail: "unreadable directory".into() },
        &Writer,
    );

    let outcome = install_rebootstrap(
        &p.w.b,
        &InstallContext { preserve: &preserve, root: &fs_root, closure_key: None },
        &group(),
        &status.recovery_id,
        &mut |_| Ok(()),
    );

    assert!(matches!(
        outcome,
        Err(InstallError::Blocked(BlockedReason::PreservationFailed(
            PreservationFailure::CapturePartial { .. }
        )))
    ));
    assert_eq!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::Preserved
    );
}

// --- restart ------------------------------------------------------------------------------------------------

/// After a crash the restart reports where the machine is, and a new target is
/// refused once the root may have been modified.
#[test]
fn a_restart_in_quarantining_resumes_and_no_other_target_is_accepted() {
    let p = preserved_scenario(&Viewer);
    let fs_root = FsRoot::new(p.root.path());
    fs::write(p.root.path().join("x"), [2]).unwrap();
    let _ = install_with(
        &p.w.b,
        p.recovery_root.path(),
        &fs_root,
        &Viewer,
        &mut crash_on(InstallPoint::AfterQuarantineItem(0)),
    );

    let restart = recover_after_restart(&p.w.b, p.recovery_root.path(), &group()).unwrap();
    assert!(matches!(restart, RestartOutcome::Quarantining(_)), "{restart:?}");

    let c = incarnation_of("device-c", 1);
    publish(&p.w.sealer, &c, &device_key(3), signed(&c, 1, None, vec![put_op("w", 5, Vec::new())]));
    let other = begin_with(&p.w.b, built(&p.w.sealer), p.recovery_root.path(), &mut no_hook);
    assert!(
        matches!(other, Err(crate::native_rebootstrap::BeginError::TargetFixed(_))),
        "{other:?}"
    );
    assert_eq!(recovery_dirs_of(p.recovery_root.path()), vec![p.preserved.dir.clone()]);
}

// --- the install keeps the rebootstrap's own state ----------------------------------------------------------------

/// Every table with a `group_id` column is either cleared by the install or kept
/// by it, and the lists say which: a new table has to be classified before it
/// can be shipped.
#[test]
fn every_group_table_is_classified_as_cleared_or_preserved_by_the_install() {
    let c = conn();
    let mut tables: BTreeSet<String> = BTreeSet::new();
    let names: Vec<String> = {
        let mut stmt = c.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").unwrap();
        stmt.query_map([], |row| row.get::<_, String>(0)).unwrap().map(Result::unwrap).collect()
    };
    for name in names {
        let has_group_id = c
            .prepare(&format!("PRAGMA table_info({name})"))
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .map(Result::unwrap)
            .any(|column| column == "group_id");
        if has_group_id {
            tables.insert(name);
        }
    }
    let cleared: BTreeSet<String> = CLEARED_BY_INSTALL.iter().map(|t| t.to_string()).collect();
    let kept: BTreeSet<String> = PRESERVED_BY_INSTALL.iter().map(|t| t.to_string()).collect();
    assert!(cleared.is_disjoint(&kept), "a table is both: {:?}", cleared.intersection(&kept));
    let unclassified: Vec<&String> =
        tables.iter().filter(|t| !cleared.contains(*t) && !kept.contains(*t)).collect();
    assert!(unclassified.is_empty(), "not classified as cleared or preserved: {unclassified:?}");
    let unknown: Vec<&String> =
        cleared.iter().chain(kept.iter()).filter(|t| !tables.contains(*t)).collect();
    assert!(unknown.is_empty(), "classified but without a group_id column: {unknown:?}");
}

/// The install clears the replicated and derived state of the group, and the
/// rebootstrap's own bookkeeping, the fence and the other groups' state stay.
#[test]
fn the_install_clears_native_state_but_keeps_the_rebootstraps_own_bookkeeping() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    // Another group's native state must not be touched.
    let other_group = FolderGroupId("another-group".into());
    p.w.b
        .execute(
            "INSERT INTO native_author_context (group_id, author, incarnation, seq) \
             VALUES (?1, 'device-z', X'00000000000000000000000000000001', 1)",
            [other_group.as_str()],
        )
        .unwrap();
    let items_before: i64 =
        p.w.b
            .query_row(
                "SELECT COUNT(*) FROM native_rebootstrap_recovery_item WHERE group_id = ?1",
                [group().as_str()],
                |row| row.get(0),
            )
            .unwrap();
    let deltas_before: i64 =
        p.w.b
            .query_row(
                "SELECT COUNT(*) FROM native_rebootstrap_delta WHERE group_id = ?1",
                [group().as_str()],
                |row| row.get(0),
            )
            .unwrap();
    assert!(items_before > 0 && deltas_before > 0);

    install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();

    let count = |table: &str, group: &str| -> i64 {
        p.w.b
            .query_row(&format!("SELECT COUNT(*) FROM {table} WHERE group_id = ?1"), [group], |r| {
                r.get(0)
            })
            .unwrap()
    };
    assert_eq!(count("native_rebootstrap_recovery_item", group().as_str()), items_before);
    assert_eq!(count("native_rebootstrap_delta", group().as_str()), deltas_before);
    assert_eq!(count("native_rebootstrap_journal", group().as_str()), 1);
    assert_eq!(count("native_author_closure", group().as_str()), 1);
    assert_eq!(count("native_author_context", other_group.as_str()), 1, "another group's state");
}

// --- the sidecar -----------------------------------------------------------------------------------------

/// The rotation commits with the install; the `<db>.instance` sidecar is written
/// after it. A crash between the two leaves the database on the new incarnation
/// and the sidecar on the old one. The restart repairs the sidecar: it does not
/// mint another incarnation, which would orphan what was authored under the
/// first.
#[test]
fn install_commits_b2_then_crash_before_sidecar_rewrite_restart_keeps_b2_and_does_not_mint_b3() {
    use crate::author_incarnation::{
        ensure_incarnation, incarnation_record, IncarnationEnvironment, InstanceSidecar,
    };
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let before = incarnation_record(&p.w.b).unwrap().unwrap();
    let stale_sidecar = InstanceSidecar::for_record(&before);

    let installed = install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();
    let environment = |sidecar| IncarnationEnvironment {
        device_id: before.author.device.clone(),
        sidecar,
        machine_fingerprint: before.machine_fingerprint.clone(),
    };

    // The restart finds the sidecar of the incarnation that was rotated away.
    let restarted = ensure_incarnation(&p.w.b, &environment(Some(stale_sidecar))).unwrap();

    assert_eq!(restarted.author, installed.new_author, "another incarnation was minted");
    assert_eq!(
        restarted.minted_reason,
        yadorilink_replica_domain::author::IncarnationMintReason::Rebootstrap
    );
    assert_eq!(incarnation_record(&p.w.b).unwrap().unwrap(), restarted);
    // The caller writes the sidecar of what it was given; with that, the next
    // start is quiet.
    let again =
        ensure_incarnation(&p.w.b, &environment(Some(InstanceSidecar::for_record(&restarted))))
            .unwrap();
    assert_eq!(again, restarted);
}

/// Only the sidecar of the incarnation this rotation replaced is accepted: any
/// other mismatch is still a restored or copied database.
#[test]
fn a_sidecar_that_is_not_the_replaced_incarnations_still_mints_a_restore() {
    use crate::author_incarnation::{ensure_incarnation, IncarnationEnvironment, InstanceSidecar};
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let before = crate::author_incarnation::incarnation_record(&p.w.b).unwrap().unwrap();
    let installed = install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();
    let foreign = InstanceSidecar {
        db_instance_nonce: [9; 16],
        incarnation: yadorilink_replica_domain::author::IncarnationId([9; 16]),
    };

    for sidecar in [None, Some(foreign)] {
        let minted = ensure_incarnation(
            &p.w.b,
            &IncarnationEnvironment {
                device_id: before.author.device.clone(),
                sidecar,
                machine_fingerprint: before.machine_fingerprint.clone(),
            },
        )
        .unwrap();
        assert_ne!(minted.author, installed.new_author, "{sidecar:?}: no restore was detected");
        assert_eq!(
            minted.minted_reason,
            yadorilink_replica_domain::author::IncarnationMintReason::Restore
        );
        // Put the rebootstrap's incarnation back for the next case.
        p.w.b
            .execute(
                "UPDATE author_incarnation SET incarnation = ?1, minted_reason = 'rebootstrap', \
                 previous = ?2",
                (
                    installed.new_author.incarnation.0.as_slice(),
                    before.author.incarnation.0.as_slice(),
                ),
            )
            .unwrap();
    }
}

// --- what stops the install, and what it arms -----------------------------------------------------------------

/// A copy in the area that does not read back as it was written stops the
/// quarantine before the original leaves the root, whether the damage was there
/// when the install began or happened after the area was checked.
#[test]
fn a_damaged_copy_stops_the_quarantine_before_the_original_leaves() {
    for damaged_before_the_install in [true, false] {
        let p = preserved_scenario(&Viewer);
        let fs_root = FsRoot::new(p.root.path());
        fs::write(p.root.path().join("x"), [2]).unwrap();
        let area = RecoveryArea::open_dir(&p.preserved.dir).unwrap();
        let manifest = area.read_intent().unwrap().manifest;
        let version = manifest.items.iter().find_map(|item| item.put_version).unwrap();
        let copy = p.preserved.dir.join("versions").join(hex::encode(version.0));
        if damaged_before_the_install {
            fs::write(&copy, [0xff]).unwrap();
        }

        let outcome =
            install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Viewer, &mut |point| {
                if !damaged_before_the_install && point == InstallPoint::AfterBeginQuarantine {
                    fs::write(&copy, [0xff]).unwrap();
                }
                Ok(())
            });

        assert!(matches!(outcome, Err(InstallError::Blocked(_))), "{outcome:?}");
        assert!(fs_root.removed.borrow().is_empty(), "an original left with a bad copy behind it");
        assert!(p.root.path().join("x").exists());
    }
}

/// The join refuses the stored target: nothing the transaction did stays, and the
/// journal is where the attempt found it.
#[test]
fn a_target_the_join_refuses_leaves_everything_as_it_was() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    // This replica fenced the sealer's author before its first delta; the target holds it.
    let s = incarnation_of("device-s", 1);
    rotation_closure_at(&p.w.b, &group(), &s, None);
    // The fence stands for a closure learned before the barrier: the barrier records it.
    let sealed: i64 =
        p.w.b
            .query_row(
                "SELECT COALESCE(capture_high_seq, -1) FROM native_rebootstrap_journal",
                [],
                |r| r.get(0),
            )
            .unwrap();
    let hash = crate::native_rebootstrap::frozen_frontier_hash(
        &p.w.b,
        &group(),
        &p.preserved.manifest_sha256,
        (sealed >= 0).then_some(sealed),
    )
    .unwrap();
    p.w.b
        .execute(
            "UPDATE native_rebootstrap_journal SET frozen_frontier_hash = ?1",
            [hash.as_slice()],
        )
        .unwrap();
    let state = heads_of(&p.w.b);
    let author = crate::author_incarnation::current_author(&p.w.b).unwrap();

    let outcome = install(&p.w.b, p.recovery_root.path(), &fs_root);

    assert!(matches!(outcome, Err(InstallError::BundleRefused(_))), "{outcome:?}");
    assert_eq!(heads_of(&p.w.b), state, "the refused install changed the state");
    assert_eq!(crate::author_incarnation::current_author(&p.w.b).unwrap(), author);
    assert_eq!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::Quarantining
    );
}

/// The projection is armed for every path whose heads changed, including the
/// ones that only the old state had.
#[test]
fn the_install_arms_the_projection_for_every_path_that_changed() {
    let o = offline_base(false);
    let d1 = signed(&o.b1, 1, None, vec![put_op("only-here", 2, Vec::new())]);
    publish(&o.b, &o.b1, &device_key(2), d1);
    let recovery_root = private_tempdir();
    let root = tempfile::tempdir().unwrap();
    begin_with(&o.b, built(&o.sealer), recovery_root.path(), &mut no_hook).unwrap();
    o.b.execute("DELETE FROM projection_obligations", []).unwrap();

    install(&o.b, recovery_root.path(), &FsRoot::new(root.path())).unwrap();

    let armed: BTreeSet<String> =
        o.b.prepare("SELECT path FROM projection_obligations WHERE group_id = ?1")
            .unwrap()
            .query_map([group().as_str()], |row| row.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
    assert!(armed.contains("x"), "the target's path: {armed:?}");
    assert!(
        armed.contains("only-here"),
        "a path only the old state had must be armed to follow the target: {armed:?}"
    );
}

/// The freeze is derived from the journal row: it is there after the database is
/// closed and opened again, and the scheduler still keeps the group's paths out of
/// its claim.
#[test]
fn the_freeze_and_the_journal_survive_a_restart_of_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("replica.db");
    {
        let c = Connection::open(&path).unwrap();
        crate::replica_tables::init_for_tests(&c).unwrap();
        c.execute(
            "INSERT INTO native_rebootstrap_journal \
             (group_id, recovery_id, state, target_checkpoint_hash, started_at, updated_at) \
             VALUES (?1, '00000000000000000000000000000001', 'quarantining', ?2, 1, 1)",
            (group().as_str(), [7u8; 32].as_slice()),
        )
        .unwrap();
    }

    let c = Connection::open(&path).unwrap();
    crate::replica_tables::init_for_tests(&c).unwrap();

    assert!(crate::native_rebootstrap::group_frozen(&c, group().as_str()).unwrap());
    assert!(!crate::native_rebootstrap::group_frozen(&c, "another-group").unwrap());
    assert_eq!(
        rebootstrap_status(&c, &group()).unwrap().unwrap().state,
        RebootstrapState::Quarantining
    );
    crate::projection_obligations::bump_projection_obligations_for_touched_paths(
        &c,
        group().as_str(),
        &["d/p", "e"],
        1000,
    )
    .unwrap();
    let claim = |c: &Connection| -> Vec<String> {
        crate::projection_obligations::claim_runnable_obligations(c, 10_000, 100, 100)
            .unwrap()
            .into_iter()
            .map(|o| o.path)
            .collect()
    };
    assert!(claim(&c).is_empty(), "a frozen group's rows were claimed");
    c.execute("UPDATE native_rebootstrap_journal SET state = 'replaying'", []).unwrap();
    assert!(crate::native_rebootstrap::finish_rebootstrap(
        &c,
        &group(),
        "00000000000000000000000000000001"
    )
    .unwrap());
    assert_eq!(claim(&c), vec!["d/p".to_string(), "e".to_string()]);
}

// --- review of the install: nothing may downgrade, lose or duplicate ---------------------------------------

#[cfg(unix)]
fn make_manifest_unreadable(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir.join("manifest.json"), fs::Permissions::from_mode(0o644)).unwrap();
}

#[cfg(unix)]
fn make_manifest_readable(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir.join("manifest.json"), fs::Permissions::from_mode(0o600)).unwrap();
}

/// A block raised while the root is being modified is an overlay on the stage, not
/// a replacement of it: when the area reads back again the machine is still where
/// it was, no other target is accepted, nothing is planned again, and the
/// originals that already left the root are still in the area.
#[cfg(unix)]
#[test]
fn a_block_raised_while_quarantining_keeps_the_stage_and_the_area() {
    let p = preserved_scenario(&Viewer);
    let fs_root = FsRoot::new(p.root.path());
    fs::write(p.root.path().join("x"), [2]).unwrap();
    let crashed = install_with(
        &p.w.b,
        p.recovery_root.path(),
        &fs_root,
        &Viewer,
        &mut crash_on(InstallPoint::AfterQuarantineItem(0)),
    );
    assert!(matches!(crashed, Err(InstallError::Crashed)));
    assert!(!p.root.path().join("x").exists(), "sanity: the original left the root");

    make_manifest_unreadable(&p.preserved.dir);
    let restart = recover_after_restart(&p.w.b, p.recovery_root.path(), &group()).unwrap();
    assert!(matches!(restart, RestartOutcome::Blocked(_)), "{restart:?}");
    assert_eq!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::Quarantining,
        "a block replaced the stage the machine had reached"
    );
    make_manifest_readable(&p.preserved.dir);

    let again = begin_with(&p.w.b, built(&p.w.sealer), p.recovery_root.path(), &mut no_hook);
    assert!(
        matches!(again, Err(crate::native_rebootstrap::BeginError::TargetFixed(_))),
        "{again:?}"
    );
    assert_eq!(recovery_dirs_of(p.recovery_root.path()), vec![p.preserved.dir.clone()]);
    let area = RecoveryArea::open_dir(&p.preserved.dir).unwrap();
    let manifest = area.read_intent().unwrap().manifest;
    assert!(
        manifest
            .versions
            .iter()
            .filter(|v| v.has_bytes)
            .all(|v| area.read_version(&v.version).is_ok()),
        "the quarantined original is no longer recoverable"
    );
    install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(())).unwrap();
    assert_eq!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::CatchingUp
    );
}

/// The same for an installed target: its own log is gone, so a "stale preserved
/// set" must never be read into it and its area must never be swept.
#[cfg(unix)]
#[test]
fn a_block_raised_after_the_install_keeps_the_stage_and_the_area() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let installed = install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();

    make_manifest_unreadable(&p.preserved.dir);
    let restart = recover_after_restart(&p.w.b, p.recovery_root.path(), &group()).unwrap();
    assert!(matches!(restart, RestartOutcome::Blocked(_)), "{restart:?}");
    make_manifest_readable(&p.preserved.dir);

    let again = install(&p.w.b, p.recovery_root.path(), &fs_root);
    assert_eq!(again.as_ref().ok(), Some(&installed), "{again:?}");
    let other = begin_with(&p.w.b, built(&p.w.sealer), p.recovery_root.path(), &mut no_hook);
    assert!(
        matches!(other, Err(crate::native_rebootstrap::BeginError::TargetFixed(_))),
        "{other:?}"
    );
    assert_eq!(recovery_dirs_of(p.recovery_root.path()), vec![p.preserved.dir.clone()]);
    assert_eq!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::CatchingUp
    );
    assert!(crate::native_rebootstrap::group_frozen(&p.w.b, group().as_str()).unwrap());
}

/// Giving a rebootstrap up on purpose is only possible before the root was
/// touched.
#[test]
fn discarding_is_refused_once_the_root_may_have_changed() {
    // A journal that never reached the barrier is discarded by the restart.
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let recovery_root = private_tempdir();
    w.b.execute(
        "INSERT INTO native_rebootstrap_journal \
         (group_id, recovery_id, state, target_checkpoint_hash, started_at, updated_at) \
         VALUES (?1, '00000000000000000000000000000001', 'planning', ?2, 1, 1)",
        (group().as_str(), [7u8; 32].as_slice()),
    )
    .unwrap();
    recover_after_restart(&w.b, recovery_root.path(), &group()).unwrap();
    assert!(rebootstrap_status(&w.b, &group()).unwrap().is_none());

    // A journal past the quarantine is not discardable.
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();
    assert!(!crate::native_rebootstrap::discard_blocked_rebootstrap(
        &p.w.b,
        p.recovery_root.path(),
        &group()
    )
    .unwrap());
    assert_eq!(recovery_dirs_of(p.recovery_root.path()), vec![p.preserved.dir.clone()]);
    assert!(crate::native_rebootstrap::group_frozen(&p.w.b, group().as_str()).unwrap());
}

/// From the final capture until the rebootstrap is finished the whole group is
/// frozen: nothing materializes over the root, and the freeze outlives the install
/// itself.
#[test]
fn the_group_is_frozen_until_the_rebootstrap_is_finished() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let crashed = install_with(
        &p.w.b,
        p.recovery_root.path(),
        &fs_root,
        &Writer,
        &mut crash_on(InstallPoint::AfterBeginQuarantine),
    );
    assert!(matches!(crashed, Err(InstallError::Crashed)));
    let frozen = |c: &Connection| {
        crate::native_rebootstrap::refuse_materialization_if_frozen(c, group().as_str()).is_err()
    };
    assert!(frozen(&p.w.b), "a lane could write while the group is quarantining");

    let installed = install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();
    assert!(frozen(&p.w.b), "the install ended the freeze");

    let finish = |c: &Connection, id: &str| {
        crate::native_rebootstrap::finish_rebootstrap(c, &group(), id).unwrap()
    };
    assert!(!finish(&p.w.b, "another-rebootstrap"), "another recovery id finished it");
    assert!(frozen(&p.w.b));
    assert!(!finish(&p.w.b, &installed.recovery_id), "the catch-up and the replay come first");
    assert!(frozen(&p.w.b));
    super::rebootstrap_replay::complete_machine(
        &p.w.b,
        p.recovery_root.path(),
        &installed.recovery_id,
        &Writer,
    );
    assert!(!frozen(&p.w.b), "finishing did not end the freeze");
    assert!(rebootstrap_status(&p.w.b, &group()).unwrap().is_none());
}

/// A rebootstrap that has not installed yet is never finished: the freeze ends
/// only after the install.
#[test]
fn a_rebootstrap_is_not_finished_before_it_is_installed() {
    let p = preserved_scenario(&Writer);
    let id = &p.preserved.recovery_id;
    assert!(!crate::native_rebootstrap::finish_rebootstrap(&p.w.b, &group(), id).unwrap());
    let fs_root = FsRoot::new(p.root.path());
    let _ = install_with(
        &p.w.b,
        p.recovery_root.path(),
        &fs_root,
        &Writer,
        &mut crash_on(InstallPoint::AfterBeginQuarantine),
    );
    assert!(!crate::native_rebootstrap::finish_rebootstrap(&p.w.b, &group(), id).unwrap());
    assert!(crate::native_rebootstrap::group_frozen(&p.w.b, group().as_str()).unwrap());
}

/// Should a delta reach the log after the quarantine began anyway (a writer that
/// does not check the freeze), the install does not clear it away: it stops before
/// the clear.
#[test]
fn a_write_past_the_freeze_after_the_quarantine_stops_the_install_before_the_clear() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let crashed = install_with(
        &p.w.b,
        p.recovery_root.path(),
        &fs_root,
        &Writer,
        &mut crash_on(InstallPoint::AfterBeginQuarantine),
    );
    assert!(matches!(crashed, Err(InstallError::Crashed)));
    let late = signed(
        &p.w.b1,
        3,
        Some(p.w.undelivered.delta_hash()),
        vec![put_op("unheld", 5, Vec::new())],
    );
    publish_past_the_freeze(&p.w.b, &p.w.b1, &device_key(2), late.clone());
    let state = heads_of(&p.w.b);

    let outcome = install(&p.w.b, p.recovery_root.path(), &fs_root);

    assert!(matches!(outcome, Err(InstallError::FrontierChanged)), "{outcome:?}");
    assert_eq!(heads_of(&p.w.b), state);
    assert!(crate::native_store::fetch_delta_body(
        &p.w.b,
        &group(),
        &p.w.b1,
        yadorilink_replica_domain::ids::AuthorSeq(3)
    )
    .unwrap()
    .is_some());
}

/// The edit copy is referenced before its original can disappear: a crash between
/// the removal and the status update still finds it recorded.
#[test]
fn a_crash_between_removing_a_late_edit_and_recording_it_still_references_the_copy() {
    let p = preserved_scenario(&Viewer);
    let fs_root = FsRoot::new(p.root.path());
    fs::write(p.root.path().join("x"), b"typed after the barrier").unwrap();

    let crashed = install_with(
        &p.w.b,
        p.recovery_root.path(),
        &fs_root,
        &Viewer,
        &mut crash_on(InstallPoint::AfterOriginalRemoved(0)),
    );
    assert!(matches!(crashed, Err(InstallError::Crashed)), "{crashed:?}");
    assert!(!p.root.path().join("x").exists());

    install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(())).unwrap();

    let digest: [u8; 32] = Sha256::digest(b"typed after the barrier").into();
    assert_eq!(
        quarantined_items(&p.w.b, &group(), None).unwrap()[0].status,
        QuarantineStatus::RemovedLateEdit { sha256: digest },
        "the edit's copy is in the area but nothing points at it"
    );
}

/// Every incarnation of this device whose changes were preserved is fenced, each at
/// its own position in the target.
#[test]
fn every_old_incarnation_is_fenced_not_only_the_current_one() {
    let o = offline_base(false);
    let d1 = signed(&o.b1, 1, None, vec![put_op("p", 2, Vec::new())]);
    publish(&o.b, &o.b1, &device_key(2), d1);
    let b2 = crate::author_incarnation::rotate_incarnation(
        &o.b,
        yadorilink_replica_domain::author::IncarnationMintReason::Restore,
    )
    .unwrap()
    .author;
    let e1 = signed(&b2, 1, None, vec![put_op("q", 3, Vec::new())]);
    publish(&o.b, &b2, &device_key(2), e1);
    let recovery_root = private_tempdir();
    let root = tempfile::tempdir().unwrap();
    begin_with(&o.b, built(&o.sealer), recovery_root.path(), &mut no_hook).unwrap();

    let installed = install(&o.b, recovery_root.path(), &FsRoot::new(root.path())).unwrap();

    let mut olds = installed.old_authors.clone();
    olds.sort();
    let mut expected = vec![o.b1.clone(), b2.clone()];
    expected.sort();
    assert_eq!(olds, expected);
    for old in [&o.b1, &b2] {
        assert!(
            unexported_rotation_cutoff(&o.b, &group(), old).is_some(),
            "{old:?} is reported as fenced but is not"
        );
    }
}

/// Two calls for one group never run together: the second is turned away while the
/// first holds the journal, and the first completes undisturbed.
#[test]
fn a_second_call_while_an_install_is_running_is_turned_away() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let inner: RefCell<Option<Result<Installed, InstallError>>> = RefCell::new(None);

    let outer = install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Writer, &mut |point| {
        if point == InstallPoint::AfterBeginQuarantine && inner.borrow().is_none() {
            *inner.borrow_mut() = Some(install(&p.w.b, p.recovery_root.path(), &fs_root));
        }
        Ok(())
    });

    assert!(outer.is_ok(), "{outer:?}");
    let inner = inner.into_inner().expect("the hook ran");
    assert!(
        matches!(inner, Err(InstallError::Busy)),
        "a concurrent call ran alongside the install: {inner:?}"
    );
}

/// The quarantine rows belong to one rebootstrap: a row left by another does not
/// make this one skip its originals.
#[test]
fn a_quarantine_row_of_another_rebootstrap_does_not_skip_this_ones() {
    let p = preserved_scenario(&Viewer);
    let fs_root = FsRoot::new(p.root.path());
    fs::write(p.root.path().join("x"), [2]).unwrap();
    p.w.b
        .execute(
            "INSERT INTO native_rebootstrap_quarantine (group_id, recovery_id, path, status) \
             VALUES (?1, 'another-rebootstrap', 'x', 'removed')",
            [group().as_str()],
        )
        .unwrap();

    install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(())).unwrap();

    assert!(!p.root.path().join("x").exists(), "a stale row made the quarantine skip the original");
}

/// The removal contract: an object that changed after it was observed is put back
/// and the call fails, so the next attempt sees (and saves) the new content.
#[test]
fn a_file_changed_between_observation_and_removal_is_put_back() {
    let dir = tempfile::tempdir().unwrap();
    let root = FsRoot::new(dir.path());
    fs::write(dir.path().join("x"), b"observed").unwrap();
    let observed = root.observe("x").unwrap();
    fs::write(dir.path().join("x"), b"saved a moment later").unwrap();

    assert!(root.remove("x", &observed).is_err());

    assert_eq!(fs::read(dir.path().join("x")).unwrap(), b"saved a moment later");
    assert!(root.removed.borrow().is_empty());
}

/// A journal blocked at the barrier is taken back to it when its area reads
/// again, but not once the group changed while it was blocked: a blocked journal
/// does not freeze the group, so what the barrier protected is no longer known.
#[cfg(unix)]
#[test]
fn a_blocked_journal_is_not_taken_back_to_the_barrier_after_the_group_changed() {
    let p = preserved_scenario(&Writer);
    make_manifest_unreadable(&p.preserved.dir);
    recover_after_restart(&p.w.b, p.recovery_root.path(), &group()).unwrap();
    assert!(matches!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::Blocked(_)
    ));
    let late =
        signed(&p.w.b1, 3, Some(p.w.undelivered.delta_hash()), vec![put_op("z", 5, Vec::new())]);
    publish(&p.w.b, &p.w.b1, &device_key(2), late);
    make_manifest_readable(&p.preserved.dir);

    let outcome = begin_with(&p.w.b, built(&p.w.sealer), p.recovery_root.path(), &mut no_hook);

    assert!(outcome.is_err(), "a journal over a changed group was taken back to the barrier");
    assert!(matches!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::Blocked(_)
    ));
    assert_eq!(recovery_dirs_of(p.recovery_root.path()), vec![p.preserved.dir.clone()]);
}

/// Starting a new journal never replaces one whose root was modified.
#[test]
fn a_new_journal_never_replaces_one_past_the_barrier() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();
    let (verified, stored) = crate::native_rebootstrap_target::verify_and_prepare_target(
        built(&p.w.sealer),
        &group(),
        &Policy,
    )
    .unwrap();
    let preserve = preserve_context(p.recovery_root.path(), CaptureBarrier::Completed, &Writer);

    let outcome = crate::native_rebootstrap::start_journal_and_preserve(
        &p.w.b,
        &device_b(),
        &group(),
        &verified,
        &stored,
        &preserve,
        Some(p.preserved.recovery_id.clone()),
        &mut no_hook,
    );

    assert!(
        matches!(outcome, Err(crate::native_rebootstrap::BeginError::TargetFixed(_))),
        "{outcome:?}"
    );
    assert_eq!(recovery_dirs_of(p.recovery_root.path()), vec![p.preserved.dir.clone()]);
    assert_eq!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::CatchingUp
    );
}

// --- the closure of the old incarnation ------------------------------------------------------------

/// The install of the journal of `local`, as a device that signs with `key` (or
/// holds no authority to sign, `None`).
fn install_signing_with(
    local: &Connection,
    recovery_root: &Path,
    root: &dyn QuarantineRoot,
    key: Option<&ed25519_dalek::SigningKey>,
) -> Result<Installed, InstallError> {
    let status = rebootstrap_status(local, &group()).unwrap().expect("a rebootstrap");
    let preserve = preserve_context(recovery_root, CaptureBarrier::Completed, &Writer);
    install_rebootstrap(
        local,
        &InstallContext { preserve: &preserve, root, closure_key: key },
        &group(),
        &status.recovery_id,
        &mut |_| Ok(()),
    )
}

#[test]
fn rotating_devices_own_closure_creates_the_same_row_and_no_fence_table_exists() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let old_author = crate::author_incarnation::current_author(&p.w.b).unwrap();
    let key = device_key(2);

    install_signing_with(&p.w.b, p.recovery_root.path(), &fs_root, Some(&key)).unwrap();

    let rows = crate::native_closure::all_closures(&p.w.b, &group()).unwrap();
    assert_eq!(rows.len(), 1, "the rotation signs one closure of the old incarnation");
    let closure = &rows[0];
    assert_eq!(closure.closure.author, old_author);
    let target = crate::native_store::frontier_entry_get(&p.w.sealer, &group(), &old_author)
        .unwrap()
        .expect("the target holds the old author");
    assert_eq!(closure.closure.cutoff, Some(target), "the cutoff is the old author's position");
    assert_eq!(closure.author_public_key, key.verifying_key().to_bytes());
    closure.verify(GROUP, |id, head| Policy.resolve_authority_key(id, head)).unwrap();
    // The one record: gating admission at once, outside every outward path.
    let (source, replacement): (String, Option<Vec<u8>>) =
        p.w.b
            .query_row(
                "SELECT source, replacement_checkpoint_hash FROM native_author_closure",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
    assert_eq!((source.as_str(), replacement), ("rotation", None));
    assert!(crate::native_closure::closures_for_export(&p.w.b, &group()).unwrap().is_empty());
    assert_eq!(
        crate::native_closure::effective_closed_cutoff(&p.w.b, &group(), &old_author)
            .unwrap()
            .map(|cutoff| cutoff.seq),
        Some(Some(AuthorSeq(1)))
    );
    let fence_tables: i64 =
        p.w.b
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'native_incarnation_fence'",
                [],
                |row| row.get(0),
            )
            .unwrap();
    assert_eq!(fence_tables, 0, "the fence table is replaced by the closure evidence store");
}

#[test]
fn author_closure_is_not_cleared_by_install() {
    assert!(PRESERVED_BY_INSTALL.contains(&"native_author_closure"));
    assert!(!CLEARED_BY_INSTALL.contains(&"native_author_closure"));
}

#[test]
fn rebootstrap_without_authority_never_signs_a_closure() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());

    install_signing_with(&p.w.b, p.recovery_root.path(), &fs_root, None).unwrap();

    assert!(crate::native_closure::all_closures(&p.w.b, &group()).unwrap().is_empty());
}

#[test]
fn an_existing_closure_row_survives_the_install() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    // A closure of another device's old incarnation, verified before the rebootstrap.
    let other = incarnation_of("device-c", 9);
    let seed = device_seed("device-c");
    let closure = closure_signed(&other, None, seed, "device-c", seed);
    crate::native_closure::store_bundle_closure(&w.b, &group(), &closure, [3; 32], &Policy)
        .unwrap();
    let recovery_root = private_tempdir();
    let root = tempfile::tempdir().unwrap();
    let setup = Setup { authority: &Writer, ..Setup::default() };
    begin_custom(&w.b, built(&w.sealer), recovery_root.path(), &setup, &mut no_hook).unwrap();

    install(&w.b, recovery_root.path(), &FsRoot::new(root.path())).unwrap();

    let held = crate::native_closure::all_closures(&w.b, &group()).unwrap();
    assert!(held.contains(&closure), "the install cleared a verified closure");
}

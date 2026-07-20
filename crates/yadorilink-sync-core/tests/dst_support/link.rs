//! Linking a folder the way production links a folder.
//!
//! Every scenario here needs one thing before its devices can talk: the state a
//! real device is in once its folder has been linked and its first startup scan
//! has committed. `SyncState::add_link` alone is *not* that state, and the two
//! ways it falls short are both silent — they do not fail, they make the peer
//! receive nothing and the scenario pass while testing nothing.
//!
//! **The startup gate.** `wait_group_ready` defers a peer change for a group
//! that has a live link and no startup gate. That pairing is not an oversight in
//! the product: it means the link's startup never got off the ground, so the
//! folder was never scanned this boot, and applying a peer change could overwrite
//! local bytes that were never indexed — with no conflict copy, because the local
//! content never became a change the DAG could see. Production therefore arms the
//! gate in the same breath as it commits the link row (at boot, and on AddLink
//! via the watcher start). A harness that calls `add_link` and stops has built a
//! state production never produces: a live link that is owed a startup forever.
//! Every arriving change is deferred, the peer's index stays empty, and the only
//! symptom is a startup canary that never converges.
//!
//! **The root marker.** Linking a folder also mints the on-disk root-identity
//! marker; a bare `add_link` writes only the index row. An unmarked root whose
//! indexed files are all absent is byte-for-byte an unmounted volume, which the
//! root-identity check refuses.
//!
//! Marking ready immediately is honest rather than a shortcut: these roots start
//! empty, so "the startup scan has committed its results" is vacuously true —
//! precisely the state the gate exists to certify. A scenario that wants to model
//! a *failed* or *in-flight* startup should drive `begin_group_startup` /
//! `mark_group_failed` itself and not use this.

use std::path::Path;

use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::root_identity::VerifiedRoot;

/// Links `root` for `group_id` and brings it to the post-first-scan state:
/// claims the root and opens the group's startup gate. See this module's doc
/// comment for why `add_link` on its own leaves a device that can never receive.
pub fn link_and_start(state: &SyncState, root: &Path, group_id: &str) -> Result<(), String> {
    state.add_link(&root.to_string_lossy(), group_id).map_err(|e| e.to_string())?;
    adopt_root(state, root, group_id)?;
    open_startup_gate(state, group_id);
    Ok(())
}

/// Claims `root` as this device's folder for `group_id`, minting the marker, the
/// way linking a folder does. Split out for scenarios that need to link and
/// adopt at different points than [`link_and_start`] does.
pub fn adopt_root(state: &SyncState, root: &Path, group_id: &str) -> Result<(), String> {
    VerifiedRoot::open(root, group_id, state).map(|_| ()).map_err(|e| e.to_string())
}

/// Opens `group_id`'s startup gate, standing in for a completed startup scan.
/// Split out for scenarios that build their links by other means but still owe
/// the group a startup.
pub fn open_startup_gate(state: &SyncState, group_id: &str) {
    let generation = state.begin_group_startup(group_id);
    state.mark_group_ready(group_id, generation);
}

#![cfg(test)]

use super::*;
use yadorilink_ipc_proto::send::SendFileEntry;

fn open_store() -> (SendStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = SendStore::open(dir.path().join("store.sqlite3")).unwrap();
    (store, dir)
}

fn sample_manifest(transfer_id: &str) -> SendManifest {
    SendManifest {
        transfer_id: transfer_id.to_string(),
        files: vec![SendFileEntry {
            relative_path: "a.txt".to_string(),
            size: 10,
            chunk_size: 131072,
            chunk_hashes: vec![vec![1u8; 32]],
        }],
        total_size: 10,
        offered_at_unix_nanos: 42,
    }
}

#[test]
fn outbound_offer_round_trips_through_the_store() {
    let (store, _dir) = open_store();
    let manifest = sample_manifest("t1");
    store
        .insert_outbound_offered("t1", "device-b", &[7u8; 32], "/src/file", &manifest, 100)
        .unwrap();

    let row = store.get_outbound("t1").unwrap().unwrap();
    assert_eq!(row.target_device_id, "device-b");
    assert_eq!(row.target_signing_key, [7u8; 32]);
    assert_eq!(row.source_path, "/src/file");
    assert_eq!(row.manifest, manifest);
    assert_eq!(row.status, OutboundStatus::Offered);

    store.mark_outbound_acked("t1").unwrap();
    assert_eq!(store.get_outbound("t1").unwrap().unwrap().status, OutboundStatus::Acked);
}

/// A declined offer moves to `Rejected`, not back to `Offered` and not
/// to `Acked` -- the terminal state
/// `SendService::handle_pull` checks to refuse serving chunks for an
/// offer the receiver never accepted.
#[test]
fn mark_outbound_rejected_moves_the_row_to_a_terminal_rejected_status() {
    let (store, _dir) = open_store();
    let manifest = sample_manifest("t2");
    store
        .insert_outbound_offered("t2", "device-b", &[7u8; 32], "/src/file", &manifest, 100)
        .unwrap();

    store.mark_outbound_rejected("t2").unwrap();
    assert_eq!(store.get_outbound("t2").unwrap().unwrap().status, OutboundStatus::Rejected);
}

/// `send`'s idempotency: re-running it for the same (source, target)
/// finds the SAME transfer id already on record, rather than a caller
/// having to track that itself.
#[test]
fn find_outbound_by_source_and_target_recovers_an_existing_offer() {
    let (store, _dir) = open_store();
    let manifest = sample_manifest("t1");
    store
        .insert_outbound_offered("t1", "device-b", &[7u8; 32], "/src/file", &manifest, 100)
        .unwrap();

    let found = store.find_outbound_by_source_and_target("/src/file", "device-b").unwrap();
    assert_eq!(found.unwrap().transfer_id, "t1");
    assert!(store.find_outbound_by_source_and_target("/src/other", "device-b").unwrap().is_none());
}

/// `Rejected` is genuinely terminal: once a row is rejected,
/// `find_outbound_by_source_and_target` must stop returning it, so a
/// caller re-running `send` for the same (source, target) mints a
/// fresh transfer id (as `offer_send` does on a `None` result) instead
/// of reusing -- and potentially flipping straight to `Acked` via
/// `mark_outbound_acked` -- the row that was already rejected.
#[test]
fn find_outbound_by_source_and_target_skips_a_rejected_row() {
    let (store, _dir) = open_store();
    let manifest = sample_manifest("t1");
    store
        .insert_outbound_offered("t1", "device-b", &[7u8; 32], "/src/file", &manifest, 100)
        .unwrap();
    store.mark_outbound_rejected("t1").unwrap();

    // The rejected row must be invisible to the idempotency lookup --
    // not handed back for a caller to mutate.
    assert!(store.find_outbound_by_source_and_target("/src/file", "device-b").unwrap().is_none());

    // A re-send for the exact same (source, target) mints a genuinely
    // new row/transfer id, exactly as `offer_send` does when the
    // lookup comes back empty.
    let manifest2 = sample_manifest("t2");
    store
        .insert_outbound_offered("t2", "device-b", &[7u8; 32], "/src/file", &manifest2, 200)
        .unwrap();

    let found = store.find_outbound_by_source_and_target("/src/file", "device-b").unwrap();
    assert_eq!(found.unwrap().transfer_id, "t2");

    // Acking the new transfer must never resurrect the old, rejected
    // one under a different status.
    store.mark_outbound_acked("t2").unwrap();
    assert_eq!(store.get_outbound("t1").unwrap().unwrap().status, OutboundStatus::Rejected);
    assert_eq!(store.get_outbound("t2").unwrap().unwrap().status, OutboundStatus::Acked);
}

/// A duplicate offer for a `transfer_id` already on record -- a
/// sender's retry after its own ack never arrived -- is a no-op, not a
/// second row or an error.
#[test]
fn duplicate_inbound_offer_is_idempotent() {
    let (store, _dir) = open_store();
    let manifest = sample_manifest("t1");
    assert!(store.insert_inbound_if_new("t1", "device-a", &manifest, 100).unwrap());
    assert!(!store.insert_inbound_if_new("t1", "device-a", &manifest, 100).unwrap());
    assert_eq!(store.list_inbound_recent(20).unwrap().len(), 1);
}

/// The "acquire authority before the first mutating action" step:
/// whichever directory the FIRST `receive` call claims is the one every
/// later call (a resume, or a redundant second run) is stuck with, even
/// if it asks for somewhere else.
#[test]
fn claim_inbound_destination_is_sticky_across_resumes() {
    let (store, _dir) = open_store();
    let manifest = sample_manifest("t1");
    store.insert_inbound_if_new("t1", "device-a", &manifest, 100).unwrap();

    let first = store.claim_inbound_destination("t1", "/dest/one").unwrap();
    assert_eq!(first, "/dest/one");
    let second = store.claim_inbound_destination("t1", "/dest/two").unwrap();
    assert_eq!(second, "/dest/one", "a resume must not silently redirect to a new destination");

    assert_eq!(store.get_inbound("t1").unwrap().unwrap().status, InboundStatus::InProgress);
}

fn status_of(store: &SendStore, id: &str) -> InboundStatus {
    store.get_inbound(id).unwrap().unwrap().status
}

/// A daemon that died mid-receive leaves `in_progress` behind with nothing
/// running; the next start must not keep reporting it as receiving, and
/// must leave every other transfer alone.
#[test]
fn interrupting_in_progress_rows_marks_only_those_failed() {
    let (store, _dir) = open_store();
    for id in ["running", "waiting", "done"] {
        store.insert_inbound_if_new(id, "device-a", &sample_manifest(id), 100).unwrap();
    }
    store.claim_inbound_destination("running", "/dest/running").unwrap();
    store.claim_inbound_destination("done", "/dest/done").unwrap();
    store.mark_inbound_completed("done").unwrap();

    assert_eq!(store.interrupt_in_progress_inbound().unwrap(), 1);
    assert_eq!(status_of(&store, "running"), InboundStatus::Failed);
    assert_eq!(status_of(&store, "waiting"), InboundStatus::Pending);
    assert_eq!(status_of(&store, "done"), InboundStatus::Completed);
    assert_eq!(store.interrupt_in_progress_inbound().unwrap(), 0);
}

/// Canceling twice, or canceling something already finished, changes
/// nothing; canceling one transfer never touches another.
#[test]
fn cancel_is_idempotent_and_scoped_to_one_transfer() {
    let (store, _dir) = open_store();
    for id in ["a", "b", "done"] {
        store.insert_inbound_if_new(id, "device-a", &sample_manifest(id), 100).unwrap();
    }
    store.claim_inbound_destination("a", "/dest/a").unwrap();
    store.claim_inbound_destination("b", "/dest/b").unwrap();
    store.mark_inbound_completed("done").unwrap();

    assert!(store.cancel_inbound("a").unwrap());
    assert!(!store.cancel_inbound("a").unwrap(), "second cancel is a no-op");
    assert!(!store.cancel_inbound("done").unwrap(), "a finished transfer cannot be canceled");

    assert_eq!(status_of(&store, "a"), InboundStatus::Canceled);
    assert_eq!(status_of(&store, "b"), InboundStatus::InProgress);
    assert_eq!(status_of(&store, "done"), InboundStatus::Completed);
}

/// A failure report from a receive that was canceled underneath it must not
/// overwrite the cancel.
#[test]
fn failure_does_not_overwrite_a_cancel() {
    let (store, _dir) = open_store();
    store.insert_inbound_if_new("a", "device-a", &sample_manifest("a"), 100).unwrap();
    store.claim_inbound_destination("a", "/dest/a").unwrap();
    store.cancel_inbound("a").unwrap();
    assert!(!store.fail_inbound("a").unwrap());
    assert_eq!(status_of(&store, "a"), InboundStatus::Canceled);
}

/// History is bounded: every unfinished transfer is listed, plus only the
/// most recent finished ones.
#[test]
fn recent_listing_keeps_unfinished_rows_and_bounds_finished_ones() {
    let (store, _dir) = open_store();
    for n in 0..5 {
        let id = format!("old{n}");
        store.insert_inbound_if_new(&id, "device-a", &sample_manifest(&id), 100 + n).unwrap();
        store.claim_inbound_destination(&id, "/d").unwrap();
        store.mark_inbound_completed(&id).unwrap();
    }
    store.insert_inbound_if_new("waiting", "device-a", &sample_manifest("waiting"), 1).unwrap();

    let listed: Vec<String> =
        store.list_inbound_recent(2).unwrap().into_iter().map(|t| t.transfer_id).collect();
    assert_eq!(listed, vec!["waiting", "old3", "old4"]);
}

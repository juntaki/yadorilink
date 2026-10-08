#![cfg(test)]

//! The evidence rule for what the OS holds: ledger, membership, freshness, no update since, no
//! publication pending. Each part has its own test, so removing any one of them fails a test
//! that no other part covers.

use std::sync::Arc;

use yadorilink_ipc_proto::shellipc::{ProviderMaterializedItem, ProviderMaterializedReport};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::session_state::ProviderKind;
use yadorilink_sync_sqlite::SyncSqliteError;

use crate::daemon_state::DaemonState;
use crate::replica_coordinator::ReplicaCoordinator;

use super::*;

const GROUP: &str = "group-1";

struct Fx {
    state: Arc<DaemonState>,
    root: String,
    membership: ProviderMembership,
}

impl Fx {
    fn new() -> Self {
        let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
        let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let state = DaemonState::new("device-a".into(), sync_state, store);
        state.replica_coordinator.link_repository().add_link("/provider/p", GROUP).unwrap();
        let root = state
            .replica_coordinator
            .provider_repository()
            .declare_root(GROUP, ProviderKind::MacFileProvider, "P")
            .unwrap();
        Self { state, root, membership: ProviderMembership::default() }
    }

    fn repo(&self) -> &yadorilink_sync_sqlite::provider::ProviderRepository {
        self.state.replica_coordinator.provider_repository()
    }

    fn commit(&self, path: &str, seq: i64, size: i64, mtime: i64) {
        let blocks = format!(r#"[{{"hash":{:?},"offset":0,"size":{size}}}]"#, vec![size as u8; 32]);
        self.state
            .replica_coordinator
            .database()
            .write_immediate::<_, SyncSqliteError>(|tx| {
                tx.execute(
                    "UPDATE files SET state = 'superseded' WHERE group_id = ?1 AND path = ?2 \
                     AND state = 'current'",
                    rusqlite::params![GROUP, path],
                )?;
                tx.execute(
                    "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, \
                     deleted, version_seq, state) VALUES (?1, ?2, ?3, ?4, ?6, 0, ?5, 'current')",
                    rusqlite::params![GROUP, path, size, mtime, seq, blocks],
                )?;
                let row = yadorilink_sync_sqlite::read_canonical_current_row(tx, GROUP, path)?
                    .expect("the row just written");
                let version = yadorilink_replica_domain::session_state::CurrentVersionRecord::from(
                    row.snapshot,
                )
                .to_file_version();
                yadorilink_sync_sqlite::dag_store::put_file_version(tx, GROUP, &version)?;
                Ok(())
            })
            .unwrap();
    }

    /// An item the OS was told at its current version (nothing pending).
    fn item(&self, path: &str, size: i64) -> ItemId {
        self.commit(path, 1, size, 100);
        let id = self.repo().mint_item(&self.root, path).unwrap();
        self.repo().publish_first(&self.root, &id, self.current(&id)).unwrap();
        id
    }

    fn current(&self, id: &ItemId) -> VersionHash {
        self.repo().current_version_hash(&self.root, id).unwrap().unwrap()
    }

    fn handoff(&self, id: &ItemId) -> u64 {
        let version = self.current(id);
        self.repo().record_handoff(&self.root, id, version).unwrap().expect("a current version")
    }

    fn presence(&self, id: &ItemId) -> (bool, bool) {
        let p = provider_local_presence(
            &self.state.replica_coordinator,
            &self.membership,
            &self.root,
            id,
        );
        (p.object_present, p.current_content_present)
    }

    fn report(
        &self,
        epoch: u64,
        seq: u64,
        full: bool,
        observed_after: u64,
        listed: &[ItemId],
        removed: &[ItemId],
    ) -> ProviderReportAck {
        self.membership.apply(
            &ProviderMaterializedReport {
                root_id: hex::decode(&self.root).unwrap(),
                reporter_epoch: epoch,
                report_seq: seq,
                full,
                observed_after_seq: observed_after,
                upserts: listed
                    .iter()
                    .map(|i| ProviderMaterializedItem { item_id: i.to_vec() })
                    .collect(),
                removed: removed.iter().map(|i| i.to_vec()).collect(),
                more: false,
            },
            self.repo().latest_evidence_seq(&self.root).unwrap().unwrap(),
        )
    }
}

/// The evidence matrix for a provider root: nothing here is a plain object; every fact is
/// derived from the ledger and the host's membership.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_local_state_matrix_for_a_provider_root() {
    let fx = Fx::new();
    // Remote: never handed over, not listed.
    let remote = fx.item("remote.txt", 10);
    assert_eq!(fx.presence(&remote), (false, false));

    // Exact: handed over at its current version and observed after the handoff.
    let exact = fx.item("exact.txt", 20);
    let seq = fx.handoff(&exact);
    fx.report(1, 1, true, seq, &[exact], &[]);
    assert_eq!(fx.presence(&exact), (true, true));

    // An object that stands over OLDER bytes: V2 arrives while the OS still lists the item.
    let stale = fx.item("stale.txt", 30);
    let seq = fx.handoff(&stale);
    fx.report(1, 2, false, seq, &[stale], &[]);
    assert_eq!(fx.presence(&stale), (true, true));
    fx.commit("stale.txt", 2, 31, 100);
    assert_eq!(fx.presence(&stale), (true, false), "an older object was reported current");

    // A read error is never "current": the ledger table is unreadable, the object still stands.
    fx.state
        .replica_coordinator
        .database()
        .write::<_, SyncSqliteError>(|conn| {
            conn.execute_batch("DROP TABLE provider_handoffs;")?;
            Ok(())
        })
        .unwrap();
    assert_eq!(fx.presence(&exact), (true, false), "a read error reported current content");
}

/// MEMBERSHIP: a handoff the OS was never seen to hold (no report, or not listed, or listed and
/// then removed by the OS) is not present at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_handoff_that_is_not_in_the_snapshot_is_not_present() {
    let fx = Fx::new();
    let id = fx.item("a.txt", 10);
    let seq = fx.handoff(&id);
    // No snapshot at all (no host, a restart): nothing is present.
    assert_eq!(fx.presence(&id), (false, false));
    // A snapshot that does not list it.
    fx.report(1, 1, true, seq, &[], &[]);
    assert_eq!(fx.presence(&id), (false, false));
    // Listed: present. The OS evicts it (a user "remove download", pressure): gone from the delta.
    fx.report(1, 2, false, seq, &[id], &[]);
    assert_eq!(fx.presence(&id), (true, true));
    fx.report(1, 3, false, seq, &[], &[id]);
    assert_eq!(fx.presence(&id), (false, false), "an eviction by the OS was not learned");
}

/// The OS dropping its copy ("Remove Download") is not canonical block reclamation and never custody
/// evidence: it changes what the OS is believed to hold, nothing the daemon's own state says about the
/// item. The version, the handoff record and the item stay as they were, and nothing that decides custody,
/// reclamation or durability reads the provider presence evidence at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_os_side_eviction_is_not_custody_evidence() {
    let fx = Fx::new();
    let id = fx.item("a.txt", 10);
    let seq = fx.handoff(&id);
    let version = fx.current(&id);
    fx.report(1, 1, true, seq, &[], &[]);
    fx.report(1, 2, false, seq, &[id], &[]);
    assert_eq!(fx.presence(&id), (true, true));
    fx.report(1, 3, false, seq, &[], &[id]);
    assert_eq!(fx.presence(&id), (false, false));
    // The daemon's own record of the item is untouched by the OS's eviction.
    assert_eq!(fx.current(&id), version);
    assert!(fx.repo().handoff(&fx.root, &id).unwrap().is_some());
    // Presence is an input to prefetch only: the custody, reclamation and durability code never reads it.
    for (name, source) in [
        ("background_custody", include_str!("../background_custody.rs")),
        ("durability_service", include_str!("../durability_service.rs")),
        ("gc", include_str!("../gc.rs")),
        ("gc_state", include_str!("../gc_state.rs")),
    ] {
        assert!(
            !source.contains("provider_local_presence") && !source.contains("provider_evidence"),
            "{name} reads the OS presence evidence; an OS eviction must never count as custody"
        );
    }
}

/// LEDGER: the OS holds something for the item (it is listed) but the daemon never handed over
/// the current version: the object stands, current content is not claimed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listed_item_without_a_handoff_has_no_current_content() {
    let fx = Fx::new();
    let id = fx.item("a.txt", 10);
    fx.report(1, 1, true, 0, &[id], &[]);
    assert_eq!(fx.presence(&id), (true, false));
    // A stale claim (a version that is not current) records nothing.
    let old = fx.current(&id);
    fx.commit("a.txt", 2, 99, 100);
    assert_eq!(fx.repo().record_handoff(&fx.root, &id, old).unwrap(), None);
    assert_eq!(fx.presence(&id), (true, false));
}

/// FRESHNESS: an old snapshot is never combined with a newer handoff. The item was listed by a
/// report that began before the handoff; only a report that began after it proves the handoff.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_old_snapshot_does_not_prove_a_newer_handoff() {
    let fx = Fx::new();
    let id = fx.item("a.txt", 10);
    fx.report(1, 1, true, 0, &[id], &[]); // began before any handoff
    let seq = fx.handoff(&id);
    assert!(seq > 0);
    assert_eq!(fx.presence(&id), (true, false), "an old snapshot proved a new handoff");
    // A report that began after the handoff (the app echoed the tick) re-confirms the item.
    fx.report(1, 2, false, seq, &[id], &[]);
    assert_eq!(fx.presence(&id), (true, true));
}

/// VERSION: a version that differs from the one handed over (a metadata-only update leaves the
/// ledger row, since the content is the same) is not the current version, so not current.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ledger_naming_another_version_is_not_current() {
    let fx = Fx::new();
    let id = fx.item("a.txt", 10);
    let seq = fx.handoff(&id);
    fx.report(1, 1, true, seq, &[id], &[]);
    assert_eq!(fx.presence(&id), (true, true));
    fx.commit("a.txt", 2, 10, 5555); // same content, new mtime
    assert!(
        fx.repo().handoff(&fx.root, &id).unwrap().is_some(),
        "a metadata-only change dropped the ledger row"
    );
    assert_eq!(fx.presence(&id), (true, false));
}

/// NO UPDATE SINCE: content that changed and then changed BACK to the very same version is not
/// present: the OS dropped its blocks on the first update. The ledger row is gone, so the
/// matching version hash alone proves nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_update_since_the_handoff_is_not_forgotten_when_the_version_comes_back() {
    let fx = Fx::new();
    let id = fx.item("a.txt", 10);
    let seq = fx.handoff(&id);
    fx.report(1, 1, true, seq, &[id], &[]);
    let original = fx.current(&id);
    fx.commit("a.txt", 2, 20, 100); // V2
    fx.commit("a.txt", 3, 10, 100); // back to V1's exact content and metadata
    assert_eq!(fx.current(&id), original, "the test did not restore the same version");
    assert!(fx.repo().handoff(&fx.root, &id).unwrap().is_none());
    assert_eq!(fx.presence(&id), (true, false), "an update since the handoff was forgotten");
}

/// A remote version commit demotes in the SAME transaction: right after the commit, with no
/// call into the provider layer, the ledger row is already gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_content_change_deletes_the_handoff_in_its_own_transaction() {
    let fx = Fx::new();
    let id = fx.item("a.txt", 10);
    fx.handoff(&id);
    let count = || -> i64 {
        fx.state
            .replica_coordinator
            .database()
            .read::<_, SyncSqliteError>(|conn| {
                Ok(conn.query_row("SELECT COUNT(*) FROM provider_handoffs", [], |r| r.get(0))?)
            })
            .unwrap()
    };
    assert_eq!(count(), 1);
    fx.commit("a.txt", 2, 99, 100);
    assert_eq!(count(), 0, "the commit left a handoff for bytes it replaced");
}

/// PUBLICATION: handed over, observed, but newer content than the OS was told is pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pending_publication_is_not_current_content() {
    let fx = Fx::new();
    let id = fx.item("a.txt", 10); // published at V1
    fx.commit("a.txt", 2, 99, 100); // V2: content pending publication
    let seq = fx.handoff(&id); // (the fence would refuse the fetch; the ledger itself does not)
    fx.report(1, 1, true, seq, &[id], &[]);
    assert_eq!(fx.presence(&id), (true, false));
}

/// The reporter protocol: a new epoch begins with a FULL snapshot; deltas apply only within the
/// same epoch and as the very next report, else the host is told to send a full one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_reporter_protocol_rejects_deltas_it_cannot_apply() {
    let fx = Fx::new();
    let id = fx.item("a.txt", 10);
    let other = fx.item("b.txt", 20);

    // A delta with no snapshot, or in a NEW epoch without a full one: needs_full, no state.
    assert!(fx.report(7, 1, false, 0, &[id], &[]).needs_full);
    assert_eq!(fx.presence(&id), (false, false));

    let ack = fx.report(7, 1, true, 0, &[id], &[]);
    assert!(!ack.needs_full);
    assert_eq!(ack.accepted_seq, 1);
    assert_eq!(fx.presence(&id), (true, false));

    // A gap, a repeat and another epoch's delta are all refused and change nothing.
    assert!(fx.report(7, 3, false, 0, &[other], &[]).needs_full, "a gap was accepted");
    assert!(fx.report(7, 1, false, 0, &[other], &[]).needs_full, "a repeat was accepted");
    assert!(
        fx.report(8, 2, false, 0, &[other], &[]).needs_full,
        "another epoch's delta was accepted"
    );
    assert_eq!(fx.presence(&other), (false, false));

    // The very next report of the same epoch applies.
    assert!(!fx.report(7, 2, false, 0, &[other], &[id]).needs_full);
    assert_eq!(fx.presence(&other), (true, false));
    assert_eq!(fx.presence(&id), (false, false));

    // A new epoch starts over with a full snapshot, which replaces everything.
    assert!(!fx.report(9, 1, true, 0, &[id], &[]).needs_full);
    assert_eq!(fx.presence(&id), (true, false));
    assert_eq!(fx.presence(&other), (false, false));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recording_a_handoff_takes_the_next_evidence_sequence() {
    let fx = Fx::new();
    let a = fx.item("a.txt", 10);
    let b = fx.item("b.txt", 20);
    assert_eq!(fx.repo().latest_evidence_seq(&fx.root).unwrap(), Some(0));
    assert_eq!(fx.handoff(&a), 1);
    assert_eq!(fx.handoff(&b), 2);
    assert_eq!(fx.handoff(&a), 3, "one row per item, latest wins");
    assert_eq!(fx.repo().latest_evidence_seq(&fx.root).unwrap(), Some(3));
    assert_eq!(fx.repo().handoff(&fx.root, &a).unwrap().unwrap().evidence_seq, 3);
}

/// A replayed full report restores nothing: after full(A), delta(remove A), the original full in
/// the same epoch is refused, and so is an older epoch's full report.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replayed_full_report_cannot_restore_removed_membership() {
    let fx = Fx::new();
    let a = fx.item("a.txt", 10);
    assert!(!fx.report(5, 1, true, 0, &[a], &[]).needs_full);
    assert!(fx.membership.stamp(&fx.root, &a).is_some());
    assert!(!fx.report(5, 2, false, 0, &[], &[a]).needs_full);
    assert!(fx.membership.stamp(&fx.root, &a).is_none());

    // The same epoch's original full report again.
    assert!(fx.report(5, 1, true, 0, &[a], &[]).needs_full, "a replay was accepted");
    assert!(fx.membership.stamp(&fx.root, &a).is_none(), "a replay restored membership");

    // A new epoch starts over; after that, an older epoch's full report is a replay too.
    assert!(!fx.report(6, 1, true, 0, &[], &[]).needs_full);
    assert!(fx.report(5, 1, true, 0, &[a], &[]).needs_full);
    assert!(fx.membership.stamp(&fx.root, &a).is_none());
    // A full report of a new epoch must begin at sequence 1.
    assert!(fx.report(7, 4, true, 0, &[a], &[]).needs_full);
    assert!(fx.membership.stamp(&fx.root, &a).is_none());
}

/// The observation claim is bounded: never above what the daemon issued, never decreasing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_observation_claim_is_bounded_and_monotonic() {
    let fx = Fx::new();
    let a = fx.item("a.txt", 10);
    let seq = fx.handoff(&a);
    assert!(fx.report(1, 1, true, seq + 1, &[a], &[]).needs_full, "a future claim was accepted");
    assert!(fx.membership.stamp(&fx.root, &a).is_none());

    assert!(!fx.report(2, 1, true, seq, &[a], &[]).needs_full);
    // A later delta cannot claim an earlier observation.
    assert!(fx.report(2, 2, false, seq - 1, &[a], &[]).needs_full);
    assert!(!fx.report(2, 2, false, seq, &[a], &[]).needs_full);
}

/// A full snapshot may arrive in pages: nothing counts until the last page, a delta cannot follow
/// an incomplete snapshot, and a hundred thousand items fit in frames of the allowed size.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_large_snapshot_counts_only_once_complete() {
    use prost::Message;
    let fx = Fx::new();
    let items: Vec<ItemId> = (0..100_000u32)
        .map(|n| {
            let mut id = [0u8; 16];
            id[..4].copy_from_slice(&n.to_be_bytes());
            id
        })
        .collect();
    let root_id = hex::decode(&fx.root).unwrap();
    let pages: Vec<ProviderMaterializedReport> = items
        .chunks(10_000)
        .enumerate()
        .map(|(index, page)| ProviderMaterializedReport {
            root_id: root_id.clone(),
            reporter_epoch: 3,
            report_seq: index as u64 + 1,
            full: true,
            observed_after_seq: 0,
            upserts: page
                .iter()
                .map(|i| ProviderMaterializedItem { item_id: i.to_vec() })
                .collect(),
            removed: Vec::new(),
            more: (index + 1) * 10_000 < items.len(),
        })
        .collect();
    for page in &pages {
        let frame = yadorilink_ipc_proto::shellipc::ShellIpcMessage {
            payload: Some(
                yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload::ProviderMaterializedReport(
                    page.clone(),
                ),
            ),
        };
        assert!(
            frame.encoded_len() < yadorilink_ipc_proto::framing::MAX_FRAME_LEN as usize,
            "a page of 10000 items does not fit a frame: {}",
            frame.encoded_len()
        );
    }
    let latest = fx.repo().latest_evidence_seq(&fx.root).unwrap().unwrap();
    for (index, page) in pages.iter().enumerate() {
        let ack = fx.membership.apply(page, latest);
        assert!(!ack.needs_full, "page {index} refused");
        if index + 1 < pages.len() {
            assert!(
                fx.membership.stamp(&fx.root, &items[0]).is_none(),
                "an incomplete snapshot counted after page {index}"
            );
        }
    }
    assert!(fx.membership.stamp(&fx.root, &items[0]).is_some());
    assert!(fx.membership.stamp(&fx.root, &items[99_999]).is_some());
    // A page after completion is a replay.
    assert!(fx.membership.apply(&pages[1], latest).needs_full);
}

/// An incomplete snapshot never grants evidence, and a delta cannot complete or extend it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_incomplete_snapshot_grants_nothing_and_takes_no_delta() {
    let fx = Fx::new();
    let a = fx.item("a.txt", 10);
    let first = ProviderMaterializedReport {
        root_id: hex::decode(&fx.root).unwrap(),
        reporter_epoch: 4,
        report_seq: 1,
        full: true,
        observed_after_seq: 0,
        upserts: vec![ProviderMaterializedItem { item_id: a.to_vec() }],
        removed: Vec::new(),
        more: true,
    };
    assert!(!fx.membership.apply(&first, 0).needs_full);
    assert!(fx.membership.stamp(&fx.root, &a).is_none());
    assert!(
        fx.report(4, 2, false, 0, &[a], &[]).needs_full,
        "a delta followed an incomplete snapshot"
    );
    // A new epoch abandons the incomplete one.
    assert!(!fx.report(5, 1, true, 0, &[a], &[]).needs_full);
    assert!(fx.membership.stamp(&fx.root, &a).is_some());
}

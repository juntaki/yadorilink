use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;

use yadorilink_replica_domain::change::{ChangePurpose, MAX_ANTI_ENTROPY_PAGE_BYTES};

use super::*;
use crate::error::AdmissionStoreError;
use crate::ports::{
    AdmissionStoreResult, ChangeAdmissionPort, DurabilityEvidencePort, DurabilityRoot,
    FrontierStorePort, ReplicaHistoryPort, ReplicaRetentionPolicy,
};
use crate::ReplicaEngineDependencies;

fn h(byte: u8) -> ChangeHash {
    ChangeHash([byte; 32])
}

/// A minimal, otherwise-unchecked `Change` -- `changes_for_request`'s
/// `change(hash).is_some()` recognition check only reads presence, never
/// content, so every recognized hash can share this one dummy value.
fn dummy_change() -> Change {
    Change {
        parents: Vec::new(),
        device_id: DeviceId("device".into()),
        group_id: FolderGroupId("group-1".into()),
        lamport: 0,
        auth_seq: 0,
        auth_epoch: 0,
        policy_head_hash: [0u8; 32],
        purpose: ChangePurpose::Ordinary,
        ops: Vec::new(),
        signature: [0u8; 64],
    }
}

/// A fake `Change` encoding is never decoded by anything these tests
/// exercise (`new_file_versions_for_change` silently skips undecodable bytes),
/// so each change's "encoding" is just its own hash bytes -- enough to
/// assert on which hashes made it into the response batch.
#[derive(Default)]
struct FakeHistory {
    /// child -> parents, oldest-first insertion order not required.
    parents: BTreeMap<ChangeHash, Vec<ChangeHash>>,
    /// Hashes recognized as live even with no parents of their own recorded
    /// here (e.g. a retained root) -- lets a test distinguish "recognized,
    /// zero parents" from "never seen at all," which plain graph edges
    /// alone cannot express.
    extra_recognized: BTreeSet<ChangeHash>,
    /// Encoded size (in bytes) `encoded_change` reports for every change --
    /// the first 32 bytes are always the hash itself, the rest is padding.
    /// Zero means "hash only," the shape every test that does not care about
    /// the page byte budget wants.
    encoded_change_bytes: usize,
}

impl FakeHistory {
    fn edge(mut self, child: ChangeHash, parents: &[ChangeHash]) -> Self {
        self.parents.insert(child, parents.to_vec());
        self
    }

    fn recognize(mut self, hash: ChangeHash) -> Self {
        self.extra_recognized.insert(hash);
        self
    }

    /// Makes every change report `bytes` of encoding, so a test can exercise
    /// the page BYTE budget independently of the page change-count cap.
    fn encoded_change_bytes(mut self, bytes: usize) -> Self {
        self.encoded_change_bytes = bytes;
        self
    }

    fn is_recognized(&self, hash: &ChangeHash) -> bool {
        self.parents.contains_key(hash)
            || self.parents.values().any(|parents| parents.contains(hash))
            || self.extra_recognized.contains(hash)
    }
}

impl ReplicaHistoryPort for FakeHistory {
    fn parents_of(&self, hash: &ChangeHash) -> Result<Vec<ChangeHash>, ReplicaEngineError> {
        Ok(self.parents.get(hash).cloned().unwrap_or_default())
    }

    fn encoded_change(&self, hash: &ChangeHash) -> Result<Option<Vec<u8>>, ReplicaEngineError> {
        let mut encoded = hash.0.to_vec();
        encoded.resize(encoded.len().max(self.encoded_change_bytes), 0u8);
        Ok(Some(encoded))
    }

    fn change(&self, hash: &ChangeHash) -> Result<Option<Change>, ReplicaEngineError> {
        Ok(self.is_recognized(hash).then(dummy_change))
    }

    fn group_heads(&self, _group: &FolderGroupId) -> Result<Vec<ChangeHash>, ReplicaEngineError> {
        unimplemented!("not exercised by changes_for_request")
    }

    fn missing_ancestor_frontier(
        &self,
        _roots: &[ChangeHash],
    ) -> Result<Vec<ChangeHash>, ReplicaEngineError> {
        unimplemented!("not exercised by changes_for_request")
    }

    fn has_file_version(
        &self,
        _group: &FolderGroupId,
        _hash: &VersionHash,
    ) -> Result<bool, ReplicaEngineError> {
        unimplemented!("not exercised by changes_for_request")
    }

    fn file_version(
        &self,
        _group: &FolderGroupId,
        _hash: &VersionHash,
    ) -> Result<Option<FileVersion>, ReplicaEngineError> {
        Ok(None)
    }
}

struct UnusedAdmission;
impl ChangeAdmissionPort for UnusedAdmission {
    fn admit_unprojected_change(
        &self,
        _change: &Change,
        _versions: &[FileVersion],
    ) -> Result<AdmissionStoreResult, AdmissionStoreError> {
        unimplemented!("not exercised by changes_for_request")
    }
}

struct UnusedFrontier;
impl FrontierStorePort for UnusedFrontier {
    fn record_acknowledged_frontier(
        &self,
        _group: &FolderGroupId,
        _device: &DeviceId,
        _frontier: &[ChangeHash],
    ) -> Result<(), ReplicaEngineError> {
        unimplemented!("not exercised by changes_for_request")
    }
}

struct UnusedDurability;
impl DurabilityEvidencePort for UnusedDurability {
    fn retention_policy(
        &self,
        _group: &FolderGroupId,
    ) -> Result<Option<ReplicaRetentionPolicy>, ReplicaEngineError> {
        unimplemented!("not exercised by changes_for_request")
    }
    fn current_root(
        &self,
        _group: &FolderGroupId,
        _path: &yadorilink_replica_domain::ids::SyncPath,
    ) -> Result<Option<DurabilityRoot>, ReplicaEngineError> {
        unimplemented!("not exercised by changes_for_request")
    }
    fn retained_roots(
        &self,
        _group: &FolderGroupId,
        _path: &yadorilink_replica_domain::ids::SyncPath,
    ) -> Result<Vec<DurabilityRoot>, ReplicaEngineError> {
        unimplemented!("not exercised by changes_for_request")
    }
    fn has_block_provenance(
        &self,
        _group: &FolderGroupId,
        _block: &yadorilink_replica_domain::ids::BlockHash,
    ) -> Result<bool, ReplicaEngineError> {
        unimplemented!("not exercised by changes_for_request")
    }
    fn verify_block(
        &self,
        _block: &yadorilink_replica_domain::ids::BlockHash,
    ) -> Result<(), ReplicaEngineError> {
        unimplemented!("not exercised by changes_for_request")
    }
}

fn engine(history: FakeHistory) -> PeerReplicaEngine {
    PeerReplicaEngine::new(ReplicaEngineDependencies {
        history: Arc::new(history),
        admission: Arc::new(UnusedAdmission),
        frontier: Arc::new(UnusedFrontier),
        durability: Arc::new(UnusedDurability),
    })
}

fn group() -> FolderGroupId {
    FolderGroupId("group-1".into())
}

fn hashes_of(batch: &[Vec<u8>]) -> Vec<ChangeHash> {
    batch
        .iter()
        .map(|encoded| {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&encoded[..32]);
            ChangeHash(bytes)
        })
        .collect()
}

fn all_hashes(pages: &[AntiEntropyPage]) -> Vec<ChangeHash> {
    pages.iter().flat_map(|page| hashes_of(&page.changes)).collect()
}

/// A long delta (want's ancestor closure exceeds the cap, `have_heads`
/// empty) is delivered as bounded, oldest-first pages -- not by forcing the
/// requested tip into every capped page. The tip is still guaranteed to
/// arrive, but by construction: it is always the last entry
/// `collect_ancestor_closure` appends, so it always lands in the final
/// page, whose `more` is `false`.
#[test]
fn long_delta_is_delivered_as_bounded_oldest_first_pages_ending_with_the_tip() {
    // c0 -> c1 -> c2 -> c3, cap = 3.
    let history = FakeHistory::default()
        .edge(h(1), &[h(0)])
        .edge(h(2), &[h(1)])
        .edge(h(3), &[h(2)]);
    let engine = engine(history);
    let pages = engine.changes_for_request(&group(), &[h(3)], &[], 3).unwrap();
    assert_eq!(pages.len(), 2, "expected two pages for 4 changes at cap 3: {pages:?}");
    assert!(pages[0].more, "first page must signal more pages follow");
    assert!(!pages[1].more, "last page must signal no further pages");
    assert_eq!(hashes_of(&pages[0].changes), vec![h(0), h(1), h(2)]);
    assert_eq!(hashes_of(&pages[1].changes), vec![h(3)]);
}

/// A page must also be bounded by BYTES, not only by change count. Each page
/// leaves the responder as one wire control frame, and the transport rejects
/// any frame over `MAX_CONTROL_FRAME_BYTES` (2 MiB) -- so a count-only bound
/// let a handful of bulk changes (a real initial import packs
/// `IMPORT_BATCH_OP_LIMIT` ops into each change) build a page no frame could
/// ever carry. Anti-entropy re-derives the identical delta on every retry, so
/// that failure never healed: the peer simply never received that history.
#[test]
fn a_page_of_large_changes_is_split_by_bytes_not_only_by_change_count() {
    // Four changes, each two thirds of the page byte budget, at a change-count
    // cap far higher than four -- so only the byte bound can split this.
    let per_change = (MAX_ANTI_ENTROPY_PAGE_BYTES / 3) * 2;
    let history = FakeHistory::default()
        .edge(h(1), &[h(0)])
        .edge(h(2), &[h(1)])
        .edge(h(3), &[h(2)])
        .encoded_change_bytes(per_change);
    let engine = engine(history);
    let pages = engine.changes_for_request(&group(), &[h(3)], &[], 1000).unwrap();

    assert_eq!(
        all_hashes(&pages),
        vec![h(0), h(1), h(2), h(3)],
        "every change must still be delivered, oldest-first, once"
    );
    assert!(
        pages.len() >= 4,
        "each change exceeds half the budget, so none may share a page: {}",
        pages.len()
    );
    for page in &pages {
        let bytes: usize = page.changes.iter().map(Vec::len).sum::<usize>()
            + page.file_versions.iter().map(Vec::len).sum::<usize>();
        assert!(
            page.changes.len() == 1 || bytes <= MAX_ANTI_ENTROPY_PAGE_BYTES,
            "a multi-change page must stay within the byte budget, got {bytes}"
        );
    }
    assert!(pages.iter().rev().skip(1).all(|page| page.more), "every page but the last sets more");
    assert!(!pages.last().expect("at least one page").more, "the last page clears more");
}

/// Teeth for the bound above: a single change larger than the whole budget is
/// still delivered, alone on its own page, rather than dropped or wedging the
/// walk. A change cannot be wire-split, so this is the only correct handling.
#[test]
fn one_change_over_the_whole_page_budget_is_still_delivered_alone() {
    let history = FakeHistory::default()
        .edge(h(1), &[h(0)])
        .encoded_change_bytes(MAX_ANTI_ENTROPY_PAGE_BYTES * 2);
    let engine = engine(history);
    let pages = engine.changes_for_request(&group(), &[h(1)], &[], 1000).unwrap();
    assert_eq!(all_hashes(&pages), vec![h(0), h(1)]);
    assert!(
        pages.iter().all(|page| page.changes.len() == 1),
        "each over-budget change alone: {pages:?}"
    );
}

/// A requester declaring `have_heads` one hash behind the responder's
/// history receives only the true delta, not a redelivery of history it
/// already declared it holds.
#[test]
fn receiver_declaring_have_heads_receives_only_the_true_delta() {
    let history = FakeHistory::default()
        .edge(h(1), &[h(0)])
        .edge(h(2), &[h(1)])
        .edge(h(3), &[h(2)]);
    let engine = engine(history);
    let pages = engine.changes_for_request(&group(), &[h(3)], &[h(2)], 3).unwrap();
    assert_eq!(pages.len(), 1);
    assert!(!pages[0].more);
    assert_eq!(hashes_of(&pages[0].changes), vec![h(3)], "must not re-send declared history");
}

/// The diverging-branches case: a shared ancestor
/// `c0` followed by independent `a`/`b` branches. `want_heads = [a2]`,
/// `have_heads = [b2]` -- a naive exact-hash check never fires (`b2` is not
/// an ancestor of `a2`), so the sender must walk `b2`'s own recognized
/// ancestry to discover the true shared frontier `c0`, and the delta must
/// be exactly `{a1, a2}`, not `c0`'s history too.
#[test]
fn diverging_branches_delta_excludes_only_the_true_shared_history() {
    let c0 = h(0);
    let a1 = ChangeHash([0xA1; 32]);
    let a2 = ChangeHash([0xA2; 32]);
    let b1 = ChangeHash([0xB1; 32]);
    let b2 = ChangeHash([0xB2; 32]);
    let history =
        FakeHistory::default().edge(a1, &[c0]).edge(a2, &[a1]).edge(b1, &[c0]).edge(b2, &[b1]);
    let engine = engine(history);
    let pages = engine.changes_for_request(&group(), &[a2], &[b2], 100).unwrap();
    assert_eq!(pages.len(), 1);
    let got = hashes_of(&pages[0].changes);
    assert_eq!(got, vec![a1, a2], "delta must be exactly {{a1, a2}}, got {got:?}");
}

/// An unrecognized/spoofed `have_heads` entry -- a hash this device has
/// never seen -- must never narrow the delta: it is not walked at all, so
/// it cannot exclude any real ancestor, even one that happens to share its
/// low bytes with a genuine hash in the chain.
#[test]
fn unrecognized_have_head_never_narrows_the_delta() {
    let history = FakeHistory::default()
        .edge(h(1), &[h(0)])
        .edge(h(2), &[h(1)])
        .edge(h(3), &[h(2)]);
    let engine = engine(history);
    let spoofed = ChangeHash([0xFF; 32]);
    let pages = engine.changes_for_request(&group(), &[h(3)], &[spoofed], 100).unwrap();
    assert_eq!(pages.len(), 1);
    assert_eq!(
        hashes_of(&pages[0].changes),
        vec![h(0), h(1), h(2), h(3)],
        "an unrecognized have_heads entry must not omit any real history"
    );
}

/// A recognized `have` hash with no recorded parents of its own (a retained
/// root) must still be excludable -- recognition is checked via `change`,
/// not merely by matching a `parents_of` key.
#[test]
fn a_recognized_root_have_head_is_excluded_even_with_no_parents_of_its_own() {
    let history = FakeHistory::default()
        .edge(h(1), &[h(0)])
        .edge(h(2), &[h(1)])
        .recognize(h(0));
    let engine = engine(history);
    let pages = engine.changes_for_request(&group(), &[h(2)], &[h(0)], 100).unwrap();
    assert_eq!(pages.len(), 1);
    assert_eq!(hashes_of(&pages[0].changes), vec![h(1), h(2)]);
}

/// Two independently-requested heads whose combined closure exceeds the
/// cap: both must survive across the resulting pages, regardless of which
/// order `want_heads` lists them in or how large either branch's history is.
#[test]
fn both_concurrently_requested_heads_survive_pagination() {
    // Two independent 3-change branches: a0->a1->a2, b0->b1->b2.
    let history = FakeHistory::default()
        .edge(ChangeHash([0xA1; 32]), &[ChangeHash([0xA0; 32])])
        .edge(ChangeHash([0xA2; 32]), &[ChangeHash([0xA1; 32])])
        .edge(ChangeHash([0xB1; 32]), &[ChangeHash([0xB0; 32])])
        .edge(ChangeHash([0xB2; 32]), &[ChangeHash([0xB1; 32])]);
    let engine = engine(history);
    let want = [ChangeHash([0xA2; 32]), ChangeHash([0xB2; 32])];
    let pages = engine.changes_for_request(&group(), &want, &[], 4).unwrap();
    let got = all_hashes(&pages);
    assert!(got.contains(&ChangeHash([0xA2; 32])), "requested head a2 missing: {got:?}");
    assert!(got.contains(&ChangeHash([0xB2; 32])), "requested head b2 missing: {got:?}");
    assert!(pages.last().is_some_and(|page| !page.more));
}

/// An empty receiver requesting a tip far beyond the per-page cap converges
/// in a single `changes_for_request` call via pagination -- not, as under
/// the old full-closure-walk-then-truncate mechanism, via repeated
/// re-requests of newly-discovered missing parents. This is a fast,
/// low-layer stand-in for the real-wire `dag_paging_termination_tests`/
/// `real_auth_dag_paging_tests` case: the whole chain must arrive, oldest
/// first, in one request.
#[test]
fn empty_receiver_reaches_a_far_tip_via_pagination_in_one_request() {
    const CHAIN_LEN: u8 = 10;
    let mut history = FakeHistory::default();
    for i in 1..CHAIN_LEN {
        history = history.edge(h(i), &[h(i - 1)]);
    }
    let engine = engine(history);
    let pages = engine.changes_for_request(&group(), &[h(CHAIN_LEN - 1)], &[], 3).unwrap();
    let expected_pages = (CHAIN_LEN as usize).div_ceil(3);
    assert_eq!(pages.len(), expected_pages, "unexpected page count: {pages:?}");
    for page in &pages[..pages.len() - 1] {
        assert!(page.more, "every page but the last must signal more");
    }
    assert!(!pages.last().unwrap().more, "the last page must signal no further pages");
    let got = all_hashes(&pages);
    let expected: Vec<ChangeHash> = (0..CHAIN_LEN).map(h).collect();
    assert_eq!(got, expected, "pages must deliver the whole chain, oldest first, in order");
}

/// A disconnect mid-transfer, followed by a reconnect that declares a
/// newly-advanced `have_heads`, transfers only the remainder -- no durable
/// cursor is needed across the gap, since `have_heads` alone is enough to
/// recompute the correct remaining delta from scratch.
#[test]
fn reconnect_with_advanced_have_heads_transfers_only_the_remainder() {
    let history = FakeHistory::default()
        .edge(h(1), &[h(0)])
        .edge(h(2), &[h(1)])
        .edge(h(3), &[h(2)])
        .edge(h(4), &[h(3)]);
    let engine = engine(history);

    // First connection: nothing received yet.
    let first = engine.changes_for_request(&group(), &[h(4)], &[], 3).unwrap();
    assert_eq!(all_hashes(&first), vec![h(0), h(1), h(2), h(3), h(4)]);

    // Disconnects after applying only the first page (h0..h2); reconnects
    // declaring its own now-advanced heads.
    let second = engine.changes_for_request(&group(), &[h(4)], &[h(2)], 3).unwrap();
    assert_eq!(
        all_hashes(&second),
        vec![h(3), h(4)],
        "reconnect must transfer only the remainder, not the whole delta again"
    );
}

/// **Phase E finding, second pass (a Codex review's finding on the first
/// pass's fix above)**: merely removing the blanket early return and
/// queueing every head for expansion is not enough. `shared_tip` (present
/// on both sides, like `branch1_tip` above) now has its OWN single parent
/// `unrelated_parent`, which has nothing to do with the a/b branches'
/// actual divergence. Both sides expand `shared_tip` in lock-step (it is
/// literally the same node with the same parent on each side), so
/// `unrelated_parent` gets discovered on BOTH sides after exactly one
/// layer each -- an immediate, spurious match that stops the ENTIRE
/// bidirectional search before `a2`/`b2`'s own chain has gone anywhere
/// near their true shared ancestor `S`, 2000 hops down a completely
/// separate chain. Without excluding an already-resolved head from
/// expansion entirely, `collect_ancestor_closure` for `a2` then has no
/// `have_seen` member anywhere on its real ancestry path and walks the
/// full 2000-deep chain looking for one that was never discovered.
#[test]
fn already_matched_heads_ancestry_never_contaminates_a_diverging_heads_boundary_search() {
    const DEPTH: u32 = 2000;
    let shared_tip = ChangeHash([0x11; 32]);
    let unrelated_parent = ChangeHash([0x99; 32]);
    let a1 = ChangeHash([0xA1; 32]);
    let a2 = ChangeHash([0xA2; 32]);
    let b1 = ChangeHash([0xB1; 32]);
    let b2 = ChangeHash([0xB2; 32]);

    let mut history = FakeHistory::default()
        .edge(shared_tip, &[unrelated_parent])
        .recognize(unrelated_parent);
    for i in 1..=DEPTH {
        history = history.edge(hn(i), &[hn(i - 1)]);
    }
    // hn(DEPTH) = S, the true shared ancestor for the diverging branch --
    // entirely unrelated to `shared_tip`/`unrelated_parent`.
    history = history.edge(a1, &[hn(DEPTH)]).edge(a2, &[a1]).edge(b1, &[hn(DEPTH)]).edge(b2, &[b1]);

    let counting = Arc::new(CountingHistory::new(history));
    let engine = PeerReplicaEngine::new(ReplicaEngineDependencies {
        history: counting.clone(),
        admission: Arc::new(UnusedAdmission),
        frontier: Arc::new(UnusedFrontier),
        durability: Arc::new(UnusedDurability),
    });

    let want = [shared_tip, a2];
    let have = [shared_tip, b2];
    let pages = engine.changes_for_request(&group(), &want, &have, 100).unwrap();
    let got = all_hashes(&pages);
    assert_eq!(got, vec![a1, a2], "true minimal delta is just {{a1, a2}}, got {got:?}");
    assert!(
        counting.parents_of_call_count() < 20,
        "expected work bounded by the divergence, got {} -- the already-matched head's own \
         ancestry contaminated the search for the still-diverging head",
        counting.parents_of_call_count()
    );
}

fn hn(index: u32) -> ChangeHash {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&index.to_be_bytes());
    ChangeHash(bytes)
}

struct CountingHistory {
    inner: FakeHistory,
    parents_of_calls: std::sync::atomic::AtomicUsize,
}

impl CountingHistory {
    fn new(inner: FakeHistory) -> Self {
        Self { inner, parents_of_calls: std::sync::atomic::AtomicUsize::new(0) }
    }

    fn parents_of_call_count(&self) -> usize {
        self.parents_of_calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl ReplicaHistoryPort for CountingHistory {
    fn parents_of(&self, hash: &ChangeHash) -> Result<Vec<ChangeHash>, ReplicaEngineError> {
        self.parents_of_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.parents_of(hash)
    }

    fn encoded_change(&self, hash: &ChangeHash) -> Result<Option<Vec<u8>>, ReplicaEngineError> {
        self.inner.encoded_change(hash)
    }

    fn change(&self, hash: &ChangeHash) -> Result<Option<Change>, ReplicaEngineError> {
        self.inner.change(hash)
    }

    fn group_heads(&self, group: &FolderGroupId) -> Result<Vec<ChangeHash>, ReplicaEngineError> {
        self.inner.group_heads(group)
    }

    fn missing_ancestor_frontier(
        &self,
        roots: &[ChangeHash],
    ) -> Result<Vec<ChangeHash>, ReplicaEngineError> {
        self.inner.missing_ancestor_frontier(roots)
    }

    fn has_file_version(
        &self,
        group: &FolderGroupId,
        hash: &VersionHash,
    ) -> Result<bool, ReplicaEngineError> {
        self.inner.has_file_version(group, hash)
    }

    fn file_version(
        &self,
        group: &FolderGroupId,
        hash: &VersionHash,
    ) -> Result<Option<FileVersion>, ReplicaEngineError> {
        self.inner.file_version(group, hash)
    }
}

/// A small divergence over deep retained history must cost work proportional
/// to the delta and the shared-frontier discovery, not to the total retained
/// history depth: `have_heads` sits 2 hashes behind a 2000-deep chain, so
/// `parents_of` must be called only a handful of times, never once per
/// retained change.
#[test]
fn small_divergence_over_deep_history_reads_are_bounded_by_the_delta() {
    const DEPTH: u32 = 2000;
    let mut history = FakeHistory::default();
    for i in 1..=DEPTH {
        history = history.edge(hn(i), &[hn(i - 1)]);
    }
    let counting = Arc::new(CountingHistory::new(history));
    let engine = PeerReplicaEngine::new(ReplicaEngineDependencies {
        history: counting.clone(),
        admission: Arc::new(UnusedAdmission),
        frontier: Arc::new(UnusedFrontier),
        durability: Arc::new(UnusedDurability),
    });

    let pages =
        engine.changes_for_request(&group(), &[hn(DEPTH)], &[hn(DEPTH - 2)], 100).unwrap();
    assert_eq!(all_hashes(&pages), vec![hn(DEPTH - 1), hn(DEPTH)]);
    assert!(
        counting.parents_of_call_count() < 20,
        "expected a bounded number of parents_of calls proportional to the delta, got {}",
        counting.parents_of_call_count()
    );
}

/// **Phase E finding**: `recognized_have_boundary` used to special-case ANY
/// want/have overlap across the WHOLE sets with a blanket early return,
/// skipping the bidirectional search entirely and returning the raw
/// `have_heads` hashes as the boundary. That is correct for the common
/// single-head "already fully caught up" case, but wrong for a MULTI-head
/// request where one head (`branch1_tip`, a recognized root already shared
/// by both sides) is already caught up while ANOTHER head genuinely
/// diverges deep in shared history: the shortcut fired on `branch1_tip`
/// alone and never discovered the true, much closer shared ancestor `S`
/// for the still-diverging branch, so `collect_ancestor_closure` had to
/// walk the whole `DEPTH`-deep ancient chain below `S` before ever finding
/// a literal `have_heads` hash to stop at. `parents_of_call_count` pins
/// this down directly: bounded (a handful of calls) after the fix, would
/// have been `O(DEPTH)` before it.
#[test]
fn multi_head_shortcut_does_not_starve_the_other_heads_boundary_search() {
    const DEPTH: u32 = 2000;
    let branch1_tip = ChangeHash([0x11; 32]);
    let a1 = ChangeHash([0xA1; 32]);
    let a2 = ChangeHash([0xA2; 32]);
    let b1 = ChangeHash([0xB1; 32]);
    let b2 = ChangeHash([0xB2; 32]);

    let mut history = FakeHistory::default().recognize(branch1_tip);
    for i in 1..=DEPTH {
        history = history.edge(hn(i), &[hn(i - 1)]);
    }
    // hn(DEPTH) = S, the true shared ancestor for the diverging branch,
    // only 2 hops from either side's requested/held tip.
    history = history.edge(a1, &[hn(DEPTH)]).edge(a2, &[a1]).edge(b1, &[hn(DEPTH)]).edge(b2, &[b1]);

    let counting = Arc::new(CountingHistory::new(history));
    let engine = PeerReplicaEngine::new(ReplicaEngineDependencies {
        history: counting.clone(),
        admission: Arc::new(UnusedAdmission),
        frontier: Arc::new(UnusedFrontier),
        durability: Arc::new(UnusedDurability),
    });

    let want = [branch1_tip, a2];
    let have = [branch1_tip, b2];
    let pages = engine.changes_for_request(&group(), &want, &have, 100).unwrap();
    let got = all_hashes(&pages);
    assert_eq!(got, vec![a1, a2], "true minimal delta is just {{a1, a2}}, got {got:?}");
    assert!(
        counting.parents_of_call_count() < 20,
        "expected work bounded by the divergence (a handful of parents_of calls), got {} -- \
         the multi-head shortcut skipped the boundary search for the still-diverging head",
        counting.parents_of_call_count()
    );
}

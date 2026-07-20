use super::*;
use std::cell::RefCell;
use std::collections::BTreeMap;

fn h(byte: u8) -> ChangeHash {
    ChangeHash([byte; 32])
}

#[test]
fn checkpoint_encoding_round_trips_and_normalizes() {
    let checkpoint = Checkpoint::new(
        FolderGroupId("group-1".into()),
        vec![h(0x33), h(0x11), h(0x33), h(0x22)],
        [0xab; 32],
    );
    assert_eq!(checkpoint.frontier, vec![h(0x11), h(0x22), h(0x33)]);
    let decoded = Checkpoint::decode(&checkpoint.canonical_encoding()).unwrap();
    assert_eq!(decoded, checkpoint);
    assert_eq!(decoded.checkpoint_hash(), checkpoint.checkpoint_hash());
}

#[test]
fn checkpoint_hash_is_independent_of_input_order() {
    let left = Checkpoint::new(FolderGroupId("g".into()), vec![h(1), h(2)], [7; 32]);
    let right = Checkpoint::new(FolderGroupId("g".into()), vec![h(2), h(1)], [7; 32]);
    assert_eq!(left.checkpoint_hash(), right.checkpoint_hash());
}

#[test]
fn decode_rejects_truncation() {
    let checkpoint = Checkpoint::new(FolderGroupId("g".into()), vec![h(1)], [0; 32]);
    let bytes = checkpoint.canonical_encoding();
    for cut in [0, 8, 12, bytes.len() - 1] {
        assert!(Checkpoint::decode(&bytes[..cut]).is_err());
    }
}

#[derive(Default)]
struct MockStore {
    parents: BTreeMap<ChangeHash, Vec<ChangeHash>>,
    heads: Vec<ChangeHash>,
    frontiers: RefCell<BTreeMap<(String, String), Vec<ChangeHash>>>,
    checkpoints: RefCell<Vec<Checkpoint>>,
    deleted: RefCell<Vec<ChangeHash>>,
}

impl MockStore {
    fn edge(&mut self, child: u8, parents: &[u8]) {
        self.parents.insert(h(child), parents.iter().map(|byte| h(*byte)).collect());
    }

    fn present(&self, change: &ChangeHash) -> bool {
        self.parents.contains_key(change) && !self.deleted.borrow().contains(change)
    }
}

impl CompactionDagStore for MockStore {
    fn heads(&self, _group: &FolderGroupId) -> Result<Vec<ChangeHash>, SyncError> {
        Ok(self.heads.clone())
    }

    fn parents(
        &self,
        _group: &FolderGroupId,
        change: &ChangeHash,
    ) -> Result<Vec<ChangeHash>, SyncError> {
        if self.deleted.borrow().contains(change) {
            return Ok(Vec::new());
        }
        Ok(self.parents.get(change).cloned().unwrap_or_default())
    }

    fn contains_change(
        &self,
        _group: &FolderGroupId,
        change: &ChangeHash,
    ) -> Result<bool, SyncError> {
        Ok(self.present(change))
    }

    fn was_pruned(&self, _group: &FolderGroupId, change: &ChangeHash) -> Result<bool, SyncError> {
        Ok(self.deleted.borrow().contains(change))
    }
}

impl DeviceFrontierStore for MockStore {
    fn set_device_frontier(
        &self,
        group: &FolderGroupId,
        device: &DeviceId,
        frontier: &[ChangeHash],
    ) -> Result<(), SyncError> {
        self.frontiers
            .borrow_mut()
            .insert((group.as_str().into(), device.as_str().into()), frontier.to_vec());
        Ok(())
    }

    fn get_device_frontier(
        &self,
        group: &FolderGroupId,
        device: &DeviceId,
    ) -> Result<Vec<ChangeHash>, SyncError> {
        Ok(self
            .frontiers
            .borrow()
            .get(&(group.as_str().into(), device.as_str().into()))
            .cloned()
            .unwrap_or_default())
    }

    fn remove_device_frontier(
        &self,
        group: &FolderGroupId,
        device: &DeviceId,
    ) -> Result<(), SyncError> {
        self.frontiers.borrow_mut().remove(&(group.as_str().into(), device.as_str().into()));
        Ok(())
    }
}

impl CheckpointStore for MockStore {
    fn latest_checkpoint(&self, group: &FolderGroupId) -> Result<Option<Checkpoint>, SyncError> {
        Ok(self
            .checkpoints
            .borrow()
            .iter()
            .filter(|checkpoint| checkpoint.group_id == *group)
            .next_back()
            .cloned())
    }

    fn commit_prune(
        &self,
        checkpoint: &Checkpoint,
        pruned: &[ChangeHash],
    ) -> Result<(), SyncError> {
        self.checkpoints.borrow_mut().push(checkpoint.clone());
        self.deleted.borrow_mut().extend_from_slice(pruned);
        Ok(())
    }

    fn history_base_previous_checkpoint_hash(
        &self,
        _group: &FolderGroupId,
    ) -> Result<Option<[u8; 32]>, SyncError> {
        let checkpoints = self.checkpoints.borrow();
        Ok(checkpoints
            .len()
            .checked_sub(2)
            .and_then(|i| checkpoints.get(i))
            .map(|checkpoint| checkpoint.checkpoint_hash().0))
    }
}

fn group() -> FolderGroupId {
    FolderGroupId("g".into())
}

fn dev(name: &str) -> DeviceId {
    DeviceId(name.into())
}

fn prunable_store() -> (MockStore, PrunePlan) {
    let mut store = MockStore::default();
    store.edge(1, &[]);
    store.edge(2, &[1]);
    store.edge(3, &[2]);
    store.edge(4, &[3]);
    store.heads = vec![h(4)];
    let enrolled = vec![dev("a"), dev("b")];
    record_acknowledged_frontier(&store, &group(), &dev("a"), &[h(3)]).unwrap();
    record_acknowledged_frontier(&store, &group(), &dev("b"), &[h(3)]).unwrap();
    let plan = plan_prune(&store, &group(), &enrolled).unwrap();
    (store, plan)
}

#[test]
fn prunes_interior_keeps_cut_and_head() {
    let (store, plan) = prunable_store();
    assert_eq!(plan.checkpoint_frontier, vec![h(3)]);
    assert_eq!(plan.pruned, vec![h(1), h(2)]);
    assert!(plan.blocking_devices.is_empty());

    let checkpoint = execute_prune_unchecked(&store, &plan, [9; 32]).unwrap().unwrap();
    assert_eq!(checkpoint.frontier, vec![h(3)]);
    assert_eq!(
        checkpoint_supersedes(&store, &group(), &h(1)).unwrap(),
        CheckpointSupersession::SupersededByCheckpoint
    );
}

#[test]
fn public_execute_prune_fails_closed_until_rebootstrap_pipeline_is_ready() {
    let (store, plan) = prunable_store();
    assert!(!crate::rebootstrap::COMPACTION_SCHEDULING_READY);

    let error = execute_prune(&store, &plan, [9; 32]).unwrap_err();
    assert!(matches!(error, SyncError::CorruptState(_)));
    assert!(store.checkpoints.borrow().is_empty());
    assert!(store.deleted.borrow().is_empty());
}

#[test]
fn lagging_device_blocks_pruning() {
    let mut store = MockStore::default();
    store.edge(1, &[]);
    store.edge(2, &[1]);
    store.heads = vec![h(2)];

    let enrolled = vec![dev("a"), dev("b")];
    record_acknowledged_frontier(&store, &group(), &dev("a"), &[h(2)]).unwrap();

    let plan = plan_prune(&store, &group(), &enrolled).unwrap();
    assert!(plan.is_empty());
    assert_eq!(plan.blocking_devices, vec![dev("b")]);

    let plan = replan_after_removal(&store, &group(), &dev("b"), &[dev("a")]).unwrap();
    assert_eq!(plan.pruned, vec![h(1)]);
    assert_eq!(plan.checkpoint_frontier, vec![h(2)]);
}

#[test]
fn rebootstrap_triggers_only_for_exactly_attested_pruned_history() {
    let mut store = MockStore::default();
    store.edge(1, &[]);
    store.edge(2, &[1]);
    store.edge(3, &[2]);
    store.heads = vec![h(3)];
    record_acknowledged_frontier(&store, &group(), &dev("a"), &[h(2)]).unwrap();
    record_acknowledged_frontier(&store, &group(), &dev("b"), &[h(2)]).unwrap();

    let plan = plan_prune(&store, &group(), &[dev("a"), dev("b")]).unwrap();
    execute_prune_unchecked(&store, &plan, [1; 32]).unwrap();

    let plan = plan_rebootstrap(&store, &group(), &[h(1)]).unwrap();
    assert!(plan.is_some());
    assert_eq!(plan.unwrap().current_heads, vec![h(3)]);
    assert!(plan_rebootstrap(&store, &group(), &[h(3)]).unwrap().is_none());
}

#[test]
fn checkpoint_does_not_classify_an_arbitrary_unknown_hash_as_pruned() {
    let mut store = MockStore::default();
    store.edge(1, &[]);
    store.edge(2, &[1]);
    store.heads = vec![h(2)];
    store.checkpoints.borrow_mut().push(Checkpoint::new(group(), vec![h(1)], [9; 32]));

    assert_eq!(
        checkpoint_supersedes(&store, &group(), &h(99)).unwrap(),
        CheckpointSupersession::Unknown
    );
    assert!(plan_rebootstrap(&store, &group(), &[h(99)]).unwrap().is_none());
}

#[test]
fn exact_checkpoint_frontier_hash_is_still_superseded() {
    let mut store = MockStore::default();
    store.edge(1, &[]);
    store.heads = vec![h(1)];
    store.checkpoints.borrow_mut().push(Checkpoint::new(group(), vec![h(1)], [7; 32]));

    assert_eq!(
        checkpoint_supersedes(&store, &group(), &h(1)).unwrap(),
        CheckpointSupersession::SupersededByCheckpoint
    );
}

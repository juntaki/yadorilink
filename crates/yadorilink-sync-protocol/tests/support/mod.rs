//! An in-memory replica, standing in for the storage layer.

// Shared by several test binaries, each of which uses only part of it.
#![allow(dead_code)]

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use yadorilink_rbsr::ItemId;
use yadorilink_sync_protocol::ports::{BaseVerdict, GroupId, PeerKey, PortError, ReplicaPort};
use yadorilink_sync_protocol::wire::OpaqueBundle;

pub const PEER_A: [u8; 32] = [0xA1; 32];
pub const PEER_B: [u8; 32] = [0xB2; 32];

pub fn group() -> GroupId {
    GroupId("shared-folder".into())
}

pub fn id(value: u64) -> ItemId {
    let mut bytes = [0u8; 32];
    // Scattered rather than contiguous, the way real content hashes are.
    let mut state = value.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    for chunk in bytes.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_be_bytes());
    }
    ItemId::from_bytes(bytes)
}

/// The payload a bundle for `id` carries. Any deterministic function will do;
/// the protocol never looks inside.
pub fn payload_for(id: &ItemId) -> Vec<u8> {
    let mut payload = b"bundle:".to_vec();
    payload.extend_from_slice(id.as_bytes());
    payload
}

pub struct MockReplica {
    possessed: Mutex<BTreeSet<ItemId>>,
    disclose: bool,
    /// Set to reject every delivery, standing in for verification failing.
    pub reject_staging: bool,
    pub stage_calls: AtomicUsize,
    pub serve_calls: AtomicUsize,
    pub disclose_calls: AtomicUsize,
    /// The history base this replica advertises. Opaque to the protocol;
    /// two replicas share a base exactly when these bytes are equal.
    pub base: Vec<u8>,
    /// Set to have every base negotiation refused.
    pub refuse_bases: bool,
    pub servable_calls: AtomicUsize,
    /// Every base verdict this replica reached, in order.
    pub verdicts: Mutex<Vec<BaseVerdict>>,
    /// Every advertisement this replica was told could not be judged.
    pub unjudged: Mutex<Vec<String>>,
}

impl MockReplica {
    pub fn with(ids: impl IntoIterator<Item = ItemId>) -> Self {
        Self {
            possessed: Mutex::new(ids.into_iter().collect()),
            disclose: true,
            reject_staging: false,
            stage_calls: AtomicUsize::new(0),
            serve_calls: AtomicUsize::new(0),
            disclose_calls: AtomicUsize::new(0),
            base: b"genesis".to_vec(),
            refuse_bases: false,
            servable_calls: AtomicUsize::new(0),
            verdicts: Mutex::new(Vec::new()),
            unjudged: Mutex::new(Vec::new()),
        }
    }

    pub fn on_base(mut self, base: &[u8]) -> Self {
        self.base = base.to_vec();
        self
    }

    pub fn refusing_bases(mut self) -> Self {
        self.refuse_bases = true;
        self
    }

    pub fn undisclosable(mut self) -> Self {
        self.disclose = false;
        self
    }

    pub fn rejecting_staging(mut self) -> Self {
        self.reject_staging = true;
        self
    }

    pub fn possessed(&self) -> BTreeSet<ItemId> {
        self.possessed.lock().unwrap().clone()
    }
}

impl ReplicaPort for MockReplica {
    async fn may_disclose(&self, _peer: PeerKey, _group: GroupId) -> Result<bool, PortError> {
        self.disclose_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.disclose)
    }

    async fn base_advertisement(
        &self,
        _peer: PeerKey,
        _group: GroupId,
    ) -> Result<Vec<u8>, PortError> {
        Ok(self.base.clone())
    }

    async fn negotiate_base(
        &self,
        _peer: PeerKey,
        _group: GroupId,
        ours: Vec<u8>,
        theirs: Vec<u8>,
    ) -> Result<BaseVerdict, PortError> {
        let verdict = if self.refuse_bases {
            BaseVerdict::Refused("refused by the test replica".into())
        } else if ours == theirs {
            BaseVerdict::SameBase
        } else {
            BaseVerdict::MergeRequired
        };
        self.verdicts.lock().unwrap().push(verdict.clone());
        Ok(verdict)
    }

    async fn base_unjudgeable(
        &self,
        _peer: PeerKey,
        _group: GroupId,
        reason: String,
    ) -> Result<(), PortError> {
        self.unjudged.lock().unwrap().push(reason);
        Ok(())
    }

    async fn servable(&self, _peer: PeerKey, _group: GroupId) -> Result<Vec<ItemId>, PortError> {
        self.servable_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.possessed.lock().unwrap().iter().copied().collect())
    }

    async fn load_bundles(
        &self,
        _peer: PeerKey,
        _group: GroupId,
        hashes: Vec<ItemId>,
    ) -> Result<Vec<OpaqueBundle>, PortError> {
        self.serve_calls.fetch_add(1, Ordering::SeqCst);
        let held = self.possessed.lock().unwrap();
        Ok(hashes
            .iter()
            .filter(|hash| held.contains(hash))
            .map(|hash| OpaqueBundle { change_hash: *hash, payload: payload_for(hash) })
            .collect())
    }

    async fn stage_bundles(
        &self,
        _peer: PeerKey,
        _group: GroupId,
        bundles: Vec<OpaqueBundle>,
    ) -> Result<Vec<ItemId>, PortError> {
        self.stage_calls.fetch_add(1, Ordering::SeqCst);

        // Validate the whole delivery before staging any of it: a peer must
        // not get the front of a batch accepted by corrupting the back.
        let mut verified = HashMap::new();
        for bundle in &bundles {
            if self.reject_staging || bundle.payload != payload_for(&bundle.change_hash) {
                return Err(PortError::new("delivery failed verification"));
            }
            verified.insert(bundle.change_hash, ());
        }

        let mut held = self.possessed.lock().unwrap();
        let mut newly = Vec::new();
        for hash in verified.keys() {
            if held.insert(*hash) {
                newly.push(*hash);
            }
        }
        newly.sort_unstable();
        Ok(newly)
    }
}

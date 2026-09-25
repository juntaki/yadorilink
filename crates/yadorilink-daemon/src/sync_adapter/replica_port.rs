//! The `ReplicaPort` this device presents to a sync session.

use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use yadorilink_rbsr::ItemId;
use yadorilink_replica_domain::base_negotiation::{self, BaseAdvertisement, BaseNegotiation};
use yadorilink_replica_domain::ids::{ChangeHash, FolderGroupId};
use yadorilink_sync_protocol::ports::{BaseVerdict, GroupId, PeerKey, PortError, ReplicaPort};
use yadorilink_sync_protocol::wire::OpaqueBundle;

use super::admission::AdmissionCoordinator;
use super::async_store::AsyncReplicaStore;
use super::foreign_base::ForeignBaseClaims;
use super::{bundle_codec, verify};
use yadorilink_lane_ports::PeerDirectory;

/// Resolves the authority key a checkpoint's signature must verify against,
/// for one group, backed by that group's verified policy chain.
pub type AuthorityResolver =
    Arc<dyn Fn(&str, &[u8; 32], &[u8; 32]) -> Option<VerifyingKey> + Send + Sync>;

/// This device's side of a sync session.
pub struct SqliteReplicaPort<D: PeerDirectory + 'static> {
    store: AsyncReplicaStore,
    directory: Arc<D>,
    authority: AuthorityResolver,
    /// Woken whenever something is newly staged. Optional so the port can be
    /// exercised on its own; in the daemon it is always present.
    admission: Option<Arc<AdmissionCoordinator>>,
    /// Told whenever this device's possession of a group grows.
    ///
    /// Shared and read live rather than captured: the driver that installs it
    /// is built on top of this port, so a snapshot taken at construction
    /// would be empty for the life of the process.
    possession: Arc<std::sync::Mutex<Option<PossessionObserver>>>,
    /// Peers found on another history base: the merge-required state.
    foreign_bases: Arc<ForeignBaseClaims>,
}

/// Notified that this device now possesses something in `group` it did not
/// before.
pub type PossessionObserver = Arc<dyn Fn(&FolderGroupId) + Send + Sync>;

impl<D: PeerDirectory + 'static> SqliteReplicaPort<D> {
    pub fn new(store: AsyncReplicaStore, directory: Arc<D>, authority: AuthorityResolver) -> Self {
        let members = directory.clone();
        let foreign_bases = ForeignBaseClaims::new(Arc::new(move |device: &str, group: &str| {
            members.is_authorized(device, group)
        }));
        Self {
            store,
            directory,
            authority,
            admission: None,
            possession: Arc::new(std::sync::Mutex::new(None)),
            foreign_bases: Arc::new(foreign_bases),
        }
    }

    /// Peers whose last negotiation found them on another history base.
    pub fn foreign_bases(&self) -> Arc<ForeignBaseClaims> {
        self.foreign_bases.clone()
    }

    /// The slot an owner installs a possession observer into.
    pub fn possession_slot(&self) -> Arc<std::sync::Mutex<Option<PossessionObserver>>> {
        self.possession.clone()
    }

    /// Wake `admission` whenever this port stages something.
    ///
    /// Staging is one of the transitions that can unblock a promotion, and
    /// becoming promotable is not the same as being re-evaluated: without this
    /// the staged Change would sit until something else happened to drive a
    /// drain.
    pub fn waking(mut self, admission: Arc<AdmissionCoordinator>) -> Self {
        self.admission = Some(admission);
        self
    }

    /// The device on the other end of this connection, if the coordination
    /// plane has published who that endpoint belongs to and that device is
    /// authorized for the group.
    fn entitled_device(&self, peer: PeerKey, group: &GroupId) -> Option<String> {
        let device = self.directory.device_for_endpoint(peer.as_bytes())?;
        self.directory.is_authorized(&device, group.as_str()).then_some(device)
    }
}

impl<D: PeerDirectory + 'static> ReplicaPort for SqliteReplicaPort<D> {
    async fn may_disclose(&self, peer: PeerKey, group: GroupId) -> Result<bool, PortError> {
        Ok(self.entitled_device(peer, &group).is_some())
    }

    async fn base_advertisement(
        &self,
        peer: PeerKey,
        group: GroupId,
    ) -> Result<Vec<u8>, PortError> {
        // The advertisement names this device's base and heads, which is
        // disclosure; fail closed on our own rather than trust every caller
        // to have asked first.
        if self.entitled_device(peer, &group).is_none() {
            return Err(PortError::new("peer is not entitled to this group's history base"));
        }
        let advertisement =
            self.store.base_advertisement(FolderGroupId(group.0)).await.map_err(PortError::new)?;
        Ok(advertisement.encode())
    }

    /// Judge the peer's advertisement against the one this device sent.
    ///
    /// The peer's claim decides only whether this session goes on. On a
    /// different base it is recorded as a merge that would be required and
    /// nothing else happens: no install, no switch of this device's base,
    /// no merge. See `yadorilink_replica_domain::base_negotiation` for why
    /// the claim can carry no more weight than that.
    async fn negotiate_base(
        &self,
        peer: PeerKey,
        group: GroupId,
        ours: Vec<u8>,
        theirs: Vec<u8>,
    ) -> Result<BaseVerdict, PortError> {
        let Some(device) = self.entitled_device(peer, &group) else {
            return Err(PortError::new("peer is not entitled to this group's history base"));
        };
        // Our own advertisement, exactly as sent. Failing to read it back is
        // a defect here, not something the peer did.
        let ours = BaseAdvertisement::decode(&ours).map_err(PortError::new)?;
        let folder = FolderGroupId(group.0);
        // A refusal is the latest word on this peer and names no base for
        // it, so no earlier claim of its survives one.
        let theirs = match BaseAdvertisement::decode(&theirs) {
            Ok(theirs) => theirs,
            Err(error) => {
                self.foreign_bases.forget(&folder, &device);
                return Ok(BaseVerdict::Refused(error.to_string()));
            }
        };
        Ok(match base_negotiation::negotiate(&ours, &theirs) {
            BaseNegotiation::SameBase => {
                self.foreign_bases.forget(&folder, &device);
                BaseVerdict::SameBase
            }
            BaseNegotiation::MergeRequired(foreign) => {
                tracing::debug!(
                    peer = %device,
                    group = %folder.0,
                    local = %foreign.local_epoch,
                    claimed = %foreign.claim.epoch(),
                    "peer stands on a different history base; no changes exchanged, merge required"
                );
                self.foreign_bases.record(&folder, &device, foreign);
                BaseVerdict::MergeRequired
            }
            BaseNegotiation::Refused(refusal) => {
                self.foreign_bases.forget(&folder, &device);
                BaseVerdict::Refused(refusal.to_string())
            }
        })
    }

    /// An advertisement the session could not even read ends the
    /// negotiation refused, and drops the peer's earlier claim exactly as a
    /// refused verdict does.
    async fn base_unjudgeable(
        &self,
        peer: PeerKey,
        group: GroupId,
        reason: String,
    ) -> Result<(), PortError> {
        if let Some(device) = self.entitled_device(peer, &group) {
            tracing::debug!(
                peer = %device,
                group = %group.0,
                %reason,
                "peer's base advertisement could not be judged; its earlier claim is dropped"
            );
            self.foreign_bases.forget(&FolderGroupId(group.0), &device);
        }
        Ok(())
    }

    async fn servable(&self, peer: PeerKey, group: GroupId) -> Result<Vec<ItemId>, PortError> {
        // Re-checked here as well as at the session's own gate. This function
        // is what turns entitlement into a concrete set, so it fails closed on
        // its own rather than relying on every caller to have asked first.
        if self.entitled_device(peer, &group).is_none() {
            return Ok(Vec::new());
        }

        let hashes =
            self.store.servable_hashes(FolderGroupId(group.0)).await.map_err(PortError::new)?;

        Ok(hashes.into_iter().map(|hash| ItemId::from_bytes(hash.0)).collect())
    }

    async fn load_bundles(
        &self,
        peer: PeerKey,
        group: GroupId,
        hashes: Vec<ItemId>,
    ) -> Result<Vec<OpaqueBundle>, PortError> {
        if self.entitled_device(peer, &group).is_none() {
            return Ok(Vec::new());
        }

        let folder = FolderGroupId(group.0);
        let mut found = Vec::new();
        for id in &hashes {
            let hash = ChangeHash(*id.as_bytes());
            let Some(bundle) =
                self.store.load_servable_bundle(hash).await.map_err(PortError::new)?
            else {
                // Not held, or held without evidence. Absence is not an error:
                // the peer's view of what we hold is a snapshot and may
                // already be stale.
                continue;
            };
            // A hash the peer asked for that belongs to a different group is
            // answered with nothing. The peer is entitled to this group and
            // was told about this group; what it holds elsewhere is not
            // established here.
            if bundle.change.group_id != folder {
                continue;
            }
            found.push(OpaqueBundle {
                change_hash: ItemId::from_bytes(bundle.change_hash().0),
                payload: bundle_codec::encode(&bundle).map_err(PortError::new)?,
            });
        }

        super::metrics::record_bundles_served(found.len());
        Ok(found)
    }

    async fn stage_bundles(
        &self,
        _peer: PeerKey,
        group: GroupId,
        bundles: Vec<OpaqueBundle>,
    ) -> Result<Vec<ItemId>, PortError> {
        // Whose connection carried these is not consulted. A bundle is
        // admissible on the strength of the proof it carries and nothing
        // else, so an entitled peer cannot get an unverifiable Change in and
        // an unentitled one cannot keep a verifiable Change out.
        let authority = self.authority.clone();
        let group_name = group.0.clone();

        // Decode and verify the entire delivery before any of it is staged. A
        // peer must not be able to get the front of a batch accepted by
        // corrupting the back of it.
        let mut verified = Vec::with_capacity(bundles.len());
        for bundle in &bundles {
            let decoded = bundle_codec::decode(&bundle.payload).map_err(PortError::new)?;

            let hash = verify::verify_bundle(&decoded, &group_name, &|key_id, policy_head| {
                authority(&group_name, key_id, policy_head)
            })
            .map_err(PortError::new)?;

            // The frame's own claim about which Change it carries must match
            // what the verified bytes actually hash to, or the requester's
            // "was this what I asked for?" check would be checking a label
            // rather than the content.
            if hash.0 != *bundle.change_hash.as_bytes() {
                return Err(PortError::new(
                    "bundle payload hashes to a different change than the frame claims",
                ));
            }

            verified.push(decoded);
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos() as i64)
            .unwrap_or(0);

        let verified_count = verified.len();
        let staged =
            self.store.stage_verified_batch(verified, now).await.map_err(PortError::new)?;

        if !staged.is_empty() {
            // This device now possesses something it did not before, and
            // every peer authorized for the group may still be missing it.
            //
            // Without this, propagation is one hop deep. A Change reaches the
            // device that pulled it and stops: nothing tells that device its
            // own set grew, so it never offers the Change onward, and the
            // rest of a mesh converges only where some other event happens to
            // drive it. Row14 found exactly that — six devices agreeing on
            // almost everything, with the last edits stranded one hop from
            // where they were authored.
            //
            // Latency, not correctness, like every other wake here: a lost
            // one costs the delay until the next event, because the
            // difference is recomputed from durable sets every time.
            let observer = self.possession.lock().expect("possession observer poisoned").clone();
            if let Some(observer) = observer {
                observer(&FolderGroupId(group.0.clone()));
            }

            if let Some(admission) = &self.admission {
                // Cheap and non-blocking: this marks the group stale and hands
                // the drain to the runtime. Promotion has its own
                // plan/revalidate sequence and must not run inside a delivery.
                admission.schedule(&FolderGroupId(group.0.clone()));
            }
        }

        super::metrics::record_delivery(bundles.len(), verified_count, staged.len());

        Ok(staged.into_iter().map(|hash| ItemId::from_bytes(hash.0)).collect())
    }
}

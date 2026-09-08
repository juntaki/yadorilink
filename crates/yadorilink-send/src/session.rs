//! Orchestrates Track Send's four operations (`send`, `inbox`, `receive`,
//! and serving an inbound connection) over the shared
//! `yadorilink_transport::QuicPeerEndpoint` -- the SAME device identity,
//! authorization set, and NAT-traversed socket the sync protocol uses,
//! reached only through `connect_send`/`take_inbound_send`, never through
//! any sync-protocol session or port.
//!
//! Device addressing is a caller-supplied [`DeviceDirectory`] rather than
//! anything this crate resolves itself -- see that trait's own doc comment
//! for why (this crate must not depend on `yadorilink-daemon`, which is
//! where the real netmap-derived directory lives).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use yadorilink_ipc_proto::send::{
    chunk_stream_message, send_envelope, ChunkHeader, ChunkPullRejected, ChunkPullRequest,
    ChunkStreamMessage, SendEnvelope, SendFileEntry, SendManifest, SendManifestAck,
};
use yadorilink_local_storage::{
    hash_block_bytes, reconstruct_file, BlockContentStore, FsBlockStore,
};
use yadorilink_transport::quic_peer_endpoint::QuicPeerEndpoint;
use yadorilink_transport::TransportError;

use crate::error::{Result, SendError};
use crate::manifest::{build_outbound_manifest, chunk_byte_size};
use crate::store::{OutboundStatus, SendStore};
use crate::wire::{read_message, write_message};

/// One same-account device this daemon already knows about, as resolved
/// by a caller-supplied [`DeviceDirectory`] -- the device id, its pinned
/// Ed25519 device key (for `connect_send`'s mutual-auth pin), and every
/// address this device has most recently been told to try it at.
#[derive(Debug, Clone)]
pub struct ResolvedDevice {
    pub device_id: String,
    pub signing_key: [u8; 32],
    pub candidate_addresses: Vec<SocketAddr>,
}

/// This daemon's already-known, same-account device list -- reused for
/// labeling an inbound connection's already-authenticated peer
/// (`device_id_for_key`) and for a receiver's own pull-phase dial back to a
/// sender it has already accepted an offer from (`receive_transfer`), never
/// re-derived. See the crate's own module doc comment for why this is a
/// port rather than a direct dependency on `yadorilink-daemon`.
///
/// Deliberately NOT consulted by [`SendService::offer_send`] to decide
/// whether a grant is needed for a given target: `resolve` succeeding only
/// ever means this device has ordinary netmap/sync connectivity to the
/// target, never that sending to it is authorized. See `request_grant`'s
/// own doc comment for why every offer requires a grant regardless of what
/// `resolve` says.
///
/// Cross-account send is out of scope for v1 by construction, not merely
/// unimplemented: the production implementation
/// (`yadorilink-daemon::send_transfer::DaemonDeviceDirectory`) obtains a
/// grant only through the coordination plane's `POST /send/authorization`
/// route, which resolves both the sender and receiver device id against the
/// SAME caller-account bearer token (`isDeviceOwnedByUser`, twice, against
/// one `userId`) -- so there is no `device_query` naming a device outside
/// the caller's own account this route can ever satisfy, independent of
/// whatever `resolve`'s own (separately account-scoped, and since Track S
/// F1, cross-account-inclusive) netmap state happens to say. Sending to a
/// device on a different account needs a cross-account permission model
/// that does not exist yet; this trait is deliberately left as the seam a
/// future cross-account-aware `DeviceDirectory` implementation would plug
/// into, once that model does.
///
/// Every Track Send offer -- same-account or not, netmap-visible or not --
/// is gated by exactly ONE primitive: a short-lived, sender+receiver-bound
/// Track Send rendezvous grant (`POST /send/authorization`,
/// `crates/yadorilink-daemon`'s `send_transfer` module), obtained by
/// `request_grant` and enforced on the receiving side by
/// [`SendService::handle_offer`]'s own unconditional `consume_grant` call.
/// Deliberately NOT an extension of ordinary netmap visibility -- see that
/// module's own doc comment for the full design -- and deliberately never
/// skipped merely because `resolve` also happens to know the target: an
/// ordinary netmap/sync relationship establishes connectivity and
/// addressing, never Send authorization.
///
/// The resolved device, plus the grant material [`SendService::offer_send`]
/// must present alongside the manifest offer this grant authorizes -- see
/// `send.proto`'s own `SendEnvelope.grant_id`/`grant_nonce` doc comment for
/// exactly where and how these travel on the wire.
#[derive(Debug, Clone)]
pub struct GrantedDevice {
    pub device: ResolvedDevice,
    pub grant_id: String,
    pub grant_nonce: String,
    /// Unix seconds. Used only to schedule this device's own eventual
    /// [`QuicPeerEndpoint::revoke_send_peer`] call for `device`'s key --
    /// the receiver may dial this device back during the pull phase, and
    /// that admission must not outlive the grant it came from.
    pub expires_at_unix: i64,
}

#[async_trait::async_trait]
pub trait DeviceDirectory: Send + Sync {
    /// Resolves a CLI-supplied device query -- today, an exact device id,
    /// matching the identifier every other device-scoped daemon command
    /// (`remove_device`, `revoke_device`, ...) already takes -- against
    /// this daemon's own device list. Used for a receiver's pull-phase
    /// dial-back to an already-accepted sender (`receive_transfer`) and by
    /// other daemon-side device-query callers -- deliberately NOT consulted
    /// by `offer_send` itself, which always goes through `request_grant`
    /// instead; see this trait's own doc comment.
    fn resolve(&self, device_query: &str) -> Option<ResolvedDevice>;

    /// The device id this daemon has pinned for `signing_key`, if any.
    /// Used only to LABEL an inbound offer's already-authenticated sender
    /// for display (`inbox`) -- authorization itself never depends on
    /// this succeeding, since the QUIC handshake already refused any key
    /// outside this device's authorized set before a connection could
    /// reach here at all. A production implementation extends this beyond
    /// ordinary netmap-pinned peers to ALSO recognize a key this device
    /// currently has an outstanding, not-yet-consumed Track Send grant
    /// for (see `GrantedDevice`'s own doc comment) -- `handle_offer` relies
    /// on this to name the sender it is about to ask `consume_grant` to
    /// validate.
    fn device_id_for_key(&self, signing_key: &[u8; 32]) -> Option<String>;

    /// Called by [`SendService::offer_send`] for EVERY outbound offer,
    /// unconditionally -- requests a Track Send rendezvous grant naming this
    /// exact device pair from the coordination plane, and resolves
    /// `receiver_device_query` to the actual target device as a side effect
    /// of that same request (the grant response carries the receiver's
    /// connect material). This has fully replaced what `resolve` used to be
    /// consulted for inside `offer_send`: `resolve` still exists for other
    /// callers, but no ordinary netmap relationship exempts a target from
    /// needing a grant here. `None` (the default) means this directory has
    /// no grant capability at all -- `offer_send` then fails loudly instead
    /// of falling back to sending ungranted, so every test/fake directory
    /// that models only an ordinary netmap and does not override this
    /// cannot send at all, which is deliberate.
    async fn request_grant(&self, _receiver_device_query: &str) -> Option<GrantedDevice> {
        None
    }

    /// Called by `handle_offer` for EVERY inbound offer, unconditionally --
    /// an offer whose envelope carries an empty `grant_id` is passed
    /// through to this call with empty strings rather than skipped, so an
    /// implementation MUST fail closed for that input exactly like it does
    /// for any other unknown, invalid, or already-consumed grant id (the
    /// default implementation below already does, by always returning
    /// `Err`). There is no "no grant presented" case that bypasses this
    /// call: a completed send-ALPN handshake alone never counts as
    /// authorization. Validates the grant against the coordination plane
    /// and, on success, marks it consumed there before the offer is durably
    /// recorded. `peer_key` is the QUIC-authenticated signing key of the
    /// connection that presented this grant.
    ///
    /// An implementation MUST derive the sender identity it reports to the
    /// coordination plane from `peer_key` alone -- via its own
    /// independently-obtained record of which grant belongs to which key
    /// (the same record `device_id_for_key` consults) -- and never from
    /// any claim inside the offer envelope or manifest itself. That is the
    /// entire defense against sender substitution: an attacker can
    /// present any `grant_id` it likes, but can only complete the QUIC
    /// handshake as the key it actually holds the private half of.
    ///
    /// `Err` (the default: grants unsupported) refuses the offer before it
    /// is stored -- same fail-closed shape as `resolve` returning `None`.
    async fn consume_grant(
        &self,
        _grant_id: &str,
        _grant_nonce: &str,
        _peer_key: &[u8; 32],
    ) -> std::result::Result<(), String> {
        Err("this directory does not support Track Send grants".to_string())
    }
}

/// One inbox entry -- a decoded, display-ready view over a stored
/// [`crate::store::InboundTransfer`].
#[derive(Debug, Clone)]
pub struct InboxEntry {
    pub transfer_id: String,
    pub sender_device_id: String,
    pub files: Vec<(String, u64)>,
    pub total_size: u64,
    pub offered_at_unix_nanos: i64,
    pub status: &'static str,
}

#[derive(Debug, Clone)]
pub struct SendOfferOutcome {
    pub transfer_id: String,
    pub files_offered: Vec<String>,
    pub total_size: u64,
}

#[derive(Debug, Clone)]
pub struct ReceiveOutcome {
    pub destination_dir: PathBuf,
    pub files_received: Vec<String>,
    pub bytes_received: u64,
}

/// How long a single dial attempt against one candidate address is given
/// before this device moves on to the next one -- Track Send dials a
/// device it already has (or can already reach) ordinary connectivity to,
/// not a fresh peer worth racing candidates for at length (see
/// `QuicPeerEndpoint::connect_send`'s own doc comment).
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Ceiling on how long a rejection path (`handle_offer`'s grant-check
/// failure, `reject_pull`'s every reason) waits for `send.stopped()` --
/// best-effort confirmation that a peer actually received the rejection
/// message before this device closes the connection out from under it --
/// see `handle_offer`'s own call site comment for why `stopped()` alone is
/// not otherwise bounded. Not correctness-critical: a peer that never
/// unblocks `stopped()` just makes this device wait out the timeout before
/// closing anyway, exactly as if the flush had never been attempted.
const REJECT_ACK_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// Application-level QUIC close codes for Track Send connections --
/// this protocol's own namespace, distinct from the sync protocol's
/// (`quic_peer_endpoint.rs`'s `CONNECTION_NOT_WANTED` and friends are
/// private to that module and never reused here on purpose: a peer must
/// not have to guess which protocol's close-code table an error came
/// from).
mod close_code {
    pub const DONE: u32 = 0;
    pub const REJECTED: u32 = 1;
    pub const PROTOCOL_ERROR: u32 = 2;
}

pub struct SendService {
    endpoint: Arc<QuicPeerEndpoint>,
    store: SendStore,
    block_store: FsBlockStore,
    directory: Arc<dyn DeviceDirectory>,
    default_inbox_dir: PathBuf,
    /// A deterministic mid-transfer "crash" seam for real crash-recovery
    /// tests -- see [`Self::test_abort_after_n_chunks`]. Always `None` in
    /// production: nothing outside a `test`/`test-support` build can set
    /// it.
    #[cfg(any(test, feature = "test-support"))]
    chunk_abort: std::sync::Mutex<Option<ChunkAbortHook>>,
}

#[cfg(any(test, feature = "test-support"))]
struct ChunkAbortHook {
    remaining: u32,
    notify: Arc<tokio::sync::Notify>,
    /// Never notified by anything -- once `remaining` reaches zero, the
    /// pull loop awaits this and parks there unconditionally, so the exact
    /// instant a caller's `notify.notified()` wakes up, the pulling task is
    /// GUARANTEED to already be parked with no further chunk read able to
    /// start, whatever the runtime's own scheduling latency turns out to
    /// be. This is what makes `test_abort_after_n_chunks` an exact
    /// rendezvous rather than a best-effort race against real network I/O.
    pause: Arc<tokio::sync::Notify>,
}

impl SendService {
    pub fn new(
        endpoint: Arc<QuicPeerEndpoint>,
        store_db_path: impl AsRef<Path>,
        block_store_root: impl AsRef<Path>,
        directory: Arc<dyn DeviceDirectory>,
        default_inbox_dir: impl Into<PathBuf>,
    ) -> Result<Self> {
        std::fs::create_dir_all(block_store_root.as_ref())?;
        let default_inbox_dir = default_inbox_dir.into();
        std::fs::create_dir_all(&default_inbox_dir)?;
        Ok(Self {
            endpoint,
            store: SendStore::open(store_db_path)?,
            block_store: FsBlockStore::new(block_store_root.as_ref())?,
            directory,
            default_inbox_dir,
            #[cfg(any(test, feature = "test-support"))]
            chunk_abort: std::sync::Mutex::new(None),
        })
    }

    /// Test-only: arranges for the returned [`tokio::sync::Notify`] to fire
    /// the instant this service has durably confirmed `n` chunks across a
    /// `receive_transfer` call (any file, in pull order) -- letting a real
    /// crash-recovery test abort the task actually driving `receive_transfer`
    /// at an EXACT, deterministic point (some chunks durably on disk, the
    /// rest not) instead of racing a fixed sleep against real network I/O.
    /// The task's own drop/abort is the "crash": nothing here fakes
    /// durability or skips the real write/verify path chunks before `n`
    /// already went through.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_abort_after_n_chunks(&self, n: u32) -> Arc<tokio::sync::Notify> {
        let notify = Arc::new(tokio::sync::Notify::new());
        *self.chunk_abort.lock().unwrap_or_else(|p| p.into_inner()) = Some(ChunkAbortHook {
            remaining: n,
            notify: notify.clone(),
            pause: Arc::new(tokio::sync::Notify::new()),
        });
        notify
    }

    /// Returns the pause handle to await (outside the lock -- holding a
    /// `std::sync::Mutex` guard across an `.await` is a bug even for a
    /// short one) exactly when `n` chunks have now been confirmed;
    /// otherwise `None`, meaning the caller should proceed immediately.
    #[cfg(any(test, feature = "test-support"))]
    fn note_chunk_confirmed(&self) -> Option<Arc<tokio::sync::Notify>> {
        let mut guard = self.chunk_abort.lock().unwrap_or_else(|p| p.into_inner());
        let hook = guard.as_mut()?;
        hook.remaining = hook.remaining.saturating_sub(1);
        if hook.remaining == 0 {
            hook.notify.notify_one();
            let pause = hook.pause.clone();
            // One-shot: clear the hook the instant it fires, so it can
            // never fire a second time. Without this, `remaining` stays
            // saturated at 0 (`saturating_sub`), and the very next chunk
            // this device EVER confirms -- whether later in this same
            // pull after some other caller happens to notify `pause`, or
            // in a wholly separate, LATER `receive_transfer` call (exactly
            // the crash-recovery retry `test_abort_after_n_chunks` exists
            // to let a test drive) -- would see `remaining == 0` again and
            // park forever on a `pause` nothing is ever going to notify a
            // second time. A real bug this exact shape caused: the retry
            // half of a crash-recovery test hung indefinitely on its
            // second chunk once the first `test_abort_after_n_chunks`
            // rendezvous had already fired once.
            *guard = None;
            Some(pause)
        } else {
            None
        }
    }

    #[cfg(not(any(test, feature = "test-support")))]
    fn note_chunk_confirmed(&self) -> Option<Arc<tokio::sync::Notify>> {
        None
    }

    // ---- sender side ---------------------------------------------------

    /// `yadorilink send <source_path> <target_device>`. Idempotent: a
    /// second call with the exact same (canonicalized source path, target
    /// device) re-drives the SAME transfer id and manifest -- built and
    /// durably recorded once -- rather than re-chunking the source or
    /// minting a new offer.
    pub async fn offer_send(
        &self,
        source_path: &Path,
        target_device_query: &str,
    ) -> Result<SendOfferOutcome> {
        // A Track Send grant is mandatory for EVERY offer, unconditionally
        // -- `resolve()` is deliberately never consulted here. This device
        // already having an ordinary netmap/sync relationship with the
        // target (same-account, or cross-account -- `computeNetmap` also
        // includes cross-account invite-accepted devices as netmap peers) is
        // not an exemption from needing its own short-lived grant: it would
        // let a stock client send with zero Send-specific authorization,
        // which is exactly the hole `handle_offer`'s matching unconditional
        // check on the receiving side exists to close. See `GrantedDevice`'s
        // own doc comment for the full design.
        let granted = self
            .directory
            .request_grant(target_device_query)
            .await
            .ok_or_else(|| SendError::NoKnownDeviceKey(target_device_query.to_string()))?;
        // The receiver will dial this device back to pull chunks once it
        // accepts the offer -- this device's own endpoint must be ready to
        // accept that inbound connection before the offer can even
        // complete, so this happens before the dial below, not after.
        self.endpoint.authorize_send_peer(granted.device.signing_key);
        self.endpoint
            .schedule_send_peer_revoke(granted.device.signing_key, granted.expires_at_unix);
        let target = granted.device;
        let grant_id = granted.grant_id;
        let grant_nonce = granted.grant_nonce;
        let canonical_source = std::fs::canonicalize(source_path)?;
        let canonical_source_str = canonical_source.to_string_lossy().into_owned();

        let existing = self
            .store
            .find_outbound_by_source_and_target(&canonical_source_str, &target.device_id)?;
        let outbound = match existing {
            Some(row) => row,
            None => {
                let transfer_id = uuid::Uuid::new_v4().to_string();
                let (manifest, _total_size) =
                    build_outbound_manifest(&self.block_store, &canonical_source, &transfer_id)?;
                let created_at_unix_nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as i64;
                self.store.insert_outbound_offered(
                    &transfer_id,
                    &target.device_id,
                    &target.signing_key,
                    &canonical_source_str,
                    &manifest,
                    created_at_unix_nanos,
                )?;
                self.store.get_outbound(&transfer_id)?.expect("just inserted")
            }
        };

        let connection =
            dial_send(&self.endpoint, &target.candidate_addresses, target.signing_key).await?;
        let (mut send, mut recv) =
            connection.open_bi().await.map_err(|e| TransportError::NoRoute(e.to_string()))?;
        write_message(
            &mut send,
            &SendEnvelope {
                payload: Some(send_envelope::Payload::Manifest(outbound.manifest.clone())),
                grant_id,
                grant_nonce,
            },
        )
        .await?;
        send.finish().ok();
        let ack: SendManifestAck = read_message(&mut recv).await?;
        if !ack.accepted {
            // Terminal, not left in `Offered`: `handle_pull` requires
            // `Acked` before serving any chunk, so a receiver that just
            // declined this offer must not be able to dial back and pull
            // the content anyway -- see `handle_pull`'s own status check.
            self.store.mark_outbound_rejected(&outbound.transfer_id)?;
            connection.close(close_code::DONE.into(), b"offer complete");
            return Err(SendError::OfferRejected(ack.reason));
        }
        // Durably recorded BEFORE this connection is closed, deliberately --
        // a receiver that just answered `accepted: true` is free to dial
        // this device straight back for the pull, and `handle_pull`'s
        // `OutboundStatus::Acked` check has to see this write land as early
        // as this side can possibly make it, not after whatever local work
        // `connection.close` itself does first. Closing before this write
        // used to leave a narrow window where an immediate pull could reach
        // `handle_pull` before this row actually flipped to `Acked` --
        // proven to fail closed (a spurious rejection the receiver simply
        // retries), never a security hole, but narrowing it costs nothing
        // here since neither statement depends on the other's result.
        self.store.mark_outbound_acked(&outbound.transfer_id)?;
        connection.close(close_code::DONE.into(), b"offer complete");

        Ok(SendOfferOutcome {
            transfer_id: outbound.transfer_id,
            files_offered: outbound
                .manifest
                .files
                .iter()
                .map(|f| f.relative_path.clone())
                .collect(),
            total_size: outbound.manifest.total_size,
        })
    }

    // ---- receiver side --------------------------------------------------

    pub fn list_inbox(&self) -> Result<Vec<InboxEntry>> {
        let rows = self.store.list_inbound()?;
        Ok(rows
            .into_iter()
            .map(|row| InboxEntry {
                transfer_id: row.transfer_id,
                sender_device_id: row.sender_device_id,
                files: row
                    .manifest
                    .files
                    .iter()
                    .map(|f| (f.relative_path.clone(), f.size))
                    .collect(),
                total_size: row.manifest.total_size,
                offered_at_unix_nanos: row.offered_at_unix_nanos,
                status: row.status.as_str(),
            })
            .collect())
    }

    /// `yadorilink receive <transfer_id> [--to <dir>]` -- the explicit
    /// accept step. Resumable: every file's missing chunks are recomputed
    /// from this device's own local block store on every call
    /// (`BlockContentStore::present_blocks`), so re-running this after a
    /// crash or a network interruption only re-pulls what never landed
    /// durably, never bytes already confirmed.
    pub async fn receive_transfer(
        &self,
        transfer_id: &str,
        destination_dir: Option<&Path>,
    ) -> Result<ReceiveOutcome> {
        let inbound = self
            .store
            .get_inbound(transfer_id)?
            .ok_or_else(|| SendError::UnknownTransfer(transfer_id.to_string()))?;

        let requested_dir = match destination_dir {
            Some(dir) => dir.to_string_lossy().into_owned(),
            None => self.default_inbox_dir.join(transfer_id).to_string_lossy().into_owned(),
        };
        let destination_dir = self.store.claim_inbound_destination(transfer_id, &requested_dir)?;
        let destination_dir = PathBuf::from(destination_dir);
        std::fs::create_dir_all(&destination_dir)?;

        let sender = self
            .directory
            .resolve(&inbound.sender_device_id)
            .ok_or_else(|| SendError::NoKnownAddress(inbound.sender_device_id.clone()))?;

        let mut files_received = Vec::new();
        let mut bytes_received: u64 = 0;
        for (file_index, entry) in inbound.manifest.files.iter().enumerate() {
            let first_missing = first_missing_chunk(&self.block_store, &entry.chunk_hashes)?;
            if let Some(start_chunk_index) = first_missing {
                self.pull_file(&sender, transfer_id, file_index as u32, entry, start_chunk_index)
                    .await?;
            }
            let out_path = safe_join(&destination_dir, &entry.relative_path)?;
            let blocks = entry
                .chunk_hashes
                .iter()
                .enumerate()
                .map(|(idx, hash)| {
                    Ok(yadorilink_replica_domain::file::BlockInfo {
                        hash: hash.clone(),
                        offset: idx as u64 * entry.chunk_size as u64,
                        size: chunk_byte_size(entry, idx)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let mtime_unix_nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as i64;
            reconstruct_file(&self.block_store, &out_path, &blocks, mtime_unix_nanos)?;
            files_received.push(entry.relative_path.clone());
            bytes_received += entry.size;
        }

        self.store.mark_inbound_completed(transfer_id)?;
        Ok(ReceiveOutcome { destination_dir, files_received, bytes_received })
    }

    async fn pull_file(
        &self,
        sender: &ResolvedDevice,
        transfer_id: &str,
        file_index: u32,
        entry: &SendFileEntry,
        start_chunk_index: u32,
    ) -> Result<()> {
        let connection =
            dial_send(&self.endpoint, &sender.candidate_addresses, sender.signing_key).await?;
        let (mut send, mut recv) =
            connection.open_bi().await.map_err(|e| TransportError::NoRoute(e.to_string()))?;
        write_message(
            &mut send,
            &SendEnvelope {
                payload: Some(send_envelope::Payload::Pull(ChunkPullRequest {
                    transfer_id: transfer_id.to_string(),
                    file_index,
                    start_chunk_index,
                })),
                // Never a grant on a pull -- see send.proto's own
                // `SendEnvelope.grant_id` doc comment for why: this
                // device's authorization to be dialed back was already
                // established when it presented (and this daemon
                // consumed) a grant for the ORIGINAL offer, if one was
                // needed at all.
                grant_id: String::new(),
                grant_nonce: String::new(),
            },
        )
        .await?;
        send.finish().ok();

        // An accepted sender is trusted for CONTENT (it already passed the
        // grant/ack gate this connection was authorized through), never for
        // how much it sends, in what order, or how large it claims each
        // chunk is -- this device's own copy of the manifest, already on
        // disk before this dial, is the only thing every chunk is checked
        // against below.
        //
        // `next_chunk_index` is both the resume cursor and the loop's own
        // hard upper bound: the `while` condition stops issuing reads the
        // instant `entry.chunk_hashes.len()` chunks have been received, no
        // matter what the peer's own `last_chunk` flag claims (or never
        // claims) after that -- otherwise an already-accepted sender could
        // keep this loop running indefinitely, streaming unbounded chunks
        // into this device's block store.
        let total_chunks = entry.chunk_hashes.len() as u32;
        let mut next_chunk_index = start_chunk_index;
        while next_chunk_index < total_chunks {
            let message: ChunkStreamMessage = read_message(&mut recv).await?;
            match message.payload {
                Some(chunk_stream_message::Payload::Rejected(ChunkPullRejected { reason })) => {
                    connection.close(close_code::REJECTED.into(), b"pull rejected");
                    return Err(SendError::PullRejected(reason));
                }
                Some(chunk_stream_message::Payload::Header(ChunkHeader {
                    chunk_index,
                    size,
                    last_chunk,
                })) => {
                    if chunk_index != next_chunk_index {
                        connection
                            .close(close_code::PROTOCOL_ERROR.into(), b"unexpected chunk index");
                        return Err(SendError::Protocol(format!(
                            "file {file_index}: expected chunk index {next_chunk_index}, peer sent {chunk_index}"
                        )));
                    }
                    // Checked, and the pull aborted, BEFORE `read_body`
                    // allocates anything: the header's `size` is a
                    // peer-controlled `u32` (up to 4 GiB), so this
                    // comparison against this device's own manifest is what
                    // actually bounds the allocation below, not whatever
                    // the peer claims.
                    let expected_size = chunk_byte_size(entry, chunk_index as usize)?;
                    if size != expected_size {
                        connection
                            .close(close_code::PROTOCOL_ERROR.into(), b"unexpected chunk size");
                        return Err(SendError::Protocol(format!(
                            "file {file_index} chunk {chunk_index}: expected {expected_size} bytes, peer declared {size}"
                        )));
                    }
                    let body = read_body(&mut recv, size as usize).await?;
                    // Verified against this device's own manifest hash
                    // BEFORE ever reaching the block store. Content-
                    // addressing alone would keep a mismatched chunk from
                    // corrupting the reconstructed file (it just would not
                    // be the block `reconstruct_file` looks up), but
                    // rejecting it here catches a bad or truncated chunk
                    // immediately and aborts the transfer with a clear
                    // error, instead of silently writing garbage the rest
                    // of this transfer will never reference.
                    let actual_hash = hash_block_bytes(&body);
                    let expected_hash = hex::encode(&entry.chunk_hashes[chunk_index as usize]);
                    if actual_hash != expected_hash {
                        connection.close(
                            close_code::PROTOCOL_ERROR.into(),
                            b"chunk failed integrity verification",
                        );
                        return Err(SendError::ChunkHashMismatch { file_index, chunk_index });
                    }
                    // Content-addressed: this write itself IS the durable
                    // resume checkpoint (see `store.rs`'s own module doc
                    // comment) -- `FsBlockStore::put`'s single-item commit
                    // path fsyncs before returning, every time.
                    self.block_store.put(&body)?;
                    if let Some(pause) = self.note_chunk_confirmed() {
                        // Parks here forever (see `ChunkAbortHook::pause`'s
                        // own doc comment) -- a real crash-recovery test
                        // aborts the task while it is parked, guaranteeing
                        // no further chunk is ever read past this point.
                        pause.notified().await;
                    }
                    next_chunk_index += 1;
                    if last_chunk {
                        break;
                    }
                }
                None => return Err(SendError::Protocol("empty chunk stream message".to_string())),
            }
        }
        connection.close(close_code::DONE.into(), b"pull complete");
        Ok(())
    }

    // ---- inbound connection handling ------------------------------------

    /// Drains every inbound Track Send connection for the life of this
    /// service -- `endpoint.take_inbound_send()` hands out its receiver
    /// exactly once, so this must be the ONLY caller. Each connection is
    /// handled on its own spawned task so one slow or stalled peer cannot
    /// hold up another's offer or pull.
    pub async fn run_inbound_dispatcher(self: Arc<Self>) {
        let Some(mut inbound) = self.endpoint.take_inbound_send() else {
            tracing::error!(
                "Track Send inbound dispatcher: take_inbound_send() already taken by another \
                 caller -- this must be the only one"
            );
            return;
        };
        while let Some((connection, peer_key)) = inbound.recv().await {
            let service = self.clone();
            tokio::spawn(async move {
                service.serve_connection(connection, peer_key).await;
            });
        }
    }

    async fn serve_connection(&self, connection: quinn::Connection, peer_key: [u8; 32]) {
        loop {
            let (send, recv) = match connection.accept_bi().await {
                Ok(pair) => pair,
                Err(_) => return, // connection closed by the peer -- normal end of session.
            };
            if let Err(error) = self.serve_stream(&connection, send, recv, peer_key).await {
                tracing::warn!(%error, "Track Send: inbound stream ended in error");
                return;
            }
        }
    }

    async fn serve_stream(
        &self,
        connection: &quinn::Connection,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        peer_key: [u8; 32],
    ) -> Result<()> {
        let envelope: SendEnvelope = read_message(&mut recv).await?;
        let grant =
            (!envelope.grant_id.is_empty()).then_some((envelope.grant_id, envelope.grant_nonce));
        match envelope.payload {
            Some(send_envelope::Payload::Manifest(manifest)) => {
                self.handle_offer(&mut send, peer_key, manifest, grant).await
            }
            Some(send_envelope::Payload::Pull(pull)) => {
                self.handle_pull(connection, &mut send, peer_key, pull).await
            }
            None => {
                connection.close(close_code::PROTOCOL_ERROR.into(), b"empty envelope");
                Err(SendError::Protocol("empty envelope".to_string()))
            }
        }
    }

    async fn handle_offer(
        &self,
        send: &mut quinn::SendStream,
        peer_key: [u8; 32],
        manifest: SendManifest,
        grant: Option<(String, String)>,
    ) -> Result<()> {
        // A grant must validate and be atomically consumed BEFORE anything
        // about this offer is durably recorded -- an offer this device
        // never actually earned authorization for must leave no trace, not
        // even a rejected-but-stored inbox entry.
        //
        // This check is UNCONDITIONAL: a completed send-ALPN handshake only
        // proves the peer's key is in `authorized` UNION `send_authorized`
        // (see `quic_peer_endpoint::accept_loop`'s own doc comment) -- it
        // says nothing about whether THIS offer was ever actually granted.
        // An envelope with an empty `grant_id` is passed straight into
        // `consume_grant` as an empty string rather than skipped, so it is
        // rejected exactly the same way an unknown/invalid/already-consumed
        // grant id is -- there is no separate "trust it because this peer
        // also happens to be an ordinary netmap peer" path, same-account or
        // cross-account (`computeNetmap` includes cross-account
        // invite-accepted devices as netmap peers too). Ordinary
        // netmap/sync authorization must never be sufficient on its own to
        // receive a Send.
        let (grant_id, grant_nonce) = grant.unwrap_or_default();
        if let Err(reason) = self.directory.consume_grant(&grant_id, &grant_nonce, &peer_key).await
        {
            write_message(send, &SendManifestAck { accepted: false, reason: reason.clone() })
                .await?;
            send.finish().ok();
            // Wait for the peer to have actually received this rejection
            // before returning `Err` -- the caller (`serve_connection`)
            // drops its own `quinn::Connection` handle as soon as this call
            // returns an error, and quinn's `Connection` implicitly closes
            // with code 0 on drop if not already closed. `finish()` only
            // QUEUES the ack for the connection's background driver task;
            // without this wait, that implicit close can race ahead of the
            // driver ever actually transmitting the ack, so the peer sees a
            // bare connection loss instead of the rejection reason it was
            // just sent. `stopped()` resolves once the peer has acknowledged
            // every byte of this finished stream (or the connection is
            // already gone, in which case there is nothing left to wait
            // for) -- but it resolves ONLY on STOP_SENDING, a full
            // transport ACK, or a connection error, and none of those is
            // guaranteed merely by this connection's idle-timeout clock: a
            // peer that keeps sending keep-alive PINGs while never reading
            // (and never sending STOP_SENDING) resets that clock forever
            // without ever unblocking `stopped()`. Explicitly timed out
            // instead -- this is best-effort ack-flushing before closing,
            // not correctness-critical, so a timeout is treated exactly
            // like any other `stopped()` outcome: ignored, and the
            // rejection error below is returned either way.
            let _ = tokio::time::timeout(REJECT_ACK_FLUSH_TIMEOUT, send.stopped()).await;
            return Err(SendError::OfferRejected(reason));
        }
        let sender_device_id =
            self.directory.device_id_for_key(&peer_key).unwrap_or_else(|| hex::encode(peer_key));
        let offered_at_unix_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64;
        // Durably recorded BEFORE the ack -- see `SendStore::
        // insert_inbound_if_new`'s own doc comment.
        self.store.insert_inbound_if_new(
            &manifest.transfer_id,
            &sender_device_id,
            &manifest,
            offered_at_unix_nanos,
        )?;
        write_message(send, &SendManifestAck { accepted: true, reason: String::new() }).await?;
        send.finish().ok();
        Ok(())
    }

    async fn handle_pull(
        &self,
        connection: &quinn::Connection,
        send: &mut quinn::SendStream,
        peer_key: [u8; 32],
        pull: ChunkPullRequest,
    ) -> Result<()> {
        // Serving a chunk pull requires BOTH that this is the exact device
        // the offer named AND that this device's own record shows that
        // device actually accepted it (`OutboundStatus::Acked`) -- the peer
        // key check alone is not enough: a receiver that dialed back,
        // received the manifest, and then answered
        // `SendManifestAck{accepted:false}` is still the device the offer
        // was addressed to, but must not be able to pull the content it
        // just declined. `offer_send` moves a declined offer to
        // `OutboundStatus::Rejected` (never leaves it in `Offered`) for
        // exactly this check; an offer still in `Offered` -- the ack has
        // not landed yet, or never will -- is refused the same way, since
        // this device has no record it was ever accepted.
        let outbound = self.store.get_outbound(&pull.transfer_id)?;
        let outbound = match outbound {
            Some(outbound) if outbound.target_signing_key != peer_key => {
                return self
                    .reject_pull(connection, send, "not the device this was offered to")
                    .await;
            }
            Some(outbound) if outbound.status != OutboundStatus::Acked => {
                return self
                    .reject_pull(connection, send, "offer was not accepted; nothing to pull")
                    .await;
            }
            Some(outbound) => outbound,
            None => return self.reject_pull(connection, send, "unknown transfer id").await,
        };
        let Some(entry) = outbound.manifest.files.get(pull.file_index as usize) else {
            return self.reject_pull(connection, send, "file index out of range").await;
        };
        let num_chunks = entry.chunk_hashes.len() as u32;
        if pull.start_chunk_index >= num_chunks {
            return self.reject_pull(connection, send, "start chunk index out of range").await;
        }
        for chunk_index in pull.start_chunk_index..num_chunks {
            let hash = &entry.chunk_hashes[chunk_index as usize];
            let hash_hex = hex::encode(hash);
            let body = self.block_store.get(&hash_hex)?;
            let last_chunk = chunk_index + 1 == num_chunks;
            write_message(
                send,
                &ChunkStreamMessage {
                    payload: Some(chunk_stream_message::Payload::Header(ChunkHeader {
                        chunk_index,
                        size: body.len() as u32,
                        last_chunk,
                    })),
                },
            )
            .await?;
            send.write_all(&body)
                .await
                .map_err(|e| TransportError::Io(std::io::Error::other(e)))?;
        }
        send.finish().ok();
        Ok(())
    }

    async fn reject_pull(
        &self,
        connection: &quinn::Connection,
        send: &mut quinn::SendStream,
        reason: &str,
    ) -> Result<()> {
        write_message(
            send,
            &ChunkStreamMessage {
                payload: Some(chunk_stream_message::Payload::Rejected(ChunkPullRejected {
                    reason: reason.to_string(),
                })),
            },
        )
        .await?;
        send.finish().ok();
        // Same hazard `handle_offer`'s rejection path guards against (see
        // that call site's own comment): `finish()` only QUEUES this
        // message for the connection's background driver, so closing the
        // connection immediately below can race ahead of the driver ever
        // actually transmitting it -- the peer would see a bare connection
        // loss instead of the rejection reason it was just sent. Wait
        // (bounded; best-effort, not correctness-critical) for the peer to
        // have received it first.
        let _ = tokio::time::timeout(REJECT_ACK_FLUSH_TIMEOUT, send.stopped()).await;
        connection.close(close_code::REJECTED.into(), reason.as_bytes());
        Ok(())
    }
}

/// The first chunk index in `chunk_hashes` not yet durably present in
/// `store`, or `None` if every chunk is already there (nothing to pull --
/// including the zero-chunk case, an empty file).
fn first_missing_chunk(store: &FsBlockStore, chunk_hashes: &[Vec<u8>]) -> Result<Option<u32>> {
    if chunk_hashes.is_empty() {
        return Ok(None);
    }
    let hex_hashes: Vec<String> = chunk_hashes.iter().map(hex::encode).collect();
    let present = store.present_blocks(&hex_hashes)?;
    Ok(present.iter().position(|&p| !p).map(|idx| idx as u32))
}

/// Joins `relative` onto `root`, refusing anything that would land outside
/// `root` -- a defense-in-depth check against a manifest carrying a
/// path-traversal `relative_path` (`../../etc/passwd`), independent of and
/// in addition to the sender being an authenticated, authorized device.
fn safe_join(root: &Path, relative: &str) -> Result<PathBuf> {
    let mut out = root.to_path_buf();
    for component in Path::new(relative).components() {
        match component {
            std::path::Component::Normal(part) => out.push(part),
            std::path::Component::CurDir => {}
            _ => {
                return Err(SendError::Protocol(format!(
                    "manifest path escapes the destination directory: {relative}"
                )))
            }
        }
    }
    Ok(out)
}

async fn read_body(recv: &mut quinn::RecvStream, len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.map_err(|e| TransportError::Io(std::io::Error::other(e)))?;
    Ok(buf)
}

/// Dials `candidates` in order, returning the first that connects within
/// [`DIAL_TIMEOUT`] -- no candidate racing (see `QuicPeerEndpoint::
/// connect_send`'s own doc comment for why Track Send deliberately has
/// none): a one-shot transfer to a device this daemon already has
/// ordinary connectivity to does not need it.
async fn dial_send(
    endpoint: &QuicPeerEndpoint,
    candidates: &[SocketAddr],
    peer_key: [u8; 32],
) -> Result<quinn::Connection> {
    if candidates.is_empty() {
        return Err(SendError::Transport(TransportError::NoRoute(
            "no candidate address on record for this device".to_string(),
        )));
    }
    let mut last_error = None;
    for addr in candidates {
        match tokio::time::timeout(DIAL_TIMEOUT, endpoint.connect_send(*addr, peer_key)).await {
            Ok(Ok(connection)) => return Ok(connection),
            Ok(Err(error)) => last_error = Some(error),
            Err(_) => last_error = Some(TransportError::NoRoute(format!("{addr}: dial timed out"))),
        }
    }
    Err(SendError::Transport(
        last_error.unwrap_or(TransportError::NoRoute("no candidates".to_string())),
    ))
}

/// Regression tests proving that a Send offer requires a validated,
/// single-use grant on BOTH sides, regardless of what ordinary netmap/sync
/// state also happens to be true. `handle_offer`'s unconditional
/// `consume_grant` call is exercised directly, over a real QUIC send-ALPN
/// connection, bypassing `offer_send` entirely so each test controls
/// precisely what an adversarial or merely non-compliant sender presents
/// (including presenting nothing at all). `offer_send`'s own unconditional
/// `request_grant` call has two separate tests, deliberately not just one:
/// the positive control at the bottom of this module proves a compliant
/// sender still succeeds when a real grant is obtainable with NO ordinary
/// netmap relationship at all, and
/// `offer_send_refuses_a_netmap_resolvable_target_when_no_grant_can_be_obtained`
/// proves the actual guard this crate depends on -- a target `resolve` can
/// reach through ordinary netmap connectivity, but for which no grant is
/// obtainable, must be refused before ever dialing, not sent to ungranted.
/// The positive-control test alone cannot exercise that guard, because its
/// own `resolve` always returns `None`; both tests are needed together.
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use yadorilink_transport::{DeviceSigningKeyPair, QuicPeerEndpoint, TransportHub};

    /// One fresh device endpoint bound to loopback -- the same helper shape
    /// `yadorilink_transport::quic_peer_endpoint`'s own test module uses.
    /// Track Send's grant gate is enforced entirely at this crate's
    /// application layer (`handle_offer`), never at the transport layer, so
    /// proving it needs the SAME real QUIC handshake/ALPN machinery that
    /// layer already exercises, not a mock.
    async fn raw_endpoint() -> (Arc<QuicPeerEndpoint>, SocketAddr, [u8; 32]) {
        let hub =
            TransportHub::bind((std::net::Ipv4Addr::LOCALHOST, 0).into()).await.expect("bind hub");
        let addr = hub.local_addr();
        let device = DeviceSigningKeyPair::generate();
        let public = device.public_bytes();
        (QuicPeerEndpoint::new(hub, device).expect("device endpoint"), addr, public)
    }

    /// A fresh `SendService` over `endpoint`, backed by its own isolated
    /// temp directory (kept alive by the returned guard). Never calls
    /// `run_inbound_dispatcher` itself -- a caller that needs this service
    /// to actually receive connections spawns that separately, exactly like
    /// production (`send_transfer::run`) and the real two-device daemon
    /// test do.
    fn make_service(
        endpoint: Arc<QuicPeerEndpoint>,
        directory: Arc<dyn DeviceDirectory>,
    ) -> (Arc<SendService>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store_db_path = dir.path().join("store.sqlite3");
        let block_store_root = dir.path().join("blocks");
        let inbox_dir = dir.path().join("inbox");
        let service =
            SendService::new(endpoint, store_db_path, block_store_root, directory, inbox_dir)
                .expect("SendService::new should succeed against a fresh temp directory");
        (Arc::new(service), dir)
    }

    /// A single-use, in-memory stand-in for the coordination plane's
    /// `send_authorizations` table -- atomic issue/consume, bound to the
    /// presenting connection's authenticated key, matching
    /// `DaemonDeviceDirectory::consume_grant`'s own doc comment for the
    /// real primitive, without needing a real D1/coordination worker for
    /// these tests.
    #[derive(Default)]
    struct FakeGrantStore {
        inner: std::sync::Mutex<FakeGrantStoreInner>,
    }

    #[derive(Default)]
    struct FakeGrantStoreInner {
        grants: HashMap<String, FakeGrantRecord>,
        last_issued: Option<(String, String)>,
    }

    struct FakeGrantRecord {
        nonce: String,
        sender_key: [u8; 32],
        consumed: bool,
    }

    impl FakeGrantStore {
        fn issue(&self, grant_id: &str, nonce: &str, sender_key: [u8; 32]) {
            let mut inner = self.inner.lock().unwrap();
            inner.grants.insert(
                grant_id.to_string(),
                FakeGrantRecord { nonce: nonce.to_string(), sender_key, consumed: false },
            );
            inner.last_issued = Some((grant_id.to_string(), nonce.to_string()));
        }

        fn last_issued(&self) -> (String, String) {
            self.inner.lock().unwrap().last_issued.clone().expect("a grant must have been issued")
        }

        /// One lock guards the whole check-then-mark sequence, so two
        /// presentations of the same grant can never both observe it as
        /// unconsumed -- the same atomicity
        /// `DaemonDeviceDirectory::consume_grant`'s own doc comment
        /// describes for the real coordination-plane primitive.
        fn consume(
            &self,
            grant_id: &str,
            nonce: &str,
            peer_key: &[u8; 32],
        ) -> std::result::Result<(), String> {
            let mut inner = self.inner.lock().unwrap();
            let Some(record) = inner.grants.get_mut(grant_id) else {
                return Err("send authorization is invalid, expired, or already used".to_string());
            };
            if record.consumed || record.nonce != nonce || &record.sender_key != peer_key {
                return Err("send authorization is invalid, expired, or already used".to_string());
            }
            record.consumed = true;
            Ok(())
        }
    }

    /// A `DeviceDirectory` for the RECEIVING side of these tests.
    /// `consume_grant` either delegates to a real (fake) grant store, or --
    /// when `grants` is `None` -- fails closed exactly like the trait's own
    /// default, modeling a directory with ZERO grant capability at all (the
    /// cross-account-shaped case: nothing this directory could ever have
    /// granted). `resolve` always returns `None`: `handle_offer` never
    /// calls it (only `offer_send` used to, before this fix), so these
    /// tests keep it inert on purpose rather than implying it takes part in
    /// the check being tested. `request_grant` is never overridden: none of
    /// these tests drive `offer_send` from the receiving side.
    struct TestDirectory {
        grants: Option<Arc<FakeGrantStore>>,
        device_labels: HashMap<[u8; 32], String>,
    }

    #[async_trait::async_trait]
    impl DeviceDirectory for TestDirectory {
        fn resolve(&self, _device_query: &str) -> Option<ResolvedDevice> {
            None
        }

        fn device_id_for_key(&self, signing_key: &[u8; 32]) -> Option<String> {
            self.device_labels.get(signing_key).cloned()
        }

        async fn consume_grant(
            &self,
            grant_id: &str,
            grant_nonce: &str,
            peer_key: &[u8; 32],
        ) -> std::result::Result<(), String> {
            match &self.grants {
                Some(store) => store.consume(grant_id, grant_nonce, peer_key),
                None => Err("this directory does not support Track Send grants".to_string()),
            }
        }
    }

    /// A `DeviceDirectory` for the SENDING side of the positive-control
    /// test at the bottom of this module: `request_grant` mints a real,
    /// single-use grant against a shared `FakeGrantStore`, bound to
    /// `sender_key` -- the same shape `DaemonDeviceDirectory::request_grant`
    /// produces against the real coordination plane. `resolve` is always
    /// `None`: the point of that test is that `offer_send` completes with
    /// NO ordinary netmap relationship at all.
    struct GrantingDirectory {
        sender_key: [u8; 32],
        grants: Arc<FakeGrantStore>,
        target: ResolvedDevice,
    }

    #[async_trait::async_trait]
    impl DeviceDirectory for GrantingDirectory {
        fn resolve(&self, _device_query: &str) -> Option<ResolvedDevice> {
            None
        }

        fn device_id_for_key(&self, _signing_key: &[u8; 32]) -> Option<String> {
            None
        }

        async fn request_grant(&self, receiver_device_query: &str) -> Option<GrantedDevice> {
            if receiver_device_query != self.target.device_id {
                return None;
            }
            let grant_id = format!("grant-{}", uuid::Uuid::new_v4());
            let grant_nonce = format!("nonce-{}", uuid::Uuid::new_v4());
            self.grants.issue(&grant_id, &grant_nonce, self.sender_key);
            Some(GrantedDevice {
                device: self.target.clone(),
                grant_id,
                grant_nonce,
                // Effectively never expires within a test's lifetime.
                expires_at_unix: i64::MAX,
            })
        }
    }

    /// Dials `addr` over send-ALPN and presents a bare-bones manifest offer
    /// carrying exactly the `grant_id`/`grant_nonce` given -- the raw
    /// wire-level primitive every test below drives directly, bypassing
    /// `offer_send` entirely, so each test controls precisely what an
    /// adversarial or merely non-compliant sender presents (including
    /// presenting nothing at all).
    async fn raw_offer(
        dialer: &QuicPeerEndpoint,
        addr: SocketAddr,
        peer_key: [u8; 32],
        transfer_id: &str,
        grant_id: &str,
        grant_nonce: &str,
    ) -> SendManifestAck {
        let connection = dialer.connect_send(addr, peer_key).await.expect(
            "a send-ALPN dial completes -- transport-layer admission is not this test's \
             concern, only the application-layer grant check is",
        );
        let (mut send, mut recv) = connection.open_bi().await.expect("open a stream");
        write_message(
            &mut send,
            &SendEnvelope {
                payload: Some(send_envelope::Payload::Manifest(SendManifest {
                    transfer_id: transfer_id.to_string(),
                    files: vec![],
                    total_size: 0,
                    offered_at_unix_nanos: 0,
                })),
                grant_id: grant_id.to_string(),
                grant_nonce: grant_nonce.to_string(),
            },
        )
        .await
        .unwrap();
        send.finish().ok();
        let ack: SendManifestAck = read_message(&mut recv).await.unwrap();
        connection.close(close_code::DONE.into(), b"test offer");
        ack
    }

    /// Same-account variant: two devices with ONLY a normal mutual
    /// `authorize()` call -- exactly what an ordinary netmap push does --
    /// and a receiving directory that DOES have real grant capability, so a
    /// compliant sender genuinely could have obtained and presented one. An
    /// offer that presents no grant at all must still be rejected: an
    /// ordinary netmap/sync relationship is never, by itself, sufficient to
    /// receive a Send.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ungranted_offer_from_an_ordinary_same_account_netmap_peer_is_rejected() {
        let (dialer, _dialer_addr, dialer_key) = raw_endpoint().await;
        let (acceptor, acceptor_addr, acceptor_key) = raw_endpoint().await;
        dialer.authorize(acceptor_key);
        acceptor.authorize(dialer_key);

        let grants = Arc::new(FakeGrantStore::default());
        let directory: Arc<dyn DeviceDirectory> = Arc::new(TestDirectory {
            grants: Some(grants),
            device_labels: HashMap::from([(dialer_key, "dialer-device".to_string())]),
        });
        let (service, _dir_guard) = make_service(acceptor.clone(), directory);
        tokio::spawn(service.clone().run_inbound_dispatcher());

        let ack =
            raw_offer(&dialer, acceptor_addr, acceptor_key, "ungranted-same-account", "", "").await;

        assert!(
            !ack.accepted,
            "an ordinary netmap-authorized peer must not be able to complete a Send offer \
             without presenting a grant"
        );
        assert!(!ack.reason.is_empty(), "a rejection must carry a reason");
        assert!(
            service.list_inbox().unwrap().is_empty(),
            "a rejected offer must leave no trace, not even a rejected-but-stored inbox entry"
        );
    }

    /// The cross-account-shaped variant: a peer present in `authorized`
    /// (`computeNetmap` includes cross-account invite-accepted devices as
    /// netmap peers too) whose receiving directory has ZERO
    /// grant capability whatsoever -- not merely "this sender didn't
    /// present one", but "nothing here could ever have granted it" (the
    /// trait's own default `consume_grant`). Must still be rejected
    /// outright.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ungranted_offer_from_a_netmap_authorized_peer_with_zero_grant_capability_is_rejected(
    ) {
        let (dialer, _dialer_addr, dialer_key) = raw_endpoint().await;
        let (acceptor, acceptor_addr, acceptor_key) = raw_endpoint().await;
        dialer.authorize(acceptor_key);
        acceptor.authorize(dialer_key);

        let directory: Arc<dyn DeviceDirectory> =
            Arc::new(TestDirectory { grants: None, device_labels: HashMap::new() });
        let (service, _dir_guard) = make_service(acceptor.clone(), directory);
        tokio::spawn(service.clone().run_inbound_dispatcher());

        let ack = raw_offer(
            &dialer,
            acceptor_addr,
            acceptor_key,
            "ungranted-cross-account-shaped",
            "",
            "",
        )
        .await;

        assert!(!ack.accepted, "a directory with zero grant capability must still reject cleanly");
        assert!(service.list_inbox().unwrap().is_empty());
    }

    /// A genuinely valid grant authorizes exactly ONE offer, not unlimited
    /// offers from an already-transport-admitted sender -- a second
    /// presentation of the SAME grant, and a third offer that omits
    /// `grant_id` entirely while still transport-authorized from the first
    /// admission, must both be rejected. Otherwise a sender could omit
    /// `grant_id` on every offer after its first and ride that one grant
    /// admission indefinitely.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_consumed_grant_cannot_authorize_a_second_or_third_offer() {
        let (dialer, _dialer_addr, dialer_key) = raw_endpoint().await;
        let (acceptor, acceptor_addr, acceptor_key) = raw_endpoint().await;
        // Admitted ONLY through a Track Send grant -- never ordinary
        // netmap authorization -- exactly the groupless-sender shape
        // `authorize_send_peer` exists for.
        acceptor.authorize_send_peer(dialer_key);

        let grants = Arc::new(FakeGrantStore::default());
        grants.issue("grant-1", "nonce-1", dialer_key);
        let directory: Arc<dyn DeviceDirectory> = Arc::new(TestDirectory {
            grants: Some(grants),
            device_labels: HashMap::from([(dialer_key, "sender-device".to_string())]),
        });
        let (service, _dir_guard) = make_service(acceptor.clone(), directory);
        tokio::spawn(service.clone().run_inbound_dispatcher());

        let first =
            raw_offer(&dialer, acceptor_addr, acceptor_key, "transfer-3a", "grant-1", "nonce-1")
                .await;
        assert!(
            first.accepted,
            "a genuinely valid, unconsumed grant must authorize its offer: {}",
            first.reason
        );

        let second =
            raw_offer(&dialer, acceptor_addr, acceptor_key, "transfer-3b", "grant-1", "nonce-1")
                .await;
        assert!(
            !second.accepted,
            "a second presentation of an already-consumed grant must be rejected"
        );

        let third = raw_offer(&dialer, acceptor_addr, acceptor_key, "transfer-3c", "", "").await;
        assert!(
            !third.accepted,
            "omitting grant_id must not let an already-transport-authorized sender make \
             unlimited offers off one grant admission"
        );

        let inbox = service.list_inbox().unwrap();
        assert_eq!(inbox.len(), 1, "only the single genuinely-granted offer should be recorded");
        assert_eq!(inbox[0].transfer_id, "transfer-3a");
    }

    /// The positive control: `offer_send` itself, driven end to end with NO
    /// ordinary netmap relationship on either side at all, still completes
    /// -- because it now always obtains a real grant via `request_grant`
    /// rather than needing `resolve` to succeed first. Proves the fix does
    /// not merely reject everything: a compliant sender presenting a real,
    /// freshly-obtained grant is still accepted, and that same grant cannot
    /// then be replayed over the raw wire path either.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offer_send_obtains_and_attaches_a_real_grant_with_no_netmap_relationship_at_all() {
        let (sender_endpoint, _sender_addr, sender_key) = raw_endpoint().await;
        let (receiver_endpoint, receiver_addr, receiver_key) = raw_endpoint().await;

        let grants = Arc::new(FakeGrantStore::default());
        let receiver_directory: Arc<dyn DeviceDirectory> = Arc::new(TestDirectory {
            grants: Some(grants.clone()),
            device_labels: HashMap::from([(sender_key, "sender-device".to_string())]),
        });
        let (receiver_service, _receiver_dir_guard) =
            make_service(receiver_endpoint.clone(), receiver_directory);
        tokio::spawn(receiver_service.clone().run_inbound_dispatcher());
        // Outside this crate's own scope in production: the coordination
        // plane pushes the grant to the RECEIVER over its netmap
        // subscription, and `peer_orchestrator::handle_incoming_send_
        // authorization` is what calls `authorize_send_peer` for the
        // sender's key there (see that function's own doc comment). This
        // crate has no idea a coordination plane exists, so this test
        // stands in for that push having already landed before the
        // sender's offer connection arrives.
        receiver_endpoint.authorize_send_peer(sender_key);

        let sender_directory: Arc<dyn DeviceDirectory> = Arc::new(GrantingDirectory {
            sender_key,
            grants: grants.clone(),
            target: ResolvedDevice {
                device_id: "receiver-device".to_string(),
                signing_key: receiver_key,
                candidate_addresses: vec![receiver_addr],
            },
        });
        let (sender_service, _sender_dir_guard) =
            make_service(sender_endpoint.clone(), sender_directory);

        let source_dir = tempfile::tempdir().unwrap();
        let source_path = source_dir.path().join("hello.txt");
        std::fs::write(&source_path, b"hello via a fresh grant, no netmap relationship at all")
            .unwrap();

        let outcome = sender_service
            .offer_send(&source_path, "receiver-device")
            .await
            .expect("offer_send should succeed once a real grant is obtained");
        assert_eq!(outcome.files_offered, vec!["hello.txt".to_string()]);

        let inbox = receiver_service.list_inbox().unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].transfer_id, outcome.transfer_id);

        // The exact grant `offer_send` minted and consumed above must not
        // be replayable over the raw wire path either.
        let (used_grant_id, used_grant_nonce) = grants.last_issued();
        let replay = raw_offer(
            &sender_endpoint,
            receiver_addr,
            receiver_key,
            "replay-attempt",
            &used_grant_id,
            &used_grant_nonce,
        )
        .await;
        assert!(!replay.accepted, "the grant offer_send already consumed must not be replayable");
    }

    /// A receiver that answers `SendManifestAck{accepted:false}` must not
    /// be able to dial the sender back afterward and pull the file content
    /// anyway. `offer_send` moves the outbound row to
    /// `OutboundStatus::Rejected` once it observes the rejection, and
    /// `handle_pull` requires `OutboundStatus::Acked` before serving any
    /// chunk -- this drives both halves together over real QUIC
    /// connections, in the exact two-connection shape (one for the offer,
    /// a wholly separate one for the pull) a real receiver uses.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_receiver_that_rejects_the_offer_cannot_later_pull_the_content() {
        let (sender_endpoint, sender_addr, sender_key) = raw_endpoint().await;
        let (receiver_endpoint, receiver_addr, receiver_key) = raw_endpoint().await;
        // Stands in for the coordination plane's own push of the grant to
        // the receiver, exactly as the positive-control test does.
        receiver_endpoint.authorize_send_peer(sender_key);

        let grants = Arc::new(FakeGrantStore::default());
        let sender_directory: Arc<dyn DeviceDirectory> = Arc::new(GrantingDirectory {
            sender_key,
            grants: grants.clone(),
            target: ResolvedDevice {
                device_id: "receiver-device".to_string(),
                signing_key: receiver_key,
                candidate_addresses: vec![receiver_addr],
            },
        });
        let (sender_service, _sender_guard) =
            make_service(sender_endpoint.clone(), sender_directory);
        // Production parity: `send_transfer::run` always runs this, so the
        // sender really does serve inbound pulls.
        tokio::spawn(sender_service.clone().run_inbound_dispatcher());

        let secret = b"content a rejecting receiver must never get".to_vec();
        let source_dir = tempfile::tempdir().unwrap();
        let source_path = source_dir.path().join("secret.txt");
        std::fs::write(&source_path, &secret).unwrap();

        // A hand-rolled receiver that rejects every offer but remembers the
        // transfer id it saw in the manifest, so it can try pulling by id
        // afterward exactly like a real (malicious or merely buggy) client
        // could.
        let mut inbox = receiver_endpoint.take_inbound_send().unwrap();
        let (id_tx, id_rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            let (connection, _peer) = inbox.recv().await.expect("an inbound offer");
            let (mut send, mut recv) = connection.accept_bi().await.expect("offer stream");
            let envelope: SendEnvelope = read_message(&mut recv).await.unwrap();
            let Some(send_envelope::Payload::Manifest(manifest)) = envelope.payload else {
                panic!("expected a manifest offer");
            };
            write_message(
                &mut send,
                &SendManifestAck {
                    accepted: false,
                    reason: "receiver rejects this offer".to_string(),
                },
            )
            .await
            .unwrap();
            send.finish().ok();
            let _ = send.stopped().await;
            let _ = id_tx.send(manifest.transfer_id);
        });

        let err = sender_service
            .offer_send(&source_path, "receiver-device")
            .await
            .expect_err("the receiver rejected, so offer_send must fail");
        assert!(matches!(err, SendError::OfferRejected(_)), "got {err:?}");
        let transfer_id = id_rx.await.expect("the receiver saw a transfer id");

        // Now the rejecting receiver dials the sender BACK, on a fresh
        // connection, and pulls -- the sender's `send_authorized` set still
        // admits this key (a grant revoke only clears that admission on its
        // own schedule, not synchronously with the rejection), so this must
        // be refused at the application layer, in `handle_pull` itself.
        let connection = receiver_endpoint
            .connect_send(sender_addr, sender_key)
            .await
            .expect("the sender still admits this key for send-ALPN");
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        write_message(
            &mut send,
            &SendEnvelope {
                payload: Some(send_envelope::Payload::Pull(ChunkPullRequest {
                    transfer_id,
                    file_index: 0,
                    start_chunk_index: 0,
                })),
                grant_id: String::new(),
                grant_nonce: String::new(),
            },
        )
        .await
        .unwrap();
        send.finish().ok();

        let message: ChunkStreamMessage =
            tokio::time::timeout(Duration::from_secs(15), read_message(&mut recv))
                .await
                .expect("the sender answered the pull within 15s")
                .unwrap();
        match message.payload {
            Some(chunk_stream_message::Payload::Rejected(r)) => {
                assert!(!r.reason.is_empty(), "a rejection must carry a reason");
            }
            Some(chunk_stream_message::Payload::Header(h)) => {
                let body = read_body(&mut recv, h.size as usize).await.unwrap();
                panic!(
                    "a receiver that rejected the offer must not be able to pull the content, \
                     but the pull was served: {} bytes, matches source: {}",
                    body.len(),
                    body == secret
                );
            }
            None => panic!("empty message"),
        }
    }

    /// A `DeviceDirectory` that can resolve a target through ordinary
    /// netmap connectivity (`resolve` -> `Some`, a real reachable address)
    /// but has ZERO grant capability (`request_grant` falls through to the
    /// trait's own `None` default) -- the shape a same-account device this
    /// daemon can already reach over sync, but for which the coordination
    /// plane will not currently mint a Send grant, would present.
    struct NetmapOnlyDirectory {
        target: ResolvedDevice,
    }

    #[async_trait::async_trait]
    impl DeviceDirectory for NetmapOnlyDirectory {
        fn resolve(&self, device_query: &str) -> Option<ResolvedDevice> {
            (device_query == self.target.device_id).then(|| self.target.clone())
        }
        fn device_id_for_key(&self, _signing_key: &[u8; 32]) -> Option<String> {
            None
        }
    }

    /// The negative control for `offer_send`'s own half of the grant
    /// requirement: a target `resolve` can reach through ordinary netmap
    /// connectivity, but for which no grant is obtainable, must make
    /// `offer_send` fail with `NoKnownDeviceKey` BEFORE it ever dials --
    /// not fall back to sending an ungranted offer the receiver then has to
    /// reject on its own. The positive-control test above cannot exercise
    /// this guard by itself, because its own `resolve` always returns
    /// `None`; this test is the one that actually proves `offer_send` never
    /// treats netmap-resolvability as a substitute for a grant.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offer_send_refuses_a_netmap_resolvable_target_when_no_grant_can_be_obtained() {
        let (sender_endpoint, _sender_addr, sender_key) = raw_endpoint().await;
        let (receiver_endpoint, receiver_addr, receiver_key) = raw_endpoint().await;
        sender_endpoint.authorize(receiver_key);
        receiver_endpoint.authorize(sender_key);

        let receiver_directory: Arc<dyn DeviceDirectory> =
            Arc::new(TestDirectory { grants: None, device_labels: HashMap::new() });
        let (receiver_service, _receiver_guard) =
            make_service(receiver_endpoint.clone(), receiver_directory);
        tokio::spawn(receiver_service.clone().run_inbound_dispatcher());

        let sender_directory: Arc<dyn DeviceDirectory> = Arc::new(NetmapOnlyDirectory {
            target: ResolvedDevice {
                device_id: "receiver-device".to_string(),
                signing_key: receiver_key,
                candidate_addresses: vec![receiver_addr],
            },
        });
        let (sender_service, _sender_guard) =
            make_service(sender_endpoint.clone(), sender_directory);

        let source_dir = tempfile::tempdir().unwrap();
        let source_path = source_dir.path().join("hello.txt");
        std::fs::write(&source_path, b"ordinary netmap peer, no grant available").unwrap();

        let error = sender_service
            .offer_send(&source_path, "receiver-device")
            .await
            .expect_err("a target with no obtainable grant must not be sendable to");
        assert!(
            matches!(error, SendError::NoKnownDeviceKey(_)),
            "offer_send must fail on the missing grant BEFORE dialing, not fall back to an \
             ungranted offer the receiver then rejects; got: {error:?}"
        );
        assert!(
            receiver_service.list_inbox().unwrap().is_empty(),
            "no offer should have reached the receiver at all"
        );
    }

    // ---- pull-loop validation against the receiver's own manifest -------
    //
    // `pull_file` is exercised directly (bypassing `receive_transfer`'s own
    // store/destination-directory bookkeeping, which is orthogonal to what
    // is being proven here) against a hand-rolled "sender" that answers a
    // pull with whatever a real, already-accepted `SendService` never
    // would -- a wrong chunk index, a chunk declared a different size than
    // the manifest says, a chunk whose body does not hash to what the
    // manifest recorded, or more chunks than the manifest has entries for.
    // The point in every case is the same: an accepted sender is trusted
    // for network reachability, never for chunk content, size, order, or
    // count -- this device's own manifest, already durably on disk before
    // any of these pulls dial out, is what every received chunk is
    // checked against.

    /// A `SendFileEntry` whose `chunk_hashes`/`chunk_size`/`size` are
    /// derived directly from `chunk_bodies`, exactly the way
    /// `build_outbound_manifest` would have produced them for a real file
    /// split into these exact chunks -- so `pull_file`'s validation against
    /// this entry is checked against the same shape of manifest a real
    /// offer would carry, not a hand-waved stand-in.
    fn pull_test_entry(chunk_size: u32, chunk_bodies: &[&[u8]]) -> SendFileEntry {
        let chunk_hashes = chunk_bodies
            .iter()
            .map(|body| hex::decode(hash_block_bytes(body)).expect("hex-decodes"))
            .collect();
        let size: u64 = chunk_bodies.iter().map(|body| body.len() as u64).sum();
        SendFileEntry { relative_path: "pulled.bin".to_string(), size, chunk_size, chunk_hashes }
    }

    /// Accepts exactly one inbound Track Send connection on `endpoint`,
    /// confirms it carries a `ChunkPullRequest` (not a manifest offer), and
    /// then writes exactly the `(header, body)` pairs given, in order,
    /// before finishing the stream -- a hand-rolled "sender" answering a
    /// pull with whatever a test wants to present, without a second real
    /// `SendService` involved at all.
    async fn fake_pull_responder(
        endpoint: Arc<QuicPeerEndpoint>,
        responses: Vec<(ChunkHeader, Vec<u8>)>,
    ) {
        let mut inbox = endpoint.take_inbound_send().unwrap();
        let (connection, _peer) = inbox.recv().await.expect("an inbound pull connection");
        let (mut send, mut recv) = connection.accept_bi().await.expect("pull stream");
        let envelope: SendEnvelope = read_message(&mut recv).await.unwrap();
        assert!(
            matches!(envelope.payload, Some(send_envelope::Payload::Pull(_))),
            "expected a chunk pull request, got {envelope:?}"
        );
        for (header, body) in responses {
            write_message(
                &mut send,
                &ChunkStreamMessage {
                    payload: Some(chunk_stream_message::Payload::Header(header)),
                },
            )
            .await
            .unwrap();
            send.write_all(&body).await.unwrap();
        }
        send.finish().ok();
        let _ = send.stopped().await;
    }

    /// A real receiver `SendService`, plus a fake sender's raw endpoint
    /// (already admitting the receiver's key for send-ALPN, exactly as a
    /// real sender's `offer_send` would have set up via
    /// `authorize_send_peer` before this device ever dialed back) and the
    /// `ResolvedDevice` `pull_file` needs to dial it -- the shared setup
    /// every test in this group starts from.
    async fn receiver_and_fake_sender(
    ) -> (Arc<SendService>, tempfile::TempDir, Arc<QuicPeerEndpoint>, ResolvedDevice) {
        let (fake_sender_endpoint, fake_sender_addr, fake_sender_key) = raw_endpoint().await;
        let (receiver_endpoint, _receiver_addr, receiver_key) = raw_endpoint().await;
        fake_sender_endpoint.authorize_send_peer(receiver_key);

        let receiver_directory: Arc<dyn DeviceDirectory> =
            Arc::new(TestDirectory { grants: None, device_labels: HashMap::new() });
        let (receiver_service, receiver_guard) =
            make_service(receiver_endpoint, receiver_directory);
        let sender = ResolvedDevice {
            device_id: "fake-sender".to_string(),
            signing_key: fake_sender_key,
            candidate_addresses: vec![fake_sender_addr],
        };
        (receiver_service, receiver_guard, fake_sender_endpoint, sender)
    }

    /// A chunk header whose declared `size` disagrees with what this
    /// device's own manifest says chunk 0 of a single-chunk file must be
    /// must be rejected -- and rejected BEFORE the body is read, since an
    /// unchecked peer-supplied `size` is exactly what would otherwise size
    /// an unbounded allocation in `read_body`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pull_file_rejects_a_chunk_whose_declared_size_disagrees_with_the_manifest() {
        let (receiver_service, _receiver_guard, fake_sender_endpoint, sender) =
            receiver_and_fake_sender().await;
        let entry = pull_test_entry(5, &[b"hello"]);

        tokio::spawn(fake_pull_responder(
            fake_sender_endpoint,
            vec![(ChunkHeader { chunk_index: 0, size: 999, last_chunk: true }, b"hello".to_vec())],
        ));

        let error = tokio::time::timeout(
            Duration::from_secs(15),
            receiver_service.pull_file(&sender, "t1", 0, &entry, 0),
        )
        .await
        .expect("pull_file must not hang on an oversized declared chunk size")
        .expect_err("a chunk whose declared size disagrees with the manifest must be rejected");
        assert!(matches!(error, SendError::Protocol(_)), "got {error:?}");
    }

    /// A chunk whose body does not hash to what this device's own manifest
    /// recorded for that chunk index must be rejected -- and rejected
    /// before `block_store.put` ever durably commits it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pull_file_rejects_a_chunk_that_fails_hash_verification() {
        let (receiver_service, _receiver_guard, fake_sender_endpoint, sender) =
            receiver_and_fake_sender().await;
        let entry = pull_test_entry(5, &[b"hello"]);

        tokio::spawn(fake_pull_responder(
            fake_sender_endpoint,
            vec![(ChunkHeader { chunk_index: 0, size: 5, last_chunk: true }, b"WRONG".to_vec())],
        ));

        let error = tokio::time::timeout(
            Duration::from_secs(15),
            receiver_service.pull_file(&sender, "t1", 0, &entry, 0),
        )
        .await
        .expect("pull_file must not hang on a hash-mismatched chunk")
        .expect_err("a chunk that does not hash to the manifest's entry must be rejected");
        assert!(
            matches!(error, SendError::ChunkHashMismatch { file_index: 0, chunk_index: 0 }),
            "got {error:?}"
        );

        // The mismatched body must never have reached the block store --
        // the receiver's own manifest hash is checked before `put`, not
        // after.
        let expected_hex = hex::encode(&entry.chunk_hashes[0]);
        let present = receiver_service
            .block_store
            .present_blocks(std::slice::from_ref(&expected_hex))
            .unwrap();
        assert_eq!(present, vec![false], "the expected chunk hash must not be present");
    }

    /// However many extra chunks a peer keeps sending, and whatever it sets
    /// `last_chunk` to, `pull_file` must stop reading once it has received
    /// as many chunks as this device's own manifest says the file has --
    /// never fewer (an early, dishonest `last_chunk: true` is a separate,
    /// pre-existing concern this test does not touch), and never more.
    /// Proven by a fake sender that never sets `last_chunk: true` at all,
    /// and would fail a THIRD chunk's own size validation if `pull_file`
    /// ever asked for it (`chunk_byte_size` has no chunk index 2 in a
    /// 2-chunk manifest) -- so the pull only succeeds if the loop stopped
    /// itself, by count, without ever issuing that third read.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pull_file_stops_at_the_manifests_chunk_count_regardless_of_last_chunk() {
        let (receiver_service, _receiver_guard, fake_sender_endpoint, sender) =
            receiver_and_fake_sender().await;
        let entry = pull_test_entry(5, &[b"AAAAA", b"BB"]);

        tokio::spawn(fake_pull_responder(
            fake_sender_endpoint,
            vec![
                // Neither chunk claims to be the last one -- a buggy or
                // malicious sender that never sends a true `last_chunk`.
                (ChunkHeader { chunk_index: 0, size: 5, last_chunk: false }, b"AAAAA".to_vec()),
                (ChunkHeader { chunk_index: 1, size: 2, last_chunk: false }, b"BB".to_vec()),
                // Would blow up `chunk_byte_size` (out of range for a
                // 2-chunk manifest) if `pull_file` ever read this far.
                (
                    ChunkHeader { chunk_index: 2, size: 999, last_chunk: true },
                    b"should never be read".to_vec(),
                ),
            ],
        ));

        tokio::time::timeout(
            Duration::from_secs(15),
            receiver_service.pull_file(&sender, "t1", 0, &entry, 0),
        )
        .await
        .expect("pull_file must not hang")
        .expect(
            "pull_file must stop cleanly at the manifest's own chunk count, \
             never reading the peer's extra, out-of-range third chunk",
        );

        // Both genuine chunks were still durably received.
        let hashes: Vec<String> = entry.chunk_hashes.iter().map(hex::encode).collect();
        let present = receiver_service.block_store.present_blocks(&hashes).unwrap();
        assert_eq!(present, vec![true, true], "both real chunks must have been stored");
    }

    // ---- ack-then-immediate-pull ordering --------------------------------

    /// A `DeviceDirectory` for the RECEIVING side of the test below only:
    /// unlike `TestDirectory` (used everywhere else in this module, which
    /// never resolves anything -- see its own doc comment), this one CAN
    /// resolve the sender back to a dialable address, because
    /// `receive_transfer`'s pull-phase dial-back needs exactly that. Also
    /// consumes grants against a real (fake) shared `FakeGrantStore`, like
    /// `TestDirectory` does, since the offer this test drives needs one to
    /// be accepted at all.
    struct ReceiverWithResolvableSender {
        sender: ResolvedDevice,
        grants: Arc<FakeGrantStore>,
    }

    #[async_trait::async_trait]
    impl DeviceDirectory for ReceiverWithResolvableSender {
        fn resolve(&self, device_query: &str) -> Option<ResolvedDevice> {
            (device_query == self.sender.device_id).then(|| self.sender.clone())
        }
        fn device_id_for_key(&self, signing_key: &[u8; 32]) -> Option<String> {
            (signing_key == &self.sender.signing_key).then(|| self.sender.device_id.clone())
        }
        async fn consume_grant(
            &self,
            grant_id: &str,
            grant_nonce: &str,
            peer_key: &[u8; 32],
        ) -> std::result::Result<(), String> {
            self.grants.consume(grant_id, grant_nonce, peer_key)
        }
    }

    /// Regression for the ack/pull reordering in `offer_send`:
    /// `mark_outbound_acked` now runs BEFORE `connection.close()` (see that
    /// call site's own comment) instead of after, so this device's own
    /// record of an acceptance lands as early as it possibly can, narrowing
    /// -- not eliminating -- the window in which a receiver that already
    /// answered `accepted: true` and immediately dials back can hit
    /// `handle_pull`'s `Acked` check first.
    ///
    /// Races a real accept against a real, immediate pull attempt with no
    /// artificial delay on either side -- the racing task starts polling
    /// before `offer_send` has even been called, which is earlier than any
    /// real client could react. A transient rejection here is therefore
    /// still an expected, self-healing outcome (see `offer_send`'s own
    /// comment: this is a narrowed race, not a closed one), so a bounded
    /// number of quick retries is allowed -- but the pull must succeed,
    /// and quickly, not require the kind of retry-with-backoff a real
    /// networked race might.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_receiver_can_pull_immediately_after_accepting_the_offer() {
        let (sender_endpoint, sender_addr, sender_key) = raw_endpoint().await;
        let (receiver_endpoint, receiver_addr, receiver_key) = raw_endpoint().await;
        receiver_endpoint.authorize_send_peer(sender_key);

        let grants = Arc::new(FakeGrantStore::default());
        let sender_directory: Arc<dyn DeviceDirectory> = Arc::new(GrantingDirectory {
            sender_key,
            grants: grants.clone(),
            target: ResolvedDevice {
                device_id: "receiver-device".to_string(),
                signing_key: receiver_key,
                candidate_addresses: vec![receiver_addr],
            },
        });
        let (sender_service, _sender_guard) =
            make_service(sender_endpoint.clone(), sender_directory);
        tokio::spawn(sender_service.clone().run_inbound_dispatcher());

        let receiver_directory: Arc<dyn DeviceDirectory> = Arc::new(ReceiverWithResolvableSender {
            sender: ResolvedDevice {
                device_id: "sender-device".to_string(),
                signing_key: sender_key,
                candidate_addresses: vec![sender_addr],
            },
            grants,
        });
        let (receiver_service, _receiver_guard) =
            make_service(receiver_endpoint.clone(), receiver_directory);
        tokio::spawn(receiver_service.clone().run_inbound_dispatcher());

        let content = b"pulled right after acceptance, no meaningful delay".to_vec();
        let source_dir = tempfile::tempdir().unwrap();
        let source_path = source_dir.path().join("race.txt");
        std::fs::write(&source_path, &content).unwrap();

        let receiver_for_race = receiver_service.clone();
        let racer = tokio::spawn(async move {
            // Polls the receiver's own inbox rather than sleeping -- picks
            // up the offer (and attempts the pull) as early as physically
            // possible on this task, which can be before the sender has
            // even read this receiver's own ack.
            let transfer_id = loop {
                if let Some(entry) = receiver_for_race.list_inbox().unwrap().into_iter().next() {
                    break entry.transfer_id;
                }
                tokio::task::yield_now().await;
            };
            for attempt in 0..50 {
                match receiver_for_race.receive_transfer(&transfer_id, None).await {
                    Ok(outcome) => return outcome,
                    Err(_) if attempt < 49 => {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    Err(error) => {
                        panic!("the pull never succeeded after 50 quick retries: {error}")
                    }
                }
            }
            unreachable!("loop above always returns or panics")
        });

        sender_service
            .offer_send(&source_path, "receiver-device")
            .await
            .expect("a granted, accepted offer must succeed");

        let outcome = racer.await.expect("the racing pull task must not panic");
        assert_eq!(outcome.bytes_received, content.len() as u64);
        assert_eq!(outcome.files_received, vec!["race.txt".to_string()]);
    }
}

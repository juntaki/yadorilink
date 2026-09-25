//! Driving one reconciliation, and moving the bundles it identifies.
//!
//! A session holds nothing durable. It has no identifier, no acknowledgement
//! table, no sent-set cache and no resumable position. Killing it at any point
//! loses only work in progress: the next session recomputes the same
//! difference from the two peers' durable sets. That is what makes a durable
//! per-peer sync-debt table unnecessary, and it is why every error path here
//! simply ends the session rather than trying to repair it.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use yadorilink_rbsr::{ItemId, MemoryIndex, RbsrConfig, Reconciler};

use crate::error::ProtocolError;
use crate::ports::{BaseVerdict, GroupId, PeerKey, ReplicaPort};
use crate::wire::{
    self, MAX_ADVERTISEMENT_BYTES, MAX_BUNDLE_BYTES, MAX_GROUP_BYTES, MAX_ROUND_BYTES,
};

/// Which side of a reconciliation this node is on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// Opens the exchange with a fingerprint over the whole space.
    Initiator,
    /// Answers.
    Responder,
}

#[derive(Clone, Copy, Debug)]
pub struct SessionConfig {
    pub rbsr: RbsrConfig,
    /// A hard ceiling on rounds. Reconciliation terminates on its own; this
    /// exists so a peer that keeps manufacturing differences cannot hold a
    /// session open indefinitely.
    pub max_rounds: usize,
    /// How many bundles are asked for in one request.
    pub bundles_per_request: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self { rbsr: RbsrConfig::default(), max_rounds: 64, bundles_per_request: 256 }
    }
}

/// What one reconciliation established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reconciled {
    /// Identifiers the peer holds and this node does not.
    pub want: Vec<ItemId>,
    /// Identifiers this node holds and the peer does not.
    pub offer: Vec<ItemId>,
    pub rounds: usize,
}

impl Reconciled {
    /// Whether the two sets already agreed.
    pub fn is_settled(&self) -> bool {
        self.want.is_empty() && self.offer.is_empty()
    }
}

/// How a reconciliation session ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReconcileOutcome {
    /// Both sides stand on the same history base and compared change sets.
    Reconciled(Reconciled),
    /// The two sides stand on different history bases. No fingerprint was
    /// computed and no change set compared: a change written on one base
    /// says nothing admissible about the other, so there is no ordinary
    /// difference between them. Merging the two histories is required,
    /// and is not something this session starts.
    MergeRequired,
}

impl ReconcileOutcome {
    /// The reconciliation, for a caller that has established both sides
    /// share a base.
    pub fn expect_reconciled(self, message: &str) -> Reconciled {
        match self {
            Self::Reconciled(reconciled) => reconciled,
            Self::MergeRequired => panic!("{message}: the peers stand on different bases"),
        }
    }
}

/// Announce what a freshly opened lane is for.
///
/// A lane stream carries no context of its own. The opener says which
/// protocol version it speaks and which group the lane is about, because the
/// accepting side needs the group in hand before it can decide whether this
/// peer may be told anything about it — and that has to be settled before a
/// fingerprint is computed, not after.
pub async fn open_lane<S: AsyncWrite + Unpin>(
    stream: &mut S,
    group: &GroupId,
) -> Result<(), ProtocolError> {
    write_frame(stream, &wire::encode_hello(group.as_str())?).await?;
    stream.flush().await?;
    Ok(())
}

/// Read what an accepted lane is for.
pub async fn accept_lane<S: AsyncRead + Unpin>(stream: &mut S) -> Result<GroupId, ProtocolError> {
    let Some(body) = read_frame(stream, MAX_GROUP_BYTES + 16).await? else {
        return Err(ProtocolError::NoHello);
    };
    Ok(GroupId(wire::decode_hello(&body)?))
}

/// Reconcile with a peer over the reconciliation lane.
///
/// Entitlement is settled before anything is computed or written. A
/// fingerprint reveals whether two sets agree, and fingerprints that differ
/// across a range reveal that the peer is missing something there; both are
/// disclosures, so a peer that may not be told about the group is refused
/// before the first fingerprint exists.
///
/// Bases are compared next, and still before any fingerprint: the opener
/// sends its advertisement, the answerer replies with its own, and each
/// side judges the pair through its port. Only peers on the same base go
/// on to compare change sets.
pub async fn reconcile<S, P>(
    stream: &mut S,
    port: &P,
    peer: PeerKey,
    group: &GroupId,
    role: Role,
    config: &SessionConfig,
) -> Result<ReconcileOutcome, ProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    P: ReplicaPort + ?Sized,
{
    if !port.may_disclose(peer, group.clone()).await? {
        return Err(ProtocolError::NotDisclosable { group: group.clone() });
    }

    match negotiate_base(stream, port, peer, group, role).await? {
        Some(BaseVerdict::SameBase) => {}
        Some(BaseVerdict::MergeRequired) => return Ok(ReconcileOutcome::MergeRequired),
        Some(BaseVerdict::Refused(reason)) => {
            return Err(ProtocolError::BaseRefused { group: group.clone(), reason })
        }
        // The peer hung up before saying where it stands -- which is also
        // what a peer that will not disclose this group looks like, and it
        // must keep looking exactly like a peer that holds nothing.
        None => {
            return Ok(ReconcileOutcome::Reconciled(Reconciled {
                want: Vec::new(),
                offer: Vec::new(),
                rounds: 0,
            }))
        }
    }

    let servable = port.servable(peer, group.clone()).await?;
    let mut reconciler = Reconciler::new(MemoryIndex::new(servable), config.rbsr);

    let mut rounds = 0usize;

    if role == Role::Initiator {
        let opening = reconciler.initiate();
        write_frame(stream, &wire::encode_round(&opening)?).await?;
    }

    loop {
        let Some(body) = read_frame(stream, MAX_ROUND_BYTES).await? else {
            // The peer hung up. Nothing is lost; the difference is
            // recomputable from durable state whenever it returns.
            break;
        };
        rounds += 1;
        if rounds > config.max_rounds {
            return Err(ProtocolError::TooManyRounds { limit: config.max_rounds });
        }

        let incoming = wire::decode_round(&body)?;
        if incoming.is_empty() {
            // The peer has nothing further to say: settled.
            break;
        }

        let reply = reconciler.ingest(&incoming)?;
        write_frame(stream, &wire::encode_round(&reply)?).await?;
        if reply.is_empty() {
            break;
        }
    }

    Ok(ReconcileOutcome::Reconciled(Reconciled {
        want: reconciler.want().iter().copied().collect(),
        offer: reconciler.offer().iter().copied().collect(),
        rounds,
    }))
}

/// Exchange base advertisements and have the port judge them. `None` when
/// the peer ended the lane before advertising.
///
/// The opener speaks first so neither side waits on the other. Each side
/// judges the advertisement it actually sent, not a fresh reading of its
/// own state, so a base that changes mid-exchange cannot make the two
/// sides judge different pairs.
async fn negotiate_base<S, P>(
    stream: &mut S,
    port: &P,
    peer: PeerKey,
    group: &GroupId,
    role: Role,
) -> Result<Option<BaseVerdict>, ProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    P: ReplicaPort + ?Sized,
{
    let ours = port.base_advertisement(peer, group.clone()).await?;
    let frame = wire::encode_advertisement(&ours)?;
    let exchange = async {
        match role {
            Role::Initiator => {
                write_frame(stream, &frame).await?;
                read_frame(stream, MAX_ADVERTISEMENT_BYTES).await
            }
            Role::Responder => {
                let theirs = read_frame(stream, MAX_ADVERTISEMENT_BYTES).await?;
                if theirs.is_some() {
                    write_frame(stream, &frame).await?;
                }
                Ok(theirs)
            }
        }
    };
    // A peer that will not disclose the group ends the lane at once, and
    // depending on timing that surfaces here as a clean end of stream or as
    // the stream being stopped under our write. Both are the same hang-up
    // and must look the same to the caller: like a peer that holds nothing.
    let theirs = match exchange.await {
        Ok(theirs) => theirs,
        Err(ProtocolError::Io(error)) if is_hang_up(&error) => None,
        // Unlike a hang-up, an advertisement too long to read is a
        // malformed one: the negotiation happened and is refused, and the
        // port hears so before the session ends.
        Err(error @ ProtocolError::FrameTooLarge { .. }) => {
            port.base_unjudgeable(peer, group.clone(), error.to_string()).await?;
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    let Some(theirs) = theirs else { return Ok(None) };
    Ok(Some(port.negotiate_base(peer, group.clone(), ours, theirs).await?))
}

fn is_hang_up(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
    )
}

/// Ask a peer for bundles and stage what comes back.
///
/// Staging is one all-or-nothing step over the whole delivery, so a peer
/// cannot get the front of a batch accepted by corrupting the back of it.
/// Returns the hashes newly staged.
pub async fn request_bundles<S, P>(
    stream: &mut S,
    port: &P,
    peer: PeerKey,
    group: &GroupId,
    wanted: &[ItemId],
    config: &SessionConfig,
) -> Result<Vec<ItemId>, ProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    P: ReplicaPort + ?Sized,
{
    let asked: Vec<ItemId> = wanted.iter().take(config.bundles_per_request).copied().collect();
    write_frame(stream, &wire::encode_bundle_request(&asked)?).await?;
    stream.flush().await?;

    let mut delivered = Vec::new();
    while let Some(body) = read_frame(stream, MAX_BUNDLE_BYTES).await? {
        let bundle = wire::decode_bundle(&body)?;
        if !asked.contains(&bundle.change_hash) {
            // A peer may only answer what it was asked. Anything else is an
            // attempt to push work we never agreed to verify.
            return Err(ProtocolError::UnrequestedBundle);
        }
        delivered.push(bundle);
        if delivered.len() > asked.len() {
            return Err(ProtocolError::UnrequestedBundle);
        }
    }

    if delivered.is_empty() {
        return Ok(Vec::new());
    }
    Ok(port.stage_bundles(peer, group.clone(), delivered).await?)
}

/// Serve a peer's bundle request.
///
/// Returns how many bundles were sent. A hash this node cannot serve — not
/// held, or not disclosable to this peer — is simply omitted; the peer's view
/// of what we hold is a snapshot and may already be stale.
pub async fn serve_bundles<S, P>(
    stream: &mut S,
    port: &P,
    peer: PeerKey,
    group: &GroupId,
) -> Result<usize, ProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    P: ReplicaPort + ?Sized,
{
    if !port.may_disclose(peer, group.clone()).await? {
        return Err(ProtocolError::NotDisclosable { group: group.clone() });
    }

    let Some(body) = read_frame(stream, MAX_ROUND_BYTES).await? else {
        return Ok(0);
    };
    let requested = wire::decode_bundle_request(&body)?;
    let bundles = port.load_bundles(peer, group.clone(), requested).await?;

    for bundle in &bundles {
        write_frame(stream, &wire::encode_bundle(bundle)?).await?;
    }
    stream.flush().await?;
    stream.shutdown().await?;

    Ok(bundles.len())
}

// --- framing i/o -----------------------------------------------------------

async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    frame: &[u8],
) -> Result<(), ProtocolError> {
    stream.write_all(frame).await?;
    Ok(())
}

/// Read one length-prefixed frame, or `None` at a clean end of stream.
///
/// The declared length is checked against `max` before anything is allocated:
/// a length is a claim by the peer, not an instruction.
async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    max: usize,
) -> Result<Option<Vec<u8>>, ProtocolError> {
    let mut length = [0u8; 4];
    match stream.read_exact(&mut length).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }

    let declared = u32::from_be_bytes(length) as usize;
    if declared > max {
        return Err(ProtocolError::FrameTooLarge { declared, limit: max });
    }

    let mut body = vec![0u8; declared];
    stream.read_exact(&mut body).await?;
    Ok(Some(body))
}

/// A bundle stream is finished by the sender; make that explicit for callers
/// that drive both halves themselves.
pub async fn finish<S: AsyncWrite + Unpin>(stream: &mut S) -> Result<(), ProtocolError> {
    stream.flush().await?;
    stream.shutdown().await?;
    Ok(())
}

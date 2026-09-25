//! A Change is admitted the same way whichever carrier delivered it.
//!
//! `verify_proof_carrying_change` takes no parameter naming who delivered a
//! Change, over what transport, or through how many hops, so
//!
//! ```text
//! Accept(change, direct) == Accept(change, relay)
//! ```
//!
//! holds by construction *for the same primitive input*. What that does not
//! establish is that two carriers actually produce the same input: finding the
//! checkpoint envelope, assembling the bundle and staging it are all
//! path-specific. This is the gap. It is not looking for a flaw in the
//! primitive — it is confirming that both carriers reach it with the same
//! thing in hand, and that the durable result is identical afterwards.
//!
//! The carriers are made genuinely different by the transports available to
//! each receiver, not by which address the author was given:
//!
//! ```text
//!   author   IP + relay
//!   near     IP + relay   →  finds a direct path
//!   far      relay only   →  no IP transport exists to find one with
//! ```
//!
//! Withholding the author's direct address from the far receiver would not
//! have been enough — iroh hole-punches its way to a direct path, and the
//! comparison would drift into direct-against-direct partway through. See
//! `NetworkConfig::relay_only_for_tests`.

use std::sync::Arc;
use std::time::Duration;

use yadorilink_replica_domain::ids::{ChangeHash, FolderGroupId};
use yadorilink_sync_sqlite::dag_store::published_view;
use yadorilink_sync_sqlite::{verified_change_store, SyncSqliteError};

use super::driver::ReconciliationDriver;
use super::sync_stack::SyncStack;
use crate::daemon_state::DaemonState;
use crate::test_support::sync_stack_fixture::{
    change_putting, device, file_version, honest_bundle_carrying, init_staging_schema, pin,
    possessed, FixtureAuthenticator, GROUP,
};

/// Everything a device durably holds about one admitted Change.
///
/// Compared field by field rather than by "is it there": a carrier that
/// resolved a checkpoint envelope differently, or assembled a bundle that
/// merely happened to verify, would leave a Change that is present on both
/// sides and backed by different evidence on each.
#[derive(Debug, PartialEq, Eq)]
struct AdmittedState {
    published: bool,
    encoded_change: Option<Vec<u8>>,
    checkpoint_hash: Option<[u8; 32]>,
    merkle_proof: Option<Vec<u8>>,
    checkpoint_encoded: Option<Vec<u8>>,
    checkpoint_signature: Option<Vec<u8>>,
    author_signing_public_key: Option<[u8; 32]>,
}

fn admitted_state(state: &DaemonState, hash: &ChangeHash) -> AdmittedState {
    state
        .replica_coordinator
        .database()
        .read::<_, SyncSqliteError>(|conn| {
            let published = published_view::is_published(conn, hash)?;
            let encoded_change = published_view::published_encoded_change(conn, hash)?;
            let (checkpoint_hash, merkle_proof) = match published_view::change_evidence(conn, hash)?
            {
                Some((checkpoint_hash, proof)) => (Some(checkpoint_hash), Some(proof)),
                None => (None, None),
            };
            let envelope = match checkpoint_hash {
                Some(hash) => published_view::checkpoint_envelope(conn, &hash)?,
                None => None,
            };
            let (checkpoint_encoded, checkpoint_signature, author_signing_public_key) =
                match envelope {
                    Some((encoded, signature, key)) => (Some(encoded), Some(signature), Some(key)),
                    None => (None, None, None),
                };
            Ok(AdmittedState {
                published,
                encoded_change,
                checkpoint_hash,
                merkle_proof,
                checkpoint_encoded,
                checkpoint_signature,
                author_signing_public_key,
            })
        })
        .expect("reading admitted state must not fail")
}

async fn within(seconds: u64, mut check: impl FnMut() -> bool) -> bool {
    tokio::time::timeout(Duration::from_secs(seconds), async {
        loop {
            if check() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or(false)
}

/// Waits for `stack` to have a relay in its own address, which is what a peer
/// needs in order to reach it through one. Registration with the relay
/// happens after the endpoint binds.
async fn relayed_address_of(stack: &SyncStack) -> Vec<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let relays: Vec<String> = stack.local_address().relay_urls().map(str::to_string).collect();
        if !relays.is_empty() {
            return relays;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "a relay-capable node never registered with the relay"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The substrate reachability field, as the coordination plane reports it.
///
/// Every test below feeds the daemon exactly what an applied netmap push feeds
/// it -- `record_peer_substrate_reachability` and `record_peer_signing_key` --
/// and never touches the address directory. Injecting there would prove the
/// directory works, which was never in doubt; what these prove is that current
/// coordination state reaches it, in every order the daemon can see.
mod substrate_reachability {
    use super::*;
    use crate::coordination_client::SubstrateReachability;

    fn peer_id_of(state: &DaemonState) -> yadorilink_sync_substrate::PeerId {
        yadorilink_sync_substrate::PeerId::from_bytes(
            state.device_signing_key().unwrap().verifying_key().to_bytes(),
        )
    }

    fn resolved(
        stack: &SyncStack,
        peer: yadorilink_sync_substrate::PeerId,
    ) -> Option<(Vec<std::net::SocketAddr>, Vec<String>)> {
        use yadorilink_sync_substrate::AddressDirectory as _;
        stack.address_directory().resolve(peer)
    }

    /// Gate: a netmap push that arrives BEFORE the reconciliation driver still
    /// reaches the directory.
    ///
    /// This is the production order -- a daemon is pushed a netmap long before
    /// its stack exists -- and the one an event-cache implementation gets
    /// wrong, because a push is a snapshot and the next identical one carries
    /// no change to react to.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_push_before_the_driver_still_reaches_the_directory() {
        let (local, _d1) = device("device-local", 71);
        let (remote, _d2) = device("device-remote", 72);
        init_staging_schema(&local);
        let remote_peer = peer_id_of(&remote);
        let direct: std::net::SocketAddr = "192.0.2.7:41000".parse().unwrap();

        // Netmap first, driver second.
        pin(&local, "device-remote", 72);
        local.record_peer_substrate_reachability(
            "device-remote",
            Some(SubstrateReachability { direct: vec![direct], relays: Vec::new() }),
        );

        let stack = Arc::new(
            SyncStack::spawn(
                local.clone(),
                Arc::new(FixtureAuthenticator),
                yadorilink_sync_substrate::NetworkConfig::direct_only(),
            )
            .await
            .unwrap(),
        );
        local.install_reconciliation_driver(ReconciliationDriver::start(
            local.clone(),
            stack.clone(),
        ));

        assert_eq!(
            resolved(&stack, remote_peer),
            Some((vec![direct], Vec::new())),
            "a netmap push that preceded the driver was never projected"
        );
    }

    /// Gate: the reverse order converges on the same state.
    ///
    /// Neither ordering may be privileged. Encoding one into the code would
    /// make the other a silent dead end, which is how the relay half broke.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_push_after_the_driver_reaches_the_same_state() {
        let (local, _d1) = device("device-local", 73);
        let (remote, _d2) = device("device-remote", 74);
        init_staging_schema(&local);
        let remote_peer = peer_id_of(&remote);
        let direct: std::net::SocketAddr = "192.0.2.8:41000".parse().unwrap();

        let stack = Arc::new(
            SyncStack::spawn(
                local.clone(),
                Arc::new(FixtureAuthenticator),
                yadorilink_sync_substrate::NetworkConfig::direct_only(),
            )
            .await
            .unwrap(),
        );
        local.install_reconciliation_driver(ReconciliationDriver::start(
            local.clone(),
            stack.clone(),
        ));

        // Driver first, netmap second.
        pin(&local, "device-remote", 74);
        local.record_peer_substrate_reachability(
            "device-remote",
            Some(SubstrateReachability { direct: vec![direct], relays: Vec::new() }),
        );

        assert_eq!(resolved(&stack, remote_peer), Some((vec![direct], Vec::new())));
    }

    /// Gate: reachability recorded before the peer's signing key is known still
    /// lands once the key arrives.
    ///
    /// The key IS the endpoint id, so it is a prerequisite of the projection
    /// rather than an input to it -- and a peer whose key arrives second must
    /// not need a second netmap push to become dialable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reachability_before_the_signing_key_still_lands() {
        let (local, _d1) = device("device-local", 75);
        let (remote, _d2) = device("device-remote", 76);
        init_staging_schema(&local);
        let remote_peer = peer_id_of(&remote);
        let direct: std::net::SocketAddr = "192.0.2.9:41000".parse().unwrap();

        let stack = Arc::new(
            SyncStack::spawn(
                local.clone(),
                Arc::new(FixtureAuthenticator),
                yadorilink_sync_substrate::NetworkConfig::direct_only(),
            )
            .await
            .unwrap(),
        );
        local.install_reconciliation_driver(ReconciliationDriver::start(
            local.clone(),
            stack.clone(),
        ));

        // Reachability with no key yet: nothing can be projected, because
        // there is no endpoint id to project it under.
        local.record_peer_substrate_reachability(
            "device-remote",
            Some(SubstrateReachability { direct: vec![direct], relays: Vec::new() }),
        );
        assert_eq!(resolved(&stack, remote_peer), None);

        pin(&local, "device-remote", 76);
        assert_eq!(
            resolved(&stack, remote_peer),
            Some((vec![direct], Vec::new())),
            "the key arriving second must complete the projection on its own"
        );
    }

    /// Gate: an absent field does not erase what is already known.
    ///
    /// An older plane, and a device whose substrate has not published yet, both
    /// send nothing. Reading that as "reachable nowhere" would make a perfectly
    /// reachable peer undialable, which is worse than the stale address it
    /// replaces.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_absent_field_does_not_erase_what_is_known() {
        let (local, _d1) = device("device-local", 77);
        let (remote, _d2) = device("device-remote", 78);
        init_staging_schema(&local);
        let remote_peer = peer_id_of(&remote);
        let direct: std::net::SocketAddr = "192.0.2.10:41000".parse().unwrap();

        let stack = Arc::new(
            SyncStack::spawn(
                local.clone(),
                Arc::new(FixtureAuthenticator),
                yadorilink_sync_substrate::NetworkConfig::direct_only(),
            )
            .await
            .unwrap(),
        );
        local.install_reconciliation_driver(ReconciliationDriver::start(
            local.clone(),
            stack.clone(),
        ));
        pin(&local, "device-remote", 78);
        local.record_peer_substrate_reachability(
            "device-remote",
            Some(SubstrateReachability { direct: vec![direct], relays: Vec::new() }),
        );

        local.record_peer_substrate_reachability("device-remote", None);

        assert_eq!(
            resolved(&stack, remote_peer),
            Some((vec![direct], Vec::new())),
            "an absent field is not an authoritative claim of no reachability"
        );
    }

    /// Gate: an explicitly empty field IS that claim, and clears.
    ///
    /// The counterpart to the test above, and the reason the two cannot share
    /// one representation: "not told" and "told nowhere" must stay different.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_explicitly_empty_field_clears_what_was_known() {
        let (local, _d1) = device("device-local", 79);
        let (remote, _d2) = device("device-remote", 80);
        init_staging_schema(&local);
        let remote_peer = peer_id_of(&remote);
        let direct: std::net::SocketAddr = "192.0.2.11:41000".parse().unwrap();

        let stack = Arc::new(
            SyncStack::spawn(
                local.clone(),
                Arc::new(FixtureAuthenticator),
                yadorilink_sync_substrate::NetworkConfig::direct_only(),
            )
            .await
            .unwrap(),
        );
        local.install_reconciliation_driver(ReconciliationDriver::start(
            local.clone(),
            stack.clone(),
        ));
        pin(&local, "device-remote", 80);
        local.record_peer_substrate_reachability(
            "device-remote",
            Some(SubstrateReachability { direct: vec![direct], relays: Vec::new() }),
        );

        local.record_peer_substrate_reachability(
            "device-remote",
            Some(SubstrateReachability::default()),
        );

        assert_eq!(
            resolved(&stack, remote_peer),
            Some((Vec::new(), Vec::new())),
            "an explicitly empty field must clear, not be ignored as a no-op"
        );
    }

    /// Gate: a newer snapshot replaces an older one outright.
    ///
    /// A push is a snapshot, not a delta, so the old direct address must not
    /// survive alongside the new one -- a peer that rebound would otherwise
    /// keep being dialled at an address nothing answers on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_newer_snapshot_replaces_an_older_one() {
        let (local, _d1) = device("device-local", 81);
        let (remote, _d2) = device("device-remote", 82);
        init_staging_schema(&local);
        let remote_peer = peer_id_of(&remote);
        let old: std::net::SocketAddr = "192.0.2.12:41000".parse().unwrap();
        let new: std::net::SocketAddr = "192.0.2.12:42000".parse().unwrap();

        let stack = Arc::new(
            SyncStack::spawn(
                local.clone(),
                Arc::new(FixtureAuthenticator),
                yadorilink_sync_substrate::NetworkConfig::direct_only(),
            )
            .await
            .unwrap(),
        );
        local.install_reconciliation_driver(ReconciliationDriver::start(
            local.clone(),
            stack.clone(),
        ));
        pin(&local, "device-remote", 82);

        local.record_peer_substrate_reachability(
            "device-remote",
            Some(SubstrateReachability { direct: vec![old], relays: Vec::new() }),
        );
        local.record_peer_substrate_reachability(
            "device-remote",
            Some(SubstrateReachability { direct: vec![new], relays: Vec::new() }),
        );

        assert_eq!(
            resolved(&stack, remote_peer),
            Some((vec![new], Vec::new())),
            "the older address must not survive a newer snapshot"
        );
    }

    /// Gate: the pinned signing key alone decides the endpoint id.
    ///
    /// The field carries no identity on purpose. If it ever grows one, this is
    /// what fails: reachability recorded for a device projects under that
    /// device's PINNED key, and under no other.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pinned_key_alone_decides_the_endpoint_id() {
        let (local, _d1) = device("device-local", 83);
        let (remote, _d2) = device("device-remote", 84);
        let (other, _d3) = device("device-other", 85);
        init_staging_schema(&local);
        let direct: std::net::SocketAddr = "192.0.2.13:41000".parse().unwrap();

        let stack = Arc::new(
            SyncStack::spawn(
                local.clone(),
                Arc::new(FixtureAuthenticator),
                yadorilink_sync_substrate::NetworkConfig::direct_only(),
            )
            .await
            .unwrap(),
        );
        local.install_reconciliation_driver(ReconciliationDriver::start(
            local.clone(),
            stack.clone(),
        ));
        pin(&local, "device-remote", 84);
        local.record_peer_substrate_reachability(
            "device-remote",
            Some(SubstrateReachability { direct: vec![direct], relays: Vec::new() }),
        );

        assert_eq!(resolved(&stack, peer_id_of(&remote)), Some((vec![direct], Vec::new())));
        assert_eq!(
            resolved(&stack, peer_id_of(&other)),
            None,
            "reachability must project under the pinned key and no other identity"
        );
    }
    /// Gate: a previously unknown peer arriving in ONE netmap becomes dialable,
    /// with no manual pin and no second push.
    ///
    /// This is the ordering production actually runs, and the one the earlier
    /// fixes missed. A netmap pass records addresses BEFORE it installs signing
    /// keys (`record_peer_*` then `apply_authoritative_peer_metadata`), so for
    /// a first-time peer the projection finds no endpoint id and writes
    /// nothing. The key lands moments later, and nothing re-projects -- and
    /// because a push is a snapshot, a repeat of the same netmap is no change
    /// and writes nothing again. The peer stays undialable until the plane
    /// happens to report something DIFFERENT about it.
    ///
    /// Every earlier test pinned the key first, which is exactly why none of
    /// them could see this.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_first_time_peer_in_one_netmap_becomes_dialable() {
        let (local, _d1) = device("device-local", 87);
        let (remote, _d2) = device("device-remote", 88);
        init_staging_schema(&local);
        let remote_peer = peer_id_of(&remote);
        let direct: std::net::SocketAddr = "192.0.2.14:41000".parse().unwrap();

        let stack = Arc::new(
            SyncStack::spawn(
                local.clone(),
                Arc::new(FixtureAuthenticator),
                yadorilink_sync_substrate::NetworkConfig::direct_only(),
            )
            .await
            .unwrap(),
        );
        local.install_reconciliation_driver(ReconciliationDriver::start(
            local.clone(),
            stack.clone(),
        ));

        // One netmap pass, in the order `peer_orchestrator` runs it: addresses
        // first, identity second. No `pin` -- this peer has never been seen.
        local.record_peer_substrate_reachability(
            "device-remote",
            Some(SubstrateReachability { direct: vec![direct], relays: Vec::new() }),
        );
        local.replace_peer_netmap_metadata(
            "device-remote",
            Some(remote.device_signing_key().unwrap().verifying_key().to_bytes()),
            &std::iter::once(GROUP.to_string()).collect(),
            &Default::default(),
        );

        assert_eq!(
            resolved(&stack, remote_peer),
            Some((vec![direct], Vec::new())),
            "a first-time peer must be dialable from the one netmap that introduced it"
        );
    }
}

/// Gate: two daemons converge over a genuinely direct path, on the link the
/// transfer actually used, with the address arriving by way of an applied
/// netmap.
///
/// Precisely, this is a *production applied-netmap -> projection -> Iroh dial*
/// gate. It is not a claim that the address travelled the whole plane: the
/// Worker POST, the durable Worker state and the websatch push are not in this
/// process, and the calls below stand in for their output. That round trip is
/// covered by the Worker's own suite, and the S3 canary is where the two halves
/// finally meet in one line.
///
/// What is asserted here:
///
///   relays disabled                no relay exists to fall back to
///   address via applied netmap     nothing injected into the directory
///   convergence                    the Change actually arrives
///   witness on every dialled link  not one connection mistaken for the whole
///   witness open before the bytes  subscribed before anything moves
///   witness says direct only       proven from path events, not assumed
///
/// The last three are what make the first three mean anything. "Relays are
/// disabled, so it must have been direct" is an argument about configuration,
/// and a benchmark that reasons that way cannot tell a direct transfer from one
/// that quietly found another route.
///
/// Which link is watched matters as much as when. A peer's traffic is spread
/// over more than one connection -- reconciliation dials its own, and the bulk
/// lanes dial another through `link_to` -- so a watcher placed on either one by
/// hand reports a fraction as the total. Measured here, the two carried 16,836
/// and 7,914 direct bytes of the same exchange. `when_link_dialed` fires on
/// every dial, which is what makes the set complete rather than merely
/// plausible.
///
/// What this does NOT cover: file content. The Change and its `FileVersion`
/// travel in the proof-carrying bundle, and the receiver converges on them
/// without fetching a single block -- raising the payload to 256 KiB leaves
/// both witnesses near 20 KB, because block bytes only move when something
/// asks for them. So this gates the DAG path, not a file transfer. The S3
/// canary measures block-lane throughput and therefore has to drive a real
/// fetch; this gate's guarantee is that when it does, every link it crosses is
/// already in view.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_daemons_converge_over_a_proven_direct_path() {
    // iroh buffers 8 path events per connection and drops the oldest when a
    // subscriber falls behind, which under a loaded machine happens here about
    // one attempt in twelve. That is a fact about this machine's scheduling,
    // not about the path, and the witness correctly refuses to vouch for
    // totals it knows are partial.
    //
    // So an attempt that cannot see is retried, and an attempt that sees a
    // relay is not. Collapsing the two -- retrying until something passes --
    // would turn a real relay into a flake and eventually into a green run.
    use yadorilink_sync_substrate::TransferVerdict;

    const ATTEMPTS: usize = 5;
    let mut gaps = Vec::new();
    for attempt in 1..=ATTEMPTS {
        match direct_path_attempt().await {
            TransferVerdict::Direct { .. } => return,
            TransferVerdict::NotDirect(why) => {
                panic!("convergence happened, but the path it used is not direct: {why}")
            }
            TransferVerdict::Inconclusive(why) => {
                eprintln!("attempt {attempt} could not vouch for its totals: {why}");
                gaps.push(why);
            }
        }
    }
    panic!(
        "{ATTEMPTS} attempts all lost path events, so none could support or refute a \
         direct-path claim: {gaps:?}"
    );
}

/// Gate: the evidence a black-box daemon leaves behind.
///
/// Everything else here reads the witness from inside the test process. A
/// harness driving two real daemons over SSH cannot do that: it sees bytes
/// arrive and has no way to ask which carrier brought them. The sink is the
/// only route out, so this drives a real convergence through it and reads
/// the file, rather than trusting that the pieces would have fitted.
///
/// What this does not cover, and what the canary therefore must: the
/// environment variable that names the file, and the call site in
/// `peer_orchestrator` that installs the sink between the stack starting and
/// the driver starting. Those are one line each, and the second one's
/// ordering is the part that matters -- it is the last moment before a link
/// can exist.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_writes_out_which_carrier_its_transfer_used() {
    let evidence = tempfile::tempdir().expect("a place to write the evidence");
    let report = evidence.path().join("paths.json");

    // Same retry rule as the gate above, and for the same reason: a lost
    // event is the absence of an answer, not a relay. The verdict written to
    // the file is what decides, since that is all a harness will ever see.
    let mut written = String::new();
    for _ in 1..=5 {
        let sink = crate::path_witness_sink::PathWitnessSink::new(report.clone(), 1);
        // Installed before the driver, exactly as production does it.
        converge_once(Some(sink.clone())).await;
        sink.flush().await;
        written = std::fs::read_to_string(&report).expect("the daemon wrote no evidence at all");
        assert!(
            !written.contains("\"verdict\":\"not_direct\""),
            "the transfer did not go direct: {written}"
        );
        if written.contains("\"verdict\":\"direct\"") {
            break;
        }
    }

    assert!(
        written.contains("\"verdict\":\"direct\""),
        "the file must carry the verdict a harness will read: {written}"
    );
    assert!(
        written.contains("\"direct_tx_bytes\""),
        "and the per-connection detail behind it: {written}"
    );
    assert!(
        !written.contains("\"relay_tx_bytes\":0,\"relay_rx_bytes\":0,\"other_tx_bytes\":0,\"other_rx_bytes\":0,\"direct_path_opened\":false"),
        "a connection that opened no direct path cannot be the one that carried it: {written}"
    );
}

async fn direct_path_attempt() -> yadorilink_sync_substrate::TransferVerdict {
    converge_once(None).await
}

async fn converge_once(
    sink: Option<std::sync::Arc<crate::path_witness_sink::PathWitnessSink>>,
) -> yadorilink_sync_substrate::TransferVerdict {
    let group = FolderGroupId(GROUP.into());
    let (author, _author_dir) = device("device-author", 91);
    let (receiver, _receiver_dir) = device("device-receiver", 92);
    for state in [&author, &receiver] {
        init_staging_schema(state);
    }
    pin(&author, "device-receiver", 92);
    pin(&receiver, "device-author", 91);

    // No relay is configured at all, so there is nothing to fall back to and a
    // direct path is the only way anything converges.
    let author_stack = Arc::new(
        SyncStack::spawn(
            author.clone(),
            Arc::new(FixtureAuthenticator),
            yadorilink_sync_substrate::NetworkConfig::direct_only(),
        )
        .await
        .unwrap(),
    );
    let receiver_stack = Arc::new(
        SyncStack::spawn(
            receiver.clone(),
            Arc::new(FixtureAuthenticator),
            yadorilink_sync_substrate::NetworkConfig::direct_only(),
        )
        .await
        .unwrap(),
    );

    let author_direct: Vec<std::net::SocketAddr> =
        author_stack.local_address().direct_addrs().copied().collect();
    let receiver_direct: Vec<std::net::SocketAddr> =
        receiver_stack.local_address().direct_addrs().copied().collect();
    assert!(!author_direct.is_empty(), "a direct-only node must have a direct address to publish");

    let author_driver = ReconciliationDriver::start(author.clone(), author_stack.clone());
    author.install_reconciliation_driver(author_driver.clone());
    receiver.install_reconciliation_driver(ReconciliationDriver::start(
        receiver.clone(),
        receiver_stack.clone(),
    ));

    // Exactly what an applied netmap push does, and nothing else. No
    // `address_directory().record(..)` anywhere in this test.
    author.record_peer_substrate_reachability(
        "device-receiver",
        Some(crate::coordination_client::SubstrateReachability {
            direct: receiver_direct,
            relays: Vec::new(),
        }),
    );
    receiver.record_peer_substrate_reachability(
        "device-author",
        Some(crate::coordination_client::SubstrateReachability {
            direct: author_direct,
            relays: Vec::new(),
        }),
    );

    // Subscribe on the link reconciliation dials, at the moment it dials it
    // -- before the first lane opens, so nothing the transfer does happens
    // outside the witness. Installed before the Change is staged, because
    // after `note_local_change` the dial is already racing this thread.
    let watchers: Arc<std::sync::Mutex<Vec<yadorilink_sync_substrate::PathWatcher>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    // A sink, when one is supplied, installs its own hook here -- the same
    // point production uses, between the stack starting and the driver
    // starting. Otherwise the attempt collects watchers directly.
    match &sink {
        Some(sink) => sink.install(&author_stack),
        None => {
            let observed = watchers.clone();
            author_stack.when_link_dialed(Arc::new(
                move |link: &yadorilink_sync_substrate::PeerLink| {
                    observed.lock().expect("watchers poisoned").push(link.watch_paths());
                },
            ));
        }
    }

    let version = file_version(4096, 0x7E);
    let change = change_putting("direct-path.bin", &version);
    author
        .replica_coordinator
        .database()
        .write_immediate::<_, SyncSqliteError>(|conn| {
            verified_change_store::stage_verified_bundles(
                conn,
                std::slice::from_ref(&honest_bundle_carrying(
                    change.clone(),
                    vec![version.clone()],
                )),
                1,
            )
        })
        .unwrap();

    author_driver.note_local_change(&group);
    assert!(
        within(90, || possessed(&receiver, &group) == vec![change.compute_hash()]).await,
        "the receiver never took delivery over the direct path"
    );

    // The verdict, from path events on the links that carried the transfer
    // rather than from configuration. Every witness is collected before any
    // of them is judged: a relay on one connection must outrank a lost event
    // on another, which is impossible to get right while returning from
    // inside the loop.
    // With a sink installed the watchers belong to it, and it will judge and
    // write them; report success here so the caller can then flush it.
    if sink.is_some() {
        return yadorilink_sync_substrate::TransferVerdict::Direct { direct_bytes: 0 };
    }
    let watchers = std::mem::take(&mut *watchers.lock().expect("watchers poisoned"));
    let mut witnesses = Vec::with_capacity(watchers.len());
    for watcher in watchers {
        witnesses.push(watcher.finish().await);
    }
    // No payload floor here: the Change converges without a block fetch, so
    // this attempt has no volume to expect. The S3 canary passes 1 GiB.
    yadorilink_sync_substrate::verdict_for(&witnesses, 1)
}

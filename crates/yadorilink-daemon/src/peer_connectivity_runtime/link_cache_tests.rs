//! The per-peer link cache: one device's dial never holds up another's link.
//!
//! A device that is registered but offline makes its dial run to its deadline.
//! Every other device's link, and every block fetch riding on it, must stay
//! unaffected for that whole time.

use std::future::pending;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::daemon_state::DaemonState;
use yadorilink_sync_substrate::{NetworkConfig, PeerLink};

use crate::sync_adapter::sync_stack::SyncStack;
use crate::test_support::sync_stack_fixture::{device, pin};

const ALICE: &str = "device-alice";
const BOB: &str = "device-bob";
const DEAD: &str = "device-dead";

const STEP: Duration = Duration::from_secs(10);

type Dial = Result<PeerLink, &'static str>;

/// What a test needs of the two devices.
struct Fixture {
    bob: Arc<SyncStack>,
    bob_state: Arc<DaemonState>,
    _alice: SyncStack,
    _dirs: (
        crate::test_support::sync_stack_fixture::ReleasingDir,
        crate::test_support::sync_stack_fixture::ReleasingDir,
    ),
}

/// Bob pins a reachable Alice and a registered-but-offline `DEAD`.
async fn bob_with_dead_peer() -> Fixture {
    let (alice, alice_dir) = device(ALICE, 11);
    let (bob_state, bob_dir) = device(BOB, 22);
    pin(&alice, BOB, 22);
    pin(&bob_state, ALICE, 11);
    pin(&bob_state, DEAD, 33);
    let alice_stack =
        SyncStack::spawn(alice, NetworkConfig::direct_only()).await.expect("alice starts");
    let bob_stack = SyncStack::spawn(bob_state.clone(), NetworkConfig::direct_only())
        .await
        .expect("bob starts");
    SyncStack::teach_each_other_for_tests(&alice_stack, &bob_stack);
    Fixture {
        bob: Arc::new(bob_stack),
        bob_state,
        _alice: alice_stack,
        _dirs: (alice_dir, bob_dir),
    }
}

/// A real dial to `peer` through bob's runtime, counted.
fn counted_dial(
    bob: &Arc<SyncStack>,
    dials: &Arc<AtomicUsize>,
) -> impl FnOnce(
    yadorilink_sync_substrate::PeerId,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Dial> + Send>> {
    let (bob, dials) = (bob.clone(), dials.clone());
    move |peer| {
        Box::pin(async move {
            dials.fetch_add(1, Ordering::SeqCst);
            bob.runtime_for_tests().connect(peer).await.map_err(|_| "dial failed")
        })
    }
}

fn spawn_stuck_dial(bob: &Arc<SyncStack>, device: &'static str) -> tokio::task::JoinHandle<()> {
    let bob = bob.clone();
    tokio::spawn(async move {
        let _ = bob.endpoint().link_to(device, |_| pending::<Dial>()).await;
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_that_never_completes_does_not_block_another_devices_link() {
    let fx = bob_with_dead_peer().await;
    let stuck = spawn_stuck_dial(&fx.bob, DEAD);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The healthy peer's lookup answers at once, whatever its own dial does.
    let started = Instant::now();
    let answer = tokio::time::timeout(
        Duration::from_secs(2),
        fx.bob.endpoint().link_to(ALICE, |_| async { Err::<PeerLink, _>("no dial") }),
    )
    .await
    .expect("alice's link is blocked behind the dead peer's dial");
    assert!(answer.is_err());
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "alice's link waited {:?} behind the dead peer's dial",
        started.elapsed()
    );

    // And a real dial to her completes while the other is still in flight.
    tokio::time::timeout(STEP, fx.bob.link_to(ALICE))
        .await
        .expect("alice's dial must not wait for the dead peer's")
        .expect("bob reaches alice");
    assert!(!stuck.is_finished(), "precondition: the dead peer's dial is still in flight");
    stuck.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hundred_concurrent_callers_for_one_device_dial_once() {
    let fx = bob_with_dead_peer().await;
    let dials = Arc::new(AtomicUsize::new(0));
    let mut callers = Vec::new();
    for _ in 0..100 {
        let (bob, dials) = (fx.bob.clone(), dials.clone());
        callers.push(tokio::spawn(async move {
            let dial = counted_dial(&bob, &dials);
            bob.endpoint().link_to(ALICE, dial).await.unwrap().expect("pinned")
        }));
    }
    let mut links = Vec::new();
    for caller in callers {
        links.push(tokio::time::timeout(STEP, caller).await.expect("no caller hangs").unwrap());
    }
    assert_eq!(dials.load(Ordering::SeqCst), 1, "callers for one device must share one dial");
    assert!(links.iter().all(|link| Arc::ptr_eq(link, &links[0])));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_dial_does_not_poison_the_next_call() {
    let fx = bob_with_dead_peer().await;
    let dials = Arc::new(AtomicUsize::new(0));
    let counter = dials.clone();
    let failed = fx
        .bob
        .endpoint()
        .link_to(ALICE, move |_| async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Err::<PeerLink, _>("first dial fails")
        })
        .await;
    assert!(failed.is_err());

    let dial = counted_dial(&fx.bob, &dials);
    tokio::time::timeout(STEP, fx.bob.endpoint().link_to(ALICE, dial))
        .await
        .expect("must not hang")
        .expect("the failure left nothing behind")
        .expect("pinned");
    assert_eq!(dials.load(Ordering::SeqCst), 2, "the next call dials again");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_dial_leaves_no_stuck_entry() {
    let fx = bob_with_dead_peer().await;
    let stuck = spawn_stuck_dial(&fx.bob, ALICE);
    tokio::time::sleep(Duration::from_millis(100)).await;
    stuck.abort();
    let _ = stuck.await;
    tokio::time::timeout(STEP, fx.bob.link_to(ALICE))
        .await
        .expect("a cancelled caller must not hold the device's entry")
        .expect("bob reaches alice");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_live_cached_link_is_reused_without_dialling() {
    let fx = bob_with_dead_peer().await;
    let first = tokio::time::timeout(STEP, fx.bob.link_to(ALICE)).await.unwrap().unwrap();
    let dialled = Arc::new(AtomicUsize::new(0));
    let counter = dialled.clone();
    let again = fx
        .bob
        .endpoint()
        .link_to(ALICE, move |_| async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Err::<PeerLink, _>("must not dial")
        })
        .await
        .unwrap()
        .expect("pinned");
    assert!(Arc::ptr_eq(&first, &again));
    assert_eq!(dialled.load(Ordering::SeqCst), 0);
}

/// A device revoked while its dial is in flight must not come out of that
/// dial as a cached link: the dial finishes, and the link is closed unused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_revoked_during_its_dial_is_not_cached() {
    let fx = bob_with_dead_peer().await;
    let release = Arc::new(tokio::sync::Notify::new());
    let dials = Arc::new(AtomicUsize::new(0));
    let in_flight = {
        let (bob, release, dials) = (fx.bob.clone(), release.clone(), dials.clone());
        tokio::spawn(async move {
            let dial = counted_dial(&bob, &dials);
            bob.endpoint()
                .link_to(ALICE, move |peer| async move {
                    // Connected, but not yet handed back to the cache.
                    let link = dial(peer).await;
                    release.notified().await;
                    link
                })
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The order `teardown_peer` uses: withdraw the key, then sweep.
    let key = fx.bob_state.authority.peer_signing_key(ALICE);
    fx.bob_state.clear_peer_netmap_metadata(ALICE);
    fx.bob_state.peer_connectivity.revoke_device(ALICE, key);
    release.notify_one();

    let outcome = tokio::time::timeout(STEP, in_flight).await.expect("dial finishes").unwrap();
    assert!(
        matches!(outcome, Ok(None)),
        "a revoked device's link must not be handed out, got {:?}",
        outcome.as_ref().map(|link| link.is_some())
    );

    // Pinned again, nothing from the revoked dial is left to be served.
    pin(&fx.bob_state, ALICE, 11);
    let redialled = Arc::new(AtomicUsize::new(0));
    let counter = redialled.clone();
    let _ = fx
        .bob
        .endpoint()
        .link_to(ALICE, move |_| async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Err::<PeerLink, _>("probe")
        })
        .await;
    assert_eq!(redialled.load(Ordering::SeqCst), 1, "no link survived the revocation in the cache");
}

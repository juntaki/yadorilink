#![cfg(test)]

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

/// A flight whose work fails must release its key, so a later attempt
/// for the same pair can claim and run it.
///
/// This is the whole reason the network steps of `sync_once` carry
/// deadlines. The key is held for as long as the work future runs, and
/// nothing else can clear it: a step that never returns keeps the pair
/// claimed forever, and from then on every attempt -- including the
/// responder-side "you are behind" rescue, which deliberately uses this
/// same single-flighted path -- coalesces and is dropped. Observed in
/// the field as three flights stuck in `connect` for 94s and still
/// stuck at 207s, while their devices sat at a divergent frontier.
///
/// Turning the expiry into an ordinary `Err` is what makes the release
/// automatic: it unwinds through `ReleaseOnDrop` exactly like any other
/// failure, with no separate cleanup path to forget.
#[tokio::test]
async fn a_timed_out_flight_releases_its_key_for_the_next_attempt() {
    let flight = SingleFlight::<&str>::new();

    // A network step that never completes, bounded by a deadline. The
    // sleep is far longer than the timeout, so the timeout is what ends
    // it -- not the sleep elapsing.
    let stalled = flight
        .run("peer/group", || async {
            match tokio::time::timeout(
                std::time::Duration::from_millis(20),
                tokio::time::sleep(std::time::Duration::from_secs(3_600)),
            )
            .await
            {
                Ok(()) => Ok(()),
                Err(_) => Err("network step timed out"),
            }
        })
        .await;
    assert_eq!(stalled, Err("network step timed out"));

    // The key must be free again. Before deadlines existed this second
    // call returned `Flight::Coalesced` forever.
    let runs = AtomicUsize::new(0);
    let outcome = flight
        .run("peer/group", || async {
            runs.fetch_add(1, Ordering::SeqCst);
            Ok::<_, &str>(())
        })
        .await
        .unwrap();

    assert_eq!(
        outcome,
        Flight::Ran { passes: 1 },
        "a released key must be claimable, not coalesced into the dead flight"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 1);
}

/// A wake landing at the terminal settle boundary must not be lost.
///
/// The window is between the runner deciding it is settled and the key
/// actually becoming free. Those were two separate critical sections, so
/// a `wake` + `claim` could interleave: the runner had already committed
/// to returning, the newcomer saw the key still held and coalesced, and
/// then the runner released it. The epoch had moved, nobody owned the
/// key, and nothing was scheduled to look again -- the wake was gone.
///
/// This is not hypothetical latency. Every later attempt for that key
/// coalesces only while someone holds it; here nobody does, so the next
/// caller does claim it -- but only if something calls again. Where the
/// wake WAS the call, as with admission scheduling, nothing ever does.
///
/// The invariant: a wake is always consumed, either by a further pass of
/// the current owner or by a new owner. It may never end with the key
/// idle and the epoch unconsumed.
#[tokio::test]
async fn a_wake_at_the_terminal_settle_boundary_is_not_lost() {
    let flight = Arc::new(SingleFlight::<&str>::new());
    let coalesced_in_window = Arc::new(AtomicUsize::new(0));

    {
        let inner = flight.clone();
        let seen = coalesced_in_window.clone();
        // Stands in for a scheduler that marks the view stale and starts a
        // drain at the exact instant the runner has decided it is settled.
        settle_hook::set(move || {
            inner.wake(&"peer/group");
            match inner.claim(&"peer/group") {
                None => {
                    seen.fetch_add(1, Ordering::SeqCst);
                }
                Some(generation) => inner.release(&"peer/group", generation),
            }
        });
    }

    let outcome = flight.run("peer/group", || async { Ok::<_, ()>(()) }).await.unwrap();
    settle_hook::clear();
    // The invariant, stated as the only two acceptable ends:
    //
    //   A. the newcomer was turned away (the key was still held), and the
    //      owner therefore consumed the wake with a further pass; or
    //   B. the newcomer took the key, because settling had already
    //      completed -- so it owns the wake instead.
    //
    // What must never happen is the newcomer being turned away AND the
    // owner settling anyway: that ends with the key idle, the epoch
    // unconsumed, and nothing scheduled to look again. Where the wake was
    // itself the only scheduling event -- admission is exactly this --
    // nothing ever looks again at all.
    let turned_away = coalesced_in_window.load(Ordering::SeqCst) == 1;
    assert!(
        !turned_away || outcome == Flight::Ran { passes: 2 },
        "a wake raised before the key was released must be consumed: the newcomer \
         coalesced, so the owner owed a further pass, but it settled after {outcome:?}"
    );
}

#[tokio::test]
async fn a_quiet_key_runs_exactly_once() {
    let flight = SingleFlight::<&str>::new();
    let runs = AtomicUsize::new(0);

    let outcome = flight
        .run("peer/group", || async {
            runs.fetch_add(1, Ordering::SeqCst);
            Ok::<_, ()>(())
        })
        .await
        .unwrap();

    assert_eq!(outcome, Flight::Ran { passes: 1 });
    assert_eq!(runs.load(Ordering::SeqCst), 1);
}

/// The property that keeps a burst from becoming a storm: many wake-ups
/// during one pass produce exactly one further pass, not one per wake-up.
#[tokio::test]
async fn a_burst_of_wakes_during_a_pass_costs_exactly_one_more_pass() {
    let flight = Arc::new(SingleFlight::<&str>::new());
    let runs = Arc::new(AtomicUsize::new(0));

    let outcome = {
        let flight = flight.clone();
        let runs = runs.clone();
        flight
            .clone()
            .run("peer/group", || {
                let flight = flight.clone();
                let runs = runs.clone();
                async move {
                    let pass = runs.fetch_add(1, Ordering::SeqCst);
                    if pass == 0 {
                        // 50 arrivals land while the first pass runs.
                        for _ in 0..50 {
                            flight.wake(&"peer/group");
                        }
                    }
                    Ok::<_, ()>(())
                }
            })
            .await
            .unwrap()
    };

    assert_eq!(outcome, Flight::Ran { passes: 2 });
    assert_eq!(runs.load(Ordering::SeqCst), 2, "50 wake-ups must not mean 50 passes");
}

#[tokio::test]
async fn a_second_caller_for_the_same_key_does_not_start_a_second_reconciliation() {
    let flight = Arc::new(SingleFlight::<&str>::new());
    let runs = Arc::new(AtomicUsize::new(0));
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let release_rx = Arc::new(tokio::sync::Mutex::new(Some(release_rx)));

    let first = {
        let flight = flight.clone();
        let runs = runs.clone();
        let release_rx = release_rx.clone();
        tokio::spawn(async move {
            flight
                .run("peer/group", || {
                    let runs = runs.clone();
                    let release_rx = release_rx.clone();
                    async move {
                        runs.fetch_add(1, Ordering::SeqCst);
                        if let Some(rx) = release_rx.lock().await.take() {
                            let _ = rx.await;
                        }
                        Ok::<_, ()>(())
                    }
                })
                .await
        })
    };

    // Wait until the first pass is definitely inside `work`.
    while runs.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }

    let second = flight.run("peer/group", || async { Ok::<_, ()>(()) }).await.unwrap();
    assert_eq!(second, Flight::Coalesced);

    release_tx.send(()).unwrap();
    assert_eq!(first.await.unwrap().unwrap(), Flight::Ran { passes: 1 });
    assert_eq!(runs.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn different_keys_do_not_block_each_other() {
    let flight = SingleFlight::<&str>::new();

    assert_eq!(
        flight.run("peer-a/group", || async { Ok::<_, ()>(()) }).await.unwrap(),
        Flight::Ran { passes: 1 }
    );
    assert_eq!(
        flight.run("peer-b/group", || async { Ok::<_, ()>(()) }).await.unwrap(),
        Flight::Ran { passes: 1 }
    );
}

#[tokio::test]
async fn a_failed_pass_releases_the_key() {
    let flight = SingleFlight::<&str>::new();

    let failed: Result<Flight, &str> =
        flight.run("peer/group", || async { Err::<(), _>("port failed") }).await;
    assert_eq!(failed, Err("port failed"));

    // The next attempt must not be reported as coalesced behind a run
    // that already ended.
    assert_eq!(
        flight.run("peer/group", || async { Ok::<_, ()>(()) }).await.unwrap(),
        Flight::Ran { passes: 1 }
    );
}

#[tokio::test]
async fn a_wake_after_a_pass_finishes_causes_a_new_pass() {
    let flight = SingleFlight::<&str>::new();
    let runs = AtomicUsize::new(0);

    for _ in 0..3 {
        flight
            .run("peer/group", || async {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok::<_, ()>(())
            })
            .await
            .unwrap();
        flight.wake(&"peer/group");
    }

    assert_eq!(runs.load(Ordering::SeqCst), 3);
}

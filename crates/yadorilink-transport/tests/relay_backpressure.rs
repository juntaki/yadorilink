//! Write readiness has to answer for the carrier that actually refused the
//! send, not for whichever carrier happens to be free.
//!
//! A hub sends through three independent carriers -- the IPv4 socket, the
//! IPv6 socket, and the bounded queue in front of the relay control
//! connection -- but quinn's `UdpPoller` carries no destination, so one
//! poller stands for all three. If that poller answers "writable" because
//! *some* carrier is free while the one that blocked is still full, quinn
//! retries immediately, gets `WouldBlock` again, and the pair spins: not a
//! wait, a busy loop. That is not hypothetical -- an earlier version of this
//! answered from the relay queue first and burned 600% CPU.
//!
//! Reordering the two only moves which case spins. This pins the property
//! that actually matters: readiness is reported for the blocked carrier, and
//! for nothing else.
#![cfg(not(madsim))]

use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Wake, Waker};
use std::time::Duration;

use yadorilink_transport::{RelayControlEgress, TransportHub};

/// A relay egress the test can hold still, so the control queue fills
/// instead of draining as fast as it is written. Stalling the writer is the
/// only way to reach a full queue deterministically -- in production it
/// fills when the control connection to the relay backs up, which is
/// exactly what this stands in for.
struct StalledEgress {
    gate: Arc<StdMutex<()>>,
}

impl RelayControlEgress for StalledEgress {
    fn send_relay_data(&self, _payload: Vec<u8>) -> bool {
        let _held = self.gate.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        true
    }
}

#[derive(Default)]
struct RecordingWaker {
    woken: AtomicBool,
}

impl Wake for RecordingWaker {
    fn wake(self: Arc<Self>) {
        self.woken.store(true, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.woken.store(true, Ordering::SeqCst);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_relay_queue_parks_the_poller_even_though_the_socket_is_writable() {
    let hub = TransportHub::bind((Ipv4Addr::LOCALHOST, 0).into()).await.expect("bind hub");
    let gate = Arc::new(StdMutex::new(()));
    // Taken before the path exists, so the writer task stalls on its very
    // first dequeue and nothing drains behind our back.
    let held = gate.lock().expect("uncontended");

    let path = hub
        .open_relay_path(Arc::new(StalledEgress { gate: gate.clone() }))
        .expect("a hub with no relay paths can open one");
    let relayed_peer = path.synthetic_addr();

    // Fill the queue. The loop is bounded so a regression that never refuses
    // fails the test instead of hanging it.
    let mut refused = false;
    for _ in 0..10_000 {
        match hub.try_send_datagram(&[0xC0u8; 64], relayed_peer) {
            Ok(()) => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                refused = true;
                break;
            }
            Err(error) => panic!("unexpected relay send failure: {error}"),
        }
    }
    assert!(refused, "a bounded relay queue must report WouldBlock once it is full");

    // The physical socket is demonstrably writable, so the assertion below
    // is about which carrier readiness is reported for -- not about a socket
    // that happens to be full too.
    hub.try_send_datagram(b"probe", hub.local_addr()).expect("the physical socket is writable");

    let poller = TransportHub::next_send_poller_id();
    let waker = Arc::new(RecordingWaker::default());
    let cx_waker: Waker = waker.clone().into();
    let mut cx = Context::from_waker(&cx_waker);

    assert!(
        hub.poll_quic_send_ready(poller, &mut cx).is_pending(),
        "the relay queue is what refused the send, so write readiness must park on it rather \
         than answering for a socket the blocked send was never going to use -- answering here \
         is what turns a wait into a spin"
    );
    assert!(!waker.woken.load(Ordering::SeqCst), "nothing has drained yet");

    // Release the writer. Draining the queue is what the parked poller is
    // waiting for, so it must be woken by it.
    drop(held);

    let mut woken = false;
    for _ in 0..500 {
        if waker.woken.load(Ordering::SeqCst) {
            woken = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(woken, "draining the relay control queue must wake the poller parked on it");

    assert!(
        hub.poll_quic_send_ready(poller, &mut cx).is_ready(),
        "once the relay queue has room again, write readiness must report it"
    );
}

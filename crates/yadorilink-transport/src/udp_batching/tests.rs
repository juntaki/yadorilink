#![cfg(test)]

use super::*;

#[test]
fn batching_mode_is_detected_at_startup() {
    let support = UdpBatchingSupport::detect();

    assert_eq!(support.mode(), UdpBatchingMode::SingleDatagramFallback);
}

#[test]
fn fallback_mode_is_reported_as_not_using_kernel_batching() {
    let support = UdpBatchingSupport { mode: UdpBatchingMode::SingleDatagramFallback };

    assert!(!support.uses_kernel_batching());
}

// Binds a real socket, so it is a native-only test: under either
// simulator the socket type belongs to a simulated world this test
// never enters. What it asserts -- dual-stack selection, port
// stability, ALPN routing on a real endpoint -- is about the
// operating system's sockets, which is exactly what a simulator
// does not model and does not need to.
#[cfg(not(turmoil))]
#[tokio::test]
async fn fallback_send_batch_preserves_datagram_boundaries_and_order() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let support = UdpBatchingSupport { mode: UdpBatchingMode::SingleDatagramFallback };
    let datagrams = vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()];

    let sent =
        support.send_batch(&sender, &datagrams, receiver.local_addr().unwrap()).await.unwrap();

    assert_eq!(sent, datagrams.len());
    for expected in datagrams {
        let mut buf = [0u8; 16];
        let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], expected.as_slice());
    }
}

// Binds a real socket, so it is a native-only test: under either
// simulator the socket type belongs to a simulated world this test
// never enters. What it asserts -- dual-stack selection, port
// stability, ALPN routing on a real endpoint -- is about the
// operating system's sockets, which is exactly what a simulator
// does not model and does not need to.
#[cfg(not(turmoil))]
#[tokio::test]
async fn fallback_try_recv_batch_drains_ready_datagrams() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let support = UdpBatchingSupport { mode: UdpBatchingMode::SingleDatagramFallback };

    sender.send_to(b"one", receiver.local_addr().unwrap()).await.unwrap();
    sender.send_to(b"two", receiver.local_addr().unwrap()).await.unwrap();
    receiver.readable().await.unwrap();

    let received = support.try_recv_batch(&receiver, 8, 16).await.unwrap();

    let payloads: Vec<Vec<u8>> = received.into_iter().map(|d| d.bytes).collect();
    assert_eq!(payloads, vec![b"one".to_vec(), b"two".to_vec()]);
}

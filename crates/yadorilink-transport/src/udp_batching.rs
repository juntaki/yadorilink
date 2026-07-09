//! UDP batching capability detection and dispatch for the direct datagram path.
//!
//! The actor always has a portable fallback that preserves the exact wire
//! behavior by sending and receiving one datagram at a time. Platforms with
//! kernel datagram batching can grow this module with the actual syscall path
//! without changing the peer-channel state machine.

#[cfg(madsim)]
use std::future::Future;
use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UdpBatchingMode {
    SingleDatagramFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UdpBatchingSupport {
    mode: UdpBatchingMode,
}

impl UdpBatchingSupport {
    pub(crate) fn detect() -> Self {
        Self { mode: detect_mode() }
    }

    pub(crate) fn mode(self) -> UdpBatchingMode {
        self.mode
    }

    pub(crate) fn uses_kernel_batching(self) -> bool {
        uses_kernel_batching(self.mode)
    }

    pub(crate) async fn send_batch(
        self,
        socket: &UdpSocket,
        datagrams: &[Vec<u8>],
        addr: SocketAddr,
    ) -> io::Result<usize> {
        match self.mode {
            UdpBatchingMode::SingleDatagramFallback => {
                send_batch_fallback(socket, datagrams, addr).await
            }
        }
    }

    pub(crate) async fn try_recv_batch(
        self,
        socket: &UdpSocket,
        max_datagrams: usize,
        max_datagram_len: usize,
    ) -> io::Result<Vec<ReceivedDatagram>> {
        match self.mode {
            UdpBatchingMode::SingleDatagramFallback => {
                try_recv_batch_fallback(socket, max_datagrams, max_datagram_len).await
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ReceivedDatagram {
    pub(crate) bytes: Vec<u8>,
    pub(crate) from: SocketAddr,
}

fn detect_mode() -> UdpBatchingMode {
    UdpBatchingMode::SingleDatagramFallback
}

fn uses_kernel_batching(mode: UdpBatchingMode) -> bool {
    match mode {
        UdpBatchingMode::SingleDatagramFallback => false,
    }
}

async fn send_batch_fallback(
    socket: &UdpSocket,
    datagrams: &[Vec<u8>],
    addr: SocketAddr,
) -> io::Result<usize> {
    let mut sent = 0;
    for datagram in datagrams {
        // add-deterministic-sync-testing: see local_discovery.rs's
        // equivalent comment — `madsim`'s simulated `UdpSocket::send_to`
        // takes `(dst, buf)`, the reverse of real tokio's `(buf, dst)`.
        #[cfg(not(madsim))]
        socket.send_to(datagram, addr).await?;
        #[cfg(madsim)]
        socket.send_to(addr, datagram).await?;
        sent += 1;
    }
    Ok(sent)
}

/// add-deterministic-sync-testing: `async` (not a plain non-blocking
/// call) so the same signature works whether or not the platform truly
/// has a non-blocking `try_recv_from` — real tokio's `UdpSocket` does
/// (used as-is below), `madsim`'s simulated `UdpSocket` doesn't, so that
/// branch approximates "return immediately if nothing is ready yet" with
/// a zero-duration `timeout` around the async `recv_from` instead. This
/// method's sole caller (`peer_channel.rs::drain_ready_direct_datagrams`)
/// already awaits it from an `async fn`, so this changes no call-site
/// behavior beyond adding `.await`.
async fn try_recv_batch_fallback(
    socket: &UdpSocket,
    max_datagrams: usize,
    max_datagram_len: usize,
) -> io::Result<Vec<ReceivedDatagram>> {
    let mut received = Vec::with_capacity(max_datagrams);
    for _ in 0..max_datagrams {
        let mut buf = vec![0u8; max_datagram_len];
        let result = recv_from_without_blocking(socket, &mut buf).await;
        match result {
            Ok((n, from)) => {
                buf.truncate(n);
                received.push(ReceivedDatagram { bytes: buf, from });
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock && received.is_empty() => {
                return Err(err)
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(err) => return Err(err),
        }
    }
    Ok(received)
}

#[cfg(not(madsim))]
async fn recv_from_without_blocking(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr)> {
    socket.try_recv_from(buf)
}

// F.4 (dst-full-stack-heat-run-framework fidelity workstream, agmsg
// investigation 2026-07-09; redesigned after a confirmed regression --
// see the revert commit this replaces reverted, and this commit's own
// message). The original `Duration::ZERO` timeout raced a *timer*
// against the recv future, decided by whichever the executor happened to
// resolve first -- under madsim's deterministic scheduler this could
// miss an already-mailbox-queued second/third datagram (a real,
// reproducible Heisenbug in the block-fetch path). Removing the timer
// entirely (a single, direct `poll` with a no-op waker) fixed that but
// broke seed 3298840601's WireGuard handshake establishment: the zero-
// duration timeout's own scheduling yield, even though it always
// resolved "immediately" from this function's own point of view, was
// load-bearing for handshake timing elsewhere in the actor loop --
// removing it entirely removed a scheduler-progression point the
// handshake path apparently depends on. This version keeps both
// properties: still a single, deterministic poll (no timer to race
// against a future for "is data already there"), but still yields once
// on `Pending` before reporting `WouldBlock`, preserving whatever
// scheduler progression the timeout version's timer used to provide as
// a side effect. Any further change to this function must be validated
// against a full seed sweep (not a handful of scenarios) before
// landing -- this is exactly the kind of dynamic, seed-dependent
// scheduling effect neither a correctness review nor narrow testing
// caught the first time.
#[cfg(madsim)]
async fn recv_from_without_blocking(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr)> {
    // The poll happens in its own block so `fut`/`cx` (neither `Send`,
    // since `Context` wraps a raw `Waker` pointer) are fully dropped
    // before the `yield_now().await` below -- otherwise the compiler
    // sees them as live across that await point (even though the
    // `Pending` arm never touches them again) and the enclosing actor
    // future stops being `Send`, breaking `tokio::spawn`.
    let outcome = {
        let fut = socket.recv_from(buf);
        let mut fut = std::pin::pin!(fut);
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        fut.as_mut().poll(&mut cx)
    };
    match outcome {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => {
            tokio::task::yield_now().await;
            Err(io::Error::new(io::ErrorKind::WouldBlock, "no datagram ready"))
        }
    }
}

#[cfg(test)]
mod tests {
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
}

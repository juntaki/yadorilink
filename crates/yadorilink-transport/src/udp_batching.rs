//! UDP batching capability detection and dispatch for the direct datagram path.
//!
//! The actor always has a portable fallback that preserves the exact wire
//! behavior by sending and receiving one datagram at a time. Platforms with
//! kernel datagram batching can grow this module with the actual syscall path
//! without changing the peer-channel state machine.
//!
//! The batched-receive path (`try_recv_batch` and its helpers) is retained as
//! capability infrastructure — the shared socket's single receive loop
//! currently drains one datagram at a time — so it is `dead_code`-allowed
//! rather than deleted; its own unit tests still exercise it.
#![allow(dead_code)]

use std::io;
use std::net::SocketAddr;

use crate::sim_net::UdpSocket;

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
        socket.send_to(datagram, addr).await?;
        sent += 1;
    }
    Ok(sent)
}

/// `async` (not a plain non-blocking call) so the same signature works
/// whether or not the platform truly has a non-blocking `try_recv_from`.
/// This method's sole caller (`peer_channel.rs::drain_ready_direct_datagrams`)
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

async fn recv_from_without_blocking(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr)> {
    socket.try_recv_from(buf)
}

#[cfg(test)]
mod tests;

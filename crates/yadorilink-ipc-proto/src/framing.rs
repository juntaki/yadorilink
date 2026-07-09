//! Generic length-prefixed (u32 big-endian) protobuf framing, shared by
//! any local-only, non-gRPC channel in the project (e.g. the daemon
//! control socket; `yadorilink-transport`'s relay protocol predates this and
//! keeps its own copy to avoid touching already-tested code).

use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_FRAME_LEN: u32 = 1024 * 1024;

pub async fn write_message<T: Message>(
    stream: &mut (impl AsyncWrite + Unpin),
    msg: &T,
) -> std::io::Result<()> {
    let body = msg.encode_to_vec();
    stream.write_all(&(body.len() as u32).to_be_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await
}

/// Returns `Ok(None)` on a clean EOF between frames.
pub async fn read_message<T: Message + Default>(
    stream: &mut (impl AsyncRead + Unpin),
) -> std::io::Result<Option<T>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame too large: {len} bytes"),
        ));
    }
    let mut body = vec![0u8; len as usize];
    stream.read_exact(&mut body).await?;
    T::decode(body.as_slice())
        .map(Some)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemonctl::DaemonControlRequest;

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_body_allocation() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            client.write_all(&(MAX_FRAME_LEN + 1).to_be_bytes()).await.unwrap();
        });

        let err = read_message::<DaemonControlRequest>(&mut server).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}

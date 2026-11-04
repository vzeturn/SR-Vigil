//! Length-prefixed framing: `u32` little-endian length, then UTF-8 JSON (max 1 MiB).

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest accepted frame; a larger announced length closes the connection.
pub const MAX_FRAME: usize = 1 << 20;

/// Read one frame. `Ok(None)` is a clean EOF between frames.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes exceeds {MAX_FRAME}"),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

/// Write one frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "payload exceeds the maximum frame size",
        ));
    }
    let len =
        u32::try_from(payload.len()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    w.write_all(&len.to_le_bytes()).await?;
    w.write_all(payload).await?;
    w.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip_and_clean_eof() {
        let (mut a, mut b) = tokio::io::duplex(64);
        write_frame(&mut a, b"{\"x\":1}").await.unwrap();
        drop(a);
        assert_eq!(read_frame(&mut b).await.unwrap().unwrap(), b"{\"x\":1}");
        assert!(read_frame(&mut b).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oversized_announcement_is_rejected_without_allocating() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let too_big = u32::try_from(MAX_FRAME + 1).unwrap();
        a.write_all(&too_big.to_le_bytes()).await.unwrap();
        let err = read_frame(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn oversized_payload_is_not_written() {
        let (mut a, _b) = tokio::io::duplex(64);
        let big = vec![b'x'; MAX_FRAME + 1];
        assert!(write_frame(&mut a, &big).await.is_err());
    }
}

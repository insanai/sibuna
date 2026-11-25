//! A socket whose first bytes were read by someone else (SID 0024).
//!
//! A worker reads the ClientHello of a connection to learn who serves it. When that is
//! the protocol runtime, the runtime must see the same bytes again. A [`Replay`] gives
//! them back first and reads the socket after them. Writes go straight to the socket.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// A TCP stream that yields `seen` before the bytes of the socket.
pub(crate) struct Replay {
    seen: Vec<u8>,
    given: usize,
    socket: TcpStream,
}

impl Replay {
    pub fn new(seen: Vec<u8>, socket: TcpStream) -> Self {
        Self { seen, given: 0, socket }
    }
}

impl AsyncRead for Replay {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let left = this.seen.get(this.given..).unwrap_or_default();
        if left.is_empty() {
            return Pin::new(&mut this.socket).poll_read(cx, buffer);
        }
        let count = left.len().min(buffer.remaining());
        buffer.put_slice(left.get(..count).unwrap_or_default());
        this.given += count;
        if this.given >= this.seen.len() {
            this.seen = Vec::new();
            this.given = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Replay {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.socket).poll_write(cx, bytes)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        slices: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.socket).poll_write_vectored(cx, slices)
    }

    fn is_write_vectored(&self) -> bool {
        self.socket.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn the_bytes_seen_come_first_and_the_socket_after_them() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut far = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (near, _) = listener.accept().await.unwrap();
        let mut replay = Replay::new(b"hello ".to_vec(), near);
        far.write_all(b"world").await.unwrap();
        let mut text = [0; 11];
        // A small buffer takes the seen bytes in pieces.
        replay.read_exact(&mut text[..4]).await.unwrap();
        replay.read_exact(&mut text[4..]).await.unwrap();
        assert_eq!(&text, b"hello world");
        replay.write_all(b"back").await.unwrap();
        let mut answer = [0; 4];
        far.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"back");
    }
}

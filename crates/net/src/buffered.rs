//! A buffered reader and writer over caller-owned buffers.
//!
//! The proxy and the daemon read and write through fixed buffers allocated once per
//! connection. [`Reader`] keeps the unread window of its buffer visible, so a parser can look at
//! bytes before consuming them, and refills by moving that window to the front only when it
//! needs room, exactly like the Zig `std.Io.Reader` the daemon was written against. [`Writer`]
//! collects small writes and sends them on [`Write::flush`], so a relay decides when bytes
//! leave.
//!
//! ```
//! use sibuna_net::buffered::Reader;
//!
//! let mut storage = [0u8; 16];
//! let mut reader = Reader::new(&b"GET / HTTP/1.1\r\n"[..], &mut storage);
//! reader.fill(3).unwrap();
//! assert_eq!(&reader.buffered()[..3], b"GET");
//! reader.consume(4);
//! assert!(reader.buffered().starts_with(b"/"));
//! ```

use std::fmt;
use std::io::{self, IoSlice, Read, Write};

/// Why a [`Reader`] could not deliver more bytes.
#[derive(Debug)]
pub enum ReadError {
    /// The source reported end of stream before the bytes asked for arrived.
    EndOfStream,
    /// The unread window already fills the whole buffer, so nothing more fits.
    BufferFull,
    /// The source failed.
    Io(io::Error),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::EndOfStream => f.write_str("end of stream"),
            ReadError::BufferFull => f.write_str("read buffer full"),
            ReadError::Io(error) => write!(f, "read failed: {error}"),
        }
    }
}

impl std::error::Error for ReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ReadError::Io(error) => Some(error),
            _ => None,
        }
    }
}

/// A reader that keeps its unread bytes in a borrowed buffer.
///
/// The buffered window is `buffer[start..end]`. Consumed bytes stay in `buffer[..start]` until
/// the next refill that needs their room, so slices taken before a refill stay meaningful
/// until then; the borrow checker enforces that they are not used after it.
pub struct Reader<'b, R> {
    inner: R,
    buffer: &'b mut [u8],
    start: usize,
    end: usize,
}

impl<'b, R: Read> Reader<'b, R> {
    /// A reader over `inner` that buffers into `buffer`. Borrows both; never fails.
    pub fn new(inner: R, buffer: &'b mut [u8]) -> Reader<'b, R> {
        Reader { inner, buffer, start: 0, end: 0 }
    }

    /// The bytes read but not yet consumed.
    #[inline]
    pub fn buffered(&self) -> &[u8] {
        // `start <= end <= buffer.len()` is an invariant of every method.
        self.buffer.get(self.start..self.end).unwrap_or_default()
    }

    /// The bytes read but not yet consumed, writable for in-place decoding.
    #[inline]
    pub fn buffered_mut(&mut self) -> &mut [u8] {
        self.buffer.get_mut(self.start..self.end).unwrap_or_default()
    }

    /// The number of bytes read but not yet consumed.
    #[inline]
    pub fn buffered_len(&self) -> usize {
        self.end - self.start
    }

    /// The size of the buffer: the most bytes the reader can hold unread.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.buffer.len()
    }

    /// The source, borrowed.
    pub fn inner(&self) -> &R {
        &self.inner
    }

    /// Marks the first `count` buffered bytes as consumed. A count beyond the buffered bytes
    /// consumes them all; it never panics.
    #[inline]
    pub fn consume(&mut self, count: usize) {
        self.start += count.min(self.buffered_len());
    }

    /// Removes `buffered()[from..to]` and closes the gap by moving the bytes after it down.
    /// The daemon uses it to cut chunk framing out of a body decoded in place. Out-of-range
    /// or reversed bounds are clamped to the buffered window; never fails.
    pub fn remove(&mut self, from: usize, to: usize) {
        let length = self.buffered_len();
        let to = to.min(length);
        let from = from.min(to);
        let window = self.buffer.get_mut(self.start..self.end).unwrap_or_default();
        window.copy_within(to.., from);
        self.end -= to - from;
    }

    /// Reads once from the source, appending at least one byte to the buffered window unless
    /// it fails. The window moves to the front of the buffer first when the free space behind
    /// it is gone. Returns the number of bytes read.
    ///
    /// # Errors
    ///
    /// [`ReadError::BufferFull`] when the window already fills the buffer,
    /// [`ReadError::EndOfStream`] when the source is at its end, and [`ReadError::Io`] when it
    /// fails. An interrupted read is retried.
    pub fn fill_more(&mut self) -> Result<usize, ReadError> {
        if self.buffered_len() == self.buffer.len() {
            return Err(ReadError::BufferFull);
        }
        if self.end == self.buffer.len() {
            self.rebase();
        }
        loop {
            let space = self.buffer.get_mut(self.end..).unwrap_or_default();
            match self.inner.read(space) {
                Ok(0) => return Err(ReadError::EndOfStream),
                Ok(count) => {
                    // A reader never reports more bytes than the space it was given.
                    self.end += count.min(space_len(self.buffer.len(), self.end));
                    return Ok(count);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(ReadError::Io(error)),
            }
        }
    }

    /// Reads until at least `count` bytes are buffered.
    ///
    /// # Errors
    ///
    /// [`ReadError::BufferFull`] when `count` exceeds the capacity, otherwise as
    /// [`Reader::fill_more`].
    pub fn fill(&mut self, count: usize) -> Result<(), ReadError> {
        if count > self.buffer.len() {
            return Err(ReadError::BufferFull);
        }
        if self.start + count > self.buffer.len() {
            self.rebase();
        }
        while self.buffered_len() < count {
            self.fill_more()?;
        }
        Ok(())
    }

    /// Moves the buffered window to the front of the buffer.
    fn rebase(&mut self) {
        self.buffer.copy_within(self.start..self.end, 0);
        self.end -= self.start;
        self.start = 0;
    }
}

fn space_len(capacity: usize, end: usize) -> usize {
    capacity.saturating_sub(end)
}

/// A writer that collects bytes in a borrowed buffer and sends them on [`Write::flush`] or
/// when the buffer is full. A write larger than the free space goes out together with the
/// buffered bytes in one vectored write, so large bodies are not copied.
pub struct Writer<'b, W: Write> {
    inner: W,
    buffer: &'b mut [u8],
    length: usize,
}

impl<'b, W: Write> Writer<'b, W> {
    /// A writer into `inner` that buffers into `buffer`. Borrows both; never fails.
    pub fn new(inner: W, buffer: &'b mut [u8]) -> Writer<'b, W> {
        Writer { inner, buffer, length: 0 }
    }

    /// The bytes written but not yet sent.
    pub fn buffered(&self) -> &[u8] {
        self.buffer.get(..self.length).unwrap_or_default()
    }

    /// The sink, borrowed.
    pub fn inner(&self) -> &W {
        &self.inner
    }

    /// Sends every buffered byte to the sink, without flushing the sink itself.
    fn drain(&mut self) -> io::Result<()> {
        let mut sent = 0;
        while sent < self.length {
            let pending = self.buffer.get(sent..self.length).unwrap_or_default();
            match self.inner.write(pending) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => sent += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    self.keep_unsent(sent);
                    return Err(error);
                }
            }
        }
        self.length = 0;
        Ok(())
    }

    /// Keeps `buffer[sent..length]` as the buffered bytes after a failed send.
    fn keep_unsent(&mut self, sent: usize) {
        self.buffer.copy_within(sent..self.length, 0);
        self.length -= sent;
    }

    /// Sends the buffered bytes and `data` with vectored writes until the buffer is empty;
    /// returns how many bytes of `data` went out with them.
    fn drain_with(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut sent = 0;
        let mut taken = 0;
        while sent < self.length {
            let pending = self.buffer.get(sent..self.length).unwrap_or_default();
            let slices = [IoSlice::new(pending), IoSlice::new(data)];
            match self.inner.write_vectored(&slices) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => {
                    let from_buffer = count.min(pending.len());
                    sent += from_buffer;
                    taken = (count - from_buffer).min(data.len());
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    self.keep_unsent(sent);
                    return Err(error);
                }
            }
        }
        self.length = 0;
        Ok(taken)
    }
}

impl<W: Write> Write for Writer<'_, W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.write_all(data)?;
        Ok(data.len())
    }

    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        let spare = self.buffer.len() - self.length;
        if data.len() <= spare {
            let end = self.length + data.len();
            if let Some(slot) = self.buffer.get_mut(self.length..end) {
                slot.copy_from_slice(data);
                self.length = end;
            }
            return Ok(());
        }
        let taken = if self.length == 0 { 0 } else { self.drain_with(data)? };
        let rest = data.get(taken..).unwrap_or_default();
        if rest.len() < self.buffer.len() {
            if let Some(slot) = self.buffer.get_mut(..rest.len()) {
                slot.copy_from_slice(rest);
                self.length = rest.len();
            }
            return Ok(());
        }
        self.inner.write_all(rest)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.drain()?;
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sink that accepts at most `limit` bytes per call, as a congested socket does.
    struct Trickle {
        output: Vec<u8>,
        limit: usize,
    }

    impl Write for Trickle {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            let count = data.len().min(self.limit);
            self.output.extend_from_slice(&data[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn reader_refills_by_moving_the_window_to_the_front() {
        let mut storage = [0u8; 8];
        let source: &[u8] = b"abcdefghijkl";
        let mut reader = Reader::new(source, &mut storage);
        reader.fill(8).unwrap();
        assert_eq!(reader.buffered(), b"abcdefgh");
        assert!(matches!(reader.fill_more(), Err(ReadError::BufferFull)));
        reader.consume(6);
        assert_eq!(reader.fill_more().unwrap(), 4);
        assert_eq!(reader.buffered(), b"ghijkl");
        reader.consume(100);
        assert!(matches!(reader.fill_more(), Err(ReadError::EndOfStream)));
        assert!(matches!(reader.fill(9), Err(ReadError::BufferFull)));
    }

    #[test]
    fn reader_removes_a_range_of_the_window() {
        let mut storage = [0u8; 16];
        let mut reader = Reader::new(&b"0123456789"[..], &mut storage);
        reader.fill(10).unwrap();
        reader.consume(1);
        reader.remove(2, 5);
        assert_eq!(reader.buffered(), b"126789");
        reader.remove(3, 1);
        reader.remove(10, 20);
        assert_eq!(reader.buffered(), b"126789");
    }

    #[test]
    fn writer_keeps_order_across_small_and_large_writes() {
        let mut storage = [0u8; 8];
        let mut writer = Writer::new(Trickle { output: Vec::new(), limit: 3 }, &mut storage);
        writer.write_all(b"head").unwrap();
        writer.write_all(b"0123456789abcdef").unwrap();
        writer.write_all(b"xy").unwrap();
        writer.write_all(b"").unwrap();
        writer.flush().unwrap();
        assert_eq!(writer.inner().output, b"head0123456789abcdefxy");
        assert!(writer.buffered().is_empty());
    }
}

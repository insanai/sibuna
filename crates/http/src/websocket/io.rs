//! Frame input over any `std::io::Read`.
//!
//! The Zig version peeked at a buffered reader and tossed a frame once it was complete. A
//! `std::io::BufRead` cannot be asked for more bytes than it happens to hold, so
//! [`FrameReader`] owns a bounded buffer and keeps an incomplete frame in it across reads.
//! A read that fails part way (a socket deadline, for example) loses nothing.

use std::fmt;
use std::io::{self, Read};

use super::{Event, FrameError, MAX_HEADER, MAX_MESSAGE, Receiver, Role, decode};

/// Why [`FrameReader::receive`] failed.
#[derive(Debug)]
pub enum ReceiveError {
    /// The frame or message was refused.
    Frame(FrameError),
    /// The stream ended before the frame did.
    EndOfStream,
    /// Reading failed.
    Io(io::Error),
}

impl From<FrameError> for ReceiveError {
    fn from(error: FrameError) -> Self {
        ReceiveError::Frame(error)
    }
}

impl fmt::Display for ReceiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReceiveError::Frame(error) => error.fmt(f),
            ReceiveError::EndOfStream => f.write_str("WebSocket stream ended inside a frame"),
            ReceiveError::Io(error) => write!(f, "WebSocket read failed: {error}"),
        }
    }
}

impl std::error::Error for ReceiveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ReceiveError::Frame(error) => Some(error),
            ReceiveError::EndOfStream => None,
            ReceiveError::Io(error) => Some(error),
        }
    }
}

/// A reader of whole frames with a fixed-capacity buffer, allocated once.
#[derive(Debug)]
pub struct FrameReader<R> {
    inner: R,
    buffer: Box<[u8]>,
    /// Buffered bytes are `buffer[start..end]`.
    start: usize,
    end: usize,
}

impl<R: Read> FrameReader<R> {
    /// A reader whose buffer holds the largest frame: [`MAX_HEADER`] plus [`MAX_MESSAGE`].
    pub fn new(inner: R) -> FrameReader<R> {
        FrameReader::with_capacity(inner, MAX_HEADER + MAX_MESSAGE)
    }

    /// A reader with a buffer of `capacity` bytes. A frame longer than the buffer is
    /// refused with [`FrameError::NoSpace`].
    pub fn with_capacity(inner: R, capacity: usize) -> FrameReader<R> {
        FrameReader { inner, buffer: vec![0; capacity].into_boxed_slice(), start: 0, end: 0 }
    }

    /// The underlying reader.
    pub fn inner(&self) -> &R {
        &self.inner
    }

    /// The underlying reader, mutably (to set deadlines, for example).
    pub fn inner_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Consumes the frame reader and returns the underlying reader; buffered bytes are lost.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// The bytes read but not yet consumed.
    pub fn buffered(&self) -> &[u8] {
        self.buffer.get(self.start..self.end).unwrap_or_default()
    }

    /// Reads the next frame received by a peer of `role` and passes it to `receiver`.
    ///
    /// The header is validated as soon as its first two bytes, and again when all of it, has
    /// arrived, so a malformed or oversized frame is refused before its payload is awaited.
    ///
    /// # Errors
    ///
    /// [`ReceiveError::Frame`] for a refused frame (including [`FrameError::NoSpace`] when
    /// it would not fit the buffer), [`ReceiveError::EndOfStream`] when the stream ends
    /// first, and [`ReceiveError::Io`] when reading fails; bytes already read stay buffered.
    pub fn receive<'r>(
        &mut self,
        receiver: &'r mut Receiver,
        role: Role,
    ) -> Result<Event<'r>, ReceiveError> {
        let prefix = self.peek(2)?;
        validate(prefix, role)?;
        let marker = prefix.get(1).map_or(0, |byte| byte & 0x7f);
        let extended = match marker {
            126 => 2,
            127 => 8,
            _ => 0,
        };
        let header_size = 2 + extended + if role == Role::Server { 4 } else { 0 };
        let header = self.peek(header_size)?;
        validate(header, role)?;
        // The codec has refused non-minimal lengths and anything beyond MAX_MESSAGE, so an
        // eight-byte length never gets here.
        let length = match marker {
            126 => header
                .get(2..)
                .and_then(<[u8]>::first_chunk::<2>)
                .map_or(0, |bytes| usize::from(u16::from_be_bytes(*bytes))),
            127 => return Err(FrameError::TooLarge.into()),
            short => usize::from(short),
        };
        let bytes = self.peek(header_size + length)?;
        let frame = decode(bytes, role)?.ok_or(ReceiveError::EndOfStream)?;
        // The frame is consumed whether or not the receiver accepts it, as in Zig.
        let consumed = frame.consumed;
        let event = receiver.accept(&frame);
        self.start += consumed;
        Ok(event?)
    }

    /// The first `length` buffered bytes, reading until they are present.
    fn peek(&mut self, length: usize) -> Result<&[u8], ReceiveError> {
        if length > self.buffer.len() {
            return Err(FrameError::NoSpace.into());
        }
        while self.end - self.start < length {
            if self.start + length > self.buffer.len() {
                // Move the partial frame to the front to make room behind it.
                self.buffer.copy_within(self.start..self.end, 0);
                self.end -= self.start;
                self.start = 0;
            }
            let space = self.buffer.get_mut(self.end..).unwrap_or_default();
            match self.inner.read(space) {
                Ok(0) => return Err(ReceiveError::EndOfStream),
                Ok(count) => self.end += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(ReceiveError::Io(error)),
            }
        }
        Ok(self.buffer.get(self.start..self.start + length).unwrap_or_default())
    }
}

/// Checks whatever part of a header is present; an incomplete header is not an error.
fn validate(header: &[u8], role: Role) -> Result<(), FrameError> {
    decode(header, role).map(|_| ())
}

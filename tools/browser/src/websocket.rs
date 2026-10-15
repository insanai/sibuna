//! The client side of RFC 6455 for the DevTools connection.
//!
//! Outgoing frames are encoded by `sibuna_http::websocket::encode`, masked with a fresh key
//! each, and fragmented into pieces of at most `MAX_MESSAGE` bytes. The server's accept key
//! is checked with `sibuna_http::websocket::accept_key`.
//!
//! Incoming frames are decoded here rather than by `sibuna_http`'s `FrameReader`: that
//! reader is built for the edge and refuses any message over 4 KiB, while Chromium sends a
//! screenshot as one unfragmented frame of several megabytes. [`MessageReader`] applies
//! the same header checks (reserved bits, opcodes, masking for the role, minimal lengths,
//! control frame rules) with a caller-chosen message bound instead.

use std::hash::{BuildHasher, Hasher, RandomState};
use std::io::{self, Read, Write};

use sibuna_encoding::base64;
use sibuna_http::websocket::{
    self, FrameError, MAX_CONTROL, MAX_HEADER, MAX_MESSAGE, Opcode, Role,
};

use crate::error::Error;

/// The longest HTTP response head we accept during the handshake.
const MAX_RESPONSE_HEAD: usize = 8 * 1024;

/// The spare room a read is offered: at least `MIN_READ` bytes, growing with the bytes
/// held (a long frame arriving) up to `MAX_READ`.
const MIN_READ: usize = 4 * 1024;
const MAX_READ: usize = 64 * 1024;

/// A source of client masks and handshake keys.
///
/// Masks exist so that a page's script cannot steer the bytes an intermediary sees; on a
/// loopback connection to Chromium they need to be unpredictable, not secret. The state
/// is seeded from `RandomState`, which the standard library keys from the operating
/// system's random source, and advanced with xorshift64*.
#[derive(Debug)]
pub(crate) struct MaskSource {
    state: u64,
}

impl MaskSource {
    /// A source seeded from the operating system's randomness.
    pub(crate) fn new() -> MaskSource {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u32(std::process::id());
        // xorshift has a fixed point at zero; an odd state avoids it.
        MaskSource { state: hasher.finish() | 1 }
    }

    /// The next 64 pseudo-random bits.
    pub(crate) fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A fresh four-byte frame mask.
    pub(crate) fn mask(&mut self) -> [u8; 4] {
        let [a, b, c, d, ..] = self.next_u64().to_le_bytes();
        [a, b, c, d]
    }

    /// A fresh `Sec-WebSocket-Key`: sixteen random bytes in padded base64.
    pub(crate) fn handshake_key(&mut self) -> String {
        let mut raw = [0u8; 16];
        let (low, high) = raw.split_at_mut(8);
        low.copy_from_slice(&self.next_u64().to_le_bytes());
        high.copy_from_slice(&self.next_u64().to_le_bytes());
        base64::encode(base64::STANDARD, &raw)
    }
}

/// Performs the client's opening handshake on `stream` for `path` on `host` (`ip:port`).
///
/// Returns the bytes that followed the response head, which belong to the first frames.
///
/// # Errors
///
/// [`Error::Io`] when writing or reading fails, and [`Error::Handshake`] when the response
/// is not `101 Switching Protocols` with the right `Sec-WebSocket-Accept`.
pub(crate) fn handshake<S: Read + Write>(
    stream: &mut S,
    host: &str,
    path: &str,
    key: &str,
) -> Result<Vec<u8>, Error> {
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|error| Error::io("sending the WebSocket handshake", error))?;
    let mut received = Vec::with_capacity(1024);
    let head_end = loop {
        if let Some(at) = find_head_end(&received) {
            break at;
        }
        if received.len() > MAX_RESPONSE_HEAD {
            return Err(Error::Handshake("the response head exceeds 8 KiB".into()));
        }
        let mut chunk = [0u8; 1024];
        match stream.read(&mut chunk) {
            Ok(0) => return Err(Error::Handshake("the server closed the connection".into())),
            Ok(count) => received.extend_from_slice(chunk.get(..count).unwrap_or_default()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Error::io("reading the WebSocket handshake", error)),
        }
    };
    let (head, rest) = received.split_at(head_end);
    check_response(head, key)?;
    Ok(rest.to_vec())
}

/// The offset just past the blank line that ends an HTTP head, if it has arrived.
fn find_head_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n").map(|at| at + 4)
}

/// Checks a handshake response head (including its final blank line) for `key`.
///
/// # Errors
///
/// [`Error::Handshake`] naming the first problem found.
pub(crate) fn check_response(head: &[u8], key: &str) -> Result<(), Error> {
    let text = std::str::from_utf8(head)
        .map_err(|_| Error::Handshake("the response head is not UTF-8".into()))?;
    let mut lines = text.split("\r\n");
    let status = lines.next().unwrap_or_default();
    let mut parts = status.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    let code = parts.next().unwrap_or_default();
    if version != "HTTP/1.1" || code != "101" {
        return Err(Error::Handshake(format!("the server answered `{status}`")));
    }
    let expected = websocket::accept_key(key.as_bytes())
        .map_err(|_| Error::Handshake("our own key is invalid".into()))?;
    let (mut upgrade, mut connection, mut accept) = (false, false, false);
    for line in lines.filter(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            return Err(Error::Handshake(format!("malformed header line `{line}`")));
        };
        let value = value.trim_matches([' ', '\t']).as_bytes();
        match name.to_ascii_lowercase().as_str() {
            "upgrade" => upgrade = value.eq_ignore_ascii_case(b"websocket"),
            "connection" => connection = websocket::contains_token(value, b"upgrade"),
            "sec-websocket-accept" => accept = value == expected,
            _ => {}
        }
    }
    if !upgrade || !connection {
        return Err(Error::Handshake("the response does not upgrade to websocket".into()));
    }
    if !accept {
        return Err(Error::Handshake("Sec-WebSocket-Accept does not match our key".into()));
    }
    Ok(())
}

/// The header of one frame a server sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FrameHeader {
    /// The FIN bit.
    pub(crate) fin: bool,
    /// The opcode.
    pub(crate) opcode: Opcode,
    /// The header's length in bytes.
    pub(crate) header_len: usize,
    /// The payload's length in bytes.
    pub(crate) payload_len: usize,
}

/// Decodes the header of a server frame at the start of `input`.
///
/// Returns `Ok(None)` when the header has not fully arrived.
///
/// # Errors
///
/// [`FrameError::Protocol`] for reserved bits or opcodes, a masked frame, a fragmented or
/// long control frame or a non-minimal length; [`FrameError::TooLarge`] for a payload over
/// `max_payload` bytes.
pub(crate) fn decode_header(
    input: &[u8],
    max_payload: usize,
) -> Result<Option<FrameHeader>, FrameError> {
    let [first, second, ..] = *input else { return Ok(None) };
    if first & 0x70 != 0 || second & 0x80 != 0 {
        return Err(FrameError::Protocol);
    }
    let opcode = Opcode::from_bits(first & 0x0f).ok_or(FrameError::Protocol)?;
    let fin = first & 0x80 != 0;
    let marker = second & 0x7f;
    if opcode.is_control() && (!fin || marker > 125) {
        return Err(FrameError::Protocol);
    }
    let (length, header_len) = match marker {
        126 => match input.get(2..).and_then(<[u8]>::first_chunk::<2>) {
            Some(bytes) => (u64::from(u16::from_be_bytes(*bytes)), 4),
            None => return Ok(None),
        },
        127 => match input.get(2..).and_then(<[u8]>::first_chunk::<8>) {
            Some(bytes) => (u64::from_be_bytes(*bytes), 10),
            None => return Ok(None),
        },
        short => (u64::from(short), 2),
    };
    let minimal = match marker {
        126 => length >= 126,
        127 => length >= 65536 && length >> 63 == 0,
        _ => true,
    };
    if !minimal {
        return Err(FrameError::Protocol);
    }
    let payload_len = usize::try_from(length).map_err(|_| FrameError::TooLarge)?;
    if payload_len > max_payload {
        return Err(FrameError::TooLarge);
    }
    Ok(Some(FrameHeader { fin, opcode, header_len, payload_len }))
}

/// What a complete incoming message was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Incoming {
    /// A text message: every DevTools message is one.
    Text(String),
    /// A binary message, which DevTools never sends.
    Binary(Vec<u8>),
    /// A ping, to be answered with a pong carrying the same data.
    Ping(Vec<u8>),
    /// A pong.
    Pong,
    /// A valid close frame.
    Close,
}

/// Reassembles server messages of up to a fixed number of bytes from a byte stream.
///
/// Bytes are appended with [`MessageReader::read_from`] and messages taken with
/// [`MessageReader::next_message`]. Only one frame's bytes plus one read are ever buffered,
/// so memory is bounded by the message bound.
#[derive(Debug)]
pub(crate) struct MessageReader {
    /// Received bytes are `buffer[start..end]`; the rest is initialised spare room, kept
    /// so that reads need not zero new memory each time.
    buffer: Vec<u8>,
    start: usize,
    end: usize,
    /// The data message being reassembled, and its first opcode.
    message: Vec<u8>,
    pending: Option<Opcode>,
    max_message: usize,
}

impl MessageReader {
    /// A reader that refuses messages over `max_message` bytes, starting with `initial`
    /// bytes already received.
    pub(crate) fn new(max_message: usize, initial: Vec<u8>) -> MessageReader {
        let end = initial.len();
        MessageReader {
            buffer: initial,
            start: 0,
            end,
            message: Vec::new(),
            pending: None,
            max_message,
        }
    }

    /// Reads once from `source`, appending what arrived. Returns the number of bytes read;
    /// zero means the stream ended.
    ///
    /// # Errors
    ///
    /// The source's error, unchanged, so the caller can tell a timeout from a failure.
    pub(crate) fn read_from<R: Read>(&mut self, source: &mut R) -> io::Result<usize> {
        if self.start > 0 {
            self.buffer.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        // The buffer grows only while one frame is longer than it; `next_message` refuses
        // frames over the bound before their payload is read, so it stays bounded.
        let spare = self.end.clamp(MIN_READ, MAX_READ);
        if self.buffer.len() - self.end < spare {
            self.buffer.resize(self.end + spare, 0);
        }
        let count = source.read(self.buffer.get_mut(self.end..).unwrap_or_default())?;
        self.end += count;
        Ok(count)
    }

    /// Takes the next complete message from the buffered bytes, or `Ok(None)` when more
    /// bytes are needed. Fragments are consumed as they complete.
    ///
    /// # Errors
    ///
    /// [`FrameError`] for a malformed frame, a broken fragment sequence, a message over the
    /// bound, or text that is not UTF-8.
    pub(crate) fn next_message(&mut self) -> Result<Option<Incoming>, FrameError> {
        loop {
            let available = self.buffer.get(self.start..self.end).unwrap_or_default();
            let Some(header) = decode_header(available, self.max_message)? else {
                return Ok(None);
            };
            // Both lengths are bounded by `max_message`, so the sum does not overflow.
            let end = header.header_len + header.payload_len;
            let Some(payload) = available.get(header.header_len..end) else {
                return Ok(None);
            };
            let result = self.accept(header, payload.to_vec());
            self.start += end;
            if let Some(incoming) = result? {
                return Ok(Some(incoming));
            }
        }
    }

    /// Applies one complete frame; returns a message when the frame completes one.
    fn accept(
        &mut self,
        header: FrameHeader,
        payload: Vec<u8>,
    ) -> Result<Option<Incoming>, FrameError> {
        match header.opcode {
            Opcode::Ping => return Ok(Some(Incoming::Ping(payload))),
            Opcode::Pong => return Ok(Some(Incoming::Pong)),
            Opcode::Close => {
                websocket::validate_close(&payload)?;
                return Ok(Some(Incoming::Close));
            }
            Opcode::Continuation if self.pending.is_none() => return Err(FrameError::Protocol),
            Opcode::Text | Opcode::Binary if self.pending.is_some() => {
                return Err(FrameError::Protocol);
            }
            Opcode::Text | Opcode::Binary => {
                self.pending = Some(header.opcode);
                self.message.clear();
            }
            Opcode::Continuation => {}
        }
        if self.message.len() + payload.len() > self.max_message {
            return Err(FrameError::TooLarge);
        }
        if self.message.is_empty() {
            self.message = payload;
        } else {
            self.message.extend_from_slice(&payload);
        }
        if !header.fin {
            return Ok(None);
        }
        let bytes = std::mem::take(&mut self.message);
        match self.pending.take() {
            Some(Opcode::Text) => String::from_utf8(bytes)
                .map(|text| Some(Incoming::Text(text)))
                .map_err(|_| FrameError::InvalidUtf8),
            _ => Ok(Some(Incoming::Binary(bytes))),
        }
    }
}

/// Writes masked client frames, reusing one frame buffer.
#[derive(Debug)]
pub(crate) struct FrameWriter {
    frame: Box<[u8]>,
    masks: MaskSource,
}

impl FrameWriter {
    /// A writer with a buffer for the largest frame `sibuna_http` encodes.
    pub(crate) fn new(masks: MaskSource) -> FrameWriter {
        FrameWriter { frame: vec![0; MAX_HEADER + MAX_MESSAGE].into_boxed_slice(), masks }
    }

    /// Sends `text` as one message, fragmented into frames of at most `MAX_MESSAGE` bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when writing fails.
    pub(crate) fn send_text<W: Write>(&mut self, sink: &mut W, text: &str) -> Result<(), Error> {
        let bytes = text.as_bytes();
        let count = bytes.len().div_ceil(MAX_MESSAGE).max(1);
        let mut pieces = bytes.chunks(MAX_MESSAGE);
        for index in 0..count {
            let piece = pieces.next().unwrap_or_default();
            let opcode = if index == 0 { Opcode::Text } else { Opcode::Continuation };
            self.send_frame(sink, opcode, index + 1 == count, piece)?;
        }
        sink.flush().map_err(|error| Error::io("sending a DevTools message", error))
    }

    /// Sends a pong echoing a ping's data (at most `MAX_CONTROL` bytes are echoed).
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when writing fails.
    pub(crate) fn send_pong<W: Write>(&mut self, sink: &mut W, data: &[u8]) -> Result<(), Error> {
        let data = data.get(..MAX_CONTROL.min(data.len())).unwrap_or_default();
        self.send_frame(sink, Opcode::Pong, true, data)?;
        sink.flush().map_err(|error| Error::io("sending a pong", error))
    }

    /// Sends a close frame with status 1000 (normal closure).
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when writing fails.
    pub(crate) fn send_close<W: Write>(&mut self, sink: &mut W) -> Result<(), Error> {
        self.send_frame(sink, Opcode::Close, true, &1000u16.to_be_bytes())?;
        sink.flush().map_err(|error| Error::io("sending a close frame", error))
    }

    fn send_frame<W: Write>(
        &mut self,
        sink: &mut W,
        opcode: Opcode,
        fin: bool,
        payload: &[u8],
    ) -> Result<(), Error> {
        let mask = self.masks.mask();
        let frame =
            websocket::encode(&mut self.frame, opcode, fin, payload, Role::Client, Some(mask))?;
        sink.write_all(frame).map_err(|error| Error::io("sending a WebSocket frame", error))
    }
}

#[cfg(test)]
mod tests;

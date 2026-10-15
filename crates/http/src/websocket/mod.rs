//! The RFC 6455 WebSocket codec.
//!
//! [`decode`] reads one frame from the start of a byte slice, [`Receiver`] reassembles
//! fragmented messages and validates text and close frames, [`encode`] writes a frame into a
//! caller buffer, and [`FrameReader`] drives both from any `std::io::Read`. The handshake
//! helpers are [`accept_key`], [`decode_key`], [`contains_token`] and [`upgrade_key`].
//! Socket deadlines and serialised writing belong to the owner of the connection.
//!
//! Messages are bounded by [`MAX_MESSAGE`] bytes, whatever their fragmentation, and every
//! frame header is checked before its payload is awaited, so a peer cannot make us buffer
//! more than one bounded frame.
//!
//! ```
//! use sibuna_http::websocket::{Event, Opcode, Receiver, Role, decode, encode};
//!
//! let mut wire = [0u8; 32];
//! let frame = encode(&mut wire, Opcode::Text, true, b"Hello", Role::Client, Some([1, 2, 3, 4]))?;
//! let decoded = decode(frame, Role::Server)?.expect("a complete frame");
//! let mut receiver = Receiver::new();
//! assert_eq!(receiver.accept(&decoded)?, Event::Text("Hello"));
//! # Ok::<(), sibuna_http::websocket::FrameError>(())
//! ```

use std::fmt;

mod handshake;
mod io;

pub use handshake::{HandshakeError, accept_key, contains_token, decode_key, upgrade_key};
pub use io::{FrameReader, ReceiveError};

/// The largest message, in payload bytes, that a [`Receiver`] reassembles and that
/// [`encode`] writes.
pub const MAX_MESSAGE: usize = 4096;

/// The largest control frame payload (RFC 6455 section 5.5).
pub const MAX_CONTROL: usize = 125;

/// The longest frame header: two bytes, an eight-byte length and a four-byte mask.
pub const MAX_HEADER: usize = 14;

/// Which end of the connection we are. A server receives masked frames and sends unmasked
/// ones; a client does the opposite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// We accepted the connection.
    Server,
    /// We opened the connection.
    Client,
}

/// A frame opcode defined by RFC 6455.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Opcode {
    /// A later fragment of a data message.
    Continuation = 0,
    /// The first frame of a UTF-8 text message.
    Text = 1,
    /// The first frame of a binary message.
    Binary = 2,
    /// The closing handshake.
    Close = 8,
    /// A ping, answered with a pong.
    Ping = 9,
    /// A pong.
    Pong = 10,
}

impl Opcode {
    /// The opcode of the low four bits of a frame's first byte, or `None` when reserved.
    pub fn from_bits(bits: u8) -> Option<Opcode> {
        match bits {
            0 => Some(Opcode::Continuation),
            1 => Some(Opcode::Text),
            2 => Some(Opcode::Binary),
            8 => Some(Opcode::Close),
            9 => Some(Opcode::Ping),
            10 => Some(Opcode::Pong),
            _ => None,
        }
    }

    /// True for close, ping and pong.
    pub fn is_control(self) -> bool {
        self as u8 >= 8
    }
}

/// Why a frame or message was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrameError {
    /// The peer broke the protocol: reserved bits or opcodes, wrong masking for its role, a
    /// fragmented or oversized control frame, a non-minimal length, a continuation without
    /// a message or a new message inside one, or an invalid close code.
    Protocol,
    /// A frame or reassembled message exceeds [`MAX_MESSAGE`].
    TooLarge,
    /// A text message or close reason is not valid UTF-8.
    InvalidUtf8,
    /// A frame arrived after the close frame.
    Closed,
    /// The output buffer, or the reader's buffer, cannot hold the frame.
    NoSpace,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            FrameError::Protocol => "WebSocket protocol violation",
            FrameError::TooLarge => "WebSocket message too large",
            FrameError::InvalidUtf8 => "WebSocket text is not valid UTF-8",
            FrameError::Closed => "WebSocket frame after close",
            FrameError::NoSpace => "buffer too small for the WebSocket frame",
        })
    }
}

impl std::error::Error for FrameError {}

/// One frame, borrowing its still-masked payload from the decoded input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    /// The FIN bit: this frame ends its message.
    pub fin: bool,
    /// The opcode.
    pub opcode: Opcode,
    /// The payload as sent, still masked when `mask` is set.
    pub payload: &'a [u8],
    /// The masking key, present exactly when the peer is a client.
    pub mask: Option<[u8; 4]>,
    /// The number of input bytes the frame occupies.
    pub consumed: usize,
}

/// Decodes the frame at the start of `input`, received by a peer of `role`.
///
/// Returns `Ok(None)` when `input` holds only part of a frame; nothing is consumed then, so
/// the caller reads more and calls again. Every check that the header alone decides is made
/// before the payload is awaited.
///
/// # Errors
///
/// [`FrameError::Protocol`] for a malformed header and [`FrameError::TooLarge`] for a
/// payload longer than [`MAX_MESSAGE`].
pub fn decode(input: &[u8], role: Role) -> Result<Option<Frame<'_>>, FrameError> {
    let [first, second, ..] = *input else { return Ok(None) };
    if first & 0x70 != 0 {
        return Err(FrameError::Protocol);
    }
    let opcode = Opcode::from_bits(first & 0x0f).ok_or(FrameError::Protocol)?;
    let fin = first & 0x80 != 0;
    let masked = second & 0x80 != 0;
    if masked != (role == Role::Server) {
        return Err(FrameError::Protocol);
    }
    let marker = second & 0x7f;
    if opcode.is_control() && (!fin || marker > 125) {
        return Err(FrameError::Protocol);
    }
    let (length, mut offset) = match marker {
        126 => {
            let Some(bytes) = input.get(2..).and_then(<[u8]>::first_chunk::<2>) else {
                return Ok(None);
            };
            (u64::from(u16::from_be_bytes(*bytes)), 4)
        }
        127 => {
            let Some(bytes) = input.get(2..).and_then(<[u8]>::first_chunk::<8>) else {
                return Ok(None);
            };
            (u64::from_be_bytes(*bytes), 10)
        }
        short => (u64::from(short), 2),
    };
    // The shortest encoding is required, and the top bit of a 64-bit length must be clear.
    let minimal = match marker {
        126 => length >= 126,
        127 => length >= 65536 && length >> 63 == 0,
        _ => true,
    };
    if !minimal {
        return Err(FrameError::Protocol);
    }
    if length > MAX_MESSAGE as u64 {
        return Err(FrameError::TooLarge);
    }
    let mut mask = None;
    if masked {
        let Some(key) = input.get(offset..).and_then(<[u8]>::first_chunk::<4>) else {
            return Ok(None);
        };
        mask = Some(*key);
        offset += 4;
    }
    // `length` is at most MAX_MESSAGE, so the sum cannot overflow.
    let end = offset + length as usize;
    let Some(payload) = input.get(offset..end) else { return Ok(None) };
    Ok(Some(Frame { fin, opcode, payload, mask, consumed: end }))
}

/// What a frame meant, once accepted by a [`Receiver`]. Payloads borrow the receiver's
/// buffers until its next `accept`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// A non-final fragment of a data message was stored.
    Fragment,
    /// A complete text message.
    Text(&'a str),
    /// A complete binary message.
    Binary(&'a [u8]),
    /// A ping with its application data.
    Ping(&'a [u8]),
    /// A pong with its application data.
    Pong(&'a [u8]),
    /// A valid close frame: empty, or a status code and a UTF-8 reason.
    Close(&'a [u8]),
}

/// Reassembles messages from frames. Control frames use a separate buffer, so a ping
/// between fragments never overwrites the pending message. About 4 KiB, no allocation.
#[derive(Clone, Debug)]
pub struct Receiver {
    message: [u8; MAX_MESSAGE],
    control: [u8; MAX_CONTROL],
    length: usize,
    pending: Option<Opcode>,
    closed: bool,
}

impl Default for Receiver {
    fn default() -> Self {
        Receiver::new()
    }
}

impl Receiver {
    /// A receiver expecting the first frame of a message.
    pub const fn new() -> Receiver {
        Receiver {
            message: [0; MAX_MESSAGE],
            control: [0; MAX_CONTROL],
            length: 0,
            pending: None,
            closed: false,
        }
    }

    /// True once a close frame has been accepted.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Accepts the next frame, unmasking its payload into the receiver's buffers.
    ///
    /// # Errors
    ///
    /// [`FrameError::Closed`] after a close frame; [`FrameError::Protocol`] for a
    /// continuation without a message, a new message inside one, or an invalid close frame;
    /// [`FrameError::TooLarge`] when the message would exceed [`MAX_MESSAGE`];
    /// [`FrameError::InvalidUtf8`] for a text message or close reason that is not UTF-8.
    pub fn accept(&mut self, frame: &Frame<'_>) -> Result<Event<'_>, FrameError> {
        if self.closed {
            return Err(FrameError::Closed);
        }
        if frame.opcode.is_control() {
            return self.accept_control(frame);
        }
        if frame.opcode == Opcode::Continuation {
            if self.pending.is_none() {
                return Err(FrameError::Protocol);
            }
        } else {
            if self.pending.is_some() {
                return Err(FrameError::Protocol);
            }
            self.pending = Some(frame.opcode);
            self.length = 0;
        }
        let end = self.length + frame.payload.len();
        let slot = self.message.get_mut(self.length..end).ok_or(FrameError::TooLarge)?;
        unmask(slot, frame);
        self.length = end;
        if !frame.fin {
            return Ok(Event::Fragment);
        }
        let opcode = self.pending.take();
        let payload = self.message.get(..self.length).unwrap_or_default();
        if opcode == Some(Opcode::Text) {
            let text = std::str::from_utf8(payload).map_err(|_| FrameError::InvalidUtf8)?;
            return Ok(Event::Text(text));
        }
        Ok(Event::Binary(payload))
    }

    fn accept_control(&mut self, frame: &Frame<'_>) -> Result<Event<'_>, FrameError> {
        if !frame.fin {
            return Err(FrameError::Protocol);
        }
        let payload = self.control.get_mut(..frame.payload.len()).ok_or(FrameError::Protocol)?;
        unmask(payload, frame);
        match frame.opcode {
            Opcode::Ping => Ok(Event::Ping(payload)),
            Opcode::Pong => Ok(Event::Pong(payload)),
            Opcode::Close => {
                validate_close(payload)?;
                self.closed = true;
                Ok(Event::Close(payload))
            }
            Opcode::Continuation | Opcode::Text | Opcode::Binary => Err(FrameError::Protocol),
        }
    }
}

/// Copies the frame's payload into `output` (of the same length), removing the mask.
fn unmask(output: &mut [u8], frame: &Frame<'_>) {
    let key = frame.mask.unwrap_or([0; 4]);
    for ((out, &byte), &k) in output.iter_mut().zip(frame.payload).zip(key.iter().cycle()) {
        *out = byte ^ k;
    }
}

/// Checks a close payload: empty, or a two-byte status code that RFC 6455 allows on the wire
/// (1000 to 1014 except 1004 to 1006, or 3000 to 4999) followed by a UTF-8 reason.
///
/// # Errors
///
/// [`FrameError::Protocol`] for a one-byte payload or a disallowed code, and
/// [`FrameError::InvalidUtf8`] for a reason that is not UTF-8.
pub fn validate_close(payload: &[u8]) -> Result<(), FrameError> {
    if payload.is_empty() {
        return Ok(());
    }
    let Some((code, reason)) = payload.split_first_chunk::<2>() else {
        return Err(FrameError::Protocol);
    };
    let code = u16::from_be_bytes(*code);
    let standard = (1000..=1014).contains(&code) && !(1004..=1006).contains(&code);
    if !standard && !(3000..=4999).contains(&code) {
        return Err(FrameError::Protocol);
    }
    std::str::from_utf8(reason).map(|_| ()).map_err(|_| FrameError::InvalidUtf8)
}

/// Encodes one frame into the front of `output` and returns the bytes written.
///
/// A client passes a fresh, cryptographically random `mask` for every frame; a server
/// passes `None`. No allocation occurs.
///
/// # Errors
///
/// [`FrameError::Protocol`] when the mask does not match `role`, a control frame is not
/// final or longer than [`MAX_CONTROL`], or a close payload is invalid;
/// [`FrameError::TooLarge`] for a payload over [`MAX_MESSAGE`]; [`FrameError::NoSpace`] when
/// `output` is too short.
pub fn encode<'o>(
    output: &'o mut [u8],
    opcode: Opcode,
    fin: bool,
    payload: &[u8],
    role: Role,
    mask: Option<[u8; 4]>,
) -> Result<&'o [u8], FrameError> {
    if (role == Role::Client) != mask.is_some() {
        return Err(FrameError::Protocol);
    }
    if payload.len() > MAX_MESSAGE {
        return Err(FrameError::TooLarge);
    }
    if opcode.is_control() && (!fin || payload.len() > MAX_CONTROL) {
        return Err(FrameError::Protocol);
    }
    if opcode == Opcode::Close {
        validate_close(payload)?;
    }
    let short = payload.len() < 126;
    let header = if short { 2 } else { 4 } + if mask.is_some() { 4 } else { 0 };
    let frame = output.get_mut(..header + payload.len()).ok_or(FrameError::NoSpace)?;
    // `frame` holds `header + payload.len()` bytes. The head is 2 bytes, 4 with an extended
    // length, and 4 more with a mask, so every index below is in bounds.
    let (head, body) = frame.split_at_mut(header);
    head[0] = opcode as u8 | if fin { 0x80 } else { 0 };
    // `payload.len()` is at most MAX_MESSAGE, so it fits sixteen bits.
    let length = payload.len() as u16;
    if short {
        head[1] = length as u8;
    } else {
        head[1] = 126;
        head[2..4].copy_from_slice(&length.to_be_bytes());
    }
    if let Some(key) = mask {
        head[1] |= 0x80;
        head[header - 4..].copy_from_slice(&key);
    }
    let key = mask.unwrap_or([0; 4]);
    for ((out, &byte), &k) in body.iter_mut().zip(payload).zip(key.iter().cycle()) {
        *out = byte ^ k;
    }
    Ok(frame)
}

#[cfg(test)]
mod fuzz;
#[cfg(test)]
mod tests;

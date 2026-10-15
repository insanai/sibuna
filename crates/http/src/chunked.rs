//! Chunked request bodies (RFC 9112 section 7.1, SID 0009).
//!
//! [`Decoder`] decodes the chunked transfer coding in place: decoded data is written back
//! into the slice being read, never ahead of the read position, so a body is recovered
//! inside the connection buffer that holds it. The grammar is strict where HTTP/1.1 parsers
//! are known to disagree: CRLF is the only line terminator, no other control byte may appear
//! in a chunk line, sizes are bare hexadecimal, and extensions follow the RFC grammar
//! exactly. Extensions and trailers are validated and dropped; whoever forwards the body
//! generates its own framing with [`write_chunk`] and [`LAST_CHUNK`].
//!
//! ```
//! use sibuna_http::chunked::Decoder;
//!
//! let mut bytes = *b"5\r\nhello\r\n0\r\n\r\n";
//! let mut decoder = Decoder::new();
//! let step = decoder.decode(&mut bytes).unwrap();
//! assert!(decoder.is_done());
//! assert_eq!(&bytes[..step.output], b"hello");
//! assert_eq!(step.consumed, bytes.len());
//! ```

use std::fmt;
use std::io::{self, Write};

use crate::bytes::{FIELD, TOKEN, find_byte, is_token, run_length};

/// Longest chunk-size or trailer line, CRLF included. A line that has not ended within this
/// many bytes is rejected, so the decoder never needs more unconsumed input than this.
pub const MAX_LINE: usize = 4096;

/// The longest trailer section in bytes, bounded like a request head.
pub const MAX_TRAILER: usize = 16 * 1024;

/// Sixteen hexadecimal digits fill a `u64` exactly; more cannot be counted.
const MAX_SIZE_DIGITS: usize = 16;

/// The chunk that ends a canonical chunked body: a zero size and no trailer fields.
pub const LAST_CHUNK: &[u8] = b"0\r\n\r\n";

/// Why a chunked body was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChunkError {
    /// The body breaks rule R5, R6 or R7 of SID 0009: a bad terminator, size, extension or
    /// trailer, or a line or trailer section over its limit.
    Malformed,
}

impl fmt::Display for ChunkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("malformed chunked body")
    }
}

impl std::error::Error for ChunkError {}

/// The result of one [`Decoder::decode`] call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Step {
    /// The number of decoded bytes now at the start of the slice.
    pub output: usize,
    /// The number of raw bytes the call used up. The caller keeps `bytes[consumed..]` and
    /// passes it again, with more bytes behind it, on the next call.
    pub consumed: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum State {
    #[default]
    Size,
    Data,
    DataEnd,
    Trailer,
    Done,
}

/// The state of one chunked body between reads: 24 bytes, no buffer of its own.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Decoder {
    state: State,
    /// Data bytes still owed by the current chunk.
    remaining: u64,
    /// Bytes of trailer section consumed so far.
    trailer_bytes: u32,
}

impl Decoder {
    /// A decoder at the start of a body.
    pub const fn new() -> Decoder {
        Decoder { state: State::Size, remaining: 0, trailer_bytes: 0 }
    }

    /// True once the last chunk and the trailer section have been consumed.
    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// Consumes every complete unit (a line, a run of data, the CRLF after data) at the
    /// start of `bytes` and writes the chunk data it carries to `bytes[..output]`.
    ///
    /// The write index never passes the read index (SID 0009, Lemma 2), so the copy is safe
    /// in place. An incomplete unit is left unconsumed for the next call, after more bytes
    /// have arrived behind it. Once the body is done, the call consumes nothing more, so
    /// bytes of a pipelined request stay in `bytes[consumed..]`.
    ///
    /// # Errors
    ///
    /// [`ChunkError::Malformed`] when the input breaks the grammar. The decoded bytes of
    /// earlier units are then unspecified, and the connection must be closed.
    pub fn decode(&mut self, bytes: &mut [u8]) -> Result<Step, ChunkError> {
        let mut read = 0;
        let mut write = 0;
        loop {
            // `read` only advances over bytes of `bytes`, so it never exceeds its length.
            let rest = bytes.get(read..).unwrap_or_default();
            match self.state {
                State::Size => {
                    let Some(line) = next_line(rest)? else { break };
                    let size = size_line(line.text)?;
                    read += line.length;
                    self.remaining = size;
                    self.state = if size == 0 { State::Trailer } else { State::Data };
                }
                State::Data => {
                    let owed = usize::try_from(self.remaining).unwrap_or(usize::MAX);
                    let count = owed.min(rest.len());
                    if count == 0 {
                        break;
                    }
                    if write != read {
                        // In bounds: `read + count <= bytes.len()` and `write <= read`.
                        bytes.copy_within(read..read + count, write);
                    }
                    read += count;
                    write += count;
                    self.remaining -= count as u64;
                    if self.remaining == 0 {
                        self.state = State::DataEnd;
                    }
                }
                State::DataEnd => match rest {
                    [] | [b'\r'] => break,
                    [b'\r', b'\n', ..] => {
                        read += 2;
                        self.state = State::Size;
                    }
                    _ => return Err(ChunkError::Malformed),
                },
                State::Trailer => {
                    let Some(line) = next_line(rest)? else { break };
                    read += line.length;
                    if line.text.is_empty() {
                        self.state = State::Done;
                        break;
                    }
                    self.add_trailer(line)?;
                }
                State::Done => break,
            }
        }
        Ok(Step { output: write, consumed: read })
    }

    fn add_trailer(&mut self, line: Line<'_>) -> Result<(), ChunkError> {
        // A line is at most MAX_LINE bytes, so the count stays far below `u32::MAX`.
        let length = u32::try_from(line.length).unwrap_or(u32::MAX);
        self.trailer_bytes = self.trailer_bytes.saturating_add(length);
        if self.trailer_bytes as usize > MAX_TRAILER || !field_line(line.text) {
            return Err(ChunkError::Malformed);
        }
        Ok(())
    }
}

/// A complete line: its text without CRLF and its length with CRLF.
#[derive(Clone, Copy)]
struct Line<'a> {
    text: &'a [u8],
    length: usize,
}

/// The next CRLF-terminated line, or `None` while it is incomplete. A line ends at its first
/// LF; anything else that could end a line for some other parser (a lone CR or LF, any
/// control byte but HTAB) makes the line malformed rather than shorter.
fn next_line(bytes: &[u8]) -> Result<Option<Line<'_>>, ChunkError> {
    let window = bytes.get(..MAX_LINE).unwrap_or(bytes);
    let Some(lf) = find_byte(window, b'\n') else {
        return if bytes.len() >= MAX_LINE { Err(ChunkError::Malformed) } else { Ok(None) };
    };
    let text = match window.get(..lf) {
        Some([text @ .., b'\r']) => text,
        _ => return Err(ChunkError::Malformed),
    };
    if run_length(text, FIELD) != text.len() {
        return Err(ChunkError::Malformed);
    }
    Ok(Some(Line { text, length: lf + 1 }))
}

/// The chunk size of a size line: 1 to 16 hexadecimal digits, then valid extensions.
fn size_line(text: &[u8]) -> Result<u64, ChunkError> {
    let digits = text.iter().take_while(|byte| byte.is_ascii_hexdigit()).count();
    if digits == 0 || digits > MAX_SIZE_DIGITS {
        return Err(ChunkError::Malformed);
    }
    let (digits, rest) = text.split_at_checked(digits).ok_or(ChunkError::Malformed)?;
    extensions(rest)?;
    // At most sixteen digits, so the value fits a `u64` without overflow.
    let size = digits.iter().fold(0u64, |size, &digit| size << 4 | u64::from(hex_value(digit)));
    Ok(size)
}

fn hex_value(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        b'A'..=b'F' => digit - b'A' + 10,
        _ => 0,
    }
}

/// `chunk-ext = *( BWS ";" BWS name [ BWS "=" BWS ( token / quoted-string ) ] )`
fn extensions(text: &[u8]) -> Result<(), ChunkError> {
    let mut index = 0;
    while index < text.len() {
        index = skip_space(text, index);
        if text.get(index) != Some(&b';') {
            return Err(ChunkError::Malformed);
        }
        index = token_end(text, skip_space(text, index + 1))?;
        let equals = skip_space(text, index);
        if text.get(equals) != Some(&b'=') {
            continue;
        }
        let value = skip_space(text, equals + 1);
        index = if text.get(value) == Some(&b'"') {
            quoted_end(text, value)?
        } else {
            token_end(text, value)?
        };
    }
    Ok(())
}

fn skip_space(text: &[u8], start: usize) -> usize {
    let rest = text.get(start..).unwrap_or_default();
    start + rest.iter().take_while(|&&byte| byte == b' ' || byte == b'\t').count()
}

/// The end of a non-empty token starting at `start`.
fn token_end(text: &[u8], start: usize) -> Result<usize, ChunkError> {
    let length = run_length(text.get(start..).unwrap_or_default(), TOKEN);
    if length == 0 {
        return Err(ChunkError::Malformed);
    }
    Ok(start + length)
}

/// The end of a quoted string opening at `start`. Control bytes were refused with the line,
/// so every other byte is quoted text or an escaped character.
fn quoted_end(text: &[u8], start: usize) -> Result<usize, ChunkError> {
    let mut index = start + 1;
    while let Some(&byte) = text.get(index) {
        match byte {
            b'"' => return Ok(index + 1),
            b'\\' => index += 2,
            _ => index += 1,
        }
    }
    Err(ChunkError::Malformed)
}

/// A trailer field line: a token name directly followed by a colon.
fn field_line(text: &[u8]) -> bool {
    match find_byte(text, b':').and_then(|colon| text.get(..colon)) {
        Some(name) => is_token(name),
        None => false,
    }
}

/// Writes `data` as one canonical chunk: the size in lower-case hexadecimal without leading
/// zeros, CRLF, the data and CRLF. Empty data writes nothing, since a zero size would end the
/// body; finish a body with [`LAST_CHUNK`].
///
/// # Errors
///
/// Any error of `out`.
pub fn write_chunk<W: Write + ?Sized>(out: &mut W, data: &[u8]) -> io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    let mut line = [0u8; 18];
    let length = chunk_size_line(data.len(), &mut line);
    out.write_all(line.get(..length).unwrap_or_default())?;
    out.write_all(data)?;
    out.write_all(b"\r\n")
}

/// Formats `size` in hexadecimal followed by CRLF into `line`; returns the length used.
fn chunk_size_line(size: usize, line: &mut [u8; 18]) -> usize {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let digits = (usize::BITS - size.leading_zeros()).div_ceil(4).max(1) as usize;
    for (index, slot) in line.iter_mut().take(digits).enumerate() {
        let shift = 4 * (digits - 1 - index);
        *slot = DIGITS[(size >> shift) & 15];
    }
    // A `usize` has at most sixteen hexadecimal digits, so CRLF fits behind them.
    line[digits] = b'\r';
    line[digits + 1] = b'\n';
    digits + 2
}

#[cfg(test)]
mod tests;

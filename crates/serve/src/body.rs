//! Reading a request body under a caller's bound.
//!
//! A `Content-Length` body is read straight into the caller's buffer. A chunked body is read
//! through a small transfer buffer, decoded in place there by `sibuna_http::chunked`, and
//! copied into the caller's buffer, so the bound applies to the decoded body.

use std::io::{self, Read};

use sibuna_http::chunked::{Decoder, MAX_LINE};

use crate::error::ServeError;
use crate::head::Framing;

/// The transfer buffer of a chunked body. It holds the longest chunk line the decoder
/// accepts plus room to read behind it, so the decoder always makes progress.
pub(crate) const TRANSFER: usize = 2 * MAX_LINE;

/// Reads the whole body framed by `framing` from `input` into `output` and returns its
/// length. `transfer` is scratch space of at least [`TRANSFER`] bytes for chunked bodies.
///
/// # Errors
///
/// [`ServeError::TooLarge`] when the body does not fit `output`; [`ServeError::EndOfStream`]
/// when the input ends inside the body; [`ServeError::InvalidRequest`] for a malformed
/// chunked body; [`ServeError::ReadFailed`] when a read fails.
pub(crate) fn read_body<R: Read>(
    input: &mut R,
    framing: Framing,
    output: &mut [u8],
    transfer: &mut [u8],
) -> Result<usize, ServeError> {
    match framing {
        Framing::Empty => Ok(0),
        Framing::Length(length) => {
            let body = output.get_mut(..length).ok_or(ServeError::TooLarge)?;
            fill(input, body)?;
            Ok(length)
        }
        Framing::Chunked => {
            let mut written = 0;
            decode_chunked(input, transfer, |data| {
                let end = written + data.len();
                output.get_mut(written..end).ok_or(ServeError::TooLarge)?.copy_from_slice(data);
                written = end;
                Ok(())
            })?;
            Ok(written)
        }
    }
}

/// Reads and drops the whole body framed by `framing`, using `transfer` as scratch space.
///
/// # Errors
///
/// As [`read_body`], except that no body is too large.
pub(crate) fn discard_body<R: Read>(
    input: &mut R,
    framing: Framing,
    transfer: &mut [u8],
) -> Result<(), ServeError> {
    match framing {
        Framing::Empty => Ok(()),
        Framing::Length(mut remaining) => {
            while remaining > 0 {
                let piece = transfer.len().min(remaining);
                let count = read_some(input, transfer.get_mut(..piece).unwrap_or_default())?;
                remaining -= count;
            }
            Ok(())
        }
        Framing::Chunked => decode_chunked(input, transfer, |_| Ok(())),
    }
}

/// Fills `buffer` exactly from `input`.
fn fill<R: Read>(input: &mut R, buffer: &mut [u8]) -> Result<(), ServeError> {
    let mut filled = 0;
    while let Some(space) = buffer.get_mut(filled..).filter(|space| !space.is_empty()) {
        filled += read_some(input, space)?;
    }
    Ok(())
}

/// One read of at least one byte into a non-empty `buffer`.
fn read_some<R: Read>(input: &mut R, buffer: &mut [u8]) -> Result<usize, ServeError> {
    loop {
        match input.read(buffer) {
            Ok(0) => return Err(ServeError::EndOfStream),
            Ok(count) => return Ok(count),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ServeError::ReadFailed),
        }
    }
}

/// Decodes a chunked body from `input`, passing each run of decoded bytes to `sink`.
fn decode_chunked<R: Read>(
    input: &mut R,
    transfer: &mut [u8],
    mut sink: impl FnMut(&[u8]) -> Result<(), ServeError>,
) -> Result<(), ServeError> {
    let mut decoder = Decoder::new();
    // Undecoded bytes are `transfer[..pending]`.
    let mut pending = 0;
    while !decoder.is_done() {
        let space = transfer.get_mut(pending..).unwrap_or_default();
        if space.is_empty() {
            // The decoder consumes any unit shorter than MAX_LINE, so a full buffer means the
            // caller's transfer buffer is shorter than TRANSFER.
            return Err(ServeError::InvalidRequest);
        }
        pending += read_some(input, space)?;
        let raw = transfer.get_mut(..pending).unwrap_or_default();
        let step = decoder.decode(raw).map_err(|_| ServeError::InvalidRequest)?;
        sink(raw.get(..step.output).unwrap_or_default())?;
        raw.copy_within(step.consumed.., 0);
        pending -= step.consumed;
    }
    Ok(())
}

#[cfg(test)]
mod tests;

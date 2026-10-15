//! DEFLATE (RFC 1951) and gzip (RFC 1952) decompression with explicit bounds, in safe Rust
//! with no dependencies.
//!
//! Two ways in:
//!
//! - One call: [`gunzip`] and [`inflate`] decompress a whole buffer into a `Vec<u8>`, and
//!   [`decompress_stream`] copies from an [`io::Read`](std::io::Read) to an
//!   [`io::Write`](std::io::Write) in bounded memory.
//! - Streaming: a [`Decoder`] takes input in chunks of any size and writes output into
//!   caller buffers ([`Decoder::decompress`]) or a sink ([`Decoder::decompress_to`]), so a
//!   caller can process a large file with a fixed amount of memory.
//!
//! ```
//! use sibuna_inflate::{gunzip, Limits};
//!
//! // "Hello world\n" as a gzip member with a stored block.
//! let gz = [
//!     0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x0c, 0x00, 0xf3,
//!     0xff, b'H', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l', b'd', b'\n', 0xd5,
//!     0xe0, 0x39, 0xb7, 0x0c, 0x00, 0x00, 0x00,
//! ];
//! let limits = Limits { max_output_bytes: 1024, ..Limits::default() };
//! assert_eq!(gunzip(&gz, limits).unwrap(), b"Hello world\n");
//! ```
//!
//! Every stream is bounded by [`Limits`]: compressed bytes consumed, bytes produced and gzip
//! members. Corrupt or hostile input yields an [`Error`], never a panic, and the work is
//! linear in the input and output sizes (one match code produces at most 258 bytes).
//!
//! The decoder is table-driven: an 11-bit first-level table resolves most literal/length
//! codes in one lookup and an 8-bit table most distance codes, with zlib-style subtables for
//! longer codes. On DB-IP-like CSV it decompresses about 1.35 times as fast as Zig 0.16
//! `std.compress.flate` (565 MiB/s against 424 MiB/s in one run, CRC included). Errors are
//! detected in the same order as zlib and Zig, including over-subscribed and incomplete code
//! sets, distances before the start of the output, reserved block types and symbols, and
//! truncation anywhere.
//!
//! # Changes from the Zig version
//!
//! Sibuna's Zig GeoIP loader decompressed DB-IP downloads with Zig 0.16
//! `std.compress.flate.Decompress` in `libs/geoip/src/gzip.zig`, checking the gzip footer and
//! the bounds itself. This crate keeps its acceptance set with these deliberate changes:
//!
//! - The decoder verifies the CRC-32 and size of each gzip member itself
//!   ([`Error::CrcMismatch`], [`Error::SizeMismatch`]) instead of leaving it to the caller,
//!   and reports bytes after the stream as [`Error::TrailingData`]. The GeoIP loader mapped
//!   all three to `InvalidChecksum`.
//! - Concatenated gzip members: Zig's decoder stops after one member, and the loader rejected
//!   anything after it. The default [`Limits::max_members`] of one keeps that behaviour;
//!   a larger bound accepts concatenated members as RFC 1952 allows, each one verified.
//! - The header CRC (flag FHCRC) is checked, and reserved flag bits are rejected, as RFC 1952
//!   requires; Zig skipped the CRC and ignored the flags. The gzip magic, method and flags
//!   are checked as soon as their byte arrives, so a short non-gzip input is
//!   [`Error::NotGzip`] where Zig reported `EndOfStream`.
//! - The bounds are explicit [`Limits`] errors ([`Error::InputLimit`], [`Error::OutputLimit`])
//!   rather than the caller counting bytes.
//! - Zig 0.16's decoder panics with an integer overflow (in safety-checked builds) on some
//!   truncated raw DEFLATE streams; we report [`Error::Truncated`] like everywhere else.
//! - Not a change, but worth knowing: as in Zig's loader, zero padding or other bytes after
//!   the last member are [`Error::TrailingData`], where `gzip -d` only warns.
//! - The zlib container (RFC 1950) is not ported; Sibuna never used it.

mod bits;
pub mod crc32;
mod decode;
mod decoder;
mod error;
mod gzip;
mod huffman;
mod inflate;
mod window;

use std::io;

pub use decoder::{Decoder, Format, Limits, Progress, Status};
pub use error::Error;

/// Decompresses a whole gzip file held in `input`.
///
/// Borrows `input` for the call and returns the concatenated output of its members. Fails
/// with [`Error::InputLimit`] when `input` is longer than `limits.max_input_bytes`, with
/// [`Error::TrailingData`] when bytes follow the last member allowed by `limits`, and with
/// any decoding error.
pub fn gunzip(input: &[u8], limits: Limits) -> Result<Vec<u8>, Error> {
    decompress_all(Format::Gzip, input, limits)
}

/// Decompresses a raw DEFLATE stream held in `input`.
///
/// Borrows `input` for the call. Fails like [`gunzip`]; bytes after the final block are
/// [`Error::TrailingData`] (a caller that expects them uses a [`Decoder`], which reports
/// where the stream ended).
pub fn inflate(input: &[u8], limits: Limits) -> Result<Vec<u8>, Error> {
    decompress_all(Format::Raw, input, limits)
}

fn decompress_all(format: Format, input: &[u8], limits: Limits) -> Result<Vec<u8>, Error> {
    if input.len() as u64 > limits.max_input_bytes {
        return Err(Error::InputLimit);
    }
    let mut output = Vec::new();
    // A single gzip member states its size modulo 2^32 in its last four bytes. Use it as a
    // capacity hint when it is plausible: within the output limit and the 1032:1 ratio
    // DEFLATE can reach.
    if let (Format::Gzip, Some(size)) = (format, input.last_chunk::<4>()) {
        let size = u64::from(u32::from_le_bytes(*size));
        if size <= limits.max_output_bytes && size <= 1032 * input.len() as u64 {
            // Only a hint: when the reservation fails, the vector grows on demand.
            let _ = output.try_reserve_exact(size as usize);
        }
    }
    let mut decoder = Decoder::new(format, limits);
    let progress = decoder.decompress_into_vec(input, &mut output)?;
    if progress.consumed != input.len() {
        return Err(Error::TrailingData);
    }
    Ok(output)
}

/// Decompresses everything `reader` yields and writes it to `sink`, in bounded memory.
///
/// Reads in 64 KiB chunks and returns the number of bytes written. Decoding errors come back
/// as [`io::ErrorKind::InvalidData`] wrapping an [`Error`], including
/// [`Error::TrailingData`] when the reader yields bytes after the stream; reader and sink
/// errors come back unchanged.
pub fn decompress_stream<R, W>(
    format: Format,
    reader: &mut R,
    sink: &mut W,
    limits: Limits,
) -> io::Result<u64>
where
    R: io::Read + ?Sized,
    W: io::Write + ?Sized,
{
    let mut decoder = Decoder::new(format, limits);
    let mut buffer = vec![0u8; 64 * 1024];
    let (mut start, mut end) = (0, 0);
    let mut at_end = false;
    loop {
        if start == end && !at_end {
            start = 0;
            end = read_retrying(reader, &mut buffer)?;
            at_end = end == 0;
        }
        let progress = decoder.decompress_to(&buffer[start..end], at_end, sink)?;
        start += progress.consumed;
        if progress.status == Status::Done {
            let trailing = start < end || (!at_end && read_retrying(reader, &mut buffer)? > 0);
            if trailing {
                return Err(io::Error::new(io::ErrorKind::InvalidData, Error::TrailingData));
            }
            return Ok(decoder.output_byte_count());
        }
    }
}

/// Reads into `buffer`, retrying reads that were interrupted.
fn read_retrying<R: io::Read + ?Sized>(reader: &mut R, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        match reader.read(buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

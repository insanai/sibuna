//! Helpers shared by the integration tests.

#![allow(dead_code)]

use sibuna_inflate::{Decoder, Error, Format, Limits, Status};

/// Decompresses `data` with a streaming decoder, feeding `chunk` input bytes and offering
/// `room` output bytes per call. Fails with [`Error::TrailingData`] when bytes follow the
/// stream, like the one-call helpers.
pub fn decode_chunked(
    format: Format,
    data: &[u8],
    chunk: usize,
    room: usize,
    limits: Limits,
) -> Result<Vec<u8>, Error> {
    let mut decoder = Decoder::new(format, limits);
    let mut output = Vec::new();
    let mut buffer = vec![0u8; room];
    let mut input = data;
    // Every call either consumes input, produces output or finishes, so this bound only
    // guards against a decoder that stops making progress.
    for _ in 0..4 * (data.len() + 1) * (1 + (1 << 20) / room.max(1)) {
        let size = input.len().min(chunk);
        let progress = decoder.decompress(&input[..size], size == input.len(), &mut buffer)?;
        output.extend_from_slice(&buffer[..progress.written]);
        input = &input[progress.consumed..];
        if progress.status == Status::Done {
            assert!(decoder.is_done());
            return if input.is_empty() { Ok(output) } else { Err(Error::TrailingData) };
        }
    }
    panic!("the decoder made no progress");
}

/// Returns `data` decoded in every way the tests care about, after checking that all ways
/// agree: one call, one byte at a time, odd chunks into a small buffer, and a sink.
pub fn decode_every_way(format: Format, data: &[u8], limits: Limits) -> Result<Vec<u8>, Error> {
    let whole = match format {
        Format::Gzip => sibuna_inflate::gunzip(data, limits),
        Format::Raw => sibuna_inflate::inflate(data, limits),
    };
    for (chunk, room) in [(1, 1 << 16), (7, 5), (4096, 1), (usize::MAX, 333)] {
        // A one-byte output buffer makes too many calls for large outputs.
        if room == 1 && data.len() > 10_000 {
            continue;
        }
        let streamed = decode_chunked(format, data, chunk, room, limits);
        assert_eq!(streamed, whole, "chunk {chunk}, room {room}");
    }
    let mut sink = Vec::new();
    let mut reader = data;
    let streamed = sibuna_inflate::decompress_stream(format, &mut reader, &mut sink, limits);
    match (&whole, streamed) {
        (Ok(output), Ok(count)) => {
            assert_eq!(&sink, output);
            assert_eq!(count, output.len() as u64);
        }
        (Err(error), Err(io_error)) => {
            assert_eq!(io_error.kind(), std::io::ErrorKind::InvalidData);
            let inner = io_error.get_ref().and_then(|e| e.downcast_ref::<Error>());
            assert_eq!(inner, Some(error));
        }
        (whole, streamed) => panic!("one call gave {whole:?}, the stream gave {streamed:?}"),
    }
    whole
}

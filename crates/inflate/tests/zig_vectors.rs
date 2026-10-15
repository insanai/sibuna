//! Test vectors from Zig 0.16 `std.compress.flate.Decompress` and error cases whose
//! expected error was produced by running Zig 0.16 std on the same bytes.

mod common;

use common::{decode_chunked, decode_every_way};
use sibuna_inflate::{Decoder, Error, Format, Limits, Status, inflate};

fn raw(data: &[u8]) -> Result<Vec<u8>, Error> {
    decode_every_way(Format::Raw, data, Limits::default())
}

fn gzip(data: &[u8]) -> Result<Vec<u8>, Error> {
    decode_every_way(Format::Gzip, data, Limits::default())
}

/// A stored block holding "Hello world\n".
const STORED_HELLO: [u8; 17] = [
    0b0000_0001,
    0b0000_1100,
    0x00,
    0b1111_0011,
    0xff,
    b'H',
    b'e',
    b'l',
    b'l',
    b'o',
    b' ',
    b'w',
    b'o',
    b'r',
    b'l',
    b'd',
    0x0a,
];
/// A fixed Huffman block holding "Hello world\n".
const FIXED_HELLO: [u8; 14] =
    [0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0xcf, 0x2f, 0xca, 0x49, 0xe1, 0x02, 0x00];
/// A dynamic Huffman block holding "ABCDEABCD ABCDEABCD".
const DYNAMIC_ABCDE: [u8; 24] = [
    0x3d, 0xc6, 0x39, 0x11, 0x00, 0x00, 0x0c, 0x02, 0x30, 0x2b, 0xb5, 0x52, 0x1e, 0xff, 0x96,
    0x38, 0x16, 0x96, 0x5c, 0x1e, 0x94, 0xcb, 0x6d, 0x01,
];
const GZIP_HEADER: [u8; 10] = [0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03];
const HELLO_FOOTER: [u8; 8] = [0xd5, 0xe0, 0x39, 0xb7, 0x0c, 0x00, 0x00, 0x00];

fn member(body: &[u8], footer: &[u8]) -> Vec<u8> {
    [&GZIP_HEADER[..], body, footer].concat()
}

#[test]
fn non_compressed_block() {
    assert_eq!(raw(&STORED_HELLO).unwrap(), b"Hello world\n");
}

#[test]
fn fixed_code_block() {
    assert_eq!(raw(&FIXED_HELLO).unwrap(), b"Hello world\n");
}

#[test]
fn dynamic_block() {
    assert_eq!(raw(&DYNAMIC_ABCDE).unwrap(), b"ABCDEABCD ABCDEABCD");
}

#[test]
fn gzip_blocks_of_each_type() {
    assert_eq!(gzip(&member(&STORED_HELLO, &HELLO_FOOTER)).unwrap(), b"Hello world\n");
    assert_eq!(gzip(&member(&FIXED_HELLO, &HELLO_FOOTER)).unwrap(), b"Hello world\n");
    let footer = [0x17, 0x1c, 0x39, 0xb4, 0x13, 0x00, 0x00, 0x00];
    assert_eq!(gzip(&member(&DYNAMIC_ABCDE, &footer)).unwrap(), b"ABCDEABCD ABCDEABCD");
}

#[test]
fn gzip_header_with_name() {
    let data = [
        0x1f, 0x8b, 0x08, 0x08, 0xe5, 0x70, 0xb1, 0x65, 0x00, 0x03, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
        0x2e, 0x74, 0x78, 0x74, 0x00, 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0xcf, 0x2f, 0xca,
        0x49, 0xe1, 0x02, 0x00, 0xd5, 0xe0, 0x39, 0xb7, 0x0c, 0x00, 0x00, 0x00,
    ];
    assert_eq!(gzip(&data).unwrap(), b"Hello world\n");
}

#[test]
fn gzip_header() {
    // Truncated header.
    assert_eq!(gzip(&[0x1f, 0x8b]), Err(Error::Truncated));
    // Wrong compression method (Zig: BadGzipHeader).
    let mut header = GZIP_HEADER;
    header[2] = 0x09;
    assert_eq!(gzip(&header), Err(Error::UnsupportedMethod));
    // Truncated checksum, then truncated size field.
    assert_eq!(gzip(&member(&[0x03, 0x00], &[0, 0, 0])), Err(Error::Truncated));
    assert_eq!(gzip(&member(&[0x03, 0x00], &[0, 0, 0, 0, 0, 0, 0])), Err(Error::Truncated));
    // FNAME and FHCRC, then an empty stored block.
    let data = [
        0x1f, 0x8b, 0x08, 0x12, 0x00, 0x09, 0x6e, 0x88, 0x00, 0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f,
        0x00, 0x99, 0xd6, 0x01, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    assert_eq!(gzip(&data).unwrap(), b"");
}

#[test]
fn invalid_block_type() {
    assert_eq!(raw(&[0b110]), Err(Error::InvalidBlockType));
}

#[test]
fn reading_into_empty_buffer() {
    let mut decoder = Decoder::new(Format::Raw, Limits::default());
    let progress = decoder.decompress(&STORED_HELLO, true, &mut []).unwrap();
    assert_eq!((progress.written, progress.status), (0, Status::OutputFull));
}

// Zig's "zlib should not overshoot", for the DEFLATE stream inside that zlib data: the
// decoder must stop exactly at the end of the stream and leave the zlib checksum and four
// extra bytes unconsumed.
#[test]
fn should_not_overshoot() {
    let data = [
        0x73, 0xce, 0x2f, 0xa8, 0x2c, 0xca, 0x4c, 0xcf, 0x28, 0x51, 0x08, 0xcf, 0xcc, 0xc9, 0x49,
        0xcd, 0x55, 0x28, 0x4b, 0xcc, 0x53, 0x08, 0x4e, 0xce, 0x48, 0xcc, 0xcc, 0xd6, 0x51, 0x08,
        0xce, 0xcc, 0x4b, 0x4f, 0x2c, 0xc8, 0x2f, 0x4a, 0x55, 0x30, 0xb4, 0xb4, 0x34, 0xd5, 0xb5,
        0x34, 0x03, 0x00, 0x8b, 0x61, 0x0f, 0xa4, 0x52, 0x5a, 0x94, 0x12,
    ];
    let text = b"Copyright Willem van Schaik, Singapore 1995-96";
    for chunk in [1, 5, data.len()] {
        let mut decoder = Decoder::new(Format::Raw, Limits::default());
        let mut output = [0u8; 128];
        let (mut offset, mut written) = (0, 0);
        loop {
            let end = (offset + chunk).min(data.len());
            let progress = decoder
                .decompress(&data[offset..end], end == data.len(), &mut output[written..])
                .unwrap();
            offset += progress.consumed;
            written += progress.written;
            if progress.status == Status::Done {
                break;
            }
        }
        assert_eq!(&output[..written], text);
        assert_eq!(&data[offset..], &data[data.len() - 8..], "chunk {chunk}");
    }
    assert_eq!(inflate(&data, Limits::default()), Err(Error::TrailingData));
}

// Each input below was decoded by Zig 0.16 std.compress.flate.Decompress (container .raw);
// the expected error is the one Zig returned. The short ones are mutations of gzip output
// found by differential testing; the named ones were written bit by bit.
#[test]
fn errors_match_zig() {
    let cases: [(&[u8], Error); 17] = [
        (&[], Error::Truncated),
        (&[0x2c, 0x2e, 0x32, 0xd5], Error::IncompleteTree),
        (&[0xcc, 0x2e, 0xce, 0x8e, 0x32], Error::IncompleteTree),
        (&[0x87, 0x5e], Error::InvalidBlockType),
        (&[0x82, 0x7c], Error::InvalidCode),
        (&[0xbb, 0x4c, 0xce, 0xd7, 0xb4, 0x4f, 0x46], Error::InvalidCode),
        (&[0xf5, 0xab, 0x26], Error::InvalidDynamicHeader),
        (&[0xc5, 0x5f, 0x76], Error::InvalidDynamicHeader),
        (&[0x03, 0xba, 0xed], Error::DistanceTooFar),
        (&[0xa3, 0x35, 0x79, 0xa8], Error::DistanceTooFar),
        (&[0x8d, 0x22, 0x92, 0xce, 0x6d], Error::OversubscribedTree),
        (&[0x3c, 0xca, 0x66, 0x66, 0x14, 0xa0], Error::OversubscribedTree),
        (&[0x51, 0x6d, 0x48, 0x50, 0x45], Error::StoredLengthMismatch),
        // A match at distance 1 before any output.
        (&[0x03, 0x02, 0x00], Error::DistanceTooFar),
        // HLIT of 287 codes.
        (&[0xf5, 0x00, 0x00], Error::InvalidDynamicHeader),
        // Code length repeat 16 as the first length.
        (&[0x05, 0x00, 0x02, 0x24], Error::InvalidDynamicHeader),
        // The reserved literal/length symbol 286 in a fixed block.
        (&[0x1b, 0x03], Error::InvalidCode),
    ];
    for (data, error) in cases {
        assert_eq!(raw(data), Err(error), "input {data:02x?}");
    }
    // The reserved distance symbol 30 after a literal.
    assert_eq!(raw(&[0x4b, 0x04, 0x3e]), Err(Error::InvalidCode));
    // 256 literals of eight bits and no end-of-block code.
    let mut missing_end = vec![0x05, 0x20, 0x00, 0x24];
    missing_end.extend_from_slice(&[0xff; 32]);
    missing_end.push(0x00);
    assert_eq!(raw(&missing_end), Err(Error::MissingEndOfBlock));
}

// A non-final stored block followed by a fixed block with an overlapping match. Taking the
// stored bytes straight from the input once broke the bit buffer's lookahead.
#[test]
fn stored_block_then_fixed_block() {
    let data = [0x00, 0x03, 0x00, 0xfc, 0xff, b'x', b'y', b'z', 0x4b, 0x4c, 0x42, 0x86, 0x00];
    assert_eq!(raw(&data).unwrap(), b"xyzababababababab");
}

#[test]
fn truncation_is_reported_at_every_length() {
    for data in [&STORED_HELLO[..], &FIXED_HELLO, &DYNAMIC_ABCDE] {
        for len in 0..data.len() {
            assert_eq!(raw(&data[..len]), Err(Error::Truncated), "{len} of {data:02x?}");
        }
    }
}

#[test]
fn errors_are_sticky() {
    let mut decoder = Decoder::new(Format::Raw, Limits::default());
    let mut output = [0u8; 16];
    assert_eq!(decoder.decompress(&[0b110], true, &mut output), Err(Error::InvalidBlockType));
    assert_eq!(decoder.decompress(&FIXED_HELLO, true, &mut output), Err(Error::InvalidBlockType));
    decoder.reset();
    let progress = decoder.decompress(&FIXED_HELLO, true, &mut output).unwrap();
    assert_eq!(&output[..progress.written], b"Hello world\n");
    assert_eq!(
        decode_chunked(Format::Raw, &FIXED_HELLO, 1, 1, Limits::default()).unwrap(),
        b"Hello world\n"
    );
}

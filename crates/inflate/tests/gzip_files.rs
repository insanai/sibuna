//! Files produced by the system `gzip` (1.13): levels 1, 6 and 9, with and without a stored
//! name, stored blocks (incompressible data), fixed Huffman blocks (short inputs) and an
//! empty member; plus the GeoIP test file of the Zig repository.

mod common;

use common::{decode_chunked, decode_every_way};
use sibuna_inflate::crc32::crc32;
use sibuna_inflate::{Decoder, Error, Format, Limits, Status, gunzip};

const SAMPLE: &[u8] = include_bytes!("data/sample.csv");
const SAMPLE_1: &[u8] = include_bytes!("data/sample.csv.1.gz");
const SAMPLE_6: &[u8] = include_bytes!("data/sample.csv.6.gz");
const SAMPLE_9: &[u8] = include_bytes!("data/sample.csv.9.gz");
const SAMPLE_NAMED: &[u8] = include_bytes!("data/sample.csv.named.gz");
const RANDOM: &[u8] = include_bytes!("data/random.bin.gz");
const HELLO: &[u8] = include_bytes!("data/hello.gz");
const EMPTY: &[u8] = include_bytes!("data/empty.gz");
/// From the Zig repository, libs/geoip/src/testdata/countries.csv.gz.
const COUNTRIES: &[u8] = include_bytes!("data/countries.csv.gz");

fn gzip(data: &[u8]) -> Result<Vec<u8>, Error> {
    decode_every_way(Format::Gzip, data, Limits::default())
}

/// The bytes of `random.bin.gz`: a 64-bit LCG, top byte of each state.
fn random_bytes() -> Vec<u8> {
    let mut state: u64 = 1951;
    (0..20_000)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 56) as u8
        })
        .collect()
}

/// Strips the ten-byte header and eight-byte footer of a gzip file without optional fields.
fn deflate_part(gz: &[u8]) -> &[u8] {
    assert_eq!(gz[3], 0, "the file has optional header fields");
    &gz[10..gz.len() - 8]
}

#[test]
fn gzip_levels_and_name() {
    for gz in [SAMPLE_1, SAMPLE_6, SAMPLE_9, SAMPLE_NAMED] {
        assert_eq!(gzip(gz).unwrap(), SAMPLE);
    }
    for gz in [SAMPLE_1, SAMPLE_6, SAMPLE_9] {
        let raw = decode_every_way(Format::Raw, deflate_part(gz), Limits::default());
        assert_eq!(raw.unwrap(), SAMPLE);
    }
}

#[test]
fn stored_fixed_and_empty() {
    assert_eq!(gzip(RANDOM).unwrap(), random_bytes());
    assert_eq!(gzip(HELLO).unwrap(), b"hello, hello, hello!\n");
    assert_eq!(gzip(EMPTY).unwrap(), b"");
    assert_eq!(gzip(&[]), Err(Error::Truncated));
}

// The decompression half of the Zig test "gzip CRC corruption and shutdown cannot activate
// a partial country dataset" in libs/geoip/src/gzip.zig: the file decodes to two rows, and
// flipping a bit of the CRC fails the check (Zig: InvalidChecksum).
#[test]
fn geoip_countries_file() {
    let text = gzip(COUNTRIES).unwrap();
    assert_eq!(text, b"8.8.8.0,8.8.8.255,US\n9.9.9.0,9.9.9.255,DE\n");
    let mut corrupt = COUNTRIES.to_vec();
    let at = corrupt.len() - 8;
    corrupt[at] ^= 1;
    assert_eq!(gzip(&corrupt), Err(Error::CrcMismatch));
}

#[test]
fn corrupted_footer() {
    let mut bad_size = SAMPLE_6.to_vec();
    let at = bad_size.len() - 1;
    bad_size[at] ^= 0x80;
    assert_eq!(gzip(&bad_size), Err(Error::SizeMismatch));
    let mut bad_crc = SAMPLE_6.to_vec();
    let at = bad_crc.len() - 5;
    bad_crc[at] ^= 0x01;
    assert_eq!(gzip(&bad_crc), Err(Error::CrcMismatch));
}

#[test]
fn truncated_at_every_length() {
    for gz in [HELLO, COUNTRIES, EMPTY, SAMPLE_NAMED] {
        for len in 0..gz.len() {
            assert_eq!(gunzip(&gz[..len], Limits::default()), Err(Error::Truncated), "{len}");
            // Streaming every prefix of the large file is slow in debug builds; the header,
            // the first block header and the footer are covered fully, the rest sampled.
            if len < 400 || len + 16 > gz.len() || len % 61 == 0 {
                let streamed =
                    decode_chunked(Format::Gzip, &gz[..len], 1 + len % 5, 64, Limits::default());
                assert_eq!(streamed, Err(Error::Truncated), "{len}");
            }
        }
    }
}

#[test]
fn concatenated_members() {
    let both = [HELLO, COUNTRIES, EMPTY, SAMPLE_9].concat();
    let expected =
        [&b"hello, hello, hello!\n"[..], b"8.8.8.0,8.8.8.255,US\n9.9.9.0,9.9.9.255,DE\n", SAMPLE]
            .concat();
    let many = Limits { max_members: 4, ..Limits::default() };
    assert_eq!(decode_every_way(Format::Gzip, &both, many).unwrap(), expected);
    // The default allows one member, as the Zig GeoIP loader did.
    assert_eq!(gzip(&both), Err(Error::TrailingData));
    let three = Limits { max_members: 3, ..Limits::default() };
    assert_eq!(gunzip(&both, three), Err(Error::TrailingData));
    // A streaming decoder stops after the last allowed member and leaves the rest.
    let mut decoder = Decoder::new(Format::Gzip, Limits::default());
    let mut output = vec![0u8; 100];
    let progress = decoder.decompress(&both, true, &mut output).unwrap();
    assert_eq!(progress.status, Status::Done);
    assert_eq!(progress.consumed, HELLO.len());
    assert_eq!(decoder.member_count(), 1);
    // Bytes after a member that cannot start another one are trailing data.
    let unlimited = Limits { max_members: u32::MAX, ..Limits::default() };
    let padded = [HELLO, &[0, 0, 0, 0]].concat();
    assert_eq!(gunzip(&padded, unlimited), Err(Error::TrailingData));
}

#[test]
fn optional_header_fields() {
    // FTEXT, FEXTRA, FNAME, FCOMMENT and FHCRC around the DEFLATE data of hello.gz.
    let mut header = vec![0x1f, 0x8b, 8, 0x1f, 0x12, 0x34, 0x56, 0x78, 2, 3];
    header.extend_from_slice(&[4, 0, b'A', b'B', 0, 0]);
    header.extend_from_slice(b"hello.txt\0a comment\0");
    let header_crc = (crc32(&header) & 0xffff) as u16;
    header.extend_from_slice(&header_crc.to_le_bytes());
    let file = [&header[..], &HELLO[10..]].concat();
    assert_eq!(gzip(&file).unwrap(), b"hello, hello, hello!\n");
    let mut bad = file.clone();
    bad[header.len() - 1] ^= 0x40;
    assert_eq!(gzip(&bad), Err(Error::HeaderCrcMismatch));
    let mut reserved = HELLO.to_vec();
    reserved[3] = 0x80;
    assert_eq!(gzip(&reserved), Err(Error::ReservedFlags));
    assert_eq!(gzip(b"PK\x03\x04 not gzip"), Err(Error::NotGzip));
}

#[test]
fn output_limit_is_exact() {
    let exact = Limits { max_output_bytes: SAMPLE.len() as u64, ..Limits::default() };
    assert_eq!(decode_every_way(Format::Gzip, SAMPLE_6, exact).unwrap(), SAMPLE);
    let short = Limits { max_output_bytes: SAMPLE.len() as u64 - 1, ..Limits::default() };
    assert_eq!(decode_every_way(Format::Gzip, SAMPLE_6, short), Err(Error::OutputLimit));
    let stored = Limits { max_output_bytes: 19_999, ..Limits::default() };
    assert_eq!(decode_every_way(Format::Gzip, RANDOM, stored), Err(Error::OutputLimit));
    let nothing = Limits { max_output_bytes: 0, ..Limits::default() };
    assert_eq!(gunzip(EMPTY, nothing).unwrap(), b"");
    assert_eq!(gunzip(HELLO, nothing), Err(Error::OutputLimit));
}

#[test]
fn input_limit() {
    let exact = Limits { max_input_bytes: SAMPLE_6.len() as u64, ..Limits::default() };
    assert_eq!(gunzip(SAMPLE_6, exact).unwrap(), SAMPLE);
    let short = Limits { max_input_bytes: SAMPLE_6.len() as u64 - 1, ..Limits::default() };
    assert_eq!(gunzip(SAMPLE_6, short), Err(Error::InputLimit));
    assert_eq!(decode_chunked(Format::Gzip, SAMPLE_6, 100, 4096, short), Err(Error::InputLimit));
}

#[test]
fn counters_and_reset() {
    let mut decoder = Decoder::new(Format::Gzip, Limits::default());
    let mut sink = Vec::new();
    let progress = decoder.decompress_to(SAMPLE_6, true, &mut sink).unwrap();
    assert_eq!(progress.status, Status::Done);
    assert_eq!(sink, SAMPLE);
    assert_eq!(decoder.input_byte_count(), SAMPLE_6.len() as u64);
    assert_eq!(decoder.output_byte_count(), SAMPLE.len() as u64);
    assert_eq!(decoder.member_count(), 1);
    assert!(decoder.is_done());
    decoder.reset();
    sink.clear();
    decoder.decompress_to(HELLO, true, &mut sink).unwrap();
    assert_eq!(sink, b"hello, hello, hello!\n");
}

#[test]
fn sink_errors_pass_through() {
    struct Full;
    impl std::io::Write for Full {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("disk full"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut decoder = Decoder::new(Format::Gzip, Limits::default());
    let error = decoder.decompress_to(HELLO, true, &mut Full).unwrap_err();
    assert_eq!(error.to_string(), "disk full");
}

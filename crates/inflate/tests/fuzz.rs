//! Deterministic fuzzing against a naive reference decoder.
//!
//! A xorshift generator mutates valid gzip and DEFLATE streams (bit flips, random bytes,
//! truncation, duplication, splicing) and every input is decoded by the crate and by the
//! reference below, which reads one bit at a time and decodes Huffman codes by the
//! canonical-code definition, as zlib's `puff.c` does. Both must agree on the output or
//! the error, the output must respect the limit, and nothing may panic. Every eighth input
//! is also decoded in random chunks into a small buffer, which must agree with one call.
//!
//! `cargo test` runs 100,000 inputs; the ignored test runs ten times as many.

use sibuna_inflate::crc32::crc32;
use sibuna_inflate::{Decoder, Error, Format, Limits, Status};

/// Marsaglia's xorshift64: small, fast and the same everywhere.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// Returns a number below `bound` (which is not zero).
    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

// ---------------------------------------------------------------------------------------
// The reference decoder.
// ---------------------------------------------------------------------------------------

/// Reads bits one at a time; past the end it reads zeros and remembers the overrun, so a
/// code can be told apart from no code before truncation is reported (Zig's order).
struct Bits<'a> {
    data: &'a [u8],
    bit: usize,
}

impl Bits<'_> {
    fn bit(&mut self) -> u32 {
        let byte = self.data.get(self.bit / 8).copied().unwrap_or(0);
        self.bit += 1;
        u32::from(byte >> ((self.bit - 1) % 8)) & 1
    }

    fn overrun(&self) -> bool {
        self.bit > self.data.len() * 8
    }

    fn take(&mut self, count: u32) -> Result<u32, Error> {
        let value = (0..count).fold(0, |value, i| value | self.bit() << i);
        if self.overrun() { Err(Error::Truncated) } else { Ok(value) }
    }

    fn align(&mut self) {
        self.bit = self.bit.next_multiple_of(8);
    }

    fn byte(&mut self) -> Result<u8, Error> {
        self.take(8).map(|value| value as u8)
    }
}

/// A canonical Huffman code: how many codes each length has and the symbols in code order.
struct Code {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl Code {
    /// Builds the code with the completeness rules of zlib and Zig.
    fn new(lens: &[u8], allow_single: bool) -> Result<Code, Error> {
        let mut counts = [0u16; 16];
        for &len in lens {
            counts[usize::from(len)] += 1;
        }
        counts[0] = 0;
        let mut left = 1i32;
        for &count in &counts[1..] {
            left = left * 2 - i32::from(count);
            if left < 0 {
                return Err(Error::OversubscribedTree);
            }
        }
        let max = (0..16).rev().find(|&len| counts[len] != 0).unwrap_or(0);
        if left > 0 && max > 0 && !(allow_single && max == 1) {
            return Err(Error::IncompleteTree);
        }
        // Symbols in code order: by length, then by value.
        let mut symbols: Vec<u16> =
            (0..lens.len() as u16).filter(|&s| lens[usize::from(s)] != 0).collect();
        symbols.sort_by_key(|&s| lens[usize::from(s)]);
        Ok(Code { counts, symbols })
    }

    /// Decodes one symbol: `InvalidCode` for no code, `Truncated` for a code that runs
    /// past the input.
    fn decode(&self, bits: &mut Bits<'_>) -> Result<u16, Error> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..16 {
            code |= bits.bit() as i32;
            let count = i32::from(self.counts[len]);
            if code - first < count {
                if bits.overrun() {
                    return Err(Error::Truncated);
                }
                return Ok(self.symbols[(index + code - first) as usize]);
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(Error::InvalidCode)
    }
}

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] =
    [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// Decodes the codes of one Huffman block, appending to `out` (whose bytes from `start`
/// belong to this stream) without passing `max` bytes in total.
fn codes(
    bits: &mut Bits<'_>,
    out: &mut Vec<u8>,
    start: usize,
    max: usize,
    litlen: &Code,
    dist: &Code,
) -> Result<(), Error> {
    loop {
        let symbol = usize::from(litlen.decode(bits)?);
        if symbol < 256 {
            if out.len() + 1 > max {
                return Err(Error::OutputLimit);
            }
            out.push(symbol as u8);
            continue;
        }
        if symbol == 256 {
            return Ok(());
        }
        let index = symbol - 257;
        if index >= 29 {
            return Err(Error::InvalidCode);
        }
        let length =
            usize::from(LENGTH_BASE[index]) + bits.take(u32::from(LENGTH_EXTRA[index]))? as usize;
        let index = usize::from(dist.decode(bits)?);
        if index >= 30 {
            return Err(Error::InvalidCode);
        }
        let distance =
            usize::from(DIST_BASE[index]) + bits.take(u32::from(DIST_EXTRA[index]))? as usize;
        if distance > out.len() - start {
            return Err(Error::DistanceTooFar);
        }
        if out.len() + length > max {
            return Err(Error::OutputLimit);
        }
        for _ in 0..length {
            out.push(out[out.len() - distance]);
        }
    }
}

/// Reads a dynamic block header and returns its two codes.
fn dynamic_codes(bits: &mut Bits<'_>) -> Result<(Code, Code), Error> {
    let litlen_count = bits.take(5)? as usize + 257;
    let dist_count = bits.take(5)? as usize + 1;
    let code_length_count = bits.take(4)? as usize + 4;
    if litlen_count > 286 || dist_count > 30 {
        return Err(Error::InvalidDynamicHeader);
    }
    const ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
    let mut code_length_lens = [0u8; 19];
    for &symbol in &ORDER[..code_length_count] {
        code_length_lens[symbol] = bits.take(3)? as u8;
    }
    let code_length_code = Code::new(&code_length_lens, false)?;
    let total = litlen_count + dist_count;
    let mut lens = Vec::new();
    while lens.len() < total {
        let symbol = code_length_code.decode(bits)?;
        let (value, repeat) = match symbol {
            0..=15 => (symbol as u8, 1),
            16 => {
                let repeat = 3 + bits.take(2)? as usize;
                (*lens.last().ok_or(Error::InvalidDynamicHeader)?, repeat)
            }
            17 => (0, 3 + bits.take(3)? as usize),
            _ => (0, 11 + bits.take(7)? as usize),
        };
        if lens.len() + repeat > total {
            return Err(Error::InvalidDynamicHeader);
        }
        lens.extend(std::iter::repeat_n(value, repeat));
    }
    if lens[256] == 0 {
        return Err(Error::MissingEndOfBlock);
    }
    let litlen = Code::new(&lens[..litlen_count], true)?;
    let dist = Code::new(&lens[litlen_count..], true)?;
    Ok((litlen, dist))
}

/// Decodes one raw DEFLATE stream; returns with `bits` at the end of the final block.
fn reference_deflate(bits: &mut Bits<'_>, out: &mut Vec<u8>, max: usize) -> Result<(), Error> {
    static FIXED: std::sync::OnceLock<(Code, Code)> = std::sync::OnceLock::new();
    let (fixed_litlen, fixed_dist) = FIXED.get_or_init(|| {
        let mut lens = [8u8; 288];
        lens[144..256].fill(9);
        lens[256..280].fill(7);
        (
            Code::new(&lens, true).expect("fixed code"),
            Code::new(&[5; 32], true).expect("fixed code"),
        )
    });
    let start = out.len();
    loop {
        let last = bits.take(1)? == 1;
        match bits.take(2)? {
            0 => {
                bits.align();
                let length = bits.take(16)?;
                if length != !bits.take(16)? & 0xffff {
                    return Err(Error::StoredLengthMismatch);
                }
                let available = (bits.data.len() - bits.bit / 8).min(length as usize);
                if length as usize > max - out.len() && available >= max - out.len() {
                    return Err(Error::OutputLimit);
                }
                for _ in 0..length {
                    let byte = bits.byte()?;
                    out.push(byte);
                }
            }
            1 => codes(bits, out, start, max, fixed_litlen, fixed_dist)?,
            2 => {
                let (litlen, dist) = dynamic_codes(bits)?;
                codes(bits, out, start, max, &litlen, &dist)?;
            }
            _ => return Err(Error::InvalidBlockType),
        }
        if last {
            bits.align();
            return Ok(());
        }
    }
}

/// Reads a gzip header, checking each fixed byte as it arrives.
fn reference_header(bits: &mut Bits<'_>) -> Result<(), Error> {
    let start = bits.bit / 8;
    let mut flags = 0;
    for index in 0..10 {
        let byte = bits.byte()?;
        match (index, byte) {
            (0, 0x1f) | (1, 0x8b) | (2, 8) => {}
            (0 | 1, _) => return Err(Error::NotGzip),
            (2, _) => return Err(Error::UnsupportedMethod),
            (3, _) if byte & 0xe0 != 0 => return Err(Error::ReservedFlags),
            (3, _) => flags = byte,
            _ => {}
        }
    }
    if flags & 4 != 0 {
        let length = u16::from(bits.byte()?) | u16::from(bits.byte()?) << 8;
        for _ in 0..length {
            bits.byte()?;
        }
    }
    for flag in [8, 16] {
        if flags & flag != 0 {
            while bits.byte()? != 0 {}
        }
    }
    if flags & 2 != 0 {
        let header_crc = crc32(&bits.data[start..bits.bit / 8]) & 0xffff;
        let stored = u32::from(bits.byte()?) | u32::from(bits.byte()?) << 8;
        if stored != header_crc {
            return Err(Error::HeaderCrcMismatch);
        }
    }
    Ok(())
}

/// Decodes `data` with the reference decoder, with the one-call helpers' rules.
fn reference(format: Format, data: &[u8], limits: Limits) -> Result<Vec<u8>, Error> {
    let max = usize::try_from(limits.max_output_bytes).unwrap_or(usize::MAX);
    let mut bits = Bits { data, bit: 0 };
    let mut out = Vec::new();
    if format == Format::Raw {
        reference_deflate(&mut bits, &mut out, max)?;
        return if bits.bit / 8 == data.len() { Ok(out) } else { Err(Error::TrailingData) };
    }
    let mut members = 0;
    loop {
        reference_header(&mut bits)?;
        let start = out.len();
        reference_deflate(&mut bits, &mut out, max)?;
        let crc = bits.take(16)? | bits.take(16)? << 16;
        let size = bits.take(16)? | bits.take(16)? << 16;
        if crc != crc32(&out[start..]) {
            return Err(Error::CrcMismatch);
        }
        if size != (out.len() - start) as u32 {
            return Err(Error::SizeMismatch);
        }
        members += 1;
        let rest = &data[bits.bit / 8..];
        if rest.is_empty() {
            return Ok(out);
        }
        if members >= limits.max_members.max(1) || rest[0] != 0x1f {
            return Err(Error::TrailingData);
        }
    }
}

// ---------------------------------------------------------------------------------------
// The fuzzer.
// ---------------------------------------------------------------------------------------

/// Valid streams to mutate: (format, bytes).
fn seeds() -> Vec<(Format, Vec<u8>)> {
    let gzip_files: [&[u8]; 5] = [
        include_bytes!("data/hello.gz"),
        include_bytes!("data/countries.csv.gz"),
        include_bytes!("data/empty.gz"),
        include_bytes!("data/sample.csv.1.gz"),
        include_bytes!("data/sample.csv.9.gz"),
    ];
    let mut seeds = Vec::new();
    for file in gzip_files {
        // Long files are cut: the mutations matter most in headers and early blocks.
        let file = &file[..file.len().min(700)];
        seeds.push((Format::Gzip, file.to_vec()));
        seeds.push((Format::Raw, file[10..file.len().saturating_sub(8).max(10)].to_vec()));
    }
    let raw: [&[u8]; 4] = [
        &[
            0x01, 0x0c, 0x00, 0xf3, 0xff, b'H', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r',
            b'l', b'd', 0x0a,
        ],
        &[0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0xcf, 0x2f, 0xca, 0x49, 0xe1, 0x02, 0x00],
        &[
            0x3d, 0xc6, 0x39, 0x11, 0x00, 0x00, 0x0c, 0x02, 0x30, 0x2b, 0xb5, 0x52, 0x1e, 0xff,
            0x96, 0x38, 0x16, 0x96, 0x5c, 0x1e, 0x94, 0xcb, 0x6d, 0x01,
        ],
        &[0x00, 0x03, 0x00, 0xfc, 0xff, b'x', b'y', b'z', 0x4b, 0x4c, 0x42, 0x86, 0x00],
    ];
    seeds.extend(raw.iter().map(|data| (Format::Raw, data.to_vec())));
    seeds
}

/// Applies one to three random mutations to `data`, splicing from `other`.
fn mutate(rng: &mut Rng, data: &mut Vec<u8>, other: &[u8]) {
    for _ in 0..1 + rng.below(3) {
        let len = data.len();
        match rng.below(7) {
            0 | 1 if len > 0 => {
                let at = rng.below(len);
                data[at] ^= 1 << rng.below(8);
            }
            2 if len > 0 => {
                let at = rng.below(len);
                data[at] = rng.next() as u8;
            }
            3 => data.truncate(rng.below(len + 1)),
            4 if len > 0 => {
                let from = rng.below(len);
                let to = from + rng.below((len - from).min(32) + 1);
                let at = rng.below(len + 1);
                let piece = data[from..to].to_vec();
                data.splice(at..at, piece);
            }
            5 if !other.is_empty() => {
                let cut = rng.below(len + 1);
                let from = rng.below(other.len());
                data.truncate(cut);
                data.extend_from_slice(&other[from..]);
            }
            _ => {
                for _ in 0..rng.below(4) {
                    data.push(rng.next() as u8);
                }
            }
        }
    }
    data.truncate(2048);
}

/// Decodes with the crate in one call to a sink, with the one-call helpers' rules.
fn crate_decode(decoder: &mut Decoder, data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let progress = decoder.decompress_to(data, true, &mut out).map_err(|error| {
        *error.get_ref().and_then(|e| e.downcast_ref::<Error>()).expect("a decoding error")
    })?;
    assert_eq!(progress.status, Status::Done);
    if progress.consumed != data.len() {
        return Err(Error::TrailingData);
    }
    Ok(out)
}

/// Decodes in random chunks into a small buffer, with the same rules.
fn chunked_decode(rng: &mut Rng, decoder: &mut Decoder, data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut buffer = [0u8; 300];
    let mut input = data;
    loop {
        let size = input.len().min(1 + rng.below(40));
        let room = 1 + rng.below(buffer.len());
        let progress =
            decoder.decompress(&input[..size], size == input.len(), &mut buffer[..room])?;
        out.extend_from_slice(&buffer[..progress.written]);
        input = &input[progress.consumed..];
        if progress.status == Status::Done {
            return if input.is_empty() { Ok(out) } else { Err(Error::TrailingData) };
        }
    }
}

fn fuzz(iterations: usize, seed: u64) {
    let seeds = seeds();
    let mut rng = Rng(seed);
    let mut decoders = [Format::Raw, Format::Gzip].map(|format| {
        let limits = Limits::default();
        (Decoder::new(format, limits), Decoder::new(format, limits))
    });
    let mut errors = 0;
    for iteration in 0..iterations {
        let (format, seed) = &seeds[rng.below(seeds.len())];
        let mut data = seed.clone();
        let other = &seeds[rng.below(seeds.len())].1;
        mutate(&mut rng, &mut data, other);
        let max_output = if rng.below(4) == 0 { rng.below(200) as u64 } else { 1 << 20 };
        let limits = Limits {
            max_output_bytes: max_output,
            max_members: 1 + rng.below(3) as u32,
            ..Limits::default()
        };
        let (one_call, chunked) = &mut decoders[usize::from(*format == Format::Gzip)];
        one_call.reset_with(limits);
        let ours = crate_decode(one_call, &data);
        let expected = reference(*format, &data, limits);
        assert_eq!(ours, expected, "iteration {iteration}: {format:?} {data:02x?}");
        if let Ok(output) = &ours {
            assert!(output.len() as u64 <= max_output);
        } else {
            errors += 1;
        }
        if iteration % 8 == 0 {
            chunked.reset_with(limits);
            assert_eq!(chunked_decode(&mut rng, chunked, &data), ours, "iteration {iteration}");
        }
    }
    // Most mutations break the stream, but not all of them.
    assert!(errors > iterations / 2 && errors < iterations);
}

#[test]
fn fuzz_against_reference() {
    fuzz(100_000, 0x5eed_1951_1952_0001);
}

#[test]
#[ignore = "a longer fuzzing run; use --release"]
fn fuzz_against_reference_long() {
    fuzz(1_000_000, 0x5eed_1951_1952_0002);
}

//! Canonical Huffman decoding tables (RFC 1951 section 3.2.2).
//!
//! A table maps the next `ROOT` bits of the stream to an [`Entry`]. Codes no longer than
//! `ROOT` bits are replicated across every slot that starts with them, so one lookup decodes
//! them. Longer codes share a root slot per `ROOT`-bit prefix; that slot links to a subtable
//! indexed by the following bits. This is zlib's two-level scheme (doc/algorithm.txt), with
//! zlib's subtable sizing, so the table sizes below are the bounds zlib's `enough` program
//! proves for complete codes: 2342 entries for literal/length codes with an 11-bit root,
//! 402 for distance codes with an 8-bit root, and 128 for the 7-bit code length code.
//!
//! Entries also carry what the decoder needs next (a literal byte, or a length or distance
//! base with its count of extra bits), so the hot loop does no second table lookup.

use crate::bits::low_mask;
use crate::error::Error;

/// Root bits and capacity of the literal/length table.
pub(crate) const LITLEN_ROOT: u32 = 11;
pub(crate) const LITLEN_ENOUGH: usize = 2342;
/// Root bits and capacity of the distance table.
pub(crate) const DIST_ROOT: u32 = 8;
pub(crate) const DIST_ENOUGH: usize = 402;
/// Root bits and capacity of the code length table (codes of at most 7 bits).
pub(crate) const CODE_LENGTH_ROOT: u32 = 7;
pub(crate) const CODE_LENGTH_ENOUGH: usize = 128;

/// The longest code DEFLATE allows.
const MAX_CODE_BITS: usize = 15;

/// What an entry decodes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A literal byte, or a code length symbol (0 to 18), in `value`.
    Literal,
    /// A length or distance: `value` is the base and `extra_bits` the bits to add.
    Base,
    /// The end-of-block symbol 256.
    EndOfBlock,
    /// A root slot of long codes: `value` is the subtable offset, `extra_bits` its index bits.
    Link,
    /// No code starts with these bits. `code_len` is the number of bits that decide it.
    Hole,
    /// A code for a symbol DEFLATE reserves (literal/length 286, 287; distance 30, 31).
    Reserved,
}

/// One table slot, packed into 32 bits so a table fits the first-level cache:
/// bits 0-7 hold the code length, 8-11 the extra bits, 12-14 the kind, 16-31 the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Entry(u32);

impl Entry {
    const fn new(kind: Kind, code_len: u32, extra_bits: u32, value: u32) -> Self {
        let kind = match kind {
            Kind::Literal => 0,
            Kind::Base => 1,
            Kind::EndOfBlock => 2,
            Kind::Link => 3,
            Kind::Hole => 4,
            Kind::Reserved => 5,
        };
        Entry(code_len | (extra_bits << 8) | (kind << 12) | (value << 16))
    }

    /// Returns the kind of the entry.
    #[inline(always)]
    pub(crate) fn kind(self) -> Kind {
        match (self.0 >> 12) & 7 {
            0 => Kind::Literal,
            1 => Kind::Base,
            2 => Kind::EndOfBlock,
            3 => Kind::Link,
            4 => Kind::Hole,
            _ => Kind::Reserved,
        }
    }

    /// Returns the number of stream bits the code occupies (root and subtable bits together).
    #[inline(always)]
    pub(crate) fn code_len(self) -> u32 {
        self.0 & 0xff
    }

    /// Returns the number of extra bits after the code, or a subtable's index bits.
    #[inline(always)]
    pub(crate) fn extra_bits(self) -> u32 {
        (self.0 >> 8) & 0xf
    }

    /// Returns the literal, base or subtable offset.
    #[inline(always)]
    pub(crate) fn value(self) -> u32 {
        self.0 >> 16
    }

    const fn with_code_len(self, code_len: u32) -> Self {
        Entry((self.0 & !0xff) | code_len)
    }
}

/// Base lengths of literal/length symbols 257 to 285 (RFC 1951 section 3.2.5).
const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] =
    [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
/// Base distances of distance symbols 0 to 29.
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// Which alphabet a table decodes; it decides the symbol entries and which incomplete codes
/// are acceptable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Alphabet {
    /// The code length code of a dynamic block header (19 symbols, at most 7 bits).
    CodeLength,
    /// Literal/length symbols 0 to 287.
    LitLen,
    /// Distance symbols 0 to 31.
    Distance,
}

impl Alphabet {
    /// Returns the entry of `symbol` without its code length.
    fn symbol(self, symbol: usize) -> Entry {
        match self {
            Alphabet::CodeLength => Entry::new(Kind::Literal, 0, 0, symbol as u32),
            Alphabet::LitLen => match symbol {
                0..=255 => Entry::new(Kind::Literal, 0, 0, symbol as u32),
                256 => Entry::new(Kind::EndOfBlock, 0, 0, 0),
                257..=285 => {
                    let index = symbol - 257;
                    let extra = u32::from(LENGTH_EXTRA[index]);
                    Entry::new(Kind::Base, 0, extra, u32::from(LENGTH_BASE[index]))
                }
                _ => Entry::new(Kind::Reserved, 0, 0, 0),
            },
            Alphabet::Distance => match symbol {
                0..=29 => {
                    let extra = u32::from(DIST_EXTRA[symbol]);
                    Entry::new(Kind::Base, 0, extra, u32::from(DIST_BASE[symbol]))
                }
                _ => Entry::new(Kind::Reserved, 0, 0, 0),
            },
        }
    }
}

/// A decoding table with `ROOT` root bits and room for `N` entries.
pub(crate) struct Table<const N: usize, const ROOT: u32> {
    entries: [Entry; N],
}

/// The literal/length table.
pub(crate) type LitLenTable = Table<LITLEN_ENOUGH, LITLEN_ROOT>;
/// The distance table.
pub(crate) type DistTable = Table<DIST_ENOUGH, DIST_ROOT>;
/// The code length table of a dynamic block header.
pub(crate) type CodeLengthTable = Table<CODE_LENGTH_ENOUGH, CODE_LENGTH_ROOT>;

impl<const N: usize, const ROOT: u32> Table<N, ROOT> {
    /// Returns a table in which every code is a hole.
    pub(crate) fn new() -> Self {
        Self { entries: [Entry::new(Kind::Hole, ROOT, 0, 0); N] }
    }

    /// Returns the entry for the code at the start of `bits` (the next stream bits, least
    /// significant first), following a link into its subtable.
    #[inline(always)]
    pub(crate) fn lookup(&self, bits: u64) -> Entry {
        // The root index is below `1 << ROOT <= N`. A link always points at a subtable that
        // the same build allocated within `N`: a build rewrites every root slot (or fills
        // them with holes first) before it can succeed, and a decoder never uses a table
        // whose build failed.
        let entry = self.entries[(bits & low_mask(ROOT)) as usize];
        if entry.kind() != Kind::Link {
            return entry;
        }
        let index = (bits >> ROOT) & low_mask(entry.extra_bits());
        self.entries[entry.value() as usize + index as usize]
    }

    /// Builds the table for the code lengths `lens` (symbol `i` has a code of `lens[i]` bits,
    /// zero for none).
    ///
    /// Fails like zlib and Zig: a literal/length code without end-of-block is
    /// [`Error::MissingEndOfBlock`], too many codes for their lengths is
    /// [`Error::OversubscribedTree`], and unused codes are [`Error::IncompleteTree`] unless the
    /// set is empty or a single code of one bit (never for the code length code). On error
    /// the table is left in an unspecified but memory-safe state.
    pub(crate) fn build(&mut self, lens: &[u8], alphabet: Alphabet) -> Result<(), Error> {
        debug_assert!(lens.len() <= 288 && lens.iter().all(|&len| len as usize <= MAX_CODE_BITS));
        if alphabet == Alphabet::LitLen && lens.get(256).copied().unwrap_or(0) == 0 {
            return Err(Error::MissingEndOfBlock);
        }
        let mut count = [0u16; MAX_CODE_BITS + 1];
        for &len in lens {
            count[len as usize] += 1;
        }
        count[0] = 0;
        let max = (1..=MAX_CODE_BITS).rev().find(|&len| count[len] != 0).unwrap_or(0);
        // `left` counts the codes still free at each length; it may not go negative.
        let mut left: i32 = 1;
        for &codes in &count[1..] {
            left = 2 * left - i32::from(codes);
            if left < 0 {
                return Err(Error::OversubscribedTree);
            }
        }
        if left > 0 {
            if max > 1 || (max == 1 && alphabet == Alphabet::CodeLength) {
                return Err(Error::IncompleteTree);
            }
            // An empty or single-code table: the unused codes stay holes.
            self.entries[..1 << ROOT].fill(Entry::new(Kind::Hole, ROOT, 0, 0));
        }
        let sorted = sort_by_length(lens, &count);
        self.fill(
            lens,
            &sorted[..lens.iter().filter(|&&len| len != 0).count()],
            count,
            max,
            alphabet,
        )
    }

    /// Assigns canonical codes to `sorted` (the coded symbols ordered by length, then value)
    /// and writes their entries. `remaining[len]` counts the codes of each length not yet
    /// written; it sizes the subtables.
    fn fill(
        &mut self,
        lens: &[u8],
        sorted: &[u16],
        mut remaining: [u16; MAX_CODE_BITS + 1],
        max: usize,
        alphabet: Alphabet,
    ) -> Result<(), Error> {
        // Indexes stay in bounds: root slots are below `1 << ROOT <= N`, subtable slots below
        // `next_free`, which is checked against `N` when a subtable is allocated, and the
        // lengths are at most 15 (3-bit fields or code length symbols 0 to 15).
        let root_slots = 1usize << ROOT;
        let mut code = 0u32; // the canonical code, most significant bit first
        let mut code_len = 0u32;
        let mut next_free = root_slots;
        let mut prefix = usize::MAX; // root slot of the current subtable
        let mut sub_start = 0usize;
        let mut sub_bits = 0u32;
        for &symbol in sorted {
            let len = u32::from(lens[symbol as usize]);
            code <<= len - code_len;
            code_len = len;
            let reversed = (code.reverse_bits() >> (32 - len)) as usize;
            let entry = alphabet.symbol(symbol as usize).with_code_len(len);
            if len <= ROOT {
                for slot in (reversed..root_slots).step_by(1 << len) {
                    self.entries[slot] = entry;
                }
            } else {
                if reversed & (root_slots - 1) != prefix {
                    prefix = reversed & (root_slots - 1);
                    sub_bits = subtable_bits(len - ROOT, ROOT, max, &remaining);
                    sub_start = next_free;
                    next_free += 1 << sub_bits;
                    if next_free > N {
                        // Unreachable for complete codes: N is zlib's proven bound.
                        return Err(Error::OversubscribedTree);
                    }
                    self.entries[prefix] =
                        Entry::new(Kind::Link, ROOT, sub_bits, sub_start as u32);
                }
                let first = reversed >> ROOT;
                for slot in (first..1 << sub_bits).step_by(1 << (len - ROOT)) {
                    self.entries[sub_start + slot] = entry;
                }
            }
            remaining[len as usize] -= 1;
            code += 1;
        }
        Ok(())
    }
}

/// Returns the coded symbols sorted by code length, then by symbol value. Only the first
/// `count[1..].sum()` entries are meaningful.
fn sort_by_length(lens: &[u8], count: &[u16; MAX_CODE_BITS + 1]) -> [u16; 288] {
    let mut offset = [0u16; MAX_CODE_BITS + 1];
    for len in 1..MAX_CODE_BITS {
        offset[len + 1] = offset[len] + count[len];
    }
    let mut sorted = [0u16; 288];
    for (symbol, &len) in lens.iter().enumerate() {
        if len != 0 {
            sorted[offset[len as usize] as usize] = symbol as u16;
            offset[len as usize] += 1;
        }
    }
    sorted
}

/// Returns the index bits of a new subtable whose first code has `first` bits beyond the
/// root: the smallest size the remaining codes with this prefix fill completely (zlib's
/// rule in `inflate_table`).
fn subtable_bits(first: u32, root: u32, max: usize, remaining: &[u16; MAX_CODE_BITS + 1]) -> u32 {
    let mut bits = first;
    let mut left: i32 = 1 << bits;
    while ((bits + root) as usize) < max {
        left -= i32::from(remaining[(bits + root) as usize]);
        if left <= 0 {
            break;
        }
        bits += 1;
        left <<= 1;
    }
    bits
}

/// The tables of fixed Huffman blocks (RFC 1951 section 3.2.6).
pub(crate) fn build_fixed(litlen: &mut LitLenTable, dist: &mut DistTable) {
    let mut lens = [0u8; 288];
    lens[..144].fill(8);
    lens[144..256].fill(9);
    lens[256..280].fill(7);
    lens[280..].fill(8);
    let fixed_dist = [5u8; 32];
    // Both codes are complete and contain end-of-block, so building cannot fail.
    let built =
        litlen.build(&lens, Alphabet::LitLen).and(dist.build(&fixed_dist, Alphabet::Distance));
    debug_assert!(built.is_ok());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns `code` of `bits` bits in stream order (the first bit is the code's top bit).
    fn stream_bits(code: u32, bits: u32) -> u64 {
        u64::from(code.reverse_bits() >> (32 - bits))
    }

    // Ported from Zig 0.16 std.compress.flate.Decompress test "init/find": the example
    // of https://youtu.be/SJPvNi4HrWQ?t=8423 decoded through every 7-bit pattern.
    #[test]
    fn zig_init_find() {
        let lens = [4u8, 3, 0, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 3, 2];
        let mut table = CodeLengthTable::new();
        table.build(&lens, Alphabet::CodeLength).unwrap();
        let expect = [
            (0b000_0000..0b010_0000, 3, 2),
            (0b010_0000..0b100_0000, 18, 2),
            (0b100_0000..0b101_0000, 1, 3),
            (0b101_0000..0b110_0000, 4, 3),
            (0b110_0000..0b111_0000, 17, 3),
            (0b111_0000..0b111_1000, 0, 4),
            (0b111_1000..0b1000_0000, 16, 4),
        ];
        for (codes, symbol, bits) in expect {
            for code in codes {
                let entry = table.lookup(stream_bits(code, 7));
                assert_eq!(entry.kind(), Kind::Literal);
                assert_eq!((entry.value(), entry.code_len()), (symbol, bits), "code {code:07b}");
            }
        }
    }

    // Ported from Zig test "encode/decode literals": the example of RFC 1951 section 3.2.2
    // plus some zeroes, decoded through a table with a 3-bit root and 5-bit codes.
    #[test]
    fn zig_rfc_example_with_subtables() {
        let lens = [3u8, 3, 3, 3, 0, 0, 3, 2, 4, 4];
        let codes = [(0, 0b010, 3), (1, 0b011, 3), (2, 0b100, 3), (3, 0b101, 3)];
        let more = [(6, 0b110, 3), (7, 0b00, 2), (8, 0b1110, 4), (9, 0b1111, 4)];
        let mut table = Table::<64, 3>::new();
        table.build(&lens, Alphabet::CodeLength).unwrap();
        for (symbol, code, bits) in codes.into_iter().chain(more) {
            // Every continuation of the code decodes to the same symbol.
            for tail in 0..1u32 << (5 - bits) {
                let stream = stream_bits(code, bits) | u64::from(tail) << bits;
                let entry = table.lookup(stream);
                assert_eq!((entry.value(), entry.code_len()), (symbol, bits));
            }
        }
    }

    #[test]
    fn completeness_rules() {
        let mut table = CodeLengthTable::new();
        // Three one-bit codes: over-subscribed.
        assert_eq!(table.build(&[1, 1, 1], Alphabet::CodeLength), Err(Error::OversubscribedTree));
        // One two-bit code: incomplete.
        assert_eq!(table.build(&[2, 0], Alphabet::CodeLength), Err(Error::IncompleteTree));
        // A single one-bit code is incomplete; only data alphabets accept it.
        assert_eq!(table.build(&[1], Alphabet::CodeLength), Err(Error::IncompleteTree));
        let mut dist = DistTable::new();
        dist.build(&[0, 1], Alphabet::Distance).unwrap();
        assert_eq!(dist.lookup(0).kind(), Kind::Base);
        assert_eq!(dist.lookup(0).value(), 2);
        assert_eq!(dist.lookup(1).kind(), Kind::Hole);
        // An empty table is accepted; every pattern is a hole.
        dist.build(&[0; 30], Alphabet::Distance).unwrap();
        assert_eq!(dist.lookup(0x5a).kind(), Kind::Hole);
        let mut litlen = LitLenTable::new();
        assert_eq!(litlen.build(&[8; 256], Alphabet::LitLen), Err(Error::MissingEndOfBlock));
    }

    #[test]
    fn fixed_tables_decode_rfc_codes() {
        let mut litlen = LitLenTable::new();
        let mut dist = DistTable::new();
        build_fixed(&mut litlen, &mut dist);
        // RFC 1951 3.2.6: literal 0 is 00110000, 144 is 110010000, 256 is 0000000,
        // 280 is 11000000; 286 and 287 are reserved.
        let cases = [
            (0b0011_0000, 8, Kind::Literal, 0),
            (0b1_1001_0000, 9, Kind::Literal, 144),
            (0b000_0000, 7, Kind::EndOfBlock, 0),
            (0b110_00000, 8, Kind::Base, 115),
            (0b1100_0110, 8, Kind::Reserved, 0),
        ];
        for (code, bits, kind, value) in cases {
            let entry = litlen.lookup(stream_bits(code, bits));
            assert_eq!((entry.kind(), entry.code_len(), entry.value()), (kind, bits, value));
        }
        assert_eq!(dist.lookup(stream_bits(29, 5)).value(), 24577);
        assert_eq!(dist.lookup(stream_bits(30, 5)).kind(), Kind::Reserved);
    }

    #[test]
    fn long_codes_use_subtables() {
        // A complete code with lengths up to 15 bits: two codes of each length 1..=14 would
        // over-subscribe, so use one code per length and two of the longest.
        let mut lens = [0u8; 288];
        for (symbol, len) in (1..=15u8).enumerate() {
            lens[symbol] = len;
        }
        lens[256] = 15;
        let mut table = LitLenTable::new();
        table.build(&lens, Alphabet::LitLen).unwrap();
        // Symbol 14 has code 111111111111110 and end-of-block 111111111111111.
        let entry = table.lookup(stream_bits(0b111_1111_1111_1110, 15));
        assert_eq!((entry.kind(), entry.value(), entry.code_len()), (Kind::Literal, 14, 15));
        let entry = table.lookup(stream_bits(0b111_1111_1111_1111, 15));
        assert_eq!(entry.kind(), Kind::EndOfBlock);
        let entry = table.lookup(stream_bits(0b111_1111_1110, 11));
        assert_eq!((entry.value(), entry.code_len()), (10, 11));
    }
}

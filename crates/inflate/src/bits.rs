//! The bit reader: input bytes of one call, and the bits taken from them but not yet decoded.
//!
//! DEFLATE packs codes least significant bit first. We keep up to 64 bits in a word and
//! refill it eight bytes at a time when the input allows, so the hot loop decodes a whole
//! literal or match (at most 48 bits) after one refill.
//!
//! The word may hold bits above `count`. They are always the true next bits of the input
//! (a refill reads eight bytes but counts only the whole bytes that fit), so OR-ing the same
//! byte in again later is harmless, and at the very end of the input they are zero. Code
//! that takes bytes from the input directly must clear them first
//! ([`BitBuffer::clear_lookahead`]). A
//! decoder that reaches the end of its input therefore reads zero padding past the last
//! byte, as Zig and zlib do.

/// The bytes of one `decompress` call and how many of them the decoder has taken.
pub(crate) struct Input<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Input<'a> {
    /// Wraps the bytes of one call; nothing is taken yet.
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Returns how many bytes the decoder has taken.
    pub(crate) fn taken(&self) -> usize {
        self.pos
    }

    /// Returns the bytes not yet taken. `pos <= bytes.len()` always holds: every advance is
    /// bounded by the bytes that remain.
    pub(crate) fn rest(&self) -> &'a [u8] {
        &self.bytes[self.pos..]
    }

    /// Marks the first `count` bytes of [`Input::rest`] as taken.
    pub(crate) fn advance(&mut self, count: usize) {
        debug_assert!(count <= self.bytes.len() - self.pos);
        self.pos += count;
    }
}

/// Bits taken from the input but not yet consumed, least significant bit first.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct BitBuffer {
    /// The bits; bit 0 is the next bit of the stream.
    pub(crate) word: u64,
    /// How many bits of `word` are valid (0 to 63).
    pub(crate) count: u32,
}

/// Returns a mask of the low `bits` bits; `bits` is at most 63.
#[inline(always)]
pub(crate) const fn low_mask(bits: u32) -> u64 {
    (1u64 << bits) - 1
}

impl BitBuffer {
    /// Fills the word to at least 56 bits, or with all remaining input when less is left.
    #[inline(always)]
    pub(crate) fn refill(&mut self, input: &mut Input<'_>) {
        if let Some(chunk) = input.bytes[input.pos..].first_chunk::<8>() {
            self.word |= u64::from_le_bytes(*chunk) << self.count;
            // (63 - count) / 8 whole bytes fit, at most 7 of the 8 just read; afterwards
            // count is 56 plus the old count
            // modulo 8, which is what `count | 56` computes for any count below 64.
            input.pos += ((63 - self.count) >> 3) as usize;
            self.count |= 56;
        } else {
            self.refill_slowly(input);
        }
    }

    /// Refills one byte at a time near the end of the input.
    #[cold]
    fn refill_slowly(&mut self, input: &mut Input<'_>) {
        while self.count <= 56 {
            let Some(&byte) = input.bytes.get(input.pos) else { break };
            self.word |= u64::from(byte) << self.count;
            self.count += 8;
            input.pos += 1;
        }
    }

    /// Returns the next `bits` bits (at most 32) without consuming them. Bits past `count`
    /// read as the following input, or as zero at the end of the input.
    #[inline(always)]
    pub(crate) fn peek(&self, bits: u32) -> u32 {
        (self.word & low_mask(bits)) as u32
    }

    /// Consumes `bits` bits; the caller has checked that `count` holds them.
    #[inline(always)]
    pub(crate) fn consume(&mut self, bits: u32) {
        debug_assert!(bits <= self.count);
        self.word >>= bits;
        self.count -= bits;
    }

    /// Takes `bits` bits (at most 32) after a refill, or `None` if the input holds fewer.
    pub(crate) fn take(&mut self, bits: u32, input: &mut Input<'_>) -> Option<u32> {
        self.refill(input);
        if self.count < bits {
            return None;
        }
        let value = self.peek(bits);
        self.consume(bits);
        Some(value)
    }

    /// Drops the bits up to the next byte boundary of the stream.
    pub(crate) fn align_to_byte(&mut self) {
        self.consume(self.count & 7);
    }

    /// Takes one byte at a byte boundary: from the word while it holds whole bytes, then
    /// directly from the input. Returns `None` when both are exhausted.
    pub(crate) fn take_byte(&mut self, input: &mut Input<'_>) -> Option<u8> {
        debug_assert_eq!(self.count & 7, 0);
        if self.count >= 8 {
            let byte = self.word as u8;
            self.consume(8);
            return Some(byte);
        }
        let byte = *input.bytes.get(input.pos)?;
        input.pos += 1;
        self.clear_lookahead();
        Some(byte)
    }

    /// Clears the bits above `count`. A caller that takes bytes from the input directly,
    /// bypassing the word, must call this: the word may still hold those bytes as lookahead,
    /// and a later refill would OR the following bytes into the same positions.
    pub(crate) fn clear_lookahead(&mut self) {
        self.word &= low_mask(self.count);
    }

    /// Returns the next byte at a byte boundary without taking it.
    pub(crate) fn peek_byte(&self, input: &Input<'_>) -> Option<u8> {
        debug_assert_eq!(self.count & 7, 0);
        if self.count >= 8 { Some(self.word as u8) } else { input.bytes.get(input.pos).copied() }
    }

    /// Returns whole bytes that the word holds but the stream has not used to the input of
    /// this call, as far as they came from it, and clears the bits above `count`.
    ///
    /// The decoder calls this whenever it returns with the stream ended or the output full,
    /// so the caller sees exactly where the stream ends and can pass the rest on.
    pub(crate) fn give_back(&mut self, input: &mut Input<'_>) {
        let bytes = ((self.count / 8) as usize).min(input.pos);
        input.pos -= bytes;
        self.count -= 8 * bytes as u32;
        self.clear_lookahead();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refill_reads_bits_in_stream_order() {
        let data: Vec<u8> = (0..40u8).map(|i| i.wrapping_mul(37) ^ 0x5a).collect();
        let mut input = Input::new(&data);
        let mut bits = BitBuffer::default();
        let mut collected = Vec::new();
        // Take odd-sized pieces so refills happen at every bit offset.
        let mut size = 1;
        loop {
            bits.refill(&mut input);
            if bits.count == 0 {
                break;
            }
            let n = size.min(bits.count);
            let value = bits.peek(n);
            bits.consume(n);
            for i in 0..n {
                collected.push((value >> i) & 1);
            }
            size = size % 13 + 1;
        }
        let expected: Vec<u32> =
            data.iter().flat_map(|&b| (0..8).map(move |i| u32::from(b >> i) & 1)).collect();
        assert_eq!(collected, expected);
    }

    #[test]
    fn give_back_returns_whole_unused_bytes() {
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut input = Input::new(&data);
        let mut bits = BitBuffer::default();
        bits.refill(&mut input);
        assert_eq!(input.taken(), 7);
        bits.consume(12);
        bits.give_back(&mut input);
        // 12 bits used one and a half bytes; the half byte stays in the word.
        assert_eq!(input.taken(), 2);
        assert_eq!(bits.count, 4);
        assert_eq!(bits.word, u64::from(data[1] >> 4));
    }

    #[test]
    fn end_of_input_reads_as_zero() {
        let data = [0xffu8];
        let mut input = Input::new(&data);
        let mut bits = BitBuffer::default();
        bits.refill(&mut input);
        assert_eq!(bits.count, 8);
        assert_eq!(bits.peek(16), 0xff);
    }
}

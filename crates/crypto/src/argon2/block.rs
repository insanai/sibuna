//! The 1 KiB memory block and the compression function G (RFC 9106 section 3.5).
//!
//! G(X, Y) computes R = X xor Y, applies the BLAKE2b-derived permutation P to the eight
//! rows of R and then to its eight columns, giving Q, and returns Q xor R. A row is 16
//! consecutive words; column `c` is the pair of words `2c, 2c + 1` of every row.

use core::fmt;

use crate::wipe;

/// Number of 64-bit words in a block.
pub(super) const WORDS: usize = 128;

/// One 1 KiB block of Argon2 memory.
///
/// The caller provides the memory of a hash as a slice of blocks, so that a server can
/// reserve it once and never allocate per password check:
///
/// ```
/// use sibuna_crypto::argon2::{self, Block, Params};
/// let params = Params::default();
/// let mut workspace = vec![Block::ZERO; argon2::block_count(&params).unwrap()];
/// # let _ = &mut workspace;
/// ```
#[derive(Clone)]
#[repr(align(64))]
pub struct Block(pub(super) [u64; WORDS]);

impl Block {
    /// A block of zeros, for filling a new workspace.
    pub const ZERO: Block = Block([0; WORDS]);

    /// Overwrites the block with zeros in a way the optimiser keeps.
    pub(super) fn wipe(&mut self) {
        wipe::wipe_u64(&mut self.0);
    }

    /// Reads a block from 1024 little-endian bytes.
    pub(super) fn load(&mut self, bytes: &[u8; WORDS * 8]) {
        let (chunks, _) = bytes.as_chunks::<8>();
        for (word, chunk) in self.0.iter_mut().zip(chunks) {
            *word = u64::from_le_bytes(*chunk);
        }
    }

    /// Writes the block as 1024 little-endian bytes.
    pub(super) fn store(&self, bytes: &mut [u8; WORDS * 8]) {
        let (chunks, _) = bytes.as_chunks_mut::<8>();
        for (chunk, word) in chunks.iter_mut().zip(&self.0) {
            *chunk = word.to_le_bytes();
        }
    }

    /// XORs `other` into this block.
    pub(super) fn xor_assign(&mut self, other: &Block) {
        for (word, x) in self.0.iter_mut().zip(&other.0) {
            *word ^= x;
        }
    }
}

impl Default for Block {
    fn default() -> Self {
        Block::ZERO
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Blocks hold password-derived state; never print them.
        f.write_str("Block { .. }")
    }
}

/// Computes G(x, y) into `out`: overwriting it when `xor_into` is false (the first pass),
/// XOR-ing into it otherwise (later passes of version 0x13).
///
/// `out` is passed as the destination of a separate step because in the memory-filling
/// loop it is another element of the slice that holds `x` and `y`; see
/// [`compress_in_slice`].
pub(super) fn compress(out: &mut Block, x: &Block, y: &Block, xor_into: bool) {
    let mut q = [0u64; WORDS];
    for ((q, x), y) in q.iter_mut().zip(&x.0).zip(&y.0) {
        *q = x ^ y;
    }
    permute(&mut q);
    combine(&mut out.0, &q, &x.0, &y.0, xor_into);
}

/// Computes G(blocks\[prev\], blocks\[reference\]) into `blocks[current]`, as [`compress`]
/// does. The three indices are distinct by construction of Argon2's indexing, and all are
/// below `blocks.len()`; a violation is a bug and panics.
#[inline]
pub(super) fn compress_in_slice(
    blocks: &mut [Block],
    current: usize,
    prev: usize,
    reference: usize,
    xor_into: bool,
) {
    let mut q = [0u64; WORDS];
    {
        let (x, y) = (&blocks[prev].0, &blocks[reference].0);
        for ((q, x), y) in q.iter_mut().zip(x).zip(y) {
            *q = x ^ y;
        }
    }
    permute(&mut q);
    // Fold R = x ^ y back in while only shared borrows are live, then write the result.
    {
        let (x, y) = (&blocks[prev].0, &blocks[reference].0);
        for ((q, x), y) in q.iter_mut().zip(x).zip(y) {
            *q ^= x ^ y;
        }
    }
    let out = &mut blocks[current].0;
    if xor_into {
        for (out, q) in out.iter_mut().zip(&q) {
            *out ^= q;
        }
    } else {
        *out = q;
    }
}

/// `out = Q ^ x ^ y`, or `out ^= Q ^ x ^ y`.
fn combine(
    out: &mut [u64; WORDS],
    q: &[u64; WORDS],
    x: &[u64; WORDS],
    y: &[u64; WORDS],
    xor_into: bool,
) {
    for (((out, q), x), y) in out.iter_mut().zip(q).zip(x).zip(y) {
        let value = q ^ x ^ y;
        *out = if xor_into { *out ^ value } else { value };
    }
}

/// The permutation P applied to every row, then to every column.
#[inline(always)]
fn permute(q: &mut [u64; WORDS]) {
    let (rows, _) = q.as_chunks_mut::<16>();
    for row in rows.iter_mut() {
        round(row);
    }
    for column in 0..8 {
        let mut v = [0u64; 16];
        for k in 0..8 {
            v[2 * k] = q[16 * k + 2 * column];
            v[2 * k + 1] = q[16 * k + 2 * column + 1];
        }
        round(&mut v);
        for k in 0..8 {
            q[16 * k + 2 * column] = v[2 * k];
            q[16 * k + 2 * column + 1] = v[2 * k + 1];
        }
    }
}

/// One BLAKE2b round on 16 words, with BlaMka multiplication in place of plain addition.
#[inline(always)]
fn round(v: &mut [u64; 16]) {
    quarter(v, 0, 4, 8, 12);
    quarter(v, 1, 5, 9, 13);
    quarter(v, 2, 6, 10, 14);
    quarter(v, 3, 7, 11, 15);
    quarter(v, 0, 5, 10, 15);
    quarter(v, 1, 6, 11, 12);
    quarter(v, 2, 7, 8, 13);
    quarter(v, 3, 4, 9, 14);
}

#[inline(always)]
fn quarter(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    v[a] = blamka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = blamka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = blamka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = blamka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// `x + y + 2 * lo32(x) * lo32(y)`, all modulo 2^64.
#[inline(always)]
fn blamka(x: u64, y: u64) -> u64 {
    let product = u64::from(x as u32) * u64::from(y as u32);
    x.wrapping_add(y).wrapping_add(product.wrapping_mul(2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_and_separate_forms_agree() {
        let mut blocks = std::vec![Block::ZERO; 3];
        for (i, word) in blocks[0].0.iter_mut().enumerate() {
            *word = (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        }
        for (i, word) in blocks[1].0.iter_mut().enumerate() {
            *word = (i as u64) ^ 0x0123_4567_89ab_cdef;
        }
        for xor_into in [false, true] {
            let mut expected = blocks[2].clone();
            compress(&mut expected, &blocks[0], &blocks[1], xor_into);
            compress_in_slice(&mut blocks, 2, 0, 1, xor_into);
            assert_eq!(blocks[2].0, expected.0);
        }
    }

    #[test]
    fn blamka_matches_definition() {
        assert_eq!(blamka(1, 2), 1 + 2 + 2 * 2);
        assert_eq!(blamka(u64::MAX, 1), 0u64.wrapping_add(2 * 0xffff_ffff));
        assert_eq!(std::format!("{:?}", Block::ZERO), "Block { .. }");
    }
}

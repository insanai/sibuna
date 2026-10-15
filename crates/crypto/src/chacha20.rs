//! The ChaCha20 stream cipher of RFC 8439 (32-bit block counter, 96-bit nonce), XChaCha20
//! (draft-irtf-cfrg-xchacha-03: a 192-bit nonce through HChaCha20), and HChaCha20.
//!
//! The state is sixteen 32-bit words: four constants, the eight key words, the block
//! counter and three nonce words. A block of keystream is the state after 20 rounds plus
//! the initial state, serialised little-endian.
//!
//! The rounds work on the four rows of the state, `[u32; 4]` each, so the compiler maps a
//! row to one SIMD register on every target with 128-bit vectors and needs no `unsafe`
//! intrinsics.

#[cfg(test)]
mod tests;

use core::fmt;

use crate::wipe;

/// Length of a key in bytes.
pub const KEY_LEN: usize = 32;

/// Length of a ChaCha20 (RFC 8439) nonce in bytes.
pub const NONCE_LEN: usize = 12;

/// Length of an XChaCha20 nonce in bytes.
pub const XNONCE_LEN: usize = 24;

/// Length of a keystream block in bytes.
pub const BLOCK_LEN: usize = 64;

/// "expand 32-byte k" as four little-endian words.
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Why the cipher refused to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The input needs keystream blocks beyond counter 2^32 - 1, where the 32-bit block
    /// counter would wrap and repeat keystream.
    CounterOverflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChaCha20 block counter would overflow")
    }
}

impl core::error::Error for Error {}

/// A ChaCha20 keystream positioned at a block counter. It erases the key from its state
/// when dropped.
///
/// ```
/// use sibuna_crypto::chacha20::ChaCha20;
/// let mut data = *b"attack at dawn";
/// ChaCha20::new(&[7; 32], &[1; 12], 1).apply_keystream(&mut data).unwrap();
/// ChaCha20::new(&[7; 32], &[1; 12], 1).apply_keystream(&mut data).unwrap();
/// assert_eq!(&data, b"attack at dawn");
/// ```
#[derive(Clone)]
pub struct ChaCha20 {
    /// The initial state of the next block; word 12 is its counter.
    state: [u32; 16],
    /// Blocks still available before the counter wraps, up to 2^32.
    remaining_blocks: u64,
}

impl ChaCha20 {
    /// A keystream for `key` and the RFC 8439 `nonce`, starting at block `counter`.
    pub fn new(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], counter: u32) -> Self {
        let mut state = [0u32; 16];
        state[..4].copy_from_slice(&CONSTANTS);
        load_words(&mut state[4..12], key);
        state[12] = counter;
        load_words(&mut state[13..], nonce);
        ChaCha20 { state, remaining_blocks: (1u64 << 32) - u64::from(counter) }
    }

    /// An XChaCha20 keystream: HChaCha20 derives a subkey from `key` and the first 16
    /// bytes of `nonce`; the last 8 bytes, after four zero bytes, are the ChaCha20 nonce.
    pub fn new_xchacha20(key: &[u8; KEY_LEN], nonce: &[u8; XNONCE_LEN], counter: u32) -> Self {
        let prefix: [u8; 16] = core::array::from_fn(|i| nonce[i]);
        let mut subkey = hchacha20(key, &prefix);
        let mut short_nonce = [0u8; NONCE_LEN];
        short_nonce[4..].copy_from_slice(&nonce[16..]);
        let cipher = ChaCha20::new(&subkey, &short_nonce, counter);
        wipe::wipe_bytes(&mut subkey);
        cipher
    }

    /// XORs the keystream into `data` and advances the counter by one block per started
    /// 64 bytes. A partial last block discards the rest of its keystream, so split a
    /// message into calls of whole blocks except the last.
    ///
    /// Fails with [`Error::CounterOverflow`], leaving `data` unchanged, when the counter
    /// would pass 2^32 - 1.
    pub fn apply_keystream(&mut self, data: &mut [u8]) -> Result<(), Error> {
        let needed = data.len().div_ceil(BLOCK_LEN) as u64;
        if needed > self.remaining_blocks {
            return Err(Error::CounterOverflow);
        }
        let (blocks, rest) = data.as_chunks_mut::<BLOCK_LEN>();
        for data_block in blocks {
            xor_block(&block(&self.state), data_block);
            self.state[12] = self.state[12].wrapping_add(1);
        }
        if !rest.is_empty() {
            let mut keystream = block(&self.state);
            let (words, tail) = rest.as_chunks_mut::<4>();
            for (bytes, key) in words.iter_mut().zip(&keystream) {
                *bytes = (u32::from_le_bytes(*bytes) ^ key).to_le_bytes();
            }
            if let Some(key) = keystream.get(words.len()) {
                for (byte, key) in tail.iter_mut().zip(key.to_le_bytes()) {
                    *byte ^= key;
                }
            }
            wipe::wipe_u32(&mut keystream);
            self.state[12] = self.state[12].wrapping_add(1);
        }
        self.remaining_blocks -= needed;
        Ok(())
    }

    /// Returns the next 64-byte keystream block and advances the counter.
    ///
    /// Fails with [`Error::CounterOverflow`] when no block is left.
    pub fn keystream_block(&mut self) -> Result<[u8; BLOCK_LEN], Error> {
        let mut out = [0u8; BLOCK_LEN];
        self.apply_keystream(&mut out)?;
        Ok(out)
    }
}

impl Drop for ChaCha20 {
    fn drop(&mut self) {
        wipe::wipe_u32(&mut self.state);
    }
}

impl fmt::Debug for ChaCha20 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChaCha20").field("counter", &self.state[12]).finish_non_exhaustive()
    }
}

/// XORs the RFC 8439 ChaCha20 keystream for `key`, `nonce` and the starting block
/// `counter` into `data`: the one-call form of [`ChaCha20::apply_keystream`].
///
/// Fails with [`Error::CounterOverflow`], leaving `data` unchanged, when `data` needs
/// blocks past counter 2^32 - 1.
pub fn apply_keystream(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    counter: u32,
    data: &mut [u8],
) -> Result<(), Error> {
    ChaCha20::new(key, nonce, counter).apply_keystream(data)
}

/// XORs the XChaCha20 keystream for `key`, the 24-byte `nonce` and the starting block
/// `counter` into `data`. Fails as [`apply_keystream`] does.
pub fn apply_xchacha20_keystream(
    key: &[u8; KEY_LEN],
    nonce: &[u8; XNONCE_LEN],
    counter: u32,
    data: &mut [u8],
) -> Result<(), Error> {
    ChaCha20::new_xchacha20(key, nonce, counter).apply_keystream(data)
}

/// HChaCha20: the 20 ChaCha rounds over the key and the 16-byte `input`, without the final
/// addition, returning words 0 to 3 and 12 to 15 as a 32-byte subkey.
pub fn hchacha20(key: &[u8; KEY_LEN], input: &[u8; 16]) -> [u8; KEY_LEN] {
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&CONSTANTS);
    load_words(&mut state[4..12], key);
    load_words(&mut state[12..], input);
    let mut x = rounds(&state);
    let mut out = [0u8; KEY_LEN];
    let (chunks, _) = out.as_chunks_mut::<4>();
    for (chunk, word) in chunks.iter_mut().zip(x[0].iter().chain(&x[3])) {
        *chunk = word.to_le_bytes();
    }
    wipe::wipe_u32(&mut state);
    wipe::wipe_u32(x.as_flattened_mut());
    out
}

/// Reads little-endian words from `bytes` into `words`.
fn load_words(words: &mut [u32], bytes: &[u8]) {
    let (chunks, _) = bytes.as_chunks::<4>();
    for (word, chunk) in words.iter_mut().zip(chunks) {
        *word = u32::from_le_bytes(*chunk);
    }
}

/// XORs a keystream block, given as words, into 64 bytes of data.
#[inline(always)]
fn xor_block(keystream: &[u32; 16], data: &mut [u8; BLOCK_LEN]) {
    let (words, _) = data.as_chunks_mut::<4>();
    for (bytes, key) in words.iter_mut().zip(keystream) {
        *bytes = (u32::from_le_bytes(*bytes) ^ key).to_le_bytes();
    }
}

#[cfg(test)]
#[inline(always)]
fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

/// One row of the 4 x 4 state matrix.
type Row = [u32; 4];

#[inline(always)]
fn add(x: Row, y: Row) -> Row {
    [
        x[0].wrapping_add(y[0]),
        x[1].wrapping_add(y[1]),
        x[2].wrapping_add(y[2]),
        x[3].wrapping_add(y[3]),
    ]
}

#[inline(always)]
fn xor_rotate(x: Row, y: Row, bits: u32) -> Row {
    [
        (x[0] ^ y[0]).rotate_left(bits),
        (x[1] ^ y[1]).rotate_left(bits),
        (x[2] ^ y[2]).rotate_left(bits),
        (x[3] ^ y[3]).rotate_left(bits),
    ]
}

/// The row rotated left by `N` lanes: lane `i` takes lane `i + N`.
#[inline(always)]
fn rotate_lanes<const N: usize>(x: Row) -> Row {
    [x[N % 4], x[(N + 1) % 4], x[(N + 2) % 4], x[(N + 3) % 4]]
}

/// Four quarter rounds at once, one per lane: lane `i` mixes `a[i]`, `b[i]`, `c[i]`,
/// `d[i]`.
#[inline(always)]
fn quarter_rounds(rows: &mut [Row; 4]) {
    let [mut a, mut b, mut c, mut d] = *rows;
    a = add(a, b);
    d = xor_rotate(d, a, 16);
    c = add(c, d);
    b = xor_rotate(b, c, 12);
    a = add(a, b);
    d = xor_rotate(d, a, 8);
    c = add(c, d);
    b = xor_rotate(b, c, 7);
    *rows = [a, b, c, d];
}

/// Ten double rounds on the state as rows. The column round mixes the lanes as they are;
/// for the diagonal round, rows 1 to 3 are rotated by one to three lanes so that each
/// diagonal lines up in one lane, and rotated back afterwards. Written on rows, the
/// rounds compile to 128-bit vector operations on targets that have them.
#[inline(always)]
fn rounds(state: &[u32; 16]) -> [Row; 4] {
    let (rows, _) = state.as_chunks::<4>();
    let mut x = [rows[0], rows[1], rows[2], rows[3]];
    for _ in 0..10 {
        quarter_rounds(&mut x);
        x = [x[0], rotate_lanes::<1>(x[1]), rotate_lanes::<2>(x[2]), rotate_lanes::<3>(x[3])];
        quarter_rounds(&mut x);
        x = [x[0], rotate_lanes::<3>(x[1]), rotate_lanes::<2>(x[2]), rotate_lanes::<1>(x[3])];
    }
    x
}

/// One keystream block for `state`, as words.
#[inline]
fn block(state: &[u32; 16]) -> [u32; 16] {
    let x = rounds(state);
    let mut out = [0u32; 16];
    for ((word, mixed), initial) in out.iter_mut().zip(x.as_flattened()).zip(state) {
        *word = mixed.wrapping_add(*initial);
    }
    out
}

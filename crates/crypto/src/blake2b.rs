//! BLAKE2b (RFC 7693) with a variable output length, an optional key, a salt and a
//! personalisation string.
//!
//! Argon2 builds its initial hash and its variable-length hash `H'` from BLAKE2b, which is
//! why the crate carries it. The parameter block is the one of Zig's
//! `std.crypto.hash.blake2.Blake2b`: digest length, key length, fanout 1, depth 1, and the
//! optional salt and personalisation XOR-ed into the last four words of the state.

#[cfg(test)]
mod tests;

use core::fmt;

use crate::{ct, wipe};

/// Length of a BLAKE2b input block in bytes.
pub const BLOCK_LEN: usize = 128;

/// The largest digest BLAKE2b produces, in bytes (BLAKE2b-512).
pub const MAX_OUTPUT_LEN: usize = 64;

/// The longest key BLAKE2b accepts, in bytes.
pub const MAX_KEY_LEN: usize = 64;

/// Length of the salt and of the personalisation string in bytes.
pub const SALT_LEN: usize = 16;

const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// The message word schedule of the twelve rounds.
const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// Why a BLAKE2b hasher could not be created or finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The output length is 0, more than 64 bytes, or differs from the length the hasher
    /// was created for.
    InvalidOutputLength,
    /// The key is longer than 64 bytes.
    InvalidKeyLength,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidOutputLength => "BLAKE2b output length must be 1 to 64 bytes",
            Error::InvalidKeyLength => "BLAKE2b key must be at most 64 bytes",
        })
    }
}

impl core::error::Error for Error {}

/// The parameters of a BLAKE2b instance. Zero salt and personalisation mean "none".
///
/// ```
/// use sibuna_crypto::blake2b::{Blake2b, Params};
/// let params = Params { output_len: 32, key: b"secret", ..Default::default() };
/// let mut hasher = Blake2b::with_params(&params).unwrap();
/// hasher.update(b"message");
/// let mut digest = [0u8; 32];
/// hasher.finalize_into(&mut digest).unwrap();
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Params<'a> {
    /// Digest length in bytes, 1 to 64. The default is 64 (BLAKE2b-512).
    pub output_len: usize,
    /// The MAC key, at most 64 bytes; empty for plain hashing.
    pub key: &'a [u8],
    /// The salt.
    pub salt: [u8; SALT_LEN],
    /// The personalisation string (Zig calls it the context).
    pub personal: [u8; SALT_LEN],
}

impl Default for Params<'_> {
    fn default() -> Self {
        Params { output_len: MAX_OUTPUT_LEN, key: &[], salt: [0; 16], personal: [0; 16] }
    }
}

/// An incremental BLAKE2b hasher. It erases its state, which includes the key, when
/// dropped.
#[derive(Clone)]
pub struct Blake2b {
    h: [u64; 8],
    /// Bytes compressed so far, the counter `t` of RFC 7693.
    counter: u128,
    /// The pending input. BLAKE2b must know which block is the last one, so a full block is
    /// kept here until more input arrives or the hash is finished.
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
    output_len: usize,
}

impl Blake2b {
    /// An unkeyed hasher producing `output_len` bytes.
    ///
    /// Fails with [`Error::InvalidOutputLength`] unless `output_len` is 1 to 64.
    pub fn new(output_len: usize) -> Result<Self, Error> {
        Self::with_params(&Params { output_len, ..Default::default() })
    }

    /// A keyed hasher (a MAC) producing `output_len` bytes. Borrows `key` for the call.
    ///
    /// Fails when `output_len` is not 1 to 64 or `key` is longer than 64 bytes.
    pub fn new_keyed(key: &[u8], output_len: usize) -> Result<Self, Error> {
        Self::with_params(&Params { output_len, key, ..Default::default() })
    }

    /// A hasher configured by `params`, which is borrowed for the call.
    ///
    /// Fails when the output length is not 1 to 64 or the key is longer than 64 bytes.
    pub fn with_params(params: &Params<'_>) -> Result<Self, Error> {
        if params.output_len == 0 || params.output_len > MAX_OUTPUT_LEN {
            return Err(Error::InvalidOutputLength);
        }
        if params.key.len() > MAX_KEY_LEN {
            return Err(Error::InvalidKeyLength);
        }
        Ok(Self::init(params))
    }

    /// Builds the initial state from validated parameters.
    fn init(params: &Params<'_>) -> Self {
        let mut h = IV;
        // Parameter block word 0: digest length, key length, fanout 1, depth 1.
        h[0] ^= 0x0101_0000 ^ ((params.key.len() as u64) << 8) ^ params.output_len as u64;
        let (salt, _) = params.salt.as_chunks::<8>();
        let (personal, _) = params.personal.as_chunks::<8>();
        for (word, bytes) in h[4..].iter_mut().zip(salt.iter().chain(personal)) {
            *word ^= u64::from_le_bytes(*bytes);
        }
        let mut hasher = Blake2b {
            h,
            counter: 0,
            buf: [0; BLOCK_LEN],
            buf_len: 0,
            output_len: params.output_len,
        };
        if !params.key.is_empty() {
            // The key, padded with zeros to a full block, is the first block of input.
            hasher.buf[..params.key.len()].copy_from_slice(params.key);
            hasher.buf_len = BLOCK_LEN;
        }
        hasher
    }

    /// An unkeyed hasher for callers inside the crate whose output length is a constant;
    /// a length outside 1 to 64 is clamped into that range.
    pub(crate) fn with_output_len(output_len: usize) -> Self {
        Self::init(&Params {
            output_len: output_len.clamp(1, MAX_OUTPUT_LEN),
            ..Default::default()
        })
    }

    /// Consumes the hasher and writes the first `out.len()` bytes of the digest, at most
    /// 64, to `out`. For callers inside the crate that created the hasher with
    /// `out.len()` as its output length.
    pub(crate) fn finalize_truncated(mut self, out: &mut [u8]) {
        let digest = self.finish();
        for (out, byte) in out.iter_mut().zip(&digest) {
            *out = *byte;
        }
    }

    /// The digest length this hasher was created for.
    pub fn output_len(&self) -> usize {
        self.output_len
    }

    /// Absorbs `data`. Never fails.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.buf_len + data.len() <= BLOCK_LEN {
            self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
            self.buf_len += data.len();
            return;
        }
        // More than a block is available: fill and compress the pending block first.
        let (head, rest) = data.split_at(BLOCK_LEN - self.buf_len);
        self.buf[self.buf_len..].copy_from_slice(head);
        self.counter += BLOCK_LEN as u128;
        compress(&mut self.h, &self.buf, self.counter, false);
        data = rest;
        // Compress whole blocks while at least one more byte follows them, so that the
        // last block always stays in the buffer.
        while data.len() > BLOCK_LEN {
            let Some((block, rest)) = data.split_first_chunk::<BLOCK_LEN>() else { break };
            self.counter += BLOCK_LEN as u128;
            compress(&mut self.h, block, self.counter, false);
            data = rest;
        }
        self.buf[..data.len()].copy_from_slice(data);
        self.buf_len = data.len();
    }

    /// Consumes the hasher and writes the digest to `out`, which must be exactly
    /// [`Blake2b::output_len`] bytes long.
    ///
    /// Fails with [`Error::InvalidOutputLength`] when the length differs; nothing is
    /// written then.
    pub fn finalize_into(mut self, out: &mut [u8]) -> Result<(), Error> {
        if out.len() != self.output_len {
            return Err(Error::InvalidOutputLength);
        }
        let digest = self.finish();
        out.copy_from_slice(&digest[..self.output_len]);
        Ok(())
    }

    /// Consumes the hasher and returns the 64-byte digest of BLAKE2b-512.
    ///
    /// Fails with [`Error::InvalidOutputLength`] when the hasher was created for a
    /// shorter output, because the parameter block then yields a different hash.
    pub fn finalize(mut self) -> Result<[u8; MAX_OUTPUT_LEN], Error> {
        if self.output_len != MAX_OUTPUT_LEN {
            return Err(Error::InvalidOutputLength);
        }
        Ok(self.finish())
    }

    /// Compresses the last block and serialises the state.
    fn finish(&mut self) -> [u8; MAX_OUTPUT_LEN] {
        self.buf[self.buf_len..].fill(0);
        self.counter += self.buf_len as u128;
        compress(&mut self.h, &self.buf, self.counter, true);
        let mut digest = [0u8; MAX_OUTPUT_LEN];
        let (chunks, _) = digest.as_chunks_mut::<8>();
        for (bytes, word) in chunks.iter_mut().zip(&self.h) {
            *bytes = word.to_le_bytes();
        }
        digest
    }
}

impl Drop for Blake2b {
    fn drop(&mut self) {
        wipe::wipe_u64(&mut self.h);
        ct::zeroize(&mut self.buf);
    }
}

impl fmt::Debug for Blake2b {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The state may hold a key; show only the configuration.
        f.debug_struct("Blake2b").field("output_len", &self.output_len).finish_non_exhaustive()
    }
}

/// Returns the BLAKE2b-512 digest of `data`.
pub fn hash(data: &[u8]) -> [u8; MAX_OUTPUT_LEN] {
    let mut hasher = Blake2b::init(&Params::default());
    hasher.update(data);
    hasher.finish()
}

/// Writes the BLAKE2b digest of `data` to `out`; the output length is `out.len()`.
///
/// Fails with [`Error::InvalidOutputLength`] unless `out` is 1 to 64 bytes long.
pub fn hash_into(out: &mut [u8], data: &[u8]) -> Result<(), Error> {
    let mut hasher = Blake2b::new(out.len())?;
    hasher.update(data);
    hasher.finalize_into(out)
}

/// Writes the keyed BLAKE2b digest (MAC) of `data` under `key` to `out`; the output length
/// is `out.len()`.
///
/// Fails when `out` is not 1 to 64 bytes long or `key` is longer than 64 bytes.
pub fn keyed_hash_into(key: &[u8], out: &mut [u8], data: &[u8]) -> Result<(), Error> {
    let mut hasher = Blake2b::new_keyed(key, out.len())?;
    hasher.update(data);
    hasher.finalize_into(out)
}

/// The mixing function G of RFC 7693 section 3.1.
#[inline(always)]
fn mix(v: &mut [u64; 16], [a, b, c, d]: [usize; 4], x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// The compression function F of RFC 7693 section 3.2. `counter` is the number of bytes
/// hashed up to and including this block; `last` marks the final block.
fn compress(h: &mut [u64; 8], block: &[u8; BLOCK_LEN], counter: u128, last: bool) {
    let mut m = [0u64; 16];
    let (words, _) = block.as_chunks::<8>();
    for (word, bytes) in m.iter_mut().zip(words) {
        *word = u64::from_le_bytes(*bytes);
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= counter as u64;
    v[13] ^= (counter >> 64) as u64;
    if last {
        v[14] = !v[14];
    }
    for s in &SIGMA {
        mix(&mut v, [0, 4, 8, 12], m[s[0]], m[s[1]]);
        mix(&mut v, [1, 5, 9, 13], m[s[2]], m[s[3]]);
        mix(&mut v, [2, 6, 10, 14], m[s[4]], m[s[5]]);
        mix(&mut v, [3, 7, 11, 15], m[s[6]], m[s[7]]);
        mix(&mut v, [0, 5, 10, 15], m[s[8]], m[s[9]]);
        mix(&mut v, [1, 6, 11, 12], m[s[10]], m[s[11]]);
        mix(&mut v, [2, 7, 8, 13], m[s[12]], m[s[13]]);
        mix(&mut v, [3, 4, 9, 14], m[s[14]], m[s[15]]);
    }
    for (i, word) in h.iter_mut().enumerate() {
        *word ^= v[i] ^ v[i + 8];
    }
    wipe::wipe_u64(&mut m);
}

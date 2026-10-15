//! SHA-1 (FIPS 180-4).
//!
//! SHA-1 is broken for collision resistance. Sibuna uses it only where a protocol demands it:
//! the WebSocket handshake (RFC 6455) and HMAC-SHA1 one-time passwords (RFC 6238), neither of
//! which relies on collision resistance. It is not on a hot path, so there is no hardware
//! implementation.

use crate::buffer::BlockBuffer;

/// Length of a SHA-1 digest in bytes.
pub const DIGEST_LEN: usize = 20;

/// Length of a SHA-1 input block in bytes.
pub const BLOCK_LEN: usize = 64;

const INITIAL_STATE: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

/// An incremental SHA-1 hasher.
///
/// ```
/// use sibuna_crypto::sha1::Sha1;
/// let mut hasher = Sha1::new();
/// hasher.update(b"ab");
/// hasher.update(b"c");
/// assert_eq!(hasher.finalize(), Sha1::digest(b"abc"));
/// ```
#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    buffer: BlockBuffer<BLOCK_LEN>,
    /// Bytes absorbed so far; the bit length wraps beyond 2^64 bits, as in Zig.
    length: u64,
}

impl Sha1 {
    /// A hasher that has absorbed nothing.
    pub const fn new() -> Self {
        Self { state: INITIAL_STATE, buffer: BlockBuffer::new(), length: 0 }
    }

    /// Absorbs `data`. Borrows it only for the call; never fails.
    pub fn update(&mut self, data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        self.buffer.update(data, |blocks| compress(&mut self.state, blocks));
    }

    /// Consumes the hasher and returns the 20-byte digest of everything absorbed.
    pub fn finalize(mut self) -> [u8; DIGEST_LEN] {
        let bits = self.length.wrapping_mul(8).to_be_bytes();
        self.buffer.finish(&bits, |blocks| compress(&mut self.state, blocks));
        let mut out = [0u8; DIGEST_LEN];
        for (bytes, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.state) {
            *bytes = word.to_be_bytes();
        }
        out
    }

    /// Returns the SHA-1 digest of `data` in one call.
    pub fn digest(data: &[u8]) -> [u8; DIGEST_LEN] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

fn compress(state: &mut [u32; 5], blocks: &[[u8; BLOCK_LEN]]) {
    for block in blocks {
        compress_block(state, block);
    }
}

/// The SHA-1 compression function, FIPS 180-4 section 6.1.2.
fn compress_block(state: &mut [u32; 5], block: &[u8; BLOCK_LEN]) {
    let mut w = [0u32; 80];
    for (word, bytes) in w.iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_be_bytes(*bytes);
    }
    for t in 16..80 {
        w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (t, word) in w.iter().enumerate() {
        let (f, k) = match t {
            0..20 => ((b & c) | (!b & d), 0x5a827999),
            20..40 => (b ^ c ^ d, 0x6ed9eba1),
            40..60 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
            _ => (b ^ c ^ d, 0xca62c1d6),
        };
        let temp =
            a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*word);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }
    for (word, value) in state.iter_mut().zip([a, b, c, d, e]) {
        *word = word.wrapping_add(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{hex_array, pattern};

    /// FIPS 180-4 example vectors, confirmed with Zig 0.16 `std.crypto.hash.Sha1`.
    const VECTORS: [(&str, &str); 4] = [
        ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        ("abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
        ),
        (
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
             hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "a49b2446a02c645bf419f995b67091253a04a259",
        ),
    ];

    #[test]
    fn fips_vectors() {
        for (input, expected) in VECTORS {
            assert_eq!(Sha1::digest(input.as_bytes()), hex_array(expected), "{input:?}");
        }
    }

    #[test]
    fn one_million_a() {
        let mut hasher = Sha1::default();
        for _ in 0..1000 {
            hasher.update(&[b'a'; 1000]);
        }
        let expected = hex_array("34aa973cd4c4daa4f61eeb2bdbad27316534016f");
        assert_eq!(hasher.finalize(), expected);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data = pattern(300);
        for len in 0..=data.len() {
            let expected = Sha1::digest(&data[..len]);
            for piece in [1, 13, 64, 65] {
                let mut hasher = Sha1::new();
                data[..len].chunks(piece).for_each(|chunk| hasher.update(chunk));
                assert_eq!(hasher.finalize(), expected, "length {len} piece {piece}");
            }
        }
    }
}

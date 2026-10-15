//! SHA-512 (FIPS 180-4).
//!
//! Ed25519 hashes with SHA-512 (RFC 8032). Signing and verification hash only a few short
//! messages, so there is no hardware implementation.

use crate::buffer::BlockBuffer;

/// Length of a SHA-512 digest in bytes.
pub const DIGEST_LEN: usize = 64;

/// Length of a SHA-512 input block in bytes.
pub const BLOCK_LEN: usize = 128;

/// The initial hash value H(0) of FIPS 180-4, section 5.3.5.
const INITIAL_STATE: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// The round constants K of FIPS 180-4, section 4.2.3.
const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// An incremental SHA-512 hasher.
///
/// ```
/// use sibuna_crypto::sha512::Sha512;
/// let mut hasher = Sha512::new();
/// hasher.update(b"ab");
/// hasher.update(b"c");
/// assert_eq!(hasher.finalize(), Sha512::digest(b"abc"));
/// ```
#[derive(Clone)]
pub struct Sha512 {
    state: [u64; 8],
    buffer: BlockBuffer<BLOCK_LEN>,
    /// Bytes absorbed so far; FIPS 180-4 allows up to 2^128 bits.
    length: u128,
}

impl Sha512 {
    /// A hasher that has absorbed nothing.
    pub const fn new() -> Self {
        Self { state: INITIAL_STATE, buffer: BlockBuffer::new(), length: 0 }
    }

    /// Absorbs `data`. Borrows it only for the call; never fails.
    pub fn update(&mut self, data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u128);
        self.buffer.update(data, |blocks| compress(&mut self.state, blocks));
    }

    /// Consumes the hasher and returns the 64-byte digest of everything absorbed.
    pub fn finalize(mut self) -> [u8; DIGEST_LEN] {
        let bits = self.length.wrapping_mul(8).to_be_bytes();
        self.buffer.finish(&bits, |blocks| compress(&mut self.state, blocks));
        let mut out = [0u8; DIGEST_LEN];
        for (bytes, word) in out.as_chunks_mut::<8>().0.iter_mut().zip(self.state) {
            *bytes = word.to_be_bytes();
        }
        out
    }

    /// Returns the SHA-512 digest of `data` in one call.
    pub fn digest(data: &[u8]) -> [u8; DIGEST_LEN] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

fn compress(state: &mut [u64; 8], blocks: &[[u8; BLOCK_LEN]]) {
    for block in blocks {
        compress_block(state, block);
    }
}

/// The SHA-512 compression function, FIPS 180-4 section 6.4.2.
fn compress_block(state: &mut [u64; 8], block: &[u8; BLOCK_LEN]) {
    let mut w = [0u64; 80];
    for (word, bytes) in w.iter_mut().zip(block.as_chunks::<8>().0) {
        *word = u64::from_be_bytes(*bytes);
    }
    for t in 16..80 {
        let s0 = w[t - 15].rotate_right(1) ^ w[t - 15].rotate_right(8) ^ (w[t - 15] >> 7);
        let s1 = w[t - 2].rotate_right(19) ^ w[t - 2].rotate_right(61) ^ (w[t - 2] >> 6);
        w[t] = w[t - 16].wrapping_add(s0).wrapping_add(w[t - 7]).wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (k, w) in K.iter().zip(w) {
        let t1 = h
            .wrapping_add(e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41))
            .wrapping_add((e & f) ^ (!e & g))
            .wrapping_add(*k)
            .wrapping_add(w);
        let t2 = (a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39))
            .wrapping_add((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (word, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *word = word.wrapping_add(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{hex_array, pattern};

    /// FIPS 180-4 example vectors, confirmed with Zig 0.16 `std.crypto.hash.sha2.Sha512`.
    const VECTORS: [(&str, &str); 4] = [
        (
            "",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ),
        (
            "abc",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335\
             96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
        ),
        (
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
             hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
             501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        ),
    ];

    #[test]
    fn fips_vectors() {
        for (input, expected) in VECTORS {
            assert_eq!(Sha512::digest(input.as_bytes()), hex_array(expected), "{input:?}");
        }
    }

    #[test]
    fn one_million_a() {
        let mut hasher = Sha512::default();
        for _ in 0..1000 {
            hasher.update(&[b'a'; 1000]);
        }
        let expected = hex_array(
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb\
             de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
        );
        assert_eq!(hasher.finalize(), expected);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data = pattern(400);
        for len in 0..=data.len() {
            let expected = Sha512::digest(&data[..len]);
            for piece in [1, 17, 111, 112, 128, 129] {
                let mut hasher = Sha512::new();
                data[..len].chunks(piece).for_each(|chunk| hasher.update(chunk));
                assert_eq!(hasher.finalize(), expected, "length {len} piece {piece}");
            }
        }
    }
}

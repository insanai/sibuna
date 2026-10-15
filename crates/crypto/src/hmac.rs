//! HMAC (RFC 2104) over SHA-256 and SHA-1.
//!
//! A MAC value holds two hasher states, already keyed with the inner and outer pads, so
//! cloning a keyed MAC to authenticate several messages under one key costs no hashing of
//! the key.

use crate::ct;
use crate::sha1::{self, Sha1};
use crate::sha256::{self, Sha256};

/// The block length of both SHA-1 and SHA-256.
const BLOCK_LEN: usize = 64;

/// Returns the key block xor-ed with the inner pad (0x36) and the outer pad (0x5c).
/// `key_block` is the key, or its digest when longer than a block, padded with zeros.
fn pads(key_block: &[u8; BLOCK_LEN]) -> ([u8; BLOCK_LEN], [u8; BLOCK_LEN]) {
    (key_block.map(|byte| byte ^ 0x36), key_block.map(|byte| byte ^ 0x5c))
}

/// Erases the derived key material once it has been absorbed.
fn erase(
    key_block: &mut [u8; BLOCK_LEN],
    inner: &mut [u8; BLOCK_LEN],
    outer: &mut [u8; BLOCK_LEN],
) {
    ct::zeroize(key_block);
    ct::zeroize(inner);
    ct::zeroize(outer);
}

/// HMAC-SHA256.
///
/// ```
/// use sibuna_crypto::hmac::{self, HmacSha256};
/// let mut mac = HmacSha256::new(b"key");
/// mac.update(b"message");
/// assert_eq!(mac.finalize(), hmac::hmac_sha256(b"key", b"message"));
/// ```
#[derive(Clone)]
pub struct HmacSha256 {
    inner: Sha256,
    outer: Sha256,
}

impl HmacSha256 {
    /// A MAC keyed with `key` of any length. Keys longer than 64 bytes are hashed first,
    /// as RFC 2104 requires.
    pub fn new(key: &[u8]) -> Self {
        let mut key_block = [0u8; BLOCK_LEN];
        if key.len() > BLOCK_LEN {
            key_block[..sha256::DIGEST_LEN].copy_from_slice(&Sha256::digest(key));
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }
        let (mut inner_pad, mut outer_pad) = pads(&key_block);
        let mut inner = Sha256::new();
        inner.update(&inner_pad);
        let mut outer = Sha256::new();
        outer.update(&outer_pad);
        erase(&mut key_block, &mut inner_pad, &mut outer_pad);
        Self { inner, outer }
    }

    /// Absorbs `data`. Never fails.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Consumes the MAC and returns the 32-byte tag. Compare tags with [`ct::eq`].
    pub fn finalize(self) -> [u8; sha256::DIGEST_LEN] {
        let mut outer = self.outer;
        outer.update(&self.inner.finalize());
        outer.finalize()
    }
}

/// HMAC-SHA1, for protocols that require it (RFC 6238 one-time passwords).
///
/// ```
/// use sibuna_crypto::hmac::{self, HmacSha1};
/// let mut mac = HmacSha1::new(b"key");
/// mac.update(b"message");
/// assert_eq!(mac.finalize(), hmac::hmac_sha1(b"key", b"message"));
/// ```
#[derive(Clone)]
pub struct HmacSha1 {
    inner: Sha1,
    outer: Sha1,
}

impl HmacSha1 {
    /// A MAC keyed with `key` of any length. Keys longer than 64 bytes are hashed first,
    /// as RFC 2104 requires.
    pub fn new(key: &[u8]) -> Self {
        let mut key_block = [0u8; BLOCK_LEN];
        if key.len() > BLOCK_LEN {
            key_block[..sha1::DIGEST_LEN].copy_from_slice(&Sha1::digest(key));
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }
        let (mut inner_pad, mut outer_pad) = pads(&key_block);
        let mut inner = Sha1::new();
        inner.update(&inner_pad);
        let mut outer = Sha1::new();
        outer.update(&outer_pad);
        erase(&mut key_block, &mut inner_pad, &mut outer_pad);
        Self { inner, outer }
    }

    /// Absorbs `data`. Never fails.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Consumes the MAC and returns the 20-byte tag. Compare tags with [`ct::eq`].
    pub fn finalize(self) -> [u8; sha1::DIGEST_LEN] {
        let mut outer = self.outer;
        outer.update(&self.inner.finalize());
        outer.finalize()
    }
}

/// Returns HMAC-SHA256 of `data` under `key`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; sha256::DIGEST_LEN] {
    let mut mac = HmacSha256::new(key);
    mac.update(data);
    mac.finalize()
}

/// Returns HMAC-SHA1 of `data` under `key`.
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; sha1::DIGEST_LEN] {
    let mut mac = HmacSha1::new(key);
    mac.update(data);
    mac.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::hex;
    use std::vec::Vec;

    /// The keys and messages of RFC 4231 test cases 1 to 7; RFC 2202 uses the same first
    /// five cases and an 80-byte key with its own messages for cases 6 and 7.
    fn cases(long_key_len: usize, case_7: &'static [u8]) -> [(Vec<u8>, Vec<u8>); 7] {
        let long_key = std::vec![0xaa; long_key_len];
        let long_message: &[u8] = b"Test Using Larger Than Block-Size Key - Hash Key First";
        [
            (std::vec![0x0b; 20], b"Hi There".to_vec()),
            (b"Jefe".to_vec(), b"what do ya want for nothing?".to_vec()),
            (std::vec![0xaa; 20], std::vec![0xdd; 50]),
            ((1..=25).collect(), std::vec![0xcd; 50]),
            (std::vec![0x0c; 20], b"Test With Truncation".to_vec()),
            (long_key.clone(), long_message.to_vec()),
            (long_key, case_7.to_vec()),
        ]
    }

    /// RFC 4231 section 4, confirmed with Zig 0.16 `std.crypto.auth.hmac.sha2.HmacSha256`.
    /// Case 5 is truncated to 128 bits in the RFC; the full tag is from Zig.
    const RFC_4231: [&str; 7] = [
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        "a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5",
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
    ];

    /// RFC 2202 section 3, confirmed with Zig 0.16 `std.crypto.auth.hmac.HmacSha1`.
    const RFC_2202: [&str; 7] = [
        "b617318655057264e28bc0b6fb378c8ef146be00",
        "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
        "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
        "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
        "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",
        "aa4ae5e15272d00e95705637ce8a3b55ed402112",
        "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
    ];

    #[test]
    fn rfc_4231_hmac_sha256() {
        let case_7: &[u8] =
            b"This is a test using a larger than block-size key and a larger than \
            block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        for (i, ((key, data), expected)) in cases(131, case_7).iter().zip(RFC_4231).enumerate() {
            assert_eq!(hmac_sha256(key, data)[..], hex(expected)[..], "case {}", i + 1);
            let mut mac = HmacSha256::new(key);
            data.chunks(7).for_each(|piece| mac.update(piece));
            assert_eq!(mac.finalize()[..], hex(expected)[..], "streamed case {}", i + 1);
        }
        assert_eq!(hex(RFC_4231[4])[..16], hex("a3b6167473100ee06e0c796c2955552b")[..]);
    }

    #[test]
    fn rfc_2202_hmac_sha1() {
        let case_7: &[u8] =
            b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";
        for (i, ((key, data), expected)) in cases(80, case_7).iter().zip(RFC_2202).enumerate() {
            assert_eq!(hmac_sha1(key, data)[..], hex(expected)[..], "case {}", i + 1);
            let mut mac = HmacSha1::new(key);
            data.chunks(5).for_each(|piece| mac.update(piece));
            assert_eq!(mac.finalize()[..], hex(expected)[..], "streamed case {}", i + 1);
        }
    }

    #[test]
    fn cloned_mac_reuses_the_key() {
        let keyed = HmacSha256::new(b"shared secret");
        let mut first = keyed.clone();
        first.update(b"one");
        let mut second = keyed;
        second.update(b"two");
        assert_eq!(first.finalize(), hmac_sha256(b"shared secret", b"one"));
        assert_eq!(second.finalize(), hmac_sha256(b"shared secret", b"two"));
    }

    #[test]
    fn block_sized_keys_are_not_hashed() {
        let key = [0x42u8; BLOCK_LEN];
        let longer = [0x42u8; BLOCK_LEN + 1];
        assert_ne!(hmac_sha256(&key, b"m"), hmac_sha256(&Sha256::digest(&key), b"m"));
        assert_eq!(hmac_sha256(&longer, b"m"), hmac_sha256(&Sha256::digest(&longer), b"m"));
        assert_eq!(hmac_sha1(&longer, b"m"), hmac_sha1(&Sha1::digest(&longer), b"m"));
    }
}

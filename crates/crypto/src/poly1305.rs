//! The Poly1305 one-time authenticator of RFC 8439 section 2.5.
//!
//! The accumulator lives in three 64-bit limbs (130 bits plus carries), as in Zig's
//! `std.crypto.onetimeauth.Poly1305`: each 16-byte block is added with its high bit set,
//! multiplied by the clamped `r` with 128-bit products, and partially reduced modulo
//! 2^130 - 5 using 2^130 = 5. The final reduction and the addition of `s` are constant
//! time.

#[cfg(test)]
mod tests;

use core::fmt;

use crate::wipe;

/// Length of a Poly1305 key (`r` then `s`) in bytes.
pub const KEY_LEN: usize = 32;

/// Length of a Poly1305 tag in bytes.
pub const TAG_LEN: usize = 16;

/// Length of a Poly1305 block in bytes.
pub const BLOCK_LEN: usize = 16;

/// An incremental Poly1305 computation. A key must authenticate one message only. The key
/// and the accumulator are erased when the value is dropped.
///
/// ```
/// use sibuna_crypto::poly1305::{self, Poly1305};
/// let mut mac = Poly1305::new(&[3; 32]);
/// mac.update(b"message");
/// assert_eq!(mac.finalize(), poly1305::mac(&[3; 32], b"message"));
/// ```
#[derive(Clone)]
pub struct Poly1305 {
    r: [u64; 2],
    s: [u64; 2],
    h: [u64; 3],
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
}

impl Poly1305 {
    /// A computation keyed with `key`: `r` (clamped) then `s`.
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        let word = |at: usize| u64::from_le_bytes(core::array::from_fn(|i| key[at + i]));
        Poly1305 {
            r: [word(0) & 0x0fff_fffc_0fff_ffff, word(8) & 0x0fff_fffc_0fff_fffc],
            s: [word(16), word(24)],
            h: [0; 3],
            buf: [0; BLOCK_LEN],
            buf_len: 0,
        }
    }

    /// Absorbs `data`. Never fails.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = (BLOCK_LEN - self.buf_len).min(data.len());
            let (head, rest) = data.split_at(take);
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(head);
            self.buf_len += take;
            data = rest;
            if self.buf_len < BLOCK_LEN {
                return;
            }
            let block = self.buf;
            self.blocks(core::slice::from_ref(&block), 1);
            self.buf_len = 0;
        }
        let (blocks, rest) = data.as_chunks::<BLOCK_LEN>();
        self.blocks(blocks, 1);
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    /// Pads the input with zeros to a whole block, as the AEAD construction requires
    /// between associated data and ciphertext. Does nothing on a block boundary.
    pub fn pad_to_block(&mut self) {
        if self.buf_len > 0 {
            self.buf[self.buf_len..].fill(0);
            let block = self.buf;
            self.blocks(core::slice::from_ref(&block), 1);
            self.buf_len = 0;
        }
    }

    /// Consumes the computation and returns the 16-byte tag. Compare tags with
    /// [`crate::ct::eq`].
    pub fn finalize(mut self) -> [u8; TAG_LEN] {
        if self.buf_len > 0 {
            // The last partial block carries its 0x01 byte inside the block, not at bit 128.
            self.buf[self.buf_len] = 1;
            self.buf[self.buf_len + 1..].fill(0);
            let block = self.buf;
            self.blocks(core::slice::from_ref(&block), 0);
        }
        let [h0, h1, h2] = self.h;
        // Subtract p = 2^130 - 5; keep the difference when it does not borrow.
        let (g0, borrow) = h0.overflowing_sub(0xffff_ffff_ffff_fffb);
        let (g1, borrow1) = sub_borrow(h1, u64::MAX, borrow);
        let (_, borrow2) = sub_borrow(h2, 3, borrow1);
        let keep_h = 0u64.wrapping_sub(u64::from(borrow2));
        let h0 = (h0 & keep_h) | (g0 & !keep_h);
        let h1 = (h1 & keep_h) | (g1 & !keep_h);
        let (t0, carry) = h0.overflowing_add(self.s[0]);
        let t1 = h1.wrapping_add(self.s[1]).wrapping_add(u64::from(carry));
        let mut tag = [0u8; TAG_LEN];
        tag[..8].copy_from_slice(&t0.to_le_bytes());
        tag[8..].copy_from_slice(&t1.to_le_bytes());
        tag
    }

    /// Processes whole blocks; `high_bit` is 1 for full message blocks and 0 for the
    /// padded final block.
    fn blocks(&mut self, blocks: &[[u8; BLOCK_LEN]], high_bit: u64) {
        let [r0, r1] = self.r;
        let [mut h0, mut h1, mut h2] = self.h;
        for block in blocks {
            let message = u128::from_le_bytes(*block);
            let (m0, m1) = (message as u64, (message >> 64) as u64);
            let (sum0, carry) = h0.overflowing_add(m0);
            let (sum1, carry) = add_carry(h1, m1, carry);
            h0 = sum0;
            h1 = sum1;
            h2 = h2.wrapping_add(u64::from(carry)).wrapping_add(high_bit);
            // h * r; h2 is small (a few bits) and r is clamped, so these do not overflow.
            let d0 = mul(h0, r0);
            let d1 = mul(h1, r0).wrapping_add(mul(h0, r1));
            let d2 = mul(h2, r0).wrapping_add(mul(h1, r1));
            let d3 = mul(h2, r1);
            let t0 = d0 as u64;
            let (t1, carry) = (d1 as u64).overflowing_add((d0 >> 64) as u64);
            let (t2, carry) = add_carry(d2 as u64, (d1 >> 64) as u64, carry);
            let t3 = (d3 as u64).wrapping_add((d2 >> 64) as u64).wrapping_add(u64::from(carry));
            // Partial reduction: the bits above 2^130, c, come back as 5c = 4c + c.
            h0 = t0;
            h1 = t1;
            h2 = t2 & 3;
            let c_low = t2 & !3;
            let c_high = t3;
            let (sum0, carry) = h0.overflowing_add(c_low);
            let (sum1, carry) = add_carry(h1, c_high, carry);
            h2 = h2.wrapping_add(u64::from(carry));
            let (sum0, carry) = sum0.overflowing_add((c_low >> 2) | (c_high << 62));
            let (sum1, carry) = add_carry(sum1, c_high >> 2, carry);
            h0 = sum0;
            h1 = sum1;
            h2 = h2.wrapping_add(u64::from(carry));
        }
        self.h = [h0, h1, h2];
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        wipe::wipe_u64(&mut self.r);
        wipe::wipe_u64(&mut self.s);
        wipe::wipe_u64(&mut self.h);
        wipe::wipe_bytes(&mut self.buf);
    }
}

impl fmt::Debug for Poly1305 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Poly1305 { .. }")
    }
}

/// Returns the Poly1305 tag of `data` under the one-time `key`.
pub fn mac(key: &[u8; KEY_LEN], data: &[u8]) -> [u8; TAG_LEN] {
    let mut state = Poly1305::new(key);
    state.update(data);
    state.finalize()
}

#[inline(always)]
fn mul(x: u64, y: u64) -> u128 {
    u128::from(x) * u128::from(y)
}

#[inline(always)]
fn add_carry(x: u64, y: u64, carry: bool) -> (u64, bool) {
    let (sum, carry1) = x.overflowing_add(y);
    let (sum, carry2) = sum.overflowing_add(u64::from(carry));
    (sum, carry1 | carry2)
}

#[inline(always)]
fn sub_borrow(x: u64, y: u64, borrow: bool) -> (u64, bool) {
    let (difference, borrow1) = x.overflowing_sub(y);
    let (difference, borrow2) = difference.overflowing_sub(u64::from(borrow));
    (difference, borrow1 | borrow2)
}

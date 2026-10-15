//! Constant-time comparison and zeroing of secrets.
//!
//! These replace Zig's `std.crypto.timing_safe.eql` and `std.crypto.secureZero`.
//!
//! `zeroize` uses volatile writes: they are the one store the compiler is required to keep,
//! which is the guarantee a secret wipe needs. That is the only `unsafe` in this module.
#![allow(unsafe_code)]

use core::hint::black_box;
use core::sync::atomic::{Ordering, compiler_fence};

/// Compares two byte strings in time that depends only on their lengths.
///
/// Borrows both slices for the call. Returns `true` when they are equal. Slices of
/// different lengths compare unequal at once; lengths are not secret in our protocols (MAC
/// tags and digests have fixed sizes).
pub fn eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0u8;
    for (x, y) in a.iter().zip(b) {
        // The optimiser must not see the running value, or it could stop at the first
        // difference and leak its position through timing.
        difference = black_box(difference | (x ^ y));
    }
    difference == 0
}

/// Overwrites `buf` with zeros using volatile stores, which the optimiser must not remove.
///
/// Borrows `buf` mutably for the call. Use it on secrets that are about to go out of scope,
/// where a plain `fill(0)` would be a dead store the compiler may delete.
pub fn zeroize(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, exclusive reference to an initialised `u8`
        // for the duration of the write.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    // Keep later code (for example freeing the memory) from being reordered before the wipe.
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eq_compares_contents_and_lengths() {
        assert!(eq(b"", b""));
        assert!(eq(b"sibuna", b"sibuna"));
        assert!(!eq(b"sibuna", b"sibunb"));
        assert!(!eq(b"sibuna", b"tibuna"));
        assert!(!eq(b"sibuna", b"sibun"));
        let a = [0x5au8; 32];
        let mut b = a;
        for i in 0..32 {
            b[i] ^= 1;
            assert!(!eq(&a, &b), "difference at byte {i} missed");
            b[i] ^= 1;
        }
        assert!(eq(&a, &b));
    }

    #[test]
    fn zeroize_clears_every_byte() {
        let mut secret = [0xa5u8; 77];
        zeroize(&mut secret);
        assert!(secret.iter().all(|&b| b == 0));
        zeroize(&mut []);
    }
}

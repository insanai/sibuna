//! Zeroing of secrets in a way the optimiser keeps, without `unsafe`.
//!
//! Key schedules and hash states are arrays of `u32` or `u64`, and reinterpreting them as
//! bytes for [`crate::ct::zeroize`] would need `unsafe`. We overwrite them with zeros and
//! hand the slice to `core::hint::black_box`, which the optimiser must treat as reading
//! it, so the stores cannot be removed as dead. The same is done for short byte buffers on
//! the AEAD path, where a vectorised fill is several times faster than the byte-wise
//! volatile stores of `ct::zeroize`.

use core::hint::black_box;

/// Overwrites `words` with zeros in a way the optimiser keeps.
pub(crate) fn wipe_u64(words: &mut [u64]) {
    words.fill(0);
    black_box(words);
}

/// Overwrites `bytes` with zeros in a way the optimiser keeps.
pub(crate) fn wipe_bytes(bytes: &mut [u8]) {
    bytes.fill(0);
    black_box(bytes);
}

/// Overwrites `words` with zeros in a way the optimiser keeps.
pub(crate) fn wipe_u32(words: &mut [u32]) {
    words.fill(0);
    black_box(words);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipes_every_word() {
        let mut long = [u64::MAX; 9];
        wipe_u64(&mut long);
        assert!(long.iter().all(|&w| w == 0));
        let mut short = [u32::MAX; 5];
        wipe_u32(&mut short);
        assert!(short.iter().all(|&w| w == 0));
        let mut bytes = [0xa5u8; 33];
        wipe_bytes(&mut bytes);
        assert!(bytes.iter().all(|&b| b == 0));
    }
}

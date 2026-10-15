//! Erasing buffers that are reused rather than freed.
//!
//! The WebAssembly module installs an allocator that zeroes every block it frees (see the
//! `abi` module), so dropped values erase themselves. Buffers that live for the whole
//! session and are only cleared, such as the event input and the rendered page, keep their
//! old bytes in spare capacity; these functions erase them. They replace Zig's
//! `std.crypto.secureZero` calls on the fixed buffers.

use std::hint::black_box;

/// Overwrites `bytes` with zeros in a way the optimiser keeps.
pub fn wipe_bytes(bytes: &mut [u8]) {
    bytes.fill(0);
    black_box(bytes);
}

/// Overwrites the contents of `text` with zeros and empties it, keeping its capacity.
pub fn wipe_string(text: &mut String) {
    let mut bytes = std::mem::take(text).into_bytes();
    wipe_bytes(&mut bytes);
    bytes.clear();
    // An empty vector is valid UTF-8, so this never fails; the fallback only avoids a panic.
    *text = String::from_utf8(bytes).unwrap_or_default();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wiping_a_string_keeps_its_allocation() {
        let mut text = String::with_capacity(64);
        text.push_str("private csrf");
        let capacity = text.capacity();
        wipe_string(&mut text);
        assert!(text.is_empty());
        assert_eq!(text.capacity(), capacity);
        let mut bytes = *b"seed";
        wipe_bytes(&mut bytes);
        assert_eq!(bytes, [0; 4]);
    }
}

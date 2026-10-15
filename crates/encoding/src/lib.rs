//! Base64 and hexadecimal codecs for Sibuna.
//!
//! Both codecs write into caller buffers and never allocate; the default `alloc` feature
//! adds small helpers that return `String` and `Vec<u8>`. The crate is `no_std`.
//!
//! The base64 module reproduces Zig 0.16 `std.base64` exactly: the four codecs
//! [`base64::STANDARD`], [`base64::STANDARD_NO_PAD`], [`base64::URL_SAFE`] and
//! [`base64::URL_SAFE_NO_PAD`] produce the same text, and decoding accepts and rejects the
//! same inputs. Decoding is strict: a character outside the alphabet, a misplaced or missing
//! padding character, or non-zero bits after the last whole byte is an error. Session
//! cookies and challenge identifiers are decoded on every request, so both directions work
//! on whole 3-byte and 4-character groups through lookup tables, with one validity check per
//! input instead of one branch per byte.
//!
//! Deliberate changes from the Zig version:
//!
//! - Zig decodes into a slice that must have exactly the decoded size; we accept any output
//!   slice at least that long and return the number of bytes written. A short slice is
//!   [`base64::Error::OutputTooSmall`] instead of undefined behaviour.
//! - After a padding character, Zig reports a later non-padding byte as `InvalidCharacter`
//!   only when the byte is `0xFF` (it compares the byte with its table sentinel) and as
//!   `InvalidPadding` otherwise. We report `InvalidPadding` for every such byte. The set of
//!   accepted inputs is unchanged.
//! - The decoder that skips ignored characters (`decoderWithIgnore`) is not ported; Sibuna
//!   never used it.
//! - `hex::decode_to_slice` requires an output of exactly half the input length, where Zig's
//!   `hexToBytes` filled a prefix of a longer buffer. A silently short value is a bug.
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod base64;
pub mod hex;

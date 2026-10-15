//! Cryptographic primitives for Sibuna, with no dependencies.
//!
//! This crate replaces the parts of Zig 0.16's standard library that the Zig daemon used:
//!
//! - [`sha1`], [`sha256`] and [`sha512`]: the SHA-1 and SHA-2 hash functions (FIPS 180-4).
//!   SHA-256 uses the x86-64 SHA extensions or the ARMv8 SHA-2 instructions when the CPU has
//!   them, and a portable implementation otherwise.
//! - [`blake3`]: BLAKE3 in its three modes (hash, keyed hash, key derivation) with
//!   extendable output.
//! - [`hmac`]: HMAC-SHA256 and HMAC-SHA1 (RFC 2104).
//! - [`ed25519`]: Ed25519 signatures (RFC 8032) with the verification rules of Zig's
//!   `std.crypto.sign.Ed25519`.
//! - [`wyhash`]: the non-cryptographic Wyhash, bit for bit identical to Zig's
//!   `std.hash.Wyhash`.
//! - [`ct`]: constant-time comparison and zeroing of secrets.
//!
//! The crate is `no_std`. The default `std` feature enables run-time detection of the SHA-256
//! hardware instructions; without it the choice is made at compile time from the enabled
//! target features.
//!
//! # Deliberate changes from Zig
//!
//! - Zig selected the SHA-256 hardware path at build time. With `std` we detect it at run
//!   time, so one binary is fast on every CPU it runs on.
//! - [`ed25519::VerifyingKey::from_bytes`] decodes the point and rejects encodings that are
//!   not on the curve, the identity, and small-order points. Zig's `PublicKey.fromBytes`
//!   accepted those and rejected them in `verify`. The set of accepted signatures is the same.
//! - Ed25519 signing cannot fail. Zig's `sign` returned an error when the nonce reduced to
//!   zero, an event of probability about 2^-252.
//! - [`ed25519::SigningKey`] zeroes its secrets when dropped.
//! - Ed25519 verification uses width-5 and width-8 NAF digits instead of Zig's signed 4-bit
//!   windows, and keeps the decoded public key. It accepts and rejects exactly the same
//!   inputs and is faster.
//! - BLAKE3 is portable only. Zig's SIMD paths hash large inputs several times faster, but
//!   Sibuna hashes inputs under 100 bytes with BLAKE3, where this implementation is faster.
//! - Wyhash counts the input length in a `u64`. Zig used `usize`, which differs only on
//!   32-bit targets for inputs of 4 GiB or more.
//! - Hash and MAC outputs are returned as arrays instead of written to an output slice.
//! - `ct::zeroize` uses safe code: a plain fill followed by `core::hint::black_box`, which
//!   the optimiser cannot see through, instead of volatile writes that would need `unsafe`.
#![no_std]

#[cfg(any(feature = "std", test))]
extern crate std;

mod buffer;
#[cfg(test)]
mod test_util;
#[cfg(test)]
mod timings;

pub mod blake3;
pub mod ct;
pub mod ed25519;
pub mod hmac;
pub mod sha1;
pub mod sha256;
pub mod sha512;
pub mod wyhash;

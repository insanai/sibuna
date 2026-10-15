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
//! - [`blake2b`]: BLAKE2b (RFC 7693) with variable output, key, salt and personalisation.
//! - [`argon2`]: Argon2id, Argon2i and Argon2d (RFC 9106, version 0x13) over a
//!   caller-provided workspace of 1 KiB blocks, and the PHC strings of Zig's
//!   `std.crypto.pwhash.argon2.strHash` and `strVerify`, verified against caller-supplied
//!   parameter maxima.
//! - [`chacha20`] and [`poly1305`]: the RFC 8439 stream cipher and one-time authenticator,
//!   XChaCha20 and HChaCha20.
//! - [`aead`]: ChaCha20-Poly1305 and XChaCha20-Poly1305 sealing and opening in place.
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
//! - Argon2 takes its memory as a `&mut [argon2::Block]` workspace instead of an
//!   allocator. The Zig console wrapped a reserved 20 MiB buffer in a
//!   `FixedBufferAllocator` for every call; ownership of one slice of blocks replaces that
//!   plumbing, and nothing is allocated per hash. The workspace is wiped before
//!   `derive_key` returns, which the Zig console did by hand with `secureZero`.
//! - Argon2 lanes run one after another; Zig ran them on threads when `p > 1`. The result
//!   is the same, and the console uses `p = 1`. Argon2id with `m = 19456`, `t = 2`, `p = 1`
//!   takes about 18 ms here against Zig's 25 ms on the same machine.
//! - `argon2::verify_phc` rejects costs above the caller's `argon2::Limits` before it
//!   touches memory, and compares hashes in constant time (Zig used `mem.eql`). A
//!   parameter list containing `alg_version=` made Zig's parser panic; it is rejected
//!   with `InvalidEncoding`. An unknown algorithm is `UnsupportedAlgorithm` (Zig reported
//!   `PasswordVerificationFailed`), and a salt or hash longer than 64 bytes is
//!   `InvalidEncoding` (Zig: `NoSpaceLeft`). Otherwise the parser accepts and rejects
//!   exactly what Zig's does, quirks included, checked on 200,000 mutated strings.
//! - `argon2::hash_phc` takes the salt from the caller, because the crate has no source of
//!   randomness; Zig drew 32 random bytes. It checks the output buffer before hashing.
//! - AEAD opening checks the tag and then decrypts in place; on failure the buffer still
//!   holds the ciphertext. Zig decrypted into a separate buffer and left it undefined.
//!   Sealing and opening return `MessageTooLong` where Zig asserted on the length.
//! - Keys of the AEADs, ChaCha20 states, Poly1305 states and keyed BLAKE2b states are
//!   wiped when dropped.
//! - `ct::zeroize` uses safe code: a plain fill followed by `core::hint::black_box`, which
//!   the optimiser cannot see through, instead of volatile writes that would need `unsafe`.
#![no_std]

// `std` serves only run-time CPU feature detection, which exists on x86-64 and aarch64.
// Elsewhere (WebAssembly) the crate stays `no_std` even with the feature on, so a `no_std`
// binary that brings its own panic handler can depend on it through the workspace defaults.
#[cfg(any(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")), test))]
extern crate std;

mod buffer;
#[cfg(test)]
mod test_util;
#[cfg(test)]
mod timings;
mod wipe;

pub mod aead;
pub mod argon2;
pub mod blake2b;
pub mod blake3;
pub mod chacha20;
pub mod ct;
pub mod ed25519;
pub mod hmac;
pub mod poly1305;
pub mod sha1;
pub mod sha256;
pub mod sha512;
pub mod wyhash;

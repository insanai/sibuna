//! Ed25519 signatures (RFC 8032) with the verification rules of Zig 0.16's
//! `std.crypto.sign.Ed25519`.
//!
//! Key pairs are derived deterministically from a 32-byte seed, and signing is
//! deterministic, so a Rust node and a Zig node with the same seed produce identical keys
//! and signatures.
//!
//! Verification is cofactored and strict about encodings, exactly as in Zig:
//!
//! - S must be canonical (S < L), else [`SignatureError::NonCanonical`].
//! - The public key A and the commitment R must be canonical encodings of curve points
//!   ([`SignatureError::NonCanonical`], [`SignatureError::InvalidEncoding`]); the sign bit
//!   is not checked, as in Zig.
//! - A and R must not have x = 0, which rules out the identity and the point of order 2
//!   ([`SignatureError::IdentityElement`]).
//! - A must not have small order ([`SignatureError::WeakPublicKey`]). R may: Zig accepts a
//!   small-order R, and so do we.
//! - The equation `[8][S]B = [8]R + [8][k]A` must hold, with `k = SHA-512(R || A || M)`.
//!
//! Zig checks A when verifying; [`VerifyingKey::from_bytes`] checks it once, when the key is
//! loaded. The set of accepted (key, message, signature) triples is the same.

mod field;
mod point;
mod scalar;

use core::fmt;

use crate::ct;
use crate::sha512::Sha512;
use point::Point;
use scalar::Scalar;

/// Length of a seed, the secret from which a key pair is derived, in bytes.
pub const SEED_LEN: usize = 32;

/// Length of an encoded public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Length of an encoded signature in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// Why a public key or a signature was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureError {
    /// A point encoding or the scalar S is not in canonical form.
    NonCanonical,
    /// A point encoding does not describe a point of the curve.
    InvalidEncoding,
    /// A point has x = 0: the identity or the point of order 2.
    IdentityElement,
    /// The public key has small order, so it would verify forged signatures.
    WeakPublicKey,
    /// The signature does not match the message and the public key.
    VerificationFailed,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            SignatureError::NonCanonical => "non-canonical encoding of a point or scalar",
            SignatureError::InvalidEncoding => "the encoding is not a point of the curve",
            SignatureError::IdentityElement => "the point is the identity or has order 2",
            SignatureError::WeakPublicKey => "the public key has small order",
            SignatureError::VerificationFailed => "signature verification failed",
        };
        f.write_str(message)
    }
}

impl core::error::Error for SignatureError {}

/// An Ed25519 signature: the encoded commitment R followed by the scalar S.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    r: [u8; 32],
    s: [u8; 32],
}

impl Signature {
    /// Splits 64 bytes into R and S. Never fails: the parts are checked by
    /// [`VerifyingKey::verify`], as in Zig.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_LEN]) -> Signature {
        let (r, s) = bytes.split_at(32);
        Signature { r: to_array(r), s: to_array(s) }
    }

    /// Returns the 64-byte encoding R || S.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        let mut bytes = [0u8; SIGNATURE_LEN];
        bytes[..32].copy_from_slice(&self.r);
        bytes[32..].copy_from_slice(&self.s);
        bytes
    }
}

/// A public key that has passed the checks of [`VerifyingKey::from_bytes`].
///
/// It keeps the decoded point, so verification does not decode it again.
#[derive(Clone, Copy)]
pub struct VerifyingKey {
    bytes: [u8; PUBLIC_KEY_LEN],
    point: Point,
}

impl VerifyingKey {
    /// Decodes and checks a public key.
    ///
    /// Fails with [`SignatureError::NonCanonical`] or [`SignatureError::InvalidEncoding`]
    /// when `bytes` is not a canonical point encoding, with
    /// [`SignatureError::IdentityElement`] when x = 0, and with
    /// [`SignatureError::WeakPublicKey`] when the point has small order.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Result<VerifyingKey, SignatureError> {
        let point = Point::decode(bytes)?;
        if point.has_zero_x() {
            return Err(SignatureError::IdentityElement);
        }
        if point.is_small_order() {
            return Err(SignatureError::WeakPublicKey);
        }
        Ok(VerifyingKey { bytes: *bytes, point })
    }

    /// Returns the 32-byte encoding of the key.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.bytes
    }

    /// Checks `signature` on `message`.
    ///
    /// Returns `Ok(())` for a valid signature. Fails with [`SignatureError::NonCanonical`]
    /// when S is not below L or R is not canonical, [`SignatureError::InvalidEncoding`] when
    /// R is not a point, [`SignatureError::IdentityElement`] when R has x = 0, and
    /// [`SignatureError::VerificationFailed`] when the equation does not hold. Runs in
    /// variable time: every input is public.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        if !Scalar::is_canonical(&signature.s) {
            return Err(SignatureError::NonCanonical);
        }
        let r = Point::decode(&signature.r)?;
        if r.has_zero_x() {
            return Err(SignatureError::IdentityElement);
        }
        let k = challenge(&signature.r, &self.bytes, message);
        // [S]B - [k]A - R, which must vanish once multiplied by the cofactor.
        let sb_minus_ka =
            Point::mul_double_vartime(&k.to_bytes(), &self.point.neg(), &signature.s);
        if sb_minus_ka.sub(&r).is_small_order() {
            Ok(())
        } else {
            Err(SignatureError::VerificationFailed)
        }
    }
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for VerifyingKey {}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("VerifyingKey").field(&self.bytes).finish()
    }
}

/// A secret signing key. Its secrets are zeroed when it is dropped.
#[derive(Clone)]
pub struct SigningKey {
    /// The clamped secret scalar a of RFC 8032 section 5.1.5, unreduced.
    scalar: [u8; 32],
    /// The second half of SHA-512(seed), which keys the deterministic nonce.
    prefix: [u8; 32],
    verifying_key: VerifyingKey,
}

impl SigningKey {
    /// Derives the key pair of `seed` as RFC 8032 section 5.1.5 specifies, identical to
    /// Zig's `Ed25519.KeyPair.generateDeterministic`. Never fails.
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> SigningKey {
        let mut digest = Sha512::digest(seed);
        let mut scalar: [u8; 32] = to_array(&digest[..32]);
        scalar[0] &= 248;
        scalar[31] = (scalar[31] & 127) | 64;
        let prefix = to_array(&digest[32..]);
        ct::zeroize(&mut digest);
        let point = Point::mul_base(&scalar);
        // A clamped scalar is a multiple of 8 in [2^254, 2^255) and not a multiple of L, so
        // the point has order L: never zero x, never small order.
        let verifying_key = VerifyingKey { bytes: point.encode(), point };
        SigningKey { scalar, prefix, verifying_key }
    }

    /// Returns the public half of the key pair.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }

    /// Signs `message` deterministically (RFC 8032 section 5.1.6). Never fails.
    pub fn sign(&self, message: &[u8]) -> Signature {
        let mut nonce_hash = Sha512::new();
        nonce_hash.update(&self.prefix);
        nonce_hash.update(message);
        let mut nonce_wide = nonce_hash.finalize();
        let nonce = Scalar::from_bytes_wide(&nonce_wide);
        ct::zeroize(&mut nonce_wide);
        let r = Point::mul_base(&nonce.to_bytes()).encode();
        let k = challenge(&r, &self.verifying_key.bytes, message);
        let a = Scalar::from_bytes_mod_order(&self.scalar);
        let s = Scalar::mul_add(&k, &a, &nonce).to_bytes();
        Signature { r, s }
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        ct::zeroize(&mut self.scalar);
        ct::zeroize(&mut self.prefix);
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("verifying_key", &self.verifying_key)
            .finish_non_exhaustive()
    }
}

/// The challenge k = SHA-512(R || A || M) mod L.
fn challenge(r: &[u8; 32], public_key: &[u8; 32], message: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(r);
    hasher.update(public_key);
    hasher.update(message);
    Scalar::from_bytes_wide(&hasher.finalize())
}

/// Copies a 32-byte slice into an array; callers pass halves of fixed-size arrays.
fn to_array(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    out
}

#[cfg(test)]
mod tests;

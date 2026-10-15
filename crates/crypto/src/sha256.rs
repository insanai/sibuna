//! SHA-256 (FIPS 180-4).
//!
//! The compression function has three implementations: the x86-64 SHA extensions
//! ([`x86`]), the ARMv8 SHA-2 instructions ([`aarch64`]) and portable Rust ([`portable`]).
//! With the `std` feature the hardware path is detected at run time, once, and the result is
//! cached; without it the choice follows the target features enabled at compile time.
//! Hashcash and the proof of sequential work are SHA-256 bound, so this is where hardware
//! acceleration pays (SID 0010).
//!
//! The hasher state is a plain value of about 110 bytes, so cloning a hasher that has
//! absorbed a common prefix is cheap. The PoSW prover does that once per tree node.

#[cfg(target_arch = "aarch64")]
mod aarch64;
mod portable;
#[cfg(target_arch = "x86_64")]
mod x86;

use crate::buffer::BlockBuffer;

/// Length of a SHA-256 digest in bytes.
pub const DIGEST_LEN: usize = 32;

/// Length of a SHA-256 input block in bytes.
pub const BLOCK_LEN: usize = 64;

/// The chaining value of the compression function: eight 32-bit words.
type State = [u32; 8];

/// A 64-byte input block.
type Block = [u8; BLOCK_LEN];

/// The initial hash value H(0) of FIPS 180-4, section 5.3.3.
const INITIAL_STATE: State = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// The round constants K of FIPS 180-4, section 4.2.2.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

/// An incremental SHA-256 hasher.
///
/// ```
/// use sibuna_crypto::sha256::Sha256;
/// let mut hasher = Sha256::new();
/// hasher.update(b"ab");
/// hasher.update(b"c");
/// assert_eq!(hasher.finalize(), Sha256::digest(b"abc"));
/// ```
#[derive(Clone)]
pub struct Sha256 {
    state: State,
    buffer: BlockBuffer<BLOCK_LEN>,
    /// Bytes absorbed so far. FIPS 180-4 limits messages to 2^64 bits; like Zig we count
    /// bytes and let the bit length wrap beyond that.
    length: u64,
}

impl Sha256 {
    /// A hasher that has absorbed nothing.
    pub const fn new() -> Self {
        Self { state: INITIAL_STATE, buffer: BlockBuffer::new(), length: 0 }
    }

    /// Absorbs `data`. Borrows it only for the call; never fails.
    pub fn update(&mut self, data: &[u8]) {
        self.update_with(data, compress);
    }

    /// Consumes the hasher and returns the 32-byte digest of everything absorbed.
    pub fn finalize(self) -> [u8; DIGEST_LEN] {
        self.finalize_with(compress)
    }

    /// Returns the SHA-256 digest of `data` in one call.
    pub fn digest(data: &[u8]) -> [u8; DIGEST_LEN] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    fn update_with(&mut self, data: &[u8], compress: impl Fn(&mut State, &[Block])) {
        self.length = self.length.wrapping_add(data.len() as u64);
        self.buffer.update(data, |blocks| compress(&mut self.state, blocks));
    }

    fn finalize_with(mut self, compress: impl Fn(&mut State, &[Block])) -> [u8; DIGEST_LEN] {
        let bits = self.length.wrapping_mul(8).to_be_bytes();
        self.buffer.finish(&bits, |blocks| compress(&mut self.state, blocks));
        let mut out = [0u8; DIGEST_LEN];
        for (bytes, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.state) {
            *bytes = word.to_be_bytes();
        }
        out
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

/// Names the compression function this process uses: `"x86-64 SHA-NI"`, `"ARMv8 SHA-2"`
/// or `"portable"`. Useful in start-up logs and benchmark reports.
pub fn implementation() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    if x86::ShaNi::detect().is_some() {
        return "x86-64 SHA-NI";
    }
    #[cfg(target_arch = "aarch64")]
    if aarch64::Sha2::detect().is_some() {
        return "ARMv8 SHA-2";
    }
    "portable"
}

/// Compresses `blocks` into `state` with the fastest implementation the CPU supports.
fn compress(state: &mut State, blocks: &[Block]) {
    #[cfg(target_arch = "x86_64")]
    if let Some(sha_ni) = x86::ShaNi::detect() {
        return sha_ni.compress(state, blocks);
    }
    #[cfg(target_arch = "aarch64")]
    if let Some(sha2) = aarch64::Sha2::detect() {
        return sha2.compress(state, blocks);
    }
    portable::compress(state, blocks);
}

/// Runs `detect` once and caches its answer in `cache` (0 unknown, 1 absent, 2 present).
///
/// `Relaxed` ordering suffices: the cached byte publishes no other memory, and a race
/// between two first callers is harmless because both compute and store the same answer.
#[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn cached_detection(cache: &core::sync::atomic::AtomicU8, detect: impl FnOnce() -> bool) -> bool {
    use core::sync::atomic::Ordering;
    const ABSENT: u8 = 1;
    const PRESENT: u8 = 2;
    match cache.load(Ordering::Relaxed) {
        PRESENT => true,
        ABSENT => false,
        _ => {
            let present = detect();
            cache.store(if present { PRESENT } else { ABSENT }, Ordering::Relaxed);
            present
        }
    }
}

#[cfg(test)]
mod tests;

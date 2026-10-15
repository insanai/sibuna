//! SHA-256 with the ARMv8 cryptographic extension (`sha256h`, `sha256h2`, `sha256su0`,
//! `sha256su1`).
//!
//! The state is two vectors, ABCD and EFGH; each `sha256h`/`sha256h2` pair performs four
//! rounds.
// SID 0010 allows SIMD intrinsics in measured modules of their own. Vector loads and stores
// through pointers and the call into the feature-gated function need `unsafe`.
#![allow(unsafe_code)]

use core::arch::aarch64::{
    uint32x4_t, vaddq_u32, vld1q_u8, vld1q_u32, vreinterpretq_u32_u8, vrev32q_u8, vsha256h2q_u32,
    vsha256hq_u32, vsha256su0q_u32, vsha256su1q_u32, vst1q_u32,
};

use super::{Block, K, State};

/// Proof that the running CPU has the ARMv8 SHA-2 instructions.
///
/// Only [`Sha2::detect`] creates one, so holding a `Sha2` makes [`Sha2::compress`] safe.
#[derive(Clone, Copy)]
pub(super) struct Sha2(());

impl Sha2 {
    /// Returns a `Sha2` when the CPU supports the instructions, `None` otherwise.
    ///
    /// With `std` the CPU is asked once and the answer is cached; without it the answer is
    /// whether the binary was compiled with the `sha2` target feature.
    pub(super) fn detect() -> Option<Sha2> {
        cpu_has_sha2().then_some(Sha2(()))
    }

    /// Compresses each block of `blocks` into `state` in order.
    pub(super) fn compress(self, state: &mut State, blocks: &[Block]) {
        // SAFETY: `self` exists only if `detect` found the neon and sha2 features.
        unsafe { compress_blocks(state, blocks) }
    }
}

#[cfg(feature = "std")]
fn cpu_has_sha2() -> bool {
    use core::sync::atomic::AtomicU8;
    static CACHE: AtomicU8 = AtomicU8::new(0);
    super::cached_detection(&CACHE, || {
        std::arch::is_aarch64_feature_detected!("neon")
            && std::arch::is_aarch64_feature_detected!("sha2")
    })
}

#[cfg(not(feature = "std"))]
fn cpu_has_sha2() -> bool {
    cfg!(all(target_feature = "neon", target_feature = "sha2"))
}

#[target_feature(enable = "neon,sha2")]
fn compress_blocks(state: &mut State, blocks: &[Block]) {
    let halves = state.as_chunks::<4>().0;
    let mut abcd = load_words(&halves[0]);
    let mut efgh = load_words(&halves[1]);
    let (first, rest) = K.as_chunks::<4>().0.split_at(4);
    for block in blocks {
        let (abcd_saved, efgh_saved) = (abcd, efgh);
        let message = load_message(block);
        for (w, k) in message.iter().zip(first) {
            (abcd, efgh) = four_rounds(abcd, efgh, *w, k);
        }
        // The four most recent quads of message words rotate through plain variables, so
        // they stay in registers.
        let [mut w0, mut w1, mut w2, mut w3] = message;
        for k in rest {
            let w4 = vsha256su1q_u32(vsha256su0q_u32(w0, w1), w2, w3);
            (abcd, efgh) = four_rounds(abcd, efgh, w4, k);
            (w0, w1, w2, w3) = (w1, w2, w3, w4);
        }
        abcd = vaddq_u32(abcd, abcd_saved);
        efgh = vaddq_u32(efgh, efgh_saved);
    }
    let halves = state.as_chunks_mut::<4>().0;
    // SAFETY: each half is 16 writable bytes; `vst1q_u32` needs only 4-byte alignment,
    // which `[u32; 4]` has.
    unsafe {
        vst1q_u32(halves[0].as_mut_ptr(), abcd);
        vst1q_u32(halves[1].as_mut_ptr(), efgh);
    }
}

/// Performs four rounds with message words `w` and round constants `k`.
#[target_feature(enable = "neon,sha2")]
fn four_rounds(
    abcd: uint32x4_t,
    efgh: uint32x4_t,
    w: uint32x4_t,
    k: &[u32; 4],
) -> (uint32x4_t, uint32x4_t) {
    let wk = vaddq_u32(w, load_words(k));
    let next_abcd = vsha256hq_u32(abcd, efgh, wk);
    let next_efgh = vsha256h2q_u32(efgh, abcd, wk);
    (next_abcd, next_efgh)
}

/// Loads a block as four quads of big-endian message words.
#[target_feature(enable = "neon")]
fn load_message(block: &Block) -> [uint32x4_t; 4] {
    let quads = block.as_chunks::<16>().0;
    core::array::from_fn(|i| {
        // SAFETY: `quads[i]` is 16 readable bytes; `vld1q_u8` has no alignment requirement.
        let raw = unsafe { vld1q_u8(quads[i].as_ptr()) };
        vreinterpretq_u32_u8(vrev32q_u8(raw))
    })
}

#[target_feature(enable = "neon")]
fn load_words(words: &[u32; 4]) -> uint32x4_t {
    // SAFETY: `words` is 16 readable bytes with the 4-byte alignment `vld1q_u32` needs.
    unsafe { vld1q_u32(words.as_ptr()) }
}

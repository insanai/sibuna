//! SHA-256 with the x86-64 SHA extensions (SHA-NI).
//!
//! The SHA extensions keep the state as two vectors, ABEF and CDGH, and perform two rounds
//! per `sha256rnds2` instruction. Message words are expanded four at a time with
//! `sha256msg1` and `sha256msg2`. The layout follows Intel's reference code ("Intel SHA
//! Extensions", 2013).
// SID 0010 allows SIMD intrinsics in measured modules of their own. Unaligned loads and
// stores of vectors and the call into the feature-gated function need `unsafe`.
#![allow(unsafe_code)]

use core::arch::x86_64::{
    __m128i, _mm_add_epi32, _mm_alignr_epi8, _mm_blend_epi16, _mm_loadu_si128, _mm_set_epi64x,
    _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32, _mm_shuffle_epi8,
    _mm_shuffle_epi32, _mm_storeu_si128,
};

use super::{Block, K, State};

/// Proof that the running CPU has the SHA, SSE2, SSSE3 and SSE4.1 instructions.
///
/// Only [`ShaNi::detect`] creates one, so holding a `ShaNi` makes [`ShaNi::compress`] safe.
#[derive(Clone, Copy)]
pub(super) struct ShaNi(());

impl ShaNi {
    /// Returns a `ShaNi` when the CPU supports the instructions, `None` otherwise.
    ///
    /// With `std` the CPU is asked once and the answer is cached; without it the answer is
    /// whether the binary was compiled with those target features enabled.
    pub(super) fn detect() -> Option<ShaNi> {
        cpu_has_sha_ni().then_some(ShaNi(()))
    }

    /// Compresses each block of `blocks` into `state` in order.
    pub(super) fn compress(self, state: &mut State, blocks: &[Block]) {
        // SAFETY: `self` exists only if `detect` found sha, sse2, ssse3 and sse4.1.
        unsafe { compress_blocks(state, blocks) }
    }
}

#[cfg(feature = "std")]
fn cpu_has_sha_ni() -> bool {
    use core::sync::atomic::AtomicU8;
    static CACHE: AtomicU8 = AtomicU8::new(0);
    super::cached_detection(&CACHE, || {
        std::arch::is_x86_feature_detected!("sha")
            && std::arch::is_x86_feature_detected!("sse2")
            && std::arch::is_x86_feature_detected!("ssse3")
            && std::arch::is_x86_feature_detected!("sse4.1")
    })
}

#[cfg(not(feature = "std"))]
fn cpu_has_sha_ni() -> bool {
    cfg!(all(
        target_feature = "sha",
        target_feature = "sse2",
        target_feature = "ssse3",
        target_feature = "sse4.1"
    ))
}

#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
fn compress_blocks(state: &mut State, blocks: &[Block]) {
    let (mut abef, mut cdgh) = load_state(state);
    let (first, rest) = K.as_chunks::<4>().0.split_at(4);
    for block in blocks {
        let (abef_saved, cdgh_saved) = (abef, cdgh);
        let message = load_message(block);
        for (w, k) in message.iter().zip(first) {
            (abef, cdgh) = four_rounds(abef, cdgh, *w, k);
        }
        // The four most recent quads of message words rotate through plain variables, so
        // they stay in registers.
        let [mut w0, mut w1, mut w2, mut w3] = message;
        for k in rest {
            let w4 = expand(w0, w1, w2, w3);
            (abef, cdgh) = four_rounds(abef, cdgh, w4, k);
            (w0, w1, w2, w3) = (w1, w2, w3, w4);
        }
        abef = _mm_add_epi32(abef, abef_saved);
        cdgh = _mm_add_epi32(cdgh, cdgh_saved);
    }
    store_state(state, abef, cdgh);
}

/// Performs four rounds with message words `w` and round constants `k`.
#[target_feature(enable = "sha,sse2")]
fn four_rounds(abef: __m128i, cdgh: __m128i, w: __m128i, k: &[u32; 4]) -> (__m128i, __m128i) {
    let wk = _mm_add_epi32(w, load_words(k));
    let cdgh = _mm_sha256rnds2_epu32(cdgh, abef, wk);
    let abef = _mm_sha256rnds2_epu32(abef, cdgh, _mm_shuffle_epi32(wk, 0x0e));
    (abef, cdgh)
}

/// Computes message words W(t)..W(t+3) from the four previous quads.
#[target_feature(enable = "sha,sse2,ssse3")]
fn expand(w0: __m128i, w1: __m128i, w2: __m128i, w3: __m128i) -> __m128i {
    let partial = _mm_sha256msg1_epu32(w0, w1);
    let w7 = _mm_alignr_epi8(w3, w2, 4);
    _mm_sha256msg2_epu32(_mm_add_epi32(partial, w7), w3)
}

/// Loads a block as four quads of big-endian message words.
#[target_feature(enable = "sse2,ssse3")]
fn load_message(block: &Block) -> [__m128i; 4] {
    let byte_swap = _mm_set_epi64x(0x0c0d_0e0f_0809_0a0b, 0x0405_0607_0001_0203);
    let quads = block.as_chunks::<16>().0;
    core::array::from_fn(|i| {
        // SAFETY: `quads[i]` is 16 readable bytes; `loadu` has no alignment requirement.
        let raw = unsafe { _mm_loadu_si128(quads[i].as_ptr().cast()) };
        _mm_shuffle_epi8(raw, byte_swap)
    })
}

#[target_feature(enable = "sse2")]
fn load_words(words: &[u32; 4]) -> __m128i {
    // SAFETY: `words` is 16 readable bytes; `loadu` has no alignment requirement.
    unsafe { _mm_loadu_si128(words.as_ptr().cast()) }
}

/// Rearranges the state words A..H into the ABEF and CDGH vectors.
#[target_feature(enable = "sse2,ssse3,sse4.1")]
fn load_state(state: &State) -> (__m128i, __m128i) {
    let halves = state.as_chunks::<4>().0;
    let dcba = load_words(&halves[0]);
    let hgfe = load_words(&halves[1]);
    let cdab = _mm_shuffle_epi32(dcba, 0xb1);
    let efgh = _mm_shuffle_epi32(hgfe, 0x1b);
    let abef = _mm_alignr_epi8(cdab, efgh, 8);
    let cdgh = _mm_blend_epi16(efgh, cdab, 0xf0);
    (abef, cdgh)
}

/// The inverse of [`load_state`].
#[target_feature(enable = "sse2,ssse3,sse4.1")]
fn store_state(state: &mut State, abef: __m128i, cdgh: __m128i) {
    let feba = _mm_shuffle_epi32(abef, 0x1b);
    let dchg = _mm_shuffle_epi32(cdgh, 0xb1);
    let dcba = _mm_blend_epi16(feba, dchg, 0xf0);
    let hgef = _mm_alignr_epi8(dchg, feba, 8);
    let halves = state.as_chunks_mut::<4>().0;
    // SAFETY: each half is 16 writable bytes; `storeu` has no alignment requirement.
    unsafe {
        _mm_storeu_si128(halves[0].as_mut_ptr().cast(), dcba);
        _mm_storeu_si128(halves[1].as_mut_ptr().cast(), hgef);
    }
}

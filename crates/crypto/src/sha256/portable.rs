//! The portable SHA-256 compression function (FIPS 180-4, section 6.2.2).
//!
//! The 64 rounds are unrolled. The message schedule lives in a 16-word window, and each
//! round from 16 on overwrites the word it no longer needs. The eight working variables are
//! renamed from round to round instead of being shifted. These choices keep every value in
//! a register (or a WebAssembly local) as straight-line code. That matters most in
//! WebAssembly, where the browser solver spends nearly all its time here: this layout runs
//! about 20% faster in V8 than a 64-word schedule with a rolled loop, and about 14% faster
//! natively.

use super::{Block, K, State};

/// Compresses each block of `blocks` into `state` in order.
pub(super) fn compress(state: &mut State, blocks: &[Block]) {
    for block in blocks {
        compress_block(state, block);
    }
}

/// One round of FIPS 180-4, section 6.2.2, steps 2 and 3, with the variables renamed.
///
/// The caller passes the working variables rotated by one position per round, so the
/// round writes only `$d` and `$h` and never moves the other six. `$i` must be a literal
/// so that every schedule index is a constant.
macro_rules! round {
    ($w:ident, $i:expr, $a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident,
     $g:ident, $h:ident) => {
        $h = $h
            .wrapping_add($e.rotate_right(6) ^ $e.rotate_right(11) ^ $e.rotate_right(25))
            .wrapping_add($g ^ ($e & ($f ^ $g)))
            .wrapping_add(K[$i])
            .wrapping_add(schedule(&mut $w, $i));
        $d = $d.wrapping_add($h);
        $h = $h
            .wrapping_add($a.rotate_right(2) ^ $a.rotate_right(13) ^ $a.rotate_right(22))
            .wrapping_add(($a & ($b | $c)) | ($b & $c));
    };
}

/// Eight rounds starting at round `$i`: one full turn of the variable names.
macro_rules! eight_rounds {
    ($w:ident, $i:expr, $a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident,
     $g:ident, $h:ident) => {
        round!($w, $i, $a, $b, $c, $d, $e, $f, $g, $h);
        round!($w, $i + 1, $h, $a, $b, $c, $d, $e, $f, $g);
        round!($w, $i + 2, $g, $h, $a, $b, $c, $d, $e, $f);
        round!($w, $i + 3, $f, $g, $h, $a, $b, $c, $d, $e);
        round!($w, $i + 4, $e, $f, $g, $h, $a, $b, $c, $d);
        round!($w, $i + 5, $d, $e, $f, $g, $h, $a, $b, $c);
        round!($w, $i + 6, $c, $d, $e, $f, $g, $h, $a, $b);
        round!($w, $i + 7, $b, $c, $d, $e, $f, $g, $h, $a);
    };
}

fn compress_block(state: &mut State, block: &Block) {
    let mut w = [0u32; 16];
    for (word, bytes) in w.iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_be_bytes(*bytes);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    eight_rounds!(w, 0, a, b, c, d, e, f, g, h);
    eight_rounds!(w, 8, a, b, c, d, e, f, g, h);
    eight_rounds!(w, 16, a, b, c, d, e, f, g, h);
    eight_rounds!(w, 24, a, b, c, d, e, f, g, h);
    eight_rounds!(w, 32, a, b, c, d, e, f, g, h);
    eight_rounds!(w, 40, a, b, c, d, e, f, g, h);
    eight_rounds!(w, 48, a, b, c, d, e, f, g, h);
    eight_rounds!(w, 56, a, b, c, d, e, f, g, h);
    for (word, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *word = word.wrapping_add(value);
    }
}

/// Returns the schedule word W(i), computing it in place for rounds 16 and later.
///
/// Position `i % 16` of the window holds W(i-16) on entry. W(i) also needs W(i-15),
/// W(i-7) and W(i-2), which sit at positions `i+1`, `i+9` and `i+14` modulo 16 and
/// have not been overwritten yet. Inlined with a constant `i`, this is straight-line code.
#[inline(always)]
fn schedule(w: &mut [u32; 16], i: usize) -> u32 {
    if i >= 16 {
        // In bounds: every index is reduced modulo 16, the window length.
        let w15 = w[(i + 1) % 16];
        let w2 = w[(i + 14) % 16];
        let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
        let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
        w[i % 16] = w[i % 16].wrapping_add(s0).wrapping_add(w[(i + 9) % 16]).wrapping_add(s1);
    }
    w[i % 16]
}

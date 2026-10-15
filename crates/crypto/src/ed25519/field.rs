//! Arithmetic modulo p = 2^255 - 19.
//!
//! An element is five 51-bit limbs, the representation Zig's `std.crypto` uses; the
//! formulas, and so the bounds on intermediate limbs, follow Zig's `field.zig`. Limbs may
//! exceed 51 bits between operations; [`Fe::reduced`] produces the canonical value. Every
//! operation except decoding checks runs in time independent of the values.
//!
//! The operations needed to build the base point tables are `const fn`, so the tables are
//! computed at compile time. The small arithmetic functions are `#[inline(always)]`: inlining
//! them into the point formulas made signing about 25% faster in our measurements.

const MASK51: u64 = (1 << 51) - 1;

/// A field element modulo 2^255 - 19.
#[derive(Clone, Copy, Debug)]
pub(super) struct Fe(pub(super) [u64; 5]);

impl Fe {
    pub(super) const ZERO: Fe = Fe([0, 0, 0, 0, 0]);
    pub(super) const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// A square root of -1.
    pub(super) const SQRT_M1: Fe = Fe([
        1718705420411056,
        234908883556509,
        2233514472574048,
        2117202627021982,
        765476049583133,
    ]);

    /// The curve constant d = -121665/121666.
    pub(super) const D: Fe = Fe([
        929955233495203,
        466365720129213,
        1662059464998953,
        2033849074728123,
        1442794654840575,
    ]);

    /// 2d.
    pub(super) const D2: Fe = Fe([
        1859910466990425,
        932731440258426,
        1072319116312658,
        1815898335770999,
        633789495995903,
    ]);

    /// Unpacks 32 little-endian bytes, ignoring the top bit. Values from p to 2^255 - 1 are
    /// accepted and behave as their residue; callers that need canonical input check
    /// [`is_canonical`] first.
    pub(super) fn from_bytes(s: &[u8; 32]) -> Fe {
        let mut w = [0u64; 4];
        for (word, bytes) in w.iter_mut().zip(s.as_chunks::<8>().0) {
            *word = u64::from_le_bytes(*bytes);
        }
        Fe([
            w[0] & MASK51,
            ((w[0] >> 51) | (w[1] << 13)) & MASK51,
            ((w[1] >> 38) | (w[2] << 26)) & MASK51,
            ((w[2] >> 25) | (w[3] << 39)) & MASK51,
            (w[3] >> 12) & MASK51,
        ])
    }

    /// Packs the canonical value into 32 little-endian bytes; the top bit is zero.
    pub(super) fn to_bytes(self) -> [u8; 32] {
        let [l0, l1, l2, l3, l4] = self.reduced().0;
        let mut s = [0u8; 32];
        s[0..8].copy_from_slice(&(l0 | (l1 << 51)).to_le_bytes());
        s[8..16].copy_from_slice(&((l1 >> 13) | (l2 << 38)).to_le_bytes());
        s[16..24].copy_from_slice(&((l2 >> 26) | (l3 << 25)).to_le_bytes());
        s[24..32].copy_from_slice(&((l3 >> 39) | (l4 << 12)).to_le_bytes());
        s
    }

    /// Returns the canonical representative, every limb below 2^51 and the value below p.
    fn reduced(self) -> Fe {
        let mut l = self.0;
        for _ in 0..2 {
            carry_chain(&mut l);
        }
        // Add 19 and carry: the carry out of bit 255 is set exactly when the value is at
        // least p. Then subtract 19 again by adding 2^255 - 19 and dropping bit 255.
        l[0] += 19;
        carry_chain(&mut l);
        l[0] += (1 << 51) - 19;
        l[1] += (1 << 51) - 1;
        l[2] += (1 << 51) - 1;
        l[3] += (1 << 51) - 1;
        l[4] += (1 << 51) - 1;
        for i in 0..4 {
            l[i + 1] += l[i] >> 51;
            l[i] &= MASK51;
        }
        l[4] &= MASK51;
        Fe(l)
    }

    pub(super) fn is_zero(self) -> bool {
        self.reduced().0.iter().fold(0, |acc, limb| acc | limb) == 0
    }

    /// The sign of the element: the low bit of its canonical encoding.
    pub(super) fn is_negative(self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    #[inline(always)]
    pub(super) const fn add(self, b: Fe) -> Fe {
        let a = self.0;
        let b = b.0;
        Fe([a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3], a[4] + b[4]])
    }

    /// `self - b`, computed as `self + 2p - b` after a weak reduction of `b`.
    #[inline(always)]
    pub(super) const fn sub(self, b: Fe) -> Fe {
        let mut b = b.0;
        let mut i = 0;
        while i < 4 {
            b[i + 1] += b[i] >> 51;
            b[i] &= MASK51;
            i += 1;
        }
        b[0] += 19 * (b[4] >> 51);
        b[4] &= MASK51;
        let a = self.0;
        Fe([
            (a[0] + 0xfffffffffffda) - b[0],
            (a[1] + 0xffffffffffffe) - b[1],
            (a[2] + 0xffffffffffffe) - b[2],
            (a[3] + 0xffffffffffffe) - b[3],
            (a[4] + 0xffffffffffffe) - b[4],
        ])
    }

    #[inline(always)]
    pub(super) const fn neg(self) -> Fe {
        Fe::ZERO.sub(self)
    }

    #[inline(always)]
    pub(super) const fn mul(self, b: Fe) -> Fe {
        let a = self.0;
        let b = b.0;
        // The multiples by 19 fit in 64 bits (limbs stay below 2^56), so every product
        // below is a single 64 x 64 -> 128-bit multiplication.
        let a19 = [0, 19 * a[1], 19 * a[2], 19 * a[3], 19 * a[4]];
        let r = [
            m(a[0], b[0]) + m(a19[1], b[4]) + m(a19[2], b[3]) + m(a19[3], b[2]) + m(a19[4], b[1]),
            m(a[0], b[1]) + m(a[1], b[0]) + m(a19[2], b[4]) + m(a19[3], b[3]) + m(a19[4], b[2]),
            m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a19[3], b[4]) + m(a19[4], b[3]),
            m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a19[4], b[4]),
            m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]),
        ];
        carry_wide(r)
    }

    #[inline(always)]
    pub(super) const fn square(self) -> Fe {
        carry_wide(square_wide(self))
    }

    /// `2 * self^2`.
    #[inline(always)]
    pub(super) const fn square2(self) -> Fe {
        let r = square_wide(self);
        carry_wide([2 * r[0], 2 * r[1], 2 * r[2], 2 * r[3], 2 * r[4]])
    }

    fn square_n(self, n: usize) -> Fe {
        let mut x = self;
        for _ in 0..n {
            x = x.square();
        }
        x
    }

    /// Returns `self^(p-2)`, the inverse of a non-zero element, or zero for zero.
    pub(super) fn invert(self) -> Fe {
        let a = self;
        let mut t0 = a.square();
        let mut t1 = t0.square_n(2).mul(a);
        t0 = t0.mul(t1);
        t1 = t1.mul(t0.square());
        t1 = t1.mul(t1.square_n(5));
        let mut t2 = t1.square_n(10).mul(t1);
        t2 = t2.mul(t2.square_n(20)).square_n(10);
        t1 = t1.mul(t2);
        t2 = t1.square_n(50).mul(t1);
        t1.mul(t2.mul(t2.square_n(100)).square_n(50)).square_n(5).mul(t0)
    }

    /// Returns `self^((p-5)/8) = self^(2^252-3)`, the core of a square root (p = 5 mod 8).
    pub(super) fn pow2523(self) -> Fe {
        let a = self;
        let mut t0 = a.mul(a.square());
        let mut t1 = t0.mul(t0.square_n(2)).square().mul(a);
        t0 = t1.square_n(5).mul(t1);
        let mut t2 = t0.square_n(5).mul(t1);
        t1 = t2.square_n(15).mul(t2);
        t2 = t1.square_n(30).mul(t1);
        t1 = t2.square_n(60).mul(t2);
        t1.square_n(120).mul(t1).square_n(10).mul(t0).square_n(2).mul(a)
    }

    /// Replaces `self` with `other` when `choice` is 1 and keeps it when `choice` is 0,
    /// without a branch.
    pub(super) fn conditional_assign(&mut self, other: Fe, choice: u64) {
        let mask = 0u64.wrapping_sub(choice);
        for (limb, new) in self.0.iter_mut().zip(other.0) {
            *limb ^= (*limb ^ new) & mask;
        }
    }
}

/// Whether the low 255 bits of `s` encode a value below p. The top (sign) bit is ignored,
/// as in Zig's `Fe.rejectNonCanonical(s, true)`.
pub(super) fn is_canonical(s: &[u8; 32]) -> bool {
    let top_all_ones = s[31] & 0x7f == 0x7f && s[1..31].iter().all(|&b| b == 0xff);
    !(top_all_ones && s[0] >= 0xed)
}

/// One pass of carries through the limbs, folding the carry out of limb 4 back as 19.
fn carry_chain(l: &mut [u64; 5]) {
    for i in 0..4 {
        l[i + 1] += l[i] >> 51;
        l[i] &= MASK51;
    }
    l[0] += 19 * (l[4] >> 51);
    l[4] &= MASK51;
}

/// The full 128-bit product of two limbs.
#[inline(always)]
const fn m(x: u64, y: u64) -> u128 {
    x as u128 * y as u128
}

#[inline(always)]
const fn square_wide(a: Fe) -> [u128; 5] {
    let a = a.0;
    let a0_2 = 2 * a[0];
    let a1_2 = 2 * a[1];
    let a1_38 = 38 * a[1];
    let a2_38 = 38 * a[2];
    let a3_38 = 38 * a[3];
    let a3_19 = 19 * a[3];
    let a4_19 = 19 * a[4];
    [
        m(a[0], a[0]) + m(a1_38, a[4]) + m(a2_38, a[3]),
        m(a0_2, a[1]) + m(a2_38, a[4]) + m(a3_19, a[3]),
        m(a0_2, a[2]) + m(a[1], a[1]) + m(a3_38, a[4]),
        m(a0_2, a[3]) + m(a1_2, a[2]) + m(a4_19, a[4]),
        m(a0_2, a[4]) + m(a1_2, a[3]) + m(a[2], a[2]),
    ]
}

/// Carries 128-bit column sums down to limbs of about 51 bits.
#[inline(always)]
const fn carry_wide(mut r: [u128; 5]) -> Fe {
    let mut out = [0u64; 5];
    let mut i = 0;
    while i < 4 {
        out[i] = (r[i] as u64) & MASK51;
        r[i + 1] += r[i] >> 51;
        i += 1;
    }
    out[4] = (r[4] as u64) & MASK51;
    out[0] += 19 * ((r[4] >> 51) as u64);
    let carry = out[0] >> 51;
    out[0] &= MASK51;
    out[1] += carry;
    let carry = out[1] >> 51;
    out[1] &= MASK51;
    out[2] += carry;
    Fe(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const P_BYTES: [u8; 32] = {
        let mut p = [0xff; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        p
    };

    fn small(n: u64) -> Fe {
        Fe([n, 0, 0, 0, 0])
    }

    #[test]
    fn encoding_round_trips_and_reduces() {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i * 37 + 11) as u8;
        }
        bytes[31] &= 0x7f;
        assert_eq!(Fe::from_bytes(&bytes).to_bytes(), bytes);
        // p encodes zero, p + 1 encodes one.
        assert!(Fe::from_bytes(&P_BYTES).is_zero());
        let mut p_plus_one = P_BYTES;
        p_plus_one[0] += 1;
        assert_eq!(Fe::from_bytes(&p_plus_one).to_bytes(), Fe::ONE.to_bytes());
    }

    #[test]
    fn canonical_check_matches_zig() {
        assert!(!is_canonical(&P_BYTES));
        let mut p_minus_one = P_BYTES;
        p_minus_one[0] -= 1;
        assert!(is_canonical(&p_minus_one));
        let mut with_sign = p_minus_one;
        with_sign[31] |= 0x80;
        assert!(is_canonical(&with_sign), "the sign bit is ignored");
        assert!(!is_canonical(&[0xff; 32]));
    }

    #[test]
    fn arithmetic_identities() {
        let a = Fe::from_bytes(&[0x5a; 32]);
        let b = Fe::from_bytes(&[0xc3; 32]);
        assert!(a.sub(a).is_zero());
        assert!(a.add(a.neg()).is_zero());
        assert_eq!(a.mul(b).to_bytes(), b.mul(a).to_bytes());
        assert_eq!(a.square().to_bytes(), a.mul(a).to_bytes());
        assert_eq!(a.square2().to_bytes(), a.square().add(a.square()).to_bytes());
        assert_eq!(a.mul(a.invert()).to_bytes(), Fe::ONE.to_bytes());
        assert!(Fe::ZERO.invert().is_zero());
        assert_eq!(Fe::SQRT_M1.square().to_bytes(), Fe::ONE.neg().to_bytes());
        assert_eq!(Fe::D.add(Fe::D).to_bytes(), Fe::D2.to_bytes());
        // d * 121666 = -121665.
        assert_eq!(Fe::D.mul(small(121666)).to_bytes(), small(121665).neg().to_bytes());
    }

    #[test]
    fn conditional_assign_selects() {
        let mut x = small(3);
        x.conditional_assign(small(9), 0);
        assert_eq!(x.to_bytes(), small(3).to_bytes());
        x.conditional_assign(small(9), 1);
        assert_eq!(x.to_bytes(), small(9).to_bytes());
        assert!(small(1).is_negative());
        assert!(!small(2).is_negative());
    }
}

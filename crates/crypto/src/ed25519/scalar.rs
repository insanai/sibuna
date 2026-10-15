//! Arithmetic modulo the group order L = 2^252 + 27742317777372353535851937790883648493.
//!
//! A scalar is five 52-bit limbs and products are reduced with Montgomery multiplication
//! (R = 2^260), the method of curve25519-dalek. All operations run in time independent of
//! the values, because signing multiplies secret scalars.

const MASK52: u64 = (1 << 52) - 1;

/// L in 52-bit limbs.
const L: [u64; 5] =
    [0x0002631a5cf5d3ed, 0x000dea2f79cd6581, 0x000000000014def9, 0, 0x0000100000000000];

/// -L^-1 mod 2^52.
const L_FACTOR: u64 = 0x51da312547e1b;

/// R = 2^260 mod L.
const R: Scalar = Scalar([
    0x000f48bd6721e6ed,
    0x0003bab5ac67e45a,
    0x000fffffeb35e51b,
    0x000fffffffffffff,
    0x00000fffffffffff,
]);

/// R^2 = 2^520 mod L.
const RR: Scalar = Scalar([
    0x0009d265e952d13b,
    0x000d63c715bea69f,
    0x0005be65cb687604,
    0x0003dceec73d217f,
    0x000009411b7c309a,
]);

/// L as 32 little-endian bytes.
const L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
    0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// An integer modulo L, fully reduced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Scalar([u64; 5]);

impl Scalar {
    /// Reduces a 512-bit little-endian integer modulo L.
    pub(super) fn from_bytes_wide(bytes: &[u8; 64]) -> Scalar {
        let w: [u64; 8] = words(bytes);
        let low = Scalar([
            w[0] & MASK52,
            ((w[0] >> 52) | (w[1] << 12)) & MASK52,
            ((w[1] >> 40) | (w[2] << 24)) & MASK52,
            ((w[2] >> 28) | (w[3] << 36)) & MASK52,
            ((w[3] >> 16) | (w[4] << 48)) & MASK52,
        ]);
        let high = Scalar([
            (w[4] >> 4) & MASK52,
            ((w[4] >> 56) | (w[5] << 8)) & MASK52,
            ((w[5] >> 44) | (w[6] << 20)) & MASK52,
            ((w[6] >> 32) | (w[7] << 32)) & MASK52,
            w[7] >> 20,
        ]);
        // low + high * 2^260 = low * R / R + high * R^2 / R.
        montgomery_mul(&low, &R).add(&montgomery_mul(&high, &RR))
    }

    /// Reduces a 256-bit little-endian integer modulo L.
    pub(super) fn from_bytes_mod_order(bytes: &[u8; 32]) -> Scalar {
        let w: [u64; 4] = words(bytes);
        let value = Scalar([
            w[0] & MASK52,
            ((w[0] >> 52) | (w[1] << 12)) & MASK52,
            ((w[1] >> 40) | (w[2] << 24)) & MASK52,
            ((w[2] >> 28) | (w[3] << 36)) & MASK52,
            w[3] >> 16,
        ]);
        montgomery_mul(&value, &R)
    }

    /// Whether the 256-bit little-endian integer `bytes` is below L. Runs in variable time;
    /// it checks the public S of a signature.
    pub(super) fn is_canonical(bytes: &[u8; 32]) -> bool {
        for (byte, l) in bytes.iter().zip(&L_BYTES).rev() {
            if byte != l {
                return byte < l;
            }
        }
        false
    }

    /// Returns 32 little-endian bytes.
    pub(super) fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut accumulator: u128 = 0;
        let mut bits = 0;
        let mut position = 0;
        for limb in self.0 {
            accumulator |= u128::from(limb) << bits;
            bits += 52;
            while bits >= 8 {
                out[position] = accumulator as u8;
                accumulator >>= 8;
                bits -= 8;
                position += 1;
            }
        }
        // 260 bits fill 32 bytes with 4 to spare; the spare bits are zero because the
        // value is below L < 2^253.
        out
    }

    /// Returns `a * b + c mod L`.
    pub(super) fn mul_add(a: &Scalar, b: &Scalar, c: &Scalar) -> Scalar {
        // The first product carries a factor R^-1, which the multiplication by R^2 cancels.
        let product = montgomery_mul(&montgomery_mul(a, b), &RR);
        product.add(c)
    }

    /// Returns `self + b mod L` for reduced inputs.
    fn add(&self, b: &Scalar) -> Scalar {
        let mut sum = [0u64; 5];
        let mut carry = 0u64;
        for (out, (x, y)) in sum.iter_mut().zip(self.0.iter().zip(&b.0)) {
            carry = x + y + (carry >> 52);
            *out = carry & MASK52;
        }
        Scalar(sum).sub(&Scalar(L))
    }

    /// Returns `self - b mod L` for inputs below L (and `self` below 2L when `b` is L).
    fn sub(&self, b: &Scalar) -> Scalar {
        let mut difference = [0u64; 5];
        let mut borrow = 0u64;
        for (out, (x, y)) in difference.iter_mut().zip(self.0.iter().zip(&b.0)) {
            borrow = x.wrapping_sub(y + (borrow >> 63));
            *out = borrow & MASK52;
        }
        // Add L back when the subtraction went below zero, without a branch.
        let underflow_mask = ((borrow >> 63) ^ 1).wrapping_sub(1);
        let mut carry = 0u64;
        for (out, l) in difference.iter_mut().zip(L) {
            carry = (carry >> 52) + *out + (l & underflow_mask);
            *out = carry & MASK52;
        }
        Scalar(difference)
    }
}

/// Reads `N` little-endian 64-bit words; callers pass exactly `8 * N` bytes.
fn words<const N: usize>(bytes: &[u8]) -> [u64; N] {
    let mut out = [0u64; N];
    for (word, chunk) in out.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*chunk);
    }
    out
}

fn wide_mul(a: u64, b: u64) -> u128 {
    u128::from(a) * u128::from(b)
}

/// Returns `a * b / R mod L`. Requires `a * b < R * L`, which holds when one factor is
/// below L and the other below R = 2^260.
fn montgomery_mul(a: &Scalar, b: &Scalar) -> Scalar {
    let mut product = [0u128; 9];
    for (i, x) in a.0.iter().enumerate() {
        for (j, y) in b.0.iter().enumerate() {
            product[i + j] += wide_mul(*x, *y);
        }
    }
    montgomery_reduce(&product)
}

/// Returns `limbs / R mod L` for a 9-limb value below `R * L`.
fn montgomery_reduce(limbs: &[u128; 9]) -> Scalar {
    // Choose n_i so that adding n_i * L clears limb i; L[3] is zero, so its terms vanish.
    fn clear_low(sum: u128) -> (u128, u64) {
        let n = (sum as u64).wrapping_mul(L_FACTOR) & MASK52;
        ((sum + wide_mul(n, L[0])) >> 52, n)
    }
    fn split(sum: u128) -> (u128, u64) {
        (sum >> 52, (sum as u64) & MASK52)
    }
    let (carry, n0) = clear_low(limbs[0]);
    let (carry, n1) = clear_low(carry + limbs[1] + wide_mul(n0, L[1]));
    let (carry, n2) = clear_low(carry + limbs[2] + wide_mul(n0, L[2]) + wide_mul(n1, L[1]));
    let (carry, n3) = clear_low(carry + limbs[3] + wide_mul(n1, L[2]) + wide_mul(n2, L[1]));
    let (carry, n4) =
        clear_low(carry + limbs[4] + wide_mul(n0, L[4]) + wide_mul(n2, L[2]) + wide_mul(n3, L[1]));
    let (carry, r0) =
        split(carry + limbs[5] + wide_mul(n1, L[4]) + wide_mul(n3, L[2]) + wide_mul(n4, L[1]));
    let (carry, r1) = split(carry + limbs[6] + wide_mul(n2, L[4]) + wide_mul(n4, L[2]));
    let (carry, r2) = split(carry + limbs[7] + wide_mul(n3, L[4]));
    let (carry, r3) = split(carry + limbs[8] + wide_mul(n4, L[4]));
    let r4 = carry as u64;
    // The result is below 2L; one conditional subtraction reduces it.
    Scalar([r0, r1, r2, r3, r4]).sub(&Scalar(L))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha512::Sha512;

    /// Reference reduction: shift in one bit at a time, subtracting L whenever the running
    /// value reaches it. Slow and obviously correct.
    fn reference_reduce(bytes: &[u8]) -> [u8; 32] {
        let l = u256_from_le(&L_BYTES);
        let mut r = [0u64; 4];
        for bit in (0..bytes.len() * 8).rev() {
            let incoming = u64::from((bytes[bit / 8] >> (bit % 8)) & 1);
            let mut carry = incoming;
            for limb in &mut r {
                let next = *limb >> 63;
                *limb = (*limb << 1) | carry;
                carry = next;
            }
            if !less_than(&r, &l) {
                subtract(&mut r, &l);
            }
        }
        let mut out = [0u8; 32];
        for (chunk, limb) in out.chunks_mut(8).zip(r) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        out
    }

    fn u256_from_le(bytes: &[u8; 32]) -> [u64; 4] {
        words(bytes)
    }

    fn less_than(a: &[u64; 4], b: &[u64; 4]) -> bool {
        for i in (0..4).rev() {
            if a[i] != b[i] {
                return a[i] < b[i];
            }
        }
        false
    }

    fn subtract(a: &mut [u64; 4], b: &[u64; 4]) {
        let mut borrow = false;
        for i in 0..4 {
            let (d1, b1) = a[i].overflowing_sub(b[i]);
            let (d2, b2) = d1.overflowing_sub(u64::from(borrow));
            a[i] = d2;
            borrow = b1 || b2;
        }
    }

    /// 512-bit product of two 256-bit values, little-endian.
    fn multiply(a: &[u8; 32], b: &[u8; 32]) -> [u8; 64] {
        let mut out = [0u8; 64];
        for i in 0..32 {
            let mut carry = 0u32;
            for j in 0..32 {
                let t = u32::from(out[i + j]) + u32::from(a[i]) * u32::from(b[j]) + carry;
                out[i + j] = t as u8;
                carry = t >> 8;
            }
            out[i + 32] = carry as u8;
        }
        out
    }

    fn sample(i: u32) -> [u8; 64] {
        Sha512::digest(&i.to_le_bytes())
    }

    #[test]
    fn wide_reduction_matches_reference() {
        let mut inputs = std::vec![[0u8; 64], [0xff; 64]];
        inputs.extend((0..200).map(sample));
        let mut l_wide = [0u8; 64];
        l_wide[..32].copy_from_slice(&L_BYTES);
        inputs.push(l_wide);
        for input in inputs {
            assert_eq!(Scalar::from_bytes_wide(&input).to_bytes(), reference_reduce(&input));
        }
    }

    #[test]
    fn narrow_reduction_matches_reference() {
        for i in 0..200 {
            let input: [u8; 32] = *sample(i).first_chunk().unwrap();
            let reduced = Scalar::from_bytes_mod_order(&input).to_bytes();
            assert_eq!(reduced, reference_reduce(&input));
            assert!(Scalar::is_canonical(&reduced));
        }
        assert_eq!(Scalar::from_bytes_mod_order(&L_BYTES).to_bytes(), [0; 32]);
        assert_eq!(
            Scalar::from_bytes_mod_order(&[0xff; 32]).to_bytes(),
            reference_reduce(&[0xff; 32])
        );
    }

    #[test]
    fn mul_add_matches_reference() {
        for i in 0..100 {
            let a = Scalar::from_bytes_wide(&sample(3 * i));
            let b = Scalar::from_bytes_wide(&sample(3 * i + 1));
            let c = Scalar::from_bytes_wide(&sample(3 * i + 2));
            let mut expected = multiply(&a.to_bytes(), &b.to_bytes());
            // Add c to the 512-bit product before reducing.
            let mut carry = 0u16;
            let c_bytes = c.to_bytes();
            for (k, byte) in expected.iter_mut().enumerate() {
                let t = u16::from(*byte) + u16::from(*c_bytes.get(k).unwrap_or(&0)) + carry;
                *byte = t as u8;
                carry = t >> 8;
            }
            assert_eq!(Scalar::mul_add(&a, &b, &c).to_bytes(), reference_reduce(&expected));
        }
    }

    #[test]
    fn canonical_check_is_exact() {
        let mut below = L_BYTES;
        below[0] -= 1;
        assert!(Scalar::is_canonical(&below));
        assert!(!Scalar::is_canonical(&L_BYTES));
        let mut above = L_BYTES;
        above[0] += 1;
        assert!(!Scalar::is_canonical(&above));
        assert!(Scalar::is_canonical(&[0; 32]));
        assert_eq!(u256_from_le(&L_BYTES)[3], 0x1000000000000000);
    }
}

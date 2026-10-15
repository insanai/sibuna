//! The twisted Edwards curve -x^2 + y^2 = 1 + d x^2 y^2 over GF(2^255 - 19).
//!
//! Points are in extended coordinates (X : Y : Z : T) with x = X/Z, y = Y/Z and xy = T/Z.
//! The addition and doubling formulas and the point decoding are those of Zig's
//! `edwards25519.zig`. Table entries are kept in the "cached" form (Y+X, Y-X, 2dT, 2Z) of
//! Hisil, Wong, Carter and Dawson (2008), which saves a multiplication per addition.
//!
//! Two scalar multiplications are provided:
//!
//! - [`Point::mul_base`], for secret scalars: a fixed 4-bit window over a compile-time
//!   table of 0B..15B with constant-time lookups, as in Zig.
//! - [`Point::mul_double_vartime`], for verification: width-5 NAF digits for the public
//!   key and width-8 NAF digits over a compile-time table of the odd multiples B..127B.
//!   It needs about 70 additions where Zig's signed 4-bit windows need about 120.

use super::SignatureError;
use super::field::{self, Fe};

/// A point of the curve in extended coordinates.
#[derive(Clone, Copy, Debug)]
pub(super) struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

/// A point prepared as the right operand of an addition: (Y+X, Y-X, 2dT, 2Z).
#[derive(Clone, Copy, Debug)]
struct Cached {
    y_plus_x: Fe,
    y_minus_x: Fe,
    t2d: Fe,
    z2: Fe,
}

/// Multiples 0B, 1B, ..., 15B, for the constant-time fixed-window multiplication.
const BASE_TABLE: [Cached; 16] = {
    let mut table = [Point::IDENTITY.to_cached(); 16];
    let mut multiple = Point::IDENTITY;
    let mut i = 1;
    while i < 16 {
        multiple = multiple.add(&Point::BASE.to_cached());
        table[i] = multiple.to_cached();
        i += 1;
    }
    table
};

/// The NAF width for the base point; its table is computed once, at compile time.
const BASE_NAF_WIDTH: u32 = 8;

/// The NAF width for the public key; its table is computed for each verification.
const KEY_NAF_WIDTH: u32 = 5;

/// Odd multiples B, 3B, 5B, ..., 127B, for width-8 NAF digits.
const BASE_ODD_MULTIPLES: [Cached; 64] = odd_multiples(&Point::BASE);

impl Point {
    pub(super) const IDENTITY: Point = Point { x: Fe::ZERO, y: Fe::ONE, z: Fe::ONE, t: Fe::ZERO };

    /// The base point B of RFC 8032, with y = 4/5 and positive x.
    pub(super) const BASE: Point = Point {
        x: Fe([
            1738742601995546,
            1146398526822698,
            2070867633025821,
            562264141797630,
            587772402128613,
        ]),
        y: Fe([
            1801439850948184,
            1351079888211148,
            450359962737049,
            900719925474099,
            1801439850948198,
        ]),
        z: Fe::ONE,
        t: Fe([
            1841354044333475,
            16398895984059,
            755974180946558,
            900171276175154,
            1821297809914039,
        ]),
    };

    /// Decodes a compressed point (y with the sign of x in the top bit).
    ///
    /// Fails with [`SignatureError::NonCanonical`] when y is not below p and with
    /// [`SignatureError::InvalidEncoding`] when no point has that y. Like Zig, it accepts a
    /// set sign bit with x = 0; callers that care reject x = 0 with [`Point::has_zero_x`].
    pub(super) fn decode(s: &[u8; 32]) -> Result<Point, SignatureError> {
        if !field::is_canonical(s) {
            return Err(SignatureError::NonCanonical);
        }
        let y = Fe::from_bytes(s);
        let y2 = y.square();
        let u = y2.sub(Fe::ONE);
        let v = y2.mul(Fe::D).add(Fe::ONE);
        // x = u (uv)^((p-5)/8) is a square root of u/v or of -u/v.
        let mut x = u.mul(v).pow2523().mul(u);
        let vxx = x.square().mul(v);
        let has_root = vxx.sub(u).is_zero();
        let has_negated_root = vxx.add(u).is_zero();
        if !has_root && !has_negated_root {
            return Err(SignatureError::InvalidEncoding);
        }
        x.conditional_assign(x.mul(Fe::SQRT_M1), u64::from(!has_root));
        let flip = u64::from(x.is_negative()) ^ u64::from(s[31] >> 7);
        x.conditional_assign(x.neg(), flip);
        Ok(Point { x, y, z: Fe::ONE, t: x.mul(y) })
    }

    /// Encodes the point as y with the sign of x in the top bit.
    pub(super) fn encode(&self) -> [u8; 32] {
        let z_inverse = self.z.invert();
        let mut s = self.y.mul(z_inverse).to_bytes();
        s[31] ^= u8::from(self.x.mul(z_inverse).is_negative()) << 7;
        s
    }

    /// Whether x = 0, which holds for the identity and for the point of order 2. Zig calls
    /// this check `rejectIdentity`.
    pub(super) fn has_zero_x(&self) -> bool {
        self.x.is_zero()
    }

    /// Whether the point is the identity.
    pub(super) fn is_identity(&self) -> bool {
        self.x.is_zero() && self.y.sub(self.z).is_zero()
    }

    /// Whether the point lies in the torsion subgroup of order 8, so that multiplying by
    /// the cofactor gives the identity.
    pub(super) fn is_small_order(&self) -> bool {
        self.double().double().double().is_identity()
    }

    pub(super) fn neg(&self) -> Point {
        Point { x: self.x.neg(), y: self.y, z: self.z, t: self.t.neg() }
    }

    const fn to_cached(self) -> Cached {
        Cached {
            y_plus_x: self.y.add(self.x),
            y_minus_x: self.y.sub(self.x),
            t2d: self.t.mul(Fe::D2),
            z2: self.z.add(self.z),
        }
    }

    /// Adds a cached point (the unified formula with a = -1, as in Zig's `add`).
    #[inline(always)]
    const fn add(&self, q: &Cached) -> Point {
        let a = self.y.sub(self.x).mul(q.y_minus_x);
        let b = self.y.add(self.x).mul(q.y_plus_x);
        let c = self.t.mul(q.t2d);
        let d = self.z.mul(q.z2);
        Point::from_parts(b.sub(a), b.add(a), d.add(c), d.sub(c))
    }

    /// Subtracts a cached point: adds its negation (-x, y), whose cached form swaps Y+X
    /// with Y-X and negates 2dT.
    #[inline(always)]
    fn sub_cached(&self, q: &Cached) -> Point {
        let a = self.y.sub(self.x).mul(q.y_plus_x);
        let b = self.y.add(self.x).mul(q.y_minus_x);
        let c = self.t.mul(q.t2d);
        let d = self.z.mul(q.z2);
        Point::from_parts(b.sub(a), b.add(a), d.sub(c), d.add(c))
    }

    pub(super) fn sub(&self, q: &Point) -> Point {
        self.sub_cached(&q.to_cached())
    }

    /// Completes an addition from E = B - A, H = B + A, G = D + C and F = D - C.
    #[inline(always)]
    const fn from_parts(e: Fe, h: Fe, g: Fe, f: Fe) -> Point {
        Point { x: e.mul(f), y: h.mul(g), z: g.mul(f), t: e.mul(h) }
    }

    #[inline(always)]
    pub(super) const fn double(&self) -> Point {
        let t0 = self.x.add(self.y).square();
        let x = self.x.square();
        let z = self.y.square();
        let y = z.add(x);
        let z = z.sub(x);
        let x = t0.sub(y);
        let t = self.z.square2().sub(z);
        Point { x: x.mul(t), y: y.mul(z), z: z.mul(t), t: x.mul(y) }
    }

    /// Returns `[scalar]B` in constant time. `scalar` is any 256-bit little-endian value;
    /// it need not be reduced. The result may be the identity.
    pub(super) fn mul_base(scalar: &[u8; 32]) -> Point {
        let mut q = Point::IDENTITY;
        for pos in (0..64).rev() {
            // Nibble `pos` of the scalar, most significant first.
            let digit = (scalar[pos / 2] >> (4 * (pos % 2))) & 0x0f;
            q = q.add(&select(&BASE_TABLE, digit));
            if pos > 0 {
                q = q.double().double().double().double();
            }
        }
        q
    }

    /// Returns `[a]A + [b]B` in variable time, for public scalars below 2^255.
    pub(super) fn mul_double_vartime(a: &[u8; 32], point_a: &Point, b: &[u8; 32]) -> Point {
        let table_a: [Cached; 8] = odd_multiples(point_a);
        let digits_a = non_adjacent_form(a, KEY_NAF_WIDTH);
        let digits_b = non_adjacent_form(b, BASE_NAF_WIDTH);
        let top = (0..256).rev().find(|&i| digits_a[i] != 0 || digits_b[i] != 0);
        let mut q = Point::IDENTITY;
        for i in (0..=top.unwrap_or(0)).rev() {
            q = q.double();
            q = add_digit(&q, &table_a, digits_a[i]);
            q = add_digit(&q, &BASE_ODD_MULTIPLES, digits_b[i]);
        }
        q
    }
}

/// Returns the odd multiples P, 3P, 5P, ..., (2N - 1)P in cached form.
const fn odd_multiples<const N: usize>(point: &Point) -> [Cached; N] {
    let double = point.double().to_cached();
    let mut table = [point.to_cached(); N];
    let mut multiple = *point;
    let mut i = 1;
    while i < N {
        multiple = multiple.add(&double);
        table[i] = multiple.to_cached();
        i += 1;
    }
    table
}

/// Adds `digit` times the point whose odd multiples are in `table`; `digit` is odd or 0.
fn add_digit(q: &Point, table: &[Cached], digit: i8) -> Point {
    // `|digit| <= 2 * table.len() - 1` by construction of the NAF, so the index is in range.
    let index = usize::from(digit.unsigned_abs() / 2);
    match digit {
        0 => *q,
        1.. => q.add(&table[index]),
        _ => q.sub_cached(&table[index]),
    }
}

/// Returns `table[index]` reading every entry, so the memory access pattern does not reveal
/// the secret index.
fn select(table: &[Cached; 16], index: u8) -> Cached {
    let mut result = table[0];
    for (i, entry) in (0u8..).zip(table).skip(1) {
        // 1 when `index == i`, else 0, without a branch.
        let equal = (u64::from(index ^ i).wrapping_sub(1) >> 63) & 1;
        result.y_plus_x.conditional_assign(entry.y_plus_x, equal);
        result.y_minus_x.conditional_assign(entry.y_minus_x, equal);
        result.t2d.conditional_assign(entry.t2d, equal);
        result.z2.conditional_assign(entry.z2, equal);
    }
    result
}

/// Writes a scalar below 2^255 in width-`w` non-adjacent form: 256 digits, least
/// significant first, each zero or odd with absolute value below 2^(w-1), and any `w`
/// consecutive digits holding at most one non-zero digit.
fn non_adjacent_form(s: &[u8; 32], w: u32) -> [i8; 256] {
    let mut limbs = [0u64; 5];
    for (limb, bytes) in limbs.iter_mut().zip(s.as_chunks::<8>().0) {
        *limb = u64::from_le_bytes(*bytes);
    }
    let width = 1u64 << w;
    let window_mask = width - 1;
    let mut naf = [0i8; 256];
    let mut position = 0;
    let mut carry = 0;
    while position < 256 {
        let (index, bit) = (position / 64, position % 64);
        // The window may straddle two limbs; `limbs[4]` is zero padding, so `index + 1`
        // stays in range for every position below 256.
        let bits = if bit < 64 - w as usize {
            limbs[index] >> bit
        } else {
            (limbs[index] >> bit) | (limbs[index + 1] << (64 - bit))
        };
        let window = carry + (bits & window_mask);
        if window & 1 == 0 {
            position += 1;
            continue;
        }
        // Choose the odd digit in (-2^(w-1), 2^(w-1)) congruent to the window.
        let digit = if window < width / 2 { window as i64 } else { window as i64 - width as i64 };
        carry = u64::from(digit < 0);
        naf[position] = digit as i8;
        position += w as usize;
    }
    naf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_tables_hold_multiples() {
        let mut expected = Point::IDENTITY;
        for (i, entry) in BASE_TABLE.iter().enumerate() {
            let from_table = Point::IDENTITY.add(entry);
            assert_eq!(from_table.encode(), expected.encode(), "{i}B");
            expected = expected.add(&Point::BASE.to_cached());
        }
        let twice = Point::BASE.double();
        let mut odd = Point::BASE;
        for (i, entry) in BASE_ODD_MULTIPLES.iter().enumerate() {
            assert_eq!(Point::IDENTITY.add(entry).encode(), odd.encode(), "{}B", 2 * i + 1);
            odd = odd.add(&twice.to_cached());
        }
    }

    #[test]
    fn non_adjacent_form_recomposes() {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i * 73 + 29) as u8;
        }
        s[31] &= 0x7f;
        for w in [5, 8] {
            let naf = non_adjacent_form(&s, w);
            let bound = 1i32 << (w - 1);
            // Recompose: sum of digit * 2^i, as 32 little-endian bytes with signed carries.
            let mut value = [0i64; 33];
            for (i, digit) in naf.iter().enumerate() {
                let d = i32::from(*digit);
                assert!(d == 0 || (d % 2 != 0 && d.abs() < bound), "digit {d}");
                value[i / 8] += i64::from(d) << (i % 8);
            }
            let mut carry = 0i64;
            for (i, byte) in s.iter().enumerate() {
                let total = value[i] + carry;
                assert_eq!(total.rem_euclid(256), i64::from(*byte), "w {w} byte {i}");
                carry = total.div_euclid(256);
            }
            assert_eq!(carry + value[32], 0);
            for window in naf.windows(w as usize) {
                assert!(window.iter().filter(|d| **d != 0).count() <= 1);
            }
        }
    }

    /// `[a]P` by double-and-add, as an independent reference.
    fn times(a: &[u8; 32], p: &Point) -> Point {
        let mut q = Point::IDENTITY;
        for bit in (0..256).rev() {
            q = q.double();
            if (a[bit / 8] >> (bit % 8)) & 1 == 1 {
                q = q.add(&p.to_cached());
            }
        }
        q
    }

    #[test]
    fn multiplications_match_double_and_add() {
        let a = [0x21u8; 32];
        let mut b = [0x7fu8; 32];
        b[31] = 0x3f;
        let point_a = Point::mul_base(&[0x42; 32]);
        assert_eq!(point_a.encode(), times(&[0x42; 32], &Point::BASE).encode());
        let combined = Point::mul_double_vartime(&a, &point_a, &b);
        let separate = times(&a, &point_a).add(&times(&b, &Point::BASE).to_cached());
        assert_eq!(combined.encode(), separate.encode());
        let zero = Point::mul_double_vartime(&[0; 32], &point_a, &[0; 32]);
        assert!(zero.is_identity());
    }

    #[test]
    fn decode_round_trips() {
        let mut p = Point::BASE;
        for _ in 0..20 {
            let bytes = p.encode();
            assert_eq!(Point::decode(&bytes).unwrap().encode(), bytes);
            p = p.double().add(&Point::BASE.to_cached());
        }
    }

    /// Independent reference for decoding: y must be canonical and x^2 = (y^2 - 1) /
    /// (d y^2 + 1) must have a solution, which Euler's criterion decides.
    fn reference_is_point(s: &[u8; 32]) -> bool {
        if !field::is_canonical(s) {
            return false;
        }
        let y = Fe::from_bytes(s);
        let y2 = y.mul(y);
        let x2 = y2.sub(Fe::ONE).mul(y2.mul(Fe::D).add(Fe::ONE).invert());
        // (p - 1) / 2 = 2^254 - 10: square-and-multiply over its bits.
        let mut exponent = [0xffu8; 32];
        exponent[0] = 0xf6;
        exponent[31] = 0x3f;
        let mut power = Fe::ONE;
        for bit in (0..255).rev() {
            power = power.mul(power);
            if (exponent[bit / 8] >> (bit % 8)) & 1 == 1 {
                power = power.mul(x2);
            }
        }
        x2.is_zero() || power.sub(Fe::ONE).is_zero()
    }

    fn check_decoding(input: &[u8; 32], with_reference: bool) {
        match Point::decode(input) {
            Ok(p) => {
                // On the curve: -x^2 + y^2 = 1 + d x^2 y^2, with z = 1 after decoding.
                let (x2, y2) = (p.x.square(), p.y.square());
                let lhs = y2.sub(x2);
                let rhs = Fe::ONE.add(Fe::D.mul(x2).mul(y2));
                assert!(lhs.sub(rhs).is_zero(), "{input:02x?} decoded off the curve");
                assert!(p.x.mul(p.y).sub(p.t).is_zero());
                if !p.has_zero_x() {
                    assert_eq!(p.encode(), *input, "re-encoding differs");
                }
                if with_reference {
                    assert!(reference_is_point(input), "{input:02x?} accepted");
                }
            }
            Err(SignatureError::NonCanonical) => assert!(!field::is_canonical(input)),
            Err(error) => {
                assert_eq!(error, SignatureError::InvalidEncoding);
                if with_reference {
                    assert!(!reference_is_point(input), "{input:02x?} rejected");
                }
            }
        }
    }

    fn fuzz_decoding(cases: usize, reference_every: usize) {
        let mut rng = crate::test_util::XorShift::new(0x5eed_0025_5190);
        let mut valid = std::vec::Vec::new();
        let mut p = Point::BASE;
        for _ in 0..8 {
            valid.push(p.encode());
            p = p.double().add(&Point::BASE.to_cached());
        }
        valid.push([0xff; 32]);
        valid.push([0; 32]);
        for case in 0..cases {
            let mut input = valid[rng.below(valid.len())];
            if rng.below(4) == 0 {
                rng.fill(&mut input);
            } else {
                let donor = valid[rng.below(valid.len())];
                rng.mutate(&mut input, &donor);
            }
            check_decoding(&input, case % reference_every == 0);
        }
    }

    /// Deterministic fuzzing of point decoding: no panic, decoded points lie on the curve
    /// and re-encode to the input, and acceptance agrees with Euler's criterion.
    #[test]
    fn fuzz_point_decoding() {
        fuzz_decoding(100_000, 50);
    }

    #[test]
    #[ignore = "long fuzz run; use --release"]
    fn fuzz_point_decoding_long() {
        fuzz_decoding(2_000_000, 1);
    }
}

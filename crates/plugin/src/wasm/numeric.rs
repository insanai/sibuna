//! The numeric instructions: their types for the validator and their meaning for the
//! interpreter. A value is the bits of its type in the low end of a `u64`; an `i32` and
//! an `f32` leave the high half zero.
//!
//! Each function takes the opcode byte of the binary format. The validator admits only
//! the opcodes 0x45 to 0xC4 and the saturating conversions 0 to 7, so an arm for "any
//! other opcode" is never taken; it returns the operand unchanged.

use super::exec::Trap;
use super::module::ValType;
use super::module::ValType::{F32, F64, I32, I64};

/// The operand type, the number of operands and the result type of the numeric
/// instruction `opcode` (0x45 to 0xC4). Every such instruction has operands of one type.
pub(crate) fn signature(opcode: u8) -> (ValType, u8, ValType) {
    match opcode {
        0x45 => (I32, 1, I32),
        0x46..=0x4f => (I32, 2, I32),
        0x50 => (I64, 1, I32),
        0x51..=0x5a => (I64, 2, I32),
        0x5b..=0x60 => (F32, 2, I32),
        0x61..=0x66 => (F64, 2, I32),
        0x67..=0x69 => (I32, 1, I32),
        0x6a..=0x78 => (I32, 2, I32),
        0x79..=0x7b => (I64, 1, I64),
        0x7c..=0x8a => (I64, 2, I64),
        0x8b..=0x91 => (F32, 1, F32),
        0x92..=0x98 => (F32, 2, F32),
        0x99..=0x9f => (F64, 1, F64),
        0xa0..=0xa6 => (F64, 2, F64),
        0xa7 => (I64, 1, I32),
        0xa8 | 0xa9 | 0xbc => (F32, 1, I32),
        0xaa | 0xab => (F64, 1, I32),
        0xac | 0xad => (I32, 1, I64),
        0xae | 0xaf => (F32, 1, I64),
        0xb0 | 0xb1 | 0xbd => (F64, 1, I64),
        0xb2 | 0xb3 | 0xbe => (I32, 1, F32),
        0xb4 | 0xb5 => (I64, 1, F32),
        0xb6 => (F64, 1, F32),
        0xb7 | 0xb8 => (I32, 1, F64),
        0xb9 | 0xba | 0xbf => (I64, 1, F64),
        0xbb => (F32, 1, F64),
        0xc0 | 0xc1 => (I32, 1, I32),
        _ => (I64, 1, I64),
    }
}

/// The operand and result types of the saturating conversion `code` (0 to 7).
pub(crate) fn saturate_signature(code: u8) -> (ValType, ValType) {
    match code {
        0 | 1 => (F32, I32),
        2 | 3 => (F64, I32),
        4 | 5 => (F32, I64),
        _ => (F64, I64),
    }
}

fn f32_of(bits: u64) -> f32 {
    f32::from_bits(bits as u32)
}

fn f64_of(bits: u64) -> f64 {
    f64::from_bits(bits)
}

fn of_f32(value: f32) -> u64 {
    u64::from(value.to_bits())
}

fn of_i32(value: i32) -> u64 {
    u64::from(value as u32)
}

/// Applies the instruction `opcode` of two operands.
///
/// # Errors
///
/// [`Trap::DivideByZero`] and [`Trap::IntegerOverflow`] from the integer divisions.
pub(crate) fn binary(opcode: u8, a: u64, b: u64) -> Result<u64, Trap> {
    Ok(match opcode {
        0x46..=0x4f => u64::from(compare_i32(opcode - 0x46, a as u32, b as u32)),
        0x51..=0x5a => u64::from(compare_i64(opcode - 0x51, a, b)),
        0x5b..=0x60 => u64::from(compare_float(opcode - 0x5b, f32_of(a).into(), f32_of(b).into())),
        0x61..=0x66 => u64::from(compare_float(opcode - 0x61, f64_of(a), f64_of(b))),
        0x6a..=0x78 => u64::from(arith_i32(opcode - 0x6a, a as u32, b as u32)?),
        0x7c..=0x8a => arith_i64(opcode - 0x7c, a, b)?,
        0x92..=0x98 => of_f32(arith_f32(opcode - 0x92, f32_of(a), f32_of(b))),
        0xa0..=0xa6 => arith_f64(opcode - 0xa0, f64_of(a), f64_of(b)).to_bits(),
        _ => a,
    })
}

/// The ten integer comparisons in opcode order: eq ne lt_s lt_u gt_s gt_u le_s le_u
/// ge_s ge_u.
fn compare_i32(which: u8, a: u32, b: u32) -> bool {
    let (sa, sb) = (a as i32, b as i32);
    match which {
        0 => a == b,
        1 => a != b,
        2 => sa < sb,
        3 => a < b,
        4 => sa > sb,
        5 => a > b,
        6 => sa <= sb,
        7 => a <= b,
        8 => sa >= sb,
        _ => a >= b,
    }
}

fn compare_i64(which: u8, a: u64, b: u64) -> bool {
    let (sa, sb) = (a as i64, b as i64);
    match which {
        0 => a == b,
        1 => a != b,
        2 => sa < sb,
        3 => a < b,
        4 => sa > sb,
        5 => a > b,
        6 => sa <= sb,
        7 => a <= b,
        8 => sa >= sb,
        _ => a >= b,
    }
}

/// The six float comparisons: eq ne lt gt le ge. Widening an `f32` keeps its order.
fn compare_float(which: u8, a: f64, b: f64) -> bool {
    match which {
        0 => a == b,
        1 => a != b,
        2 => a < b,
        3 => a > b,
        4 => a <= b,
        _ => a >= b,
    }
}

/// add sub mul div_s div_u rem_s rem_u and or xor shl shr_s shr_u rotl rotr.
fn arith_i32(which: u8, a: u32, b: u32) -> Result<u32, Trap> {
    let (sa, sb) = (a as i32, b as i32);
    if matches!(which, 3..=6) && b == 0 {
        return Err(Trap::DivideByZero);
    }
    Ok(match which {
        0 => a.wrapping_add(b),
        1 => a.wrapping_sub(b),
        2 => a.wrapping_mul(b),
        3 => sa.checked_div(sb).ok_or(Trap::IntegerOverflow)? as u32,
        4 => a / b,
        5 => sa.wrapping_rem(sb) as u32,
        6 => a % b,
        7 => a & b,
        8 => a | b,
        9 => a ^ b,
        10 => a.wrapping_shl(b),
        11 => sa.wrapping_shr(b) as u32,
        12 => a.wrapping_shr(b),
        13 => a.rotate_left(b & 31),
        _ => a.rotate_right(b & 31),
    })
}

fn arith_i64(which: u8, a: u64, b: u64) -> Result<u64, Trap> {
    let (sa, sb) = (a as i64, b as i64);
    if matches!(which, 3..=6) && b == 0 {
        return Err(Trap::DivideByZero);
    }
    let shift = (b & 63) as u32;
    Ok(match which {
        0 => a.wrapping_add(b),
        1 => a.wrapping_sub(b),
        2 => a.wrapping_mul(b),
        3 => sa.checked_div(sb).ok_or(Trap::IntegerOverflow)? as u64,
        4 => a / b,
        5 => sa.wrapping_rem(sb) as u64,
        6 => a % b,
        7 => a & b,
        8 => a | b,
        9 => a ^ b,
        10 => a.wrapping_shl(shift),
        11 => sa.wrapping_shr(shift) as u64,
        12 => a.wrapping_shr(shift),
        13 => a.rotate_left(shift),
        _ => a.rotate_right(shift),
    })
}

/// The smaller of two floats as WebAssembly defines it: a NaN wins, and -0 is below +0.
fn float_min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else if a == b {
        if a.is_sign_negative() { a } else { b }
    } else if a < b {
        a
    } else {
        b
    }
}

fn float_max(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else if a == b {
        if a.is_sign_positive() { a } else { b }
    } else if a > b {
        a
    } else {
        b
    }
}

/// add sub mul div min max copysign. Minimum and maximum are exact in `f64`.
fn arith_f32(which: u8, a: f32, b: f32) -> f32 {
    match which {
        0 => a + b,
        1 => a - b,
        2 => a * b,
        3 => a / b,
        4 => float_min(a.into(), b.into()) as f32,
        5 => float_max(a.into(), b.into()) as f32,
        _ => a.copysign(b),
    }
}

fn arith_f64(which: u8, a: f64, b: f64) -> f64 {
    match which {
        0 => a + b,
        1 => a - b,
        2 => a * b,
        3 => a / b,
        4 => float_min(a, b),
        5 => float_max(a, b),
        _ => a.copysign(b),
    }
}

/// Applies the instruction `opcode` of one operand.
///
/// # Errors
///
/// [`Trap::InvalidConversion`] and [`Trap::IntegerOverflow`] from the trapping
/// conversions of a float to an integer.
pub(crate) fn unary(opcode: u8, a: u64) -> Result<u64, Trap> {
    Ok(match opcode {
        0x45 => u64::from(a as u32 == 0),
        0x50 => u64::from(a == 0),
        0x67 => u64::from((a as u32).leading_zeros()),
        0x68 => u64::from((a as u32).trailing_zeros()),
        0x69 => u64::from((a as u32).count_ones()),
        0x79 => u64::from(a.leading_zeros()),
        0x7a => u64::from(a.trailing_zeros()),
        0x7b => u64::from(a.count_ones()),
        0x8b..=0x91 => of_f32(round_f32(opcode - 0x8b, f32_of(a))),
        0x99..=0x9f => round_f64(opcode - 0x99, f64_of(a)).to_bits(),
        0xa7..=0xbb => convert(opcode, a)?,
        // The four reinterpretations keep the bits.
        0xbc..=0xbf => a,
        0xc0 => of_i32(i32::from(a as i8)),
        0xc1 => of_i32(i32::from(a as i16)),
        0xc2 => i64::from(a as i8) as u64,
        0xc3 => i64::from(a as i16) as u64,
        0xc4 => i64::from(a as i32) as u64,
        _ => a,
    })
}

/// abs neg ceil floor trunc nearest sqrt.
fn round_f32(which: u8, a: f32) -> f32 {
    match which {
        0 => a.abs(),
        1 => -a,
        2 => a.ceil(),
        3 => a.floor(),
        4 => a.trunc(),
        5 => a.round_ties_even(),
        _ => a.sqrt(),
    }
}

fn round_f64(which: u8, a: f64) -> f64 {
    match which {
        0 => a.abs(),
        1 => -a,
        2 => a.ceil(),
        3 => a.floor(),
        4 => a.trunc(),
        5 => a.round_ties_even(),
        _ => a.sqrt(),
    }
}

/// Truncates `value` to an integer that is at least `least` and below `above`. Both
/// bounds are powers of two or zero, so they are exact floats.
fn truncate(value: f64, least: f64, above: f64) -> Result<f64, Trap> {
    if value.is_nan() {
        return Err(Trap::InvalidConversion);
    }
    let whole = value.trunc();
    if whole >= least && whole < above { Ok(whole) } else { Err(Trap::IntegerOverflow) }
}

const TWO_31: f64 = 2_147_483_648.0;
const TWO_32: f64 = 4_294_967_296.0;
const TWO_63: f64 = 9_223_372_036_854_775_808.0;
const TWO_64: f64 = 18_446_744_073_709_551_616.0;

/// The conversions 0xA7 to 0xBB.
fn convert(opcode: u8, a: u64) -> Result<u64, Trap> {
    let float =
        if matches!(opcode, 0xa8 | 0xa9 | 0xae | 0xaf) { f32_of(a).into() } else { f64_of(a) };
    Ok(match opcode {
        0xa7 => a & 0xffff_ffff,
        0xa8 | 0xaa => of_i32(truncate(float, -TWO_31, TWO_31)? as i32),
        0xa9 | 0xab => u64::from(truncate(float, 0.0, TWO_32)? as u32),
        0xac => i64::from(a as i32) as u64,
        0xad => a & 0xffff_ffff,
        0xae | 0xb0 => truncate(float, -TWO_63, TWO_63)? as i64 as u64,
        0xaf | 0xb1 => truncate(float, 0.0, TWO_64)? as u64,
        0xb2 => of_f32(a as i32 as f32),
        0xb3 => of_f32(a as u32 as f32),
        0xb4 => of_f32(a as i64 as f32),
        0xb5 => of_f32(a as f32),
        0xb6 => of_f32(f64_of(a) as f32),
        0xb7 => f64::from(a as i32).to_bits(),
        0xb8 => f64::from(a as u32).to_bits(),
        0xb9 => (a as i64 as f64).to_bits(),
        0xba => (a as f64).to_bits(),
        _ => f64::from(f32_of(a)).to_bits(),
    })
}

/// The saturating conversion `code` (0 to 7). A cast of a float to an integer in Rust
/// saturates and maps NaN to zero, which is the meaning WebAssembly gives these.
pub(crate) fn saturate(code: u8, a: u64) -> u64 {
    let float = if matches!(code, 0 | 1 | 4 | 5) { f32_of(a).into() } else { f64_of(a) };
    match code {
        0 | 2 => of_i32(float as i32),
        1 | 3 => u64::from(float as u32),
        4 | 6 => float as i64 as u64,
        _ => float as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn i32_op(opcode: u8, a: i32, b: i32) -> Result<i32, Trap> {
        binary(opcode, of_i32(a), of_i32(b)).map(|bits| bits as u32 as i32)
    }

    #[test]
    fn integer_division_traps_as_the_specification_says() {
        assert_eq!(i32_op(0x6d, 7, 0), Err(Trap::DivideByZero));
        assert_eq!(i32_op(0x6d, i32::MIN, -1), Err(Trap::IntegerOverflow));
        assert_eq!(i32_op(0x6f, i32::MIN, -1), Ok(0));
        assert_eq!(i32_op(0x6d, -7, 2), Ok(-3));
        assert_eq!(i32_op(0x6f, -7, 2), Ok(-1));
        assert_eq!(i32_op(0x6e, -1, 2), Ok(i32::MAX));
        assert_eq!(binary(0x7f, 1u64 << 63, u64::MAX), Err(Trap::IntegerOverflow));
        assert_eq!(binary(0x81, 1u64 << 63, u64::MAX), Ok(0));
        assert_eq!(binary(0x82, 9, 0), Err(Trap::DivideByZero));
    }

    #[test]
    fn shifts_and_rotations_take_the_count_modulo_the_width() {
        assert_eq!(i32_op(0x74, 1, 33), Ok(2));
        assert_eq!(i32_op(0x75, -8, 33), Ok(-4));
        assert_eq!(i32_op(0x76, -8, 1), Ok(0x7fff_fffc));
        assert_eq!(i32_op(0x77, 0x4000_0001, 1), Ok(i32::MIN + 2));
        assert_eq!(binary(0x86, 1, 65), Ok(2));
        assert_eq!(binary(0x8a, 1, 1), Ok(1u64 << 63));
    }

    #[test]
    fn comparisons_distinguish_signed_from_unsigned() {
        assert_eq!(i32_op(0x48, -1, 1), Ok(1));
        assert_eq!(i32_op(0x49, -1, 1), Ok(0));
        assert_eq!(binary(0x53, u64::MAX, 1), Ok(1));
        assert_eq!(binary(0x54, u64::MAX, 1), Ok(0));
    }

    #[test]
    fn float_minimum_and_maximum_follow_webassembly() {
        assert!(float_min(f64::NAN, 1.0).is_nan());
        assert!(float_min(-0.0, 0.0).is_sign_negative());
        assert!(float_max(-0.0, 0.0).is_sign_positive());
        assert_eq!(float_min(1.0, 2.0), 1.0);
        let nearest = unary(0x9e, 2.5f64.to_bits()).unwrap();
        assert_eq!(f64::from_bits(nearest), 2.0);
    }

    #[test]
    fn trapping_conversions_refuse_nan_and_values_out_of_range() {
        let f = |value: f64| value.to_bits();
        assert_eq!(unary(0xaa, f(f64::NAN)), Err(Trap::InvalidConversion));
        assert_eq!(unary(0xaa, f(2_147_483_648.0)), Err(Trap::IntegerOverflow));
        assert_eq!(unary(0xaa, f(-2_147_483_648.9)), Ok(of_i32(i32::MIN)));
        assert_eq!(unary(0xaa, f(-2_147_483_649.0)), Err(Trap::IntegerOverflow));
        assert_eq!(unary(0xab, f(-0.9)), Ok(0));
        assert_eq!(unary(0xab, f(-1.0)), Err(Trap::IntegerOverflow));
        assert_eq!(unary(0xab, f(4_294_967_295.5)), Ok(u64::from(u32::MAX)));
        assert_eq!(unary(0xb0, f(-TWO_63)), Ok(i64::MIN as u64));
        assert_eq!(unary(0xb0, f(TWO_63)), Err(Trap::IntegerOverflow));
        assert_eq!(unary(0xb1, f(TWO_64)), Err(Trap::IntegerOverflow));
    }

    #[test]
    fn saturating_conversions_clamp_and_map_nan_to_zero() {
        assert_eq!(saturate(2, f64::NAN.to_bits()), 0);
        assert_eq!(saturate(2, 1e30f64.to_bits()), of_i32(i32::MAX));
        assert_eq!(saturate(2, (-1e30f64).to_bits()), of_i32(i32::MIN));
        assert_eq!(saturate(3, (-5.0f64).to_bits()), 0);
        assert_eq!(saturate(7, 1e30f64.to_bits()), u64::MAX);
        assert_eq!(saturate(0, of_f32(-3.9)), of_i32(-3));
    }

    #[test]
    fn extensions_and_wrapping_keep_the_right_bits() {
        assert_eq!(unary(0xc0, 0x80), Ok(0xffff_ff80));
        assert_eq!(unary(0xc2, 0x80), Ok(0xffff_ffff_ffff_ff80));
        assert_eq!(unary(0xc4, 0x8000_0000), Ok(0xffff_ffff_8000_0000));
        assert_eq!(unary(0xa7, 0x1_2345_6789), Ok(0x2345_6789));
        assert_eq!(unary(0xac, 0xffff_ffff), Ok(u64::MAX));
        assert_eq!(unary(0xad, 0xffff_ffff), Ok(0xffff_ffff));
        assert_eq!(unary(0x67, 1), Ok(31));
        assert_eq!(unary(0x79, 1), Ok(63));
    }

    #[test]
    fn every_numeric_opcode_has_one_or_two_operands() {
        for opcode in 0x45..=0xc4u8 {
            let (_, count, _) = signature(opcode);
            assert!(count == 1 || count == 2, "{opcode:#x}");
        }
    }
}

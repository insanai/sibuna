//! Scene coordinates with one decimal, as [`format::decimal`] writes them, but without
//! the shortest-digits conversion for almost every value.
//!
//! A busy frame writes about 40,000 coordinates, and the shortest-digits conversion that
//! [`format::decimal`] needs to reproduce Zig's rounding was most of the frame's cost.
//! Zig rounds the shortest decimal `s` of a value `v` half up. Rounding half up changes
//! only at the midpoints `(k + 1/2) / 10`, and `s` lies in the interval of reals that
//! round to `v`, so rounding `s` and rounding `v` itself can differ only when a midpoint
//! lies within that interval, that is within an ulp of `v`. Values that close to a
//! midpoint, and values too large for the margin below to exceed their rounding error,
//! take the exact path.

use std::fmt::{self, Write};

use crate::format;

/// Beyond this magnitude the exact path runs (the coordinates of a scene are below 1,000).
const FAST_LIMIT: f64 = 1e6;
/// How far `10 v` must be from a midpoint, in tenths, for the fast path. The error of
/// `10 v` below [`FAST_LIMIT`] is below `2^-29`, so this margin is wide.
const MARGIN: f64 = 1e-6;

/// Writes `value` with one decimal exactly as `format::decimal(out, value, 1)` does.
///
/// # Errors
///
/// The sink's error.
pub(super) fn tenths(out: &mut impl Write, value: f64) -> fmt::Result {
    let magnitude = value.abs();
    if magnitude.is_nan() || magnitude >= FAST_LIMIT {
        return format::decimal(out, value, 1);
    }
    let scaled = magnitude * 10.0;
    let fraction = scaled - scaled.floor();
    if (fraction - 0.5).abs() < MARGIN {
        return format::decimal(out, value, 1);
    }
    // Below FAST_LIMIT the rounded value fits a u64 exactly; the cast cannot truncate.
    let rounded = (scaled + 0.5).floor() as u64;
    if value.is_sign_negative() {
        out.write_str("-")?;
    }
    write_whole(out, rounded / 10)?;
    let digit = [b'.', b'0' + (rounded % 10) as u8];
    // Both bytes are ASCII.
    out.write_str(std::str::from_utf8(&digit).map_err(|_| fmt::Error)?)
}

/// Writes a whole number in decimal without the formatting machinery.
fn write_whole(out: &mut impl Write, mut value: u64) -> fmt::Result {
    let mut digits = [0u8; 20];
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    out.write_str(std::str::from_utf8(&digits[start..]).map_err(|_| fmt::Error)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn both(value: f64) -> (String, String) {
        let mut fast = String::new();
        tenths(&mut fast, value).unwrap();
        let mut exact = String::new();
        format::decimal(&mut exact, value, 1).unwrap();
        (fast, exact)
    }

    #[test]
    fn known_values_round_like_zig() {
        for (value, text) in [
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (0.15, "0.2"),
            (0.25, "0.3"),
            (-0.04, "-0.0"),
            (199.95, "200.0"),
            (25.449_999, "25.4"),
            (135.0, "135.0"),
            (9.96, "10.0"),
            (1e7, "10000000.0"),
            (f64::NAN, "nan"),
            (f64::NEG_INFINITY, "-inf"),
        ] {
            let (fast, exact) = both(value);
            assert_eq!(fast, text, "{value}");
            assert_eq!(exact, text, "{value}");
        }
    }

    /// The fast path agrees with `format::decimal` on random coordinates, on values next
    /// to every midpoint of the scene, and on random bit patterns.
    #[test]
    fn agrees_with_format_decimal() {
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..200_000 {
            let unit = (next() >> 11) as f64 / (1u64 << 53) as f64;
            let value = unit * 1000.0 - 500.0;
            let (fast, exact) = both(value);
            assert_eq!(fast, exact, "{value:?}");
            let (fast, exact) = both(f64::from_bits(next()));
            assert_eq!(fast, exact);
        }
        for k in -5000..5000 {
            let midpoint = (f64::from(k) + 0.5) / 10.0;
            let mut value = midpoint;
            for _ in 0..4 {
                value = value.next_down();
            }
            for _ in 0..8 {
                let (fast, exact) = both(value);
                assert_eq!(fast, exact, "{value:?}");
                value = value.next_up();
            }
        }
    }
}

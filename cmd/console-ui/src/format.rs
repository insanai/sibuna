//! Number and time formatting shared by the pages, byte for byte as the Zig module
//! printed them.
//!
//! Zig printed floats from their shortest round-trip decimal digits and rounded those
//! digits half up at the requested precision (`{d:.1}` of 0.15 is `0.2`), while Rust's
//! `{:.1}` rounds the exact binary value half to even (`0.1`). [`decimal`] reproduces
//! Zig. Rust's `{}` already prints the same shortest digits as Zig's `{d}`, without an
//! exponent, so [`shortest`] only adds Zig's spelling of NaN and infinities.

use std::fmt::{self, Write};

use sibuna_console_protocol::minute_summary::Deviation;
use sibuna_html::write_value;

/// Room for the longest `{}` output of an `f64` (subnormals print about 330 digits).
const FLOAT_TEXT: usize = 400;

/// A fixed buffer for one float's digits.
struct Digits {
    bytes: [u8; FLOAT_TEXT],
    len: usize,
}

impl Write for Digits {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(fmt::Error)?;
        self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?.copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Writes Zig's spelling of a non-finite value and returns true, or returns false.
fn non_finite(out: &mut dyn Write, value: f64) -> Result<bool, fmt::Error> {
    if value.is_nan() {
        out.write_str("nan")?;
    } else if value.is_infinite() {
        out.write_str(if value < 0.0 { "-inf" } else { "inf" })?;
    } else {
        return Ok(false);
    }
    Ok(true)
}

/// Writes `value` with its shortest round-trip digits and no exponent (Zig's `{d}`).
///
/// # Errors
///
/// The sink's error.
pub fn shortest(out: &mut dyn Write, value: f64) -> fmt::Result {
    if non_finite(out, value)? {
        return Ok(());
    }
    write!(out, "{value}")
}

/// Writes `value` with exactly `places` decimals, rounding its shortest digits half up
/// (Zig's `{d:.N}`). A negative value keeps its sign even when it rounds to zero.
///
/// Most values take a fast path that rounds the value itself (see [`fast_decimal`]); a busy
/// globe frame writes about 40,000 coordinates, and the shortest-digits conversion was most
/// of its cost.
///
/// # Errors
///
/// The sink's error.
pub fn decimal(out: &mut dyn Write, value: f64, places: usize) -> fmt::Result {
    if non_finite(out, value)? {
        return Ok(());
    }
    match fast_decimal(out, value, places) {
        Some(result) => result,
        None => exact_decimal(out, value, places),
    }
}

/// Powers of ten for the fast path, by number of decimals.
const POWERS: [u64; 5] = [1, 10, 100, 1000, 10_000];
/// The fast path handles `|value| * 10^places` below this; the exact path the rest.
const FAST_LIMIT: f64 = 1e7;
/// How far `|value| * 10^places` must be from a rounding midpoint for the fast path.
const MARGIN: f64 = 1e-6;

/// Writes a finite `value` like [`exact_decimal`] by rounding the value itself, or returns
/// `None` when that could differ.
///
/// Zig rounds the shortest decimal `s` of a value `v` half up. Rounding half up changes
/// only at the midpoints `(k + 1/2) / 10^places`, and `s` lies within half an ulp of `v`,
/// so rounding `s` and rounding `v` can differ only when a midpoint lies within an ulp of
/// `v`. Below [`FAST_LIMIT`] that ulp, scaled by `10^places`, is below `2^-29`, as is the
/// error of the scaled product, so a scaled value at least [`MARGIN`] from a midpoint
/// rounds the same both ways.
fn fast_decimal(out: &mut dyn Write, value: f64, places: usize) -> Option<fmt::Result> {
    let power = *POWERS.get(places)?;
    let scaled = value.abs() * power as f64;
    if scaled >= FAST_LIMIT || (scaled - scaled.floor() - 0.5).abs() < MARGIN {
        return None;
    }
    // Below FAST_LIMIT the rounded value fits a u64 exactly; the cast cannot truncate.
    let rounded = (scaled + 0.5).floor() as u64;
    Some(write_fixed(out, value.is_sign_negative(), rounded, places))
}

/// Writes `rounded / 10^places` with `places` decimals, after a minus sign when
/// `negative`.
fn write_fixed(out: &mut dyn Write, negative: bool, rounded: u64, places: usize) -> fmt::Result {
    // `rounded` is below 10^8 and `places` at most 4, so at most nine digits and a point
    // are written from the right: every index below stays in bounds.
    let mut digits = [0u8; 24];
    let mut start = digits.len();
    let mut rest = rounded;
    for _ in 0..places {
        start -= 1;
        digits[start] = b'0' + (rest % 10) as u8;
        rest /= 10;
    }
    if places > 0 {
        start -= 1;
        digits[start] = b'.';
    }
    loop {
        start -= 1;
        digits[start] = b'0' + (rest % 10) as u8;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    if negative {
        out.write_str("-")?;
    }
    out.write_str(std::str::from_utf8(&digits[start..]).map_err(|_| fmt::Error)?)
}

/// Writes `value` with exactly `places` decimals from its shortest round-trip digits.
fn exact_decimal(out: &mut dyn Write, value: f64, places: usize) -> fmt::Result {
    let mut digits = Digits { bytes: [0; FLOAT_TEXT], len: 0 };
    write!(digits, "{}", value.abs())?;
    let text = digits.bytes.get(..digits.len).ok_or(fmt::Error)?;
    let point = text.iter().position(|byte| *byte == b'.').unwrap_or(text.len());
    let (whole, fraction) = text.split_at(point);
    let fraction = fraction.get(1..).unwrap_or_default();
    // The kept digits, without the point; rounding may carry into a new leading digit.
    let mut kept = [0u8; FLOAT_TEXT + 1];
    let mut length = 0;
    for byte in whole.iter().chain(fraction.iter().take(places)) {
        kept[1 + length] = *byte;
        length += 1;
    }
    for _ in fraction.len()..places {
        kept[1 + length] = b'0';
        length += 1;
    }
    let mut start = 1;
    if fraction.get(places).is_some_and(|digit| *digit >= b'5') {
        let mut index = length;
        loop {
            if index == 0 {
                kept[0] = b'1';
                start = 0;
                break;
            }
            if kept[index] == b'9' {
                kept[index] = b'0';
                index -= 1;
            } else {
                kept[index] += 1;
                break;
            }
        }
    }
    if value.is_sign_negative() {
        out.write_str("-")?;
    }
    let digits = kept.get(start..=length).ok_or(fmt::Error)?;
    let (whole, fraction) = digits.split_at(digits.len() - places);
    out.write_str(std::str::from_utf8(whole).map_err(|_| fmt::Error)?)?;
    if places > 0 {
        out.write_str(".")?;
        out.write_str(std::str::from_utf8(fraction).map_err(|_| fmt::Error)?)?;
    }
    Ok(())
}

/// Returns `bytes` as lowercase hexadecimal digits, two per byte.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    text
}

/// Writes a count with thousands separators (`12,345`); identifiers and wire values stay
/// ungrouped.
///
/// # Errors
///
/// The sink's error.
pub fn count(out: &mut dyn Write, value: u64) -> fmt::Result {
    let mut buffer = [0u8; 26];
    let mut start = buffer.len();
    let mut remaining = value;
    let mut group = 0;
    loop {
        start -= 1;
        buffer[start] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
        group += 1;
        if group == 3 {
            start -= 1;
            buffer[start] = b',';
            group = 0;
        }
    }
    out.write_str(std::str::from_utf8(&buffer[start..]).map_err(|_| fmt::Error)?)
}

/// The latest second [`timestamp`] prints: 9999-12-31 23:59:59 UTC.
pub const MAX_TIMESTAMP: u64 = 253_402_300_799;

/// Writes Unix seconds as `YYYY-MM-DD hh:mm:ss UTC`, or `Time unavailable` beyond the
/// year 9999.
///
/// # Errors
///
/// The sink's error.
pub fn timestamp(out: &mut dyn Write, seconds: u64) -> fmt::Result {
    if seconds > MAX_TIMESTAMP {
        return out.write_str("Time unavailable");
    }
    let (year, month, day) = civil_date(seconds / 86_400);
    let time = seconds % 86_400;
    let parts = [
        (year, 4, "-"),
        (month, 2, "-"),
        (day, 2, " "),
        (time / 3600, 2, ":"),
        (time % 3600 / 60, 2, ":"),
        (time % 60, 2, " UTC"),
    ];
    for (value, width, suffix) in parts {
        padded(out, value, width)?;
        out.write_str(suffix)?;
    }
    Ok(())
}

/// Writes `value` with leading zeros to `width` digits.
fn padded(out: &mut dyn Write, value: u64, width: u32) -> fmt::Result {
    let mut limit = 10u64.pow(width.saturating_sub(1));
    while limit > 1 && value < limit {
        out.write_str("0")?;
        limit /= 10;
    }
    write_value(out, &value)
}

/// Returns the proleptic Gregorian date of `days` since 1970-01-01 (Howard Hinnant's
/// `civil_from_days`).
fn civil_date(days: u64) -> (u64, u64, u64) {
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

/// Returns true when a deviation is large enough to tint: at least 25 percent, or new.
pub fn is_tinted(change: Deviation) -> bool {
    match change {
        Deviation::Percent(percent) => percent.abs() >= 25.0,
        Deviation::New => true,
        Deviation::Unavailable => false,
    }
}

/// Writes a deviation: `Not available`, `\u{2191} New`, or an arrow and the percentage
/// with one decimal.
///
/// # Errors
///
/// The sink's error.
pub fn deviation(out: &mut dyn Write, change: Deviation) -> fmt::Result {
    match change {
        Deviation::Unavailable => out.write_str("Not available"),
        Deviation::New => out.write_str("\u{2191} New"),
        Deviation::Percent(percent) => {
            out.write_str(if percent > 0.0 {
                "\u{2191} "
            } else if percent < 0.0 {
                "\u{2193} "
            } else {
                "\u{2192} "
            })?;
            decimal(out, percent.abs(), 1)?;
            out.write_str("%")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(write: impl FnOnce(&mut dyn Write) -> fmt::Result) -> String {
        let mut out = String::new();
        write(&mut out).unwrap();
        out
    }

    /// Expected values printed by Zig 0.16 `std.fmt` (`{d:.1}`, `{d:.4}`, `{d:.2}`,
    /// `{d:.0}`).
    #[test]
    fn decimals_round_the_shortest_digits_half_up_like_zig() {
        let cases: [(f64, &str, &str, &str, &str); 18] = [
            (0.05, "0.1", "0.0500", "0.05", "0"),
            (0.15, "0.2", "0.1500", "0.15", "0"),
            (0.25, "0.3", "0.2500", "0.25", "0"),
            (1.25, "1.3", "1.2500", "1.25", "1"),
            (2.675, "2.7", "2.6750", "2.68", "3"),
            (-0.04, "-0.0", "-0.0400", "-0.04", "-0"),
            (-0.0, "-0.0", "-0.0000", "-0.00", "-0"),
            (-0.25, "-0.3", "-0.2500", "-0.25", "-0"),
            (0.249, "0.2", "0.2490", "0.25", "0"),
            (0.95, "1.0", "0.9500", "0.95", "1"),
            (9.95, "10.0", "9.9500", "9.95", "10"),
            (99.95, "100.0", "99.9500", "99.95", "100"),
            (199.99999, "200.0", "200.0000", "200.00", "200"),
            (123_456.789, "123456.8", "123456.7890", "123456.79", "123457"),
            (140.0 / 3.0, "46.7", "46.6667", "46.67", "47"),
            (0.000049, "0.0", "0.0000", "0.00", "0"),
            (0.00005, "0.0", "0.0001", "0.00", "0"),
            (1e-7, "0.0", "0.0000", "0.00", "0"),
        ];
        for (value, one, four, two, zero) in cases {
            assert_eq!(text(|out| decimal(out, value, 1)), one, "{value}");
            assert_eq!(text(|out| decimal(out, value, 4)), four, "{value}");
            assert_eq!(text(|out| decimal(out, value, 2)), two, "{value}");
            assert_eq!(text(|out| decimal(out, value, 0)), zero, "{value}");
        }
        assert_eq!(text(|out| decimal(out, f64::NAN, 1)), "nan");
        assert_eq!(text(|out| decimal(out, f64::NEG_INFINITY, 1)), "-inf");
        assert_eq!(text(|out| decimal(out, 1e21, 1)), "1000000000000000000000.0");
        assert!(text(|out| decimal(out, 5e-324, 4)) == "0.0000");
        assert_eq!(text(|out| shortest(out, 46.666666666666664)), "46.666666666666664");
        assert_eq!(text(|out| shortest(out, 1e-7)), "0.0000001");
        assert_eq!(text(|out| shortest(out, f64::INFINITY)), "inf");
    }

    #[test]
    fn hex_is_lowercase_with_two_digits_per_byte() {
        assert_eq!(hex(&[0, 0xab, 0x10]), "00ab10");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn counts_group_thousands_and_keep_full_precision() {
        let cases = [
            (0, "0"),
            (999, "999"),
            (1000, "1,000"),
            (1_000_000, "1,000,000"),
            (u64::MAX, "18,446,744,073,709,551,615"),
        ];
        for (value, expected) in cases {
            assert_eq!(text(|out| count(out, value)), expected);
        }
    }

    /// Expected values printed by the Zig `events_page.timestamp`.
    #[test]
    fn timestamps_match_zig_across_leap_days_and_bounds() {
        let cases = [
            (0, "1970-01-01 00:00:00 UTC"),
            (1, "1970-01-01 00:00:01 UTC"),
            (172_800, "1970-01-03 00:00:00 UTC"),
            (951_782_400, "2000-02-29 00:00:00 UTC"),
            (951_868_800, "2000-03-01 00:00:00 UTC"),
            (1_709_251_199, "2024-02-29 23:59:59 UTC"),
            (4_102_444_800, "2100-01-01 00:00:00 UTC"),
            (253_402_300_799, "9999-12-31 23:59:59 UTC"),
            (253_402_300_800, "Time unavailable"),
            (1_000_000_000, "2001-09-09 01:46:40 UTC"),
        ];
        for (seconds, expected) in cases {
            assert_eq!(text(|out| timestamp(out, seconds)), expected);
        }
    }

    #[test]
    fn deviations_name_missing_coverage_and_new_traffic() {
        assert_eq!(text(|out| deviation(out, Deviation::Unavailable)), "Not available");
        assert_eq!(text(|out| deviation(out, Deviation::New)), "\u{2191} New");
        assert_eq!(text(|out| deviation(out, Deviation::Percent(20.0))), "\u{2191} 20.0%");
        assert_eq!(text(|out| deviation(out, Deviation::Percent(-33.35))), "\u{2193} 33.4%");
        assert_eq!(text(|out| deviation(out, Deviation::Percent(0.0))), "\u{2192} 0.0%");
        assert!(is_tinted(Deviation::Percent(-25.0)) && !is_tinted(Deviation::Percent(24.9)));
    }

    fn both(value: f64, places: usize) -> (String, String) {
        let fast = text(|out| decimal(out, value, places));
        let exact = text(|out| {
            if !non_finite(out, value)? {
                exact_decimal(out, value, places)?;
            }
            Ok(())
        });
        (fast, exact)
    }

    /// The fast path agrees with the shortest-digits path on random coordinates, on values
    /// next to every midpoint of a scene, and on random bit patterns (ported from the
    /// globe's `tenths`, which this path replaces).
    #[test]
    fn the_fast_path_agrees_with_the_shortest_digits() {
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for round in 0..200_000 {
            let places = round % 5;
            let unit = (next() >> 11) as f64 / (1u64 << 53) as f64;
            let value = unit * 1000.0 - 500.0;
            let (fast, exact) = both(value, places);
            assert_eq!(fast, exact, "{value:?} at {places}");
            let (fast, exact) = both(f64::from_bits(next()), places);
            assert_eq!(fast, exact);
        }
        for (places, &power) in POWERS.iter().enumerate() {
            let scale = power as f64;
            for k in -5000..5000 {
                let mut value = (f64::from(k) + 0.5) / scale;
                for _ in 0..4 {
                    value = value.next_down();
                }
                for _ in 0..8 {
                    let (fast, exact) = both(value, places);
                    assert_eq!(fast, exact, "{value:?} at {places}");
                    value = value.next_up();
                }
            }
        }
        for (value, expected) in
            [(0.15, "0.2"), (-0.04, "-0.0"), (199.95, "200.0"), (1e7, "10000000.0")]
        {
            assert_eq!(both(value, 1), (expected.to_owned(), expected.to_owned()));
        }
    }

    /// Random values: `decimal` never panics and agrees with exact rounding whenever it
    /// cuts digits that are not a tie.
    #[test]
    fn fuzz_decimal_agrees_with_rounding_away_from_ties() {
        let mut seed = 0x1234_5678_9abc_def1_u64;
        for _ in 0..100_000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let value = f64::from_bits(seed);
            let places = (seed % 6) as usize;
            let ours = text(|out| decimal(out, value, places));
            if !value.is_finite() || value.abs() > 1e15 || value.abs() < 1e-3 {
                continue;
            }
            let reference = format!("{value:.places$}");
            let shortest = format!("{}", value.abs());
            let fraction = shortest.split('.').nth(1).unwrap_or("");
            // Zig pads short digits with zeros where Rust prints the exact binary
            // expansion, and the two round a tie differently: compare the other cases.
            let tie = fraction.len() == places + 1 && fraction.ends_with('5');
            if fraction.len() > places && !tie {
                assert_eq!(ours, reference, "{value} at {places}");
            }
        }
    }
}

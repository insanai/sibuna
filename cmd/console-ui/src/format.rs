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
fn non_finite(out: &mut impl Write, value: f64) -> Result<bool, fmt::Error> {
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
pub fn shortest(out: &mut impl Write, value: f64) -> fmt::Result {
    if non_finite(out, value)? {
        return Ok(());
    }
    write!(out, "{value}")
}

/// Writes `value` with exactly `places` decimals, rounding its shortest digits half up
/// (Zig's `{d:.N}`). A negative value keeps its sign even when it rounds to zero.
///
/// # Errors
///
/// The sink's error.
pub fn decimal(out: &mut impl Write, value: f64, places: usize) -> fmt::Result {
    if non_finite(out, value)? {
        return Ok(());
    }
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

/// Writes a count with thousands separators (`12,345`); identifiers and wire values stay
/// ungrouped.
///
/// # Errors
///
/// The sink's error.
pub fn count(out: &mut impl Write, value: u64) -> fmt::Result {
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
pub fn timestamp(out: &mut impl Write, seconds: u64) -> fmt::Result {
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
fn padded(out: &mut impl Write, value: u64, width: u32) -> fmt::Result {
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
pub fn deviation(out: &mut impl Write, change: Deviation) -> fmt::Result {
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

    fn text(write: impl FnOnce(&mut String) -> fmt::Result) -> String {
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

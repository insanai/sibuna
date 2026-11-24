//! Wall-clock time in whole milliseconds.

use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch. Negative values are instants before 1970.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Millis(pub i64);

impl Millis {
    /// The current time. A clock before 1970 reads as zero.
    pub fn now() -> Millis {
        let since = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        Millis(i64::try_from(since.as_millis()).unwrap_or(i64::MAX))
    }

    /// This instant moved by `delta` milliseconds, saturating at the ends of the range.
    pub fn plus(self, delta: i64) -> Millis {
        Millis(self.0.saturating_add(delta))
    }

    /// The instant in UTC to the minute, such as `2026-10-20 14:05 UTC`, for messages.
    pub fn to_utc_text(self) -> String {
        let minutes = self.0.div_euclid(60_000);
        let (days, minute) = (minutes.div_euclid(1440), minutes.rem_euclid(1440));
        let (year, month, day) = civil_from_days(days);
        format!("{year:04}-{month:02}-{day:02} {:02}:{:02} UTC", minute / 60, minute % 60)
    }
}

/// The proleptic Gregorian date of day `days` since 1970-01-01 (Howard Hinnant's
/// `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_text_names_the_date_and_minute() {
        assert_eq!(Millis(0).to_utc_text(), "1970-01-01 00:00 UTC");
        assert_eq!(Millis(1_792_505_100_000).to_utc_text(), "2026-10-20 14:05 UTC");
        assert_eq!(Millis(951_782_400_000).to_utc_text(), "2000-02-29 00:00 UTC");
        assert_eq!(Millis(-60_000).to_utc_text(), "1969-12-31 23:59 UTC");
    }
}

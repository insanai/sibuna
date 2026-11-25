//! Calendar arithmetic for certificate dates: seconds since 1970 to and from a UTC date.

/// The days from 1970-01-01 to the given date of the proleptic Gregorian calendar.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month = i64::from(month);
    let shifted = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The date of a day counted from 1970-01-01: year, month and day.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted + 2) / 5 + 1) as u32;
    let month = if shifted < 10 { shifted + 3 } else { shifted - 9 } as u32;
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// A UTC date and time of day.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Civil {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

impl Civil {
    /// The date of `seconds` after 1970-01-01T00:00:00Z.
    pub fn from_unix(seconds: u64) -> Self {
        let days = (seconds / 86_400) as i64;
        let rest = (seconds % 86_400) as u32;
        let (year, month, day) = civil_from_days(days);
        Self { year, month, day, hour: rest / 3600, minute: rest / 60 % 60, second: rest % 60 }
    }

    /// The seconds from 1970 to this date. Returns `None` for a field out of range or a
    /// year outside 1970 to 9999.
    pub fn to_unix(self) -> Option<u64> {
        let in_range = (1..=12).contains(&self.month)
            && (1..=31).contains(&self.day)
            && self.hour < 24
            && self.minute < 60
            && self.second < 61
            && (1970..=9999).contains(&self.year);
        if !in_range {
            return None;
        }
        let days = days_from_civil(self.year, self.month, self.day);
        let seconds = days * 86_400
            + i64::from(self.hour) * 3600
            + i64::from(self.minute) * 60
            + i64::from(self.second);
        u64::try_from(seconds).ok()
    }
}

/// Writes a time in seconds since 1970 as `2027-02-22T10:00:00Z`.
pub fn format_rfc3339(seconds: u64) -> String {
    let c = Civil::from_unix(seconds);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        c.year, c.month, c.day, c.hour, c.minute, c.second
    )
}

/// Writes a time as the content of a DER `UTCTime`: `YYMMDDHHMMSSZ`. The form covers the
/// years 1950 to 2049, which is enough for a certificate that lives one week.
pub(crate) fn format_utc_time(seconds: u64) -> String {
    let c = Civil::from_unix(seconds);
    let year = c.year % 100;
    format!("{year:02}{:02}{:02}{:02}{:02}{:02}Z", c.month, c.day, c.hour, c.minute, c.second)
}

/// Reads the content of a DER `UTCTime` (`two_digit_year`) or `GeneralizedTime`, in the
/// form that certificates use: no fraction, and the zone `Z`.
pub(crate) fn parse_der_time(text: &[u8], two_digit_year: bool) -> Option<u64> {
    let text = std::str::from_utf8(text).ok()?.strip_suffix('Z')?;
    let year_digits = if two_digit_year { 2 } else { 4 };
    if text.len() != year_digits + 10 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let number = |from: usize, len: usize| text.get(from..from + len)?.parse::<u32>().ok();
    let year = i64::from(number(0, year_digits)?);
    // RFC 5280: a two-digit year below 50 is in the twenty-first century.
    let year = match (two_digit_year, year) {
        (true, year) if year < 50 => 2000 + year,
        (true, year) => 1900 + year,
        (false, year) => year,
    };
    let at = year_digits;
    Civil {
        year,
        month: number(at, 2)?,
        day: number(at + 2, 2)?,
        hour: number(at + 4, 2)?,
        minute: number(at + 6, 2)?,
        second: number(at + 8, 2)?,
    }
    .to_unix()
}

/// Reads a time of RFC 3339, such as `2027-02-22T10:00:00Z` or
/// `2027-02-22T12:00:00.25+02:00`, as seconds since 1970. A fraction is dropped.
pub(crate) fn parse_rfc3339(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    let shape_ok = text.is_ascii()
        && (20..=40).contains(&bytes.len())
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && matches!(bytes.get(10), Some(b'T' | b't' | b' '))
        && bytes.get(13) == Some(&b':')
        && bytes.get(16) == Some(&b':');
    if !shape_ok {
        return None;
    }
    let number = |from: usize, len: usize| {
        let digits = text.get(from..from + len)?;
        digits.bytes().all(|byte| byte.is_ascii_digit()).then(|| digits.parse::<u32>().ok())?
    };
    let civil = Civil {
        year: i64::from(number(0, 4)?),
        month: number(5, 2)?,
        day: number(8, 2)?,
        hour: number(11, 2)?,
        minute: number(14, 2)?,
        second: number(17, 2)?,
    };
    let mut zone = text.get(19..)?;
    if let Some(fraction) = zone.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        zone = fraction.get(digits..).filter(|_| digits > 0)?;
    }
    let local = civil.to_unix()?;
    if zone.eq_ignore_ascii_case("z") {
        return Some(local);
    }
    let offset_ok = zone.len() == 6 && zone.as_bytes().get(3) == Some(&b':');
    let at = 19 + (text.len() - 19 - zone.len());
    let (hours, minutes) = (number(at + 1, 2)?, number(at + 4, 2)?);
    if !offset_ok || hours > 23 || minutes > 59 {
        return None;
    }
    let offset = u64::from(hours * 3600 + minutes * 60);
    match zone.as_bytes().first() {
        Some(b'+') => local.checked_sub(offset),
        Some(b'-') => local.checked_add(offset),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOVEMBER: u64 = 1_795_516_496;

    #[test]
    fn dates_round_trip() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(format_rfc3339(NOVEMBER), "2026-11-24T10:34:56Z");
        for seconds in [0, 86_399, 951_782_400, NOVEMBER, 4_102_444_800, 32_503_679_999] {
            assert_eq!(Civil::from_unix(seconds).to_unix(), Some(seconds));
        }
    }

    #[test]
    fn rfc_3339_times_parse_with_fractions_and_zones() {
        assert_eq!(parse_rfc3339("2026-11-24T10:34:56Z"), Some(NOVEMBER));
        assert_eq!(parse_rfc3339("2026-11-24t10:34:56z"), Some(NOVEMBER));
        assert_eq!(parse_rfc3339("2026-11-24T10:34:56.789Z"), Some(NOVEMBER));
        assert_eq!(parse_rfc3339("2026-11-24T12:34:56+02:00"), Some(NOVEMBER));
        assert_eq!(parse_rfc3339("2026-11-24T05:04:56.5-05:30"), Some(NOVEMBER));
        assert_eq!(parse_rfc3339(&format_rfc3339(NOVEMBER)), Some(NOVEMBER));
        let bad = [
            "",
            "2026-11-24",
            "2026-11-24T10:34:56",
            "2026-11-24T10:34:56.Z",
            "2026-13-24T10:34:56Z",
            "2026-11-24T10:34:56+0200",
            "2026-11-24T10:34:56+24:00",
            "2026-11-24T10:34:56Zjunk",
            "1970-01-01T00:00:00+01:00",
            "2026-11-24T1\u{e9}:34:56Z",
        ];
        for text in bad {
            assert_eq!(parse_rfc3339(text), None, "{text}");
        }
    }

    #[test]
    fn certificate_times_parse() {
        assert_eq!(parse_der_time(b"261124103456Z", true), Some(NOVEMBER));
        assert_eq!(parse_der_time(b"20261124103456Z", false), Some(NOVEMBER));
        assert_eq!(parse_der_time(b"700101000000Z", true), Some(0));
        assert_eq!(parse_der_time(format_utc_time(NOVEMBER).as_bytes(), true), Some(NOVEMBER));
        let bad: [&[u8]; 5] =
            [b"261124103456", b"2611241034Z", b"261324103456Z", b"26112410345xZ", b""];
        for text in bad {
            assert_eq!(parse_der_time(text, true), None);
        }
    }
}

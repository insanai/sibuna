//! Syslog lines for the syslog destination (Zig's `notify_syslog.zig`): RFC 5424 messages,
//! with RFC 6587 octet-counting framing for TCP. A message longer than [`MAX_MESSAGE`]
//! bytes is cut at the bound rather than split.

use std::fmt::Write;

/// The longest message, in bytes.
pub const MAX_MESSAGE: usize = 1024;
/// The `local0` facility.
pub const FACILITY_LOCAL0: u8 = 16;

/// The severity of a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Severity {
    /// Warning (4).
    Warning,
    /// Notice (5); only the ported Zig test formats one.
    #[cfg(test)]
    Notice,
}

impl Severity {
    fn code(self) -> u8 {
        match self {
            Severity::Warning => 4,
            #[cfg(test)]
            Severity::Notice => 5,
        }
    }
}

/// Returns the RFC 5424 line `<PRI>1 TIMESTAMP HOST sibuna - EVENT - MESSAGE` for an event
/// raised at `unix_seconds` (UTC). An empty host or event is written as `-`; bytes of the
/// message outside printable ASCII become `?`. The line is at most [`MAX_MESSAGE`] bytes.
pub fn format(
    severity: Severity,
    unix_seconds: u64,
    hostname: &str,
    event: &str,
    message: &str,
) -> String {
    let priority = u16::from(FACILITY_LOCAL0) * 8 + u16::from(severity.code());
    let (year, month, day) = civil_date(unix_seconds / 86_400);
    let time = unix_seconds % 86_400;
    let mut line = String::with_capacity(MAX_MESSAGE);
    // Writing into a String cannot fail.
    let _ = write!(
        line,
        "<{priority}>1 {year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z {} sibuna - {} - ",
        time / 3600,
        time / 60 % 60,
        time % 60,
        if hostname.is_empty() { "-" } else { hostname },
        if event.is_empty() { "-" } else { event },
    );
    // The fixed part is ASCII; cut it at the bound like Zig's fixed writer did.
    line.truncate(MAX_MESSAGE);
    for byte in message.bytes() {
        if line.len() >= MAX_MESSAGE {
            break;
        }
        line.push(if (32..127).contains(&byte) { char::from(byte) } else { '?' });
    }
    line
}

/// Returns `<length> <message>`, the TCP framing; UDP sends the bare message.
pub fn framed(message: &str) -> String {
    format!("{} {message}", message.len())
}

/// Returns the proleptic Gregorian year, month and day of the day `days` after 1970-01-01
/// (Howard Hinnant's `civil_from_days`).
fn civil_date(days: u64) -> (u64, u64, u64) {
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 { shifted_month + 3 } else { shifted_month - 9 };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    // notify_syslog.zig: "syslog lines carry the priority, UTC timestamp, event id and a
    // sanitized message".
    #[test]
    fn lines_carry_the_priority_utc_timestamp_event_and_a_sanitized_message() {
        let line = format(Severity::Warning, 1788922213, "edge-1", "denial_spike", "denied 240\n");
        let expected = "<132>1 2026-09-09T02:50:13Z edge-1 sibuna - denial_spike - denied 240?";
        assert_eq!(line, expected);
        assert!(framed(&line).starts_with("70 <132>1 "));
        let long = "x".repeat(2048);
        assert_eq!(format(Severity::Notice, 0, "", "", &long).len(), MAX_MESSAGE);
        assert!(
            format(Severity::Notice, 0, "", "", "").starts_with("<133>1 1970-01-01T00:00:00Z - ")
        );
        assert!(format(Severity::Notice, 0, "h", "e", "\u{e9}").ends_with("- ??"));
    }

    #[test]
    fn civil_dates_match_the_calendar() {
        assert_eq!(civil_date(0), (1970, 1, 1));
        assert_eq!(civil_date(11_016), (2000, 2, 29));
        assert_eq!(civil_date(20_705), (2026, 9, 9));
        // Any second, up to the largest, stays in range without overflow.
        let _ = format(Severity::Warning, i64::MAX as u64, "h", "e", "m");
        let _ = format(Severity::Warning, u64::MAX, "h", "e", "m");
    }
}

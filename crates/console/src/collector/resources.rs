//! Process resource gauges (Zig's `resources.zig`), read on the collector tick, never on a
//! request thread. Resident memory is a level (last and peak); CPU is cumulative process
//! time whose per-interval increase becomes a rate. A platform without a source reports the
//! gauge as unavailable, never as zero.
//!
//! Zig read CPU time and the peak with `getrusage`. This crate has no `unsafe` and no libc
//! binding, so on Linux it reads `/proc/self/status` (`VmRSS`, `VmHWM`) and
//! `/proc/self/stat` (user and system time in clock ticks of 1/100 s, the fixed `USER_HZ`
//! of the Linux ABI); CPU time therefore has a resolution of 10 ms.

use std::fs::File;
use std::io::Read;

/// The longest proc file read, in bytes.
const READ_LIMIT: usize = 4096;
/// Milliseconds per clock tick of `/proc/self/stat` (`USER_HZ` = 100).
const TICK_MS: u64 = 10;

/// One reading of the gauges.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Sample {
    /// Resident memory now, in KiB.
    pub rss_kib: Option<u64>,
    /// Peak resident memory, in KiB.
    pub rss_max_kib: Option<u64>,
    /// Cumulative user and system CPU time, in milliseconds.
    pub cpu_ms: Option<u64>,
}

/// Reads the gauges of this process; fields without a source are `None`.
pub(crate) fn sample() -> Sample {
    let mut buffer = [0u8; READ_LIMIT];
    let (rss_kib, rss_max_kib) = match read("/proc/self/status", &mut buffer) {
        Some(text) => (parse_kib(text, "VmRSS:"), parse_kib(text, "VmHWM:")),
        None => (None, None),
    };
    let cpu_ms = read("/proc/self/stat", &mut buffer).and_then(parse_cpu_ms);
    Sample { rss_kib, rss_max_kib, cpu_ms }
}

/// Reads at most [`READ_LIMIT`] bytes of `path` into `buffer`; `None` when the file cannot
/// be read or is not UTF-8.
fn read<'b>(path: &str, buffer: &'b mut [u8; READ_LIMIT]) -> Option<&'b str> {
    let mut file = File::open(path).ok()?;
    let mut length = 0;
    while length < buffer.len() {
        let count = file.read(buffer.get_mut(length..)?).ok()?;
        if count == 0 {
            break;
        }
        length += count;
    }
    std::str::from_utf8(buffer.get(..length)?).ok()
}

/// Returns the value of the line starting with `label`, which must be a number of `kB`.
fn parse_kib(text: &str, label: &str) -> Option<u64> {
    let line = text.lines().find_map(|line| line.strip_prefix(label))?;
    let mut words = line.split_ascii_whitespace();
    let number = words.next()?;
    if words.next()? != "kB" {
        return None;
    }
    number.parse().ok()
}

/// Returns user plus system time of a `/proc/<pid>/stat` line in milliseconds. The command
/// name in parentheses may contain spaces, so fields are counted after its closing one:
/// `utime` and `stime` are the 12th and 13th fields there (fields 14 and 15 of the line).
fn parse_cpu_ms(text: &str) -> Option<u64> {
    let (_, rest) = text.rsplit_once(')')?;
    let mut fields = rest.split_ascii_whitespace().skip(11);
    let user: u64 = fields.next()?.parse().ok()?;
    let system: u64 = fields.next()?.parse().ok()?;
    user.checked_add(system)?.checked_mul(TICK_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    // resources.zig: "resource samples are monotonic in CPU time and parse the Linux status
    // line".
    #[test]
    fn samples_are_monotonic_and_the_status_lines_parse() {
        let first = sample();
        if cfg!(target_os = "linux") {
            assert!(first.rss_max_kib.unwrap() > 0);
            assert!(first.rss_kib.unwrap() > 0);
            assert!(sample().cpu_ms.unwrap() >= first.cpu_ms.unwrap());
        }
        let status = "VmPeak:\t9000 kB\nVmRSS:\t   5120 kB\n";
        assert_eq!(parse_kib(status, "VmRSS:"), Some(5120));
        assert_eq!(parse_kib("VmRSS: 5120 MB\n", "VmRSS:"), None);
        assert_eq!(parse_kib("VmSize: 1 kB\n", "VmRSS:"), None);
        let stat = "42 (a b) c) S 1 1 1 0 -1 4194560 100 0 0 0 7 3 0 0 20 0 1 0 5 0 0";
        assert_eq!(parse_cpu_ms(stat), Some(100));
        assert_eq!(parse_cpu_ms("42 (x) S 1"), None);
    }
}

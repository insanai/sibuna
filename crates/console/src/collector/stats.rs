//! Sliding sixty-second country windows (Zig's per-second buckets of `stats.zig` and
//! `incident_geo.zig`) and the ranking of countries into the snapshot's 32 slots.
//!
//! A window holds one bucket per second of the last minute, each with a count per country
//! code and a count of unknown origins. Samples are placed by their own time, so a sample
//! that arrives late still lands in its second, and one older than the window or stamped in
//! the future is counted separately instead.

use sibuna_console_protocol::{COUNTRY_SLOTS, CountryCount};
use sibuna_geoip::country::INDEX_COUNT;
use sibuna_geoip::{Country, Database, address};

/// Seconds a window covers.
pub(crate) const WINDOW_SECONDS: u64 = 60;
/// Buckets per window: one per second.
const BUCKETS: usize = WINDOW_SECONDS as usize;

/// Where a sample's second falls relative to now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Age {
    /// Within the last [`WINDOW_SECONDS`] seconds.
    Current,
    /// Older than the window.
    Expired,
    /// After now.
    Future,
}

/// Returns where `second` falls relative to `now`.
pub(crate) fn age(second: u64, now: u64) -> Age {
    if second > now {
        Age::Future
    } else if now - second >= WINDOW_SECONDS {
        Age::Expired
    } else {
        Age::Current
    }
}

/// Returns the country of the client address `ip` in `database`; `None` when no generation
/// is loaded, the address does not parse or no range holds it.
pub(crate) fn country_of(database: Option<&Database>, ip: &[u8]) -> Option<Country> {
    let address = address::parse_bytes(ip).ok()?;
    database?.lookup(address)
}

/// One second of a window.
#[derive(Clone, Debug)]
struct Bucket {
    second: u64,
    unknown: u64,
    countries: [u32; INDEX_COUNT],
}

impl Default for Bucket {
    fn default() -> Bucket {
        Bucket { second: 0, unknown: 0, countries: [0; INDEX_COUNT] }
    }
}

/// Counts by country over the last sixty seconds.
#[derive(Debug)]
pub(crate) struct CountryWindow {
    buckets: Box<[Bucket]>,
}

impl Default for CountryWindow {
    fn default() -> CountryWindow {
        CountryWindow { buckets: vec![Bucket::default(); BUCKETS].into_boxed_slice() }
    }
}

impl CountryWindow {
    /// Counts one sample of `second` (within the window) from `country`, or of unknown
    /// origin.
    pub(crate) fn add(&mut self, second: u64, country: Option<Country>) {
        // The remainder is below `BUCKETS`, the slice's length.
        let Some(bucket) = self.buckets.get_mut((second % WINDOW_SECONDS) as usize) else {
            return;
        };
        if bucket.second != second {
            *bucket = Bucket { second, ..Bucket::default() };
        }
        match country.and_then(|country| bucket.countries.get_mut(usize::from(country.index()))) {
            Some(count) => *count = count.saturating_add(1),
            None => bucket.unknown = bucket.unknown.saturating_add(1),
        }
    }

    /// Adds the counts of the window ending at `now` to `countries` and returns the count
    /// of unknown origin.
    pub(crate) fn sum(&self, now: u64, countries: &mut [u64; INDEX_COUNT]) -> u64 {
        let mut unknown = 0u64;
        for bucket in self.buckets.iter().filter(|bucket| age(bucket.second, now) == Age::Current)
        {
            unknown = unknown.saturating_add(bucket.unknown);
            for (total, &count) in countries.iter_mut().zip(&bucket.countries) {
                *total = total.saturating_add(u64::from(count));
            }
        }
        unknown
    }
}

/// The largest countries and the sum of the rest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ranked {
    /// The [`COUNTRY_SLOTS`] largest counts, largest first; empty slots are zero.
    pub top: [CountryCount; COUNTRY_SLOTS],
    /// The sum of the counts that did not fit.
    pub other: u64,
}

/// Ranks counts indexed by [`Country::index`] into the snapshot's slots: each count is
/// inserted by swapping it down the slots; whatever falls off the end goes to `other`.
pub(crate) fn rank(counts: &[u64; INDEX_COUNT]) -> Ranked {
    let mut result = Ranked { top: [CountryCount::default(); COUNTRY_SLOTS], other: 0 };
    for (index, &count) in counts.iter().enumerate().filter(|(_, count)| **count != 0) {
        // `index` is below 676, so both letters are within 'A'..='Z'.
        let first = u16::from(b'A') + (index / 26) as u16;
        let second = u16::from(b'A') + (index % 26) as u16;
        let mut candidate = CountryCount { code: first << 8 | second, samples: count };
        for entry in &mut result.top {
            if candidate.samples > entry.samples {
                std::mem::swap(&mut candidate, entry);
            }
        }
        result.other = result.other.saturating_add(candidate.samples);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranking_keeps_the_largest_countries_and_sums_the_rest() {
        let mut counts = [0u64; INDEX_COUNT];
        for (index, count) in counts.iter_mut().enumerate().take(40) {
            *count = index as u64 + 1;
        }
        let ranked = rank(&counts);
        assert_eq!(ranked.top[0], CountryCount { code: 0x424e, samples: 40 });
        assert_eq!(ranked.top[31].samples, 9);
        assert_eq!(ranked.other, (1..9).sum::<u64>());
        let us = Country::parse(b"US").unwrap();
        let mut window = CountryWindow::default();
        window.add(100, Some(us));
        window.add(100, None);
        window.add(160, Some(us));
        let mut totals = [0u64; INDEX_COUNT];
        assert_eq!(window.sum(160, &mut totals), 0);
        assert_eq!(totals[usize::from(us.index())], 1);
    }
}

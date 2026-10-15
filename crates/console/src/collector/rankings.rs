//! Current-minute rankings (Zig's `rankings.zig` and the page of `ranking_routes.zig`):
//! Space-Saving sketches of path prefixes and referring hosts, and exact histograms of
//! client families and statuses, per UTC minute of sampled traffic.
//!
//! Two minute slots let a late sample from the previous minute land in its own minute
//! without mixing intervals. A minute is handed to the archive journal once the whole
//! late-sample horizon (sixty seconds) after it has passed.

use sibuna_console_protocol::Text;
use sibuna_console_protocol::client_family::status_slot;
use sibuna_console_protocol::ranking_storage::Minute;
use sibuna_console_protocol::rankings::{Encoding, MAX_ROWS, Row};
use sibuna_console_protocol::space_saving::{Counter, order};
use sibuna_encoding::hex;
use sibuna_store::telemetry::Record;

/// The collector's two minute slots.
#[derive(Debug, Default)]
pub(crate) struct Rankings {
    minutes: [Minute; 2],
}

impl Rankings {
    /// Counts the sampled request `record`, whose second the caller checked is within the
    /// sixty-second horizon, in the slot of its minute; a slot holding an older minute is
    /// started afresh.
    pub(crate) fn add(&mut self, record: &Record) {
        let minute = record.second / 60;
        let slot = &mut self.minutes[(minute % 2) as usize];
        if slot.minute != Some(minute) {
            *slot = Minute {
                minute: Some(minute),
                first_second: record.second,
                last_second: record.second,
                ..Minute::default()
            };
        }
        slot.first_second = slot.first_second.min(record.second);
        slot.last_second = slot.last_second.max(record.second);
        if record.truncated {
            slot.truncated_records = slot.truncated_records.saturating_add(1);
        }
        // A refused key leaves the estimates intact; its loss is visible.
        if slot.paths.add(record.path()).is_err() {
            slot.rejected_records = slot.rejected_records.saturating_add(1);
        }
        let host = record.referer();
        if !host.is_empty() && slot.referrers.add(host).is_err() {
            slot.rejected_records = slot.rejected_records.saturating_add(1);
        }
        let families = &mut slot.families;
        // Labels outside the shared numbering count as unknown rather than being dropped.
        let os = usize::from(record.os);
        let os = if os < families.os.len() { os } else { 0 };
        families.os[os] = families.os[os].saturating_add(1);
        let browser = usize::from(record.browser);
        let browser = if browser < families.browser.len() { browser } else { 0 };
        families.browser[browser] = families.browser[browser].saturating_add(1);
        if let Some(count) = families.status.get_mut(status_slot(record.status)) {
            *count = count.saturating_add(1);
        }
    }

    /// Returns a copy of the minute that `second` falls in; an empty minute when no sample
    /// of it was counted.
    pub(crate) fn snapshot(&self, second: u64) -> Minute {
        let minute = second / 60;
        let slot = &self.minutes[(minute % 2) as usize];
        if slot.minute == Some(minute) {
            slot.clone()
        } else {
            Minute { minute: Some(minute), ..Minute::default() }
        }
    }

    /// Moves out one sealed minute: one whose whole late-sample horizon has passed at
    /// `now`; `None` when none has.
    pub(crate) fn take_closed(&mut self, now: u64) -> Option<Minute> {
        let current = now / 60;
        let slot = self.minutes.iter_mut().find(|slot| {
            slot.minute.is_some_and(|minute| minute < current && current - minute >= 2)
        })?;
        Some(std::mem::take(slot))
    }
}

/// Returns the first `limit` counters in export order as display rows; a key that is not
/// UTF-8 is written as hex.
pub(crate) fn leading<const N: usize>(counters: &[Counter<N>], limit: usize) -> Vec<Row> {
    let mut sorted = counters.to_vec();
    sorted.sort_by(order);
    sorted
        .iter()
        .take(limit.min(MAX_ROWS))
        .map(|counter| {
            let bytes = counter.key.as_bytes();
            let (key, encoding) = match std::str::from_utf8(bytes) {
                Ok(text) => (Text::new(text), Encoding::Utf8),
                Err(_) => (Text::from_string(hex::encode(bytes)), Encoding::Hex),
            };
            Row {
                // Keys are at most 128 bytes, so even their hex fits the row's 256.
                key: key.unwrap_or_default(),
                encoding,
                estimate: counter.estimate,
                error_bound: counter.error_bound,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use sibuna_console_protocol::client_family::{Browser, Os};
    use sibuna_store::telemetry::Sample;

    use super::*;
    use crate::collector::testing::sampled_record;

    fn record(second: u64) -> Record {
        sampled_record(Sample { second, path: b"/", ..Sample::default() })
    }

    fn sampled(rankings: &Rankings, second: u64) -> u64 {
        rankings.snapshot(second).paths.samples()
    }

    // rankings.zig: "late samples remain in their original minute and slot reuse drops old
    // populations".
    #[test]
    fn late_samples_stay_in_their_minute_and_reused_slots_drop_old_ones() {
        let mut rankings = Rankings::default();
        for second in [119, 120, 119, 180] {
            rankings.add(&record(second));
        }
        assert_eq!(sampled(&rankings, 119), 0);
        assert_eq!(sampled(&rankings, 120), 1);
        assert_eq!(sampled(&rankings, 180), 1);
        assert_eq!(sampled(&rankings, 240), 0);
    }

    // rankings.zig: "families and referring hosts are counted beside paths within the same
    // minute".
    #[test]
    fn families_and_referring_hosts_are_counted_beside_paths() {
        let mut rankings = Rankings::default();
        let mut sample = Sample {
            second: 120,
            path: b"/",
            status: 429,
            os: Os::Linux as u8,
            browser: Browser::Firefox as u8,
            referer: b"news.example.test",
            ..Sample::default()
        };
        rankings.add(&sampled_record(sample));
        sample.referer = b"";
        rankings.add(&sampled_record(sample));
        let minute = rankings.snapshot(120);
        assert_eq!(minute.families.os[Os::Linux as usize], 2);
        assert_eq!(minute.families.browser[Browser::Firefox as usize], 2);
        assert_eq!(minute.families.status[status_slot(429)], 2);
        assert_eq!(minute.referrers.samples(), 1);
        assert_eq!(minute.referrers.counters()[0].key.as_bytes(), b"news.example.test");
    }

    // stats.zig: "ranking minute seals only after the entire late-sample horizon has
    // expired".
    #[test]
    fn a_minute_seals_only_after_its_late_sample_horizon() {
        let mut rankings = Rankings::default();
        rankings.add(&record(119));
        assert!(rankings.take_closed(179).is_none());
        let minute = rankings.take_closed(180).unwrap();
        assert_eq!((minute.minute, minute.paths.samples()), (Some(1), 1));
        assert!(rankings.take_closed(180).is_none());
    }

    #[test]
    fn rows_follow_the_export_order_and_hex_encode_binary_keys() {
        let mut rankings = Rankings::default();
        for path in [&b"/a"[..], b"/b", b"/b", b"\xff\x00"] {
            rankings.add(&sampled_record(Sample { second: 120, path, ..Sample::default() }));
        }
        let minute = rankings.snapshot(120);
        let rows = leading(minute.paths.counters(), 12);
        assert_eq!(rows[0].key.as_str(), "/b");
        assert_eq!(rows[0].estimate, 2);
        let binary = rows.iter().find(|row| row.encoding == Encoding::Hex).unwrap();
        assert_eq!(binary.key.as_str(), "ff00");
        assert_eq!(leading(minute.paths.counters(), 1).len(), 1);
    }
}

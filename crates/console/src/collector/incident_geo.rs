//! The geography of committed incidents (Zig's `incident_geo.zig`): countries of the
//! findings the storage thread acknowledged in the last sixty seconds, by the finding's own
//! time, so a slow write never turns an old finding into a current one.

use sibuna_console_protocol::incident_geo::Snapshot;
use sibuna_geoip::Database;
use sibuna_geoip::country::INDEX_COUNT;
use sibuna_store::incidents::Record;

use super::stats::{Age, CountryWindow, age, country_of, rank};

/// The rolling window of finding countries and its loss counters.
#[derive(Debug, Default)]
pub(crate) struct IncidentWindow {
    started_at: u64,
    expired: u64,
    future: u64,
    dropped: u64,
    window: CountryWindow,
}

impl IncidentWindow {
    /// Returns an empty window whose observation started at `started_at` (Unix seconds).
    pub(crate) fn new(started_at: u64) -> IncidentWindow {
        IncidentWindow { started_at, ..IncidentWindow::default() }
    }

    /// Counts the committed finding `record` at `now` with the country `database` gives its
    /// address; an unparsable or unmapped address counts as unknown.
    pub(crate) fn add(&mut self, record: &Record, now: u64, database: Option<&Database>) {
        match age(record.second, now) {
            Age::Future => self.future = self.future.saturating_add(1),
            Age::Expired => self.expired = self.expired.saturating_add(1),
            Age::Current => {
                self.window.add(record.second, country_of(database, record.ip()));
            }
        }
    }

    /// Records the feed's loss counter.
    pub(crate) fn set_dropped(&mut self, dropped: u64) {
        self.dropped = dropped;
    }

    /// Returns the window ending at `now`.
    pub(crate) fn snapshot(&self, now: u64) -> Snapshot {
        let mut counts = [0u64; INDEX_COUNT];
        let unknown = self.window.sum(now, &mut counts);
        let ranked = rank(&counts);
        Snapshot {
            started_at: self.started_at,
            countries: ranked.top,
            other: ranked.other,
            unknown,
            dropped: self.dropped,
            expired: self.expired,
            future: self.future,
            ..Snapshot::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use sibuna_geoip::{Loader, Provider};
    use sibuna_store::incidents::ConsoleIncidents;
    use std::sync::atomic::Ordering;

    use super::*;

    /// A generation mapping 8.8.8.0/24 to the United States.
    pub(crate) fn database() -> Database {
        let mut loader = Loader::new();
        loader.feed(b"8.8.8.0,8.8.8.255,US\n").unwrap();
        loader.end_file().unwrap();
        loader.finish(Provider::Dbip, "2026-09").unwrap()
    }

    // incident_geo.zig: "incident geography uses event time, keeps unknowns and expires
    // without subscribers".
    #[test]
    fn findings_use_event_time_keep_unknowns_and_expire() {
        let mut feed = ConsoleIncidents::new();
        feed.enabled.store(true, Ordering::Release);
        let mut window = IncidentWindow::new(90);
        let database = database();
        for second in [39, 40, 41, 100, 101] {
            feed.publish(second, b"8.8.8.8");
        }
        feed.publish(100, b"::1");
        feed.publish(100, b"invalid");
        while let Some(record) = feed.queue.pop() {
            window.add(&record, 100, Some(&database));
        }
        let snapshot = window.snapshot(100);
        assert_eq!(snapshot.started_at, 90);
        assert_eq!(snapshot.countries[0].samples, 2);
        assert_eq!(snapshot.countries[0].code, 0x5553);
        assert_eq!((snapshot.unknown, snapshot.expired, snapshot.future), (2, 2, 1));
        assert_eq!(window.snapshot(101).countries[0].samples, 1);
        assert_eq!(window.snapshot(160).countries[0].samples, 0);
        assert_eq!(window.snapshot(160).unknown, 0);
    }
}

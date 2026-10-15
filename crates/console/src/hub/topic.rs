//! A topic's state and journal (Zig's `topic_store.zig`).
//!
//! A state topic (`stats`, `nodes`, `policy`, `challenges`) keeps its current view, a JSON
//! object of at most [`SNAPSHOT_BYTES`]; each new view is journaled as the delta from the
//! previous one ([`json_delta`]). A row topic (`events`, `audit`) journals each new row and
//! keeps the 64 most recent ones for snapshots, with the coverage of its feed: which ids of
//! which issuers it has read, and how many were missing. Every journal entry is split into
//! fragments of at most [`FRAGMENT_BYTES`] bytes, one ring record each, numbered by part.
//!
//! The feeder thread publishes; the hub's fan-out reads. Both hold the hub's topic lock.
//!
//! [`FRAGMENT_BYTES`]: sibuna_console_protocol::subscriptions::FRAGMENT_BYTES

use std::collections::VecDeque;
use std::fmt::{self, Write};

use sibuna_console_protocol::codec::{Encode, counter_field, field, to_json};
use sibuna_console_protocol::events::country;
use sibuna_console_protocol::nodes::MAX_MEMBERS;
use sibuna_console_protocol::security::classify;
use sibuna_console_protocol::subscription_feed::{Page, RECENT_IDS, Row};
use sibuna_console_protocol::subscriptions::{
    Args, RECORD_BYTES, SNAPSHOT_BYTES, Topic, fragment_length,
};
use sibuna_console_protocol::{Text, json_delta};
use sibuna_json::Writer;

use super::ring::{Ring, RingError};

/// The view of a topic that has no state yet.
pub const UNAVAILABLE: &str = "{\"available\":false}";

/// Why a publication or snapshot failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TopicError {
    /// A view, row or delta exceeds its bound, or is not a JSON object.
    TooLarge,
    /// The topic's update numbers or ring sequence are exhausted.
    SequenceExhausted,
    /// The feed names more issuers than a cluster has members.
    TooManySources,
}

impl fmt::Display for TopicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TopicError::TooLarge => "a topic view exceeds its bound",
            TopicError::SequenceExhausted => "the topic's sequence numbers are exhausted",
            TopicError::TooManySources => "the feed has more sources than cluster members",
        })
    }
}

impl std::error::Error for TopicError {}

impl From<RingError> for TopicError {
    fn from(error: RingError) -> TopicError {
        match error {
            RingError::TooLarge => TopicError::TooLarge,
            RingError::SequenceExhausted => TopicError::SequenceExhausted,
        }
    }
}

/// What a journal entry is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A delta of the topic's state.
    #[default]
    Patch,
    /// A new row of a row topic.
    Row,
    /// Summaries were lost; subscribers must take a new snapshot.
    Gap,
}

/// A ring record's routing data: its entry and fragment, and the row fields filters read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Metadata {
    /// What the entry is.
    pub kind: Kind,
    /// The entry's update number within the topic.
    pub update: u64,
    /// The fragment's part, from 0.
    pub part: u16,
    /// The entry's fragment count.
    pub parts: u16,
    /// An incident's node.
    pub node: u32,
    /// An audit row's actor.
    pub actor: u64,
    /// An incident's category.
    pub category: Text<32>,
    /// An incident's country label: the code, `unknown` or `not_recorded`.
    pub country: country::Filter,
    /// An incident's client address.
    pub ip: Text<48>,
    /// An incident's path.
    pub path: Text<128>,
    /// An audit row's action.
    pub action: Text<48>,
}

impl Metadata {
    /// Returns true when the row this metadata describes passes the filter `args`.
    pub fn matches(&self, args: &Args) -> bool {
        let equal = |filter: &str, value: &str| filter.is_empty() || filter == value;
        args.node.is_none_or(|node| node == self.node)
            && args.actor.is_none_or(|actor| actor == self.actor)
            && args.module.is_none_or(|module| module == classify(self.category.as_str()))
            && equal(args.category.as_str(), self.category.as_str())
            && equal(args.country.as_str(), self.country.as_str())
            && equal(args.ip.as_str(), self.ip.as_str())
            && equal(args.action.as_str(), self.action.as_str())
            && self.path.as_str().starts_with(args.path_prefix.as_str())
    }

    /// Returns the routing data of `row`.
    fn of(row: &Row) -> Metadata {
        let mut metadata = Metadata { kind: Kind::Row, ..Metadata::default() };
        match row {
            Row::Events(event) => {
                let geography = &event.geography;
                let absent = if geography.recorded { "unknown" } else { "not_recorded" };
                let code =
                    if geography.code.is_empty() { absent } else { geography.code.as_str() };
                metadata.node = event.node;
                metadata.ip = event.ip.clone();
                metadata.path = event.path.clone();
                metadata.category = event.category.clone();
                metadata.country = Text::new(code).unwrap_or_default();
            }
            Row::Audit(audit) => {
                metadata.actor = audit.actor;
                metadata.action = audit.action.clone();
            }
        }
        metadata
    }
}

/// How far the feed of one issuer has been read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Watermark {
    /// The issuing node; 0 for audit.
    pub node: u32,
    /// The last id read.
    pub id: u64,
    /// When storage read it, in Unix seconds.
    pub observed_at: u64,
    /// Incidents the producer dropped, for this node's own feed.
    pub producer_dropped: Option<u64>,
    /// The producer's boot as hex, with `producer_dropped`.
    pub producer_boot: Option<Text<32>>,
    /// When the replica was last observed, in Unix seconds.
    pub replica_observed_at: u64,
    /// The replica had a quorum.
    pub replica_quorum: bool,
}

impl Encode for Watermark {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "node", &self.node)?;
        counter_field(json, "id", self.id)?;
        counter_field(json, "observed_at", self.observed_at)?;
        json.key("producer_dropped")?;
        sibuna_console_protocol::codec::optional_counter(json, self.producer_dropped)?;
        field(json, "producer_boot", &self.producer_boot)?;
        counter_field(json, "replica_observed_at", self.replica_observed_at)?;
        field(json, "replica_quorum", &self.replica_quorum)?;
        json.end_object()
    }
}

/// A row topic's coverage, as its snapshots and coverage patches carry it.
struct Coverage<'s>(&'s Store);

impl Encode for Coverage<'_> {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        let store = self.0;
        json.begin_object()?;
        field(json, "available", &store.available)?;
        counter_field(json, "observed_at", store.observed_at)?;
        counter_field(json, "missing_ids", store.missing_ids)?;
        field(json, "retained_summaries", &(store.recent.len() as u64))?;
        field(json, "summary_limit", &(RECENT_IDS as u64))?;
        field(json, "expected_sources", &store.expected_sources)?;
        field(json, "sources", &store.sources)?;
        json.end_object()
    }
}

/// A sink that refuses to grow `out` beyond `limit` bytes.
pub struct Bounded<'o> {
    /// The text written so far.
    pub out: &'o mut String,
    /// The largest length `out` may reach.
    pub limit: usize,
}

impl Write for Bounded<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if self.out.len() + text.len() > self.limit {
            return Err(fmt::Error);
        }
        self.out.push_str(text);
        Ok(())
    }
}

/// One topic's state, recent rows, coverage and journal.
#[derive(Clone, Debug)]
pub struct Store {
    /// The journal of deltas and rows.
    pub ring: Ring<Metadata>,
    /// The current view of a state topic.
    current: String,
    /// The most recent rows of a row topic, newest last, with their routing data.
    recent: VecDeque<(Metadata, String)>,
    /// The last update number.
    pub update: u64,
    /// A state was published, or a feed page read.
    pub available: bool,
    observed_at: u64,
    missing_ids: u64,
    sources: Vec<Watermark>,
    /// The issuers the feed should cover (the cluster's members, for `events`).
    pub expected_sources: u8,
}

impl Default for Store {
    fn default() -> Store {
        Store {
            ring: Ring::default(),
            current: String::new(),
            recent: VecDeque::new(),
            update: 0,
            available: false,
            observed_at: 0,
            missing_ids: 0,
            sources: Vec::new(),
            expected_sources: 1,
        }
    }
}

impl Store {
    /// Makes `view`, a JSON object of at most [`SNAPSHOT_BYTES`], the topic's state and
    /// journals the delta from the previous state when anything changed.
    ///
    /// Fails with [`TopicError::TooLarge`] for a larger view, one that is not a JSON object,
    /// or a delta over [`SNAPSHOT_BYTES`], and with [`TopicError::SequenceExhausted`].
    pub fn state(&mut self, view: &str) -> Result<(), TopicError> {
        if view.len() > SNAPSHOT_BYTES {
            return Err(TopicError::TooLarge);
        }
        let previous = if self.available { self.current.as_str() } else { UNAVAILABLE };
        let mut delta = String::new();
        let mut sink = Bounded { out: &mut delta, limit: SNAPSHOT_BYTES };
        let changed = json_delta::write(previous.as_bytes(), view.as_bytes(), &mut sink)
            .map_err(|_| TopicError::TooLarge)?;
        if changed {
            self.publish(Metadata::default(), &delta)?;
        }
        view.clone_into(&mut self.current);
        self.available = true;
        Ok(())
    }

    /// Journals `row` and keeps it among the 64 most recent.
    ///
    /// Fails with [`TopicError::TooLarge`] for a row longer than a ring record, and with
    /// [`TopicError::SequenceExhausted`].
    pub fn row(&mut self, row: &Row) -> Result<(), TopicError> {
        let text = match row {
            Row::Events(event) => to_json(event),
            Row::Audit(audit) => to_json(audit),
        };
        if text.len() > RECORD_BYTES {
            return Err(TopicError::TooLarge);
        }
        let metadata = Metadata::of(row);
        self.publish(metadata.clone(), &text)?;
        if self.recent.len() == RECENT_IDS {
            self.recent.pop_front();
        }
        self.recent.push_back((metadata, text));
        Ok(())
    }

    /// Records that the feed `page` was read: journals a gap when ids were missing, moves
    /// the issuer's watermark and journals the new coverage.
    ///
    /// Fails with [`TopicError::TooManySources`] past [`MAX_MEMBERS`] issuers, and like
    /// [`Store::state`].
    pub fn advance(&mut self, page: &Page) -> Result<(), TopicError> {
        if page.missing_ids != 0 {
            self.missing_ids = self.missing_ids.saturating_add(page.missing_ids);
            self.publish(Metadata { kind: Kind::Gap, ..Metadata::default() }, "{}")?;
        }
        let index = match self.sources.iter().position(|source| source.node == page.node) {
            Some(index) => index,
            None if self.sources.len() == MAX_MEMBERS => return Err(TopicError::TooManySources),
            None => {
                self.sources.push(Watermark::default());
                self.sources.len() - 1
            }
        };
        let dropped = page.producer_dropped;
        self.sources[index] = Watermark {
            node: page.node,
            id: page.next,
            observed_at: page.observed_at,
            producer_dropped: dropped,
            producer_boot: dropped.map(|_| page.producer_boot.clone()),
            replica_observed_at: page.replica_observed_at,
            replica_quorum: page.replica_quorum,
        };
        self.observed_at = page.observed_at;
        self.available = true;
        let mut patch = String::from("{\"set\":{\"coverage\":");
        patch.push_str(&to_json(&Coverage(self)));
        patch.push_str("},\"remove\":[]}");
        self.publish(Metadata::default(), &patch)
    }

    /// Writes the snapshot of `topic` filtered by `args` into `out`: the recent matching
    /// rows with the coverage for a row topic, otherwise the current state.
    ///
    /// Fails with [`TopicError::TooLarge`] when `out` would pass [`SNAPSHOT_BYTES`].
    pub fn snapshot(&self, topic: Topic, args: &Args, out: &mut String) -> Result<(), TopicError> {
        if matches!(topic, Topic::Events | Topic::Audit) {
            return self.rows(args, out);
        }
        let view = if self.available { self.current.as_str() } else { UNAVAILABLE };
        Bounded { out, limit: SNAPSHOT_BYTES }.write_str(view).map_err(|_| TopicError::TooLarge)
    }

    /// Splits `bytes` into fragments and journals them as the next update.
    fn publish(&mut self, metadata: Metadata, bytes: &str) -> Result<(), TopicError> {
        let update = self.update.checked_add(1).ok_or(TopicError::SequenceExhausted)?;
        let parts = fragments(bytes).count();
        let parts = u16::try_from(parts).map_err(|_| TopicError::TooLarge)?;
        self.update = update;
        for (part, fragment) in (0..parts).zip(fragments(bytes)) {
            let entry = Metadata { update, part, parts, ..metadata.clone() };
            self.ring.publish(entry, fragment)?;
        }
        Ok(())
    }

    /// Writes `{"rows":[...],"coverage":{...}}`: the recent rows matching `args`, newest
    /// first, while a row and the closing coverage still fit.
    fn rows(&self, args: &Args, out: &mut String) -> Result<(), TopicError> {
        out.push_str("{\"rows\":[");
        let mut count = 0;
        for (metadata, text) in self.recent.iter().rev() {
            if !metadata.matches(args) {
                continue;
            }
            // Zig reserved 2 KiB for the coverage behind the rows.
            if out.len() + text.len() + 2048 > SNAPSHOT_BYTES {
                break;
            }
            if count != 0 {
                out.push(',');
            }
            out.push_str(text);
            count += 1;
        }
        out.push_str("],\"coverage\":");
        out.push_str(&to_json(&Coverage(self)));
        out.push('}');
        if out.len() > SNAPSHOT_BYTES {
            return Err(TopicError::TooLarge);
        }
        Ok(())
    }
}

/// Returns the fragments of `text`: each at most `FRAGMENT_BYTES` bytes and ending on a
/// character boundary.
pub fn fragments(text: &str) -> impl Iterator<Item = &str> {
    let mut rest = text;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let (fragment, tail) = rest.split_at(fragment_length(rest));
        rest = tail;
        Some(fragment)
    })
}

#[cfg(test)]
mod tests {
    use sibuna_console_protocol::audit;
    use sibuna_console_protocol::codec::from_json;
    use sibuna_console_protocol::subscription_feed::Event;
    use sibuna_json::Value;

    use super::*;

    // Port of topic_store.zig "topic snapshots bound escaped summaries and keep filtered
    // node probes consistent" (its node half is the hub's, which keeps the structured
    // nodes view; see the hub's tests).
    #[test]
    fn topic_snapshots_bound_escaped_summaries() {
        let mut store = Store::default();
        for id in 1..=64 {
            let row = audit::Row {
                id,
                action: Text::new(&"\u{1}".repeat(48)).unwrap(),
                target: Some(Text::new(&"\u{1}".repeat(128)).unwrap()),
                ..audit::Row::default()
            };
            store.row(&Row::Audit(row)).unwrap();
        }
        let mut out = String::new();
        store.snapshot(Topic::Audit, &Args::default(), &mut out).unwrap();
        assert!(out.len() <= SNAPSHOT_BYTES);
        let value = sibuna_json::parse(out.as_bytes()).unwrap();
        let rows = value.as_object().unwrap().get("rows").and_then(Value::as_array).unwrap();
        assert!(!rows.is_empty() && rows.len() < 64);
        let newest = rows[0].as_object().unwrap().get("id").unwrap();
        assert_eq!(newest.as_number().unwrap().as_str(), "64");
    }

    #[test]
    fn states_journal_deltas_in_fragments_and_rows_carry_their_filters() {
        let mut store = Store::default();
        let mut out = String::new();
        store.snapshot(Topic::Stats, &Args::default(), &mut out).unwrap();
        assert_eq!(out, UNAVAILABLE);
        let big = format!("{{\"text\":\"{}\"}}", "x".repeat(1500));
        store.state(&big).unwrap();
        // The delta {"set":{"text":...},"remove":["available"]} has 1,542 bytes.
        assert_eq!(store.ring.watermark(), 4);
        store.state(&big).unwrap();
        assert_eq!(store.ring.watermark(), 4, "an unchanged view journals nothing");
        assert_eq!(store.state("[1]"), Err(TopicError::TooLarge));
        let event = Event {
            id: (2 << 40) + 1,
            node: 2,
            category: Text::new("honeypot").unwrap(),
            ..Event::default()
        };
        let mut events = Store::default();
        events.row(&Row::Events(event)).unwrap();
        let only = |node| Args { node: Some(node), ..Args::default() };
        let (metadata, _) = events.recent.back().unwrap();
        assert!(metadata.matches(&only(2)) && !metadata.matches(&only(1)));
        assert_eq!(metadata.country, "not_recorded");
        let page = Page { node: 2, next: (2 << 40) + 3, missing_ids: 1, ..Page::default() };
        events.advance(&page).unwrap();
        let mut out = String::new();
        events.snapshot(Topic::Events, &Args::default(), &mut out).unwrap();
        let coverage = r#""coverage":{"available":true,"observed_at":0,"missing_ids":1,"#;
        assert!(out.contains(coverage), "{out}");
        assert!(from_json::<Event>(to_json(&Event::default()).as_bytes()).is_ok());
    }
}

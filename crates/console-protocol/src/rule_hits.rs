//! Rule identities and per-minute hit intervals, independent of engines, sockets and
//! database handles.

use std::fmt;

use crate::error::MAX_I64;
use crate::text::Text;

/// The most rules one engine generation counts.
pub const MAX_RULES: usize = 128;
/// Observations per storage step.
pub const BATCH_ROWS: usize = 8;

/// A rule's stable key.
pub type Key = Text<160>;
/// A rule's display name.
pub type Name = Text<128>;

/// An interval whose fields are inconsistent or out of range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InvalidInterval;

impl fmt::Display for InvalidInterval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the rule-hit interval is inconsistent or out of range")
    }
}

impl std::error::Error for InvalidInterval {}

/// A rule's key and name.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Identity {
    /// The stable key.
    pub key: Key,
    /// The display name.
    pub name: Name,
}

/// A moment on both clocks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Clock {
    /// UTC seconds.
    pub utc: u64,
    /// Monotonic milliseconds.
    pub ms: u64,
}

/// One immutable engine generation and the rules its counters belong to.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Generation {
    /// The node.
    pub node: u32,
    /// The node's boot id.
    pub boot: [u8; 16],
    /// The generation number within the boot.
    pub number: u64,
    /// The policy revision it was built from.
    pub revision: u64,
    /// When it was published.
    pub born: Clock,
    /// At most [`MAX_RULES`] rules, in match-index order.
    pub rules: Vec<Identity>,
}

/// One minute interval of one generation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Span {
    /// The node.
    pub node: u32,
    /// The node's boot id.
    pub boot: [u8; 16],
    /// The generation number.
    pub generation: u64,
    /// The policy revision.
    pub revision: u64,
    /// The interval's sequence within the boot.
    pub sequence: u64,
    /// The UTC minute index the interval ends in.
    pub minute: u64,
    /// The interval's start, in UTC seconds.
    pub utc_start: u64,
    /// The interval's end, in UTC seconds.
    pub utc_end: u64,
    /// The interval's start, in monotonic milliseconds.
    pub start_ms: u64,
    /// The interval's end, in monotonic milliseconds.
    pub end_ms: u64,
    /// Milliseconds observed.
    pub observed_ms: u64,
    /// Sampler observations.
    pub observations: u32,
    /// Gap-free and observed for 59 to 61 seconds.
    pub complete: bool,
    /// The collection was interrupted.
    pub gap: bool,
    /// Observations not confirmed as stored, at the time of this one.
    pub unconfirmed: u64,
}

impl Span {
    /// Checks the interval's identity and arithmetic.
    ///
    /// # Errors
    ///
    /// [`InvalidInterval`] for a zero node, generation or sequence, an oversized value, an
    /// empty or inconsistent interval, a missing boot, or a complete interval that has a
    /// gap or was not observed for 59 to 61 seconds.
    pub fn validate(&self) -> Result<(), InvalidInterval> {
        let invalid = self.node == 0
            || self.generation == 0
            || self.sequence == 0
            || self.revision > MAX_I64
            || self.sequence > MAX_I64
            || self.generation > MAX_I64
            || self.utc_end > MAX_I64
            || self.end_ms > MAX_I64
            || self.end_ms <= self.start_ms
            || self.utc_start > self.utc_end
            || self.observed_ms != self.end_ms - self.start_ms
            || self.minute != self.utc_end / 60
            || self.observations == 0
            || self.boot == [0; 16]
            || (self.complete && (self.gap || !(59_000..=61_000).contains(&self.observed_ms)));
        if invalid { Err(InvalidInterval) } else { Ok(()) }
    }
}

/// One rule's hits in a frame; `None` when the counter is unavailable.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Entry {
    /// The rule.
    pub identity: Identity,
    /// Its hits.
    pub hits: Option<u64>,
}

impl Default for Entry {
    fn default() -> Entry {
        Entry { identity: Identity::default(), hits: Some(0) }
    }
}

/// One interval's hits for every rule of a generation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Frame {
    /// The interval.
    pub span: Span,
    /// At most [`MAX_RULES`] entries.
    pub entries: Vec<Entry>,
}

/// The rule-hit journal's health.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Status {
    /// Frames waiting to be stored.
    pub pending: u32,
    /// Frames confirmed as stored.
    pub confirmed: u64,
    /// Frames not confirmed.
    pub unconfirmed: u64,
    /// The last stored interval end, in UTC seconds.
    pub last_stored_utc: u64,
    /// Clock resets observed.
    pub clock_resets: u64,
    /// The pending frames overflowed.
    pub overflow: bool,
}

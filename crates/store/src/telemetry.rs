//! Allocation-free producers of console telemetry: exact outcome counters and sampled
//! request records.
//!
//! Connection threads count every request outcome exactly, in striped counters so that
//! they do not contend on one cache line, and offer one request in 64 as a sample to a
//! bounded queue that the console collector drains. A full queue drops the sample and
//! counts the loss; it never blocks a request.
//!
//! Each thread owns its sampling state and its stripe choice in thread-local cells, set once
//! by [`seed`] when a connection thread starts.

use std::cell::Cell;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::challenge_metrics::{Algorithm, Cause, Metrics};
use crate::ring::BoundedQueue;

/// The number of counter stripes.
pub const STRIPES: usize = 16;
/// The capacity of each sample queue.
pub const QUEUE_CAPACITY: usize = 4096;
/// The longest address a record keeps.
pub const IP_CAPACITY: usize = 48;
/// The longest path a record keeps.
pub const PATH_CAPACITY: usize = 128;
/// The longest referring host a record keeps.
pub const REFERER_CAPACITY: usize = 24;

/// The multiplier of xorshift64*.
const XORSHIFT_STAR: u64 = 2_685_821_657_736_338_717;

thread_local! {
    /// The xorshift64* state of this thread's sampler; never zero.
    static RANDOM_STATE: Cell<u64> = const { Cell::new(1) };
    /// The counter stripe this thread writes; below `STRIPES`.
    static STRIPE: Cell<usize> = const { Cell::new(0) };
}

/// Seeds this thread's sampler and chooses its counter stripe from `value`.
///
/// Called once when a connection thread starts, outside request processing; a zero
/// `value` is replaced by one, since xorshift has a fixed point at zero.
pub fn seed(value: u64) {
    RANDOM_STATE.set(value.max(1));
    STRIPE.set((value % STRIPES as u64) as usize);
}

/// Returns whether to sample the current request, with probability 1/64.
///
/// Advances this thread's xorshift64* state, so no shared sampling counter is contended.
/// Callers decide before doing any per-sample work.
pub fn selected() -> bool {
    let mut x = RANDOM_STATE.get();
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    RANDOM_STATE.set(x);
    x.wrapping_mul(XORSHIFT_STAR) & 63 == 0
}

/// Returns this thread's counter stripe, below [`STRIPES`].
pub(crate) fn stripe() -> usize {
    STRIPE.get()
}

/// How the daemon answered a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Outcome {
    /// Forwarded to the origin.
    Admitted = 0,
    /// Answered with a challenge.
    Challenged,
    /// Refused by policy.
    Denied,
    /// Refused because the address is banned.
    Banned,
    /// Refused by a rate limit.
    RateLimited,
    /// Anything else, such as a malformed request.
    Other,
}

impl Outcome {
    /// Every outcome, in numbering order.
    pub const ALL: [Outcome; 6] = [
        Outcome::Admitted,
        Outcome::Challenged,
        Outcome::Denied,
        Outcome::Banned,
        Outcome::RateLimited,
        Outcome::Other,
    ];
}

/// A sum of the exact counters.
///
/// The counters are read one after another with relaxed loads, so this is a bounded
/// observation, not a simultaneous snapshot of all counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    /// Requests forwarded to the origin.
    pub admitted: u64,
    /// Requests answered with a challenge.
    pub challenged: u64,
    /// Requests refused by policy.
    pub denied: u64,
    /// Requests refused for a banned address.
    pub banned: u64,
    /// Requests refused by a rate limit.
    pub rate_limited: u64,
    /// Other requests.
    pub other: u64,
    /// Origin responses with a 4xx status.
    pub origin_4xx: u64,
    /// Origin responses with a 5xx status.
    pub origin_5xx: u64,
}

impl Totals {
    /// Returns the number of requests: the sum of the six outcomes, wrapping.
    pub fn requests(&self) -> u64 {
        [self.admitted, self.challenged, self.denied, self.banned, self.rate_limited]
            .into_iter()
            .fold(self.other, u64::wrapping_add)
    }

    /// Returns the count of `outcome`.
    pub fn outcome(&self, outcome: Outcome) -> u64 {
        match outcome {
            Outcome::Admitted => self.admitted,
            Outcome::Challenged => self.challenged,
            Outcome::Denied => self.denied,
            Outcome::Banned => self.banned,
            Outcome::RateLimited => self.rate_limited,
            Outcome::Other => self.other,
        }
    }
}

/// Copies at most `N` bytes of `text` into a zeroed array; returns the array, the stored
/// length and whether `text` was cut.
fn truncated<const N: usize>(text: &[u8]) -> ([u8; N], u8, bool) {
    let mut out = [0u8; N];
    let len = text.len().min(N);
    out[..len].copy_from_slice(&text[..len]);
    // Every capacity here is below 256, so the length fits in `u8`.
    (out, len as u8, text.len() > N)
}

/// One sampled request, copied into fixed arrays; at most 256 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    /// The request time in seconds.
    pub second: u64,
    /// How the daemon answered.
    pub outcome: Outcome,
    /// Whether the address, path or referring host was cut to fit.
    pub truncated: bool,
    /// The local status selected, the origin status observed, or zero when unknown.
    pub status: u16,
    /// The client operating-system family label (the console protocol's numbering),
    /// classified from the full User-Agent at sample time; the agent itself is not kept.
    pub os: u8,
    /// The client browser family label, as `os`.
    pub browser: u8,
    ip_len: u8,
    path_len: u8,
    referer_len: u8,
    ip: [u8; IP_CAPACITY],
    path: [u8; PATH_CAPACITY],
    referer: [u8; REFERER_CAPACITY],
}

const _: () = assert!(size_of::<Record>() <= 256);

impl Record {
    /// Returns the client address, at most [`IP_CAPACITY`] bytes.
    pub fn ip(&self) -> &[u8] {
        self.ip.get(..usize::from(self.ip_len)).unwrap_or(&self.ip)
    }

    /// Returns the request path, at most [`PATH_CAPACITY`] bytes.
    pub fn path(&self) -> &[u8] {
        self.path.get(..usize::from(self.path_len)).unwrap_or(&self.path)
    }

    /// Returns the referring host (never a path or query), at most [`REFERER_CAPACITY`]
    /// bytes.
    pub fn referer(&self) -> &[u8] {
        self.referer.get(..usize::from(self.referer_len)).unwrap_or(&self.referer)
    }
}

/// What the request path knows about a sampled request; borrowed for the copy.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sample<'a> {
    /// The request time in seconds.
    pub second: u64,
    /// The client address.
    pub ip: &'a [u8],
    /// The request path.
    pub path: &'a [u8],
    /// The referring host only; empty when absent.
    pub referer: &'a [u8],
    /// The selected or observed status, zero when unknown.
    pub status: u16,
    /// The operating-system family label.
    pub os: u8,
    /// The browser family label.
    pub browser: u8,
}

/// What happened to a challenge, in the console protocol's numbering.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum ChallengeOutcome {
    /// A challenge was issued.
    #[default]
    Issued = 0,
    /// A solution was accepted.
    Accepted = 1,
    /// A submission was refused.
    Rejected = 2,
}

/// One challenge event: issued, accepted or refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChallengeRecord {
    /// The event time in seconds.
    pub second: u64,
    /// The reported solve time of an accepted solution, when known and valid.
    pub duration_ms: Option<u32>,
    /// What happened.
    pub outcome: ChallengeOutcome,
    /// Why a submission was refused; `None` for other outcomes.
    pub cause: Option<Cause>,
    /// The challenge algorithm (hashcash for a refusal before it is known).
    pub algorithm: Algorithm,
    /// The difficulty parameter.
    pub parameter: u8,
    /// The number of PoSW openings; zero for hashcash.
    pub openings: u8,
    ip_len: u8,
    ip: [u8; IP_CAPACITY],
}

impl Default for ChallengeRecord {
    fn default() -> Self {
        Self {
            second: 0,
            duration_ms: None,
            outcome: ChallengeOutcome::Issued,
            cause: None,
            algorithm: Algorithm::Hashcash,
            parameter: 0,
            openings: 0,
            ip_len: 0,
            ip: [0; IP_CAPACITY],
        }
    }
}

impl ChallengeRecord {
    /// Stores the client address, cut to [`IP_CAPACITY`] bytes.
    pub fn set_ip(&mut self, ip: &[u8]) {
        (self.ip, self.ip_len, _) = truncated(ip);
    }

    /// Returns the client address.
    pub fn ip(&self) -> &[u8] {
        self.ip.get(..usize::from(self.ip_len)).unwrap_or(&self.ip)
    }
}

/// One cache line of exact counters for one group of connection threads.
///
/// Every counter is a relaxed atomic: each is an independent monotonic count.
#[derive(Debug, Default)]
#[repr(C, align(64))]
struct Stripe {
    admitted: AtomicU64,
    challenged: AtomicU64,
    denied: AtomicU64,
    banned: AtomicU64,
    rate_limited: AtomicU64,
    other: AtomicU64,
    origin_4xx: AtomicU64,
    origin_5xx: AtomicU64,
}

const _: () = assert!(size_of::<Stripe>() == 64);

impl Stripe {
    fn outcome(&self, outcome: Outcome) -> &AtomicU64 {
        match outcome {
            Outcome::Admitted => &self.admitted,
            Outcome::Challenged => &self.challenged,
            Outcome::Denied => &self.denied,
            Outcome::Banned => &self.banned,
            Outcome::RateLimited => &self.rate_limited,
            Outcome::Other => &self.other,
        }
    }
}

/// The console's telemetry producers: exact counters, two bounded sample queues and the
/// challenge counters. Shared by reference between connection threads and the collector.
///
/// Construct it once at startup with [`ConsoleTelemetry::new`], which allocates the two
/// queues (about 1.3 MiB); recording never allocates.
#[derive(Debug)]
pub struct ConsoleTelemetry {
    /// Challenge counters.
    pub challenges: Metrics,
    /// Sampled request records; the collector drains it.
    pub queue: BoundedQueue<Record, QUEUE_CAPACITY>,
    /// Challenge events; the collector drains it.
    pub challenge_queue: BoundedQueue<ChallengeRecord, QUEUE_CAPACITY>,
    /// The effective adaptive difficulty bump at the last issued challenge (relaxed).
    pub adaptive_bits: AtomicU32,
    /// The smoothed issue rate, times 256, at the last issued challenge (relaxed).
    pub adaptive_rate_256: AtomicU64,
    counts: [Stripe; STRIPES],
    dropped: AtomicU64,
    challenge_dropped: AtomicU64,
}

impl ConsoleTelemetry {
    /// Returns telemetry with every counter at zero and empty queues.
    pub fn new() -> Self {
        Self {
            challenges: Metrics::new(),
            queue: BoundedQueue::new(),
            challenge_queue: BoundedQueue::new(),
            adaptive_bits: AtomicU32::new(0),
            adaptive_rate_256: AtomicU64::new(0),
            counts: Default::default(),
            dropped: AtomicU64::new(0),
            challenge_dropped: AtomicU64::new(0),
        }
    }

    /// Offers a challenge event; every event is offered, and a full queue drops it and
    /// counts the loss.
    pub fn challenge_event(&self, item: ChallengeRecord) {
        if self.challenge_queue.push(item).is_err() {
            self.challenge_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Returns the exact counters summed over all stripes (wrapping).
    pub fn totals(&self) -> Totals {
        let sum = |field: fn(&Stripe) -> &AtomicU64| {
            self.counts
                .iter()
                .fold(0u64, |acc, s| acc.wrapping_add(field(s).load(Ordering::Relaxed)))
        };
        Totals {
            admitted: sum(|s| &s.admitted),
            challenged: sum(|s| &s.challenged),
            denied: sum(|s| &s.denied),
            banned: sum(|s| &s.banned),
            rate_limited: sum(|s| &s.rate_limited),
            other: sum(|s| &s.other),
            origin_4xx: sum(|s| &s.origin_4xx),
            origin_5xx: sum(|s| &s.origin_5xx),
        }
    }

    /// Returns how many request samples a full queue dropped.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Returns how many challenge events a full queue dropped.
    pub fn challenge_dropped_count(&self) -> u64 {
        self.challenge_dropped.load(Ordering::Relaxed)
    }

    /// Counts `outcome` and offers `sample` with probability 1/64.
    pub fn record(&self, outcome: Outcome, sample: &Sample<'_>) {
        self.count(outcome);
        self.offer(outcome, sample);
    }

    /// Counts `outcome` exactly; called once per request, before delivery.
    pub fn count(&self, outcome: Outcome) {
        self.stripe().outcome(outcome).fetch_add(1, Ordering::Relaxed);
    }

    /// Pushes `sample` with probability 1/64. An admitted request offers its sample once
    /// the origin status is known, so the status describes what was sent.
    pub fn offer(&self, outcome: Outcome, sample: &Sample<'_>) {
        if selected() {
            self.push(outcome, sample);
        }
    }

    /// Copies a sample already chosen by [`selected`] into the queue, cutting long fields;
    /// a full queue drops it and counts the loss. Callers build the sample only for chosen
    /// requests.
    pub fn push(&self, outcome: Outcome, sample: &Sample<'_>) {
        let (ip, ip_len, ip_cut) = truncated(sample.ip);
        let (path, path_len, path_cut) = truncated(sample.path);
        let (referer, referer_len, referer_cut) = truncated(sample.referer);
        let item = Record {
            second: sample.second,
            outcome,
            truncated: ip_cut || path_cut || referer_cut,
            status: sample.status,
            os: sample.os,
            browser: sample.browser,
            ip_len,
            path_len,
            referer_len,
            ip,
            path,
            referer,
        };
        if self.queue.push(item).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Counts an origin response status in the 4xx or 5xx class; other statuses are
    /// ignored.
    pub fn origin(&self, status: u16) {
        let stripe = self.stripe();
        match status {
            400..=499 => stripe.origin_4xx.fetch_add(1, Ordering::Relaxed),
            500..=599 => stripe.origin_5xx.fetch_add(1, Ordering::Relaxed),
            _ => return,
        };
    }

    fn stripe(&self) -> &Stripe {
        // `stripe()` is always below `STRIPES`, the array length.
        &self.counts[stripe()]
    }
}

impl Default for ConsoleTelemetry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_outcomes_remain_complete_when_the_bounded_sample_queue_overflows() {
        let telemetry = ConsoleTelemetry::new();
        seed(1234);
        let sample = Sample {
            second: 1,
            ip: b"127.0.0.1",
            path: b"/",
            referer: b"news.example.test",
            status: 200,
            ..Sample::default()
        };
        for _ in 0..500_000 {
            telemetry.record(Outcome::Admitted, &sample);
        }
        assert_eq!(telemetry.totals().admitted, 500_000);
        assert!(telemetry.dropped_count() > 0);
        telemetry.origin(404);
        seed(77); // another stripe; totals still sum every stripe
        telemetry.origin(502);
        telemetry.origin(200);
        assert_eq!(telemetry.totals().origin_4xx, 1);
        assert_eq!(telemetry.totals().origin_5xx, 1);
    }

    #[test]
    fn external_outcomes_partition_traffic_independently_of_origin_response_classes() {
        let telemetry = ConsoleTelemetry::new();
        let sample = Sample { second: 1, ip: b"8.8.8.8", path: b"/", ..Sample::default() };
        for outcome in Outcome::ALL {
            telemetry.record(outcome, &sample);
        }
        telemetry.origin(404);
        telemetry.origin(503);
        let snapshot = telemetry.totals();
        assert_eq!(snapshot.requests(), 6);
        for outcome in Outcome::ALL {
            assert_eq!(snapshot.outcome(outcome), 1);
        }
    }

    #[test]
    fn samples_are_copied_and_cut_to_their_fields() {
        let mut telemetry = ConsoleTelemetry::new();
        let long_path = [b'p'; 300];
        let mut ip = *b"203.0.113.9";
        telemetry.push(
            Outcome::Denied,
            &Sample {
                second: 9,
                ip: &ip,
                path: &long_path,
                referer: b"example.org",
                status: 403,
                os: 2,
                browser: 3,
            },
        );
        ip.fill(b'x');
        let record = telemetry.queue.pop().expect("one record");
        assert_eq!(record.ip(), b"203.0.113.9");
        assert_eq!(record.path(), &long_path[..PATH_CAPACITY]);
        assert_eq!(record.referer(), b"example.org");
        assert!(record.truncated);
        assert_eq!((record.second, record.status, record.os, record.browser), (9, 403, 2, 3));
        assert_eq!(record.outcome, Outcome::Denied);
    }

    #[test]
    fn challenge_events_are_bounded_and_losses_counted() {
        let telemetry = ConsoleTelemetry::new();
        let mut event = ChallengeRecord {
            outcome: ChallengeOutcome::Rejected,
            cause: Some(Cause::Replay),
            ..ChallengeRecord::default()
        };
        event.set_ip(&[b'1'; 60]);
        assert_eq!(event.ip().len(), IP_CAPACITY);
        for _ in 0..QUEUE_CAPACITY + 3 {
            telemetry.challenge_event(event);
        }
        assert_eq!(telemetry.challenge_dropped_count(), 3);
        let mut consumer = telemetry.challenge_queue.consumer().expect("first claim");
        assert_eq!(consumer.pop(), Some(event));
    }

    #[test]
    fn sampling_selects_about_one_in_sixty_four_and_seed_zero_is_safe() {
        seed(0);
        let hits = (0..640_000).filter(|_| selected()).count();
        assert!((9_000..11_000).contains(&hits), "{hits} samples");
        seed(31);
        assert_eq!(stripe(), 15);
    }
}

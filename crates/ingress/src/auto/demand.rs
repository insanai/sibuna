//! Issuance on demand (SID 0021): the names that handshakes asked for.
//!
//! ```text
//!   handshake                 queue (64)          thread edge-acme         held (names)
//!   ---------                 ----------          ----------------         ------------
//!   request(name)  --room-->  name        --->    storage, ask, token -->  name
//!   wait           <------------- wake ---------  deny (60 s) or hold
//! ```
//!
//! A handshake reads and writes memory only. The thread applies the guards that take
//! time. Every table has a bound.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use sibuna_lb::{AutoName, OnDemand};

/// The most names that wait for the thread.
pub(crate) const MAX_QUEUE: usize = 64;
/// The most names that are remembered as denied.
pub(crate) const MAX_DENIED: usize = 1024;
/// How long a refusal of a guard is remembered, in milliseconds.
pub(crate) const DENIAL_MS: u64 = 60_000;

/// A bucket of tokens. It starts full, holds at most `capacity` tokens, and gains one
/// every `period_ms` milliseconds. One new certificate takes one token.
#[derive(Debug)]
pub(crate) struct Bucket {
    capacity: u32,
    tokens: u32,
    period_ms: u64,
    /// The time up to which the gained tokens are counted.
    counted_ms: u64,
}

impl Bucket {
    /// A full bucket for `rate` tokens per hour.
    pub fn new(rate: u32, now_ms: u64) -> Self {
        let capacity = rate.max(1);
        let period_ms = (3_600_000 / u64::from(capacity)).max(1);
        Self { capacity, tokens: capacity, period_ms, counted_ms: now_ms }
    }

    /// Adds the tokens gained up to `now_ms`, to at most the capacity.
    fn refill(&mut self, now_ms: u64) {
        let gained = now_ms.saturating_sub(self.counted_ms) / self.period_ms;
        let room = u64::from(self.capacity - self.tokens);
        if gained >= room {
            // A full bucket gains nothing: the time it stood full is not saved up.
            self.tokens = self.capacity;
            self.counted_ms = now_ms.max(self.counted_ms);
        } else {
            self.tokens += u32::try_from(gained).unwrap_or(0);
            self.counted_ms += gained * self.period_ms;
        }
    }

    /// Takes one token. Without one, returns the milliseconds until the next.
    pub fn take(&mut self, now_ms: u64) -> Result<(), u64> {
        self.refill(now_ms);
        if self.tokens == 0 {
            let next = self.counted_ms + self.period_ms;
            return Err(next.saturating_sub(now_ms).max(1));
        }
        self.tokens -= 1;
        Ok(())
    }

    #[cfg(test)]
    fn tokens(&self) -> u32 {
        self.tokens
    }
}

/// A name that the daemon holds on demand.
struct Held {
    name: AutoName,
    /// The time of the last handshake that named it, in milliseconds.
    used_ms: AtomicU64,
    /// The time its certificate was obtained or loaded, in milliseconds.
    since_ms: AtomicU64,
}

/// What the thread writes and a refused handshake reads.
struct Waiting {
    queue: VecDeque<AutoName>,
    /// Denied names and the time their denial ends, in milliseconds.
    denied: HashMap<String, u64>,
    bucket: Bucket,
}

/// What a handshake learns when it asks for a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Admission {
    /// The name is denied, or a table is full. The handshake does not wait.
    Refused,
    /// The name is held or queued. The handshake may wait for its certificate.
    Pending,
}

/// The tables of issuance on demand.
pub(crate) struct Demand {
    guards: Option<OnDemand>,
    held: RwLock<HashMap<String, Held>>,
    waiting: Mutex<Waiting>,
    /// Wakes the handshakes that wait, whenever a name was decided or served.
    changed: tokio::sync::Notify,
}

impl Demand {
    /// Empty tables. Without `guards` nothing is ever admitted.
    pub fn new(guards: Option<OnDemand>, now_ms: u64) -> Self {
        let rate = guards.as_ref().map_or(1, |guards| guards.rate);
        Self {
            guards,
            held: RwLock::default(),
            waiting: Mutex::new(Waiting {
                queue: VecDeque::new(),
                denied: HashMap::new(),
                bucket: Bucket::new(rate, now_ms),
            }),
            changed: tokio::sync::Notify::new(),
        }
    }

    fn waiting(&self) -> std::sync::MutexGuard<'_, Waiting> {
        self.waiting.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The `ask` URL, when the guards have one.
    pub fn ask(&self) -> Option<&str> {
        self.guards.as_ref()?.ask.as_deref()
    }

    /// The longest wait of a handshake.
    pub fn wait(&self) -> Duration {
        Duration::from_secs(self.guards.as_ref().map_or(0, |guards| guards.wait))
    }

    /// A handshake asks for `wanted`, which passed the guards that read no state. A
    /// held name is marked as used. A new name is queued when it is not denied and the
    /// tables have room.
    pub fn request(&self, wanted: AutoName, now_ms: u64) -> Admission {
        let Some(guards) = &self.guards else { return Admission::Refused };
        let held = super::read(&self.held);
        if let Some(found) = held.get(&wanted.name) {
            found.used_ms.store(now_ms, Ordering::Relaxed);
            return Admission::Pending;
        }
        let mut waiting = self.waiting();
        if waiting.denied.get(&wanted.name).is_some_and(|until| *until > now_ms) {
            return Admission::Refused;
        }
        if waiting.queue.iter().any(|queued| queued.name == wanted.name) {
            return Admission::Pending;
        }
        let full = held.len() + waiting.queue.len() >= guards.names;
        if full || waiting.queue.len() >= MAX_QUEUE {
            return Admission::Refused;
        }
        waiting.queue.push_back(wanted);
        Admission::Pending
    }

    /// Marks a held name as used by a handshake.
    pub fn touch(&self, name: &str, now_ms: u64) {
        if let Some(found) = super::read(&self.held).get(name) {
            found.used_ms.store(now_ms, Ordering::Relaxed);
        }
    }

    /// Whether the daemon holds `name` on demand.
    pub fn is_held(&self, name: &str) -> bool {
        super::read(&self.held).contains_key(name)
    }

    /// Whether `name` waits for the thread.
    pub fn is_queued(&self, name: &str) -> bool {
        self.waiting().queue.iter().any(|queued| queued.name == name)
    }

    /// The held name `name`, with its port and its issuer.
    pub fn held(&self, name: &str) -> Option<AutoName> {
        super::read(&self.held).get(name).map(|found| found.name.clone())
    }

    /// Every held name.
    pub fn held_names(&self) -> Vec<AutoName> {
        super::read(&self.held).values().map(|found| found.name.clone()).collect()
    }

    /// The names that wait for the thread, oldest first. They stay queued until
    /// [`Demand::hold`] or [`Demand::deny`] decides each.
    pub fn queued(&self) -> Vec<AutoName> {
        self.waiting().queue.iter().cloned().collect()
    }

    /// Takes one token for a new certificate. Without one, returns the milliseconds
    /// until the next.
    pub fn take_token(&self, now_ms: u64) -> Result<(), u64> {
        self.waiting().bucket.take(now_ms)
    }

    /// Moves a queued name into the held names. The table of held names has room: a
    /// name is queued only when both together stay within the bound.
    pub fn hold(&self, wanted: AutoName, now_ms: u64) {
        let name = wanted.name.clone();
        let entry =
            Held { name: wanted, used_ms: AtomicU64::new(now_ms), since_ms: AtomicU64::new(0) };
        super::write(&self.held).insert(name.clone(), entry);
        self.waiting().queue.retain(|queued| queued.name != name);
    }

    /// Removes `name` from the queue and refuses it until `until_ms`. The table keeps
    /// at most [`MAX_DENIED`] names: a denial that is over leaves, and else the one that
    /// ends first.
    pub fn deny(&self, name: &str, until_ms: u64, now_ms: u64) {
        let mut waiting = self.waiting();
        waiting.queue.retain(|queued| queued.name != name);
        if waiting.denied.len() >= MAX_DENIED && !waiting.denied.contains_key(name) {
            waiting.denied.retain(|_, until| *until > now_ms);
        }
        if waiting.denied.len() >= MAX_DENIED && !waiting.denied.contains_key(name) {
            let first = waiting.denied.iter().min_by_key(|(_, until)| **until);
            if let Some(first) = first.map(|(name, _)| name.clone()) {
                waiting.denied.remove(&first);
            }
        }
        waiting.denied.insert(name.to_owned(), until_ms);
    }

    /// Records that the certificate of a held name was obtained or loaded.
    pub fn obtained(&self, name: &str, now_ms: u64) {
        if let Some(found) = super::read(&self.held).get(name) {
            found.since_ms.store(now_ms, Ordering::Relaxed);
        }
    }

    /// Whether no handshake named the held name since its certificate was obtained.
    pub fn is_unused(&self, name: &str) -> bool {
        super::read(&self.held).get(name).is_some_and(|found| {
            found.used_ms.load(Ordering::Relaxed) <= found.since_ms.load(Ordering::Relaxed)
        })
    }

    /// Lets go of a held name.
    pub fn release(&self, name: &str) {
        super::write(&self.held).remove(name);
    }

    /// Wakes the handshakes that wait.
    pub fn wake(&self) {
        self.changed.notify_waiters();
    }

    /// Waits until `settled` holds, for at most [`Demand::wait`]. `settled` is looked
    /// at before the first wait and after every wake, so no wake is lost.
    pub async fn wait_until(&self, settled: impl Fn() -> bool) {
        let end = Instant::now() + self.wait();
        loop {
            let woken = self.changed.notified();
            tokio::pin!(woken);
            woken.as_mut().enable();
            if settled() {
                return;
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() || tokio::time::timeout(left, woken).await.is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(name: &str) -> AutoName {
        AutoName { name: name.to_owned(), port: 443, local: false }
    }

    fn demand(names: usize) -> Demand {
        let guards = OnDemand { allow: vec!["test".to_owned()], names, ..OnDemand::default() };
        Demand::new(Some(guards), 0)
    }

    #[test]
    fn the_bucket_starts_full_and_gains_one_token_per_period() {
        // Four per hour: one token every 15 minutes.
        let mut bucket = Bucket::new(4, 1000);
        for _ in 0..4 {
            assert_eq!(bucket.take(1000), Ok(()));
        }
        assert_eq!(bucket.take(1000), Err(900_000));
        assert_eq!(bucket.take(1000 + 899_999), Err(1));
        assert_eq!(bucket.take(1000 + 900_000), Ok(()));
        assert_eq!(bucket.take(1000 + 900_001), Err(899_999));
        // A long rest fills it, and no more.
        assert_eq!(bucket.take(1000 + 100 * 3_600_000), Ok(()));
        assert_eq!(bucket.tokens(), 3);
        // A clock that steps back gives nothing and breaks nothing.
        assert_eq!(bucket.take(0), Ok(()));
        assert_eq!(bucket.tokens(), 2);
    }

    #[test]
    fn a_window_admits_at_most_the_capacity_and_the_refills() {
        let mut bucket = Bucket::new(60, 0);
        // One try per second for two hours: 60 at once, then one per minute.
        let admitted = (0..7200u64).filter(|second| bucket.take(second * 1000).is_ok()).count();
        assert_eq!(admitted, 60 + 119);
    }

    #[test]
    fn a_name_is_queued_once_and_held_names_and_queue_share_the_bound() {
        let demand = demand(2);
        assert_eq!(demand.request(name("a.test"), 0), Admission::Pending);
        assert_eq!(demand.request(name("a.test"), 0), Admission::Pending);
        assert_eq!(demand.queued().len(), 1);
        assert_eq!(demand.request(name("b.test"), 0), Admission::Pending);
        assert_eq!(demand.request(name("c.test"), 0), Admission::Refused);
        demand.hold(name("a.test"), 5);
        assert!(demand.is_held("a.test") && !demand.is_queued("a.test"));
        assert_eq!(demand.request(name("c.test"), 0), Admission::Refused);
        demand.deny("b.test", 100, 0);
        assert_eq!(demand.request(name("b.test"), 99), Admission::Refused);
        assert_eq!(demand.request(name("c.test"), 0), Admission::Pending);
        // The denial ends. The table is full by then.
        assert_eq!(demand.request(name("b.test"), 100), Admission::Refused);
        demand.release("a.test");
        assert_eq!(demand.request(name("b.test"), 100), Admission::Pending);
        assert_eq!(demand.held_names().len() + demand.queued().len(), 2);
    }

    #[test]
    fn the_queue_and_the_denied_table_are_bounded() {
        let demand = demand(10_000);
        for index in 0..MAX_QUEUE + 5 {
            let admission = demand.request(name(&format!("n{index}.test")), 0);
            assert_eq!(admission == Admission::Pending, index < MAX_QUEUE, "{index}");
        }
        for index in 0..MAX_DENIED as u64 + 10 {
            demand.deny(&format!("d{index}.test"), 1000 + index, 0);
        }
        assert_eq!(demand.waiting().denied.len(), MAX_DENIED);
        // The denials that end first made room for the last ones.
        assert_eq!(demand.request(name("d0.test"), 0), Admission::Refused);
        assert!(!demand.waiting().denied.contains_key("d0.test"));
        assert!(demand.waiting().denied.contains_key("d1033.test"));
        // Denials that are over leave first.
        demand.deny("late.test", 9000, 5000);
        assert_eq!(demand.waiting().denied.len(), 1);
    }

    #[test]
    fn a_name_is_unused_until_a_handshake_names_it_after_its_certificate() {
        let demand = demand(4);
        demand.request(name("a.test"), 10);
        demand.hold(name("a.test"), 11);
        demand.obtained("a.test", 20);
        assert!(demand.is_unused("a.test"));
        demand.touch("a.test", 20);
        assert!(demand.is_unused("a.test"));
        assert_eq!(demand.request(name("a.test"), 21), Admission::Pending);
        assert!(!demand.is_unused("a.test"));
        assert_eq!(demand.held("a.test").map(|held| held.port), Some(443));
        assert!(!demand.is_unused("other.test"));
    }

    #[test]
    fn nothing_is_admitted_without_guards() {
        let demand = Demand::new(None, 0);
        assert_eq!(demand.request(name("a.test"), 0), Admission::Refused);
        assert!(demand.wait().is_zero() && demand.ask().is_none());
    }

    #[tokio::test]
    async fn a_waiter_returns_when_woken_and_settled_or_when_the_wait_is_over() {
        let guards = OnDemand { wait: 1, ..OnDemand::default() };
        let demand = std::sync::Arc::new(Demand::new(Some(guards), 0));
        let settled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (waker, flag) = (demand.clone(), settled.clone());
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            flag.store(true, Ordering::Release);
            waker.wake();
        });
        let start = Instant::now();
        demand.wait_until(|| settled.load(Ordering::Acquire)).await;
        assert!(start.elapsed() < Duration::from_millis(900));
        let start = Instant::now();
        demand.wait_until(|| false).await;
        assert!(start.elapsed() >= Duration::from_secs(1));
    }
}

//! What SID 0019 adds to admission: the servers a request already tried, passive
//! health and slow start.
//!
//! The state of a server lives in its [`Load`], which a reload keeps for every address.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use super::{Load, Pool, Target, Ticket};
use crate::sticky::{self, Key, Token};
use crate::{Passive, Sticky};

/// The servers one request has tried. A retry never selects one of them again.
#[derive(Default)]
pub(crate) struct Tried(Vec<Arc<Load>>);

impl Tried {
    /// The servers of `self` and the server of `ticket`.
    pub fn with(&self, ticket: &Ticket) -> Self {
        let mut tried = Vec::with_capacity(self.0.len() + 1);
        tried.extend(self.0.iter().cloned());
        tried.push(Arc::clone(&ticket.load));
        Self(tried)
    }

    /// How many servers were tried.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    fn holds(&self, load: &Arc<Load>) -> bool {
        self.0.iter().any(|tried| Arc::ptr_eq(tried, load))
    }
}

/// What one reservation asks for beyond the scheduler's choice.
#[derive(Default)]
pub(crate) struct Wish<'a> {
    /// Servers that must not be selected.
    pub tried: Option<&'a Tried>,
    /// The server the client's cookie names. It is used only when it is eligible.
    pub sticky: Option<usize>,
}

impl Wish<'_> {
    /// Whether the request may still use `target`.
    pub(super) fn allows(&self, target: &Target) -> bool {
        self.tried.is_none_or(|tried| !tried.holds(&target.load))
    }
}

/// What SID 0019 remembers about one server.
#[derive(Default)]
pub(super) struct State {
    /// Consecutive failures that passive health has counted.
    failures: AtomicU32,
    /// Set while `ejected_until` may lie in the future, so that the usual reservation
    /// reads one atomic and takes no lock.
    ejected: AtomicBool,
    ejected_until: Mutex<Option<Instant>>,
    /// When the server last entered service, for slow start.
    service: Mutex<Service>,
    /// The weight of a server in its ramp, in units of 1/[`SCALE`]. Zero outside a ramp.
    ramped: AtomicU32,
    /// The sticky token of the server, with a mark of the key and names it was made from.
    token: Mutex<(u64, Token)>,
}

impl Pool {
    /// The server that source stickiness gives the client `peer`: the nearest server of
    /// the pool that is not a backup, whether or not it can serve now. `None` when the
    /// pool is not sticky by source.
    pub(super) fn home(&self, peer: std::net::SocketAddr) -> Option<usize> {
        if self.policy.sticky != Some(Sticky::Source) {
            return None;
        }
        let client = sticky::client_bytes(peer.ip());
        let distance =
            |target: &Target| sticky::distance(&client, &target.server.name, target.server.weight);
        let servers = self.targets.iter().enumerate().filter(|(_, target)| !target.server.backup);
        servers
            .map(|(index, target)| (index, distance(target)))
            .reduce(|best, next| if next.1.nearer_than(&best.1) { next } else { best })
            .map(|(index, _)| index)
    }

    /// The server whose sticky token under `key` is `presented`, for the pool `name`.
    pub(crate) fn holder(&self, key: &Key, name: &str, presented: &[u8]) -> Option<usize> {
        self.targets
            .iter()
            .position(|target| sibuna_crypto::ct::eq(&target.token(key, name), presented))
    }

    /// The sticky token of the server that `ticket` reserved.
    pub(crate) fn token_of(&self, key: &Key, name: &str, ticket: &Ticket) -> Option<Token> {
        let target = self.targets.iter().find(|target| Arc::ptr_eq(&target.load, &ticket.load))?;
        Some(target.token(key, name))
    }
}

impl Target {
    /// The sticky token of the server in the pool `pool`. It is computed once for each
    /// key and pair of names.
    fn token(&self, key: &Key, pool: &str) -> Token {
        let names = sibuna_crypto::wyhash::hash(pool.len() as u64, pool.as_bytes());
        let names = sibuna_crypto::wyhash::hash(names, self.server.name.as_bytes());
        let mark = (key.tag ^ names) | 1;
        let mut cached = self.load.extra.token.lock().unwrap_or_else(PoisonError::into_inner);
        if cached.0 != mark {
            *cached = (mark, key.token(pool, &self.server.name));
        }
        cached.1
    }
}

/// What slow start has seen of a server.
#[derive(Default)]
struct Service {
    /// A reservation has looked at the server before.
    seen: bool,
    /// The server was out of service when it was last looked at.
    down: bool,
    /// The start of the current ramp.
    since: Option<Instant>,
}

/// Weights are compared in units of 1/256 of a configured weight, so that a server of
/// weight 1 ramps in 256 steps.
pub(super) const SCALE: u64 = 256;

/// The weight of a server of configured weight `weight` that entered service `elapsed`
/// ago, with a ramp of `ramp`, in units of 1/[`SCALE`].
///
/// The result is at least 1, never above `weight * SCALE`, and never decreases as
/// `elapsed` grows. After the ramp it is `weight * SCALE`.
pub(crate) fn ramp_weight(weight: u32, elapsed: Duration, ramp: Duration) -> u64 {
    let full = u64::from(weight.max(1)) * SCALE;
    if elapsed >= ramp {
        return full;
    }
    // A ramp is at most one day and a weight at most 65535, so the product fits.
    let (elapsed, ramp) = (elapsed.as_millis() as u64, ramp.as_millis() as u64);
    (full * elapsed / ramp.max(1)).max(1)
}

impl State {
    /// Looks at the server for slow start and stores its weight for this moment. `up`
    /// says whether the server is in service. `veteran` says whether the pool had a
    /// server before this one was first seen, which makes this one an addition.
    fn observe(&self, weight: u32, ramp: Duration, now: Instant, up: bool, veteran: bool) {
        let mut service = self.service.lock().unwrap_or_else(PoisonError::into_inner);
        let added = !service.seen && veteran;
        service.seen = true;
        if !up {
            service.down = true;
            return;
        }
        if service.down || added {
            service.since = Some(now);
            service.down = false;
        }
        let elapsed = service.since.map(|since| now.saturating_duration_since(since));
        let ramped = match elapsed {
            Some(elapsed) if elapsed < ramp => ramp_weight(weight, elapsed, ramp) as u32,
            _ => {
                service.since = None;
                0
            }
        };
        self.ramped.store(ramped, Ordering::Relaxed);
    }

    fn seen(&self) -> bool {
        self.service.lock().unwrap_or_else(PoisonError::into_inner).seen
    }
}

impl Target {
    /// The weight of the server in units of 1/[`SCALE`]. While `ramping`, a server in
    /// its slow start has the reduced weight that [`Pool::ramp`] stored.
    pub(super) fn weight(&self, ramping: bool) -> u64 {
        let ramped = if ramping { self.load.extra.ramped.load(Ordering::Relaxed) } else { 0 };
        if ramped == 0 { u64::from(self.server.weight) * SCALE } else { u64::from(ramped) }
    }

    /// Whether the server is in service: healthy, not marked by a failed connect and not
    /// ejected. A full server and a server the request already tried are in service.
    fn in_service(&self, now: Instant) -> bool {
        let marked = self.load.retry_after.lock().unwrap_or_else(PoisonError::into_inner);
        self.server.healthy.as_ref().is_none_or(|healthy| healthy.load(Ordering::Relaxed))
            && marked.is_none_or(|deadline| deadline <= now)
            && !self.load.extra.is_ejected(now)
    }
}

impl Pool {
    /// Brings the slow-start weights of the servers up to `now`. Returns whether the
    /// pool has a slow start at all.
    pub(super) fn ramp(&self, now: Instant) -> bool {
        let Some(ramp) = self.policy.slow_start else { return false };
        // Servers that are first seen together started together: none of them ramps.
        let veteran = self.targets.iter().any(|target| target.load.extra.seen());
        for target in &self.targets {
            let up = target.in_service(now);
            target.load.extra.observe(target.server.weight, ramp, now, up, veteran);
        }
        true
    }
}

impl State {
    /// Whether passive health keeps the server out at `now`.
    pub fn is_ejected(&self, now: Instant) -> bool {
        if !self.ejected.load(Ordering::Relaxed) {
            return false;
        }
        let mut until = self.ejected_until.lock().unwrap_or_else(PoisonError::into_inner);
        if until.is_some_and(|until| now < until) {
            return true;
        }
        *until = None;
        self.ejected.store(false, Ordering::Relaxed);
        false
    }

    /// Counts one outcome of a request under `rule` and ejects the server at the limit.
    fn record(&self, rule: &Passive, failed: bool, now: Instant) {
        // Two workers may count at once. A lost update delays an ejection by one
        // failure, which passive health tolerates.
        let (count, eject) = rule.step(self.failures.load(Ordering::Relaxed), failed);
        self.failures.store(count, Ordering::Relaxed);
        if eject {
            let mut until = self.ejected_until.lock().unwrap_or_else(PoisonError::into_inner);
            *until = Some(now + rule.ejection);
            self.ejected.store(true, Ordering::Relaxed);
        }
    }
}

impl Ticket {
    /// The server stayed silent for its response bound.
    pub fn timed_out(&self, rule: Option<&Passive>, now: Instant) {
        if let Some(rule) = rule {
            self.load.extra.record(rule, true, now);
        }
    }

    /// The server sent a complete response with `status`.
    pub fn answered(&self, rule: Option<&Passive>, status: u16, now: Instant) {
        if let Some(rule) = rule {
            self.load.extra.record(rule, rule.counts(status), now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ramp_weight_grows_to_the_full_weight_and_is_never_zero() {
        let ramp = Duration::from_secs(30);
        let at = |weight, millis| ramp_weight(weight, Duration::from_millis(millis), ramp);
        assert_eq!(at(1, 0), 1);
        assert_eq!(at(1, 15_000), 128);
        assert_eq!(at(1, 30_000), 256);
        assert_eq!(at(1, 90_000), 256);
        assert_eq!(at(10, 3_000), 256);
        assert_eq!(at(65535, 29_999), 65535 * 256 * 29_999 / 30_000);
        for weight in [1, 2, 7, 100, 65535] {
            let mut last = 0;
            for millis in (0..=31_000).step_by(250) {
                let now = at(weight, millis);
                assert!(
                    now >= last.max(1) && now <= u64::from(weight) * SCALE,
                    "{weight} {millis}"
                );
                last = now;
            }
            assert_eq!(last, u64::from(weight) * SCALE);
        }
        // A ramp shorter than a millisecond is over at once.
        assert_eq!(ramp_weight(3, Duration::ZERO, Duration::ZERO), 3 * SCALE);
    }

    #[test]
    fn a_server_ramps_when_it_returns_and_when_it_is_added_but_not_at_the_start() {
        let ramp = Duration::from_secs(10);
        let start = Instant::now();
        let state = State::default();
        let weight = || state.ramped.load(Ordering::Relaxed);
        // First seen with the rest of its pool: full weight.
        state.observe(2, ramp, start, true, false);
        assert_eq!(weight(), 0);
        // Out of service, then back: the ramp starts when it is seen again.
        state.observe(2, ramp, start + Duration::from_secs(1), false, true);
        state.observe(2, ramp, start + Duration::from_secs(5), true, true);
        assert_eq!(weight(), 1);
        state.observe(2, ramp, start + Duration::from_secs(10), true, true);
        assert_eq!(weight(), 256);
        state.observe(2, ramp, start + Duration::from_secs(15), true, true);
        assert_eq!(weight(), 0);
        // A server first seen in a pool that had servers is an addition.
        let added = State::default();
        added.observe(1, ramp, start, true, true);
        assert_eq!(added.ramped.load(Ordering::Relaxed), 1);
        added.observe(1, ramp, start + Duration::from_secs(5), true, true);
        assert_eq!(added.ramped.load(Ordering::Relaxed), 128);
    }
}

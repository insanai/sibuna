//! What SID 0019 adds to admission: the servers a request already tried, passive
//! health and slow start.
//!
//! The state of a server lives in its [`Load`], which a reload keeps for every address.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering};
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
    /// The client address behind trusted proxies, for source stickiness. Without it
    /// the address of the transport is the client.
    pub client: Option<std::net::IpAddr>,
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
    /// The credit of the server in round robin.
    credit: AtomicI64,
}

impl Pool {
    /// Round robin: the next server in turn among those `eligible`, in proportion to
    /// the weights. Backups take turns only when no other server is eligible.
    ///
    /// This is the smooth weighted round robin of nginx. Each eligible server gains its
    /// weight in credit, the server with the most credit is chosen, and it pays the sum
    /// of the weights. Over one sum of weights each server is chosen its weight in
    /// times, and the choices of a heavy server are spread out, not bunched.
    pub(super) fn in_turn(
        &self,
        ramping: bool,
        eligible: impl Fn(&Target) -> bool,
    ) -> Option<usize> {
        let backups = !self.targets.iter().any(|t| eligible(t) && !t.server.backup);
        let mut total = 0;
        let mut best: Option<(usize, i64)> = None;
        for (index, target) in self.targets.iter().enumerate() {
            if !eligible(target) || target.server.backup != backups {
                continue;
            }
            // A weight is at most 65535 * 256, so credits stay far inside an i64.
            let weight = target.weight(ramping) as i64;
            let credit = target.load.extra.credit.fetch_add(weight, Ordering::Relaxed) + weight;
            total += weight;
            if best.is_none_or(|(_, most)| credit > most) {
                best = Some((index, credit));
            }
        }
        let (index, _) = best?;
        self.targets.get(index)?.load.extra.credit.fetch_sub(total, Ordering::Relaxed);
        Some(index)
    }
}

impl Pool {
    /// The server that source stickiness gives `client`: the nearest server of the pool
    /// that is `eligible` and not a backup. `None` when the pool is not sticky by
    /// source, and when only backups are eligible.
    ///
    /// The ranking is a rendezvous hash, so the clients of a server that is drained,
    /// down, ejected or full get one other server each and keep it until their own
    /// returns. The other clients stay where they are.
    pub(super) fn home(
        &self,
        client: std::net::IpAddr,
        eligible: impl Fn(&Target) -> bool,
    ) -> Option<usize> {
        if self.policy.sticky != Some(Sticky::Source) {
            return None;
        }
        let client = sticky::client_bytes(client);
        let distance =
            |target: &Target| sticky::distance(&client, target.rank_seed, target.server.weight);
        let stays = |target: &Target| !target.server.backup && eligible(target);
        let servers = self.targets.iter().enumerate().filter(|(_, target)| stays(target));
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

    /// The share of its weight that the server has in its slow start, in percent, or
    /// `None` when it is not in a ramp.
    pub(super) fn ramp_percent(&self, ramping: bool) -> Option<u8> {
        let ramped = u64::from(self.load.extra.ramped.load(Ordering::Relaxed));
        if !ramping || ramped == 0 {
            return None;
        }
        let full = u64::from(self.server.weight.max(1)) * SCALE;
        Some((ramped * 100 / full).min(99) as u8)
    }

    /// Whether the server is in service: healthy, not drained (SID 0018), not marked by
    /// a failed connect and not ejected. A full server and a server the request already
    /// tried are in service.
    fn in_service(&self, now: Instant) -> bool {
        let marked = self.load.retry_after.lock().unwrap_or_else(PoisonError::into_inner);
        self.server.healthy.as_ref().is_none_or(|healthy| healthy.load(Ordering::Relaxed))
            && marked.is_none_or(|deadline| deadline <= now)
            && !self.load.extra.is_ejected(now)
            && !self.drained
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

    /// How long passive health still keeps the server out at `now`.
    pub fn ejected_for(&self, now: Instant) -> Option<Duration> {
        if !self.ejected.load(Ordering::Relaxed) {
            return None;
        }
        let until = self.ejected_until.lock().unwrap_or_else(PoisonError::into_inner);
        until.and_then(|until| until.checked_duration_since(now)).filter(|left| !left.is_zero())
    }

    /// Counts one outcome of a request under `rule` and ejects the server at the limit.
    /// Returns whether this outcome ejected the server.
    fn record(&self, rule: &Passive, failed: bool, now: Instant) -> bool {
        // Two workers may count at once. The update is repeated until it applies to the
        // count it read, so no failure is lost and exactly one report ejects.
        let mut count = self.failures.load(Ordering::Acquire);
        let eject = loop {
            let (next, eject) = rule.step(count, failed);
            let swap = self.failures.compare_exchange_weak(
                count,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            match swap {
                Ok(_) => break eject,
                Err(seen) => count = seen,
            }
        };
        if eject {
            let mut until = self.ejected_until.lock().unwrap_or_else(PoisonError::into_inner);
            *until = Some(now + rule.ejection);
            self.ejected.store(true, Ordering::Relaxed);
        }
        eject
    }
}

impl Ticket {
    /// The server stayed silent for its response bound. Returns whether this ejected it.
    pub fn timed_out(&self, rule: Option<&Passive>, now: Instant) -> bool {
        rule.is_some_and(|rule| self.load.extra.record(rule, true, now))
    }

    /// The server sent a complete response with `status`. Returns whether this ejected
    /// it.
    pub fn answered(&self, rule: Option<&Passive>, status: u16, now: Instant) -> bool {
        rule.is_some_and(|rule| self.load.extra.record(rule, rule.counts(status), now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_failure_reports_lose_no_count() {
        let rule = Passive { failures: 5, ejection: Duration::from_secs(1), http_5xx: false };
        let state = State::default();
        let now = Instant::now();
        let ejections = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..5_000 {
                        if state.record(&rule, true, now) {
                            ejections.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }
        });
        // Forty thousand failures in runs of five: each fifth report ejects, and none
        // is lost between two threads.
        assert_eq!(ejections.load(Ordering::Relaxed), 8_000);
    }

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

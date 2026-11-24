//! Single-owner admission. A ticket holds the reservation across configuration revisions.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};

use crate::config::{Backend, Protocol, Scheduler, Server};

mod extra;
pub(crate) use extra::{Tried, Wish};

#[derive(Default)]
struct Load {
    active: AtomicUsize,
    latency: Mutex<Option<(Instant, u64)>>,
    retry_after: Mutex<Option<Instant>>,
    /// The state that SID 0019 keeps for a server.
    extra: extra::State,
}

impl Load {
    fn estimate(&self, now: Instant) -> u64 {
        let sample = *self.latency.lock().unwrap_or_else(PoisonError::into_inner);
        let Some((last, peak)) = sample else { return 1000 };
        // Let an unused origin recover from an old spike. The resting estimate is 1 ms.
        let age = now.saturating_duration_since(last).as_secs().min(32);
        1000u64.saturating_add_signed(((peak as i64) - 1000) >> age)
    }
}

pub(crate) struct Ticket {
    pub addr: SocketAddr,
    load: Arc<Load>,
}

impl Ticket {
    pub fn observe(&self, start: Instant, now: Instant) {
        let sample = now.saturating_duration_since(start).as_micros().clamp(1, 60_000_000) as u64;
        let peak = sample.max((7 * self.load.estimate(now) + sample) / 8);
        *self.load.latency.lock().unwrap_or_else(PoisonError::into_inner) = Some((now, peak));
    }

    pub fn failed(&self, now: Instant) {
        *self.load.retry_after.lock().unwrap_or_else(PoisonError::into_inner) =
            Some(now + Duration::from_secs(2));
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        self.load.active.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Default)]
pub(crate) struct Loads(HashMap<(Protocol, SocketAddr), Weak<Load>>);

impl Loads {
    pub fn prune(&mut self) {
        self.0.retain(|_, load| load.strong_count() != 0);
    }
}

struct Target {
    server: Server,
    load: Arc<Load>,
    admitted: u64,
}

impl Target {
    fn preferred_to(&self, other: &Self, ramping: bool) -> bool {
        let score = |target: &Self, weight: u64| {
            let scale = u128::from(weight);
            (
                target.load.active.load(Ordering::Relaxed) as u128 * scale,
                u128::from(target.admitted) * scale,
            )
        };
        (self.server.backup, score(self, other.weight(ramping)))
            < (other.server.backup, score(other, self.weight(ramping)))
    }
}

pub(crate) struct Pool {
    targets: Vec<Target>,
    scheduler: Scheduler,
    /// The traffic options of SID 0019.
    pub policy: Arc<crate::PoolPolicy>,
    pub proxy_v2: Option<crate::proxy::Spec>,
    choices: RandomState,
}

impl Pool {
    pub fn new(backend: Backend, loads: &mut Loads) -> Self {
        let mut targets = Vec::with_capacity(backend.servers.len());
        for server in backend.servers {
            let slot = loads.0.entry((backend.protocol, server.addr)).or_default();
            let load = slot.upgrade().unwrap_or_default();
            *slot = Arc::downgrade(&load);
            targets.push(Target { server, load, admitted: 0 });
        }
        Self {
            targets,
            scheduler: backend.scheduler,
            policy: backend.policy,
            proxy_v2: backend.proxy_v2,
            choices: RandomState::new(),
        }
    }

    pub fn reserve(
        &mut self,
        now: Instant,
        peer: SocketAddr,
        vip: SocketAddr,
        regime: crate::Regime,
    ) -> Option<Ticket> {
        self.reserve_with(now, peer, vip, regime, &Wish::default())
    }

    /// Reserves a place on a server that `wish` allows (SID 0019).
    pub fn reserve_with(
        &mut self,
        now: Instant,
        peer: SocketAddr,
        vip: SocketAddr,
        regime: crate::Regime,
        wish: &Wish<'_>,
    ) -> Option<Ticket> {
        let ramping = self.ramp(now);
        let available = |target: &Target| {
            target.server.addr != vip
                && target.server.healthy.as_ref().is_none_or(|h| h.load(Ordering::Relaxed))
                && target.load.active.load(Ordering::Relaxed) < target.server.limit
                && target
                    .load
                    .retry_after
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .is_none_or(|deadline| deadline <= now)
                && wish.allows(target)
        };
        // Passive health keeps a server out only while another can serve (SID 0019).
        let spared = self.targets.iter().any(|t| available(t) && !t.load.extra.is_ejected(now));
        let available = |t: &Target| available(t) && !(spared && t.load.extra.is_ejected(now));
        let prefer_local = regime == crate::Regime::WideArea
            && self.targets.iter().any(|t| !t.server.remote && available(t));
        let eligible = |t: &Target| available(t) && !(prefer_local && t.server.remote);
        let (table, peak) = match &self.scheduler {
            Scheduler::Maglev { table, peak_fallback } => (Some(table), *peak_fallback),
            Scheduler::Adaptive(table) => {
                ((regime != crate::Regime::Standalone).then_some(table), true)
            }
            Scheduler::LeastConnections => (None, false),
            Scheduler::PeakEwma => (None, true),
        };
        let primary = table.and_then(|table| {
            let index = table.primary(peer, vip);
            let primary = &self.targets[index];
            let load: usize =
                self.targets.iter().map(|target| target.load.active.load(Ordering::Relaxed)).sum();
            let desired = (load + 1) as u64 * primary.weight(ramping);
            let bound = (desired * u64::from(table.factor))
                .div_ceil(u64::from(table.weight) * 100 * extra::SCALE);
            (eligible(primary) && (primary.load.active.load(Ordering::Relaxed) as u64) < bound)
                .then_some(index)
        });
        // A sticky server serves its client whenever it is eligible (SID 0019).
        let sticky = wish.sticky.or_else(|| self.home(peer));
        let sticky = sticky.filter(|&index| self.targets.get(index).is_some_and(eligible));
        let index = sticky.or(primary).or_else(|| {
            if peak {
                return self.choose_two(now, peer, vip, eligible);
            }
            self.targets
                .iter()
                .enumerate()
                .filter(|(_, t)| eligible(t))
                .reduce(
                    |best, next| if next.1.preferred_to(best.1, ramping) { next } else { best },
                )
                .map(|(i, _)| i)
        })?;
        let target = &mut self.targets[index];
        target.load.active.fetch_add(1, Ordering::Relaxed);
        target.admitted = target.admitted.saturating_add(1);
        // An HTTP exchange enters the pool's protocol adapter when it has one.
        let addr = target.server.via.unwrap_or(target.server.addr);
        Some(Ticket { addr, load: Arc::clone(&target.load) })
    }

    fn choose_two(
        &self,
        now: Instant,
        peer: SocketAddr,
        vip: SocketAddr,
        eligible: impl Fn(&Target) -> bool,
    ) -> Option<usize> {
        // Configuration bounds a pool to 128 servers. Collect the eligible tier once.
        let mut choices = [0usize; 128];
        let mut count = 0;
        let mut backups = true;
        for (i, target) in self.targets.iter().enumerate().filter(|(_, t)| eligible(t)) {
            if backups && !target.server.backup {
                count = 0;
                backups = false;
            }
            if backups == target.server.backup {
                choices[count] = i;
                count += 1;
            }
        }
        if count == 0 {
            return None;
        }
        let hash = self.choices.hash_one((peer, vip));
        let a = (hash as usize) % count;
        if count == 1 {
            return Some(choices[a]);
        }
        let b = (a + 1 + ((hash >> 32) as usize) % (count - 1)) % count;
        let ramping = self.policy.slow_start.is_some();
        let cost = |i: usize| {
            let t = &self.targets[choices[i]];
            let work = (t.load.active.load(Ordering::Relaxed) as u128 + 1)
                * u128::from(t.load.estimate(now));
            work * 65535 * u128::from(extra::SCALE) / u128::from(t.weight(ramping))
        };
        Some(choices[if cost(a) <= cost(b) { a } else { b }])
    }
}

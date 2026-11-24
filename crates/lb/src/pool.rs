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
    /// An operator took the server out of rotation for new flows (SID 0018).
    drained: bool,
    /// A command added the server; the file does not have it.
    added: bool,
    /// The weight the file gave, when a command replaced it.
    file_weight: Option<u32>,
    /// The part of the rendezvous ranking that depends on the name alone (SID 0019).
    rank_seed: u64,
}

impl Target {
    fn new(server: Server, protocol: Protocol, loads: &mut Loads) -> Self {
        let slot = loads.0.entry((protocol, server.addr)).or_default();
        let load = slot.upgrade().unwrap_or_default();
        *slot = Arc::downgrade(&load);
        let rank_seed = crate::sticky::rank_seed(&server.name);
        Self {
            server,
            load,
            admitted: 0,
            drained: false,
            added: false,
            file_weight: None,
            rank_seed,
        }
    }

    /// Whether a command changed this server since the file was loaded.
    fn changed(&self) -> bool {
        self.drained || self.added || self.file_weight.is_some()
    }
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
    protocol: Protocol,
    /// The probe that every server of the pool has, also one added at run time.
    pub health: Option<crate::health::Spec>,
    /// The servers are reached through protocol adapters that only a reload prepares.
    adapted: bool,
    /// Names of the file's servers that a command removed.
    pub removed: Vec<String>,
}

impl Pool {
    pub fn new(backend: Backend, loads: &mut Loads) -> Self {
        let protocol = backend.protocol;
        let targets =
            backend.servers.into_iter().map(|s| Target::new(s, protocol, loads)).collect();
        Self {
            targets,
            scheduler: backend.scheduler,
            policy: backend.policy,
            proxy_v2: backend.proxy_v2,
            choices: RandomState::new(),
            protocol,
            health: backend.health,
            adapted: backend.origin.is_some(),
            removed: Vec::new(),
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
                && !target.drained
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
            Scheduler::LeastConnections | Scheduler::RoundRobin => (None, false),
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
        let sticky = wish.sticky.filter(|&index| self.targets.get(index).is_some_and(eligible));
        let sticky = sticky.or_else(|| self.home(wish.client.unwrap_or(peer.ip()), eligible));
        let index = sticky.or(primary).or_else(|| {
            if matches!(self.scheduler, Scheduler::RoundRobin) {
                return self.in_turn(ramping, eligible);
            }
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

/// The run-time view and the run-time changes of SID 0018. Each change applies to
/// reservations made after it. A [`Ticket`] already issued keeps its server.
impl Pool {
    /// The protocol of the pool's servers.
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Why the membership and the weights of this pool change only by reload, if they do.
    pub fn fixed(&self) -> Option<&'static str> {
        match self.scheduler {
            Scheduler::Maglev { .. } | Scheduler::Adaptive(_) => {
                Some("places clients by a table that every node builds from the file")
            }
            _ if self.adapted => Some("reaches its servers through protocol adapters"),
            _ => None,
        }
    }

    /// Appends one status per server, in the pool's order.
    pub fn statuses(&self, pool: &str, out: &mut Vec<crate::ServerStatus>) {
        let now = Instant::now();
        // The ramp weights are stored by a reservation. An idle pool is brought up to
        // date here, so that the answer is that of this moment.
        let ramping = self.ramp(now);
        out.extend(self.targets.iter().map(|target| crate::ServerStatus {
            pool: pool.to_owned(),
            name: target.server.name.clone(),
            addr: target.server.addr,
            state: if target.drained {
                crate::ServerState::Drain
            } else {
                crate::ServerState::Ready
            },
            weight: target.server.weight,
            flows: target.load.active.load(Ordering::Relaxed),
            healthy: target.server.healthy.as_ref().map(|h| h.load(Ordering::Relaxed)),
            backup: target.server.backup,
            added: target.added,
            reweighted: target.file_weight.is_some(),
            ejected: target.load.extra.ejected_for(now),
            ramp: target.ramp_percent(ramping),
        }));
    }

    /// The names of the servers, for a "did you mean" hint.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.targets.iter().map(|target| target.server.name.as_str())
    }

    /// Counts the servers a command changed and the servers a command removed.
    pub fn change_count(&self) -> usize {
        self.targets.iter().filter(|target| target.changed()).count() + self.removed.len()
    }

    /// The drained servers by name and address, to carry them over a reload.
    pub fn drained(&self) -> impl Iterator<Item = (&str, SocketAddr)> {
        let drained = self.targets.iter().filter(|target| target.drained);
        drained.map(|target| (target.server.name.as_str(), target.server.addr))
    }

    /// The probe targets of the pool's servers: the address a probe connects to.
    pub fn probed(&self) -> impl Iterator<Item = SocketAddr> {
        self.targets.iter().map(|target| target.server.via.unwrap_or(target.server.addr))
    }

    /// Drains or readmits a server. Returns false when the pool has no such server.
    pub fn set_drained(&mut self, name: &str, drained: bool) -> bool {
        let target = self.targets.iter_mut().find(|target| target.server.name == name);
        target.map(|target| target.drained = drained).is_some()
    }

    /// Drains the server again after a reload, when the file still has it at `addr`.
    pub fn keep_drained(&mut self, name: &str, addr: SocketAddr) -> bool {
        let target = self.targets.iter_mut().find(|t| t.server.name == name);
        let same = target.filter(|target| target.server.addr == addr);
        same.map(|target| target.drained = true).is_some()
    }

    /// Sets a weight. Returns false when the pool has no such server.
    pub fn set_weight(&mut self, name: &str, weight: u32) -> bool {
        let Some(target) = self.targets.iter_mut().find(|t| t.server.name == name) else {
            return false;
        };
        let file = target.file_weight.unwrap_or(target.server.weight);
        target.server.weight = weight;
        // Setting the file's weight again leaves nothing changed.
        target.file_weight = (weight != file && !target.added).then_some(file);
        true
    }

    /// Whether a server has this name or this address.
    pub fn holds(&self, name: &str, addr: SocketAddr) -> bool {
        self.targets.iter().any(|t| t.server.name == name || t.server.addr == addr)
    }

    /// The number of servers.
    pub fn server_count(&self) -> usize {
        self.targets.len()
    }

    /// Adds a server that the caller has validated against the pool and the listeners.
    pub fn add(&mut self, server: Server, loads: &mut Loads) {
        // The name of a removed server of the file is served again, as an addition.
        let restored = self.removed.iter().position(|name| *name == server.name);
        if let Some(index) = restored {
            self.removed.swap_remove(index);
        }
        let mut target = Target::new(server, self.protocol, loads);
        target.added = true;
        self.targets.push(target);
    }

    /// Removes a server and returns its address. Its tickets stay valid.
    pub fn remove(&mut self, name: &str) -> Option<SocketAddr> {
        let index = self.targets.iter().position(|target| target.server.name == name)?;
        let target = self.targets.remove(index);
        if !target.added {
            self.removed.push(target.server.name);
        }
        Some(target.server.addr)
    }
}

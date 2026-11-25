//! Admission. A ticket holds the reservation across configuration revisions.
//!
//! A pool is read by many threads at once: a reservation takes `&self`. What a
//! reservation changes is atomic and lives in the [`Load`] of a server, which a reload
//! keeps, or in a counter that the copies of a pool share (SID 0019).

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};

use crate::config::{Backend, Protocol, Scheduler, Server};

mod extra;
mod learned;
pub(crate) use extra::{Tried, Wish};

/// The milliseconds from the first use of this clock to `at`. An atomic holds a moment
/// in this form, where it cannot hold an `Instant`.
fn millis(at: Instant) -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = *EPOCH.get_or_init(Instant::now);
    at.saturating_duration_since(epoch).as_millis() as u64
}

/// The bits of a latency sample that hold the peak, in microseconds. A peak is at most
/// one minute, which is below 2^26 microseconds.
const PEAK_BITS: u32 = 26;

#[derive(Default)]
struct Load {
    active: AtomicUsize,
    /// The last latency sample: its moment in milliseconds plus one above [`PEAK_BITS`],
    /// and the peak below. Zero before the first sample.
    latency: AtomicU64,
    /// Until when a failed connect keeps the server out, in milliseconds. Zero when
    /// no connect failed.
    retry_after: AtomicU64,
    /// The state that SID 0019 keeps for a server.
    extra: extra::State,
}

impl Load {
    fn estimate(&self, now: Instant) -> u64 {
        let sample = self.latency.load(Ordering::Relaxed);
        if sample == 0 {
            return 1000;
        }
        let (last, peak) = ((sample >> PEAK_BITS) - 1, sample & ((1 << PEAK_BITS) - 1));
        // Let an unused origin recover from an old spike. The resting estimate is 1 ms.
        let age = (millis(now).saturating_sub(last) / 1000).min(32);
        1000u64.saturating_add_signed(((peak as i64) - 1000) >> age)
    }

    /// Whether a failed connect still keeps the server out at `now`, in milliseconds.
    fn is_marked(&self, now: u64) -> bool {
        self.retry_after.load(Ordering::Relaxed) > now
    }
}

pub(crate) struct Ticket {
    pub addr: SocketAddr,
    load: Arc<Load>,
    /// The share that the flow holds a place of, on a server capped for the fleet.
    quota: Option<Arc<crate::quota::Cell>>,
}

impl Ticket {
    pub fn observe(&self, start: Instant, now: Instant) {
        let sample = now.saturating_duration_since(start).as_micros().clamp(1, 60_000_000) as u64;
        let peak = sample.max((7 * self.load.estimate(now) + sample) / 8);
        let packed = ((millis(now) + 1) << PEAK_BITS) | peak.min((1 << PEAK_BITS) - 1);
        self.load.latency.store(packed, Ordering::Relaxed);
    }

    pub fn failed(&self, now: Instant) {
        let until = millis(now + Duration::from_secs(2));
        self.load.retry_after.store(until, Ordering::Relaxed);
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        self.load.active.fetch_sub(1, Ordering::Relaxed);
        if let Some(cell) = &self.quota {
            cell.leave();
        }
    }
}

#[derive(Default)]
pub(crate) struct Loads {
    loads: HashMap<(Protocol, SocketAddr), Weak<Load>>,
    /// The sticky table and the shares of the edge (SID 0025). A pool that is built
    /// without them has neither.
    pub cluster: Option<crate::ClusterState>,
}

impl Loads {
    /// The loads of an edge whose pools use the sticky table and the shares of
    /// `cluster`.
    pub fn of(cluster: crate::ClusterState) -> Self {
        Self { loads: HashMap::new(), cluster: Some(cluster) }
    }

    pub fn prune(&mut self) {
        self.loads.retain(|_, load| load.strong_count() != 0);
    }
}

#[derive(Clone)]
struct Target {
    server: Server,
    load: Arc<Load>,
    /// The requests this server was given since the pool was loaded. The copies of a
    /// pool share the count.
    admitted: Arc<AtomicU64>,
    /// An operator took the server out of rotation for new flows (SID 0018).
    drained: bool,
    /// A command added the server; the file does not have it.
    added: bool,
    /// The weight the file gave, when a command replaced it.
    file_weight: Option<u32>,
    /// The part of the rendezvous ranking that depends on the name alone (SID 0019).
    rank_seed: u64,
    /// The sticky token of the server, in a pool that is sticky by cookie.
    token: Option<crate::sticky::Token>,
    /// The share of this node, when `max_flows` bounds the whole fleet (SID 0025).
    quota: Option<Arc<crate::quota::Cell>>,
}

impl Target {
    fn new(server: Server, protocol: Protocol, loads: &mut Loads) -> Self {
        let slot = loads.loads.entry((protocol, server.addr)).or_default();
        let load = slot.upgrade().unwrap_or_default();
        *slot = Arc::downgrade(&load);
        let rank_seed = crate::sticky::rank_seed(&server.name);
        // Without the state of an edge the limit holds on this node, as before.
        let cluster = loads.cluster.as_ref().filter(|_| server.fleet);
        let quota = cluster.map(|state| state.quotas().cell(protocol, server.addr, server.limit));
        Self {
            quota,
            server,
            load,
            admitted: Arc::default(),
            drained: false,
            added: false,
            file_weight: None,
            rank_seed,
            token: None,
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
                u128::from(target.admitted.load(Ordering::Relaxed)) * scale,
            )
        };
        (self.server.backup, score(self, other.weight(ramping)))
            < (other.server.backup, score(other, self.weight(ramping)))
    }
}

/// How often a reservation chooses again when another thread took the last place of
/// the server it chose.
const CROWDED: usize = 8;

#[derive(Clone)]
pub(crate) struct Pool {
    targets: Vec<Target>,
    scheduler: Arc<Scheduler>,
    /// The ranking table of source stickiness, when the pool has it (SID 0019).
    ranks: Option<Arc<[extra::Slot]>>,
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
    /// The learned sticky table, when the pool is sticky by one (SID 0025).
    learner: Option<Arc<learned::Learner>>,
}

impl Pool {
    pub fn new(backend: Backend, loads: &mut Loads) -> Self {
        let protocol = backend.protocol;
        let learner = learned::Learner::of(&backend.name, &backend.policy, loads.cluster.as_ref());
        let targets =
            backend.servers.into_iter().map(|s| Target::new(s, protocol, loads)).collect();
        let mut pool = Self {
            targets,
            scheduler: Arc::new(backend.scheduler),
            ranks: None,
            policy: backend.policy,
            proxy_v2: backend.proxy_v2,
            choices: RandomState::new(),
            protocol,
            health: backend.health,
            adapted: backend.origin.is_some(),
            removed: Vec::new(),
            learner: learner.map(Arc::new),
        };
        pool.rank();
        pool
    }

    pub fn reserve(
        &self,
        now: Instant,
        peer: SocketAddr,
        vip: SocketAddr,
        regime: crate::Regime,
    ) -> Option<Ticket> {
        self.reserve_with(now, peer, vip, regime, &Wish::default())
    }

    /// Reserves a place on a server that `wish` allows (SID 0019).
    ///
    /// Many threads reserve at once. A thread counts itself on the server it chose and
    /// then looks at the count: when another thread took the last place meanwhile, it
    /// gives the place back and chooses again. So a server never serves more than its
    /// limit.
    pub fn reserve_with(
        &self,
        now: Instant,
        peer: SocketAddr,
        vip: SocketAddr,
        regime: crate::Regime,
        wish: &Wish<'_>,
    ) -> Option<Ticket> {
        // The learned table names the server of the client, when it knows one. It is
        // read once here and never by the flow that this reservation begins.
        let recalled = self.learner.as_ref().and_then(|learner| {
            learner.recall(&self.targets, wish.affinity, wish.client.unwrap_or(peer.ip()))
        });
        let learned = recalled.as_ref().and_then(|recalled| recalled.index);
        let wish = &Wish { sticky: wish.sticky.or(learned), ..*wish };
        for _ in 0..CROWDED {
            let target = &self.targets[self.pick(now, peer, vip, regime, wish)?];
            if target.load.active.fetch_add(1, Ordering::Relaxed) >= target.server.limit {
                target.load.active.fetch_sub(1, Ordering::Relaxed);
                continue;
            }
            // The share of this node in a limit of the fleet (SID 0025).
            if target.quota.as_ref().is_some_and(|cell| !cell.enter()) {
                target.load.active.fetch_sub(1, Ordering::Relaxed);
                continue;
            }
            target.admitted.fetch_add(1, Ordering::Relaxed);
            if let (Some(learner), Some(recalled)) = (&self.learner, &recalled) {
                learner.note(recalled, target.rank_seed);
            }
            // An HTTP exchange enters the pool's protocol adapter when it has one.
            let addr = target.server.via.unwrap_or(target.server.addr);
            let quota = target.quota.clone();
            return Some(Ticket { addr, load: Arc::clone(&target.load), quota });
        }
        None
    }

    /// The index of the server that the scheduler and `wish` choose now.
    fn pick(
        &self,
        now: Instant,
        peer: SocketAddr,
        vip: SocketAddr,
        regime: crate::Regime,
        wish: &Wish<'_>,
    ) -> Option<usize> {
        let ramping = self.ramp(now);
        let clock = millis(now);
        let available = |target: &Target| {
            target.server.addr != vip
                && !target.drained
                && target.server.healthy.as_ref().is_none_or(|h| h.load(Ordering::Relaxed))
                && target.load.active.load(Ordering::Relaxed) < target.server.limit
                && target.quota.as_ref().is_none_or(|cell| cell.has_room())
                && !target.load.is_marked(clock)
                && wish.allows(target)
        };
        // Passive health keeps a server out only while another can serve (SID 0019).
        let spared = self.targets.iter().any(|t| available(t) && !t.load.extra.is_ejected(now));
        let available = |t: &Target| available(t) && !(spared && t.load.extra.is_ejected(now));
        let prefer_local = regime == crate::Regime::WideArea
            && self.targets.iter().any(|t| !t.server.remote && available(t));
        let eligible = |t: &Target| available(t) && !(prefer_local && t.server.remote);
        let (table, peak) = match &*self.scheduler {
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
        sticky.or(primary).or_else(|| {
            if matches!(*self.scheduler, Scheduler::RoundRobin) {
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
        })
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
        match *self.scheduler {
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
        self.rank();
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
        self.rank();
    }

    /// Removes a server and returns its address. Its tickets stay valid.
    pub fn remove(&mut self, name: &str) -> Option<SocketAddr> {
        let index = self.targets.iter().position(|target| target.server.name == name)?;
        let target = self.targets.remove(index);
        if !target.added {
            self.removed.push(target.server.name);
        }
        self.rank();
        Some(target.server.addr)
    }
}

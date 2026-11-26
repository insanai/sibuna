//! Node-wide admission shared by the accept threads, the packet worker and QUIC endpoints.
//!
//! A flow takes one permit from the budget and gives it back when it ends. A permit is
//! taken only when the node, the frontend and the client address on that frontend are
//! each below their cap (SID 0034). Takes and releases run under one lock, so the caps
//! hold whatever the order of the threads: `caps_hold` in the Lean model
//! `docs/sid/assets/admission-under-attack.lean`. The same lock holds the state of
//! pressure mode and the bucket of new addresses.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use sibuna_store::limiter::{Limits, RateLimiter};

use crate::known::Known;
use crate::{Config, Refusal};

/// What a frontend asks of the budget for each of its flows (SID 0034).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Caps {
    /// The frontend, by a hash of its name, so that its count survives a reload.
    pub frontend: u64,
    /// The most flows of the frontend on the node (`max_flows`).
    pub max_flows: Option<usize>,
    /// The most flows of one client address on the frontend (`max_flows_per_ip`).
    pub max_flows_per_ip: Option<usize>,
}

/// Pressure mode of a node (`global.pressure`, SID 0034).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PressureOptions {
    /// The load in percent of `global.max_flows` at which pressure switches on.
    pub on: u8,
    /// The load at which it switches off, below `on`.
    pub off: u8,
    /// The new addresses admitted per second while it is on.
    pub new_per_second: u32,
}

impl Default for PressureOptions {
    fn default() -> Self {
        Self { on: 90, off: 75, new_per_second: 1000 }
    }
}

/// One micro-token: a new address costs a million of them.
const TOKEN: u64 = 1_000_000;

struct Pressure {
    options: Option<PressureOptions>,
    on: bool,
    /// Tokens of the bucket of new addresses, in micro-tokens.
    tokens: u64,
    /// When the bucket was last refilled, in microseconds since the epoch of the budget.
    refilled: u64,
}

impl Pressure {
    fn new(options: Option<PressureOptions>) -> Self {
        let full = options.map_or(0, |o| u64::from(o.new_per_second) * TOKEN);
        Self { options, on: false, tokens: full, refilled: 0 }
    }

    /// Takes a token for a new address at `now` microseconds. False when none is left.
    fn take(&mut self, now: u64) -> bool {
        let Some(options) = self.options else { return true };
        let rate = u64::from(options.new_per_second);
        let elapsed = now.saturating_sub(self.refilled);
        self.refilled = now;
        self.tokens = self.tokens.saturating_add(elapsed.saturating_mul(rate)).min(rate * TOKEN);
        if self.tokens < TOKEN {
            return false;
        }
        self.tokens -= TOKEN;
        true
    }
}

struct State {
    active: usize,
    limit: usize,
    quic: BTreeMap<SocketAddr, (usize, Option<Limits>, Caps)>,
    /// The live flows of each frontend.
    frontends: HashMap<u64, usize>,
    /// The live flows of each client address on a frontend with `max_flows_per_ip`.
    addresses: HashMap<(u64, u128), usize>,
    pressure: Pressure,
}

impl State {
    fn release(&mut self, frontend: u64, address: Option<u128>) {
        self.active -= 1;
        decrement(&mut self.frontends, frontend);
        if let Some(address) = address {
            decrement(&mut self.addresses, (frontend, address));
        }
    }
}

/// Lowers the count of `key` and forgets it at zero, so the table holds only live keys.
fn decrement<K: std::hash::Hash + Eq>(counts: &mut HashMap<K, usize>, key: K) {
    if let Some(count) = counts.get_mut(&key) {
        *count -= 1;
        if *count == 0 {
            counts.remove(&key);
        }
    }
}

struct Budget {
    state: Mutex<State>,
    /// A copy of the pressure mode that the accept threads read without the lock.
    pressed: std::sync::atomic::AtomicBool,
    limiter: RateLimiter,
    known: Known,
    epoch: Instant,
}

/// One request for a permit (SID 0034).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Claim {
    /// The caps of the frontend.
    pub caps: Caps,
    /// The key of the client address, or `None` for a trusted proxy, which carries many
    /// clients and is exempt from the address cap and from pressure.
    pub client: Option<u128>,
}

impl Claim {
    /// A claim of `peer` on a frontend with `caps`. A `trusted` peer is a proxy.
    pub fn new(caps: Caps, peer: IpAddr, trusted: bool) -> Self {
        Self { caps, client: (!trusted).then(|| sibuna_cidr::client_key(peer, 64)) }
    }
}

/// Counts one slot per live client connection or UDP mapping across all transports.
#[derive(Clone)]
pub struct FlowBudget(Arc<Budget>);

impl FlowBudget {
    pub(super) fn new(config: &Config) -> Self {
        Self(Arc::new(Budget {
            state: Mutex::new(State {
                active: 0,
                limit: config.limit,
                quic: quic_limits(config),
                frontends: HashMap::new(),
                addresses: HashMap::new(),
                pressure: Pressure::new(config.pressure),
            }),
            pressed: std::sync::atomic::AtomicBool::new(false),
            limiter: RateLimiter::with_cells(65536),
            known: Known::default(),
            epoch: Instant::now(),
        }))
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn micros(&self) -> u64 {
        self.0.epoch.elapsed().as_micros() as u64
    }

    /// Reserves one slot after QUIC Retry has validated the peer's address. The
    /// frontend's rate, caps and pressure apply, as for a TCP connection.
    pub fn reserve_quic(&self, bind: SocketAddr, peer: SocketAddr) -> Option<FlowPermit> {
        let listener = self.state().quic.get(&bind).copied();
        let Some((scope, rate, caps)) = listener else {
            return self.take(Claim::new(Caps::default(), peer.ip(), false)).ok();
        };
        if let Some(rate) = rate
            && !self.allowed(scope, peer, rate)
        {
            return None;
        }
        self.take(Claim::new(caps, peer.ip(), false)).ok()
    }

    pub(super) fn allowed(&self, listener: usize, peer: SocketAddr, rate: Limits) -> bool {
        let now = self.micros();
        let check = |key: &[u8]| self.0.limiter.check_scoped(key, listener as u64, now, rate);
        match peer.ip().to_canonical() {
            IpAddr::V4(ip) => !check(&ip.octets()).limited,
            IpAddr::V6(ip) => !check(&ip.octets()[..8]).limited,
        }
    }

    /// Takes a permit for `claim`, or says which cap or pressure refused it.
    pub(crate) fn take(&self, claim: Claim) -> Result<FlowPermit, Refusal> {
        let Caps { frontend, max_flows, max_flows_per_ip } = claim.caps;
        let known = claim.client.is_some_and(|client| self.0.known.knows(client));
        let mut state = self.state();
        let now = self.micros();
        if state.active >= state.limit {
            return Err(Refusal::FlowLimit);
        }
        let held = state.frontends.get(&frontend).copied().unwrap_or(0);
        if max_flows.is_some_and(|cap| held >= cap) {
            return Err(Refusal::FrontendLimit);
        }
        let counted = claim.client.filter(|_| max_flows_per_ip.is_some());
        if let (Some(client), Some(cap)) = (counted, max_flows_per_ip)
            && state.addresses.get(&(frontend, client)).copied().unwrap_or(0) >= cap
        {
            return Err(Refusal::ClientFlowLimit);
        }
        if state.pressure.on && claim.client.is_some() && !known && !state.pressure.take(now) {
            return Err(Refusal::Pressure);
        }
        state.active += 1;
        *state.frontends.entry(frontend).or_default() += 1;
        if let Some(client) = counted {
            *state.addresses.entry((frontend, client)).or_default() += 1;
        }
        drop(state);
        let budget = self.clone();
        Ok(FlowPermit { budget, frontend, address: counted, client: claim.client })
    }

    /// Takes a permit that only the node cap bounds: a flow that no frontend admitted,
    /// such as one lent by a replaced process or forwarded by a peer.
    pub(super) fn reserve(&self) -> Option<FlowPermit> {
        self.take(Claim { caps: Caps::default(), client: None }).ok()
    }

    pub(super) fn configure(&self, config: &Config) {
        let mut state = self.state();
        state.quic = quic_limits(config);
        state.limit = config.limit;
        if state.pressure.options != config.pressure {
            state.pressure = Pressure { on: state.pressure.on, ..Pressure::new(config.pressure) };
        }
    }

    pub(super) fn drain(&self) {
        self.state().limit = 0;
    }

    pub(super) fn active(&self) -> usize {
        self.state().active
    }

    /// Switches pressure mode by the load of the node: on at `on` percent of the flow
    /// table, off at `off` percent. Returns the new mode when it changed.
    pub(super) fn update_pressure(&self) -> Option<bool> {
        let mut state = self.state();
        let options = state.pressure.options;
        let load = (state.active * 100).checked_div(state.limit.max(1)).unwrap_or(0);
        let next = options.is_some_and(|options| {
            if state.pressure.on {
                load > usize::from(options.off)
            } else {
                load >= usize::from(options.on)
            }
        });
        (next != state.pressure.on).then(|| {
            state.pressure.on = next;
            self.0.pressed.store(next, std::sync::atomic::Ordering::Relaxed);
            next
        })
    }

    /// True while pressure mode is on.
    pub(crate) fn is_pressed(&self) -> bool {
        self.0.pressed.load(std::sync::atomic::Ordering::Relaxed)
    }
}

fn quic_limits(config: &Config) -> BTreeMap<SocketAddr, (usize, Option<Limits>, Caps)> {
    config
        .listeners
        .iter()
        .enumerate()
        .filter_map(|(index, ((_, bind), route))| {
            route.tls.as_ref().filter(|tls| tls.http3)?;
            Some((*bind, (index, route.rate, route.guard.caps)))
        })
        .collect()
}

/// A flow slot, released on cancellation, close or expiry.
pub struct FlowPermit {
    budget: FlowBudget,
    frontend: u64,
    /// The address key counted under `max_flows_per_ip`, when it was counted.
    address: Option<u128>,
    /// The address key of the client, for proofs; `None` for a trusted proxy.
    client: Option<u128>,
}

impl FlowPermit {
    /// Records that the flow of this permit proved its client: the address becomes
    /// known for pressure mode (SID 0034). A proxy proves nobody.
    pub fn prove(&self) {
        if let Some(client) = self.client {
            self.budget.0.known.prove(client);
        }
    }
}

impl Drop for FlowPermit {
    fn drop(&mut self) {
        self.budget.state().release(self.frontend, self.address);
    }
}

#[cfg(test)]
mod tests;

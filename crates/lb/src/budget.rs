//! Node-wide admission shared by the packet worker and QUIC endpoints.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use sibuna_store::limiter::{Limits, RateLimiter};

use crate::Config;

struct State {
    active: usize,
    limit: usize,
    quic: BTreeMap<SocketAddr, (usize, Limits)>,
}

struct Budget {
    state: Mutex<State>,
    limiter: RateLimiter,
    epoch: Instant,
}

/// Counts one slot per live client connection or UDP mapping across all transports.
#[derive(Clone)]
pub struct FlowBudget(Arc<Budget>);

impl FlowBudget {
    pub(super) fn new(config: &Config) -> Self {
        Self(Arc::new(Budget {
            state: Mutex::new(State { active: 0, limit: config.limit, quic: quic_limits(config) }),
            limiter: RateLimiter::with_cells(65536),
            epoch: Instant::now(),
        }))
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Reserves one slot after QUIC Retry has validated the peer's address.
    pub fn reserve_quic(&self, bind: SocketAddr, peer: SocketAddr) -> Option<FlowPermit> {
        let mut state = self.state();
        if let Some(&(scope, rate)) = state.quic.get(&bind)
            && !self.allowed(scope, peer, rate)
        {
            return None;
        }
        self.take(&mut state)
    }

    pub(super) fn allowed(&self, listener: usize, peer: SocketAddr, rate: Limits) -> bool {
        let now = self.0.epoch.elapsed().as_micros() as u64;
        let check = |key: &[u8]| self.0.limiter.check_scoped(key, listener as u64, now, rate);
        match peer.ip().to_canonical() {
            IpAddr::V4(ip) => !check(&ip.octets()).limited,
            IpAddr::V6(ip) => !check(&ip.octets()[..8]).limited,
        }
    }

    fn take(&self, state: &mut State) -> Option<FlowPermit> {
        if state.active >= state.limit {
            return None;
        }
        state.active += 1;
        Some(FlowPermit { budget: self.clone() })
    }

    pub(super) fn reserve(&self) -> Option<FlowPermit> {
        self.take(&mut self.state())
    }

    pub(super) fn configure(&self, config: &Config) {
        let mut state = self.state();
        state.quic = quic_limits(config);
        state.limit = config.limit;
    }

    pub(super) fn drain(&self) {
        self.state().limit = 0;
    }

    pub(super) fn active(&self) -> usize {
        self.state().active
    }
}

fn quic_limits(config: &Config) -> BTreeMap<SocketAddr, (usize, Limits)> {
    config
        .listeners
        .iter()
        .enumerate()
        .filter_map(|(index, ((_, bind), route))| {
            route.tls.as_ref().filter(|tls| tls.http3)?;
            Some((*bind, (index, route.rate?)))
        })
        .collect()
}

/// A flow slot, released on cancellation, close or expiry.
pub struct FlowPermit {
    budget: FlowBudget,
}

impl Drop for FlowPermit {
    fn drop(&mut self) {
        self.budget.state().active -= 1;
    }
}

#[cfg(test)]
mod tests;

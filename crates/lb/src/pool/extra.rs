//! What SID 0019 adds to admission: the servers a request already tried, and passive
//! health.
//!
//! The state of a server lives in its [`Load`], which a reload keeps for every address.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use super::{Load, Target, Ticket};
use crate::Passive;

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

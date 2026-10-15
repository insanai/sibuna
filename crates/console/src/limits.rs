//! Fixed-window allowances (Zig's `limiter.zig` and `query_budget.zig`).
//!
//! - [`Limiter`]: password verification attempts, five per minute per key. The login route
//!   asks once with an address key and once with an account key (domain-separated digests),
//!   and the kiosk exchange with keys of its own.
//! - [`QueryBudget`]: management reads, exports and mutations per credential digest, plus a
//!   global allowance for reads and exports.
//!
//! Both tables are fixed-size and never evict a live key: when every slot is live, new keys
//! are refused, so an attacker cannot reset an allowance by flooding the table with other
//! keys. Each table is one `Mutex`; a request holds it for one scan of at most 4,096 slots.
//! The slot arrays are boxed so the tables do not sit on a thread's stack.

use std::fmt;
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Slots of the login limiter.
pub const LIMITER_SLOTS: usize = 2048;
/// Attempts per key per window.
pub const LOGIN_ATTEMPTS: u16 = 5;
/// The length of every window, in seconds.
pub const WINDOW_SECONDS: u64 = 60;
/// Slots of the query budget.
pub const BUDGET_SLOTS: usize = 4096;
/// Reads (queries, exports and mutations together) per credential per window.
pub const SESSION_QUERIES: u16 = 120;
/// Export pages per credential per window.
pub const SESSION_EXPORTS: u16 = 6;
/// Management mutations per credential per window (SID 0007: 60 per minute per session).
pub const SESSION_MUTATIONS: u16 = 60;
/// Reads of every credential together per window.
pub const GLOBAL_QUERIES: u16 = 1200;
/// Export pages of every credential together per window.
pub const GLOBAL_EXPORTS: u16 = 30;

/// Locks `mutex`, recovering the data after a panic elsewhere: every update of these
/// tables is a few plain assignments, so a poisoned table is still consistent.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Clone, Copy, Default)]
struct LimiterSlot {
    key: [u8; 32],
    until: u64,
    count: u16,
}

/// Five attempts per key per fixed 60-second window, over [`LIMITER_SLOTS`] keys.
pub struct Limiter {
    slots: Mutex<Box<[LimiterSlot]>>,
}

impl fmt::Debug for Limiter {
    /// Shows no keys: they are digests of addresses and accounts.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Limiter").finish_non_exhaustive()
    }
}

impl Default for Limiter {
    fn default() -> Limiter {
        Limiter::new()
    }
}

impl Limiter {
    /// Returns an empty limiter.
    pub fn new() -> Limiter {
        Limiter { slots: Mutex::new(vec![LimiterSlot::default(); LIMITER_SLOTS].into()) }
    }

    /// Counts one attempt for `key` at `now` (Unix seconds) and returns whether it is
    /// allowed: at most [`LOGIN_ATTEMPTS`] per key until its window ends. Returns false when
    /// the key is exhausted, or new and every slot holds a live key.
    pub fn allow(&self, key: &[u8; 32], now: u64) -> bool {
        let mut slots = lock(&self.slots);
        let mut free = None;
        for (index, slot) in slots.iter_mut().enumerate() {
            if slot.until <= now {
                free.get_or_insert(index);
                continue;
            }
            if &slot.key != key {
                continue;
            }
            if slot.count >= LOGIN_ATTEMPTS {
                return false;
            }
            slot.count += 1;
            return true;
        }
        let Some(slot) = free.and_then(|index| slots.get_mut(index)) else { return false };
        *slot = LimiterSlot { key: *key, until: now.saturating_add(WINDOW_SECONDS), count: 1 };
        true
    }
}

/// What a request spends from the [`QueryBudget`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Spend {
    /// A management read.
    Query,
    /// One page of an export; also a read.
    Export,
    /// A management mutation; also a read.
    Mutation,
}

#[derive(Clone, Copy, Default)]
struct BudgetSlot {
    digest: [u8; 32],
    until: u64,
    queries: u16,
    exports: u16,
    mutations: u16,
}

struct BudgetTable {
    slots: Box<[BudgetSlot]>,
    until: u64,
    queries: u16,
    exports: u16,
}

/// Fixed-window management budgets per credential digest, and global read and export
/// budgets, separate from the login [`Limiter`].
pub struct QueryBudget {
    table: Mutex<BudgetTable>,
}

impl fmt::Debug for QueryBudget {
    /// Shows no digests: they identify credentials.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueryBudget").finish_non_exhaustive()
    }
}

impl Default for QueryBudget {
    fn default() -> QueryBudget {
        QueryBudget::new()
    }
}

impl QueryBudget {
    /// Returns a budget with every allowance unspent.
    pub fn new() -> QueryBudget {
        let slots = vec![BudgetSlot::default(); BUDGET_SLOTS].into();
        QueryBudget { table: Mutex::new(BudgetTable { slots, until: 0, queries: 0, exports: 0 }) }
    }

    /// Spends `spend` for the credential `digest` at `now` (Unix seconds) and returns
    /// whether it was allowed. Every spend is a read: at most [`SESSION_QUERIES`] per
    /// credential and [`GLOBAL_QUERIES`] in all per window; exports at most
    /// [`SESSION_EXPORTS`] and [`GLOBAL_EXPORTS`]; mutations at most [`SESSION_MUTATIONS`].
    /// A refused spend changes nothing.
    pub fn allow(&self, digest: &[u8; 32], now: u64, spend: Spend) -> bool {
        let mut table = lock(&self.table);
        if table.until <= now {
            table.until = now.saturating_add(WINDOW_SECONDS);
            table.queries = 0;
            table.exports = 0;
        }
        let exporting = spend == Spend::Export;
        if table.queries >= GLOBAL_QUERIES || (exporting && table.exports >= GLOBAL_EXPORTS) {
            return false;
        }
        let Some(index) = find_slot(&table.slots, digest, now) else { return false };
        let Some(slot) = table.slots.get_mut(index) else { return false };
        if slot.until <= now {
            let until = now.saturating_add(WINDOW_SECONDS);
            *slot = BudgetSlot { digest: *digest, until, ..BudgetSlot::default() };
        }
        if slot.queries >= SESSION_QUERIES || (exporting && slot.exports >= SESSION_EXPORTS) {
            return false;
        }
        if spend == Spend::Mutation && slot.mutations >= SESSION_MUTATIONS {
            return false;
        }
        slot.queries += 1;
        slot.mutations += u16::from(spend == Spend::Mutation);
        slot.exports += u16::from(exporting);
        table.queries += 1;
        table.exports += u16::from(exporting);
        true
    }
}

/// Returns the live slot of `digest`, or else the first expired slot, or `None` when every
/// slot holds another live digest.
fn find_slot(slots: &[BudgetSlot], digest: &[u8; 32], now: u64) -> Option<usize> {
    let mut free = None;
    for (index, slot) in slots.iter().enumerate() {
        if slot.until <= now {
            free.get_or_insert(index);
        } else if &slot.digest == digest {
            return Some(index);
        }
    }
    free
}

#[cfg(test)]
mod tests {
    use super::*;

    // limiter.zig: "login allowance has fixed window and cannot evict live accounts".
    #[test]
    fn login_allowance_has_a_fixed_window_and_cannot_evict_live_keys() {
        let limiter = Limiter::new();
        for _ in 0..5 {
            assert!(limiter.allow(&[1; 32], 10));
        }
        assert!(!limiter.allow(&[1; 32], 69));
        assert!(limiter.allow(&[1; 32], 70));
        // A full table of live keys refuses a new key instead of evicting one.
        let full = Limiter::new();
        for index in 0..LIMITER_SLOTS {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&(index as u64).to_le_bytes());
            assert!(full.allow(&key, 100));
        }
        assert!(!full.allow(&[0xff; 32], 159));
        assert!(full.allow(&[0xff; 32], 160));
    }

    // query_budget.zig: "investigation budgets isolate sessions and exports and bound
    // global work".
    #[test]
    fn budgets_isolate_sessions_and_exports_and_bound_global_work() {
        let budget = QueryBudget::new();
        for _ in 0..6 {
            assert!(budget.allow(&[1; 32], 10, Spend::Export));
        }
        assert!(!budget.allow(&[1; 32], 10, Spend::Export));
        for _ in 0..114 {
            assert!(budget.allow(&[1; 32], 10, Spend::Query));
        }
        assert!(!budget.allow(&[1; 32], 69, Spend::Query));
        assert!(budget.allow(&[2; 32], 69, Spend::Query));
        assert!(budget.allow(&[1; 32], 70, Spend::Export));
        lock(&budget.table).queries = GLOBAL_QUERIES;
        assert!(!budget.allow(&[3; 32], 70, Spend::Query));
    }

    // query_budget.zig: "management mutations have an independent sixty-per-minute session
    // allowance".
    #[test]
    fn mutations_have_an_independent_sixty_per_minute_allowance() {
        let budget = QueryBudget::new();
        for _ in 0..60 {
            assert!(budget.allow(&[1; 32], 10, Spend::Mutation));
        }
        assert!(!budget.allow(&[1; 32], 69, Spend::Mutation));
        assert!(budget.allow(&[1; 32], 69, Spend::Query));
        assert!(budget.allow(&[2; 32], 69, Spend::Mutation));
        assert!(budget.allow(&[1; 32], 70, Spend::Mutation));
    }
}

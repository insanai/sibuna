//! What the daemon does for the console: the [`Node`] trait.
//!
//! The console never reaches into the data plane (SID 0007, invariants I1 to I3). The few
//! local effects it needs (drain, clear the local bans) and the few live readings that are
//! not atomics it can load itself (the ban gauge, rule-hit counters of the published engine,
//! the applied policy revision) go through this trait, which the daemon implements in
//! `cmd/sibuna/src/console/node.rs` and tests implement with a fake.

use std::fmt;
use std::sync::Arc;

use sibuna_console_protocol::rule_hits::{Generation, MAX_RULES};
use sibuna_store::rule_hits::Snapshot;

/// The rule-hit counters of the published engine at one moment, with the identity of the
/// generation they count (SID 0007, "Rule observations").
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleHitSample {
    /// Which engine generation the counters belong to: node, boot, number, policy revision,
    /// publication time and the rule identities in match-index order.
    pub generation: Generation,
    /// The counter values, read from the generation's own counters.
    pub counts: Snapshot<MAX_RULES>,
    /// The final counter values of the generation the previous sample read, when a
    /// publication has retired it since; `retired.generation` names it. The daemon keeps a
    /// retired generation's counters until a sample has read them, so the hits counted
    /// between the last sample and the publication are not lost.
    pub retired: Option<Snapshot<MAX_RULES>>,
}

/// The daemon's side of the console: local effects and live readings.
///
/// Every method may be called from any console thread and must not block for long: the
/// collector calls the readings once a second, the node-command route calls the effects.
/// None of them may take a lock that a request thread holds while serving a request, except
/// [`Node::clear_local_bans`], a rare audited command (SID 0007, "Cluster Management").
pub trait Node: Send + Sync + fmt::Debug {
    /// Sets the drain flag the accept loop reads: while set, the node answers 503 "node is
    /// draining" to new connections and finishes the current ones.
    fn set_draining(&self, draining: bool);

    /// Returns the drain flag.
    fn is_draining(&self) -> bool;

    /// Removes every local ban (not the replicated reputation denials) and returns how many
    /// entries were removed. `now` is Unix seconds.
    fn clear_local_bans(&self, now: u64) -> u32;

    /// Returns the number of active local bans at `now` (Unix seconds), read without the
    /// ban table's writer lock; approximate is acceptable for a gauge (decision 5). `None`
    /// when the node has no ban table.
    fn active_bans(&self, now: u64) -> Option<u32>;

    /// Fills `sample` with the published engine's rule-hit counters and their generation
    /// and returns true, or returns false (leaving `sample` unspecified) when the engine has
    /// no counters. When a publication retired the generation the previous call read, its
    /// final counters go to `sample.retired` (once), else `sample.retired` is `None`.
    /// `sample` is reused across calls so the collector does not allocate.
    fn sample_rule_hits(&self, sample: &mut RuleHitSample) -> bool;

    /// Returns the policy revision of the engine the node currently serves; 0 before the
    /// first snapshot was applied.
    fn applied_revision(&self) -> u64;

    /// Returns how many data-plane connections the node serves now, for `nodes/local`; 0
    /// when the node does not report it (the default).
    fn connection_count(&self) -> u32 {
        0
    }

    /// Returns the engine the node currently serves, for the policy page's applied rules,
    /// inspection modes and reputation trie size (Zig read the published engine on the
    /// storage owner). `None` when the node does not report it; the default.
    fn engine(&self) -> Option<Arc<sibuna_policy::Engine>> {
        None
    }
}

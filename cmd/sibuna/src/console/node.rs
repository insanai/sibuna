//! The daemon's side of the console: local effects and live readings (the console's
//! [`Node`] trait; Zig's `console_node_state.zig` and the readings of
//! `console_policy_hits.zig`).
//!
//! Every method reads atomics or takes a short lock off the request path: the drain flag
//! and the connection count are atomics the accept loop maintains, the ban gauge is the ban
//! table's lock-free count (decision 5), rule hits are read from the published engine's
//! counters, the engine is the published `Arc`, and only the rare audited clear of the
//! local bans takes the ban table's writer lock.

use std::sync::Arc;

use sibuna_console::{Node, RuleHitSample};
use sibuna_policy::Engine;

use crate::server::Server;

/// The console's view of this daemon.
#[derive(Debug)]
pub struct DaemonNode {
    server: Arc<Server>,
}

impl DaemonNode {
    /// Returns the node of `server`.
    pub fn new(server: Arc<Server>) -> DaemonNode {
        DaemonNode { server }
    }
}

impl Node for DaemonNode {
    fn set_draining(&self, draining: bool) {
        self.server.set_draining(draining);
    }

    fn is_draining(&self) -> bool {
        self.server.is_draining()
    }

    fn clear_local_bans(&self, now: u64) -> u32 {
        self.server.bans().clear(now)
    }

    fn active_bans(&self, now: u64) -> Option<u32> {
        Some(self.server.bans().approximate_active_count(now))
    }

    fn sample_rule_hits(&self, sample: &mut RuleHitSample) -> bool {
        self.server.slot().sample_hits(sample)
    }

    fn applied_revision(&self) -> u64 {
        // While the console runs every stored snapshot is published with its counters,
        // whose generation names the revision; the startup engine has none.
        self.server.slot().load_hits().map_or(0, |hits| hits.generation().revision)
    }

    fn connection_count(&self) -> u32 {
        self.server.connection_count()
    }

    fn engine(&self) -> Option<Arc<Engine>> {
        Some(self.server.slot().load())
    }
}

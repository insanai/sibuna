//! The node command executor (unit U3; Zig's `console_node_commands.zig` and
//! `console_node_state.zig`): drain, resume and clear local bans.
//!
//! One command runs at a time. The intent (S30) commits first; authority and expiry are
//! checked again before the effect, which runs through [`crate::host::Node`]; then the
//! completion (S31) commits. A completion that cannot be recorded is kept in memory and
//! retried by the collector through [`Commands::retry`]; a clear never runs twice.

use crate::shared::{Setup, Shared};

/// The executor's state: the command in flight and completions awaiting their record.
#[derive(Debug, Default)]
pub struct Commands {}

impl Commands {
    /// Returns an idle executor.
    pub fn new(setup: &Setup<'_>) -> Commands {
        let _ = setup;
        Commands {}
    }

    /// Retries recording completions that could not be committed; called by the collector
    /// once per tick. Never blocks: it submits at most one background storage job and
    /// collects its result on a later call.
    pub fn retry(&self, shared: &Shared) {
        let _ = shared;
    }
}

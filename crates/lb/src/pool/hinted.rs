//! The pool's side of learned source affinity (SID 0027): ask for the hint of a client
//! before the choice, and remember the choice after it.

use std::net::SocketAddr;
use std::sync::Arc;

use super::{Pool, Target, Wish};
use crate::Sticky;
use crate::hints::{self, Hints, Recall};
use crate::sticky;

/// The hints of the edge as one pool uses them.
#[derive(Clone)]
pub(super) struct Link {
    hints: Arc<Hints>,
    /// The part of every key that names this pool.
    seed: u64,
}

/// What a pool learned about a client before it chose a server.
pub(super) struct Recalled {
    key: u64,
    now: u32,
    /// The choice is made without a hint.
    missed: bool,
    /// The server that the hint names, when the pool still has it.
    pub server: Option<usize>,
}

impl Pool {
    /// Gives the pool `name` the hints of the edge, when it is sticky by source. Other
    /// pools, and every pool of an edge without hints, keep none.
    pub(crate) fn remember(&mut self, hints: Option<&Arc<Hints>>, name: &str) {
        let source = self.policy.sticky == Some(Sticky::Source);
        self.hints = hints
            .filter(|_| source)
            .map(|hints| Link { hints: Arc::clone(hints), seed: hints::pool_seed(name) });
    }

    /// The hint of the client of this reservation. `None` when the pool keeps no hints.
    pub(super) fn recall(&self, wish: &Wish<'_>, peer: SocketAddr) -> Option<Recalled> {
        let link = self.hints.as_ref()?;
        let client = sticky::client_bytes(wish.client.unwrap_or(peer.ip()));
        let (key, now) = (hints::key(link.seed, &client), hints::now());
        let recalled = match link.hints.recall(key, now) {
            Recall::Miss => Recalled { key, now, missed: true, server: None },
            Recall::Hit(tag) => {
                let named = |target: &Target| hints::tag(target.rank_seed) == tag;
                let server = self.targets.iter().position(named);
                Recalled { key, now, missed: false, server }
            }
        };
        Some(recalled)
    }

    /// Remembers that `target` now serves the client of `recalled`. A backup is not
    /// remembered: it serves only while no other server can.
    pub(super) fn learn(&self, recalled: Option<&Recalled>, target: &Target) {
        let (Some(link), Some(recalled)) = (&self.hints, recalled) else { return };
        if target.server.backup {
            return;
        }
        let tag = hints::tag(target.rank_seed);
        link.hints.learn(recalled.key, tag, recalled.missed, recalled.now);
    }
}

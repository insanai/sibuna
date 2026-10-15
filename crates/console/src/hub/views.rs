//! The state views of the `nodes` and `policy` topics, as the feeder builds them.

use std::fmt::{self, Write};

use sibuna_console_protocol::codec::{Encode, counter_field, field};
use sibuna_console_protocol::nodes::{Page, Peer, Probe};
use sibuna_json::Writer;

/// The `nodes` topic's view: the membership page, this console's probes and the direct
/// reports of its peers (the shape of the `nodes` route's reply).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NodesView {
    /// The membership page.
    pub page: Page,
    /// This console's probes, in configuration order.
    pub probes: Vec<Probe>,
    /// The configured peers' reports.
    pub peers: Vec<Peer>,
    /// When the view was assembled, in Unix seconds.
    pub observed_at: u64,
}

impl NodesView {
    /// Returns the view restricted to `node`: its member row, probes and peer report.
    pub fn filtered(&self, node: u32) -> NodesView {
        let mut page = self.page.clone();
        page.members.retain(|member| member.node == node);
        NodesView {
            page,
            probes: self.probes.iter().filter(|probe| probe.node == node).cloned().collect(),
            peers: self.peers.iter().filter(|peer| peer.node == node).cloned().collect(),
            observed_at: self.observed_at,
        }
    }
}

impl Encode for NodesView {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "page", &self.page)?;
        field(json, "probes", &self.probes)?;
        field(json, "peers", &self.peers)?;
        counter_field(json, "observed_at", self.observed_at)?;
        json.end_object()
    }
}

/// The `policy` topic's view: the committed revision and the one this node applies.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PolicyView {
    /// This node.
    pub node: u32,
    /// The committed policy revision.
    pub committed: u64,
    /// The revision of the engine this node serves.
    pub applied: u64,
    /// When the revision was read, in Unix seconds.
    pub observed_at: u64,
}

impl Encode for PolicyView {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "node", &self.node)?;
        counter_field(json, "committed", self.committed)?;
        counter_field(json, "applied", self.applied)?;
        counter_field(json, "observed_at", self.observed_at)?;
        json.end_object()
    }
}

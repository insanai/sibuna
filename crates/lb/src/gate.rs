//! The connection stage of the hooks (SID 0030): the worker asks the hooks of a
//! frontend before it starts a flow.

use std::net::SocketAddr;
use std::sync::Arc;

use sibuna_plugin::{Local, Protocol, Slot, Stage, Verdict, View};

/// The published hooks and this worker's own instances of them.
pub(crate) struct Gate {
    slot: Arc<Slot>,
    local: Local,
}

/// What the connection stage knows about a new flow.
pub(crate) struct Flow<'a> {
    pub protocol: Protocol,
    pub secure: bool,
    pub client: SocketAddr,
    pub local: SocketAddr,
    pub frontend: &'a str,
    /// The server name and the JA4 fingerprint of an inspected ClientHello, else empty.
    pub server_name: &'a [u8],
    pub ja4: &'a [u8],
}

impl Gate {
    pub fn new(slot: Arc<Slot>) -> Gate {
        Gate { slot, local: Local::new() }
    }
}

/// Whether a connection that arrived at `local` came in through the listener `bind`.
pub(crate) fn covers(bind: SocketAddr, local: SocketAddr) -> bool {
    bind == local || (bind.ip().is_unspecified() && bind.port() == local.port())
}

/// Whether the connection hooks of the frontend admit `flow`. Without a gate, and
/// without a connection hook in the node, the answer costs one atomic load at most.
/// A challenge has no meaning before a request exists, so it refuses like a denial.
pub(crate) fn admits(gate: &mut Option<Gate>, flow: &Flow<'_>) -> bool {
    let Some(gate) = gate else { return true };
    if !gate.slot.has(Stage::Connection) {
        return true;
    }
    let view = View {
        stage: Stage::Connection,
        protocol: flow.protocol,
        secure: flow.secure,
        client: flow.client,
        local: flow.local,
        frontend: flow.frontend,
        server_name: flow.server_name,
        ja4: flow.ja4,
        ..View::default()
    };
    gate.local.run(&gate.slot, &view).verdict == Verdict::Admit
}

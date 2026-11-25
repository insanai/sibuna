//! The connection stage of the hooks (SID 0030): the worker asks the hooks of a
//! frontend before it starts a flow.
//!
//! The worker accepts for every frontend, so it never waits for an agent. A flow whose
//! chain names an agent is parked: the judges of `sibuna-plugin` decide it on their
//! own threads and wake the worker with the ruling.
//!
//! ```text
//!  accept / ClientHello / first datagram
//!        |
//!   [rule] -- no agent in the chain --> admit or deny at once
//!        |
//!        +-- agent --> [Judges::submit] --> Parked(ticket) ... wake --> [Gate::next]
//!                          | queue full
//!                          +--> the chain runs here, its agents fail with overload
//! ```

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use sibuna_plugin::{Case, Judges, Local, Protocol, Slot, Stage, Verdict, View};
use sibuna_reactor::Wake;

use crate::{Client, FlowPermit, Inspecting, forward, inspect};

/// A parked flow without a ruling after this time is dropped. The judges answer
/// within the deadlines of the agents, so this passes only if a judge died.
const PARKED_LIMIT: Duration = Duration::from_secs(5);

/// A flow that waits for the ruling of the judges, with all that it holds.
pub(crate) enum Parked {
    /// An accepted connection that has started nothing yet.
    Stream {
        listener: usize,
        client: TcpStream,
        peer: SocketAddr,
        reached: Option<SocketAddr>,
        permit: FlowPermit,
        named: Option<SocketAddr>,
    },
    /// A connection whose inspection ended with `end`.
    Hello { id: u64, flow: Box<Inspecting>, end: inspect::End },
    /// The first datagram of a UDP client and the permit of its mapping.
    Datagram { key: Client, permit: FlowPermit, bytes: Vec<u8>, via: Option<forward::Via> },
}

/// What the connection hooks say about a new flow.
pub(crate) enum Ruling {
    Admit,
    Deny,
    /// The judges decide. The caller parks the flow under this ticket.
    Parked(u64),
}

/// The ticket of a parked flow and whether the judges admit it.
type Ruled = (u64, bool);

/// The published hooks, this worker's own instances of them, and its parked flows.
pub(crate) struct Gate {
    slot: Arc<Slot>,
    local: Local,
    wake: Option<Wake>,
    /// Started when the first flow is parked.
    judges: Option<Judges>,
    rulings: (Sender<Ruled>, Receiver<Ruled>),
    parked: HashMap<u64, (Instant, Parked)>,
    /// The UDP clients among the parked flows. Their further datagrams are dropped.
    clients: HashSet<Client>,
    next: u64,
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
    /// A gate for the hooks that `slot` publishes. The judges wake the worker
    /// through `wake`.
    pub fn new(slot: Arc<Slot>, wake: Option<Wake>) -> Gate {
        Gate {
            slot,
            local: Local::new(),
            wake,
            judges: None,
            rulings: mpsc::channel(),
            parked: HashMap::new(),
            clients: HashSet::new(),
            next: 0,
        }
    }

    /// Gives the case of `view` to the judges. Returns the ticket of the ruling, or
    /// `None` when the judges have no room or cannot start.
    fn submit(&mut self, view: &View<'_>) -> Option<u64> {
        let wake = self.wake.clone()?;
        if self.judges.is_none() {
            let options = self.slot.load().judges();
            self.judges = Judges::start(&self.slot, options).ok();
        }
        let judges = self.judges.as_ref()?;
        self.next = self.next.wrapping_add(1);
        let (ticket, rulings) = (self.next, self.rulings.0.clone());
        let deliver = Box::new(move |answer: sibuna_plugin::Answer| {
            let _ = rulings.send((ticket, answer.verdict == Verdict::Admit));
            wake.wake();
        });
        judges.submit(Case::of(view), deliver).then_some(ticket)
    }

    /// Keeps `flow` until the ruling of `ticket` arrives.
    pub fn hold(&mut self, ticket: u64, flow: Parked) {
        if let Parked::Datagram { key, .. } = &flow {
            self.clients.insert(*key);
        }
        self.parked.insert(ticket, (Instant::now(), flow));
    }

    /// True while the first datagram of the UDP client `key` waits for its ruling.
    pub fn holds(&self, key: Client) -> bool {
        !self.clients.is_empty() && self.clients.contains(&key)
    }

    /// The next parked flow that has its ruling, and whether it is admitted. A flow
    /// that waited longer than [`PARKED_LIMIT`] at `now` comes back as denied.
    pub fn next(&mut self, now: Instant) -> Option<(Parked, bool)> {
        let ruled = loop {
            match self.rulings.1.try_recv() {
                Ok((ticket, admitted)) => {
                    // A ruling for a flow that was dropped as overdue has no flow.
                    if let Some((_, flow)) = self.parked.remove(&ticket) {
                        break Some((flow, admitted));
                    }
                }
                Err(_) => break None,
            }
        };
        let ruled = ruled.or_else(|| {
            let overdue = |(_, (since, _)): &(&u64, &(Instant, Parked))| {
                now.saturating_duration_since(*since) >= PARKED_LIMIT
            };
            let ticket = *self.parked.iter().find(overdue)?.0;
            self.parked.remove(&ticket).map(|(_, flow)| (flow, false))
        });
        if let Some((Parked::Datagram { key, .. }, _)) = &ruled {
            self.clients.remove(key);
        }
        ruled
    }
}

/// Whether a connection that arrived at `local` came in through the listener `bind`.
pub(crate) fn covers(bind: SocketAddr, local: SocketAddr) -> bool {
    bind == local || (bind.ip().is_unspecified() && bind.port() == local.port())
}

/// Asks the connection hooks of the frontend about `flow`. Without a gate, and
/// without a connection hook in the node, the answer costs one atomic load at most.
/// A challenge has no meaning before a request exists, so it refuses like a denial.
/// A chain that names an agent is not run here: the judges run it.
pub(crate) fn rule(gate: &mut Option<Gate>, flow: &Flow<'_>) -> Ruling {
    let Some(gate) = gate else { return Ruling::Admit };
    if !gate.slot.has(Stage::Connection) {
        return Ruling::Admit;
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
    let verdict = if !gate.local.parks(&gate.slot, flow.frontend, Stage::Connection) {
        gate.local.run(&gate.slot, &view).verdict
    } else if let Some(ticket) = gate.submit(&view) {
        return Ruling::Parked(ticket);
    } else {
        gate.local.run_shedding(&gate.slot, &view).verdict
    };
    if verdict == Verdict::Admit { Ruling::Admit } else { Ruling::Deny }
}

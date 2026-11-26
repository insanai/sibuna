//! Accept threads (SID 0034).
//!
//! Several threads accept the connections of the TCP and HTTP listeners and run the
//! cheap checks of admission on them: the drain, bans, the connection rate, the caps and
//! pressure. A refusal ends on the thread that accepted, so a flood is refused on every
//! core. An admitted connection goes with its permit to the packet worker, which runs
//! the hooks, the inspection and the choice of a server, as before.
//!
//! The packet worker owns the listeners and publishes the [`Table`] that the threads
//! watch. A thread swaps in a new table when it wakes, and the worker wakes them on
//! every publish. Each thread registers every listener with an exclusive interest, so on
//! Linux one connection wakes one thread.

use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sibuna_reactor::{Poller, READ, READ_EXCLUSIVE, Wake, Waker, handle};
use sibuna_store::limiter::Limits;

use crate::budget::Claim;
use crate::config::Protocol;
use crate::defense::unix_now;
use crate::guard::{Guard, Refuse, TARPIT};
use crate::{Defense, FlowBudget, FlowPermit, FrontendInfo, Refusal, Stats, flowlog};

/// The most connections one thread accepts from one listener per wake-up, so that the
/// other listeners also make progress.
const BATCH: usize = 64;
/// The most connections one thread holds in its tarpit.
const TARPIT_SLOTS: usize = 1024;
/// How long a listener that ran out of descriptors rests on one thread.
const PAUSE: Duration = Duration::from_millis(50);
/// The key of the waker in the poller of a thread.
const WAKE: usize = usize::MAX;
/// The longest wait of [`Acceptors::publish_and_settle`].
const SETTLE: Duration = Duration::from_millis(500);

/// What admission needs to know about one listener.
#[derive(Clone)]
pub(crate) struct Rules {
    /// The index of the listener in the packet worker.
    pub listener: usize,
    pub protocol: Protocol,
    pub info: Arc<FrontendInfo>,
    pub pool: Arc<str>,
    pub rate: Option<Limits>,
    pub guard: Guard,
}

/// A listener that the threads watch.
pub(crate) struct Entry {
    pub socket: Arc<TcpListener>,
    pub rules: Rules,
}

/// The listeners that the threads watch now.
#[derive(Default)]
pub(crate) struct Table {
    pub entries: Vec<Entry>,
}

/// An admitted connection on its way to the packet worker.
pub(crate) struct Arrival {
    pub listener: usize,
    pub stream: TcpStream,
    pub peer: SocketAddr,
    /// The permit of the connection, or `None` for a connection of a PROXY frontend:
    /// the worker admits it once it has read the header.
    pub permit: Option<FlowPermit>,
}

/// What the threads share with the packet worker.
pub(crate) struct Shared {
    table: Mutex<Arc<Table>>,
    generation: AtomicU64,
    stop: AtomicBool,
    draining: AtomicBool,
    pub budget: FlowBudget,
    pub defense: Arc<Defense>,
    pub stats: Arc<Stats>,
    pub flow_log: Arc<flowlog::FlowLog>,
    /// Connections refused or lost on the threads.
    drops: AtomicU64,
    /// Wakes the packet worker after an arrival.
    edge: Wake,
}

/// The accept threads of a packet worker. Dropping it stops and joins them.
pub(crate) struct Acceptors {
    shared: Arc<Shared>,
    threads: Vec<Handle>,
    /// The admitted connections.
    pub arrivals: mpsc::Receiver<Arrival>,
}

/// The parent's side of one thread.
struct Handle {
    wake: Wake,
    /// The generation of the table the thread watches.
    seen: Arc<AtomicU64>,
    thread: Option<JoinHandle<()>>,
}

/// What a thread needs besides the shared state.
pub(crate) struct Parts {
    pub budget: FlowBudget,
    pub defense: Arc<Defense>,
    pub stats: Arc<Stats>,
    pub flow_log: Arc<flowlog::FlowLog>,
    pub edge: Wake,
}

impl Acceptors {
    /// Starts `count` threads with nothing to watch. Fails when a thread or its poller
    /// cannot be created.
    pub fn start(count: usize, parts: Parts) -> io::Result<Self> {
        let Parts { budget, defense, stats, flow_log, edge } = parts;
        let shared = Arc::new(Shared {
            table: Mutex::default(),
            generation: AtomicU64::new(0),
            stop: AtomicBool::new(false),
            draining: AtomicBool::new(false),
            budget,
            defense,
            stats,
            flow_log,
            drops: AtomicU64::new(0),
            edge,
        });
        let (sender, arrivals) = mpsc::channel();
        let mut threads = Vec::with_capacity(count);
        for index in 0..count.max(1) {
            let (waker, wake) = Waker::new()?;
            let mut poll = Poller::new()?;
            poll.set(handle(waker.socket()), READ, WAKE)?;
            let seen = Arc::new(AtomicU64::new(0));
            let mut thread = Thread::new(Arc::clone(&shared), sender.clone(), waker, poll);
            thread.seen = Arc::clone(&seen);
            let name = format!("edge-accept-{index}");
            let joined = std::thread::Builder::new().name(name).spawn(move || thread.run())?;
            threads.push(Handle { wake, seen, thread: Some(joined) });
        }
        Ok(Self { shared, threads, arrivals })
    }

    /// Makes the threads watch the listeners of `table` from their next wake-up.
    pub fn publish(&self, table: Table) {
        *self.shared.table.lock().unwrap_or_else(PoisonError::into_inner) = Arc::new(table);
        self.shared.generation.fetch_add(1, Ordering::Release);
        self.wake();
    }

    /// As [`Acceptors::publish`], and waits until every thread watches the new table, at
    /// most [`SETTLE`]. A listener that the table leaves out is accepted on by nobody
    /// once this returns, which a handoff and a drain rely on. Connections accepted
    /// before still arrive and are served.
    pub fn publish_and_settle(&self, table: Table) {
        self.publish(table);
        let wanted = self.shared.generation.load(Ordering::Acquire);
        let deadline = Instant::now() + SETTLE;
        while self.threads.iter().any(|thread| thread.seen.load(Ordering::Acquire) < wanted)
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn wake(&self) {
        for thread in &self.threads {
            thread.wake.wake();
        }
    }

    /// Refuses every connection from now on, as `draining`.
    pub fn drain(&self) {
        self.shared.draining.store(true, Ordering::Release);
    }

    /// The number of accept threads.
    pub fn count(&self) -> usize {
        self.threads.len()
    }

    /// The connections refused or lost on the threads.
    pub fn drops(&self) -> u64 {
        self.shared.drops.load(Ordering::Relaxed)
    }
}

impl Drop for Acceptors {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        self.wake();
        for handle in &mut self.threads {
            if let Some(thread) = handle.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

/// One accept thread.
struct Thread {
    shared: Arc<Shared>,
    sender: mpsc::Sender<Arrival>,
    waker: Waker,
    poll: Poller<usize>,
    table: Arc<Table>,
    generation: u64,
    /// Where the thread tells the parent which generation it watches.
    seen: Arc<AtomicU64>,
    /// Listeners that ran out of descriptors, by index in `table`, and when they resume.
    paused: Vec<(usize, Instant)>,
    /// Refused connections held without reading, oldest first.
    tarpit: VecDeque<(Instant, TcpStream)>,
    events: Vec<usize>,
}

impl Thread {
    fn new(
        shared: Arc<Shared>,
        sender: mpsc::Sender<Arrival>,
        waker: Waker,
        poll: Poller<usize>,
    ) -> Self {
        Self {
            shared,
            sender,
            waker,
            poll,
            table: Arc::default(),
            generation: 0,
            seen: Arc::default(),
            paused: Vec::new(),
            tarpit: VecDeque::new(),
            events: Vec::new(),
        }
    }

    fn run(mut self) {
        while !self.shared.stop.load(Ordering::Acquire) {
            self.follow();
            self.events.clear();
            if self.poll.wait(100, &mut self.events).is_err() {
                std::thread::sleep(PAUSE);
            }
            for index in 0..self.events.len() {
                match self.events[index] {
                    WAKE => self.waker.drain(),
                    entry => self.accept(entry),
                }
            }
            let now = Instant::now();
            self.resume(now);
            while self.tarpit.front().is_some_and(|(until, _)| *until <= now) {
                if let Some((_, stream)) = self.tarpit.pop_front() {
                    sibuna_reactor::reset(stream);
                }
            }
        }
    }

    /// Swaps in the table that the worker published last, when it is new.
    fn follow(&mut self) {
        let generation = self.shared.generation.load(Ordering::Acquire);
        if generation == self.generation {
            return;
        }
        self.generation = generation;
        for entry in &self.table.entries {
            self.poll.remove(handle(&*entry.socket));
        }
        self.paused.clear();
        self.table = Arc::clone(&self.shared.table.lock().unwrap_or_else(PoisonError::into_inner));
        for (index, entry) in self.table.entries.iter().enumerate() {
            // A listener this thread cannot watch is served by the others.
            let _ = self.poll.set(handle(&*entry.socket), READ_EXCLUSIVE, index);
        }
        self.seen.store(generation, Ordering::Release);
    }

    fn resume(&mut self, now: Instant) {
        let table = &self.table;
        let poll = &mut self.poll;
        self.paused.retain(|&(index, until)| {
            let ready = until <= now;
            if ready && let Some(entry) = table.entries.get(index) {
                let _ = poll.set(handle(&*entry.socket), READ_EXCLUSIVE, index);
            }
            !ready
        });
    }

    /// Accepts a batch of connections of the listener at `index` of the table.
    fn accept(&mut self, index: usize) {
        let table = Arc::clone(&self.table);
        let Some(entry) = table.entries.get(index) else { return };
        for _ in 0..BATCH {
            match entry.socket.accept() {
                Ok((stream, peer)) => self.admit(&entry.rules, stream, peer),
                Err(error) if crate::tcp::transient(&error) => break,
                Err(error) if crate::resource_pressure(&error) => {
                    self.poll.remove(handle(&*entry.socket));
                    self.paused.push((index, Instant::now() + PAUSE));
                    break;
                }
                // Every other error belongs to one connection.
                Err(_) => {
                    self.shared.drops.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Runs the admission order of SID 0034 on one connection.
    fn admit(&mut self, rules: &Rules, stream: TcpStream, peer: SocketAddr) {
        let shared = &self.shared;
        let now = unix_now();
        if shared.draining.load(Ordering::Acquire) {
            return self.refuse(rules, stream, peer, Refusal::Draining);
        }
        let trusted = rules.info.trusts(peer.ip());
        // An HTTP frontend answers a banned client with its ban page, unless the node
        // is under pressure and every accept counts.
        let screened = rules.protocol == Protocol::Tcp || shared.budget.is_pressed();
        if !trusted && screened && shared.defense.is_banned(peer.ip(), now) {
            return self.refuse(rules, stream, peer, Refusal::Banned);
        }
        if rules.info.proxy_protocol {
            return self.send(Arrival { listener: rules.listener, stream, peer, permit: None });
        }
        if let Some(rate) = rules.rate
            && !trusted
            && !shared.budget.allowed(rules.listener, peer, rate)
        {
            return self.refuse(rules, stream, peer, Refusal::RateLimit);
        }
        match shared.budget.take(Claim::new(rules.guard.caps, peer.ip(), trusted)) {
            Ok(permit) => {
                let listener = rules.listener;
                self.send(Arrival { listener, stream, peer, permit: Some(permit) });
            }
            Err(reason) => self.refuse(rules, stream, peer, reason),
        }
    }

    fn send(&self, arrival: Arrival) {
        if self.sender.send(arrival).is_ok() {
            self.shared.edge.wake();
        }
    }

    /// Counts, logs and strikes a refused connection, then ends it as the frontend says.
    fn refuse(&mut self, rules: &Rules, stream: TcpStream, peer: SocketAddr, reason: Refusal) {
        let shared = &self.shared;
        let now = unix_now();
        shared.stats.refuse_from(reason, peer.ip(), now);
        shared.drops.fetch_add(1, Ordering::Relaxed);
        if shared.flow_log.is_on() && shared.stats.may_log_refusal(now) {
            let protocol = if rules.protocol == Protocol::Udp { "udp" } else { "tcp" };
            let mut line = shared.flow_log.begin(protocol, peer, &rules.info.name, &rules.pool);
            flowlog::mark(&mut line, reason.end());
        }
        if let Some(rule) = rules.guard.auto_ban
            && reason.is_strike()
        {
            let banned = shared.defense.strike(peer.ip(), rules.guard.caps.frontend, rule, now);
            shared.stats.count_strike(banned);
        }
        match rules.guard.refuse {
            Refuse::Reset => sibuna_reactor::reset(stream),
            Refuse::Close => drop(stream),
            Refuse::Tarpit => {
                if self.tarpit.len() >= TARPIT_SLOTS
                    && let Some((_, oldest)) = self.tarpit.pop_front()
                {
                    sibuna_reactor::reset(oldest);
                }
                self.tarpit.push_back((Instant::now() + TARPIT, stream));
            }
        }
    }
}

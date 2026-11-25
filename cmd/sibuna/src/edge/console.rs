//! The operator console of the edge (SID 0031): the `console` section of the topology
//! starts the console of SID 0007 beside the load balancer, on a listener of its own.
//!
//! ```text
//! console thread                         edge worker
//!   Host::view  -- Board::ask ------->   Link::turn (once per readiness batch)
//!               <- servers, reloads --     publishes the table when one was asked for
//!   Host::run   -- admin::run_line -->   Serving::answer, as for the admin socket
//! ```
//!
//! The console adds no power. A command is the line that an operator would write to the
//! admin socket, and the function of that socket runs it. The view reads counters that
//! the metrics endpoint already shows, and the table that `show servers` prints. The
//! worker never waits for the console: it looks at one flag in each turn.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use sibuna_console::config::{Config as ConsoleConfig, PeerTarget, Peers};
use sibuna_console::{Console, EdgeHost, Inputs, Keys, Node, RuleHitSample, load_key};
use sibuna_console_protocol::edge::{
    Answer, Frontend, MAX_GROUPS, MAX_SERVERS, NodeState, Pool, Queues, Refused, Server, View,
};
use sibuna_lb::{ConsoleOptions, Edge, Regime, ServerState, ServerStatus, Stats, StatsView};
use sibuna_storage::{Hooks, Storage};

use super::watch::Source;
use super::{admin, cluster, control, note};
use crate::access::Observe;
use crate::console::start::{ASSETS, Seams, banner, is_uninitialized};

/// How long a view serves every reader before the worker is asked again.
const VIEW_AGE: Duration = Duration::from_millis(250);
/// How long a reader waits for the table of the worker.
const TABLE_WAIT: Duration = Duration::from_secs(1);
/// The most servers in one view, over all pools. The rest is counted, not sent.
const VIEW_SERVERS: usize = MAX_SERVERS;

/// What the worker last published.
#[derive(Default)]
struct Table {
    /// Counts the publications, so that a reader can tell a new one.
    serial: u64,
    servers: Vec<ServerStatus>,
    reloads: u64,
    runtime_changes: usize,
    regime: &'static str,
}

/// Where the worker leaves its table for the console threads.
#[derive(Default)]
struct Board {
    /// A reader asks for a new table. Release on store, Acquire on load.
    wanted: AtomicBool,
    table: Mutex<Table>,
    published: Condvar,
}

impl Board {
    /// Asks the worker for its table and waits for it, at most [`TABLE_WAIT`].
    fn ask<T>(&self, read: impl FnOnce(&Table) -> T) -> Option<T> {
        let table = self.table.lock().unwrap_or_else(PoisonError::into_inner);
        let before = table.serial;
        self.wanted.store(true, Ordering::Release);
        let waited = self.published.wait_timeout_while(table, TABLE_WAIT, |t| t.serial == before);
        let (table, _) = waited.unwrap_or_else(PoisonError::into_inner);
        (table.serial != before).then(|| read(&table))
    }
}

/// The side of the edge worker. Without a console it is one flag that nobody sets.
pub(super) struct Link {
    board: Arc<Board>,
    regime: Regime,
    running: Option<Running>,
}

/// The console and its storage. The console stops first: it holds the storage.
struct Running {
    console: Console,
    _storage: Arc<Storage>,
    /// The section the console started with.
    started: ConsoleOptions,
}

/// What the console reads of the edge, handed over at start.
pub(super) struct Parts {
    pub stats: Arc<Stats>,
    pub observe: Arc<Observe>,
    pub source: Arc<Source>,
    pub jobs: Sender<admin::Job>,
}

impl Link {
    /// Starts the console that `options` describes, or nothing without the section.
    /// Fails when the storage, a key file or the listener cannot start.
    pub fn start(options: Option<&ConsoleOptions>, parts: Parts) -> io::Result<Self> {
        let board = Arc::new(Board::default());
        let running = match options {
            Some(options) => Some(start(options, parts, Arc::clone(&board))?),
            None => None,
        };
        Ok(Self { board, regime: Regime::Standalone, running })
    }

    /// Records the routing regime that the worker follows now.
    pub fn set_regime(&mut self, regime: Regime) {
        self.regime = regime;
    }

    /// Publishes the table of the worker when a reader asked for it. The worker calls
    /// this once per readiness batch. It costs one load when nobody asked.
    pub fn turn(&self, edge: &Edge, reloads: u64) {
        if !self.board.wanted.load(Ordering::Acquire) {
            return;
        }
        self.board.wanted.store(false, Ordering::Release);
        let servers = edge.servers();
        let mut table = self.board.table.lock().unwrap_or_else(PoisonError::into_inner);
        table.serial = table.serial.wrapping_add(1);
        table.servers = servers;
        table.reloads = reloads;
        table.runtime_changes = edge.change_count();
        table.regime = match self.regime {
            Regime::Standalone => "standalone",
            Regime::Regional => "regional",
            Regime::WideArea => "wide_area",
        };
        drop(table);
        self.board.published.notify_all();
    }

    /// Checks the section of a file that is about to be reloaded, and returns the peers
    /// that the file no longer names. Fails when the file changes what only a restart
    /// can change: the section itself, the listener, the storage, the keys.
    pub fn plan(&self, next: Option<&ConsoleOptions>) -> io::Result<Vec<u32>> {
        let restart = |what: &str| {
            io::Error::other(format!("changing {what} of the console requires a restart"))
        };
        let (running, next) = match (&self.running, next) {
            (None, None) => return Ok(Vec::new()),
            (None, Some(_)) | (Some(_), None) => return Err(restart("the presence")),
            (Some(running), Some(next)) => (running, next),
        };
        let started = &running.started;
        // Everything but the peers must stay.
        let same = ConsoleOptions { peers: Vec::new(), ..next.clone() }
            == ConsoleOptions { peers: Vec::new(), ..started.clone() };
        if !same {
            return Err(restart("the listener, the storage, the proxy or the keys"));
        }
        let live = running.console.peer_nodes();
        let named = |node: u32| next.peers.iter().any(|peer| peer.node == node);
        Ok(live.into_iter().filter(|&node| !named(node)).collect())
    }

    /// Follows a reloaded file: closes the streams of the peers in `removed`, and says
    /// what waits for a restart.
    pub fn apply(&self, removed: &[u32], next: Option<&ConsoleOptions>) {
        let (Some(running), Some(next)) = (&self.running, next) else { return };
        for &node in removed {
            if running.console.remove_peer(node) {
                note(format_args!("Sibuna edge console: peer {node} removed, streams closed"));
            }
        }
        let live = running.console.peer_nodes();
        let waiting = next.peers.iter().filter(|peer| {
            let started = running.started.peers.iter().find(|old| old.node == peer.node);
            !live.contains(&peer.node) || started != Some(peer)
        });
        for peer in waiting {
            note(format_args!(
                "EDGE014: console peer {} is new or changed: it is used after a restart",
                peer.node
            ));
        }
    }
}

/// Opens the storage, reads the keys and starts the console.
fn start(options: &ConsoleOptions, parts: Parts, board: Arc<Board>) -> io::Result<Running> {
    let failed = |what: &str, error: &dyn fmt::Display| {
        io::Error::other(format!("console: {what}: {error}"))
    };
    let seams = Seams::new().map_err(|error| failed("boot id", &error))?;
    let core =
        sibuna_core::Config { data_dir: Some(options.data_dir.clone()), ..Default::default() };
    let mut hooks = Hooks::default();
    seams.extend_storage(&mut hooks);
    let storage = Storage::start(&core, hooks).map_err(|error| failed("storage", &error))?;
    let storage = Arc::new(storage);
    if options.behind_proxy && options.key_file.is_none() {
        return Err(io::Error::other("console: behind_proxy needs console.key_file"));
    }
    let key = |path: &Option<String>| {
        let path = path.as_deref().map(std::path::Path::new);
        path.map(load_key).transpose().map_err(|error| failed("key file", &error))
    };
    let peer_key = if options.peers.is_empty() { None } else { key(&options.peer_key_file)? };
    let keys = Keys { totp: key(&options.key_file)?, peer: peer_key };
    let host = Host {
        board,
        stats: parts.stats,
        observe: parts.observe,
        source: parts.source,
        jobs: Mutex::new(parts.jobs),
        node: options.node,
        started: Instant::now(),
        cached: Mutex::new(None),
    };
    let inputs = Inputs {
        telemetry: Arc::clone(&seams.telemetry),
        incidents: Arc::clone(&seams.incidents),
        geo: Arc::clone(&seams.geo),
        edge: Some(Arc::new(host)),
        node_id: options.node,
        version: crate::server::VERSION.to_owned(),
        keys,
        assets: ASSETS,
        clock: Arc::clone(&seams.clock) as Arc<dyn sibuna_console::Clock>,
        ..Inputs::new(Arc::clone(&storage), Arc::new(EdgeNode), seams.boot)
    };
    let console = Console::start(console_config(options), inputs)
        .map_err(|error| failed("start", &error))?;
    let uninitialized = is_uninitialized(&storage).unwrap_or(false);
    for line in banner(&console, uninitialized).lines() {
        note(format_args!("{line}"));
    }
    Ok(Running { console, _storage: storage, started: options.clone() })
}

/// The configuration of `sibuna-console` for the section. The source of a connection
/// is screened at accept: the proxy behind one, the operators otherwise.
fn console_config(options: &ConsoleOptions) -> ConsoleConfig {
    let targets = options.peers.iter().map(|peer| PeerTarget {
        node: peer.node,
        origin: peer.origin.clone(),
        allow_ips: peer.allow_ips.clone(),
    });
    let screens = options.behind_proxy || !options.allow_operators.is_empty();
    ConsoleConfig {
        listen: options.listen,
        behind_proxy: options.behind_proxy,
        key_file: options.key_file.as_ref().map(PathBuf::from),
        origin: options.origin.clone().unwrap_or_default(),
        trusted_proxies: options.trusted_proxies.clone(),
        allow_operators: options.allow_operators.clone(),
        screen_at_accept: screens,
        peers: Peers {
            targets: targets.collect(),
            key_file: options.peer_key_file.as_ref().map(PathBuf::from),
            ca_file: options.peer_ca_file.as_ref().map(PathBuf::from),
        },
        ..ConsoleConfig::default()
    }
}

/// The node of an edge, for the pages of the firewall console. An edge has no ban
/// table, no rule counters and no drain flag of that kind: every reading is empty and
/// every effect does nothing. The edge page drains servers through the admin path.
#[derive(Debug)]
struct EdgeNode;

impl Node for EdgeNode {
    fn set_draining(&self, _draining: bool) {}

    fn is_draining(&self) -> bool {
        false
    }

    fn clear_local_bans(&self, _now: u64) -> u32 {
        0
    }

    fn active_bans(&self, _now: u64) -> Option<u32> {
        None
    }

    fn sample_rule_hits(&self, _sample: &mut RuleHitSample) -> bool {
        false
    }

    fn applied_revision(&self) -> u64 {
        0
    }
}

/// The edge as the console threads reach it.
struct Host {
    board: Arc<Board>,
    stats: Arc<Stats>,
    observe: Arc<Observe>,
    source: Arc<Source>,
    /// The queue of the admin thread. A console thread takes a clone for one command.
    jobs: Mutex<Sender<admin::Job>>,
    node: u32,
    started: Instant,
    /// The last view and when it was built. It serves every reader for [`VIEW_AGE`].
    cached: Mutex<Option<(Instant, View)>>,
}

impl fmt::Debug for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Host").field("node", &self.node).finish_non_exhaustive()
    }
}

impl EdgeHost for Host {
    fn view(&self) -> Option<View> {
        let mut cached = self.cached.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((built, view)) = cached.as_ref()
            && built.elapsed() < VIEW_AGE
        {
            return Some(view.clone());
        }
        let view = self.board.ask(|table| self.build(table))?;
        *cached = Some((Instant::now(), view.clone()));
        Some(view)
    }

    fn run(&self, line: &str, who: &str) -> Answer {
        let jobs = self.jobs.lock().unwrap_or_else(PoisonError::into_inner).clone();
        match admin::run_line(line, &self.source, &jobs) {
            Ok(text) => {
                if !who.is_empty() {
                    note(format_args!("EDGE010: console: {who}: {line}"));
                }
                // The next view shows the change.
                *self.cached.lock().unwrap_or_else(PoisonError::into_inner) = None;
                Answer { ok: true, text, ..Answer::default() }
            }
            Err(error) => Answer {
                code: error.code.to_owned(),
                title: error.title.to_owned(),
                message: error.message,
                hint: error.hint,
                ..Answer::default()
            },
        }
    }
}

impl Host {
    /// Builds the view from the table of the worker and the counters.
    fn build(&self, table: &Table) -> View {
        let stats = self.stats.view();
        let frontends = stats.frontends.iter().take(MAX_GROUPS).map(|front| Frontend {
            name: front.name.to_string(),
            requests: front.requests,
            flows: front.flows,
            bytes_in: front.bytes_in,
            bytes_out: front.bytes_out,
            mean_micros: front.latency.mean_micros,
            p95_micros: front.latency.p95_micros,
        });
        let access_log_dropped = self.observe.log().map_or(0, |log| log.counts().1);
        View {
            frontends: frontends.collect(),
            pools: pools(&table.servers, &stats),
            queues: Queues { access_log_dropped, flow_log_dropped: stats.flow_log_dropped },
            node: self.summary(table, &stats),
        }
    }

    /// The summary of this node: what a peer sends for the fleet view.
    fn summary(&self, table: &Table, stats: &StatsView) -> sibuna_console_protocol::edge::Node {
        let count = |keep: fn(&ServerStatus) -> bool| {
            u32::try_from(table.servers.iter().filter(|server| keep(server)).count())
                .unwrap_or(u32::MAX)
        };
        let full = stats.flows_limit > 0 && stats.flows_active >= stats.flows_limit;
        // Readiness turns off when the daemon was asked to stop.
        let state = match (self.observe.is_ready(), full) {
            (false, _) => NodeState::Draining,
            (true, true) => NodeState::Full,
            (true, false) => NodeState::Serving,
        };
        let file = self.source.path().and_then(|path| std::fs::read(path).ok());
        sibuna_console_protocol::edge::Node {
            node: self.node,
            version: crate::server::VERSION.to_owned(),
            uptime_seconds: self.started.elapsed().as_secs(),
            state,
            flows: stats.flows_active,
            max_flows: stats.flows_limit,
            drops: stats.drops,
            reloads: table.reloads,
            runtime_changes: table.runtime_changes as u64,
            servers: count(|_| true),
            servers_drained: count(|server| server.state == ServerState::Drain),
            servers_down: count(|server| server.healthy == Some(false)),
            // The digest that `show cluster` compares: the revision of today.
            file_digest: file.map(|file| cluster::digest(&file)),
            // SID 0028 puts the revision of the database authority here.
            authority_revision: None,
            regime: table.regime.to_owned(),
            refused: stats
                .refused
                .iter()
                .map(|(reason, count)| Refused { reason: reason.name().to_owned(), count: *count })
                .collect(),
        }
    }
}

/// Groups the servers by pool, in the order of `show servers`, with their counters.
fn pools(servers: &[ServerStatus], stats: &StatsView) -> Vec<Pool> {
    let counters: HashMap<(&str, &str), &sibuna_lb::ServerView> =
        stats.servers.iter().map(|view| ((&*view.backend, &*view.server), view)).collect();
    let mut pools: Vec<Pool> = Vec::new();
    let mut sent = 0;
    for status in servers {
        if pools.last().is_none_or(|pool| pool.name != status.pool) {
            if pools.len() == MAX_GROUPS {
                break;
            }
            pools.push(Pool { name: status.pool.clone(), ..Pool::default() });
        }
        let Some(pool) = pools.last_mut() else { break };
        if sent == VIEW_SERVERS || pool.servers.len() == MAX_SERVERS {
            pool.more = pool.more.saturating_add(1);
            continue;
        }
        sent += 1;
        let counted = counters.get(&(status.pool.as_str(), status.name.as_str()));
        pool.servers.push(server(status, counted.copied()));
    }
    pools
}

/// One row: the columns of `show servers`, then the counters of the server.
fn server(status: &ServerStatus, counted: Option<&sibuna_lb::ServerView>) -> Server {
    let health = match status.healthy {
        None => "-",
        Some(true) => "up",
        Some(false) => "down",
    };
    let latency = counted.map(|view| view.latency).unwrap_or_default();
    Server {
        name: status.name.clone(),
        address: status.addr.to_string(),
        state: status.state.word().to_owned(),
        weight: status.weight,
        flows: status.flows as u64,
        health: health.to_owned(),
        backup: status.backup,
        changed: control::changed(status),
        // Rounded up, as `show servers` prints it.
        ejected_seconds: status.ejected.map(|left| left.as_secs() + 1),
        ramp_percent: status.ramp.map(u32::from),
        requests: counted.map_or(0, |view| view.requests),
        failures: counted.map_or(0, |view| view.failures),
        active: counted.map_or(0, |view| view.active),
        mean_micros: latency.mean_micros,
        p95_micros: latency.p95_micros,
    }
}

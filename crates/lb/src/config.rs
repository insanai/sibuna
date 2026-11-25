//! Parse the supported SID 0015 topology before opening any socket.

use std::collections::{BTreeMap, HashSet};
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::time::Duration;

use sibuna_json::{Object, ObjectReader, Value};

/// The largest configurable flow table. The descriptor limit of the process bounds it first.
pub(crate) const MAX_FLOWS: usize = 1_000_000;
const MAX_WORKERS: usize = 64;

/// The parsed topology. Create one with [`Config::parse`].
pub struct Config {
    pub(crate) limit: usize,
    pub(crate) udp_limit: usize,
    pub(crate) workers: usize,
    pub(crate) admin_socket: Option<String>,
    pub(crate) watch: Option<Duration>,
    pub(crate) shutdown_timeout: Duration,
    /// How long the node answers "not ready" before it stops accepting (SID 0020).
    pub(crate) drain_delay: Duration,
    /// Listeners share their address, so a new process can bind it (`global.reuse_port`).
    pub(crate) reuse_port: bool,
    pub(crate) http: crate::HttpOptions,
    pub(crate) observe: crate::ObserveOptions,
    /// The `global.acme` object of automatic HTTPS (SID 0021).
    pub(crate) acme: Option<crate::AcmeOptions>,
    pub(crate) mesh: Option<crate::MeshConfig>,
    /// The `spill` section of learned source affinity (SID 0027).
    pub(crate) spill: Option<crate::SpillOptions>,
    pub(crate) listeners: BTreeMap<(Protocol, SocketAddr), Frontend>,
    pub(crate) pools: BTreeMap<String, Backend>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialOrd, PartialEq)]
pub(crate) enum Protocol {
    Tcp,
    Http,
    Udp,
}

pub(crate) struct Frontend {
    pub tls: Option<std::sync::Arc<crate::TlsOptions>>,
    pub http_rules: std::sync::Arc<[crate::http::Rule]>,
    /// Whether requests without a matching route pass the HTTP firewall.
    pub firewall: bool,
    /// The WebSocket rule of requests without a matching route.
    pub websocket: Option<std::sync::Arc<crate::WebSocketRule>>,
    /// The policy of requests without a matching route (SID 0019).
    pub policy: std::sync::Arc<crate::RoutePolicy>,
    pub rate: Option<sibuna_store::limiter::Limits>,
    pub pool: std::sync::Arc<str>,
    pub timeout: Duration,
    pub inspect: Option<(Duration, std::sync::Arc<[crate::rules::Rule]>)>,
    /// The name, the counters and the trusted proxies of the frontend (SID 0020).
    pub info: std::sync::Arc<crate::FrontendInfo>,
}

pub(crate) struct Backend {
    pub protocol: Protocol,
    pub servers: Vec<Server>,
    pub scheduler: Scheduler,
    pub proxy_v2: Option<crate::proxy::Spec>,
    pub health: Option<crate::health::Spec>,
    pub origin: Option<std::sync::Arc<crate::OriginOptions>>,
    /// The traffic options of SID 0019.
    pub policy: std::sync::Arc<crate::PoolPolicy>,
}

#[derive(Clone)]
pub(crate) struct Server {
    pub name: String,
    pub addr: SocketAddr,
    pub weight: u32,
    pub limit: usize,
    pub backup: bool,
    pub remote: bool,
    /// The local protocol adapter that reaches this server, when its pool needs one.
    pub via: Option<SocketAddr>,
    pub healthy: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// The names and the counters of the server, set when an edge adopts the topology.
    pub info: Option<crate::ServerInfo>,
}

pub(crate) fn invalid(message: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::InvalidData, message.to_string())
}

pub(crate) fn field<T, E: std::fmt::Display>(result: std::result::Result<T, E>) -> Result<T> {
    result.map_err(invalid)
}

pub(crate) fn required<'a>(r: &mut ObjectReader<'_, 'a>, key: &str) -> Result<String> {
    field(r.take_str(key))?.map(str::to_owned).ok_or_else(|| invalid(r.missing(key)))
}

/// Reads a protocol. A frontend or a backend without one speaks HTTP (SID 0018).
fn protocol(r: &mut ObjectReader<'_, '_>, key: &str) -> Result<Protocol> {
    match field(r.take_str(key))? {
        Some("tcp") => Ok(Protocol::Tcp),
        None | Some("http") => Ok(Protocol::Http),
        Some("udp") => Ok(Protocol::Udp),
        Some(_) => Err(invalid(format!("{} must be http, tcp or udp", r.field_path(key)))),
    }
}

pub(crate) fn number(
    r: &mut ObjectReader<'_, '_>,
    key: &str,
    default: usize,
    max: usize,
) -> Result<usize> {
    match field(r.take_u64(key))? {
        None => Ok(default),
        Some(n) if n > 0 && n <= max as u64 => Ok(n as usize),
        _ => Err(invalid(format!("{} must be in 1..={max}", r.field_path(key)))),
    }
}

fn named<'a, 'b>(r: &mut ObjectReader<'a, 'b>, key: &str) -> Result<&'a Object<'b>> {
    let items = r.take(key).and_then(Value::as_object);
    items
        .filter(|items| (1..=128).contains(&items.len()))
        .ok_or_else(|| invalid(format!("{key} must contain 1 to 128 named entries")))
}

impl Config {
    /// Bounds shared by the edge file readers and the topology validator.
    pub const DOCUMENT_LIMITS: sibuna_json::Limits = sibuna_json::Limits {
        max_input_bytes: 256 * 1024,
        max_values: 32768,
        max_string_bytes: 512,
        max_depth: 16,
    };

    /// HTTP firewall settings when at least one HTTP frontend is present.
    pub fn http(&self) -> Option<&crate::HttpOptions> {
        self.listeners.keys().any(|(proto, _)| *proto == Protocol::Http).then_some(&self.http)
    }

    /// The number of servers in the HTTP pools. Each can hold idle connections of the
    /// protocol runtime, which the descriptor check counts (SID 0020).
    pub fn http_server_count(&self) -> usize {
        let http = self.pools.values().filter(|pool| pool.protocol == Protocol::Http);
        http.map(|pool| pool.servers.len()).sum()
    }

    /// TLS frontends and their listener addresses, for the protocol adapter.
    pub fn tls(&self) -> BTreeMap<SocketAddr, std::sync::Arc<crate::TlsOptions>> {
        self.listeners.iter().filter_map(|((_, addr), f)| Some((*addr, f.tls.clone()?))).collect()
    }

    /// The servers that need a protocol adapter, each with its pool's origin options.
    pub fn origins(&self) -> Vec<(SocketAddr, std::sync::Arc<crate::OriginOptions>)> {
        let mut origins = Vec::new();
        for pool in self.pools.values() {
            if let Some(options) = &pool.origin {
                origins.extend(pool.servers.iter().map(|s| (s.addr, options.clone())));
            }
        }
        origins
    }

    /// Routes each server from [`Config::origins`] through the adapter address that
    /// `adapter` returns for it. Fails when a server has no adapter.
    pub fn route_through(
        &mut self,
        adapter: impl Fn(SocketAddr, &crate::OriginOptions) -> Option<SocketAddr>,
    ) -> Result<()> {
        for (name, pool) in &mut self.pools {
            let Some(options) = &pool.origin else { continue };
            for server in &mut pool.servers {
                server.via = Some(adapter(server.addr, options).ok_or_else(|| {
                    invalid(format!("backends.{name}: no protocol adapter for {}", server.addr))
                })?);
            }
        }
        Ok(())
    }

    /// The access log, the access control of the internal routes and the separate
    /// listener (SID 0020).
    pub fn observe(&self) -> &crate::ObserveOptions {
        &self.observe
    }

    /// The size of the flow table (`global.max_flows`).
    pub fn max_flows(&self) -> usize {
        self.limit
    }

    /// The path of the admin socket (`global.admin_socket`), when the operator asked for one.
    pub fn admin_socket(&self) -> Option<&str> {
        self.admin_socket.as_deref()
    }

    /// How often the daemon looks at its file for a change (`global.watch`), if at all.
    pub fn watch(&self) -> Option<Duration> {
        self.watch
    }

    /// Whether the listeners share their address with other processes of the same user
    /// (`global.reuse_port`).
    pub fn reuse_port(&self) -> bool {
        self.reuse_port
    }

    /// How long a shutdown waits for established flows (`global.shutdown_timeout`).
    pub fn shutdown_timeout(&self) -> Duration {
        self.shutdown_timeout
    }

    /// How long a shutdown keeps serving while readiness answers 503, before the
    /// listeners stop (`global.drain_delay`). Zero by default.
    pub fn drain_delay(&self) -> Duration {
        self.drain_delay
    }

    /// Where learned source affinity is kept (`spill`), when the operator enabled it
    /// (SID 0027).
    pub fn spill(&self) -> Option<&crate::SpillOptions> {
        self.spill.as_ref()
    }

    /// Static peer configuration, when the operator enabled RTT-based routing.
    pub fn mesh(&self) -> Option<&crate::MeshConfig> {
        self.mesh.as_ref()
    }

    /// Parses canonical JSON and resolves each frontend to a protocol-compatible backend.
    /// Returns a diagnostic for malformed JSON, unknown options or invalid resource bounds.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value = field(sibuna_json::parse_with_limits(bytes, &Self::DOCUMENT_LIMITS))?;
        let mut root = field(ObjectReader::new(&value))?;
        let Global {
            limit,
            udp_limit,
            workers,
            admin_socket,
            watch,
            shutdown_timeout,
            drain_delay,
            reuse_port,
            acme,
        } = global(&mut root)?;
        let mesh = field(root.take_object("mesh"))?.map(crate::MeshConfig::parse).transpose()?;
        let http = field(root.take_object("http"))?.map(crate::HttpOptions::parse).transpose()?;
        let explicit_http = http.is_some();
        let http = http.unwrap_or_default();
        let observe = field(root.take_object("observability"))?
            .map(crate::ObserveOptions::parse)
            .transpose()?
            .unwrap_or_default();
        let spill =
            field(root.take_object("spill"))?.map(crate::SpillOptions::parse).transpose()?;
        let adaptive = mesh.is_some();
        let mut config = Self {
            limit,
            udp_limit: limit,
            workers,
            admin_socket,
            watch,
            shutdown_timeout,
            drain_delay,
            reuse_port,
            mesh,
            http,
            observe,
            acme,
            spill,
            pools: BTreeMap::new(),
            listeners: BTreeMap::new(),
        };
        for (name, value) in named(&mut root, "backends")? {
            config.pools.insert(name.into(), Backend::parse(name, value, adaptive)?);
        }
        for (name, value) in named(&mut root, "frontends")? {
            config.add_frontend(name, value)?;
        }
        field(root.finish())?;
        // Datagram sources are unvalidated. Beside stream listeners they share the table
        // only up to half, unless the operator sets the ceiling.
        let mixed = config.listeners.keys().any(|(proto, _)| *proto != Protocol::Udp);
        config.udp_limit = udp_limit.unwrap_or(if mixed { limit.div_ceil(2) } else { limit });
        if explicit_http && config.http().is_none() {
            return Err(invalid("http settings require an HTTP frontend"));
        }
        for (addr, tls) in config.tls() {
            if tls.http3
                && (config
                    .listeners
                    .keys()
                    .any(|(p, a)| *p == Protocol::Udp && overlaps(*a, addr))
                    || config.mesh.as_ref().is_some_and(|m| overlaps(m.listen, addr)))
            {
                return Err(invalid(format!("HTTP/3 bind {addr} overlaps a UDP listener")));
            }
        }
        config.check_servers()?;
        config.check_automatic_https()?;
        Ok(config)
    }

    /// Refuses a server whose address is one of our own listeners.
    fn check_servers(&self) -> Result<()> {
        for (name, backend) in &self.pools {
            for server in &backend.servers {
                let mut binds = self.listeners.keys();
                if binds.any(|&bind| is_listener(bind, backend.protocol, server.addr)) {
                    return Err(invalid(format!(
                        "backends.{name}: {} is a frontend",
                        server.addr
                    )));
                }
            }
        }
        Ok(())
    }

    /// The backend of a frontend that names none: the only one of its protocol.
    fn only_backend(&self, proto: Protocol, path: &str) -> Result<String> {
        let mut matching = self.pools.iter().filter(|(_, pool)| pool.protocol == proto);
        match (matching.next(), matching.next()) {
            (Some((name, _)), None) => Ok(name.clone()),
            (None, _) => Err(invalid(format!("{path}: no {proto:?} backend to serve it"))),
            (Some((first, _)), Some((second, _))) => Err(invalid(format!(
                "{path}: default_backend is required with several {proto:?} backends \
                 ({first}, {second}, ...)"
            ))),
        }
    }

    fn add_frontend(&mut self, name: &str, value: &Value<'_>) -> Result<()> {
        let path = format!("frontends.{name}");
        let mut r = field(ObjectReader::with_path(value, path.clone()))?;
        let proto = protocol(&mut r, "proto")?;
        let pool = match field(r.take_str("default_backend"))? {
            Some(pool) => pool.to_owned(),
            None => self.only_backend(proto, &path)?,
        };
        if self.pools.get(&pool).is_none_or(|b| b.protocol != proto) {
            return Err(invalid(format!("{path}: no matching {proto:?} backend named {pool}")));
        }
        let rate = frontend_rate(&mut r, proto)?;
        let timeout_field = field(r.take_str("session_timeout"))?;
        if proto == Protocol::Http && timeout_field.is_some() {
            return Err(invalid("HTTP deadlines belong to the HTTP firewall"));
        }
        let timeout = match timeout_field {
            None => Duration::from_secs(30),
            Some(s) => duration(s).ok_or_else(|| invalid(format!("{path}: invalid timeout")))?,
        };
        let inspect = match field(r.take_str("tcp_inspect"))? {
            Some("tls_client_hello") if proto == Protocol::Tcp => {
                let delay = field(r.take_str("inspect_delay"))?.unwrap_or("2s");
                let delay =
                    duration(delay).ok_or_else(|| invalid(r.field_path("inspect_delay")))?;
                Some((delay, std::sync::Arc::from(crate::rules::parse(&mut r, &self.pools)?)))
            }
            Some(_) => return Err(invalid(format!("{path}: invalid TCP inspection mode"))),
            None => None,
        };
        let (tls, firewall, websocket, http_rules, policy) =
            http_frontend(&mut r, proto, &self.pools)?;
        let http_rules: std::sync::Arc<[_]> = http_rules.into();
        let info = crate::FrontendInfo::parse(&mut r, name, proto)?;
        let info = std::sync::Arc::new(info);
        let binds = field(r.take_array("binds"))?.ok_or_else(|| invalid(r.missing("binds")))?;
        if binds.is_empty() || self.listeners.len() + binds.len() > 128 {
            return Err(invalid(format!("{path}: expected 1 to 128 binds in total")));
        }
        for bind in binds {
            let addr = address(bind.as_str().unwrap_or(""), &path)?;
            if proto == Protocol::Udp && addr.ip().is_unspecified() {
                return Err(invalid(format!("{path}: bind UDP to a specific local IP")));
            }
            let listener = Frontend {
                tls: tls.clone(),
                http_rules: http_rules.clone(),
                firewall,
                websocket: websocket.clone(),
                policy: policy.clone(),
                pool: pool.as_str().into(),
                timeout,
                inspect: inspect.clone(),
                rate,
                info: info.clone(),
            };
            if self.listeners.keys().any(|&(p, bound)| {
                (p == Protocol::Udp) == (proto == Protocol::Udp) && overlaps(bound, addr)
            }) {
                return Err(invalid(format!("{path}: overlapping listener {addr}")));
            }
            if self.mesh.as_ref().is_some_and(|mesh| proto == Protocol::Udp && mesh.listen == addr)
            {
                return Err(invalid(format!("{path}: listener {addr} also handles mesh probes")));
            }
            self.listeners.insert((proto, addr), listener);
        }
        field(r.finish())
    }
}

/// The `global` object.
struct Global {
    limit: usize,
    udp_limit: Option<usize>,
    workers: usize,
    admin_socket: Option<String>,
    watch: Option<Duration>,
    shutdown_timeout: Duration,
    drain_delay: Duration,
    reuse_port: bool,
    acme: Option<crate::AcmeOptions>,
}

/// Reads `global`: the flow table size, the optional UDP share, the relay threads, the
/// admin socket and the file watcher.
fn global(root: &mut ObjectReader<'_, '_>) -> Result<Global> {
    let mut limit = 8192;
    let mut udp_limit = None;
    let mut workers = default_workers();
    let mut admin_socket = None;
    let mut watch = None;
    let mut shutdown_timeout = Duration::from_secs(5);
    let mut drain_delay = Duration::ZERO;
    let mut reuse_port = false;
    let mut acme = None;
    if let Some(mut global) = field(root.take_object("global"))? {
        acme = field(global.take_object("acme"))?.map(crate::AcmeOptions::parse).transpose()?;
        if let Some(text) = field(global.take_str("shutdown_timeout"))? {
            shutdown_timeout = duration(text)
                .filter(|d| *d <= Duration::from_secs(3600))
                .ok_or_else(|| invalid("global.shutdown_timeout must be a duration up to 1h"))?;
        }
        if let Some(text) = field(global.take_str("drain_delay"))? {
            drain_delay = duration(text)
                .filter(|d| *d <= Duration::from_secs(600))
                .ok_or_else(|| invalid("global.drain_delay must be a duration up to 10m"))?;
        }
        reuse_port = field(global.take_bool("reuse_port"))?.unwrap_or(false);
        if reuse_port && !sibuna_reactor::CAN_SHARE_ADDRESS {
            return Err(invalid("global.reuse_port needs Linux"));
        }
        limit = number(&mut global, "max_flows", limit, MAX_FLOWS)?;
        admin_socket = match field(global.take_str("admin_socket"))? {
            Some("") => return Err(invalid("global.admin_socket must be a path")),
            path => path.map(str::to_owned),
        };
        watch = match field(global.take_str("watch"))? {
            None => None,
            Some(text) => Some(
                duration(text)
                    .filter(|d| (1..=3600).contains(&d.as_secs()))
                    .ok_or_else(|| invalid("global.watch must be a duration from 1s to 1h"))?,
            ),
        };
        workers = match global.take("workers") {
            None => workers,
            Some(value) if value.as_str() == Some("auto") => workers,
            Some(value) => match value.as_number().and_then(|n| n.as_u64().ok()) {
                Some(n) if (1..=MAX_WORKERS as u64).contains(&n) => n as usize,
                _ => return Err(invalid("global.workers must be auto or in 1..=64")),
            },
        };
        udp_limit = match field(global.take_u64("max_udp_flows"))? {
            None => None,
            Some(n) if n > 0 && n <= limit as u64 => Some(n as usize),
            Some(_) => return Err(invalid("global.max_udp_flows must be in 1..=max_flows")),
        };
        field(global.finish())?;
    }
    Ok(Global {
        limit,
        udp_limit,
        workers,
        admin_socket,
        watch,
        shutdown_timeout,
        drain_delay,
        reuse_port,
        acme,
    })
}

/// One relay thread per available CPU, up to eight.
fn default_workers() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get().min(8))
}

type Tunnels = Option<std::sync::Arc<crate::WebSocketRule>>;
type HttpFrontend = (
    Option<std::sync::Arc<crate::TlsOptions>>,
    bool,
    Tunnels,
    Vec<crate::http::Rule>,
    std::sync::Arc<crate::RoutePolicy>,
);

/// Reads the options that only an HTTP frontend has: TLS, the firewall switch and routes.
fn http_frontend(
    r: &mut ObjectReader<'_, '_>,
    proto: Protocol,
    pools: &BTreeMap<String, Backend>,
) -> Result<HttpFrontend> {
    if proto != Protocol::Http {
        return Ok((None, true, None, Vec::new(), std::sync::Arc::default()));
    }
    let tls = field(r.take_object("tls"))?
        .map(crate::TlsOptions::parse)
        .transpose()?
        .map(std::sync::Arc::new);
    let firewall = field(r.take_bool("firewall"))?.unwrap_or(true);
    let websocket =
        field(r.take_object("websocket"))?.map(crate::WebSocketRule::parse).transpose()?;
    let policy = crate::RoutePolicy::parse(r, &std::sync::Arc::default(), tls.is_some())?;
    let base = (&policy, tls.is_some());
    let rules = crate::http::rules(r, pools, firewall, websocket.as_ref(), base)?;
    Ok((tls, firewall, websocket, rules, policy))
}

/// Whether a server at `addr` in a pool of `protocol` would be the listener `bind`.
pub(crate) fn is_listener(
    bind: (Protocol, SocketAddr),
    protocol: Protocol,
    addr: SocketAddr,
) -> bool {
    (bind.0 == Protocol::Udp) == (protocol == Protocol::Udp)
        && (bind.1 == addr || (addr.ip().is_loopback() && overlaps(bind.1, addr)))
}

fn overlaps(a: SocketAddr, b: SocketAddr) -> bool {
    a == b
        || (a.port() == b.port()
            && a.is_ipv4() == b.is_ipv4()
            && (a.ip().is_unspecified() || b.ip().is_unspecified()))
}

pub(crate) fn address(text: &str, path: &str) -> Result<SocketAddr> {
    text.parse::<SocketAddr>()
        .ok()
        .filter(|addr| addr.port() != 0)
        .ok_or_else(|| invalid(format!("{path}: expected numeric IP:port, found {text:?}")))
}

/// Parses a positive duration of at most one day: digits with `ms`, `s`, `m` or `h`.
pub(crate) fn duration(text: &str) -> Option<Duration> {
    let (digits, multiplier) = if let Some(ms) = text.strip_suffix("ms") {
        (ms, 1)
    } else if let Some(seconds) = text.strip_suffix('s') {
        (seconds, 1000)
    } else if let Some(minutes) = text.strip_suffix('m') {
        (minutes, 60_000)
    } else {
        (text.strip_suffix('h')?, 3_600_000)
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let millis = digits.parse::<u64>().ok()?.checked_mul(multiplier)?;
    (1..=86_400_000).contains(&millis).then(|| Duration::from_millis(millis))
}

impl Backend {
    fn parse(name: &str, value: &Value<'_>, mesh: bool) -> Result<Self> {
        let path = format!("backends.{name}");
        let mut r = field(ObjectReader::with_path(value, path.clone()))?;
        let protocol = protocol(&mut r, "mode")?;
        let rows = field(r.take_array("servers"))?.ok_or_else(|| invalid(r.missing("servers")))?;
        if !(1..=128).contains(&rows.len()) {
            return Err(invalid(format!("{path}.servers: expected 1 to 128 servers")));
        }
        let mut servers = Vec::with_capacity(rows.len());
        let mut addresses = HashSet::new();
        let mut names = HashSet::new();
        for (index, row) in rows.iter().enumerate() {
            let server = Server::parse(row, format!("{path}.servers[{index}]"))?;
            if !addresses.insert(server.addr) || !names.insert(server.name.clone()) {
                return Err(invalid(format!("{path}: duplicate server name or address")));
            }
            servers.push(server);
        }
        let health =
            field(r.take_object("health_check"))?.map(crate::health::Spec::parse).transpose()?;
        if protocol == Protocol::Tcp && health.as_ref().is_some_and(|spec| spec.is_http()) {
            return Err(invalid(format!("{path}: HTTP probes require an HTTP pool")));
        }
        if protocol == Protocol::Udp && health.is_some() {
            return Err(invalid(format!("{path}: health probes require a TCP or HTTP pool")));
        }
        let proxy_v2 = field(r.take_object("proxy_v2"))?
            .map(|r| crate::proxy::Spec::parse(r, protocol))
            .transpose()?
            .flatten();
        let origin =
            if protocol == Protocol::Http { crate::OriginOptions::parse(&mut r)? } else { None };
        let policy = std::sync::Arc::new(crate::PoolPolicy::parse(&mut r, protocol)?);
        let scheduler = scheduler(&mut r, mesh, &mut servers)?;
        field(r.finish())?;
        Ok(Self { protocol, servers, scheduler, proxy_v2, health, origin, policy })
    }
}

pub(crate) enum Scheduler {
    LeastConnections,
    PeakEwma,
    Maglev {
        table: crate::maglev::Table,
        peak_fallback: bool,
    },
    Adaptive(crate::maglev::Table),
    /// Each server in turn, in proportion to its weight (SID 0019).
    RoundRobin,
}

fn scheduler(
    r: &mut ObjectReader<'_, '_>,
    mesh: bool,
    servers: &mut [Server],
) -> Result<Scheduler> {
    let Some(mut balance) = field(r.take_object("balance"))? else {
        if !mesh {
            return Ok(Scheduler::LeastConnections);
        }
        servers.sort_by(|a, b| a.name.cmp(&b.name));
        return Ok(crate::maglev::Table::build(servers, 125)
            .map_or(Scheduler::PeakEwma, Scheduler::Adaptive));
    };
    let kind = required(&mut balance, "kind")?;
    let scheduler = match kind.as_str() {
        "least_connections" => Scheduler::LeastConnections,
        "p2c_pewma" => Scheduler::PeakEwma,
        "round_robin" => Scheduler::RoundRobin,
        "bounded_maglev" => {
            let peak_fallback = match field(balance.take_str("fallback"))? {
                None => false,
                Some("pewma") => true,
                _ => return Err(invalid("expected pewma fallback")),
            };
            let factor = number(&mut balance, "load_factor_pct", 125, 1000)?;
            if factor < 100 {
                return Err(invalid("load_factor_pct must be at least 100"));
            }
            servers.sort_by(|a, b| a.name.cmp(&b.name));
            match crate::maglev::Table::build(servers, factor as u32) {
                Some(table) => Scheduler::Maglev { table, peak_fallback },
                None if peak_fallback => Scheduler::PeakEwma,
                None => Scheduler::LeastConnections,
            }
        }
        _ => {
            return Err(invalid(format!(
                "{}: unknown scheduler {kind}",
                balance.field_path("kind")
            )));
        }
    };
    field(balance.finish())?;
    Ok(scheduler)
}

impl Server {
    /// The largest weight of a server.
    pub const MAX_WEIGHT: u32 = 65535;

    /// A server with the defaults of the file: no flow limit, primary, local.
    pub fn new(name: String, addr: SocketAddr, weight: u32) -> Self {
        Self {
            name,
            addr,
            weight,
            limit: MAX_FLOWS,
            backup: false,
            remote: false,
            via: None,
            healthy: None,
            info: None,
        }
    }

    /// Whether a flow may be sent to `addr`: a unicast address that names one host.
    pub fn routable(addr: SocketAddr) -> bool {
        addr.port() != 0
            && addr.ip() != std::net::Ipv4Addr::BROADCAST
            && !addr.ip().is_unspecified()
            && !addr.ip().is_multicast()
    }

    fn parse(value: &Value<'_>, path: String) -> Result<Self> {
        // The short form (SID 0018): an address alone, which is also the name.
        if let Some(text) = value.as_str() {
            let addr = address(text, &path)?;
            if !Self::routable(addr) {
                return Err(invalid(format!("{path}: expected unicast server")));
            }
            return Ok(Self::new(addr.to_string(), addr, 1));
        }
        let mut r = field(ObjectReader::with_path(value, path))?;
        let name = required(&mut r, "name")?;
        let addr = address(&required(&mut r, "addr")?, r.path())?;
        if name.is_empty() || !Self::routable(addr) {
            return Err(invalid(format!("{}: expected named unicast server", r.path())));
        }
        let weight = number(&mut r, "weight", 1, Self::MAX_WEIGHT as usize)? as u32;
        let limit = number(&mut r, "max_flows", MAX_FLOWS, MAX_FLOWS)?;
        let remote = field(r.take_bool("remote"))?.unwrap_or(false);
        let backup = field(r.take_bool("backup"))?.unwrap_or(false);
        field(r.finish())?;
        Ok(Self {
            name,
            addr,
            limit,
            weight,
            backup,
            remote,
            via: None,
            healthy: None,
            info: None,
        })
    }
}

fn frontend_rate(
    r: &mut ObjectReader<'_, '_>,
    proto: Protocol,
) -> Result<Option<sibuna_store::limiter::Limits>> {
    let (key, count, window_ms) = match proto {
        Protocol::Tcp | Protocol::Http => ("rate_limit", "conn_per_10s", 10_000),
        Protocol::Udp => ("udp_defense", "threshold_pps", 1_000),
    };
    let Some(mut options) = field(r.take_object(key))? else { return Ok(None) };
    if proto == Protocol::Udp && required(&mut options, "mode")? != "rate_limit" {
        return Err(invalid("udp_defense.mode must be rate_limit"));
    }
    let rate = field(options.take_u64(count))?.ok_or_else(|| invalid(options.missing(count)))?;
    if rate == 0 || rate > 1_000_000 {
        return Err(invalid(options.field_path(count)));
    }
    if let Some(prefix) = field(options.take_u64("ipv6_prefix"))?
        && prefix != 64
    {
        return Err(invalid("IPv6 admission budgets use a /64 prefix"));
    }
    field(options.finish())?;
    // The existing limiter accepts an arbitrary integral timebase. Use microseconds
    // here so rates above 1,000 packets/s retain their intended pacing.
    Ok(Some(sibuna_store::limiter::Limits { rate: rate as u32, window_ms: window_ms * 1000 }))
}

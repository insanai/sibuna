//! Parse the supported SID 0015 topology before opening any socket.

use std::collections::{BTreeMap, HashSet};
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::time::Duration;

use sibuna_json::{Object, ObjectReader, Value};

pub(crate) const MAX_FLOWS: usize = 8192;

/// The parsed topology. Create one with [`Config::parse`].
pub struct Config {
    pub(crate) limit: usize,
    pub(crate) mesh: Option<crate::MeshConfig>,
    pub(crate) listeners: BTreeMap<(Protocol, SocketAddr), Frontend>,
    pub(crate) pools: BTreeMap<String, Backend>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialOrd, PartialEq)]
pub(crate) enum Protocol {
    Tcp,
    Udp,
}

pub(crate) struct Frontend {
    pub rate: Option<sibuna_store::limiter::Limits>,
    pub pool: std::sync::Arc<str>,
    pub timeout: Duration,
    pub inspect: Option<(Duration, std::sync::Arc<[crate::rules::Rule]>)>,
}

pub(crate) struct Backend {
    pub protocol: Protocol,
    pub servers: Vec<Server>,
    pub scheduler: Scheduler,
    pub proxy_v2: Option<crate::proxy::Spec>,
    pub health: Option<crate::health::Spec>,
}

pub(crate) struct Server {
    pub name: String,
    pub addr: SocketAddr,
    pub weight: u32,
    pub limit: usize,
    pub backup: bool,
    pub remote: bool,
    pub healthy: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
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

fn protocol(r: &mut ObjectReader<'_, '_>, key: &str) -> Result<Protocol> {
    match required(r, key)?.as_str() {
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        _ => Err(invalid(format!("{} must be tcp or udp", r.field_path(key)))),
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

    /// Static peer configuration, when the operator enabled RTT-based routing.
    pub fn mesh(&self) -> Option<&crate::MeshConfig> {
        self.mesh.as_ref()
    }

    /// Parses canonical JSON and resolves each frontend to a protocol-compatible backend.
    /// Returns a diagnostic for malformed JSON, unknown options or invalid resource bounds.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value = field(sibuna_json::parse_with_limits(bytes, &Self::DOCUMENT_LIMITS))?;
        let mut root = field(ObjectReader::new(&value))?;
        let mut limit = 1024;
        if let Some(mut global) = field(root.take_object("global"))? {
            limit = number(&mut global, "max_flows", limit, MAX_FLOWS)?;
            field(global.finish())?;
        }
        let mesh = field(root.take_object("mesh"))?.map(crate::MeshConfig::parse).transpose()?;
        let adaptive = mesh.is_some();
        let mut config = Self { limit, mesh, pools: BTreeMap::new(), listeners: BTreeMap::new() };
        for (name, value) in named(&mut root, "backends")? {
            config.pools.insert(name.into(), Backend::parse(name, value, adaptive)?);
        }
        for (name, value) in named(&mut root, "frontends")? {
            config.add_frontend(name, value)?;
        }
        field(root.finish())?;
        for (name, backend) in &config.pools {
            for server in &backend.servers {
                if config.listeners.keys().any(|&(proto, bind)| {
                    proto == backend.protocol
                        && (bind == server.addr
                            || (server.addr.ip().is_loopback() && overlaps(bind, server.addr)))
                }) {
                    return Err(invalid(format!(
                        "backends.{name}: {} is a frontend",
                        server.addr
                    )));
                }
            }
        }
        Ok(config)
    }

    fn add_frontend(&mut self, name: &str, value: &Value<'_>) -> Result<()> {
        let path = format!("frontends.{name}");
        let mut r = field(ObjectReader::with_path(value, path.clone()))?;
        let proto = protocol(&mut r, "proto")?;
        let pool = required(&mut r, "default_backend")?;
        if self.pools.get(&pool).is_none_or(|b| b.protocol != proto) {
            return Err(invalid(format!("{path}: no matching {proto:?} backend named {pool}")));
        }
        let rate = frontend_rate(&mut r, proto)?;
        let timeout = match field(r.take_str("session_timeout"))? {
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
        let binds = field(r.take_array("binds"))?.ok_or_else(|| invalid(r.missing("binds")))?;
        if binds.is_empty() || self.listeners.len() + binds.len() > 128 {
            return Err(invalid(format!("{path}: expected 1 to 128 binds in total")));
        }
        for bind in binds {
            let addr = address(bind.as_str().unwrap_or(""), &path)?;
            if proto == Protocol::Udp && addr.ip().is_unspecified() {
                return Err(invalid(format!("{path}: bind UDP to a specific local IP")));
            }
            let listener =
                Frontend { pool: pool.as_str().into(), timeout, inspect: inspect.clone(), rate };
            if self.listeners.keys().any(|&(p, bound)| p == proto && overlaps(bound, addr)) {
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

pub(crate) fn duration(text: &str) -> Option<Duration> {
    let (digits, multiplier) = if let Some(ms) = text.strip_suffix("ms") {
        (ms, 1)
    } else {
        (text.strip_suffix('s')?, 1000)
    };
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
        if protocol == Protocol::Udp && health.is_some() {
            return Err(invalid(format!("{path}: TCP probes require a TCP pool")));
        }
        let proxy_v2 = field(r.take_object("proxy_v2"))?
            .map(|r| crate::proxy::Spec::parse(r, protocol))
            .transpose()?
            .flatten();
        let scheduler = scheduler(&mut r, mesh, &mut servers)?;
        field(r.finish())?;
        Ok(Self { protocol, servers, scheduler, proxy_v2, health })
    }
}

pub(crate) enum Scheduler {
    LeastConnections,
    PeakEwma,
    Maglev { table: crate::maglev::Table, peak_fallback: bool },
    Adaptive(crate::maglev::Table),
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
    fn parse(value: &Value<'_>, path: String) -> Result<Self> {
        let mut r = field(ObjectReader::with_path(value, path))?;
        let name = required(&mut r, "name")?;
        let addr = address(&required(&mut r, "addr")?, r.path())?;
        if name.is_empty()
            || addr.ip() == std::net::Ipv4Addr::BROADCAST
            || addr.ip().is_unspecified()
            || addr.ip().is_multicast()
        {
            return Err(invalid(format!("{}: expected named unicast server", r.path())));
        }
        let weight = number(&mut r, "weight", 1, 65535)? as u32;
        let limit = number(&mut r, "max_flows", MAX_FLOWS, MAX_FLOWS)?;
        let remote = field(r.take_bool("remote"))?.unwrap_or(false);
        let backup = field(r.take_bool("backup"))?.unwrap_or(false);
        field(r.finish())?;
        Ok(Self { name, addr, limit, weight, backup, remote, healthy: None })
    }
}

fn frontend_rate(
    r: &mut ObjectReader<'_, '_>,
    proto: Protocol,
) -> Result<Option<sibuna_store::limiter::Limits>> {
    let (key, count, window_ms) = match proto {
        Protocol::Tcp => ("rate_limit", "conn_per_10s", 10_000),
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

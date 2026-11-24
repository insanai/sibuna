//! Request-level routing for the daemon's HTTP firewall. A reservation lasts through the
//! response body, including an upgraded connection.

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use sibuna_json::ObjectReader;

use crate::Regime;
use crate::config::{Backend, Config, Protocol, field, invalid, required};
use crate::pool::{Loads, Pool};

mod choose;
pub use choose::{HttpTarget, Query};

/// Node-local settings shared by HTTP frontends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpOptions {
    /// Apply the admission policy. When false the frontend only balances load: every
    /// well-formed request is routed, with no challenge and no policy file.
    pub firewall: bool,
    /// Run the semantic firewall as well as admission.
    pub shield: bool,
    /// The existing Sibuna JSON firewall policy.
    pub policy_file: Option<String>,
    /// Optional shared challenge seed for a cluster.
    pub secret_file: Option<String>,
    /// Requests per window for each client. `None` turns the default limiter off.
    pub rate_limit: Option<u32>,
    /// The length of the rate window in seconds.
    pub rate_window_seconds: u64,
    /// Concurrent HTTP/1.1 connections and multiplexed exchanges served.
    pub max_connections: u32,
    /// Concurrent connections and exchanges for one client address.
    pub max_connections_per_ip: u32,
    /// The longest silence on an HTTP connection, in seconds.
    pub idle_timeout_seconds: u32,
    /// The longest silence on an upgraded connection, in seconds.
    pub websocket_idle_timeout_seconds: u32,
    /// Serve HTTP on event-driven workers (SID 0016) where the platform has them.
    pub event_loop: bool,
    /// The number of event-driven workers. `None` uses one per processor.
    pub workers: Option<usize>,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            firewall: true,
            shield: true,
            policy_file: None,
            secret_file: None,
            rate_limit: Some(100),
            rate_window_seconds: 10,
            max_connections: 1024,
            max_connections_per_ip: 64,
            idle_timeout_seconds: 15,
            websocket_idle_timeout_seconds: 300,
            event_loop: true,
            workers: None,
        }
    }
}

impl HttpOptions {
    /// The most connections the event-driven workers serve: the size of the flow table.
    pub const MAX_CONNECTIONS: usize = 1_000_000;
    /// The most connections the thread-per-connection firewall serves.
    pub const MAX_THREADS: usize = 8192;

    pub(crate) fn parse(mut r: ObjectReader<'_, '_>) -> io::Result<Self> {
        let defaults = Self::default();
        let (firewall, shield) = match field(r.take_str("surface"))?.unwrap_or("shield") {
            "shield" => (true, true),
            "gate" => (true, false),
            "off" => (false, false),
            _ => return Err(invalid("http.surface must be off, gate or shield")),
        };
        let policy_file = field(r.take_str("policy_file"))?.map(str::to_owned);
        if !firewall && policy_file.is_some() {
            return Err(invalid("http.surface off takes no policy_file; use gate or shield"));
        }
        let secret_file = field(r.take_str("secret_file"))?.map(str::to_owned);
        // Without the firewall the default per-client limiter is off unless requested.
        let rate_default = if firewall { defaults.rate_limit } else { None };
        let rate_limit = match r.take("rate_limit") {
            None => rate_default,
            Some(value) if value.as_str() == Some("off") => None,
            Some(value) => match value.as_number().and_then(|n| n.as_u64().ok()) {
                Some(n) if (1..=1_000_000).contains(&n) => Some(n as u32),
                _ => return Err(invalid("http.rate_limit must be off or in 1..=1000000")),
            },
        };
        let seconds = |r: &mut ObjectReader<'_, '_>, key: &str, default: u32| match field(
            r.take_str(key),
        )? {
            None => Ok(default),
            Some(text) => crate::config::duration(text)
                .filter(|d| d.subsec_nanos() == 0)
                .map(|d| d.as_secs() as u32)
                .ok_or_else(|| invalid(format!("{}: expected whole seconds", r.field_path(key)))),
        };
        let rate_window_seconds = u64::from(seconds(&mut r, "rate_window", 10)?);
        let idle_timeout_seconds = seconds(&mut r, "idle_timeout", defaults.idle_timeout_seconds)?;
        let websocket_idle_timeout_seconds =
            seconds(&mut r, "websocket_idle_timeout", defaults.websocket_idle_timeout_seconds)?;
        let max_connections = crate::config::number(
            &mut r,
            "max_connections",
            defaults.max_connections as usize,
            Self::MAX_CONNECTIONS,
        )? as u32;
        let max_connections_per_ip = crate::config::number(
            &mut r,
            "max_connections_per_ip",
            defaults.max_connections_per_ip as usize,
            Self::MAX_CONNECTIONS,
        )? as u32;
        let event_loop = field(r.take_bool("event_loop"))?.unwrap_or(defaults.event_loop);
        if !event_loop && max_connections as usize > Self::MAX_THREADS {
            return Err(invalid("http.max_connections above 8192 needs http.event_loop"));
        }
        let workers = match field(r.take_u64("workers"))? {
            None => None,
            Some(count) if (1..=64).contains(&count) => Some(count as usize),
            Some(_) => return Err(invalid("http.workers must be in 1..=64")),
        };
        field(r.finish())?;
        Ok(Self {
            firewall,
            shield,
            policy_file,
            secret_file,
            rate_limit,
            rate_window_seconds,
            max_connections,
            max_connections_per_ip,
            idle_timeout_seconds,
            websocket_idle_timeout_seconds,
            event_loop,
            workers,
        })
    }
}

/// TLS and optional QUIC termination on one HTTP listener address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsOptions {
    /// Combined PEM files, or directories of them, in the order given. Each file holds a
    /// certificate chain, leaf first, and its private key. The first certificate is the
    /// default. The server name of a handshake selects among the others.
    pub crt: Vec<String>,
    /// A PEM certificate chain, leaf first, with its key in `key_file`.
    pub cert_file: Option<String>,
    /// The PEM private key matching the leaf of `cert_file`.
    pub key_file: Option<String>,
    /// Refuse a handshake whose server name matches no certificate.
    pub strict_sni: bool,
    /// Also bind UDP on this address for HTTP/3.
    pub http3: bool,
}

impl TlsOptions {
    pub(crate) fn parse(mut r: ObjectReader<'_, '_>) -> io::Result<Self> {
        let crt = match r.take("crt") {
            None => Vec::new(),
            Some(value) => match (value.as_str(), value.as_array()) {
                (Some(path), _) => vec![path.to_owned()],
                (_, Some(paths)) if (1..=64).contains(&paths.len()) => paths
                    .iter()
                    .map(|path| path.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| invalid(format!("{}: expected paths", r.field_path("crt"))))?,
                _ => {
                    return Err(invalid(format!(
                        "{}: expected a path or a list of 1 to 64 paths",
                        r.field_path("crt")
                    )));
                }
            },
        };
        let cert_file = field(r.take_str("cert_file"))?.map(str::to_owned);
        let key_file = field(r.take_str("key_file"))?.map(str::to_owned);
        if cert_file.is_some() != key_file.is_some() {
            return Err(invalid(format!("{}: cert_file and key_file go together", r.path())));
        }
        if crt.is_empty() && cert_file.is_none() {
            return Err(invalid(format!(
                "{}: expected crt (combined PEM) or cert_file with key_file",
                r.path()
            )));
        }
        let strict_sni = field(r.take_bool("strict_sni"))?.unwrap_or(false);
        let http3 = field(r.take_bool("http3"))?.unwrap_or(false);
        field(r.finish())?;
        Ok(Self { crt, cert_file, key_file, strict_sni, http3 })
    }
}

/// The HTTP version spoken to the servers of a pool.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OriginVersion {
    /// HTTP/1.1 with keep-alive.
    Http1,
    /// HTTP/2, over TLS with ALPN or in cleartext with prior knowledge.
    Http2,
    /// HTTP/3 over QUIC.
    Http3,
}

/// TLS towards the servers of a pool.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OriginTls {
    /// Check the server certificate and its name. Turn this off only on a trusted network.
    pub verify: bool,
    /// PEM trust anchors that replace the system roots.
    pub ca_file: Option<String>,
    /// The name to send as SNI and to verify. Defaults to the server's IP address.
    pub server_name: Option<String>,
}

/// How the firewall's HTTP/1.1 exchange reaches the servers of a pool. A pool without
/// these options speaks cleartext HTTP/1.1 and needs no adapter.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OriginOptions {
    /// The protocol version on the origin connection.
    pub version: OriginVersion,
    /// TLS settings, or `None` for cleartext.
    pub tls: Option<OriginTls>,
}

impl OriginOptions {
    /// Reads `http_version` and `tls` of an HTTP pool. Returns `None` for the default.
    pub(crate) fn parse(r: &mut ObjectReader<'_, '_>) -> io::Result<Option<Arc<Self>>> {
        let version = match field(r.take_str("http_version"))? {
            None | Some("1.1") => OriginVersion::Http1,
            Some("2") => OriginVersion::Http2,
            Some("3") => OriginVersion::Http3,
            Some(_) => {
                return Err(invalid(format!(
                    "{}: expected \"1.1\", \"2\" or \"3\"",
                    r.field_path("http_version")
                )));
            }
        };
        let tls = match field(r.take_object("tls"))? {
            None => None,
            Some(mut tls) => {
                let verify = field(tls.take_bool("verify"))?.unwrap_or(true);
                let ca_file = field(tls.take_str("ca_file"))?.map(str::to_owned);
                let server_name = field(tls.take_str("sni"))?.map(str::to_owned);
                if server_name.as_deref().is_some_and(|name| !crate::hello::valid_host(name)) {
                    return Err(invalid(format!(
                        "{}: expected a DNS name",
                        tls.field_path("sni")
                    )));
                }
                field(tls.finish())?;
                Some(OriginTls { verify, ca_file, server_name })
            }
        };
        if version == OriginVersion::Http3 && tls.is_none() {
            return Err(invalid(format!("{}: HTTP/3 servers need a tls section", r.path())));
        }
        if version == OriginVersion::Http1 && tls.is_none() {
            return Ok(None);
        }
        Ok(Some(Arc::new(Self { version, tls })))
    }
}

/// Checks a DNS name, IPv4 address or bracketed IPv6 literal with an optional numeric port.
pub fn valid_authority(bytes: &[u8]) -> bool {
    let Ok(value) = std::str::from_utf8(bytes) else { return false };
    if let Some(rest) = value.strip_prefix('[') {
        let Some((ip, tail)) = rest.split_once(']') else { return false };
        return ip.parse::<std::net::Ipv6Addr>().is_ok()
            && (tail.is_empty() || tail.strip_prefix(':').is_some_and(valid_port));
    }
    let (host, port) = value.split_once(':').map_or((value, None), |(h, p)| (h, Some(p)));
    crate::hello::valid_host(host.strip_suffix('.').unwrap_or(host)) && port.is_none_or(valid_port)
}

fn valid_port(port: &str) -> bool {
    port.bytes().all(|b| b.is_ascii_digit()) && port.parse::<u16>().is_ok()
}

pub(crate) struct Rule {
    host: Option<String>,
    path: Option<String>,
    pool: Arc<str>,
    firewall: bool,
    websocket: Option<Arc<crate::WebSocketRule>>,
}

impl Rule {
    fn matches(&self, host: &[u8], path: &[u8]) -> bool {
        self.host.as_ref().is_none_or(|h| host.eq_ignore_ascii_case(h.as_bytes()))
            && self.path.as_ref().is_none_or(|p| path.starts_with(p.as_bytes()))
    }
}

/// The host of an authority without its port and trailing dot.
fn bare_host(host: &[u8]) -> &[u8] {
    // A bracketed IPv6 literal keeps its colons.
    let end = if host.first() == Some(&b'[') {
        host.iter().position(|b| *b == b']').map_or(host.len(), |i| i + 1)
    } else {
        host.iter().position(|b| *b == b':').unwrap_or(host.len())
    };
    let host = &host[..end];
    host.strip_suffix(b".").unwrap_or(host)
}

pub(crate) fn rules(
    r: &mut ObjectReader<'_, '_>,
    pools: &BTreeMap<String, Backend>,
    firewall: bool,
    websocket: Option<&Arc<crate::WebSocketRule>>,
) -> io::Result<Vec<Rule>> {
    let mut rules = Vec::new();
    let entries = field(r.take_array("routes"))?.unwrap_or_default();
    if entries.len() > 128 {
        return Err(invalid("HTTP frontend supports up to 128 routes"));
    }
    for (i, row) in entries.iter().enumerate() {
        let mut row =
            field(ObjectReader::with_path(row, format!("{}[{i}]", r.field_path("routes"))))?;
        let host = field(row.take_str("host"))?.map(str::to_ascii_lowercase);
        let path = field(row.take_str("path_prefix"))?.map(str::to_owned);
        let pool = required(&mut row, "backend")?;
        let firewall = field(row.take_bool("firewall"))?.unwrap_or(firewall);
        if host.as_deref().is_some_and(|h| !crate::hello::valid_host(h))
            || path.as_deref().is_some_and(|p| !p.starts_with('/') || p.contains(['?', '#']))
            || (host.is_none() && path.is_none())
        {
            return Err(invalid(format!(
                "{}: expected a DNS host or absolute path_prefix",
                row.path()
            )));
        }
        if !pools.get(&pool).is_some_and(|p| p.protocol == Protocol::Http) {
            return Err(invalid(format!("{}: unknown HTTP backend {pool}", row.path())));
        }
        // A route without a rule of its own keeps the rule of its frontend.
        let websocket = match field(row.take_object("websocket"))? {
            Some(rule) => Some(crate::WebSocketRule::parse(rule)?),
            None => websocket.cloned(),
        };
        field(row.finish())?;
        rules.push(Rule { host, path, pool: pool.into(), firewall, websocket });
    }
    Ok(rules)
}

struct Frontend {
    pool: Arc<str>,
    rules: Arc<[Rule]>,
    firewall: bool,
    websocket: Option<Arc<crate::WebSocketRule>>,
}

impl Frontend {
    fn bypasses(&self) -> bool {
        !self.firewall || self.rules.iter().any(|rule| !rule.firewall)
    }
}

#[derive(Default)]
struct Table {
    revision: u64,
    fronts: BTreeMap<SocketAddr, Frontend>,
    pools: BTreeMap<String, Pool>,
    loads: Loads,
    regime: Option<Regime>,
    /// Some frontend or route turns the firewall off, so requests need the lookup.
    bypasses: bool,
    /// The key of the sticky cookies (SID 0019).
    sticky: crate::sticky::Key,
}

impl Table {
    fn front(&self, vip: SocketAddr) -> Option<&Frontend> {
        let wildcard = SocketAddr::new(
            if vip.is_ipv4() {
                std::net::Ipv4Addr::UNSPECIFIED.into()
            } else {
                std::net::Ipv6Addr::UNSPECIFIED.into()
            },
            vip.port(),
        );
        self.fronts.get(&vip).or_else(|| self.fronts.get(&wildcard))
    }
}

/// A shared view of the current HTTP routing table. Each exchange chooses its origin afresh.
#[derive(Clone, Default)]
pub struct HttpRoutes(Arc<Mutex<Table>>);

impl HttpRoutes {
    pub(crate) fn publish(&self, config: &mut Config) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        state.revision = state.revision.wrapping_add(1);
        state.fronts = config
            .listeners
            .iter()
            .filter(|((p, _), _)| *p == Protocol::Http)
            .map(|((_, addr), f)| {
                let front = Frontend {
                    pool: f.pool.clone(),
                    rules: f.http_rules.clone(),
                    firewall: f.firewall,
                    websocket: f.websocket.clone(),
                };
                (*addr, front)
            })
            .collect();
        state.bypasses = state.fronts.values().any(Frontend::bypasses);
        state.pools = config
            .pools
            .extract_if(.., |_, p| p.protocol == Protocol::Http)
            .map(|(name, p)| (name, Pool::new(p, &mut state.loads)))
            .collect();
        state.loads.prune();
    }

    /// Derives the key of the sticky cookies from `seed`, the challenge seed of the
    /// node (SID 0019). Nodes that share the seed accept each other's cookies. Without
    /// this call the key is random and lasts as long as the process.
    pub fn set_sticky_seed(&self, seed: &[u8]) {
        let mut table = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        table.sticky = crate::sticky::Key::derive(seed);
    }

    pub(crate) fn set_regime(&self, regime: Regime) {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).regime = Some(regime);
    }

    /// Whether the firewall applies to this request. A frontend or a matching route may
    /// turn it off (`"firewall": false`), which leaves plain load balancing. A request
    /// for an unknown listener keeps the firewall.
    pub fn firewall_applies(&self, vip: SocketAddr, host: &[u8], path: &[u8]) -> bool {
        let table = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if !table.bypasses {
            return true;
        }
        let Some(front) = table.front(vip) else { return true };
        let host = bare_host(host);
        front.rules.iter().find(|r| r.matches(host, path)).map_or(front.firewall, |r| r.firewall)
    }

    /// The WebSocket rule of this request: that of the first matching route, or that of
    /// the frontend. `None` when no rule applies.
    pub fn websocket(
        &self,
        vip: SocketAddr,
        host: &[u8],
        path: &[u8],
    ) -> Option<Arc<crate::WebSocketRule>> {
        let table = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let front = table.front(vip)?;
        let host = bare_host(host);
        match front.rules.iter().find(|r| r.matches(host, path)) {
            Some(rule) => rule.websocket.clone(),
            None => front.websocket.clone(),
        }
    }

    /// Selects an eligible HTTP origin for the validated authority and normalized path.
    /// This is [`HttpRoutes::choose`] for a request without cookies on a cleartext
    /// frontend.
    pub fn select(
        &self,
        vip: SocketAddr,
        peer: SocketAddr,
        host: &[u8],
        path: &[u8],
        policy_revision: u64,
    ) -> Option<HttpTarget> {
        self.choose(&Query { vip, peer, host, path, policy_revision, ..Query::default() })
    }
}

//! Request-level routing for the daemon's HTTP firewall. A reservation lasts through the
//! response body, including an upgraded connection.

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use sibuna_json::ObjectReader;

use crate::Regime;
use crate::config::{Backend, Config, Protocol, field, invalid, required};
use crate::pool::{Loads, Pool, Ticket};

/// Node-local settings shared by HTTP frontends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpOptions {
    /// Run the semantic firewall as well as admission.
    pub shield: bool,
    /// The existing Sibuna JSON firewall policy.
    pub policy_file: Option<String>,
    /// Optional shared challenge seed for a cluster.
    pub secret_file: Option<String>,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self { shield: true, policy_file: None, secret_file: None }
    }
}

impl HttpOptions {
    pub(crate) fn parse(mut r: ObjectReader<'_, '_>) -> io::Result<Self> {
        let shield = match field(r.take_str("surface"))?.unwrap_or("shield") {
            "shield" => true,
            "gate" => false,
            _ => return Err(invalid("http.surface must be gate or shield")),
        };
        let policy_file = field(r.take_str("policy_file"))?.map(str::to_owned);
        let secret_file = field(r.take_str("secret_file"))?.map(str::to_owned);
        field(r.finish())?;
        Ok(Self { shield, policy_file, secret_file })
    }
}

/// TLS and optional QUIC termination on one HTTP listener address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsOptions {
    /// PEM certificate chain, leaf first.
    pub cert_file: String,
    /// PEM private key matching the leaf certificate.
    pub key_file: String,
    /// Also bind UDP on this address for HTTP/3.
    pub http3: bool,
}

impl TlsOptions {
    pub(crate) fn parse(mut r: ObjectReader<'_, '_>) -> io::Result<Self> {
        let cert_file = required(&mut r, "cert_file")?;
        let key_file = required(&mut r, "key_file")?;
        let http3 = field(r.take_bool("http3"))?.unwrap_or(false);
        field(r.finish())?;
        Ok(Self { cert_file, key_file, http3 })
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
}

pub(crate) fn rules(
    r: &mut ObjectReader<'_, '_>,
    pools: &BTreeMap<String, Backend>,
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
        field(row.finish())?;
        rules.push(Rule { host, path, pool: pool.into() });
    }
    Ok(rules)
}

struct Frontend {
    pool: Arc<str>,
    rules: Arc<[Rule]>,
}

#[derive(Default)]
struct Table {
    revision: u64,
    fronts: BTreeMap<SocketAddr, Frontend>,
    pools: BTreeMap<String, Pool>,
    loads: Loads,
    regime: Option<Regime>,
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
                (*addr, Frontend { pool: f.pool.clone(), rules: f.http_rules.clone() })
            })
            .collect();
        state.pools = config
            .pools
            .extract_if(.., |_, p| p.protocol == Protocol::Http)
            .map(|(name, p)| (name, Pool::new(p, &mut state.loads)))
            .collect();
        state.loads.prune();
    }

    pub(crate) fn set_regime(&self, regime: Regime) {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).regime = Some(regime);
    }

    /// Selects an eligible HTTP origin for the validated authority and normalized path.
    pub fn select(
        &self,
        vip: SocketAddr,
        peer: SocketAddr,
        host: &[u8],
        path: &[u8],
        policy_revision: u64,
    ) -> Option<HttpTarget> {
        let mut table = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if policy_revision != table.revision {
            return None;
        }
        let wildcard = SocketAddr::new(
            if vip.is_ipv4() {
                std::net::Ipv4Addr::UNSPECIFIED.into()
            } else {
                std::net::Ipv6Addr::UNSPECIFIED.into()
            },
            vip.port(),
        );
        let front = table.fronts.get(&vip).or_else(|| table.fronts.get(&wildcard))?;
        let host = host.iter().position(|b| *b == b':').map_or(host, |i| &host[..i]);
        let host = host.strip_suffix(b".").unwrap_or(host);
        let pool = front
            .rules
            .iter()
            .find(|r| {
                r.host.as_ref().is_none_or(|h| host.eq_ignore_ascii_case(h.as_bytes()))
                    && r.path.as_ref().is_none_or(|p| path.starts_with(p.as_bytes()))
            })
            .map_or(&front.pool, |r| &r.pool)
            .clone();
        let regime = table.regime.unwrap_or(Regime::Standalone);
        table
            .pools
            .get_mut(pool.as_ref())?
            .reserve(Instant::now(), peer, vip, regime)
            .map(HttpTarget)
    }
}

/// An admitted HTTP exchange. Dropping it returns the backend's capacity.
pub struct HttpTarget(Ticket);

impl HttpTarget {
    /// The numeric HTTP/1.1 origin.
    pub fn address(&self) -> SocketAddr {
        self.0.addr
    }
    /// Records an origin connection failure for subsequent admissions.
    pub fn failed(&self) {
        self.0.failed(Instant::now());
    }
    /// Records the duration of a completed exchange.
    pub fn completed(&self, start: Instant) {
        self.0.observe(start, Instant::now());
    }
}

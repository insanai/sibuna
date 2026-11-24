//! The options of SID 0020: the access log, the access control of the internal routes,
//! and the proxies a frontend trusts.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use sibuna_cidr::Prefix;
use sibuna_json::{ObjectReader, Value};

use crate::config::{field, invalid};
use crate::stats::FrontendStats;

/// The most networks one list holds.
const MAX_NETWORKS: usize = 64;
/// The most forwarded entries the client walk reads.
const MAX_FORWARDED: usize = 32;

/// Where access log lines go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogOutput {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
    /// A file, opened for appending and reopened on SIGHUP.
    File(String),
}

/// The access log of the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessLogOptions {
    /// The destination.
    pub output: LogOutput,
    /// The capacity of the queue between the request paths and the writer, in entries.
    pub queue: usize,
}

/// The root object `observability`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObserveOptions {
    /// The access log, or `None` for no log.
    pub access_log: Option<AccessLogOptions>,
    /// The networks that may read the health, readiness and metrics routes on an HTTP
    /// frontend.
    pub internal_allow: Vec<Prefix>,
    /// The separate listener for health, readiness and metrics.
    pub listen: Option<SocketAddr>,
}

impl Default for ObserveOptions {
    /// No log, no separate listener, and the internal routes open to the loopback
    /// networks only.
    fn default() -> Self {
        let loopback = [
            Prefix::new(IpAddr::from([127, 0, 0, 0]), 8),
            Prefix::new(IpAddr::from(std::net::Ipv6Addr::LOCALHOST), 128),
        ];
        Self {
            access_log: None,
            internal_allow: loopback.into_iter().flatten().collect(),
            listen: None,
        }
    }
}

impl ObserveOptions {
    /// The smallest and the largest queue.
    pub const QUEUE_RANGE: std::ops::RangeInclusive<usize> = 64..=1_048_576;

    pub(crate) fn parse(mut r: ObjectReader<'_, '_>) -> io::Result<Self> {
        let defaults = Self::default();
        let access_log = field(r.take_object("access_log"))?.map(access_log).transpose()?;
        let internal_allow = match field(r.take_array("internal_allow"))? {
            Some(items) => networks(items, &r.field_path("internal_allow"))?,
            None => defaults.internal_allow,
        };
        let listen = match field(r.take_str("listen"))? {
            Some(text) => Some(crate::config::address(text, &r.field_path("listen"))?),
            None => None,
        };
        field(r.finish())?;
        Ok(Self { access_log, internal_allow, listen })
    }

    /// True when `address` may read the internal routes.
    pub fn allows(&self, address: IpAddr) -> bool {
        self.internal_allow.iter().any(|network| network.contains(address))
    }
}

fn access_log(mut r: ObjectReader<'_, '_>) -> io::Result<AccessLogOptions> {
    let output = match field(r.take_str("output"))? {
        Some("stdout") => LogOutput::Stdout,
        Some("stderr") => LogOutput::Stderr,
        Some(path) if !path.is_empty() => LogOutput::File(path.to_owned()),
        _ => {
            return Err(invalid(format!(
                "{}: expected a file path, \"stdout\" or \"stderr\"",
                r.field_path("output")
            )));
        }
    };
    if !matches!(field(r.take_str("format"))?, None | Some("json")) {
        return Err(invalid(format!("{}: only \"json\" exists", r.field_path("format"))));
    }
    let queue = match field(r.take_u64("queue"))? {
        None => 8192,
        Some(n) if ObserveOptions::QUEUE_RANGE.contains(&(n as usize)) => n as usize,
        Some(_) => {
            return Err(invalid(format!("{} must be in 64..=1048576", r.field_path("queue"))));
        }
    };
    field(r.finish())?;
    Ok(AccessLogOptions { output, queue })
}

/// Reads a list of at most 64 CIDR networks. `path` names the list in a diagnostic.
fn networks(items: &[Value<'_>], path: &str) -> io::Result<Vec<Prefix>> {
    if items.len() > MAX_NETWORKS {
        return Err(invalid(format!("{path}: expected at most {MAX_NETWORKS} networks")));
    }
    items
        .iter()
        .map(|item| {
            let text = item.as_str().unwrap_or("");
            sibuna_cidr::parse_cidr(text.as_bytes()).map_err(|_| {
                invalid(format!("{path}: expected a network such as 10.0.0.0/8, found {text:?}"))
            })
        })
        .collect()
}

/// The names and counters of the servers of one pool, by address.
pub(crate) fn server_infos(
    servers: &[crate::config::Server],
) -> Vec<(SocketAddr, crate::ServerInfo)> {
    // A reservation names the adapter of a server that has one.
    servers
        .iter()
        .filter_map(|server| Some((server.via.unwrap_or(server.addr), server.info.clone()?)))
        .collect()
}

/// What a request path knows about the frontend it serves.
#[derive(Clone, Debug, Default)]
pub struct FrontendInfo {
    /// The name of the frontend in the topology.
    pub name: Arc<str>,
    /// The counters of the frontend.
    pub stats: Arc<FrontendStats>,
    /// The networks of the proxies in front of the frontend.
    pub trusted: Arc<[Prefix]>,
    /// Every connection begins with a PROXY header.
    pub proxy_protocol: bool,
}

/// What the forwarded entries of a request say about its client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Forwarded<'a> {
    /// The client, as the text of its entry and as an address.
    Client(&'a [u8], IpAddr),
    /// An entry on the walk is not an address, or the list is longer than 32 entries.
    Malformed,
    /// There are no entries.
    Absent,
}

impl FrontendInfo {
    /// Reads `trusted_proxies` and `proxy_protocol` of the frontend `name`. A UDP
    /// frontend has neither, and a TCP frontend has both or neither: without the header
    /// a TCP connection says nothing about its client.
    pub(crate) fn parse(
        r: &mut ObjectReader<'_, '_>,
        name: &str,
        protocol: crate::config::Protocol,
    ) -> io::Result<Self> {
        use crate::config::Protocol;

        let trusted = match field(r.take_array("trusted_proxies"))? {
            Some(items) => networks(items, &r.field_path("trusted_proxies"))?,
            None => Vec::new(),
        };
        let proxy_protocol = field(r.take_bool("proxy_protocol"))?.unwrap_or(false);
        if protocol == Protocol::Udp && (proxy_protocol || !trusted.is_empty()) {
            return Err(invalid(format!(
                "{}: trusted_proxies and proxy_protocol need an HTTP or a TCP frontend",
                r.path()
            )));
        }
        if protocol == Protocol::Tcp && !proxy_protocol && !trusted.is_empty() {
            return Err(invalid(format!(
                "{}: a TCP frontend reads trusted_proxies only with proxy_protocol",
                r.path()
            )));
        }
        if proxy_protocol && trusted.is_empty() {
            return Err(invalid(format!(
                "{}: proxy_protocol needs trusted_proxies, the networks that may send the header",
                r.path()
            )));
        }
        Ok(Self {
            name: name.into(),
            stats: Arc::default(),
            trusted: trusted.into(),
            proxy_protocol,
        })
    }

    /// True when `peer` is one of the proxies this frontend trusts.
    pub fn trusts(&self, peer: IpAddr) -> bool {
        self.trusted.iter().any(|network| network.contains(peer))
    }

    /// Finds the client in the forwarded entries of a request whose socket peer is
    /// trusted. `entries` yields the entries from the right, the last proxy's first. The
    /// client is the first entry that is not a trusted proxy, or the leftmost entry when
    /// all are. Entries a client wrote lie to the left of that one and are never read.
    pub fn forwarded_client<'a>(&self, entries: impl Iterator<Item = &'a [u8]>) -> Forwarded<'a> {
        let mut leftmost = Forwarded::Absent;
        for (index, entry) in entries.enumerate() {
            if index >= MAX_FORWARDED {
                return Forwarded::Malformed;
            }
            let Ok(address) = sibuna_cidr::parse_ip(entry) else { return Forwarded::Malformed };
            leftmost = Forwarded::Client(entry, address);
            if !self.trusts(address) {
                return leftmost;
            }
        }
        leftmost
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(trusted: &[&str]) -> FrontendInfo {
        let trusted: Vec<Prefix> =
            trusted.iter().map(|text| sibuna_cidr::parse_cidr(text.as_bytes()).unwrap()).collect();
        FrontendInfo { trusted: trusted.into(), ..FrontendInfo::default() }
    }

    fn walk<'a>(info: &FrontendInfo, chain: &'a str) -> Forwarded<'a> {
        info.forwarded_client(chain.rsplit(',').map(|entry| entry.trim().as_bytes()))
    }

    #[test]
    fn the_client_is_the_first_untrusted_entry_from_the_right() {
        let info = info(&["198.51.100.0/24", "10.0.0.0/8"]);
        let client =
            |text: &'static str| Forwarded::Client(text.as_bytes(), text.parse().unwrap());
        assert_eq!(walk(&info, "203.0.113.7"), client("203.0.113.7"));
        assert_eq!(walk(&info, "203.0.113.7, 198.51.100.9, 10.1.2.3"), client("203.0.113.7"));
        // A forged entry to the left of the client is never read, even a malformed one.
        assert_eq!(walk(&info, "10.9.9.9, 203.0.113.7"), client("203.0.113.7"));
        assert_eq!(walk(&info, "junk, 203.0.113.7, 10.1.2.3"), client("203.0.113.7"));
        // Only proxies: the leftmost one is the client.
        assert_eq!(walk(&info, "10.0.0.1, 10.0.0.2"), client("10.0.0.1"));
    }

    #[test]
    fn a_malformed_or_endless_chain_names_nobody() {
        let info = info(&["10.0.0.0/8"]);
        assert_eq!(walk(&info, "junk, 10.0.0.1"), Forwarded::Malformed);
        assert_eq!(info.forwarded_client(std::iter::empty()), Forwarded::Absent);
        let endless = vec!["10.0.0.1"; 33].join(",");
        assert_eq!(walk(&info, &endless), Forwarded::Malformed);
    }

    #[test]
    fn the_default_opens_the_internal_routes_to_loopback_only() {
        let options = ObserveOptions::default();
        assert!(options.allows("127.0.0.1".parse().unwrap()));
        assert!(options.allows("127.8.9.10".parse().unwrap()));
        assert!(options.allows("::1".parse().unwrap()));
        assert!(!options.allows("10.0.0.1".parse().unwrap()));
        assert!(!options.allows("::2".parse().unwrap()));
        assert!(options.access_log.is_none() && options.listen.is_none());
    }
}

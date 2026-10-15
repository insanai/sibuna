//! The console's configuration (Zig's `config.zig`): the listener, the proxy ingress and
//! canonical origin, the advertised URL, probes, management peers and the budget.
//!
//! The daemon fills a [`Config`] from its `--console*` flags; [`Config::validate`] checks
//! it before [`Console::start`](crate::Console::start) binds anything. The rules protect
//! the edge: the console listens on loopback unless it sits behind a TLS-terminating proxy
//! with an explicit list of trusted proxy networks and an HTTPS origin, and every outbound
//! target is an explicit operator choice, never a replicated value.

pub mod budget;
pub mod peers;

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use sibuna_console_protocol::Location;

use crate::http::ingress::Network;
pub use budget::{Budget, BudgetError};
pub use peers::{PeerConfigError, PeerOrigin, PeerTarget, Peers, parse_peer_origin};

/// The default listener: loopback, port 9443.
pub const DEFAULT_LISTEN: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9443);
/// The most trusted proxy networks.
pub const MAX_PROXIES: usize = 16;
/// The longest trusted proxy network text, `<address>/<bits>`.
pub const MAX_PROXY: usize = 49;
/// The longest origin or advertised URL.
pub const MAX_ORIGIN: usize = 255;
/// The most probed data-plane listeners.
pub const MAX_PROBES: usize = 8;

/// One probed data-plane listener (`--console-probe <node>=http://<ip>[:port]`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Probe {
    /// The probed node's id.
    pub node: u32,
    /// `http://` and a numeric host with an optional port.
    pub url: String,
}

/// A parsed probe URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeTarget {
    /// The address to connect to.
    pub address: SocketAddr,
    /// The host as written (IPv6 keeps its brackets), for the `Host` field.
    pub host: String,
}

/// The console's configuration. Plain data; [`Config::validate`] checks it.
#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    /// Where the console listens. Port 0 binds an ephemeral port; the daemon's flag parser
    /// refuses it, tests use it.
    pub listen: SocketAddr,
    /// A TLS-terminating proxy delivers every request (`--console-behind-proxy`).
    pub behind_proxy: bool,
    /// Cookies carry `Secure` even without a proxy (`--console-cookie-secure`).
    pub cookie_secure: bool,
    /// The console key file (`--console-key-file`); the About page reports whether one is set.
    pub key_file: Option<PathBuf>,
    /// The canonical origin, `https://host[:port]` behind a proxy. Empty: derived from the
    /// bound address as `http://<ip>:<port>`.
    pub origin: String,
    /// The networks whose connections may carry forwarded fields, `<address>/<bits>`.
    pub trusted_proxies: Vec<String>,
    /// The origin peers show as this console's link; empty for none.
    pub advertise: String,
    /// This node's declared position, shown on the globe.
    pub server_location: Option<Location>,
    /// The data-plane listeners this console probes.
    pub probes: Vec<Probe>,
    /// Management peers.
    pub peers: Peers,
    /// Slot quotas and the memory budget.
    pub budget: Budget,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            listen: DEFAULT_LISTEN,
            behind_proxy: false,
            cookie_secure: false,
            key_file: None,
            origin: String::new(),
            trusted_proxies: Vec::new(),
            advertise: String::new(),
            server_location: None,
            probes: Vec::new(),
            peers: Peers::default(),
            budget: Budget::default(),
        }
    }
}

/// Why a configuration was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfigError {
    /// The slot quotas or the stack break a budget rule.
    Budget(BudgetError),
    /// The server location is not a valid latitude and longitude.
    InvalidLocation,
    /// The console listens off loopback without `--console-behind-proxy` and a trusted
    /// proxy network.
    TrustedProxyRequired,
    /// The canonical origin is not `https://host[:port]` (behind a proxy).
    InvalidOrigin,
    /// A trusted proxy is not `<address>/<bits>`.
    InvalidProxy,
    /// More than [`MAX_PROXIES`] trusted proxy networks.
    TooManyProxies,
    /// The advertised URL is not an origin, or HTTP to a host other than loopback.
    InvalidAdvertise,
    /// A probe is not `http://<ip>[:port]`, names node 0 or this node, or there are more
    /// than [`MAX_PROBES`].
    InvalidProbe,
    /// Two probes name the same node.
    DuplicateProbe,
    /// The management peers are invalid.
    Peers(PeerConfigError),
}

impl ConfigError {
    /// Returns a sentence that tells an operator how to fix the problem.
    pub fn hint(self) -> &'static str {
        match self {
            ConfigError::Budget(_) => "Keep 16 to 256 slots with at least 16 reserved for HTTP.",
            ConfigError::InvalidLocation => "Give the location as `<latitude>,<longitude>`.",
            ConfigError::TrustedProxyRequired => {
                "Listen on loopback, or add `--console-behind-proxy` with \
                 `--console-trusted-proxy <cidr>` and an HTTPS `--console-origin`."
            }
            ConfigError::InvalidOrigin => "Write the origin as `https://host[:port]`.",
            ConfigError::InvalidProxy => "Write each trusted proxy as `<address>/<bits>`.",
            ConfigError::TooManyProxies => "Give at most 16 trusted proxy networks.",
            ConfigError::InvalidAdvertise => {
                "Advertise `https://host[:port]`, or `http://` only on a loopback address."
            }
            ConfigError::InvalidProbe => {
                "Write probes as `<node>=http://<ip>[:port]` for other nodes, at most eight."
            }
            ConfigError::DuplicateProbe => "Probe each node once.",
            ConfigError::Peers(error) => error.hint(),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Budget(error) => error.fmt(f),
            ConfigError::InvalidLocation => f.write_str("invalid console server location"),
            ConfigError::TrustedProxyRequired => {
                f.write_str("an off-loopback console needs a trusted proxy")
            }
            ConfigError::InvalidOrigin => f.write_str("invalid console origin"),
            ConfigError::InvalidProxy => f.write_str("invalid trusted proxy network"),
            ConfigError::TooManyProxies => f.write_str("too many trusted proxy networks"),
            ConfigError::InvalidAdvertise => f.write_str("invalid advertised console URL"),
            ConfigError::InvalidProbe => f.write_str("invalid console probe"),
            ConfigError::DuplicateProbe => f.write_str("duplicate console probe"),
            ConfigError::Peers(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Budget(error) => Some(error),
            ConfigError::Peers(error) => Some(error),
            _ => None,
        }
    }
}

impl Config {
    /// Checks the configuration of the console of node `node_id`.
    ///
    /// Fails with the first [`ConfigError`] that applies, in Zig's order: the budget, the
    /// location, the advertised URL, the probes, the peers, then the loopback rule and,
    /// behind a proxy, the trusted networks and the origin.
    pub fn validate(&self, node_id: u32) -> Result<(), ConfigError> {
        self.budget.validate().map_err(ConfigError::Budget)?;
        if self.server_location.is_some_and(|location| !location.is_valid()) {
            return Err(ConfigError::InvalidLocation);
        }
        self.validate_advertise()?;
        self.validate_probes(node_id)?;
        self.peers.validate(node_id, self.behind_proxy).map_err(ConfigError::Peers)?;
        if !self.listen.ip().is_loopback() && !self.behind_proxy {
            return Err(ConfigError::TrustedProxyRequired);
        }
        if self.behind_proxy {
            self.validate_proxy()?;
        }
        Ok(())
    }

    /// An advertised URL is an origin; HTTP only for loopback literals.
    fn validate_advertise(&self) -> Result<(), ConfigError> {
        let invalid = ConfigError::InvalidAdvertise;
        if self.advertise.is_empty() {
            return Ok(());
        }
        if self.advertise.len() > MAX_ORIGIN {
            return Err(invalid);
        }
        let (https, authority) = match self.advertise.strip_prefix("https://") {
            Some(authority) => (true, authority),
            None => (false, self.advertise.strip_prefix("http://").ok_or(invalid)?),
        };
        if authority.is_empty() || !authority.bytes().all(is_origin_byte) {
            return Err(invalid);
        }
        let (host, port) = split_authority(authority).ok_or(invalid)?;
        if port == Some(0) {
            return Err(invalid);
        }
        if https {
            return Ok(());
        }
        match host.parse::<IpAddr>() {
            Ok(address) if address.is_loopback() => Ok(()),
            _ => Err(invalid),
        }
    }

    fn validate_probes(&self, node_id: u32) -> Result<(), ConfigError> {
        if self.probes.len() > MAX_PROBES {
            return Err(ConfigError::InvalidProbe);
        }
        for (index, probe) in self.probes.iter().enumerate() {
            if probe.node == 0 || probe.node == node_id {
                return Err(ConfigError::InvalidProbe);
            }
            parse_probe(&probe.url)?;
            if self.probes.iter().take(index).any(|earlier| earlier.node == probe.node) {
                return Err(ConfigError::DuplicateProbe);
            }
        }
        Ok(())
    }

    fn validate_proxy(&self) -> Result<(), ConfigError> {
        if self.trusted_proxies.is_empty() {
            return Err(ConfigError::TrustedProxyRequired);
        }
        if self.trusted_proxies.len() > MAX_PROXIES {
            return Err(ConfigError::TooManyProxies);
        }
        if !is_https_origin(&self.origin) {
            return Err(ConfigError::InvalidOrigin);
        }
        for proxy in &self.trusted_proxies {
            if proxy.len() > MAX_PROXY || Network::parse(proxy).is_none() {
                return Err(ConfigError::InvalidProxy);
            }
        }
        Ok(())
    }
}

/// Returns true for `https://` and an authority of printable ASCII without `/?#@%\`, with
/// a non-empty host and an optional nonzero port.
fn is_https_origin(origin: &str) -> bool {
    let Some(authority) = origin.strip_prefix("https://") else { return false };
    if origin.len() > MAX_ORIGIN || authority.is_empty() || !authority.bytes().all(is_origin_byte)
    {
        return false;
    }
    matches!(split_authority(authority), Some((_, port)) if port != Some(0))
}

/// Parses a probe URL: `http://` and a numeric host, IPv6 in brackets (or bare when no port
/// is given), with an optional nonzero port (80 by default). Probes carry no TLS client
/// and never resolve names.
///
/// Fails with [`ConfigError::InvalidProbe`] for anything else.
pub fn parse_probe(url: &str) -> Result<ProbeTarget, ConfigError> {
    let invalid = ConfigError::InvalidProbe;
    let authority = url.strip_prefix("http://").ok_or(invalid)?;
    if authority.is_empty() || authority.bytes().any(|byte| b"/?#@ \\".contains(&byte)) {
        return Err(invalid);
    }
    let bracketed = authority.starts_with('[');
    let (host, port) = match authority.rfind(':') {
        // `[v6]:port`, or `v4:port` where the colon is the only one.
        Some(at)
            if (bracketed && authority[..at].ends_with(']'))
                || (!bracketed && !authority[..at].contains(':')) =>
        {
            let port = authority[at + 1..].parse::<u16>().map_err(|_| invalid)?;
            (&authority[..at], port)
        }
        _ => (authority, 80),
    };
    let bare = if bracketed {
        host.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')).ok_or(invalid)?
    } else {
        host
    };
    let address = bare.parse::<IpAddr>().map_err(|_| invalid)?;
    if port == 0 {
        return Err(invalid);
    }
    Ok(ProbeTarget { address: SocketAddr::new(address, port), host: host.to_owned() })
}

/// Returns true for a byte an origin's authority may hold: printable ASCII except
/// `/?#@%\` (no path, query, fragment, user information, escapes or backslashes).
pub(crate) fn is_origin_byte(byte: u8) -> bool {
    (33..127).contains(&byte) && !b"/?#@%\\".contains(&byte)
}

/// Splits an authority into its host (IPv6 without brackets) and optional port. Returns
/// `None` for an empty host, a malformed bracket, an unbracketed host with several colons,
/// or a port that is not a decimal `u16`.
pub(crate) fn split_authority(authority: &str) -> Option<(&str, Option<u16>)> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        match after {
            "" => (host, None),
            _ => (host, Some(after.strip_prefix(':')?)),
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return None;
    }
    let port = match port {
        Some(text) if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => {
            Some(text.parse::<u16>().ok()?)
        }
        Some(_) => return None,
        None => None,
    };
    Some((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxied(origin: &str) -> Config {
        Config {
            behind_proxy: true,
            origin: origin.into(),
            trusted_proxies: vec!["::1/128".into()],
            ..Config::default()
        }
    }

    // config.zig: "off-loopback requires explicit HTTPS ingress and bounded CIDR list".
    // Zig also refused an enabled console without storage; here `Console::start` cannot be
    // called without a storage handle, so that check is the type system's.
    #[test]
    fn off_loopback_requires_an_https_ingress_and_bounded_networks() {
        let mut config = Config::default();
        assert_eq!(config.validate(0), Ok(()));
        config.listen = "0.0.0.0:9443".parse().unwrap();
        assert_eq!(config.validate(0), Err(ConfigError::TrustedProxyRequired));
        config.behind_proxy = true;
        config.origin = "https://console.example".into();
        config.trusted_proxies = vec!["127.0.0.1/32".into()];
        assert_eq!(config.validate(0), Ok(()));
        config.origin = "https://console.example/path".into();
        assert_eq!(config.validate(0), Err(ConfigError::InvalidOrigin));
        config.origin = "https://console.example".into();
        config.trusted_proxies = vec!["127.0.0.1/33".into()];
        assert_eq!(config.validate(0), Err(ConfigError::InvalidProxy));
        config.trusted_proxies = vec!["10.0.0.0/8".into(); 17];
        assert_eq!(config.validate(0), Err(ConfigError::TooManyProxies));
        config.trusted_proxies.clear();
        assert_eq!(config.validate(0), Err(ConfigError::TrustedProxyRequired));
    }

    // config.zig: "advertised URLs and probe targets are explicit, numeric and unique".
    #[test]
    fn advertised_urls_and_probes_are_explicit_numeric_and_unique() {
        let mut config = Config { advertise: "http://127.0.0.1:9443".into(), ..Config::default() };
        assert_eq!(config.validate(1), Ok(()));
        config.advertise = "https://console.example:8443".into();
        assert_eq!(config.validate(1), Ok(()));
        for url in ["http://console.example", "https://a@b", "ftp://x", "https://x/y"] {
            config.advertise = url.into();
            assert_eq!(config.validate(1), Err(ConfigError::InvalidAdvertise), "{url}");
        }
        config.advertise.clear();
        config.probes = vec![Probe { node: 2, url: "http://127.0.0.1:8082".into() }];
        assert_eq!(config.validate(1), Ok(()));
        let target = parse_probe("http://[::1]:8082").unwrap();
        assert_eq!(target.host, "[::1]");
        assert_eq!(target.address.port(), 8082);
        assert_eq!(parse_probe("http://10.0.0.2").unwrap().address.port(), 80);
        for url in ["https://127.0.0.1:1", "http://peer.example:1", "http://127.0.0.1:0"] {
            assert_eq!(parse_probe(url), Err(ConfigError::InvalidProbe), "{url}");
        }
        config.probes.push(Probe { node: 2, url: "http://127.0.0.1:8083".into() });
        assert_eq!(config.validate(1), Err(ConfigError::DuplicateProbe));
        config.probes[1].node = 1;
        assert_eq!(config.validate(1), Err(ConfigError::InvalidProbe));
    }

    // config.zig: "proxy origin rejects unusable authorities and ambiguous encoded hosts".
    #[test]
    fn the_proxy_origin_refuses_unusable_and_encoded_authorities() {
        for origin in [
            "https://:443",
            "https://console.example:0",
            "https://%65xample.com",
            "https://user@console.example",
            "https://console.example:",
            "https://console.example:65536",
            "https://[::1",
            "https://a:b:c",
        ] {
            assert_eq!(proxied(origin).validate(0), Err(ConfigError::InvalidOrigin), "{origin}");
        }
        assert_eq!(proxied("https://[::1]:9443").validate(0), Ok(()));
    }

    #[test]
    fn errors_have_hints_and_sources() {
        let error = ConfigError::Peers(PeerConfigError::PeerKeyRequired);
        assert!(error.hint().contains("peer-key-file"));
        assert!(std::error::Error::source(&error).is_some());
        assert!(ConfigError::TrustedProxyRequired.hint().contains("behind-proxy"));
    }
}

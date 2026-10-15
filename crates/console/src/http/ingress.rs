//! Trusted ingress (Zig's `ingress.zig`): behind a proxy, a request is accepted only from a
//! configured proxy network and only with exactly `X-Forwarded-Proto: https`.
//!
//! Forwarded metadata is believed only from those transport peers. The canonical HTTPS
//! origin comes from configuration; `Host` and forwarded host fields never authorize a
//! request. The networks are parsed once at start, where Zig parsed them per request.

use std::net::IpAddr;

use crate::config::Config;

/// One trusted network: an address normalised to 16 bytes (IPv4 as IPv4-mapped IPv6) and
/// its prefix length in that 128-bit space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Network {
    address: [u8; 16],
    bits: u8,
}

impl Network {
    /// Parses `<address>/<bits>`, with at most 32 bits for IPv4 and 128 for IPv6. Returns
    /// `None` for anything else.
    pub fn parse(text: &str) -> Option<Network> {
        let (address, bits) = text.rsplit_once('/')?;
        let address: IpAddr = address.parse().ok()?;
        if bits.is_empty() || !bits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let bits: u8 = bits.parse().ok()?;
        let (limit, offset) = if address.is_ipv4() { (32, 96) } else { (128, 0) };
        if bits > limit {
            return None;
        }
        Some(Network { address: normalized(address), bits: bits + offset })
    }

    /// Returns true when `peer` lies in the network. An IPv4 peer and an IPv4-mapped IPv6
    /// peer are the same address.
    pub fn contains(&self, peer: IpAddr) -> bool {
        let peer = normalized(peer);
        let whole = usize::from(self.bits / 8);
        // `bits` is at most 128, so `whole` is at most 16 and both slices are in bounds.
        if self.address.get(..whole) != peer.get(..whole) {
            return false;
        }
        let tail = self.bits % 8;
        if tail == 0 {
            return true;
        }
        let mask = 0xffu8 << (8 - tail);
        match (self.address.get(whole), peer.get(whole)) {
            (Some(expected), Some(actual)) => expected & mask == actual & mask,
            _ => false,
        }
    }
}

fn normalized(address: IpAddr) -> [u8; 16] {
    match address {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// The ingress rule of one console.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ingress {
    behind_proxy: bool,
    networks: Vec<Network>,
}

impl Ingress {
    /// Returns the rule of `config`; networks that do not parse are left out, which
    /// [`Config::validate`] has already refused.
    pub fn new(config: &Config) -> Ingress {
        let networks = config.trusted_proxies.iter().filter_map(|text| Network::parse(text));
        Ingress { behind_proxy: config.behind_proxy, networks: networks.collect() }
    }

    /// Returns true when a request from `peer` with the `X-Forwarded-Proto` value
    /// `forwarded_proto` may be served: always without a proxy; behind one, only from a
    /// trusted network and with exactly `https`.
    pub fn accepts(&self, peer: IpAddr, forwarded_proto: Option<&[u8]>) -> bool {
        if !self.behind_proxy {
            return true;
        }
        if forwarded_proto != Some(b"https") {
            return false;
        }
        self.networks.iter().any(|network| network.contains(peer))
    }

    /// Returns true when the console sits behind a proxy.
    pub fn is_behind_proxy(&self) -> bool {
        self.behind_proxy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    // ingress.zig: "trusted ingress requires the transport CIDR and a single HTTPS
    // indication".
    #[test]
    fn trusted_ingress_requires_the_network_and_https() {
        let config = Config {
            behind_proxy: true,
            trusted_proxies: vec!["127.0.0.0/25".into(), "2001:db8::2/127".into()],
            ..Config::default()
        };
        let ingress = Ingress::new(&config);
        let loopback = ip("127.0.0.1");
        assert!(ingress.accepts(loopback, Some(b"https")));
        assert!(!ingress.accepts(loopback, None));
        assert!(!ingress.accepts(loopback, Some(b"http")));
        assert!(!ingress.accepts(loopback, Some(b"https,http")));
        assert!(!ingress.accepts(ip("127.0.0.128"), Some(b"https")));
        assert!(ingress.accepts(ip("::ffff:127.0.0.1"), Some(b"https")));
        assert!(ingress.accepts(ip("2001:db8::3"), Some(b"https")));
        assert!(!ingress.accepts(ip("2001:db8::4"), Some(b"https")));
        assert!(Ingress::new(&Config::default()).accepts(ip("203.0.113.9"), None));
    }

    #[test]
    fn networks_parse_strictly() {
        assert!(Network::parse("10.0.0.0/8").is_some());
        assert!(Network::parse("::/0").is_some_and(|all| all.contains(ip("8.8.8.8"))));
        for invalid in ["10.0.0.0", "10.0.0.0/33", "::1/129", "10.0.0.0/+8", "x/8", "10.0.0.0/"] {
            assert!(Network::parse(invalid).is_none(), "{invalid}");
        }
    }
}

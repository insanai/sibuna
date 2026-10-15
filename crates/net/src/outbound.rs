//! The address policy of management-only outbound connections (webhooks, GeoIP downloads,
//! management peers and probes), never the request path.
//!
//! DNS answers are bounded and every one is validated against a [`Policy`] before any
//! connection, so a name cannot smuggle a private address past the check. The caller then
//! pins its connection to one validated address while TLS still authenticates the original
//! host name. The connections themselves belong to the console (`sibuna-console`'s HTTP
//! client over `sibuna-tls`, SID 0012); this module opens none.

use std::fmt;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

/// Which destinations a caller may reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Policy {
    /// Public unicast addresses only.
    PublicOnly,
    /// Public addresses and loopback.
    LoopbackAllowed,
    /// Administrator-configured management origins: private networks too, but never
    /// unspecified, multicast or link-local destinations.
    ConfiguredManagement,
}

/// The most distinct addresses a name may resolve to.
pub const MAX_ADDRESSES: usize = 16;

/// The longest host name, as RFC 1123 allows.
pub const MAX_HOST: usize = 255;

/// Why an outbound operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OutboundError {
    /// The host is empty, too long, or not a valid name.
    InvalidHost,
    /// An address is not allowed by the policy.
    TargetRejected,
    /// The name did not resolve.
    HostUnresolved,
    /// The name resolved to more than [`MAX_ADDRESSES`] distinct addresses.
    TooManyAddresses,
}

impl fmt::Display for OutboundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OutboundError::InvalidHost => "invalid host",
            OutboundError::TargetRejected => "target address not allowed",
            OutboundError::HostUnresolved => "host did not resolve",
            OutboundError::TooManyAddresses => "host resolved to too many addresses",
        })
    }
}

impl std::error::Error for OutboundError {}

/// A host name held inline, at most [`MAX_HOST`] bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Host {
    data: [u8; MAX_HOST],
    length: u8,
}

impl fmt::Debug for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Host").field(&self.as_str()).finish()
    }
}

impl Host {
    /// Copies `text`; only its length is checked, as in Zig.
    ///
    /// # Errors
    ///
    /// [`OutboundError::InvalidHost`] when it is empty or longer than [`MAX_HOST`].
    pub fn new(text: &str) -> Result<Host, OutboundError> {
        let length = u8::try_from(text.len()).map_err(|_| OutboundError::InvalidHost)?;
        if length == 0 {
            return Err(OutboundError::InvalidHost);
        }
        let mut data = [0u8; MAX_HOST];
        data.get_mut(..text.len())
            .ok_or(OutboundError::InvalidHost)?
            .copy_from_slice(text.as_bytes());
        Ok(Host { data, length })
    }

    /// The host text.
    pub fn as_str(&self) -> &str {
        let bytes = self.data.get(..usize::from(self.length)).unwrap_or_default();
        // `new` copied a whole `&str`, so the bytes are valid UTF-8.
        std::str::from_utf8(bytes).unwrap_or_default()
    }
}

/// The validated addresses of one name, in answer order, without duplicates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Addresses {
    items: [Option<SocketAddr>; MAX_ADDRESSES],
    count: usize,
}

impl Addresses {
    /// Adds `address` after checking it against `policy`; a duplicate is ignored.
    ///
    /// # Errors
    ///
    /// [`OutboundError::TargetRejected`] for a disallowed address,
    /// [`OutboundError::TooManyAddresses`] when the set is full.
    pub fn add(&mut self, address: SocketAddr, policy: Policy) -> Result<(), OutboundError> {
        if !is_allowed(address.ip(), policy) {
            return Err(OutboundError::TargetRejected);
        }
        if self.iter().any(|previous| previous == address) {
            return Ok(());
        }
        let slot = self.items.get_mut(self.count).ok_or(OutboundError::TooManyAddresses)?;
        *slot = Some(address);
        self.count += 1;
        Ok(())
    }

    /// The addresses in order.
    pub fn iter(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.items.iter().flatten().copied()
    }

    /// The number of addresses.
    pub fn len(&self) -> usize {
        self.count
    }

    /// True when there are none.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// Validates a host name per RFC 1123 as Zig's `HostName.validate` does: labels of 1 to 63
/// letters, digits and inner hyphens, at most 255 bytes without a trailing dot.
pub fn is_valid_host_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    let trimmed = bytes.strip_suffix(b".").unwrap_or(bytes);
    if bytes.is_empty() || trimmed.len() > MAX_HOST || trimmed.is_empty() {
        return false;
    }
    trimmed.split(|&byte| byte == b'.').all(|label| {
        (1..=63).contains(&label.len())
            && label.iter().all(|&byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && label.first().is_some_and(u8::is_ascii_alphanumeric)
            && label.last().is_some_and(u8::is_ascii_alphanumeric)
    })
}

/// Resolves `host` (an address literal or a name) and validates every answer against
/// `policy` before returning any. Blocks in the system resolver.
///
/// # Errors
///
/// [`OutboundError::InvalidHost`], [`OutboundError::HostUnresolved`], or the errors of
/// [`Addresses::add`] for any answer.
pub fn resolve(host: &str, port: u16, policy: Policy) -> Result<Addresses, OutboundError> {
    let mut addresses = Addresses::default();
    if let Ok(ip) = host.parse::<IpAddr>() {
        addresses.add(SocketAddr::new(ip, port), policy)?;
        return Ok(addresses);
    }
    if !is_valid_host_name(host) {
        return Err(OutboundError::InvalidHost);
    }
    let answers = (host, port).to_socket_addrs().map_err(|_| OutboundError::HostUnresolved)?;
    for answer in answers {
        addresses.add(answer, policy)?;
    }
    if addresses.is_empty() {
        return Err(OutboundError::HostUnresolved);
    }
    Ok(addresses)
}

/// Whether `ip` may be reached under `policy`.
///
/// Private networks are allowed only for administrator-configured management origins, and
/// unspecified, multicast, link-local and mapped IPv6 destinations stay excluded. The IPv6
/// loopback test is Zig's `isLoopBack`, which looks at bytes 0 to 2 and 12 to 15 only.
pub fn is_allowed(ip: IpAddr, policy: Policy) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let b = v4.octets();
            if policy == Policy::ConfiguredManagement {
                return b[0] != 0 && b[0] < 224 && !(b[0] == 169 && b[1] == 254);
            }
            if b[0] == 127 {
                return policy == Policy::LoopbackAllowed;
            }
            let private = b[0] == 0
                || b[0] == 10
                || b[0] >= 224
                || (b[0] == 172 && (16..=31).contains(&b[1]))
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 100 && (64..=127).contains(&b[1]));
            !private && !(b[0] == 169 && b[1] == 254)
        }
        IpAddr::V6(v6) => {
            let b = v6.octets();
            let loopback = b[0] == 0 && b[1] == 0 && b[2] == 0 && b[12..16] == [0, 0, 0, 1];
            if policy == Policy::ConfiguredManagement {
                return loopback || b[0] & 0xfe == 0xfc || b[0] & 0xe0 == 0x20;
            }
            if loopback {
                return policy == Policy::LoopbackAllowed;
            }
            b[0] & 0xe0 == 0x20
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> SocketAddr {
        SocketAddr::new(text.parse().unwrap(), 443)
    }

    #[test]
    fn all_dns_answers_are_checked_before_connecting_and_results_have_a_fixed_bound() {
        let mut answers = Addresses::default();
        for index in 0..MAX_ADDRESSES {
            answers.add(addr(&format!("8.8.8.{index}")), Policy::PublicOnly).unwrap();
        }
        assert_eq!(
            answers.add(addr("10.0.0.1"), Policy::PublicOnly),
            Err(OutboundError::TargetRejected)
        );
        assert_eq!(
            answers.add(addr("8.8.4.4"), Policy::PublicOnly),
            Err(OutboundError::TooManyAddresses)
        );
        assert!(!is_allowed("::ffff:127.0.0.1".parse().unwrap(), Policy::PublicOnly));
    }

    #[test]
    fn only_explicit_management_targets_may_reach_private_networks() {
        for host in ["10.0.0.1", "172.16.0.1", "192.168.1.1", "fd00::1"] {
            let ip = host.parse().unwrap();
            assert!(is_allowed(ip, Policy::ConfiguredManagement));
            assert!(!is_allowed(ip, Policy::PublicOnly));
            assert!(!is_allowed(ip, Policy::LoopbackAllowed));
        }
        for host in ["0.0.0.0", "169.254.169.254", "224.0.0.1", "::", "fe80::1"] {
            assert!(!is_allowed(host.parse().unwrap(), Policy::ConfiguredManagement));
        }
        assert!(is_allowed("127.0.0.1".parse().unwrap(), Policy::LoopbackAllowed));
        assert!(is_allowed("::1".parse().unwrap(), Policy::LoopbackAllowed));
        assert!(is_allowed("2001:db8::1".parse().unwrap(), Policy::PublicOnly));
    }

    /// Cases from Zig 0.16 `std.Io.net.HostName.validate`'s own tests.
    #[test]
    fn host_names_follow_rfc_1123() {
        let long_label = format!("{}.com", "a".repeat(63));
        let longest = format!("{}a", "a.".repeat(127));
        let longest_dot = format!("{}a.", "a.".repeat(127));
        for name in ["example", "example.com.", "host-name.example.com.", "127.0.0.1", "a-b.com"]
            .into_iter()
            .chain([long_label.as_str(), longest.as_str(), longest_dot.as_str()])
        {
            assert!(is_valid_host_name(name), "{name}");
        }
        let too_long_label = format!("{}.com", "a".repeat(64));
        let too_long = format!("{}ab", "a.".repeat(127));
        for name in ["", ".example.com", "example.com..", "host..domain", "-hostname", "hostname-"]
            .into_iter()
            .chain(["hostname-.com", "a.-.b", "host_name.com", ".", ".."])
            .chain([too_long_label.as_str(), too_long.as_str()])
        {
            assert!(!is_valid_host_name(name), "{name}");
        }
        assert_eq!(resolve("bad_name", 80, Policy::PublicOnly), Err(OutboundError::InvalidHost));
        assert_eq!(
            resolve("127.0.0.1", 80, Policy::PublicOnly),
            Err(OutboundError::TargetRejected)
        );
        assert_eq!(resolve("127.0.0.1", 80, Policy::LoopbackAllowed).unwrap().len(), 1);
    }
}

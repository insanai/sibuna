//! The `global.acme.internal` object: the lifetime of a certificate of the local
//! authority, the name constraints of its root and its ACME server (SID 0021). Nothing
//! here opens a socket or a file.

use std::io;
use std::net::IpAddr;

use sibuna_json::ObjectReader;

use super::server::InternalServer;
use crate::config::{field, invalid};

/// The default lifetime of a certificate of the local authority, in seconds: 12 hours.
pub const INTERNAL_LIFETIME: u64 = 43_200;
/// The most entries of `constraints`.
const MAX_CONSTRAINTS: usize = 32;

/// The `global.acme.internal` object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Internal {
    /// The lifetime of a certificate, in seconds.
    pub lifetime: u64,
    /// What the root may sign for: DNS suffixes in lower case without a leading dot,
    /// and address ranges as `ADDRESS/PREFIX` with the bits after the prefix cleared.
    /// Sorted, without repetitions. Empty: the root signs for every name.
    pub constraints: Vec<String>,
    /// The ACME server in front of the authority. `None`: there is none.
    pub server: Option<InternalServer>,
}

impl Default for Internal {
    fn default() -> Self {
        Self { lifetime: INTERNAL_LIFETIME, constraints: Vec::new(), server: None }
    }
}

/// The address range that `text` spells: `ADDRESS/PREFIX`, or one address, which is the
/// range of that address alone. The bits after the prefix are cleared.
pub(super) fn range(text: &str) -> Option<(IpAddr, u8)> {
    let (address, prefix) = match text.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (text, None),
    };
    let address: IpAddr = address.parse().ok()?;
    let width: u8 = if address.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(prefix) => prefix.parse::<u8>().ok().filter(|prefix| *prefix <= width)?,
        None => width,
    };
    Some((masked(address, prefix), prefix))
}

/// `address` with every bit after the first `prefix` bits cleared.
fn masked(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V4((u32::from(address) & mask).into())
        }
        IpAddr::V6(address) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V6((u128::from(address) & mask).into())
        }
    }
}

/// One entry of `constraints` in its stored form, or `None` when it is no DNS suffix
/// and no address range.
pub(super) fn canonical(entry: &str) -> Option<String> {
    if let Some((address, prefix)) = range(entry) {
        return Some(format!("{address}/{prefix}"));
    }
    let suffix = entry.trim_start_matches('.');
    let plain = !entry.contains('/') && !entry.contains(':') && crate::hello::valid_host(suffix);
    plain.then(|| suffix.to_ascii_lowercase())
}

impl Internal {
    /// Reads `global.acme.internal: { lifetime: SECONDS, constraints: [...], server: {...} }`.
    pub(crate) fn take(r: &mut ObjectReader<'_, '_>) -> io::Result<Self> {
        let Some(mut internal) = field(r.take_object("internal"))? else {
            return Ok(Self::default());
        };
        let path = internal.field_path("lifetime");
        let lifetime = match field(internal.take_u64("lifetime"))? {
            None => INTERNAL_LIFETIME,
            Some(seconds) if (10..=172_800).contains(&seconds) => seconds,
            Some(_) => return Err(invalid(format!("{path}: expected 10 to 172800 seconds"))),
        };
        let path = internal.field_path("constraints");
        let mut constraints = match field(internal.take_array("constraints"))? {
            None => Vec::new(),
            Some(items) if (1..=MAX_CONSTRAINTS).contains(&items.len()) => items
                .iter()
                .map(|item| {
                    item.as_str().and_then(canonical).ok_or_else(|| {
                        invalid(format!(
                            "{path}: expected DNS suffixes such as \"corp.internal\" and \
                             address ranges such as \"10.0.0.0/8\""
                        ))
                    })
                })
                .collect::<io::Result<Vec<_>>>()?,
            Some(_) => {
                return Err(invalid(format!("{path}: expected 1 to {MAX_CONSTRAINTS} entries")));
            }
        };
        constraints.sort();
        constraints.dedup();
        let server = field(internal.take_object("server"))?
            .map(|server| InternalServer::parse(server, &constraints))
            .transpose()?;
        field(internal.finish())?;
        Ok(Self { lifetime, constraints, server })
    }

    /// Whether the root of the local authority may sign for `name`: a host name, a
    /// wildcard `*.NAME` or an IP address. The empty list permits every name. Else a
    /// host name needs a suffix that equals it or ends it at a dot, a wildcard needs
    /// one for the name below the star, and an address needs a range that contains it.
    pub fn permits(&self, name: &str) -> bool {
        if self.constraints.is_empty() {
            return true;
        }
        if let Ok(address) = name.parse::<IpAddr>() {
            return self.constraints.iter().filter_map(|entry| range(entry)).any(
                |(network, prefix)| {
                    network.is_ipv4() == address.is_ipv4() && masked(address, prefix) == network
                },
            );
        }
        let host = name.strip_prefix("*.").unwrap_or(name).to_ascii_lowercase();
        self.constraints.iter().filter(|entry| !entry.contains('/')).any(|suffix| {
            host.strip_suffix(suffix.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn constrained(entries: &[&str]) -> Internal {
        let constraints = entries.iter().filter_map(|entry| canonical(entry)).collect();
        Internal { constraints, ..Internal::default() }
    }

    #[test]
    fn entries_take_one_form() {
        assert_eq!(canonical(".Corp.Internal").as_deref(), Some("corp.internal"));
        assert_eq!(canonical("localhost").as_deref(), Some("localhost"));
        assert_eq!(canonical("10.1.2.3/8").as_deref(), Some("10.0.0.0/8"));
        assert_eq!(canonical("127.0.0.1").as_deref(), Some("127.0.0.1/32"));
        assert_eq!(canonical("FD00::1/8").as_deref(), Some("fd00::/8"));
        assert_eq!(canonical("::1").as_deref(), Some("::1/128"));
        assert_eq!(canonical("0.0.0.0/0").as_deref(), Some("0.0.0.0/0"));
        for bad in ["", "a b", "10.0.0.0/33", "::/129", "corp/8", "*.corp", "a..b", "10.0.0.0/"] {
            assert_eq!(canonical(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_empty_list_permits_every_name() {
        let open = Internal::default();
        assert!(open.permits("bank.example") && open.permits("192.0.2.1") && open.permits("::1"));
    }

    #[test]
    fn a_suffix_covers_a_name_at_a_label_boundary() {
        let internal = constrained(&["corp.internal", "localhost", "10.0.0.0/8", "fd00::/8"]);
        for name in ["corp.internal", "a.corp.internal", "A.B.Corp.Internal", "localhost"] {
            assert!(internal.permits(name), "{name}");
        }
        assert!(internal.permits("*.corp.internal") && internal.permits("*.a.corp.internal"));
        for name in ["evilcorp.internal", "internal", "corp.internal.example", "*.internal"] {
            assert!(!internal.permits(name), "{name}");
        }
        for address in ["10.0.0.1", "10.255.255.255", "fd00::1", "fdff::"] {
            assert!(internal.permits(address), "{address}");
        }
        for address in ["11.0.0.1", "9.255.255.255", "127.0.0.1", "::1", "fe80::1"] {
            assert!(!internal.permits(address), "{address}");
        }
    }

    #[test]
    fn a_list_of_one_kind_closes_the_other() {
        let names = constrained(&["corp.internal"]);
        assert!(names.permits("a.corp.internal") && !names.permits("10.0.0.1"));
        let ranges = constrained(&["10.0.0.0/8"]);
        assert!(ranges.permits("10.0.0.1") && !ranges.permits("a.corp.internal"));
        // A range of IPv4 never contains an IPv6 address with the same leading bits.
        let all_v4 = constrained(&["0.0.0.0/0"]);
        assert!(all_v4.permits("192.0.2.1") && !all_v4.permits("::"));
    }
}

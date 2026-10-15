//! IP address parsing and a radix trie of CIDR prefixes.
//!
//! We parse IPv4 and IPv6 addresses and CIDR prefixes with exactly the syntax the Zig daemon
//! accepted, and we store prefixes with values in a binary radix trie that answers
//! longest-prefix lookups without allocation. Both families share one 128-bit key space in
//! which an IPv4 address is its IPv4-mapped IPv6 address.
//!
//! ```
//! use sibuna_cidr::{PrefixTrie, parse_ip};
//!
//! let mut trie = PrefixTrie::new();
//! trie.insert_cidr(b"10.0.0.0/8", "challenge").unwrap();
//! trie.insert_cidr(b"10.1.2.0/24", "allow").unwrap();
//! trie.insert_cidr(b"2001:db8::/32", "deny").unwrap();
//! assert_eq!(trie.lookup_str(b"10.1.2.55"), Some(&"allow"));
//! assert_eq!(trie.lookup_str(b"::ffff:10.5.6.7"), Some(&"challenge"));
//! assert_eq!(trie.lookup(parse_ip(b"2001:db8::1").unwrap()), Some(&"deny"));
//! assert_eq!(trie.lookup_str(b"192.0.2.1"), None);
//! ```
//!
//! # Changes from the Zig version
//!
//! `libs/policy/src/radix_trie.zig` and Zig 0.16's `std.Io.net` parsers are the
//! specification. The port differs deliberately as follows.
//!
//! - Fix: the prefix `0.0.0.0/0` (equally `::ffff:0:0/96`) now matches every IPv4 address.
//!   Zig stored it on the node where IPv4 lookups start but never read that node's value,
//!   so such an entry silently matched nothing.
//! - The trie stores any value type instead of a policy `Action`, and `insert` returns the
//!   value it replaced.
//! - The node capacity is a run-time value (default 8,192, as in Zig) with `u32` indices.
//!   A failed insertion leaves the trie unchanged; Zig kept the nodes it had created.
//! - Parsers return `Result` with a `ParseError` instead of `null`. `parse_ip` returns a
//!   `std::net::IpAddr` (IPv4 text gives `V4`) instead of the mapped `u128`; `mapped_key`
//!   gives the same key Zig used. The accepted and refused texts are unchanged, including
//!   Zig's lenient IPv4 parts (`010`, `+1`, `-0`, `1_0`), which existing policy files may
//!   rely on.
//! - `Prefix::contains` replaces the policy crate's `CidrMatcher.matches` arithmetic.

mod parse;
mod trie;

pub use parse::{
    IPV4_MAPPED_PREFIX, ParseError, Prefix, mapped_key, parse_cidr, parse_ip, parse_ipv4,
    parse_ipv6,
};
pub use trie::{DEFAULT_MAX_NODES, PrefixTrie, TrieError};

#[cfg(test)]
mod tests;

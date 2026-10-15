//! A binary radix trie of CIDR prefixes with longest-prefix lookup.
//!
//! One trie over 128-bit keys serves both families: IPv6 prefixes are inserted as they are
//! and IPv4 prefixes under `::ffff:0:0/96`, so an IPv4 `/24` is a path of depth 120. Nodes
//! live in one flat `Vec` indexed by `u32` (index 0 is the root and doubles as "no child"),
//! so a lookup is at most 128 dependent loads, with no pointer chasing and no allocation.
//!
//! ```text
//!   root (::/0)
//!    |  96 nodes along ::ffff:0:0/96, created up front
//!    v
//!   ipv4_root (0.0.0.0/0) --> IPv4 lookups start here and walk at most 32 levels
//! ```

use std::fmt;
use std::net::IpAddr;

use crate::parse::{IPV4_MAPPED_PREFIX, ParseError, Prefix, is_ipv4_mapped, mapped_key};

/// Node capacity of `PrefixTrie::new`, as in the Zig daemon.
pub const DEFAULT_MAX_NODES: u32 = 8192;

/// Depth of the IPv4 subtree's root in the key space.
const IPV4_DEPTH: u8 = 96;

/// Why an insertion failed. The trie is unchanged after an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrieError {
    /// The prefix needs more nodes than the capacity allows.
    Full,
    /// The CIDR text does not parse.
    InvalidCidr(ParseError),
}

impl fmt::Display for TrieError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrieError::Full => f.write_str("the prefix trie is full"),
            TrieError::InvalidCidr(error) => write!(f, "invalid CIDR prefix: {error}"),
        }
    }
}

impl std::error::Error for TrieError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TrieError::Full => None,
            TrieError::InvalidCidr(error) => Some(error),
        }
    }
}

#[derive(Clone, Debug)]
struct Node<V> {
    /// Children for bit 0 and bit 1; 0 means none.
    children: [u32; 2],
    value: Option<V>,
}

impl<V> Node<V> {
    fn empty() -> Node<V> {
        Node { children: [0, 0], value: None }
    }
}

/// A set of CIDR prefixes, each with a value, answering longest-prefix lookups.
///
/// Inserting allocates at most up to the node capacity; looking up never allocates.
///
/// IPv4 lookups (including IPv4-mapped IPv6 addresses) consult the IPv4 prefixes, the
/// prefix `0.0.0.0/0` (equally `::ffff:0:0/96`), and the catch-all `::/0`. Other IPv6
/// prefixes that happen to cover `::ffff:0:0/96`, such as `::/64`, do not apply to them: an
/// operator who writes an IPv6 network means IPv6 clients.
#[derive(Clone, Debug)]
pub struct PrefixTrie<V> {
    nodes: Vec<Node<V>>,
    ipv4_root: u32,
    max_nodes: u32,
}

impl<V> Default for PrefixTrie<V> {
    fn default() -> PrefixTrie<V> {
        PrefixTrie::new()
    }
}

impl<V> PrefixTrie<V> {
    /// Returns an empty trie with room for `DEFAULT_MAX_NODES` nodes.
    pub fn new() -> PrefixTrie<V> {
        let mut trie =
            PrefixTrie { nodes: Vec::new(), ipv4_root: 0, max_nodes: DEFAULT_MAX_NODES };
        trie.clear();
        trie
    }

    /// Returns an empty trie with room for `max_nodes` nodes, the root and the 96 nodes
    /// leading to the IPv4 subtree included.
    ///
    /// Fails with `Full` when `max_nodes` is below 97.
    pub fn with_max_nodes(max_nodes: u32) -> Result<PrefixTrie<V>, TrieError> {
        if max_nodes <= u32::from(IPV4_DEPTH) {
            return Err(TrieError::Full);
        }
        let mut trie = PrefixTrie { nodes: Vec::new(), ipv4_root: 0, max_nodes };
        trie.clear();
        Ok(trie)
    }

    /// Removes every prefix and frees the nodes beyond the path to the IPv4 subtree.
    pub fn clear(&mut self) {
        self.nodes.clear();
        self.nodes.push(Node::empty());
        // The capacity always covers this path (checked by the constructors).
        self.ipv4_root = self.path_to(IPV4_MAPPED_PREFIX, IPV4_DEPTH);
    }

    /// Returns the number of nodes in use, the root and the IPv4 path included.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the node capacity.
    pub fn max_nodes(&self) -> u32 {
        self.max_nodes
    }

    /// Associates `value` with `prefix`, replacing and returning any earlier value.
    ///
    /// Fails with `Full` when the new nodes would exceed the capacity.
    pub fn insert(&mut self, prefix: Prefix, value: V) -> Result<Option<V>, TrieError> {
        let (reached, depth) = self.longest_existing_path(prefix.key(), prefix.length());
        let needed = usize::from(prefix.length() - depth);
        if self.nodes.len() + needed > self.max_nodes as usize {
            return Err(TrieError::Full);
        }
        let node = self.extend_path(reached, depth, prefix.key(), prefix.length());
        Ok(self.nodes[node as usize].value.replace(value))
    }

    /// Parses `text` as a CIDR prefix (see `parse_cidr`) and inserts it with `value`.
    ///
    /// Fails with `InvalidCidr` or `Full`.
    pub fn insert_cidr(&mut self, text: &[u8], value: V) -> Result<Option<V>, TrieError> {
        let prefix = crate::parse_cidr(text).map_err(TrieError::InvalidCidr)?;
        self.insert(prefix, value)
    }

    /// Returns the value of the longest prefix that contains `address`, if any.
    pub fn lookup(&self, address: IpAddr) -> Option<&V> {
        let key = mapped_key(address);
        let (mut node, mut depth, mut best) = if is_ipv4_mapped(key) {
            let start = self.ipv4_root;
            let value = self.nodes[start as usize].value.as_ref();
            (start, IPV4_DEPTH, value.or(self.nodes[0].value.as_ref()))
        } else {
            (0, 0, self.nodes[0].value.as_ref())
        };
        while depth < 128 {
            let next = self.nodes[node as usize].children[bit_at(key, depth)];
            if next == 0 {
                break;
            }
            node = next;
            best = self.nodes[node as usize].value.as_ref().or(best);
            depth += 1;
        }
        best
    }

    /// Parses `text` as an address (see `parse_ip`) and looks it up. Returns `None` when the
    /// text is not an address.
    pub fn lookup_str(&self, text: &[u8]) -> Option<&V> {
        crate::parse_ip(text).ok().and_then(|address| self.lookup(address))
    }

    /// Follows the existing nodes along the first `length` bits of `key`; returns the last
    /// node reached and its depth.
    fn longest_existing_path(&self, key: u128, length: u8) -> (u32, u8) {
        let mut node = 0;
        for depth in 0..length {
            match self.nodes[node as usize].children[bit_at(key, depth)] {
                0 => return (node, depth),
                child => node = child,
            }
        }
        (node, length)
    }

    /// Creates the nodes from `node` at `depth` down to depth `length` along `key` and
    /// returns the last one. The caller checked the capacity.
    fn extend_path(&mut self, mut node: u32, depth: u8, key: u128, length: u8) -> u32 {
        for depth in depth..length {
            let child = self.nodes.len() as u32;
            self.nodes.push(Node::empty());
            self.nodes[node as usize].children[bit_at(key, depth)] = child;
            node = child;
        }
        node
    }

    /// Returns the node for the first `length` bits of `key`, creating nodes as needed. Used
    /// only where the capacity is known to suffice.
    fn path_to(&mut self, key: u128, length: u8) -> u32 {
        let (reached, depth) = self.longest_existing_path(key, length);
        self.extend_path(reached, depth, key, length)
    }
}

/// Returns bit `depth` of `key`, counting from the most significant bit, as a child index.
fn bit_at(key: u128, depth: u8) -> usize {
    ((key >> (127 - depth)) & 1) as usize
}

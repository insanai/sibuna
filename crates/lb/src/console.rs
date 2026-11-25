//! The `console` section of the topology (SID 0031): where the operator console of this
//! node listens, where it keeps its accounts, and which other nodes are its peers.
//!
//! The section has two forms. A single node writes `listen`. A fleet writes `nodes`, the
//! same list on every node, and each node finds itself in it by its number, which `node`
//! gives in place or `node_file` names a file for. Nothing here opens a socket. The
//! daemon turns these options into the configuration of `sibuna-console`.

use std::io;
use std::net::{IpAddr, SocketAddr};

use sibuna_json::{ObjectReader, Value};

use crate::config::{field, invalid};

/// The most members of a fleet, this node included (SID 0031).
pub const MAX_CONSOLE_NODES: usize = 64;
/// The most networks in one list of the section.
const MAX_NETWORKS: usize = 16;
/// Node numbers are below 2^23, as the console requires.
const NODE_LIMIT: u64 = 1 << 23;

/// Another member of the fleet, as this node sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsolePeer {
    /// The number of the peer.
    pub node: u32,
    /// The HTTPS origin of the console of the peer.
    pub origin: String,
    /// The networks that the connections of the peer come from. Never empty.
    pub allow_ips: Vec<String>,
}

/// The `console` section, resolved for this node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsoleOptions {
    /// The address the console binds.
    pub listen: SocketAddr,
    /// The number of this node, from 1.
    pub node: u32,
    /// The directory of the SQLite file with accounts, sessions and the audit log.
    pub data_dir: String,
    /// The canonical origin of this console, when the file gives one.
    pub origin: Option<String>,
    /// A TLS proxy stands in front of the console.
    pub behind_proxy: bool,
    /// The networks of that proxy.
    pub trusted_proxies: Vec<String>,
    /// The networks operators come from. Empty admits every address.
    pub allow_operators: Vec<String>,
    /// The key that seals second factors.
    pub key_file: Option<String>,
    /// The key that peers prove themselves with.
    pub peer_key_file: Option<String>,
    /// The trust anchors of the certificates of the peers.
    pub peer_ca_file: Option<String>,
    /// The other members of the fleet, in the order of the file.
    pub peers: Vec<ConsolePeer>,
}

impl Default for ConsoleOptions {
    /// A console on the loopback address, port 9443, for node 1, without peers.
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 9443)),
            node: 1,
            data_dir: String::new(),
            origin: None,
            behind_proxy: false,
            trusted_proxies: Vec::new(),
            allow_operators: Vec::new(),
            key_file: None,
            peer_key_file: None,
            peer_ca_file: None,
            peers: Vec::new(),
        }
    }
}

/// One entry of `console.nodes`.
struct Member {
    node: u32,
    listen: SocketAddr,
    origin: String,
    allow_ips: Vec<String>,
}

impl ConsoleOptions {
    /// Takes the `console` section out of the topology `root`, or `None` without one.
    /// Fails as [`Self::parse`] does, and when `console` is not an object.
    pub(crate) fn section(root: &mut ObjectReader<'_, '_>) -> io::Result<Option<Self>> {
        field(root.take_object("console"))?.map(Self::parse).transpose()
    }

    /// Reads the section. With `nodes` it reads the number of this node from the file
    /// that `node_file` names.
    ///
    /// # Errors
    ///
    /// An `InvalidData` error that names the field: an unknown key, a bad address or
    /// network, a number twice, a list that does not hold this node, or a `node_file`
    /// that cannot be read.
    pub(crate) fn parse(mut r: ObjectReader<'_, '_>) -> io::Result<Self> {
        let text = |r: &mut ObjectReader<'_, '_>, key: &str| -> io::Result<Option<String>> {
            Ok(field(r.take_str(key))?.filter(|text| !text.is_empty()).map(str::to_owned))
        };
        let data_dir = text(&mut r, "data_dir")?
            .ok_or_else(|| invalid("console.data_dir is required: the console keeps accounts"))?;
        let mut options = Self {
            data_dir,
            origin: text(&mut r, "origin")?,
            behind_proxy: field(r.take_bool("behind_proxy"))?.unwrap_or(false),
            trusted_proxies: networks(&mut r, "trusted_proxies")?,
            allow_operators: networks(&mut r, "allow_operators")?,
            key_file: text(&mut r, "key_file")?,
            peer_key_file: text(&mut r, "peer_key_file")?,
            peer_ca_file: text(&mut r, "peer_ca_file")?,
            ..Self::default()
        };
        let own = own_number(&mut r)?;
        match field(r.take_array("nodes"))? {
            Some(entries) => options.join(own, members(entries)?)?,
            None => {
                let listen = field(r.take_str("listen"))?;
                let listen = listen.ok_or_else(|| invalid(r.missing("listen")))?;
                options.listen = address(listen, "console.listen")?;
                options.node = own.unwrap_or(1);
            }
        }
        field(r.finish())?;
        Ok(options)
    }

    /// Takes this node and its peers from the members of a fleet.
    fn join(&mut self, own: Option<u32>, members: Vec<Member>) -> io::Result<()> {
        let own = own.ok_or_else(|| {
            invalid("console.nodes needs console.node or console.node_file to name this node")
        })?;
        if !members.iter().any(|member| member.node == own) {
            return Err(invalid(format!("console.nodes does not name this node, {own}")));
        }
        for member in members {
            if member.node == own {
                self.listen = member.listen;
                self.origin = Some(member.origin);
            } else {
                let Member { node, origin, allow_ips, .. } = member;
                self.peers.push(ConsolePeer { node, origin, allow_ips });
            }
        }
        self.node = own;
        Ok(())
    }
}

/// The number of this node: `node`, or the content of the file `node_file` names.
fn own_number(r: &mut ObjectReader<'_, '_>) -> io::Result<Option<u32>> {
    let given = field(r.take_u64("node"))?;
    let from_file = match field(r.take_str("node_file"))? {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|error| invalid(format!("console.node_file {path}: {error}")))?;
            let number = text.trim().parse::<u64>().map_err(|_| {
                invalid(format!("console.node_file {path} must hold the number of this node"))
            })?;
            Some(number)
        }
        None => None,
    };
    match (given, from_file) {
        (Some(_), Some(_)) => {
            Err(invalid("console.node and console.node_file exclude each other"))
        }
        (number, other) => number.or(other).map(|n| node_number(n, "console.node")).transpose(),
    }
}

fn node_number(number: u64, path: &str) -> io::Result<u32> {
    if number == 0 || number >= NODE_LIMIT {
        return Err(invalid(format!("{path} must be in 1..={}", NODE_LIMIT - 1)));
    }
    Ok(number as u32)
}

fn address(text: &str, path: &str) -> io::Result<SocketAddr> {
    let address: SocketAddr =
        text.parse().map_err(|_| invalid(format!("{path} must be IP:PORT, got {text}")))?;
    if address.port() == 0 {
        return Err(invalid(format!("{path} needs a port other than 0")));
    }
    Ok(address)
}

/// Reads a list of at most 16 networks, each `ADDRESS/BITS`.
fn networks(r: &mut ObjectReader<'_, '_>, key: &str) -> io::Result<Vec<String>> {
    let path = r.field_path(key);
    match field(r.take_array(key))? {
        Some(entries) => network_list(entries, &path),
        None => Ok(Vec::new()),
    }
}

fn network_list(entries: &[Value<'_>], path: &str) -> io::Result<Vec<String>> {
    if entries.len() > MAX_NETWORKS {
        return Err(invalid(format!("{path} holds at most {MAX_NETWORKS} networks")));
    }
    entries
        .iter()
        .map(|entry| match entry.as_str() {
            Some(text) if is_network(text) => Ok(text.to_owned()),
            _ => Err(invalid(format!("{path} must hold networks such as 10.0.0.0/24"))),
        })
        .collect()
}

/// Whether `text` is an address, a slash and a prefix length that fits the address.
fn is_network(text: &str) -> bool {
    let Some((address, bits)) = text.rsplit_once('/') else { return false };
    let Ok(address) = address.parse::<IpAddr>() else { return false };
    let limit = if address.is_ipv4() { 32 } else { 128 };
    !bits.is_empty()
        && bits.bytes().all(|byte| byte.is_ascii_digit())
        && bits.parse::<u8>().is_ok_and(|bits| bits <= limit)
}

/// Reads `console.nodes`: 2 to 64 members with distinct numbers, addresses and origins.
fn members(entries: &[Value<'_>]) -> io::Result<Vec<Member>> {
    if !(2..=MAX_CONSOLE_NODES).contains(&entries.len()) {
        return Err(invalid(format!(
            "console.nodes must hold 2 to {MAX_CONSOLE_NODES} members, this node included"
        )));
    }
    let mut members: Vec<Member> = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let path = format!("console.nodes[{index}]");
        let mut r = field(ObjectReader::with_path(entry, path.clone()))?;
        let number = field(r.take_u64("node"))?.ok_or_else(|| invalid(r.missing("node")))?;
        let node = node_number(number, &format!("{path}.node"))?;
        let listen = field(r.take_str("listen"))?.ok_or_else(|| invalid(r.missing("listen")))?;
        let listen = address(listen, &format!("{path}.listen"))?;
        let origin = field(r.take_str("origin"))?.ok_or_else(|| invalid(r.missing("origin")))?;
        if !origin.starts_with("https://") {
            return Err(invalid(format!("{path}.origin must begin with https://")));
        }
        let allow_ips = networks(&mut r, "allow_ips")?;
        if allow_ips.is_empty() {
            return Err(invalid(format!(
                "{path}.allow_ips must name the networks this member connects from"
            )));
        }
        field(r.finish())?;
        if members.iter().any(|m| m.node == node || m.listen == listen || m.origin == origin) {
            return Err(invalid(format!("{path} repeats a node, an address or an origin")));
        }
        members.push(Member { node, listen, origin: origin.to_owned(), allow_ips });
    }
    Ok(members)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> io::Result<ConsoleOptions> {
        let value = sibuna_json::parse(text.as_bytes()).unwrap();
        ConsoleOptions::parse(ObjectReader::new(&value).unwrap())
    }

    #[test]
    fn a_single_node_names_its_address() {
        let options = parse(r#"{"listen":"127.0.0.1:9443","data_dir":"/var/lib/sibuna"}"#);
        let options = options.unwrap();
        assert_eq!(options.listen, "127.0.0.1:9443".parse().unwrap());
        assert_eq!((options.node, options.peers.len()), (1, 0));
        assert!(parse(r#"{"listen":"127.0.0.1:9443"}"#).is_err(), "no data_dir");
        assert!(parse(r#"{"data_dir":"d"}"#).is_err(), "no listen");
        assert!(parse(r#"{"listen":"127.0.0.1:0","data_dir":"d"}"#).is_err());
        assert!(parse(r#"{"listen":"127.0.0.1:1","data_dir":"d","bogus":1}"#).is_err());
        assert!(parse(r#"{"listen":"127.0.0.1:1","data_dir":"d","node":0}"#).is_err());
    }

    const FLEET: &str = r#""nodes":[
        {"node":1,"listen":"10.0.0.1:9443","origin":"https://a.test","allow_ips":["10.0.0.1/32"]},
        {"node":2,"listen":"10.0.0.2:9443","origin":"https://b.test","allow_ips":["10.0.0.2/32"]},
        {"node":3,"listen":"10.0.0.3:9443","origin":"https://c.test","allow_ips":["fd00::/8"]}]"#;

    #[test]
    fn a_member_finds_itself_by_its_number() {
        let options = parse(&format!(r#"{{"data_dir":"d","node":2,{FLEET}}}"#)).unwrap();
        assert_eq!(options.listen, "10.0.0.2:9443".parse().unwrap());
        assert_eq!(options.origin.as_deref(), Some("https://b.test"));
        let peers: Vec<u32> = options.peers.iter().map(|peer| peer.node).collect();
        assert_eq!(peers, [1, 3]);
        assert_eq!(options.peers[1].allow_ips, ["fd00::/8"]);
        assert!(parse(&format!(r#"{{"data_dir":"d","node":9,{FLEET}}}"#)).is_err());
        assert!(parse(&format!(r#"{{"data_dir":"d",{FLEET}}}"#)).is_err(), "no number");
    }

    #[test]
    fn the_number_can_come_from_a_file() {
        let path = std::env::temp_dir().join(format!("sibuna-node-{}", std::process::id()));
        std::fs::write(&path, "3\n").unwrap();
        let text = format!(r#"{{"data_dir":"d","node_file":"{}",{FLEET}}}"#, path.display());
        assert_eq!(parse(&text).unwrap().node, 3);
        std::fs::write(&path, "three").unwrap();
        assert!(parse(&text).is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(parse(&text).is_err(), "a missing file");
    }

    #[test]
    fn members_are_distinct_and_screened() {
        let member = |node: u32, origin: &str, allow: &str| {
            format!(
                r#"{{"node":{node},"listen":"10.0.0.{node}:9443","origin":"{origin}",
                   "allow_ips":[{allow}]}}"#
            )
        };
        let fleet = |members: &[String]| {
            parse(&format!(r#"{{"data_dir":"d","node":1,"nodes":[{}]}}"#, members.join(",")))
        };
        let good = member(1, "https://a.test", r#""10.0.0.1/32""#);
        assert!(fleet(&[good.clone(), member(2, "https://b.test", r#""10.0.0.2/32""#)]).is_ok());
        assert!(fleet(std::slice::from_ref(&good)).is_err(), "one member is no fleet");
        assert!(fleet(&[good.clone(), member(2, "https://a.test", r#""10.0.0.2/32""#)]).is_err());
        assert!(fleet(&[good.clone(), member(2, "http://b.test", r#""10.0.0.2/32""#)]).is_err());
        assert!(fleet(&[good.clone(), member(2, "https://b.test", "")]).is_err());
        assert!(fleet(&[good.clone(), member(2, "https://b.test", r#""10.0.0.2/33""#)]).is_err());
        assert!(fleet(&[good, member(2, "https://b.test", r#""b.test/8""#)]).is_err());
        assert!(is_network("::/0") && !is_network("10.0.0.0") && !is_network("10.0.0.0/+8"));
    }
}

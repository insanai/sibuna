//! The run-time view of the servers and the run-time changes of SID 0018.
//!
//! The file is the authority for the topology. A change made here is laid over the serving
//! revision and applies to new flows only. [`Edge::reload`] replaces weights, additions and
//! removals with the file and keeps the drains of servers that the file still describes.

use std::fmt;
use std::net::SocketAddr;

use crate::Edge;
use crate::config::{Server, is_listener};
use crate::pool::{Loads, Pool};

/// The most servers in one pool, as in the file.
const MAX_SERVERS: usize = 128;
/// The longest name of a server added at run time.
const MAX_NAME: usize = 64;

/// Whether a server receives new flows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerState {
    /// The server is in rotation, subject to its health and its limits.
    Ready,
    /// An operator took the server out of rotation. Established flows finish.
    Drain,
}

impl ServerState {
    /// The word of the admin protocol for this state.
    pub fn word(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Drain => "drain",
        }
    }
}

/// One server as it is served now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerStatus {
    /// The backend that holds the server.
    pub pool: String,
    /// The name of the server, unique in its pool.
    pub name: String,
    /// The address new flows are sent to.
    pub addr: SocketAddr,
    /// Whether an operator drained the server.
    pub state: ServerState,
    /// The weight in use.
    pub weight: u32,
    /// The flows and exchanges that hold the server now.
    pub flows: usize,
    /// The result of the health probe, or `None` for a pool without one.
    pub healthy: Option<bool>,
    /// The server is used only when no primary is eligible.
    pub backup: bool,
    /// A command added the server. The file does not have it.
    pub added: bool,
    /// A command replaced the weight that the file gave.
    pub reweighted: bool,
}

/// Why a run-time change was refused. Nothing changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeError {
    /// A stable code. The edge produces `ADM003` to `ADM007`, the admin socket the others.
    pub code: &'static str,
    /// A short title in upper case.
    pub title: &'static str,
    /// What is wrong, in one sentence.
    pub message: String,
    /// What the operator can do instead.
    pub hint: String,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} Hint: {}", self.code, self.message, self.hint)
    }
}

impl std::error::Error for RuntimeError {}

impl RuntimeError {
    fn new(code: &'static str, title: &'static str, message: String, hint: String) -> Self {
        Self { code, title, message, hint }
    }

    /// A value outside its domain (`ADM005`).
    pub fn invalid(message: String, hint: &str) -> Self {
        Self::new("ADM005", "INVALID VALUE", message, hint.to_owned())
    }

    fn refused(message: String, hint: &str) -> Self {
        Self::new("ADM007", "CHANGE REFUSED", message, hint.to_owned())
    }

    fn unknown_server(pool: &str, name: &str, known: &Pool) -> Self {
        let mut hint = "Run `show servers` to list them.".to_owned();
        if let Some(near) = nearest(name, known.names()) {
            hint.push_str(&format!(" Did you mean `{pool}/{near}`?"));
        }
        let message = format!("Pool `{pool}` has no server named `{name}`.");
        Self::new("ADM004", "UNKNOWN SERVER", message, hint)
    }
}

/// The candidate closest to `word`, when it is at most two edits away.
fn nearest<'a>(word: &str, candidates: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    let scored = candidates.filter(|c| c.len() <= MAX_NAME && word.len() <= MAX_NAME);
    let best = scored.map(|c| (distance(word.as_bytes(), c.as_bytes()), c)).min()?;
    (best.0 <= 2).then_some(best.1)
}

/// The Levenshtein distance of two short byte strings.
fn distance(a: &[u8], b: &[u8]) -> usize {
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, x) in a.iter().enumerate() {
        let mut diagonal = row[0];
        row[0] = i + 1;
        for (j, y) in b.iter().enumerate() {
            let substitute = diagonal + usize::from(x != y);
            diagonal = row[j + 1];
            row[j + 1] = substitute.min(row[j] + 1).min(diagonal + 1);
        }
    }
    row[b.len()]
}

/// Whether `name` can be written in a command: 1 to 64 letters, digits and `._:[]-`.
fn valid_name(name: &str) -> bool {
    (1..=MAX_NAME).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:[]-".contains(&b))
}

fn fixed(pool: &str, reason: &str) -> RuntimeError {
    RuntimeError::refused(
        format!("Pool `{pool}` {reason}, so its servers and weights change only by reload."),
        "Edit the configuration file and run `reload`. `set server ... state drain` works.",
    )
}

impl Edge {
    /// Visits every pool: the TCP and UDP pools of the worker, then the HTTP pools.
    fn each_pool(&self, mut visit: impl FnMut(&str, &Pool)) {
        for (name, pool) in &self.pools {
            visit(name, pool);
        }
        self.http.with_pools(|pools, _| {
            for (name, pool) in pools.iter() {
                visit(name, pool);
            }
        });
    }

    /// Runs `change` on the pool named `name`. Fails with `ADM003` for an unknown pool.
    fn in_pool<R>(
        &mut self,
        name: &str,
        change: impl FnOnce(&mut Pool, &mut Loads) -> R,
    ) -> Result<R, RuntimeError> {
        if let Some(pool) = self.pools.get_mut(name) {
            return Ok(change(pool, &mut self.loads));
        }
        let done = self
            .http
            .with_pools(|pools, loads| pools.get_mut(name).map(|pool| change(pool, loads)));
        done.ok_or_else(|| {
            let mut names = Vec::new();
            self.each_pool(|pool, _| names.push(pool.to_owned()));
            let mut hint = "Run `show servers` to list the pools.".to_owned();
            if let Some(near) = nearest(name, names.iter().map(String::as_str)) {
                hint.push_str(&format!(" Did you mean `{near}`?"));
            }
            let message = format!("No backend is named `{name}`.");
            RuntimeError::new("ADM003", "UNKNOWN POOL", message, hint)
        })
    }

    /// Lists every server as it is served now, pool by pool.
    pub fn servers(&self) -> Vec<ServerStatus> {
        let mut servers = Vec::new();
        self.each_pool(|name, pool| pool.statuses(name, &mut servers));
        servers
    }

    /// Lists, as `pool/name`, the servers of the file that a command removed.
    pub fn removed_servers(&self) -> Vec<String> {
        let mut removed = Vec::new();
        self.each_pool(|pool, state| {
            removed.extend(state.removed.iter().map(|name| format!("{pool}/{name}")));
        });
        removed
    }

    /// Counts the servers that differ from the file: changed, added or removed.
    pub fn change_count(&self) -> usize {
        let mut count = 0;
        self.each_pool(|_, pool| count += pool.change_count());
        count
    }

    /// The drained servers as pool, name and address.
    pub(crate) fn drained_servers(&self) -> Vec<(String, String, SocketAddr)> {
        let mut drained = Vec::new();
        self.each_pool(|pool, state| {
            let servers = state.drained();
            drained.extend(servers.map(|(name, addr)| (pool.to_owned(), name.to_owned(), addr)));
        });
        drained
    }

    /// Drains again, after a reload, each server that the file still describes.
    pub(crate) fn keep_drained(&mut self, drained: Vec<(String, String, SocketAddr)>) {
        for (pool, name, addr) in drained {
            // A pool or a server that left the file has nothing to drain.
            let _ = self.in_pool(&pool, |pool, _| pool.keep_drained(&name, addr));
        }
    }

    /// Drains a server or returns it to rotation, for new flows. Every pool allows it.
    /// Fails with `ADM003` or `ADM004` when the pool or the server is unknown.
    pub fn set_server_state(
        &mut self,
        pool: &str,
        name: &str,
        state: ServerState,
    ) -> Result<(), RuntimeError> {
        self.in_pool(pool, |servers, _| {
            if servers.set_drained(name, state == ServerState::Drain) {
                Ok(())
            } else {
                Err(RuntimeError::unknown_server(pool, name, servers))
            }
        })?
    }

    /// Sets the weight of a server, 1 to 65,535, for new flows. Fails with `ADM005` for a
    /// weight outside that range and with `ADM007` for a pool that changes only by reload.
    pub fn set_server_weight(
        &mut self,
        pool: &str,
        name: &str,
        weight: u32,
    ) -> Result<(), RuntimeError> {
        check_weight(weight)?;
        self.in_pool(pool, |servers, _| {
            if let Some(reason) = servers.fixed() {
                return Err(fixed(pool, reason));
            }
            if servers.set_weight(name, weight) {
                Ok(())
            } else {
                Err(RuntimeError::unknown_server(pool, name, servers))
            }
        })?
    }

    /// Adds a server to a pool. It takes the pool's health probe and starts in service.
    /// Fails with `ADM005` for a bad name, address or weight, `ADM006` for a name or an
    /// address the pool already has, and `ADM007` for a full pool or one that changes
    /// only by reload.
    pub fn add_server(
        &mut self,
        pool: &str,
        name: &str,
        addr: SocketAddr,
        weight: u32,
    ) -> Result<(), RuntimeError> {
        check_weight(weight)?;
        if !valid_name(name) {
            return Err(RuntimeError::invalid(
                format!("`{name}` cannot name a server."),
                "Use 1 to 64 letters, digits and the characters `. _ : [ ] -`.",
            ));
        }
        if !Server::routable(addr) {
            return Err(RuntimeError::invalid(
                format!("`{addr}` is not the address of one host."),
                "Give a unicast IP address and a port, such as 10.0.0.3:80.",
            ));
        }
        let (protocol, probe) = self.in_pool(pool, |servers, _| {
            admits(pool, servers, name, addr)
                .map(|()| (servers.protocol(), servers.health.clone()))
        })??;
        if self.binds.iter().any(|&bind| is_listener(bind, protocol, addr)) {
            return Err(RuntimeError::invalid(
                format!("`{addr}` is a listener of this node."),
                "A pool cannot send flows back to its own frontend.",
            ));
        }
        let mut server = Server::new(name.to_owned(), addr, weight);
        if let Some(spec) = probe {
            let status = self.checks.watch(addr, &spec).map_err(|error| {
                RuntimeError::refused(
                    format!("The health probe of `{addr}` could not start: {error}."),
                    "Try again, or add the server to the file and reload.",
                )
            })?;
            server.healthy = Some(status);
        }
        self.in_pool(pool, |servers, loads| servers.add(server, loads))
    }

    /// Removes a server from a pool. Its established flows finish. Fails with `ADM004`
    /// for an unknown server and `ADM007` for the last server of a pool or a pool that
    /// changes only by reload.
    pub fn remove_server(&mut self, pool: &str, name: &str) -> Result<(), RuntimeError> {
        self.in_pool(pool, |servers, _| {
            if let Some(reason) = servers.fixed() {
                return Err(fixed(pool, reason));
            }
            if !servers.names().any(|known| known == name) {
                return Err(RuntimeError::unknown_server(pool, name, servers));
            }
            if servers.server_count() == 1 {
                return Err(RuntimeError::refused(
                    format!("`{name}` is the last server of pool `{pool}`."),
                    "Drain it with `set server ... state drain`, or add another server first.",
                ));
            }
            servers.remove(name);
            Ok(())
        })??;
        self.stop_unused_probes();
        Ok(())
    }

    /// Stops the health probes that no server uses any more.
    fn stop_unused_probes(&mut self) {
        let mut used = Vec::new();
        self.each_pool(|_, pool| {
            if let Some(spec) = &pool.health {
                used.extend(pool.probed().map(|addr| (addr, spec.clone())));
            }
        });
        self.checks.retain(|addr, spec| used.iter().any(|(a, s)| *a == addr && s == spec));
    }
}

fn check_weight(weight: u32) -> Result<(), RuntimeError> {
    if (1..=Server::MAX_WEIGHT).contains(&weight) {
        return Ok(());
    }
    Err(RuntimeError::invalid(
        format!("A weight of {weight} is outside 1 to {}.", Server::MAX_WEIGHT),
        "To stop new flows to a server, use `set server ... state drain`.",
    ))
}

/// Whether `pool` can take a new server with this name and address.
fn admits(pool: &str, servers: &Pool, name: &str, addr: SocketAddr) -> Result<(), RuntimeError> {
    if let Some(reason) = servers.fixed() {
        return Err(fixed(pool, reason));
    }
    if servers.holds(name, addr) {
        return Err(RuntimeError::new(
            "ADM006",
            "DUPLICATE SERVER",
            format!(
                "Pool `{pool}` already has a server with the name `{name}` or the address {addr}."
            ),
            "Choose another name, or change the existing server with `set server`.".to_owned(),
        ));
    }
    if servers.server_count() >= MAX_SERVERS {
        return Err(RuntimeError::refused(
            format!("Pool `{pool}` is full: it has {MAX_SERVERS} servers."),
            "Remove a server first with `del server`.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_offers_only_close_names() {
        let names = ["web1", "web2", "database"];
        assert_eq!(nearest("web3", names.into_iter()), Some("web1"));
        assert_eq!(nearest("wbe1", names.into_iter()), Some("web1"));
        assert_eq!(nearest("cache", names.into_iter()), None);
        assert_eq!(distance(b"kitten", b"sitting"), 3);
        assert_eq!(distance(b"", b"abc"), 3);
    }

    #[test]
    fn names_are_bounded_and_plain() {
        assert!(valid_name("10.0.0.3:80"));
        assert!(valid_name("[2001:db8::1]:80"));
        assert!(valid_name("blue_2"));
        assert!(!valid_name(""));
        assert!(!valid_name("a/b"));
        assert!(!valid_name("a b"));
        assert!(!valid_name(&"x".repeat(65)));
    }
}

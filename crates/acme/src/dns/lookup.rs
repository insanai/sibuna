//! Is the TXT record visible? We ask the authoritative servers of the zone, as the
//! authority does, and not a resolver with a cache.
//!
//! ```text
//! owner --CNAME, at most 8--> final owner            (through the resolver)
//! final owner, parent, ... --SOA--> zone             (through the resolver)
//! zone --NS--> server names --A, AAAA--> addresses   (through the resolver)
//! each address --TXT final owner, no recursion--> value shown?
//! ```

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use super::wire::{self, Data, Message, TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_NS, TYPE_SOA};
use super::{random_id, transport, wire::TYPE_TXT};
use crate::Error;

/// The most CNAME records followed from the owner of the challenge.
pub const MAX_ALIASES: usize = 8;
/// The most name servers of a zone that we ask.
pub const MAX_SERVERS: usize = 8;
/// The most addresses of one name server that we ask.
pub const MAX_ADDRESSES: usize = 4;
/// How long one question waits for its answer.
const QUESTION_TIMEOUT: Duration = Duration::from_secs(3);
/// The pause between two rounds of the check.
pub const ROUND_PAUSE: Duration = Duration::from_secs(2);

/// Where to ask.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lookup {
    /// The recursive resolver that finds the zone and its servers.
    pub resolver: Option<SocketAddr>,
    /// The authoritative servers to ask. Empty: the servers of the NS records.
    pub servers: Vec<SocketAddr>,
    /// The port of the servers found from the NS records: 53.
    pub port: u16,
}

impl Default for Lookup {
    /// No resolver, the servers of the NS records, port 53.
    fn default() -> Self {
        Self { resolver: None, servers: Vec::new(), port: 53 }
    }
}

/// The first `nameserver` of the text of `/etc/resolv.conf`, with port 53.
pub fn system_resolver(resolv_conf: &str) -> Option<SocketAddr> {
    resolv_conf.lines().take(256).find_map(|line| {
        let mut words = line.split_whitespace();
        (words.next() == Some("nameserver")).then_some(())?;
        // A link-local address may carry a zone, which we cannot use.
        let address: IpAddr = words.next()?.split('%').next()?.parse().ok()?;
        Some(SocketAddr::new(address, 53))
    })
}

fn not_visible(message: String) -> Error {
    Error::not_visible(message)
}

/// Sends one question and returns the answer to it, when one comes before `deadline`
/// and it has our identifier and our question.
fn ask(
    server: SocketAddr,
    name: &str,
    kind: u16,
    recurse: bool,
    deadline: Instant,
) -> Option<Message> {
    let left = deadline.saturating_duration_since(Instant::now()).min(QUESTION_TIMEOUT);
    if left.is_zero() {
        return None;
    }
    let id = random_id().ok()?;
    let request = wire::query(id, name, kind, recurse).ok()?;
    let answer = wire::parse(&transport::exchange(server, &request, left).ok()?)?;
    let asked = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    let ours = answer.id == id && answer.question == Some((asked, kind));
    ours.then_some(answer)
}

impl Lookup {
    /// The servers that answer questions about names: the resolver, or else the given
    /// authoritative servers.
    fn guides(&self) -> Vec<SocketAddr> {
        self.resolver.map_or_else(|| self.servers.clone(), |resolver| vec![resolver])
    }

    /// Asks the guides in turn, with recursion, until one answers.
    fn resolve(&self, name: &str, kind: u16, deadline: Instant) -> Option<Message> {
        self.guides().into_iter().find_map(|server| ask(server, name, kind, true, deadline))
    }

    /// Follows the CNAME records from `owner`, [`MAX_ALIASES`] at most, and returns the
    /// last name: where the TXT record must be. Without an alias this is `owner`.
    pub fn final_owner(&self, owner: &str, deadline: Instant) -> String {
        let mut current = owner.strip_suffix('.').unwrap_or(owner).to_ascii_lowercase();
        for _ in 0..MAX_ALIASES {
            let Some(answer) = self.resolve(&current, TYPE_CNAME, deadline) else { break };
            let target = answer.answers().iter().find_map(|record| match &record.data {
                Data::Name(target) if record.kind == TYPE_CNAME && record.name == current => {
                    Some(target.clone())
                }
                _ => None,
            });
            match target {
                Some(target) if target != current => current = target,
                _ => break,
            }
        }
        current
    }

    /// The zone that holds `name`: the first of the name and its parents that has an
    /// SOA record. Fails with `ACME010` when no resolver is known or none has one.
    pub fn zone_of(&self, name: &str, deadline: Instant) -> Result<String, Error> {
        if self.guides().is_empty() {
            return Err(not_visible(
                "No resolver is known: `/etc/resolv.conf` names no `nameserver`. Set \
                 `global.acme.dns.resolver`."
                    .to_owned(),
            ));
        }
        let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
        let mut candidate = name.as_str();
        loop {
            let found = self.resolve(candidate, TYPE_SOA, deadline).is_some_and(|answer| {
                let is_soa = |record: &wire::Record| record.kind == TYPE_SOA;
                answer.answers().iter().any(|record| is_soa(record) && record.name == candidate)
            });
            if found {
                return Ok(candidate.to_owned());
            }
            match candidate.split_once('.') {
                Some((_, parent)) => candidate = parent,
                None => {
                    return Err(not_visible(format!(
                        "The resolver names no zone for `{name}`: no SOA record at the name \
                         or at a parent."
                    )));
                }
            }
        }
    }

    /// The addresses of the authoritative servers of `zone`, each with the name to show
    /// in a diagnostic. With `servers` set, those. Fails with `ACME010` for none.
    pub fn servers_of(
        &self,
        zone: &str,
        deadline: Instant,
    ) -> Result<Vec<(String, SocketAddr)>, Error> {
        if !self.servers.is_empty() {
            return Ok(self.servers.iter().map(|server| (server.to_string(), *server)).collect());
        }
        let names: Vec<String> = self
            .resolve(zone, TYPE_NS, deadline)
            .map(|answer| {
                let targets = answer.answers().iter().filter_map(|record| match &record.data {
                    Data::Name(target) if record.kind == TYPE_NS => Some(target.clone()),
                    _ => None,
                });
                targets.take(MAX_SERVERS).collect()
            })
            .unwrap_or_default();
        let mut found = Vec::new();
        for name in &names {
            let mut addresses = Vec::new();
            for kind in [TYPE_A, TYPE_AAAA] {
                let Some(answer) = self.resolve(name, kind, deadline) else { continue };
                addresses.extend(answer.answers().iter().filter_map(|record| match record.data {
                    Data::A(address) => Some(IpAddr::V4(address)),
                    Data::Aaaa(address) => Some(IpAddr::V6(address)),
                    _ => None,
                }));
            }
            addresses.truncate(MAX_ADDRESSES);
            found.extend(
                addresses.into_iter().map(|a| (name.clone(), SocketAddr::new(a, self.port))),
            );
        }
        if found.is_empty() {
            return Err(not_visible(format!(
                "The resolver names no name server with an address for the zone `{zone}`."
            )));
        }
        Ok(found)
    }
}

/// The servers among `servers` that answered and did not show the TXT `value` at
/// `owner`, and whether any server answered at all. A server may answer through a
/// CNAME of its own: any TXT record of the answer counts.
fn round(
    servers: &[(String, SocketAddr)],
    owner: &str,
    value: &str,
    deadline: Instant,
) -> (Vec<String>, bool) {
    let mut missing = Vec::new();
    let mut answered = false;
    for (name, address) in servers {
        let Some(answer) = ask(*address, owner, TYPE_TXT, false, deadline) else { continue };
        answered = true;
        let shown = answer.answers().iter().any(|record| {
            matches!(&record.data, Data::Txt(text) if text.as_slice() == value.as_bytes())
        });
        if !shown {
            missing.push(format!("{name} ({address})"));
        }
    }
    (missing, answered)
}

/// Waits until every authoritative server that answers shows the TXT `value` at
/// `owner`, for `timeout` at most. `pause` sleeps between two rounds and returns false
/// when the daemon stops. Fails with `ACME010`, naming the servers without the record.
pub fn wait_visible(
    lookup: &Lookup,
    owner: &str,
    value: &str,
    timeout: Duration,
    pause: &mut dyn FnMut(Duration) -> bool,
) -> Result<(), Error> {
    let deadline = Instant::now() + timeout;
    let owner = lookup.final_owner(owner, deadline);
    let servers = if lookup.servers.is_empty() {
        let zone = lookup.zone_of(&owner, deadline)?;
        lookup.servers_of(&zone, deadline)?
    } else {
        lookup.servers_of("", deadline)?
    };
    loop {
        let (missing, answered) = round(&servers, &owner, value, deadline);
        if answered && missing.is_empty() {
            return Ok(());
        }
        if Instant::now() + ROUND_PAUSE >= deadline || !pause(ROUND_PAUSE) {
            let seconds = timeout.as_secs();
            return Err(not_visible(if answered {
                format!(
                    "After {seconds} seconds the TXT record `{owner}` is not at: {}.",
                    missing.join(", ")
                )
            } else {
                format!(
                    "In {seconds} seconds no name server of `{owner}` answered. We asked \
                     {} of them.",
                    servers.len()
                )
            }));
        }
    }
}

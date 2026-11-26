//! The decision of a TLS passthrough inspection (SID 0032).
//!
//! A TCP frontend with `tcp_inspect` reads the start of a connection within two bounds,
//! bytes and time. When the inspection ends, the connection is in one class of
//! [`Metadata`], and the [`Plan`] of the frontend maps every class to one outcome:
//! refuse, or forward to one pool. The bytes read so far are replayed to that pool.
//!
//! ```text
//!   bytes ---> [hello::Inspection] --Whole/Over/Invalid--+
//!   deadline --------------------------------------------+--> Metadata --> Plan::decide
//!                                                                 |              |
//!                                                     visible: rules      refuse | pool
//! ```

use std::collections::BTreeMap;
use std::io::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sibuna_json::ObjectReader;

use crate::config::{Backend, Protocol, duration, field, invalid, number, required};
use crate::hello::{Hello, LIMIT, Step};
use crate::rules::Rule;
use crate::tcp::transient;
use crate::{Edge, Inspecting, Refusal, flowlog, proxy, rules};

/// The smallest `inspect_bytes`. A ClientHello with one server name needs less.
const MIN_BYTES: usize = 1024;

/// What an inspection saw when it ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Metadata {
    /// A well-formed ClientHello with a server name and no ECH extension.
    Visible,
    /// A well-formed ClientHello without a server name.
    Absent,
    /// A well-formed ClientHello with the ECH extension, real or greased.
    Encrypted,
    /// A bound, bytes or time, was reached before a whole ClientHello.
    Incomplete,
    /// The bytes are not a ClientHello, or the ClientHello is malformed.
    Invalid,
}

/// What a frontend does with one class of metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Evaluate the rules of the frontend on what is visible.
    Rules,
    /// Close the connection.
    Deny,
    /// Forward to this pool without consulting the rules.
    Backend(Arc<str>),
}

/// The actions of the four classes that are not [`Metadata::Visible`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Fallback {
    pub absent: Action,
    pub encrypted: Action,
    pub incomplete: Action,
    pub invalid: Action,
}

impl Default for Fallback {
    /// The behaviour before SID 0032: the rules see what is visible, and a connection
    /// without a whole, well-formed ClientHello closes.
    fn default() -> Self {
        Self {
            absent: Action::Rules,
            encrypted: Action::Rules,
            incomplete: Action::Deny,
            invalid: Action::Deny,
        }
    }
}

/// How a frontend inspects: its two bounds, its rules and its fallback.
pub(crate) struct Plan {
    /// The longest wait for a ClientHello (`inspect_delay`).
    pub delay: Duration,
    /// The most bytes held (`inspect_bytes`).
    pub limit: usize,
    pub rules: Arc<[Rule]>,
    pub fallback: Fallback,
}

/// Why an inspection ended, before the ClientHello is parsed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum End {
    /// A whole handshake message is assembled.
    Whole,
    /// The byte bound was reached.
    Bytes,
    /// The time bound was reached.
    Time,
    /// The bytes are not a ClientHello.
    Invalid,
}

/// The class of a parsed ClientHello.
pub(crate) fn classify(hello: &Hello<'_>) -> Metadata {
    if hello.ech {
        Metadata::Encrypted
    } else if hello.sni.is_none() {
        Metadata::Absent
    } else {
        Metadata::Visible
    }
}

impl Plan {
    /// Reads `tcp_inspect` and the options that belong to it from a frontend. Returns
    /// `None` for a frontend that does not inspect. `default` is its `default_backend`.
    /// Fails on an unknown mode, a bound out of range, an unknown pool, or the action
    /// `rules` for a class that has no ClientHello.
    pub fn parse(
        r: &mut ObjectReader<'_, '_>,
        proto: Protocol,
        pools: &BTreeMap<String, Backend>,
        default: &str,
    ) -> Result<Option<Arc<Self>>> {
        match field(r.take_str("tcp_inspect"))? {
            None => return Ok(None),
            Some("tls_client_hello") if proto == Protocol::Tcp => {}
            Some(_) => return Err(invalid(format!("{}: invalid TCP inspection mode", r.path()))),
        }
        let delay = field(r.take_str("inspect_delay"))?.unwrap_or("2s");
        let delay = duration(delay).ok_or_else(|| invalid(r.field_path("inspect_delay")))?;
        let limit = number(r, "inspect_bytes", LIMIT, LIMIT)?;
        if limit < MIN_BYTES {
            let path = r.field_path("inspect_bytes");
            return Err(invalid(format!("{path} must be in {MIN_BYTES}..={LIMIT}")));
        }
        let fallback = match field(r.take_object("inspect_fallback"))? {
            Some(reader) => Fallback::parse(reader, pools, default)?,
            None => Fallback::default(),
        };
        let rules = Arc::from(rules::parse(r, pools)?);
        Ok(Some(Arc::new(Self { delay, limit, rules, fallback })))
    }

    /// The pool of a connection in class `metadata`, or `None` to refuse it. `hello` is
    /// the parsed ClientHello when there is one, and `default` the `default_backend`.
    /// Every class has an answer.
    pub fn decide<'a>(
        &'a self,
        metadata: Metadata,
        hello: Option<&Hello<'_>>,
        default: &'a Arc<str>,
    ) -> Option<&'a Arc<str>> {
        let action = match metadata {
            Metadata::Visible => &Action::Rules,
            Metadata::Absent => &self.fallback.absent,
            Metadata::Encrypted => &self.fallback.encrypted,
            Metadata::Incomplete => &self.fallback.incomplete,
            Metadata::Invalid => &self.fallback.invalid,
        };
        match (action, hello) {
            (Action::Rules, Some(hello)) => rules::select(&self.rules, hello, default),
            // The file refuses `rules` for a class without a ClientHello. Should one
            // arrive here all the same, there is nothing to evaluate.
            (Action::Rules | Action::Deny, _) => None,
            (Action::Backend(pool), _) => Some(pool),
        }
    }
}

impl Fallback {
    fn parse(
        mut r: ObjectReader<'_, '_>,
        pools: &BTreeMap<String, Backend>,
        default: &str,
    ) -> Result<Self> {
        let mut fallback = Self::default();
        let classes = [
            ("absent", &mut fallback.absent, true),
            ("encrypted", &mut fallback.encrypted, true),
            ("incomplete", &mut fallback.incomplete, false),
            ("invalid", &mut fallback.invalid, false),
        ];
        for (class, slot, has_hello) in classes {
            if let Some(reader) = field(r.take_object(class))? {
                *slot = action(reader, pools, default, has_hello)?;
            }
        }
        field(r.finish())?;
        Ok(fallback)
    }
}

/// Reads one `{ action, backend }` object of `inspect_fallback`.
fn action(
    mut r: ObjectReader<'_, '_>,
    pools: &BTreeMap<String, Backend>,
    default: &str,
    has_hello: bool,
) -> Result<Action> {
    let path = r.path().to_owned();
    let action = match required(&mut r, "action")?.as_str() {
        "deny" => Action::Deny,
        "rules" if has_hello => Action::Rules,
        "rules" => {
            return Err(invalid(format!(
                "{path}: rules need a ClientHello, use deny or use_backend"
            )));
        }
        "use_backend" => {
            let pool = field(r.take_str("backend"))?.unwrap_or(default);
            if !pools.get(pool).is_some_and(|b| b.protocol == Protocol::Tcp) {
                return Err(invalid(format!("{path}: unknown TCP backend {pool}")));
            }
            Action::Backend(pool.into())
        }
        _ => return Err(invalid(format!("{path}: expected deny, rules or use_backend"))),
    };
    field(r.finish())?;
    Ok(action)
}

impl Edge {
    /// Reads what a client under inspection sent. Returns false when the connection
    /// was dropped.
    pub(crate) fn inspect(&mut self, id: u64) -> bool {
        let Some(flow) = self.inspecting.get_mut(&id) else { return true };
        let limit = flow.plan.limit;
        let end = match flow.input.read(&mut flow.opening.client, &mut self.buffer, limit) {
            Ok(Step::More) => return true,
            Err(error) if transient(&error) => return true,
            Err(_) => {
                // The client closed or reset. There is nothing to forward.
                if let Some(mut flow) = self.finish_inspection(id) {
                    flowlog::mark(&mut flow.opening.line, "reset");
                }
                return false;
            }
            Ok(Step::Whole) => End::Whole,
            Ok(Step::Over) => End::Bytes,
            Ok(Step::Invalid) => End::Invalid,
        };
        self.conclude(id, end)
    }

    /// Ends the inspections whose time bound passed. Each takes its fallback.
    pub(crate) fn expire_inspections(&mut self, now: Instant) {
        // Collecting allocates only when an inspection expired.
        let due = self.inspecting.iter().filter(|(_, flow)| now >= flow.deadline);
        let due: Vec<u64> = due.map(|(id, _)| *id).collect();
        for id in due {
            if !self.conclude(id, End::Time) {
                self.drops = self.drops.saturating_add(1);
            }
        }
    }

    /// Decides an ended inspection: refuses the connection, or starts the connect to
    /// its pool with the bytes read so far as the prefix. Returns false on a refusal.
    fn conclude(&mut self, id: u64, end: End) -> bool {
        let Some(mut flow) = self.finish_inspection(id) else { return false };
        // The connection hooks judge every ended inspection (SID 0030). One that takes
        // a fallback has no ClientHello: its view has no server name and no JA4.
        let hello = if end == End::Whole { flow.input.hello() } else { None };
        match self.rule_hello(&flow.opening, hello.as_ref()) {
            crate::gate::Ruling::Admit => self.settle_inspection(id, flow, end),
            crate::gate::Ruling::Deny => {
                self.stats.refuse(Refusal::Hook);
                flowlog::mark(&mut flow.opening.line, Refusal::Hook.end());
                false
            }
            crate::gate::Ruling::Parked(ticket) => {
                let parked = crate::gate::Parked::Hello { id, flow: Box::new(flow), end };
                self.park(ticket, parked);
                true
            }
        }
    }

    /// Decides an inspection that the connection hooks admitted.
    pub(crate) fn settle_inspection(&mut self, id: u64, mut flow: Inspecting, end: End) -> bool {
        let wire = std::mem::take(&mut flow.input.wire);
        if let Some(line) = &mut flow.opening.line {
            // These bytes are replayed to the server from here, not relayed.
            line.bytes_in = wire.len() as u64;
        }
        let hello = if end == End::Whole { flow.input.hello() } else { None };
        let metadata = match (end, &hello) {
            (End::Whole, Some(hello)) => classify(hello),
            (End::Whole | End::Invalid, _) => Metadata::Invalid,
            (End::Bytes | End::Time, _) => Metadata::Incomplete,
        };
        let Some(pool) = flow.plan.decide(metadata, hello.as_ref(), &flow.opening.pool) else {
            self.stats.refuse(Refusal::InspectDenied);
            // A silent client that is refused keeps the end it had before SID 0032.
            let mark = if end == End::Time { "idle_timeout" } else { "inspect_denied" };
            flowlog::mark(&mut flow.opening.line, mark);
            return false;
        };
        let pool = pool.clone();
        if let Some(line) = &mut flow.opening.line {
            line.backend = pool.clone();
        }
        flow.opening.pool = pool;
        let Some(pool) = self.pools.get(flow.opening.pool.as_ref()) else { return false };
        let (peer, vip) = (flow.opening.peer, flow.opening.vip);
        flow.opening.prefix = proxy::prefix(pool.proxy_v2, peer, vip, hello.as_ref(), wire);
        self.connect(id, flow.opening)
    }

    /// Takes an inspection out of the worker's poller. The relay thread registers the
    /// client socket in its own poller once the origin is connected.
    pub(crate) fn finish_inspection(&mut self, id: u64) -> Option<Inspecting> {
        let flow = self.inspecting.remove(&id)?;
        self.poll.remove(sibuna_reactor::handle(&flow.opening.client));
        Some(flow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(fallback: Fallback) -> Plan {
        Plan { delay: Duration::from_secs(2), limit: LIMIT, rules: Arc::from([]), fallback }
    }

    #[test]
    fn every_class_has_exactly_one_outcome_under_every_fallback() {
        let default: Arc<str> = "default".into();
        let other: Arc<str> = "other".into();
        let actions = [Action::Rules, Action::Deny, Action::Backend(other.clone())];
        let classes = [
            Metadata::Visible,
            Metadata::Absent,
            Metadata::Encrypted,
            Metadata::Incomplete,
            Metadata::Invalid,
        ];
        let hello = crate::hello::tests::parsed(&crate::hello::tests::hello(Some(b"a.test"), &[]));
        for absent in &actions {
            for encrypted in &actions {
                for rest in &actions[1..] {
                    let plan = plan(Fallback {
                        absent: absent.clone(),
                        encrypted: encrypted.clone(),
                        incomplete: rest.clone(),
                        invalid: rest.clone(),
                    });
                    for class in classes {
                        let seen = !matches!(class, Metadata::Incomplete | Metadata::Invalid);
                        let hello = seen.then(|| hello.hello().unwrap());
                        let pool = plan.decide(class, hello.as_ref(), &default);
                        let configured = match class {
                            Metadata::Visible => &Action::Rules,
                            Metadata::Absent => absent,
                            Metadata::Encrypted => encrypted,
                            _ => rest,
                        };
                        let expected = match configured {
                            Action::Rules => Some(&default),
                            Action::Deny => None,
                            Action::Backend(pool) => Some(pool),
                        };
                        assert_eq!(pool, expected, "{class:?} under {configured:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn rules_without_a_client_hello_refuse() {
        let default: Arc<str> = "default".into();
        let plan = plan(Fallback { incomplete: Action::Rules, ..Fallback::default() });
        assert_eq!(plan.decide(Metadata::Incomplete, None, &default), None);
    }

    #[test]
    fn a_hello_is_classified_by_its_server_name_and_ech_extension() {
        use crate::hello::tests::{hello, parsed};
        let ech = [0xfe, 0x0d, 0, 1, 0];
        let cases = [
            (hello(Some(b"a.test"), &[]), Metadata::Visible),
            (hello(None, &[]), Metadata::Absent),
            (hello(Some(b"public.test"), &ech), Metadata::Encrypted),
            (hello(None, &ech), Metadata::Encrypted),
        ];
        for (bytes, class) in cases {
            assert_eq!(classify(&parsed(&bytes).hello().unwrap()), class);
        }
    }
}

//! Subscription commands and the bounds of the real-time transport (SID 0007, "The
//! Real-Time Protocol"): one WebSocket per tab, six topics, snapshot then deltas.

use std::fmt::{self, Write};

use sibuna_json::{Limits, Value, Writer};

use crate::access::Principal;
use crate::codec::{
    DecodeError, Encode, Fields, Path, WireEnum, counter, field, zig_byte_string_value,
};
use crate::error::MAX_I64;
use crate::events::country;
use crate::security::Module;
use crate::text::Text;

/// A subscription topic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Topic {
    /// Live statistics, delivered as the dashboard view.
    #[default]
    Stats,
    /// Recorded incidents.
    Events,
    /// Cluster members, probes and peers.
    Nodes,
    /// Policy revisions and their application.
    Policy,
    /// The challenge funnel.
    Challenges,
    /// Audit rows.
    Audit,
}

impl Topic {
    /// Returns the topic's slot index, 0 to [`TOPIC_COUNT`] - 1.
    pub fn index(self) -> usize {
        self.ordinal()
    }
}

impl WireEnum for Topic {
    const ALL: &'static [Topic] = &[
        Topic::Stats,
        Topic::Events,
        Topic::Nodes,
        Topic::Policy,
        Topic::Challenges,
        Topic::Audit,
    ];

    fn name(self) -> &'static str {
        match self {
            Topic::Stats => "stats",
            Topic::Events => "events",
            Topic::Nodes => "nodes",
            Topic::Policy => "policy",
            Topic::Challenges => "challenges",
            Topic::Audit => "audit",
        }
    }
}

/// The number of topics.
pub const TOPIC_COUNT: usize = 6;
/// Entries in each topic's ring.
pub const RING_CAPACITY: usize = 1024;
/// The largest ring entry, in bytes.
pub const RECORD_BYTES: usize = 2048;
/// Frames a subscriber's send queue holds.
pub const QUEUE_CAPACITY: usize = 64;
/// Frames delivered to one subscriber per second.
pub const MESSAGES_PER_SECOND: usize = 64;
/// The largest reassembled view, in bytes.
pub const SNAPSHOT_BYTES: usize = 65_536;
/// The largest fragment of a chunked view, in bytes.
pub const FRAGMENT_BYTES: usize = 512;
/// The largest client message, in bytes.
pub const MAX_MESSAGE: usize = crate::MAX_MESSAGE;

/// A position in a subscription: its epoch and sequence.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Cursor {
    /// The subscription epoch.
    pub epoch: u64,
    /// The sequence within the epoch.
    pub sequence: u64,
}

/// A subscription change between a consumer and the hub.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Subscription {
    /// Starts a topic, optionally resuming after a position.
    Subscribe {
        /// The topic.
        topic: Topic,
        /// Resume after this position.
        after: Option<Cursor>,
    },
    /// Stops a topic.
    Unsubscribe(Topic),
    /// Acknowledges delivery up to a position.
    Acknowledge {
        /// The topic.
        topic: Topic,
        /// The acknowledged position.
        cursor: Cursor,
    },
}

/// What a client command does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Op {
    /// Subscribe; a snapshot precedes deltas.
    #[default]
    Sub,
    /// Stop a subscription.
    Unsub,
    /// Replace the filter and start a new epoch.
    Filter,
    /// Application heartbeat.
    Ping,
}

impl WireEnum for Op {
    const ALL: &'static [Op] = &[Op::Sub, Op::Unsub, Op::Filter, Op::Ping];

    fn name(self) -> &'static str {
        match self {
            Op::Sub => "sub",
            Op::Unsub => "unsub",
            Op::Filter => "filter",
            Op::Ping => "ping",
        }
    }
}

/// A subscription's filter. Event filters apply to `events`, actor and action filters to
/// `audit`, and a node filter to `events`, `nodes` and `stats`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Args {
    /// One node.
    pub node: Option<u32>,
    /// One finding source.
    pub module: Option<Module>,
    /// One category.
    pub category: Text<32>,
    /// A country filter ([`country::valid_filter`]).
    pub country: country::Filter,
    /// One address.
    pub ip: Text<48>,
    /// A path prefix.
    pub path_prefix: Text<128>,
    /// One actor.
    pub actor: Option<u64>,
    /// One action.
    pub action: Text<48>,
}

/// Writes only the filters that are set; numbers above 2^53 as decimal strings.
impl Encode for Args {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        if let Some(node) = self.node {
            json.key("node")?;
            counter(json, u64::from(node))?;
        }
        if let Some(module) = self.module {
            field(json, "module", &module)?;
        }
        let texts = [
            ("category", self.category.as_str()),
            ("country", self.country.as_str()),
            ("ip", self.ip.as_str()),
            ("path_prefix", self.path_prefix.as_str()),
        ];
        for (name, text) in texts.into_iter().filter(|(_, text)| !text.is_empty()) {
            field(json, name, text)?;
        }
        if let Some(actor) = self.actor {
            json.key("actor")?;
            counter(json, actor)?;
        }
        if !self.action.is_empty() {
            field(json, "action", &self.action)?;
        }
        json.end_object()
    }
}

/// A client command.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Command {
    /// What it does.
    pub op: Op,
    /// The topic; absent for `ping`.
    pub topic: Option<Topic>,
    /// The filter.
    pub args: Args,
}

impl Encode for Command {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "op", &self.op)?;
        field(json, "topic", &self.topic)?;
        field(json, "args", &self.args)?;
        json.end_object()
    }
}

/// A command that is malformed, oversized or not allowed in its combination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InvalidCommand;

impl fmt::Display for InvalidCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the subscription command is malformed or not allowed")
    }
}

impl std::error::Error for InvalidCommand {}

/// The command as Zig's typed parse read it, before the bounds are applied.
struct WireCommand {
    op: Op,
    topic: Option<Topic>,
    node: Option<u32>,
    module: Option<Module>,
    texts: [String; 5],
    actor: Option<u64>,
}

fn decode_wire(value: &Value<'_>) -> Result<WireCommand, DecodeError> {
    let mut fields = Fields::new(value, Path::Root)?;
    let op = fields.required("op")?;
    let topic = fields.or_default("topic")?;
    let args = fields.take("args");
    fields.finish()?;
    let mut command = WireCommand {
        op,
        topic,
        node: None,
        module: None,
        texts: Default::default(),
        actor: None,
    };
    let Some(args) = args else { return Ok(command) };
    let outer = Path::Root;
    let mut fields = Fields::new(args, outer.key("args"))?;
    command.node = fields.or_default("node")?;
    command.module = fields.or_default("module")?;
    let names = ["category", "country", "ip", "path_prefix", "action"];
    for (text, name) in command.texts.iter_mut().zip(names) {
        *text = fields.or_with(name, String::new(), zig_byte_string_value)?;
    }
    command.actor = fields.or_default("actor")?;
    fields.finish()?;
    Ok(command)
}

/// Parses and validates a client command of at most [`MAX_MESSAGE`] bytes.
///
/// The rules are those of Zig's typed parse: unknown and duplicate keys are refused,
/// `topic` and `args` may be absent, enumerations may be names or ordinals, numbers may be
/// numeric strings, and text may also be an array of byte values (which must form UTF-8).
/// Text longer than its filter's capacity is refused, never truncated.
///
/// # Errors
///
/// [`InvalidCommand`] for anything else, and for a command [`validate`] refuses.
pub fn parse(bytes: &[u8]) -> Result<Command, InvalidCommand> {
    if bytes.len() > MAX_MESSAGE {
        return Err(InvalidCommand);
    }
    let limits = Limits { max_input_bytes: MAX_MESSAGE, ..Limits::default() };
    let value = sibuna_json::parse_with_limits(bytes, &limits).map_err(|_| InvalidCommand)?;
    let wire = decode_wire(&value).map_err(|_| InvalidCommand)?;
    let [category, country, ip, path_prefix, action] = wire.texts;
    let command = Command {
        op: wire.op,
        topic: wire.topic,
        args: Args {
            node: wire.node,
            module: wire.module,
            category: Text::from_string(category).map_err(|_| InvalidCommand)?,
            country: Text::from_string(country).map_err(|_| InvalidCommand)?,
            ip: Text::from_string(ip).map_err(|_| InvalidCommand)?,
            path_prefix: Text::from_string(path_prefix).map_err(|_| InvalidCommand)?,
            actor: wire.actor,
            action: Text::from_string(action).map_err(|_| InvalidCommand)?,
        },
    };
    validate(&command)?;
    Ok(command)
}

/// Checks a command's filter against its operation and topic.
///
/// # Errors
///
/// [`InvalidCommand`] for an invalid country filter, node or actor zero, an oversized
/// actor, a ping with a topic or filter, a missing topic, an unsubscription with a filter,
/// or a filter for another topic.
pub fn validate(command: &Command) -> Result<(), InvalidCommand> {
    let args = &command.args;
    let invalid = |condition: bool| if condition { Err(InvalidCommand) } else { Ok(()) };
    invalid(!country::valid_filter(args.country.as_str()))?;
    let event = !args.category.is_empty()
        || !args.ip.is_empty()
        || !args.path_prefix.is_empty()
        || !args.country.is_empty()
        || args.module.is_some();
    let audit = args.actor.is_some() || !args.action.is_empty();
    invalid(args.node == Some(0) || args.actor == Some(0))?;
    invalid(args.actor.is_some_and(|actor| actor > MAX_I64))?;
    if command.op == Op::Ping {
        return invalid(command.topic.is_some() || event || audit || args.node.is_some());
    }
    let topic = command.topic.ok_or(InvalidCommand)?;
    invalid(command.op == Op::Unsub && (event || audit || args.node.is_some()))?;
    invalid(event && topic != Topic::Events)?;
    invalid(audit && topic != Topic::Audit)?;
    invalid(args.node.is_some() && !matches!(topic, Topic::Events | Topic::Nodes | Topic::Stats))
}

/// Returns true if `principal` may subscribe to `topic`: browser sessions only, no pending
/// password change, and kiosk sessions only to statistics.
pub fn allowed(topic: Topic, principal: &Principal) -> bool {
    principal.token_id.is_none()
        && !principal.must_change
        && (!principal.kiosk || topic == Topic::Stats)
}

/// Returns the length of the next fragment of `text`: at most [`FRAGMENT_BYTES`] bytes,
/// ending on a character boundary so each fragment is valid UTF-8 on its own. JSON
/// escaping is applied by the wire writer; the receiver reassembles the original bytes
/// before interpreting any field.
pub fn fragment_length(text: &str) -> usize {
    text.floor_char_boundary(FRAGMENT_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::to_json;

    // Port of subscriptions.zig "subscription filters reject unrelated fields and retain
    // owned UTF-8".
    #[test]
    fn subscription_filters_reject_unrelated_fields_and_retain_owned_utf8() {
        let command =
            parse(br#"{"op":"filter","topic":"events","args":{"node":2,"category":"sqli"}}"#)
                .unwrap();
        assert_eq!(command.args.node, Some(2));
        assert_eq!(command.args.category, "sqli");
        assert_eq!(parse(br#"{"op":"sub"}"#), Err(InvalidCommand));
        assert_eq!(
            parse(br#"{"op":"sub","topic":"stats","args":{"actor":2}}"#),
            Err(InvalidCommand)
        );
        assert_eq!(
            parse(br#"{"op":"sub","topic":"events","args":{"node":0}}"#),
            Err(InvalidCommand)
        );
        let unicode = format!("{}\u{754c}", "a".repeat(FRAGMENT_BYTES - 1));
        assert_eq!(fragment_length(&unicode), FRAGMENT_BYTES - 1);
    }

    // Port of subscriptions.zig "owned command serialization preserves an actor above the
    // browser integer range".
    #[test]
    fn owned_command_serialization_preserves_an_actor_above_the_browser_integer_range() {
        let command = Command {
            op: Op::Filter,
            topic: Some(Topic::Audit),
            args: Args {
                actor: Some(9_007_199_254_740_993),
                action: Text::new("policy.edit").unwrap(),
                ..Args::default()
            },
        };
        let text = to_json(&command);
        assert_eq!(
            text,
            "{\"op\":\"filter\",\"topic\":\"audit\",\"args\":{\"actor\":\"9007199254740993\",\
             \"action\":\"policy.edit\"}}"
        );
        let result = parse(text.as_bytes()).unwrap();
        assert_eq!(result, command);
    }

    #[test]
    fn commands_follow_zig_typed_parse() {
        let ping = parse(br#"{"op":3}"#).unwrap();
        assert_eq!((ping.op, ping.topic), (Op::Ping, None));
        assert!(parse(br#"{"op":"ping","topic":"stats"}"#).is_err());
        assert!(parse(br#"{"op":"sub","topic":"stats","extra":1}"#).is_err());
        assert!(parse(br#"{"op":"sub","topic":"stats","topic":"stats"}"#).is_err());
        let bytes =
            parse(br#"{"op":"sub","topic":"events","args":{"category":[115,113,108]}}"#).unwrap();
        assert_eq!(bytes.args.category, "sql");
        let long = format!(
            r#"{{"op":"sub","topic":"events","args":{{"category":"{}"}}}}"#,
            "x".repeat(33)
        );
        assert!(parse(long.as_bytes()).is_err());
        assert!(parse(&[b' '; MAX_MESSAGE + 1]).is_err());
        let node = parse(br#"{"op":"sub","topic":"nodes","args":{"node":"7"}}"#).unwrap();
        assert_eq!(node.args.node, Some(7));
        assert!(parse(br#"{"op":"unsub","topic":"nodes","args":{"node":7}}"#).is_err());
        assert!(
            parse(br#"{"op":"sub","topic":"audit","args":{"actor":9223372036854775808}}"#)
                .is_err()
        );
        assert_eq!(
            to_json(&Command { op: Op::Ping, ..Command::default() }),
            "{\"op\":\"ping\",\"topic\":null,\"args\":{}}"
        );
    }

    #[test]
    fn kiosk_and_token_principals_are_limited() {
        let mut principal = Principal::default();
        assert!(allowed(Topic::Audit, &principal));
        principal.kiosk = true;
        assert!(allowed(Topic::Stats, &principal) && !allowed(Topic::Events, &principal));
        principal.token_id = Some(1);
        assert!(!allowed(Topic::Stats, &principal));
    }
}

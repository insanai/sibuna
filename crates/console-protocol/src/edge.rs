//! The edge view (SID 0031): the load balancer of a node as the console shows it, the
//! summary a peer answers with, the fleet, and a command with its answer.
//!
//! Every list has a bound that a decoder enforces. A text is bounded by the JSON limits
//! of its reader.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::codec::{
    Decode, DecodeError, Encode, Fields, Path, WireEnum, counter_field, decode_list, field,
    optional_counter_field,
};

/// The most members of a fleet, this node included.
pub const MAX_FLEET: usize = 64;
/// The most frontends of a view, and the most pools.
pub const MAX_GROUPS: usize = 128;
/// The most servers of one pool in a view. A longer pool is cut, and `more` counts the
/// rest.
pub const MAX_SERVERS: usize = 256;
/// The most refusal reasons a node reports.
pub const MAX_REASONS: usize = 32;
/// The longest command line, as on the admin socket.
pub const MAX_LINE: usize = 512;

/// Whether a node takes new flows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum NodeState {
    /// The node takes new flows.
    #[default]
    Serving,
    /// The node was told to stop. It finishes its flows and refuses new ones.
    Draining,
    /// The flow table is full. The node refuses new flows for lack of capacity.
    Full,
}

impl WireEnum for NodeState {
    const ALL: &'static [NodeState] = &[NodeState::Serving, NodeState::Draining, NodeState::Full];

    fn name(self) -> &'static str {
        match self {
            NodeState::Serving => "serving",
            NodeState::Draining => "draining",
            NodeState::Full => "full",
        }
    }
}

/// The refusals for one reason.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Refused {
    /// The reason, as the metrics label it.
    pub reason: String,
    /// How many connections, requests or datagrams.
    pub count: u64,
}

/// An address with many refusals in the current minute (SID 0034).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Source {
    /// The client address, IPv6 cut to its /64.
    pub address: String,
    /// The refusals counted for it: at least its true count.
    pub count: u64,
    /// The reason of its last refusal, as the metrics label it.
    pub reason: String,
}

/// The most sources of one node.
pub const MAX_SOURCES: usize = 16;

/// The summary of one node. A peer answers a fleet query with it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Node {
    /// The number of the node.
    pub node: u32,
    /// The version of the daemon.
    pub version: String,
    /// Seconds since the edge started.
    pub uptime_seconds: u64,
    /// Whether the node takes new flows.
    pub state: NodeState,
    /// The flows in the table.
    pub flows: u64,
    /// The size of the table.
    pub max_flows: u64,
    /// Flows and datagrams the edge dropped.
    pub drops: u64,
    /// Reloads since the start.
    pub reloads: u64,
    /// Run-time changes that the file does not hold.
    pub runtime_changes: u64,
    /// The servers of every pool.
    pub servers: u32,
    /// The servers an operator drained.
    pub servers_drained: u32,
    /// The servers whose health check fails.
    pub servers_down: u32,
    /// The digest of the topology file, as `show cluster` prints it. `None` for a
    /// daemon without a file.
    pub file_digest: Option<String>,
    /// The revision of the database authority (SID 0028). `None` until a node has one.
    pub authority_revision: Option<u64>,
    /// The routing regime: `standalone`, `regional` or `wide_area`.
    pub regime: String,
    /// The refusals by reason.
    pub refused: Vec<Refused>,
    /// Whether pressure mode is on (SID 0034).
    pub pressure: bool,
    /// The addresses with the most refusals in the current minute, most first.
    pub top_refused: Vec<Source>,
}

/// One frontend.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Frontend {
    /// The name in the topology.
    pub name: String,
    /// Finished HTTP requests.
    pub requests: u64,
    /// Accepted connections and UDP mappings.
    pub flows: u64,
    /// Bytes from clients.
    pub bytes_in: u64,
    /// Bytes to clients.
    pub bytes_out: u64,
    /// The mean duration of a request, in microseconds.
    pub mean_micros: u64,
    /// The bucket bound of the 95th percentile, in microseconds.
    pub p95_micros: Option<u64>,
}

/// One server of a pool: the columns of `show servers` and its counters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Server {
    /// The name, unique in its pool.
    pub name: String,
    /// The address new flows go to.
    pub address: String,
    /// `ready` or `drain`.
    pub state: String,
    /// The weight in use.
    pub weight: u32,
    /// The flows and exchanges that hold the server.
    pub flows: u64,
    /// `up`, `down`, or `-` for a pool without a check.
    pub health: String,
    /// The server is used only when no primary is eligible.
    pub backup: bool,
    /// What a command changed: `-`, or a list of `added`, `state`, `weight`.
    pub changed: String,
    /// Seconds that passive health still keeps the server out.
    pub ejected_seconds: Option<u64>,
    /// The share of its weight in a slow start, in percent.
    pub ramp_percent: Option<u32>,
    /// Requests the server was chosen for.
    pub requests: u64,
    /// Requests the server failed.
    pub failures: u64,
    /// Requests in flight.
    pub active: u64,
    /// The mean wait for the first byte, in microseconds.
    pub mean_micros: u64,
    /// The bucket bound of the 95th percentile of that wait, in microseconds.
    pub p95_micros: Option<u64>,
}

/// One backend pool.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pool {
    /// The name in the topology.
    pub name: String,
    /// At most [`MAX_SERVERS`] servers.
    pub servers: Vec<Server>,
    /// The servers left out because the pool is longer.
    pub more: u32,
}

/// Where a full queue made the node drop a line. The refusals for lack of a thread or
/// an exchange are in [`Node::refused`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Queues {
    /// Request lines the access log dropped.
    pub access_log_dropped: u64,
    /// Flow lines the access log dropped.
    pub flow_log_dropped: u64,
}

/// The view of one node.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct View {
    /// The node.
    pub node: Node,
    /// At most [`MAX_GROUPS`] frontends.
    pub frontends: Vec<Frontend>,
    /// At most [`MAX_GROUPS`] pools.
    pub pools: Vec<Pool>,
    /// The queues.
    pub queues: Queues,
}

/// One member of the fleet.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Member {
    /// The number of the member.
    pub node: u32,
    /// `self`, or the state of the link: `current`, `stale`, `rejected`, `unobserved`.
    pub link: String,
    /// The summary, when the member answered.
    pub summary: Option<Node>,
}

/// The fleet as one node sees it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fleet {
    /// The number of the node that answers.
    pub self_node: u32,
    /// At most [`MAX_FLEET`] members, this node first.
    pub members: Vec<Member>,
}

/// A command for the edge: one line of the admin socket.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Command {
    /// The line, at most [`MAX_LINE`] bytes of printable ASCII.
    pub line: String,
}

/// The answer to a command, as the admin socket gives it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Answer {
    /// The command succeeded.
    pub ok: bool,
    /// The result of a command that succeeded.
    pub text: String,
    /// The code of a failure, such as `ADM005`.
    pub code: String,
    /// The title of a failure.
    pub title: String,
    /// The explanation of a failure.
    pub message: String,
    /// How to correct a failure.
    pub hint: String,
}

impl Encode for Refused {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "reason", &self.reason)?;
        counter_field(json, "count", self.count)?;
        json.end_object()
    }
}

impl Decode for Refused {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Refused, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let refused =
            Refused { reason: fields.required("reason")?, count: fields.required("count")? };
        fields.finish()?;
        Ok(refused)
    }
}

impl Encode for Source {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "address", &self.address)?;
        counter_field(json, "count", self.count)?;
        field(json, "reason", &self.reason)?;
        json.end_object()
    }
}

impl Decode for Source {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Source, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let source = Source {
            address: fields.required("address")?,
            count: fields.required("count")?,
            reason: fields.required("reason")?,
        };
        fields.finish()?;
        Ok(source)
    }
}

impl Encode for Node {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "node", &self.node)?;
        field(json, "version", &self.version)?;
        counter_field(json, "uptime_seconds", self.uptime_seconds)?;
        field(json, "state", &self.state)?;
        counter_field(json, "flows", self.flows)?;
        counter_field(json, "max_flows", self.max_flows)?;
        counter_field(json, "drops", self.drops)?;
        counter_field(json, "reloads", self.reloads)?;
        counter_field(json, "runtime_changes", self.runtime_changes)?;
        field(json, "servers", &self.servers)?;
        field(json, "servers_drained", &self.servers_drained)?;
        field(json, "servers_down", &self.servers_down)?;
        field(json, "file_digest", &self.file_digest)?;
        optional_counter_field(json, "authority_revision", self.authority_revision)?;
        field(json, "regime", &self.regime)?;
        field(json, "refused", &self.refused)?;
        field(json, "pressure", &self.pressure)?;
        field(json, "top_refused", &self.top_refused)?;
        json.end_object()
    }
}

impl Decode for Node {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Node, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let node = Node {
            node: fields.required("node")?,
            version: fields.or_default("version")?,
            uptime_seconds: fields.or_default("uptime_seconds")?,
            state: fields.required("state")?,
            flows: fields.or_default("flows")?,
            max_flows: fields.or_default("max_flows")?,
            drops: fields.or_default("drops")?,
            reloads: fields.or_default("reloads")?,
            runtime_changes: fields.or_default("runtime_changes")?,
            servers: fields.or_default("servers")?,
            servers_drained: fields.or_default("servers_drained")?,
            servers_down: fields.or_default("servers_down")?,
            file_digest: fields.or_default("file_digest")?,
            authority_revision: fields.or_default("authority_revision")?,
            regime: fields.or_default("regime")?,
            refused: fields.or_with("refused", Vec::new(), |value, path| {
                decode_list(value, path, MAX_REASONS)
            })?,
            pressure: fields.or_default("pressure")?,
            top_refused: fields.or_with("top_refused", Vec::new(), |value, path| {
                decode_list(value, path, MAX_SOURCES)
            })?,
        };
        fields.finish()?;
        Ok(node)
    }
}

impl Encode for Frontend {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "name", &self.name)?;
        counter_field(json, "requests", self.requests)?;
        counter_field(json, "flows", self.flows)?;
        counter_field(json, "bytes_in", self.bytes_in)?;
        counter_field(json, "bytes_out", self.bytes_out)?;
        counter_field(json, "mean_micros", self.mean_micros)?;
        optional_counter_field(json, "p95_micros", self.p95_micros)?;
        json.end_object()
    }
}

impl Decode for Frontend {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Frontend, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let frontend = Frontend {
            name: fields.required("name")?,
            requests: fields.or_default("requests")?,
            flows: fields.or_default("flows")?,
            bytes_in: fields.or_default("bytes_in")?,
            bytes_out: fields.or_default("bytes_out")?,
            mean_micros: fields.or_default("mean_micros")?,
            p95_micros: fields.or_default("p95_micros")?,
        };
        fields.finish()?;
        Ok(frontend)
    }
}

impl Encode for Server {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "name", &self.name)?;
        field(json, "address", &self.address)?;
        field(json, "state", &self.state)?;
        field(json, "weight", &self.weight)?;
        counter_field(json, "flows", self.flows)?;
        field(json, "health", &self.health)?;
        field(json, "backup", &self.backup)?;
        field(json, "changed", &self.changed)?;
        optional_counter_field(json, "ejected_seconds", self.ejected_seconds)?;
        field(json, "ramp_percent", &self.ramp_percent)?;
        counter_field(json, "requests", self.requests)?;
        counter_field(json, "failures", self.failures)?;
        counter_field(json, "active", self.active)?;
        counter_field(json, "mean_micros", self.mean_micros)?;
        optional_counter_field(json, "p95_micros", self.p95_micros)?;
        json.end_object()
    }
}

impl Decode for Server {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Server, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let server = Server {
            name: fields.required("name")?,
            address: fields.required("address")?,
            state: fields.required("state")?,
            weight: fields.required("weight")?,
            flows: fields.or_default("flows")?,
            health: fields.or_default("health")?,
            backup: fields.or_default("backup")?,
            changed: fields.or_default("changed")?,
            ejected_seconds: fields.or_default("ejected_seconds")?,
            ramp_percent: fields.or_default("ramp_percent")?,
            requests: fields.or_default("requests")?,
            failures: fields.or_default("failures")?,
            active: fields.or_default("active")?,
            mean_micros: fields.or_default("mean_micros")?,
            p95_micros: fields.or_default("p95_micros")?,
        };
        fields.finish()?;
        Ok(server)
    }
}

impl Encode for Pool {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "name", &self.name)?;
        field(json, "servers", &self.servers)?;
        field(json, "more", &self.more)?;
        json.end_object()
    }
}

impl Decode for Pool {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Pool, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let pool = Pool {
            name: fields.required("name")?,
            servers: fields
                .required_with("servers", |value, path| decode_list(value, path, MAX_SERVERS))?,
            more: fields.or_default("more")?,
        };
        fields.finish()?;
        Ok(pool)
    }
}

impl Encode for Queues {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        counter_field(json, "access_log_dropped", self.access_log_dropped)?;
        counter_field(json, "flow_log_dropped", self.flow_log_dropped)?;
        json.end_object()
    }
}

impl Decode for Queues {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Queues, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let queues = Queues {
            access_log_dropped: fields.or_default("access_log_dropped")?,
            flow_log_dropped: fields.or_default("flow_log_dropped")?,
        };
        fields.finish()?;
        Ok(queues)
    }
}

impl Encode for View {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "node", &self.node)?;
        field(json, "frontends", &self.frontends)?;
        field(json, "pools", &self.pools)?;
        field(json, "queues", &self.queues)?;
        json.end_object()
    }
}

impl Decode for View {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<View, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let groups = MAX_GROUPS;
        let view = View {
            node: fields.required("node")?,
            frontends: fields
                .required_with("frontends", |value, path| decode_list(value, path, groups))?,
            pools: fields
                .required_with("pools", |value, path| decode_list(value, path, groups))?,
            queues: fields.or_default("queues")?,
        };
        fields.finish()?;
        Ok(view)
    }
}

impl Encode for Member {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "node", &self.node)?;
        field(json, "link", &self.link)?;
        field(json, "summary", &self.summary)?;
        json.end_object()
    }
}

impl Decode for Member {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Member, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let member = Member {
            node: fields.required("node")?,
            link: fields.required("link")?,
            summary: fields.or_default("summary")?,
        };
        fields.finish()?;
        Ok(member)
    }
}

impl Encode for Fleet {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "self", &self.self_node)?;
        field(json, "members", &self.members)?;
        json.end_object()
    }
}

impl Decode for Fleet {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Fleet, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let fleet = Fleet {
            self_node: fields.required("self")?,
            members: fields
                .required_with("members", |value, path| decode_list(value, path, MAX_FLEET))?,
        };
        fields.finish()?;
        Ok(fleet)
    }
}

impl Encode for Command {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "line", &self.line)?;
        json.end_object()
    }
}

impl Decode for Command {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Command, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let command = Command { line: fields.required("line")? };
        fields.finish()?;
        Ok(command)
    }
}

impl Encode for Answer {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "ok", &self.ok)?;
        field(json, "text", &self.text)?;
        field(json, "code", &self.code)?;
        field(json, "title", &self.title)?;
        field(json, "message", &self.message)?;
        field(json, "hint", &self.hint)?;
        json.end_object()
    }
}

impl Decode for Answer {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Answer, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let answer = Answer {
            ok: fields.required("ok")?,
            text: fields.or_default("text")?,
            code: fields.or_default("code")?,
            title: fields.or_default("title")?,
            message: fields.or_default("message")?,
            hint: fields.or_default("hint")?,
        };
        fields.finish()?;
        Ok(answer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_json, to_json};

    fn sample() -> View {
        let server = Server {
            name: "a".into(),
            address: "10.0.0.1:80".into(),
            state: "drain".into(),
            weight: 2,
            flows: 7,
            health: "up".into(),
            changed: "state,weight".into(),
            ejected_seconds: Some(7),
            ramp_percent: Some(40),
            p95_micros: Some(5_000),
            ..Server::default()
        };
        let node = Node {
            node: 2,
            state: NodeState::Full,
            file_digest: Some("3fa9c1d2e4b50c77".into()),
            refused: vec![Refused { reason: "flow_limit".into(), count: 3 }],
            pressure: true,
            top_refused: vec![Source {
                address: "192.0.2.7".into(),
                count: 41,
                reason: "client_flow_limit".into(),
            }],
            ..Node::default()
        };
        View {
            node,
            frontends: vec![Frontend { name: "web".into(), requests: 9, ..Frontend::default() }],
            pools: vec![Pool { name: "app".into(), servers: vec![server], more: 0 }],
            queues: Queues { access_log_dropped: 1, flow_log_dropped: 2 },
        }
    }

    #[test]
    fn a_view_survives_the_wire() {
        let view = sample();
        let text = to_json(&view);
        assert!(text.contains(r#""state":"full""#), "{text}");
        assert!(text.contains(r#""authority_revision":null"#), "{text}");
        assert_eq!(from_json::<View>(text.as_bytes()).unwrap(), view);
        let fleet = Fleet {
            self_node: 1,
            members: vec![
                Member { node: 1, link: "self".into(), summary: Some(view.node.clone()) },
                Member { node: 2, link: "stale".into(), summary: None },
            ],
        };
        assert_eq!(from_json::<Fleet>(to_json(&fleet).as_bytes()).unwrap(), fleet);
    }

    #[test]
    fn lists_are_bounded() {
        let member = r#"{"node":1,"link":"self","summary":null}"#;
        let many = vec![member; MAX_FLEET + 1].join(",");
        let text = format!(r#"{{"self":1,"members":[{many}]}}"#);
        assert!(from_json::<Fleet>(text.as_bytes()).is_err());
        let exact = vec![member; MAX_FLEET].join(",");
        let text = format!(r#"{{"self":1,"members":[{exact}]}}"#);
        assert_eq!(from_json::<Fleet>(text.as_bytes()).unwrap().members.len(), MAX_FLEET);
        assert!(from_json::<Command>(br#"{"line":"show servers","extra":1}"#).is_err());
    }

    #[test]
    fn an_answer_carries_the_failure_of_the_socket() {
        let answer = Answer {
            code: "ADM005".into(),
            title: "INVALID VALUE".into(),
            message: "`up` is not a server state.".into(),
            hint: "The states are `ready` and `drain`.".into(),
            ..Answer::default()
        };
        assert_eq!(from_json::<Answer>(to_json(&answer).as_bytes()).unwrap(), answer);
    }
}

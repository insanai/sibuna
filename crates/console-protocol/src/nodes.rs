//! Cluster members, probes, peer telemetry and local node commands. A command's identity
//! includes a boot and the expected control revision; a durable intent alone never proves
//! a runtime effect, so callers keep the operation id across retries.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::codec::{
    Decode, DecodeError, Encode, Fields, Path, WireEnum, counter_field, decode_list, field,
    optional_counter_field,
};
use crate::error::{MAX_I64, ValidationError, limit};
use crate::text::Text;
use crate::users;

/// How long a command stays valid, in seconds.
pub const COMMAND_SECONDS: u64 = 30;
/// How long receipts are kept, in days.
pub const RECEIPT_DAYS: u16 = 30;
/// The most receipts storage keeps.
pub const COMMAND_CAPACITY: u16 = 4096;
/// The most cluster members a page lists.
pub const MAX_MEMBERS: usize = 9;
/// The most configured peer probes.
pub const MAX_PROBES: usize = 8;
/// The longest member address; bounded so a full page fits the storage envelope.
pub const MAX_ADDRESS: usize = 64;
/// The longest console link.
pub const MAX_URL: usize = 128;

/// A local node command.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Kind {
    /// Stop accepting new connections.
    #[default]
    Drain,
    /// Accept connections again.
    Resume,
    /// Clear the node's dynamic ban table.
    ClearLocalBans,
}

impl WireEnum for Kind {
    const ALL: &'static [Kind] = &[Kind::Drain, Kind::Resume, Kind::ClearLocalBans];

    fn name(self) -> &'static str {
        match self {
            Kind::Drain => "drain",
            Kind::Resume => "resume",
            Kind::ClearLocalBans => "clear_local_bans",
        }
    }
}

/// What is known about a command's effect.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum State {
    /// Recorded, not yet applied.
    #[default]
    Intent,
    /// The node applied it.
    Applied,
    /// The node refused it.
    Rejected,
    /// The outcome was not confirmed.
    Uncertain,
}

impl WireEnum for State {
    const ALL: &'static [State] =
        &[State::Intent, State::Applied, State::Rejected, State::Uncertain];

    fn name(self) -> &'static str {
        match self {
            State::Intent => "intent",
            State::Applied => "applied",
            State::Rejected => "rejected",
            State::Uncertain => "uncertain",
        }
    }
}

/// A member's consensus role.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Role {
    /// Not observed.
    #[default]
    Unknown,
    /// A single-node deployment.
    Single,
    /// The leader.
    Leader,
    /// A follower.
    Follower,
    /// A candidate in an election.
    Candidate,
}

impl WireEnum for Role {
    const ALL: &'static [Role] =
        &[Role::Unknown, Role::Single, Role::Leader, Role::Follower, Role::Candidate];

    fn name(self) -> &'static str {
        match self {
            Role::Unknown => "unknown",
            Role::Single => "single",
            Role::Leader => "leader",
            Role::Follower => "follower",
            Role::Candidate => "candidate",
        }
    }
}

/// A probe's verdict on a peer's data plane.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Health {
    /// Not observed.
    #[default]
    Unknown,
    /// Answering normally.
    Healthy,
    /// Answering slowly or partially.
    Degraded,
    /// Not answering.
    Down,
}

impl WireEnum for Health {
    const ALL: &'static [Health] =
        &[Health::Unknown, Health::Healthy, Health::Degraded, Health::Down];

    fn name(self) -> &'static str {
        match self {
            Health::Unknown => "unknown",
            Health::Healthy => "healthy",
            Health::Degraded => "degraded",
            Health::Down => "down",
        }
    }
}

/// One console's view of its cluster: itself plus every configured peer probe. Peers
/// without an observation count as unknown, never as healthy zeros.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Summary {
    /// Healthy members.
    pub healthy: u8,
    /// Degraded members.
    pub degraded: u8,
    /// Members that are down.
    pub down: u8,
    /// Members without an observation.
    pub unknown: u8,
}

impl Summary {
    /// Returns the number of members counted.
    pub fn total(&self) -> u16 {
        u16::from(self.healthy)
            + u16::from(self.degraded)
            + u16::from(self.down)
            + u16::from(self.unknown)
    }
}

impl Encode for Summary {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "healthy", &self.healthy)?;
        field(json, "degraded", &self.degraded)?;
        field(json, "down", &self.down)?;
        field(json, "unknown", &self.unknown)?;
        json.end_object()
    }
}

impl Decode for Summary {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Summary, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let summary = Summary {
            healthy: fields.or_default("healthy")?,
            degraded: fields.or_default("degraded")?,
            down: fields.or_default("down")?,
            unknown: fields.or_default("unknown")?,
        };
        fields.finish()?;
        Ok(summary)
    }
}

/// Storage's view of the local member's consensus state. Stale values keep their last
/// observation and `quorum` becomes false rather than inventing progress.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Storage {
    /// The member's role.
    pub role: Role,
    /// The leader's node id, if known.
    pub leader: Option<u32>,
    /// The consensus term.
    pub term: u64,
    /// The last decided slot.
    pub decided: u64,
    /// The last applied slot.
    pub applied: u64,
    /// The last durable slot.
    pub durable: u64,
    /// A quorum was reachable at the observation.
    pub quorum: bool,
    /// When it was observed, in Unix seconds.
    pub observed_at: u64,
}

impl Encode for Storage {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "role", &self.role)?;
        field(json, "leader", &self.leader)?;
        counter_field(json, "term", self.term)?;
        counter_field(json, "decided", self.decided)?;
        counter_field(json, "applied", self.applied)?;
        counter_field(json, "durable", self.durable)?;
        field(json, "quorum", &self.quorum)?;
        counter_field(json, "observed_at", self.observed_at)?;
        json.end_object()
    }
}

impl Decode for Storage {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Storage, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let storage = Storage {
            role: fields.or_default("role")?,
            leader: fields.or_default("leader")?,
            term: fields.or_default("term")?,
            decided: fields.or_default("decided")?,
            applied: fields.or_default("applied")?,
            durable: fields.or_default("durable")?,
            quorum: fields.or_default("quorum")?,
            observed_at: fields.or_default("observed_at")?,
        };
        fields.finish()?;
        Ok(storage)
    }
}

/// A replicated cluster member row.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Member {
    /// The node id.
    pub node: u32,
    /// The member's management address.
    pub address: Text<MAX_ADDRESS>,
    /// The member's console link ([`safe_url`] before rendering).
    pub console_url: Text<MAX_URL>,
    /// The member's software version.
    pub version: Text<32>,
    /// The member's boot id as hex.
    pub boot: Text<32>,
    /// First seen, in Unix seconds.
    pub first_seen: u64,
    /// Last seen, in Unix seconds.
    pub last_seen: u64,
    /// The policy revision the member applied.
    pub applied_revision: u64,
    /// The control revision the member applied.
    pub control_revision: u64,
    /// The member's applied slot.
    pub applied_slot: u64,
    /// The member's decided slot.
    pub decided_slot: u64,
    /// The member is draining.
    pub draining: bool,
}

impl Encode for Member {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "node", &self.node)?;
        field(json, "address", &self.address)?;
        field(json, "console_url", &self.console_url)?;
        field(json, "version", &self.version)?;
        field(json, "boot", &self.boot)?;
        counter_field(json, "first_seen", self.first_seen)?;
        counter_field(json, "last_seen", self.last_seen)?;
        counter_field(json, "applied_revision", self.applied_revision)?;
        counter_field(json, "control_revision", self.control_revision)?;
        counter_field(json, "applied_slot", self.applied_slot)?;
        counter_field(json, "decided_slot", self.decided_slot)?;
        field(json, "draining", &self.draining)?;
        json.end_object()
    }
}

impl Decode for Member {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Member, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let member = Member {
            node: fields.required("node")?,
            address: fields.or_default("address")?,
            console_url: fields.or_default("console_url")?,
            version: fields.or_default("version")?,
            boot: fields.or_default("boot")?,
            first_seen: fields.or_default("first_seen")?,
            last_seen: fields.or_default("last_seen")?,
            applied_revision: fields.or_default("applied_revision")?,
            control_revision: fields.or_default("control_revision")?,
            applied_slot: fields.or_default("applied_slot")?,
            decided_slot: fields.or_default("decided_slot")?,
            draining: fields.or_default("draining")?,
        };
        fields.finish()?;
        Ok(member)
    }
}

/// One configured peer's most recent data-plane probe. `requests` is the counter delta
/// between the last two successful probes, not a rate; zero means not yet observed twice.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Probe {
    /// The peer's node id.
    pub node: u32,
    /// The probe's verdict.
    pub health: Health,
    /// The probe's round trip, in milliseconds.
    pub latency_ms: u32,
    /// The last successful probe, in Unix seconds.
    pub last_seen: u64,
    /// The last probe, in Unix seconds.
    pub observed_at: u64,
    /// The peer is draining.
    pub draining: bool,
    /// Requests between the last two successful probes.
    pub requests: u64,
}

impl Encode for Probe {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "node", &self.node)?;
        field(json, "health", &self.health)?;
        field(json, "latency_ms", &self.latency_ms)?;
        counter_field(json, "last_seen", self.last_seen)?;
        counter_field(json, "observed_at", self.observed_at)?;
        field(json, "draining", &self.draining)?;
        counter_field(json, "requests", self.requests)?;
        json.end_object()
    }
}

impl Decode for Probe {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Probe, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let probe = Probe {
            node: fields.required("node")?,
            health: fields.or_default("health")?,
            latency_ms: fields.or_default("latency_ms")?,
            last_seen: fields.or_default("last_seen")?,
            observed_at: fields.or_default("observed_at")?,
            draining: fields.or_default("draining")?,
            requests: fields.or_default("requests")?,
        };
        fields.finish()?;
        Ok(probe)
    }
}

/// The state of direct telemetry from a peer over an authenticated management connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum PeerStatus {
    /// Never observed.
    #[default]
    Unobserved,
    /// Connecting.
    Connecting,
    /// Receiving current snapshots.
    Current,
    /// The last snapshot is old.
    Stale,
    /// The peer's snapshots were refused.
    Rejected,
}

impl WireEnum for PeerStatus {
    const ALL: &'static [PeerStatus] = &[
        PeerStatus::Unobserved,
        PeerStatus::Connecting,
        PeerStatus::Current,
        PeerStatus::Stale,
        PeerStatus::Rejected,
    ];

    fn name(self) -> &'static str {
        match self {
            PeerStatus::Unobserved => "unobserved",
            PeerStatus::Connecting => "connecting",
            PeerStatus::Current => "current",
            PeerStatus::Stale => "stale",
            PeerStatus::Rejected => "rejected",
        }
    }
}

/// One peer's direct telemetry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Peer {
    /// The peer's node id.
    pub node: u32,
    /// The telemetry state.
    pub status: PeerStatus,
    /// The peer's boot id as hex, once observed.
    pub boot: Option<Text<32>>,
    /// Age of the last snapshot, in seconds.
    pub age_seconds: Option<u64>,
    /// Clock difference to the peer, in seconds.
    pub clock_skew_seconds: Option<u64>,
    /// The last snapshot's sequence.
    pub sequence: u64,
    /// The last snapshot's watermark.
    pub watermark: u64,
    /// Subscription restarts.
    pub resets: u64,
    /// The peer's request counter.
    pub requests: Option<u64>,
    /// The peer's sample loss counter.
    pub sample_loss: Option<u64>,
    /// The peer has country data.
    pub geoip_available: bool,
    /// The peer's resident memory, in KiB.
    pub rss_kib: Option<u64>,
    /// The peer's CPU use in per mille of one core.
    pub cpu_permille: Option<u32>,
}

impl Encode for Peer {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "node", &self.node)?;
        field(json, "status", &self.status)?;
        field(json, "boot", &self.boot)?;
        optional_counter_field(json, "age_seconds", self.age_seconds)?;
        optional_counter_field(json, "clock_skew_seconds", self.clock_skew_seconds)?;
        counter_field(json, "sequence", self.sequence)?;
        counter_field(json, "watermark", self.watermark)?;
        counter_field(json, "resets", self.resets)?;
        optional_counter_field(json, "requests", self.requests)?;
        optional_counter_field(json, "sample_loss", self.sample_loss)?;
        field(json, "geoip_available", &self.geoip_available)?;
        optional_counter_field(json, "rss_kib", self.rss_kib)?;
        field(json, "cpu_permille", &self.cpu_permille)?;
        json.end_object()
    }
}

impl Decode for Peer {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Peer, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let peer = Peer {
            node: fields.required("node")?,
            status: fields.required("status")?,
            boot: fields.or_default("boot")?,
            age_seconds: fields.or_default("age_seconds")?,
            clock_skew_seconds: fields.or_default("clock_skew_seconds")?,
            sequence: fields.or_default("sequence")?,
            watermark: fields.or_default("watermark")?,
            resets: fields.or_default("resets")?,
            requests: fields.or_default("requests")?,
            sample_loss: fields.or_default("sample_loss")?,
            geoip_available: fields.or_default("geoip_available")?,
            rss_kib: fields.or_default("rss_kib")?,
            cpu_permille: fields.or_default("cpu_permille")?,
        };
        fields.finish()?;
        Ok(peer)
    }
}

/// The cluster page.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Page {
    /// This console's node id (`self` on the wire).
    pub self_node: u32,
    /// The committed policy revision.
    pub committed: u64,
    /// The local consensus state.
    pub storage: Storage,
    /// At most [`MAX_MEMBERS`] members.
    pub members: Vec<Member>,
}

impl Encode for Page {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "self", &self.self_node)?;
        counter_field(json, "committed", self.committed)?;
        field(json, "storage", &self.storage)?;
        field(json, "members", &self.members)?;
        json.end_object()
    }
}

impl Decode for Page {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Page, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let page = Page {
            self_node: fields.required("self")?,
            committed: fields.required("committed")?,
            storage: fields.required("storage")?,
            members: fields
                .required_with("members", |value, path| decode_list(value, path, MAX_MEMBERS))?,
        };
        fields.finish()?;
        Ok(page)
    }
}

/// Returns true for a plain `http://` or `https://` link of at most [`MAX_URL`] bytes
/// without spaces, quotes, `<` or non-ASCII bytes. Links rendered from replicated rows
/// must pass this.
pub fn safe_url(text: &str) -> bool {
    (1..=MAX_URL).contains(&text.len())
        && (text.starts_with("https://") || text.starts_with("http://"))
        && text.bytes().all(|byte| byte > 32 && byte < 127 && !b"\"'<".contains(&byte))
}

/// A local node command.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Command {
    /// The operator's credential.
    pub auth: users::Auth,
    /// The operation id the caller keeps across retries; never all zeros.
    pub id: [u8; 16],
    /// The target node's boot; never all zeros.
    pub boot: [u8; 16],
    /// The target node.
    pub node: u32,
    /// The control revision the operator saw.
    pub expected_revision: u64,
    /// When the command expires, in Unix seconds.
    pub expires: u64,
    /// What to do.
    pub kind: Kind,
}

/// Reads a command's receipt.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Read {
    /// The operator's credential.
    pub auth: users::Auth,
    /// The operation id.
    pub id: [u8; 16],
}

/// The local node's control status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// The operation this status answers, as hex.
    pub operation_id: Text<32>,
    /// How long receipts are kept, in days.
    pub receipt_retention_days: u16,
    /// The most receipts storage keeps.
    pub command_capacity: u16,
    /// The node id.
    pub node: u32,
    /// The node's boot id as hex.
    pub boot: Text<32>,
    /// The applied control revision.
    pub control_revision: u64,
    /// The node is draining.
    pub draining: bool,
    /// Open connections.
    pub connections: u32,
    /// Occupied ban-table entries.
    pub active_ban_entries: u32,
    /// The committed policy revision.
    pub committed: u64,
    /// The applied policy revision.
    pub applied: u64,
    /// When it was observed, in Unix seconds.
    pub observed_at: u64,
    /// The process's uptime, in milliseconds.
    pub uptime_ms: u64,
    /// A completion record is not yet durable.
    pub completion_pending: bool,
}

impl Default for Status {
    fn default() -> Status {
        Status {
            operation_id: Text::default(),
            receipt_retention_days: RECEIPT_DAYS,
            command_capacity: COMMAND_CAPACITY,
            node: 0,
            boot: Text::default(),
            control_revision: 0,
            draining: false,
            connections: 0,
            active_ban_entries: 0,
            committed: 0,
            applied: 0,
            observed_at: 0,
            uptime_ms: 0,
            completion_pending: false,
        }
    }
}

impl Encode for Status {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "operation_id", &self.operation_id)?;
        field(json, "receipt_retention_days", &self.receipt_retention_days)?;
        field(json, "command_capacity", &self.command_capacity)?;
        field(json, "node", &self.node)?;
        field(json, "boot", &self.boot)?;
        counter_field(json, "control_revision", self.control_revision)?;
        field(json, "draining", &self.draining)?;
        field(json, "connections", &self.connections)?;
        field(json, "active_ban_entries", &self.active_ban_entries)?;
        counter_field(json, "committed", self.committed)?;
        counter_field(json, "applied", self.applied)?;
        counter_field(json, "observed_at", self.observed_at)?;
        counter_field(json, "uptime_ms", self.uptime_ms)?;
        field(json, "completion_pending", &self.completion_pending)?;
        json.end_object()
    }
}

impl Decode for Status {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Status, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let status = Status {
            operation_id: fields.required("operation_id")?,
            receipt_retention_days: fields.or("receipt_retention_days", RECEIPT_DAYS)?,
            command_capacity: fields.or("command_capacity", COMMAND_CAPACITY)?,
            node: fields.required("node")?,
            boot: fields.required("boot")?,
            control_revision: fields.required("control_revision")?,
            draining: fields.required("draining")?,
            connections: fields.required("connections")?,
            active_ban_entries: fields.required("active_ban_entries")?,
            committed: fields.required("committed")?,
            applied: fields.required("applied")?,
            observed_at: fields.required("observed_at")?,
            uptime_ms: fields.required("uptime_ms")?,
            completion_pending: fields.required("completion_pending")?,
        };
        fields.finish()?;
        Ok(status)
    }
}

/// A command's receipt.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Receipt {
    /// The operation id as hex.
    pub id: Text<32>,
    /// The target boot as hex.
    pub boot: Text<32>,
    /// The target node.
    pub node: u32,
    /// What was asked.
    pub kind: Kind,
    /// What is known of its effect.
    pub state: State,
    /// The control revision the operator saw.
    pub expected_revision: u64,
    /// The control revision after applying.
    pub applied_revision: Option<u64>,
    /// Ban entries cleared.
    pub cleared_entries: Option<u32>,
    /// When it was requested, in Unix seconds.
    pub requested_at: u64,
    /// When it completed, in Unix seconds.
    pub completed_at: Option<u64>,
    /// The completion record is durable.
    pub completion_persisted: bool,
}

impl Encode for Receipt {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "id", &self.id)?;
        field(json, "boot", &self.boot)?;
        field(json, "node", &self.node)?;
        field(json, "kind", &self.kind)?;
        field(json, "state", &self.state)?;
        counter_field(json, "expected_revision", self.expected_revision)?;
        optional_counter_field(json, "applied_revision", self.applied_revision)?;
        field(json, "cleared_entries", &self.cleared_entries)?;
        counter_field(json, "requested_at", self.requested_at)?;
        optional_counter_field(json, "completed_at", self.completed_at)?;
        field(json, "completion_persisted", &self.completion_persisted)?;
        json.end_object()
    }
}

impl Decode for Receipt {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Receipt, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let receipt = Receipt {
            id: fields.required("id")?,
            boot: fields.required("boot")?,
            node: fields.required("node")?,
            kind: fields.required("kind")?,
            state: fields.required("state")?,
            expected_revision: fields.required("expected_revision")?,
            applied_revision: fields.or_default("applied_revision")?,
            cleared_entries: fields.or_default("cleared_entries")?,
            requested_at: fields.required("requested_at")?,
            completed_at: fields.or_default("completed_at")?,
            completion_persisted: fields.or_default("completion_persisted")?,
        };
        fields.finish()?;
        Ok(receipt)
    }
}

/// Checks a node command.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for node zero, an oversized revision or expiry, or
/// an all-zero operation id or boot.
pub fn validate(input: &Command) -> Result<(), ValidationError> {
    limit(
        input.node == 0
            || input.expected_revision >= MAX_I64
            || input.expires > MAX_I64
            || input.id == [0; 16]
            || input.boot == [0; 16],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_json, to_json};

    // Port of nodes.zig "console links from replicated rows are restricted to plain
    // origins".
    #[test]
    fn console_links_from_replicated_rows_are_restricted_to_plain_origins() {
        assert!(safe_url("https://console.example:9443"));
        assert!(safe_url("http://127.0.0.1:9443"));
        assert!(!safe_url("javascript:alert(1)"));
        assert!(!safe_url("https://a\"b"));
        assert!(!safe_url(""));
    }

    #[test]
    fn pages_round_trip() {
        let page = Page {
            self_node: 1,
            committed: 4,
            storage: Storage {
                role: Role::Leader,
                leader: Some(1),
                quorum: true,
                ..Default::default()
            },
            members: vec![Member {
                node: 1,
                address: Text::new("10.0.0.1:7000").unwrap(),
                applied_slot: u64::MAX,
                ..Default::default()
            }],
        };
        let text = to_json(&page);
        assert!(text.starts_with(
            "{\"self\":1,\"committed\":4,\"storage\":{\"role\":\"leader\",\"leader\":1,\"term\":0,"
        ));
        assert!(text.contains("\"applied_slot\":\"18446744073709551615\""));
        assert_eq!(from_json::<Page>(text.as_bytes()), Ok(page));
        let receipt =
            Receipt { applied_revision: Some(2), cleared_entries: Some(3), ..Default::default() };
        assert_eq!(from_json::<Receipt>(to_json(&receipt).as_bytes()), Ok(receipt));
        let status = Status { boot: Text::new("ab").unwrap(), ..Default::default() };
        assert_eq!(from_json::<Status>(to_json(&status).as_bytes()), Ok(status));
    }

    #[test]
    fn commands_need_identity() {
        let command = Command { id: [1; 16], boot: [1; 16], node: 1, ..Default::default() };
        assert_eq!(validate(&command), Ok(()));
        assert!(validate(&Command { id: [0; 16], ..command.clone() }).is_err());
        assert!(validate(&Command { expected_revision: MAX_I64, ..command }).is_err());
        assert_eq!(Summary { healthy: 255, degraded: 255, down: 255, unknown: 255 }.total(), 1020);
    }
}
